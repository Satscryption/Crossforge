"""Deterministic provider routing, budgets, fallback evidence, and statistics."""

from __future__ import annotations

import json
import re
import secrets
import statistics
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .errors import (
    InvalidInputError,
    PolicyError,
    PreconditionError,
    ProviderUnavailableError,
    StateInconsistencyError,
)
from .locking import repository_lock
from .models import Budget, ProviderStatus, Risk, RoutingConfig, Strategy
from .providers.base import ProviderProbe
from .util import atomic_write_json, ensure_private_directory, utc_now


PROVIDERS = ("codex", "grok")
BUDGET_LIMITS: Mapping[Budget, int] = {
    Budget.LEAN: 4,
    Budget.BALANCED: 6,
    Budget.QUALITY: 8,
}
STATISTICS_SCHEMA_VERSION = 1
MAX_COMPARISON_WINDOW = 50
MINIMUM_PROMOTION_SAMPLES = 10
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TASK_ID_RE = re.compile(r"^T[1-9][0-9]*$")
_RUN_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_OBSERVATION_FIELDS = {
    "observationId",
    "runId",
    "taskId",
    "provider",
    "taskClass",
    "risk",
    "eligible",
    "firstPassGatePassed",
    "blockingReviewFindingCount",
    "durationMs",
    "correctionRounds",
    "selected",
    "gateCommandFingerprint",
    "repositoryIdentity",
    "crossforgeSchemaMajor",
    "recordedAt",
}


@dataclass(frozen=True, slots=True)
class ProviderAccess:
    """Local policy and probe state required before selecting a provider."""

    provider: str
    enabled: bool
    available: bool
    consented: bool
    managed_allowed: bool = True
    failure_category: str | None = None

    def __post_init__(self) -> None:
        if self.provider not in PROVIDERS:
            raise InvalidInputError(f"Unknown provider: {self.provider}")
        if self.failure_category is not None and (
            not self.failure_category or _CONTROL_RE.search(self.failure_category)
        ):
            raise InvalidInputError("Provider failure category is invalid")

    @property
    def usable(self) -> bool:
        return (
            self.enabled
            and self.available
            and self.consented
            and self.managed_allowed
        )

    @classmethod
    def from_probe(
        cls,
        probe: ProviderProbe,
        *,
        enabled: bool,
        consented: bool,
        managed_allowed: bool = True,
    ) -> "ProviderAccess":
        return cls(
            provider=probe.provider,
            enabled=enabled,
            available=probe.available and probe.authenticated,
            consented=consented,
            managed_allowed=managed_allowed,
            failure_category=probe.failure_category,
        )


@dataclass(frozen=True, slots=True)
class FallbackRecord:
    original_lane: str
    failure_category: str
    replacement_lane: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "originalLane": self.original_lane,
            "failureCategory": self.failure_category,
            "replacementLane": self.replacement_lane,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class RoutingRequest:
    strategy: Strategy
    budget: Budget
    risk: Risk
    task_class: str
    oracle_strong: bool = False
    fallback_allowed: bool = True
    author_family: str | None = None
    review_calls: Mapping[str, int] | None = None

    def __post_init__(self) -> None:
        if not self.task_class or _CONTROL_RE.search(self.task_class):
            raise InvalidInputError("Task class must be non-empty and contain no controls")
        if self.author_family not in (None, "unknown", "claude", "codex", "grok"):
            raise InvalidInputError("Unknown author family")
        if self.review_calls is not None:
            for provider, count in self.review_calls.items():
                if provider not in PROVIDERS or isinstance(count, bool) or count < 0:
                    raise InvalidInputError("Invalid per-provider review call count")


@dataclass(frozen=True, slots=True)
class RoutingDecision:
    strategy: Strategy
    implementation_lanes: tuple[str, ...]
    review_lanes: tuple[str, ...]
    plan_critique_lanes: tuple[str, ...]
    commitment_advisor: bool
    maximum_invocations: int
    fallback: FallbackRecord | None
    reason: str
    author_family: str

    @property
    def is_race(self) -> bool:
        return len(self.implementation_lanes) == 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "implementationLanes": list(self.implementation_lanes),
            "reviewLanes": list(self.review_lanes),
            "planCritiqueLanes": list(self.plan_critique_lanes),
            "commitmentAdvisor": self.commitment_advisor,
            "maximumInvocations": self.maximum_invocations,
            "fallback": self.fallback.to_dict() if self.fallback else None,
            "reason": self.reason,
            "authorFamily": self.author_family,
        }


class InvocationBudget:
    """Fail-before-exceeding counter for all provider invocation categories."""

    def __init__(self, budget: Budget, *, used: int = 0) -> None:
        if isinstance(used, bool) or not isinstance(used, int) or used < 0:
            raise InvalidInputError("Used invocation count must be a non-negative integer")
        self.profile = Budget(budget)
        self.maximum = BUDGET_LIMITS[self.profile]
        if used > self.maximum:
            raise StateInconsistencyError("Recorded invocations exceed the budget profile")
        self.used = used
        self.categories: list[str] = []

    @property
    def remaining(self) -> int:
        return self.maximum - self.used

    def can_consume(self, count: int = 1) -> bool:
        return (
            not isinstance(count, bool)
            and isinstance(count, int)
            and count >= 0
            and self.used + count <= self.maximum
        )

    def consume(self, category: str, count: int = 1) -> int:
        if category not in {"implementation", "correction", "critique", "review"}:
            raise InvalidInputError(f"Unknown invocation category: {category}")
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            raise InvalidInputError("Invocation count must be a positive integer")
        if not self.can_consume(count):
            raise PreconditionError(
                "Provider invocation budget would be exceeded",
                details={
                    "profile": self.profile.value,
                    "maximum": self.maximum,
                    "used": self.used,
                    "requested": count,
                },
            )
        self.used += count
        self.categories.extend([category] * count)
        return self.remaining


def _access_map(access: Mapping[str, ProviderAccess] | Iterable[ProviderAccess]) -> dict[str, ProviderAccess]:
    values = dict(access) if isinstance(access, Mapping) else {
        item.provider: item for item in access
    }
    if set(values) != set(PROVIDERS):
        raise InvalidInputError("Routing requires exact codex and grok access records")
    for name, item in values.items():
        if not isinstance(item, ProviderAccess) or item.provider != name:
            raise InvalidInputError(f"Provider access record disagrees with key: {name}")
    return values


def _require_explicit_provider(provider: str, access: ProviderAccess) -> None:
    if not access.enabled or not access.available:
        raise ProviderUnavailableError(
            f"Explicit provider is unavailable: {provider}",
            details={
                "provider": provider,
                "failureCategory": access.failure_category or "unavailable",
            },
        )
    if not access.consented:
        raise PolicyError(f"Provider consent is missing: {provider}")
    if not access.managed_allowed:
        raise PolicyError(f"Provider is blocked by managed policy: {provider}")


def _reviewer(
    primary: str,
    access: Mapping[str, ProviderAccess],
    review_calls: Mapping[str, int],
) -> tuple[str, ...]:
    candidates = [
        provider
        for provider in PROVIDERS
        if provider != primary and access[provider].usable
    ]
    return tuple(sorted(candidates, key=lambda name: (review_calls.get(name, 0), name))[:1])


def select_review_provider(
    *,
    author_family: str,
    access: Mapping[str, ProviderAccess] | Iterable[ProviderAccess],
    review_calls: Mapping[str, int] | None = None,
) -> str:
    """Select an actually external reviewer, or least-used when author is unknown."""

    providers = _access_map(access)
    if author_family not in {"unknown", "claude", "codex", "grok"}:
        raise InvalidInputError("Unknown author family")
    candidates = [name for name in PROVIDERS if providers[name].usable]
    if author_family in PROVIDERS:
        candidates = [name for name in candidates if name != author_family]
    if not candidates:
        raise ProviderUnavailableError("No independent review provider is available")
    counts = dict(review_calls or {})
    return min(candidates, key=lambda name: (counts.get(name, 0), name))


def create_fallback(
    *,
    original_lane: str,
    replacement_lane: str,
    access: ProviderAccess,
) -> FallbackRecord:
    category = access.failure_category or (
        "disabled" if not access.enabled else "unavailable"
    )
    return FallbackRecord(
        original_lane=original_lane,
        failure_category=category,
        replacement_lane=replacement_lane,
        reason=f"{original_lane} could not be used; auto routing selected {replacement_lane}",
    )


def route_task(
    request: RoutingRequest,
    *,
    access: Mapping[str, ProviderAccess] | Iterable[ProviderAccess],
    routing_config: RoutingConfig,
    promotion: "PromotionDecision | None" = None,
) -> RoutingDecision:
    """Resolve implementation and independent evidence lanes deterministically."""

    providers = _access_map(access)
    review_calls = dict(request.review_calls or {})
    maximum = BUDGET_LIMITS[request.budget]
    usable = tuple(name for name in PROVIDERS if providers[name].usable)
    author = request.author_family or "unknown"

    if request.strategy is not Strategy.AUTO:
        if request.strategy is Strategy.RACE:
            if request.budget is Budget.LEAN:
                raise PreconditionError("Lean budget does not permit provider races")
            _require_explicit_provider("codex", providers["codex"])
            _require_explicit_provider("grok", providers["grok"])
            implementation = PROVIDERS
            reason = "explicit race strategy"
        else:
            selected = request.strategy.value
            _require_explicit_provider(selected, providers[selected])
            implementation = (selected,)
            reason = f"explicit {selected} strategy"
        fallback = None
    else:
        if not usable:
            raise ProviderUnavailableError("No usable implementation provider is available")

        promoted = bool(promotion and promotion.promote_grok)
        mechanical = request.task_class in routing_config.grok_preferred_classes
        preferred = "grok" if promoted or mechanical else "codex"
        fallback = None
        if providers[preferred].usable:
            primary = preferred
            selection_reason = None
        else:
            replacement = "grok" if preferred == "codex" else "codex"
            if not providers[replacement].usable:
                raise ProviderUnavailableError("No usable implementation provider is available")
            if providers[preferred].available and (
                not providers[preferred].consented
                or not providers[preferred].managed_allowed
                or not providers[preferred].enabled
            ):
                # Policy exclusions are not availability fallbacks; auto simply
                # selects from the providers it is allowed to use.
                primary = replacement
                selection_reason = (
                    f"auto selected {replacement}; {preferred} is excluded by local policy"
                )
            elif request.fallback_allowed:
                primary = replacement
                fallback = create_fallback(
                    original_lane=preferred,
                    replacement_lane=replacement,
                    access=providers[preferred],
                )
                selection_reason = fallback.reason
            else:
                raise ProviderUnavailableError(
                    f"Preferred provider is unavailable and fallback is disabled: {preferred}"
                )

        race_allowed = (
            request.budget is not Budget.LEAN
            and request.oracle_strong
            and len(usable) == 2
            and (
                request.risk is Risk.HIGH
                or request.budget is Budget.QUALITY
                and request.risk is Risk.MEDIUM
            )
        )
        implementation = PROVIDERS if race_allowed else (primary,)
        if race_allowed:
            reason = "auto race: risk, budget, and objective oracle permit comparison"
        elif selection_reason is not None:
            reason = selection_reason
        elif promoted:
            reason = "auto provider statistics promoted Grok for this task class and risk"
        elif mechanical:
            reason = "auto mechanical task-class preference selected Grok"
        else:
            reason = "auto Codex cold-start default"

    primary = implementation[0]
    # Kept in the serialized decision for schema compatibility. Release 0.1.0
    # performs plan critique locally and has no executable external plan lane.
    plan_critiques: tuple[str, ...] = ()
    commitment = request.risk is Risk.HIGH

    if len(implementation) > 1:
        reviews: tuple[str, ...] = ()
    elif request.budget is Budget.LEAN:
        reviews = (
            _reviewer(primary, providers, review_calls)
            if request.risk is Risk.HIGH
            else ()
        )
    elif request.risk in {Risk.MEDIUM, Risk.HIGH}:
        reviews = _reviewer(primary, providers, review_calls)
    else:
        reviews = ()

    return RoutingDecision(
        strategy=request.strategy,
        implementation_lanes=tuple(implementation),
        review_lanes=tuple(reviews),
        plan_critique_lanes=tuple(plan_critiques),
        commitment_advisor=commitment,
        maximum_invocations=maximum,
        fallback=fallback,
        reason=reason,
        author_family=author,
    )


@dataclass(frozen=True, slots=True)
class ProviderObservation:
    observation_id: str
    run_id: str
    task_id: str
    provider: str
    task_class: str
    risk: Risk
    eligible: bool
    first_pass_gate_passed: bool
    blocking_review_finding_count: int
    duration_ms: int
    correction_rounds: int
    selected: bool
    gate_command_fingerprint: str
    repository_identity: str
    crossforge_schema_major: int
    recorded_at: str

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        task_id: str,
        provider: str,
        task_class: str,
        risk: Risk,
        eligible: bool,
        first_pass_gate_passed: bool,
        blocking_review_finding_count: int,
        duration_ms: int,
        correction_rounds: int,
        selected: bool,
        gate_command_fingerprint: str,
        repository_identity: str,
        crossforge_schema_major: int = 1,
        recorded_at: str | None = None,
    ) -> "ProviderObservation":
        observation = cls(
            observation_id=secrets.token_hex(16),
            run_id=run_id,
            task_id=task_id,
            provider=provider,
            task_class=task_class,
            risk=Risk(risk),
            eligible=eligible,
            first_pass_gate_passed=first_pass_gate_passed,
            blocking_review_finding_count=blocking_review_finding_count,
            duration_ms=duration_ms,
            correction_rounds=correction_rounds,
            selected=selected,
            gate_command_fingerprint=gate_command_fingerprint,
            repository_identity=repository_identity,
            crossforge_schema_major=crossforge_schema_major,
            recorded_at=recorded_at or utc_now(),
        )
        observation.validate()
        return observation

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProviderObservation":
        if set(value) != _OBSERVATION_FIELDS:
            raise StateInconsistencyError(
                "Provider observation has missing or unknown fields",
                details={
                    "missing": sorted(_OBSERVATION_FIELDS - set(value)),
                    "unknown": sorted(set(value) - _OBSERVATION_FIELDS),
                },
            )
        try:
            observation = cls(
                observation_id=value["observationId"],
                run_id=value["runId"],
                task_id=value["taskId"],
                provider=value["provider"],
                task_class=value["taskClass"],
                risk=Risk(value["risk"]),
                eligible=value["eligible"],
                first_pass_gate_passed=value["firstPassGatePassed"],
                blocking_review_finding_count=value["blockingReviewFindingCount"],
                duration_ms=value["durationMs"],
                correction_rounds=value["correctionRounds"],
                selected=value["selected"],
                gate_command_fingerprint=value["gateCommandFingerprint"],
                repository_identity=value["repositoryIdentity"],
                crossforge_schema_major=value["crossforgeSchemaMajor"],
                recorded_at=value["recordedAt"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise StateInconsistencyError("Provider observation has invalid values") from error
        observation.validate(state=True)
        return observation

    def validate(self, *, state: bool = False) -> None:
        error_type = StateInconsistencyError if state else InvalidInputError
        if (
            not isinstance(self.observation_id, str)
            or len(self.observation_id) < 16
            or not _HEX_RE.fullmatch(self.observation_id)
        ):
            raise error_type("Invalid provider observation ID")
        if not isinstance(self.run_id, str) or not _RUN_ID_RE.fullmatch(self.run_id):
            raise error_type("Invalid observation run ID")
        if not isinstance(self.task_id, str) or not _TASK_ID_RE.fullmatch(self.task_id):
            raise error_type("Invalid observation task ID")
        if self.provider not in PROVIDERS:
            raise error_type("Invalid observation provider")
        if (
            not isinstance(self.task_class, str)
            or not self.task_class
            or _CONTROL_RE.search(self.task_class)
        ):
            raise error_type("Invalid observation task class")
        for value, label in (
            (self.eligible, "eligible"),
            (self.first_pass_gate_passed, "firstPassGatePassed"),
            (self.selected, "selected"),
        ):
            if type(value) is not bool:
                raise error_type(f"Observation {label} must be boolean")
        for value, label in (
            (self.blocking_review_finding_count, "blockingReviewFindingCount"),
            (self.duration_ms, "durationMs"),
            (self.correction_rounds, "correctionRounds"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise error_type(f"Observation {label} must be a non-negative integer")
        if (
            self.first_pass_gate_passed
            and (not self.eligible or self.correction_rounds != 0)
        ):
            raise error_type(
                "First-pass success requires an eligible zero-correction observation"
            )
        if self.selected and not self.eligible:
            raise error_type("An ineligible provider observation cannot be selected")
        if not _SHA256_RE.fullmatch(self.gate_command_fingerprint):
            raise error_type("Invalid gate-command fingerprint")
        if not _SHA256_RE.fullmatch(self.repository_identity):
            raise error_type("Invalid repository identity")
        if (
            isinstance(self.crossforge_schema_major, bool)
            or not isinstance(self.crossforge_schema_major, int)
            or self.crossforge_schema_major <= 0
        ):
            raise error_type("Invalid Crossforge schema major version")
        try:
            parsed_at = datetime.fromisoformat(self.recorded_at.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as error:
            raise error_type("Invalid observation recordedAt timestamp") from error
        if (
            not self.recorded_at.endswith("Z")
            or parsed_at.tzinfo is None
            or parsed_at.utcoffset() != timezone.utc.utcoffset(parsed_at)
        ):
            raise error_type("Observation recordedAt must be RFC3339 UTC")

    def to_dict(self) -> dict[str, Any]:
        return {
            "observationId": self.observation_id,
            "runId": self.run_id,
            "taskId": self.task_id,
            "provider": self.provider,
            "taskClass": self.task_class,
            "risk": self.risk.value,
            "eligible": self.eligible,
            "firstPassGatePassed": self.first_pass_gate_passed,
            "blockingReviewFindingCount": self.blocking_review_finding_count,
            "durationMs": self.duration_ms,
            "correctionRounds": self.correction_rounds,
            "selected": self.selected,
            "gateCommandFingerprint": self.gate_command_fingerprint,
            "repositoryIdentity": self.repository_identity,
            "crossforgeSchemaMajor": self.crossforge_schema_major,
            "recordedAt": self.recorded_at,
        }


def observation_from_invocation(
    invocation: Any,
    **fields: Any,
) -> ProviderObservation:
    """Create statistics from T6's invocation result without trusting its prose."""

    status = invocation.status
    eligible = status is ProviderStatus.COMPLETE and bool(fields.pop("eligible", True))
    first_pass = eligible and int(fields.get("correction_rounds", 0)) == 0 and bool(
        fields.pop("gate_passed", False)
    )
    return ProviderObservation.create(
        provider=invocation.provider,
        duration_ms=invocation.duration_ms,
        eligible=eligible,
        first_pass_gate_passed=first_pass,
        **fields,
    )


class ProviderStatisticsStore:
    """Strict append-oriented logical store backed by one atomic JSON file."""

    def __init__(self, path: str | Path, *, lock_timeout: float = 0) -> None:
        self.path = Path(path).expanduser().resolve()
        self.lock_timeout = lock_timeout

    def load(self) -> tuple[ProviderObservation, ...]:
        if not self.path.exists():
            return ()
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StateInconsistencyError("Provider statistics file is invalid") from error
        if not isinstance(value, dict) or set(value) != {"schemaVersion", "observations"}:
            raise StateInconsistencyError("Provider statistics schema is invalid")
        if value["schemaVersion"] != STATISTICS_SCHEMA_VERSION or not isinstance(
            value["observations"], list
        ):
            raise StateInconsistencyError("Provider statistics schema is invalid")
        observations = tuple(
            ProviderObservation.from_dict(item)
            if isinstance(item, Mapping)
            else _raise_bad_observation()
            for item in value["observations"]
        )
        identifiers = [item.observation_id for item in observations]
        if len(identifiers) != len(set(identifiers)):
            raise StateInconsistencyError("Provider statistics contain duplicate IDs")
        return observations

    def append(self, observation: ProviderObservation) -> tuple[ProviderObservation, ...]:
        observation.validate()
        state_root = ensure_private_directory(self.path.parent)
        with repository_lock(state_root, timeout=self.lock_timeout):
            observations = list(self.load())
            existing = [
                item
                for item in observations
                if item.observation_id == observation.observation_id
            ]
            if existing:
                if existing[0] == observation:
                    return tuple(observations)
                raise StateInconsistencyError(
                    "Provider observation ID already exists with different data"
                )
            observations.append(observation)
            atomic_write_json(
                self.path,
                {
                    "schemaVersion": STATISTICS_SCHEMA_VERSION,
                    "observations": [item.to_dict() for item in observations],
                },
            )
        return tuple(observations)


def _raise_bad_observation() -> ProviderObservation:
    raise StateInconsistencyError("Provider observation must be an object")


@dataclass(frozen=True, slots=True)
class ProviderMetrics:
    provider: str
    sample_count: int
    eligible_count: int
    first_pass_rate: float
    blocking_review_rate: float
    median_duration_ms: float
    median_correction_rounds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "sampleCount": self.sample_count,
            "eligibleCount": self.eligible_count,
            "firstPassRate": self.first_pass_rate,
            "blockingReviewRate": self.blocking_review_rate,
            "medianDurationMs": self.median_duration_ms,
            "medianCorrectionRounds": self.median_correction_rounds,
        }


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    promote_grok: bool
    selected_provider: str
    reason: str
    codex: ProviderMetrics | None
    grok: ProviderMetrics | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "promoteGrok": self.promote_grok,
            "selectedProvider": self.selected_provider,
            "reason": self.reason,
            "codex": self.codex.to_dict() if self.codex else None,
            "grok": self.grok.to_dict() if self.grok else None,
        }


def _metrics(provider: str, observations: Sequence[ProviderObservation]) -> ProviderMetrics:
    eligible = [item for item in observations if item.eligible]
    if not observations or not eligible:
        raise ValueError("metrics require attempts and at least one eligible observation")
    return ProviderMetrics(
        provider=provider,
        sample_count=len(observations),
        eligible_count=len(eligible),
        first_pass_rate=sum(item.first_pass_gate_passed for item in observations)
        / len(observations),
        blocking_review_rate=sum(item.blocking_review_finding_count for item in eligible)
        / len(eligible),
        median_duration_ms=float(statistics.median(item.duration_ms for item in eligible)),
        median_correction_rounds=float(
            statistics.median(item.correction_rounds for item in eligible)
        ),
    )


def promotion_decision(
    observations: Iterable[ProviderObservation],
    *,
    task_class: str,
    risk: Risk,
    gate_command_fingerprint: str,
    repository_identity: str,
    crossforge_schema_major: int = 1,
    minimum_evidence_tasks: int = MINIMUM_PROMOTION_SAMPLES,
) -> PromotionDecision:
    """Evaluate exact within-cohort Grok promotion thresholds."""

    if not task_class or _CONTROL_RE.search(task_class):
        raise InvalidInputError("Task class is invalid")
    if not _SHA256_RE.fullmatch(gate_command_fingerprint):
        raise InvalidInputError("Gate-command fingerprint is invalid")
    if not _SHA256_RE.fullmatch(repository_identity):
        raise InvalidInputError("Repository identity is invalid")
    if (
        isinstance(minimum_evidence_tasks, bool)
        or not isinstance(minimum_evidence_tasks, int)
        or minimum_evidence_tasks < 0
    ):
        raise InvalidInputError("Minimum evidence tasks must be non-negative")
    minimum = max(MINIMUM_PROMOTION_SAMPLES, minimum_evidence_tasks)

    cohort = [
        item
        for item in observations
        if item.task_class == task_class
        and item.risk is Risk(risk)
        and item.gate_command_fingerprint == gate_command_fingerprint
        and item.repository_identity == repository_identity
        and item.crossforge_schema_major == crossforge_schema_major
    ]
    by_provider: dict[str, list[ProviderObservation]] = {name: [] for name in PROVIDERS}
    for item in cohort:
        by_provider[item.provider].append(item)
    for provider in PROVIDERS:
        by_provider[provider] = sorted(
            by_provider[provider],
            key=lambda item: (
                datetime.fromisoformat(item.recorded_at.replace("Z", "+00:00")),
                item.observation_id,
            ),
            reverse=True,
        )[:MAX_COMPARISON_WINDOW]

    if any(len(by_provider[name]) < minimum for name in PROVIDERS):
        return PromotionDecision(
            False,
            "codex",
            f"cold start: fewer than {minimum} comparable observations per provider",
            None,
            None,
        )
    if any(not any(item.eligible for item in by_provider[name]) for name in PROVIDERS):
        return PromotionDecision(
            False,
            "codex",
            "cold start: a provider has no eligible comparable observations",
            None,
            None,
        )

    codex = _metrics("codex", by_provider["codex"])
    grok = _metrics("grok", by_provider["grok"])
    checks = {
        "first-pass success": grok.first_pass_rate + 1e-12
        >= codex.first_pass_rate - 0.03,
        "blocking review findings": grok.blocking_review_rate
        <= codex.blocking_review_rate,
        "duration": grok.median_duration_ms <= codex.median_duration_ms * 0.85,
        "correction rounds": grok.median_correction_rounds
        <= codex.median_correction_rounds,
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        return PromotionDecision(
            False,
            "codex",
            "Grok promotion thresholds failed: " + ", ".join(failed),
            codex,
            grok,
        )
    return PromotionDecision(
        True,
        "grok",
        "Grok met every comparable promotion threshold",
        codex,
        grok,
    )
