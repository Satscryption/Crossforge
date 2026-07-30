"""Routing, budget, fallback, and adaptive provider-statistics tests."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "crossforge" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.errors import (
    InvalidInputError,
    PolicyError,
    PreconditionError,
    ProviderUnavailableError,
    StateInconsistencyError,
)
from crossforge_lib.models import Budget, Risk, RoutingConfig, Strategy
from crossforge_lib.routing import (
    BUDGET_LIMITS,
    FallbackRecord,
    InvocationBudget,
    ProviderAccess,
    ProviderObservation,
    ProviderStatisticsStore,
    RoutingRequest,
    promotion_decision,
    route_task,
    select_review_provider,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
ROUTING = RoutingConfig(
    minimum_evidence_tasks=10,
    grok_preferred_classes=(
        "boilerplate",
        "fixtures",
        "repetitive-wiring",
        "crud",
        "straightforward-ui",
    ),
)


def all_access(**changes: object) -> dict[str, ProviderAccess]:
    result = {
        name: ProviderAccess(name, True, True, True)
        for name in ("codex", "grok")
    }
    for provider, value in changes.items():
        result[provider] = value  # type: ignore[assignment]
    return result


class ExplicitRoutingTests(unittest.TestCase):
    def test_explicit_provider_overrides_preferences_and_statistics(self) -> None:
        decision = route_task(
            RoutingRequest(
                strategy=Strategy.CODEX,
                budget=Budget.BALANCED,
                risk=Risk.LOW,
                task_class="fixtures",
            ),
            access=all_access(),
            routing_config=ROUTING,
        )
        self.assertEqual(("codex",), decision.implementation_lanes)
        self.assertIsNone(decision.fallback)

    def test_explicit_provider_requires_availability_consent_and_policy(self) -> None:
        with self.assertRaises(ProviderUnavailableError):
            route_task(
                RoutingRequest(Strategy.GROK, Budget.BALANCED, Risk.LOW, "feature"),
                access=all_access(
                    grok=ProviderAccess("grok", True, False, True, failure_category="auth")
                ),
                routing_config=ROUTING,
            )
        with self.assertRaises(PolicyError):
            route_task(
                RoutingRequest(Strategy.GROK, Budget.BALANCED, Risk.LOW, "feature"),
                access=all_access(
                    grok=ProviderAccess("grok", True, True, False)
                ),
                routing_config=ROUTING,
            )

    def test_explicit_race_requires_both_and_is_forbidden_in_lean(self) -> None:
        with self.assertRaises(PreconditionError):
            route_task(
                RoutingRequest(Strategy.RACE, Budget.LEAN, Risk.HIGH, "security"),
                access=all_access(),
                routing_config=ROUTING,
            )
        decision = route_task(
            RoutingRequest(Strategy.RACE, Budget.QUALITY, Risk.HIGH, "security"),
            access=all_access(),
            routing_config=ROUTING,
        )
        self.assertEqual(("codex", "grok"), decision.implementation_lanes)


class AutomaticRoutingTests(unittest.TestCase):
    def test_codex_cold_start_and_grok_mechanical_preference(self) -> None:
        codex = route_task(
            RoutingRequest(Strategy.AUTO, Budget.BALANCED, Risk.LOW, "feature"),
            access=all_access(),
            routing_config=ROUTING,
        )
        grok = route_task(
            RoutingRequest(Strategy.AUTO, Budget.BALANCED, Risk.LOW, "fixtures"),
            access=all_access(),
            routing_config=ROUTING,
        )
        self.assertEqual(("codex",), codex.implementation_lanes)
        self.assertIn("cold-start", codex.reason)
        self.assertEqual(("grok",), grok.implementation_lanes)
        self.assertIn("mechanical", grok.reason)

    def test_medium_balanced_has_different_family_review(self) -> None:
        decision = route_task(
            RoutingRequest(Strategy.AUTO, Budget.BALANCED, Risk.MEDIUM, "feature"),
            access=all_access(),
            routing_config=ROUTING,
        )
        self.assertEqual(("codex",), decision.implementation_lanes)
        self.assertEqual(("grok",), decision.review_lanes)

    def test_quality_medium_and_balanced_high_race_only_with_oracle(self) -> None:
        medium = route_task(
            RoutingRequest(
                Strategy.AUTO,
                Budget.QUALITY,
                Risk.MEDIUM,
                "feature",
                oracle_strong=True,
            ),
            access=all_access(),
            routing_config=ROUTING,
        )
        high_without_oracle = route_task(
            RoutingRequest(
                Strategy.AUTO,
                Budget.BALANCED,
                Risk.HIGH,
                "security",
                oracle_strong=False,
            ),
            access=all_access(),
            routing_config=ROUTING,
        )
        high_with_oracle = route_task(
            RoutingRequest(
                Strategy.AUTO,
                Budget.BALANCED,
                Risk.HIGH,
                "security",
                oracle_strong=True,
            ),
            access=all_access(),
            routing_config=ROUTING,
        )
        self.assertTrue(medium.is_race)
        self.assertFalse(high_without_oracle.is_race)
        self.assertTrue(high_with_oracle.is_race)
        self.assertTrue(high_with_oracle.commitment_advisor)
        self.assertEqual((), high_with_oracle.plan_critique_lanes)

    def test_lean_never_races_and_reviews_only_high_risk(self) -> None:
        medium = route_task(
            RoutingRequest(
                Strategy.AUTO, Budget.LEAN, Risk.MEDIUM, "feature", oracle_strong=True
            ),
            access=all_access(),
            routing_config=ROUTING,
        )
        high = route_task(
            RoutingRequest(
                Strategy.AUTO, Budget.LEAN, Risk.HIGH, "security", oracle_strong=True
            ),
            access=all_access(),
            routing_config=ROUTING,
        )
        self.assertFalse(medium.is_race)
        self.assertEqual((), medium.review_lanes)
        self.assertFalse(high.is_race)
        self.assertEqual(("grok",), high.review_lanes)
        self.assertLessEqual(
            len(high.implementation_lanes)
            + len(high.review_lanes),
            high.maximum_invocations,
        )

    def test_release_never_routes_external_plan_critiques(self) -> None:
        for budget in Budget:
            for risk in Risk:
                with self.subTest(budget=budget, risk=risk):
                    decision = route_task(
                        RoutingRequest(
                            Strategy.AUTO,
                            budget,
                            risk,
                            "security",
                            oracle_strong=True,
                        ),
                        access=all_access(),
                        routing_config=ROUTING,
                    )
                    self.assertEqual((), decision.plan_critique_lanes)

    def test_unknown_author_uses_least_used_available_reviewer(self) -> None:
        selected = select_review_provider(
            author_family="unknown",
            access=all_access(),
            review_calls={"codex": 4, "grok": 1},
        )
        self.assertEqual("grok", selected)
        selected = select_review_provider(
            author_family="codex",
            access=all_access(),
            review_calls={"codex": 0, "grok": 9},
        )
        self.assertEqual("grok", selected)


class FallbackTests(unittest.TestCase):
    def test_auto_unavailable_provider_records_fallback(self) -> None:
        decision = route_task(
            RoutingRequest(Strategy.AUTO, Budget.BALANCED, Risk.LOW, "feature"),
            access=all_access(
                codex=ProviderAccess(
                    "codex", True, False, True, failure_category="authentication"
                )
            ),
            routing_config=ROUTING,
        )
        self.assertEqual(("grok",), decision.implementation_lanes)
        self.assertEqual(
            FallbackRecord(
                original_lane="codex",
                failure_category="authentication",
                replacement_lane="grok",
                reason="codex could not be used; auto routing selected grok",
            ),
            decision.fallback,
        )

    def test_auto_fallback_can_be_disabled_and_explicit_never_falls_back(self) -> None:
        unavailable = ProviderAccess("codex", True, False, True)
        with self.assertRaises(ProviderUnavailableError):
            route_task(
                RoutingRequest(
                    Strategy.AUTO,
                    Budget.BALANCED,
                    Risk.LOW,
                    "feature",
                    fallback_allowed=False,
                ),
                access=all_access(codex=unavailable),
                routing_config=ROUTING,
            )
        with self.assertRaises(ProviderUnavailableError):
            route_task(
                RoutingRequest(Strategy.CODEX, Budget.BALANCED, Risk.LOW, "feature"),
                access=all_access(codex=unavailable),
                routing_config=ROUTING,
            )


class InvocationBudgetTests(unittest.TestCase):
    def test_exact_profile_limits_and_fail_before_exceeding(self) -> None:
        for profile, expected in BUDGET_LIMITS.items():
            with self.subTest(profile=profile):
                budget = InvocationBudget(profile)
                self.assertEqual(expected, budget.maximum)
                budget.consume("implementation", expected)
                self.assertEqual(0, budget.remaining)
                with self.assertRaises(PreconditionError):
                    budget.consume("review")
                self.assertEqual(expected, budget.used)

    def test_corrections_critiques_and_reviews_all_count(self) -> None:
        budget = InvocationBudget(Budget.LEAN)
        for category in ("implementation", "correction", "critique", "review"):
            budget.consume(category)
        self.assertEqual(0, budget.remaining)
        self.assertEqual(
            ["implementation", "correction", "critique", "review"],
            budget.categories,
        )


def observation(
    provider: str,
    index: int,
    *,
    success: bool = True,
    eligible: bool = True,
    duration: int | None = None,
    findings: int = 0,
    corrections: int = 0,
    task_class: str = "feature",
    risk: Risk = Risk.LOW,
    gate: str = SHA_A,
    repository: str = SHA_B,
) -> ProviderObservation:
    moment = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=index)
    return ProviderObservation.create(
        run_id=f"20260101T000000Z-{index:08x}",
        task_id=f"T{index + 1}",
        provider=provider,
        task_class=task_class,
        risk=risk,
        eligible=eligible,
        first_pass_gate_passed=success,
        blocking_review_finding_count=findings,
        duration_ms=duration if duration is not None else (
            1000 if provider == "codex" else 800
        ),
        correction_rounds=corrections,
        selected=provider == "grok" and eligible,
        gate_command_fingerprint=gate,
        repository_identity=repository,
        recorded_at=moment.isoformat().replace("+00:00", "Z"),
    )


class StatisticsTests(unittest.TestCase):
    def test_atomic_append_round_trip_and_owner_only_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state" / "provider-stats.json"
            store = ProviderStatisticsStore(path)
            item = observation("codex", 0)
            self.assertEqual((item,), store.append(item))
            self.assertEqual((item,), store.load())
            self.assertEqual(0, path.stat().st_mode & 0o077)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(1, payload["schemaVersion"])
            self.assertEqual(item.observation_id, payload["observations"][0]["observationId"])

    def test_unknown_fields_duplicates_and_invalid_attempts_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "provider-stats.json"
            item = observation("codex", 0)
            value = {"schemaVersion": 1, "observations": [item.to_dict()]}
            value["observations"][0]["unknown"] = True
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(StateInconsistencyError):
                ProviderStatisticsStore(path).load()
        with self.assertRaises(InvalidInputError):
            replace(observation("codex", 0), duration_ms=-1).validate()

    def test_cold_start_requires_at_least_ten_each(self) -> None:
        items = [observation("codex", index) for index in range(10)]
        items += [observation("grok", 20 + index) for index in range(9)]
        result = promotion_decision(
            items,
            task_class="feature",
            risk=Risk.LOW,
            gate_command_fingerprint=SHA_A,
            repository_identity=SHA_B,
        )
        self.assertFalse(result.promote_grok)
        self.assertEqual("codex", result.selected_provider)
        self.assertIn("cold start", result.reason)

    def test_exact_promotion_thresholds(self) -> None:
        items = [observation("codex", index, duration=1000) for index in range(10)]
        # Exactly three percentage points below is represented exactly with 100
        # observations, so exercise that boundary in the 50-item window as a
        # separate assertion below.  Ten perfect attempts exercise all other
        # threshold equalities, including exactly 15% faster.
        items += [
            observation("grok", 20 + index, duration=850)
            for index in range(10)
        ]
        result = promotion_decision(
            items,
            task_class="feature",
            risk=Risk.LOW,
            gate_command_fingerprint=SHA_A,
            repository_identity=SHA_B,
        )
        self.assertTrue(result.promote_grok)
        self.assertEqual("grok", result.selected_provider)

        too_slow = [
            replace(item, duration_ms=851) if item.provider == "grok" else item
            for item in items
        ]
        result = promotion_decision(
            too_slow,
            task_class="feature",
            risk=Risk.LOW,
            gate_command_fingerprint=SHA_A,
            repository_identity=SHA_B,
        )
        self.assertFalse(result.promote_grok)
        self.assertIn("duration", result.reason)

    def test_failures_remain_samples_and_count_against_first_pass(self) -> None:
        items = [observation("codex", index) for index in range(10)]
        items += [
            observation(
                "grok",
                20 + index,
                eligible=index != 0,
                success=index != 0,
            )
            for index in range(10)
        ]
        result = promotion_decision(
            items,
            task_class="feature",
            risk=Risk.LOW,
            gate_command_fingerprint=SHA_A,
            repository_identity=SHA_B,
        )
        self.assertFalse(result.promote_grok)
        self.assertAlmostEqual(0.9, result.grok.first_pass_rate if result.grok else -1)

    def test_only_exact_cohort_and_most_recent_fifty_are_compared(self) -> None:
        old_slow = [
            observation("grok", index, duration=5000) for index in range(10)
        ]
        recent_grok = [
            observation("grok", 100 + index, duration=800) for index in range(50)
        ]
        recent_codex = [
            observation("codex", 200 + index, duration=1000) for index in range(50)
        ]
        unrelated = [
            observation(
                "grok",
                300 + index,
                duration=5000,
                gate="c" * 64,
            )
            for index in range(20)
        ]
        result = promotion_decision(
            old_slow + recent_grok + recent_codex + unrelated,
            task_class="feature",
            risk=Risk.LOW,
            gate_command_fingerprint=SHA_A,
            repository_identity=SHA_B,
        )
        self.assertTrue(result.promote_grok)
        self.assertEqual(50, result.grok.sample_count if result.grok else -1)

    def test_blocking_finding_and_correction_regressions_prevent_promotion(self) -> None:
        codex = [observation("codex", index) for index in range(10)]
        grok = [
            observation(
                "grok",
                20 + index,
                findings=1 if index == 0 else 0,
                corrections=1,
                success=False,
            )
            for index in range(10)
        ]
        result = promotion_decision(
            codex + grok,
            task_class="feature",
            risk=Risk.LOW,
            gate_command_fingerprint=SHA_A,
            repository_identity=SHA_B,
        )
        self.assertFalse(result.promote_grok)
        self.assertIn("blocking review findings", result.reason)
        self.assertIn("correction rounds", result.reason)


if __name__ == "__main__":
    unittest.main()
