"""Repository-scoped consent records for provider operations.

Consent is an explicit, expiring approval of a provider, operation class, and
the exact transmission policies in force.  Provider discovery or availability
must never be interpreted as consent.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .errors import ConsentError
from .util import atomic_write_json

SCHEMA_VERSION = 2
CONSENT_REQUEST_SCHEMA_VERSION = 1
CONSENT_REQUEST_PRODUCER = "crossforge-consent-request/v1"
CONSENT_REQUEST_LIFETIME = timedelta(minutes=15)
VALID_OPERATION_CLASSES = frozenset({"probe", "plan", "review", "implement"})
NO_MANAGED_POLICY = "no-managed-policy"


@dataclass(frozen=True, slots=True)
class ConsentCheck:
    """Machine-friendly result of a consent check."""

    approved: bool
    reason: str

    def __bool__(self) -> bool:
        return self.approved


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ConsentError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return _as_utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ConsentError(f"{field} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConsentError(f"{field} must be an RFC3339 timestamp") from exc
    return _as_utc(parsed)


def _require_sha256(value: object, field: str, *, allow_literal: bool = False) -> str:
    if allow_literal and value == NO_MANAGED_POLICY:
        return str(value)
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ConsentError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def _require_nullable_sha256(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field)


def _require_nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConsentError(f"{field} must be a non-empty string")
    return value


def _require_absolute_path(
    value: object,
    field: str,
    *,
    nullable: bool = False,
) -> str | None:
    if nullable and value is None:
        return None
    raw = _require_nonempty_string(value, field)
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise ConsentError(f"{field} must be an absolute path")
    return str(path.resolve())


def canonical_json_sha256(value: object) -> str:
    """Hash JSON-compatible data using a stable UTF-8 representation."""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def managed_policy_hash(policy: object | None = None) -> str:
    """Return the hash used to bind consent to organization-managed policy."""

    if policy is None:
        return hashlib.sha256(NO_MANAGED_POLICY.encode("utf-8")).hexdigest()
    return canonical_json_sha256(policy)


def deny_policy_hash(
    deny_globs: Sequence[str],
    detectors: Sequence[str],
    unexpired_exceptions: Sequence[Mapping[str, object]],
    context_policy: Mapping[str, object],
) -> str:
    """Hash every component that controls provider-visible source context."""

    normalized_globs = sorted(dict.fromkeys(str(pattern) for pattern in deny_globs))
    normalized_detectors = sorted(dict.fromkeys(str(detector) for detector in detectors))
    normalized_exceptions = sorted(
        (dict(entry) for entry in unexpired_exceptions),
        key=lambda entry: (
            str(entry.get("path", "")),
            str(entry.get("detector", "")),
            int(entry.get("line", 0)),
            str(entry.get("sha256", "")),
            str(entry.get("expiresAt", "")),
        ),
    )
    return canonical_json_sha256(
        {
            "denyGlobs": normalized_globs,
            "detectors": normalized_detectors,
            "exceptions": normalized_exceptions,
            "providerVisibleContextPolicy": dict(context_policy),
        }
    )


def _validate_operations(operation_classes: Iterable[str]) -> list[str]:
    operations = sorted(dict.fromkeys(operation_classes))
    unknown = set(operations) - VALID_OPERATION_CLASSES
    if unknown:
        raise ConsentError(
            "unknown operation class(es): " + ", ".join(sorted(unknown))
        )
    if not operations:
        raise ConsentError("at least one operation class is required")
    return operations


def validate_consent(record: Mapping[str, object]) -> dict[str, Any]:
    """Validate and normalize an in-memory consent document."""

    if set(record) != {"schemaVersion", "repositoryIdentity", "providers"}:
        raise ConsentError("consent document has unknown or missing top-level keys")
    if record.get("schemaVersion") != SCHEMA_VERSION:
        raise ConsentError("unsupported consent schema version")
    repository_identity = _require_sha256(
        record.get("repositoryIdentity"), "repositoryIdentity"
    )
    providers = record.get("providers")
    if not isinstance(providers, Mapping):
        raise ConsentError("providers must be an object")

    normalized_providers: dict[str, dict[str, Any]] = {}
    expected_keys = {
        "approved",
        "operationClasses",
        "denyPolicySha256",
        "managedPolicySha256",
        "providerExecutablePath",
        "providerExecutableSha256",
        "approvedAt",
        "expiresAt",
    }
    for provider, raw_entry in providers.items():
        if not isinstance(provider, str) or not provider:
            raise ConsentError("provider names must be non-empty strings")
        if not isinstance(raw_entry, Mapping) or set(raw_entry) != expected_keys:
            raise ConsentError(f"invalid consent entry for provider {provider}")
        if raw_entry.get("approved") is not True:
            raise ConsentError(f"provider {provider} is not explicitly approved")
        approved_at = _parse_timestamp(raw_entry.get("approvedAt"), "approvedAt")
        expires_at = _parse_timestamp(raw_entry.get("expiresAt"), "expiresAt")
        if expires_at <= approved_at:
            raise ConsentError("expiresAt must be later than approvedAt")
        raw_operations = raw_entry.get("operationClasses")
        if not isinstance(raw_operations, list) or not all(
            isinstance(item, str) for item in raw_operations
        ):
            raise ConsentError("operationClasses must be an array of strings")
        normalized_providers[provider] = {
            "approved": True,
            "operationClasses": _validate_operations(raw_operations),
            "denyPolicySha256": _require_sha256(
                raw_entry.get("denyPolicySha256"), "denyPolicySha256"
            ),
            "managedPolicySha256": _require_sha256(
                raw_entry.get("managedPolicySha256"), "managedPolicySha256"
            ),
            "providerExecutablePath": str(
                Path(
                    _require_nonempty_string(
                        raw_entry.get("providerExecutablePath"),
                        "providerExecutablePath",
                    )
                ).expanduser().resolve()
            ),
            "providerExecutableSha256": _require_sha256(
                raw_entry.get("providerExecutableSha256"),
                "providerExecutableSha256",
            ),
            "approvedAt": _format_timestamp(approved_at),
            "expiresAt": _format_timestamp(expires_at),
        }
    return {
        "schemaVersion": SCHEMA_VERSION,
        "repositoryIdentity": repository_identity,
        "providers": normalized_providers,
    }


def load_consent(path: str | os.PathLike[str]) -> dict[str, Any] | None:
    """Load a consent document, returning ``None`` when it does not exist."""

    consent_path = Path(path)
    try:
        with consent_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise ConsentError(f"could not read consent record: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ConsentError("consent document must be a JSON object")
    return validate_consent(raw)


def validate_consent_request(record: Mapping[str, object]) -> dict[str, Any]:
    """Validate and normalize a short-lived, unapproved consent request."""

    expected_keys = {
        "schemaVersion",
        "producer",
        "requestId",
        "repositoryRoot",
        "gitCommonDir",
        "repositoryIdentity",
        "provider",
        "operationClasses",
        "denyPolicySha256",
        "managedPolicySha256",
        "providerExecutablePath",
        "providerExecutableSha256",
        "preparedAt",
        "requestedExpiresAt",
        "requestValidUntil",
        "ttlDays",
        "userConfigPath",
        "userConfigSha256",
        "projectConfigPath",
        "projectConfigSha256",
        "allowFile",
        "contextManifestPath",
        "contextManifestSha256",
        "contextFileCount",
        "contextTotalBytes",
    }
    if set(record) != expected_keys:
        raise ConsentError(
            "consent request has unknown or missing top-level keys"
        )
    if record.get("schemaVersion") != CONSENT_REQUEST_SCHEMA_VERSION:
        raise ConsentError("unsupported consent request schema version")
    if record.get("producer") != CONSENT_REQUEST_PRODUCER:
        raise ConsentError("unsupported consent request producer")
    request_id = _require_sha256(record.get("requestId"), "requestId")
    repository_root = _require_absolute_path(
        record.get("repositoryRoot"), "repositoryRoot"
    )
    git_common_dir = _require_absolute_path(
        record.get("gitCommonDir"), "gitCommonDir"
    )
    repository_identity = _require_sha256(
        record.get("repositoryIdentity"), "repositoryIdentity"
    )
    provider = _require_nonempty_string(record.get("provider"), "provider")
    raw_operations = record.get("operationClasses")
    if not isinstance(raw_operations, list) or not all(
        isinstance(item, str) for item in raw_operations
    ):
        raise ConsentError("operationClasses must be an array of strings")
    operations = _validate_operations(raw_operations)
    deny_policy_sha256 = _require_sha256(
        record.get("denyPolicySha256"), "denyPolicySha256"
    )
    managed_policy_sha256 = _require_sha256(
        record.get("managedPolicySha256"), "managedPolicySha256"
    )
    executable_path = _require_absolute_path(
        record.get("providerExecutablePath"), "providerExecutablePath"
    )
    executable_sha256 = _require_sha256(
        record.get("providerExecutableSha256"), "providerExecutableSha256"
    )
    prepared_at = _parse_timestamp(record.get("preparedAt"), "preparedAt")
    requested_expires_at = _parse_timestamp(
        record.get("requestedExpiresAt"), "requestedExpiresAt"
    )
    request_valid_until = _parse_timestamp(
        record.get("requestValidUntil"), "requestValidUntil"
    )
    ttl_days = record.get("ttlDays")
    if isinstance(ttl_days, bool) or not isinstance(ttl_days, int):
        raise ConsentError("ttlDays must be an integer")
    if not 1 <= ttl_days <= 365:
        raise ConsentError("ttlDays must be from 1 through 365")
    if requested_expires_at != prepared_at + timedelta(days=ttl_days):
        raise ConsentError("requestedExpiresAt does not match ttlDays")
    if (
        request_valid_until <= prepared_at
        or request_valid_until > prepared_at + CONSENT_REQUEST_LIFETIME
    ):
        raise ConsentError("consent request validity window is invalid")

    user_config_path = _require_absolute_path(
        record.get("userConfigPath"), "userConfigPath"
    )
    user_config_sha256 = _require_nullable_sha256(
        record.get("userConfigSha256"), "userConfigSha256"
    )
    project_config_path = _require_absolute_path(
        record.get("projectConfigPath"), "projectConfigPath"
    )
    project_config_sha256 = _require_nullable_sha256(
        record.get("projectConfigSha256"), "projectConfigSha256"
    )
    allow_file = _require_absolute_path(
        record.get("allowFile"), "allowFile", nullable=True
    )
    source_bearing = any(operation != "probe" for operation in operations)
    if source_bearing:
        context_manifest_path = _require_absolute_path(
            record.get("contextManifestPath"), "contextManifestPath"
        )
        context_manifest_sha256 = _require_sha256(
            record.get("contextManifestSha256"), "contextManifestSha256"
        )
        context_file_count = record.get("contextFileCount")
        context_total_bytes = record.get("contextTotalBytes")
        if (
            isinstance(context_file_count, bool)
            or not isinstance(context_file_count, int)
            or context_file_count < 0
        ):
            raise ConsentError("contextFileCount must be a non-negative integer")
        if (
            isinstance(context_total_bytes, bool)
            or not isinstance(context_total_bytes, int)
            or context_total_bytes < 0
        ):
            raise ConsentError("contextTotalBytes must be a non-negative integer")
    else:
        if any(
            record.get(field) is not None
            for field in (
                "contextManifestPath",
                "contextManifestSha256",
                "contextFileCount",
                "contextTotalBytes",
            )
        ):
            raise ConsentError(
                "source-free consent requests must not contain context metadata"
            )
        context_manifest_path = None
        context_manifest_sha256 = None
        context_file_count = None
        context_total_bytes = None

    return {
        "schemaVersion": CONSENT_REQUEST_SCHEMA_VERSION,
        "producer": CONSENT_REQUEST_PRODUCER,
        "requestId": request_id,
        "repositoryRoot": repository_root,
        "gitCommonDir": git_common_dir,
        "repositoryIdentity": repository_identity,
        "provider": provider,
        "operationClasses": operations,
        "denyPolicySha256": deny_policy_sha256,
        "managedPolicySha256": managed_policy_sha256,
        "providerExecutablePath": executable_path,
        "providerExecutableSha256": executable_sha256,
        "preparedAt": _format_timestamp(prepared_at),
        "requestedExpiresAt": _format_timestamp(requested_expires_at),
        "requestValidUntil": _format_timestamp(request_valid_until),
        "ttlDays": ttl_days,
        "userConfigPath": user_config_path,
        "userConfigSha256": user_config_sha256,
        "projectConfigPath": project_config_path,
        "projectConfigSha256": project_config_sha256,
        "allowFile": allow_file,
        "contextManifestPath": context_manifest_path,
        "contextManifestSha256": context_manifest_sha256,
        "contextFileCount": context_file_count,
        "contextTotalBytes": context_total_bytes,
    }


def load_consent_request(
    path: str | os.PathLike[str],
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    """Load a consent request only when its exact bytes match *expected_sha256*."""

    expected_sha256 = _require_sha256(expected_sha256, "requestSha256")
    request_path = Path(path)
    try:
        raw_bytes = request_path.read_bytes()
    except OSError as exc:
        raise ConsentError(f"could not read consent request: {exc}") from exc
    if hashlib.sha256(raw_bytes).hexdigest() != expected_sha256:
        raise ConsentError("consent request bytes changed after disclosure")
    try:
        raw = json.loads(raw_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConsentError(f"could not parse consent request: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ConsentError("consent request must be a JSON object")
    return validate_consent_request(raw)


def consent_request_summary(request: Mapping[str, object]) -> dict[str, object]:
    """Return the exact non-sensitive disclosure for a consent request."""

    normalized = validate_consent_request(request)
    context_manifest = None
    if normalized["contextManifestPath"] is not None:
        context_manifest = {
            "fileCount": normalized["contextFileCount"],
            "totalBytes": normalized["contextTotalBytes"],
        }
    summary = consent_summary(
        repository_identity=normalized["repositoryIdentity"],
        provider=normalized["provider"],
        operation_classes=normalized["operationClasses"],
        deny_policy_sha256=normalized["denyPolicySha256"],
        managed_policy_sha256=normalized["managedPolicySha256"],
        provider_executable_path=normalized["providerExecutablePath"],
        provider_executable_sha256=normalized["providerExecutableSha256"],
        expires_at=_parse_timestamp(
            normalized["requestedExpiresAt"], "requestedExpiresAt"
        ),
        context_manifest=context_manifest,
    )
    summary["requestIdPrefix"] = normalized["requestId"][:12]
    return summary


def record_consent(
    path: str | os.PathLike[str],
    *,
    repository_identity: str,
    provider: str,
    operation_classes: Iterable[str],
    deny_policy_sha256: str,
    managed_policy_sha256: str,
    provider_executable_path: str,
    provider_executable_sha256: str,
    ttl_days: int,
    now: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    """Record explicit approval for one provider.

    A repository identity change discards all approvals from the previous
    repository.  Re-recording a provider replaces, rather than expands, its
    approved operation set.
    """

    repository_identity = _require_sha256(
        repository_identity, "repositoryIdentity"
    )
    deny_policy_sha256 = _require_sha256(
        deny_policy_sha256, "denyPolicySha256"
    )
    managed_policy_sha256 = _require_sha256(
        managed_policy_sha256, "managedPolicySha256"
    )
    executable_path = str(
        Path(
            _require_nonempty_string(
                provider_executable_path, "providerExecutablePath"
            )
        ).expanduser().resolve()
    )
    provider_executable_sha256 = _require_sha256(
        provider_executable_sha256, "providerExecutableSha256"
    )
    if not isinstance(provider, str) or not provider:
        raise ConsentError("provider must be a non-empty string")
    operations = _validate_operations(operation_classes)
    if isinstance(ttl_days, bool) or not isinstance(ttl_days, int):
        raise ConsentError("ttlDays must be an integer")
    if not 1 <= ttl_days <= 365:
        raise ConsentError("ttlDays must be from 1 through 365")
    approved_at = _as_utc(now or _utc_now())
    consent_expires_at = (
        _as_utc(expires_at)
        if expires_at is not None
        else approved_at + timedelta(days=ttl_days)
    )
    if (
        consent_expires_at <= approved_at
        or consent_expires_at > approved_at + timedelta(days=ttl_days)
    ):
        raise ConsentError("expiresAt is outside the approved TTL")

    existing = load_consent(path)
    providers: dict[str, Any] = {}
    if existing and existing["repositoryIdentity"] == repository_identity:
        providers.update(existing["providers"])
    providers[provider] = {
        "approved": True,
        "operationClasses": operations,
        "denyPolicySha256": deny_policy_sha256,
        "managedPolicySha256": managed_policy_sha256,
        "providerExecutablePath": executable_path,
        "providerExecutableSha256": provider_executable_sha256,
        "approvedAt": _format_timestamp(approved_at),
        "expiresAt": _format_timestamp(consent_expires_at),
    }
    result = validate_consent(
        {
            "schemaVersion": SCHEMA_VERSION,
            "repositoryIdentity": repository_identity,
            "providers": providers,
        }
    )
    atomic_write_json(Path(path), result)
    return result


def check_consent(
    record: Mapping[str, object] | None,
    *,
    repository_identity: str,
    provider: str,
    operation_class: str,
    deny_policy_sha256: str,
    managed_policy_sha256: str,
    provider_executable_path: str,
    provider_executable_sha256: str,
    now: datetime | None = None,
) -> ConsentCheck:
    """Check consent without mutating state or inferring approval."""

    if record is None:
        return ConsentCheck(False, "missing_consent")
    try:
        normalized = validate_consent(record)
    except ConsentError:
        return ConsentCheck(False, "invalid_consent")
    if normalized["repositoryIdentity"] != repository_identity:
        return ConsentCheck(False, "repository_identity_changed")
    entry = normalized["providers"].get(provider)
    if entry is None:
        return ConsentCheck(False, "provider_not_approved")
    if operation_class not in VALID_OPERATION_CLASSES:
        return ConsentCheck(False, "unknown_operation_class")
    if operation_class not in entry["operationClasses"]:
        return ConsentCheck(False, "operation_not_approved")
    if entry["denyPolicySha256"] != deny_policy_sha256:
        return ConsentCheck(False, "deny_policy_changed")
    if entry["managedPolicySha256"] != managed_policy_sha256:
        return ConsentCheck(False, "managed_policy_changed")
    if entry["providerExecutablePath"] != str(
        Path(provider_executable_path).expanduser().resolve()
    ):
        return ConsentCheck(False, "provider_executable_changed")
    if entry["providerExecutableSha256"] != provider_executable_sha256:
        return ConsentCheck(False, "provider_executable_changed")
    current_time = _as_utc(now or _utc_now())
    if current_time >= _parse_timestamp(entry["expiresAt"], "expiresAt"):
        return ConsentCheck(False, "consent_expired")
    return ConsentCheck(True, "approved")


def require_consent(*args: Any, **kwargs: Any) -> None:
    """Raise ``ConsentError`` unless :func:`check_consent` succeeds."""

    result = check_consent(*args, **kwargs)
    if not result:
        raise ConsentError(result.reason)


def consent_summary(
    *,
    repository_identity: str,
    provider: str,
    operation_classes: Iterable[str],
    deny_policy_sha256: str,
    managed_policy_sha256: str,
    provider_executable_path: str,
    provider_executable_sha256: str,
    expires_at: datetime,
    context_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build the non-sensitive facts shown before requesting approval."""

    operations = _validate_operations(operation_classes)
    summary: dict[str, object] = {
        "provider": provider,
        "operationClasses": operations,
        "repositoryIdentityPrefix": repository_identity[:12],
        "denyPolicySha256Prefix": deny_policy_sha256[:12],
        "managedPolicySha256Prefix": managed_policy_sha256[:12],
        "providerExecutablePath": str(
            Path(provider_executable_path).expanduser().resolve()
        ),
        "providerExecutableSha256Prefix": provider_executable_sha256[:12],
        "expiresAt": _format_timestamp(expires_at),
    }
    if any(operation != "probe" for operation in operations) and context_manifest:
        files = context_manifest.get("files", [])
        summary["contextFileCount"] = context_manifest.get(
            "fileCount", len(files) if isinstance(files, list) else 0
        )
        summary["contextTotalBytes"] = context_manifest.get("totalBytes", 0)
    return summary


__all__ = [
    "ConsentCheck",
    "ConsentError",
    "CONSENT_REQUEST_LIFETIME",
    "CONSENT_REQUEST_PRODUCER",
    "CONSENT_REQUEST_SCHEMA_VERSION",
    "NO_MANAGED_POLICY",
    "SCHEMA_VERSION",
    "VALID_OPERATION_CLASSES",
    "canonical_json_sha256",
    "check_consent",
    "consent_summary",
    "consent_request_summary",
    "deny_policy_hash",
    "load_consent",
    "load_consent_request",
    "managed_policy_hash",
    "record_consent",
    "require_consent",
    "validate_consent",
    "validate_consent_request",
]
