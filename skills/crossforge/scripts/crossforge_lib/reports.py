"""Strict provider-report validation.

A valid provider report is still only a provider claim.  Independent gate
results are accepted separately and are never inferred from the report's
``verification`` field.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import InvalidInputError, PreconditionError
from .evidence import contained_evidence_path, normalize_evidence_path, safe_user_summary
from .util import sha256_file

PROVIDER_STATUSES = frozenset(
    {
        "complete",
        "partial",
        "failed",
        "timeout",
        "unavailable",
        "spec_gap",
        "scope_violation",
        "gate_failed",
    }
)
PROVIDERS = frozenset({"codex", "grok", "claude"})
CHANGED_FILE_STATUSES = frozenset(
    {"added", "modified", "deleted", "renamed", "copied", "type_changed", "mode_changed"}
)
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_UTC = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$"
)
_TOP_KEYS = frozenset(
    {
        "schemaVersion",
        "status",
        "provider",
        "requestedModel",
        "resolvedModel",
        "cliVersion",
        "baseCommit",
        "objective",
        "taskBriefSha256",
        "contextManifestSha256",
        "runtimeManifestSha256",
        "sandboxPolicySha256",
        "startedAt",
        "completedAt",
        "durationMs",
        "exitCode",
        "timedOut",
        "changedFiles",
        "scopeCheck",
        "verification",
        "gaps",
        "risks",
        "finalMessagePath",
        "patchPath",
        "patchSha256",
        "rawStdoutPath",
        "rawStderrPath",
    }
)


@dataclass(frozen=True)
class ProviderReport:
    """Validated report data and the directory against which paths were bound."""

    data: dict[str, Any]
    evidence_directory: Path | None = None

    @property
    def status(self) -> str:
        return self.data["status"]

    @property
    def provider(self) -> str:
        return self.data["provider"]

    @property
    def eligible_by_claim(self) -> bool:
        """Whether the provider claims completion, not acceptance eligibility."""

        return (
            self.status == "complete"
            and self.data["exitCode"] == 0
            and not self.data["timedOut"]
            and self.data["scopeCheck"]["passed"]
        )

    def as_dict(self) -> dict[str, Any]:
        return dict(self.data)

    def user_summary(self) -> str:
        return safe_user_summary(self.data)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InvalidInputError(f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unknown {', '.join(unknown)}")
        raise InvalidInputError(f"{label} has invalid keys: {'; '.join(details)}")


def _string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise InvalidInputError(f"{label} must be a non-empty string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise InvalidInputError(f"{label} contains a control character")
    return value


def _nonnegative_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvalidInputError(f"{label} must be a non-negative integer")
    return value


def _hash(value: Any, label: str) -> str:
    text = _string(value, label)
    if not _HEX_64.fullmatch(text):
        raise InvalidInputError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _timestamp(value: Any, label: str) -> datetime:
    text = _string(value, label)
    if not _RFC3339_UTC.fullmatch(text):
        raise InvalidInputError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise InvalidInputError(f"{label} must be an RFC3339 UTC timestamp") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise InvalidInputError(f"{label} must be an RFC3339 UTC timestamp")
    return parsed


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise InvalidInputError(f"{label} must be an array")
    return [_string(item, f"{label} item", allow_empty=False) for item in value]


def _report_path(
    value: Any,
    label: str,
    evidence_directory: Path | None,
    *,
    required_file: bool,
) -> str:
    normalized = normalize_evidence_path(_string(value, label))
    if evidence_directory is not None:
        path = contained_evidence_path(evidence_directory, normalized)
        if required_file and (path.is_symlink() or not path.is_file()):
            raise PreconditionError(f"{label} evidence is missing: {normalized}")
    return normalized


def _validate_changed_files(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise InvalidInputError("changedFiles must be an array")
    result: list[dict[str, str]] = []
    paths: set[str] = set()
    expected = frozenset({"path", "status", "summary"})
    for index, raw in enumerate(value):
        item = _mapping(raw, f"changedFiles[{index}]")
        _exact_keys(item, expected, f"changedFiles[{index}]")
        path = normalize_evidence_path(_string(item["path"], f"changedFiles[{index}].path"))
        if path in paths:
            raise InvalidInputError(f"changedFiles contains duplicate path: {path}")
        paths.add(path)
        status = _string(item["status"], f"changedFiles[{index}].status")
        if status not in CHANGED_FILE_STATUSES:
            raise InvalidInputError(f"Unsupported changed-file status: {status}")
        result.append(
            {
                "path": path,
                "status": status,
                "summary": _string(
                    item["summary"],
                    f"changedFiles[{index}].summary",
                    allow_empty=True,
                ),
            }
        )
    return result


def _validate_scope(value: Any) -> dict[str, Any]:
    item = _mapping(value, "scopeCheck")
    _exact_keys(item, frozenset({"passed", "violations"}), "scopeCheck")
    if not isinstance(item["passed"], bool):
        raise InvalidInputError("scopeCheck.passed must be a boolean")
    violations = _string_list(item["violations"], "scopeCheck.violations")
    if item["passed"] and violations:
        raise InvalidInputError("A passed scope check cannot contain violations")
    return {"passed": item["passed"], "violations": violations}


def _validate_verification(
    value: Any,
    evidence_directory: Path | None,
    *,
    require_files: bool,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise InvalidInputError("verification must be an array")
    expected = frozenset({"argv", "exitCode", "durationMs", "outputPath"})
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        item = _mapping(raw, f"verification[{index}]")
        _exact_keys(item, expected, f"verification[{index}]")
        argv = item["argv"]
        if not isinstance(argv, list) or not argv:
            raise InvalidInputError(f"verification[{index}].argv must be a non-empty array")
        normalized_argv = [
            _string(argument, f"verification[{index}].argv item") for argument in argv
        ]
        exit_code = item["exitCode"]
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise InvalidInputError(f"verification[{index}].exitCode must be an integer")
        result.append(
            {
                "argv": normalized_argv,
                "exitCode": exit_code,
                "durationMs": _nonnegative_integer(
                    item["durationMs"],
                    f"verification[{index}].durationMs",
                ),
                "outputPath": _report_path(
                    item["outputPath"],
                    f"verification[{index}].outputPath",
                    evidence_directory,
                    required_file=require_files,
                ),
            }
        )
    return result


def validate_provider_report(
    value: Mapping[str, Any],
    *,
    evidence_directory: str | Path | None = None,
    require_evidence_files: bool = False,
    verify_hashes: bool = False,
) -> ProviderReport:
    """Validate and normalize a provider report.

    ``verification`` remains provider-reported evidence.  A caller must pass
    separately generated :class:`~crossforge_lib.gates.GateResult` objects to
    its acceptance policy.
    """

    report = _mapping(value, "Provider report")
    _exact_keys(report, _TOP_KEYS, "Provider report")
    if report["schemaVersion"] != 1:
        raise InvalidInputError("Provider report schemaVersion must be 1")

    status = _string(report["status"], "status")
    if status not in PROVIDER_STATUSES:
        raise InvalidInputError(f"Unsupported provider status: {status}")
    provider = _string(report["provider"], "provider")
    if provider not in PROVIDERS:
        raise InvalidInputError(f"Unsupported provider: {provider}")
    base_commit = _string(report["baseCommit"], "baseCommit")
    if not _HEX_40.fullmatch(base_commit):
        raise InvalidInputError("baseCommit must be a 40-character lowercase Git object ID")

    directory = Path(evidence_directory).resolve() if evidence_directory is not None else None
    started = _timestamp(report["startedAt"], "startedAt")
    completed = _timestamp(report["completedAt"], "completedAt")
    if completed < started:
        raise InvalidInputError("completedAt cannot precede startedAt")

    exit_code = report["exitCode"]
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise InvalidInputError("exitCode must be an integer")
    if not isinstance(report["timedOut"], bool):
        raise InvalidInputError("timedOut must be a boolean")
    timed_out = report["timedOut"]
    if status == "complete" and (exit_code != 0 or timed_out):
        raise InvalidInputError("A complete report must have exitCode 0 and timedOut false")
    if status == "timeout" and not timed_out:
        raise InvalidInputError("A timeout report must set timedOut true")
    if timed_out and status != "timeout":
        raise InvalidInputError("timedOut true requires timeout status")

    normalized: dict[str, Any] = {
        "schemaVersion": 1,
        "status": status,
        "provider": provider,
        "requestedModel": _string(report["requestedModel"], "requestedModel"),
        "resolvedModel": _string(report["resolvedModel"], "resolvedModel"),
        "cliVersion": _string(report["cliVersion"], "cliVersion"),
        "baseCommit": base_commit,
        "objective": _string(report["objective"], "objective"),
        "taskBriefSha256": _hash(report["taskBriefSha256"], "taskBriefSha256"),
        "contextManifestSha256": _hash(
            report["contextManifestSha256"],
            "contextManifestSha256",
        ),
        "runtimeManifestSha256": _hash(
            report["runtimeManifestSha256"],
            "runtimeManifestSha256",
        ),
        "sandboxPolicySha256": _hash(
            report["sandboxPolicySha256"],
            "sandboxPolicySha256",
        ),
        "startedAt": report["startedAt"],
        "completedAt": report["completedAt"],
        "durationMs": _nonnegative_integer(report["durationMs"], "durationMs"),
        "exitCode": exit_code,
        "timedOut": timed_out,
        "changedFiles": _validate_changed_files(report["changedFiles"]),
        "scopeCheck": _validate_scope(report["scopeCheck"]),
        "verification": _validate_verification(
            report["verification"],
            directory,
            require_files=require_evidence_files,
        ),
        "gaps": _string_list(report["gaps"], "gaps"),
        "risks": _string_list(report["risks"], "risks"),
        "finalMessagePath": _report_path(
            report["finalMessagePath"],
            "finalMessagePath",
            directory,
            required_file=require_evidence_files,
        ),
        "patchPath": _report_path(
            report["patchPath"],
            "patchPath",
            directory,
            required_file=require_evidence_files,
        ),
        "patchSha256": _hash(report["patchSha256"], "patchSha256"),
        "rawStdoutPath": _report_path(
            report["rawStdoutPath"],
            "rawStdoutPath",
            directory,
            required_file=require_evidence_files,
        ),
        "rawStderrPath": _report_path(
            report["rawStderrPath"],
            "rawStderrPath",
            directory,
            required_file=require_evidence_files,
        ),
    }

    if verify_hashes:
        if directory is None:
            raise InvalidInputError("verify_hashes requires evidence_directory")
        patch_path = contained_evidence_path(directory, normalized["patchPath"])
        if not patch_path.is_file() or patch_path.is_symlink():
            raise PreconditionError("Candidate patch evidence is missing")
        if sha256_file(patch_path) != normalized["patchSha256"]:
            raise PreconditionError("Candidate patch hash does not match provider report")
        hash_bound_files = (
            (
                directory / "spec.md",
                normalized["taskBriefSha256"],
                "Task brief",
            ),
            (
                directory / "context-manifest.json",
                normalized["contextManifestSha256"],
                "Context manifest",
            ),
            (
                directory / "runtime-manifest.json",
                normalized["runtimeManifestSha256"],
                "Runtime manifest",
            ),
            (
                directory / "sandbox-policy.json",
                normalized["sandboxPolicySha256"],
                "Sandbox policy",
            ),
        )
        for bound_path, expected_hash, label in hash_bound_files:
            if bound_path.is_symlink() or not bound_path.is_file():
                raise PreconditionError(f"{label} evidence is missing")
            if sha256_file(bound_path) != expected_hash:
                raise PreconditionError(f"{label} hash does not match provider report")
        try:
            runtime_manifest = json.loads(
                (directory / "runtime-manifest.json").read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise InvalidInputError("Runtime manifest is not valid UTF-8 JSON") from error
        if (
            not isinstance(runtime_manifest, Mapping)
            or not isinstance(runtime_manifest.get("providerExecutableIdentity"), Mapping)
            or not runtime_manifest["providerExecutableIdentity"]
        ):
            raise InvalidInputError(
                "Runtime manifest must record providerExecutableIdentity"
            )
        argv_sha256 = runtime_manifest.get("providerArgvSha256")
        if (
            not isinstance(argv_sha256, str)
            or not _HEX_64.fullmatch(argv_sha256)
        ):
            raise InvalidInputError(
                "Runtime manifest must record providerArgvSha256"
            )

    return ProviderReport(normalized, directory)


def load_provider_report(
    path: str | Path,
    *,
    require_evidence_files: bool = True,
    verify_hashes: bool = True,
    expected_sha256: str | None = None,
) -> ProviderReport:
    """Read and validate ``report.json`` relative to its containing directory."""

    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise PreconditionError(f"Provider report is missing: {candidate}")
    try:
        raw_bytes = candidate.read_bytes()
        if expected_sha256 is not None and (
            _HEX_64.fullmatch(expected_sha256) is None
            or hashlib.sha256(raw_bytes).hexdigest() != expected_sha256
        ):
            raise PreconditionError(
                "Provider report bytes do not match invoke-bound evidence"
            )
        raw = json.loads(raw_bytes)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InvalidInputError(f"Provider report is not valid UTF-8 JSON: {candidate}") from error
    return validate_provider_report(
        raw,
        evidence_directory=candidate.parent,
        require_evidence_files=require_evidence_files,
        verify_hashes=verify_hashes,
    )


def independent_gates_passed(results: Sequence[Any]) -> bool:
    """Return true only for non-empty, independently produced passing results."""

    if not results:
        return False
    for result in results:
        passed = getattr(result, "passed", None)
        provenance = getattr(result, "provenance", None)
        if passed is not True or provenance != "independent":
            return False
    return True


def candidate_evidence_eligible(
    report: ProviderReport,
    independent_gate_results: Sequence[Any],
) -> bool:
    """Combine provider completion claims with distinct trusted gate evidence."""

    return report.eligible_by_claim and independent_gates_passed(independent_gate_results)
