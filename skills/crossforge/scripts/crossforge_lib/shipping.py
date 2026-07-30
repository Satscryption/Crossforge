"""Explicit, durable, idempotent Crossforge shipping."""

from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

from .errors import (
    InvalidInputError,
    PreconditionError,
    SecretPolicyError,
    StateInconsistencyError,
)
from .gates import ExecutableIdentity, executable_identity, validate_path_environment
from .git import (
    GitRepository,
    current_branch,
    is_dirty,
    normalize_remote_url,
    repository_identity,
    resolve_commit,
)
from .locking import repository_lock, run_lock
from .models import RunMode, RunStatus, TaskStatus
from .secrets import MAX_TEXT_BYTES, match_deny_path, scan_text
from .state import StateStore
from .util import atomic_write_json, canonical_json_bytes, sha256_bytes, utc_now

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_KEY = re.compile(r"^[0-9a-f]{32}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._/-]+$")
_AUTHORIZATION_TTL = timedelta(hours=24)
_SHIPMENT_FIELDS = {
    "schemaVersion",
    "repositoryIdentity",
    "runId",
    "status",
    "idempotencyKey",
    "remote",
    "remoteUrl",
    "headBranch",
    "targetBranch",
    "finalCommit",
    "authorizedAt",
    "expiresAt",
    "preflightGate",
    "forgeExecutable",
    "bodySha256",
    "publicationPayloadSha256",
    "push",
    "pullRequest",
    "completedAt",
}


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    def __call__(
        self, argv: Sequence[str], *, cwd: Path, input_text: str | None = None
    ) -> CommandResult: ...


@dataclass(frozen=True, slots=True)
class RemoteReadback:
    head_commit: str | None
    target_commit: str | None
    head_is_ancestor: bool | None
    target_is_ancestor: bool | None


@dataclass(frozen=True, slots=True)
class PullRequestReadback:
    forge: str
    number: int
    url: str
    state: str
    head_branch: str
    target_branch: str
    head_commit: str | None


@dataclass(frozen=True, slots=True)
class ShippingPlan:
    repository_identity: str
    run_id: str
    remote: str
    remote_url: str
    head_branch: str
    target_branch: str
    final_commit: str
    remote_readback: RemoteReadback
    final_gate_evidence: FinalGateEvidence
    dry_run: bool

    def authorization_tuple(self) -> tuple[str, str, str, str, str, str, str]:
        return (
            self.repository_identity,
            self.run_id,
            self.remote,
            self.remote_url,
            self.head_branch,
            self.target_branch,
            self.final_commit,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "repositoryIdentity": self.repository_identity,
            "runId": self.run_id,
            "remote": self.remote,
            "remoteUrl": self.remote_url,
            "headBranch": self.head_branch,
            "targetBranch": self.target_branch,
            "finalCommit": self.final_commit,
            "dryRun": self.dry_run,
            "plannedPush": self.remote_readback.head_commit != self.final_commit,
            "plannedPullRequest": True,
        }


@dataclass(frozen=True, slots=True)
class FinalGateEvidence:
    run_id: str
    final_commit: str
    plan_sha256: str
    global_commands_sha256: str
    gate_policy_sha256: str
    sandbox_policy_sha256: str
    result_sha256: str
    provenance: str
    passed: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "runId": self.run_id,
            "finalCommit": self.final_commit,
            "planSha256": self.plan_sha256,
            "globalCommandsSha256": self.global_commands_sha256,
            "gatePolicySha256": self.gate_policy_sha256,
            "sandboxPolicySha256": self.sandbox_policy_sha256,
            "resultSha256": self.result_sha256,
            "provenance": self.provenance,
            "passed": self.passed,
        }


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise StateInconsistencyError(f"shipment {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise StateInconsistencyError(f"shipment {label} is not RFC3339") from exc
    if parsed.tzinfo is None:
        raise StateInconsistencyError(f"shipment {label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_datetime() -> datetime:
    return datetime.now(timezone.utc)


def _remote_urls(
    repository: GitRepository,
    remote: str,
    *,
    runner: CommandRunner | None = None,
) -> tuple[str, str]:
    """Resolve one unambiguous fetch/push destination for a remote alias."""

    command_runner = runner or default_command_runner
    remote = _validate_name(remote, "remote")
    if remote.startswith("-"):
        raise InvalidInputError("invalid remote")
    rewrite_check = command_runner(
        (
            repository.git_executable,
            "config",
            "--get-regexp",
            r"^url\.",
        ),
        cwd=repository.root,
    )
    if rewrite_check.returncode not in {0, 1}:
        raise PreconditionError("Git URL rewrite policy could not be inspected")
    if rewrite_check.returncode == 0 and any(
        line.split(None, 1)[0].lower().endswith((".insteadof", ".pushinsteadof"))
        for line in rewrite_check.stdout.splitlines()
        if line.split(None, 1)
    ):
        raise PreconditionError(
            "Git URL rewrite rules are not supported for shipping"
        )

    def resolve(*extra: str) -> list[str]:
        result = command_runner(
            (
                repository.git_executable,
                "remote",
                "get-url",
                *extra,
                "--all",
                remote,
            ),
            cwd=repository.root,
        )
        if result.returncode != 0:
            raise PreconditionError("authorized remote URL could not be resolved")
        values = [line for line in result.stdout.splitlines() if line]
        if len(values) != 1 or any(
            value != value.strip() or "\x00" in value for value in values
        ):
            raise PreconditionError(
                "shipping requires exactly one unambiguous remote URL"
            )
        return values

    fetch_url = resolve()[0]
    push_url = resolve("--push")[0]
    for value in (fetch_url, push_url):
        if "://" in value:
            parsed = urlsplit(value)
            if parsed.password is not None or (
                parsed.username is not None
                and parsed.scheme.lower() not in {"ssh", "git+ssh"}
            ):
                raise PreconditionError(
                    "shipping remote URLs must not contain credentials"
                )
        else:
            scp_match = re.fullmatch(r"(?:(?P<user>[^@/:]+)@)?[^/:]+:.+", value)
            if scp_match and scp_match.group("user") not in {None, "git"}:
                raise PreconditionError(
                    "shipping remote URLs must not contain credentials"
                )
    if normalize_remote_url(fetch_url) != normalize_remote_url(push_url):
        raise PreconditionError("remote fetch and push destinations differ")
    return fetch_url, push_url


def _assert_remote_binding(
    repository: GitRepository,
    shipment: Mapping[str, Any],
    *,
    runner: CommandRunner | None = None,
) -> str:
    fetch_url, push_url = _remote_urls(
        repository, str(shipment["remote"]), runner=runner
    )
    if (
        normalize_remote_url(fetch_url) != shipment["remoteUrl"]
        or normalize_remote_url(push_url) != shipment["remoteUrl"]
    ):
        raise StateInconsistencyError(
            "authorized remote URL changed after shipment authorization"
        )
    return push_url


def resolve_forge_executable(
    executable: str = "gh",
    *,
    path_value: str | None = None,
) -> ExecutableIdentity:
    """Resolve and pin the trusted forge CLI before any publication write."""

    effective_path = path_value if path_value is not None else os.environ.get("PATH", "")
    validate_path_environment(effective_path)
    if Path(executable).is_absolute():
        resolved = Path(executable).resolve(strict=True)
    else:
        if "/" in executable or "\\" in executable:
            raise InvalidInputError("forge executable must be a basename or absolute path")
        found = shutil.which(executable, path=effective_path)
        if found is None:
            raise PreconditionError("GitHub CLI is unavailable")
        resolved = Path(found).resolve(strict=True)
    return executable_identity(resolved)


def _require_forge_identity(identity: Mapping[str, Any] | ExecutableIdentity) -> str:
    expected = (
        identity.as_dict()
        if isinstance(identity, ExecutableIdentity)
        else dict(identity)
    )
    if set(expected) != {"basename", "path", "mode", "sha256"}:
        raise StateInconsistencyError("forge executable identity is invalid")
    observed = executable_identity(str(expected["path"])).as_dict()
    if observed != expected:
        raise StateInconsistencyError("forge executable changed after validation")
    return str(observed["path"])


def _assert_publication_authority(
    shipment: Mapping[str, Any],
    *,
    publication_requested: bool,
) -> None:
    if not publication_requested:
        raise PreconditionError("current user request does not authorize publication")


def _assert_authorization_fresh(shipment: Mapping[str, Any]) -> None:
    current = _utc_datetime()
    authorized = _parse_timestamp(shipment["authorizedAt"], "authorizedAt")
    if current < authorized:
        raise PreconditionError("shipment authorization is future-dated")
    if current >= _parse_timestamp(shipment["expiresAt"], "expiresAt"):
        raise PreconditionError(
            "shipment authorization expired; rerun authorization with current intent"
        )


def load_pull_request_body(
    path: str | os.PathLike[str],
    *,
    repository: GitRepository,
    deny_paths: Sequence[str],
    allowed_root: str | os.PathLike[str],
    max_bytes: int = MAX_TEXT_BYTES,
) -> str:
    """Read one owner-private, non-link PR body and screen its exact bytes."""

    source = Path(path)
    allowed = Path(allowed_root).resolve()
    try:
        source.resolve().relative_to(allowed)
    except ValueError as exc:
        raise SecretPolicyError(
            "pull-request body must be inside the run shipping-evidence directory"
        ) from exc
    try:
        initial = source.lstat()
    except OSError as exc:
        raise SecretPolicyError(
            "pull-request body is not a readable regular file"
        ) from exc
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISREG(initial.st_mode):
        raise SecretPolicyError("pull-request body must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise SecretPolicyError("pull-request body is not a readable regular file") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SecretPolicyError("pull-request body must be a regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise SecretPolicyError("pull-request body must be owner-private")
        if info.st_size > max_bytes:
            raise SecretPolicyError("pull-request body exceeds the size limit")
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > max_bytes:
            raise SecretPolicyError("pull-request body exceeds the size limit")
    finally:
        os.close(descriptor)
    try:
        body = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecretPolicyError("pull-request body must be valid UTF-8") from exc
    resolved = source.resolve()
    candidates = [source.name, resolved.name]
    try:
        candidates.append(resolved.relative_to(repository.root).as_posix())
    except ValueError:
        pass
    if any(match_deny_path(candidate, deny_paths) for candidate in candidates):
        raise SecretPolicyError("pull-request body path is denied by policy")
    if scan_text(body, "pull-request-body.md"):
        raise SecretPolicyError("pull-request body contains secret-like content")
    return body


def validate_publication_text(value: str, *, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise InvalidInputError(f"{label} must be non-empty text")
    if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        raise SecretPolicyError(f"{label} exceeds the size limit")
    if scan_text(value, label):
        raise SecretPolicyError(f"{label} contains secret-like content")


def validate_final_gate_evidence(
    run: Mapping[str, Any], evidence: FinalGateEvidence
) -> None:
    """Require final verification evidence bound to this exact completed run."""

    if not isinstance(evidence, FinalGateEvidence):
        raise PreconditionError("trusted final-gate executor returned invalid evidence")
    expected = (
        run["runId"],
        run["currentCommit"],
        run["planSha256"],
        _sha256_json(run["globalVerificationCommands"]),
        _sha256_json(run["gateSandbox"]),
    )
    observed = (
        evidence.run_id,
        evidence.final_commit,
        evidence.plan_sha256,
        evidence.global_commands_sha256,
        evidence.gate_policy_sha256,
    )
    if observed != expected:
        raise StateInconsistencyError(
            "final verification evidence is not bound to the completed run"
        )
    for value in (evidence.sandbox_policy_sha256, evidence.result_sha256):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise StateInconsistencyError("final verification evidence hash is invalid")
    if evidence.provenance != "independent" or evidence.passed is not True:
        raise PreconditionError("canonical global verification gate did not pass")


def _validate_stored_preflight_gate(
    run: Mapping[str, Any], value: Mapping[str, Any]
) -> None:
    keys = {
        "runId",
        "finalCommit",
        "planSha256",
        "globalCommandsSha256",
        "gatePolicySha256",
        "sandboxPolicySha256",
        "resultSha256",
        "provenance",
        "passed",
    }
    if set(value) != keys:
        raise StateInconsistencyError("stored preflight gate is malformed")
    evidence = FinalGateEvidence(
        run_id=value["runId"],
        final_commit=value["finalCommit"],
        plan_sha256=value["planSha256"],
        global_commands_sha256=value["globalCommandsSha256"],
        gate_policy_sha256=value["gatePolicySha256"],
        sandbox_policy_sha256=value["sandboxPolicySha256"],
        result_sha256=value["resultSha256"],
        provenance=value["provenance"],
        passed=value["passed"],
    )
    validate_final_gate_evidence(run, evidence)


def default_command_runner(
    argv: Sequence[str], *, cwd: Path, input_text: str | None = None
) -> CommandResult:
    if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise InvalidInputError("shipping command argv is invalid")
    try:
        result = subprocess.run(
            tuple(argv),
            cwd=cwd,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreconditionError("shipping command could not complete") from exc
    return CommandResult(tuple(argv), result.returncode, result.stdout, result.stderr)


def _validate_name(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not _SAFE_NAME.fullmatch(value)
        or ".." in value.split("/")
    ):
        raise InvalidInputError(f"invalid {label}")
    return value


def _shipment_path(store: StateStore, run_id: str) -> Path:
    return store.run_dir(run_id) / "shipment.json"


def _load_shipment(store: StateStore, run_id: str) -> dict[str, Any] | None:
    path = _shipment_path(store, run_id)
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateInconsistencyError("invalid shipment.json") from exc
    return validate_shipment(value)


def validate_shipment(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _SHIPMENT_FIELDS:
        raise StateInconsistencyError("shipment.json has missing or unknown fields")
    if value["schemaVersion"] != 2:
        raise StateInconsistencyError("unsupported shipment schema")
    for field in (
        "repositoryIdentity",
        "runId",
        "remote",
        "remoteUrl",
        "headBranch",
        "targetBranch",
        "authorizedAt",
        "expiresAt",
    ):
        if not isinstance(value[field], str) or not value[field]:
            raise StateInconsistencyError(f"shipment {field} is invalid")
    if not _COMMIT.fullmatch(value["finalCommit"] or ""):
        raise StateInconsistencyError("shipment finalCommit is invalid")
    if not _KEY.fullmatch(value["idempotencyKey"] or ""):
        raise StateInconsistencyError("shipment idempotencyKey is invalid")
    try:
        normalized_remote = normalize_remote_url(value["remoteUrl"])
    except InvalidInputError as exc:
        raise StateInconsistencyError("shipment remoteUrl is invalid") from exc
    if normalized_remote != value["remoteUrl"]:
        raise StateInconsistencyError("shipment remoteUrl is not canonical")
    authorized_at = _parse_timestamp(value["authorizedAt"], "authorizedAt")
    expires_at = _parse_timestamp(value["expiresAt"], "expiresAt")
    if expires_at <= authorized_at or expires_at - authorized_at > _AUTHORIZATION_TTL:
        raise StateInconsistencyError("shipment authorization expiry is invalid")
    if not isinstance(value["preflightGate"], dict):
        raise StateInconsistencyError("shipment preflightGate is invalid")
    if value["forgeExecutable"] is not None and not isinstance(
        value["forgeExecutable"], dict
    ):
        raise StateInconsistencyError("shipment forgeExecutable is invalid")
    if value["bodySha256"] is not None and not re.fullmatch(
        r"[0-9a-f]{64}", str(value["bodySha256"])
    ):
        raise StateInconsistencyError("shipment bodySha256 is invalid")
    if value["publicationPayloadSha256"] is not None and not re.fullmatch(
        r"[0-9a-f]{64}", str(value["publicationPayloadSha256"])
    ):
        raise StateInconsistencyError("shipment publicationPayloadSha256 is invalid")
    if value["status"] not in {
        "authorized",
        "remote_confirmed",
        "pr_confirmed",
        "recorded",
        "push_only_recorded",
    }:
        raise StateInconsistencyError("shipment status is invalid")
    if value["status"] != "authorized" and not isinstance(value["push"], dict):
        raise StateInconsistencyError("shipment checkpoint is missing push readback")
    if value["status"] in {"pr_confirmed", "recorded"} and not isinstance(
        value["pullRequest"], dict
    ):
        raise StateInconsistencyError("shipment checkpoint is missing PR readback")
    if value["status"] in {"recorded", "push_only_recorded"}:
        if not isinstance(value["completedAt"], str) or not value["completedAt"]:
            raise StateInconsistencyError("recorded shipment is missing completedAt")
    elif value["completedAt"] is not None:
        raise StateInconsistencyError("incomplete shipment has completedAt")
    return dict(value)


def _assert_complete_build(
    store: StateStore, repository: GitRepository, run_id: str
) -> dict[str, Any]:
    run = store.load_run(run_id)
    if run["mode"] != RunMode.BUILD.value or run["status"] not in {
        RunStatus.COMPLETE.value,
        RunStatus.SHIPPED.value,
    }:
        raise PreconditionError("only a completed Crossforge build can be shipped")
    if run["activeTaskId"] is not None or run["blockedReason"] is not None:
        raise PreconditionError("run still has an active or blocked task")
    tasks = store.load_tasks(run_id)
    unfinished = [
        item["id"]
        for item in tasks["tasks"]
        if item["status"] != TaskStatus.COMPLETE.value
    ]
    if unfinished:
        raise PreconditionError(
            "run contains incomplete tasks", details={"taskIds": unfinished}
        )
    if is_dirty(repository):
        raise PreconditionError("shipping requires a clean orchestration worktree")
    if repository_identity(repository) != run["repositoryIdentity"]:
        raise StateInconsistencyError(
            "current repository identity differs from the completed run"
        )
    branch = current_branch(repository)
    head = resolve_commit(repository)
    if branch != run["branch"] or head != run["currentCommit"]:
        raise StateInconsistencyError(
            "current branch or commit does not match the completed run"
        )
    return run


def ship_preflight(
    store: StateStore,
    repository: GitRepository,
    *,
    run_id: str | None,
    remote: str | None,
    target_branch: str | None,
    publication_requested: bool,
    dry_run: bool,
    final_gate: Callable[[Mapping[str, Any]], FinalGateEvidence],
    inspect_remote: Callable[[str, str, str, str], RemoteReadback],
    target_change_approved: bool = False,
) -> ShippingPlan:
    """Perform all read-only checks. This function never authorizes or writes."""

    if not publication_requested:
        raise PreconditionError("current user request does not authorize publication")
    selected_run = run_id or store.latest_complete_run_id()
    if selected_run is None:
        raise PreconditionError("there is no completed Crossforge build to ship")
    run = _assert_complete_build(store, repository, selected_run)
    gate_evidence = final_gate(run)
    validate_final_gate_evidence(run, gate_evidence)
    selected_remote = _validate_name(remote or run["targetRemote"], "remote")
    selected_target = _validate_name(
        target_branch or run["targetBranch"], "target branch"
    )
    if (
        selected_remote != run["targetRemote"]
        or selected_target != run["targetBranch"]
    ) and not target_change_approved:
        raise PreconditionError(
            "shipping target differs from the approved plan and needs explicit approval"
        )
    head_branch = _validate_name(run["branch"], "head branch")
    final_commit = run["currentCommit"]
    fetch_url, push_url = _remote_urls(repository, selected_remote)
    remote_url = normalize_remote_url(push_url)
    remote_state = inspect_remote(
        push_url, head_branch, selected_target, final_commit
    )
    if (
        remote_state.head_commit not in {None, final_commit}
        and remote_state.head_is_ancestor is not True
    ):
        raise PreconditionError("remote head has diverged; Crossforge will not force push")
    if (
        remote_state.target_commit is not None
        and remote_state.target_is_ancestor is not True
    ):
        raise PreconditionError(
            "target branch has diverged; update separately and rerun verification"
        )
    return ShippingPlan(
        repository_identity=run["repositoryIdentity"],
        run_id=selected_run,
        remote=selected_remote,
        remote_url=remote_url,
        head_branch=head_branch,
        target_branch=selected_target,
        final_commit=final_commit,
        remote_readback=remote_state,
        final_gate_evidence=gate_evidence,
        dry_run=dry_run,
    )


def authorize_shipment(
    store: StateStore,
    repository: GitRepository,
    plan: ShippingPlan,
    *,
    idempotency_key: str,
    publication_requested: bool,
) -> dict[str, Any]:
    if plan.dry_run:
        raise PreconditionError("dry-run cannot record shipping authorization")
    if not publication_requested:
        raise PreconditionError("current user request does not authorize publication")
    if not _KEY.fullmatch(idempotency_key):
        raise InvalidInputError("idempotency key must be 32 lowercase hexadecimal characters")
    run = store.load_run(plan.run_id)
    _assert_complete_build(store, repository, plan.run_id)
    validate_final_gate_evidence(run, plan.final_gate_evidence)
    _assert_remote_binding(
        repository, {"remote": plan.remote, "remoteUrl": plan.remote_url}
    )
    expected = (
        run["repositoryIdentity"],
        run["runId"],
        plan.remote,
        plan.remote_url,
        plan.head_branch,
        plan.target_branch,
        run["currentCommit"],
    )
    if plan.authorization_tuple() != expected:
        raise StateInconsistencyError("shipping plan no longer matches durable run state")
    existing = _load_shipment(store, plan.run_id)
    if existing is not None:
        existing_tuple = (
            existing["repositoryIdentity"],
            existing["runId"],
            existing["remote"],
            existing["remoteUrl"],
            existing["headBranch"],
            existing["targetBranch"],
            existing["finalCommit"],
        )
        if existing_tuple == expected:
            expired = _utc_datetime() >= _parse_timestamp(
                existing["expiresAt"], "expiresAt"
            )
            if existing["idempotencyKey"] == idempotency_key:
                if expired and existing["status"] not in {
                    "recorded",
                    "push_only_recorded",
                }:
                    raise PreconditionError(
                        "expired authorization renewal requires a new idempotency key"
                    )
                return existing
            if expired and existing["status"] not in {
                "recorded",
                "push_only_recorded",
            }:
                renewed = dict(existing)
                renewed_at = _utc_datetime()
                renewed["idempotencyKey"] = idempotency_key
                renewed["authorizedAt"] = _format_timestamp(renewed_at)
                renewed["expiresAt"] = _format_timestamp(
                    renewed_at + _AUTHORIZATION_TTL
                )
                renewed["preflightGate"] = plan.final_gate_evidence.to_dict()
                return _write_shipment(store, renewed)
        raise StateInconsistencyError("an immutable shipment authorization already exists")
    authorized_at = _utc_datetime()
    value = {
        "schemaVersion": 2,
        "repositoryIdentity": plan.repository_identity,
        "runId": plan.run_id,
        "status": "authorized",
        "idempotencyKey": idempotency_key,
        "remote": plan.remote,
        "remoteUrl": plan.remote_url,
        "headBranch": plan.head_branch,
        "targetBranch": plan.target_branch,
        "finalCommit": plan.final_commit,
        "authorizedAt": _format_timestamp(authorized_at),
        "expiresAt": _format_timestamp(authorized_at + _AUTHORIZATION_TTL),
        "preflightGate": plan.final_gate_evidence.to_dict(),
        "forgeExecutable": None,
        "bodySha256": None,
        "publicationPayloadSha256": None,
        "push": None,
        "pullRequest": None,
        "completedAt": None,
    }
    atomic_write_json(_shipment_path(store, plan.run_id), value)
    return value


def _write_shipment(store: StateStore, shipment: Mapping[str, Any]) -> dict[str, Any]:
    value = validate_shipment(dict(shipment))
    atomic_write_json(_shipment_path(store, value["runId"]), value)
    return value


def reconcile_push(
    store: StateStore,
    repository: GitRepository,
    *,
    run_id: str,
    inspect_remote: Callable[[str, str, str, str], RemoteReadback],
    publication_requested: bool,
    final_gate: Callable[[Mapping[str, Any]], FinalGateEvidence],
    push_only: bool,
    title: str | None = None,
    body: str | None = None,
    draft: bool | None = None,
    forge_identity: Mapping[str, Any] | ExecutableIdentity | None = None,
    runner: CommandRunner = default_command_runner,
) -> dict[str, Any]:
    shipment = _load_shipment(store, run_id)
    if shipment is None:
        raise PreconditionError("shipment is not authorized")
    _assert_publication_authority(
        shipment, publication_requested=publication_requested
    )
    run = _assert_complete_build(store, repository, run_id)
    if run["repositoryIdentity"] != shipment["repositoryIdentity"]:
        raise StateInconsistencyError("repository identity changed after authorization")
    _validate_stored_preflight_gate(run, shipment["preflightGate"])
    fresh_gate = final_gate(run)
    validate_final_gate_evidence(run, fresh_gate)
    remote_url = _assert_remote_binding(repository, shipment, runner=runner)
    pinned_forge: dict[str, Any] | None = None
    body_sha256: str | None = None
    if push_only:
        if (
            title is not None
            or body is not None
            or draft is not None
            or forge_identity is not None
        ):
            raise InvalidInputError("push-only shipment cannot bind pull-request inputs")
    else:
        if title is None or body is None or draft is None or forge_identity is None:
            raise PreconditionError(
                "pull-request inputs must be validated before the shipment push"
            )
        validate_publication_text(title, label="pull-request title")
        validate_publication_text(body, label="pull-request body")
        _require_forge_identity(forge_identity)
        pinned_forge = dict(
            forge_identity.as_dict()
            if isinstance(forge_identity, ExecutableIdentity)
            else forge_identity
        )
        body_sha256 = sha256_bytes(body.encode("utf-8"))
        payload_sha256 = sha256_bytes(
            canonical_json_bytes(
                {"title": title, "bodySha256": body_sha256, "draft": draft}
            )
        )
        resolve_authorized_forge_repository(str(shipment["remoteUrl"]))
        expected_bindings = (pinned_forge, body_sha256, payload_sha256)
        existing_bindings = (
            shipment["forgeExecutable"],
            shipment["bodySha256"],
            shipment["publicationPayloadSha256"],
        )
        if any(value is not None for value in existing_bindings):
            if existing_bindings != expected_bindings:
                raise StateInconsistencyError(
                    "publication inputs differ from the prepared shipment"
                )
        else:
            prepared = dict(shipment)
            prepared["forgeExecutable"] = pinned_forge
            prepared["bodySha256"] = body_sha256
            prepared["publicationPayloadSha256"] = payload_sha256
            shipment = _write_shipment(store, prepared)
    observed = inspect_remote(
        remote_url,
        shipment["headBranch"],
        shipment["targetBranch"],
        shipment["finalCommit"],
    )
    performed = False
    if observed.head_commit != shipment["finalCommit"]:
        if observed.head_commit is not None and observed.head_is_ancestor is not True:
            raise PreconditionError("remote head diverged; refusing non-fast-forward push")
        argv = (
            repository.git_executable,
            "-c",
            "core.hooksPath=/dev/null",
            "push",
            "--no-verify",
            remote_url,
            f"{shipment['finalCommit']}:refs/heads/{shipment['headBranch']}",
        )
        _assert_authorization_fresh(shipment)
        result = runner(argv, cwd=repository.root)
        if result.returncode != 0:
            raise PreconditionError("authorized push failed")
        performed = True
        observed = inspect_remote(
            remote_url,
            shipment["headBranch"],
            shipment["targetBranch"],
            shipment["finalCommit"],
        )
    if observed.head_commit != shipment["finalCommit"]:
        raise StateInconsistencyError("remote readback does not contain final commit")
    if shipment["status"] in {"recorded", "push_only_recorded"}:
        return shipment
    checkpoint = dict(shipment)
    previous = shipment.get("push")
    result_kind = (
        previous["result"]
        if isinstance(previous, dict) and previous.get("result") == "performed"
        else "performed" if performed else "discovered"
    )
    checkpoint["status"] = (
        shipment["status"] if shipment["status"] != "authorized" else "remote_confirmed"
    )
    checkpoint["push"] = {
        "result": result_kind,
        "remoteRef": f"refs/heads/{shipment['headBranch']}",
        "observedCommit": shipment["finalCommit"],
        "recordedAt": utc_now(),
    }
    checkpoint["forgeExecutable"] = pinned_forge
    checkpoint["bodySha256"] = body_sha256
    return _write_shipment(store, checkpoint)


def _query_pull_requests(
    shipment: Mapping[str, Any],
    *,
    repository: GitRepository,
    forge_identity: Mapping[str, Any] | ExecutableIdentity,
    runner: CommandRunner,
) -> list[PullRequestReadback]:
    _assert_remote_binding(repository, shipment, runner=runner)
    forge_repository = resolve_authorized_forge_repository(
        str(shipment["remoteUrl"])
    )
    forge_owner = forge_repository.split("/", 1)[0]
    gh_executable = _require_forge_identity(forge_identity)
    argv = (
        gh_executable,
        "pr",
        "list",
        "--repo",
        forge_repository,
        "--state",
        "all",
        "--head",
        f"{forge_owner}:{shipment['headBranch']}",
        "--base",
        shipment["targetBranch"],
        "--json",
        "number,url,state,headRefName,baseRefName,headRefOid,isCrossRepository,headRepositoryOwner",
    )
    result = runner(argv, cwd=repository.root)
    if result.returncode != 0:
        raise PreconditionError("pull-request readback failed")
    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise StateInconsistencyError("forge returned invalid pull-request JSON") from exc
    if not isinstance(raw, list):
        raise StateInconsistencyError("forge pull-request response is not an array")
    matches: list[PullRequestReadback] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        if item.get("headRefName") != shipment["headBranch"] or item.get(
            "baseRefName"
        ) != shipment["targetBranch"]:
            continue
        number = item.get("number")
        state = item.get("state")
        url = item.get("url")
        expected_path = f"/{forge_repository}/pull/{number}"
        try:
            parsed_pr_url = urlsplit(url) if isinstance(url, str) else None
            valid_pr_url = bool(
                parsed_pr_url
                and parsed_pr_url.scheme == "https"
                and (parsed_pr_url.hostname or "").lower() == "github.com"
                and parsed_pr_url.path.lower() == expected_path.lower()
                and not parsed_pr_url.query
                and not parsed_pr_url.fragment
                and parsed_pr_url.username is None
            )
        except ValueError:
            valid_pr_url = False
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or number <= 0
            or not isinstance(state, str)
            or state.lower() not in {"open", "closed", "merged"}
            or item.get("headRefOid") != shipment["finalCommit"]
            or item.get("isCrossRepository") is not False
            or not isinstance(item.get("headRepositoryOwner"), dict)
            or str(item["headRepositoryOwner"].get("login", "")).lower()
            != forge_owner.lower()
            or not isinstance(url, str)
            or not valid_pr_url
        ):
            raise StateInconsistencyError(
                "matching pull-request readback is not bound to the authorized shipment"
            )
        matches.append(
            PullRequestReadback(
                forge="github",
                number=number,
                url=url,
                state=state.lower(),
                head_branch=str(item["headRefName"]),
                target_branch=str(item["baseRefName"]),
                head_commit=str(item["headRefOid"]),
            )
        )
    return matches


def inspect_pull_requests(
    shipment: Mapping[str, Any],
    *,
    repository: GitRepository,
    forge_identity: Mapping[str, Any] | ExecutableIdentity,
    runner: CommandRunner = default_command_runner,
) -> tuple[PullRequestReadback, ...]:
    """Read matching open and closed PRs without changing forge state."""

    return tuple(
        _query_pull_requests(
            shipment,
            repository=repository,
            forge_identity=forge_identity,
            runner=runner,
        )
    )


def reconcile_pull_request(
    store: StateStore,
    repository: GitRepository,
    *,
    run_id: str,
    title: str,
    body: str,
    draft: bool,
    publication_requested: bool,
    final_gate: Callable[[Mapping[str, Any]], FinalGateEvidence],
    forge_identity: Mapping[str, Any] | ExecutableIdentity,
    runner: CommandRunner = default_command_runner,
) -> dict[str, Any]:
    shipment = _load_shipment(store, run_id)
    if shipment is None or shipment["push"] is None:
        raise PreconditionError("remote commit must be confirmed before PR creation")
    _assert_publication_authority(
        shipment, publication_requested=publication_requested
    )
    run = _assert_complete_build(store, repository, run_id)
    if (
        run["repositoryIdentity"] != shipment["repositoryIdentity"]
        or run["currentCommit"] != shipment["finalCommit"]
    ):
        raise StateInconsistencyError("durable run changed after shipment authorization")
    _validate_stored_preflight_gate(run, shipment["preflightGate"])
    fresh_gate = final_gate(run)
    validate_final_gate_evidence(run, fresh_gate)
    _assert_remote_binding(repository, shipment, runner=runner)
    validate_publication_text(title, label="pull-request title")
    validate_publication_text(body, label="pull-request body")
    gh_executable = _require_forge_identity(forge_identity)
    pinned = dict(forge_identity.as_dict() if isinstance(forge_identity, ExecutableIdentity) else forge_identity)
    if shipment["forgeExecutable"] != pinned:
        raise StateInconsistencyError("forge executable differs from shipment binding")
    if shipment["bodySha256"] != sha256_bytes(body.encode("utf-8")):
        raise StateInconsistencyError(
            "pull-request body differs from the pre-push shipment binding"
        )
    payload_sha256 = sha256_bytes(
        canonical_json_bytes(
            {
                "title": title,
                "bodySha256": shipment["bodySha256"],
                "draft": draft,
            }
        )
    )
    if shipment["publicationPayloadSha256"] != payload_sha256:
        raise StateInconsistencyError(
            "pull-request title, body, or draft mode differs from the prepared shipment"
        )
    matches = _query_pull_requests(
        shipment,
        repository=repository,
        forge_identity=forge_identity,
        runner=runner,
    )
    if len(matches) > 1:
        raise StateInconsistencyError("multiple matching pull requests already exist")
    if shipment["status"] == "recorded" and len(matches) == 1:
        return shipment
    if shipment["status"] == "push_only_recorded":
        raise StateInconsistencyError("push-only shipment is already terminal")
    created = False
    if not matches:
        with tempfile.TemporaryDirectory(prefix="crossforge-pr-") as tmp:
            body_file = Path(tmp) / "body.md"
            body_file.write_text(body, encoding="utf-8")
            argv = [
                gh_executable,
                "pr",
                "create",
                "--repo",
                resolve_authorized_forge_repository(str(shipment["remoteUrl"])),
                "--head",
                f"{resolve_authorized_forge_repository(str(shipment['remoteUrl'])).split('/', 1)[0]}:{shipment['headBranch']}",
                "--base",
                shipment["targetBranch"],
                "--title",
                title,
                "--body-file",
                str(body_file),
            ]
            if draft:
                argv.append("--draft")
            if _require_forge_identity(forge_identity) != gh_executable:
                raise StateInconsistencyError(
                    "forge executable changed before pull-request creation"
                )
            _assert_authorization_fresh(shipment)
            result = runner(tuple(argv), cwd=repository.root)
            if result.returncode != 0:
                raise PreconditionError("pull-request creation failed")
        created = True
        matches = _query_pull_requests(
            shipment,
            repository=repository,
            forge_identity=forge_identity,
            runner=runner,
        )
    if len(matches) != 1:
        raise StateInconsistencyError("pull-request readback did not find exactly one PR")
    match = matches[0]
    checkpoint = dict(shipment)
    previous = shipment.get("pullRequest")
    result_kind = (
        previous["result"]
        if isinstance(previous, dict) and previous.get("result") == "created"
        else "created" if created else "discovered"
    )
    checkpoint["status"] = "pr_confirmed"
    checkpoint["pullRequest"] = {
        "result": result_kind,
        "forge": match.forge,
        "number": match.number,
        "url": match.url,
        "state": match.state,
        "recordedAt": utc_now(),
    }
    checkpoint["forgeExecutable"] = pinned
    checkpoint["bodySha256"] = sha256_bytes(body.encode("utf-8"))
    return _write_shipment(store, checkpoint)


def record_shipment(
    store: StateStore,
    repository: GitRepository,
    *,
    run_id: str,
    inspect_remote: Callable[[str, str, str, str], RemoteReadback],
    push_only: bool,
    publication_requested: bool,
    forge_identity: Mapping[str, Any] | ExecutableIdentity | None = None,
    runner: CommandRunner = default_command_runner,
) -> dict[str, Any]:
    shipment = _load_shipment(store, run_id)
    if shipment is None or shipment["push"] is None:
        raise PreconditionError("shipment lacks a confirmed remote commit")
    _assert_publication_authority(
        shipment, publication_requested=publication_requested
    )
    _assert_complete_build(store, repository, run_id)
    remote_url = _assert_remote_binding(repository, shipment, runner=runner)
    remote = inspect_remote(
        remote_url,
        shipment["headBranch"],
        shipment["targetBranch"],
        shipment["finalCommit"],
    )
    if remote.head_commit != shipment["finalCommit"]:
        raise StateInconsistencyError("remote commit readback no longer matches")
    if not push_only:
        if forge_identity is None:
            raise PreconditionError("forge executable identity is required")
        pinned = (
            forge_identity.as_dict()
            if isinstance(forge_identity, ExecutableIdentity)
            else dict(forge_identity)
        )
        if shipment["forgeExecutable"] != pinned:
            raise StateInconsistencyError(
                "forge executable differs from the prepared shipment"
            )
        if shipment["pullRequest"] is None:
            raise PreconditionError("shipment lacks a confirmed pull request")
        matches = _query_pull_requests(
            shipment,
            repository=repository,
            forge_identity=forge_identity,
            runner=runner,
        )
        expected = shipment["pullRequest"]
        if not any(
            item.number == expected["number"] and item.url == expected["url"]
            for item in matches
        ):
            raise StateInconsistencyError("pull-request readback no longer matches")
    elif shipment["pullRequest"] is not None:
        raise StateInconsistencyError("cannot convert a PR shipment to push-only")
    completed = dict(shipment)
    completed["status"] = "push_only_recorded" if push_only else "recorded"
    completed["completedAt"] = completed["completedAt"] or utc_now()
    result = _write_shipment(store, completed)
    run = store.load_run(run_id)
    if run["status"] == RunStatus.COMPLETE.value:
        store.mark_shipped(run_id)
    elif run["status"] != RunStatus.SHIPPED.value:
        raise StateInconsistencyError("run is not complete or shipped")
    return result


def cancel_shipment(
    store: StateStore,
    repository: GitRepository,
    *,
    run_id: str,
    inspect_remote: Callable[[str, str, str, str], RemoteReadback],
    inspect_pull_requests: Callable[[Mapping[str, Any]], Sequence[PullRequestReadback]],
    runner: CommandRunner = default_command_runner,
) -> bool:
    shipment = _load_shipment(store, run_id)
    if shipment is None:
        return False
    if (
        shipment["status"] != "authorized"
        or shipment["push"] is not None
        or shipment["pullRequest"] is not None
    ):
        raise PreconditionError("shipment cannot be cancelled after an external write")
    remote_url = _assert_remote_binding(repository, shipment, runner=runner)
    remote = inspect_remote(
        remote_url,
        shipment["headBranch"],
        shipment["targetBranch"],
        shipment["finalCommit"],
    )
    if remote.head_commit == shipment["finalCommit"] or inspect_pull_requests(shipment):
        raise PreconditionError("remote readback cannot prove that no write occurred")
    _shipment_path(store, run_id).unlink()
    return True


def inspect_remote_git(
    repository: GitRepository,
    remote: str,
    head_branch: str,
    target_branch: str,
    final_commit: str,
    *,
    runner: CommandRunner = default_command_runner,
) -> RemoteReadback:
    """Inspect remote refs and locally prove ancestry without fetching."""

    if (
        not isinstance(remote, str)
        or not remote
        or remote != remote.strip()
        or "\x00" in remote
        or remote.startswith("-")
    ):
        raise InvalidInputError("invalid remote URL")
    head_branch = _validate_name(head_branch, "head branch")
    target_branch = _validate_name(target_branch, "target branch")
    if not _COMMIT.fullmatch(final_commit):
        raise InvalidInputError("invalid final commit")
    result = runner(
        (
            repository.git_executable,
            "ls-remote",
            "--heads",
            remote,
            f"refs/heads/{head_branch}",
            f"refs/heads/{target_branch}",
        ),
        cwd=repository.root,
    )
    if result.returncode != 0:
        raise PreconditionError("remote-ref readback failed")
    refs: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2 or not _COMMIT.fullmatch(parts[0]):
            raise StateInconsistencyError("remote-ref readback was malformed")
        refs[parts[1]] = parts[0]
    head_commit = refs.get(f"refs/heads/{head_branch}")
    target_commit = refs.get(f"refs/heads/{target_branch}")

    def ancestry(ancestor: str | None) -> bool | None:
        if ancestor is None:
            return True
        if ancestor == final_commit:
            return True
        check = runner(
            (
                repository.git_executable,
                "merge-base",
                "--is-ancestor",
                ancestor,
                final_commit,
            ),
            cwd=repository.root,
        )
        if check.returncode == 0:
            return True
        if check.returncode == 1:
            return False
        return None

    return RemoteReadback(
        head_commit=head_commit,
        target_commit=target_commit,
        head_is_ancestor=ancestry(head_commit),
        target_is_ancestor=ancestry(target_commit),
    )


def resolve_authorized_forge_repository(remote_url: str) -> str:
    """Map the already-authorized Git remote URL to exact GitHub ``owner/name``."""

    url = remote_url.strip()
    if not url or "\n" in url or "\r" in url:
        raise StateInconsistencyError("authorized remote returned an invalid URL")
    host: str
    path: str
    if "://" in url:
        try:
            parsed = urlsplit(url)
        except ValueError as exc:
            raise PreconditionError("authorized remote URL is not forge-compatible") from exc
        host = (parsed.hostname or "").lower()
        if (
            parsed.scheme.lower() not in {"https", "ssh", "git+ssh"}
            or "%" in parsed.path
            or parsed.port not in {None, 443, 22}
            or parsed.query
            or parsed.fragment
            or parsed.password is not None
        ):
            raise PreconditionError("authorized remote URL is forge-ambiguous")
        path = parsed.path
    else:
        if any(character in url for character in ("?", "#", "%", "\\")):
            raise PreconditionError("authorized remote URL is forge-ambiguous")
        match = re.fullmatch(r"(?:(?:[^@/:]+)@)?([^/:]+):(.+)", url)
        if match is None:
            raise PreconditionError("authorized remote is not a supported GitHub URL")
        host = match.group(1).lower()
        path = match.group(2)
    if host != "github.com":
        raise PreconditionError(
            "authorized remote is not supported by the GitHub pull-request adapter"
        )
    normalized = path.strip("/")
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    parts = normalized.split("/")
    if (
        len(parts) != 2
        or any(not item or item in {".", ".."} for item in parts)
        or any(
            not re.fullmatch(r"[A-Za-z0-9_.-]+", item)
            for item in parts
        )
    ):
        raise PreconditionError("authorized GitHub remote path is invalid")
    return f"{parts[0]}/{parts[1]}"


# Serialize authorization and external checkpoints across processes.  The
# internal implementations remain separate so record_shipment can transition
# run state without attempting a nested, non-reentrant StateStore lock.
_authorize_shipment_unlocked = authorize_shipment
_reconcile_push_unlocked = reconcile_push
_reconcile_pull_request_unlocked = reconcile_pull_request
_cancel_shipment_unlocked = cancel_shipment


def authorize_shipment(
    store: StateStore,
    repository: GitRepository,
    plan: ShippingPlan,
    *,
    idempotency_key: str,
    publication_requested: bool,
) -> dict[str, Any]:
    with repository_lock(store.root, timeout=getattr(store, "lock_timeout", 0)):
        with run_lock(
            store.run_dir(plan.run_id), timeout=getattr(store, "lock_timeout", 0)
        ):
            return _authorize_shipment_unlocked(
                store,
                repository,
                plan,
                idempotency_key=idempotency_key,
                publication_requested=publication_requested,
            )


def reconcile_push(
    store: StateStore,
    repository: GitRepository,
    *,
    run_id: str,
    inspect_remote: Callable[[str, str, str, str], RemoteReadback],
    publication_requested: bool,
    final_gate: Callable[[Mapping[str, Any]], FinalGateEvidence],
    push_only: bool,
    title: str | None = None,
    body: str | None = None,
    draft: bool | None = None,
    forge_identity: Mapping[str, Any] | ExecutableIdentity | None = None,
    runner: CommandRunner = default_command_runner,
) -> dict[str, Any]:
    with repository_lock(store.root, timeout=getattr(store, "lock_timeout", 0)):
        with run_lock(store.run_dir(run_id), timeout=getattr(store, "lock_timeout", 0)):
            return _reconcile_push_unlocked(
                store,
                repository,
                run_id=run_id,
                inspect_remote=inspect_remote,
                publication_requested=publication_requested,
                final_gate=final_gate,
                push_only=push_only,
                title=title,
                body=body,
                draft=draft,
                forge_identity=forge_identity,
                runner=runner,
            )


def reconcile_pull_request(
    store: StateStore,
    repository: GitRepository,
    *,
    run_id: str,
    title: str,
    body: str,
    draft: bool,
    publication_requested: bool,
    final_gate: Callable[[Mapping[str, Any]], FinalGateEvidence],
    forge_identity: Mapping[str, Any] | ExecutableIdentity,
    runner: CommandRunner = default_command_runner,
) -> dict[str, Any]:
    with repository_lock(store.root, timeout=getattr(store, "lock_timeout", 0)):
        with run_lock(store.run_dir(run_id), timeout=getattr(store, "lock_timeout", 0)):
            return _reconcile_pull_request_unlocked(
                store,
                repository,
                run_id=run_id,
                title=title,
                body=body,
                draft=draft,
                publication_requested=publication_requested,
                final_gate=final_gate,
                forge_identity=forge_identity,
                runner=runner,
            )


def cancel_shipment(
    store: StateStore,
    repository: GitRepository,
    *,
    run_id: str,
    inspect_remote: Callable[[str, str, str, str], RemoteReadback],
    inspect_pull_requests: Callable[[Mapping[str, Any]], Sequence[PullRequestReadback]],
    runner: CommandRunner = default_command_runner,
) -> bool:
    with repository_lock(store.root, timeout=getattr(store, "lock_timeout", 0)):
        with run_lock(store.run_dir(run_id), timeout=getattr(store, "lock_timeout", 0)):
            return _cancel_shipment_unlocked(
                store,
                repository,
                run_id=run_id,
                inspect_remote=inspect_remote,
                inspect_pull_requests=inspect_pull_requests,
                runner=runner,
            )
