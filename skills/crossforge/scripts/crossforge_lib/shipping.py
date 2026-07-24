"""Explicit, durable, idempotent Crossforge shipping."""

from __future__ import annotations

import json
import hashlib
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

from .errors import InvalidInputError, PreconditionError, StateInconsistencyError
from .git import GitRepository, current_branch, is_dirty, resolve_commit
from .locking import repository_lock, run_lock
from .models import RunMode, RunStatus, TaskStatus
from .state import StateStore
from .util import atomic_write_json, canonical_json_bytes, utc_now

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_KEY = re.compile(r"^[0-9a-f]{32}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._/-]+$")
_SHIPMENT_FIELDS = {
    "schemaVersion",
    "repositoryIdentity",
    "runId",
    "status",
    "idempotencyKey",
    "remote",
    "headBranch",
    "targetBranch",
    "finalCommit",
    "authorizedAt",
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
    head_branch: str
    target_branch: str
    final_commit: str
    remote_readback: RemoteReadback
    dry_run: bool

    def authorization_tuple(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.repository_identity,
            self.run_id,
            self.remote,
            self.head_branch,
            self.target_branch,
            self.final_commit,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "repositoryIdentity": self.repository_identity,
            "runId": self.run_id,
            "remote": self.remote,
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


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


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
    if value["schemaVersion"] != 1:
        raise StateInconsistencyError("unsupported shipment schema")
    for field in (
        "repositoryIdentity",
        "runId",
        "remote",
        "headBranch",
        "targetBranch",
        "authorizedAt",
    ):
        if not isinstance(value[field], str) or not value[field]:
            raise StateInconsistencyError(f"shipment {field} is invalid")
    if not _COMMIT.fullmatch(value["finalCommit"] or ""):
        raise StateInconsistencyError("shipment finalCommit is invalid")
    if not _KEY.fullmatch(value["idempotencyKey"] or ""):
        raise StateInconsistencyError("shipment idempotencyKey is invalid")
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
    validate_final_gate_evidence(run, final_gate(run))
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
    remote_state = inspect_remote(
        selected_remote, head_branch, selected_target, final_commit
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
        head_branch=head_branch,
        target_branch=selected_target,
        final_commit=final_commit,
        remote_readback=remote_state,
        dry_run=dry_run,
    )


def authorize_shipment(
    store: StateStore,
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
    expected = (
        run["repositoryIdentity"],
        run["runId"],
        plan.remote,
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
            existing["headBranch"],
            existing["targetBranch"],
            existing["finalCommit"],
        )
        if existing_tuple == expected and existing["idempotencyKey"] == idempotency_key:
            return existing
        raise StateInconsistencyError("an immutable shipment authorization already exists")
    value = {
        "schemaVersion": 1,
        "repositoryIdentity": plan.repository_identity,
        "runId": plan.run_id,
        "status": "authorized",
        "idempotencyKey": idempotency_key,
        "remote": plan.remote,
        "headBranch": plan.head_branch,
        "targetBranch": plan.target_branch,
        "finalCommit": plan.final_commit,
        "authorizedAt": utc_now(),
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
    runner: CommandRunner = default_command_runner,
) -> dict[str, Any]:
    shipment = _load_shipment(store, run_id)
    if shipment is None:
        raise PreconditionError("shipment is not authorized")
    run = _assert_complete_build(store, repository, run_id)
    if run["repositoryIdentity"] != shipment["repositoryIdentity"]:
        raise StateInconsistencyError("repository identity changed after authorization")
    observed = inspect_remote(
        shipment["remote"],
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
            shipment["remote"],
            f"{shipment['finalCommit']}:refs/heads/{shipment['headBranch']}",
        )
        result = runner(argv, cwd=repository.root)
        if result.returncode != 0:
            raise PreconditionError("authorized push failed")
        performed = True
        observed = inspect_remote(
            shipment["remote"],
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
    return _write_shipment(store, checkpoint)


def _query_pull_requests(
    shipment: Mapping[str, Any],
    *,
    repository: GitRepository,
    gh_executable: str,
    runner: CommandRunner,
) -> list[PullRequestReadback]:
    forge_repository = resolve_authorized_forge_repository(
        repository, str(shipment["remote"]), runner=runner
    )
    argv = (
        gh_executable,
        "pr",
        "list",
        "--repo",
        forge_repository,
        "--state",
        "all",
        "--head",
        shipment["headBranch"],
        "--base",
        shipment["targetBranch"],
        "--json",
        "number,url,state,headRefName,baseRefName,headRefOid",
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
        if (
            item.get("headRefName") == shipment["headBranch"]
            and item.get("baseRefName") == shipment["targetBranch"]
            and item.get("headRefOid") in {None, shipment["finalCommit"]}
        ):
            matches.append(
                PullRequestReadback(
                    forge="github",
                    number=int(item["number"]),
                    url=str(item["url"]),
                    state=str(item["state"]).lower(),
                    head_branch=str(item["headRefName"]),
                    target_branch=str(item["baseRefName"]),
                    head_commit=item.get("headRefOid"),
                )
            )
    return matches


def inspect_pull_requests(
    shipment: Mapping[str, Any],
    *,
    repository: GitRepository,
    gh_executable: str = "gh",
    runner: CommandRunner = default_command_runner,
) -> tuple[PullRequestReadback, ...]:
    """Read matching open and closed PRs without changing forge state."""

    return tuple(
        _query_pull_requests(
            shipment,
            repository=repository,
            gh_executable=gh_executable,
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
    gh_executable: str = "gh",
    runner: CommandRunner = default_command_runner,
) -> dict[str, Any]:
    shipment = _load_shipment(store, run_id)
    if shipment is None or shipment["push"] is None:
        raise PreconditionError("remote commit must be confirmed before PR creation")
    run = _assert_complete_build(store, repository, run_id)
    if (
        run["repositoryIdentity"] != shipment["repositoryIdentity"]
        or run["currentCommit"] != shipment["finalCommit"]
    ):
        raise StateInconsistencyError("durable run changed after shipment authorization")
    matches = _query_pull_requests(
        shipment,
        repository=repository,
        gh_executable=gh_executable,
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
                resolve_authorized_forge_repository(
                    repository, str(shipment["remote"]), runner=runner
                ),
                "--head",
                shipment["headBranch"],
                "--base",
                shipment["targetBranch"],
                "--title",
                title,
                "--body-file",
                str(body_file),
            ]
            if draft:
                argv.append("--draft")
            result = runner(tuple(argv), cwd=repository.root)
            if result.returncode != 0:
                raise PreconditionError("pull-request creation failed")
        created = True
        matches = _query_pull_requests(
            shipment,
            repository=repository,
            gh_executable=gh_executable,
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
    return _write_shipment(store, checkpoint)


def record_shipment(
    store: StateStore,
    repository: GitRepository,
    *,
    run_id: str,
    inspect_remote: Callable[[str, str, str, str], RemoteReadback],
    push_only: bool,
    gh_executable: str = "gh",
    runner: CommandRunner = default_command_runner,
) -> dict[str, Any]:
    shipment = _load_shipment(store, run_id)
    if shipment is None or shipment["push"] is None:
        raise PreconditionError("shipment lacks a confirmed remote commit")
    _assert_complete_build(store, repository, run_id)
    remote = inspect_remote(
        shipment["remote"],
        shipment["headBranch"],
        shipment["targetBranch"],
        shipment["finalCommit"],
    )
    if remote.head_commit != shipment["finalCommit"]:
        raise StateInconsistencyError("remote commit readback no longer matches")
    if not push_only:
        if shipment["pullRequest"] is None:
            raise PreconditionError("shipment lacks a confirmed pull request")
        matches = _query_pull_requests(
            shipment,
            repository=repository,
            gh_executable=gh_executable,
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
    *,
    run_id: str,
    inspect_remote: Callable[[str, str, str, str], RemoteReadback],
    inspect_pull_requests: Callable[[Mapping[str, Any]], Sequence[PullRequestReadback]],
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
    remote = inspect_remote(
        shipment["remote"],
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

    remote = _validate_name(remote, "remote")
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


def resolve_authorized_forge_repository(
    repository: GitRepository,
    remote: str,
    *,
    runner: CommandRunner = default_command_runner,
) -> str:
    """Resolve the authorized Git remote to an exact GitHub ``owner/name``."""

    remote = _validate_name(remote, "remote")
    result = runner(
        (repository.git_executable, "remote", "get-url", remote),
        cwd=repository.root,
    )
    if result.returncode != 0:
        raise PreconditionError("authorized remote URL could not be resolved")
    url = result.stdout.strip()
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
        path = parsed.path
    else:
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
        or any(re.search(r"[\x00-\x1f\x7f]", item) for item in parts)
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
    runner: CommandRunner = default_command_runner,
) -> dict[str, Any]:
    with repository_lock(store.root, timeout=getattr(store, "lock_timeout", 0)):
        with run_lock(store.run_dir(run_id), timeout=getattr(store, "lock_timeout", 0)):
            return _reconcile_push_unlocked(
                store,
                repository,
                run_id=run_id,
                inspect_remote=inspect_remote,
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
    gh_executable: str = "gh",
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
                gh_executable=gh_executable,
                runner=runner,
            )


def cancel_shipment(
    store: StateStore,
    *,
    run_id: str,
    inspect_remote: Callable[[str, str, str, str], RemoteReadback],
    inspect_pull_requests: Callable[[Mapping[str, Any]], Sequence[PullRequestReadback]],
) -> bool:
    with repository_lock(store.root, timeout=getattr(store, "lock_timeout", 0)):
        with run_lock(store.run_dir(run_id), timeout=getattr(store, "lock_timeout", 0)):
            return _cancel_shipment_unlocked(
                store,
                run_id=run_id,
                inspect_remote=inspect_remote,
                inspect_pull_requests=inspect_pull_requests,
            )
