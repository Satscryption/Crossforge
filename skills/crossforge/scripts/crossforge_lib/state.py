"""Durable repository-common state for Crossforge runs."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .errors import PreconditionError, StateInconsistencyError
from .locking import repository_lock, run_lock
from .models import RunMode, RunStatus, TaskStatus
from .util import (
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    canonical_json_bytes,
    ensure_private_directory,
    sha256_bytes,
    sha256_file,
    utc_now,
)


_RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUN_STATUSES = {item.value for item in RunStatus}
_RUN_MODES = {item.value for item in RunMode}
_TASK_STATUSES = {item.value for item in TaskStatus}

RUN_TRANSITIONS: Mapping[str, frozenset[str]] = {
    RunStatus.ACTIVE.value: frozenset(
        {
            RunStatus.BLOCKED.value,
            RunStatus.COMPLETE.value,
            RunStatus.ABANDONED.value,
        }
    ),
    RunStatus.BLOCKED.value: frozenset(
        {RunStatus.ACTIVE.value, RunStatus.ABANDONED.value}
    ),
    RunStatus.COMPLETE.value: frozenset({RunStatus.SHIPPED.value}),
    RunStatus.SHIPPED.value: frozenset(),
    RunStatus.ABANDONED.value: frozenset(),
}

TASK_TRANSITIONS: Mapping[str, frozenset[str]] = {
    TaskStatus.PENDING.value: frozenset(
        {TaskStatus.IN_PROGRESS.value, TaskStatus.BLOCKED.value}
    ),
    TaskStatus.IN_PROGRESS.value: frozenset(
        {TaskStatus.CANDIDATE_READY.value, TaskStatus.BLOCKED.value}
    ),
    TaskStatus.CANDIDATE_READY.value: frozenset(
        {TaskStatus.ACCEPTED.value, TaskStatus.BLOCKED.value}
    ),
    TaskStatus.ACCEPTED.value: frozenset(
        {
            TaskStatus.COMMITTED.value,
            TaskStatus.COMPLETE.value,
            TaskStatus.BLOCKED.value,
        }
    ),
    TaskStatus.COMMITTED.value: frozenset(
        {TaskStatus.COMPLETE.value, TaskStatus.BLOCKED.value}
    ),
    TaskStatus.BLOCKED.value: frozenset({TaskStatus.IN_PROGRESS.value}),
    TaskStatus.COMPLETE.value: frozenset(),
}

_RUN_FIELDS = {
    "schemaVersion",
    "runId",
    "status",
    "mode",
    "repositoryRoot",
    "repositoryIdentity",
    "gitCommonDir",
    "orchestrationGitDir",
    "branch",
    "branchCreatedByCrossforge",
    "targetRemote",
    "targetBranch",
    "defaultBranch",
    "startCommit",
    "currentCommit",
    "planJsonPath",
    "planMarkdownPath",
    "planSha256",
    "planApproval",
    "globalVerificationCommands",
    "budget",
    "maximumProviderInvocationsPerTask",
    "strategy",
    "noCommit",
    "keepWorktrees",
    "gateSandbox",
    "providers",
    "activeTaskId",
    "completedTaskIds",
    "blockedReason",
    "createdAt",
    "updatedAt",
    "completedAt",
}

_TASK_FIELDS = {
    "id",
    "title",
    "status",
    "baseCommit",
    "risk",
    "taskClass",
    "suggestedStrategy",
    "dependsOn",
    "allowedFiles",
    "objective",
    "interfaces",
    "constraints",
    "approvedBinaryContext",
    "approvedSymlinks",
    "verificationCommands",
    "doneWhen",
    "routing",
    "selectedCandidate",
    "commit",
    "attempts",
    "createdAt",
    "updatedAt",
}
_TASK_OPTIONAL_FIELDS = {
    "selectedCandidatePath",
    "selectedGateEvidencePath",
    "selectedGateEvidenceSha256",
    "selectedInvocationEvidencePath",
    "selectedInvocationEvidenceSha256",
    "acceptanceIntent",
}
_SELECTION_BOOKKEEPING_FIELDS = frozenset(
    {"routing", "attempts", "updatedAt", "acceptanceIntent"}
)
_ACCEPTANCE_INTENT_FIELDS = {
    "schemaVersion",
    "provider",
    "candidatePath",
    "baseCommit",
    "capturedPatchSha256",
    "verifiedScopedTreeSha256",
    "quarantinePathsSha256",
    "selectedGateEvidenceSha256",
    "commitMessageSha256",
    "noCommit",
}


def _selection_stable_task(task: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in task.items()
        if key not in _SELECTION_BOOKKEEPING_FIELDS
    }


def _validate_acceptance_intent(
    value: object,
    *,
    label: str,
) -> dict[str, Any] | None:
    if value is None:
        return None
    intent = _require_object(value, label)
    _require_exact_fields(intent, _ACCEPTANCE_INTENT_FIELDS, label)
    if intent["schemaVersion"] != 1:
        raise StateInconsistencyError(f"{label}.schemaVersion is invalid")
    for field in ("provider", "candidatePath", "baseCommit"):
        _require_string(intent[field], f"{label}.{field}")
    for field in (
        "capturedPatchSha256",
        "verifiedScopedTreeSha256",
        "quarantinePathsSha256",
        "selectedGateEvidenceSha256",
        "commitMessageSha256",
    ):
        if (
            not isinstance(intent[field], str)
            or not _SHA256.fullmatch(intent[field])
        ):
            raise StateInconsistencyError(f"{label}.{field} is invalid")
    if not isinstance(intent["noCommit"], bool):
        raise StateInconsistencyError(f"{label}.noCommit must be boolean")
    return intent


def generate_run_id(now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    moment = moment.astimezone(timezone.utc)
    return f"{moment.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"


def validate_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise StateInconsistencyError("invalid Crossforge run ID")
    try:
        datetime.strptime(run_id[:16], "%Y%m%dT%H%M%SZ")
    except ValueError as exc:
        raise StateInconsistencyError("invalid timestamp in Crossforge run ID") from exc
    return run_id


def _require_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StateInconsistencyError(f"{label} must be a JSON object")
    return value


def _require_exact_fields(
    value: Mapping[str, Any], expected: set[str], label: str
) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        raise StateInconsistencyError(
            f"{label} has missing or unknown fields",
            details={"missing": missing, "unknown": extra},
        )


def _require_string(value: object, label: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, str) or not value:
        raise StateInconsistencyError(f"{label} must be a non-empty string")


def _require_list_of_strings(value: object, label: str) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise StateInconsistencyError(f"{label} must be an array of strings")


def _validate_gate_commands(value: object, label: str) -> None:
    if not isinstance(value, list):
        raise StateInconsistencyError(f"{label} must be an array")
    for index, command in enumerate(value):
        item = _require_object(command, f"{label}[{index}]")
        _require_exact_fields(item, {"argv", "timeoutSeconds"}, f"{label}[{index}]")
        if (
            not isinstance(item["argv"], list)
            or not item["argv"]
            or any(not isinstance(arg, str) or not arg for arg in item["argv"])
        ):
            raise StateInconsistencyError(f"{label}[{index}].argv is invalid")
        timeout = item["timeoutSeconds"]
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
            raise StateInconsistencyError(
                f"{label}[{index}].timeoutSeconds is invalid"
            )


def validate_run_record(value: object) -> dict[str, Any]:
    run = _require_object(value, "run.json")
    _require_exact_fields(run, _RUN_FIELDS, "run.json")
    if run["schemaVersion"] != 1:
        raise StateInconsistencyError("unsupported run.json schemaVersion")
    validate_run_id(run["runId"])
    if run["status"] not in _RUN_STATUSES:
        raise StateInconsistencyError("run.json has an invalid status")
    if run["mode"] not in _RUN_MODES:
        raise StateInconsistencyError("run.json has an invalid mode")

    for field in (
        "repositoryRoot",
        "repositoryIdentity",
        "gitCommonDir",
        "orchestrationGitDir",
        "planJsonPath",
        "planMarkdownPath",
        "planSha256",
        "budget",
        "strategy",
        "createdAt",
        "updatedAt",
    ):
        _require_string(run[field], f"run.json.{field}")
    for field in ("branch", "targetRemote", "targetBranch", "defaultBranch"):
        _require_string(run[field], f"run.json.{field}", nullable=True)
    for field in ("startCommit", "currentCommit"):
        if run[field] is not None and (
            not isinstance(run[field], str) or not _COMMIT.fullmatch(run[field])
        ):
            raise StateInconsistencyError(f"run.json.{field} is not a commit ID")
    if not _SHA256.fullmatch(run["planSha256"]):
        raise StateInconsistencyError("run.json.planSha256 is not SHA-256")
    for field in ("branchCreatedByCrossforge", "noCommit", "keepWorktrees"):
        if run[field] is not None and not isinstance(run[field], bool):
            raise StateInconsistencyError(f"run.json.{field} must be boolean or null")
    maximum = run["maximumProviderInvocationsPerTask"]
    if maximum is not None and (
        isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0
    ):
        raise StateInconsistencyError(
            "run.json.maximumProviderInvocationsPerTask is invalid"
        )
    _validate_gate_commands(run["globalVerificationCommands"], "run.json gates")
    _require_list_of_strings(run["completedTaskIds"], "run.json.completedTaskIds")
    if len(set(run["completedTaskIds"])) != len(run["completedTaskIds"]):
        raise StateInconsistencyError("run.json.completedTaskIds contains duplicates")
    _require_string(run["activeTaskId"], "run.json.activeTaskId", nullable=True)
    _require_string(run["blockedReason"], "run.json.blockedReason", nullable=True)
    _require_string(run["completedAt"], "run.json.completedAt", nullable=True)
    if not isinstance(run["providers"], dict):
        raise StateInconsistencyError("run.json.providers must be an object")
    if run["gateSandbox"] is not None and not isinstance(run["gateSandbox"], dict):
        raise StateInconsistencyError("run.json.gateSandbox must be an object or null")
    approval = _require_object(run["planApproval"], "run.json.planApproval")
    _require_exact_fields(
        approval,
        {"approved", "approvedBy", "approvedAt", "approvedPlanSha256"},
        "run.json.planApproval",
    )
    if not isinstance(approval["approved"], bool):
        raise StateInconsistencyError("run.json.planApproval.approved must be boolean")
    _require_string(approval["approvedBy"], "run.json.planApproval.approvedBy")
    _require_string(approval["approvedAt"], "run.json.planApproval.approvedAt")
    _require_string(
        approval["approvedPlanSha256"],
        "run.json.planApproval.approvedPlanSha256",
    )
    if approval["approvedPlanSha256"] != run["planSha256"]:
        raise StateInconsistencyError("plan approval is not bound to planSha256")

    mode = run["mode"]
    if mode == RunMode.BUILD.value:
        for field in ("branch", "targetBranch", "defaultBranch", "startCommit", "currentCommit"):
            _require_string(run[field], f"build run.json.{field}")
        if run["status"] == RunStatus.COMPLETE.value and run["completedAt"] is None:
            raise StateInconsistencyError("complete run is missing completedAt")
    else:
        if run["status"] not in {RunStatus.ACTIVE.value, RunStatus.COMPLETE.value}:
            raise StateInconsistencyError("plan/review run has an invalid status")
        if run["activeTaskId"] is not None or run["completedTaskIds"]:
            raise StateInconsistencyError("plan/review run contains build task state")
    return run


def validate_tasks_record(value: object) -> dict[str, Any]:
    record = _require_object(value, "tasks.json")
    _require_exact_fields(record, {"schemaVersion", "tasks"}, "tasks.json")
    if record["schemaVersion"] != 1 or not isinstance(record["tasks"], list):
        raise StateInconsistencyError("invalid tasks.json schema")
    seen: set[str] = set()
    for index, raw_task in enumerate(record["tasks"]):
        task = _require_object(raw_task, f"tasks[{index}]")
        missing = sorted(_TASK_FIELDS - set(task))
        unknown = sorted(set(task) - _TASK_FIELDS - _TASK_OPTIONAL_FIELDS)
        if missing or unknown:
            raise StateInconsistencyError(
                f"tasks[{index}] has missing or unknown fields",
                details={"missing": missing, "unknown": unknown},
            )
        _require_string(task["id"], f"tasks[{index}].id")
        if task["id"] in seen:
            raise StateInconsistencyError(f"duplicate task ID: {task['id']}")
        seen.add(task["id"])
        if task["status"] not in _TASK_STATUSES:
            raise StateInconsistencyError(f"task {task['id']} has an invalid status")
        for field in ("title", "risk", "taskClass", "suggestedStrategy", "objective", "createdAt", "updatedAt"):
            _require_string(task[field], f"task {task['id']}.{field}")
        if task["baseCommit"] is not None and (
            not isinstance(task["baseCommit"], str)
            or not _COMMIT.fullmatch(task["baseCommit"])
        ):
            raise StateInconsistencyError(f"task {task['id']} has an invalid baseCommit")
        for field in (
            "dependsOn",
            "allowedFiles",
            "interfaces",
            "constraints",
            "doneWhen",
        ):
            _require_list_of_strings(task[field], f"task {task['id']}.{field}")
        for field in ("approvedBinaryContext", "approvedSymlinks"):
            if not isinstance(task[field], list):
                raise StateInconsistencyError(f"task {task['id']}.{field} must be an array")
        _validate_gate_commands(
            task["verificationCommands"], f"task {task['id']}.verificationCommands"
        )
        attempts = _require_object(task["attempts"], f"task {task['id']}.attempts")
        _require_exact_fields(attempts, {"codex", "grok", "claude"}, "task attempts")
        if any(
            isinstance(count, bool) or not isinstance(count, int) or count < 0
            for count in attempts.values()
        ):
            raise StateInconsistencyError(f"task {task['id']} has invalid attempts")
        _require_string(task["commit"], f"task {task['id']}.commit", nullable=True)
        for field in (
            "selectedCandidatePath",
            "selectedGateEvidencePath",
            "selectedInvocationEvidencePath",
        ):
            _require_string(
                task.get(field),
                f"task {task['id']}.{field}",
                nullable=True,
            )
        for field in (
            "selectedGateEvidenceSha256",
            "selectedInvocationEvidenceSha256",
        ):
            selected_evidence = task.get(field)
            if selected_evidence is not None and (
                not isinstance(selected_evidence, str)
                or not _SHA256.fullmatch(selected_evidence)
            ):
                raise StateInconsistencyError(
                    f"task {task['id']}.{field} is invalid"
                )
        intent = _validate_acceptance_intent(
            task.get("acceptanceIntent"),
            label=f"task {task['id']}.acceptanceIntent",
        )
        selection_statuses = {
            TaskStatus.CANDIDATE_READY.value,
            TaskStatus.ACCEPTED.value,
            TaskStatus.COMMITTED.value,
        }
        if task["status"] in selection_statuses:
            for field in (
                "selectedCandidate",
                "selectedCandidatePath",
                "selectedGateEvidencePath",
                "selectedGateEvidenceSha256",
            ):
                if not task.get(field):
                    raise StateInconsistencyError(
                        f"task {task['id']}.{field} is required "
                        f"when status is {task['status']}"
                    )
            if task["selectedCandidate"] in {"codex", "grok"}:
                for field in (
                    "selectedInvocationEvidencePath",
                    "selectedInvocationEvidenceSha256",
                ):
                    if not task.get(field):
                        raise StateInconsistencyError(
                            f"task {task['id']}.{field} is required "
                            f"for external-provider selection"
                        )
        if intent is not None:
            if task["status"] not in {
                TaskStatus.CANDIDATE_READY.value,
                TaskStatus.ACCEPTED.value,
                TaskStatus.COMMITTED.value,
                TaskStatus.COMPLETE.value,
                TaskStatus.BLOCKED.value,
            }:
                raise StateInconsistencyError(
                    f"task {task['id']}.acceptanceIntent requires "
                    "selected or accepted status"
                )
            expected = (
                task["selectedCandidate"],
                task["selectedCandidatePath"],
                task["baseCommit"],
                task["selectedGateEvidenceSha256"],
            )
            observed = (
                intent["provider"],
                intent["candidatePath"],
                intent["baseCommit"],
                intent["selectedGateEvidenceSha256"],
            )
            if observed != expected:
                raise StateInconsistencyError(
                    f"task {task['id']}.acceptanceIntent is not bound "
                    "to the selected candidate"
                )
        if (
            task["status"]
            in {
                TaskStatus.ACCEPTED.value,
                TaskStatus.COMMITTED.value,
            }
            and intent is None
        ):
            raise StateInconsistencyError(
                f"task {task['id']}.acceptanceIntent is required "
                f"when status is {task['status']}"
            )
    dependencies = {
        dependency
        for task in record["tasks"]
        for dependency in task["dependsOn"]
    }
    unknown = sorted(dependencies - seen)
    if unknown:
        raise StateInconsistencyError(
            "tasks.json contains unknown dependencies", details={"taskIds": unknown}
        )
    return record


_PLAN_TASK_POLICY_FIELDS = (
    "id",
    "title",
    "risk",
    "taskClass",
    "suggestedStrategy",
    "dependsOn",
    "allowedFiles",
    "objective",
    "interfaces",
    "constraints",
    "approvedBinaryContext",
    "approvedSymlinks",
    "verificationCommands",
    "doneWhen",
)


def validate_plan_state_binding(
    run: Mapping[str, Any],
    plan: Mapping[str, Any],
    tasks: Mapping[str, Any],
) -> None:
    """Prove that durable build policy is derived from the approved plan."""

    actual_hash = sha256_bytes(canonical_json_bytes(dict(plan)))
    if actual_hash != run["planSha256"]:
        raise StateInconsistencyError(
            "supplied canonical plan does not match run.planSha256",
            details={"expected": run["planSha256"], "actual": actual_hash},
        )
    approval = run["planApproval"]
    if (
        approval["approved"] is not True
        or approval["approvedPlanSha256"] != actual_hash
    ):
        raise StateInconsistencyError("plan approval is not bound to supplied plan bytes")
    if run["mode"] != RunMode.BUILD.value:
        return
    plan_tasks = plan.get("tasks")
    if not isinstance(plan_tasks, list):
        raise StateInconsistencyError("approved build plan is missing tasks")
    materialized = tasks["tasks"]
    if len(plan_tasks) != len(materialized):
        raise StateInconsistencyError("materialized tasks do not match approved plan")
    for index, (planned, task) in enumerate(zip(plan_tasks, materialized)):
        if not isinstance(planned, Mapping):
            raise StateInconsistencyError(f"approved plan task {index} is invalid")
        for field in _PLAN_TASK_POLICY_FIELDS:
            if planned.get(field) != task.get(field):
                raise StateInconsistencyError(
                    "materialized task policy differs from approved plan",
                    details={"taskIndex": index, "field": field},
                )
    if plan.get("globalVerificationCommands") != run["globalVerificationCommands"]:
        raise StateInconsistencyError(
            "run global verification commands differ from approved plan"
        )


class StateStore:
    """Owns one repository's durable state under its common Git directory."""

    def __init__(
        self,
        git_common_dir: str | os.PathLike[str],
        *,
        lock_timeout: float = 0,
    ) -> None:
        common = Path(git_common_dir).expanduser()
        if not common.is_absolute():
            raise PreconditionError("git common directory must be absolute")
        self.git_common_dir = common.resolve()
        self.root = self.git_common_dir / "crossforge"
        self.runs_dir = self.root / "runs"
        self.lock_timeout = lock_timeout

    def initialize(self) -> Path:
        ensure_private_directory(self.root)
        ensure_private_directory(self.runs_dir)
        self._validate_private_path(self.root, directory=True)
        self._validate_private_path(self.runs_dir, directory=True)
        return self.root

    @staticmethod
    def _validate_private_path(path: Path, *, directory: bool) -> os.stat_result:
        try:
            info = path.lstat()
        except FileNotFoundError as exc:
            raise StateInconsistencyError(f"required state path is missing: {path}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise StateInconsistencyError(f"state path is a symlink: {path}")
        expected = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected(info.st_mode):
            raise StateInconsistencyError(f"state path has the wrong type: {path}")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise StateInconsistencyError(f"state path is owned by another user: {path}")
        if info.st_mode & 0o077:
            raise StateInconsistencyError(f"state path is accessible by group or others: {path}")
        return info

    def run_dir(self, run_id: str) -> Path:
        validate_run_id(run_id)
        return self.runs_dir / run_id

    def _read_json(self, path: Path) -> Any:
        self._validate_private_path(path, directory=False)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StateInconsistencyError(f"invalid durable JSON: {path}") from exc

    def _read_pointer(self, name: str) -> str | None:
        path = self.root / name
        try:
            self._validate_private_path(path, directory=False)
        except StateInconsistencyError:
            if not path.exists() and not path.is_symlink():
                return None
            raise
        try:
            contents = path.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as exc:
            raise StateInconsistencyError(f"invalid {name} pointer") from exc
        if not contents.endswith("\n") or contents.count("\n") != 1:
            raise StateInconsistencyError(f"invalid {name} pointer format")
        return validate_run_id(contents[:-1])

    def _write_pointer(self, name: str, run_id: str) -> None:
        validate_run_id(run_id)
        atomic_write_text(self.root / name, run_id + "\n")

    def _remove_pointer(self, name: str, *, expected: str | None = None) -> None:
        path = self.root / name
        current = self._read_pointer(name)
        if current is None:
            return
        if expected is not None and current != expected:
            raise StateInconsistencyError(
                f"{name} changed unexpectedly",
                details={"expected": expected, "actual": current},
            )
        path.unlink()
        self._fsync_root()

    def _fsync_root(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(self.root, flags)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    def active_run_id(self) -> str | None:
        self.initialize()
        return self._read_pointer("active")

    def latest_complete_run_id(self) -> str | None:
        self.initialize()
        return self._read_pointer("latest-complete")

    def load_run(self, run_id: str) -> dict[str, Any]:
        self._recover_block_transaction(run_id)
        path = self.run_dir(run_id) / "run.json"
        run = validate_run_record(self._read_json(path))
        if run["runId"] != run_id:
            raise StateInconsistencyError("run directory and run.json ID disagree")
        return run

    def load_tasks(self, run_id: str) -> dict[str, Any]:
        self._recover_block_transaction(run_id)
        return validate_tasks_record(self._read_json(self.run_dir(run_id) / "tasks.json"))

    def _recover_block_transaction(self, run_id: str) -> None:
        """Finish an interrupted two-record exhausted-attempt transition."""

        transaction = self.run_dir(run_id) / "attempt-block-transaction.json"
        if not transaction.exists() and not transaction.is_symlink():
            return
        value = self._read_json(transaction)
        if (
            not isinstance(value, dict)
            or set(value) != {"schemaVersion", "run", "tasks"}
            or value.get("schemaVersion") != 1
        ):
            raise StateInconsistencyError(
                "invalid exhausted-attempt transaction journal"
            )
        run = validate_run_record(value["run"])
        tasks = validate_tasks_record(value["tasks"])
        if run["runId"] != run_id:
            raise StateInconsistencyError(
                "attempt-block transaction run ID differs"
            )
        atomic_write_json(self.run_dir(run_id) / "tasks.json", tasks)
        atomic_write_json(self.run_dir(run_id) / "run.json", run)
        transaction.unlink()
        self._fsync_directory(self.run_dir(run_id))

    def initialize_run(
        self,
        run: Mapping[str, Any],
        *,
        plan: Mapping[str, Any],
        plan_markdown: str,
        tasks: Mapping[str, Any] | None = None,
    ) -> Path:
        self.initialize()
        run_value = validate_run_record(dict(run))
        run_id = run_value["runId"]
        run_directory = self.run_dir(run_id)
        if Path(run_value["gitCommonDir"]).resolve() != self.git_common_dir:
            raise StateInconsistencyError(
                "run gitCommonDir does not match the state store"
            )
        task_value = dict(tasks or {"schemaVersion": 1, "tasks": []})
        validate_tasks_record(task_value)
        validate_plan_state_binding(run_value, plan, task_value)
        with repository_lock(self.root, timeout=self.lock_timeout):
            if run_directory.exists() or run_directory.is_symlink():
                raise StateInconsistencyError(f"run already exists: {run_id}")
            if run_value["mode"] == RunMode.BUILD.value:
                if run_value["status"] != RunStatus.ACTIVE.value:
                    raise StateInconsistencyError("new build run must be active")
                active = self._read_pointer("active")
                if active is not None:
                    active_run = self.load_run(active)
                    if active_run["status"] in {
                        RunStatus.ACTIVE.value,
                        RunStatus.BLOCKED.value,
                    }:
                        raise PreconditionError(
                            "another build run is already active",
                            details={"runId": active},
                        )
                    raise StateInconsistencyError(
                        "active pointer names a non-active run",
                        details={"runId": active, "status": active_run["status"]},
                    )
            staging = Path(
                tempfile.mkdtemp(prefix=f".{run_id}.", dir=self.runs_dir)
            )
            os.chmod(staging, 0o700)
            try:
                for directory in (
                    staging / "locks",
                    staging / "allowlists",
                    staging / "evidence",
                ):
                    ensure_private_directory(directory)
                atomic_write_json(staging / "run.json", run_value)
                atomic_write_json(staging / "plan.json", dict(plan))
                atomic_write_text(staging / "plan.md", plan_markdown)
                atomic_write_json(staging / "tasks.json", task_value)
                atomic_write_text(staging / "tasks.md", "")
                atomic_write_text(staging / "interfaces.md", "")
                atomic_write_text(staging / "decisions.md", "")
                atomic_write_json(
                    staging / "worktrees.json",
                    {"schemaVersion": 1, "worktreeRoot": "", "entries": []},
                )
                os.replace(staging, run_directory)
                self._fsync_directory(self.runs_dir)
            except BaseException:
                if staging.exists():
                    shutil.rmtree(staging)
                raise
            if run_value["mode"] == RunMode.BUILD.value:
                self._write_pointer("active", run_id)
        return run_directory

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(directory, flags)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    def _write_run(self, run_id: str, value: Mapping[str, Any]) -> None:
        validated = validate_run_record(dict(value))
        if validated["runId"] != run_id:
            raise StateInconsistencyError("cannot change a run ID")
        atomic_write_json(self.run_dir(run_id) / "run.json", validated)

    def _transition_run_locked(
        self,
        run_id: str,
        target_status: str,
        updates: Mapping[str, Any],
    ) -> dict[str, Any]:
        run = self.load_run(run_id)
        current = run["status"]
        if current == target_status:
            if all(run.get(key) == value for key, value in updates.items()):
                return run
            raise StateInconsistencyError(
                "idempotent run transition does not match durable state"
            )
        if target_status not in RUN_TRANSITIONS[current]:
            raise StateInconsistencyError(
                f"invalid run transition: {current} -> {target_status}"
            )
        if run["mode"] != RunMode.BUILD.value and target_status != RunStatus.COMPLETE.value:
            raise StateInconsistencyError("plan/review runs may only become complete")
        updated = dict(run)
        updated.update(updates)
        updated["status"] = target_status
        updated["updatedAt"] = updates.get("updatedAt", utc_now())
        if target_status == RunStatus.COMPLETE.value:
            updated["completedAt"] = updates.get("completedAt", utc_now())
            updated["activeTaskId"] = None
            updated["blockedReason"] = None
        elif target_status == RunStatus.BLOCKED.value:
            _require_string(updated.get("blockedReason"), "blockedReason")
        elif target_status == RunStatus.ACTIVE.value:
            updated["blockedReason"] = None
        self._write_run(run_id, updated)
        return updated

    def transition_run(
        self,
        run_id: str,
        target_status: RunStatus | str,
        *,
        updates: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.initialize()
        target = (
            target_status.value if isinstance(target_status, RunStatus) else target_status
        )
        if target not in _RUN_STATUSES:
            raise StateInconsistencyError(f"unknown run status: {target}")
        run_directory = self.run_dir(run_id)
        with repository_lock(self.root, timeout=self.lock_timeout):
            with run_lock(run_directory, timeout=self.lock_timeout):
                current = self.load_run(run_id)
                result = self._transition_run_locked(run_id, target, updates or {})
                if (
                    current["mode"] == RunMode.BUILD.value
                    and target == RunStatus.COMPLETE.value
                ):
                    self._write_pointer("latest-complete", run_id)
                    self._remove_pointer("active", expected=run_id)
                elif target == RunStatus.ABANDONED.value:
                    self._remove_pointer("active", expected=run_id)
                elif target == RunStatus.SHIPPED.value:
                    if self._read_pointer("latest-complete") == run_id:
                        replacement = self._newest_unshipped_complete(exclude=run_id)
                        if replacement is None:
                            self._remove_pointer("latest-complete", expected=run_id)
                        else:
                            self._write_pointer("latest-complete", replacement)
                return result

    def complete_run(
        self, run_id: str, *, updates: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        return self.transition_run(run_id, RunStatus.COMPLETE, updates=updates)

    def abandon_run(
        self, run_id: str, *, reason: str | None = None
    ) -> dict[str, Any]:
        updates = {"blockedReason": reason} if reason is not None else {}
        return self.transition_run(run_id, RunStatus.ABANDONED, updates=updates)

    def mark_shipped(self, run_id: str) -> dict[str, Any]:
        return self.transition_run(run_id, RunStatus.SHIPPED)

    def _newest_unshipped_complete(self, *, exclude: str) -> str | None:
        candidates: list[tuple[str, str]] = []
        if not self.runs_dir.exists():
            return None
        for entry in self.runs_dir.iterdir():
            if not entry.is_dir() or entry.name == exclude or not _RUN_ID.fullmatch(entry.name):
                continue
            try:
                run = self.load_run(entry.name)
            except StateInconsistencyError:
                raise
            if (
                run["mode"] == RunMode.BUILD.value
                and run["status"] == RunStatus.COMPLETE.value
            ):
                candidates.append((run["completedAt"] or run["updatedAt"], entry.name))
        return max(candidates, default=(None, None))[1]

    def transition_task(
        self,
        run_id: str,
        task_id: str,
        target_status: TaskStatus | str,
        *,
        updates: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        target = (
            target_status.value
            if isinstance(target_status, TaskStatus)
            else target_status
        )
        if target not in _TASK_STATUSES:
            raise StateInconsistencyError(f"unknown task status: {target}")
        if target == TaskStatus.CANDIDATE_READY.value:
            raise StateInconsistencyError(
                "candidate_ready may only be entered by "
                "bind_candidate_selection"
            )
        run_directory = self.run_dir(run_id)
        with repository_lock(self.root, timeout=self.lock_timeout):
            return self._transition_task_locked(
                run_directory,
                run_id,
                task_id,
                target,
                updates or {},
            )

    def _transition_task_locked(
        self,
        run_directory: Path,
        run_id: str,
        task_id: str,
        target: str,
        updates: Mapping[str, Any],
    ) -> dict[str, Any]:
        with run_lock(run_directory, timeout=self.lock_timeout):
            record = self.load_tasks(run_id)
            matches = [task for task in record["tasks"] if task["id"] == task_id]
            if not matches:
                raise StateInconsistencyError(f"unknown task ID: {task_id}")
            task = matches[0]
            current = task["status"]
            changes = dict(updates)
            if current == target:
                if all(task.get(key) == value for key, value in changes.items()):
                    return task
                raise StateInconsistencyError(
                    "idempotent task transition does not match durable state"
                )
            if target not in TASK_TRANSITIONS[current]:
                raise StateInconsistencyError(
                    f"invalid task transition: {current} -> {target}"
                )
            if current == TaskStatus.BLOCKED.value and target == TaskStatus.IN_PROGRESS.value:
                decisions = run_directory / "decisions.md"
                self._validate_private_path(decisions, directory=False)
                if not decisions.read_text(encoding="utf-8").strip():
                    raise PreconditionError(
                        "blocked task requires a recorded user-approved recovery decision"
                    )
                if task.get("acceptanceIntent") is not None:
                    changes.setdefault("acceptanceIntent", None)
            task.update(changes)
            task["status"] = target
            task["updatedAt"] = changes.get("updatedAt", utc_now())
            validate_tasks_record(record)
            atomic_write_json(run_directory / "tasks.json", record)
            return task

    def bind_candidate_selection(
        self,
        run_id: str,
        task_id: str,
        *,
        expected_run: Mapping[str, Any],
        expected_task: Mapping[str, Any],
        updates: Mapping[str, Any],
        validate_evidence: Callable[[], None],
    ) -> dict[str, Any]:
        """CAS-bind a verified selection under repository and run locks."""

        run_directory = self.run_dir(run_id)
        changes = dict(updates)
        with repository_lock(self.root, timeout=self.lock_timeout):
            if self.active_run_id() != run_id:
                raise StateInconsistencyError(
                    "selection run is no longer active"
                )
            with run_lock(run_directory, timeout=self.lock_timeout):
                run = self.load_run(run_id)
                if (
                    run != dict(expected_run)
                    or run["mode"] != RunMode.BUILD.value
                    or run["status"] != RunStatus.ACTIVE.value
                    or run["activeTaskId"] != task_id
                ):
                    raise StateInconsistencyError(
                        "selection run changed during gate verification"
                    )
                record = self.load_tasks(run_id)
                matches = [
                    task for task in record["tasks"] if task["id"] == task_id
                ]
                if len(matches) != 1:
                    raise StateInconsistencyError(
                        f"unknown or duplicate task ID: {task_id}"
                    )
                task = matches[0]
                if task["status"] == TaskStatus.CANDIDATE_READY.value:
                    if not all(
                        task.get(key) == value
                        for key, value in changes.items()
                    ):
                        raise StateInconsistencyError(
                            "selection retry differs from durable task state"
                        )
                    validate_evidence()
                    return task
                if (
                    _selection_stable_task(task)
                    != _selection_stable_task(expected_task)
                    or task["status"] != TaskStatus.IN_PROGRESS.value
                    or task["baseCommit"] != run["currentCommit"]
                ):
                    raise StateInconsistencyError(
                        "selection task changed during gate verification"
                    )
                validate_evidence()
                task.update(changes)
                task["status"] = TaskStatus.CANDIDATE_READY.value
                task["updatedAt"] = utc_now()
                validate_tasks_record(record)
                atomic_write_json(run_directory / "tasks.json", record)
                return task

    def record_candidate_acceptance_intent_in_transaction(
        self,
        run_id: str,
        task_id: str,
        *,
        expected_run: Mapping[str, Any],
        expected_task: Mapping[str, Any],
        intent: Mapping[str, Any],
        validate_evidence: Callable[[], None],
    ) -> dict[str, Any]:
        """Persist acceptance intent while the caller holds repository lock."""

        run_directory = self.run_dir(run_id)
        validated_intent = _validate_acceptance_intent(
            dict(intent),
            label="acceptance intent",
        )
        if validated_intent is None:
            raise StateInconsistencyError("acceptance intent is required")
        if self.active_run_id() != run_id:
            raise StateInconsistencyError(
                "acceptance run is no longer active"
            )
        with run_lock(run_directory, timeout=self.lock_timeout):
            run = self.load_run(run_id)
            if (
                run != dict(expected_run)
                or run["mode"] != RunMode.BUILD.value
                or run["status"] != RunStatus.ACTIVE.value
                or run["activeTaskId"] != task_id
            ):
                raise StateInconsistencyError(
                    "acceptance run changed during verification"
                )
            record = self.load_tasks(run_id)
            matches = [
                task for task in record["tasks"] if task["id"] == task_id
            ]
            if len(matches) != 1:
                raise StateInconsistencyError(
                    f"unknown or duplicate task ID: {task_id}"
                )
            task = matches[0]
            if (
                _selection_stable_task(task)
                != _selection_stable_task(expected_task)
                or task["status"] != TaskStatus.CANDIDATE_READY.value
            ):
                raise StateInconsistencyError(
                    "selected task changed during acceptance"
                )
            existing = task.get("acceptanceIntent")
            if existing is not None and existing != validated_intent:
                raise StateInconsistencyError(
                    "task has a different durable acceptance intent"
                )
            validate_evidence()
            if existing is None:
                task["acceptanceIntent"] = validated_intent
                task["updatedAt"] = utc_now()
                validate_tasks_record(record)
                atomic_write_json(run_directory / "tasks.json", record)
            return task

    def bind_candidate_acceptance(
        self,
        run_id: str,
        task_id: str,
        *,
        expected_run: Mapping[str, Any],
        expected_task: Mapping[str, Any],
        selected_provider: str,
        commit: str | None,
        expected_intent: Mapping[str, Any],
        validate_evidence: Callable[[], None],
    ) -> dict[str, Any]:
        """CAS-bind acceptance after revalidating selection evidence."""

        with repository_lock(self.root, timeout=self.lock_timeout):
            return self.bind_candidate_acceptance_in_transaction(
                run_id,
                task_id,
                expected_run=expected_run,
                expected_task=expected_task,
                selected_provider=selected_provider,
                commit=commit,
                expected_intent=expected_intent,
                validate_evidence=validate_evidence,
            )

    def bind_candidate_acceptance_in_transaction(
        self,
        run_id: str,
        task_id: str,
        *,
        expected_run: Mapping[str, Any],
        expected_task: Mapping[str, Any],
        selected_provider: str,
        commit: str | None,
        expected_intent: Mapping[str, Any],
        validate_evidence: Callable[[], None],
    ) -> dict[str, Any]:
        """Bind acceptance while the caller holds the repository lock."""

        run_directory = self.run_dir(run_id)
        if self.active_run_id() != run_id:
            raise StateInconsistencyError(
                "acceptance run is no longer active"
            )
        with run_lock(run_directory, timeout=self.lock_timeout):
            run = self.load_run(run_id)
            if (
                run != dict(expected_run)
                or run["mode"] != RunMode.BUILD.value
                or run["status"] != RunStatus.ACTIVE.value
                or run["activeTaskId"] != task_id
            ):
                raise StateInconsistencyError(
                    "acceptance run changed during verification"
                )
            record = self.load_tasks(run_id)
            matches = [
                task for task in record["tasks"] if task["id"] == task_id
            ]
            if len(matches) != 1:
                raise StateInconsistencyError(
                    f"unknown or duplicate task ID: {task_id}"
                )
            task = matches[0]
            if (
                _selection_stable_task(task)
                != _selection_stable_task(expected_task)
                or task["status"] != TaskStatus.CANDIDATE_READY.value
                or task.get("selectedCandidate") != selected_provider
                or task.get("acceptanceIntent") != dict(expected_intent)
            ):
                raise StateInconsistencyError(
                    "selected task changed during acceptance"
                )
            validate_evidence()
            task["selectedCandidate"] = selected_provider
            task["status"] = (
                TaskStatus.COMMITTED.value
                if commit is not None
                else TaskStatus.ACCEPTED.value
            )
            if commit is not None:
                task["commit"] = commit
            task["updatedAt"] = utc_now()
            validate_tasks_record(record)
            atomic_write_json(run_directory / "tasks.json", record)
            return task

    def start_task(
        self,
        run_id: str,
        task_id: str,
        *,
        base_commit: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Atomically mark a task and its parent run active."""

        run_directory = self.run_dir(run_id)
        with repository_lock(self.root, timeout=self.lock_timeout):
            with run_lock(run_directory, timeout=self.lock_timeout):
                run = self.load_run(run_id)
                record = self.load_tasks(run_id)
                if run["status"] != RunStatus.ACTIVE.value:
                    raise PreconditionError("task can start only in an active build run")
                if run["activeTaskId"] not in (None, task_id):
                    raise PreconditionError(
                        "another task is already active",
                        details={"taskId": run["activeTaskId"]},
                    )
                matches = [item for item in record["tasks"] if item["id"] == task_id]
                if len(matches) != 1:
                    raise StateInconsistencyError(f"unknown or duplicate task ID: {task_id}")
                task = matches[0]
                if task["status"] == TaskStatus.IN_PROGRESS.value:
                    if run["activeTaskId"] == task_id and (
                        base_commit is None or task["baseCommit"] == base_commit
                    ):
                        return task, run
                    raise StateInconsistencyError("partial prior task start detected")
                if TaskStatus.IN_PROGRESS.value not in TASK_TRANSITIONS[task["status"]]:
                    raise StateInconsistencyError(
                        f"invalid task transition: {task['status']} -> in_progress"
                    )
                if base_commit is not None:
                    if not _COMMIT.fullmatch(base_commit):
                        raise StateInconsistencyError("task baseCommit is invalid")
                    if base_commit != run["currentCommit"]:
                        raise StateInconsistencyError(
                            "task baseCommit differs from run currentCommit"
                        )
                    task["baseCommit"] = base_commit
                elif task["baseCommit"] != run["currentCommit"]:
                    raise StateInconsistencyError(
                        "materialized task baseCommit differs from run currentCommit"
                    )
                timestamp = utc_now()
                task["status"] = TaskStatus.IN_PROGRESS.value
                task["updatedAt"] = timestamp
                run["activeTaskId"] = task_id
                run["updatedAt"] = timestamp
                validate_tasks_record(record)
                validate_run_record(run)
                transaction = run_directory / "attempt-block-transaction.json"
                atomic_write_json(
                    transaction,
                    {
                        "schemaVersion": 1,
                        "run": run,
                        "tasks": record,
                    },
                )
                atomic_write_json(run_directory / "tasks.json", record)
                atomic_write_json(run_directory / "run.json", run)
                transaction.unlink()
                self._fsync_directory(run_directory)
                return task, run

    def reserve_provider_invocation(
        self,
        run_id: str,
        task_id: str,
        provider: str,
    ) -> dict[str, Any]:
        """Atomically charge one provider call to the active durable task."""

        return self.reserve_provider_invocations(
            run_id, task_id, (provider,)
        )[0]

    def record_task_routing(
        self,
        run_id: str,
        task_id: str,
        routing: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Atomically bind a routing decision to an in-progress task."""

        run_directory = self.run_dir(run_id)
        with run_lock(run_directory, timeout=self.lock_timeout):
            run = self.load_run(run_id)
            record = self.load_tasks(run_id)
            if run["status"] != RunStatus.ACTIVE.value:
                raise PreconditionError("routing requires an active run")
            matches = [item for item in record["tasks"] if item["id"] == task_id]
            if len(matches) != 1:
                raise StateInconsistencyError(f"unknown or duplicate task ID: {task_id}")
            task = matches[0]
            if task["status"] != TaskStatus.IN_PROGRESS.value:
                raise PreconditionError("routing requires an in-progress task")
            if task["routing"] is not None and task["routing"] != dict(routing):
                raise StateInconsistencyError(
                    "task already has a different durable routing decision"
                )
            task["routing"] = dict(routing)
            task["updatedAt"] = utc_now()
            validate_tasks_record(record)
            atomic_write_json(run_directory / "tasks.json", record)
            return task

    def bind_provider_capability(
        self,
        run_id: str,
        provider: str,
        *,
        evidence_bytes: bytes,
        evidence_sha256: str,
    ) -> dict[str, Any]:
        """Atomically persist and bind trusted provider capability evidence."""

        if provider not in {"codex", "grok"}:
            raise StateInconsistencyError("unsupported capability provider")
        run_directory = self.run_dir(run_id)
        with repository_lock(self.root, timeout=self.lock_timeout):
            with run_lock(run_directory, timeout=self.lock_timeout):
                run = self.load_run(run_id)
                if run["status"] != RunStatus.ACTIVE.value:
                    raise PreconditionError(
                        "capability binding requires an active run"
                    )
                destination = (
                    run_directory
                    / "evidence"
                    / "preflight"
                    / f"{provider}-capability.json"
                )
                atomic_write_bytes(destination, evidence_bytes, mode=0o600)
                if sha256_file(destination) != evidence_sha256:
                    raise StateInconsistencyError(
                        "persisted capability evidence hash changed"
                    )
                providers = dict(run["providers"])
                providers[provider] = {
                    "capabilityEvidencePath": str(destination.resolve()),
                    "capabilityEvidenceSha256": evidence_sha256,
                }
                run["providers"] = providers
                run["updatedAt"] = utc_now()
                self._write_run(run_id, run)
                return providers[provider]

    def block_exhausted_provider_attempt(
        self,
        run_id: str,
        task_id: str,
        provider: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Atomically block task and run after a third terminal lane failure."""

        run_directory = self.run_dir(run_id)
        with repository_lock(self.root, timeout=self.lock_timeout):
            with run_lock(run_directory, timeout=self.lock_timeout):
                run = self.load_run(run_id)
                record = self.load_tasks(run_id)
                matches = [item for item in record["tasks"] if item["id"] == task_id]
                if len(matches) != 1:
                    raise StateInconsistencyError(
                        f"unknown or duplicate task ID: {task_id}"
                    )
                task = matches[0]
                if task["attempts"].get(provider, 0) < 3:
                    raise PreconditionError(
                        "provider has not exhausted three attempts"
                    )
                reason = f"{provider} exhausted three correction attempts"
                if task["status"] == TaskStatus.IN_PROGRESS.value:
                    task["status"] = TaskStatus.BLOCKED.value
                    task["updatedAt"] = utc_now()
                if run["status"] == RunStatus.ACTIVE.value:
                    run["status"] = RunStatus.BLOCKED.value
                    run["blockedReason"] = reason
                    run["updatedAt"] = utc_now()
                validate_tasks_record(record)
                validate_run_record(run)
                atomic_write_json(run_directory / "tasks.json", record)
                atomic_write_json(run_directory / "run.json", run)
                return task, run

    def reserve_provider_invocations(
        self,
        run_id: str,
        task_id: str,
        providers: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        """Atomically charge one or more provider calls to the active task.

        Race reservations are all-or-none. Reservations are intentionally
        never rolled back, so a crash or timeout cannot create an unaccounted
        retry.
        """

        if (
            not providers
            or len(set(providers)) != len(providers)
            or any(provider not in {"codex", "grok"} for provider in providers)
        ):
            raise StateInconsistencyError(
                "provider invocation reservation is empty, duplicated, or unsupported"
            )
        run_directory = self.run_dir(run_id)
        with run_lock(run_directory, timeout=self.lock_timeout):
            run = self.load_run(run_id)
            record = self.load_tasks(run_id)
            if (
                run["status"] != RunStatus.ACTIVE.value
                or run["mode"] != RunMode.BUILD.value
                or run["activeTaskId"] != task_id
            ):
                raise PreconditionError(
                    "provider invocation requires the active task of an active build run"
                )
            matches = [item for item in record["tasks"] if item["id"] == task_id]
            if len(matches) != 1:
                raise StateInconsistencyError(
                    f"unknown or duplicate task ID: {task_id}"
                )
            task = matches[0]
            if task["status"] != TaskStatus.IN_PROGRESS.value:
                raise PreconditionError(
                    "provider invocation requires an in-progress task"
                )
            maximum = run["maximumProviderInvocationsPerTask"]
            used = sum(int(count) for count in task["attempts"].values())
            if maximum is not None and used + len(providers) > maximum:
                raise PreconditionError(
                    "provider invocation budget is exhausted",
                    details={
                        "used": used,
                        "requested": len(providers),
                        "maximum": maximum,
                    },
                )
            reservations: list[dict[str, Any]] = []
            for offset, provider in enumerate(providers, start=1):
                if task["attempts"][provider] >= 3:
                    raise PreconditionError(
                        "provider correction-attempt limit is exhausted",
                        details={
                            "provider": provider,
                            "attempts": task["attempts"][provider],
                            "maximum": 3,
                        },
                    )
            for offset, provider in enumerate(providers, start=1):
                task["attempts"][provider] += 1
                reservations.append(
                    {
                        "provider": provider,
                        "providerAttempt": task["attempts"][provider],
                        "totalAttempts": used + offset,
                        "maximum": maximum,
                    }
                )
            task["updatedAt"] = utc_now()
            validate_tasks_record(record)
            atomic_write_json(run_directory / "tasks.json", record)
            return reservations

    def finish_task(
        self,
        run_id: str,
        task_id: str,
        *,
        interface_ledger_append: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Atomically finish the active task and advance durable run state."""

        run_directory = self.run_dir(run_id)
        with repository_lock(self.root, timeout=self.lock_timeout):
            with run_lock(run_directory, timeout=self.lock_timeout):
                run = self.load_run(run_id)
                record = self.load_tasks(run_id)
                matches = [item for item in record["tasks"] if item["id"] == task_id]
                if len(matches) != 1:
                    raise StateInconsistencyError(f"unknown or duplicate task ID: {task_id}")
                task = matches[0]
                if task["status"] == TaskStatus.COMPLETE.value:
                    if (
                        run["activeTaskId"] is None
                        and task_id in run["completedTaskIds"]
                    ):
                        return task, run
                    raise StateInconsistencyError("partial prior task completion detected")
                if run["activeTaskId"] != task_id:
                    raise PreconditionError("finished task is not the active run task")
                if TaskStatus.COMPLETE.value not in TASK_TRANSITIONS[task["status"]]:
                    raise StateInconsistencyError(
                        f"invalid task transition: {task['status']} -> complete"
                    )
                if interface_ledger_append is not None and not isinstance(
                    interface_ledger_append, str
                ):
                    raise StateInconsistencyError("interface ledger update must be text")
                timestamp = utc_now()
                task["status"] = TaskStatus.COMPLETE.value
                task["updatedAt"] = timestamp
                completed = list(run["completedTaskIds"])
                if task_id not in completed:
                    completed.append(task_id)
                run["completedTaskIds"] = completed
                run["activeTaskId"] = None
                if task.get("commit") is not None:
                    run["currentCommit"] = task["commit"]
                run["updatedAt"] = timestamp
                validate_tasks_record(record)
                validate_run_record(run)
                if interface_ledger_append:
                    ledger_path = run_directory / "interfaces.md"
                    self._validate_private_path(ledger_path, directory=False)
                    existing = ledger_path.read_text(encoding="utf-8")
                    separator = "" if not existing or existing.endswith("\n") else "\n"
                    atomic_write_text(
                        ledger_path,
                        existing + separator + interface_ledger_append,
                    )
                atomic_write_json(run_directory / "tasks.json", record)
                atomic_write_json(run_directory / "run.json", run)
                return task, run

    def validate_resume(
        self,
        *,
        repository_identity: str,
        branch: str,
        head: str,
        orchestration_git_dir: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        """Load and cross-check the active build without mutating it."""

        self.initialize()
        run_id = self._read_pointer("active")
        if run_id is None:
            raise PreconditionError("there is no active Crossforge build to resume")
        run_directory = self.run_dir(run_id)
        with repository_lock(self.root, timeout=self.lock_timeout):
            with run_lock(run_directory, timeout=self.lock_timeout):
                run = self.load_run(run_id)
                tasks = self.load_tasks(run_id)
                if run["mode"] != RunMode.BUILD.value or run["status"] not in {
                    RunStatus.ACTIVE.value,
                    RunStatus.BLOCKED.value,
                }:
                    raise StateInconsistencyError(
                        "active pointer does not name an unfinished build"
                    )
                expected_common = Path(run["gitCommonDir"]).resolve()
                if expected_common != self.git_common_dir:
                    raise StateInconsistencyError("recorded Git common directory changed")
                if orchestration_git_dir is not None and (
                    Path(run["orchestrationGitDir"]).resolve()
                    != Path(orchestration_git_dir).resolve()
                ):
                    raise StateInconsistencyError(
                        "resume was invoked from a different orchestration checkout"
                    )
                if run["repositoryIdentity"] != repository_identity:
                    raise StateInconsistencyError("repository identity changed")
                if run["branch"] != branch:
                    raise StateInconsistencyError("current branch differs from run state")
                if run["currentCommit"] != head:
                    raise StateInconsistencyError(
                        "HEAD differs from the last recorded accepted commit",
                        details={"expected": run["currentCommit"], "actual": head},
                    )
                plan_path = Path(run["planJsonPath"])
                if plan_path != run_directory / "plan.json":
                    raise StateInconsistencyError("recorded plan path changed")
                self._validate_private_path(plan_path, directory=False)
                actual_plan_hash = sha256_file(plan_path)
                if actual_plan_hash != run["planSha256"]:
                    raise StateInconsistencyError("canonical plan hash changed")
                if (
                    run["planApproval"]["approved"] is not True
                    or run["planApproval"]["approvedPlanSha256"] != actual_plan_hash
                ):
                    raise StateInconsistencyError("approved plan binding changed")
                task_by_id = {task["id"]: task for task in tasks["tasks"]}
                active_task_id = run["activeTaskId"]
                if active_task_id is not None:
                    active_task = task_by_id.get(active_task_id)
                    if active_task is None or active_task["status"] not in {
                        TaskStatus.IN_PROGRESS.value,
                        TaskStatus.CANDIDATE_READY.value,
                        TaskStatus.BLOCKED.value,
                        TaskStatus.ACCEPTED.value,
                        TaskStatus.COMMITTED.value,
                    }:
                        raise StateInconsistencyError("activeTaskId is inconsistent")
                for completed_id in run["completedTaskIds"]:
                    task = task_by_id.get(completed_id)
                    if task is None or task["status"] != TaskStatus.COMPLETE.value:
                        raise StateInconsistencyError(
                            "completedTaskIds disagrees with tasks.json"
                        )
                worktrees = self._read_json(run_directory / "worktrees.json")
                self._validate_worktrees(worktrees)
                return {"run": run, "tasks": tasks, "worktrees": worktrees}

    @staticmethod
    def _validate_worktrees(value: object) -> None:
        record = _require_object(value, "worktrees.json")
        _require_exact_fields(
            record, {"schemaVersion", "worktreeRoot", "entries"}, "worktrees.json"
        )
        if record["schemaVersion"] != 1 or not isinstance(record["entries"], list):
            raise StateInconsistencyError("invalid worktrees.json schema")
        if not isinstance(record["worktreeRoot"], str):
            raise StateInconsistencyError("invalid worktreeRoot")
        valid_statuses = {"creating", "active", "captured", "retained", "cleaned"}
        required = {
            "taskId",
            "provider",
            "path",
            "baseCommit",
            "status",
            "writerLockPath",
            "capturedPatchSha256",
            "createdAt",
            "cleanedAt",
        }
        optional = {"invocationEvidenceSha256"}
        for entry in record["entries"]:
            item = _require_object(entry, "worktree entry")
            unknown = set(item) - required - optional
            missing = required - set(item)
            if unknown or missing:
                raise StateInconsistencyError(
                    "worktree entry fields are invalid",
                    details={
                        "unknown": sorted(unknown),
                        "missing": sorted(missing),
                    },
                )
            if item["status"] not in valid_statuses:
                raise StateInconsistencyError("worktree entry has an invalid status")
            for field in ("taskId", "provider", "path", "baseCommit", "writerLockPath", "createdAt"):
                _require_string(item[field], f"worktree entry {field}")
            invocation_hash = item.get("invocationEvidenceSha256")
            if invocation_hash is not None and (
                not isinstance(invocation_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", invocation_hash) is None
            ):
                raise StateInconsistencyError(
                    "worktree entry invocationEvidenceSha256 is invalid"
                )


def initialize_state(git_common_dir: str | os.PathLike[str]) -> StateStore:
    store = StateStore(git_common_dir)
    store.initialize()
    return store


def plan_sha256(plan: Mapping[str, Any]) -> str:
    """Return the hash written for a canonical ``plan.json`` value."""

    return sha256_bytes(canonical_json_bytes(dict(plan)))
