"""Canonical plan validation, rendering, approval, and materialization."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .errors import PlanValidationError
from .models import (
    ApprovedSymlink,
    BinaryContext,
    BranchIntent,
    GateCommand,
    Plan,
    PlanApproval,
    PlanTask,
    Risk,
    RunMode,
    ShippingIntent,
    Strategy,
)
from .util import atomic_write_json, atomic_write_text, canonical_json_bytes, sha256_bytes


_PLAN_KEYS = {
    "schemaVersion",
    "title",
    "objective",
    "userVisibleOutcome",
    "context",
    "assumptions",
    "nonGoals",
    "architectureDecisions",
    "securityPrivacyConstraints",
    "branch",
    "globalVerificationCommands",
    "tasks",
    "decisionLog",
    "deferredWork",
}
_BRANCH_KEYS = {"requested", "targetRemote", "targetBranch", "shippingIntent"}
_TASK_KEYS = {
    "id",
    "title",
    "risk",
    "taskClass",
    "dependsOn",
    "suggestedStrategy",
    "allowedFiles",
    "objective",
    "interfaces",
    "constraints",
    "approvedBinaryContext",
    "approvedSymlinks",
    "verificationCommands",
    "doneWhen",
}
_GATE_KEYS = {"argv", "timeoutSeconds"}
_BINARY_KEYS = {"path", "sha256"}
_SYMLINK_KEYS = {"path", "target"}
_APPROVAL_KEYS = {
    "approved",
    "approvedBy",
    "approvedAt",
    "approvedPlanSha256",
}
_TASK_ID_RE = re.compile(r"T[1-9][0-9]*\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_REF_FORBIDDEN_RE = re.compile(
    r"(^|/)\.($|/)|(^|/)\.\.($|/)|\s|[\x00-\x1f\x7f]|"
    r"\.\.|@\{|[~^:?*\[\\]"
)
_SHELL_OPERATORS = {
    "|",
    "||",
    "&",
    "&&",
    ";",
    ">",
    ">>",
    "<",
    "<<",
    "2>",
    "2>>",
}
_SHELL_INTERPRETERS = {
    "sh",
    "bash",
    "dash",
    "zsh",
    "fish",
    "ksh",
    "csh",
    "tcsh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
}
_INLINE_INTERPRETERS = {
    "python",
    "python2",
    "python3",
    "node",
    "nodejs",
    "ruby",
    "perl",
    "php",
}
_DESTRUCTIVE_EXECUTABLES = {
    "rm",
    "rmdir",
    "unlink",
    "shred",
    "mkfs",
    "dd",
    "sudo",
    "doas",
    "su",
}


def _object(value: Any, location: str, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PlanValidationError(f"{location} must be an object")
    unknown = sorted(set(value) - keys)
    missing = sorted(keys - set(value))
    if unknown:
        raise PlanValidationError(
            f"{location} contains unknown key(s): {', '.join(unknown)}"
        )
    if missing:
        raise PlanValidationError(
            f"{location} is missing key(s): {', '.join(missing)}"
        )
    return value


def _clean_string(value: Any, location: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or _CONTROL_RE.search(value)
    ):
        raise PlanValidationError(
            f"{location} must be a non-empty string without surrounding "
            "whitespace or control characters"
        )
    return value


def _optional_clean_string(value: Any, location: str) -> str | None:
    if value is None:
        return None
    return _clean_string(value, location)


def _string_array(
    value: Any,
    location: str,
    *,
    non_empty: bool = False,
    unique: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PlanValidationError(f"{location} must be an array")
    result = tuple(
        _clean_string(item, f"{location}[{index}]")
        for index, item in enumerate(value)
    )
    if non_empty and not result:
        raise PlanValidationError(f"{location} must not be empty")
    if unique and len(set(result)) != len(result):
        raise PlanValidationError(f"{location} must not contain duplicates")
    return result


def _enum(enum_type: type[Any], value: Any, location: str) -> Any:
    if not isinstance(value, str):
        raise PlanValidationError(f"{location} must be a string")
    try:
        return enum_type(value)
    except ValueError as error:
        allowed = ", ".join(item.value for item in enum_type)
        raise PlanValidationError(f"{location} must be one of: {allowed}") from error


def _repository_path(value: Any, location: str) -> str:
    value = _clean_string(value, location)
    if "\\" in value:
        raise PlanValidationError(f"{location} must use POSIX '/' separators")
    path = PurePosixPath(value)
    components = value.split("/")
    if (
        path.is_absolute()
        or value.endswith("/")
        or any(component in ("", ".", "..") for component in components)
        or any(character in value for character in "*?[")
    ):
        raise PlanValidationError(
            f"{location} must be an exact repository-relative POSIX file path"
        )
    return value


def _branch_name(value: Any, location: str) -> str:
    value = _clean_string(value, location)
    if (
        value == "@"
        or value.startswith("-")
        or value.startswith("/")
        or value.endswith("/")
        or value.endswith(".")
        or value.endswith(".lock")
        or "//" in value
        or _REF_FORBIDDEN_RE.search(value)
        or any(component.startswith(".") for component in value.split("/"))
        or any(component.endswith(".lock") for component in value.split("/"))
    ):
        raise PlanValidationError(f"{location} is not a valid Git branch name")
    return value


def _executable_basename(argv0: str, location: str) -> str:
    if os.path.isabs(argv0):
        canonical = os.path.realpath(argv0)
        resolved = shutil.which(Path(argv0).name)
        if resolved is None or os.path.realpath(resolved) != canonical:
            raise PlanValidationError(
                f"{location} absolute executable does not match the executable "
                "resolved for its basename through PATH"
            )
        return Path(argv0).name.lower()
    if "/" in argv0 or "\\" in argv0:
        raise PlanValidationError(
            f"{location} executable must be a basename or an approved canonical "
            "absolute path"
        )
    return argv0.lower()


def _has_flag(arguments: Sequence[str], flags: set[str]) -> bool:
    return any(argument.lower() in flags for argument in arguments)


def _validate_command_policy(argv: tuple[str, ...], location: str) -> None:
    executable = _executable_basename(argv[0], f"{location}.argv[0]")
    executable_no_extension = executable.removesuffix(".exe")
    arguments = tuple(argument.lower() for argument in argv[1:])

    if executable in _DESTRUCTIVE_EXECUTABLES or executable_no_extension in _DESTRUCTIVE_EXECUTABLES:
        raise PlanValidationError(f"{location} uses forbidden executable {argv[0]!r}")
    if any(argument in _SHELL_OPERATORS for argument in argv):
        raise PlanValidationError(f"{location} contains a shell operator")

    if executable in _SHELL_INTERPRETERS or executable_no_extension in _SHELL_INTERPRETERS:
        if _has_flag(arguments, {"-c", "/c", "-command", "-encodedcommand"}):
            raise PlanValidationError(
                f"{location} uses a shell interpreter with inline code"
            )
    if executable in _INLINE_INTERPRETERS or executable_no_extension in _INLINE_INTERPRETERS:
        if _has_flag(arguments, {"-c", "-e", "--eval", "-r"}):
            raise PlanValidationError(
                f"{location} uses an interpreter with inline code"
            )

    if executable_no_extension == "git":
        if "push" in arguments:
            raise PlanValidationError(f"{location} may not perform git push")
        if "clean" in arguments:
            raise PlanValidationError(f"{location} may not perform git clean")
        if "credential" in arguments or any(
            argument.startswith("credential-") for argument in arguments
        ):
            raise PlanValidationError(
                f"{location} may not manage Git credentials"
            )
        if "reset" in arguments and "--hard" in arguments:
            raise PlanValidationError(
                f"{location} may not perform destructive git reset"
            )
        if "remote" in arguments and any(
            action in arguments for action in ("add", "remove", "rename", "set-url")
        ):
            raise PlanValidationError(
                f"{location} may not modify Git remote configuration"
            )

    publish_pairs = {
        "npm": {"publish", "login", "adduser"},
        "pnpm": {"publish", "login"},
        "yarn": {"publish", "npm"},
        "twine": {"upload"},
        "cargo": {"publish", "login"},
        "gem": {"push", "signin"},
        "docker": {"push", "login"},
        "gh": {"pr", "release", "auth"},
    }
    if executable_no_extension in publish_pairs and any(
        action in arguments for action in publish_pairs[executable_no_extension]
    ):
        raise PlanValidationError(
            f"{location} may not publish or manage remote credentials"
        )
    if executable_no_extension in {"pip", "pip3"} and "upload" in arguments:
        raise PlanValidationError(f"{location} may not publish packages")


def validate_gate_command(value: Any, location: str = "gate") -> GateCommand:
    item = _object(value, location, _GATE_KEYS)
    argv_value = item["argv"]
    if not isinstance(argv_value, list) or not argv_value:
        raise PlanValidationError(f"{location}.argv must be a non-empty array")
    argv: list[str] = []
    for index, argument in enumerate(argv_value):
        if (
            not isinstance(argument, str)
            or not argument
            or _CONTROL_RE.search(argument)
        ):
            raise PlanValidationError(
                f"{location}.argv[{index}] must be a non-empty string without "
                "control characters"
            )
        argv.append(argument)
    timeout = item["timeoutSeconds"]
    if type(timeout) is not int or not 10 <= timeout <= 7200:
        raise PlanValidationError(
            f"{location}.timeoutSeconds must be an integer from 10 through 7200"
        )
    command = GateCommand(tuple(argv), timeout)
    _validate_command_policy(command.argv, location)
    return command


def _binary_context(value: Any, location: str) -> BinaryContext:
    item = _object(value, location, _BINARY_KEYS)
    digest = item["sha256"]
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise PlanValidationError(f"{location}.sha256 must be 64 lowercase hex")
    return BinaryContext(
        path=_repository_path(item["path"], f"{location}.path"),
        sha256=digest,
    )


def _approved_symlink(value: Any, location: str) -> ApprovedSymlink:
    item = _object(value, location, _SYMLINK_KEYS)
    path = _repository_path(item["path"], f"{location}.path")
    target = _clean_string(item["target"], f"{location}.target")
    if "\\" in target or PurePosixPath(target).is_absolute():
        raise PlanValidationError(
            f"{location}.target must be a relative POSIX symlink target"
        )
    combined = PurePosixPath(path).parent.joinpath(target)
    depth = 0
    for component in combined.parts:
        if component in ("", "."):
            continue
        if component == "..":
            depth -= 1
            if depth < 0:
                raise PlanValidationError(
                    f"{location}.target resolves outside the candidate worktree"
                )
        else:
            depth += 1
    return ApprovedSymlink(path=path, target=target)


def _plan_task(value: Any, index: int) -> PlanTask:
    location = f"plan.tasks[{index}]"
    item = _object(value, location, _TASK_KEYS)
    task_id = _clean_string(item["id"], f"{location}.id")
    if not _TASK_ID_RE.fullmatch(task_id):
        raise PlanValidationError(f"{location}.id must match T[1-9][0-9]*")
    allowed_files = tuple(
        _repository_path(path, f"{location}.allowedFiles[{path_index}]")
        for path_index, path in enumerate(
            _string_array(
                item["allowedFiles"],
                f"{location}.allowedFiles",
                non_empty=True,
                unique=True,
            )
        )
    )
    verification_value = item["verificationCommands"]
    if not isinstance(verification_value, list) or not verification_value:
        raise PlanValidationError(
            f"{location}.verificationCommands must be a non-empty array"
        )
    binary_value = item["approvedBinaryContext"]
    symlink_value = item["approvedSymlinks"]
    if not isinstance(binary_value, list):
        raise PlanValidationError(
            f"{location}.approvedBinaryContext must be an array"
        )
    if not isinstance(symlink_value, list):
        raise PlanValidationError(f"{location}.approvedSymlinks must be an array")
    binary_context = tuple(
        _binary_context(entry, f"{location}.approvedBinaryContext[{entry_index}]")
        for entry_index, entry in enumerate(binary_value)
    )
    symlinks = tuple(
        _approved_symlink(entry, f"{location}.approvedSymlinks[{entry_index}]")
        for entry_index, entry in enumerate(symlink_value)
    )
    if len({entry.path for entry in binary_context}) != len(binary_context):
        raise PlanValidationError(
            f"{location}.approvedBinaryContext contains duplicate paths"
        )
    if len({entry.path for entry in symlinks}) != len(symlinks):
        raise PlanValidationError(
            f"{location}.approvedSymlinks contains duplicate paths"
        )
    return PlanTask(
        id=task_id,
        title=_clean_string(item["title"], f"{location}.title"),
        risk=_enum(Risk, item["risk"], f"{location}.risk"),
        task_class=_clean_string(item["taskClass"], f"{location}.taskClass"),
        depends_on=_string_array(
            item["dependsOn"], f"{location}.dependsOn", unique=True
        ),
        suggested_strategy=_enum(
            Strategy, item["suggestedStrategy"], f"{location}.suggestedStrategy"
        ),
        allowed_files=allowed_files,
        objective=_clean_string(item["objective"], f"{location}.objective"),
        interfaces=_string_array(item["interfaces"], f"{location}.interfaces"),
        constraints=_string_array(item["constraints"], f"{location}.constraints"),
        approved_binary_context=binary_context,
        approved_symlinks=symlinks,
        verification_commands=tuple(
            validate_gate_command(command, f"{location}.verificationCommands[{i}]")
            for i, command in enumerate(verification_value)
        ),
        done_when=_string_array(
            item["doneWhen"], f"{location}.doneWhen", non_empty=True
        ),
    )


def _validate_dependency_graph(tasks: tuple[PlanTask, ...]) -> None:
    identifiers = {task.id for task in tasks}
    for task in tasks:
        unknown = sorted(set(task.depends_on) - identifiers)
        if unknown:
            raise PlanValidationError(
                f"plan task {task.id} has unknown dependency ID(s): "
                + ", ".join(unknown)
            )

    graph = {task.id: task.depends_on for task in tasks}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str, trail: tuple[str, ...]) -> None:
        if task_id in visited:
            return
        if task_id in visiting:
            cycle_start = trail.index(task_id)
            cycle = trail[cycle_start:] + (task_id,)
            raise PlanValidationError(
                "plan task dependencies contain a cycle: " + " -> ".join(cycle)
            )
        visiting.add(task_id)
        for dependency in graph[task_id]:
            visit(dependency, trail + (task_id,))
        visiting.remove(task_id)
        visited.add(task_id)

    for identifier in sorted(graph):
        visit(identifier, ())


def validate_plan(
    value: Any,
    *,
    mode: RunMode | str = RunMode.BUILD,
    no_commit: bool = False,
) -> Plan:
    """Validate exact canonical plan data and return an immutable Plan."""

    item = _object(value, "plan", _PLAN_KEYS)
    if item["schemaVersion"] != 1 or type(item["schemaVersion"]) is not int:
        raise PlanValidationError("plan.schemaVersion must be integer 1")
    try:
        run_mode = mode if isinstance(mode, RunMode) else RunMode(mode)
    except ValueError as error:
        raise PlanValidationError(f"Invalid plan validation mode: {mode}") from error
    branch_value = _object(item["branch"], "plan.branch", _BRANCH_KEYS)
    global_value = item["globalVerificationCommands"]
    if not isinstance(global_value, list):
        raise PlanValidationError(
            "plan.globalVerificationCommands must be an array"
        )
    if run_mode is RunMode.BUILD and not global_value:
        raise PlanValidationError(
            "plan.globalVerificationCommands must not be empty in build mode"
        )
    tasks_value = item["tasks"]
    if not isinstance(tasks_value, list) or not tasks_value:
        raise PlanValidationError("plan.tasks must be a non-empty array")
    tasks = tuple(_plan_task(task, index) for index, task in enumerate(tasks_value))
    identifiers = [task.id for task in tasks]
    if len(set(identifiers)) != len(identifiers):
        raise PlanValidationError("plan task IDs must be unique")
    _validate_dependency_graph(tasks)
    if no_commit and len(tasks) != 1:
        raise PlanValidationError(
            "--no-commit requires a plan containing exactly one task"
        )

    remote = _optional_clean_string(
        branch_value["targetRemote"], "plan.branch.targetRemote"
    )
    if remote is not None and any(character in remote for character in "/\\"):
        raise PlanValidationError(
            "plan.branch.targetRemote must be a Git remote name, not a path"
        )
    return Plan(
        schema_version=1,
        title=_clean_string(item["title"], "plan.title"),
        objective=_clean_string(item["objective"], "plan.objective"),
        user_visible_outcome=_clean_string(
            item["userVisibleOutcome"], "plan.userVisibleOutcome"
        ),
        context=_string_array(item["context"], "plan.context"),
        assumptions=_string_array(item["assumptions"], "plan.assumptions"),
        non_goals=_string_array(item["nonGoals"], "plan.nonGoals"),
        architecture_decisions=_string_array(
            item["architectureDecisions"], "plan.architectureDecisions"
        ),
        security_privacy_constraints=_string_array(
            item["securityPrivacyConstraints"],
            "plan.securityPrivacyConstraints",
        ),
        branch=BranchIntent(
            requested=(
                None
                if branch_value["requested"] is None
                else _branch_name(
                    branch_value["requested"], "plan.branch.requested"
                )
            ),
            target_remote=remote,
            target_branch=_branch_name(
                branch_value["targetBranch"], "plan.branch.targetBranch"
            ),
            shipping_intent=_enum(
                ShippingIntent,
                branch_value["shippingIntent"],
                "plan.branch.shippingIntent",
            ),
        ),
        global_verification_commands=tuple(
            validate_gate_command(
                command, f"plan.globalVerificationCommands[{index}]"
            )
            for index, command in enumerate(global_value)
        ),
        tasks=tasks,
        decision_log=_string_array(item["decisionLog"], "plan.decisionLog"),
        deferred_work=_string_array(item["deferredWork"], "plan.deferredWork"),
    )


def plan_sha256(plan: Plan | Mapping[str, Any]) -> str:
    validated = plan if isinstance(plan, Plan) else validate_plan(plan)
    return sha256_bytes(canonical_json_bytes(validated.to_dict()))


def _rfc3339_utc(value: Any, location: str) -> str:
    value = _clean_string(value, location)
    if not value.endswith("Z"):
        raise PlanValidationError(f"{location} must be RFC3339 UTC ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PlanValidationError(f"{location} must be RFC3339 UTC") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise PlanValidationError(f"{location} must be RFC3339 UTC")
    return value


def validate_plan_approval(
    plan: Plan | Mapping[str, Any],
    approval: PlanApproval | Mapping[str, Any],
) -> PlanApproval:
    """Require approval of exactly the canonical JSON hash for *plan*."""

    if isinstance(approval, PlanApproval):
        result = approval
    else:
        item = _object(approval, "planApproval", _APPROVAL_KEYS)
        if type(item["approved"]) is not bool:
            raise PlanValidationError("planApproval.approved must be a boolean")
        digest = item["approvedPlanSha256"]
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise PlanValidationError(
                "planApproval.approvedPlanSha256 must be 64 lowercase hex"
            )
        result = PlanApproval(
            approved=item["approved"],
            approved_by=_clean_string(
                item["approvedBy"], "planApproval.approvedBy"
            ),
            approved_at=_rfc3339_utc(
                item["approvedAt"], "planApproval.approvedAt"
            ),
            approved_plan_sha256=digest,
        )
    if not result.approved:
        raise PlanValidationError("The canonical plan has not been approved")
    expected = plan_sha256(plan)
    if result.approved_plan_sha256 != expected:
        raise PlanValidationError(
            "Plan approval does not match the exact canonical plan hash"
        )
    return result


def _markdown_list(values: Sequence[str]) -> str:
    if not values:
        return "- None"
    return "\n".join(f"- {value}" for value in values)


def _command_label(command: GateCommand) -> str:
    return f"`{shlex.join(command.argv)}` (timeout: {command.timeout_seconds}s)"


def render_plan_markdown(plan: Plan | Mapping[str, Any]) -> str:
    """Render the canonical plan in a deterministic human-readable form."""

    value = plan if isinstance(plan, Plan) else validate_plan(plan)
    branch = value.branch
    branch_lines = [
        f"- Requested branch: {branch.requested or 'automatic'}",
        f"- Target remote: {branch.target_remote or 'none'}",
        f"- Target branch: {branch.target_branch}",
        f"- Shipping intent: {branch.shipping_intent.value}",
    ]
    lines = [
        f"# Plan: {value.title}",
        "",
        "## Objective",
        "",
        value.objective,
        "",
        "## User-visible outcome",
        "",
        value.user_visible_outcome,
        "",
        "## Context",
        "",
        _markdown_list(value.context),
        "",
        "## Assumptions",
        "",
        _markdown_list(value.assumptions),
        "",
        "## Non-goals",
        "",
        _markdown_list(value.non_goals),
        "",
        "## Architecture decisions",
        "",
        _markdown_list(value.architecture_decisions),
        "",
        "## Security and privacy constraints",
        "",
        _markdown_list(value.security_privacy_constraints),
        "",
        "## Branch and shipping intent",
        "",
        *branch_lines,
        "",
        "## Global verification gate",
        "",
        _markdown_list(
            [_command_label(command) for command in value.global_verification_commands]
        ),
        "",
        "## Tasks",
        "",
    ]
    for task in value.tasks:
        lines.extend(
            [
                f"### {task.id} — {task.title}",
                "",
                f"- Risk: {task.risk.value}",
                f"- Task class: {task.task_class}",
                "- Depends on: " + (", ".join(task.depends_on) or "None"),
                f"- Suggested strategy: {task.suggested_strategy.value}",
                "- Files:",
                *[f"  - {path}" for path in task.allowed_files],
                f"- Objective: {task.objective}",
                "- Interfaces:",
                *(
                    [f"  - {entry}" for entry in task.interfaces]
                    if task.interfaces
                    else ["  - None"]
                ),
                "- Constraints:",
                *(
                    [f"  - {entry}" for entry in task.constraints]
                    if task.constraints
                    else ["  - None"]
                ),
                "- Verification:",
                *[
                    f"  - {_command_label(command)}"
                    for command in task.verification_commands
                ],
                "- Done when:",
                *[f"  - {entry}" for entry in task.done_when],
                "",
            ]
        )
    lines.extend(
        [
            "## Decision log",
            "",
            _markdown_list(value.decision_log),
            "",
            "## Deferred work",
            "",
            _markdown_list(value.deferred_work),
            "",
        ]
    )
    return "\n".join(lines)


def materialize_tasks(
    plan: Plan | Mapping[str, Any],
    *,
    base_commit: str,
    timestamp: str,
) -> dict[str, Any]:
    """Add only specified runtime fields to canonical plan tasks."""

    value = plan if isinstance(plan, Plan) else validate_plan(plan)
    if not re.fullmatch(r"[0-9a-f]{40}", base_commit):
        raise PlanValidationError("base_commit must be a 40-character lowercase SHA")
    timestamp = _rfc3339_utc(timestamp, "timestamp")
    tasks: list[dict[str, Any]] = []
    for task in value.tasks:
        result = task.to_dict()
        result.update(
            {
                "status": "pending",
                "baseCommit": base_commit,
                "routing": None,
                "selectedCandidate": None,
                "selectedCandidatePath": None,
                "selectedInvocationEvidencePath": None,
                "selectedInvocationEvidenceSha256": None,
                "commit": None,
                "attempts": {"codex": 0, "grok": 0, "claude": 0},
                "createdAt": timestamp,
                "updatedAt": timestamp,
            }
        )
        # Match the durable tasks schema's stable field ordering after canonical
        # JSON sorting; no semantic fields are inferred or discarded.
        tasks.append(result)
    return {"schemaVersion": 1, "tasks": tasks}


def write_plan_files(
    plan: Plan | Mapping[str, Any],
    *,
    json_path: str | os.PathLike[str],
    markdown_path: str | os.PathLike[str],
) -> str:
    """Write canonical plan representations and return the approved hash input."""

    value = plan if isinstance(plan, Plan) else validate_plan(plan)
    atomic_write_json(json_path, value.to_dict())
    atomic_write_text(markdown_path, render_plan_markdown(value))
    return plan_sha256(value)


def load_plan(
    path: str | os.PathLike[str],
    *,
    mode: RunMode | str = RunMode.BUILD,
    no_commit: bool = False,
) -> Plan:
    source = Path(path)
    try:
        raw = source.read_text(encoding="utf-8")
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_plan_keys)
    except PlanValidationError:
        raise
    except (OSError, UnicodeError) as error:
        raise PlanValidationError(f"Could not read plan {source}: {error}") from error
    except json.JSONDecodeError as error:
        raise PlanValidationError(
            f"Invalid JSON in plan {source}: line {error.lineno}, "
            f"column {error.colno}"
        ) from error
    return validate_plan(value, mode=mode, no_commit=no_commit)


def _reject_duplicate_plan_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PlanValidationError(f"Plan contains duplicate key: {key}")
        result[key] = value
    return result


# Concise aliases used by the control CLI.
render_plan = render_plan_markdown
canonical_plan_hash = plan_sha256
