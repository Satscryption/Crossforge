"""Candidate eligibility, isolated verification, exact staging, and commits."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence

from .errors import (
    GateFailureError,
    InvalidInputError,
    PreconditionError,
    StateInconsistencyError,
)
from .evidence import EvidenceStore
from .gates import GateCommand, GateResult
from .git import (
    GitRepository,
    current_branch,
    discover_repository,
    index_entry,
    is_dirty,
    resolve_commit,
    run_git,
    stage_allowlist_filter_free,
)
from .locking import repository_lock
from .reports import ProviderReport, independent_gates_passed
from .scope import (
    ScopeResult,
    enforce_scope,
    parse_allowlist,
    scoped_tree_hash,
    scoped_tree_manifest,
    validate_relative_path,
)
from .state import StateStore
from .util import (
    canonical_json_bytes,
    ensure_private_directory,
    sha256_bytes,
    sha256_file,
)
from .worktrees import WorktreeEntry, WorktreeManager


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DISALLOWED_MICRO_FIX_CLASSES = frozenset(
    {
        "authentication",
        "authorization",
        "security",
        "persistence",
        "migration",
        "concurrency",
        "behavioral",
    }
)


class GateRunnerLike(Protocol):
    """The narrow T8 gate-runner interface used during acceptance."""

    policy: Any

    def run(
        self,
        command: GateCommand | Mapping[str, Any],
        *,
        result_name: str,
        **kwargs: Any,
    ) -> Any: ...


GateRunnerFactory = Callable[[Path, EvidenceStore], GateRunnerLike]
QuarantineResolver = Callable[[Path], Sequence[str]]
PreApplyValidator = Callable[[str, str], None]
AcceptanceIntentRecorder = Callable[[str, str], None]
AcceptanceFinalizer = Callable[["AcceptanceResult"], None]


@dataclass(frozen=True, slots=True)
class CandidateGateVerification:
    """Control-produced gate evidence bound to one captured candidate patch."""

    gate_results: tuple[GateResult, ...]
    verified_scoped_tree_sha256: str
    quarantine_paths_sha256: str
    verification_worktree: str
    verification_cleanup: str
    receipt_path: str
    receipt_sha256: str


@dataclass(frozen=True, slots=True)
class PatchMetadata:
    sha256: str
    size_bytes: int
    paths: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "sha256": self.sha256,
            "sizeBytes": self.size_bytes,
            "paths": list(self.paths),
        }


@dataclass(frozen=True, slots=True)
class EligibilityResult:
    eligible: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"eligible": self.eligible, "reasons": list(self.reasons)}


@dataclass(frozen=True, slots=True)
class MicroFixResult:
    allowed: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "reasons": list(self.reasons),
            "assurance": "caller-attested",
            "authoritative": False,
            "attestedInputs": [
                "changed_lines",
                "changed_paths",
                "allowlist",
                "task_risk",
                "task_class",
                "public_interface_change",
                "security_or_behavioral_decision",
                "persistence_migration_or_concurrency",
                "new_test_logic",
                "deterministic_gates_cover",
                "evidence_will_record",
                "commit_body_will_record",
            ],
        }


@dataclass(frozen=True, slots=True)
class AcceptanceResult:
    task_id: str
    provider: str
    patch_sha256: str
    verified_scoped_tree_sha256: str
    applied_scoped_tree_sha256: str
    quarantine_paths_sha256: str
    gate_results: tuple[Mapping[str, Any], ...]
    staged_paths: tuple[str, ...]
    commit: str | None
    no_commit: bool
    verification_worktree: str
    verification_cleanup: str

    def to_dict(self) -> dict[str, object]:
        return {
            "taskId": self.task_id,
            "provider": self.provider,
            "patchSha256": self.patch_sha256,
            "verifiedScopedTreeSha256": self.verified_scoped_tree_sha256,
            "appliedScopedTreeSha256": self.applied_scoped_tree_sha256,
            "quarantinePathsSha256": self.quarantine_paths_sha256,
            "gates": [dict(item) for item in self.gate_results],
            "stagedPaths": list(self.staged_paths),
            "commit": self.commit,
            "noCommit": self.no_commit,
            "verificationWorktree": self.verification_worktree,
            "verificationCleanup": self.verification_cleanup,
        }


def assess_candidate_eligibility(
    *,
    candidate: WorktreeEntry,
    patch_path: str | os.PathLike[str],
    task_base_commit: str,
    scope_result: ScopeResult | None,
    provider_report: ProviderReport | None,
    independent_gate_results: Sequence[Any],
    plan_guardrails_passed: bool = True,
    public_contract_approved: bool = True,
    generated_and_binary_content_explained: bool = True,
) -> EligibilityResult:
    """Apply mandatory hard gates before Claude compares candidates."""

    reasons: list[str] = []
    patch = Path(patch_path)
    if candidate.status != "captured":
        reasons.append("candidate_not_captured")
    if candidate.base_commit != task_base_commit:
        reasons.append("base_commit_mismatch")
    if candidate.captured_patch_sha256 is None:
        reasons.append("missing_patch_hash")
    elif not _SHA256.fullmatch(candidate.captured_patch_sha256):
        reasons.append("invalid_patch_hash")
    if not patch.is_file() or patch.is_symlink():
        reasons.append("missing_patch")
    elif (
        candidate.captured_patch_sha256 is not None
        and sha256_file(patch) != candidate.captured_patch_sha256
    ):
        reasons.append("patch_hash_mismatch")
    if scope_result is None or not scope_result.passed:
        reasons.append("scope_failed")
    if provider_report is None:
        reasons.append("invalid_provider_report")
    elif not provider_report.eligible_by_claim:
        reasons.append("provider_did_not_complete")
    if not independent_gates_passed(independent_gate_results):
        reasons.append("independent_gate_failed")
    if not plan_guardrails_passed:
        reasons.append("plan_guardrail_failed")
    if not public_contract_approved:
        reasons.append("unapproved_public_contract_change")
    if not generated_and_binary_content_explained:
        reasons.append("unexplained_generated_or_binary_content")
    unique = tuple(dict.fromkeys(reasons))
    return EligibilityResult(not unique, unique)


def inspect_patch(
    repository: GitRepository,
    patch_path: str | os.PathLike[str],
    *,
    expected_sha256: str,
    allowlist: Iterable[str],
) -> PatchMetadata:
    """Validate a captured patch's identity and repository-relative path metadata."""

    patch = Path(patch_path)
    if not patch.is_file() or patch.is_symlink():
        raise PreconditionError("Captured patch is missing or is not a regular file")
    if not _SHA256.fullmatch(expected_sha256):
        raise StateInconsistencyError("Recorded candidate patch hash is invalid")
    actual_hash = sha256_file(patch)
    if actual_hash != expected_sha256:
        raise StateInconsistencyError("Captured patch hash does not match candidate state")
    allowed = set(parse_allowlist(allowlist))
    result = run_git(
        repository.root,
        ["apply", "--numstat", "-z", "--binary", str(patch.resolve())],
        git_executable=repository.git_executable,
    )
    paths: set[str] = set()
    for record in result.stdout_bytes.split(b"\0"):
        if not record:
            continue
        fields = record.split(b"\t", 2)
        if len(fields) != 3:
            raise StateInconsistencyError("Git returned malformed patch metadata")
        path = fields[2].decode("utf-8", errors="surrogateescape")
        validate_relative_path(path)
        if path == ".git" or path.startswith(".git/") or "/.git/" in f"/{path}/":
            raise PreconditionError("Captured patch attempts to modify Git metadata")
        if path not in allowed:
            raise PreconditionError(
                "Captured patch contains a path outside the exact allowlist",
                details={"path": path},
            )
        paths.add(path)
    if not paths:
        raise PreconditionError("Captured patch contains no file changes")
    return PatchMetadata(actual_hash, patch.stat().st_size, tuple(sorted(paths)))


def validate_acceptance_state(
    state_store: StateStore,
    *,
    run_id: str,
    task_id: str,
    repository: GitRepository,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """Read and cross-check durable state without transitioning it."""

    run, task_record = state_store.load_state(run_id)
    tasks = task_record["tasks"]
    matches = [task for task in tasks if task["id"] == task_id]
    if len(matches) != 1:
        raise StateInconsistencyError(f"unknown or duplicate task ID: {task_id}")
    task = matches[0]
    if run["mode"] != "build" or run["status"] != "active":
        raise StateInconsistencyError("candidate acceptance requires an active build run")
    if run["activeTaskId"] != task_id:
        raise StateInconsistencyError("task is not the active run task")
    if task["status"] not in {
        "candidate_ready",
        "accepted",
        "committed",
    }:
        raise StateInconsistencyError("task is not ready for candidate acceptance")
    if task["baseCommit"] != run["currentCommit"]:
        raise StateInconsistencyError("task base and run current commit disagree")
    head = resolve_commit(repository, "HEAD")
    terminal_replay = (
        task["status"] == "committed"
        and task.get("commit") == head
        and task.get("acceptanceIntent") is not None
    ) or (
        task["status"] == "accepted"
        and run["noCommit"] is True
        and head == task["baseCommit"]
        and task.get("acceptanceIntent") is not None
    )
    if task["status"] in {"accepted", "committed"} and not terminal_replay:
        raise StateInconsistencyError(
            "durably accepted task does not match orchestration state"
        )
    if (
        head != task["baseCommit"]
        and task.get("acceptanceIntent") is None
        and not terminal_replay
    ):
        raise StateInconsistencyError("orchestration HEAD is stale for this task")
    if run["noCommit"] and len(tasks) != 1:
        raise StateInconsistencyError("no-commit mode requires exactly one task")
    return run, task


def check_micro_fix(
    *,
    changed_lines: int,
    changed_paths: Iterable[str],
    allowlist: Iterable[str],
    maximum_changed_lines: int = 5,
    enabled: bool = True,
    task_risk: str,
    task_class: str,
    public_interface_change: bool,
    security_or_behavioral_decision: bool,
    persistence_migration_or_concurrency: bool,
    new_test_logic: bool,
    deterministic_gates_cover: bool,
    evidence_will_record: bool,
    commit_body_will_record: bool,
) -> MicroFixResult:
    """Check the internal consistency of caller-attested micro-fix inputs.

    This helper does not independently observe a repository, patch, task, gate,
    evidence record, or future commit body. Its output must therefore never be
    represented as verified control-layer evidence.
    """

    reasons: list[str] = []
    if not enabled:
        reasons.append("micro_fix_disabled")
    if (
        isinstance(maximum_changed_lines, bool)
        or not isinstance(maximum_changed_lines, int)
        or not 0 <= maximum_changed_lines <= 10
    ):
        raise InvalidInputError("maximum micro-fix lines must be from 0 through 10")
    if isinstance(changed_lines, bool) or not isinstance(changed_lines, int):
        raise InvalidInputError("changed_lines must be an integer")
    if changed_lines < 1 or changed_lines > min(5, maximum_changed_lines):
        reasons.append("changed_line_limit_exceeded")
    allowed = set(parse_allowlist(allowlist))
    normalized_changed: set[str] = set()
    for path in changed_paths:
        normalized_changed.add(validate_relative_path(path))
    if not normalized_changed or not normalized_changed <= allowed:
        reasons.append("path_outside_allowlist")
    if task_risk == "high":
        reasons.append("high_risk_task")
    if task_class.strip().lower() in _DISALLOWED_MICRO_FIX_CLASSES:
        reasons.append("disallowed_task_class")
    if public_interface_change:
        reasons.append("public_interface_change")
    if security_or_behavioral_decision:
        reasons.append("security_or_behavioral_decision")
    if persistence_migration_or_concurrency:
        reasons.append("persistence_migration_or_concurrency")
    if new_test_logic:
        reasons.append("new_test_logic")
    if not deterministic_gates_cover:
        reasons.append("deterministic_gates_do_not_cover")
    if not evidence_will_record:
        reasons.append("evidence_not_recorded")
    if not commit_body_will_record:
        reasons.append("commit_body_not_recorded")
    unique = tuple(dict.fromkeys(reasons))
    return MicroFixResult(not unique, unique)


def build_commit_message(
    *,
    change_type: str,
    summary: str,
    why: str,
    tests: str,
    provider: str,
    resolved_model: str,
    task_id: str,
) -> str:
    """Build the required one-task commit message without co-author trailers."""

    fields = {
        "change_type": change_type,
        "summary": summary,
        "why": why,
        "tests": tests,
        "provider": provider,
        "resolved_model": resolved_model,
        "task_id": task_id,
    }
    for name, value in fields.items():
        if not isinstance(value, str) or not value.strip() or _CONTROL.search(value):
            raise InvalidInputError(f"commit message field {name} is invalid")
    if "\n" in change_type or "\n" in summary or "\n" in tests:
        raise InvalidInputError("commit type, summary, and tests must be single-line")
    message = (
        f"{change_type}: {summary}\n\n"
        f"{why.strip()}\n"
        f"Tests: {tests.strip()}\n"
        f"Crossforge: {provider.strip()}/{resolved_model.strip()}; task {task_id.strip()}"
    )
    if re.search(r"(?im)^co-authored-by:", message):
        raise InvalidInputError("AI co-author attribution is not permitted")
    return message


def _binary_diff(repository: GitRepository, base_commit: str) -> bytes:
    """Capture all tracked and non-ignored untracked changes without filters."""

    untracked_result = run_git(
        repository.root,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        git_executable=repository.git_executable,
    )
    untracked = [
        item.decode("utf-8", "surrogateescape")
        for item in untracked_result.stdout_bytes.split(b"\0")
        if item
    ]
    for path in untracked:
        run_git(
            repository.root,
            ["add", "--intent-to-add", "--", path],
            git_executable=repository.git_executable,
        )
    try:
        return run_git(
            repository.root,
            [
                "diff",
                "--binary",
                "--no-ext-diff",
                "--no-renames",
                base_commit,
                "--",
            ],
            git_executable=repository.git_executable,
        ).stdout_bytes
    finally:
        for path in untracked:
            run_git(
                repository.root,
                ["reset", "--quiet", "--", path],
                check=False,
                git_executable=repository.git_executable,
            )


def _approved_symlink_map(
    approved_symlinks: Mapping[str, str] | Sequence[Mapping[str, Any]] | None,
) -> dict[str, str]:
    if approved_symlinks is None:
        return {}
    if isinstance(approved_symlinks, Mapping):
        return {str(path): str(target) for path, target in approved_symlinks.items()}
    return {
        str(item["path"]): str(item["target"])
        for item in approved_symlinks
        if isinstance(item, Mapping) and "path" in item and "target" in item
    }


def _binary_changes_are_approved(
    root: Path,
    paths: Iterable[str],
    approvals: Iterable[Mapping[str, Any]],
) -> None:
    approved = {
        (str(item.get("path")), str(item.get("sha256")))
        for item in approvals
        if isinstance(item, Mapping)
    }
    for relative in paths:
        absolute = root / relative
        try:
            info = absolute.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        data = absolute.read_bytes()
        try:
            data.decode("utf-8")
            binary = b"\x00" in data
        except UnicodeDecodeError:
            binary = True
        if binary:
            digest = hashlib.sha256(data).hexdigest()
            if (relative, digest) not in approved:
                raise PreconditionError(
                    "Candidate contains an unexplained binary output",
                    details={"path": relative, "sha256": digest},
                )


def _verify_index_matches_manifest(
    repository: GitRepository,
    *,
    base_commit: str,
    allowlist: Iterable[str],
    approved_symlinks: Mapping[str, str],
) -> tuple[str, ...]:
    manifest = scoped_tree_manifest(
        repository.root,
        allowlist,
        approved_symlinks=approved_symlinks,
    )
    for expected in manifest:
        actual = index_entry(repository, expected.path)
        if expected.file_type == "absent":
            if actual is not None:
                raise StateInconsistencyError(
                    f"Deleted path remains in the index: {expected.path}"
                )
            continue
        if actual is None or actual.mode != expected.git_mode or actual.stage != 0:
            raise StateInconsistencyError(
                f"Index mode does not match verified content: {expected.path}"
            )
        blob = run_git(
            repository.root,
            ["cat-file", "blob", actual.object_id],
            git_executable=repository.git_executable,
        ).stdout_bytes
        if hashlib.sha256(blob).hexdigest() != expected.sha256:
            raise StateInconsistencyError(
                f"Index bytes do not match verified content: {expected.path}"
            )
    staged = run_git(
        repository.root,
        ["diff", "--cached", "--name-only", "-z", base_commit, "--"],
        git_executable=repository.git_executable,
    )
    staged_paths = tuple(
        sorted(
            item.decode("utf-8", "surrogateescape")
            for item in staged.stdout_bytes.split(b"\0")
            if item
        )
    )
    if not set(staged_paths) <= set(parse_allowlist(allowlist)):
        raise StateInconsistencyError("Index contains a path outside the allowlist")
    return staged_paths


def _gate_result_mapping(result: Any) -> Mapping[str, Any]:
    if hasattr(result, "as_dict"):
        value = result.as_dict()
    elif hasattr(result, "to_dict"):
        value = result.to_dict()
    elif isinstance(result, Mapping):
        value = dict(result)
    else:
        raise StateInconsistencyError("gate runner returned an invalid result")
    return value


def _retain_verification(
    manager: WorktreeManager, entry: WorktreeEntry | None
) -> str:
    if entry is None:
        return "not_created"
    try:
        current = manager.registry.get(entry.path)
        if current.status in {"active", "captured"}:
            manager.registry.update(replace(current, status="retained"))
            return "retained"
        return current.status
    except BaseException:
        return "retention_unconfirmed"


def verify_candidate_gates(
    *,
    repository: GitRepository,
    worktree_manager: WorktreeManager,
    run_id: str,
    task_id: str,
    candidate: WorktreeEntry,
    patch_path: str | os.PathLike[str],
    gate_runner_factory: GateRunnerFactory,
    evidence_store: EvidenceStore,
    state_root: str | os.PathLike[str],
    durable_task_policy: Mapping[str, Any],
    repository_identity: str,
    plan_sha256: str,
    gate_policy: Mapping[str, Any],
    quarantine_paths: Sequence[str] = (),
    quarantine_resolver: QuarantineResolver | None = None,
) -> CandidateGateVerification:
    """Independently run durable task gates against the exact captured patch."""

    if durable_task_policy.get("id") != task_id:
        raise StateInconsistencyError(
            "durable task policy ID does not match gate verification"
        )
    canonical_allowlist = durable_task_policy.get("allowedFiles")
    canonical_gates = durable_task_policy.get("verificationCommands")
    canonical_symlinks = durable_task_policy.get("approvedSymlinks", ())
    canonical_binary_context = durable_task_policy.get(
        "approvedBinaryContext", ()
    )
    if (
        not isinstance(canonical_allowlist, list)
        or not isinstance(canonical_gates, list)
        or not canonical_gates
    ):
        raise StateInconsistencyError(
            "durable task gate policy is malformed or empty"
        )
    allowed = parse_allowlist(canonical_allowlist)
    symlinks = _approved_symlink_map(canonical_symlinks)
    if candidate.task_id != task_id:
        raise StateInconsistencyError("candidate task ID does not match")
    recorded_candidate = worktree_manager.registry.get(candidate.path)
    if recorded_candidate != candidate:
        raise StateInconsistencyError("candidate disagrees with worktree state")
    if (
        candidate.status != "captured"
        or candidate.captured_patch_sha256 is None
    ):
        raise StateInconsistencyError("candidate is not durably captured")
    if candidate.writer_lock_path.exists() or candidate.writer_lock_path.is_symlink():
        raise PreconditionError("candidate still has an active writer lock")

    verification: WorktreeEntry | None = None
    cleanup_status = "not_created"
    gate_result_values: list[Mapping[str, Any]] = []
    gate_results: list[GateResult] = []
    patch = Path(patch_path).resolve()
    with repository_lock(state_root, timeout=0):
        if is_dirty(repository, include_untracked=True):
            raise PreconditionError(
                "orchestration checkout must be clean before gate verification"
            )
        if resolve_commit(repository, "HEAD") != candidate.base_commit:
            raise StateInconsistencyError(
                "orchestration HEAD differs from candidate base"
            )
        if current_branch(repository) is None:
            raise PreconditionError(
                "orchestration checkout must be on a branch"
            )

        verification_evidence = ensure_private_directory(
            evidence_store.independent_path(
                f"selection/{task_id}-{candidate.captured_patch_sha256[:12]}"
            )
        )
        prefix = (
            f"selection-verification-"
            f"{candidate.captured_patch_sha256[:8]}"
        )
        attempt = 1 + sum(
            entry.task_id == task_id and entry.provider.startswith(prefix)
            for entry in worktree_manager.registry.load()
        )
        try:
            verification = worktree_manager.create(
                run_id=run_id,
                task_id=task_id,
                provider=f"{prefix}-{attempt:02d}",
                base_commit=candidate.base_commit,
                evidence_dir=verification_evidence,
            )
            verification_repository = discover_repository(verification.path)
            metadata = inspect_patch(
                verification_repository,
                patch,
                expected_sha256=candidate.captured_patch_sha256,
                allowlist=allowed,
            )
            run_git(
                verification.path,
                ["apply", "--check", "--binary", str(patch)],
                git_executable=verification_repository.git_executable,
            )
            run_git(
                verification.path,
                ["apply", "--binary", str(patch)],
                git_executable=verification_repository.git_executable,
            )
            enforce_scope(
                verification_repository,
                base_commit=candidate.base_commit,
                allowlist=allowed,
                approved_symlinks=symlinks,
            )
            verification_diff = _binary_diff(
                verification_repository, candidate.base_commit
            )
            if sha256_bytes(verification_diff) != metadata.sha256:
                raise StateInconsistencyError(
                    "gate worktree does not reproduce the captured patch"
                )
            evidence_store.write_bytes(
                (
                    f"independent/selection/{task_id}-"
                    f"{candidate.captured_patch_sha256[:12]}.patch"
                ),
                verification_diff,
            )
            before_gate_hash = scoped_tree_hash(
                verification.path,
                allowed,
                approved_symlinks=symlinks,
            )
            exact_quarantine_paths = tuple(
                quarantine_resolver(verification.path)
                if quarantine_resolver is not None
                else quarantine_paths
            )
            quarantine_paths_sha256 = sha256_bytes(
                canonical_json_bytes(list(exact_quarantine_paths))
            )

            with worktree_manager.expose_to_provider(
                verification,
                evidence_dir=verification_evidence,
                quarantine_paths_list=exact_quarantine_paths,
                approved_binary_context=canonical_binary_context,
                runtime_metadata={
                    "purpose": "selection-gate-verification",
                    "candidatePatchSha256": candidate.captured_patch_sha256,
                },
            ):
                runner = gate_runner_factory(
                    verification.path, evidence_store
                )
                policy_root = Path(str(runner.policy.worktree)).resolve()
                if policy_root != verification.path.resolve():
                    raise StateInconsistencyError(
                        "gate runner is not bound to the verification worktree"
                    )
                for index, raw_command in enumerate(
                    canonical_gates, start=1
                ):
                    command = GateCommand.from_mapping(raw_command)
                    result = runner.run(
                        command,
                        result_name=(
                            f"selection-{task_id}-"
                            f"attempt-{attempt:02d}-{index:02d}"
                        ),
                    )
                    if not isinstance(result, GateResult):
                        raise StateInconsistencyError(
                            "selection gate runner returned an invalid result"
                        )
                    gate_result_values.append(
                        _gate_result_mapping(result)
                    )
                    gate_results.append(result)
                    if (
                        getattr(result, "passed", None) is not True
                        or getattr(result, "provenance", None)
                        != "independent"
                    ):
                        raise GateFailureError(
                            f"selection verification gate {index} failed"
                        )

            enforce_scope(
                verification_repository,
                base_commit=candidate.base_commit,
                allowlist=allowed,
                approved_symlinks=symlinks,
            )
            after_gate_diff = _binary_diff(
                verification_repository, candidate.base_commit
            )
            if sha256_bytes(after_gate_diff) != metadata.sha256:
                raise GateFailureError(
                    "selection gates changed the captured candidate tree"
                )
            verified_hash = scoped_tree_hash(
                verification.path,
                allowed,
                approved_symlinks=symlinks,
            )
            if verified_hash != before_gate_hash:
                raise GateFailureError(
                    "selection gates changed allowlisted candidate bytes"
                )

            captured_verification = replace(
                worktree_manager.registry.get(verification.path),
                status="captured",
                captured_patch_sha256=metadata.sha256,
            )
            worktree_manager.registry.update(captured_verification)
            cleaned = worktree_manager.cleanup(
                captured_verification,
                patch,
            )
            cleanup_status = cleaned.status
        except BaseException:
            cleanup_status = _retain_verification(
                worktree_manager, verification
            )
            raise

        task_policy = {
            key: durable_task_policy[key]
            for key in (
                "id",
                "baseCommit",
                "allowedFiles",
                "approvedBinaryContext",
                "approvedSymlinks",
                "verificationCommands",
            )
        }
        receipt = {
            "schemaVersion": 1,
            "producer": "crossforge-selection-gates-v1",
            "repositoryIdentity": repository_identity,
            "runId": run_id,
            "planSha256": plan_sha256,
            "taskId": task_id,
            "attempt": attempt,
            "taskPolicySha256": sha256_bytes(
                canonical_json_bytes(task_policy)
            ),
            "provider": candidate.provider,
            "candidatePath": str(candidate.path),
            "baseCommit": candidate.base_commit,
            "capturedPatchSha256": candidate.captured_patch_sha256,
            "gatePolicySha256": sha256_bytes(
                canonical_json_bytes(dict(gate_policy))
            ),
            "gateCommandsSha256": sha256_bytes(
                canonical_json_bytes(canonical_gates)
            ),
            "quarantinePathsSha256": quarantine_paths_sha256,
            "verifiedScopedTreeSha256": verified_hash,
            "verificationWorktree": str(verification.path),
            "verificationCleanup": cleanup_status,
            "gateResults": gate_result_values,
            "passed": True,
        }
        receipt_artifact = evidence_store.write_independent_json(
            (
                f"selection/{task_id}-"
                f"{candidate.captured_patch_sha256[:12]}-"
                f"attempt-{attempt:02d}.suite.json"
            ),
            receipt,
        )
        return CandidateGateVerification(
            gate_results=tuple(gate_results),
            verified_scoped_tree_sha256=verified_hash,
            quarantine_paths_sha256=quarantine_paths_sha256,
            verification_worktree=str(verification.path),
            verification_cleanup=cleanup_status,
            receipt_path=str(
                evidence_store.path(receipt_artifact.relative_path)
            ),
            receipt_sha256=receipt_artifact.sha256,
        )


def accept_candidate(
    *,
    repository: GitRepository,
    worktree_manager: WorktreeManager,
    run_id: str,
    task_id: str,
    candidate: WorktreeEntry,
    patch_path: str | os.PathLike[str],
    allowlist: Iterable[str],
    gate_commands: Sequence[GateCommand | Mapping[str, Any]],
    gate_runner_factory: GateRunnerFactory,
    evidence_store: EvidenceStore,
    commit_message: str,
    state_root: str | os.PathLike[str],
    approved_symlinks: Mapping[str, str] | Sequence[Mapping[str, Any]] | None = None,
    approved_binary_context: Sequence[Mapping[str, Any]] = (),
    approved_binary_outputs: Sequence[Mapping[str, Any]] = (),
    quarantine_paths: Sequence[str] = (),
    quarantine_resolver: QuarantineResolver | None = None,
    pre_apply_validator: PreApplyValidator | None = None,
    acceptance_intent_recorder: AcceptanceIntentRecorder | None = None,
    acceptance_finalizer: AcceptanceFinalizer | None = None,
    no_commit: bool = False,
    task_count: int = 1,
    keep_verification_worktree: bool = False,
    durable_task_policy: Mapping[str, Any] | None = None,
) -> AcceptanceResult:
    """Verify and accept one captured patch without executing it in orchestration."""

    if durable_task_policy is None:
        raise StateInconsistencyError(
            "candidate acceptance requires canonical durable task policy"
        )
    if durable_task_policy.get("id") != task_id:
        raise StateInconsistencyError("durable task policy ID does not match acceptance")
    canonical_allowlist = durable_task_policy.get("allowedFiles")
    canonical_gates = durable_task_policy.get("verificationCommands")
    canonical_symlinks = durable_task_policy.get("approvedSymlinks", ())
    canonical_binary_context = durable_task_policy.get("approvedBinaryContext", ())
    if not isinstance(canonical_allowlist, list) or not isinstance(canonical_gates, list):
        raise StateInconsistencyError("durable task policy is malformed")
    if list(allowlist) != canonical_allowlist:
        raise StateInconsistencyError(
            "acceptance allowlist differs from canonical durable task policy"
        )
    normalized_gates = [
        (
            item.as_dict()
            if isinstance(item, GateCommand)
            else dict(item)
            if isinstance(item, Mapping)
            else item
        )
        for item in gate_commands
    ]
    if normalized_gates != canonical_gates:
        raise StateInconsistencyError(
            "acceptance gates differ from canonical durable task policy"
        )
    supplied_symlinks = (
        [
            {"path": path, "target": target}
            for path, target in approved_symlinks.items()
        ]
        if isinstance(approved_symlinks, Mapping)
        else list(approved_symlinks or ())
    )
    if supplied_symlinks != list(canonical_symlinks):
        raise StateInconsistencyError(
            "acceptance symlink approvals differ from canonical durable task policy"
        )
    if list(approved_binary_context) != list(canonical_binary_context):
        raise StateInconsistencyError(
            "acceptance binary context differs from canonical durable task policy"
        )

    allowed = parse_allowlist(canonical_allowlist)
    symlinks = _approved_symlink_map(canonical_symlinks)
    if no_commit and task_count != 1:
        raise InvalidInputError("no-commit mode requires exactly one task")
    if not gate_commands:
        raise InvalidInputError("candidate acceptance requires at least one gate")
    if candidate.task_id != task_id:
        raise StateInconsistencyError("selected candidate task ID does not match")
    recorded_candidate = worktree_manager.registry.get(candidate.path)
    if recorded_candidate != candidate:
        raise StateInconsistencyError("selected candidate disagrees with worktree state")
    if candidate.status != "captured" or candidate.captured_patch_sha256 is None:
        raise StateInconsistencyError("selected candidate is not durably captured")
    if candidate.writer_lock_path.exists() or candidate.writer_lock_path.is_symlink():
        raise PreconditionError("selected candidate still has an active writer lock")
    task_base = candidate.base_commit
    if _CONTROL.search(commit_message) or not commit_message.strip():
        raise InvalidInputError("commit message is invalid")
    if re.search(r"(?im)^co-authored-by:", commit_message):
        raise InvalidInputError("AI co-author attribution is not permitted")

    verification: WorktreeEntry | None = None
    cleanup_status = "not_created"
    gate_result_values: list[Mapping[str, Any]] = []
    patch = Path(patch_path).resolve()
    with repository_lock(state_root, timeout=0):
        if is_dirty(repository, include_untracked=True):
            raise PreconditionError("orchestration checkout must be clean before acceptance")
        if resolve_commit(repository, "HEAD") != task_base:
            raise StateInconsistencyError("orchestration HEAD differs from task base")
        if current_branch(repository) is None:
            raise PreconditionError("orchestration checkout must be on a branch")

        verification_evidence = ensure_private_directory(
            evidence_store.independent_path(
                f"acceptance/{task_id}-{candidate.captured_patch_sha256[:12]}"
            )
        )
        try:
            verification = worktree_manager.create(
                run_id=run_id,
                task_id=task_id,
                provider=f"verification-{candidate.captured_patch_sha256[:8]}",
                base_commit=task_base,
                evidence_dir=verification_evidence,
            )
            verification_repository = discover_repository(verification.path)
            metadata = inspect_patch(
                verification_repository,
                patch,
                expected_sha256=candidate.captured_patch_sha256,
                allowlist=allowed,
            )
            run_git(
                verification.path,
                ["apply", "--check", "--binary", str(patch)],
                git_executable=verification_repository.git_executable,
            )
            run_git(
                verification.path,
                ["apply", "--binary", str(patch)],
                git_executable=verification_repository.git_executable,
            )
            enforce_scope(
                verification_repository,
                base_commit=task_base,
                allowlist=allowed,
                approved_symlinks=symlinks,
            )
            verification_diff = _binary_diff(verification_repository, task_base)
            if sha256_bytes(verification_diff) != metadata.sha256:
                raise StateInconsistencyError(
                    "verification worktree does not reproduce the captured patch"
                )
            evidence_store.write_bytes(
                f"independent/acceptance/{task_id}-verified-before-gates.patch",
                verification_diff,
            )
            _binary_changes_are_approved(
                verification.path, metadata.paths, approved_binary_outputs
            )
            before_gate_hash = scoped_tree_hash(
                verification.path,
                allowed,
                approved_symlinks=symlinks,
            )
            exact_quarantine_paths = tuple(
                quarantine_resolver(verification.path)
                if quarantine_resolver is not None
                else quarantine_paths
            )
            quarantine_paths_sha256 = sha256_bytes(
                canonical_json_bytes(list(exact_quarantine_paths))
            )

            with worktree_manager.expose_to_provider(
                verification,
                evidence_dir=verification_evidence,
                quarantine_paths_list=exact_quarantine_paths,
                approved_binary_context=approved_binary_context,
                runtime_metadata={"purpose": "acceptance-verification"},
            ):
                runner = gate_runner_factory(verification.path, evidence_store)
                policy_root = Path(str(runner.policy.worktree)).resolve()
                if policy_root != verification.path.resolve():
                    raise StateInconsistencyError(
                        "gate runner is not bound to the verification worktree"
                    )
                for index, raw_command in enumerate(gate_commands, start=1):
                    command = (
                        raw_command
                        if isinstance(raw_command, GateCommand)
                        else GateCommand.from_mapping(raw_command)
                    )
                    result = runner.run(
                        command,
                        result_name=f"acceptance-{task_id}-{index:02d}",
                    )
                    gate_result_values.append(_gate_result_mapping(result))
                    if (
                        getattr(result, "passed", None) is not True
                        or getattr(result, "provenance", None) != "independent"
                    ):
                        raise GateFailureError(
                            f"acceptance verification gate {index} failed"
                        )

            enforce_scope(
                verification_repository,
                base_commit=task_base,
                allowlist=allowed,
                approved_symlinks=symlinks,
            )
            after_gate_diff = _binary_diff(verification_repository, task_base)
            if sha256_bytes(after_gate_diff) != metadata.sha256:
                raise GateFailureError(
                    "verification gates changed the captured candidate tree"
                )
            verified_hash = scoped_tree_hash(
                verification.path,
                allowed,
                approved_symlinks=symlinks,
            )
            if verified_hash != before_gate_hash:
                raise GateFailureError(
                    "verification gates changed allowlisted candidate bytes"
                )

            captured_verification = replace(
                worktree_manager.registry.get(verification.path),
                status="captured",
                captured_patch_sha256=metadata.sha256,
            )
            worktree_manager.registry.update(captured_verification)
            if keep_verification_worktree:
                worktree_manager.registry.update(
                    replace(captured_verification, status="retained")
                )
                cleanup_status = "retained"
            else:
                cleaned = worktree_manager.cleanup(
                    captured_verification,
                    patch,
                )
                cleanup_status = cleaned.status
        except BaseException:
            cleanup_status = _retain_verification(worktree_manager, verification)
            raise

        # Nothing above this point changed or executed code in orchestration.
        if is_dirty(repository, include_untracked=True):
            raise StateInconsistencyError(
                "orchestration checkout changed during isolated verification"
            )
        if resolve_commit(repository, "HEAD") != task_base:
            raise StateInconsistencyError(
                "orchestration HEAD changed during isolated verification"
            )
        if pre_apply_validator is not None:
            pre_apply_validator(
                verified_hash,
                quarantine_paths_sha256,
            )
        if acceptance_intent_recorder is not None:
            acceptance_intent_recorder(
                verified_hash,
                quarantine_paths_sha256,
            )
        run_git(
            repository.root,
            ["apply", "--check", "--binary", str(patch)],
            git_executable=repository.git_executable,
        )
        run_git(
            repository.root,
            ["apply", "--binary", str(patch)],
            git_executable=repository.git_executable,
        )
        enforce_scope(
            repository,
            base_commit=task_base,
            allowlist=allowed,
            approved_symlinks=symlinks,
        )
        applied_diff = _binary_diff(repository, task_base)
        if sha256_bytes(applied_diff) != candidate.captured_patch_sha256:
            raise StateInconsistencyError(
                "applied orchestration patch differs from verified candidate"
            )
        applied_hash = scoped_tree_hash(
            repository.root,
            allowed,
            approved_symlinks=symlinks,
        )
        if applied_hash != verified_hash:
            raise StateInconsistencyError(
                "orchestration scoped tree differs from verified scoped tree"
            )
        stage_allowlist_filter_free(
            repository,
            allowed,
            approved_symlinks=symlinks,
        )
        staged_paths = _verify_index_matches_manifest(
            repository,
            base_commit=task_base,
            allowlist=allowed,
            approved_symlinks=symlinks,
        )

        commit: str | None = None
        if not no_commit:
            empty_hooks = ensure_private_directory(
                evidence_store.independent_path("acceptance/empty-hooks")
            )
            run_git(
                repository.root,
                [
                    "-c",
                    f"core.hooksPath={empty_hooks}",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "--no-verify",
                    "--no-gpg-sign",
                    "-m",
                    commit_message,
                ],
                environment={
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_OPTIONAL_LOCKS": "0",
                },
                git_executable=repository.git_executable,
            )
            commit = resolve_commit(repository, "HEAD")
            if commit == task_base:
                raise StateInconsistencyError("task commit did not advance HEAD")
            if is_dirty(repository, include_untracked=True):
                raise StateInconsistencyError("task commit did not leave a clean checkout")

        result = AcceptanceResult(
            task_id=task_id,
            provider=candidate.provider,
            patch_sha256=candidate.captured_patch_sha256,
            verified_scoped_tree_sha256=verified_hash,
            applied_scoped_tree_sha256=applied_hash,
            quarantine_paths_sha256=quarantine_paths_sha256,
            gate_results=tuple(gate_result_values),
            staged_paths=staged_paths,
            commit=commit,
            no_commit=no_commit,
            verification_worktree=str(verification.path),
            verification_cleanup=cleanup_status,
        )
        if acceptance_finalizer is not None:
            acceptance_finalizer(result)
        return result


__all__ = [
    "AcceptanceResult",
    "CandidateGateVerification",
    "EligibilityResult",
    "GateRunnerFactory",
    "MicroFixResult",
    "PatchMetadata",
    "accept_candidate",
    "assess_candidate_eligibility",
    "build_commit_message",
    "check_micro_fix",
    "inspect_patch",
    "validate_acceptance_state",
    "verify_candidate_gates",
]
