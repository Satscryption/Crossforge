"""Safe candidate-worktree lifecycle management.

This module owns paths only after they have been recorded in ``worktrees.json``.
It deliberately delegates lock ownership and provider-context quarantine to the
``locking`` and ``secrets`` modules while keeping Git projection and patch
capture mechanics here.
"""

from __future__ import annotations

import codecs
import json
import os
import re
import stat
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterator, Mapping, Sequence

from .errors import PreconditionError, StateInconsistencyError
from .locking import FileLock
from .util import (
    atomic_write_bytes,
    atomic_write_json,
    ensure_private_directory,
    sha256_bytes,
    sha256_file,
    utc_now,
)


_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_ENTRY_KEYS = {
    "taskId",
    "provider",
    "path",
    "baseCommit",
    "status",
    "writerLockPath",
    "capturedPatchSha256",
    "invocationEvidenceSha256",
    "createdAt",
    "cleanedAt",
}
_ENTRY_REQUIRED_KEYS = _ENTRY_KEYS - {"invocationEvidenceSha256"}
_REGISTRY_KEYS = {"schemaVersion", "worktreeRoot", "entries"}
_ENTRY_STATUSES = {
    "creating",
    "active",
    "captured",
    "blocked",
    "retained",
    "cleaned",
}


class WorktreeError(PreconditionError):
    """A worktree operation could not be proven safe."""


class WorktreeStateError(StateInconsistencyError):
    """Recorded worktree state is invalid or disagrees with the filesystem."""


@dataclass(frozen=True)
class WorktreeEntry:
    """One strictly validated ``worktrees.json`` entry."""

    task_id: str
    provider: str
    path: Path
    base_commit: str
    status: str
    writer_lock_path: Path
    captured_patch_sha256: str | None
    invocation_evidence_sha256: str | None
    created_at: str
    cleaned_at: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "taskId": self.task_id,
            "provider": self.provider,
            "path": str(self.path),
            "baseCommit": self.base_commit,
            "status": self.status,
            "writerLockPath": str(self.writer_lock_path),
            "capturedPatchSha256": self.captured_patch_sha256,
            "invocationEvidenceSha256": self.invocation_evidence_sha256,
            "createdAt": self.created_at,
            "cleanedAt": self.cleaned_at,
        }

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "WorktreeEntry":
        unknown = set(value) - _ENTRY_KEYS
        missing = _ENTRY_REQUIRED_KEYS - set(value)
        if unknown or missing:
            raise WorktreeStateError(
                "Invalid worktree entry keys",
                details={"unknown": sorted(unknown), "missing": sorted(missing)},
            )
        for name in ("taskId", "provider", "path", "baseCommit", "status", "writerLockPath", "createdAt"):
            if not isinstance(value[name], str) or not value[name]:
                raise WorktreeStateError(f"Invalid worktree entry field: {name}")
        if value["status"] not in _ENTRY_STATUSES:
            raise WorktreeStateError(f"Invalid worktree status: {value['status']}")
        if not _COMMIT_RE.fullmatch(value["baseCommit"]):
            raise WorktreeStateError("Worktree baseCommit must be a 40-character lowercase SHA-1")
        for name in ("capturedPatchSha256", "invocationEvidenceSha256"):
            field = value.get(name)
            if field is not None and (
                not isinstance(field, str) or not re.fullmatch(r"[0-9a-f]{64}", field)
            ):
                raise WorktreeStateError(f"Invalid worktree entry field: {name}")
        if value["cleanedAt"] is not None and not isinstance(value["cleanedAt"], str):
            raise WorktreeStateError("Invalid worktree entry field: cleanedAt")
        return cls(
            task_id=value["taskId"],
            provider=value["provider"],
            path=Path(value["path"]),
            base_commit=value["baseCommit"],
            status=value["status"],
            writer_lock_path=Path(value["writerLockPath"]),
            captured_patch_sha256=value["capturedPatchSha256"],
            invocation_evidence_sha256=value.get("invocationEvidenceSha256"),
            created_at=value["createdAt"],
            cleaned_at=value["cleanedAt"],
        )


@dataclass(frozen=True)
class ProjectionState:
    """Evidence required to restore a linked worktree after provider exposure."""

    worktree: Path
    evidence_dir: Path
    git_control_evidence: Path
    git_control_sha256: str
    git_control_mode: int
    isolated_git_fingerprint: str
    isolated_commit: str
    isolated_tree: str
    sanitized_home: Path
    global_config: Path


@dataclass(frozen=True)
class ProviderContext:
    """Prepared provider-visible context yielded by :meth:`expose_to_provider`."""

    entry: WorktreeEntry
    source_manifest: Mapping[str, Any]
    context_manifest: Mapping[str, Any]
    quarantine_manifest: Mapping[str, Any]
    projection: ProjectionState


class WorktreeRegistry:
    """Strict, atomic persistence for ``worktrees.json``."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        worktree_root: str | os.PathLike[str],
        *,
        lock_timeout: float = 10.0,
    ):
        self.path = Path(path)
        self.worktree_root = _canonicalize_root(Path(worktree_root))
        self.lock_path = self.path.parent / "locks" / "worktrees.lock"
        self.lock_timeout = lock_timeout
        ensure_private_directory(self.lock_path.parent)

    def load(self) -> list[WorktreeEntry]:
        if not self.path.exists():
            return []
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise WorktreeStateError(f"Cannot read worktree registry: {self.path}") from exc
        if not isinstance(value, dict):
            raise WorktreeStateError("Worktree registry must be a JSON object")
        unknown = set(value) - _REGISTRY_KEYS
        missing = _REGISTRY_KEYS - set(value)
        if unknown or missing:
            raise WorktreeStateError(
                "Invalid worktree registry keys",
                details={"unknown": sorted(unknown), "missing": sorted(missing)},
            )
        if value["schemaVersion"] != 1:
            raise WorktreeStateError("Unsupported worktree registry schemaVersion")
        if value["worktreeRoot"] != str(self.worktree_root):
            raise WorktreeStateError("Recorded worktree root does not match configured canonical root")
        if not isinstance(value["entries"], list):
            raise WorktreeStateError("Worktree registry entries must be an array")
        entries = [WorktreeEntry.from_json(item) for item in value["entries"]]
        paths: set[Path] = set()
        for entry in entries:
            normalized = _contained_path(self.worktree_root, entry.path)
            if normalized != entry.path:
                raise WorktreeStateError("Recorded worktree path is not canonical")
            if entry.path in paths:
                raise WorktreeStateError(f"Duplicate recorded worktree path: {entry.path}")
            paths.add(entry.path)
        return entries

    def _write_unlocked(self, entries: Sequence[WorktreeEntry]) -> None:
        for entry in entries:
            if _contained_path(self.worktree_root, entry.path) != entry.path:
                raise WorktreeStateError("Cannot record a non-canonical worktree path")
        atomic_write_json(
            self.path,
            {
                "schemaVersion": 1,
                "worktreeRoot": str(self.worktree_root),
                "entries": [entry.to_json() for entry in entries],
            },
        )

    def write(self, entries: Sequence[WorktreeEntry]) -> None:
        with FileLock(self.lock_path, kind="run", timeout=self.lock_timeout):
            self._write_unlocked(entries)

    def add(self, entry: WorktreeEntry) -> None:
        with FileLock(self.lock_path, kind="run", timeout=self.lock_timeout):
            entries = self.load()
            if any(existing.path == entry.path for existing in entries):
                raise WorktreeStateError(f"Worktree path is already recorded: {entry.path}")
            entries.append(entry)
            self._write_unlocked(entries)

    def update(self, entry: WorktreeEntry) -> None:
        with FileLock(self.lock_path, kind="run", timeout=self.lock_timeout):
            entries = self.load()
            matches = [index for index, existing in enumerate(entries) if existing.path == entry.path]
            if len(matches) != 1:
                raise WorktreeStateError(f"Expected one recorded worktree: {entry.path}")
            entries[matches[0]] = entry
            self._write_unlocked(entries)

    def get(self, path: str | os.PathLike[str]) -> WorktreeEntry:
        canonical = _contained_path(self.worktree_root, Path(path))
        matches = [entry for entry in self.load() if entry.path == canonical]
        if len(matches) != 1:
            raise WorktreeStateError(f"Worktree is not recorded exactly once: {canonical}")
        return matches[0]


class WorktreeManager:
    """Create, expose, capture, prove, and clean disposable Git worktrees."""

    def __init__(
        self,
        repository: str | os.PathLike[str],
        worktree_root: str | os.PathLike[str],
        registry_path: str | os.PathLike[str],
        *,
        repository_id_prefix: str | None = None,
    ) -> None:
        self.repository = Path(repository).resolve(strict=True)
        if not self.repository.is_dir():
            raise WorktreeError(f"Repository is not a directory: {self.repository}")
        self.worktree_root = _canonicalize_root(Path(worktree_root))
        self.registry = WorktreeRegistry(registry_path, self.worktree_root)
        derived = sha256_bytes(str(self.repository).encode("utf-8"))[:12]
        self.repository_id_prefix = _safe_component(repository_id_prefix or derived, "repository id")

    def create(
        self,
        *,
        run_id: str,
        task_id: str,
        provider: str,
        base_commit: str,
        evidence_dir: str | os.PathLike[str],
    ) -> WorktreeEntry:
        run_component = _safe_component(run_id, "run id")
        task_component = _safe_component(task_id, "task id")
        provider_component = _safe_component(provider, "provider")
        resolved_base = self._git_text(self.repository, "rev-parse", "--verify", f"{base_commit}^{{commit}}")
        if not _COMMIT_RE.fullmatch(resolved_base):
            raise WorktreeError("Git repository does not use the required 40-character object IDs")
        destination = _contained_path(
            self.worktree_root,
            self.worktree_root
            / self.repository_id_prefix
            / run_component
            / f"{task_component}-{provider_component}",
        )
        _assert_no_symlink_components(self.worktree_root, destination.parent)
        if destination.exists() or destination.is_symlink():
            raise WorktreeError(f"Worktree destination already exists: {destination}")
        ensure_private_directory(destination.parent)
        evidence = ensure_private_directory(Path(evidence_dir).resolve(strict=False))
        entry = WorktreeEntry(
            task_id=task_id,
            provider=provider,
            path=destination,
            base_commit=resolved_base,
            status="creating",
            writer_lock_path=evidence / "writer.lock",
            captured_patch_sha256=None,
            invocation_evidence_sha256=None,
            created_at=utc_now(),
            cleaned_at=None,
        )
        self.registry.add(entry)
        try:
            self._git(self.repository, "worktree", "add", "--detach", str(destination), resolved_base)
            self.validate(entry)
        except Exception:
            if destination.exists():
                self.registry.update(replace(entry, status="blocked"))
            raise
        entry = replace(entry, status="active")
        self.registry.update(entry)
        return entry

    def validate(self, entry: WorktreeEntry, *, require_clean: bool = True) -> None:
        recorded = self.registry.get(entry.path)
        if recorded.base_commit != entry.base_commit:
            raise WorktreeStateError("Worktree entry base commit disagrees with registry")
        path = _contained_path(self.worktree_root, entry.path)
        _assert_no_symlink_components(self.worktree_root, path)
        if not path.is_dir():
            raise WorktreeStateError(f"Recorded worktree is missing: {path}")
        head = self._git_text(path, "rev-parse", "HEAD")
        if head != entry.base_commit:
            raise WorktreeStateError(
                "Worktree HEAD does not equal its recorded base commit",
                details={"expected": entry.base_commit, "actual": head},
            )
        if require_clean and self._git_bytes(path, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
            raise WorktreeStateError(f"Candidate worktree did not start clean: {path}")

    def recover_missing(self, entry: WorktreeEntry, *, uncaptured_changes: bool) -> WorktreeEntry:
        """Recreate a missing recorded candidate only when no changes were lost."""

        recorded = self.registry.get(entry.path)
        if recorded.path.exists():
            self.validate(recorded, require_clean=recorded.status in {"creating", "active"})
            return recorded
        if uncaptured_changes or recorded.captured_patch_sha256 is not None:
            raise WorktreeStateError("Cannot recreate a missing worktree with candidate changes")
        if recorded.status not in {"creating", "active", "blocked"}:
            raise WorktreeStateError(f"Cannot recreate worktree in status {recorded.status}")
        _assert_no_symlink_components(self.worktree_root, recorded.path.parent)
        ensure_private_directory(recorded.path.parent)
        self._git(
            self.repository,
            "worktree",
            "add",
            "--detach",
            str(recorded.path),
            recorded.base_commit,
        )
        recovered = replace(recorded, status="active")
        self.registry.update(recovered)
        self.validate(recovered)
        return recovered

    def acquire_writer_lock(
        self,
        entry: WorktreeEntry,
        *,
        timeout: float = 0,
        approve_foreign_stale: Callable[[Mapping[str, Any]], bool] | None = None,
    ) -> Any:
        """Acquire the owning T4 lock implementation for this exact worktree."""

        self.registry.get(entry.path)
        from .locking import FileLock

        lock = FileLock(
            entry.writer_lock_path,
            kind="writer",
            provider=entry.provider,
            worktree=str(entry.path),
            timeout=timeout,
            approve_foreign_stale=approve_foreign_stale,
        )
        lock.acquire()
        return lock

    def quarantine_context(
        self,
        entry: WorktreeEntry,
        paths: Sequence[str],
        quarantine_dir: str | os.PathLike[str],
        *,
        git_modes: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]:
        """Delegate byte-exact deny/binary quarantine to the T5 implementation."""

        self.registry.get(entry.path)
        from .secrets import quarantine_paths

        return quarantine_paths(
            entry.path,
            paths,
            Path(quarantine_dir),
            git_modes=git_modes,
        )

    def restore_context(
        self,
        entry: WorktreeEntry,
        quarantine_dir: str | os.PathLike[str],
        manifest: Mapping[str, Any],
        *,
        conflict_dir: str | os.PathLike[str] | None = None,
    ) -> Mapping[str, Any]:
        self.registry.get(entry.path)
        from .secrets import restore_quarantine

        return restore_quarantine(
            entry.path,
            Path(quarantine_dir),
            manifest,
            conflict_dir=Path(conflict_dir) if conflict_dir is not None else None,
        )

    @contextmanager
    def expose_to_provider(
        self,
        entry: WorktreeEntry,
        *,
        evidence_dir: str | os.PathLike[str],
        quarantine_paths_list: Sequence[str] = (),
        approved_binary_context: Sequence[Mapping[str, Any]] = (),
        git_modes: Mapping[str, str] | None = None,
        lock_timeout: float = 0,
        runtime_metadata: Mapping[str, Any] | None = None,
    ) -> Iterator[ProviderContext]:
        """Prepare and always restore a complete provider trust boundary."""

        evidence = _evidence_outside_worktree(entry.path, Path(evidence_dir))
        evidence = ensure_private_directory(evidence)
        quarantine_dir = evidence / "quarantine"
        conflict_dir = evidence / "provider-denied-conflicts"
        lock = self.acquire_writer_lock(entry, timeout=lock_timeout)
        quarantine_manifest: Mapping[str, Any] = {"entries": []}
        projection: ProjectionState | None = None
        try:
            from .secrets import build_context_manifest

            initial_manifest = build_context_manifest(
                entry.path,
                excluded_paths=(".git",),
            )
            approved_binary = _approved_binary_pairs(approved_binary_context)
            binary_paths = [
                str(item["path"])
                for item in initial_manifest["files"]
                if item["fileType"] == "regular"
                and _is_binary_file(entry.path / Path(str(item["path"])))
                and (str(item["path"]), str(item["sha256"])) not in approved_binary
            ]
            quarantine_manifest = self.quarantine_context(
                entry,
                sorted(set(quarantine_paths_list) | set(binary_paths)),
                quarantine_dir,
                git_modes=git_modes,
            )
            context_manifest = build_context_manifest(
                entry.path,
                output_path=evidence / "context-manifest.json",
                excluded_paths=(".git",),
            )
            manifest_paths = _manifest_paths(context_manifest)
            projection = self.prepare_projection(
                entry,
                evidence_dir=evidence,
                manifest_paths=manifest_paths,
                runtime_metadata=runtime_metadata,
            )
            yield ProviderContext(
                entry,
                initial_manifest,
                context_manifest,
                quarantine_manifest,
                projection,
            )
        finally:
            restoration_error: BaseException | None = None
            if projection is not None:
                try:
                    self.restore_projection(projection)
                except BaseException as exc:
                    restoration_error = exc
            try:
                quarantine_result = self.restore_context(
                    entry,
                    quarantine_dir,
                    quarantine_manifest,
                    conflict_dir=conflict_dir,
                )
                if quarantine_result.get("scopeViolation"):
                    restoration_error = restoration_error or WorktreeStateError(
                        "Provider created a conflicting denied path"
                    )
            except BaseException as exc:
                restoration_error = restoration_error or exc
            try:
                lock.release()
            except BaseException as exc:
                restoration_error = restoration_error or exc
            if restoration_error is not None:
                self.registry.update(replace(self.registry.get(entry.path), status="blocked"))
                raise WorktreeStateError(
                    "Provider context restoration proof failed; worktree retained"
                ) from restoration_error

    def prepare_projection(
        self,
        entry: WorktreeEntry,
        *,
        evidence_dir: str | os.PathLike[str],
        manifest_paths: Sequence[str],
        runtime_metadata: Mapping[str, Any] | None = None,
    ) -> ProjectionState:
        """Replace a linked-worktree control file with a one-commit repository."""

        self.registry.get(entry.path)
        worktree = _contained_path(self.worktree_root, entry.path)
        git_control = worktree / ".git"
        info = git_control.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise WorktreeError("Expected linked-worktree .git control file")
        evidence_root = _evidence_outside_worktree(entry.path, Path(evidence_dir))
        evidence = ensure_private_directory(evidence_root / "git-projection")
        saved_control = evidence / "linked-worktree.git"
        if saved_control.exists() or saved_control.is_symlink():
            raise WorktreeError(f"Git-control evidence already exists: {saved_control}")
        control_bytes = git_control.read_bytes()
        control_hash = sha256_bytes(control_bytes)
        control_mode = stat.S_IMODE(info.st_mode)
        os.replace(git_control, saved_control)
        os.chmod(saved_control, 0o600)

        sanitized_home = ensure_private_directory(evidence / "home")
        global_config = evidence / "global.gitconfig"
        atomic_write_bytes(global_config, b"", mode=0o600)
        hooks_dir = ensure_private_directory(evidence / "empty-hooks")
        env = _sanitized_git_environment(sanitized_home, global_config)
        try:
            self._git(worktree, "init", "--quiet", env=env)
            config_pairs = (
                ("user.name", "Crossforge"),
                ("user.email", "crossforge@invalid"),
                ("core.hooksPath", str(hooks_dir)),
                ("commit.gpgSign", "false"),
                ("tag.gpgSign", "false"),
                ("credential.helper", ""),
                ("maintenance.auto", "false"),
                ("gc.auto", "0"),
                ("fetch.writeCommitGraph", "false"),
                ("core.autocrlf", "false"),
            )
            for key, value in config_pairs:
                self._git(worktree, "config", "--local", key, value, env=env)
            normalized_paths = _validate_manifest_paths(worktree, manifest_paths)
            for relative in normalized_paths:
                self._git(worktree, "add", "-f", "--", relative, env=env)
            commit_env = dict(env)
            commit_env.update(
                {
                    "GIT_AUTHOR_NAME": "Crossforge",
                    "GIT_AUTHOR_EMAIL": "crossforge@invalid",
                    "GIT_COMMITTER_NAME": "Crossforge",
                    "GIT_COMMITTER_EMAIL": "crossforge@invalid",
                    "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
                    "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
                }
            )
            self._git(
                worktree,
                "commit",
                "--quiet",
                "--allow-empty",
                "--no-gpg-sign",
                "--no-verify",
                "-m",
                "Crossforge provider baseline",
                env=commit_env,
            )
            if self._git_text(worktree, "remote", "-v", env=env):
                raise WorktreeStateError("Sanitized provider repository unexpectedly has a remote")
            if self._git_text(worktree, "rev-list", "--all", "--count", env=env) != "1":
                raise WorktreeStateError("Sanitized provider repository must contain one commit")
            forbidden_config = self._git_text(
                worktree,
                "config",
                "--local",
                "--get-regexp",
                r"^(remote\.|credential\.|filter\..*\.(clean|smudge|process)$)",
                env=env,
                check=False,
            )
            forbidden_lines = [
                line
                for line in forbidden_config.splitlines()
                if line
                and line != "credential.helper"
                and not line.startswith("credential.helper ")
            ]
            if forbidden_lines:
                raise WorktreeStateError("Sanitized provider repository has forbidden Git config")
            commit = self._git_text(worktree, "rev-parse", "HEAD", env=env)
            tree = self._git_text(worktree, "rev-parse", "HEAD^{tree}", env=env)
            fingerprint = _directory_fingerprint(worktree / ".git")
            state = ProjectionState(
                worktree=worktree,
                evidence_dir=evidence,
                git_control_evidence=saved_control,
                git_control_sha256=control_hash,
                git_control_mode=control_mode,
                isolated_git_fingerprint=fingerprint,
                isolated_commit=commit,
                isolated_tree=tree,
                sanitized_home=sanitized_home,
                global_config=global_config,
            )
            runtime = {
                "schemaVersion": 1,
                "isolatedCommit": commit,
                "isolatedTree": tree,
                "identity": {
                    "name": "Crossforge",
                    "email": "crossforge@invalid",
                },
                "gitConfiguration": {
                    "credentialHelper": "disabled",
                    "globalConfig": "empty-explicit",
                    "hooksPath": "empty-owner-only-directory",
                    "signing": "disabled",
                    "systemConfig": "disabled",
                },
            }
            if runtime_metadata:
                runtime["runtime"] = _safe_runtime_metadata(runtime_metadata)
            atomic_write_json(evidence.parent / "runtime-manifest.json", runtime)
            return state
        except BaseException:
            if git_control.is_dir() and not git_control.is_symlink():
                _remove_isolated_git_directory(worktree, git_control)
            if saved_control.exists() and not git_control.exists():
                os.replace(saved_control, git_control)
                os.chmod(git_control, control_mode)
            raise

    def restore_projection(self, state: ProjectionState) -> dict[str, Any]:
        worktree = _contained_path(self.worktree_root, state.worktree)
        git_dir = worktree / ".git"
        if not git_dir.is_dir() or git_dir.is_symlink():
            raise WorktreeStateError("Isolated provider .git directory is missing or unsafe")
        changed = _directory_fingerprint(git_dir) != state.isolated_git_fingerprint
        _remove_isolated_git_directory(worktree, git_dir)
        if git_dir.exists() or git_dir.is_symlink():
            raise WorktreeStateError("Could not remove isolated provider Git metadata")
        if sha256_file(state.git_control_evidence) != state.git_control_sha256:
            raise WorktreeStateError("Quarantined linked-worktree Git control file changed")
        os.replace(state.git_control_evidence, git_dir)
        os.chmod(git_dir, state.git_control_mode)
        if sha256_file(git_dir) != state.git_control_sha256:
            raise WorktreeStateError("Linked-worktree Git control restoration hash mismatch")
        return {"isolatedGitMetadataChanged": changed, "restored": True}

    def capture_patch(
        self,
        entry: WorktreeEntry,
        patch_path: str | os.PathLike[str],
    ) -> WorktreeEntry:
        """Capture a binary patch and prove it applies to a clean detached base."""

        current = self.registry.get(entry.path)
        if current.status != "active":
            raise WorktreeStateError(f"Cannot capture worktree in status {current.status}")
        self.validate(current, require_clean=False)
        untracked = self._untracked_paths(current.path)
        for relative in untracked:
            self._git(current.path, "add", "--intent-to-add", "--", relative)
        try:
            patch = self._git_bytes(
                current.path,
                "diff",
                "--binary",
                "--no-ext-diff",
                "--no-renames",
                current.base_commit,
                "--",
            )
            if not patch:
                raise WorktreeError("Candidate produced no patch")
            destination = Path(patch_path)
            atomic_write_bytes(destination, patch)
            patch_hash = sha256_bytes(patch)
            try:
                self._prove_patch_applies(current, destination)
            except BaseException:
                self.registry.update(replace(current, status="blocked"))
                raise
        finally:
            for relative in untracked:
                self._git(current.path, "reset", "--quiet", "--", relative, check=False)
        if sha256_file(destination) != patch_hash:
            raise WorktreeStateError("Captured patch changed while clearing intent-to-add entries")
        captured = replace(current, status="captured", captured_patch_sha256=patch_hash)
        self.registry.update(captured)
        return captured

    def cleanup(
        self,
        entry: WorktreeEntry,
        patch_path: str | os.PathLike[str],
        *,
        evidence_durable: bool,
        retention_permits: bool = True,
    ) -> WorktreeEntry:
        """Remove a candidate only after exact reverse-patch and cleanliness proof."""

        current = self.registry.get(entry.path)
        if not evidence_durable:
            raise WorktreeError("Cannot clean worktree before evidence is durable")
        if not retention_permits:
            retained = replace(current, status="retained")
            self.registry.update(retained)
            return retained
        if current.writer_lock_path.exists() or current.writer_lock_path.is_symlink():
            raise WorktreeError("Cannot clean worktree while writer lock exists")
        if current.status != "captured" or current.captured_patch_sha256 is None:
            raise WorktreeStateError("Only a captured candidate can be cleaned")
        path = _contained_path(self.worktree_root, current.path)
        _assert_no_symlink_components(self.worktree_root, path)
        patch = Path(patch_path)
        if not patch.is_file() or patch.is_symlink():
            raise WorktreeError("Captured patch is missing or is not a regular file")
        if sha256_file(patch) != current.captured_patch_sha256:
            raise WorktreeStateError("Captured patch hash does not match worktree state")

        untracked = self._untracked_paths(path)
        for relative in untracked:
            self._git(path, "add", "--intent-to-add", "--", relative)
        try:
            actual = self._git_bytes(
                path,
                "diff",
                "--binary",
                "--no-ext-diff",
                "--no-renames",
                current.base_commit,
                "--",
            )
        finally:
            for relative in untracked:
                self._git(path, "reset", "--quiet", "--", relative, check=False)
        if sha256_bytes(actual) != current.captured_patch_sha256:
            raise WorktreeStateError("Worktree contains uncaptured changes; retaining it")
        self._git(path, "reset", "--mixed", "--quiet", current.base_commit, "--")
        self._git(path, "apply", "--reverse", "--check", "--binary", str(patch))
        self._git(path, "apply", "--reverse", "--binary", str(patch))
        if self._git_bytes(path, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
            raise WorktreeStateError("Reverse-patch cleanup did not produce a clean worktree")
        self._git(self.repository, "worktree", "remove", str(path))
        if path.exists() or path.is_symlink():
            raise WorktreeStateError("Git reported worktree removal but path still exists")
        cleaned = replace(current, status="cleaned", cleaned_at=utc_now())
        self.registry.update(cleaned)
        return cleaned

    def _prove_patch_applies(self, entry: WorktreeEntry, patch_path: Path) -> None:
        proof_provider = f"{entry.provider}-capture-proof"
        proof_task = f"{entry.task_id}-proof"
        proof_run = f"proof-{sha256_file(patch_path)[:10]}"
        proof_evidence = ensure_private_directory(patch_path.parent / ".capture-proof")
        proof = self.create(
            run_id=proof_run,
            task_id=proof_task,
            provider=proof_provider,
            base_commit=entry.base_commit,
            evidence_dir=proof_evidence,
        )
        try:
            self._git(proof.path, "apply", "--check", "--binary", str(patch_path))
            self._git(proof.path, "apply", "--binary", str(patch_path))
            untracked = self._untracked_paths(proof.path)
            for relative in untracked:
                self._git(proof.path, "add", "--intent-to-add", "--", relative)
            try:
                applied = self._git_bytes(
                    proof.path,
                    "diff",
                    "--binary",
                    "--no-ext-diff",
                    "--no-renames",
                    proof.base_commit,
                    "--",
                )
            finally:
                for relative in untracked:
                    self._git(proof.path, "reset", "--quiet", "--", relative, check=False)
            if sha256_bytes(applied) != sha256_file(patch_path):
                raise WorktreeStateError("Applied proof worktree does not match captured patch")
            self._git(proof.path, "apply", "--reverse", "--check", "--binary", str(patch_path))
            self._git(proof.path, "apply", "--reverse", "--binary", str(patch_path))
            if self._git_bytes(
                proof.path, "status", "--porcelain=v1", "-z", "--untracked-files=all"
            ):
                raise WorktreeStateError("Patch proof could not return to its clean base")
            self._git(self.repository, "worktree", "remove", str(proof.path))
        except BaseException:
            self.registry.update(replace(proof, status="blocked"))
            raise
        self.registry.update(replace(proof, status="cleaned", cleaned_at=utc_now()))

    def _untracked_paths(self, worktree: Path) -> list[str]:
        raw = self._git_bytes(worktree, "ls-files", "--others", "--exclude-standard", "-z")
        return [item.decode("utf-8", "surrogateescape") for item in raw.split(b"\0") if item]

    def _git(
        self,
        repository: Path,
        *args: str,
        env: Mapping[str, str] | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        command = ["git", "-C", str(repository), *args]
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env) if env is not None else None,
            check=False,
            shell=False,
        )
        if check and result.returncode != 0:
            stderr = result.stderr.decode("utf-8", "replace").strip()
            raise WorktreeError(
                f"Git command failed: git {args[0] if args else ''}",
                details={"returnCode": result.returncode, "stderr": stderr},
            )
        return result

    def _git_bytes(
        self,
        repository: Path,
        *args: str,
        env: Mapping[str, str] | None = None,
        check: bool = True,
    ) -> bytes:
        return self._git(repository, *args, env=env, check=check).stdout

    def _git_text(
        self,
        repository: Path,
        *args: str,
        env: Mapping[str, str] | None = None,
        check: bool = True,
    ) -> str:
        return self._git_bytes(repository, *args, env=env, check=check).decode(
            "utf-8", "replace"
        ).strip()


def _canonicalize_root(root: Path) -> Path:
    if root.exists() and root.is_symlink():
        raise WorktreeError(f"Worktree root must not be a symlink: {root}")
    canonical = root.resolve(strict=False)
    ensure_private_directory(canonical)
    return canonical


def _evidence_outside_worktree(worktree: Path, evidence: Path) -> Path:
    candidate_root = worktree.resolve(strict=True)
    evidence_path = evidence.resolve(strict=False)
    try:
        evidence_path.relative_to(candidate_root)
    except ValueError:
        return evidence_path
    raise WorktreeError("Restricted evidence must be outside the candidate worktree")


def _contained_path(root: Path, candidate: Path) -> Path:
    canonical_root = root.resolve(strict=True)
    canonical_candidate = candidate.resolve(strict=False)
    try:
        canonical_candidate.relative_to(canonical_root)
    except ValueError as exc:
        raise WorktreeError(
            f"Path escapes configured worktree root: {candidate}",
            details={"worktreeRoot": str(canonical_root)},
        ) from exc
    if canonical_candidate == canonical_root:
        raise WorktreeError("A worktree path cannot be the configured root itself")
    return canonical_candidate


def _assert_no_symlink_components(root: Path, path: Path) -> None:
    root = root.resolve(strict=True)
    candidate = _contained_path(root, path)
    relative = candidate.relative_to(root)
    cursor = root
    for component in relative.parts:
        cursor = cursor / component
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise WorktreeError(f"Symlink component is forbidden in worktree path: {cursor}")


def _safe_component(value: str, label: str) -> str:
    if not isinstance(value, str) or not _COMPONENT_RE.fullmatch(value):
        raise WorktreeError(f"Invalid {label}: {value!r}")
    if value in {".", ".."}:
        raise WorktreeError(f"Invalid {label}: {value!r}")
    return value


def _normalized_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise WorktreeError(f"Invalid manifest path: {value!r}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise WorktreeError(f"Invalid manifest path: {value!r}")
    if pure.parts[0] == ".git":
        raise WorktreeError("Provider context manifest cannot include .git metadata")
    return pure.as_posix()


def _validate_manifest_paths(root: Path, paths: Sequence[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    canonical_root = root.resolve(strict=True)
    for value in paths:
        normalized = _normalized_relative_path(value)
        if normalized in seen:
            raise WorktreeError(f"Duplicate manifest path: {normalized}")
        seen.add(normalized)
        candidate = root / Path(*PurePosixPath(normalized).parts)
        try:
            info = candidate.lstat()
        except FileNotFoundError as exc:
            raise WorktreeError(f"Manifest path is missing: {normalized}") from exc
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
            raise WorktreeError(f"Manifest path has unsupported type: {normalized}")
        if stat.S_ISLNK(info.st_mode):
            resolved = candidate.resolve(strict=True)
            try:
                resolved.relative_to(canonical_root)
            except ValueError as exc:
                raise WorktreeError(f"Manifest symlink escapes worktree: {normalized}") from exc
        result.append(normalized)
    return sorted(result)


def _manifest_paths(manifest: Mapping[str, Any]) -> list[str]:
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise WorktreeError("Context manifest does not contain an entries array")
    paths: list[str] = []
    for entry in entries:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("path"), str):
            raise WorktreeError("Context manifest entry is missing a path")
        paths.append(entry["path"])
    return paths


def _approved_binary_pairs(
    entries: Sequence[Mapping[str, Any]],
) -> set[tuple[str, str]]:
    approved: set[tuple[str, str]] = set()
    for entry in entries:
        if set(entry) != {"path", "sha256"}:
            raise WorktreeError("Binary-context approval has unknown or missing keys")
        path = _normalized_relative_path(entry["path"])
        digest = entry["sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise WorktreeError("Binary-context approval has an invalid SHA-256")
        pair = (path, digest)
        if pair in approved:
            raise WorktreeError("Duplicate binary-context approval")
        approved.add(pair)
    return approved


def _is_binary_file(path: Path) -> bool:
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    try:
        with path.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                if b"\x00" in block:
                    return True
                decoder.decode(block, final=False)
            decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        return True
    return False


def _sanitized_git_environment(home: Path, global_config: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for name in ("PATH", "SYSTEMROOT", "WINDIR", "TMPDIR", "TMP", "TEMP"):
        value = os.environ.get(name)
        if value:
            env[name] = value
    env.update(
        {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(global_config),
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return env


def _safe_runtime_metadata(value: Mapping[str, Any]) -> dict[str, Any]:
    """Copy JSON-like identity metadata while rejecting credential-shaped keys."""

    forbidden = {
        "authorization",
        "credential",
        "password",
        "privatekey",
        "secret",
        "token",
    }

    def copy(item: Any, path: tuple[str, ...]) -> Any:
        if item is None or isinstance(item, (bool, int, float, str)):
            return item
        if isinstance(item, Mapping):
            result: dict[str, Any] = {}
            for key, child in item.items():
                if not isinstance(key, str) or not key:
                    raise WorktreeError("Runtime-manifest metadata keys must be non-empty strings")
                normalized = re.sub(r"[^a-z]", "", key.lower())
                if any(fragment in normalized for fragment in forbidden):
                    raise WorktreeError(
                        f"Runtime-manifest metadata may not contain sensitive field: {'.'.join(path + (key,))}"
                    )
                result[key] = copy(child, path + (key,))
            return result
        if isinstance(item, (list, tuple)):
            return [copy(child, path) for child in item]
        raise WorktreeError("Runtime-manifest metadata must contain only JSON values")

    return copy(value, ())


def _directory_fingerprint(directory: Path) -> str:
    records: list[bytes] = []
    for root, directories, files in os.walk(directory, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        root_path = Path(root)
        for name in directories + files:
            path = root_path / name
            relative = path.relative_to(directory).as_posix().encode("utf-8", "surrogateescape")
            info = path.lstat()
            mode = f"{stat.S_IFMT(info.st_mode):o}:{stat.S_IMODE(info.st_mode):o}".encode()
            if stat.S_ISREG(info.st_mode):
                payload = sha256_file(path).encode()
            elif stat.S_ISLNK(info.st_mode):
                payload = sha256_bytes(os.fsencode(os.readlink(path))).encode()
            else:
                payload = b"-"
            records.append(relative + b"\0" + mode + b"\0" + payload)
    return sha256_bytes(b"\n".join(records))


def _remove_isolated_git_directory(worktree: Path, git_dir: Path) -> None:
    """Remove only the recorded contained isolated ``.git`` tree, never a worktree."""

    expected = worktree.resolve(strict=True) / ".git"
    if git_dir != expected or git_dir.name != ".git":
        raise WorktreeError("Refusing to remove unrecorded Git metadata path")
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise WorktreeError("Refusing to traverse unsafe isolated Git metadata")
    for root, directories, files in os.walk(git_dir, topdown=False, followlinks=False):
        root_path = Path(root)
        for name in files:
            path = root_path / name
            path.unlink()
        for name in directories:
            path = root_path / name
            if path.is_symlink():
                path.unlink()
            else:
                path.rmdir()
    git_dir.rmdir()
