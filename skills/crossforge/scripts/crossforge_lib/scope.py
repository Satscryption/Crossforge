"""Exact path allowlists and candidate-scope validation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence

from .errors import InvalidInputError, ScopeViolationError, StateInconsistencyError
from .git import GitRepository, resolve_commit, run_git


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_GLOB_CHARS = frozenset("*?[")
_SUPPORTED_GIT_MODES = {"000000", "100644", "100755", "120000"}


@dataclass(frozen=True, slots=True)
class ChangedEntry:
    path: str
    status: str
    old_mode: str = "000000"
    new_mode: str = "000000"
    old_object_id: str | None = None
    new_object_id: str | None = None
    untracked: bool = False


@dataclass(frozen=True, slots=True)
class ScopeIssue:
    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class ScopeResult:
    base: str
    allowed: tuple[str, ...]
    changed: tuple[str, ...]
    violations: tuple[str, ...]
    issues: tuple[ScopeIssue, ...] = ()

    @property
    def passed(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict[str, object]:
        # The four path fields are the stable machine interface promised by the
        # specification.  Reasons add diagnostics without file contents.
        result: dict[str, object] = {
            "passed": self.passed,
            "base": self.base,
            "allowed": list(self.allowed),
            "changed": list(self.changed),
            "violations": list(self.violations),
        }
        if self.issues:
            result["issues"] = [
                {"path": issue.path, "reason": issue.reason} for issue in self.issues
            ]
        return result


@dataclass(frozen=True, slots=True)
class ScopedTreeEntry:
    path: str
    file_type: str
    git_mode: str | None
    sha256: str | None
    symlink_target: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "path": self.path,
            "fileType": self.file_type,
            "gitMode": self.git_mode,
            "sha256": self.sha256,
            "symlinkTarget": self.symlink_target,
        }


def validate_relative_path(
    path: str,
    *,
    root: str | os.PathLike[str] | None = None,
) -> str:
    """Validate one exact repository-relative POSIX file path."""

    if not isinstance(path, str) or not path:
        raise InvalidInputError("Allowlist paths must be non-empty strings")
    if path != path.strip():
        raise InvalidInputError(f"Allowlist path has surrounding whitespace: {path!r}")
    if _CONTROL_RE.search(path):
        raise InvalidInputError(f"Allowlist path contains control characters: {path!r}")
    if "\\" in path:
        raise InvalidInputError(f"Allowlist paths must use POSIX separators: {path!r}")
    if any(character in path for character in _GLOB_CHARS):
        raise InvalidInputError(f"Allowlist paths must not contain globs: {path!r}")
    if path.endswith("/"):
        raise InvalidInputError(f"Allowlist path must not end in '/': {path!r}")

    pure = PurePosixPath(path)
    if pure.is_absolute():
        raise InvalidInputError(f"Allowlist path must be relative: {path!r}")
    components = path.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise InvalidInputError(f"Allowlist path has an unsafe component: {path!r}")

    if root is not None:
        root_path = Path(root).resolve()
        cursor = root_path
        for index, component in enumerate(components):
            cursor = cursor / component
            try:
                info = cursor.lstat()
            except FileNotFoundError:
                # A missing component makes all descendants missing, so there
                # is no existing object left to inspect.
                break
            is_final = index == len(components) - 1
            if stat.S_ISLNK(info.st_mode):
                if not is_final:
                    raise InvalidInputError(
                        f"Allowlist path traverses a symlink parent: {path!r}"
                    )
                _validate_symlink_containment(root_path, cursor, path)
            elif is_final and stat.S_ISDIR(info.st_mode):
                raise InvalidInputError(
                    f"Allowlist entries must name files, not directories: {path!r}"
                )
    return path


def parse_allowlist(
    source: str | Iterable[str],
    *,
    root: str | os.PathLike[str] | None = None,
) -> tuple[str, ...]:
    """Parse UTF-8 allowlist text or exact line values.

    Blank lines are ignored as permitted by the "per non-empty line" format.
    Duplicate paths are rejected because ambiguity is unnecessary.
    """

    lines = source.splitlines() if isinstance(source, str) else list(source)
    paths: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if not isinstance(line, str):
            raise InvalidInputError("Allowlist lines must be strings")
        if line == "":
            continue
        if line.startswith("#"):
            raise InvalidInputError("Allowlist comments are not supported")
        value = validate_relative_path(line, root=root)
        if value in seen:
            raise InvalidInputError(f"Duplicate allowlist path: {value}")
        seen.add(value)
        paths.append(value)
    if not paths:
        raise InvalidInputError("Task allowlist must not be empty")
    return tuple(paths)


def read_allowlist(
    path: str | os.PathLike[str],
    *,
    root: str | os.PathLike[str] | None = None,
) -> tuple[str, ...]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise InvalidInputError("Allowlist must be valid UTF-8") from error
    except OSError as error:
        raise InvalidInputError(f"Unable to read allowlist: {error}") from error
    return parse_allowlist(text, root=root)


def _parse_raw_diff(data: bytes) -> list[ChangedEntry]:
    fields = data.split(b"\0")
    entries: list[ChangedEntry] = []
    index = 0
    while index < len(fields):
        raw_header = fields[index]
        index += 1
        if not raw_header:
            continue
        if not raw_header.startswith(b":") or index >= len(fields):
            raise StateInconsistencyError("Git returned malformed raw diff output")
        raw_path = fields[index]
        index += 1
        try:
            header = raw_header[1:].decode("ascii")
            old_mode, new_mode, old_oid, new_oid, change_status = header.split()
        except (UnicodeDecodeError, ValueError) as error:
            raise StateInconsistencyError("Git returned malformed raw diff metadata") from error
        # --no-renames makes every record single-path.  Treat an unexpected
        # rename/copy as inconsistent rather than accidentally omitting a side.
        status = change_status[:1]
        if status in {"R", "C"}:
            raise StateInconsistencyError("Git performed rename detection unexpectedly")
        path = raw_path.decode("utf-8", errors="surrogateescape")
        entries.append(
            ChangedEntry(
                path=path,
                status=status,
                old_mode=old_mode,
                new_mode=new_mode,
                old_object_id=old_oid,
                new_object_id=new_oid,
            )
        )
    return entries


def changed_entries(
    repository: GitRepository,
    *,
    base_commit: str,
) -> tuple[ChangedEntry, ...]:
    """Return staged, unstaged, and non-ignored untracked changes.

    Staged and unstaged raw diffs are intentionally collected separately.  This
    preserves a path whose staged deletion is masked by a recreated working
    file and ensures no dirty index state escapes the scope check.
    """

    base = resolve_commit(repository, base_commit)
    raw_options = [
        "-c",
        "core.filemode=true",
        "diff",
        "--raw",
        "-z",
        "--no-abbrev",
        "--no-renames",
        "--ignore-submodules=none",
    ]
    staged = run_git(
        repository.root,
        [*raw_options, "--cached", base, "--"],
        git_executable=repository.git_executable,
    )
    unstaged = run_git(
        repository.root,
        [*raw_options, "--"],
        git_executable=repository.git_executable,
    )
    entries = _parse_raw_diff(staged.stdout_bytes)
    entries.extend(_parse_raw_diff(unstaged.stdout_bytes))

    untracked = run_git(
        repository.root,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        git_executable=repository.git_executable,
    )
    tracked_paths = {entry.path for entry in entries}
    for raw_path in untracked.stdout_bytes.split(b"\0"):
        if not raw_path:
            continue
        path = raw_path.decode("utf-8", errors="surrogateescape")
        if path not in tracked_paths:
            entries.append(ChangedEntry(path=path, status="?", untracked=True))
    return tuple(entries)


def changed_paths(
    repository: GitRepository,
    *,
    base_commit: str,
) -> tuple[str, ...]:
    return tuple(sorted({entry.path for entry in changed_entries(
        repository, base_commit=base_commit
    )}))


def _is_contained(root: Path, target: Path) -> bool:
    try:
        target.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_symlink_containment(root: Path, link: Path, display_path: str) -> str:
    target = os.readlink(link)
    try:
        resolved = (link.parent / target).resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise InvalidInputError(
            f"Symlink target cannot be resolved safely: {display_path!r}"
        ) from error
    if not _is_contained(root.resolve(), resolved):
        raise InvalidInputError(
            f"Symlink target escapes the candidate worktree: {display_path!r}"
        )
    return target


def _approval_map(
    approved_symlinks: Mapping[str, str] | Sequence[object] | None,
) -> dict[str, str]:
    if approved_symlinks is None:
        return {}
    if isinstance(approved_symlinks, Mapping):
        return dict(approved_symlinks)
    result: dict[str, str] = {}
    for item in approved_symlinks:
        if hasattr(item, "path") and hasattr(item, "target"):
            result[str(getattr(item, "path"))] = str(getattr(item, "target"))
        elif isinstance(item, Mapping) and "path" in item and "target" in item:
            result[str(item["path"])] = str(item["target"])
        else:
            raise InvalidInputError("Malformed approved symlink entry")
    return result


def _entry_issue(
    repository: GitRepository,
    root: Path,
    entry: ChangedEntry,
    approvals: Mapping[str, str],
) -> str | None:
    if entry.old_mode == "160000" or entry.new_mode == "160000":
        return "gitlinks/submodules are unsupported"
    if entry.old_mode not in _SUPPORTED_GIT_MODES:
        return f"unsupported old Git mode {entry.old_mode}"
    if entry.new_mode not in _SUPPORTED_GIT_MODES:
        return f"unsupported new Git mode {entry.new_mode}"
    components = entry.path.split("/")
    cursor = root
    for component in components[:-1]:
        cursor /= component
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            break
        if stat.S_ISLNK(info.st_mode):
            return "changed path traverses a symlink parent"

    regular_modes = {"100644", "100755"}
    if (
        entry.old_mode in regular_modes
        and entry.new_mode in regular_modes
        and entry.old_mode != entry.new_mode
    ):
        old_oid = entry.old_object_id
        new_oid = entry.new_object_id
        if old_oid and new_oid and set(new_oid) != {"0"}:
            mode_only = old_oid == new_oid
        else:
            absolute = root / entry.path
            try:
                data = absolute.read_bytes()
            except (FileNotFoundError, OSError):
                mode_only = False
            else:
                current = run_git(
                    repository.root,
                    ["hash-object", "--no-filters", "--stdin"],
                    input_bytes=data,
                    git_executable=repository.git_executable,
                ).stdout.strip()
                mode_only = current == old_oid
        if mode_only:
            return "mode-only changes are unsupported"

    absolute = root / entry.path
    try:
        info = absolute.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISDIR(info.st_mode):
        return "changed path is a directory"
    if stat.S_ISLNK(info.st_mode):
        try:
            target = _validate_symlink_containment(root, absolute, entry.path)
        except InvalidInputError as error:
            return str(error)
        if approvals.get(entry.path) != target:
            return "changed symlink path and target were not exactly approved"
        if entry.new_mode not in {"000000", "120000"} and not entry.untracked:
            return "working symlink does not match its Git mode"
    elif stat.S_ISREG(info.st_mode):
        if entry.new_mode == "120000":
            return "working regular file does not match its Git mode"
    else:
        return "special files are unsupported"
    return None


def check_scope(
    repository: GitRepository,
    *,
    base_commit: str,
    allowlist: Iterable[str],
    approved_symlinks: Mapping[str, str] | Sequence[object] | None = None,
) -> ScopeResult:
    """Compare all changed paths to an exact allowlist and structural policy."""

    allowlist_source = allowlist if isinstance(allowlist, str) else list(allowlist)
    # Syntax is plan input; changed filesystem structure is candidate output.
    # Keeping them separate ensures an escaping changed symlink is reported as
    # a scope violation rather than misclassified as invalid plan input.
    allowed = parse_allowlist(allowlist_source)
    approvals = _approval_map(approved_symlinks)
    entries = changed_entries(repository, base_commit=base_commit)
    changed = tuple(sorted({entry.path for entry in entries}))
    allowed_set = set(allowed)
    issues: list[ScopeIssue] = []

    for path in changed:
        if path not in allowed_set:
            issues.append(ScopeIssue(path, "path is outside the exact allowlist"))
    for entry in entries:
        reason = _entry_issue(repository, repository.root, entry, approvals)
        if reason is not None:
            issues.append(ScopeIssue(entry.path, reason))

    # Keep diagnostics stable and avoid duplicate violation paths when a single
    # entry is both out of scope and structurally unsafe.
    unique_issues = tuple(
        ScopeIssue(path, reason)
        for path, reason in sorted({(issue.path, issue.reason) for issue in issues})
    )
    violations = tuple(sorted({issue.path for issue in unique_issues}))
    return ScopeResult(
        base=resolve_commit(repository, base_commit),
        allowed=tuple(sorted(allowed)),
        changed=changed,
        violations=violations,
        issues=unique_issues,
    )


def enforce_scope(
    repository: GitRepository,
    *,
    base_commit: str,
    allowlist: Iterable[str],
    approved_symlinks: Mapping[str, str] | Sequence[object] | None = None,
) -> ScopeResult:
    """Return a passing result or raise a stable scope-violation error."""

    result = check_scope(
        repository,
        base_commit=base_commit,
        allowlist=allowlist,
        approved_symlinks=approved_symlinks,
    )
    if not result.passed:
        raise ScopeViolationError(
            "Candidate changed paths outside the approved scope or used unsafe types",
            details=result.to_dict(),
        )
    return result


def scoped_tree_manifest(
    root: str | os.PathLike[str],
    allowlist: Iterable[str],
    *,
    approved_symlinks: Mapping[str, str] | Sequence[object] | None = None,
) -> tuple[ScopedTreeEntry, ...]:
    """Hash exact allowlisted working-tree bytes for cross-worktree comparison."""

    root_path = Path(root).resolve()
    allowlist_source = allowlist if isinstance(allowlist, str) else list(allowlist)
    allowed = parse_allowlist(allowlist_source, root=root_path)
    approvals = _approval_map(approved_symlinks)
    manifest: list[ScopedTreeEntry] = []
    for path in sorted(allowed):
        absolute = root_path / path
        try:
            info = absolute.lstat()
        except FileNotFoundError:
            manifest.append(ScopedTreeEntry(path, "absent", None, None))
            continue
        if stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256(absolute.read_bytes()).hexdigest()
            mode = "100755" if info.st_mode & 0o111 else "100644"
            manifest.append(ScopedTreeEntry(path, "regular", mode, digest))
        elif stat.S_ISLNK(info.st_mode):
            target = _validate_symlink_containment(root_path, absolute, path)
            if approvals.get(path) != target:
                raise ScopeViolationError(f"Symlink is not exactly approved: {path}")
            digest = hashlib.sha256(os.fsencode(target)).hexdigest()
            manifest.append(ScopedTreeEntry(path, "symlink", "120000", digest, target))
        elif stat.S_ISDIR(info.st_mode):
            raise ScopeViolationError(f"Allowlisted path is a directory: {path}")
        else:
            raise ScopeViolationError(f"Allowlisted path is a special file: {path}")
    return tuple(manifest)


def scoped_tree_hash(
    root: str | os.PathLike[str],
    allowlist: Iterable[str],
    *,
    approved_symlinks: Mapping[str, str] | Sequence[object] | None = None,
) -> str:
    manifest = scoped_tree_manifest(
        root, allowlist, approved_symlinks=approved_symlinks
    )
    encoded = json.dumps(
        [entry.to_dict() for entry in manifest],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
