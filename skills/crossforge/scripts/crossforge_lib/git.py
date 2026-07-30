"""Safe, argument-array-only Git primitives used by Crossforge.

This module deliberately keeps Git plumbing small and explicit.  Callers pass
argument sequences; no API accepts a shell command string and no subprocess is
started through a shell.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .errors import InvalidInputError, PreconditionError, StateInconsistencyError


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_OID_RE = re.compile(r"^[0-9a-f]{40,64}$")
_SCP_REMOTE_RE = re.compile(
    r"^(?:(?P<user>[^@/:]+)@)?(?P<host>\[[^\]]+\]|[^/:]+):(?P<path>.+)$"
)
_CREDENTIAL_QUERY_KEYS = {
    "access_token",
    "apikey",
    "api_key",
    "auth",
    "authorization",
    "credential",
    "credentials",
    "key",
    "password",
    "private_key",
    "secret",
    "signature",
    "sig",
    "token",
}
_DEFAULT_PORTS = {"http": 80, "https": 443, "ssh": 22, "git": 9418}


class GitError(PreconditionError):
    """A Git operation failed without exposing sensitive process state."""


@dataclass(frozen=True, slots=True)
class GitResult:
    """Captured result of one Git subprocess."""

    argv: tuple[str, ...]
    cwd: Path
    returncode: int
    stdout_bytes: bytes
    stderr_bytes: bytes

    @property
    def stdout(self) -> str:
        return self.stdout_bytes.decode("utf-8", errors="surrogateescape")

    @property
    def stderr(self) -> str:
        return self.stderr_bytes.decode("utf-8", errors="surrogateescape")


@dataclass(frozen=True, slots=True)
class GitRepository:
    """Canonical repository and Git administrative paths for one worktree."""

    root: Path
    common_git_dir: Path
    git_dir: Path
    git_executable: str = "git"


@dataclass(frozen=True, slots=True)
class BranchResolution:
    """The deterministic result of selecting a Crossforge work branch."""

    branch: str
    target_branch: str
    start_commit: str
    created: bool
    reused_current: bool


@dataclass(frozen=True, slots=True)
class IndexEntry:
    """One stage-zero entry in Git's index."""

    path: str
    mode: str
    object_id: str
    stage: int = 0


def _validated_argv(
    arguments: Sequence[str | os.PathLike[str]], git_executable: str
) -> tuple[str, ...]:
    if not git_executable or "\x00" in git_executable:
        raise InvalidInputError("Git executable must be a non-empty path without NUL")
    converted: list[str] = [git_executable]
    for argument in arguments:
        value = os.fspath(argument)
        if not isinstance(value, str):
            raise InvalidInputError("Git arguments must be strings")
        if "\x00" in value:
            raise InvalidInputError("Git arguments must not contain NUL")
        converted.append(value)
    return tuple(converted)


def run_git(
    cwd: str | os.PathLike[str] | None,
    arguments: Sequence[str | os.PathLike[str]],
    *,
    input_bytes: bytes | None = None,
    check: bool = True,
    timeout_seconds: int | float | None = 60,
    environment: Mapping[str, str] | None = None,
    git_executable: str = "git",
) -> GitResult:
    """Run Git without a shell and capture byte-exact stdout/stderr.

    ``environment`` is an overlay rather than a replacement so normal local
    Git discovery continues to work.  Environment keys and values containing
    NUL are rejected before process creation.
    """

    argv = _validated_argv(arguments, git_executable)
    working_directory = Path(cwd or os.getcwd()).resolve()
    process_environment = os.environ.copy()
    if environment is not None:
        for key, value in environment.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise InvalidInputError("Git environment names and values must be strings")
            if "\x00" in key or "\x00" in value or "=" in key:
                raise InvalidInputError("Invalid Git environment entry")
            process_environment[key] = value
    try:
        completed = subprocess.run(
            argv,
            cwd=working_directory,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=process_environment,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except FileNotFoundError as error:
        raise GitError("Git executable was not found") from error
    except subprocess.TimeoutExpired as error:
        raise GitError(
            f"Git command timed out after {timeout_seconds} seconds",
        ) from error
    except OSError as error:
        raise GitError("Git command could not be started") from error

    result = GitResult(
        argv=argv,
        cwd=working_directory,
        returncode=completed.returncode,
        stdout_bytes=completed.stdout,
        stderr_bytes=completed.stderr,
    )
    if check and result.returncode != 0:
        raise GitError(
            f"Git command failed with exit code {result.returncode}",
            details={"returnCode": result.returncode},
        )
    return result


def git_stdout(
    cwd: str | os.PathLike[str] | None,
    arguments: Sequence[str | os.PathLike[str]],
    **kwargs: object,
) -> str:
    """Return stripped text stdout from :func:`run_git`."""

    return run_git(cwd, arguments, **kwargs).stdout.strip()


def discover_repository(
    start: str | os.PathLike[str] = ".",
    *,
    git_executable: str = "git",
) -> GitRepository:
    """Discover canonical worktree root, common Git dir, and worktree Git dir."""

    candidate = Path(start)
    if candidate.is_file():
        candidate = candidate.parent
    candidate = candidate.resolve()
    probe = run_git(
        candidate,
        ["rev-parse", "--is-inside-work-tree"],
        check=False,
        git_executable=git_executable,
    )
    if probe.returncode != 0 or probe.stdout.strip() != "true":
        raise GitError("Not inside a non-bare Git worktree")

    root = Path(
        git_stdout(
            candidate,
            ["rev-parse", "--path-format=absolute", "--show-toplevel"],
            git_executable=git_executable,
        )
    ).resolve()
    common_git_dir = Path(
        git_stdout(
            root,
            ["rev-parse", "--path-format=absolute", "--git-common-dir"],
            git_executable=git_executable,
        )
    ).resolve()
    git_dir = Path(
        git_stdout(
            root,
            ["rev-parse", "--absolute-git-dir"],
            git_executable=git_executable,
        )
    ).resolve()
    return GitRepository(
        root=root,
        common_git_dir=common_git_dir,
        git_dir=git_dir,
        git_executable=git_executable,
    )


def resolve_commit(repository: GitRepository, revision: str = "HEAD") -> str:
    """Resolve *revision* to a full commit object ID."""

    value = git_stdout(
        repository.root,
        ["rev-parse", "--verify", f"{revision}^{{commit}}"],
        git_executable=repository.git_executable,
    )
    if not _OID_RE.fullmatch(value):
        raise StateInconsistencyError(f"Git returned an invalid object ID for {revision}")
    return value


def current_branch(repository: GitRepository) -> str | None:
    """Return the current local branch or ``None`` for detached HEAD."""

    result = run_git(
        repository.root,
        ["symbolic-ref", "--quiet", "--short", "HEAD"],
        check=False,
        git_executable=repository.git_executable,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    if result.returncode == 1:
        return None
    raise GitError("Unable to determine current branch")


def is_dirty(
    repository: GitRepository,
    *,
    include_untracked: bool = True,
) -> bool:
    """Return whether tracked state or non-ignored untracked state is dirty."""

    untracked = "normal" if include_untracked else "no"
    result = run_git(
        repository.root,
        ["status", "--porcelain=v1", "-z", f"--untracked-files={untracked}"],
        git_executable=repository.git_executable,
    )
    return bool(result.stdout_bytes)


def branch_exists(repository: GitRepository, branch: str) -> bool:
    result = run_git(
        repository.root,
        ["show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
        check=False,
        git_executable=repository.git_executable,
    )
    if result.returncode not in (0, 1):
        raise GitError("Unable to inspect branch")
    return result.returncode == 0


def validate_branch_name(repository: GitRepository, branch: str) -> str:
    if not branch or _CONTROL_RE.search(branch):
        raise InvalidInputError("Branch name must be non-empty and contain no controls")
    result = run_git(
        repository.root,
        ["check-ref-format", "--branch", branch],
        check=False,
        git_executable=repository.git_executable,
    )
    if result.returncode != 0:
        raise InvalidInputError(f"Invalid Git branch name: {branch}")
    return branch


def branch_checkout_paths(repository: GitRepository, branch: str) -> tuple[Path, ...]:
    """Return canonical worktree paths currently checking out *branch*."""

    target_ref = f"refs/heads/{branch}"
    result = run_git(
        repository.root,
        ["worktree", "list", "--porcelain", "-z"],
        git_executable=repository.git_executable,
    )
    fields = result.stdout_bytes.split(b"\0")
    paths: list[Path] = []
    active_path: Path | None = None
    for raw in fields:
        if not raw:
            continue
        text = raw.decode("utf-8", errors="surrogateescape")
        if text.startswith("worktree "):
            active_path = Path(text[len("worktree ") :]).resolve()
        elif text == f"branch {target_ref}" and active_path is not None:
            paths.append(active_path)
    return tuple(paths)


def _local_branch_exists(repository: GitRepository, name: str) -> bool:
    return branch_exists(repository, name)


def detect_default_branch(
    repository: GitRepository,
    *,
    explicit_target: str | None = None,
    remote: str | None = "origin",
    policy_default: str | None = None,
) -> str:
    """Resolve the default branch in the specification's required order."""

    if explicit_target is not None:
        return validate_branch_name(repository, explicit_target)

    if remote:
        symbolic = run_git(
            repository.root,
            [
                "symbolic-ref",
                "--quiet",
                "--short",
                f"refs/remotes/{remote}/HEAD",
            ],
            check=False,
            git_executable=repository.git_executable,
        )
        if symbolic.returncode == 0:
            value = symbolic.stdout.strip()
            prefix = f"{remote}/"
            if value.startswith(prefix) and len(value) > len(prefix):
                return validate_branch_name(repository, value[len(prefix) :])
        elif symbolic.returncode not in (1, 128):
            raise GitError("Unable to inspect symbolic default branch")

    if policy_default:
        return validate_branch_name(repository, policy_default)
    if _local_branch_exists(repository, "main"):
        return "main"
    if _local_branch_exists(repository, "master"):
        return "master"

    configured = run_git(
        repository.root,
        ["config", "--get", "init.defaultBranch"],
        check=False,
        git_executable=repository.git_executable,
    )
    if configured.returncode == 0 and configured.stdout.strip():
        return validate_branch_name(repository, configured.stdout.strip())
    if configured.returncode not in (0, 1):
        raise GitError("Unable to read init.defaultBranch")
    raise PreconditionError(
        "Unable to determine the target branch; supply --target-branch"
    )


def ensure_dedicated_branch(
    repository: GitRepository,
    *,
    start_commit: str,
    target_branch: str,
    run_id: str,
    requested_branch: str | None = None,
    protected_branches: Iterable[str] = (),
) -> BranchResolution:
    """Create or safely reuse a non-default Crossforge work branch."""

    if is_dirty(repository):
        raise PreconditionError("Refusing to switch branches in a dirty checkout")
    start = resolve_commit(repository, start_commit)
    target = validate_branch_name(repository, target_branch)
    protected = set(protected_branches)
    protected.add(target)
    active = current_branch(repository)

    if requested_branch is not None:
        selected = validate_branch_name(repository, requested_branch)
        if selected in protected:
            raise PreconditionError(f"Refusing to use protected branch: {selected}")
        exists = branch_exists(repository, selected)
        if exists:
            branch_commit = resolve_commit(repository, f"refs/heads/{selected}")
            if branch_commit != start:
                raise PreconditionError(
                    f"Existing branch {selected!r} does not point at the start commit"
                )
            other_paths = {
                path
                for path in branch_checkout_paths(repository, selected)
                if path != repository.root
            }
            if other_paths:
                raise PreconditionError(
                    f"Branch {selected!r} is checked out in another worktree"
                )
            if active != selected:
                run_git(
                    repository.root,
                    ["switch", selected],
                    git_executable=repository.git_executable,
                )
            return BranchResolution(selected, target, start, False, active == selected)
        run_git(
            repository.root,
            ["switch", "-c", selected, start],
            git_executable=repository.git_executable,
        )
        return BranchResolution(selected, target, start, True, False)

    if active is not None and active not in protected:
        if resolve_commit(repository, "HEAD") != start:
            raise PreconditionError("Current branch no longer points at the start commit")
        return BranchResolution(active, target, start, False, True)

    if not re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{8}", run_id):
        raise InvalidInputError("Run ID cannot be converted to a Crossforge branch")
    generated = validate_branch_name(repository, f"crossforge/{run_id.lower()}")
    if branch_exists(repository, generated):
        raise PreconditionError(f"Generated branch already exists: {generated}")
    run_git(
        repository.root,
        ["switch", "-c", generated, start],
        git_executable=repository.git_executable,
    )
    return BranchResolution(generated, target, start, True, False)


def _query_contains_credentials(query: str) -> bool:
    for key, _value in parse_qsl(query, keep_blank_values=True):
        normalized = key.lower().replace("-", "_")
        if normalized in _CREDENTIAL_QUERY_KEYS:
            return True
        if any(word in normalized for word in ("token", "secret", "password")):
            return True
    return False


def _strip_repository_suffix(path: str) -> str:
    if path.endswith("/"):
        path = path[:-1]
    if path.endswith(".git"):
        path = path[:-4]
    return path


def normalize_remote_url(remote_url: str) -> str:
    """Normalize a Git remote while removing all separable user information."""

    if not isinstance(remote_url, str) or not remote_url:
        raise InvalidInputError("Remote URL must be a non-empty string")
    if remote_url != remote_url.strip() or _CONTROL_RE.search(remote_url):
        raise InvalidInputError("Remote URL contains whitespace or control characters")

    if "://" in remote_url:
        try:
            parsed = urlsplit(remote_url)
            port = parsed.port
        except ValueError as error:
            raise InvalidInputError("Remote URL cannot be parsed safely") from error
        scheme = parsed.scheme.lower()
        if not scheme:
            raise InvalidInputError("Remote URL has no scheme")
        if _query_contains_credentials(parsed.query):
            raise InvalidInputError("Remote URL contains credentials in its query")
        if parsed.hostname is None and scheme != "file":
            raise InvalidInputError("Remote URL has no host")

        if parsed.hostname is None:
            netloc = ""
        else:
            host = parsed.hostname.lower()
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            netloc = host
            if port is not None and port != _DEFAULT_PORTS.get(scheme):
                netloc = f"{netloc}:{port}"
        path = _strip_repository_suffix(parsed.path)
        if not path:
            raise InvalidInputError("Remote URL has no repository path")
        return urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))

    scp_match = _SCP_REMOTE_RE.fullmatch(remote_url)
    if scp_match:
        host = scp_match.group("host").lower()
        path = _strip_repository_suffix(scp_match.group("path"))
        if not path:
            raise InvalidInputError("Remote URL has no repository path")
        return f"{host}:{path}"

    # Local-path remotes have no user-info component.  Keep their case and
    # relativity because both can affect the repository they identify.
    path = _strip_repository_suffix(remote_url)
    if not path:
        raise InvalidInputError("Remote URL has no repository path")
    return path


def origin_remote_url(repository: GitRepository) -> str | None:
    result = run_git(
        repository.root,
        ["remote", "get-url", "origin"],
        check=False,
        git_executable=repository.git_executable,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    if result.returncode == 2:
        return None
    # Git has used both 2 and 128 for a missing remote across versions.
    if "No such remote" in result.stderr or "No such remote" in result.stdout:
        return None
    raise GitError("Unable to read origin remote")


def repository_identity(
    repository: GitRepository,
    *,
    remote_url: str | None = None,
) -> str:
    """Return the stable SHA-256 identity for repository root and origin."""

    discovered = origin_remote_url(repository) if remote_url is None else remote_url
    normalized = (
        normalize_remote_url(discovered) if discovered is not None else "<no-origin>"
    )
    material = f"{repository.root.resolve()}\n{normalized}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def hash_object_no_filters(repository: GitRepository, data: bytes) -> str:
    """Write *data* as a Git blob without invoking clean/process filters."""

    result = run_git(
        repository.root,
        ["hash-object", "-w", "--no-filters", "--stdin"],
        input_bytes=data,
        git_executable=repository.git_executable,
    )
    object_id = result.stdout.strip()
    if not _OID_RE.fullmatch(object_id):
        raise StateInconsistencyError("git hash-object returned an invalid object ID")
    return object_id


def update_index_cacheinfo(
    repository: GitRepository,
    *,
    path: str,
    mode: str,
    object_id: str,
) -> IndexEntry:
    """Stage an exact mode/object/path tuple without reading working-tree data."""

    if mode not in {"100644", "100755", "120000"}:
        raise InvalidInputError(f"Unsupported Git mode for exact staging: {mode}")
    if not _OID_RE.fullmatch(object_id):
        raise InvalidInputError("Invalid object ID for exact staging")
    run_git(
        repository.root,
        ["update-index", "--add", "--cacheinfo", f"{mode},{object_id},{path}"],
        git_executable=repository.git_executable,
    )
    entry = index_entry(repository, path)
    if entry is None or entry.mode != mode or entry.object_id != object_id:
        raise StateInconsistencyError(f"Index did not retain exact entry for {path}")
    return entry


def remove_index_path(repository: GitRepository, path: str) -> None:
    """Stage deletion of an absent path."""

    if (repository.root / path).exists() or (repository.root / path).is_symlink():
        raise PreconditionError(f"Refusing to stage deletion of existing path: {path}")
    run_git(
        repository.root,
        ["update-index", "--remove", "--", path],
        git_executable=repository.git_executable,
    )
    if index_entry(repository, path) is not None:
        raise StateInconsistencyError(f"Index still contains deleted path: {path}")


def index_entry(repository: GitRepository, path: str) -> IndexEntry | None:
    result = run_git(
        repository.root,
        ["--literal-pathspecs", "ls-files", "--stage", "-z", "--", path],
        git_executable=repository.git_executable,
    )
    records = [record for record in result.stdout_bytes.split(b"\0") if record]
    if not records:
        return None
    if len(records) != 1:
        raise StateInconsistencyError(f"Index returned multiple entries for {path}")
    metadata, separator, raw_path = records[0].partition(b"\t")
    fields = metadata.decode("ascii").split()
    decoded_path = raw_path.decode("utf-8", errors="surrogateescape")
    if not separator or len(fields) != 3 or decoded_path != path:
        raise StateInconsistencyError(f"Malformed index entry for {path}")
    mode, object_id, stage_text = fields
    return IndexEntry(path, mode, object_id, int(stage_text))


def stage_path_filter_free(
    repository: GitRepository,
    path: str,
    *,
    approved_symlink_target: str | None = None,
) -> IndexEntry | None:
    """Stage exact working bytes for one regular file, symlink, or deletion."""

    # Import lazily to avoid a module cycle while keeping path validation in one
    # canonical implementation.
    from .scope import validate_relative_path

    validate_relative_path(path, root=repository.root)
    absolute = repository.root / path
    try:
        info = absolute.lstat()
    except FileNotFoundError:
        remove_index_path(repository, path)
        return None

    if stat.S_ISREG(info.st_mode):
        mode = "100755" if info.st_mode & 0o111 else "100644"
        data = absolute.read_bytes()
    elif stat.S_ISLNK(info.st_mode):
        target = os.readlink(absolute)
        if approved_symlink_target is None or target != approved_symlink_target:
            raise PreconditionError(f"Symlink is not exactly approved: {path}")
        mode = "120000"
        data = os.fsencode(target)
    else:
        raise PreconditionError(f"Unsupported file type for exact staging: {path}")

    object_id = hash_object_no_filters(repository, data)
    return update_index_cacheinfo(
        repository, path=path, mode=mode, object_id=object_id
    )


def stage_allowlist_filter_free(
    repository: GitRepository,
    paths: Iterable[str],
    *,
    approved_symlinks: Mapping[str, str] | None = None,
) -> tuple[IndexEntry, ...]:
    """Stage only exact allowlisted paths and return resulting present entries."""

    approvals = dict(approved_symlinks or {})
    entries: list[IndexEntry] = []
    for path in sorted(set(paths)):
        entry = stage_path_filter_free(
            repository,
            path,
            approved_symlink_target=approvals.get(path),
        )
        if entry is not None:
            entries.append(entry)
    return tuple(entries)
