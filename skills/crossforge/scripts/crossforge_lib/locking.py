"""Cross-process locks used by Crossforge.

The locks in this module deliberately use an ordinary, inspectable JSON file.
Creation is atomic (``O_CREAT | O_EXCL``), ownership is never inferred from a
command line, and stale locks are removed only under the rules documented in
the build specification.
"""

from __future__ import annotations

import errno
import json
import os
import socket
import stat
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .errors import PreconditionError, StateInconsistencyError
from .util import ensure_private_directory, utc_now


class LockHeldError(PreconditionError):
    """Raised when a live lock prevents an operation."""


class InvalidLockError(StateInconsistencyError):
    """Raised when lock state cannot be trusted."""


@dataclass(frozen=True)
class LockMetadata:
    """Non-sensitive information persisted in a lock file."""

    pid: int
    hostname: str
    provider: str | None
    worktree: str | None
    startedAt: str

    @classmethod
    def from_object(cls, value: object) -> "LockMetadata":
        if not isinstance(value, dict):
            raise InvalidLockError("lock metadata must be a JSON object")
        expected = {"pid", "hostname", "provider", "worktree", "startedAt"}
        if set(value) != expected:
            raise InvalidLockError("lock metadata has unknown or missing fields")
        pid = value["pid"]
        hostname = value["hostname"]
        provider = value["provider"]
        worktree = value["worktree"]
        started_at = value["startedAt"]
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise InvalidLockError("lock metadata contains an invalid PID")
        if not isinstance(hostname, str) or not hostname:
            raise InvalidLockError("lock metadata contains an invalid hostname")
        if provider is not None and not isinstance(provider, str):
            raise InvalidLockError("lock metadata contains an invalid provider")
        if worktree is not None and not isinstance(worktree, str):
            raise InvalidLockError("lock metadata contains an invalid worktree")
        if not isinstance(started_at, str) or not started_at:
            raise InvalidLockError("lock metadata contains an invalid start time")
        return cls(
            pid=pid,
            hostname=hostname,
            provider=provider,
            worktree=worktree,
            startedAt=started_at,
        )


ForeignStaleApproval = Callable[[LockMetadata], bool]

_LOCK_RANKS = {"repository": 1, "run": 2, "writer": 3}
_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: set[str] = set()
_THREAD_STATE = threading.local()


def _ensure_thread_state_pid() -> None:
    current_pid = os.getpid()
    if getattr(_THREAD_STATE, "pid", None) != current_pid:
        _THREAD_STATE.pid = current_pid
        _THREAD_STATE.held_ranks = []
        _THREAD_STATE.held_paths = []


def _held_ranks() -> list[int]:
    _ensure_thread_state_pid()
    ranks = getattr(_THREAD_STATE, "held_ranks", None)
    if ranks is None:
        ranks = []
        _THREAD_STATE.held_ranks = ranks
    return ranks


def _held_paths() -> list[str]:
    _ensure_thread_state_pid()
    paths = getattr(_THREAD_STATE, "held_paths", None)
    if paths is None:
        paths = []
        _THREAD_STATE.held_paths = paths
    return paths


def current_thread_holds_lock(path: str | os.PathLike[str]) -> bool:
    """Return whether the calling thread owns the exact file lock."""

    return str(Path(path).absolute()) in _held_paths()


def _reset_locks_after_fork() -> None:
    global _PROCESS_LOCKS_GUARD

    _PROCESS_LOCKS_GUARD = threading.Lock()
    _PROCESS_LOCKS.clear()
    _THREAD_STATE.pid = os.getpid()
    _THREAD_STATE.held_ranks = []
    _THREAD_STATE.held_paths = []


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_locks_after_fork)


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        return exc.errno != errno.ESRCH
    return True


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        # Some supported filesystems do not permit directory fsync.
        pass
    finally:
        os.close(descriptor)


class FileLock:
    """An exclusive, non-reentrant file lock with bounded acquisition."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        kind: str,
        provider: str | None = None,
        worktree: str | os.PathLike[str] | None = None,
        timeout: float = 0,
        poll_interval: float = 0.05,
        approve_foreign_stale: ForeignStaleApproval | None = None,
        hostname: str | None = None,
        pid: int | None = None,
    ) -> None:
        if kind not in _LOCK_RANKS:
            raise ValueError(f"unknown lock kind: {kind}")
        if timeout < 0:
            raise ValueError("lock timeout cannot be negative")
        if poll_interval <= 0:
            raise ValueError("lock poll interval must be positive")
        self.path = Path(path).absolute()
        self.kind = kind
        self.provider = provider
        self.worktree = str(Path(worktree).absolute()) if worktree is not None else None
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.approve_foreign_stale = approve_foreign_stale
        self.hostname = hostname or socket.gethostname()
        self._pid_override = pid
        self.pid = pid if pid is not None else os.getpid()
        self.metadata: LockMetadata | None = None
        self._identity: tuple[int, int] | None = None
        self._acquired = False
        self._owner_pid: int | None = None

    def _validate_order(self) -> None:
        ranks = _held_ranks()
        rank = _LOCK_RANKS[self.kind]
        if ranks and rank < ranks[-1]:
            raise PreconditionError(
                "lock order violation",
                details={
                    "requested": self.kind,
                    "requiredOrder": ["repository", "run", "writer"],
                },
            )

    def _read_holder(self) -> tuple[LockMetadata, os.stat_result]:
        try:
            before = self.path.lstat()
        except FileNotFoundError:
            raise
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise InvalidLockError(f"lock path is not a regular file: {self.path}")
        if hasattr(os, "getuid") and before.st_uid != os.getuid():
            raise InvalidLockError(f"lock file is owned by another user: {self.path}")
        if before.st_mode & 0o077:
            raise InvalidLockError(f"lock file is writable or readable by other users: {self.path}")
        try:
            raw = self.path.read_bytes()
            after = self.path.lstat()
        except FileNotFoundError:
            raise
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise FileNotFoundError(self.path)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvalidLockError(f"lock file contains invalid JSON: {self.path}") from exc
        return LockMetadata.from_object(value), after

    def _remove_stale(self, holder: LockMetadata, identity: os.stat_result) -> bool:
        foreign = holder.hostname != self.hostname
        if foreign:
            if self.approve_foreign_stale is None or not self.approve_foreign_stale(holder):
                raise LockHeldError(
                    "lock belongs to another host and requires "
                    "caller-attested recovery approval",
                    details={"holder": asdict(holder), "path": str(self.path)},
                )
        elif _pid_is_alive(holder.pid):
            return False

        # Do not unlink a lock that was replaced after it was inspected.
        try:
            current = self.path.lstat()
        except FileNotFoundError:
            return True
        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
            return True
        self.path.unlink()
        _fsync_directory(self.path.parent)
        return True

    def _try_create(self) -> bool:
        effective_pid = (
            self._pid_override
            if self._pid_override is not None
            else os.getpid()
        )
        self.pid = effective_pid
        metadata = LockMetadata(
            pid=effective_pid,
            hostname=self.hostname,
            provider=self.provider,
            worktree=self.worktree,
            startedAt=utc_now(),
        )
        payload = (
            json.dumps(asdict(metadata), sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        try:
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            return False
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        except BaseException:
            os.close(descriptor)
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            raise
        else:
            os.close(descriptor)
        _fsync_directory(self.path.parent)
        identity = self.path.lstat()
        self.metadata = metadata
        self._identity = (identity.st_dev, identity.st_ino)
        return True

    def acquire(self) -> "FileLock":
        if self._acquired:
            raise PreconditionError(f"lock is not reentrant: {self.path}")
        ensure_private_directory(self.path.parent)
        self._validate_order()
        key = str(self.path)
        with _PROCESS_LOCKS_GUARD:
            if key in _PROCESS_LOCKS:
                raise LockHeldError(
                    "lock is already held by this process",
                    details={"path": key},
                )

        deadline = time.monotonic() + self.timeout
        last_holder: LockMetadata | None = None
        while True:
            if self._try_create():
                with _PROCESS_LOCKS_GUARD:
                    # A second thread can only win here if it bypassed the
                    # exclusive file creation, which is impossible.
                    _PROCESS_LOCKS.add(key)
                _held_ranks().append(_LOCK_RANKS[self.kind])
                _held_paths().append(key)
                self._acquired = True
                self._owner_pid = os.getpid()
                return self
            try:
                holder, identity = self._read_holder()
            except FileNotFoundError:
                continue
            last_holder = holder
            if self._remove_stale(holder, identity):
                continue
            if time.monotonic() >= deadline:
                raise LockHeldError(
                    "lock acquisition timed out",
                    details={"holder": asdict(last_holder), "path": key},
                )
            time.sleep(min(self.poll_interval, max(0, deadline - time.monotonic())))

    def release(self) -> None:
        if not self._acquired:
            return
        if self._owner_pid != os.getpid():
            # A forked child inherits the Python object, not ownership of the
            # parent's live filesystem lock.
            self._acquired = False
            self._owner_pid = None
            self.metadata = None
            self._identity = None
            return
        key = str(self.path)
        try:
            try:
                current = self.path.lstat()
            except FileNotFoundError as exc:
                raise InvalidLockError(f"owned lock disappeared: {self.path}") from exc
            identity = (current.st_dev, current.st_ino)
            if identity != self._identity:
                raise InvalidLockError(f"owned lock was replaced: {self.path}")
            self.path.unlink()
            _fsync_directory(self.path.parent)
        finally:
            self._acquired = False
            self._owner_pid = None
            self.metadata = None
            self._identity = None
            with _PROCESS_LOCKS_GUARD:
                _PROCESS_LOCKS.discard(key)
            paths = _held_paths()
            if key in paths:
                paths.remove(key)
            ranks = _held_ranks()
            rank = _LOCK_RANKS[self.kind]
            if ranks and ranks[-1] == rank:
                ranks.pop()
            elif rank in ranks:
                # Keep the process usable while still surfacing the violation.
                ranks.remove(rank)
                raise PreconditionError(
                    "locks must be released in reverse acquisition order"
                )

    def __enter__(self) -> "FileLock":
        return self.acquire()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


def repository_lock(
    state_root: str | os.PathLike[str], **kwargs: object
) -> FileLock:
    return FileLock(Path(state_root) / "repository.lock", kind="repository", **kwargs)


def run_lock(run_directory: str | os.PathLike[str], **kwargs: object) -> FileLock:
    return FileLock(Path(run_directory) / "locks" / "run.lock", kind="run", **kwargs)


def writer_lock(
    evidence_directory: str | os.PathLike[str],
    *,
    provider: str,
    worktree: str | os.PathLike[str],
    **kwargs: object,
) -> FileLock:
    return FileLock(
        Path(evidence_directory) / "writer.lock",
        kind="writer",
        provider=provider,
        worktree=worktree,
        **kwargs,
    )
