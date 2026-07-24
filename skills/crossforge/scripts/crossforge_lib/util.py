"""Small deterministic and filesystem-safe utility functions."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import PreconditionError


def utc_now() -> str:
    """Return the current time as an RFC 3339 UTC string."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical_json_text(value: Any) -> str:
    """Serialize JSON deterministically, including one trailing newline."""

    return json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        separators=(",", ": "),
    ) + "\n"


def canonical_json_bytes(value: Any) -> bytes:
    return canonical_json_text(value).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_owned_private_path(path: Path, *, directory: bool) -> None:
    """Refuse unsafe pre-existing state paths on POSIX systems."""

    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise PreconditionError(f"Refusing to use symlinked state path: {path}")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise PreconditionError(f"Expected a directory: {path}")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise PreconditionError(f"Expected a regular file: {path}")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PreconditionError(f"State path is owned by another user: {path}")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PreconditionError(f"State path is writable by group or others: {path}")


def ensure_private_directory(path: str | os.PathLike[str]) -> Path:
    """Create a private directory and validate any pre-existing components."""

    directory = Path(path)
    if os.path.lexists(directory):
        _validate_owned_private_path(directory, directory=True)
        return directory

    # Create one level at a time so existing unsafe ancestors in the requested
    # state subtree are detected rather than silently traversed.
    missing: list[Path] = []
    cursor = directory
    while not os.path.lexists(cursor):
        missing.append(cursor)
        cursor = cursor.parent
    if cursor.is_symlink():
        raise PreconditionError(
            f"Refusing to traverse symlinked state-directory parent: {cursor}"
        )
    if not cursor.is_dir():
        raise PreconditionError(f"State-directory parent is not a directory: {cursor}")
    for item in reversed(missing):
        item.mkdir(mode=0o700)
        _validate_owned_private_path(item, directory=True)
    return directory


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(directory, flags)
    except (OSError, NotImplementedError):
        return
    try:
        os.fsync(descriptor)
    except OSError:
        # Some platforms/filesystems do not support fsync on a directory.
        pass
    finally:
        os.close(descriptor)


def atomic_write_bytes(
    path: str | os.PathLike[str],
    data: bytes,
    *,
    mode: int = 0o600,
) -> None:
    """Atomically replace *path* with complete, flushed bytes."""

    target = Path(path)
    parent = ensure_private_directory(target.parent)
    if os.path.lexists(target):
        _validate_owned_private_path(target, directory=False)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        _fsync_directory(parent)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def atomic_write_text(
    path: str | os.PathLike[str],
    text: str,
    *,
    mode: int = 0o600,
) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def atomic_write_json(
    path: str | os.PathLike[str],
    value: Any,
    *,
    mode: int = 0o600,
) -> None:
    atomic_write_bytes(path, canonical_json_bytes(value), mode=mode)
