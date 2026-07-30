from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "crossforge" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


from crossforge_lib.errors import PreconditionError
from crossforge_lib.locking import (
    FileLock,
    InvalidLockError,
    LockHeldError,
    repository_lock,
    run_lock,
    writer_lock,
)


class FileLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "state"
        self.root.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_exclusive_acquisition_and_release(self) -> None:
        path = self.root / "writer.lock"
        first = FileLock(
            path,
            kind="writer",
            provider="codex",
            worktree=self.root / "candidate",
        )
        second = FileLock(
            path,
            kind="writer",
            provider="grok",
            worktree=self.root / "candidate",
        )
        with first:
            self.assertTrue(path.is_file())
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            with self.assertRaises(LockHeldError) as caught:
                second.acquire()
            self.assertNotIn("command", str(caught.exception.details))
        self.assertFalse(path.exists())
        with second:
            self.assertEqual("grok", second.metadata.provider)

    def test_same_host_dead_pid_is_cleared(self) -> None:
        path = self.root / "repository.lock"
        path.write_text(
            json.dumps(
                {
                    "pid": 999_999_999,
                    "hostname": socket.gethostname(),
                    "provider": None,
                    "worktree": None,
                    "startedAt": "2026-07-24T12:00:00Z",
                }
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        lock = FileLock(path, kind="repository")
        with mock.patch("crossforge_lib.locking._pid_is_alive", return_value=False):
            lock.acquire()
        try:
            self.assertEqual(os.getpid(), lock.metadata.pid)
        finally:
            lock.release()

    def test_live_same_host_lock_is_not_cleared(self) -> None:
        path = self.root / "repository.lock"
        path.write_text(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "hostname": socket.gethostname(),
                    "provider": None,
                    "worktree": None,
                    "startedAt": "2026-07-24T12:00:00Z",
                }
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        with self.assertRaises(LockHeldError):
            FileLock(path, kind="repository").acquire()
        self.assertTrue(path.exists())

    def test_foreign_host_requires_explicit_approval(self) -> None:
        path = self.root / "repository.lock"
        value = {
            "pid": 123,
            "hostname": "another-host.example",
            "provider": None,
            "worktree": None,
            "startedAt": "2026-07-24T12:00:00Z",
        }
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(0o600)
        with self.assertRaises(LockHeldError):
            FileLock(path, kind="repository").acquire()
        self.assertTrue(path.exists())

        approved = FileLock(
            path,
            kind="repository",
            approve_foreign_stale=lambda metadata: metadata.hostname
            == "another-host.example",
        )
        with approved:
            self.assertEqual(socket.gethostname(), approved.metadata.hostname)

    def test_malformed_and_public_lock_files_are_rejected(self) -> None:
        path = self.root / "repository.lock"
        path.write_text("not-json", encoding="utf-8")
        path.chmod(0o600)
        with self.assertRaises(InvalidLockError):
            FileLock(path, kind="repository").acquire()
        path.write_text("{}", encoding="utf-8")
        path.chmod(0o644)
        with self.assertRaises(InvalidLockError):
            FileLock(path, kind="repository").acquire()

    def test_lock_order_is_enforced(self) -> None:
        run_directory = self.root / "runs" / "run"
        evidence = self.root / "evidence"
        with repository_lock(self.root):
            with run_lock(run_directory):
                with writer_lock(
                    evidence,
                    provider="codex",
                    worktree=self.root / "candidate",
                ):
                    with self.assertRaises(PreconditionError):
                        repository_lock(self.root / "nested").acquire()

    def test_convenience_paths_match_contract(self) -> None:
        self.assertEqual(
            self.root / "repository.lock", repository_lock(self.root).path
        )
        self.assertEqual(
            self.root / "run" / "locks" / "run.lock",
            run_lock(self.root / "run").path,
        )
        self.assertEqual(
            self.root / "evidence" / "writer.lock",
            writer_lock(
                self.root / "evidence",
                provider="codex",
                worktree=self.root,
            ).path,
        )

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_forked_child_cannot_release_parent_lock(self) -> None:
        lock = repository_lock(self.root)
        lock.acquire()
        child_pid = os.fork()
        if child_pid == 0:
            lock.release()
            os._exit(0)
        _, status = os.waitpid(child_pid, 0)
        self.assertEqual(0, status)
        self.assertTrue(lock.path.exists())
        lock.release()
        self.assertFalse(lock.path.exists())

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_lock_constructed_before_fork_records_child_pid(self) -> None:
        lock = repository_lock(self.root)
        read_fd, write_fd = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:
            os.close(read_fd)
            with lock:
                persisted = json.loads(lock.path.read_text(encoding="utf-8"))
                os.write(write_fd, str(persisted["pid"]).encode("ascii"))
            os.close(write_fd)
            os._exit(0)
        os.close(write_fd)
        recorded_pid = int(os.read(read_fd, 64).decode("ascii"))
        os.close(read_fd)
        _, status = os.waitpid(child_pid, 0)
        self.assertEqual(0, status)
        self.assertEqual(child_pid, recorded_pid)


if __name__ == "__main__":
    unittest.main()
