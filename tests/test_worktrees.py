"""Focused tests for candidate worktree isolation, capture, and cleanup."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "crossforge" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.locking import LockHeldError
from crossforge_lib.worktrees import (
    WorktreeEntry,
    WorktreeError,
    WorktreeManager,
    WorktreeRegistry,
    WorktreeStateError,
)


def command(
    cwd: Path, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


class WorktreeCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.sandbox = Path(self.temporary.name).resolve()
        self.repository = self.sandbox / "repository"
        self.repository.mkdir()
        command(self.repository, "git", "init", "-b", "main")
        command(self.repository, "git", "config", "user.name", "Crossforge Test")
        command(self.repository, "git", "config", "user.email", "test@invalid")
        (self.repository / "tracked.txt").write_text("base\n", encoding="utf-8")
        (self.repository / "rename-me.txt").write_text("rename\n", encoding="utf-8")
        (self.repository / ".env").write_text("API_TOKEN=trusted\n", encoding="utf-8")
        (self.repository / "artifact.bin").write_bytes(b"\x00private binary\xff")
        command(self.repository, "git", "add", ".")
        command(self.repository, "git", "commit", "-m", "base")
        self.base = command(self.repository, "git", "rev-parse", "HEAD").stdout.decode().strip()
        self.root = self.sandbox / "worktrees"
        self.registry_path = self.sandbox / "state" / "worktrees.json"
        self.evidence = self.sandbox / "state" / "evidence" / "T1" / "codex"
        self.manager = WorktreeManager(
            self.repository,
            self.root,
            self.registry_path,
            repository_id_prefix="repo1234",
        )

    def tearDown(self) -> None:
        command(self.repository, "git", "worktree", "prune", check=False)
        self.temporary.cleanup()

    def create(self, provider: str = "codex") -> WorktreeEntry:
        return self.manager.create(
            run_id="run-1",
            task_id="T1",
            provider=provider,
            base_commit=self.base,
            evidence_dir=self.evidence.parent / provider,
        )


class CreationAndRegistryTests(WorktreeCase):
    def test_creation_is_detached_clean_at_base_and_recorded(self) -> None:
        entry = self.create()

        self.assertTrue(entry.path.is_dir())
        self.assertEqual(self.base, command(entry.path, "git", "rev-parse", "HEAD").stdout.decode().strip())
        self.assertEqual(b"", command(entry.path, "git", "status", "--porcelain").stdout)
        self.assertEqual(b"", command(entry.path, "git", "symbolic-ref", "-q", "HEAD", check=False).stdout)
        recorded = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self.assertEqual(str(self.root.resolve()), recorded["worktreeRoot"])
        self.assertEqual(str(entry.path), recorded["entries"][0]["path"])
        self.assertEqual("active", recorded["entries"][0]["status"])
        self.assertIsNone(
            recorded["entries"][0]["invocationEvidenceSha256"]
        )
        self.assertIsNone(
            recorded["entries"][0]["invocationEvidencePath"]
        )

    def test_existing_destination_and_escape_are_refused(self) -> None:
        self.create()
        with self.assertRaises(WorktreeError):
            self.create()

        escaped = replace(
            self.manager.registry.load()[0],
            path=self.sandbox / "outside",
        )
        with self.assertRaises(WorktreeError):
            self.manager.registry.write([escaped])

    def test_registry_rejects_unknown_keys(self) -> None:
        self.create()
        value = json.loads(self.registry_path.read_text(encoding="utf-8"))
        value["unexpected"] = True
        self.registry_path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(WorktreeStateError):
            self.manager.registry.load()

    def test_registry_rejects_invalid_invocation_evidence_hash(self) -> None:
        self.create()
        value = json.loads(self.registry_path.read_text(encoding="utf-8"))
        value["entries"][0]["invocationEvidenceSha256"] = "not-a-hash"
        self.registry_path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(WorktreeStateError):
            self.manager.registry.load()

    def test_registry_rejects_invalid_invocation_evidence_path(self) -> None:
        self.create()
        value = json.loads(self.registry_path.read_text(encoding="utf-8"))
        value["entries"][0]["invocationEvidencePath"] = ""
        self.registry_path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(WorktreeStateError):
            self.manager.registry.load()

    def test_writer_lock_is_exclusive_and_bound_to_worktree(self) -> None:
        entry = self.create()
        first = self.manager.acquire_writer_lock(entry)
        try:
            metadata = json.loads(entry.writer_lock_path.read_text(encoding="utf-8"))
            self.assertEqual("codex", metadata["provider"])
            self.assertEqual(str(entry.path), metadata["worktree"])
            with self.assertRaises(LockHeldError):
                self.manager.acquire_writer_lock(entry)
        finally:
            first.release()
        self.assertFalse(entry.writer_lock_path.exists())

    def test_concurrent_registry_adds_preserve_both_entries(self) -> None:
        registries = (
            WorktreeRegistry(self.registry_path, self.root),
            WorktreeRegistry(self.registry_path, self.root),
        )

        def entry(index: int) -> WorktreeEntry:
            path = (self.root / f"parallel-{index}").resolve()
            return WorktreeEntry(
                task_id=f"T{index}",
                provider="codex",
                path=path,
                base_commit=self.base,
                status="creating",
                writer_lock_path=path / ".crossforge-writer.lock",
                captured_patch_sha256=None,
                invocation_evidence_sha256=None,
                invocation_evidence_path=None,
                created_at="2026-07-24T12:00:00Z",
                cleaned_at=None,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(registries[index].add, entry(index))
                for index in range(2)
            ]
            for future in futures:
                future.result()
        self.assertEqual(
            {"T0", "T1"},
            {record.task_id for record in registries[0].load()},
        )


class ProjectionTests(WorktreeCase):
    def test_projection_has_one_sanitized_commit_and_restores_control_file(self) -> None:
        entry = self.create()
        original_control = (entry.path / ".git").read_bytes()
        original_mode = stat.S_IMODE((entry.path / ".git").lstat().st_mode)

        with self.manager.expose_to_provider(
            entry,
            evidence_dir=self.evidence,
            quarantine_paths_list=[".env"],
            runtime_metadata={"providerExecutable": {"path": "/fake/codex", "sha256": "0" * 64}},
        ) as context:
            self.assertTrue((entry.path / ".git").is_dir())
            self.assertFalse((entry.path / ".env").exists())
            self.assertFalse((entry.path / "artifact.bin").exists())
            self.assertEqual(
                b"1\n",
                command(entry.path, "git", "rev-list", "--all", "--count").stdout,
            )
            self.assertEqual(b"", command(entry.path, "git", "remote", "-v").stdout)
            self.assertNotEqual(
                0,
                command(
                    entry.path,
                    "git",
                    "cat-file",
                    "-e",
                    f"{context.projection.isolated_commit}:.env",
                    check=False,
                ).returncode,
            )
            self.assertTrue(entry.writer_lock_path.exists())
            (entry.path / "tracked.txt").write_text("provider\n", encoding="utf-8")

        self.assertTrue((entry.path / ".git").is_file())
        self.assertEqual(original_control, (entry.path / ".git").read_bytes())
        self.assertEqual(original_mode, stat.S_IMODE((entry.path / ".git").lstat().st_mode))
        self.assertEqual("API_TOKEN=trusted\n", (entry.path / ".env").read_text(encoding="utf-8"))
        self.assertEqual(b"\x00private binary\xff", (entry.path / "artifact.bin").read_bytes())
        self.assertFalse(entry.writer_lock_path.exists())
        runtime = json.loads((self.evidence / "runtime-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual("disabled", runtime["gitConfiguration"]["credentialHelper"])
        context_paths = {item["path"] for item in context.context_manifest["files"]}
        self.assertEqual({"tracked.txt", "rename-me.txt"}, context_paths)

    def test_provider_created_denied_path_is_preserved_as_conflict_evidence(self) -> None:
        entry = self.create()
        with self.assertRaises(WorktreeStateError):
            with self.manager.expose_to_provider(
                entry,
                evidence_dir=self.evidence,
                quarantine_paths_list=[".env"],
            ):
                (entry.path / ".env").write_text("provider replacement\n", encoding="utf-8")

        self.assertEqual("API_TOKEN=trusted\n", (entry.path / ".env").read_text(encoding="utf-8"))
        conflict = self.evidence / "provider-denied-conflicts" / ".env"
        self.assertEqual("provider replacement\n", conflict.read_text(encoding="utf-8"))
        self.assertEqual("blocked", self.manager.registry.get(entry.path).status)


class CaptureAndCleanupTests(WorktreeCase):
    def test_binary_safe_capture_proof_and_non_force_cleanup(self) -> None:
        entry = self.create()
        (entry.path / "tracked.txt").write_text("changed\n", encoding="utf-8")
        (entry.path / "rename-me.txt").rename(entry.path / "renamed.txt")
        (entry.path / "new.txt").write_text("new\n", encoding="utf-8")
        (entry.path / "binary.bin").write_bytes(b"\x00\xff\x01new binary\x00")
        command(entry.path, "git", "add", "tracked.txt", "new.txt")
        patch = self.evidence / "candidate.patch"

        captured = self.manager.capture_patch(entry, patch)

        self.assertEqual("captured", captured.status)
        self.assertEqual(captured.captured_patch_sha256, __import__("hashlib").sha256(patch.read_bytes()).hexdigest())
        self.assertIn(b"GIT binary patch", patch.read_bytes())
        # Provider-created staging is preserved; only Crossforge's temporary
        # intent-to-add entries are cleared.
        self.assertEqual(
            1,
            command(entry.path, "git", "diff", "--cached", "--quiet", check=False).returncode,
        )
        cleaned = self.manager.cleanup(captured, patch)
        self.assertEqual("cleaned", cleaned.status)
        self.assertIsNotNone(cleaned.cleaned_at)
        self.assertFalse(entry.path.exists())
        self.assertEqual("cleaned", self.manager.registry.get(entry.path).status)

    def test_cleanup_refuses_uncaptured_changes_and_active_lock(self) -> None:
        entry = self.create()
        (entry.path / "tracked.txt").write_text("captured\n", encoding="utf-8")
        patch = self.evidence / "candidate.patch"
        captured = self.manager.capture_patch(entry, patch)

        lock = self.manager.acquire_writer_lock(captured)
        try:
            with self.assertRaises(WorktreeError):
                self.manager.cleanup(captured, patch)
        finally:
            lock.release()

        (entry.path / "tracked.txt").write_text("uncaptured\n", encoding="utf-8")
        with self.assertRaises(WorktreeStateError):
            self.manager.cleanup(captured, patch)
        self.assertTrue(entry.path.exists())

    def test_cleanup_derives_durable_evidence_and_honors_retention(self) -> None:
        entry = self.create()
        (entry.path / "tracked.txt").write_text("candidate\n", encoding="utf-8")
        patch = self.evidence / "candidate.patch"
        captured = self.manager.capture_patch(entry, patch)
        original_patch = patch.read_bytes()
        patch.write_text("tampered\n", encoding="utf-8")
        with self.assertRaises(WorktreeStateError):
            self.manager.cleanup(captured, patch)
        patch.write_bytes(original_patch)
        retained = self.manager.cleanup(
            captured,
            patch,
            retention_permits=False,
        )
        self.assertEqual("retained", retained.status)
        self.assertTrue(entry.path.exists())


if __name__ == "__main__":
    unittest.main()
