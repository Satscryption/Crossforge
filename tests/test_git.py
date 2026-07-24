"""Tests for safe Git discovery, branch, identity, and staging primitives."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "crossforge" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.errors import InvalidInputError, PreconditionError
from crossforge_lib.git import (
    branch_exists,
    detect_default_branch,
    discover_repository,
    ensure_dedicated_branch,
    hash_object_no_filters,
    index_entry,
    is_dirty,
    normalize_remote_url,
    repository_identity,
    resolve_commit,
    run_git,
    stage_path_filter_free,
)


def command(cwd: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


class GitRepositoryCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        command(self.root, "git", "init", "-b", "main")
        command(self.root, "git", "config", "user.name", "Crossforge Test")
        command(self.root, "git", "config", "user.email", "test@invalid")
        (self.root / "tracked.txt").write_text("base\n", encoding="utf-8")
        command(self.root, "git", "add", "tracked.txt")
        command(self.root, "git", "commit", "-m", "base")
        self.repository = discover_repository(self.root)
        self.base = resolve_commit(self.repository)

    def tearDown(self) -> None:
        self.temporary.cleanup()


class GitDiscoveryTests(GitRepositoryCase):
    def test_discovers_root_common_and_worktree_specific_dirs(self) -> None:
        nested = self.root / "nested"
        nested.mkdir()
        discovered = discover_repository(nested)
        self.assertEqual(self.root, discovered.root)
        self.assertEqual((self.root / ".git").resolve(), discovered.common_git_dir)
        self.assertEqual(discovered.common_git_dir, discovered.git_dir)

        linked = self.root.parent / f"{self.root.name}-linked"
        command(self.root, "git", "worktree", "add", "-b", "linked", str(linked))
        try:
            worktree_repository = discover_repository(linked)
            self.assertEqual(self.repository.common_git_dir, worktree_repository.common_git_dir)
            self.assertNotEqual(
                worktree_repository.common_git_dir, worktree_repository.git_dir
            )
        finally:
            command(self.root, "git", "worktree", "remove", str(linked))

    def test_argument_array_wrapper_captures_bytes_and_never_needs_a_shell(self) -> None:
        result = run_git(self.root, ["rev-parse", "--show-toplevel"])
        self.assertEqual(0, result.returncode)
        self.assertEqual(self.root, Path(result.stdout.strip()))
        self.assertEqual("git", result.argv[0])
        with self.assertRaises(InvalidInputError):
            run_git(self.root, ["status", "bad\x00argument"])

    def test_dirty_state_includes_untracked_but_not_ignored(self) -> None:
        self.assertFalse(is_dirty(self.repository))
        (self.root / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        command(self.root, "git", "add", ".gitignore")
        command(self.root, "git", "commit", "-m", "ignore")
        self.assertFalse(is_dirty(self.repository))
        (self.root / "ignored.txt").write_text("ignored", encoding="utf-8")
        self.assertFalse(is_dirty(self.repository))
        (self.root / "visible.txt").write_text("visible", encoding="utf-8")
        self.assertTrue(is_dirty(self.repository))

    def test_default_branch_prefers_explicit_then_remote_then_local(self) -> None:
        self.assertEqual("release", detect_default_branch(
            self.repository, explicit_target="release"
        ))
        self.assertEqual("main", detect_default_branch(self.repository, remote=None))
        command(
            self.root,
            "git",
            "update-ref",
            "refs/remotes/upstream/trunk",
            self.base,
        )
        command(
            self.root,
            "git",
            "symbolic-ref",
            "refs/remotes/upstream/HEAD",
            "refs/remotes/upstream/trunk",
        )
        self.assertEqual(
            "trunk", detect_default_branch(self.repository, remote="upstream")
        )


class RemoteIdentityTests(GitRepositoryCase):
    def test_normalizes_https_ssh_scp_ports_and_mixed_case_paths(self) -> None:
        self.assertEqual(
            "https://github.com/Owner/MixedCase",
            normalize_remote_url(
                "HTTPS://alice:secret@GitHub.COM/Owner/MixedCase.git/"
            ),
        )
        self.assertEqual(
            "ssh://example.com/Org/Repo",
            normalize_remote_url("ssh://git@Example.COM:22/Org/Repo.git"),
        )
        self.assertEqual(
            "ssh://example.com:2222/Org/Repo",
            normalize_remote_url("ssh://git@Example.COM:2222/Org/Repo.git"),
        )
        self.assertEqual(
            "github.com:Owner/Repo",
            normalize_remote_url("git@GitHub.COM:Owner/Repo.git"),
        )

    def test_rejects_query_credentials_but_preserves_safe_query(self) -> None:
        with self.assertRaises(InvalidInputError):
            normalize_remote_url("https://example.com/o/r.git?access_token=secret")
        self.assertEqual(
            "https://example.com/O/R?ref=One",
            normalize_remote_url("https://Example.com/O/R.git?ref=One"),
        )

    def test_identity_is_stable_and_never_depends_on_remote_user_info(self) -> None:
        first = repository_identity(
            self.repository,
            remote_url="https://alice:one@example.com/Owner/Repo.git",
        )
        second = repository_identity(
            self.repository,
            remote_url="https://bob:two@EXAMPLE.COM/Owner/Repo/",
        )
        self.assertEqual(first, second)
        self.assertEqual(64, len(first))


class BranchTests(GitRepositoryCase):
    def test_creates_generated_branch_from_exact_start(self) -> None:
        resolution = ensure_dedicated_branch(
            self.repository,
            start_commit=self.base,
            target_branch="main",
            run_id="20260724T120000Z-a1b2c3d4",
        )
        self.assertEqual("crossforge/20260724t120000z-a1b2c3d4", resolution.branch)
        self.assertTrue(resolution.created)
        self.assertTrue(branch_exists(self.repository, resolution.branch))
        self.assertEqual(self.base, resolve_commit(self.repository))

    def test_reuses_clean_non_default_branch(self) -> None:
        command(self.root, "git", "switch", "-c", "feature")
        resolution = ensure_dedicated_branch(
            self.repository,
            start_commit=self.base,
            target_branch="main",
            run_id="20260724T120000Z-a1b2c3d4",
        )
        self.assertEqual("feature", resolution.branch)
        self.assertTrue(resolution.reused_current)
        self.assertFalse(resolution.created)

    def test_requested_branch_collision_and_dirty_checkout_are_refused(self) -> None:
        command(self.root, "git", "branch", "occupied")
        command(self.root, "git", "switch", "occupied")
        (self.root / "tracked.txt").write_text("different\n", encoding="utf-8")
        command(self.root, "git", "commit", "-am", "advance")
        command(self.root, "git", "switch", "main")
        with self.assertRaises(PreconditionError):
            ensure_dedicated_branch(
                self.repository,
                start_commit=self.base,
                target_branch="main",
                run_id="20260724T120000Z-a1b2c3d4",
                requested_branch="occupied",
            )

        (self.root / "untracked.txt").write_text("dirty", encoding="utf-8")
        with self.assertRaises(PreconditionError):
            ensure_dedicated_branch(
                self.repository,
                start_commit=self.base,
                target_branch="main",
                run_id="20260724T120000Z-a1b2c3d4",
            )


class FilterFreeStagingTests(GitRepositoryCase):
    def test_hash_object_uses_exact_supplied_bytes(self) -> None:
        data = b"raw\r\nbytes\x00remain exact"
        object_id = hash_object_no_filters(self.repository, data)
        stored = command(self.root, "git", "cat-file", "blob", object_id).stdout
        self.assertEqual(data, stored)

    def test_staging_bypasses_clean_filter_and_records_exact_mode(self) -> None:
        (self.root / ".gitattributes").write_text(
            "filtered.txt filter=neverrun\n", encoding="utf-8"
        )
        command(self.root, "git", "add", ".gitattributes")
        command(self.root, "git", "commit", "-m", "attributes")
        command(self.root, "git", "config", "filter.neverrun.clean", "false")
        payload = b"candidate bytes\n"
        (self.root / "filtered.txt").write_bytes(payload)

        entry = stage_path_filter_free(self.repository, "filtered.txt")
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual("100644", entry.mode)
        self.assertEqual(payload, command(
            self.root, "git", "cat-file", "blob", entry.object_id
        ).stdout)
        self.assertEqual(entry, index_entry(self.repository, "filtered.txt"))

    def test_stages_deletion_without_reading_candidate_content(self) -> None:
        (self.root / "tracked.txt").unlink()
        self.assertIsNone(stage_path_filter_free(self.repository, "tracked.txt"))
        self.assertIsNone(index_entry(self.repository, "tracked.txt"))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unsupported")
    def test_symlink_requires_exact_approval(self) -> None:
        (self.root / "inside.txt").write_text("inside", encoding="utf-8")
        os.symlink("inside.txt", self.root / "link")
        with self.assertRaises(PreconditionError):
            stage_path_filter_free(self.repository, "link")
        entry = stage_path_filter_free(
            self.repository, "link", approved_symlink_target="inside.txt"
        )
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual("120000", entry.mode)


if __name__ == "__main__":
    unittest.main()
