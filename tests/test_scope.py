"""Tests for Crossforge's exact allowlist and change-type enforcement."""

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

from crossforge_lib.errors import InvalidInputError, ScopeViolationError
from crossforge_lib.git import discover_repository, resolve_commit
from crossforge_lib.scope import (
    changed_paths,
    check_scope,
    enforce_scope,
    parse_allowlist,
    scoped_tree_hash,
    validate_relative_path,
)


def command(cwd: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


class ScopeRepositoryCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        command(self.root, "git", "init", "-b", "main")
        command(self.root, "git", "config", "user.name", "Crossforge Test")
        command(self.root, "git", "config", "user.email", "test@invalid")
        (self.root / "a.txt").write_text("a\n", encoding="utf-8")
        (self.root / "b.txt").write_text("b\n", encoding="utf-8")
        command(self.root, "git", "add", "a.txt", "b.txt")
        command(self.root, "git", "commit", "-m", "base")
        self.repository = discover_repository(self.root)
        self.base = resolve_commit(self.repository)

    def tearDown(self) -> None:
        self.temporary.cleanup()


class AllowlistTests(unittest.TestCase):
    def test_accepts_exact_posix_paths_and_ignores_blank_lines(self) -> None:
        self.assertEqual(("src/a.py", "tests/a.py"), parse_allowlist(
            "src/a.py\n\ntests/a.py\n"
        ))

    def test_rejects_empty_absolute_traversal_glob_directory_and_whitespace(self) -> None:
        invalid = [
            "",
            "/absolute",
            "../escape",
            "a/../escape",
            "src/*.py",
            "src\\a.py",
            " src/a.py",
            "src/a.py ",
            "src//a.py",
            "src/",
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(InvalidInputError):
                parse_allowlist(value)

    def test_rejects_duplicate_and_comment_lines(self) -> None:
        with self.assertRaises(InvalidInputError):
            parse_allowlist("a.txt\na.txt\n")
        with self.assertRaises(InvalidInputError):
            parse_allowlist("# comment\na.txt\n")

    def test_rejects_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "subdir").mkdir()
            with self.assertRaises(InvalidInputError):
                validate_relative_path("subdir", root=root)


class ChangedPathTests(ScopeRepositoryCase):
    def test_tracked_unstaged_and_staged_modifications(self) -> None:
        (self.root / "a.txt").write_text("changed\n", encoding="utf-8")
        self.assertEqual(("a.txt",), changed_paths(
            self.repository, base_commit=self.base
        ))
        command(self.root, "git", "add", "a.txt")
        self.assertEqual(("a.txt",), changed_paths(
            self.repository, base_commit=self.base
        ))

    def test_deletion_is_included(self) -> None:
        (self.root / "a.txt").unlink()
        self.assertEqual(("a.txt",), changed_paths(
            self.repository, base_commit=self.base
        ))

    def test_rename_includes_old_and_new_paths(self) -> None:
        command(self.root, "git", "mv", "a.txt", "renamed.txt")
        self.assertEqual(
            ("a.txt", "renamed.txt"),
            changed_paths(self.repository, base_commit=self.base),
        )

    def test_ignored_untracked_is_excluded_and_visible_untracked_included(self) -> None:
        (self.root / ".gitignore").write_text("ignored.tmp\n", encoding="utf-8")
        command(self.root, "git", "add", ".gitignore")
        command(self.root, "git", "commit", "-m", "ignore")
        base = resolve_commit(self.repository)
        (self.root / "ignored.tmp").write_text("ignored", encoding="utf-8")
        (self.root / "visible.tmp").write_text("visible", encoding="utf-8")
        self.assertEqual(
            ("visible.tmp",),
            changed_paths(self.repository, base_commit=base),
        )

    def test_outside_allowlist_is_a_machine_readable_violation(self) -> None:
        (self.root / "a.txt").write_text("changed a\n", encoding="utf-8")
        (self.root / "b.txt").write_text("changed b\n", encoding="utf-8")
        result = check_scope(
            self.repository, base_commit=self.base, allowlist=["a.txt"]
        )
        self.assertFalse(result.passed)
        self.assertEqual(("b.txt",), result.violations)
        self.assertEqual(
            {
                "passed": False,
                "base": self.base,
                "allowed": ["a.txt"],
                "changed": ["a.txt", "b.txt"],
                "violations": ["b.txt"],
                "issues": [
                    {
                        "path": "b.txt",
                        "reason": "path is outside the exact allowlist",
                    }
                ],
            },
            result.to_dict(),
        )
        with self.assertRaises(ScopeViolationError):
            enforce_scope(
                self.repository, base_commit=self.base, allowlist=["a.txt"]
            )

    def test_clean_allowed_change_passes(self) -> None:
        (self.root / "a.txt").write_text("changed\n", encoding="utf-8")
        result = enforce_scope(
            self.repository, base_commit=self.base, allowlist=["a.txt"]
        )
        self.assertTrue(result.passed)


@unittest.skipUnless(hasattr(os, "symlink"), "symlinks unsupported")
class SymlinkTests(ScopeRepositoryCase):
    def test_rejects_symlink_escape_and_intermediate_parent(self) -> None:
        outside = self.root.parent / "outside-target"
        outside.write_text("outside", encoding="utf-8")
        try:
            os.symlink(str(outside), self.root / "escape")
            with self.assertRaises(InvalidInputError):
                validate_relative_path("escape", root=self.root)

            target_dir = self.root / "real-parent"
            target_dir.mkdir()
            os.symlink("real-parent", self.root / "linked-parent")
            with self.assertRaises(InvalidInputError):
                validate_relative_path("linked-parent/child.txt", root=self.root)
        finally:
            outside.unlink(missing_ok=True)

    def test_changed_symlink_requires_exact_path_and_target_approval(self) -> None:
        (self.root / "target.txt").write_text("target", encoding="utf-8")
        os.symlink("target.txt", self.root / "link")
        rejected = check_scope(
            self.repository,
            base_commit=self.base,
            allowlist=["link", "target.txt"],
        )
        self.assertFalse(rejected.passed)
        accepted = check_scope(
            self.repository,
            base_commit=self.base,
            allowlist=["link", "target.txt"],
            approved_symlinks={"link": "target.txt"},
        )
        self.assertTrue(accepted.passed)

    def test_scoped_hash_is_byte_and_symlink_target_sensitive(self) -> None:
        (self.root / "target.txt").write_text("one", encoding="utf-8")
        os.symlink("target.txt", self.root / "link")
        first = scoped_tree_hash(
            self.root,
            ["target.txt", "link"],
            approved_symlinks={"link": "target.txt"},
        )
        (self.root / "target.txt").write_text("two", encoding="utf-8")
        second = scoped_tree_hash(
            self.root,
            ["target.txt", "link"],
            approved_symlinks={"link": "target.txt"},
        )
        self.assertNotEqual(first, second)


class UnsafeModeTests(ScopeRepositoryCase):
    @unittest.skipIf(os.name == "nt", "executable mode unsupported on Windows")
    def test_rejects_mode_change(self) -> None:
        os.chmod(self.root / "a.txt", 0o755)
        result = check_scope(
            self.repository, base_commit=self.base, allowlist=["a.txt"]
        )
        self.assertFalse(result.passed)
        self.assertIn("a.txt", result.violations)
        self.assertTrue(any("mode" in issue.reason for issue in result.issues))

    def test_rejects_gitlink_submodule_entry(self) -> None:
        command(
            self.root,
            "git",
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.base},vendor/module",
        )
        result = check_scope(
            self.repository,
            base_commit=self.base,
            allowlist=["vendor/module"],
        )
        self.assertFalse(result.passed)
        self.assertTrue(any("submodule" in issue.reason for issue in result.issues))


if __name__ == "__main__":
    unittest.main()
