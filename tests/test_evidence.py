from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "crossforge" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.evidence import (  # noqa: E402
    EvidenceStore,
    contained_evidence_path,
    evidence_manifest,
    normalize_evidence_path,
    safe_user_summary,
)
from crossforge_lib.errors import InvalidInputError, PolicyError  # noqa: E402


class EvidenceTests(unittest.TestCase):
    def test_private_atomic_artifact_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = EvidenceStore(Path(temporary) / "evidence")
            artifact = store.write_json("shared/value.json", {"answer": 42})
            path = store.path(artifact.relative_path)

            self.assertTrue(store.verify(artifact))
            self.assertEqual(0, path.stat().st_mode & 0o077)
            self.assertEqual(0, store.root.stat().st_mode & 0o077)

    def test_provider_claims_and_independent_evidence_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = EvidenceStore(Path(temporary) / "evidence")
            claim = store.write_provider_json("codex", "report.json", {"status": "complete"})
            fact = store.write_independent_json("gates/unit.json", {"passed": True})

            self.assertEqual("provider_claim", store.classify(store.path(claim.relative_path)))
            self.assertEqual("independent", store.classify(store.path(fact.relative_path)))
            self.assertNotEqual(
                store.path(claim.relative_path).parent,
                store.path(fact.relative_path).parent,
            )

    def test_paths_reject_traversal_backslash_and_symlink(self) -> None:
        for invalid in ("../secret", "/absolute", "a\\b", "./alias", "a//b"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(InvalidInputError):
                    normalize_evidence_path(invalid)
        if not hasattr(os, "symlink"):
            return
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            outside = Path(temporary) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "link").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(PolicyError):
                contained_evidence_path(root, "link/file")

    def test_manifest_is_deterministic_and_content_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.txt").write_text("secret-looking-content", encoding="utf-8")
            (root / "b.txt").write_text("safe", encoding="utf-8")
            first = evidence_manifest(root, [root / "b.txt", root / "a.txt"])
            second = evidence_manifest(root, [root / "a.txt", root / "b.txt"])

            self.assertEqual(first, second)
            self.assertEqual(["a.txt", "b.txt"], [item["path"] for item in first["files"]])
            self.assertNotIn("secret-looking-content", repr(first))

    def test_user_summary_does_not_echo_provider_content(self) -> None:
        summary = safe_user_summary(
            {
                "provider": "codex",
                "status": "failed",
                "risks": ["token=super-secret"],
                "changedFiles": [],
            }
        )
        self.assertNotIn("super-secret", summary)
        self.assertEqual("Evidence summary: provider=codex, status=failed, changedFiles=0", summary)


if __name__ == "__main__":
    unittest.main()
