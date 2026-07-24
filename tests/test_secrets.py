from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "crossforge" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.secrets import (  # noqa: E402
    SecretPolicyError,
    build_context_manifest,
    denied_paths,
    load_allow_entries,
    match_deny_path,
    quarantine_paths,
    restore_quarantine,
    scan_context,
    scan_text,
)


class SecretTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "candidate"
        self.root.mkdir()

    def write(self, relative: str, data: bytes | str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            path.write_text(data, encoding="utf-8")
        else:
            path.write_bytes(data)
        return path

    def test_fixed_deny_glob_semantics(self):
        patterns = ["**/.env", "**/.env.*", "**/secrets/**", "*.pem", "a/**/blocked"]
        self.assertTrue(match_deny_path(".env", patterns))
        self.assertTrue(match_deny_path("service/.env.local", patterns))
        self.assertTrue(match_deny_path("a/secrets/token.txt", patterns))
        self.assertTrue(match_deny_path("a/blocked", patterns))
        self.assertTrue(match_deny_path("a/deep/blocked", patterns))
        self.assertTrue(match_deny_path("root.pem", patterns))
        self.assertFalse(match_deny_path("keys/root.pem", patterns))
        self.assertFalse(match_deny_path("not.env", patterns))
        self.assertEqual(
            denied_paths(["safe.txt", ".env", "x/secrets/a"], patterns),
            [".env", "x/secrets/a"],
        )

    def test_private_key_and_assignment_detection_without_value_disclosure(self):
        secret = "UltraSensitiveValueThatMustNeverAppear123456789"
        findings = scan_text(
            "-----BEGIN PRIVATE KEY-----\n" f'api_key = "{secret}"\n',
            "config.txt",
        )
        encoded = json.dumps([finding.to_dict() for finding in findings])
        self.assertIn("pem-private-key", encoded)
        self.assertIn("credential-assignment", encoded)
        self.assertNotIn(secret, encoded)
        self.assertNotIn(secret, repr(findings))

    def test_placeholder_suppression(self):
        findings = scan_text(
            "api_key=YOUR_API_KEY\npassword=changeme\ntoken=placeholder\n",
            "sample.env",
        )
        self.assertEqual(findings, [])

    def test_context_manifest_includes_all_regular_files_and_internal_symlink(self):
        one = self.write("a.txt", "alpha")
        two = self.write("nested/b.txt", "beta")
        os.symlink("../a.txt", self.root / "nested" / "link")
        (self.root / ".git").mkdir()
        self.write(".git/config", "not provider context")
        output = Path(self.temporary.name) / "context-manifest.json"
        manifest = build_context_manifest(self.root, output_path=output)
        self.assertEqual(
            [entry["path"] for entry in manifest["files"]],
            ["a.txt", "nested/b.txt", "nested/link"],
        )
        self.assertEqual(manifest["fileCount"], 3)
        self.assertEqual(
            manifest["totalBytes"],
            one.stat().st_size + two.stat().st_size + len("../a.txt"),
        )
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_escaping_symlink_is_rejected(self):
        outside = Path(self.temporary.name) / "outside"
        outside.write_text("outside", encoding="utf-8")
        os.symlink(outside, self.root / "escape")
        with self.assertRaisesRegex(SecretPolicyError, "symlink escapes"):
            build_context_manifest(self.root)

    def test_symlink_cannot_reintroduce_excluded_context(self):
        (self.root / ".git").mkdir()
        self.write(".git/config", "sensitive repository metadata")
        os.symlink(".git/config", self.root / "git-config-alias")
        with self.assertRaisesRegex(SecretPolicyError, "exposes excluded"):
            build_context_manifest(self.root)

    def test_allow_entry_expiry_and_hash_invalidation(self):
        secret_file = self.write(
            "settings.txt",
            'token = "qwertyuiopasdfghjklzxcvbnm1234567890"\n',
        )
        manifest = build_context_manifest(self.root)
        finding = scan_context(self.root, manifest)[0]
        now = datetime(2026, 7, 24, tzinfo=timezone.utc)
        allow_path = Path(self.temporary.name) / "secret-scan-allow.json"
        entry = {
            "path": finding.path,
            "detector": finding.detector,
            "line": finding.line,
            "justification": "Synthetic fixture",
            "expiresAt": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            "sha256": hashlib.sha256(secret_file.read_bytes()).hexdigest(),
        }
        allow_path.write_text(json.dumps({"entries": [entry]}), encoding="utf-8")
        allows = load_allow_entries(allow_path, now=now)
        remaining = scan_context(self.root, manifest, allow_entries=allows)
        self.assertLess(len(remaining), len(scan_context(self.root, manifest)))

        secret_file.write_text(
            'token = "a-different-sensitive-value-123456789012345"\n',
            encoding="utf-8",
        )
        changed_manifest = build_context_manifest(self.root)
        remaining = scan_context(self.root, changed_manifest, allow_entries=allows)
        self.assertTrue(remaining)
        self.assertEqual(
            load_allow_entries(allow_path, now=now + timedelta(days=2)), []
        )

    def test_unapproved_binary_blocks_and_hash_approval_allows(self):
        binary = self.write("asset.bin", b"\x00\x01\x02")
        manifest = build_context_manifest(self.root)
        with self.assertRaisesRegex(SecretPolicyError, "unapproved_binary_context"):
            scan_context(self.root, manifest)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.assertEqual(
            scan_context(
                self.root,
                manifest,
                approved_binary_context=[{"path": "asset.bin", "sha256": digest}],
            ),
            [],
        )

    def test_binary_marker_after_prefix_is_still_detected(self):
        self.write("late-binary.dat", b"a" * 9000 + b"\x00")
        manifest = build_context_manifest(self.root)
        with self.assertRaisesRegex(SecretPolicyError, "unapproved_binary_context"):
            scan_context(self.root, manifest)

    def test_large_text_requires_exact_hash_bound_file_exception(self):
        large = self.write("large.txt", "credential-free text")
        manifest = build_context_manifest(self.root)
        with self.assertRaisesRegex(SecretPolicyError, "unscannable_large_text"):
            scan_context(self.root, manifest, max_text_bytes=4)
        digest = hashlib.sha256(large.read_bytes()).hexdigest()
        exception = {
            "path": "large.txt",
            "detector": "unscannable-large-text",
            "line": 0,
            "justification": "Reviewed generated fixture",
            "expiresAt": "2026-08-01T00:00:00Z",
            "sha256": digest,
        }
        self.assertEqual(
            scan_context(
                self.root,
                manifest,
                allow_entries=[exception],
                max_text_bytes=4,
            ),
            [],
        )
        exception["sha256"] = "0" * 64
        with self.assertRaisesRegex(SecretPolicyError, "unscannable_large_text"):
            scan_context(
                self.root,
                manifest,
                allow_entries=[exception],
                max_text_bytes=4,
            )

    def test_quarantine_and_byte_exact_restore(self):
        original = b"trusted secret bytes\x00"
        self.write(".env", original)
        quarantine = Path(self.temporary.name) / "evidence" / "quarantine"
        manifest = quarantine_paths(self.root, [".env"], quarantine)
        self.assertFalse((self.root / ".env").exists())
        result = restore_quarantine(self.root, quarantine, manifest)
        self.assertEqual((self.root / ".env").read_bytes(), original)
        self.assertEqual(result["conflicts"], [])
        self.assertFalse(result["scopeViolation"])

    def test_provider_created_denied_path_conflict_is_preserved(self):
        self.write(".env", "trusted")
        quarantine = Path(self.temporary.name) / "evidence" / "quarantine"
        manifest = quarantine_paths(self.root, [".env"], quarantine)
        self.write(".env", "provider-created")
        result = restore_quarantine(self.root, quarantine, manifest)
        self.assertEqual((self.root / ".env").read_text(encoding="utf-8"), "trusted")
        self.assertEqual(
            (quarantine / "provider-conflicts" / ".env").read_text(encoding="utf-8"),
            "provider-created",
        )
        self.assertEqual(result["conflicts"], [".env"])
        self.assertTrue(result["scopeViolation"])


if __name__ == "__main__":
    unittest.main()
