from __future__ import annotations

import json
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "crossforge" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.consent import (  # noqa: E402
    ConsentError,
    check_consent,
    consent_summary,
    deny_policy_hash,
    load_consent,
    managed_policy_hash,
    record_consent,
)


class ConsentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "crossforge" / "consent.json"
        self.now = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)
        self.repository = "a" * 64
        self.deny = "b" * 64
        self.managed = "c" * 64
        self.executable = str(Path(self.temporary.name) / "bin" / "codex")
        self.executable_sha256 = "e" * 64

    def record(self, **overrides):
        arguments = {
            "repository_identity": self.repository,
            "provider": "codex",
            "operation_classes": ["probe", "plan"],
            "deny_policy_sha256": self.deny,
            "managed_policy_sha256": self.managed,
            "provider_executable_path": self.executable,
            "provider_executable_sha256": self.executable_sha256,
            "ttl_days": 30,
            "now": self.now,
        }
        arguments.update(overrides)
        return record_consent(self.path, **arguments)

    def check(self, record, **overrides):
        arguments = {
            "repository_identity": self.repository,
            "provider": "codex",
            "operation_class": "plan",
            "deny_policy_sha256": self.deny,
            "managed_policy_sha256": self.managed,
            "provider_executable_path": self.executable,
            "provider_executable_sha256": self.executable_sha256,
            "now": self.now + timedelta(days=1),
        }
        arguments.update(overrides)
        return check_consent(record, **arguments)

    def test_missing_consent(self):
        result = self.check(None)
        self.assertFalse(result)
        self.assertEqual(result.reason, "missing_consent")

    def test_legacy_unpinned_consent_is_rejected(self):
        legacy = {
            "schemaVersion": 1,
            "repositoryIdentity": self.repository,
            "providers": {},
        }
        result = self.check(legacy)
        self.assertFalse(result)
        self.assertEqual(result.reason, "invalid_consent")

    def test_valid_consent_is_persisted_owner_only(self):
        record = self.record()
        self.assertTrue(self.check(load_consent(self.path)))
        self.assertEqual(record["providers"]["codex"]["operationClasses"], ["plan", "probe"])
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_expiry(self):
        record = self.record(ttl_days=1)
        result = self.check(record, now=self.now + timedelta(days=1))
        self.assertFalse(result)
        self.assertEqual(result.reason, "consent_expired")

    def test_repository_identity_change(self):
        result = self.check(self.record(), repository_identity="d" * 64)
        self.assertEqual(result.reason, "repository_identity_changed")

    def test_new_provider(self):
        result = self.check(self.record(), provider="grok")
        self.assertEqual(result.reason, "provider_not_approved")

    def test_operation_class_expansion_requires_new_consent(self):
        result = self.check(self.record(), operation_class="implement")
        self.assertEqual(result.reason, "operation_not_approved")

    def test_deny_policy_change(self):
        result = self.check(self.record(), deny_policy_sha256="d" * 64)
        self.assertEqual(result.reason, "deny_policy_changed")

    def test_managed_policy_change(self):
        result = self.check(self.record(), managed_policy_sha256="d" * 64)
        self.assertEqual(result.reason, "managed_policy_changed")

    def test_provider_executable_change(self):
        result = self.check(
            self.record(),
            provider_executable_sha256="f" * 64,
        )
        self.assertEqual(result.reason, "provider_executable_changed")

    def test_repository_change_discards_previous_provider_approvals(self):
        self.record()
        record = self.record(
            repository_identity="d" * 64,
            provider="grok",
            operation_classes=["probe"],
        )
        self.assertEqual(set(record["providers"]), {"grok"})

    def test_policy_hash_is_canonical_and_sensitive_to_exception(self):
        first = deny_policy_hash(
            ["**/.env", "**/*.pem"],
            ["assignment", "pem"],
            [{"path": "a", "line": 1}],
            {"maxBytes": 10},
        )
        reordered = deny_policy_hash(
            ["**/*.pem", "**/.env"],
            ["pem", "assignment"],
            [{"line": 1, "path": "a"}],
            {"maxBytes": 10},
        )
        changed = deny_policy_hash(
            ["**/*.pem", "**/.env"],
            ["pem", "assignment"],
            [{"line": 1, "path": "a", "sha256": "0" * 64}],
            {"maxBytes": 10},
        )
        self.assertEqual(first, reordered)
        self.assertNotEqual(first, changed)
        self.assertEqual(
            managed_policy_hash(),
            __import__("hashlib").sha256(b"no-managed-policy").hexdigest(),
        )

    def test_summary_contains_counts_but_not_findings_or_content(self):
        summary = consent_summary(
            repository_identity=self.repository,
            provider="codex",
            operation_classes=["plan"],
            deny_policy_sha256=self.deny,
            managed_policy_sha256=self.managed,
            provider_executable_path=self.executable,
            provider_executable_sha256=self.executable_sha256,
            expires_at=self.now + timedelta(days=30),
            context_manifest={
                "fileCount": 2,
                "totalBytes": 99,
                "findings": ["must not leak"],
            },
        )
        encoded = json.dumps(summary)
        self.assertEqual(summary["contextFileCount"], 2)
        self.assertEqual(summary["contextTotalBytes"], 99)
        self.assertEqual(
            summary["providerExecutableSha256Prefix"],
            self.executable_sha256[:12],
        )
        self.assertNotIn("findings", encoded)
        self.assertNotIn("must not leak", encoded)

    def test_invalid_ttl_and_unknown_operation_rejected(self):
        with self.assertRaises(ConsentError):
            self.record(ttl_days=0)
        with self.assertRaises(ConsentError):
            self.record(operation_classes=["ship"])


if __name__ == "__main__":
    unittest.main()
