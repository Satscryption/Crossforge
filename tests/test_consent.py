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
    CONSENT_REQUEST_PRODUCER,
    CONSENT_REQUEST_SCHEMA_VERSION,
    ConsentError,
    check_consent,
    consent_request_summary,
    consent_summary,
    deny_policy_hash,
    load_consent_request,
    load_consent,
    managed_policy_hash,
    record_consent,
    validate_consent_request,
)
from crossforge_lib.util import atomic_write_json, sha256_file  # noqa: E402


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
        self.context_manifest_sha256 = "f" * 64
        self.context_file_count = 2
        self.context_total_bytes = 99

    def record(self, **overrides):
        arguments = {
            "repository_identity": self.repository,
            "provider": "codex",
            "operation_classes": ["probe", "plan"],
            "deny_policy_sha256": self.deny,
            "managed_policy_sha256": self.managed,
            "provider_executable_path": self.executable,
            "provider_executable_sha256": self.executable_sha256,
            "context_manifest_sha256": self.context_manifest_sha256,
            "context_file_count": self.context_file_count,
            "context_total_bytes": self.context_total_bytes,
            "ttl_days": 30,
            "now": self.now,
        }
        arguments.update(overrides)
        if all(
            operation == "probe"
            for operation in arguments["operation_classes"]
        ):
            arguments["context_manifest_sha256"] = overrides.get(
                "context_manifest_sha256"
            )
            arguments["context_file_count"] = overrides.get(
                "context_file_count"
            )
            arguments["context_total_bytes"] = overrides.get(
                "context_total_bytes"
            )
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
            "context_manifest_sha256": self.context_manifest_sha256,
            "context_file_count": self.context_file_count,
            "context_total_bytes": self.context_total_bytes,
            "now": self.now + timedelta(days=1),
        }
        arguments.update(overrides)
        return check_consent(record, **arguments)

    def consent_request(self, **overrides):
        request = {
            "schemaVersion": CONSENT_REQUEST_SCHEMA_VERSION,
            "producer": CONSENT_REQUEST_PRODUCER,
            "requestId": "1" * 64,
            "repositoryRoot": str(Path(self.temporary.name) / "repository"),
            "gitCommonDir": str(Path(self.temporary.name) / "repository" / ".git"),
            "repositoryIdentity": self.repository,
            "provider": "codex",
            "operationClasses": ["probe"],
            "denyPolicySha256": self.deny,
            "managedPolicySha256": self.managed,
            "providerExecutablePath": self.executable,
            "providerExecutableSha256": self.executable_sha256,
            "preparedAt": "2026-07-24T12:00:00Z",
            "requestedExpiresAt": "2026-08-23T12:00:00Z",
            "requestValidUntil": "2026-07-24T12:15:00Z",
            "ttlDays": 30,
            "userConfigPath": str(
                Path(self.temporary.name) / "user-config.json"
            ),
            "userConfigSha256": None,
            "projectConfigPath": str(
                Path(self.temporary.name) / "project-config.json"
            ),
            "projectConfigSha256": None,
            "allowFile": None,
            "contextManifestPath": None,
            "contextManifestSha256": None,
            "contextFileCount": None,
            "contextTotalBytes": None,
        }
        request.update(overrides)
        return request

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
        self.assertEqual(
            record["providers"]["codex"]["contextManifestSha256"],
            self.context_manifest_sha256,
        )
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

    def test_source_context_change_requires_new_consent(self):
        record = self.record()
        changed_manifest = self.check(
            record,
            context_manifest_sha256="0" * 64,
        )
        self.assertEqual(
            changed_manifest.reason,
            "context_manifest_changed",
        )
        changed_counts = self.check(record, context_total_bytes=100)
        self.assertEqual(changed_counts.reason, "context_counts_changed")

    def test_probe_ignores_source_context_binding(self):
        record = self.record(
            operation_classes=["probe"],
        )
        result = self.check(
            record,
            operation_class="probe",
            context_manifest_sha256=None,
            context_file_count=None,
            context_total_bytes=None,
        )
        self.assertTrue(result)

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

    def test_consent_request_is_byte_bound_and_has_exact_disclosure(self):
        manifest = Path(self.temporary.name) / "manifest.json"
        atomic_write_json(manifest, {"files": [], "fileCount": 2, "totalBytes": 99})
        request = self.consent_request(
            operationClasses=["implement", "probe"],
            contextManifestPath=str(manifest),
            contextManifestSha256=sha256_file(manifest),
            contextFileCount=2,
            contextTotalBytes=99,
        )
        request_path = Path(self.temporary.name) / "request.json"
        atomic_write_json(request_path, request)
        request_hash = sha256_file(request_path)

        loaded = load_consent_request(
            request_path,
            expected_sha256=request_hash,
        )
        summary = consent_request_summary(loaded)

        self.assertEqual(summary["operationClasses"], ["implement", "probe"])
        self.assertEqual(summary["contextFileCount"], 2)
        self.assertEqual(summary["contextTotalBytes"], 99)
        self.assertEqual(summary["requestIdPrefix"], "1" * 12)
        request_path.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ConsentError, "changed after disclosure"
        ):
            load_consent_request(
                request_path,
                expected_sha256=request_hash,
            )

    def test_request_rejects_context_omission_and_overlong_window(self):
        with self.assertRaisesRegex(ConsentError, "context metadata"):
            validate_consent_request(
                self.consent_request(contextFileCount=0)
            )
        with self.assertRaisesRegex(ConsentError, "contextManifestPath"):
            validate_consent_request(
                self.consent_request(operationClasses=["implement"])
            )
        with self.assertRaisesRegex(ConsentError, "validity window"):
            validate_consent_request(
                self.consent_request(
                    requestValidUntil="2026-07-24T12:15:01Z"
                )
            )

    def test_record_consent_can_preserve_the_disclosed_expiry(self):
        disclosed_expiry = self.now + timedelta(days=30)
        record = self.record(
            now=self.now + timedelta(minutes=1),
            expires_at=disclosed_expiry,
        )
        self.assertEqual(
            record["providers"]["codex"]["expiresAt"],
            "2026-08-23T12:00:00Z",
        )
        with self.assertRaisesRegex(ConsentError, "outside the approved TTL"):
            self.record(
                now=self.now + timedelta(minutes=1),
                expires_at=self.now + timedelta(days=31),
            )

    def test_record_consent_accepts_disclosed_expiry_with_clock_skew(self):
        prepared_at = self.now + timedelta(seconds=5)
        record = self.record(
            prepared_at=prepared_at,
            expires_at=prepared_at + timedelta(days=30),
        )
        self.assertEqual(
            record["providers"]["codex"]["expiresAt"],
            "2026-08-23T12:00:05Z",
        )
        with self.assertRaisesRegex(ConsentError, "clock skew"):
            self.record(
                prepared_at=self.now + timedelta(seconds=6),
                expires_at=self.now + timedelta(days=30),
            )

    def test_invalid_ttl_and_unknown_operation_rejected(self):
        with self.assertRaises(ConsentError):
            self.record(ttl_days=0)
        with self.assertRaises(ConsentError):
            self.record(operation_classes=["ship"])


if __name__ == "__main__":
    unittest.main()
