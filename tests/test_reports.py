from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "crossforge" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.errors import InvalidInputError, PreconditionError  # noqa: E402
from crossforge_lib.reports import (  # noqa: E402
    candidate_evidence_eligible,
    load_provider_report,
    validate_provider_report,
)
from crossforge_lib.util import sha256_file  # noqa: E402


@dataclass
class _Gate:
    passed: bool
    provenance: str = "independent"


class ProviderReportTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, dict[str, object]]:
        task = root / "T1"
        provider = task / "codex"
        provider.mkdir(parents=True)
        (provider / "spec.md").write_text("task brief\n", encoding="utf-8")
        (provider / "context-manifest.json").write_text('{"files":[]}\n', encoding="utf-8")
        runtime = {
            "schemaVersion": 1,
            "providerExecutableIdentity": {"path": "/usr/bin/codex", "sha256": "a" * 64},
            "providerArgvSha256": "b" * 64,
        }
        (provider / "runtime-manifest.json").write_text(
            json.dumps(runtime) + "\n",
            encoding="utf-8",
        )
        (provider / "sandbox-policy.json").write_text('{"network":"deny"}\n', encoding="utf-8")
        for name, value in (
            ("final.txt", "done\n"),
            ("candidate.patch", "diff --git a/a b/a\n"),
            ("stdout.raw", ""),
            ("stderr.raw", ""),
            ("tests.txt", "ok\n"),
        ):
            (provider / name).write_text(value, encoding="utf-8")
        report: dict[str, object] = {
            "schemaVersion": 1,
            "status": "complete",
            "provider": "codex",
            "requestedModel": "auto",
            "resolvedModel": "gpt-test",
            "cliVersion": "1.2.3",
            "baseCommit": "a" * 40,
            "objective": "Implement T1",
            "taskBriefSha256": sha256_file(provider / "spec.md"),
            "contextManifestSha256": sha256_file(provider / "context-manifest.json"),
            "runtimeManifestSha256": sha256_file(provider / "runtime-manifest.json"),
            "sandboxPolicySha256": sha256_file(provider / "sandbox-policy.json"),
            "startedAt": "2026-07-24T12:00:00Z",
            "completedAt": "2026-07-24T12:00:01Z",
            "durationMs": 1000,
            "exitCode": 0,
            "timedOut": False,
            "changedFiles": [
                {"path": "src/a.py", "status": "modified", "summary": "Updated behavior"}
            ],
            "scopeCheck": {"passed": True, "violations": []},
            "verification": [
                {
                    "argv": ["python3", "-m", "unittest"],
                    "exitCode": 0,
                    "durationMs": 100,
                    "outputPath": "tests.txt",
                }
            ],
            "gaps": [],
            "risks": [],
            "finalMessagePath": "final.txt",
            "patchPath": "candidate.patch",
            "patchSha256": sha256_file(provider / "candidate.patch"),
            "rawStdoutPath": "stdout.raw",
            "rawStderrPath": "stderr.raw",
        }
        report_path = provider / "report.json"
        report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")
        return report_path, report

    def test_complete_report_and_hash_bound_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path, _ = self._fixture(Path(temporary))
            report = load_provider_report(report_path)

            self.assertTrue(report.eligible_by_claim)
            self.assertEqual("codex", report.provider)
            self.assertNotIn("Updated behavior", report.user_summary())

    def test_unknown_key_and_path_escape_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path, raw = self._fixture(Path(temporary))
            raw["surprise"] = True
            with self.assertRaises(InvalidInputError):
                validate_provider_report(raw)
            raw.pop("surprise")
            raw["patchPath"] = "../candidate.patch"
            with self.assertRaises(InvalidInputError):
                validate_provider_report(raw)

    def test_missing_or_modified_evidence_blocks_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path, _ = self._fixture(Path(temporary))
            (report_path.parent / "candidate.patch").write_text("changed", encoding="utf-8")
            with self.assertRaises(PreconditionError):
                load_provider_report(report_path)

    def test_runtime_manifest_provider_identity_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path, raw = self._fixture(Path(temporary))
            runtime = report_path.parent / "runtime-manifest.json"
            runtime.write_text('{"schemaVersion":1}\n', encoding="utf-8")
            raw["runtimeManifestSha256"] = sha256_file(runtime)
            report_path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(InvalidInputError):
                load_provider_report(report_path)

    def test_provider_verification_claim_cannot_replace_independent_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path, _ = self._fixture(Path(temporary))
            report = load_provider_report(report_path)

            self.assertFalse(candidate_evidence_eligible(report, []))
            self.assertFalse(candidate_evidence_eligible(report, [_Gate(True, "provider_claim")]))
            self.assertFalse(candidate_evidence_eligible(report, [_Gate(False)]))
            self.assertTrue(candidate_evidence_eligible(report, [_Gate(True)]))


if __name__ == "__main__":
    unittest.main()
