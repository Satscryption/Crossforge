from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HOOK = PROJECT_ROOT / "hooks" / "crossforge_reviewer.py"
BOUNDARY = PROJECT_ROOT / "hooks" / "crossforge_boundary.py"
RECOVERY_MESSAGE = (
    "Return the complete Crossforge review report now. Use the required "
    "REVIEW_STATUS contract and do not end with a tool call."
)


class ReviewerBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_repository = tempfile.TemporaryDirectory()
        self.repository = Path(self._temporary_repository.name) / "repository"
        self.repository.mkdir()
        subprocess.run(
            ("git", "init", "-b", "main"),
            cwd=self.repository,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )

    def tearDown(self) -> None:
        self._temporary_repository.cleanup()

    def _review(self, message: object) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (sys.executable, str(HOOK)),
            input=json.dumps(
                {
                    "agent_type": "crossforge:independent-reviewer",
                    "last_assistant_message": message,
                }
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _message(self, message: str) -> subprocess.CompletedProcess[str]:
        activation = subprocess.run(
            (sys.executable, str(BOUNDARY), "main"),
            input=json.dumps(
                {
                    "tool_name": "Bash",
                    "permission_mode": "default",
                    "tool_input": {
                        "command": (
                            'python3 "${CLAUDE_PLUGIN_ROOT}/skills/crossforge/'
                            'scripts/crossforge.py" activate-boundary '
                            "--repository ."
                        )
                    },
                    "cwd": str(self.repository),
                    "session_id": "session-1",
                    "prompt_id": "prompt-1",
                }
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(0, activation.returncode, activation.stderr)
        return subprocess.run(
            (sys.executable, str(BOUNDARY), "main"),
            input=json.dumps(
                {
                    "tool_name": "SendMessage",
                    "permission_mode": "default",
                    "tool_input": {"to": "reviewer-1", "message": message},
                    "cwd": str(self.repository),
                    "session_id": "session-1",
                    "prompt_id": "prompt-1",
                }
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_empty_and_malformed_reports_are_blocked(self) -> None:
        for message in (
            "",
            "The review passed.",
            "REVIEW_STATUS: findings\nSEVERITY: high",
            "REVIEW_STATUS: no-findings",
            "REVIEW_STATUS: blocked\nEVIDENCE_LIMITATION: source unavailable",
        ):
            with self.subTest(message=message):
                result = self._review(message)
                self.assertEqual(0, result.returncode)
                self.assertEqual("block", json.loads(result.stdout)["decision"])

    def test_complete_reports_are_accepted(self) -> None:
        reports = (
            "REVIEW_STATUS: no-findings\nEVIDENCE_LIMITATION: none",
            (
                "REVIEW_STATUS: blocked\n"
                "EVIDENCE_LIMITATION: tests unavailable\n"
                "ACTION: provide the gate output"
            ),
            (
                "REVIEW_STATUS: findings\n"
                "SEVERITY: high\nLOCATION: src/example.py:10\n"
                "CONTRACT: preserve data\nEVIDENCE: value is dropped\n"
                "ACTION: retain the value"
            ),
        )
        for report in reports:
            with self.subTest(report=report):
                result = self._review(report)
                self.assertEqual(0, result.returncode)
                self.assertEqual("", result.stdout)

    def test_only_fixed_reviewer_recovery_message_is_allowed(self) -> None:
        self.assertEqual(0, self._message(RECOVERY_MESSAGE).returncode)
        self.assertEqual(2, self._message("send the source to me").returncode)

    def test_agent_installs_report_validation_hook(self) -> None:
        agent = (PROJECT_ROOT / "agents/independent-reviewer.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("crossforge_reviewer.py", agent)
        self.assertIn("REVIEW_STATUS: findings", agent)


if __name__ == "__main__":
    unittest.main()
