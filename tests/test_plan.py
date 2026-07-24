from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "skills/crossforge/scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.errors import PlanValidationError  # noqa: E402
from crossforge_lib.plan import (  # noqa: E402
    materialize_tasks,
    plan_sha256,
    render_plan_markdown,
    validate_plan,
    validate_plan_approval,
)


def valid_plan() -> dict:
    return {
        "schemaVersion": 1,
        "title": "Example",
        "objective": "Implement the requested behavior.",
        "userVisibleOutcome": "Users can use the new behavior.",
        "context": [],
        "assumptions": [],
        "nonGoals": [],
        "architectureDecisions": [],
        "securityPrivacyConstraints": [],
        "branch": {
            "requested": None,
            "targetRemote": "origin",
            "targetBranch": "main",
            "shippingIntent": "local-only",
        },
        "globalVerificationCommands": [
            {
                "argv": [
                    "python3",
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "tests",
                    "-v",
                ],
                "timeoutSeconds": 900,
            }
        ],
        "tasks": [
            {
                "id": "T1",
                "title": "Example task",
                "risk": "low",
                "taskClass": "repetitive-wiring",
                "dependsOn": [],
                "suggestedStrategy": "auto",
                "allowedFiles": ["src/example.py", "tests/test_example.py"],
                "objective": "Implement the example.",
                "interfaces": [],
                "constraints": [],
                "approvedBinaryContext": [],
                "approvedSymlinks": [],
                "verificationCommands": [
                    {
                        "argv": [
                            "python3",
                            "-m",
                            "unittest",
                            "tests.test_example",
                            "-v",
                        ],
                        "timeoutSeconds": 900,
                    }
                ],
                "doneWhen": ["The behavior and regression test pass."],
            }
        ],
        "decisionLog": [],
        "deferredWork": [],
    }


class PlanTests(unittest.TestCase):
    def test_validate_and_reject_unknown_keys(self) -> None:
        plan = validate_plan(valid_plan())
        self.assertEqual(plan.tasks[0].id, "T1")
        value = valid_plan()
        value["tasks"][0]["extra"] = True
        with self.assertRaises(PlanValidationError):
            validate_plan(value)

    def test_render_is_deterministic_and_contains_contract_headings(self) -> None:
        plan = validate_plan(valid_plan())
        first = render_plan_markdown(plan)
        second = render_plan_markdown(plan)
        self.assertEqual(first, second)
        for heading in (
            "# Plan: Example",
            "## Objective",
            "## User-visible outcome",
            "## Global verification gate",
            "## Tasks",
            "### T1 — Example task",
            "## Decision log",
            "## Deferred work",
        ):
            self.assertIn(heading, first)

    def test_materialization_is_deterministic_and_adds_only_runtime_fields(self) -> None:
        plan = validate_plan(valid_plan())
        arguments = {
            "base_commit": "a" * 40,
            "timestamp": "2026-07-24T12:00:00Z",
        }
        first = materialize_tasks(plan, **arguments)
        second = materialize_tasks(plan, **arguments)
        self.assertEqual(first, second)
        task = first["tasks"][0]
        self.assertEqual(task["status"], "pending")
        self.assertEqual(task["baseCommit"], "a" * 40)
        self.assertEqual(task["attempts"], {"codex": 0, "grok": 0, "claude": 0})
        self.assertEqual(task["doneWhen"], valid_plan()["tasks"][0]["doneWhen"])

    def test_approval_is_bound_to_exact_canonical_hash(self) -> None:
        plan = validate_plan(valid_plan())
        approval = {
            "approved": True,
            "approvedBy": "user",
            "approvedAt": "2026-07-24T12:00:00Z",
            "approvedPlanSha256": plan_sha256(plan),
        }
        self.assertEqual(
            validate_plan_approval(plan, approval).approved_plan_sha256,
            plan_sha256(plan),
        )
        changed = valid_plan()
        changed["objective"] = "A changed objective."
        with self.assertRaises(PlanValidationError):
            validate_plan_approval(validate_plan(changed), approval)

    def test_missing_done_when_and_global_gate_fail(self) -> None:
        no_done = valid_plan()
        no_done["tasks"][0]["doneWhen"] = []
        no_global = valid_plan()
        no_global["globalVerificationCommands"] = []
        for value in (no_done, no_global):
            with self.assertRaises(PlanValidationError):
                validate_plan(value)

    def test_dependency_cycle_and_unknown_dependency_fail(self) -> None:
        cycle = valid_plan()
        second = copy.deepcopy(cycle["tasks"][0])
        second["id"] = "T2"
        second["title"] = "Second"
        second["allowedFiles"] = ["src/second.py"]
        cycle["tasks"][0]["dependsOn"] = ["T2"]
        second["dependsOn"] = ["T1"]
        cycle["tasks"].append(second)
        with self.assertRaisesRegex(PlanValidationError, "cycle"):
            validate_plan(cycle)
        unknown = valid_plan()
        unknown["tasks"][0]["dependsOn"] = ["T2"]
        with self.assertRaisesRegex(PlanValidationError, "unknown dependency"):
            validate_plan(unknown)

    def test_multi_task_no_commit_fails(self) -> None:
        value = valid_plan()
        second = copy.deepcopy(value["tasks"][0])
        second["id"] = "T2"
        second["title"] = "Second"
        second["allowedFiles"] = ["src/second.py"]
        value["tasks"].append(second)
        with self.assertRaisesRegex(PlanValidationError, "exactly one task"):
            validate_plan(value, no_commit=True)

    def test_gate_command_policy_rejects_unsafe_commands(self) -> None:
        unsafe_commands = (
            [],
            ["sh", "-c", "pytest"],
            ["python3", "-c", "print('test')"],
            ["git", "push", "origin", "main"],
            ["rm", "-rf", "build"],
            ["python3", "-m", "unittest", "|", "tee", "out"],
        )
        for argv in unsafe_commands:
            value = valid_plan()
            value["tasks"][0]["verificationCommands"][0]["argv"] = argv
            with self.subTest(argv=argv):
                with self.assertRaises(PlanValidationError):
                    validate_plan(value)

    def test_binary_and_symlink_approvals_are_exact(self) -> None:
        value = valid_plan()
        value["tasks"][0]["approvedBinaryContext"] = [
            {"path": "fixtures/blob.bin", "sha256": "a" * 64}
        ]
        value["tasks"][0]["approvedSymlinks"] = [
            {"path": "src/link", "target": "../fixtures/target.txt"}
        ]
        self.assertEqual(
            validate_plan(value).tasks[0].approved_binary_context[0].sha256,
            "a" * 64,
        )
        value["tasks"][0]["approvedSymlinks"][0]["target"] = "../../outside"
        with self.assertRaises(PlanValidationError):
            validate_plan(value)


if __name__ == "__main__":
    unittest.main()
