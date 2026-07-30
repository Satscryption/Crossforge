from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "crossforge" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


from crossforge_lib.errors import PreconditionError, StateInconsistencyError
from crossforge_lib.models import RunStatus, TaskStatus
from crossforge_lib.state import StateStore, generate_run_id, plan_sha256
from crossforge_lib.util import atomic_write_json


COMMIT_A = "a" * 40
COMMIT_B = "b" * 40
GLOBAL_GATES = [
    {"argv": ["python3", "-m", "unittest"], "timeoutSeconds": 900}
]
PLAN_TASK_FIELDS = (
    "id",
    "title",
    "risk",
    "taskClass",
    "suggestedStrategy",
    "dependsOn",
    "allowedFiles",
    "objective",
    "interfaces",
    "constraints",
    "approvedBinaryContext",
    "approvedSymlinks",
    "verificationCommands",
    "doneWhen",
)


def make_task(*, status: str = "pending") -> dict:
    return {
        "id": "T1",
        "title": "State task",
        "status": status,
        "baseCommit": COMMIT_A,
        "risk": "low",
        "taskClass": "state",
        "suggestedStrategy": "auto",
        "dependsOn": [],
        "allowedFiles": ["src/state.py"],
        "objective": "Persist state.",
        "interfaces": [],
        "constraints": [],
        "approvedBinaryContext": [],
        "approvedSymlinks": [],
        "verificationCommands": [
            {"argv": ["python3", "-m", "unittest"], "timeoutSeconds": 900}
        ],
        "doneWhen": ["State is durable."],
        "routing": None,
        "selectedCandidate": None,
        "commit": None,
        "attempts": {"codex": 0, "grok": 0, "claude": 0},
        "createdAt": "2026-07-24T12:00:00Z",
        "updatedAt": "2026-07-24T12:00:00Z",
    }


class StateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = (Path(self.temporary.name) / "repository").resolve()
        self.common = self.repository / ".git"
        self.common.mkdir(parents=True)
        self.store = StateStore(self.common)
        self.common = self.store.git_common_dir
        self.plan = {
            "schemaVersion": 1,
            "title": "Test plan",
            "tasks": [],
            "globalVerificationCommands": GLOBAL_GATES,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_run(
        self,
        run_id: str,
        *,
        status: str = "active",
        current_commit: str = COMMIT_A,
    ) -> dict:
        run_directory = self.common / "crossforge" / "runs" / run_id
        digest = plan_sha256(self.plan)
        return {
            "schemaVersion": 1,
            "runId": run_id,
            "status": status,
            "mode": "build",
            "repositoryRoot": str(self.repository),
            "repositoryIdentity": "1" * 64,
            "gitCommonDir": str(self.common),
            "orchestrationGitDir": str(self.common),
            "branch": f"crossforge/{run_id.lower()}",
            "branchCreatedByCrossforge": True,
            "targetRemote": "origin",
            "targetBranch": "main",
            "defaultBranch": "main",
            "startCommit": COMMIT_A,
            "currentCommit": current_commit,
            "planJsonPath": str(run_directory / "plan.json"),
            "planMarkdownPath": str(run_directory / "plan.md"),
            "planSha256": digest,
            "planApproval": {
                "approved": True,
                "approvedBy": "user",
                "approvedAt": "2026-07-24T12:00:00Z",
                "approvedPlanSha256": digest,
            },
            "globalVerificationCommands": GLOBAL_GATES,
            "budget": "balanced",
            "maximumProviderInvocationsPerTask": 6,
            "strategy": "auto",
            "noCommit": False,
            "keepWorktrees": False,
            "gateSandbox": {
                "backend": "bwrap",
                "network": "deny",
                "probeVersion": "1",
            },
            "providers": {},
            "activeTaskId": None,
            "completedTaskIds": [],
            "blockedReason": None,
            "createdAt": "2026-07-24T12:00:00Z",
            "updatedAt": "2026-07-24T12:00:00Z",
            "completedAt": None,
        }

    def create_run(self, *, tasks: list[dict] | None = None) -> tuple[str, dict]:
        materialized = tasks or []
        self.plan = {
            "schemaVersion": 1,
            "title": "Test plan",
            "tasks": [
                {field: task[field] for field in PLAN_TASK_FIELDS}
                for task in materialized
            ],
            "globalVerificationCommands": GLOBAL_GATES,
        }
        run_id = generate_run_id()
        run = self.make_run(run_id)
        self.store.initialize_run(
            run,
            plan=self.plan,
            plan_markdown="# Plan\n",
            tasks={"schemaVersion": 1, "tasks": materialized},
        )
        return run_id, run

    def test_initialize_uses_common_git_directory_and_private_modes(self) -> None:
        run_id, _ = self.create_run()
        self.assertEqual(run_id, self.store.active_run_id())
        self.assertEqual(
            self.common / "crossforge" / "runs" / run_id,
            self.store.run_dir(run_id),
        )
        self.assertEqual(0o700, self.store.root.stat().st_mode & 0o777)
        self.assertEqual(
            0o600,
            (self.store.run_dir(run_id) / "run.json").stat().st_mode & 0o777,
        )

    def test_second_active_build_is_refused(self) -> None:
        first, _ = self.create_run()
        second = generate_run_id()
        with self.assertRaises(PreconditionError) as caught:
            self.store.initialize_run(
                self.make_run(second),
                plan=self.plan,
                plan_markdown="# Plan\n",
                tasks={"schemaVersion": 1, "tasks": []},
            )
        self.assertEqual(first, caught.exception.details["runId"])
        self.assertFalse(self.store.run_dir(second).exists())

    def test_completion_moves_repository_pointers_and_is_idempotent(self) -> None:
        run_id, _ = self.create_run()
        completed = self.store.complete_run(run_id)
        self.assertEqual("complete", completed["status"])
        self.assertIsNone(self.store.active_run_id())
        self.assertEqual(run_id, self.store.latest_complete_run_id())
        repeated = self.store.complete_run(run_id)
        self.assertEqual(completed, repeated)

    def test_abandonment_clears_active_and_invalid_transition_fails(self) -> None:
        run_id, _ = self.create_run()
        self.store.abandon_run(run_id, reason="user cancelled")
        self.assertIsNone(self.store.active_run_id())
        with self.assertRaises(StateInconsistencyError):
            self.store.complete_run(run_id)

    def test_task_transition_machine_and_recovery_decision(self) -> None:
        run_id, _ = self.create_run(tasks=[make_task()])
        self.store.transition_task(run_id, "T1", TaskStatus.BLOCKED)
        with self.assertRaises(PreconditionError):
            self.store.transition_task(run_id, "T1", TaskStatus.IN_PROGRESS)
        decisions = self.store.run_dir(run_id) / "decisions.md"
        decisions.write_text("User approved retry after fixing the blocker.\n")
        decisions.chmod(0o600)
        task = self.store.transition_task(run_id, "T1", TaskStatus.IN_PROGRESS)
        self.assertEqual("in_progress", task["status"])
        with self.assertRaises(StateInconsistencyError):
            self.store.transition_task(run_id, "T1", TaskStatus.COMPLETE)

    def test_selection_and_acceptance_bindings_are_compare_and_swap(self) -> None:
        run_id, _ = self.create_run(tasks=[make_task()])
        self.store.start_task(run_id, "T1")
        run = self.store.load_run(run_id)
        task = self.store.load_tasks(run_id)["tasks"][0]
        self.store.record_task_routing(
            run_id,
            "T1",
            {
                "implementationLanes": ["codex"],
                "reviewLanes": [],
                "providerSettings": {
                    "codex": {
                        "model": "auto",
                        "effort": "high",
                        "timeoutSeconds": 60,
                    }
                },
            },
        )
        self.store.reserve_provider_invocations(
            run_id, "T1", ("codex",)
        )
        validated = []
        updates = {
            "selectedCandidate": "codex",
            "selectedCandidatePath": str(self.repository / "candidate"),
            "selectedGateEvidencePath": str(
                self.store.run_dir(run_id) / "selection.json"
            ),
            "selectedGateEvidenceSha256": "2" * 64,
            "selectedInvocationEvidencePath": str(
                self.store.run_dir(run_id) / "invocation.json"
            ),
            "selectedInvocationEvidenceSha256": "3" * 64,
        }
        selected = self.store.bind_candidate_selection(
            run_id,
            "T1",
            expected_run=run,
            expected_task=task,
            updates=updates,
            validate_evidence=lambda: validated.append("selection"),
        )
        self.assertEqual("candidate_ready", selected["status"])
        self.assertEqual(1, selected["attempts"]["codex"])
        self.assertIsNotNone(selected["routing"])
        self.assertEqual(["selection"], validated)
        with self.assertRaisesRegex(
            StateInconsistencyError,
            "acceptanceIntent is required",
        ):
            self.store.transition_task(
                run_id,
                "T1",
                TaskStatus.ACCEPTED,
            )

        intent = {
            "schemaVersion": 1,
            "provider": "codex",
            "candidatePath": updates["selectedCandidatePath"],
            "baseCommit": COMMIT_A,
            "capturedPatchSha256": "4" * 64,
            "verifiedScopedTreeSha256": "5" * 64,
            "quarantinePathsSha256": "6" * 64,
            "selectedGateEvidenceSha256": "2" * 64,
            "commitMessageSha256": "7" * 64,
            "noCommit": False,
        }
        selected_with_intent = (
            self.store.record_candidate_acceptance_intent_in_transaction(
                run_id,
                "T1",
                expected_run=run,
                expected_task=selected,
                intent=intent,
                validate_evidence=lambda: validated.append("intent"),
            )
        )
        accepted = self.store.bind_candidate_acceptance(
            run_id,
            "T1",
            expected_run=run,
            expected_task=selected_with_intent,
            selected_provider="codex",
            commit=COMMIT_B,
            expected_intent=intent,
            validate_evidence=lambda: validated.append("acceptance"),
        )
        self.assertEqual("committed", accepted["status"])
        self.assertEqual(COMMIT_B, accepted["commit"])
        self.assertEqual(
            ["selection", "intent", "acceptance"], validated
        )

        with self.assertRaisesRegex(
            StateInconsistencyError, "selected task changed"
        ):
            self.store.bind_candidate_acceptance(
                run_id,
                "T1",
                expected_run=run,
                expected_task=selected,
                selected_provider="codex",
                commit=COMMIT_B,
                expected_intent=intent,
                validate_evidence=lambda: validated.append("stale"),
            )
        self.assertNotIn("stale", validated)

    def test_generic_transition_cannot_forge_candidate_ready(self) -> None:
        run_id, _ = self.create_run(tasks=[make_task()])
        self.store.start_task(run_id, "T1")
        with self.assertRaisesRegex(
            StateInconsistencyError,
            "bind_candidate_selection",
        ):
            self.store.transition_task(
                run_id,
                "T1",
                TaskStatus.CANDIDATE_READY,
                updates={
                    "selectedCandidate": "codex",
                    "selectedCandidatePath": str(
                        self.repository / "candidate"
                    ),
                },
            )
        self.assertEqual(
            "in_progress",
            self.store.load_tasks(run_id)["tasks"][0]["status"],
        )

    def test_candidate_ready_record_requires_bound_gate_evidence(self) -> None:
        forged = make_task(status="candidate_ready")
        forged["selectedCandidate"] = "codex"
        forged["selectedCandidatePath"] = str(
            self.repository / "candidate"
        )
        with self.assertRaisesRegex(
            StateInconsistencyError,
            "selectedGateEvidencePath is required",
        ):
            self.create_run(tasks=[forged])
        self.assertIsNone(self.store.active_run_id())

    def test_resume_succeeds_for_consistent_state(self) -> None:
        task = make_task(status="in_progress")
        run_id, _ = self.create_run(tasks=[task])
        run = self.store.load_run(run_id)
        run["activeTaskId"] = "T1"
        atomic_write_json(self.store.run_dir(run_id) / "run.json", run)
        result = self.store.validate_resume(
            repository_identity="1" * 64,
            branch=f"crossforge/{run_id.lower()}",
            head=COMMIT_A,
            orchestration_git_dir=self.common,
        )
        self.assertEqual(run_id, result["run"]["runId"])

    def test_resume_rejects_stale_head_and_changed_plan(self) -> None:
        run_id, _ = self.create_run()
        with self.assertRaisesRegex(StateInconsistencyError, "HEAD differs"):
            self.store.validate_resume(
                repository_identity="1" * 64,
                branch=f"crossforge/{run_id.lower()}",
                head=COMMIT_B,
            )
        plan_path = self.store.run_dir(run_id) / "plan.json"
        plan_path.write_text(json.dumps({"changed": True}), encoding="utf-8")
        plan_path.chmod(0o600)
        with self.assertRaisesRegex(StateInconsistencyError, "plan hash changed"):
            self.store.validate_resume(
                repository_identity="1" * 64,
                branch=f"crossforge/{run_id.lower()}",
                head=COMMIT_A,
            )

    def test_malformed_pointer_and_partial_json_are_detected(self) -> None:
        run_id, _ = self.create_run()
        active = self.store.root / "active"
        active.write_text(run_id, encoding="ascii")
        active.chmod(0o600)
        with self.assertRaisesRegex(StateInconsistencyError, "pointer format"):
            self.store.active_run_id()
        active.write_text(run_id + "\n", encoding="ascii")
        run_json = self.store.run_dir(run_id) / "run.json"
        run_json.write_text('{"schemaVersion":', encoding="utf-8")
        run_json.chmod(0o600)
        with self.assertRaisesRegex(StateInconsistencyError, "invalid durable JSON"):
            self.store.load_run(run_id)

    def test_state_path_with_public_permissions_is_rejected(self) -> None:
        self.store.initialize()
        self.store.root.chmod(0o755)
        with self.assertRaisesRegex(StateInconsistencyError, "group or others"):
            self.store.initialize()

    def test_initialize_rejects_unapproved_task_policy_without_partial_state(self) -> None:
        task = make_task()
        self.plan = {
            "schemaVersion": 1,
            "title": "Test plan",
            "tasks": [{field: task[field] for field in PLAN_TASK_FIELDS}],
            "globalVerificationCommands": GLOBAL_GATES,
        }
        run_id = generate_run_id()
        run = self.make_run(run_id)
        task["allowedFiles"] = ["src/**"]
        with self.assertRaisesRegex(
            StateInconsistencyError, "materialized task policy differs"
        ):
            self.store.initialize_run(
                run,
                plan=self.plan,
                plan_markdown="# Plan\n",
                tasks={"schemaVersion": 1, "tasks": [task]},
            )
        self.assertFalse(self.store.run_dir(run_id).exists())
        self.assertIsNone(self.store.active_run_id())

    def test_start_and_finish_task_update_task_and_run_together(self) -> None:
        run_id, _ = self.create_run(tasks=[make_task()])
        task, run = self.store.start_task(run_id, "T1", base_commit=COMMIT_A)
        self.assertEqual("in_progress", task["status"])
        self.assertEqual("T1", run["activeTaskId"])

        selection = {
            "selectedCandidate": "claude-microfix",
            "selectedCandidatePath": str(self.repository / "candidate"),
            "selectedGateEvidencePath": str(
                self.store.run_dir(run_id) / "selection.json"
            ),
            "selectedGateEvidenceSha256": "2" * 64,
            "selectedInvocationEvidencePath": None,
            "selectedInvocationEvidenceSha256": None,
        }
        selected = self.store.bind_candidate_selection(
            run_id,
            "T1",
            expected_run=run,
            expected_task=task,
            updates=selection,
            validate_evidence=lambda: None,
        )
        intent = {
            "schemaVersion": 1,
            "provider": "claude-microfix",
            "candidatePath": selection["selectedCandidatePath"],
            "baseCommit": COMMIT_A,
            "capturedPatchSha256": "3" * 64,
            "verifiedScopedTreeSha256": "4" * 64,
            "quarantinePathsSha256": "5" * 64,
            "selectedGateEvidenceSha256": "2" * 64,
            "commitMessageSha256": "6" * 64,
            "noCommit": False,
        }
        selected = self.store.record_candidate_acceptance_intent_in_transaction(
            run_id,
            "T1",
            expected_run=run,
            expected_task=selected,
            intent=intent,
            validate_evidence=lambda: None,
        )
        self.store.bind_candidate_acceptance(
            run_id,
            "T1",
            expected_run=run,
            expected_task=selected,
            selected_provider="claude-microfix",
            commit=COMMIT_B,
            expected_intent=intent,
            validate_evidence=lambda: None,
        )
        task, run = self.store.finish_task(
            run_id,
            "T1",
            interface_ledger_append="- T1: state interface\n",
        )
        self.assertEqual("complete", task["status"])
        self.assertIsNone(run["activeTaskId"])
        self.assertEqual(["T1"], run["completedTaskIds"])
        self.assertEqual(COMMIT_B, run["currentCommit"])
        self.assertIn(
            "state interface",
            (self.store.run_dir(run_id) / "interfaces.md").read_text(),
        )

    def test_race_invocation_budget_reservation_is_all_or_none(self) -> None:
        run_id, _ = self.create_run(tasks=[make_task()])
        self.store.start_task(run_id, "T1", base_commit=COMMIT_A)
        run_path = self.store.run_dir(run_id) / "run.json"
        run = self.store.load_run(run_id)
        run["maximumProviderInvocationsPerTask"] = 1
        atomic_write_json(run_path, run)

        with self.assertRaises(PreconditionError):
            self.store.reserve_provider_invocations(
                run_id, "T1", ("codex", "grok")
            )
        attempts = self.store.load_tasks(run_id)["tasks"][0]["attempts"]
        self.assertEqual({"codex": 0, "grok": 0, "claude": 0}, attempts)

        run["maximumProviderInvocationsPerTask"] = 2
        atomic_write_json(run_path, run)
        reservations = self.store.reserve_provider_invocations(
            run_id, "T1", ("codex", "grok")
        )
        self.assertEqual(["codex", "grok"], [item["provider"] for item in reservations])
        attempts = self.store.load_tasks(run_id)["tasks"][0]["attempts"]
        self.assertEqual({"codex": 1, "grok": 1, "claude": 0}, attempts)

        run["maximumProviderInvocationsPerTask"] = 10
        atomic_write_json(run_path, run)
        self.store.reserve_provider_invocations(run_id, "T1", ("codex",))
        self.store.reserve_provider_invocations(run_id, "T1", ("codex",))
        with self.assertRaises(PreconditionError):
            self.store.reserve_provider_invocations(run_id, "T1", ("codex",))
        self.assertEqual(
            3,
            self.store.load_tasks(run_id)["tasks"][0]["attempts"]["codex"],
        )


if __name__ == "__main__":
    unittest.main()
