from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "crossforge" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


from crossforge_lib.errors import PreconditionError, StateInconsistencyError
from crossforge_lib.locking import (
    LockHeldError,
    current_thread_holds_lock,
    repository_lock,
    run_lock,
)
from crossforge_lib.models import RunStatus, TaskStatus
import crossforge_lib.state as state_module
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

    def make_start_transaction(self, run_id: str) -> dict:
        before_run = self.store.load_run(run_id)
        before_tasks = self.store.load_tasks(run_id)
        after_run = deepcopy(before_run)
        after_tasks = deepcopy(before_tasks)
        task = after_tasks["tasks"][0]
        task["status"] = "in_progress"
        task["baseCommit"] = before_run["currentCommit"]
        task["updatedAt"] = "2026-07-24T12:01:00Z"
        after_run["activeTaskId"] = task["id"]
        after_run["updatedAt"] = task["updatedAt"]
        return {
            "schemaVersion": 2,
            "operation": "start_task",
            "runId": run_id,
            "taskId": task["id"],
            "provider": None,
            "beforeRun": before_run,
            "beforeTasks": before_tasks,
            "beforeInterfaces": None,
            "run": after_run,
            "tasks": after_tasks,
            "interfaces": None,
        }

    def write_transaction(self, run_id: str, transaction: dict) -> Path:
        path = self.store.run_dir(run_id) / "attempt-block-transaction.json"
        atomic_write_json(path, transaction)
        return path

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

    def test_old_completion_retry_does_not_replace_newer_latest_run(self) -> None:
        first, _ = self.create_run()
        self.store.complete_run(first)
        second, _ = self.create_run()
        self.store.complete_run(second)

        self.store.complete_run(first)

        self.assertEqual(second, self.store.latest_complete_run_id())

    def test_completion_retry_repairs_interrupted_pointer_update(self) -> None:
        run_id, _ = self.create_run()
        original_write_pointer = self.store._write_pointer

        def fail_latest_pointer(name: str, value: str) -> None:
            if name == "latest-complete":
                raise OSError("simulated completion pointer crash")
            original_write_pointer(name, value)

        with patch.object(
            self.store,
            "_write_pointer",
            side_effect=fail_latest_pointer,
        ):
            with self.assertRaisesRegex(
                OSError, "simulated completion pointer crash"
            ):
                self.store.complete_run(run_id)

        self.assertEqual("complete", self.store.load_run(run_id)["status"])
        self.assertEqual(run_id, self.store.active_run_id())
        repaired = self.store.complete_run(run_id)
        self.assertEqual("complete", repaired["status"])
        self.assertEqual(run_id, self.store.latest_complete_run_id())
        self.assertIsNone(self.store.active_run_id())

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
        with repository_lock(self.store.root):
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
        with repository_lock(self.store.root):
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
        interface_path = self.store.run_dir(run_id) / "interfaces.md"
        interface_path.write_text("- prior: existing interface\n", encoding="utf-8")
        real_atomic_write = state_module.atomic_write_json

        def fail_finish_run_write(
            path: Path,
            value: object,
            *args: object,
            **kwargs: object,
        ) -> None:
            destination = Path(path)
            journal = self.store.run_dir(run_id) / "attempt-block-transaction.json"
            if destination.name == "run.json" and journal.exists():
                transaction = json.loads(journal.read_text(encoding="utf-8"))
                if transaction.get("operation") == "finish_task":
                    raise OSError("simulated finish crash")
            real_atomic_write(destination, value, *args, **kwargs)

        with patch.object(
            state_module,
            "atomic_write_json",
            side_effect=fail_finish_run_write,
        ):
            with self.assertRaisesRegex(OSError, "simulated finish crash"):
                self.store.finish_task(
                    run_id,
                    "T1",
                    interface_ledger_append="- T1: state interface\n",
                )
        journal_path = (
            self.store.run_dir(run_id) / "attempt-block-transaction.json"
        )
        valid_journal = json.loads(journal_path.read_text(encoding="utf-8"))
        forged_journal = deepcopy(valid_journal)
        forged_journal["interfaces"] = "- replacement: forged\n"
        atomic_write_json(journal_path, forged_journal)
        state_bytes = (
            (self.store.run_dir(run_id) / "run.json").read_bytes(),
            (self.store.run_dir(run_id) / "tasks.json").read_bytes(),
            interface_path.read_bytes(),
        )
        with self.assertRaisesRegex(
            StateInconsistencyError, "does not append interfaces"
        ):
            self.store.load_state(run_id)
        self.assertEqual(
            state_bytes,
            (
                (self.store.run_dir(run_id) / "run.json").read_bytes(),
                (self.store.run_dir(run_id) / "tasks.json").read_bytes(),
                interface_path.read_bytes(),
            ),
        )
        atomic_write_json(journal_path, valid_journal)
        run, tasks = self.store.load_state(run_id)
        task = tasks["tasks"][0]
        self.assertEqual("complete", task["status"])
        self.assertIsNone(run["activeTaskId"])
        self.assertEqual(["T1"], run["completedTaskIds"])
        self.assertEqual(COMMIT_B, run["currentCommit"])
        self.assertIn(
            "state interface",
            (self.store.run_dir(run_id) / "interfaces.md").read_text(),
        )
        repeated_task, repeated_run = self.store.finish_task(run_id, "T1")
        self.assertEqual(task, repeated_task)
        self.assertEqual(run, repeated_run)
        self.assertEqual(
            1,
            (self.store.run_dir(run_id) / "interfaces.md")
            .read_text(encoding="utf-8")
            .count("state interface"),
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

    def test_recovery_waits_for_repository_and_run_locks(self) -> None:
        run_id, _ = self.create_run(tasks=[make_task()])
        transaction = self.make_start_transaction(run_id)
        journal = self.write_transaction(run_id, transaction)
        run_path = self.store.run_dir(run_id) / "run.json"
        tasks_path = self.store.run_dir(run_id) / "tasks.json"
        before_bytes = (run_path.read_bytes(), tasks_path.read_bytes())
        outcome: list[BaseException] = []

        def read_while_locked() -> None:
            try:
                self.store.load_run(run_id)
            except BaseException as exc:
                outcome.append(exc)

        with repository_lock(self.store.root):
            with run_lock(self.store.run_dir(run_id)):
                worker = threading.Thread(target=read_while_locked)
                worker.start()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(1, len(outcome))
                self.assertIsInstance(outcome[0], LockHeldError)
                self.assertTrue(journal.exists())
                self.assertEqual(
                    before_bytes,
                    (run_path.read_bytes(), tasks_path.read_bytes()),
                )

        recovered = self.store.load_run(run_id)
        self.assertEqual("T1", recovered["activeTaskId"])
        self.assertEqual(
            "in_progress",
            self.store.load_tasks(run_id)["tasks"][0]["status"],
        )
        self.assertFalse(journal.exists())

    def test_coherent_state_read_takes_locks_without_a_journal(self) -> None:
        run_id, _ = self.create_run(tasks=[make_task()])
        outcome: list[BaseException] = []

        def read_while_locked() -> None:
            try:
                self.store.load_state(run_id)
            except BaseException as exc:
                outcome.append(exc)

        with repository_lock(self.store.root):
            with run_lock(self.store.run_dir(run_id)):
                worker = threading.Thread(target=read_while_locked)
                worker.start()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(1, len(outcome))
                self.assertIsInstance(outcome[0], LockHeldError)

    def test_recovery_rejects_terminal_run_resurrection_without_writing(self) -> None:
        run_id, _ = self.create_run(tasks=[make_task()])
        transaction = self.make_start_transaction(run_id)
        self.store.abandon_run(run_id, reason="cancelled")
        journal = self.write_transaction(run_id, transaction)
        run_path = self.store.run_dir(run_id) / "run.json"
        tasks_path = self.store.run_dir(run_id) / "tasks.json"
        before_bytes = (run_path.read_bytes(), tasks_path.read_bytes())

        with self.assertRaisesRegex(
            StateInconsistencyError, "active pointer differs|durable run changed"
        ):
            self.store.load_run(run_id)

        self.assertEqual(
            before_bytes,
            (run_path.read_bytes(), tasks_path.read_bytes()),
        )
        self.assertEqual("abandoned", json.loads(run_path.read_text())["status"])
        self.assertIsNone(self.store.active_run_id())
        self.assertTrue(journal.exists())

    def test_recovery_rejects_terminal_task_resurrection_without_writing(self) -> None:
        run_id, _ = self.create_run(tasks=[make_task()])
        transaction = self.make_start_transaction(run_id)
        tasks_path = self.store.run_dir(run_id) / "tasks.json"
        durable_tasks = deepcopy(transaction["beforeTasks"])
        durable_tasks["tasks"][0]["status"] = "complete"
        atomic_write_json(tasks_path, durable_tasks)
        journal = self.write_transaction(run_id, transaction)
        run_path = self.store.run_dir(run_id) / "run.json"
        before_bytes = (run_path.read_bytes(), tasks_path.read_bytes())

        with self.assertRaisesRegex(
            StateInconsistencyError, "durable tasks changed"
        ):
            self.store.load_tasks(run_id)

        self.assertEqual(
            before_bytes,
            (run_path.read_bytes(), tasks_path.read_bytes()),
        )
        self.assertTrue(journal.exists())

    def test_recovery_rejects_missing_or_conflicting_active_pointer(self) -> None:
        for pointer in (None, "20260724T120000Z-deadbeef"):
            with self.subTest(pointer=pointer):
                self.tearDown()
                self.setUp()
                run_id, _ = self.create_run(tasks=[make_task()])
                transaction = self.make_start_transaction(run_id)
                journal = self.write_transaction(run_id, transaction)
                active = self.store.root / "active"
                if pointer is None:
                    active.unlink()
                else:
                    active.write_text(pointer + "\n", encoding="ascii")
                run_path = self.store.run_dir(run_id) / "run.json"
                tasks_path = self.store.run_dir(run_id) / "tasks.json"
                before_bytes = (run_path.read_bytes(), tasks_path.read_bytes())

                with self.assertRaisesRegex(
                    StateInconsistencyError, "active pointer differs"
                ):
                    self.store.load_state(run_id)

                self.assertEqual(
                    before_bytes,
                    (run_path.read_bytes(), tasks_path.read_bytes()),
                )
                self.assertTrue(journal.exists())

    def test_recovery_converges_from_every_partial_v2_snapshot(self) -> None:
        for run_after, tasks_after in (
            (False, False),
            (False, True),
            (True, False),
            (True, True),
        ):
            with self.subTest(run_after=run_after, tasks_after=tasks_after):
                self.tearDown()
                self.setUp()
                run_id, _ = self.create_run(tasks=[make_task()])
                transaction = self.make_start_transaction(run_id)
                if run_after:
                    atomic_write_json(
                        self.store.run_dir(run_id) / "run.json",
                        transaction["run"],
                    )
                if tasks_after:
                    atomic_write_json(
                        self.store.run_dir(run_id) / "tasks.json",
                        transaction["tasks"],
                    )
                journal = self.write_transaction(run_id, transaction)

                self.assertEqual(transaction["run"], self.store.load_run(run_id))
                self.assertEqual(
                    transaction["tasks"], self.store.load_tasks(run_id)
                )
                self.assertFalse(journal.exists())
                self.assertEqual(transaction["run"], self.store.load_run(run_id))

    def test_legacy_recovery_only_cleans_an_exact_completed_replay(self) -> None:
        run_id, _ = self.create_run(tasks=[make_task()])
        transaction = self.make_start_transaction(run_id)
        legacy = {
            "schemaVersion": 1,
            "run": transaction["run"],
            "tasks": transaction["tasks"],
        }
        journal = self.write_transaction(run_id, legacy)
        with self.assertRaisesRegex(
            StateInconsistencyError, "cannot be replayed safely"
        ):
            self.store.load_run(run_id)
        self.assertTrue(journal.exists())

        atomic_write_json(
            self.store.run_dir(run_id) / "tasks.json", legacy["tasks"]
        )
        atomic_write_json(
            self.store.run_dir(run_id) / "run.json", legacy["run"]
        )
        self.assertEqual(legacy["run"], self.store.load_run(run_id))
        self.assertFalse(journal.exists())

    def test_legacy_journal_cannot_resurrect_a_shipped_run(self) -> None:
        run_id, _ = self.create_run()
        self.store.complete_run(run_id)
        target_run, target_tasks = self.store.load_state(run_id)
        self.store.mark_shipped(run_id)
        legacy = {
            "schemaVersion": 1,
            "run": target_run,
            "tasks": target_tasks,
        }
        journal = self.write_transaction(run_id, legacy)
        run_path = self.store.run_dir(run_id) / "run.json"
        tasks_path = self.store.run_dir(run_id) / "tasks.json"
        before_bytes = (run_path.read_bytes(), tasks_path.read_bytes())

        with self.assertRaisesRegex(
            StateInconsistencyError, "cannot be replayed safely"
        ):
            self.store.load_state(run_id)

        self.assertEqual(
            before_bytes,
            (run_path.read_bytes(), tasks_path.read_bytes()),
        )
        self.assertEqual("shipped", json.loads(run_path.read_text())["status"])
        self.assertIsNone(self.store.latest_complete_run_id())
        self.assertTrue(journal.exists())

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_forked_child_cannot_inherit_recovery_lock_ownership(self) -> None:
        run_id, _ = self.create_run(tasks=[make_task()])
        transaction = self.make_start_transaction(run_id)
        journal = self.write_transaction(run_id, transaction)
        run_path = self.store.run_dir(run_id) / "run.json"
        tasks_path = self.store.run_dir(run_id) / "tasks.json"
        before_bytes = (run_path.read_bytes(), tasks_path.read_bytes())
        read_fd, write_fd = os.pipe()

        with repository_lock(self.store.root):
            with run_lock(self.store.run_dir(run_id)):
                child_pid = os.fork()
                if child_pid == 0:
                    os.close(read_fd)
                    inherited = current_thread_holds_lock(
                        self.store.root / "repository.lock"
                    )
                    try:
                        self.store.load_state(run_id)
                    except BaseException as exc:
                        outcome = f"{int(inherited)}:{type(exc).__name__}"
                    else:
                        outcome = f"{int(inherited)}:recovered"
                    os.write(write_fd, outcome.encode("ascii"))
                    os.close(write_fd)
                    os._exit(0)
                os.close(write_fd)
                outcome = os.read(read_fd, 128).decode("ascii")
                os.close(read_fd)
                _, status = os.waitpid(child_pid, 0)
                self.assertEqual(0, status)
                self.assertEqual("0:LockHeldError", outcome)
                self.assertTrue(journal.exists())
                self.assertEqual(
                    before_bytes,
                    (run_path.read_bytes(), tasks_path.read_bytes()),
                )

    def test_run_lock_mutator_recovers_without_nested_lock_failure(self) -> None:
        run_id, _ = self.create_run(tasks=[make_task()])
        transaction = self.make_start_transaction(run_id)
        self.write_transaction(run_id, transaction)

        reservations = self.store.reserve_provider_invocations(
            run_id, "T1", ("codex",)
        )

        self.assertEqual(1, reservations[0]["providerAttempt"])
        self.assertFalse(
            (self.store.run_dir(run_id) / "attempt-block-transaction.json").exists()
        )

    def test_exhausted_attempt_transaction_recovers_after_partial_write(self) -> None:
        run_id, _ = self.create_run(tasks=[make_task()])
        self.store.start_task(run_id, "T1")
        self.store.reserve_provider_invocations(run_id, "T1", ("codex",))
        self.store.reserve_provider_invocations(run_id, "T1", ("codex",))
        self.store.reserve_provider_invocations(run_id, "T1", ("codex",))
        real_atomic_write = state_module.atomic_write_json

        def fail_run_write(path: Path, value: object, *args: object, **kwargs: object) -> None:
            destination = Path(path)
            journal = self.store.run_dir(run_id) / "attempt-block-transaction.json"
            if destination.name == "run.json" and journal.exists():
                raise OSError("simulated crash")
            real_atomic_write(destination, value, *args, **kwargs)

        with patch.object(
            state_module, "atomic_write_json", side_effect=fail_run_write
        ):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                self.store.block_exhausted_provider_attempt(
                    run_id, "T1", "codex"
                )

        journal = self.store.run_dir(run_id) / "attempt-block-transaction.json"
        self.assertTrue(journal.exists())
        recovered_run = self.store.load_run(run_id)
        recovered_task = self.store.load_tasks(run_id)["tasks"][0]
        self.assertEqual("blocked", recovered_run["status"])
        self.assertEqual("blocked", recovered_task["status"])
        self.assertFalse(journal.exists())

    def test_transaction_held_shipped_transition_updates_pointers(self) -> None:
        run_id, _ = self.create_run()
        self.store.complete_run(run_id)
        run_directory = self.store.run_dir(run_id)

        with repository_lock(self.store.root):
            with run_lock(run_directory):
                shipped = self.store.mark_shipped_in_transaction(run_id)

        self.assertEqual("shipped", shipped["status"])
        self.assertIsNone(self.store.latest_complete_run_id())
        with repository_lock(self.store.root):
            with run_lock(run_directory):
                repeated = self.store.mark_shipped_in_transaction(run_id)
        self.assertEqual(shipped, repeated)

    def test_shipped_transition_retry_repairs_interrupted_pointer_update(self) -> None:
        run_id, _ = self.create_run()
        self.store.complete_run(run_id)
        run_directory = self.store.run_dir(run_id)

        with patch.object(
            self.store,
            "_remove_pointer",
            side_effect=OSError("simulated pointer crash"),
        ):
            with repository_lock(self.store.root):
                with run_lock(run_directory):
                    with self.assertRaisesRegex(
                        OSError, "simulated pointer crash"
                    ):
                        self.store.mark_shipped_in_transaction(run_id)

        self.assertEqual("shipped", self.store.load_run(run_id)["status"])
        self.assertEqual(run_id, self.store.latest_complete_run_id())
        with repository_lock(self.store.root):
            with run_lock(run_directory):
                self.store.mark_shipped_in_transaction(run_id)
        self.assertIsNone(self.store.latest_complete_run_id())


if __name__ == "__main__":
    unittest.main()
