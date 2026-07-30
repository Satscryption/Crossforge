from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace


SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "crossforge" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import crossforge as crossforge_cli  # noqa: E402
from crossforge_lib.acceptance import (  # noqa: E402
    accept_candidate,
    assess_candidate_eligibility,
    build_commit_message,
    check_micro_fix,
    verify_candidate_gates,
)
from crossforge_lib.evidence import EvidenceStore  # noqa: E402
from crossforge_lib.errors import (  # noqa: E402
    GateFailureError,
    InvalidInputError,
    PreconditionError,
    StateInconsistencyError,
)
from crossforge_lib.git import discover_repository, resolve_commit  # noqa: E402
from crossforge_lib.gates import ExecutableIdentity, GateResult  # noqa: E402
from crossforge_lib.locking import LockHeldError, repository_lock  # noqa: E402
from crossforge_lib.scope import check_scope  # noqa: E402
from crossforge_lib.util import (  # noqa: E402
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
)
from crossforge_lib.worktrees import WorktreeManager  # noqa: E402


def git(cwd: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


@dataclass(frozen=True)
class FakeGateResult:
    passed: bool
    provenance: str = "independent"

    def as_dict(self):
        return {
            "passed": self.passed,
            "provenance": self.provenance,
            "exitCode": 0 if self.passed else 1,
        }


class FakeGateRunner:
    def __init__(self, root: Path, *, passed: bool = True, mutate: bool = False):
        self.policy = SimpleNamespace(worktree=str(root))
        self.root = root
        self.passed = passed
        self.mutate = mutate
        self.calls = []

    def run(self, command, *, result_name: str, **_kwargs):
        self.calls.append((command, result_name))
        if self.mutate:
            (self.root / "app.txt").write_text("gate-mutated\n", encoding="utf-8")
        return FakeGateResult(self.passed)


class BoundFakeGateRunner:
    def __init__(
        self,
        root: Path,
        evidence: EvidenceStore,
        *,
        passed: bool = True,
        mutate: bool = False,
    ):
        self.policy = SimpleNamespace(worktree=str(root))
        self.root = root
        self.evidence = evidence
        self.passed = passed
        self.mutate = mutate

    def run(self, command, *, result_name: str, **_kwargs):
        if self.mutate:
            (self.root / "app.txt").write_text(
                "gate-mutated\n", encoding="utf-8"
            )
        policy = self.evidence.write_independent_json(
            f"gates/{result_name}.sandbox-policy.json",
            {
                "backend": "fake",
                "worktree": str(self.root),
                "network": "deny",
            },
        )
        output = self.evidence.write_text(
            f"independent/gates/{result_name}.output",
            "ok\n" if self.passed else "failed\n",
        )
        result = GateResult(
            argv=command.argv,
            working_directory=str(self.root),
            started_at="2026-07-24T12:00:00Z",
            completed_at="2026-07-24T12:00:01Z",
            duration_ms=1,
            exit_code=0 if self.passed else 1,
            timed_out=False,
            output_path=output.relative_path,
            output_sha256=output.sha256,
            executable=ExecutableIdentity(
                basename="true",
                path="/usr/bin/true",
                mode=0o100755,
                sha256="a" * 64,
            ),
            sandbox_backend="fake",
            sandbox_policy_path=policy.relative_path,
            sandbox_policy_sha256=policy.sha256,
            environment=(),
        )
        self.evidence.write_independent_json(
            f"gates/{result_name}.result.json",
            result.as_dict(),
        )
        return result


class AcceptanceCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.sandbox = Path(self.temporary.name).resolve()
        self.repository_path = self.sandbox / "repository"
        self.repository_path.mkdir()
        git(self.repository_path, "init", "-b", "feature")
        git(self.repository_path, "config", "user.name", "Crossforge Test")
        git(self.repository_path, "config", "user.email", "test@invalid")
        (self.repository_path / "app.txt").write_text("base\n", encoding="utf-8")
        git(self.repository_path, "add", "app.txt")
        git(self.repository_path, "commit", "-m", "base")
        self.repository = discover_repository(self.repository_path)
        self.base = resolve_commit(self.repository, "HEAD")
        self.worktree_root = self.sandbox / "worktrees"
        self.registry_path = self.sandbox / "state" / "worktrees.json"
        self.manager = WorktreeManager(
            self.repository_path,
            self.worktree_root,
            self.registry_path,
            repository_id_prefix="acceptance",
        )
        self.candidate_evidence = self.sandbox / "state" / "candidate"
        self.acceptance_evidence = EvidenceStore(self.sandbox / "state" / "acceptance")
        self.state_root = self.sandbox / "state" / "crossforge"

    def tearDown(self):
        git(self.repository_path, "worktree", "prune", check=False)

    def candidate(self, *, changed: str = "candidate\n", extra_path: str | None = None):
        entry = self.manager.create(
            run_id="run-1",
            task_id="T1",
            provider="codex",
            base_commit=self.base,
            evidence_dir=self.candidate_evidence,
        )
        (entry.path / "app.txt").write_text(changed, encoding="utf-8")
        if extra_path:
            (entry.path / extra_path).write_text("outside\n", encoding="utf-8")
        patch = self.candidate_evidence / "candidate.patch"
        captured = self.manager.capture_patch(entry, patch)
        return captured, patch

    def message(self):
        return build_commit_message(
            change_type="fix",
            summary="update app behavior",
            why="Apply the approved candidate exactly.",
            tests="fake isolated gate passed",
            provider="codex",
            resolved_model="test-model",
            task_id="T1",
        )

    def accept(
        self,
        candidate,
        patch,
        *,
        passed=True,
        mutate=False,
        allowlist=None,
        gate_commands=None,
        durable_task_policy=None,
        **kwargs,
    ):
        runners = []

        def factory(root, _evidence):
            runner = FakeGateRunner(root, passed=passed, mutate=mutate)
            runners.append(runner)
            return runner

        canonical_policy = {
            "id": "T1",
            "allowedFiles": ["app.txt"],
            "verificationCommands": [
                {"argv": ["true"], "timeoutSeconds": 10}
            ],
            "approvedSymlinks": [],
            "approvedBinaryContext": [],
        }
        result = accept_candidate(
            repository=self.repository,
            worktree_manager=self.manager,
            run_id="run-1",
            task_id="T1",
            candidate=candidate,
            patch_path=patch,
            allowlist=allowlist if allowlist is not None else ["app.txt"],
            gate_commands=(
                gate_commands
                if gate_commands is not None
                else [{"argv": ["true"], "timeoutSeconds": 10}]
            ),
            durable_task_policy=(
                durable_task_policy
                if durable_task_policy is not None
                else canonical_policy
            ),
            gate_runner_factory=factory,
            evidence_store=self.acceptance_evidence,
            commit_message=self.message(),
            state_root=self.state_root,
            **kwargs,
        )
        return result, runners


class AcceptanceTests(AcceptanceCase):
    def test_selection_gates_are_control_run_against_captured_patch(self):
        candidate, patch = self.candidate()
        run_directory = self.sandbox / "state" / "run-1"
        evidence = EvidenceStore(
            run_directory
            / "evidence"
            / "T1"
            / "selection-gates"
            / f"codex-{candidate.captured_patch_sha256[:12]}"
        )
        runners = []

        def factory(root, store):
            runner = BoundFakeGateRunner(root, store)
            runners.append(runner)
            return runner

        policy = {
            "id": "T1",
            "baseCommit": self.base,
            "allowedFiles": ["app.txt"],
            "verificationCommands": [
                {"argv": ["true"], "timeoutSeconds": 10},
                {"argv": ["true", "--version"], "timeoutSeconds": 20},
            ],
            "approvedSymlinks": [],
            "approvedBinaryContext": [],
        }
        result = verify_candidate_gates(
            repository=self.repository,
            worktree_manager=self.manager,
            run_id="run-1",
            task_id="T1",
            candidate=candidate,
            patch_path=patch,
            gate_runner_factory=factory,
            evidence_store=evidence,
            state_root=self.state_root,
            durable_task_policy=policy,
            repository_identity="b" * 64,
            plan_sha256="c" * 64,
            gate_policy={"backend": "fake", "network": "deny"},
            quarantine_resolver=lambda root: (
                self.assertNotEqual(root, candidate.path) or ["app.txt"]
            ),
        )

        self.assertEqual(2, len(result.gate_results))
        self.assertEqual("cleaned", result.verification_cleanup)
        self.assertFalse(Path(result.verification_worktree).exists())
        self.assertEqual(result.receipt_sha256, sha256_file(result.receipt_path))
        self.assertEqual(resolve_commit(self.repository, "HEAD"), self.base)
        self.assertEqual(
            git(self.repository_path, "status", "--porcelain").stdout,
            b"",
        )
        self.assertEqual(1, len(runners))
        self.assertNotEqual(runners[0].root, self.repository_path)

        selected_task = {
            **policy,
            "selectedGateEvidencePath": result.receipt_path,
            "selectedGateEvidenceSha256": result.receipt_sha256,
        }
        context = SimpleNamespace(
            store=SimpleNamespace(run_dir=lambda _run_id: run_directory),
            run_id="run-1",
            run={
                "repositoryIdentity": "b" * 64,
                "planSha256": "c" * 64,
                "gateSandbox": {"backend": "fake", "network": "deny"},
            },
        )
        receipt = crossforge_cli._load_selected_gate_receipt(
            context,
            candidate,
            selected_task,
        )
        self.assertTrue(receipt["passed"])
        self.assertEqual(
            sha256_bytes(canonical_json_bytes(["app.txt"])),
            receipt["quarantinePathsSha256"],
        )

        output = evidence.root / receipt["gateResults"][0]["outputPath"]
        output.write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(
            StateInconsistencyError,
            "output 1 hash changed",
        ):
            crossforge_cli._load_selected_gate_receipt(
                context,
                candidate,
                selected_task,
            )

    def test_gate_evidence_with_multiple_hard_links_is_rejected(self):
        candidate, patch = self.candidate()
        run_directory = self.sandbox / "state" / "run-1"
        evidence = EvidenceStore(
            run_directory
            / "evidence"
            / "T1"
            / "selection-gates"
            / f"codex-{candidate.captured_patch_sha256[:12]}"
        )
        policy = {
            "id": "T1",
            "baseCommit": self.base,
            "allowedFiles": ["app.txt"],
            "verificationCommands": [
                {"argv": ["true"], "timeoutSeconds": 10}
            ],
            "approvedSymlinks": [],
            "approvedBinaryContext": [],
        }
        result = verify_candidate_gates(
            repository=self.repository,
            worktree_manager=self.manager,
            run_id="run-1",
            task_id="T1",
            candidate=candidate,
            patch_path=patch,
            gate_runner_factory=lambda root, store: BoundFakeGateRunner(
                root, store
            ),
            evidence_store=evidence,
            state_root=self.state_root,
            durable_task_policy=policy,
            repository_identity="b" * 64,
            plan_sha256="c" * 64,
            gate_policy={"backend": "fake", "network": "deny"},
        )
        receipt = json.loads(Path(result.receipt_path).read_text())
        output = evidence.root / receipt["gateResults"][0]["outputPath"]
        os.link(output, output.with_suffix(".linked"))
        context = SimpleNamespace(
            store=SimpleNamespace(
                run_dir=lambda _run_id: run_directory
            ),
            run_id="run-1",
            run={
                "repositoryIdentity": "b" * 64,
                "planSha256": "c" * 64,
                "gateSandbox": {"backend": "fake", "network": "deny"},
            },
        )
        selected_task = {
            **policy,
            "selectedGateEvidencePath": result.receipt_path,
            "selectedGateEvidenceSha256": result.receipt_sha256,
        }
        with self.assertRaisesRegex(
            StateInconsistencyError, "exactly one hard link"
        ):
            crossforge_cli._load_selected_gate_receipt(
                context, candidate, selected_task
            )

    def test_gate_evidence_with_symlinked_ancestor_is_rejected(self):
        candidate, patch = self.candidate()
        run_directory = self.sandbox / "state" / "run-1"
        selection_root = (
            run_directory / "evidence" / "T1" / "selection-gates"
        )
        evidence = EvidenceStore(
            selection_root
            / f"codex-{candidate.captured_patch_sha256[:12]}"
        )
        policy = {
            "id": "T1",
            "baseCommit": self.base,
            "allowedFiles": ["app.txt"],
            "verificationCommands": [
                {"argv": ["true"], "timeoutSeconds": 10}
            ],
            "approvedSymlinks": [],
            "approvedBinaryContext": [],
        }
        result = verify_candidate_gates(
            repository=self.repository,
            worktree_manager=self.manager,
            run_id="run-1",
            task_id="T1",
            candidate=candidate,
            patch_path=patch,
            gate_runner_factory=lambda root, store: BoundFakeGateRunner(
                root, store
            ),
            evidence_store=evidence,
            state_root=self.state_root,
            durable_task_policy=policy,
            repository_identity="b" * 64,
            plan_sha256="c" * 64,
            gate_policy={"backend": "fake", "network": "deny"},
        )
        replay_root = run_directory / "replayed-selection-gates"
        selection_root.rename(replay_root)
        selection_root.symlink_to(replay_root, target_is_directory=True)
        context = SimpleNamespace(
            store=SimpleNamespace(run_dir=lambda _run_id: run_directory),
            run_id="run-1",
            run={
                "repositoryIdentity": "b" * 64,
                "planSha256": "c" * 64,
                "gateSandbox": {"backend": "fake", "network": "deny"},
            },
        )
        selected_task = {
            **policy,
            "selectedGateEvidencePath": result.receipt_path,
            "selectedGateEvidenceSha256": result.receipt_sha256,
        }
        with self.assertRaisesRegex(
            StateInconsistencyError, "cannot be opened safely"
        ):
            crossforge_cli._load_selected_gate_receipt(
                context, candidate, selected_task
            )

    def test_selection_gate_mutation_cannot_produce_receipt(self):
        candidate, patch = self.candidate()
        evidence = EvidenceStore(self.sandbox / "state" / "selection-mutated")
        policy = {
            "id": "T1",
            "baseCommit": self.base,
            "allowedFiles": ["app.txt"],
            "verificationCommands": [
                {"argv": ["true"], "timeoutSeconds": 10}
            ],
            "approvedSymlinks": [],
            "approvedBinaryContext": [],
        }

        def factory(root, store):
            return BoundFakeGateRunner(
                root,
                store,
                mutate=True,
            )

        with self.assertRaises(GateFailureError):
            verify_candidate_gates(
                repository=self.repository,
                worktree_manager=self.manager,
                run_id="run-1",
                task_id="T1",
                candidate=candidate,
                patch_path=patch,
                gate_runner_factory=factory,
                evidence_store=evidence,
                state_root=self.state_root,
                durable_task_policy=policy,
                repository_identity="b" * 64,
                plan_sha256="c" * 64,
                gate_policy={"backend": "fake", "network": "deny"},
            )
        self.assertFalse(list(evidence.root.glob("**/*.suite.json")))

        retried = verify_candidate_gates(
            repository=self.repository,
            worktree_manager=self.manager,
            run_id="run-1",
            task_id="T1",
            candidate=candidate,
            patch_path=patch,
            gate_runner_factory=lambda root, store: BoundFakeGateRunner(
                root, store
            ),
            evidence_store=evidence,
            state_root=self.state_root,
            durable_task_policy=policy,
            repository_identity="b" * 64,
            plan_sha256="c" * 64,
            gate_policy={"backend": "fake", "network": "deny"},
        )
        receipt = json.loads(Path(retried.receipt_path).read_text())
        self.assertEqual(2, receipt["attempt"])

    def test_fresh_verification_exact_staging_and_safe_commit(self):
        hook_marker = self.sandbox / "hook-ran"
        hook = self.repository.git_dir / "hooks" / "pre-commit"
        hook.write_text(
            f"#!/bin/sh\ntouch '{hook_marker}'\nexit 1\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)
        git(self.repository_path, "config", "commit.gpgsign", "true")
        candidate, patch = self.candidate()

        result, runners = self.accept(candidate, patch)

        self.assertIsNotNone(result.commit)
        self.assertNotEqual(self.base, result.commit)
        self.assertEqual(
            result.verified_scoped_tree_sha256,
            result.applied_scoped_tree_sha256,
        )
        self.assertEqual(result.patch_sha256, hashlib.sha256(patch.read_bytes()).hexdigest())
        self.assertEqual(result.staged_paths, ("app.txt",))
        self.assertEqual(result.verification_cleanup, "cleaned")
        self.assertFalse(Path(result.verification_worktree).exists())
        self.assertEqual(
            (self.repository_path / "app.txt").read_text(encoding="utf-8"),
            "candidate\n",
        )
        self.assertEqual(git(self.repository_path, "status", "--porcelain").stdout, b"")
        self.assertFalse(hook_marker.exists())
        self.assertEqual(len(runners), 1)
        self.assertNotEqual(runners[0].root.resolve(), self.repository_path.resolve())

    def test_selection_binding_is_revalidated_before_orchestration_apply(self):
        candidate, patch = self.candidate()
        observed = []

        def reject(tree_sha256, quarantine_sha256):
            observed.append((tree_sha256, quarantine_sha256))
            raise StateInconsistencyError("selection evidence changed")

        with self.assertRaisesRegex(
            StateInconsistencyError, "selection evidence changed"
        ):
            self.accept(
                candidate,
                patch,
                quarantine_resolver=lambda root: ["app.txt"],
                pre_apply_validator=reject,
            )
        self.assertEqual(1, len(observed))
        self.assertEqual(
            sha256_bytes(canonical_json_bytes(["app.txt"])),
            observed[0][1],
        )
        self.assertEqual(resolve_commit(self.repository, "HEAD"), self.base)
        self.assertEqual(
            (self.repository_path / "app.txt").read_text(encoding="utf-8"),
            "base\n",
        )

    def test_acceptance_finalizer_runs_inside_repository_transaction(self):
        candidate, patch = self.candidate()
        finalized = []
        events = []

        def record_intent(_tree, _quarantine):
            events.append(("intent", resolve_commit(self.repository, "HEAD")))

        def finalize(result):
            events.append(("finalize", resolve_commit(self.repository, "HEAD")))
            finalized.append(result.commit)
            with self.assertRaises(LockHeldError):
                with repository_lock(self.state_root, timeout=0):
                    self.fail("repository lock was released before finalizer")

        self.accept(
            candidate,
            patch,
            acceptance_intent_recorder=record_intent,
            acceptance_finalizer=finalize,
        )
        self.assertEqual(1, len(finalized))
        self.assertEqual("intent", events[0][0])
        self.assertEqual(self.base, events[0][1])
        self.assertEqual(
            [("finalize", finalized[0])],
            events[1:],
        )

    def test_gate_failure_leaves_orchestration_clean_at_base(self):
        candidate, patch = self.candidate()

        with self.assertRaises(GateFailureError):
            self.accept(candidate, patch, passed=False)

        self.assertEqual(resolve_commit(self.repository, "HEAD"), self.base)
        self.assertEqual(git(self.repository_path, "status", "--porcelain").stdout, b"")
        verification_entries = [
            entry for entry in self.manager.registry.load() if "verification" in entry.provider
        ]
        self.assertEqual(len(verification_entries), 1)
        self.assertEqual(verification_entries[0].status, "retained")

    def test_gate_mutation_is_not_accepted_or_applied(self):
        candidate, patch = self.candidate()
        with self.assertRaises(GateFailureError):
            self.accept(candidate, patch, mutate=True)
        self.assertEqual(resolve_commit(self.repository, "HEAD"), self.base)
        self.assertEqual(
            (self.repository_path / "app.txt").read_text(encoding="utf-8"), "base\n"
        )

    def test_stale_or_dirty_orchestration_is_rejected_before_verification(self):
        candidate, patch = self.candidate()
        (self.repository_path / "local.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(PreconditionError):
            self.accept(candidate, patch)
        self.assertEqual(
            [
                entry
                for entry in self.manager.registry.load()
                if "verification" in entry.provider
            ],
            [],
        )

    def test_patch_metadata_outside_allowlist_blocks_before_orchestration(self):
        candidate, patch = self.candidate(extra_path="outside.txt")
        with self.assertRaises(PreconditionError):
            self.accept(candidate, patch)
        self.assertEqual(resolve_commit(self.repository, "HEAD"), self.base)
        self.assertEqual(git(self.repository_path, "status", "--porcelain").stdout, b"")

    def test_no_commit_requires_one_task_and_leaves_verified_staged_change(self):
        candidate, patch = self.candidate()
        with self.assertRaises(InvalidInputError):
            self.accept(candidate, patch, no_commit=True, task_count=2)
        self.assertEqual(git(self.repository_path, "status", "--porcelain").stdout, b"")

        result, _runners = self.accept(
            candidate,
            patch,
            no_commit=True,
            task_count=1,
        )
        self.assertIsNone(result.commit)
        self.assertEqual(resolve_commit(self.repository, "HEAD"), self.base)
        self.assertIn(b"app.txt", git(self.repository_path, "diff", "--cached", "--name-only").stdout)

    def test_patch_hash_tampering_is_detected(self):
        candidate, patch = self.candidate()
        patch.write_bytes(patch.read_bytes() + b"\n")
        with self.assertRaises(StateInconsistencyError):
            self.accept(candidate, patch)
        self.assertEqual(resolve_commit(self.repository, "HEAD"), self.base)

    def test_acceptance_rejects_caller_policy_broader_than_durable_task(self):
        candidate, patch = self.candidate()
        with self.assertRaisesRegex(StateInconsistencyError, "allowlist"):
            self.accept(candidate, patch, allowlist=["app.txt", "outside.txt"])
        with self.assertRaisesRegex(StateInconsistencyError, "gates"):
            self.accept(
                candidate,
                patch,
                gate_commands=[
                    {"argv": ["python3", "-m", "unittest"], "timeoutSeconds": 10}
                ],
            )


class EligibilityAndMicroFixTests(AcceptanceCase):
    def test_eligibility_requires_every_hard_gate(self):
        candidate, patch = self.candidate()
        scope = check_scope(
            discover_repository(candidate.path),
            base_commit=self.base,
            allowlist=["app.txt"],
        )
        report = SimpleNamespace(eligible_by_claim=True)
        gate_result = FakeGateResult(True)
        eligible = assess_candidate_eligibility(
            candidate=candidate,
            patch_path=patch,
            task_base_commit=self.base,
            scope_result=scope,
            provider_report=report,
            independent_gate_results=[gate_result],
        )
        self.assertTrue(eligible.eligible)

        rejected = assess_candidate_eligibility(
            candidate=candidate,
            patch_path=patch,
            task_base_commit="0" * 40,
            scope_result=scope,
            provider_report=report,
            independent_gate_results=[FakeGateResult(False)],
            plan_guardrails_passed=False,
            public_contract_approved=False,
            generated_and_binary_content_explained=False,
        )
        self.assertFalse(rejected.eligible)
        self.assertIn("base_commit_mismatch", rejected.reasons)
        self.assertIn("independent_gate_failed", rejected.reasons)
        self.assertIn("plan_guardrail_failed", rejected.reasons)

    def test_micro_fix_mechanical_contract(self):
        allowed = check_micro_fix(
            changed_lines=5,
            changed_paths=["app.txt"],
            allowlist=["app.txt"],
            maximum_changed_lines=5,
            enabled=True,
            task_risk="low",
            task_class="bugfix",
            public_interface_change=False,
            security_or_behavioral_decision=False,
            persistence_migration_or_concurrency=False,
            new_test_logic=False,
            deterministic_gates_cover=True,
            evidence_will_record=True,
            commit_body_will_record=True,
        )
        self.assertTrue(allowed.allowed)
        self.assertEqual("caller-attested", allowed.to_dict()["assurance"])
        self.assertFalse(allowed.to_dict()["authoritative"])
        self.assertIn(
            "changed_lines",
            allowed.to_dict()["attestedInputs"],
        )

        rejected = check_micro_fix(
            changed_lines=6,
            changed_paths=["outside.txt"],
            allowlist=["app.txt"],
            maximum_changed_lines=5,
            enabled=True,
            task_risk="high",
            task_class="security",
            public_interface_change=True,
            security_or_behavioral_decision=True,
            persistence_migration_or_concurrency=True,
            new_test_logic=True,
            deterministic_gates_cover=False,
            evidence_will_record=False,
            commit_body_will_record=False,
        )
        self.assertFalse(rejected.allowed)
        self.assertIn("changed_line_limit_exceeded", rejected.reasons)
        self.assertIn("path_outside_allowlist", rejected.reasons)
        self.assertIn("high_risk_task", rejected.reasons)


if __name__ == "__main__":
    unittest.main()
