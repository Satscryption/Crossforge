from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from unittest.mock import patch

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE_ROOT / "skills" / "crossforge" / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.errors import (  # noqa: E402
    PreconditionError,
    SecretPolicyError,
    StateInconsistencyError,
)
from crossforge_lib.gates import executable_identity  # noqa: E402
from crossforge_lib.git import (  # noqa: E402
    discover_repository,
    repository_identity,
    resolve_commit,
)
from crossforge_lib.shipping import (  # noqa: E402
    CommandResult,
    FinalGateEvidence,
    PullRequestReadback,
    RemoteReadback,
    authorize_shipment,
    cancel_shipment,
    load_pull_request_body,
    reconcile_pull_request,
    reconcile_push,
    record_shipment,
    ship_preflight,
)
import crossforge_lib.shipping as shipping_module  # noqa: E402
from crossforge_lib.locking import LockHeldError  # noqa: E402
from crossforge_lib.util import canonical_json_bytes  # noqa: E402

RUN_ID = "20260724T120000Z-1234abcd"
KEY = "0123456789abcdef0123456789abcdef"


class FakeStore:
    def __init__(self, root: Path, run: dict[str, Any], tasks: dict[str, Any]) -> None:
        self.root = root
        self.runs_dir = root / "runs"
        self.runs_dir.mkdir(parents=True)
        self._run = run
        self._tasks = tasks
        self.mark_calls = 0
        (self.runs_dir / RUN_ID).mkdir()

    def run_dir(self, run_id: str) -> Path:
        self.assert_run(run_id)
        return self.runs_dir / run_id

    def assert_run(self, run_id: str) -> None:
        if run_id != RUN_ID:
            raise AssertionError(run_id)

    def load_run(self, run_id: str) -> dict[str, Any]:
        self.assert_run(run_id)
        return dict(self._run)

    def load_tasks(self, run_id: str) -> dict[str, Any]:
        self.assert_run(run_id)
        return {"schemaVersion": 1, "tasks": [dict(item) for item in self._tasks["tasks"]]}

    def load_state(self, run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.load_run(run_id), self.load_tasks(run_id)

    def latest_complete_run_id(self) -> str:
        return RUN_ID

    def mark_shipped(self, run_id: str) -> dict[str, Any]:
        self.assert_run(run_id)
        self.mark_calls += 1
        self._run["status"] = "shipped"
        return dict(self._run)

    def mark_shipped_in_transaction(self, run_id: str) -> dict[str, Any]:
        return self.mark_shipped(run_id)


class FakeRemote:
    def __init__(self, *, head: str | None = None, target_ok: bool = True) -> None:
        self.head = head
        self.target = "b" * 40
        self.target_ok = target_ok
        self.push_calls = 0
        self.argv: list[tuple[str, ...]] = []

    def inspect(
        self, remote: str, head: str, target: str, final: str
    ) -> RemoteReadback:
        return RemoteReadback(
            head_commit=self.head,
            target_commit=self.target,
            head_is_ancestor=(self.head is None or self.head == final),
            target_is_ancestor=self.target_ok,
        )

    def runner(
        self, argv: Sequence[str], *, cwd: Path, input_text: str | None = None
    ) -> CommandResult:
        values = tuple(argv)
        self.argv.append(values)
        if ("remote" in values and "get-url" in values) or "config" in values:
            result = subprocess.run(
                values,
                cwd=cwd,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            return CommandResult(values, result.returncode, result.stdout, result.stderr)
        if "push" not in values:
            return CommandResult(values, 2, "", "unexpected")
        self.push_calls += 1
        destination = values[-1]
        self.head = destination.split(":", 1)[0]
        return CommandResult(values, 0, "", "")


class ShippingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo_path = self.root / "repo"
        self.repo_path.mkdir()
        self._git("init", "-b", "crossforge/test")
        self._git("config", "user.name", "Test")
        self._git("config", "user.email", "test@example.invalid")
        (self.repo_path / "file.txt").write_text("content\n", encoding="utf-8")
        self._git("add", "file.txt")
        self._git("commit", "-m", "test")
        self._git(
            "remote",
            "add",
            "origin",
            "https://github.com/example/crossforge-test.git",
        )
        self.repository = discover_repository(self.repo_path)
        self.commit = resolve_commit(self.repository)
        self.run = {
            "runId": RUN_ID,
            "mode": "build",
            "status": "complete",
            "repositoryIdentity": repository_identity(self.repository),
            "branch": "crossforge/test",
            "targetRemote": "origin",
            "targetBranch": "main",
            "currentCommit": self.commit,
            "planSha256": "d" * 64,
            "globalVerificationCommands": [
                {"argv": ["python3", "-m", "unittest"], "timeoutSeconds": 900}
            ],
            "gateSandbox": {
                "backend": "bwrap",
                "network": "deny",
                "probeVersion": "1",
            },
            "activeTaskId": None,
            "blockedReason": None,
        }
        self.tasks = {
            "schemaVersion": 1,
            "tasks": [{"id": "T1", "status": "complete"}],
        }
        self.store = FakeStore(self.root / "state", self.run, self.tasks)
        self.remote = FakeRemote()
        self.gh_state = self.root / "gh.json"
        self.fake_gh = self.root / "gh"
        self.gh_argv: list[tuple[str, ...]] = []
        shutil.copyfile(FIXTURES / "fake_gh.py", self.fake_gh)
        self.fake_gh.chmod(self.fake_gh.stat().st_mode | stat.S_IXUSR)
        self.forge_identity = executable_identity(self.fake_gh)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _git(self, *args: str) -> None:
        subprocess.run(
            ("git", *args),
            cwd=self.repo_path,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def _plan(self, *, dry_run: bool = False):
        return ship_preflight(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            remote=None,
            target_branch=None,
            publication_requested=True,
            dry_run=dry_run,
            final_gate=self._gate_evidence,
            inspect_remote=self.remote.inspect,
        )

    @staticmethod
    def _digest(value: object) -> str:
        return hashlib.sha256(canonical_json_bytes(value)).hexdigest()

    def _gate_evidence(self, run: Mapping[str, Any]) -> FinalGateEvidence:
        return FinalGateEvidence(
            run_id=str(run["runId"]),
            final_commit=str(run["currentCommit"]),
            plan_sha256=str(run["planSha256"]),
            global_commands_sha256=self._digest(run["globalVerificationCommands"]),
            gate_policy_sha256=self._digest(run["gateSandbox"]),
            sandbox_policy_sha256="e" * 64,
            result_sha256="f" * 64,
            provenance="independent",
            passed=True,
        )

    def _gh_runner(
        self, argv: Sequence[str], *, cwd: Path, input_text: str | None = None
    ) -> CommandResult:
        self.gh_argv.append(tuple(argv))
        env = dict(os.environ)
        env["FAKE_GH_STATE"] = str(self.gh_state)
        env["FAKE_GH_HEAD_COMMIT"] = self.commit
        result = subprocess.run(
            tuple(argv),
            cwd=cwd,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )
        return CommandResult(tuple(argv), result.returncode, result.stdout, result.stderr)

    def _gh_data(self) -> dict[str, Any]:
        return json.loads(self.gh_state.read_text(encoding="utf-8"))

    def test_incomplete_run_and_dirty_repository_are_rejected(self) -> None:
        self.store._run["status"] = "active"
        with self.assertRaisesRegex(PreconditionError, "completed"):
            self._plan()
        self.store._run["status"] = "complete"
        (self.repo_path / "dirty.txt").write_text("dirty", encoding="utf-8")
        with self.assertRaisesRegex(PreconditionError, "clean"):
            self._plan()

    def test_explicit_publication_and_target_change_are_required(self) -> None:
        with self.assertRaisesRegex(PreconditionError, "authorize publication"):
            ship_preflight(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                remote=None,
                target_branch=None,
                publication_requested=False,
                dry_run=False,
                final_gate=self._gate_evidence,
                inspect_remote=self.remote.inspect,
            )
        with self.assertRaisesRegex(PreconditionError, "explicit approval"):
            ship_preflight(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                remote="upstream",
                target_branch="release",
                publication_requested=True,
                dry_run=False,
                final_gate=self._gate_evidence,
                inspect_remote=self.remote.inspect,
            )

    def test_dry_run_performs_no_authorization_or_write(self) -> None:
        plan = self._plan(dry_run=True)
        self.assertTrue(plan.dry_run)
        self.assertFalse((self.store.run_dir(RUN_ID) / "shipment.json").exists())
        self.assertEqual(self.remote.push_calls, 0)
        with self.assertRaisesRegex(PreconditionError, "dry-run"):
            authorize_shipment(
                self.store,  # type: ignore[arg-type]
                self.repository,
                plan,
                idempotency_key=KEY,
                publication_requested=True,
            )

    def test_remote_and_target_divergence_block(self) -> None:
        self.remote.head = "c" * 40
        with self.assertRaisesRegex(PreconditionError, "diverged"):
            self._plan()
        self.remote.head = None
        self.remote.target_ok = False
        with self.assertRaisesRegex(PreconditionError, "target branch"):
            self._plan()

    def test_live_repository_identity_mismatch_blocks_preflight(self) -> None:
        self.store._run["repositoryIdentity"] = "f" * 64
        with self.assertRaisesRegex(StateInconsistencyError, "repository identity"):
            self._plan()

    def test_authorization_tuple_is_immutable_and_idempotent(self) -> None:
        plan = self._plan()
        first = authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            plan,
            idempotency_key=KEY,
            publication_requested=True,
        )
        second = authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            plan,
            idempotency_key=KEY,
            publication_requested=True,
        )
        self.assertEqual(first, second)
        with self.assertRaises(StateInconsistencyError):
            authorize_shipment(
                self.store,  # type: ignore[arg-type]
                self.repository,
                plan,
                idempotency_key="f" * 32,
                publication_requested=True,
            )

    def test_push_and_pr_retries_do_not_duplicate_writes(self) -> None:
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        pushed = reconcile_push(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            publication_requested=True,
            final_gate=self._gate_evidence,
            push_only=False,
            title="Crossforge run",
            body="Evidence",
            draft=True,
            forge_identity=self.forge_identity,
            runner=self.remote.runner,
        )
        self.assertEqual(pushed["push"]["result"], "performed")
        reconcile_push(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            publication_requested=True,
            final_gate=self._gate_evidence,
            push_only=False,
            title="Crossforge run",
            body="Evidence",
            draft=True,
            forge_identity=self.forge_identity,
            runner=self.remote.runner,
        )
        self.assertEqual(self.remote.push_calls, 1)
        self.assertTrue(all("--force" not in item for argv in self.remote.argv for item in argv))
        created = reconcile_pull_request(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            title="Crossforge run",
            body="Evidence",
            draft=True,
            publication_requested=True,
            final_gate=self._gate_evidence,
            forge_identity=self.forge_identity,
            runner=self._gh_runner,
        )
        self.assertEqual(created["pullRequest"]["result"], "created")
        reconcile_pull_request(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            title="Crossforge run",
            body="Evidence",
            draft=True,
            publication_requested=True,
            final_gate=self._gate_evidence,
            forge_identity=self.forge_identity,
            runner=self._gh_runner,
        )
        self.assertEqual(self._gh_data()["createCalls"], 1)
        gh_commands = [argv for argv in self.gh_argv if Path(argv[0]).name == "gh"]
        self.assertTrue(gh_commands)
        for argv in gh_commands:
            self.assertIn("--repo", argv)
            self.assertEqual(argv[argv.index("--repo") + 1], "example/crossforge-test")
        completed = record_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            push_only=False,
            publication_requested=True,
            forge_identity=self.forge_identity,
            runner=self._gh_runner,
        )
        self.assertEqual(completed["status"], "recorded")
        self.assertEqual(self.store.mark_calls, 1)

    def test_push_only_retry_rejects_remote_confirmed_pr_bindings(self) -> None:
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        prepared = reconcile_push(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            publication_requested=True,
            final_gate=self._gate_evidence,
            push_only=False,
            title="Crossforge run",
            body="Evidence",
            draft=True,
            forge_identity=self.forge_identity,
            runner=self.remote.runner,
        )
        expected_bindings = (
            prepared["forgeExecutable"],
            prepared["bodySha256"],
            prepared["publicationPayloadSha256"],
        )
        with self.assertRaisesRegex(
            StateInconsistencyError, "PR publication bindings"
        ):
            reconcile_push(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                inspect_remote=self.remote.inspect,
                publication_requested=True,
                final_gate=self._gate_evidence,
                push_only=True,
                runner=self.remote.runner,
            )
        persisted = json.loads(
            (self.store.run_dir(RUN_ID) / "shipment.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            expected_bindings,
            (
                persisted["forgeExecutable"],
                persisted["bodySha256"],
                persisted["publicationPayloadSha256"],
            ),
        )

    def test_push_only_retry_rejects_pr_bindings_after_failed_push(self) -> None:
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )

        def fail_push(
            argv: Sequence[str], *, cwd: Path, input_text: str | None = None
        ) -> CommandResult:
            values = tuple(argv)
            if "push" in values:
                return CommandResult(values, 1, "", "rejected")
            return self.remote.runner(values, cwd=cwd, input_text=input_text)

        with self.assertRaisesRegex(PreconditionError, "authorized push failed"):
            reconcile_push(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                inspect_remote=self.remote.inspect,
                publication_requested=True,
                final_gate=self._gate_evidence,
                push_only=False,
                title="Crossforge run",
                body="Evidence",
                draft=False,
                forge_identity=self.forge_identity,
                runner=fail_push,
            )
        persisted = json.loads(
            (self.store.run_dir(RUN_ID) / "shipment.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIsNotNone(persisted["forgeExecutable"])
        self.assertIsNotNone(persisted["bodySha256"])
        self.assertIsNotNone(persisted["publicationPayloadSha256"])
        with self.assertRaisesRegex(
            StateInconsistencyError, "PR publication bindings"
        ):
            reconcile_push(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                inspect_remote=self.remote.inspect,
                publication_requested=True,
                final_gate=self._gate_evidence,
                push_only=True,
                runner=self.remote.runner,
            )

    def test_record_push_only_rejects_prepared_pr_bindings(self) -> None:
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        reconcile_push(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            publication_requested=True,
            final_gate=self._gate_evidence,
            push_only=False,
            title="Crossforge run",
            body="Evidence",
            draft=False,
            forge_identity=self.forge_identity,
            runner=self.remote.runner,
        )
        with self.assertRaisesRegex(
            StateInconsistencyError, "PR publication bindings"
        ):
            record_shipment(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                inspect_remote=self.remote.inspect,
                push_only=True,
                publication_requested=True,
                runner=self.remote.runner,
            )
        self.assertEqual(self.store.mark_calls, 0)

    def test_first_shot_push_only_shipment_still_completes(self) -> None:
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        pushed = reconcile_push(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            publication_requested=True,
            final_gate=self._gate_evidence,
            push_only=True,
            runner=self.remote.runner,
        )
        completed = record_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            push_only=True,
            publication_requested=True,
            runner=self.remote.runner,
        )
        self.assertIsNone(pushed["forgeExecutable"])
        self.assertIsNone(pushed["bodySha256"])
        self.assertIsNone(pushed["publicationPayloadSha256"])
        self.assertEqual(completed["status"], "push_only_recorded")
        self.assertEqual(self.store.mark_calls, 1)

    def test_terminal_push_only_shipment_cannot_acquire_pr_bindings(self) -> None:
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        reconcile_push(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            publication_requested=True,
            final_gate=self._gate_evidence,
            push_only=True,
            runner=self.remote.runner,
        )
        record_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            push_only=True,
            publication_requested=True,
            runner=self.remote.runner,
        )
        with self.assertRaisesRegex(
            StateInconsistencyError, "terminal push-only shipment"
        ):
            reconcile_push(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                inspect_remote=self.remote.inspect,
                publication_requested=True,
                final_gate=self._gate_evidence,
                push_only=False,
                title="Crossforge run",
                body="Evidence",
                draft=False,
                forge_identity=self.forge_identity,
                runner=self.remote.runner,
            )
        persisted = json.loads(
            (self.store.run_dir(RUN_ID) / "shipment.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIsNone(persisted["forgeExecutable"])
        self.assertIsNone(persisted["bodySha256"])
        self.assertIsNone(persisted["publicationPayloadSha256"])

    def test_incomplete_pr_publication_bindings_fail_closed(self) -> None:
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        shipment_path = self.store.run_dir(RUN_ID) / "shipment.json"
        shipment = json.loads(shipment_path.read_text(encoding="utf-8"))
        shipment["bodySha256"] = "a" * 64
        shipment_path.write_text(json.dumps(shipment), encoding="utf-8")
        with self.assertRaisesRegex(
            StateInconsistencyError, "PR publication bindings are incomplete"
        ):
            reconcile_push(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                inspect_remote=self.remote.inspect,
                publication_requested=True,
                final_gate=self._gate_evidence,
                push_only=True,
                runner=self.remote.runner,
            )
        self.assertEqual(self.remote.push_calls, 0)

    def test_existing_remote_and_pr_are_discovered(self) -> None:
        self.remote.head = self.commit
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        pushed = reconcile_push(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            publication_requested=True,
            final_gate=self._gate_evidence,
            push_only=False,
            title="ignored",
            body="ignored",
            draft=False,
            forge_identity=self.forge_identity,
            runner=self.remote.runner,
        )
        self.assertEqual(pushed["push"]["result"], "discovered")
        self.gh_state.write_text(
            json.dumps(
                {
                    "createCalls": 0,
                    "listCalls": 0,
                    "prs": [
                        {
                            "number": 7,
                            "url": "https://github.com/example/crossforge-test/pull/7",
                            "state": "CLOSED",
                            "headRefName": "crossforge/test",
                            "baseRefName": "main",
                            "headRefOid": self.commit,
                            "isCrossRepository": False,
                            "headRepositoryOwner": {"login": "example"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        pr = reconcile_pull_request(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            title="ignored",
            body="ignored",
            draft=False,
            publication_requested=True,
            final_gate=self._gate_evidence,
            forge_identity=self.forge_identity,
            runner=self._gh_runner,
        )
        self.assertEqual(pr["pullRequest"]["result"], "discovered")
        self.assertEqual(self._gh_data()["createCalls"], 0)

    def test_cross_repository_pull_request_readback_is_rejected(self) -> None:
        self.remote.head = self.commit
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        reconcile_push(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            publication_requested=True,
            final_gate=self._gate_evidence,
            push_only=False,
            title="Crossforge run",
            body="Evidence",
            draft=False,
            forge_identity=self.forge_identity,
            runner=self.remote.runner,
        )
        self.gh_state.write_text(
            json.dumps(
                {
                    "createCalls": 0,
                    "listCalls": 0,
                    "prs": [
                        {
                            "number": 8,
                            "url": "https://github.com/example/crossforge-test/pull/8",
                            "state": "OPEN",
                            "headRefName": "crossforge/test",
                            "baseRefName": "main",
                            "headRefOid": self.commit,
                            "isCrossRepository": True,
                            "headRepositoryOwner": {"login": "attacker"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(StateInconsistencyError, "not bound"):
            reconcile_pull_request(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                title="Crossforge run",
                body="Evidence",
                draft=False,
                publication_requested=True,
                final_gate=self._gate_evidence,
                forge_identity=self.forge_identity,
                runner=self._gh_runner,
            )

    def test_cancellation_only_before_remote_write(self) -> None:
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        self.assertTrue(
            cancel_shipment(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                inspect_remote=self.remote.inspect,
                inspect_pull_requests=lambda _shipment: (),
            )
        )
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        reconcile_push(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            publication_requested=True,
            final_gate=self._gate_evidence,
            push_only=True,
            runner=self.remote.runner,
        )
        with self.assertRaisesRegex(PreconditionError, "cannot be cancelled"):
            cancel_shipment(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                inspect_remote=self.remote.inspect,
                inspect_pull_requests=lambda _shipment: (),
            )

    def test_remote_pushurl_change_after_authorization_blocks_before_push(self) -> None:
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        self._git(
            "remote",
            "set-url",
            "--add",
            "--push",
            "origin",
            "https://github.com/attacker/redirect.git",
        )
        with self.assertRaisesRegex(
            (PreconditionError, StateInconsistencyError),
            "remote|destinations",
        ):
            reconcile_push(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                inspect_remote=self.remote.inspect,
                publication_requested=True,
                final_gate=self._gate_evidence,
                push_only=True,
                runner=self.remote.runner,
            )
        self.assertEqual(self.remote.push_calls, 0)

    def test_failed_write_time_gate_blocks_before_push(self) -> None:
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        with self.assertRaisesRegex(PreconditionError, "did not pass"):
            reconcile_push(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                inspect_remote=self.remote.inspect,
                publication_requested=True,
                final_gate=lambda run: replace(
                    self._gate_evidence(run), passed=False
                ),
                push_only=True,
                runner=self.remote.runner,
            )
        self.assertEqual(self.remote.push_calls, 0)

    def test_missing_or_expired_write_authority_blocks_before_push(self) -> None:
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        with self.assertRaisesRegex(PreconditionError, "authorize publication"):
            reconcile_push(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                inspect_remote=self.remote.inspect,
                publication_requested=False,
                final_gate=self._gate_evidence,
                push_only=True,
                runner=self.remote.runner,
            )
        shipment_path = self.store.run_dir(RUN_ID) / "shipment.json"
        shipment = json.loads(shipment_path.read_text(encoding="utf-8"))
        authorized = datetime.now(timezone.utc) - timedelta(hours=25)
        shipment["authorizedAt"] = authorized.isoformat().replace("+00:00", "Z")
        shipment["expiresAt"] = (
            authorized + timedelta(hours=24)
        ).isoformat().replace("+00:00", "Z")
        shipment_path.write_text(json.dumps(shipment), encoding="utf-8")
        with self.assertRaisesRegex(PreconditionError, "expired"):
            reconcile_push(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                inspect_remote=self.remote.inspect,
                publication_requested=True,
                final_gate=self._gate_evidence,
                push_only=True,
                runner=self.remote.runner,
            )
        self.assertEqual(self.remote.push_calls, 0)

    def test_pull_request_body_is_private_bounded_and_secret_screened(self) -> None:
        body_root = self.root / "shipping-evidence"
        body_root.mkdir(mode=0o700)
        safe = body_root / "body.md"
        safe.write_text("Summary of independently verified changes.\n", encoding="utf-8")
        safe.chmod(0o600)
        self.assertEqual(
            "Summary of independently verified changes.\n",
            load_pull_request_body(
                safe,
                repository=self.repository,
                deny_paths=("**/.env", "**/*.pem"),
                allowed_root=body_root,
            ),
        )

        secret = body_root / "secret.md"
        secret.write_text(
            "api_key=sk-abcdefghijklmnopqrstuvwxyz012345\n",
            encoding="utf-8",
        )
        secret.chmod(0o600)
        with self.assertRaisesRegex(SecretPolicyError, "secret-like"):
            load_pull_request_body(
                secret,
                repository=self.repository,
                deny_paths=("**/.env",),
                allowed_root=body_root,
            )

        denied = body_root / ".env"
        denied.write_text("ordinary prose\n", encoding="utf-8")
        denied.chmod(0o600)
        with self.assertRaisesRegex(SecretPolicyError, "denied"):
            load_pull_request_body(
                denied,
                repository=self.repository,
                deny_paths=("**/.env",),
                allowed_root=body_root,
            )

        linked = body_root / "linked.md"
        linked.symlink_to(safe)
        with self.assertRaisesRegex(SecretPolicyError, "regular file"):
            load_pull_request_body(
                linked,
                repository=self.repository,
                deny_paths=("**/.env",),
                allowed_root=body_root,
            )
        outside = self.root / "outside.md"
        outside.write_text("quiet private notes\n", encoding="utf-8")
        outside.chmod(0o600)
        with self.assertRaisesRegex(SecretPolicyError, "shipping-evidence"):
            load_pull_request_body(
                outside,
                repository=self.repository,
                deny_paths=("**/.env",),
                allowed_root=body_root,
            )

    def test_forge_executable_replacement_is_rejected(self) -> None:
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        reconcile_push(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            publication_requested=True,
            final_gate=self._gate_evidence,
            push_only=False,
            title="Crossforge run",
            body="Evidence",
            draft=False,
            forge_identity=self.forge_identity,
            runner=self.remote.runner,
        )
        self.fake_gh.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.fake_gh.chmod(0o700)
        with self.assertRaisesRegex(StateInconsistencyError, "changed"):
            reconcile_pull_request(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                title="Crossforge run",
                body="Evidence",
                draft=False,
                publication_requested=True,
                final_gate=self._gate_evidence,
                forge_identity=self.forge_identity,
                runner=self._gh_runner,
            )

    def test_final_gate_must_return_exact_commit_and_policy_bound_evidence(self) -> None:
        with self.assertRaisesRegex(PreconditionError, "invalid evidence"):
            ship_preflight(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                remote=None,
                target_branch=None,
                publication_requested=True,
                dry_run=False,
                final_gate=lambda _run: True,  # type: ignore[return-value]
                inspect_remote=self.remote.inspect,
            )
        evidence = self._gate_evidence(self.run)
        forged = replace(evidence, final_commit="0" * 40)
        with self.assertRaisesRegex(StateInconsistencyError, "not bound"):
            ship_preflight(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                remote=None,
                target_branch=None,
                publication_requested=True,
                dry_run=False,
                final_gate=lambda _run: forged,
                inspect_remote=self.remote.inspect,
            )

    def test_record_shipment_lock_wrapper_is_exclusive(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        calls: list[str] = []
        outcomes: list[object] = []

        def blocked_record(*args: object, **kwargs: object) -> dict[str, str]:
            calls.append("entered")
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("test did not release shipment recorder")
            return {"status": "recorded"}

        def first_call() -> None:
            try:
                outcomes.append(
                    record_shipment(
                        self.store,  # type: ignore[arg-type]
                        self.repository,
                        run_id=RUN_ID,
                        inspect_remote=self.remote.inspect,
                        push_only=True,
                        publication_requested=True,
                        runner=self.remote.runner,
                    )
                )
            except BaseException as exc:
                outcomes.append(exc)

        with patch.object(
            shipping_module,
            "_record_shipment_unlocked",
            side_effect=blocked_record,
        ):
            worker = threading.Thread(target=first_call)
            worker.start()
            self.assertTrue(entered.wait(timeout=5))
            with self.assertRaises(LockHeldError):
                record_shipment(
                    self.store,  # type: ignore[arg-type]
                    self.repository,
                    run_id=RUN_ID,
                    inspect_remote=self.remote.inspect,
                    push_only=True,
                    publication_requested=True,
                    runner=self.remote.runner,
                )
            self.assertEqual(["entered"], calls)
            release.set()
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertEqual([{"status": "recorded"}], outcomes)
            retry = record_shipment(
                self.store,  # type: ignore[arg-type]
                self.repository,
                run_id=RUN_ID,
                inspect_remote=self.remote.inspect,
                push_only=True,
                publication_requested=True,
                runner=self.remote.runner,
            )
            self.assertEqual("recorded", retry["status"])
            self.assertEqual(["entered", "entered"], calls)

    def test_record_shipment_retry_finishes_run_after_transition_crash(self) -> None:
        authorize_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            self._plan(),
            idempotency_key=KEY,
            publication_requested=True,
        )
        reconcile_push(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            publication_requested=True,
            final_gate=self._gate_evidence,
            push_only=True,
            runner=self.remote.runner,
        )
        with patch.object(
            self.store,
            "mark_shipped_in_transaction",
            side_effect=OSError("simulated transition crash"),
        ):
            with self.assertRaisesRegex(OSError, "simulated transition crash"):
                record_shipment(
                    self.store,  # type: ignore[arg-type]
                    self.repository,
                    run_id=RUN_ID,
                    inspect_remote=self.remote.inspect,
                    push_only=True,
                    publication_requested=True,
                    runner=self.remote.runner,
                )

        shipment_path = self.store.run_dir(RUN_ID) / "shipment.json"
        interrupted = json.loads(shipment_path.read_text(encoding="utf-8"))
        self.assertEqual("push_only_recorded", interrupted["status"])
        self.assertEqual("complete", self.store._run["status"])

        recovered = record_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            push_only=True,
            publication_requested=True,
            runner=self.remote.runner,
        )
        self.assertEqual("shipped", self.store._run["status"])
        self.assertEqual(interrupted["completedAt"], recovered["completedAt"])
        self.assertEqual(1, self.store.mark_calls)
        repeated = record_shipment(
            self.store,  # type: ignore[arg-type]
            self.repository,
            run_id=RUN_ID,
            inspect_remote=self.remote.inspect,
            push_only=True,
            publication_requested=True,
            runner=self.remote.runner,
        )
        self.assertEqual(recovered["completedAt"], repeated["completedAt"])
        self.assertEqual(2, self.store.mark_calls)


if __name__ == "__main__":
    unittest.main()
