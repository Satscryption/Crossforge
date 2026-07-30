from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT_ROOT / "skills" / "crossforge" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import crossforge as crossforge_cli  # noqa: E402
from crossforge_lib.config import load_config  # noqa: E402
from crossforge_lib.consent import deny_policy_hash, record_consent  # noqa: E402
from crossforge_lib.errors import InvalidInputError, PreconditionError  # noqa: E402
from crossforge_lib.gates import ProbeCheck, SandboxProbeResult  # noqa: E402
from crossforge_lib.git import (  # noqa: E402
    discover_repository,
    repository_identity,
    resolve_commit,
)
from crossforge_lib.models import ProviderStatus  # noqa: E402
from crossforge_lib.plan import load_plan, materialize_tasks, plan_sha256  # noqa: E402
from crossforge_lib.providers.base import (  # noqa: E402
    CapabilityProbe,
    ProviderInvocation,
    ProviderProbe,
)
from crossforge_lib.providers.codex_cli import CodexCLIAdapter  # noqa: E402
from crossforge_lib.reports import load_provider_report  # noqa: E402
from crossforge_lib.secrets import DETECTOR_NAMES  # noqa: E402
from crossforge_lib.shipping import RemoteReadback  # noqa: E402
from crossforge_lib.state import StateStore, generate_run_id  # noqa: E402
from crossforge_lib.util import (  # noqa: E402
    atomic_write_bytes,
    atomic_write_json,
    sha256_file,
    utc_now,
)
from crossforge_lib.worktrees import WorktreeManager  # noqa: E402


def git(cwd: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def invoke_cli(*arguments: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            result = crossforge_cli.main(list(arguments))
        except SystemExit as error:
            result = int(error.code)
    return int(result), stdout.getvalue(), stderr.getvalue()


def canonical_plan(*, title: str = "CLI regression", allowed: list[str] | None = None) -> dict:
    return {
        "schemaVersion": 1,
        "title": title,
        "objective": "Exercise the deterministic CLI boundary.",
        "userVisibleOutcome": "The boundary is enforced.",
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
                "argv": ["python3", "-m", "unittest", "discover", "-s", "tests"],
                "timeoutSeconds": 900,
            }
        ],
        "tasks": [
            {
                "id": "T1",
                "title": "CLI task",
                "risk": "low",
                "taskClass": "mechanical",
                "dependsOn": [],
                "suggestedStrategy": "auto",
                "allowedFiles": allowed or ["app.txt"],
                "objective": "Change the approved file.",
                "interfaces": [],
                "constraints": [],
                "approvedBinaryContext": [],
                "approvedSymlinks": [],
                "verificationCommands": [
                    {"argv": ["python3", "-m", "unittest"], "timeoutSeconds": 900}
                ],
                "doneWhen": ["The approved verification command passes."],
            }
        ],
        "decisionLog": [],
        "deferredWork": [],
    }


def runtime_task(
    commit: str,
    *,
    task_id: str = "T1",
    status: str = "pending",
    selected: str | None = None,
    allowed: list[str] | None = None,
) -> dict:
    task = materialize_tasks(
        load_plan_value(canonical_plan(allowed=allowed)),
        base_commit=commit,
        timestamp="2026-07-24T12:00:00Z",
    )["tasks"][0]
    task["id"] = task_id
    task["title"] = f"Task {task_id}"
    task["status"] = status
    task["selectedCandidate"] = selected
    task["commit"] = commit if status in {"committed", "complete"} else None
    return task


def load_plan_value(value: dict):
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "plan.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return load_plan(path)


def run_record(
    repository: Path,
    common: Path,
    run_id: str,
    plan: dict,
    commit: str,
    *,
    active_task: str | None = None,
    completed_tasks: list[str] | None = None,
) -> dict:
    run_directory = common / "crossforge" / "runs" / run_id
    digest = plan_sha256(load_plan_value(plan))
    branch = git(repository, "branch", "--show-current").stdout.decode().strip()
    return {
        "schemaVersion": 1,
        "runId": run_id,
        "status": "active",
        "mode": "build",
        "repositoryRoot": str(repository),
        "repositoryIdentity": "1" * 64,
        "gitCommonDir": str(common),
        "orchestrationGitDir": str(common),
        "branch": branch,
        "branchCreatedByCrossforge": True,
        "targetRemote": "origin",
        "targetBranch": "main",
        "defaultBranch": "main",
        "startCommit": commit,
        "currentCommit": commit,
        "planJsonPath": str(run_directory / "plan.json"),
        "planMarkdownPath": str(run_directory / "plan.md"),
        "planSha256": digest,
        "planApproval": {
            "approved": True,
            "approvedBy": "user",
            "approvedAt": "2026-07-24T12:00:00Z",
            "approvedPlanSha256": digest,
        },
        "globalVerificationCommands": plan["globalVerificationCommands"],
        "budget": "balanced",
        "maximumProviderInvocationsPerTask": 6,
        "strategy": "auto",
        "noCommit": False,
        "keepWorktrees": False,
        "gateSandbox": {
            "backend": "bwrap",
            "network": "deny",
            "probeVersion": "fake-1",
        },
        "providers": {},
        "activeTaskId": active_task,
        "completedTaskIds": completed_tasks or [],
        "blockedReason": None,
        "createdAt": "2026-07-24T12:00:00Z",
        "updatedAt": "2026-07-24T12:00:00Z",
        "completedAt": None,
    }


class CLITestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repository = self.root / "repository"
        self.repository.mkdir()
        git(self.repository, "init", "-b", "main")
        git(self.repository, "config", "user.name", "Crossforge Test")
        git(self.repository, "config", "user.email", "test@invalid")
        (self.repository / "app.txt").write_text("base\n", encoding="utf-8")
        (self.repository / "extra.txt").write_text("base extra\n", encoding="utf-8")
        git(self.repository, "add", "app.txt", "extra.txt")
        git(self.repository, "commit", "-m", "base")
        self.discovered = discover_repository(self.repository)
        self.common = self.discovered.common_git_dir
        self.commit = resolve_commit(self.discovered, "HEAD")

    def seed_state(
        self,
        *,
        tasks: list[dict],
        active_task: str | None = None,
        completed_tasks: list[str] | None = None,
        plan: dict | None = None,
    ) -> tuple[StateStore, str]:
        if plan is None:
            approved = canonical_plan()
            policy_fields = (
                "id",
                "title",
                "risk",
                "taskClass",
                "dependsOn",
                "suggestedStrategy",
                "allowedFiles",
                "objective",
                "interfaces",
                "constraints",
                "approvedBinaryContext",
                "approvedSymlinks",
                "verificationCommands",
                "doneWhen",
            )
            approved["tasks"] = [
                {field: task[field] for field in policy_fields}
                for task in tasks
            ]
        else:
            approved = plan
        run_id = generate_run_id()
        store = StateStore(self.common)
        run = run_record(
            self.repository,
            self.common,
            run_id,
            approved,
            self.commit,
            active_task=active_task,
            completed_tasks=completed_tasks,
        )
        store.initialize_run(
            run,
            plan=approved,
            plan_markdown="# Plan\n",
            tasks={"schemaVersion": 1, "tasks": tasks},
        )
        return store, run_id


class ApprovalAndStateCLIRegressionTests(CLITestCase):
    def test_init_run_rejects_plan_hash_mismatch_before_state_mutation(self) -> None:
        approved = canonical_plan(title="Approved bytes")
        supplied = canonical_plan(title="Different bytes")
        run_id = generate_run_id()
        run = run_record(
            self.repository, self.common, run_id, approved, self.commit
        )
        run_path = self.root / "run.json"
        plan_path = self.root / "different-plan.json"
        run_path.write_text(json.dumps(run), encoding="utf-8")
        plan_path.write_text(json.dumps(supplied), encoding="utf-8")

        code, _stdout, _stderr = invoke_cli(
            "init-run",
            "--git-common-dir",
            str(self.common),
            "--run-json",
            str(run_path),
            "--plan",
            str(plan_path),
            "--json",
        )

        self.assertNotEqual(0, code)
        self.assertFalse(
            (self.common / "crossforge" / "runs" / run_id).exists(),
            "plan mismatch must block before any run directory is created",
        )
        self.assertFalse((self.common / "crossforge" / "active").exists())

    def test_finish_wrong_active_task_is_failure_atomic(self) -> None:
        tasks = [
            runtime_task(self.commit, task_id="T1", status="in_progress"),
            runtime_task(self.commit, task_id="T2", status="committed"),
        ]
        store, run_id = self.seed_state(tasks=tasks, active_task="T1")
        tasks_path = store.run_dir(run_id) / "tasks.json"
        run_path = store.run_dir(run_id) / "run.json"
        before_tasks = tasks_path.read_bytes()
        before_run = run_path.read_bytes()
        request = self.root / "finish.json"
        request.write_text(
            json.dumps(
                {
                    "gitCommonDir": str(self.common),
                    "runId": run_id,
                    "taskId": "T2",
                }
            ),
            encoding="utf-8",
        )

        code, _stdout, _stderr = invoke_cli(
            "finish-task", "--request", str(request), "--json"
        )

        self.assertNotEqual(0, code)
        self.assertEqual(before_tasks, tasks_path.read_bytes())
        self.assertEqual(before_run, run_path.read_bytes())

    def test_malformed_request_is_json_exit_two_without_traceback(self) -> None:
        request = self.root / "malformed.json"
        request.write_text('{"runId":', encoding="utf-8")

        code, stdout, stderr = invoke_cli(
            "finish-task", "--request", str(request), "--json"
        )

        self.assertEqual(2, code)
        payload = json.loads(stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(2, payload["exitCode"])
        self.assertNotIn("Traceback", stdout + stderr)
        self.assertEqual("", stderr)


class ProviderBoundaryCLIRegressionTests(CLITestCase):
    def test_valid_invoke_is_consent_bound_and_writes_verified_report(self) -> None:
        task = runtime_task(self.commit, status="in_progress")
        store, run_id = self.seed_state(tasks=[task], active_task="T1")
        run = store.load_run(run_id)
        identity = repository_identity(self.discovered)
        run["repositoryIdentity"] = identity
        atomic_write_json(store.run_dir(run_id) / "run.json", run)

        worktree_root = self.root / "worktrees"
        registry = store.run_dir(run_id) / "worktrees.json"
        atomic_write_json(
            registry,
            {
                "schemaVersion": 1,
                "worktreeRoot": str(worktree_root.resolve()),
                "entries": [],
            },
        )
        manager = WorktreeManager(
            self.repository,
            worktree_root,
            registry,
            repository_id_prefix=identity[:12],
        )
        candidate = manager.create(
            run_id=run_id,
            task_id="T1",
            provider="codex",
            base_commit=self.commit,
            evidence_dir=store.run_dir(run_id) / "evidence" / "T1" / "worktree",
        )

        executable = Path(sys.executable).resolve()
        capability = (
            store.run_dir(run_id)
            / "evidence"
            / "preflight"
            / "codex-capability.json"
        )
        managed_hash = "b" * 64
        capability_record = {
            "schemaVersion": 2,
            "producer": crossforge_cli.CAPABILITY_PRODUCER_ID,
            "provider": "codex",
            "sourceFree": True,
            "recordedAt": utc_now(),
            "executablePath": str(executable),
            "executableSha256": sha256_file(executable),
            "sandboxPolicySha256": crossforge_cli.provider_sandbox_policy_sha256(
                "codex"
            ),
            "managedPolicySha256": managed_hash,
            "probeContractSha256": (
                crossforge_cli.provider_capability_contract_sha256()
            ),
            "probeResultSha256": "d" * 64,
            "message": "all boundaries proven",
            "sandboxEnforced": True,
            "networkDenied": True,
            "outsideWriteDenied": True,
            "credentialReadDenied": True,
            "orchestrationReadDenied": True,
            "gitCommonDirReadDenied": True,
            "outsideSentinelReadDenied": True,
            "finalOutputProtected": True,
            "conclusive": True,
        }
        config = load_config()
        deny_hash = deny_policy_hash(
            config.deny_paths,
            DETECTOR_NAMES,
            (),
            crossforge_cli._CONTEXT_POLICY,
        )
        record_consent(
            store.root / "consent.json",
            repository_identity=identity,
            provider="codex",
            operation_classes=["implement", "probe"],
            deny_policy_sha256=deny_hash,
            managed_policy_sha256=managed_hash,
            provider_executable_path=str(executable),
            provider_executable_sha256=sha256_file(executable),
            ttl_days=90,
        )
        with mock.patch.object(
            crossforge_cli,
            "produce_provider_capability",
            return_value=capability_record,
        ), mock.patch.object(
            crossforge_cli,
            "resolve_provider_executable",
            return_value=(executable, sha256_file(executable)),
        ), mock.patch.object(
            crossforge_cli.shutil,
            "which",
            return_value=str(executable),
        ):
            code, stdout, stderr = invoke_cli(
                "record-capability",
                "--repository",
                str(self.repository),
                "--git-common-dir",
                str(self.common),
                "--run-id",
                run_id,
                "--provider",
                "codex",
                "--managed-policy-sha256",
                managed_hash,
                "--json",
            )
        self.assertEqual(0, code, stdout + stderr)
        store.record_task_routing(
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
        class FakeAdapter:
            def probe(self, requested_model: str, effort: str) -> ProviderProbe:
                return ProviderProbe(
                    provider="codex",
                    available=True,
                    cli_path=str(executable),
                    cli_version="fake-1",
                    authenticated=True,
                    requested_model=requested_model,
                    resolved_model="fake-model",
                    effort=effort,
                    capability_probe=CapabilityProbe(
                        True, True, True, True, True, True, True, True
                    ),
                )

            def implement(
                self,
                *,
                spec_path: Path,
                worktree: Path,
                requested_model: str,
                effort: str,
                timeout_seconds: int,
                final_output_path: Path,
            ) -> ProviderInvocation:
                self.assert_spec = spec_path.read_text(encoding="utf-8")
                (worktree / "app.txt").write_text("provider change\n", encoding="utf-8")
                stdout = final_output_path.parent / "stdout.raw"
                stderr = final_output_path.parent / "stderr.raw"
                atomic_write_bytes(stdout, b"completed\n")
                atomic_write_bytes(stderr, b"")
                atomic_write_bytes(final_output_path, b"done\n")
                return ProviderInvocation(
                    provider="codex",
                    status=ProviderStatus.COMPLETE,
                    requested_model=requested_model,
                    resolved_model="fake-model",
                    argv=("fake-codex", "exec"),
                    exit_code=0,
                    timed_out=False,
                    duration_ms=5,
                    raw_stdout_path=stdout,
                    raw_stderr_path=stderr,
                    final_output_path=final_output_path,
                    message="completed",
                )

        request = self.root / "invoke.json"
        atomic_write_json(
            request,
            {
                "schemaVersion": 1,
                "repository": str(self.repository),
                "gitCommonDir": str(self.common),
                "worktreeRoot": str(worktree_root),
                "registry": str(registry),
                "runId": run_id,
                "taskId": "T1",
                "operation": "implement",
                "denyPolicySha256": deny_hash,
                "managedPolicySha256": managed_hash,
                "lanes": [
                    {
                        "provider": "codex",
                        "candidatePath": str(candidate.path),
                        "capabilityEvidence": str(capability),
                        "requestedModel": "auto",
                        "effort": "high",
                        "timeoutSeconds": 60,
                        "executable": str(executable),
                    }
                ],
            },
        )

        with mock.patch.object(
            crossforge_cli, "_provider_adapter", return_value=FakeAdapter()
        ):
            code, stdout, stderr = invoke_cli(
                "invoke", "--request", str(request), "--json"
            )

        self.assertEqual(0, code, stdout + stderr)
        result = json.loads(stdout)["result"]["lanes"][0]
        report = load_provider_report(result["reportPath"])
        self.assertEqual("complete", report.status)
        self.assertEqual(["app.txt"], [item["path"] for item in report.data["changedFiles"]])
        self.assertEqual(1, store.load_tasks(run_id)["tasks"][0]["attempts"]["codex"])
        self.assertTrue((candidate.path / ".git").is_file())
        self.assertEqual("provider change\n", (candidate.path / "app.txt").read_text())

    def test_forged_capability_cannot_invoke_without_durable_boundary(self) -> None:
        worktree = self.root / "candidate"
        git(self.repository, "worktree", "add", "--detach", str(worktree), self.commit)
        self.addCleanup(
            lambda: subprocess.run(
                ["git", "worktree", "remove", "--force", str(worktree)],
                cwd=self.repository,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        )
        spec = self.root / "task-brief.md"
        spec.write_text("PRIVATE_SOURCE_SENTINEL\n", encoding="utf-8")
        capability = self.root / "forged-capability.json"
        capability.write_text(
            json.dumps(
                {
                    "sandboxEnforced": True,
                    "networkDenied": True,
                    "outsideWriteDenied": True,
                    "credentialReadDenied": True,
                    "orchestrationReadDenied": True,
                    "gitCommonDirReadDenied": True,
                    "outsideSentinelReadDenied": True,
                    "finalOutputProtected": True,
                }
            ),
            encoding="utf-8",
        )
        argv_log = self.root / "provider-argv.json"
        final_output = self.root / "evidence" / "final.txt"
        fake_codex = PROJECT_ROOT / "tests" / "fixtures" / "fake_codex.py"

        with mock.patch.dict(
            os.environ, {"FAKE_ARGV_LOG": str(argv_log)}, clear=False
        ):
            code, _stdout, _stderr = invoke_cli(
                "invoke",
                "--provider",
                "codex",
                "--operation",
                "implement",
                "--spec",
                str(spec),
                "--worktree",
                str(worktree),
                "--final-output",
                str(final_output),
                "--capability-evidence",
                str(capability),
                "--executable",
                str(fake_codex),
                "--json",
            )

        self.assertNotEqual(0, code)
        self.assertFalse(final_output.exists())
        if argv_log.exists():
            self.assertNotEqual("exec", json.loads(argv_log.read_text())[0])
        self.assertTrue(
            (worktree / ".git").is_file(),
            "a rejected invocation must leave the linked-worktree control file intact",
        )

    def test_record_capability_rejects_caller_authored_evidence(self) -> None:
        forged = self.root / "caller-authored-capability.json"
        forged.write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "producer": crossforge_cli.CAPABILITY_PRODUCER_ID,
                    "provider": "codex",
                    "sandboxEnforced": True,
                    "conclusive": True,
                }
            ),
            encoding="utf-8",
        )

        code, stdout, stderr = invoke_cli(
            "record-capability",
            "--git-common-dir",
            str(self.common),
            "--run-id",
            "20260724T120000Z-1234abcd",
            "--provider",
            "codex",
            "--managed-policy-sha256",
            "a" * 64,
            "--evidence",
            str(forged),
            "--json",
        )

        self.assertEqual(2, code)
        self.assertIn("unrecognized arguments: --evidence", stdout + stderr)

    def test_record_capability_rejects_executable_override(self) -> None:
        code, stdout, stderr = invoke_cli(
            "record-capability",
            "--repository",
            str(self.repository),
            "--git-common-dir",
            str(self.common),
            "--run-id",
            "20260724T120000Z-1234abcd",
            "--provider",
            "codex",
            "--managed-policy-sha256",
            "a" * 64,
            "--executable",
            str(self.root / "caller-provider"),
            "--json",
        )

        self.assertEqual(2, code)
        self.assertIn("unrecognized arguments: --executable", stdout + stderr)

    def test_failed_producer_result_is_never_durably_bound(self) -> None:
        store, run_id = self.seed_state(
            tasks=[runtime_task(self.commit)],
            active_task=None,
        )
        executable = Path(sys.executable).resolve()
        identity = repository_identity(self.discovered)
        config = load_config()
        deny_hash = deny_policy_hash(
            config.deny_paths,
            DETECTOR_NAMES,
            (),
            crossforge_cli._CONTEXT_POLICY,
        )
        record_consent(
            store.root / "consent.json",
            repository_identity=identity,
            provider="codex",
            operation_classes=["probe"],
            deny_policy_sha256=deny_hash,
            managed_policy_sha256="b" * 64,
            provider_executable_path=str(executable),
            provider_executable_sha256=sha256_file(executable),
            ttl_days=90,
        )
        failed = {
            "schemaVersion": 2,
            "producer": crossforge_cli.CAPABILITY_PRODUCER_ID,
            "provider": "codex",
            "sourceFree": True,
            "recordedAt": utc_now(),
            "executablePath": str(executable),
            "executableSha256": sha256_file(executable),
            "sandboxPolicySha256": crossforge_cli.provider_sandbox_policy_sha256(
                "codex"
            ),
            "managedPolicySha256": "b" * 64,
            "probeContractSha256": (
                crossforge_cli.provider_capability_contract_sha256()
            ),
            "probeResultSha256": "d" * 64,
            "message": "credential read escaped",
            "sandboxEnforced": True,
            "networkDenied": True,
            "outsideWriteDenied": True,
            "credentialReadDenied": False,
            "orchestrationReadDenied": True,
            "gitCommonDirReadDenied": True,
            "outsideSentinelReadDenied": True,
            "finalOutputProtected": True,
            "conclusive": True,
        }
        with mock.patch.object(
            crossforge_cli,
            "produce_provider_capability",
            return_value=failed,
        ), mock.patch.object(
            crossforge_cli,
            "resolve_provider_executable",
            return_value=(executable, sha256_file(executable)),
        ), mock.patch.object(
            crossforge_cli.shutil,
            "which",
            return_value=str(executable),
        ):
            code, _stdout, _stderr = invoke_cli(
                "record-capability",
                "--repository",
                str(self.repository),
                "--git-common-dir",
                str(self.common),
                "--run-id",
                run_id,
                "--provider",
                "codex",
                "--managed-policy-sha256",
                "b" * 64,
                "--json",
            )

        self.assertNotEqual(0, code)
        self.assertFalse(
            (
                store.run_dir(run_id)
                / "evidence"
                / "preflight"
                / "codex-capability.json"
            ).exists()
        )

    def test_capability_probe_requires_consent_before_external_call(self) -> None:
        store, run_id = self.seed_state(
            tasks=[runtime_task(self.commit)],
            active_task=None,
        )
        producer = mock.Mock()

        with mock.patch.object(
            crossforge_cli,
            "produce_provider_capability",
            producer,
        ):
            code, _stdout, _stderr = invoke_cli(
                "record-capability",
                "--repository",
                str(self.repository),
                "--git-common-dir",
                str(self.common),
                "--run-id",
                run_id,
                "--provider",
                "codex",
                "--managed-policy-sha256",
                "b" * 64,
                "--json",
            )

        self.assertNotEqual(0, code)
        producer.assert_not_called()
        self.assertFalse(
            (
                store.run_dir(run_id)
                / "evidence"
                / "preflight"
                / "codex-capability.json"
            ).exists()
        )

    def test_legacy_capability_schema_is_not_accepted_as_proof(self) -> None:
        executable = Path(sys.executable).resolve()
        legacy = {
            "schemaVersion": 1,
            "provider": "codex",
            "sourceFree": True,
            "recordedAt": utc_now(),
            "executablePath": str(executable),
            "executableSha256": sha256_file(executable),
            "sandboxPolicySha256": "a" * 64,
            "managedPolicySha256": "b" * 64,
            "message": "caller says every boundary passed",
            "sandboxEnforced": True,
            "networkDenied": True,
            "outsideWriteDenied": True,
            "credentialReadDenied": True,
            "orchestrationReadDenied": True,
            "gitCommonDirReadDenied": True,
            "outsideSentinelReadDenied": True,
            "finalOutputProtected": True,
            "conclusive": True,
        }
        path = self.root / "legacy-capability.json"
        atomic_write_json(path, legacy)

        with self.assertRaisesRegex(
            InvalidInputError, "missing or unknown fields"
        ):
            crossforge_cli._capability_record(
                str(path),
                provider="codex",
                executable=str(executable),
            )

    def test_stale_probe_contract_or_policy_is_not_accepted(self) -> None:
        executable = Path(sys.executable).resolve()
        record = {
            "schemaVersion": 2,
            "producer": crossforge_cli.CAPABILITY_PRODUCER_ID,
            "provider": "codex",
            "sourceFree": True,
            "recordedAt": utc_now(),
            "executablePath": str(executable),
            "executableSha256": sha256_file(executable),
            "sandboxPolicySha256": (
                crossforge_cli.provider_sandbox_policy_sha256("codex")
            ),
            "managedPolicySha256": "b" * 64,
            "probeContractSha256": (
                crossforge_cli.provider_capability_contract_sha256()
            ),
            "probeResultSha256": "d" * 64,
            "message": "all boundaries proven",
            "sandboxEnforced": True,
            "networkDenied": True,
            "outsideWriteDenied": True,
            "credentialReadDenied": True,
            "orchestrationReadDenied": True,
            "gitCommonDirReadDenied": True,
            "outsideSentinelReadDenied": True,
            "finalOutputProtected": True,
            "conclusive": True,
        }
        for field in ("probeContractSha256", "sandboxPolicySha256"):
            with self.subTest(field=field):
                changed = dict(record)
                changed[field] = "f" * 64
                with self.assertRaisesRegex(
                    PreconditionError, "different"
                ):
                    crossforge_cli._validate_capability_record(
                        changed,
                        provider="codex",
                        executable=str(executable),
                    )

    def test_source_free_provider_probe_excludes_repository_and_source(self) -> None:
        log = self.root / "probe.jsonl"
        executable = self.root / "fake-codex-probe"
        executable.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import json
                import os
                import pathlib
                import sys

                args = sys.argv[1:]
                stdin = sys.stdin.read()
                with pathlib.Path(os.environ["PROBE_LOG"]).open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"argv": args, "cwd": os.getcwd(), "stdin": stdin}) + "\\n")
                if args == ["--version"]:
                    print("codex 1.2.3")
                    raise SystemExit(0)
                if args == ["login", "status"]:
                    print("authenticated")
                    raise SystemExit(0)
                if args and args[0] == "exec":
                    destination = pathlib.Path(args[args.index("--output-last-message") + 1])
                    destination.write_text("named-model", encoding="utf-8")
                    print("{}")
                    raise SystemExit(0)
                raise SystemExit(2)
                """
            ),
            encoding="utf-8",
        )
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        secret = self.repository / "source-secret.txt"
        secret.write_text("REPOSITORY_SOURCE_MUST_NOT_ENTER_PROBE\n", encoding="utf-8")
        environment = dict(os.environ)
        environment["PROBE_LOG"] = str(log)
        adapter = CodexCLIAdapter(
            executable=str(executable),
            env=environment,
            capability_source=lambda _mode: CapabilityProbe(
                True, True, True, True, True, True, True, True
            ),
        )

        result = adapter.probe("named-model", "high")

        self.assertTrue(result.available, result.to_dict())
        records = [
            json.loads(line)
            for line in log.read_text(encoding="utf-8").splitlines()
        ]
        remote = next(item for item in records if item["argv"][:1] == ["exec"])
        self.assertEqual(
            "Crossforge source-free readiness probe. Reply with the exact active model identifier only.",
            remote["stdin"],
        )
        serialized = json.dumps(remote)
        self.assertNotIn(str(self.repository), serialized)
        self.assertNotIn(secret.name, serialized)
        self.assertNotIn("REPOSITORY_SOURCE_MUST_NOT_ENTER_PROBE", serialized)


class AcceptanceAndShippingCLIRegressionTests(CLITestCase):
    def test_main_and_shipping_command_surfaces_are_disjoint(self) -> None:
        main_parser = crossforge_cli.build_parser()
        ship_parser = crossforge_cli.build_shipping_parser()
        main_choices = set(main_parser._subparsers._group_actions[0].choices)
        ship_choices = set(ship_parser._subparsers._group_actions[0].choices)

        self.assertEqual(set(crossforge_cli.SHIPPING_COMMANDS), ship_choices)
        self.assertTrue(main_choices.isdisjoint(ship_choices))
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                main_parser.parse_args(["record-shipment", "--run-id", "invalid"])
            with self.assertRaises(SystemExit):
                ship_parser.parse_args(["status"])

    def test_accept_candidate_rejects_scope_and_gate_overrides(self) -> None:
        task = runtime_task(
            self.commit,
            status="candidate_ready",
            selected="codex",
            allowed=["app.txt"],
        )
        store, run_id = self.seed_state(tasks=[task], active_task="T1")
        registry = self.root / "candidate-state" / "worktrees.json"
        manager = WorktreeManager(
            self.repository,
            self.root / "worktrees",
            registry,
            repository_id_prefix="cli",
        )
        candidate = manager.create(
            run_id=run_id,
            task_id="T1",
            provider="codex",
            base_commit=self.commit,
            evidence_dir=self.root / "candidate-evidence",
        )
        (candidate.path / "extra.txt").write_text("unapproved\n", encoding="utf-8")
        patch_path = self.root / "candidate-evidence" / "candidate.patch"
        candidate = manager.capture_patch(candidate, patch_path)
        request = self.root / "accept.json"
        request.write_text(
            json.dumps(
                {
                    "repository": str(self.repository),
                    "worktreeRoot": str(manager.worktree_root),
                    "registry": str(registry),
                    "repositoryIdPrefix": "cli",
                    "gitCommonDir": str(self.common),
                    "runId": run_id,
                    "taskId": "T1",
                    "candidatePath": str(candidate.path),
                    "patchPath": str(patch_path),
                    "evidenceRoot": str(self.root / "acceptance-evidence"),
                    "commitMessage": "fix: bypass attempt",
                    "allowlist": ["app.txt", "extra.txt"],
                    "gateCommands": [
                        {"argv": ["true"], "timeoutSeconds": 10}
                    ],
                    "gateSandbox": {},
                }
            ),
            encoding="utf-8",
        )
        fake_result = SimpleNamespace(
            commit=None,
            to_dict=lambda: {"commit": None},
        )

        with mock.patch.object(
            crossforge_cli, "perform_acceptance", return_value=fake_result
        ) as acceptance:
            code, _stdout, _stderr = invoke_cli(
                "accept-candidate", "--request", str(request), "--json"
            )

        self.assertNotEqual(0, code)
        acceptance.assert_not_called()
        self.assertEqual(
            "candidate_ready",
            store.load_tasks(run_id)["tasks"][0]["status"],
        )

    def test_shipping_rejects_bare_passed_final_gate(self) -> None:
        task = runtime_task(self.commit, status="complete")
        store, run_id = self.seed_state(
            tasks=[task], completed_tasks=["T1"]
        )
        store.complete_run(run_id)
        bare_gate = self.root / "bare-final-gate.json"
        bare_gate.write_text(json.dumps({"passed": True}), encoding="utf-8")

        def no_remote(_repository):
            return lambda *_arguments: RemoteReadback(None, None, None, None)

        with mock.patch.object(crossforge_cli, "_remote_readback", no_remote):
            code, _stdout, _stderr = invoke_cli(
                "ship-preflight",
                "--repository",
                str(self.repository),
                "--git-common-dir",
                str(self.common),
                "--run-id",
                run_id,
                "--final-gate-result",
                str(bare_gate),
                "--publication-requested",
                "--dry-run",
                "--json",
            )

        self.assertNotEqual(0, code)
        self.assertFalse((store.run_dir(run_id) / "shipment.json").exists())

    def test_repeated_final_gate_uses_distinct_worktree_identity(self) -> None:
        task = runtime_task(self.commit, status="complete")
        store, run_id = self.seed_state(
            tasks=[task], completed_tasks=["T1"]
        )
        store.complete_run(run_id)
        run = store.load_run(run_id)
        executor = crossforge_cli._final_gate_executor(self.discovered, store)

        class StopAfterCreate(RuntimeError):
            pass

        manager = mock.Mock()
        manager.create.side_effect = StopAfterCreate
        with mock.patch.object(
            crossforge_cli, "WorktreeManager", return_value=manager
        ), mock.patch.object(
            crossforge_cli.random_secrets,
            "token_hex",
            side_effect=("1111111111111111", "2222222222222222"),
        ):
            with self.assertRaises(StopAfterCreate):
                executor(run)
            with self.assertRaises(StopAfterCreate):
                executor(run)

        task_ids = [call.kwargs["task_id"] for call in manager.create.call_args_list]
        self.assertEqual(
            [
                "final-gate-1111111111111111",
                "final-gate-2222222222222222",
            ],
            task_ids,
        )


class SandboxPolicyCLIRegressionTests(CLITestCase):
    @staticmethod
    def passed_probe(*, policy, **_kwargs):
        check = ProbeCheck("test-boundary", "denied", "denied", True)
        return SandboxProbeResult(
            policy.backend, "fake-1", (check,), policy.sha256
        )

    def gate_arguments(
        self,
        command: dict,
        *,
        result_name: str,
        read_only: Path | None = None,
    ) -> list[str]:
        command_path = self.root / f"{result_name}.command.json"
        command_path.write_text(json.dumps(command), encoding="utf-8")
        runtime = self.root / f"{result_name}-runtime"
        directories = {
            name: runtime / name
            for name in ("worktree", "evidence", "home", "tmp", "cache")
        }
        for directory in directories.values():
            directory.mkdir(parents=True)
        sandbox = PROJECT_ROOT / "tests" / "fixtures" / "fake_sandbox.py"
        arguments = [
            "run-gate",
            "--command-json",
            str(command_path),
            "--worktree",
            str(directories["worktree"]),
            "--evidence-dir",
            str(directories["evidence"]),
            "--result-name",
            result_name,
            "--backend",
            "bwrap",
            "--sandbox-executable",
            str(sandbox),
            "--home",
            str(directories["home"]),
            "--tmpdir",
            str(directories["tmp"]),
            "--cache",
            str(directories["cache"]),
            "--repository-git-dir",
            str(self.common),
            "--json",
        ]
        if read_only is not None:
            arguments.extend(("--read-only", str(read_only)))
        return arguments

    def test_nested_launcher_and_protected_mount_are_blocked(self) -> None:
        class PermissiveRunner:
            def __init__(self, **_kwargs):
                pass

            def run(self, *_args, **_kwargs):
                return SimpleNamespace(
                    as_dict=lambda: {
                        "passed": True,
                        "provenance": "independent",
                    }
                )

        cases = (
            (
                {"argv": ["env", "true"], "timeoutSeconds": 10},
                "nested-launcher",
                None,
            ),
            (
                {"argv": ["true"], "timeoutSeconds": 10},
                "protected-mount",
                self.common,
            ),
        )
        for command, name, mount in cases:
            with self.subTest(name=name):
                with mock.patch.object(
                    crossforge_cli, "probe_sandbox", self.passed_probe
                ), mock.patch.object(
                    crossforge_cli, "GateRunner", PermissiveRunner
                ):
                    code, _stdout, _stderr = invoke_cli(
                        *self.gate_arguments(
                            command, result_name=name, read_only=mount
                        )
                    )
                self.assertNotEqual(0, code)

    def test_build_preflight_requires_and_accepts_observed_fake_sandbox_proof(self) -> None:
        tools = self.root / "tools"
        tools.mkdir()
        self._write_executable(tools / "git", "print('git version 2.45.1')")
        backend_name = "sandbox-exec" if sys.platform == "darwin" else "bwrap"
        backend = tools / backend_name
        self._write_executable(
            backend,
            """
import sys
if sys.argv[1:] in (['--version'], ['-h']):
    print('fake sandbox 1')
    raise SystemExit(0)
raise SystemExit(0)
""",
        )
        path_value = os.pathsep.join((str(tools), "/usr/bin", "/bin"))
        with mock.patch.dict(os.environ, {"PATH": path_value}, clear=False):
            unproven, _stdout, _stderr = invoke_cli(
                "preflight", "--mode", "build", "--no-claude", "--json"
            )
        self.assertNotEqual(0, unproven)

        self._write_executable(
            backend,
            """
import sys
arguments = sys.argv[1:]
if arguments in (['--version'], ['-h']):
    print('fake sandbox 1')
    raise SystemExit(0)
if '-c' not in arguments:
    raise SystemExit(2)
script = arguments[arguments.index('-c') + 1]
positive = "read_bytes()==b'crossforge'" in script or "write_bytes(b'ok')" in script
raise SystemExit(0 if positive else 1)
""",
        )
        observed = SandboxProbeResult(
            backend_name,
            "fake sandbox 1",
            (ProbeCheck("policy-bound-fake", "denied", "denied", True),),
            "f" * 64,
        )
        with mock.patch.dict(
            os.environ, {"PATH": path_value}, clear=False
        ), mock.patch.object(
            crossforge_cli,
            "probe_gate_sandbox",
            return_value=observed,
        ):
            proven, stdout, stderr = invoke_cli(
                "preflight", "--mode", "build", "--no-claude", "--json"
            )
        self.assertEqual(0, proven, stdout + stderr)

    @staticmethod
    def _write_executable(path: Path, body: str) -> None:
        path.write_text(
            "#!/usr/bin/env python3\n" + textwrap.dedent(body).lstrip(),
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | stat.S_IXUSR)


if __name__ == "__main__":
    unittest.main()
