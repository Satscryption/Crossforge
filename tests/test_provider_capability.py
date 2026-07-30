from __future__ import annotations

import json
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Sequence

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE_ROOT / "skills" / "crossforge" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.provider_capability import (  # noqa: E402
    PRODUCER_ID,
    produce_provider_capability,
)
from crossforge_lib.errors import ProviderUnavailableError  # noqa: E402
from crossforge_lib.providers.base import ProcessResult  # noqa: E402


class FakeListener:
    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def setsockopt(self, *_args: object) -> None:
        return None

    def bind(self, _address: tuple[str, int]) -> None:
        return None

    def listen(self, _backlog: int) -> None:
        return None

    def settimeout(self, _timeout: float) -> None:
        return None

    def getsockname(self) -> tuple[str, int]:
        return ("127.0.0.1", 43123)

    def accept(self):
        raise socket.timeout


class FailingListener(FakeListener):
    def bind(self, _address: tuple[str, int]) -> None:
        raise PermissionError("network disabled")

    def close(self) -> None:
        return None


class ProviderCapabilityProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.executable = self.root / "codex"
        self.executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
        self.grok_executable = self.root / "grok"
        self.grok_executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.grok_executable.chmod(
            self.grok_executable.stat().st_mode | stat.S_IXUSR
        )
        self.git_common = self.root / "git-common"
        self.git_common.mkdir()
        (self.git_common / "HEAD").write_text("ref: refs/heads/main\n")
        self.orchestration = self.root / "orchestration.py"
        self.orchestration.write_text("trusted control layer\n", encoding="utf-8")
        self.credentials = self.root / "credentials"
        self.credentials.mkdir()
        (self.credentials / "auth.json").write_text("not-a-real-secret\n")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _runner(
        self,
        *,
        escaped_field: str | None = None,
        execute: bool = True,
    ):
        def run(
            argv: Sequence[str],
            *,
            cwd: Path,
            stdin_bytes: bytes | None,
            timeout_seconds: float,
            stdout_path: Path,
            stderr_path: Path,
            **_kwargs: object,
        ) -> ProcessResult:
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_bytes(b"")
            stderr_path.write_bytes(b"")
            stdout_preview = b""
            if tuple(argv)[1:] == ("--help",):
                stdout_preview = (
                    b"--cwd --output-format --permission-mode --sandbox "
                    b"--disable-web-search --no-subagents --no-memory "
                    b"--max-turns --tools --allow --single"
                )
                stdout_path.write_bytes(stdout_preview)
            elif execute:
                prompt = (stdin_bytes or b"").decode("utf-8")
                if not prompt and "--single" in argv:
                    prompt = str(argv[argv.index("--single") + 1])
                command = shlex.split(prompt.strip().splitlines()[-1])
                spec = json.loads(Path(command[-2]).read_text(encoding="utf-8"))
                Path(spec["workspaceMarker"]).write_text(
                    spec["nonce"], encoding="ascii"
                )
                result = {
                    "schemaVersion": 1,
                    "nonce": spec["nonce"],
                    "workspaceWriteSucceeded": True,
                    "networkConnectSucceeded": False,
                    "outsideWriteSucceeded": False,
                    "credentialReadSucceeded": False,
                    "orchestrationReadSucceeded": False,
                    "gitCommonDirReadSucceeded": False,
                    "outsideSentinelReadSucceeded": False,
                    "finalOutputReadSucceeded": False,
                    "finalOutputWriteSucceeded": False,
                }
                if escaped_field is not None:
                    result[escaped_field] = True
                Path(command[-1]).write_text(
                    json.dumps(result), encoding="utf-8"
                )
            return ProcessResult(
                argv=tuple(argv),
                exit_code=0,
                timed_out=False,
                duration_ms=1,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                stdout_preview=stdout_preview,
                stderr_preview=b"",
            )

        return run

    def _produce(self, runner, *, provider: str = "codex") -> dict[str, object]:
        return produce_provider_capability(
            provider=provider,
            executable=str(
                self.executable if provider == "codex" else self.grok_executable
            ),
            managed_policy_sha256="a" * 64,
            git_common_dir=self.git_common,
            orchestration_path=self.orchestration,
            credential_paths=(self.credentials,),
            timeout_seconds=10,
            runner=runner,
            listener_factory=FakeListener,
        )

    def test_safe_observed_probe_produces_schema_two_evidence(self) -> None:
        record = self._produce(self._runner())

        self.assertEqual(2, record["schemaVersion"])
        self.assertEqual(PRODUCER_ID, record["producer"])
        self.assertTrue(record["sourceFree"])
        for field in (
            "sandboxEnforced",
            "networkDenied",
            "outsideWriteDenied",
            "credentialReadDenied",
            "orchestrationReadDenied",
            "gitCommonDirReadDenied",
            "outsideSentinelReadDenied",
            "finalOutputProtected",
            "conclusive",
        ):
            self.assertIs(record[field], True, field)
        for field in (
            "executableSha256",
            "sandboxPolicySha256",
            "managedPolicySha256",
            "probeContractSha256",
            "probeResultSha256",
        ):
            self.assertRegex(str(record[field]), r"\A[0-9a-f]{64}\Z")

    def test_current_grok_cli_shape_uses_same_observed_contract(self) -> None:
        observed_argv: list[tuple[str, ...]] = []
        delegate = self._runner()

        def recording_runner(argv: Sequence[str], **kwargs: object) -> ProcessResult:
            observed_argv.append(tuple(argv))
            return delegate(argv, **kwargs)

        record = self._produce(recording_runner, provider="grok")

        self.assertTrue(record["conclusive"])
        invocation = next(argv for argv in observed_argv if "--single" in argv)
        self.assertIn("--disable-web-search", invocation)
        self.assertEqual("Execute", invocation[invocation.index("--tools") + 1])
        self.assertTrue(
            invocation[invocation.index("--allow") + 1].startswith("Execute(")
        )

    def test_successful_forbidden_read_fails_closed(self) -> None:
        record = self._produce(
            self._runner(escaped_field="credentialReadSucceeded")
        )

        self.assertIs(record["credentialReadDenied"], False)
        self.assertIn("credentialReadDenied", record["message"])

    def test_provider_that_does_not_execute_probe_is_inconclusive(self) -> None:
        record = self._produce(self._runner(execute=False))

        self.assertIs(record["conclusive"], False)
        self.assertIs(record["sandboxEnforced"], False)

    def test_executable_inside_caller_writable_boundary_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            ProviderUnavailableError, "caller-writable probe boundary"
        ):
            produce_provider_capability(
                provider="codex",
                executable=str(self.executable),
                managed_policy_sha256="a" * 64,
                git_common_dir=self.git_common,
                orchestration_path=self.orchestration,
                credential_paths=(self.credentials,),
                forbidden_executable_roots=(self.root,),
                timeout_seconds=10,
                runner=self._runner(),
                listener_factory=FakeListener,
            )

    def test_unavailable_loopback_probe_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            ProviderUnavailableError, "network callback probe is unavailable"
        ):
            produce_provider_capability(
                provider="codex",
                executable=str(self.executable),
                managed_policy_sha256="a" * 64,
                git_common_dir=self.git_common,
                orchestration_path=self.orchestration,
                credential_paths=(self.credentials,),
                timeout_seconds=10,
                runner=self._runner(),
                listener_factory=FailingListener,
            )

    def test_executable_replacement_during_probe_is_rejected(self) -> None:
        delegate = self._runner()

        def replacing_runner(argv: Sequence[str], **kwargs: object) -> ProcessResult:
            result = delegate(argv, **kwargs)
            if tuple(argv)[1:2] == ("exec",):
                self.executable.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
                self.executable.chmod(
                    self.executable.stat().st_mode | stat.S_IXUSR
                )
            return result

        with self.assertRaisesRegex(
            ProviderUnavailableError, "changed during capability probe"
        ):
            self._produce(replacing_runner)

    def test_probe_helper_really_attempts_forbidden_operations(self) -> None:
        workspace = self.root / "helper-workspace"
        workspace.mkdir()
        protected = self.root / "helper-protected"
        protected.mkdir()
        outside_write = protected / "outside-write"
        outside_sentinel = protected / "outside-sentinel"
        outside_sentinel.write_text("outside\n", encoding="utf-8")
        final_output = protected / "final"
        final_output.write_text("protected\n", encoding="utf-8")
        result_path = workspace / "result.json"
        nonce = "b" * 64
        spec = {
            "schemaVersion": 1,
            "nonce": nonce,
            "workspaceMarker": str(workspace / "marker"),
            "outsideWriteTarget": str(outside_write),
            "credentialTargets": [str(self.credentials)],
            "orchestrationTarget": str(self.orchestration),
            "gitCommonDirTarget": str(self.git_common),
            "outsideSentinel": str(outside_sentinel),
            "finalOutputTarget": str(final_output),
            "networkHost": "127.0.0.1",
            "networkPort": 1,
        }
        spec_path = workspace / "spec.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        helper = SCRIPTS / "provider_capability_probe.py"

        completed = subprocess.run(
            (sys.executable, str(helper), str(spec_path), str(result_path)),
            cwd=workspace,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertTrue(result["workspaceWriteSucceeded"])
        self.assertTrue(result["outsideWriteSucceeded"])
        self.assertTrue(result["credentialReadSucceeded"])
        self.assertTrue(result["orchestrationReadSucceeded"])
        self.assertTrue(result["gitCommonDirReadSucceeded"])
        self.assertTrue(result["outsideSentinelReadSucceeded"])
        self.assertTrue(result["finalOutputReadSucceeded"])
        self.assertTrue(result["finalOutputWriteSucceeded"])


if __name__ == "__main__":
    unittest.main()
