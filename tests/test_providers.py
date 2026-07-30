from __future__ import annotations

import os
import shutil
import signal
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE_ROOT / "skills" / "crossforge" / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.models import ProviderStatus  # noqa: E402
from crossforge_lib.providers import (  # noqa: E402
    CapabilityProbe,
    CodexCLIAdapter,
    GrokCLIAdapter,
)
from crossforge_lib.providers.base import MAX_EVIDENCE_BYTES  # noqa: E402


def safe_capability(_mode: str) -> CapabilityProbe:
    return CapabilityProbe(
        sandbox_enforced=True,
        network_denied=True,
        outside_write_denied=True,
        credential_read_denied=True,
        orchestration_read_denied=True,
        git_common_dir_read_denied=True,
        outside_sentinel_read_denied=True,
        final_output_protected=True,
    )


class ProviderAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.codex = self._install_fake("fake_codex.py", "codex")
        self.grok = self._install_fake("fake_grok.py", "grok")
        self.worktree = self.root / "worktree"
        self.worktree.mkdir()
        self.spec = self.root / "spec.md"
        self.spec.write_text(
            "# Task\n\nLiteral prompt: $(touch NO) ; `uname` $HOME\n",
            encoding="utf-8",
        )
        self.env = dict(os.environ)
        self.env["PATH"] = f"{self.bin}{os.pathsep}{self.env.get('PATH', '')}"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _install_fake(self, source: str, name: str) -> Path:
        destination = self.bin / name
        shutil.copyfile(FIXTURES / source, destination)
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR)
        return destination

    def test_missing_executable(self) -> None:
        env = dict(self.env)
        env["PATH"] = str(self.bin / "missing")
        probe = CodexCLIAdapter(
            env=env, capability_source=safe_capability
        ).probe("auto", "high")
        self.assertFalse(probe.available)
        self.assertEqual(probe.failure_category, "missing_executable")

    def test_codex_probe_and_safe_implementation_argv(self) -> None:
        log = self.root / "codex-argv.json"
        env = dict(self.env)
        env["FAKE_ARGV_LOG"] = str(log)
        adapter = CodexCLIAdapter(env=env, capability_source=safe_capability)
        probe = adapter.probe("codex-test", "xhigh")
        self.assertTrue(probe.available, probe)
        self.assertEqual(probe.requested_model, "codex-test")
        self.assertEqual(probe.resolved_model, "codex-test")
        final = self.root / "evidence" / "final.txt"
        invocation = adapter.implement(
            spec_path=self.spec,
            worktree=self.worktree,
            requested_model="codex-test",
            effort="xhigh",
            timeout_seconds=5,
            final_output_path=final,
        )
        self.assertEqual(invocation.status, ProviderStatus.COMPLETE)
        argv = invocation.argv
        self.assertIn("--sandbox", argv)
        self.assertEqual(argv[argv.index("--sandbox") + 1], "workspace-write")
        self.assertIn("--ask-for-approval", argv)
        self.assertEqual(argv[argv.index("--ask-for-approval") + 1], "never")
        self.assertIn("--ephemeral", argv)
        self.assertIn("--strict-config", argv)
        joined = "\n".join(argv)
        self.assertNotIn("danger-full-access", joined)
        self.assertNotIn("--yolo", joined)
        self.assertNotIn("--skip-git-repo-check", joined)
        self.assertTrue(final.is_file())
        self.assertEqual(stat.S_IMODE(final.stat().st_mode), 0o600)

    def test_codex_auto_omits_model_and_review_is_read_only(self) -> None:
        adapter = CodexCLIAdapter(env=self.env, capability_source=safe_capability)
        probe = adapter.probe("auto", "high")
        self.assertEqual(probe.resolved_model, "cli-default")
        result = adapter.review(
            spec_path=self.spec,
            worktree=self.worktree,
            requested_model="auto",
            effort="high",
            timeout_seconds=5,
            final_output_path=self.root / "review" / "final.txt",
        )
        self.assertNotIn("--model", result.argv)
        self.assertEqual(result.argv[result.argv.index("--sandbox") + 1], "read-only")

    def test_auth_failure_is_sanitized(self) -> None:
        env = dict(self.env)
        env["FAKE_AUTH_FAIL"] = "1"
        probe = CodexCLIAdapter(
            env=env, capability_source=safe_capability
        ).probe("auto", "high")
        self.assertFalse(probe.available)
        self.assertEqual(probe.failure_category, "authentication_failed")
        self.assertNotIn("super-secret-value", probe.message)

    def test_missing_capability_evidence_fails_closed(self) -> None:
        probe = CodexCLIAdapter(env=self.env).probe("auto", "high")
        self.assertFalse(probe.available)
        self.assertEqual(probe.failure_category, "sandbox_inconclusive")
        bad = safe_capability("workspace-write")
        bad = CapabilityProbe(
            **{
                field: getattr(bad, field)
                for field in bad.__dataclass_fields__
                if field not in {"network_denied", "message"}
            },
            network_denied=False,
            message="network negative probe failed",
        )
        grok_probe = GrokCLIAdapter(
            env=self.env, capability_source=lambda _mode: bad
        ).probe("auto", "high")
        self.assertFalse(grok_probe.available)
        self.assertEqual(grok_probe.failure_category, "sandbox_incompatible")

    def test_grok_probe_model_and_fail_closed_argv(self) -> None:
        adapter = GrokCLIAdapter(
            env=self.env,
            capability_source=safe_capability,
            verification_command_prefixes=(("python3", "-m", "unittest"),),
        )
        probe = adapter.probe("grok-4", "high")
        self.assertTrue(probe.available, probe)
        self.assertEqual(probe.resolved_model, "grok-4")
        result = adapter.implement(
            spec_path=self.spec,
            worktree=self.worktree,
            requested_model="grok-4",
            effort="high",
            timeout_seconds=5,
            final_output_path=self.root / "grok-evidence" / "final.txt",
        )
        self.assertEqual(result.status, ProviderStatus.COMPLETE)
        argv = result.argv
        self.assertEqual(argv[argv.index("--permission-mode") + 1], "dontAsk")
        self.assertEqual(argv[argv.index("--sandbox") + 1], "workspace-write")
        self.assertIn("Edit", argv)
        self.assertIn("WebSearch", argv)
        self.assertIn("Network", argv)
        self.assertNotIn("--always-approve", argv)
        prompt = argv[argv.index("--prompt") + 1]
        self.assertIn("$(touch NO)", prompt)
        self.assertFalse((self.worktree / "NO").exists())

    def test_grok_review_has_no_edit_or_shell_allowance(self) -> None:
        adapter = GrokCLIAdapter(
            env=self.env,
            capability_source=safe_capability,
            verification_command_prefixes=(("python3", "-m", "unittest"),),
        )
        adapter.probe("auto", "high")
        result = adapter.review(
            spec_path=self.spec,
            worktree=self.worktree,
            requested_model="auto",
            effort="high",
            timeout_seconds=5,
            final_output_path=self.root / "grok-review" / "final.txt",
        )
        self.assertEqual(result.argv[result.argv.index("--sandbox") + 1], "read-only")
        allow_values = [
            result.argv[index + 1]
            for index, value in enumerate(result.argv)
            if value == "--allow"
        ]
        self.assertEqual(allow_values, ["Read", "Grep", "Glob"])

    def test_current_grok_shape_uses_shared_production_policy(self) -> None:
        env = dict(self.env)
        env["FAKE_CURRENT_HELP"] = "1"
        adapter = GrokCLIAdapter(
            env=env,
            capability_source=safe_capability,
            verification_command_prefixes=(("python3", "-m", "unittest"),),
        )
        probe = adapter.probe("auto", "high")
        self.assertTrue(probe.available, probe)

        result = adapter.implement(
            spec_path=self.spec,
            worktree=self.worktree,
            requested_model="auto",
            effort="high",
            timeout_seconds=5,
            final_output_path=self.root / "grok-current" / "final.txt",
        )

        self.assertIn("--single", result.argv)
        self.assertNotIn("--prompt", result.argv)
        self.assertIn("--disable-web-search", result.argv)
        tools = result.argv[result.argv.index("--tools") + 1].split(",")
        self.assertEqual(
            tools,
            ["Read", "Search", "ListDir", "Edit", "Execute"],
        )
        self.assertEqual(
            result.argv[result.argv.index("--sandbox") + 1],
            "workspace-write",
        )

    def test_grok_incompatible_help_and_model_unavailable(self) -> None:
        env = dict(self.env)
        env["FAKE_UNSAFE_HELP"] = "1"
        incompatible = GrokCLIAdapter(
            env=env, capability_source=safe_capability
        ).probe("auto", "high")
        self.assertEqual(incompatible.failure_category, "incompatible_cli")
        unavailable = GrokCLIAdapter(
            env=self.env, capability_source=safe_capability
        ).probe("not-a-model", "high")
        self.assertEqual(unavailable.failure_category, "model_unavailable")

    def test_timeout_terminates_provider_process_group(self) -> None:
        child_pid_file = self.root / "child.pid"
        env = dict(self.env)
        env.update(
            {
                "FAKE_SLEEP": "300",
                "FAKE_SPAWN_CHILD": "1",
                "FAKE_CHILD_PID_FILE": str(child_pid_file),
            }
        )
        adapter = CodexCLIAdapter(env=env, capability_source=safe_capability)
        adapter.probe("auto", "high")
        started = time.monotonic()
        result = adapter.implement(
            spec_path=self.spec,
            worktree=self.worktree,
            requested_model="auto",
            effort="high",
            timeout_seconds=1,
            final_output_path=self.root / "timeout" / "final.txt",
        )
        self.assertEqual(result.status, ProviderStatus.TIMEOUT)
        self.assertLess(time.monotonic() - started, 6)
        self.assertTrue(child_pid_file.is_file())
        child_pid = int(child_pid_file.read_text(encoding="ascii"))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.fail("provider descendant survived process-group timeout")

    def test_large_stdout_and_stderr_are_drained_and_bounded(self) -> None:
        env = dict(self.env)
        env["FAKE_LARGE_OUTPUT"] = "1"
        adapter = GrokCLIAdapter(env=env, capability_source=safe_capability)
        adapter.probe("auto", "high")
        result = adapter.implement(
            spec_path=self.spec,
            worktree=self.worktree,
            requested_model="auto",
            effort="high",
            timeout_seconds=10,
            final_output_path=self.root / "large" / "final.txt",
        )
        self.assertEqual(result.status, ProviderStatus.COMPLETE)
        self.assertLessEqual(result.raw_stdout_path.stat().st_size, MAX_EVIDENCE_BYTES)
        self.assertLessEqual(result.raw_stderr_path.stat().st_size, MAX_EVIDENCE_BYTES)

    def test_nonzero_error_hides_paths_and_secrets(self) -> None:
        env = dict(self.env)
        env["FAKE_INVOKE_FAIL"] = "1"
        adapter = GrokCLIAdapter(env=env, capability_source=safe_capability)
        adapter.probe("auto", "high")
        result = adapter.implement(
            spec_path=self.spec,
            worktree=self.worktree,
            requested_model="auto",
            effort="high",
            timeout_seconds=5,
            final_output_path=self.root / "failed" / "final.txt",
        )
        self.assertEqual(result.status, ProviderStatus.FAILED)
        self.assertNotIn(str(self.root), result.message)
        self.assertNotIn("do-not-return", result.message)

    def test_evidence_path_inside_candidate_is_rejected(self) -> None:
        adapter = CodexCLIAdapter(env=self.env, capability_source=safe_capability)
        adapter.probe("auto", "high")
        with self.assertRaisesRegex(ValueError, "outside the candidate"):
            adapter.implement(
                spec_path=self.spec,
                worktree=self.worktree,
                requested_model="auto",
                effort="high",
                timeout_seconds=5,
                final_output_path=self.worktree / "final.txt",
            )


if __name__ == "__main__":
    unittest.main()
