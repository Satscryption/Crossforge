from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "crossforge" / "scripts"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "fake_sandbox.py"
sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.errors import InvalidInputError, PolicyError  # noqa: E402
from crossforge_lib.evidence import EvidenceStore  # noqa: E402
from crossforge_lib.gates import (  # noqa: E402
    GateCommand,
    GateRunner,
    ProbeCheck,
    SandboxProbeResult,
    bwrap_argv,
    create_sandbox_policy,
    environment_evidence,
    minimal_gate_environment,
    probe_sandbox,
    resolve_gate_command,
    sandbox_exec_profile,
    _terminate_process_group,
    validate_gate_command,
)
from crossforge_lib.util import sha256_file  # noqa: E402


class GateTests(unittest.TestCase):
    def test_structured_command_validation(self) -> None:
        command = GateCommand.from_mapping(
            {"argv": ["python3", "-m", "unittest"], "timeoutSeconds": 30}
        )
        self.assertEqual(("python3", "-m", "unittest"), command.argv)
        for raw in (
            {"argv": "python3 -m unittest", "timeoutSeconds": 30},
            {"argv": [], "timeoutSeconds": 30},
            {"argv": ["python3"], "timeoutSeconds": 9},
            {"argv": ["./tool"], "timeoutSeconds": 30},
            {"argv": ["python3", ""], "timeoutSeconds": 30},
        ):
            with self.subTest(raw=raw), self.assertRaises(InvalidInputError):
                GateCommand.from_mapping(raw)

    def test_inline_destructive_remote_write_and_credentials_are_rejected(self) -> None:
        rejected = (
            ("sh", "-c", "echo no"),
            ("env", "python3", "-m", "unittest"),
            ("command", "python3", "-m", "unittest"),
            ("python3", "-c", "print('no')"),
            ("node", "--eval", "1"),
            ("node", "-pe", "1"),
            ("ruby", "-we", "puts 1"),
            ("bash", "-lc", "echo no"),
            ("rm", "-rf", "build"),
            ("git", "push", "origin"),
            ("git", "-c", "alias.test=!sh -c id", "test"),
            ("git", "--config-env", "alias.test=ALIAS", "test"),
            ("npm", "publish"),
            ("gh", "auth", "token"),
            ("curl", "-X", "POST", "https://example.invalid"),
            ("wget", "--post-data=x", "https://example.invalid"),
            ("rsync", "a", "host:b"),
        )
        for argv in rejected:
            with self.subTest(argv=argv), self.assertRaises(PolicyError):
                validate_gate_command(GateCommand(argv, 30))

    def test_path_and_executable_identity_are_bound(self) -> None:
        python = Path(sys.executable).resolve()
        path_value = os.pathsep.join(
            dict.fromkeys((str(python.parent), "/usr/bin", "/bin"))
        )
        resolved = resolve_gate_command(
            GateCommand((python.name, "-m", "unittest"), 30),
            path_value=path_value,
            executable_allowlist=(python.name,),
        )
        again = resolve_gate_command(
            GateCommand((str(python), "-m", "unittest"), 30),
            path_value=path_value,
            approved_executables={python.name: resolved.executable},
        )
        self.assertEqual(resolved.executable, again.executable)
        with self.assertRaisesRegex(PolicyError, "allowlist must be non-empty"):
            resolve_gate_command(
                GateCommand((python.name, "-m", "unittest"), 30),
                path_value=path_value,
            )

    def test_minimal_environment_excludes_credentials_and_hashes_values(self) -> None:
        sensitive = {
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_KEY",
            "APP_KEY",
            "AWS_ACCESS_KEY_ID",
            "CONNECTION_STRING",
            "DATABASE_URL",
            "DOCKER_CONFIG",
            "ENCRYPTION_KEY",
            "KUBECONFIG",
            "KUBE_CONFIG",
            "MONGODB_URI",
            "MYSQL_PWD",
            "NETRC",
            "OPENAI_API_KEY",
            "OPENAI_KEY",
            "PGPASSFILE",
            "POSTGRES_URL",
            "REDIS_URL",
            "SSLKEYLOGFILE",
            "STRIPE_KEY",
            "XAI_APIKEY",
        }
        safe = {
            "CONFIG_PATH": "/tmp/config",
            "KEYBOARD_LAYOUT": "gb",
            "MONKEY": "capuchin",
            "PUBLIC_URL": "https://example.invalid",
        }
        inherited = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "CI": "1",
            "PROVIDER_TOKEN": "secret-value",
            **{name: f"sensitive-{name}" for name in sensitive},
            **safe,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("home", "tmp", "cache"):
                (root / name).mkdir()
            environment = minimal_gate_environment(
                inherited,
                allowlist=("LANG", *sorted(sensitive), *sorted(safe)),
                home=root / "home",
                tmpdir=root / "tmp",
                cache=root / "cache",
            )
        self.assertNotIn("PROVIDER_TOKEN", environment)
        for name in sensitive:
            self.assertNotIn(name, environment)
        for name, value in safe.items():
            self.assertEqual(environment[name], value)
        recorded = environment_evidence(environment)
        self.assertNotIn("secret-value", repr(recorded))
        self.assertTrue(all(set(item) == {"name", "valueSha256"} for item in recorded))

    def _policy(self, root: Path, backend: str = "bwrap"):
        for name in ("worktree", "home", "tmp", "cache"):
            (root / name).mkdir()
        os.chmod(FIXTURE, 0o755)
        environment = minimal_gate_environment(
            {"PATH": os.environ["PATH"], "LANG": "C", "TOKEN": "hidden"},
            allowlist=("LANG",),
            home=root / "home",
            tmpdir=root / "tmp",
            cache=root / "cache",
        )
        policy = create_sandbox_policy(
            backend=backend,
            executable=str(FIXTURE),
            worktree=root / "worktree",
            home=root / "home",
            tmpdir=root / "tmp",
            cache=root / "cache",
            read_only_paths=(Path(sys.executable).resolve().parent,),
            environment=environment,
        )
        return policy, environment

    def test_sandbox_templates_deny_network_and_do_not_use_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy, environment = self._policy(root)
            argv = bwrap_argv(policy, ["/usr/bin/python3", "-m", "unittest"], environment)
            self.assertIn("--unshare-net", argv)
            self.assertIn("--", argv)
            self.assertNotIn("sh", argv)

            sandbox_policy = type(policy)(
                **{**policy.__dict__, "backend": "sandbox-exec"}
            )
            profile = sandbox_exec_profile(sandbox_policy)
            self.assertIn("(deny network*)", profile)
            self.assertIn(str(root / "worktree"), profile)

    def test_probe_requires_all_positive_and_negative_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy, environment = self._policy(root)
            git_dir = root / "git"
            credentials = root / "credentials"
            git_dir.mkdir()
            credentials.mkdir()

            expected = {
                "worktree-read": "allowed",
                "worktree-write": "allowed",
                "network": "denied",
                "outside-worktree-write": "denied",
                "repository-git-read": "denied",
                "provider-credential-read": "denied",
            }
            result = probe_sandbox(
                policy=policy,
                environment=environment,
                repository_git_dir=git_dir,
                credential_directories=(credentials,),
                run_probe=lambda name, _policy, _environment: expected[name],
            )
            self.assertTrue(result.passed)

            failed = probe_sandbox(
                policy=policy,
                environment=environment,
                repository_git_dir=git_dir,
                credential_directories=(credentials,),
                run_probe=lambda name, _policy, _environment: (
                    "inconclusive" if name == "network" else expected[name]
                ),
            )
            self.assertFalse(failed.passed)

    def test_runner_captures_combined_output_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy, environment = self._policy(root)
            script = root / "worktree" / "gate.py"
            script.write_text(
                "import sys\nprint('stdout-line')\nprint('stderr-line', file=sys.stderr)\n",
                encoding="utf-8",
            )
            python = Path(sys.executable).resolve()
            path_value = os.pathsep.join(
                dict.fromkeys((str(python.parent), *os.environ["PATH"].split(os.pathsep)))
            )
            environment["PATH"] = path_value
            probe = SandboxProbeResult(
                backend="bwrap",
                version="fake",
                checks=(ProbeCheck("all", "allowed", "allowed", True),),
                policy_sha256=policy.sha256,
            )
            store = EvidenceStore(root / "evidence")
            runner = GateRunner(
                policy=policy,
                evidence_store=store,
                environment=environment,
                sandbox_probe=probe,
                executable_allowlist=(python.name,),
            )
            result = runner.run(
                GateCommand((python.name, str(script)), 30),
                result_name="unit",
                path_value=path_value,
            )

            self.assertTrue(result.passed)
            output = store.path(result.output_path).read_text(encoding="utf-8")
            self.assertIn("stdout-line", output)
            self.assertIn("stderr-line", output)
            self.assertTrue(store.path("independent/gates/unit.result.json").is_file())
            self.assertEqual(sha256_file(store.path(result.output_path)), result.output_sha256)
            self.assertNotIn("hidden", repr(result.environment))

    def test_sensitive_path_cannot_be_mounted_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("worktree", "home", "tmp", "cache", "credentials"):
                (root / name).mkdir()
            environment = minimal_gate_environment(
                {"PATH": os.environ["PATH"]},
                allowlist=(),
                home=root / "home",
                tmpdir=root / "tmp",
                cache=root / "cache",
            )
            with self.assertRaisesRegex(PolicyError, "sensitive"):
                create_sandbox_policy(
                    backend="bwrap",
                    executable=str(FIXTURE),
                    worktree=root / "worktree",
                    home=root / "home",
                    tmpdir=root / "tmp",
                    cache=root / "cache",
                    read_only_paths=(root / "credentials",),
                    sensitive_paths=(root / "credentials",),
                    environment=environment,
                )

    def test_timeout_termination_covers_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "descendant-survived"
            child = (
                "import pathlib,sys,time;"
                "time.sleep(.5);"
                "pathlib.Path(sys.argv[1]).write_text('bad')"
            )
            parent = (
                "import subprocess,sys,time;"
                f"subprocess.Popen([sys.executable,'-c',{child!r},sys.argv[1]]);"
                "time.sleep(30)"
            )
            process = subprocess.Popen(
                [sys.executable, "-c", parent, str(marker)],
                start_new_session=True,
            )
            time.sleep(0.2)
            _terminate_process_group(process)
            time.sleep(0.6)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
