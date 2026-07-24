from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE_ROOT / "skills" / "crossforge" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.preflight import (  # noqa: E402
    discover_sandbox_backend,
    parse_version,
    path_is_safe,
    probe_gate_sandbox,
    resolve_executable,
    run_preflight,
    run_source_free_provider_probe,
    trusted_gate_read_only_paths,
)
from crossforge_lib.errors import ConsentError, PreconditionError  # noqa: E402
from crossforge_lib.providers.base import ProviderProbe  # noqa: E402


class PreflightTests(unittest.TestCase):
    def test_version_parser(self) -> None:
        self.assertEqual(parse_version("git version 2.45.1"), (2, 45, 1))
        self.assertEqual(parse_version("Claude Code 2.1.216"), (2, 1, 216))
        self.assertIsNone(parse_version("not a version"))

    def test_path_rejects_empty_and_relative_components(self) -> None:
        self.assertFalse(path_is_safe(""))
        self.assertFalse(path_is_safe(f"/usr/bin{os.pathsep}"))
        self.assertFalse(path_is_safe(f"/usr/bin{os.pathsep}bin"))
        self.assertTrue(path_is_safe(f"/usr/bin{os.pathsep}/bin"))

    def test_resolve_executable_rejects_path_like_name(self) -> None:
        self.assertIsNone(resolve_executable("../git", path_value="/usr/bin:/bin"))

    def test_build_requires_proven_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._executable(root / "git", "echo 'git version 2.45.1'")
            self._executable(root / "claude", "echo 'Claude Code 2.1.216'")
            sandbox_name = "sandbox-exec" if sys.platform == "darwin" else "bwrap"
            self._executable(root / sandbox_name, "exit 0")
            env = {"PATH": f"{root}{os.pathsep}/usr/bin{os.pathsep}/bin"}
            unproven = run_preflight("build", env=env)
            self.assertFalse(unproven.passed)
            self.assertIn("gate-sandbox", {item.name for item in unproven.blockers})
            proven = run_preflight(
                "build",
                env=env,
                sandbox_capability=lambda _name, _path: True,
            )
            self.assertTrue(proven.passed, proven.to_dict())

    def test_plan_does_not_require_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._executable(root / "git", "echo 'git version 2.45.1'")
            env = {"PATH": f"{root}{os.pathsep}/usr/bin{os.pathsep}/bin"}
            report = run_preflight("plan", env=env, require_claude=False)
            self.assertTrue(report.passed, report.to_dict())
            sandbox = next(item for item in report.checks if item.name == "gate-sandbox")
            self.assertFalse(sandbox.required)

    def test_provider_probes_are_opt_in(self) -> None:
        class StubAdapter:
            provider = "codex"

            def __init__(self) -> None:
                self.calls = 0

            def probe(self, requested_model: str, effort: str):
                self.calls += 1
                raise AssertionError("remote probe must not run")

        stub = StubAdapter()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._executable(root / "git", "echo 'git version 2.45.1'")
            env = {"PATH": f"{root}{os.pathsep}/usr/bin{os.pathsep}/bin"}
            run_preflight(
                "status",
                env=env,
                require_claude=False,
                provider_adapters=(stub,),  # type: ignore[arg-type]
            )
        self.assertEqual(stub.calls, 0)

    def test_source_free_provider_probe_requires_caller_validated_consent(self) -> None:
        class StubAdapter:
            provider = "codex"

            def __init__(self) -> None:
                self.calls: list[tuple[str, str]] = []

            def probe(self, requested_model: str, effort: str) -> ProviderProbe:
                self.calls.append((requested_model, effort))
                return ProviderProbe(
                    provider="codex",
                    available=True,
                    cli_path="/fake/codex",
                    cli_version="1.0",
                    authenticated=True,
                    requested_model=requested_model,
                    resolved_model="cli-default",
                    effort=effort,
                )

        stub = StubAdapter()
        with self.assertRaises(ConsentError):
            run_source_free_provider_probe(
                stub,  # type: ignore[arg-type]
                requested_model="auto",
                effort="high",
                consent_confirmed=False,
            )
        self.assertEqual([], stub.calls)

        result = run_source_free_provider_probe(
            stub,  # type: ignore[arg-type]
            requested_model="auto",
            effort="high",
            consent_confirmed=True,
        )
        self.assertTrue(result.passed)
        self.assertEqual([("auto", "high")], stub.calls)
        serialized = result.to_dict()
        self.assertTrue(serialized["sourceFree"])
        self.assertEqual("probe", serialized["operation"])
        self.assertNotIn("repository", repr(serialized).lower())
        self.assertNotIn("task brief", repr(serialized).lower())

    def test_run_preflight_provider_probe_requires_explicit_consent(self) -> None:
        class StubAdapter:
            provider = "codex"

            def __init__(self) -> None:
                self.calls = 0

            def probe(self, requested_model: str, effort: str) -> ProviderProbe:
                self.calls += 1
                return ProviderProbe(
                    provider="codex",
                    available=True,
                    cli_path="/fake/codex",
                    cli_version="1.0",
                    authenticated=True,
                    requested_model=requested_model,
                    resolved_model="cli-default",
                    effort=effort,
                )

        stub = StubAdapter()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._executable(root / "git", "echo 'git version 2.45.1'")
            env = {"PATH": f"{root}{os.pathsep}/usr/bin{os.pathsep}/bin"}
            with self.assertRaises(ConsentError):
                run_preflight(
                    "status",
                    env=env,
                    require_claude=False,
                    provider_adapters=(stub,),  # type: ignore[arg-type]
                    probe_providers=True,
                )
            report = run_preflight(
                "status",
                env=env,
                require_claude=False,
                provider_adapters=(stub,),  # type: ignore[arg-type]
                probe_providers=True,
                provider_probe_consent_confirmed=True,
            )
        self.assertEqual(1, stub.calls)
        self.assertEqual(1, len(report.source_free_provider_probes))

    def test_concrete_gate_sandbox_probe_is_policy_bound_and_consumable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend_name = "sandbox-exec" if sys.platform == "darwin" else "bwrap"
            backend = root / backend_name
            self._executable(
                backend,
                "echo 'fake sandbox 1'",
            )
            git_dir = root / "common.git"
            credentials = root / "credentials"
            git_dir.mkdir()
            credentials.mkdir()
            env = {"PATH": f"{root}{os.pathsep}/usr/bin{os.pathsep}/bin"}
            expected = {
                "worktree-read": "allowed",
                "worktree-write": "allowed",
                "network": "denied",
                "outside-worktree-write": "denied",
                "repository-git-read": "denied",
                "provider-credential-read": "denied",
            }
            probe = probe_gate_sandbox(
                backend=backend_name,
                executable=backend,
                environment=env,
                repository_git_dir=git_dir,
                credential_directories=(credentials,),
                run_probe=lambda name, _policy, _environment: expected[name],
            )
            self.assertTrue(probe.passed, probe.as_dict())
            self.assertEqual(64, len(probe.policy_sha256))

            self._executable(root / "git", "echo 'git version 2.45.1'")
            self._executable(root / "claude", "echo 'Claude Code 2.1.216'")
            report = run_preflight("build", env=env, sandbox_probe=probe)
            self.assertTrue(report.passed, report.to_dict())
            self.assertEqual(probe.as_dict(), report.to_dict()["gateSandboxProbe"])

    def test_concrete_probe_rejects_missing_credentials_and_exposed_protected_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = root / "bwrap"
            self._executable(backend, "echo 'fake bwrap 1'")
            git_dir = root / "common.git"
            credentials = root / "credentials"
            git_dir.mkdir()
            credentials.mkdir()
            env = {"PATH": f"{root}{os.pathsep}/usr/bin{os.pathsep}/bin"}
            with self.assertRaises(PreconditionError):
                probe_gate_sandbox(
                    backend="bwrap",
                    executable=backend,
                    environment=env,
                    repository_git_dir=git_dir,
                    credential_directories=(),
                    run_probe=lambda *_args: "denied",
                )
            with self.assertRaises(PreconditionError):
                probe_gate_sandbox(
                    backend="bwrap",
                    executable=backend,
                    environment=env,
                    repository_git_dir=git_dir,
                    credential_directories=(credentials,),
                    read_only_paths=(root,),
                    run_probe=lambda *_args: "denied",
                )

    def test_trusted_mounts_never_infer_home_or_repository(self) -> None:
        paths = trusted_gate_read_only_paths()
        self.assertNotIn(Path.home().resolve(), paths)
        self.assertNotIn(Path.cwd().resolve(), paths)

    def test_sandbox_discovery_is_platform_specific(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._executable(root / "bwrap", "exit 0")
            result = discover_sandbox_backend(path_value=str(root), system="Linux")
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result[0], "bwrap")
            self.assertIsNone(
                discover_sandbox_backend(path_value=str(root), system="Darwin")
            )

    @staticmethod
    def _executable(path: Path, body: str) -> None:
        path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)


if __name__ == "__main__":
    unittest.main()
