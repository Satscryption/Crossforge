from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HOOK = PROJECT_ROOT / "hooks" / "crossforge_boundary.py"


class ShippingBoundaryTests(unittest.TestCase):
    def _run(
        self,
        mode: str,
        command: str,
        *,
        environment: dict[str, str] | None = None,
        permission_mode: str = "default",
        tool_name: str = "Bash",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (sys.executable, str(HOOK), mode),
            input=json.dumps(
                {
                    "tool_name": tool_name,
                    "permission_mode": permission_mode,
                    "tool_input": {"command": command},
                }
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )

    def test_main_skill_allows_only_local_control_surface(self) -> None:
        local = (
            'python3 "${CLAUDE_PLUGIN_ROOT}/skills/crossforge/scripts/'
            'crossforge.py" status --repository .'
        )
        self.assertEqual(0, self._run("main", local).returncode)
        self.assertEqual(
            2,
            self._run(
                "deny-mutation",
                "",
                tool_name="Write",
            ).returncode,
        )
        prepare = (
            'python3 "${CLAUDE_PLUGIN_ROOT}/skills/crossforge/scripts/'
            'crossforge.py" prepare-consent --repository .'
        )
        self.assertEqual(0, self._run("main", prepare).returncode)

        shipping = (
            'python3 "${CLAUDE_PLUGIN_ROOT}/skills/crossforge-ship/scripts/'
            'crossforge_ship.py" record-shipment --publication-requested'
        )
        self.assertEqual(2, self._run("main", shipping).returncode)
        consent = (
            'python3 "${CLAUDE_PLUGIN_ROOT}/skills/crossforge-consent/scripts/'
            'crossforge_consent.py" record-consent --request /tmp/request '
            f'--request-sha256 {"0" * 64}'
        )
        self.assertEqual(2, self._run("main", consent).returncode)
        old_self_issuance = (
            'python3 "${CLAUDE_PLUGIN_ROOT}/skills/crossforge/scripts/'
            'crossforge.py" record-consent --path /tmp/consent.json'
        )
        self.assertEqual(2, self._run("main", old_self_issuance).returncode)
        self.assertEqual(2, self._run("main", "git push origin HEAD").returncode)
        self.assertEqual(
            2,
            self._run("main", f"{local} && git push origin HEAD").returncode,
        )
        self.assertEqual(
            2,
            self._run("main", f"{local} & git push origin HEAD").returncode,
        )
        self.assertEqual(
            2,
            self._run(
                "main",
                "python3 /tmp/attacker/skills/crossforge/scripts/"
                "crossforge.py status",
            ).returncode,
        )
        self.assertEqual(
            2,
            self._run(
                "main",
                f"/tmp/python3 {PROJECT_ROOT}/skills/crossforge/scripts/"
                "crossforge.py status",
            ).returncode,
        )

    def test_ship_skill_allows_only_shipping_control_surface(self) -> None:
        shipping = (
            'python3 "${CLAUDE_PLUGIN_ROOT}/skills/crossforge-ship/scripts/'
            'crossforge_ship.py" record-shipment --publication-requested'
        )
        self.assertEqual(0, self._run("ship", shipping).returncode)
        self.assertEqual(2, self._run("ship", "gh pr create").returncode)
        self.assertEqual(
            2,
            self._run(
                "ship",
                'python3 "${CLAUDE_PLUGIN_ROOT}/skills/crossforge/scripts/'
                'crossforge.py" status',
            ).returncode,
        )

    def test_hook_fails_closed_on_malformed_input(self) -> None:
        result = subprocess.run(
            (sys.executable, str(HOOK), "main"),
            input="not-json",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(2, result.returncode)

    def test_consent_surface_forces_exact_user_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            subprocess.run(
                ("git", "init", "-b", "main"),
                cwd=repository,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            fake_bin = root / "bin"
            fake_bin.mkdir()
            executable = fake_bin / "codex"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            config = root / "config.json"
            config.write_text("{}\n", encoding="utf-8")
            environment = dict(os.environ)
            environment["PATH"] = (
                str(fake_bin) + os.pathsep + environment.get("PATH", "")
            )
            control = (
                PROJECT_ROOT
                / "skills"
                / "crossforge"
                / "scripts"
                / "crossforge.py"
            )
            prepared = subprocess.run(
                (
                    sys.executable,
                    str(control),
                    "prepare-consent",
                    "--repository",
                    str(repository),
                    "--provider",
                    "codex",
                    "--operation",
                    "probe",
                    "--managed-policy-sha256",
                    "b" * 64,
                    "--config",
                    str(config),
                    "--json",
                ),
                cwd=repository,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            result = json.loads(prepared.stdout)["result"]
            command = (
                'python3 "${CLAUDE_PLUGIN_ROOT}/skills/crossforge-consent/'
                "scripts/crossforge_consent.py\" record-consent "
                f"--request {shlex.quote(result['requestPath'])} "
                f"--request-sha256 {result['requestSha256']} --json"
            )

            decision = self._run(
                "consent",
                command,
                environment=environment,
            )

            self.assertEqual(0, decision.returncode, decision.stderr)
            output = json.loads(decision.stdout)["hookSpecificOutput"]
            self.assertEqual(output["permissionDecision"], "ask")
            self.assertIn('"provider":"codex"', output["permissionDecisionReason"])
            self.assertIn(
                '"operationClasses":["probe"]',
                output["permissionDecisionReason"],
            )
            consent_path = repository / ".git" / "crossforge" / "consent.json"
            self.assertFalse(consent_path.exists())

            mutation = self._run(
                "consent",
                command,
                environment=environment,
                tool_name="Write",
            )
            self.assertEqual(2, mutation.returncode)
            self.assertFalse(consent_path.exists())

            bypassed = self._run(
                "consent",
                command,
                environment=environment,
                permission_mode="bypassPermissions",
            )
            self.assertEqual(2, bypassed.returncode)
            self.assertFalse(consent_path.exists())

            Path(result["requestPath"]).write_text("{}\n", encoding="utf-8")
            denied = self._run(
                "consent",
                command,
                environment=environment,
            )
            self.assertEqual(2, denied.returncode)
            self.assertFalse(consent_path.exists())

    def test_shipping_skill_requires_direct_user_invocation(self) -> None:
        main_skill = (PROJECT_ROOT / "skills/crossforge/SKILL.md").read_text(
            encoding="utf-8"
        )
        ship_skill = (
            PROJECT_ROOT / "skills/crossforge-ship/SKILL.md"
        ).read_text(encoding="utf-8")
        self.assertIn("crossforge_boundary.py", main_skill)
        self.assertIn('matcher: "Write|Edit|NotebookEdit|Agent"', main_skill)
        self.assertIn("deny-mutation", main_skill)
        self.assertIn("disable-model-invocation: true", ship_skill)
        self.assertIn("crossforge_boundary.py", ship_skill)
        consent_skill = (
            PROJECT_ROOT / "skills" / "crossforge-consent" / "SKILL.md"
        ).read_text(encoding="utf-8")
        self.assertIn("disable-model-invocation: true", consent_skill)
        self.assertIn('matcher: "*"', consent_skill)
        self.assertIn("crossforge_boundary.py", consent_skill)


if __name__ == "__main__":
    unittest.main()
