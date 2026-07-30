from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HOOK = PROJECT_ROOT / "hooks" / "crossforge_boundary.py"


class ShippingBoundaryTests(unittest.TestCase):
    def _run(self, mode: str, command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (sys.executable, str(HOOK), mode),
            input=json.dumps({"tool_input": {"command": command}}),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_main_skill_allows_only_local_control_surface(self) -> None:
        local = (
            'python3 "${CLAUDE_PLUGIN_ROOT}/skills/crossforge/scripts/'
            'crossforge.py" status --repository .'
        )
        self.assertEqual(0, self._run("main", local).returncode)

        shipping = (
            'python3 "${CLAUDE_PLUGIN_ROOT}/skills/crossforge-ship/scripts/'
            'crossforge_ship.py" record-shipment --publication-requested'
        )
        self.assertEqual(2, self._run("main", shipping).returncode)
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

    def test_shipping_skill_requires_direct_user_invocation(self) -> None:
        main_skill = (PROJECT_ROOT / "skills/crossforge/SKILL.md").read_text(
            encoding="utf-8"
        )
        ship_skill = (
            PROJECT_ROOT / "skills/crossforge-ship/SKILL.md"
        ).read_text(encoding="utf-8")
        self.assertIn("crossforge_boundary.py", main_skill)
        self.assertIn("disable-model-invocation: true", ship_skill)
        self.assertIn("crossforge_boundary.py", ship_skill)


if __name__ == "__main__":
    unittest.main()
