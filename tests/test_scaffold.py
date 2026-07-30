"""Bootstrap checks for Crossforge's repository and plugin metadata."""

from __future__ import annotations

import json
from pathlib import Path
import tomllib
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RELEASE_VERSION = "0.1.0"


def load_json(relative_path: str) -> dict[str, object]:
    with (PROJECT_ROOT / relative_path).open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise TypeError(f"{relative_path} must contain a JSON object")
    return value


class ScaffoldTests(unittest.TestCase):
    def test_project_metadata_version_and_dependencies(self) -> None:
        with (PROJECT_ROOT / "pyproject.toml").open("rb") as handle:
            metadata = tomllib.load(handle)

        project = metadata["project"]
        self.assertEqual(RELEASE_VERSION, project["version"])
        self.assertEqual(">=3.11", project["requires-python"])
        self.assertEqual([], project["dependencies"])

    def test_plugin_manifest_matches_release(self) -> None:
        plugin = load_json(".claude-plugin/plugin.json")

        self.assertEqual("crossforge", plugin["name"])
        self.assertEqual(RELEASE_VERSION, plugin["version"])
        self.assertEqual("MIT", plugin["license"])
        self.assertEqual({"name": "Sadiq Jaffer"}, plugin["author"])

    def test_marketplace_points_to_plugin_root(self) -> None:
        marketplace = load_json(".claude-plugin/marketplace.json")

        self.assertEqual("crossforge", marketplace["name"])
        self.assertEqual({"name": "Sadiq Jaffer"}, marketplace["owner"])
        self.assertEqual(1, len(marketplace["plugins"]))
        plugin = marketplace["plugins"][0]
        self.assertEqual("crossforge", plugin["name"])
        self.assertEqual("./", plugin["source"])
        self.assertEqual(RELEASE_VERSION, plugin["version"])
        self.assertEqual("MIT", plugin["license"])

    def test_license_and_verified_notice_are_present(self) -> None:
        license_text = (PROJECT_ROOT / "LICENSE").read_text(encoding="utf-8")
        notices = (PROJECT_ROOT / "THIRD_PARTY_NOTICES.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("MIT License", license_text)
        self.assertIn("Copyright (c) 2026 Sadiq Jaffer", license_text)
        self.assertIn("Copyright (c) 2026 Dan McAteer", notices)
        self.assertIn("https://github.com/DannyMac180/fable-advisor", notices)

    def test_assurance_docs_distinguish_binding_from_human_provenance(self) -> None:
        threat_model = (PROJECT_ROOT / "docs/THREAT_MODEL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("## Assurance vocabulary and orchestrator boundary", threat_model)
        self.assertIn("**Control-verified**", threat_model)
        self.assertIn("**User-confirmed**", threat_model)
        self.assertIn("**Caller-attested** or **model-attested**", threat_model)
        self.assertIn("`planApproval`", threat_model)
        self.assertIn("`--publication-requested`", threat_model)
        self.assertNotIn(
            "Neither can silently weaken deterministic invariants during a run",
            threat_model,
        )

        assurance_docs = (
            "README.md",
            "CROSSFORGE_BUILD_SPEC.md",
            "docs/ARCHITECTURE.md",
            "docs/LIVE_TESTING.md",
            "skills/crossforge/SKILL.md",
            "skills/crossforge/references/plan-contract.md",
            "skills/crossforge/references/recovery.md",
            "skills/crossforge-ship/SKILL.md",
            "skills/crossforge-ship/references/shipping-protocol.md",
        )
        for relative_path in assurance_docs:
            with self.subTest(path=relative_path):
                text = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
                self.assertTrue(
                    "caller-attested" in text or "model-attested" in text
                )


if __name__ == "__main__":
    unittest.main()
