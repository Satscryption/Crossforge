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
        normalized_threat_model = " ".join(threat_model.split())
        for expected in (
            "## Assurance vocabulary and orchestrator boundary",
            "**Control-verified**",
            "**User-confirmed**",
            "**Caller-attested** or **model-attested**",
            "`planApproval`",
            "`--publication-requested`",
            "cannot authenticate their semantic",
        ):
            self.assertIn(" ".join(expected.split()), normalized_threat_model)

        required_by_document = {
            "README.md": (
                "Trust and assurance boundary",
                "plan-approval record is model-attested",
                "destination-override flags are caller-attested",
            ),
            "CROSSFORGE_BUILD_SPEC.md": (
                "**Caller-attested/model-attested:**",
                "`planApproval`",
                "`--target-change-approved`",
            ),
            "docs/ARCHITECTURE.md": (
                "Plan content and `planApproval` provenance",
                "caller-attested approval",
            ),
            "docs/IMPLEMENTATION_DECISIONS.md": (
                "DEV-010",
                "`planApproval` remains model-attested",
            ),
            "docs/LIVE_TESTING.md": (
                "user-invoked surfaces",
                "publication/destination flags remain caller-attested",
            ),
            "skills/crossforge/SKILL.md": (
                "**User-confirmed decisions:**",
                "**Caller/model attestations:**",
            ),
            "skills/crossforge/references/candidate-selection.md": (
                "caller-attested decision",
            ),
            "skills/crossforge/references/plan-contract.md": (
                "approval record",
                "model-attested",
                "not human provenance",
            ),
            "skills/crossforge/references/recovery.md": (
                "caller-attested recovery",
                "cannot authenticate",
            ),
            "skills/crossforge/references/worktree-protocol.md": (
                "caller-attested recovery approval",
            ),
            "skills/crossforge-ship/SKILL.md": (
                "`--publication-requested`",
                "caller attestations",
            ),
            "skills/crossforge-ship/references/shipping-protocol.md": (
                "`--target-change-approved`",
                "caller-attested inputs",
            ),
        }
        all_text = threat_model
        for relative_path, expected_phrases in required_by_document.items():
            with self.subTest(path=relative_path):
                text = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
                all_text += "\n" + text
                normalized_text = " ".join(text.split())
                for expected in expected_phrases:
                    self.assertIn(" ".join(expected.split()), normalized_text)

        normalized_all_text = " ".join(all_text.split())
        for overclaim in (
            "Neither can silently weaken deterministic invariants during a run",
            "user-approved recovery decision",
            "explicit user approval when host identity differs",
        ):
            self.assertNotIn(overclaim, normalized_all_text)

    def test_operator_messages_label_caller_attestations(self) -> None:
        sources = {
            relative_path: (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
            for relative_path in (
                "skills/crossforge/scripts/crossforge.py",
                "skills/crossforge/scripts/crossforge_lib/locking.py",
                "skills/crossforge/scripts/crossforge_lib/shipping.py",
                "skills/crossforge/scripts/crossforge_lib/state.py",
            )
        }
        for relative_path, text in sources.items():
            with self.subTest(path=relative_path):
                self.assertIn("caller-attested", text)

        combined = "\n".join(sources.values())
        for overclaim in (
            "current user request explicitly authorizes publication",
            "current user request does not authorize publication",
            "user-approved recovery decision",
            "requires explicit approval",
            "needs explicit approval",
        ):
            self.assertNotIn(overclaim, combined)


if __name__ == "__main__":
    unittest.main()
