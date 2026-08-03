"""Bootstrap checks for Crossforge's repository and plugin metadata."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path


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

    def test_security_review_closeout_links_and_release_contracts(self) -> None:
        closeout = (PROJECT_ROOT / "docs/SECURITY_REVIEW_CLOSEOUT.md").read_text(
            encoding="utf-8"
        )
        for issue_number in range(3, 16):
            with self.subTest(issue=issue_number):
                self.assertIn(
                    f"https://github.com/Satscryption/Crossforge/issues/{issue_number}",
                    closeout,
                )
        for pull_request in range(17, 27):
            with self.subTest(pull_request=pull_request):
                self.assertIn(
                    f"https://github.com/Satscryption/Crossforge/pull/{pull_request}",
                    closeout,
                )

        linked_docs = (
            "README.md",
            "docs/ARCHITECTURE.md",
            "docs/IMPLEMENTATION_DECISIONS.md",
            "docs/THREAT_MODEL.md",
        )
        for relative_path in linked_docs:
            with self.subTest(path=relative_path):
                text = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn("SECURITY_REVIEW_CLOSEOUT.md", text)

        specification = (PROJECT_ROOT / "CROSSFORGE_BUILD_SPEC.md").read_text(
            encoding="utf-8"
        )
        config_schema = specification.split(
            "### Configuration schema", maxsplit=1
        )[1].split("### Required config validation", maxsplit=1)[0]
        self.assertIn(
            "**Target product:** Claude Code plugin with three user-facing skills",
            specification,
        )
        self.assertIn('"schemaVersion": 1', config_schema)
        self.assertIn(
            "`record-shipment` to the dedicated shipping CLI, not the normal CLI",
            specification,
        )
        live_testing = (PROJECT_ROOT / "docs/LIVE_TESTING.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "No Crossforge 0.1.0 test or control command reads this variable",
            live_testing,
        )
        self.assertNotIn(
            "Setting the variable is necessary",
            live_testing,
        )

        release_contract = "\n".join(
            (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
            for relative_path in (
                "CROSSFORGE_BUILD_SPEC.md",
                "docs/ARCHITECTURE.md",
                "skills/crossforge/SKILL.md",
                "skills/crossforge/references/routing-policy.md",
            )
        )
        for stale_claim in (
            "**Target product:** Claude Code plugin with two user-facing skills",
            "Medium-risk plans receive one external read-only critique",
            "High-risk plans receive independent Codex and Grok critiques",
            "Obtain independent read-only Codex and Grok plan critiques",
            "cross-vendor planning, isolated coding",
        ):
            self.assertNotIn(stale_claim, release_contract)

    def test_documented_command_boundaries_match_runtime(self) -> None:
        main_script = (
            PROJECT_ROOT / "skills/crossforge/scripts/crossforge.py"
        )
        consent_script = (
            PROJECT_ROOT
            / "skills/crossforge-consent/scripts/crossforge_consent.py"
        )
        shipping_script = (
            PROJECT_ROOT
            / "skills/crossforge-ship/scripts/crossforge_ship.py"
        )
        main_help = subprocess.run(
            [sys.executable, str(main_script), "--help"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        consent_help = subprocess.run(
            [sys.executable, str(consent_script), "--help"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        shipping_help = subprocess.run(
            [sys.executable, str(shipping_script), "--help"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        for shipping_command in (
            "ship-preflight",
            "authorize-shipment",
            "cancel-shipment",
            "record-shipment",
        ):
            with self.subTest(command=shipping_command):
                self.assertNotIn(shipping_command, main_help)
                self.assertIn(shipping_command, shipping_help)
        self.assertNotIn("record-consent", main_help)
        self.assertIn("record-consent", consent_help)

        control_source = main_script.read_text(encoding="utf-8")
        self.assertIn(
            'raise PreconditionError("capability probe requires an active run")',
            control_source,
        )
        runtime_source = "\n".join(
            path.read_text(encoding="utf-8")
            for root in (
                PROJECT_ROOT / "skills",
                PROJECT_ROOT / "hooks",
            )
            for path in root.rglob("*.py")
        )
        self.assertNotIn("CROSSFORGE_LIVE_TESTS", runtime_source)

    def test_launchers_fail_clearly_on_unsupported_python(self) -> None:
        launchers = (
            PROJECT_ROOT / "skills/crossforge/scripts/crossforge.py",
            PROJECT_ROOT
            / "skills/crossforge-consent/scripts/crossforge_consent.py",
            PROJECT_ROOT
            / "skills/crossforge-ship/scripts/crossforge_ship.py",
        )
        simulated_unsupported_runtime = (
            "import runpy, sys; "
            "sys.version_info = (3, 9, 6, 'final', 0); "
            "runpy.run_path(sys.argv[1], run_name='__main__')"
        )
        for launcher in launchers:
            with self.subTest(launcher=launcher.relative_to(PROJECT_ROOT)):
                launcher_source = launcher.read_text(encoding="utf-8")
                package_import = (
                    "from crossforge_lib"
                    if launcher.name == "crossforge.py"
                    else "from crossforge import"
                )
                self.assertLess(
                    launcher_source.index("if sys.version_info"),
                    launcher_source.index(package_import),
                )
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        simulated_unsupported_runtime,
                        str(launcher),
                        "--help",
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(1, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn(
                    "Python 3.11 or newer is required",
                    result.stderr,
                )
                self.assertIn("found Python 3.9", result.stderr)
                self.assertIn(str(Path(sys.executable)), result.stderr)
                self.assertIn("first on PATH", result.stderr)

    def test_local_markdown_links_resolve(self) -> None:
        link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
        for document in PROJECT_ROOT.rglob("*.md"):
            text = document.read_text(encoding="utf-8")
            for raw_target in link_pattern.findall(text):
                target = raw_target.strip().strip("<>")
                if (
                    not target
                    or target.startswith("#")
                    or "://" in target
                    or target.startswith("mailto:")
                ):
                    continue
                relative_target = target.split("#", maxsplit=1)[0]
                resolved = (document.parent / relative_target).resolve()
                with self.subTest(
                    document=document.relative_to(PROJECT_ROOT),
                    target=raw_target,
                ):
                    self.assertTrue(
                        resolved.is_file(),
                        f"{document}: local Markdown link does not resolve: {raw_target}",
                    )


if __name__ == "__main__":
    unittest.main()
