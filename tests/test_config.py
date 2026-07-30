from __future__ import annotations

import copy
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "skills/crossforge/scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from crossforge_lib.config import (  # noqa: E402
    DEFAULT_CONFIG,
    config_to_dict,
    load_config,
    merge_config,
    normalize_config,
)
from crossforge_lib.errors import ConfigError  # noqa: E402
from crossforge_lib.models import Budget, SandboxBackend  # noqa: E402
from crossforge_lib.util import atomic_write_json, atomic_write_text  # noqa: E402


class ConfigTests(unittest.TestCase):
    def test_default_normalization(self) -> None:
        config = normalize_config(copy.deepcopy(DEFAULT_CONFIG))
        self.assertEqual(config.budget, Budget.BALANCED)
        self.assertTrue(config.codex.enabled)
        self.assertTrue(config.grok.enabled)
        self.assertEqual(config.gates.sandbox_backend, SandboxBackend.AUTO)
        self.assertEqual(config.gates.network.value, "deny")
        self.assertEqual(config_to_dict(config), DEFAULT_CONFIG)

    def test_precedence_and_recursive_merge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            user = root / "user.json"
            project = root / "project.json"
            user.write_text(
                json.dumps(
                    {
                        "budget": "lean",
                        "providers": {"codex": {"timeoutSeconds": 100}},
                    }
                ),
                encoding="utf-8",
            )
            project.write_text(
                json.dumps(
                    {
                        "budget": "quality",
                        "providers": {"codex": {"model": "o3"}},
                    }
                ),
                encoding="utf-8",
            )
            config = load_config(
                user_path=user,
                project_path=project,
                cli_overrides={
                    "budget": "balanced",
                    "providers": {"codex": {"effort": "xhigh"}},
                },
            )
        self.assertEqual(config.budget.value, "balanced")
        self.assertEqual(config.codex.timeout_seconds, 100)
        self.assertEqual(config.codex.model, "o3")
        self.assertEqual(config.codex.effort.value, "xhigh")

    def test_default_discovery_can_be_disabled_for_bound_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".claude").mkdir()
            (root / ".claude" / "crossforge.json").write_text(
                '{"budget":"quality"}\n',
                encoding="utf-8",
            )
            previous = Path.cwd()
            try:
                os.chdir(root)
                discovered = load_config()
                bound = load_config(discover_defaults=False)
            finally:
                os.chdir(previous)
        self.assertEqual(discovered.budget, Budget.QUALITY)
        self.assertEqual(bound.budget, Budget.BALANCED)

    def test_merge_replaces_arrays_in_full(self) -> None:
        merged = merge_config(
            {"nested": {"array": ["old"], "kept": True}},
            {"nested": {"array": ["new"]}},
        )
        self.assertEqual(merged, {"nested": {"array": ["new"], "kept": True}})

    def test_unknown_top_level_and_nested_keys_fail(self) -> None:
        for override in (
            {"budegt": "lean"},
            {"providers": {"codex": {"timeotSeconds": 10}}},
        ):
            with self.subTest(override=override):
                with self.assertRaises(ConfigError):
                    load_config(cli_overrides=override)

    def test_bounds_and_enums_fail(self) -> None:
        invalid_values = (
            ("provider timeout", ("providers", "codex", "timeoutSeconds"), 9),
            ("provider timeout high", ("providers", "grok", "timeoutSeconds"), 7201),
            ("consent low", ("consent", "ttlDays"), 0),
            ("consent high", ("consent", "ttlDays"), 366),
            ("microfix low", ("microFix", "maximumChangedLines"), -1),
            ("microfix high", ("microFix", "maximumChangedLines"), 11),
            ("gate timeout", ("gates", "timeoutSeconds"), 9),
            ("budget enum", ("budget",), "fast"),
            ("effort enum", ("providers", "codex", "effort"), "extreme"),
        )
        for label, path, invalid in invalid_values:
            value = copy.deepcopy(DEFAULT_CONFIG)
            cursor = value
            for component in path[:-1]:
                cursor = cursor[component]
            cursor[path[-1]] = invalid
            with self.subTest(label=label):
                with self.assertRaises(ConfigError):
                    normalize_config(value)

    def test_gate_validation(self) -> None:
        for key, invalid in (
            ("sandboxBackend", "docker"),
            ("network", "allow"),
            ("executableAllowlist", ["bin/python"]),
            ("executableAllowlist", [""]),
        ):
            value = copy.deepcopy(DEFAULT_CONFIG)
            value["gates"][key] = invalid
            with self.subTest(key=key, invalid=invalid):
                with self.assertRaises(ConfigError):
                    normalize_config(value)

    def test_provider_can_be_disabled_but_not_omitted_after_normalization(self) -> None:
        value = copy.deepcopy(DEFAULT_CONFIG)
        value["providers"]["codex"]["enabled"] = False
        self.assertFalse(normalize_config(value).codex.enabled)
        del value["providers"]["grok"]
        with self.assertRaises(ConfigError):
            normalize_config(value)

    def test_invalid_models_and_deny_paths_fail(self) -> None:
        values = []
        model = copy.deepcopy(DEFAULT_CONFIG)
        model["providers"]["codex"]["model"] = "bad\nmodel"
        values.append(model)
        absolute = copy.deepcopy(DEFAULT_CONFIG)
        absolute["denyPaths"] = ["/secrets/**"]
        values.append(absolute)
        parent = copy.deepcopy(DEFAULT_CONFIG)
        parent["denyPaths"] = ["../secrets/**"]
        values.append(parent)
        for value in values:
            with self.assertRaises(ConfigError):
                normalize_config(value)

    def test_atomic_text_and_json_writes_replace_complete_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            text_path = root / "pointer"
            json_path = root / "record.json"
            atomic_write_text(text_path, "first\n")
            atomic_write_text(text_path, "second\n")
            atomic_write_json(json_path, {"z": 1, "a": 2})
            self.assertEqual(text_path.read_text(encoding="utf-8"), "second\n")
            self.assertEqual(
                json_path.read_text(encoding="utf-8"),
                '{\n  "a": 2,\n  "z": 1\n}\n',
            )
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(text_path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(json_path.stat().st_mode), 0o600)
            self.assertEqual(list(root.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
