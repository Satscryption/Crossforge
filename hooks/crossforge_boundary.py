#!/usr/bin/env python3
"""Fail-closed Bash guard for Crossforge skill execution surfaces."""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path


MAIN_COMMANDS = frozenset(
    {
        "version",
        "config",
        "preflight",
        "init-run",
        "status",
        "validate-plan",
        "render-plan",
        "materialize-tasks",
        "start-task",
        "route-task",
        "record-consent",
        "record-capability",
        "create-candidate",
        "invoke",
        "check-scope",
        "scan-context",
        "run-gate",
        "capture-candidate",
        "record-selection",
        "accept-candidate",
        "check-micro-fix",
        "finish-task",
        "complete-run",
        "abandon-run",
        "cleanup",
    }
)
SHIP_COMMANDS = frozenset(
    {"ship-preflight", "authorize-shipment", "cancel-shipment", "record-shipment"}
)
FORBIDDEN_SHELL_SYNTAX = (
    "&&",
    "||",
    "&",
    ";",
    "|",
    "\n",
    "\r",
    "`",
    "$(",
    ">",
    "<",
)
PLUGIN_ROOT = Path(__file__).resolve().parents[1]


def deny(reason: str) -> int:
    print(f"Crossforge boundary denied Bash: {reason}", file=sys.stderr)
    return 2


def _script_suffix(mode: str) -> str:
    if mode == "main":
        return "/skills/crossforge/scripts/crossforge.py"
    if mode == "ship":
        return "/skills/crossforge-ship/scripts/crossforge_ship.py"
    raise ValueError("unknown boundary mode")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return deny("invalid hook mode")
    mode = argv[1]
    try:
        payload = json.load(sys.stdin)
        command = payload["tool_input"]["command"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return deny("malformed hook input")
    if not isinstance(command, str) or not command.strip():
        return deny("missing command")
    if any(marker in command for marker in FORBIDDEN_SHELL_SYNTAX):
        return deny("compound or dynamic shell syntax is not allowed")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return deny("unparseable command")
    if len(tokens) < 3 or tokens[0] != "python3":
        return deny("only the canonical Python control launcher is allowed")
    script_text = tokens[1].replace(
        "${CLAUDE_PLUGIN_ROOT}", str(PLUGIN_ROOT)
    ).replace("$CLAUDE_PLUGIN_ROOT", str(PLUGIN_ROOT))
    if "$" in script_text:
        return deny("unresolved launcher path")
    try:
        script = Path(os.path.expandvars(script_text)).resolve(strict=True)
        expected = (PLUGIN_ROOT / _script_suffix(mode).lstrip("/")).resolve(
            strict=True
        )
    except OSError:
        return deny("launcher path does not exist")
    if script != expected or not script.is_file():
        return deny("wrong Crossforge control surface")
    command_name = next((item for item in tokens[2:] if not item.startswith("-")), None)
    allowed = MAIN_COMMANDS if mode == "main" else SHIP_COMMANDS
    if command_name not in allowed:
        return deny("command is outside the active skill authority")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
