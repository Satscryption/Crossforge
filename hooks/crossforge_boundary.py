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
        "prepare-consent",
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
CONSENT_COMMANDS = frozenset({"record-consent"})
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
    if mode == "consent":
        return "/skills/crossforge-consent/scripts/crossforge_consent.py"
    if mode == "ship":
        return "/skills/crossforge-ship/scripts/crossforge_ship.py"
    raise ValueError("unknown boundary mode")


def _option_value(tokens: list[str], option: str) -> str:
    positions = [index for index, token in enumerate(tokens) if token == option]
    if len(positions) != 1 or positions[0] + 1 >= len(tokens):
        raise ValueError(f"{option} must appear exactly once")
    return tokens[positions[0] + 1]


def _consent_approval(tokens: list[str]) -> int:
    try:
        request_path = _option_value(tokens, "--request")
        request_sha256 = _option_value(tokens, "--request-sha256")
        scripts = PLUGIN_ROOT / "skills" / "crossforge" / "scripts"
        sys.path.insert(0, str(scripts))
        from crossforge import _load_runtime_consent_request
        from crossforge_lib.consent import consent_request_summary
        from types import SimpleNamespace

        request, _path, _store = _load_runtime_consent_request(
            SimpleNamespace(
                request=request_path,
                request_sha256=request_sha256,
            )
        )
        summary = consent_request_summary(request)
    except Exception as error:
        return deny(f"invalid consent request: {error}")
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": (
                        "Approve this exact Crossforge provider consent? "
                        + json.dumps(
                            summary,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    ),
                }
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return deny("invalid hook mode")
    mode = argv[1]
    try:
        payload = json.load(sys.stdin)
        tool_name = payload["tool_name"]
        permission_mode = payload["permission_mode"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return deny("malformed hook input")
    if not isinstance(tool_name, str) or not tool_name:
        return deny("missing tool name")
    if not isinstance(permission_mode, str) or not permission_mode:
        return deny("missing permission mode")
    if mode == "deny-mutation":
        return deny(f"{tool_name} is outside the deterministic control surface")
    if mode == "consent" and tool_name != "Bash":
        return deny("only the canonical consent launcher is allowed")
    try:
        command = payload["tool_input"]["command"]
    except (KeyError, TypeError):
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
    if mode == "main":
        allowed = MAIN_COMMANDS
    elif mode == "consent":
        allowed = CONSENT_COMMANDS
    else:
        allowed = SHIP_COMMANDS
    if command_name not in allowed:
        return deny("command is outside the active skill authority")
    if mode == "consent":
        if permission_mode == "bypassPermissions":
            return deny(
                "provider consent cannot be recorded in bypassPermissions mode"
            )
        return _consent_approval(tokens)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
