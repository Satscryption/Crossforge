#!/usr/bin/env python3
"""Fail-closed Bash guard for Crossforge skill execution surfaces."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
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
MAIN_READ_TOOLS = frozenset({"Read", "Grep", "Glob", "AskUserQuestion"})
MAIN_FILE_TOOLS = frozenset({"Write", "Edit", "NotebookEdit"})
MAIN_AGENT_TYPES = frozenset({"commitment-advisor", "independent-reviewer"})
REVIEW_RECOVERY_MESSAGE = (
    "Return the complete Crossforge review report now. Use the required "
    "REVIEW_STATUS contract and do not end with a tool call."
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


def _tool_input(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("malformed hook input")
    value = payload.get("tool_input")
    if not isinstance(value, dict):
        raise ValueError("malformed hook input")
    return value


def _git_common_dir(cwd: Path) -> Path:
    executable = shutil.which("git")
    if executable is None:
        raise ValueError("Git is unavailable")
    completed = subprocess.run(
        (
            str(Path(executable).resolve(strict=True)),
            "-C",
            str(cwd),
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise ValueError("repository Git common directory is unavailable")
    return Path(completed.stdout.strip()).resolve(strict=True)


def _same_or_within_casefold(path: Path, root: Path) -> bool:
    path_parts = tuple(part.casefold() for part in path.parts)
    root_parts = tuple(part.casefold() for part in root.parts)
    return (
        len(path_parts) >= len(root_parts)
        and path_parts[: len(root_parts)] == root_parts
    )


def _main_file_tool(payload: dict[str, object], tool_name: str) -> int:
    try:
        tool_input = _tool_input(payload)
        field = "notebook_path" if tool_name == "NotebookEdit" else "file_path"
        raw_path = tool_input.get(field)
        if not isinstance(raw_path, str) or not raw_path:
            raise ValueError(f"{tool_name} is missing {field}")
        raw_cwd = payload.get("cwd", os.getcwd())
        if not isinstance(raw_cwd, str) or not raw_cwd:
            raise ValueError("hook input is missing cwd")
        cwd = Path(raw_cwd).expanduser().resolve(strict=True)
        path = Path(raw_path).expanduser()
        resolved = (
            path.resolve(strict=False)
            if path.is_absolute()
            else (cwd / path).resolve(strict=False)
        )
        if resolved.name.casefold() == "consent.json":
            return deny("the normal skill cannot write a consent record")
        state_root = _git_common_dir(cwd) / "crossforge"
        if _same_or_within_casefold(resolved, state_root):
            return deny("the normal skill cannot edit Crossforge durable state")
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        return deny(str(error))
    return 0


def _main_non_bash(payload: dict[str, object], tool_name: str) -> int:
    if tool_name in MAIN_READ_TOOLS:
        return 0
    if tool_name in MAIN_FILE_TOOLS:
        return _main_file_tool(payload, tool_name)
    if tool_name == "Agent":
        try:
            tool_input = _tool_input(payload)
            agent_type = tool_input.get("subagent_type")
            if not isinstance(agent_type, str) or not agent_type:
                raise ValueError("Agent is missing subagent_type")
            if agent_type.rsplit(":", 1)[-1] not in MAIN_AGENT_TYPES:
                raise ValueError("Agent type is outside the read-only allowlist")
        except ValueError as error:
            return deny(str(error))
        return 0
    if tool_name == "SendMessage":
        try:
            tool_input = _tool_input(payload)
            recipient = tool_input.get("to")
            message = tool_input.get("message")
            if not isinstance(recipient, str) or not recipient.strip():
                raise ValueError("SendMessage is missing its reviewer recipient")
            if message != REVIEW_RECOVERY_MESSAGE:
                raise ValueError(
                    "SendMessage is limited to the fixed reviewer recovery request"
                )
        except ValueError as error:
            return deny(str(error))
        return 0
    return deny(f"{tool_name} is outside the deterministic control surface")


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
    if mode == "main" and tool_name != "Bash":
        return _main_non_bash(payload, tool_name)
    if mode == "consent" and tool_name != "Bash":
        return deny("only the canonical consent launcher is allowed")
    try:
        command = _tool_input(payload)["command"]
    except (KeyError, TypeError, ValueError):
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
