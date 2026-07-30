"""Shared, fail-closed Grok CLI policy construction."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Sequence

CURRENT_SHAPE = "current"
LEGACY_SHAPE = "legacy"

_CURRENT_REQUIRED = (
    "--cwd",
    "--model",
    "--output-format",
    "--permission-mode",
    "--sandbox",
    "--disable-web-search",
    "--no-subagents",
    "--no-memory",
    "--max-turns",
    "--tools",
    "--allow",
    "--deny",
    "--single",
)
_LEGACY_REQUIRED = (
    "--no-auto-update",
    "--cwd",
    "--model",
    "--output-format",
    "--permission-mode",
    "--sandbox",
    "--allow",
    "--disallow",
    "--prompt",
)


def detect_grok_cli_shape(help_text: str) -> str:
    """Return the supported Grok CLI shape or raise ``ValueError``."""

    if all(flag in help_text for flag in _CURRENT_REQUIRED):
        return CURRENT_SHAPE
    if all(flag in help_text for flag in _LEGACY_REQUIRED):
        return LEGACY_SHAPE
    missing_current = sorted(
        flag for flag in _CURRENT_REQUIRED if flag not in help_text
    )
    missing_legacy = sorted(
        flag for flag in _LEGACY_REQUIRED if flag not in help_text
    )
    raise ValueError(
        "Grok CLI lacks a supported constrained headless interface "
        f"(current missing: {', '.join(missing_current)}; "
        f"legacy missing: {', '.join(missing_legacy)})"
    )


def _permission_rule(tool: str, command: Sequence[str]) -> str:
    return f"{tool}({shlex.join(tuple(command))})"


def build_grok_argv(
    executable: Path,
    *,
    shape: str,
    worktree: Path,
    requested_model: str,
    sandbox: str,
    prompt: str,
    review: bool,
    verification_command_prefixes: Sequence[Sequence[str]] = (),
    probe_command: Sequence[str] | None = None,
) -> tuple[str, ...]:
    """Build current or legacy Grok argv from one policy source.

    Capability probes deliberately expose only the command tool. A
    control-host hook separately proves that the exact fixed helper command
    was selected; the common builder keeps all sandbox and network policy
    flags identical to production.
    """

    if shape not in {CURRENT_SHAPE, LEGACY_SHAPE}:
        raise ValueError("unsupported Grok CLI shape")
    if probe_command is not None and (review or verification_command_prefixes):
        raise ValueError("probe policy cannot include review or verification tools")

    if shape == CURRENT_SHAPE:
        argv = [
            str(executable),
            "--cwd",
            str(worktree.resolve()),
            "--output-format",
            "json",
            "--permission-mode",
            "dontAsk",
            "--sandbox",
            sandbox,
            "--disable-web-search",
            "--no-subagents",
            "--no-memory",
            "--max-turns",
            "8" if probe_command is not None else "60",
        ]
        if requested_model != "auto":
            argv.extend(("--model", requested_model))
        if probe_command is not None:
            tools = ("Execute",)
            allow_rules = (_permission_rule("Execute", probe_command),)
        elif review:
            tools = ("Read", "Search", "ListDir")
            allow_rules = tools
        else:
            tools = ("Read", "Search", "ListDir", "Edit")
            allow_rules = list(tools)
            if verification_command_prefixes:
                tools = (*tools, "Execute")
                allow_rules.extend(
                    _permission_rule("Execute", prefix)
                    for prefix in verification_command_prefixes
                )
        argv.extend(("--tools", ",".join(tools)))
        for rule in allow_rules:
            argv.extend(("--allow", rule))
        argv.extend(("--single", prompt))
        return tuple(argv)

    argv = [
        str(executable),
        "--no-auto-update",
        "--cwd",
        str(worktree.resolve()),
        "--output-format",
        "json",
        "--permission-mode",
        "dontAsk",
        "--sandbox",
        sandbox,
    ]
    if requested_model != "auto":
        argv.extend(("--model", requested_model))
    if probe_command is not None:
        argv.extend(("--allow", _permission_rule("Bash", probe_command)))
        disallowed = (
            "Read",
            "Grep",
            "Glob",
            "Edit",
            "Write",
            "WebSearch",
            "RemoteMCP",
            "Computer",
            "Network",
        )
    else:
        for tool in ("Read", "Grep", "Glob"):
            argv.extend(("--allow", tool))
        if not review:
            argv.extend(("--allow", "Edit"))
            for prefix in verification_command_prefixes:
                argv.extend(("--allow", _permission_rule("Bash", prefix)))
        disallowed = ("WebSearch", "RemoteMCP", "Computer", "Network")
    for tool in disallowed:
        argv.extend(("--disallow", tool))
    argv.extend(("--prompt", prompt))
    return tuple(argv)


__all__ = [
    "CURRENT_SHAPE",
    "LEGACY_SHAPE",
    "build_grok_argv",
    "detect_grok_cli_shape",
]
