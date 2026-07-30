#!/usr/bin/env python3
"""Fail-closed Grok control-host receipt for the exact probe command."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path


def _deny(reason: str) -> int:
    print(json.dumps({"decision": "deny", "reason": reason}))
    return 2


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return _deny("invalid Crossforge capability hook contract")
    expected_sha256, nonce, receipt_text = argv
    if (
        len(expected_sha256) != 64
        or len(nonce) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
        or any(character not in "0123456789abcdef" for character in nonce)
    ):
        return _deny("invalid Crossforge capability hook identity")
    try:
        event = json.load(sys.stdin)
    except (UnicodeError, json.JSONDecodeError):
        return _deny("invalid Grok hook event")
    if not isinstance(event, dict):
        return _deny("invalid Grok hook event")
    tool_name = event.get("toolName") or event.get("tool_name")
    tool_input = event.get("toolInput") or event.get("tool_input")
    if not isinstance(tool_input, dict):
        return _deny("missing Grok tool input")
    command = tool_input.get("command") or tool_input.get("cmd")
    if tool_name not in {
        "Execute",
        "Bash",
        "run_terminal_cmd",
        "run_terminal_command",
    } or not isinstance(command, str):
        return _deny("only the fixed capability helper command is allowed")
    command_sha256 = hashlib.sha256(command.encode("utf-8")).hexdigest()
    if command_sha256 != expected_sha256:
        return _deny("capability helper command does not match the sealed contract")
    receipt = Path(receipt_text)
    encoded = json.dumps(
        {
            "schemaVersion": 1,
            "nonce": nonce,
            "toolName": tool_name,
            "commandSha256": command_sha256,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        descriptor = os.open(
            receipt,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.write(descriptor, encoded + b"\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        return _deny("capability hook receipt could not be recorded")
    print(json.dumps({"decision": "allow"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
