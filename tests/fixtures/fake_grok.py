#!/usr/bin/env python3
"""Deterministic fake Grok CLI; never performs network or credential access."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


HELP = """usage: grok
--no-auto-update
--cwd DIR
--model MODEL
--output-format json
--permission-mode dontAsk
--allow TOOL
--disallow TOOL
--sandbox PROFILE
--prompt TEXT
"""
CURRENT_HELP = """usage: grok
--cwd DIR
--model MODEL
--output-format json
--permission-mode dontAsk
--sandbox PROFILE
--disable-web-search
--no-subagents
--no-memory
--max-turns N
--tools TOOLS
--allow RULE
--deny RULE
--single PROMPT
"""


def truthy(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes"}


def log_argv() -> None:
    destination = os.environ.get("FAKE_ARGV_LOG")
    if destination:
        Path(destination).write_text(json.dumps(sys.argv[1:]), encoding="utf-8")


def main() -> int:
    log_argv()
    args = sys.argv[1:]
    if args == ["version"]:
        print("grok-cli 0.9.1")
        return 0
    if args == ["--help"]:
        help_text = CURRENT_HELP if truthy("FAKE_CURRENT_HELP") else HELP
        print(
            help_text.replace("--sandbox PROFILE\n", "")
            if truthy("FAKE_UNSAFE_HELP")
            else help_text
        )
        return 0
    if args == ["models"]:
        if truthy("FAKE_AUTH_FAIL"):
            print("password=not-for-logs authentication failed", file=sys.stderr)
            return 4
        print(json.dumps({"models": ["grok-code-fast-1", "grok-4"], "defaultModel": "grok-code-fast-1"}))
        return 0
    delay = float(os.environ.get("FAKE_SLEEP", "0"))
    child: subprocess.Popen[bytes] | None = None
    if truthy("FAKE_SPAWN_CHILD"):
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(300)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        child_path = os.environ.get("FAKE_CHILD_PID_FILE")
        if child_path:
            Path(child_path).write_text(str(child.pid), encoding="ascii")
    if delay:
        time.sleep(delay)
    if truthy("FAKE_LARGE_OUTPUT"):
        block = b"y" * (1024 * 1024)
        for _ in range(10):
            sys.stdout.buffer.write(block)
            sys.stdout.buffer.flush()
            sys.stderr.buffer.write(block)
            sys.stderr.buffer.flush()
    if truthy("FAKE_INVOKE_FAIL"):
        print(f"failure in {os.getcwd()} api_key=do-not-return", file=sys.stderr)
        return 7
    prompt = (
        args[args.index("--single") + 1]
        if "--single" in args
        else args[args.index("--prompt") + 1]
        if "--prompt" in args
        else ""
    )
    print(json.dumps({"provider": "grok", "prompt": prompt, "result": "ok"}))
    if child is not None:
        child.wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
