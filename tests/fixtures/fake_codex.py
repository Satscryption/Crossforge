#!/usr/bin/env python3
"""Deterministic fake Codex CLI; never performs network or credential access."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


def truthy(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes"}


def log_argv() -> None:
    destination = os.environ.get("FAKE_ARGV_LOG")
    if destination:
        Path(destination).write_text(json.dumps(sys.argv[1:]), encoding="utf-8")


def main() -> int:
    log_argv()
    args = sys.argv[1:]
    if args == ["--version"]:
        print("codex-cli 1.2.3")
        return 0
    if args == ["login", "status"]:
        if truthy("FAKE_AUTH_FAIL"):
            print("authentication token=super-secret-value invalid", file=sys.stderr)
            return 4
        print("authenticated")
        return 0
    if not args or args[0] != "exec":
        print("unsupported fake command", file=sys.stderr)
        return 2
    prompt = sys.stdin.buffer.read()
    if truthy("FAKE_MODEL_FAIL") and b"source-free readiness probe" in prompt:
        print("requested model unavailable", file=sys.stderr)
        return 5
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
    delay = float(os.environ.get("FAKE_SLEEP", "0"))
    if delay:
        time.sleep(delay)
    if truthy("FAKE_LARGE_OUTPUT"):
        block = b"x" * (1024 * 1024)
        for _ in range(10):
            sys.stdout.buffer.write(block)
            sys.stdout.buffer.flush()
            sys.stderr.buffer.write(block)
            sys.stderr.buffer.flush()
    if truthy("FAKE_INVOKE_FAIL"):
        print(
            f"failure in {os.getcwd()} bearer fake-sensitive-token",
            file=sys.stderr,
        )
        return 7
    if "--output-last-message" in args:
        destination = Path(args[args.index("--output-last-message") + 1])
        model = "cli-default"
        if "--model" in args:
            model = args[args.index("--model") + 1]
        if b"source-free readiness probe" in prompt:
            content = model
        else:
            content = json.dumps(
                {"provider": "codex", "promptBytes": len(prompt), "model": model}
            )
        destination.write_text(content, encoding="utf-8")
    print('{"result":"ok"}')
    if child is not None:
        child.wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
