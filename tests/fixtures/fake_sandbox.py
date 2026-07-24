#!/usr/bin/env python3
"""Small sandbox CLI double used by unit tests.

It understands the invocation surface emitted by ``gates.py``.  It is not a
security boundary and must never be used outside tests.
"""

from __future__ import annotations

import os
import subprocess
import sys


def _run_bwrap(arguments: list[str]) -> int:
    environment: dict[str, str] = dict(os.environ)
    working_directory: str | None = None
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            command = arguments[index + 1 :]
            break
        if argument == "--clearenv":
            environment = {}
            index += 1
            continue
        if argument == "--setenv":
            environment[arguments[index + 1]] = arguments[index + 2]
            index += 3
            continue
        if argument == "--chdir":
            working_directory = arguments[index + 1]
            index += 2
            continue
        if argument in {"--proc", "--dev"}:
            index += 2
            continue
        if argument in {"--ro-bind", "--bind"}:
            index += 3
            continue
        index += 1
    else:
        print("missing command separator", file=sys.stderr)
        return 2
    if not command:
        return 2
    return subprocess.run(
        command,
        cwd=working_directory,
        env=environment,
        check=False,
    ).returncode


def _run_sandbox_exec(arguments: list[str]) -> int:
    if arguments and arguments[0] == "-f":
        arguments = arguments[2:]
    if not arguments:
        return 2
    return subprocess.run(arguments, check=False).returncode


def main() -> int:
    arguments = sys.argv[1:]
    if arguments in (["--version"], ["-h"]):
        print("crossforge fake sandbox 1")
        return 0
    if "--die-with-parent" in arguments or "--unshare-net" in arguments:
        return _run_bwrap(arguments)
    return _run_sandbox_exec(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
