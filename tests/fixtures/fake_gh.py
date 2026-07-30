#!/usr/bin/env python3
"""Stateful fake GitHub CLI for shipping tests only."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def load(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"createCalls": 0, "listCalls": 0, "prs": []}


def save(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def option(args: list[str], name: str) -> str:
    return args[args.index(name) + 1]


def main() -> int:
    state_path = Path(os.environ["FAKE_GH_STATE"])
    state = load(state_path)
    args = sys.argv[1:]
    if args[:2] == ["pr", "list"]:
        state["listCalls"] += 1
        save(state_path, state)
        print(json.dumps(state["prs"]))
        return 0
    if args[:2] == ["pr", "create"]:
        state["createCalls"] += 1
        number = len(state["prs"]) + 1
        state["prs"].append(
            {
                "number": number,
                "url": f"https://github.com/{option(args, '--repo')}/pull/{number}",
                "state": "OPEN",
                "headRefName": option(args, "--head").split(":", 1)[-1],
                "baseRefName": option(args, "--base"),
                "headRefOid": os.environ.get("FAKE_GH_HEAD_COMMIT"),
                "isCrossRepository": False,
                "headRepositoryOwner": {
                    "login": option(args, "--repo").split("/", 1)[0]
                },
            }
        )
        save(state_path, state)
        print(state["prs"][-1]["url"])
        return 0
    print("unsupported fake gh command", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
