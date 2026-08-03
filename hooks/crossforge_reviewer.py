#!/usr/bin/env python3
"""Require independent reviewers to return a complete final report."""

from __future__ import annotations

import json
import re
import sys


STATUSES = frozenset({"findings", "no-findings", "blocked"})
FINDING_FIELDS = ("SEVERITY", "LOCATION", "CONTRACT", "EVIDENCE", "ACTION")


def _block(reason: str) -> int:
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": (
                    f"Crossforge reviewer report is incomplete: {reason}. "
                    "Return a complete final report now; do not end with a tool call."
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _status(message: str) -> str | None:
    match = re.search(
        r"(?m)^REVIEW_STATUS:\s*(findings|no-findings|blocked)\s*$",
        message,
    )
    return match.group(1) if match else None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("malformed hook input")
        agent_type = payload.get("agent_type")
        message = payload.get("last_assistant_message")
        if not isinstance(agent_type, str) or not agent_type:
            raise ValueError("missing agent_type")
        if agent_type.rsplit(":", 1)[-1] != "independent-reviewer":
            return 0
        if not isinstance(message, str) or not message.strip():
            return _block("the final response was empty")
    except (ValueError, json.JSONDecodeError) as error:
        return _block(str(error))

    status = _status(message)
    if status not in STATUSES:
        return _block("the first line must declare a valid REVIEW_STATUS")
    if status == "findings":
        missing = [
            field
            for field in FINDING_FIELDS
            if not re.search(rf"(?m)^{field}:\s*\S", message)
        ]
        if missing:
            return _block("findings are missing " + ", ".join(missing))
    elif not re.search(r"(?m)^EVIDENCE_LIMITATION:\s*\S", message):
        return _block(f"{status} reports require EVIDENCE_LIMITATION")
    if status == "blocked" and not re.search(r"(?m)^ACTION:\s*\S", message):
        return _block("blocked reports require ACTION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
