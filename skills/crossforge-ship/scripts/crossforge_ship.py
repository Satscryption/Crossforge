#!/usr/bin/env python3
"""User-invoked Crossforge publication entry point."""

from __future__ import annotations

import sys


if sys.version_info[:2] < (3, 11):
    detected_python = ".".join(str(part) for part in sys.version_info[:2])
    raise SystemExit(
        f"Crossforge: Python 3.11 or newer is required (found Python "
        f"{detected_python} at {sys.executable}). Put a 3.11+ interpreter "
        "first on PATH, or invoke this script with one."
    )

from pathlib import Path


CONTROL_SCRIPTS = (
    Path(__file__).resolve().parents[2] / "crossforge" / "scripts"
)
if str(CONTROL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(CONTROL_SCRIPTS))

from crossforge import shipping_main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(shipping_main())
