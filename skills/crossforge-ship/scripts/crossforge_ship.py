#!/usr/bin/env python3
"""User-invoked Crossforge publication entry point."""

from __future__ import annotations

import sys
from pathlib import Path


CONTROL_SCRIPTS = (
    Path(__file__).resolve().parents[2] / "crossforge" / "scripts"
)
if str(CONTROL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(CONTROL_SCRIPTS))

from crossforge import shipping_main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(shipping_main())
