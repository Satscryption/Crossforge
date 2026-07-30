#!/usr/bin/env python3
"""Deterministic child used by Crossforge's provider-sandbox capability probe."""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

_SPEC_KEYS = {
    "schemaVersion",
    "nonce",
    "workspaceMarker",
    "outsideWriteTarget",
    "credentialTargets",
    "orchestrationTarget",
    "gitCommonDirTarget",
    "outsideSentinel",
    "finalOutputTarget",
    "networkHost",
    "networkPort",
}


def _read_attempt(path: str) -> bool:
    target = Path(path)
    try:
        if target.is_dir():
            iterator = os.scandir(target)
            try:
                next(iterator, None)
            finally:
                iterator.close()
            return True
        descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.read(descriptor, 1)
        finally:
            os.close(descriptor)
        return True
    except OSError:
        return False


def _write_new_attempt(path: str, nonce: str) -> bool:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.write(descriptor, nonce.encode("ascii"))
        finally:
            os.close(descriptor)
        return True
    except OSError:
        return False


def _overwrite_attempt(path: str, nonce: str) -> bool:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.write(descriptor, nonce.encode("ascii"))
        finally:
            os.close(descriptor)
        return True
    except OSError:
        return False


def _network_attempt(host: str, port: int, nonce: str) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2.0) as connection:
            connection.sendall(nonce.encode("ascii"))
        return True
    except OSError:
        return False


def _load_spec(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != _SPEC_KEYS:
        raise ValueError("invalid provider capability probe specification")
    if value["schemaVersion"] != 1:
        raise ValueError("unsupported provider capability probe specification")
    if (
        not isinstance(value["nonce"], str)
        or len(value["nonce"]) != 64
        or any(character not in "0123456789abcdef" for character in value["nonce"])
    ):
        raise ValueError("invalid provider capability probe nonce")
    if not isinstance(value["credentialTargets"], list) or not value[
        "credentialTargets"
    ]:
        raise ValueError("provider capability probe requires credential targets")
    return value


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return 2
    spec_path = Path(argv[0])
    result_path = Path(argv[1])
    try:
        spec = _load_spec(spec_path)
        nonce = spec["nonce"]
        workspace_write_succeeded = _write_new_attempt(
            spec["workspaceMarker"], nonce
        )
        result = {
            "schemaVersion": 1,
            "nonce": nonce,
            "workspaceWriteSucceeded": workspace_write_succeeded,
            "networkConnectSucceeded": _network_attempt(
                spec["networkHost"], spec["networkPort"], nonce
            ),
            "outsideWriteSucceeded": _write_new_attempt(
                spec["outsideWriteTarget"], nonce
            ),
            "credentialReadSucceeded": any(
                _read_attempt(path) for path in spec["credentialTargets"]
            ),
            "orchestrationReadSucceeded": _read_attempt(
                spec["orchestrationTarget"]
            ),
            "gitCommonDirReadSucceeded": _read_attempt(
                spec["gitCommonDirTarget"]
            ),
            "outsideSentinelReadSucceeded": _read_attempt(
                spec["outsideSentinel"]
            ),
            "finalOutputReadSucceeded": _read_attempt(
                spec["finalOutputTarget"]
            ),
            "finalOutputWriteSucceeded": _overwrite_attempt(
                spec["finalOutputTarget"], nonce
            ),
        }
        encoded = json.dumps(
            result, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        descriptor = os.open(
            result_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.write(descriptor, encoded + b"\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return 3


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
