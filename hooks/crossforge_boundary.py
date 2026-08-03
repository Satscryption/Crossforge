#!/usr/bin/env python3
"""Fail-closed Bash guard for Crossforge skill execution surfaces."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path


MAIN_COMMANDS = frozenset(
    {
        "version",
        "activate-boundary",
        "release-boundary",
        "config",
        "preflight",
        "init-run",
        "status",
        "validate-plan",
        "render-plan",
        "materialize-tasks",
        "start-task",
        "route-task",
        "prepare-consent",
        "record-capability",
        "create-candidate",
        "invoke",
        "check-scope",
        "scan-context",
        "run-gate",
        "capture-candidate",
        "record-selection",
        "accept-candidate",
        "check-micro-fix",
        "finish-task",
        "complete-run",
        "abandon-run",
        "cleanup",
    }
)
CONSENT_COMMANDS = frozenset({"record-consent"})
SHIP_COMMANDS = frozenset(
    {"ship-preflight", "authorize-shipment", "cancel-shipment", "record-shipment"}
)
MAIN_READ_TOOLS = frozenset({"Read", "Grep", "Glob", "AskUserQuestion"})
MAIN_FILE_TOOLS = frozenset({"Write", "Edit", "NotebookEdit"})
MAIN_AGENT_TYPES = frozenset({"commitment-advisor", "independent-reviewer"})
REVIEW_RECOVERY_MESSAGE = (
    "Return the complete Crossforge review report now. Use the required "
    "REVIEW_STATUS contract and do not end with a tool call."
)
FORBIDDEN_SHELL_SYNTAX = (
    "&&",
    "||",
    "&",
    ";",
    "|",
    "\n",
    "\r",
    "`",
    "$(",
    ">",
    "<",
)
PLUGIN_ROOT = Path(__file__).resolve().parents[1]
LEASE_SCHEMA_VERSION = 1


def deny(reason: str) -> int:
    print(f"Crossforge boundary denied tool use: {reason}", file=sys.stderr)
    return 2


def _script_suffix(mode: str) -> str:
    if mode == "main":
        return "/skills/crossforge/scripts/crossforge.py"
    if mode == "consent":
        return "/skills/crossforge-consent/scripts/crossforge_consent.py"
    if mode == "ship":
        return "/skills/crossforge-ship/scripts/crossforge_ship.py"
    raise ValueError("unknown boundary mode")


def _option_value(tokens: list[str], option: str) -> str:
    positions = [index for index, token in enumerate(tokens) if token == option]
    if len(positions) != 1 or positions[0] + 1 >= len(tokens):
        raise ValueError(f"{option} must appear exactly once")
    return tokens[positions[0] + 1]


def _consent_approval(tokens: list[str]) -> int:
    try:
        request_path = _option_value(tokens, "--request")
        request_sha256 = _option_value(tokens, "--request-sha256")
        scripts = PLUGIN_ROOT / "skills" / "crossforge" / "scripts"
        sys.path.insert(0, str(scripts))
        from crossforge import _load_runtime_consent_request
        from crossforge_lib.consent import consent_request_summary
        from types import SimpleNamespace

        request, _path, _store = _load_runtime_consent_request(
            SimpleNamespace(
                request=request_path,
                request_sha256=request_sha256,
            )
        )
        summary = consent_request_summary(request)
    except Exception as error:
        return deny(f"invalid consent request: {error}")
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": (
                        "Approve this exact Crossforge provider consent? "
                        + json.dumps(
                            summary,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    ),
                }
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _tool_input(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("malformed hook input")
    value = payload.get("tool_input")
    if not isinstance(value, dict):
        raise ValueError("malformed hook input")
    return value


def _git_common_dir(cwd: Path) -> Path:
    executable = shutil.which("git")
    if executable is None:
        raise ValueError("Git is unavailable")
    completed = subprocess.run(
        (
            str(Path(executable).resolve(strict=True)),
            "-C",
            str(cwd),
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise ValueError("repository Git common directory is unavailable")
    return Path(completed.stdout.strip()).resolve(strict=True)


def _same_or_within_casefold(path: Path, root: Path) -> bool:
    path_parts = tuple(part.casefold() for part in path.parts)
    root_parts = tuple(part.casefold() for part in root.parts)
    return (
        len(path_parts) >= len(root_parts)
        and path_parts[: len(root_parts)] == root_parts
    )


def _main_file_tool(
    payload: dict[str, object],
    tool_name: str,
    *,
    require_repository: bool = True,
) -> int:
    try:
        tool_input = _tool_input(payload)
        field = "notebook_path" if tool_name == "NotebookEdit" else "file_path"
        raw_path = tool_input.get(field)
        if not isinstance(raw_path, str) or not raw_path:
            raise ValueError(f"{tool_name} is missing {field}")
        raw_cwd = payload.get("cwd", os.getcwd())
        if not isinstance(raw_cwd, str) or not raw_cwd:
            raise ValueError("hook input is missing cwd")
        cwd = Path(raw_cwd).expanduser().resolve(strict=True)
        path = Path(raw_path).expanduser()
        resolved = (
            path.resolve(strict=False)
            if path.is_absolute()
            else (cwd / path).resolve(strict=False)
        )
        if resolved.name.casefold() == "consent.json":
            return deny("the normal skill cannot write a consent record")
        try:
            state_root = _git_common_dir(cwd) / "crossforge"
        except (OSError, subprocess.SubprocessError, ValueError):
            if require_repository:
                raise
        else:
            if _same_or_within_casefold(resolved, state_root):
                return deny("the normal skill cannot edit Crossforge durable state")
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        return deny(str(error))
    return 0


def _payload_identifier(payload: dict[str, object], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"hook input is missing {field}")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _lease_directory(common_dir: Path) -> Path:
    state_root = common_dir / "crossforge"
    lease_root = state_root / "boundary-leases"
    for path in (state_root, lease_root):
        path.mkdir(mode=0o700, exist_ok=True)
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ValueError("Crossforge boundary lease directory is not private")
    return lease_root


def _lease_path(
    common_dir: Path,
    session_sha256: str,
    *,
    create_directory: bool = False,
) -> Path:
    lease_root = (
        _lease_directory(common_dir)
        if create_directory
        else common_dir / "crossforge" / "boundary-leases"
    )
    return lease_root / f"{session_sha256}.json"


def _read_lease(path: Path, session_sha256: str) -> dict[str, object] | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ValueError("Crossforge boundary lease cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o177
        ):
            raise ValueError(
                "Crossforge boundary lease is not a private regular file"
            )
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as handle:
            value = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Crossforge boundary lease is malformed") from error
    finally:
        os.close(descriptor)
    if (
        not isinstance(value, dict)
        or set(value) != {"schemaVersion", "sessionSha256", "promptSha256"}
        or value.get("schemaVersion") != LEASE_SCHEMA_VERSION
        or value.get("sessionSha256") != session_sha256
        or not isinstance(value.get("promptSha256"), str)
    ):
        raise ValueError("Crossforge boundary lease has an invalid schema")
    return value


def _write_lease(path: Path, session_sha256: str, prompt_sha256: str) -> None:
    value = {
        "schemaVersion": LEASE_SCHEMA_VERSION,
        "sessionSha256": session_sha256,
        "promptSha256": prompt_sha256,
    }
    data = (
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _active_pointer_exists(common_dir: Path) -> bool:
    try:
        (common_dir / "crossforge" / "active").lstat()
    except FileNotFoundError:
        return False
    return True


def _is_boundary_command_request(command: str) -> bool:
    if any(marker in command for marker in FORBIDDEN_SHELL_SYNTAX):
        return False
    try:
        tokens = shlex.split(command, posix=True)
        if len(tokens) < 3 or tokens[0] != "python3":
            return False
        script_text = tokens[1].replace(
            "${CLAUDE_PLUGIN_ROOT}", str(PLUGIN_ROOT)
        ).replace("$CLAUDE_PLUGIN_ROOT", str(PLUGIN_ROOT))
        if "$" in script_text:
            return False
        script = Path(os.path.expandvars(script_text)).resolve(strict=True)
        expected = (
            PLUGIN_ROOT / "skills" / "crossforge" / "scripts" / "crossforge.py"
        ).resolve(strict=True)
    except (OSError, ValueError):
        return False
    command_name = next(
        (item for item in tokens[2:] if not item.startswith("-")),
        None,
    )
    return script == expected and command_name in {
        "activate-boundary",
        "release-boundary",
    }


def _main_lifecycle(
    payload: dict[str, object],
) -> tuple[bool, Path | None, str | None, str | None]:
    raw_cwd = payload.get("cwd", os.getcwd())
    if not isinstance(raw_cwd, str) or not raw_cwd:
        raise ValueError("hook input is missing cwd")
    cwd = Path(raw_cwd).expanduser().resolve(strict=True)
    try:
        common_dir = _git_common_dir(cwd)
    except (OSError, subprocess.SubprocessError, ValueError):
        return False, None, None, None
    active_run = _active_pointer_exists(common_dir)
    try:
        session_sha256 = _payload_identifier(payload, "session_id")
        prompt_sha256 = _payload_identifier(payload, "prompt_id")
    except ValueError:
        if active_run:
            raise
        return False, common_dir, None, None
    path = _lease_path(common_dir, session_sha256)
    lease = _read_lease(path, session_sha256)
    if active_run:
        return True, common_dir, session_sha256, prompt_sha256
    if lease is None:
        return False, common_dir, session_sha256, prompt_sha256
    if lease["promptSha256"] == prompt_sha256:
        return True, common_dir, session_sha256, prompt_sha256
    path.unlink()
    return False, common_dir, session_sha256, prompt_sha256


def _activate_boundary(
    common_dir: Path | None,
    session_sha256: str | None,
    prompt_sha256: str | None,
) -> int:
    if common_dir is None or session_sha256 is None or prompt_sha256 is None:
        return deny("boundary activation requires repository, session, and prompt IDs")
    path = _lease_path(common_dir, session_sha256, create_directory=True)
    existing = _read_lease(path, session_sha256)
    if existing is not None and existing["promptSha256"] == prompt_sha256:
        return 0
    _write_lease(path, session_sha256, prompt_sha256)
    return 0


def _release_boundary(common_dir: Path | None, session_sha256: str | None) -> int:
    if common_dir is None or session_sha256 is None:
        return deny("boundary release requires repository and session IDs")
    if _active_pointer_exists(common_dir):
        return deny("the boundary cannot be released while a durable run is active")
    path = _lease_path(common_dir, session_sha256)
    lease = _read_lease(path, session_sha256)
    if lease is not None:
        path.unlink()
    return 0


def _main_non_bash(payload: dict[str, object], tool_name: str) -> int:
    if tool_name in MAIN_READ_TOOLS:
        return 0
    if tool_name in MAIN_FILE_TOOLS:
        return _main_file_tool(payload, tool_name)
    if tool_name == "Agent":
        try:
            tool_input = _tool_input(payload)
            agent_type = tool_input.get("subagent_type")
            if not isinstance(agent_type, str) or not agent_type:
                raise ValueError("Agent is missing subagent_type")
            if agent_type.rsplit(":", 1)[-1] not in MAIN_AGENT_TYPES:
                raise ValueError("Agent type is outside the read-only allowlist")
        except ValueError as error:
            return deny(str(error))
        return 0
    if tool_name == "SendMessage":
        try:
            tool_input = _tool_input(payload)
            recipient = tool_input.get("to")
            message = tool_input.get("message")
            if not isinstance(recipient, str) or not recipient.strip():
                raise ValueError("SendMessage is missing its reviewer recipient")
            if message != REVIEW_RECOVERY_MESSAGE:
                raise ValueError(
                    "SendMessage is limited to the fixed reviewer recovery request"
                )
        except ValueError as error:
            return deny(str(error))
        return 0
    return deny(f"{tool_name} is outside the deterministic control surface")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return deny("invalid hook mode")
    mode = argv[1]
    try:
        payload = json.load(sys.stdin)
        tool_name = payload["tool_name"]
        permission_mode = payload["permission_mode"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return deny("malformed hook input")
    if not isinstance(tool_name, str) or not tool_name:
        return deny("missing tool name")
    if not isinstance(permission_mode, str) or not permission_mode:
        return deny("missing permission mode")
    strict_main = True
    common_dir: Path | None = None
    session_sha256: str | None = None
    prompt_sha256: str | None = None
    if mode == "main":
        try:
            strict_main, common_dir, session_sha256, prompt_sha256 = _main_lifecycle(
                payload
            )
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            return deny(str(error))
        if tool_name != "Bash":
            if strict_main:
                return _main_non_bash(payload, tool_name)
            if tool_name in MAIN_FILE_TOOLS:
                return _main_file_tool(
                    payload,
                    tool_name,
                    require_repository=False,
                )
            return 0
    if mode == "consent" and tool_name != "Bash":
        return deny("only the canonical consent launcher is allowed")
    try:
        command = _tool_input(payload)["command"]
    except (KeyError, TypeError, ValueError):
        return deny("malformed hook input")
    if not isinstance(command, str) or not command.strip():
        return deny("missing command")
    if mode == "main" and not strict_main:
        if not _is_boundary_command_request(command):
            return 0
    if any(marker in command for marker in FORBIDDEN_SHELL_SYNTAX):
        return deny("compound or dynamic shell syntax is not allowed")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return deny("unparseable command")
    if len(tokens) < 3 or tokens[0] != "python3":
        return deny("only the canonical Python control launcher is allowed")
    script_text = tokens[1].replace(
        "${CLAUDE_PLUGIN_ROOT}", str(PLUGIN_ROOT)
    ).replace("$CLAUDE_PLUGIN_ROOT", str(PLUGIN_ROOT))
    if "$" in script_text:
        return deny("unresolved launcher path")
    try:
        script = Path(os.path.expandvars(script_text)).resolve(strict=True)
        expected = (PLUGIN_ROOT / _script_suffix(mode).lstrip("/")).resolve(
            strict=True
        )
    except OSError:
        return deny("launcher path does not exist")
    if script != expected or not script.is_file():
        return deny("wrong Crossforge control surface")
    command_name = next((item for item in tokens[2:] if not item.startswith("-")), None)
    if mode == "main":
        allowed = MAIN_COMMANDS
    elif mode == "consent":
        allowed = CONSENT_COMMANDS
    else:
        allowed = SHIP_COMMANDS
    if command_name not in allowed:
        return deny("command is outside the active skill authority")
    if mode == "main" and command_name == "activate-boundary":
        try:
            return _activate_boundary(common_dir, session_sha256, prompt_sha256)
        except (OSError, ValueError) as error:
            return deny(str(error))
    if mode == "main" and command_name == "release-boundary":
        try:
            return _release_boundary(common_dir, session_sha256)
        except (OSError, ValueError) as error:
            return deny(str(error))
    if mode == "consent":
        if permission_mode == "bypassPermissions":
            return deny(
                "provider consent cannot be recorded in bypassPermissions mode"
            )
        return _consent_approval(tokens)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
