"""Structured, sandboxed verification-gate execution."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from .errors import GateFailureError, InvalidInputError, PolicyError, PreconditionError
from .evidence import EvidenceStore, normalize_evidence_path
from .util import canonical_json_bytes, ensure_private_directory, sha256_bytes, sha256_file

SUPPORTED_BACKENDS = frozenset({"auto", "sandbox-exec", "bwrap"})
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SHELL_SHORT_INLINE = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")
_SHELL_EXPRESSION = re.compile(r"(?:\$\(|`|&&|\|\||(?:^|[0-9])>>?|<<|[|;])")
_SENSITIVE_ENVIRONMENT = re.compile(
    r"(?:"
    r"TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|COOKIE|AUTH|PRIVATE_KEY|"
    r"SSH_AUTH_SOCK|API_?KEY|ACCESS_?KEY|DATABASE_URL|KUBECONFIG"
    r")",
    re.IGNORECASE,
)
_SHELLS = frozenset(
    {"sh", "bash", "dash", "zsh", "fish", "ksh", "csh", "tcsh", "cmd", "powershell", "pwsh"}
)
_INDIRECT_LAUNCHERS = frozenset(
    {
        "env",
        "command",
        "xargs",
        "find",
        "nice",
        "nohup",
        "timeout",
        "setsid",
        "watch",
    }
)
_INTERPRETER_INLINE_FLAGS: dict[str, frozenset[str]] = {
    "python": frozenset({"-c"}),
    "python3": frozenset({"-c"}),
    "pypy": frozenset({"-c"}),
    "pypy3": frozenset({"-c"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "nodejs": frozenset({"-e", "--eval", "-p", "--print"}),
    "ruby": frozenset({"-e"}),
    "perl": frozenset({"-e", "-E"}),
    "php": frozenset({"-r"}),
    "lua": frozenset({"-e"}),
}
_SHELL_INLINE_FLAGS = frozenset(
    {"-c", "--command", "-command", "/c", "-encodedcommand", "-enc"}
)
_ALWAYS_REJECT = frozenset(
    {
        "rm",
        "rmdir",
        "unlink",
        "shred",
        "wipefs",
        "mkfs",
        "fdisk",
        "parted",
        "dd",
        "mv",
        "truncate",
        "chown",
        "sudo",
        "doas",
        "su",
        "pkexec",
        "scp",
        "sftp",
        "ssh",
    }
)
_GIT_REJECT = frozenset(
    {
        "push",
        "pull",
        "fetch",
        "clone",
        "remote",
        "credential",
        "clean",
        "reset",
        "restore",
        "checkout",
        "switch",
        "rm",
        "worktree",
        "submodule",
        "commit",
        "tag",
        "send-email",
    }
)
_PUBLISH_ACTIONS: dict[str, frozenset[str]] = {
    "npm": frozenset({"publish", "login", "adduser", "token", "unpublish", "deprecate"}),
    "pnpm": frozenset({"publish", "login"}),
    "yarn": frozenset({"npm", "publish", "login"}),
    "cargo": frozenset({"publish", "login", "owner", "yank"}),
    "twine": frozenset({"upload"}),
    "gem": frozenset({"push", "yank", "signin", "signout"}),
    "poetry": frozenset({"publish"}),
    "docker": frozenset({"push", "login", "logout"}),
    "podman": frozenset({"push", "login", "logout"}),
    "gh": frozenset({"auth", "pr", "release", "repo", "secret", "variable"}),
}
_CURL_WRITE_FLAGS = frozenset(
    {
        "-T",
        "--upload-file",
        "--data",
        "--data-ascii",
        "--data-binary",
        "--data-raw",
        "--data-urlencode",
        "-d",
        "-F",
        "--form",
        "--form-string",
    }
)


def _utc(timestamp: float | None = None) -> str:
    value = datetime.fromtimestamp(timestamp or time.time(), timezone.utc)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class GateCommand:
    """Canonical gate representation from an approved plan."""

    argv: tuple[str, ...]
    timeout_seconds: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "GateCommand":
        if not isinstance(value, Mapping):
            raise InvalidInputError("Gate command must be an object")
        if set(value) != {"argv", "timeoutSeconds"}:
            raise InvalidInputError("Gate command accepts only argv and timeoutSeconds")
        argv = value["argv"]
        timeout = value["timeoutSeconds"]
        if not isinstance(argv, list):
            raise InvalidInputError("Gate command argv must be an array")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 10 <= timeout <= 7200:
            raise InvalidInputError("Gate timeoutSeconds must be an integer from 10 through 7200")
        command = cls(tuple(argv), timeout)
        validate_gate_command(command)
        return command

    def as_dict(self) -> dict[str, Any]:
        return {"argv": list(self.argv), "timeoutSeconds": self.timeout_seconds}

    def to_dict(self) -> dict[str, Any]:
        return self.as_dict()


@dataclass(frozen=True)
class ExecutableIdentity:
    basename: str
    path: str
    mode: int
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "basename": self.basename,
            "path": self.path,
            "mode": self.mode,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class ResolvedGateCommand:
    command: GateCommand
    executable: ExecutableIdentity


@dataclass(frozen=True)
class SandboxPolicy:
    backend: str
    executable: str
    worktree: str
    home: str
    tmpdir: str
    cache: str
    read_only_paths: tuple[str, ...]
    sensitive_paths: tuple[str, ...]
    environment_names: tuple[str, ...]
    network: str = "deny"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": 1,
            "backend": self.backend,
            "executable": self.executable,
            "worktree": self.worktree,
            "home": self.home,
            "tmpdir": self.tmpdir,
            "cache": self.cache,
            "readOnlyPaths": list(self.read_only_paths),
            "sensitivePaths": list(self.sensitive_paths),
            "environmentNames": list(self.environment_names),
            "network": self.network,
        }

    @property
    def sha256(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.as_dict()))


@dataclass(frozen=True)
class GateResult:
    argv: tuple[str, ...]
    working_directory: str
    started_at: str
    completed_at: str
    duration_ms: int
    exit_code: int | None
    timed_out: bool
    output_path: str
    output_sha256: str
    executable: ExecutableIdentity
    sandbox_backend: str
    sandbox_policy_path: str
    sandbox_policy_sha256: str
    environment: tuple[dict[str, str], ...]
    provenance: str = "independent"

    @property
    def passed(self) -> bool:
        return not self.timed_out and self.exit_code == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "workingDirectory": self.working_directory,
            "startedAt": self.started_at,
            "completedAt": self.completed_at,
            "durationMs": self.duration_ms,
            "exitCode": self.exit_code,
            "timedOut": self.timed_out,
            "outputPath": self.output_path,
            "outputSha256": self.output_sha256,
            "executable": self.executable.as_dict(),
            "sandboxBackend": self.sandbox_backend,
            "sandboxPolicyPath": self.sandbox_policy_path,
            "sandboxPolicySha256": self.sandbox_policy_sha256,
            "environment": list(self.environment),
            "provenance": self.provenance,
            "passed": self.passed,
        }


@dataclass(frozen=True)
class ProbeCheck:
    name: str
    expected: str
    observed: str
    passed: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "expected": self.expected,
            "observed": self.observed,
            "passed": self.passed,
        }


@dataclass(frozen=True)
class SandboxProbeResult:
    backend: str
    version: str
    checks: tuple[ProbeCheck, ...]
    policy_sha256: str

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(check.passed for check in self.checks)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": 1,
            "backend": self.backend,
            "version": self.version,
            "policySha256": self.policy_sha256,
            "checks": [check.as_dict() for check in self.checks],
            "passed": self.passed,
        }


def _argument(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidInputError("Gate command arguments must be non-empty strings")
    if _CONTROL.search(value):
        raise InvalidInputError("Gate command arguments cannot contain control characters")
    if _SHELL_EXPRESSION.search(value):
        raise PolicyError("Shell expressions are not supported in gate arguments")
    return value


def _basename(executable: str) -> str:
    return Path(executable).name.lower()


def _first_operand(arguments: Sequence[str]) -> str | None:
    for argument in arguments:
        if not argument.startswith("-"):
            return argument.lower()
    return None


def _reject_dangerous(executable: str, arguments: Sequence[str]) -> None:
    basename = _basename(executable)
    lowered = tuple(argument.lower() for argument in arguments)
    if basename in _INDIRECT_LAUNCHERS:
        raise PolicyError(
            f"Indirect command launcher is not a valid verification gate: {basename}"
        )
    if basename in _SHELLS and any(
        argument in _SHELL_INLINE_FLAGS or _SHELL_SHORT_INLINE.fullmatch(argument)
        for argument in lowered
    ):
        raise PolicyError("Shell interpreters with inline command flags are not valid gates")

    interpreter = basename
    if interpreter.startswith("python"):
        interpreter = "python3" if "3" in interpreter else "python"
    inline_flags = _INTERPRETER_INLINE_FLAGS.get(interpreter, frozenset())
    inline_letter = {
        "python": "c",
        "python3": "c",
        "node": "ep",
        "nodejs": "ep",
        "ruby": "e",
        "perl": "eE",
        "php": "r",
        "lua": "e",
    }.get(interpreter)
    if any(
        argument in inline_flags
        or (
            inline_letter is not None
            and re.fullmatch(
                rf"-[A-Za-z]*[{re.escape(inline_letter)}][A-Za-z]*",
                argument,
            )
        )
        for argument in lowered
    ):
        raise PolicyError("Interpreter inline-code flags are not valid gates")

    if basename in _ALWAYS_REJECT:
        raise PolicyError(f"Destructive, remote, or privileged executable is not a valid gate: {basename}")
    operand = _first_operand(lowered)
    if basename == "git":
        if any(
            item == "-c"
            or item.startswith("-c")
            or item == "--config-env"
            or item.startswith("--config-env=")
            for item in lowered
        ):
            raise PolicyError("Git runtime configuration and aliases are not valid gates")
        rejected_git = next((item for item in lowered if item in _GIT_REJECT), None)
        if rejected_git is not None:
            raise PolicyError(f"Git {rejected_git} is not a valid verification gate")
        if "config" in lowered and (
            any(item in {"--global", "--system"} for item in lowered)
            or any("credential" in item or "insteadof" in item for item in lowered)
        ):
            raise PolicyError("Git credential or global configuration is not a valid gate")
    if basename in _PUBLISH_ACTIONS:
        rejected_action = next(
            (item for item in lowered if item in _PUBLISH_ACTIONS[basename]),
            None,
        )
        if rejected_action is not None:
            raise PolicyError(f"{basename} {rejected_action} may publish or manage credentials")
    if basename == "curl":
        if any(
            argument in _CURL_WRITE_FLAGS
            or argument.lower() in (_CURL_WRITE_FLAGS - {"-T", "-F"})
            for argument in arguments
        ):
            raise PolicyError("curl write requests are not valid verification gates")
        for index, argument in enumerate(lowered[:-1]):
            if argument in {"-x", "--request"} and lowered[index + 1] not in {"get", "head"}:
                raise PolicyError("curl remote-write requests are not valid verification gates")
        if any(
            argument.startswith("--request=")
            and argument.partition("=")[2] not in {"get", "head"}
            for argument in lowered
        ):
            raise PolicyError("curl remote-write requests are not valid verification gates")
    if basename == "wget" and any(
        argument.startswith(("--post-data", "--post-file", "--method="))
        for argument in lowered
    ):
        raise PolicyError("wget remote-write requests are not valid verification gates")
    if basename == "rsync" and any(":" in argument for argument in arguments):
        raise PolicyError("Remote rsync is not a valid verification gate")


def validate_gate_command(command: GateCommand | Mapping[str, Any]) -> GateCommand:
    """Validate structure and reject inline, destructive, and remote commands."""

    if isinstance(command, Mapping):
        return GateCommand.from_mapping(command)
    if not isinstance(command, GateCommand):
        if hasattr(command, "argv") and hasattr(command, "timeout_seconds"):
            command = GateCommand(tuple(command.argv), command.timeout_seconds)
        else:
            raise InvalidInputError("Gate command must be a GateCommand or object")
    if not command.argv:
        raise InvalidInputError("Gate command argv cannot be empty")
    if not 10 <= command.timeout_seconds <= 7200:
        raise InvalidInputError("Gate timeoutSeconds must be from 10 through 7200")
    argv = tuple(_argument(argument) for argument in command.argv)
    executable = argv[0]
    if not Path(executable).is_absolute() and ("/" in executable or "\\" in executable):
        raise InvalidInputError("Relative gate executable cannot contain path separators")
    _reject_dangerous(executable, argv[1:])
    return command


def validate_path_environment(path_value: str) -> tuple[str, ...]:
    """Reject empty or relative PATH entries."""

    if not isinstance(path_value, str) or not path_value:
        raise PolicyError("PATH must be non-empty")
    components = tuple(path_value.split(os.pathsep))
    if any(not component or not Path(component).is_absolute() for component in components):
        raise PolicyError("PATH contains an empty or relative component")
    return components


def executable_identity(path: str | os.PathLike[str]) -> ExecutableIdentity:
    candidate = Path(path).resolve(strict=True)
    info = candidate.stat()
    if not stat.S_ISREG(info.st_mode) or not os.access(candidate, os.X_OK):
        raise PreconditionError(f"Gate executable is not an executable regular file: {candidate}")
    return ExecutableIdentity(
        basename=candidate.name,
        path=str(candidate),
        mode=stat.S_IMODE(info.st_mode),
        sha256=sha256_file(candidate),
    )


def resolve_gate_command(
    command: GateCommand | Mapping[str, Any],
    *,
    path_value: str | None = None,
    executable_allowlist: Iterable[str] = (),
    approved_executables: Mapping[str, ExecutableIdentity] | None = None,
) -> ResolvedGateCommand:
    """Resolve an approved basename and bind the command to its file identity."""

    canonical = validate_gate_command(command)
    effective_path = path_value if path_value is not None else os.environ.get("PATH", "")
    validate_path_environment(effective_path)
    configured = frozenset(executable_allowlist)
    if not configured and approved_executables:
        configured = frozenset(approved_executables)
    if not configured:
        raise PolicyError("Gate executable allowlist must be non-empty")
    if any(not item or "/" in item or "\\" in item or _CONTROL.search(item) for item in configured):
        raise InvalidInputError("Executable allowlist entries must be basenames")

    requested = canonical.argv[0]
    requested_path = Path(requested)
    basename = requested_path.name
    if configured and basename not in configured:
        raise PolicyError(f"Gate executable is not in the configured allowlist: {basename}")
    resolved_by_name = shutil.which(basename, path=effective_path)
    if resolved_by_name is None:
        raise PreconditionError(f"Gate executable was not found in approved PATH: {basename}")
    named_path = Path(resolved_by_name).resolve(strict=True)
    if requested_path.is_absolute():
        absolute = requested_path.resolve(strict=True)
        if absolute != named_path:
            raise PolicyError("Absolute gate executable differs from the approved PATH executable")
    else:
        absolute = named_path

    identity = executable_identity(absolute)
    if approved_executables is not None:
        approved = approved_executables.get(basename)
        if approved is None:
            raise PolicyError(f"Gate executable was not approved: {basename}")
        if approved != identity:
            raise PolicyError(f"Gate executable identity changed after approval: {basename}")
    return ResolvedGateCommand(canonical, identity)


def minimal_gate_environment(
    inherited: Mapping[str, str],
    *,
    allowlist: Iterable[str],
    home: str | os.PathLike[str],
    tmpdir: str | os.PathLike[str],
    cache: str | os.PathLike[str],
) -> dict[str, str]:
    """Construct the provider-independent gate environment."""

    names = frozenset(allowlist) | {"PATH", "LANG", "LC_ALL", "CI"}
    result = {
        name: inherited[name]
        for name in sorted(names)
        if name in inherited and not _SENSITIVE_ENVIRONMENT.search(name)
    }
    path_value = result.get("PATH", os.defpath)
    validate_path_environment(path_value)
    result["PATH"] = path_value
    result["HOME"] = str(Path(home).resolve())
    result["TMPDIR"] = str(Path(tmpdir).resolve())
    result["XDG_CACHE_HOME"] = str(Path(cache).resolve())
    result["PYTHONNOUSERSITE"] = "1"
    return result


def environment_evidence(environment: Mapping[str, str]) -> tuple[dict[str, str], ...]:
    """Record names and value hashes, never raw environment values."""

    return tuple(
        {"name": name, "valueSha256": sha256_bytes(value.encode("utf-8"))}
        for name, value in sorted(environment.items())
    )


def detect_sandbox_backend(
    requested: str = "auto",
    *,
    platform: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> tuple[str, str]:
    if requested not in SUPPORTED_BACKENDS:
        raise InvalidInputError("Sandbox backend must be auto, sandbox-exec, or bwrap")
    system = platform or sys.platform
    candidates = (
        ("sandbox-exec",) if system == "darwin" else ("bwrap",)
    ) if requested == "auto" else (requested,)
    for name in candidates:
        executable = which(name)
        if executable:
            return name, str(Path(executable).resolve())
    raise PreconditionError("No supported gate sandbox backend is available")


def _canonical_directory(path: str | os.PathLike[str], label: str) -> str:
    candidate = Path(path).resolve(strict=True)
    if not candidate.is_dir():
        raise PreconditionError(f"{label} is not a directory: {candidate}")
    return str(candidate)


def create_sandbox_policy(
    *,
    backend: str,
    executable: str,
    worktree: str | os.PathLike[str],
    home: str | os.PathLike[str],
    tmpdir: str | os.PathLike[str],
    cache: str | os.PathLike[str],
    read_only_paths: Iterable[str | os.PathLike[str]],
    environment: Mapping[str, str],
    sensitive_paths: Iterable[str | os.PathLike[str]] = (),
) -> SandboxPolicy:
    if backend not in {"sandbox-exec", "bwrap"}:
        raise InvalidInputError("Resolved sandbox backend must be sandbox-exec or bwrap")
    canonical_ro = tuple(sorted({_canonical_directory(path, "Read-only mount") for path in read_only_paths}))
    discovered_sensitive = trusted_sensitive_paths()
    explicit_sensitive = {
        str(Path(path).expanduser().resolve(strict=False)) for path in sensitive_paths
    }
    canonical_sensitive = tuple(sorted(set(discovered_sensitive) | explicit_sensitive))
    for readable in canonical_ro:
        readable_path = Path(readable)
        for sensitive in canonical_sensitive:
            sensitive_path = Path(sensitive)
            if (
                readable_path == sensitive_path
                or readable_path in sensitive_path.parents
                or sensitive_path in readable_path.parents
            ):
                raise PolicyError(
                    "Read-only sandbox mount overlaps a sensitive credential path"
                )
    return SandboxPolicy(
        backend=backend,
        executable=str(Path(executable).resolve(strict=True)),
        worktree=_canonical_directory(worktree, "Verification worktree"),
        home=_canonical_directory(home, "Gate HOME"),
        tmpdir=_canonical_directory(tmpdir, "Gate TMPDIR"),
        cache=_canonical_directory(cache, "Gate cache"),
        read_only_paths=canonical_ro,
        sensitive_paths=canonical_sensitive,
        environment_names=tuple(sorted(environment)),
    )


def trusted_sensitive_paths(
    repository_git_dir: str | os.PathLike[str] | None = None,
) -> tuple[str, ...]:
    """Discover credential and Git-admin paths without caller policy input."""

    home = Path.home().resolve()
    candidates = [
        home / ".ssh",
        home / ".gnupg",
        home / ".codex",
        home / ".config" / "gh",
        home / ".config" / "grok",
        home / ".grok",
        home / ".netrc",
        home / ".git-credentials",
    ]
    if repository_git_dir is not None:
        candidates.append(Path(repository_git_dir).expanduser().resolve(strict=False))
    return tuple(
        sorted(
            {
                str(path.resolve(strict=False))
                for path in candidates
                if path.exists() or path.is_symlink()
            }
        )
    )


def _sandbox_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def sandbox_exec_profile(policy: SandboxPolicy) -> str:
    """Generate a fixed-template macOS sandbox profile from canonical paths."""

    if policy.backend != "sandbox-exec":
        raise InvalidInputError("sandbox_exec_profile requires a sandbox-exec policy")
    read_paths = tuple(
        dict.fromkeys(
            (
                policy.worktree,
                policy.home,
                policy.tmpdir,
                policy.cache,
                *policy.read_only_paths,
                "/dev",
                "/private/var/db",
                "/System",
                "/usr",
                "/bin",
                "/sbin",
            )
        )
    )
    write_paths = (policy.worktree, policy.home, policy.tmpdir, policy.cache)
    lines = [
        "(version 1)",
        "(deny default)",
        "(allow process-exec)",
        "(allow process-fork)",
        "(allow signal (target self))",
        "(allow sysctl-read)",
    ]
    lines.extend(f"(allow file-read* (subpath {_sandbox_quote(path)}))" for path in read_paths)
    lines.extend(f"(allow file-write* (subpath {_sandbox_quote(path)}))" for path in write_paths)
    lines.append("(deny network*)")
    return "\n".join(lines) + "\n"


def bwrap_argv(
    policy: SandboxPolicy,
    command: Sequence[str],
    environment: Mapping[str, str],
) -> list[str]:
    """Generate a bubblewrap invocation without shell interpolation."""

    if policy.backend != "bwrap":
        raise InvalidInputError("bwrap_argv requires a bwrap policy")
    argv = [
        policy.executable,
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-ipc",
        "--clearenv",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
    ]
    mounts: set[str] = set()
    for path in policy.read_only_paths:
        if path not in mounts:
            argv.extend(["--ro-bind", path, path])
            mounts.add(path)
    for path in (policy.worktree, policy.home, policy.tmpdir, policy.cache):
        if path not in mounts:
            argv.extend(["--bind", path, path])
            mounts.add(path)
    for name, value in sorted(environment.items()):
        argv.extend(["--setenv", name, value])
    argv.extend(["--chdir", policy.worktree, "--", *command])
    return argv


def sandboxed_argv(
    policy: SandboxPolicy,
    command: Sequence[str],
    environment: Mapping[str, str],
    *,
    profile_path: str | os.PathLike[str] | None = None,
) -> list[str]:
    if policy.backend == "bwrap":
        return bwrap_argv(policy, command, environment)
    if profile_path is None:
        raise InvalidInputError("sandbox-exec requires a saved profile path")
    return [policy.executable, "-f", str(Path(profile_path).resolve()), *command]


def _terminate_process_group(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=2)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        process.wait()


class GateRunner:
    """Execute approved commands through an already-probed sandbox policy."""

    def __init__(
        self,
        *,
        policy: SandboxPolicy,
        evidence_store: EvidenceStore,
        environment: Mapping[str, str],
        sandbox_probe: SandboxProbeResult,
        executable_allowlist: Iterable[str],
    ) -> None:
        if not sandbox_probe.passed or sandbox_probe.backend != policy.backend:
            raise PreconditionError("Gate sandbox capability probe did not pass")
        if sandbox_probe.policy_sha256 != policy.sha256:
            raise PreconditionError("Gate sandbox probe is not bound to this sandbox policy")
        self.policy = policy
        self.evidence = evidence_store
        self.environment = dict(environment)
        self.sandbox_executable = executable_identity(policy.executable)
        self.executable_allowlist = frozenset(executable_allowlist)
        if not self.executable_allowlist:
            raise PolicyError("Gate executable allowlist must be non-empty")
        self.approved_executables: dict[str, ExecutableIdentity] = {}
        for basename in self.executable_allowlist:
            path = shutil.which(basename, path=self.environment.get("PATH"))
            if path is None:
                raise PreconditionError(
                    f"Allowlisted gate executable was not found: {basename}"
                )
            self.approved_executables[basename] = executable_identity(path)

    def run(
        self,
        command: GateCommand | Mapping[str, Any],
        *,
        result_name: str,
        path_value: str | None = None,
        executable_allowlist: Iterable[str] = (),
        approved_executables: Mapping[str, ExecutableIdentity] | None = None,
        raise_on_failure: bool = False,
    ) -> GateResult:
        requested_allowlist = frozenset(executable_allowlist)
        if requested_allowlist and requested_allowlist != self.executable_allowlist:
            raise PolicyError("Per-command executable allowlist differs from runner policy")
        if approved_executables is not None and dict(approved_executables) != self.approved_executables:
            raise PolicyError("Per-command executable identities differ from runner policy")
        resolved = resolve_gate_command(
            command,
            path_value=path_value or self.environment.get("PATH"),
            executable_allowlist=self.executable_allowlist,
            approved_executables=self.approved_executables,
        )
        # Recalculate immediately before execution to catch replacement after
        # approval or resolution.
        if executable_identity(resolved.executable.path) != resolved.executable:
            raise PolicyError("Gate executable changed immediately before execution")
        if executable_identity(self.policy.executable) != self.sandbox_executable:
            raise PolicyError("Gate sandbox executable changed after its capability probe")

        normalized_name = normalize_evidence_path(result_name)
        if "/" in normalized_name:
            raise InvalidInputError("Gate result name must be one path component")
        policy_artifact = self.evidence.write_independent_json(
            f"gates/{normalized_name}.sandbox-policy.json",
            self.policy.as_dict(),
        )
        profile_path: Path | None = None
        if self.policy.backend == "sandbox-exec":
            profile_artifact = self.evidence.write_text(
                f"{EvidenceStore.INDEPENDENT_NAMESPACE}/gates/{normalized_name}.sb",
                sandbox_exec_profile(self.policy),
            )
            profile_path = self.evidence.path(profile_artifact.relative_path)

        output_path = self.evidence.independent_path(f"gates/{normalized_name}.output")
        ensure_private_directory(output_path.parent)
        output_path.touch(mode=0o600, exist_ok=False)
        os.chmod(output_path, 0o600)

        child_command = [resolved.executable.path, *resolved.command.argv[1:]]
        invocation = sandboxed_argv(
            self.policy,
            child_command,
            self.environment,
            profile_path=profile_path,
        )
        started_monotonic = time.monotonic()
        started_at = _utc()
        timed_out = False
        exit_code: int | None = None
        with output_path.open("wb", buffering=0) as output:
            process = subprocess.Popen(
                invocation,
                cwd=self.policy.worktree,
                env=self.environment,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
            try:
                exit_code = process.wait(timeout=resolved.command.timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_process_group(process)
                exit_code = process.returncode
        completed_at = _utc()
        duration_ms = max(0, round((time.monotonic() - started_monotonic) * 1000))
        result = GateResult(
            argv=resolved.command.argv,
            working_directory=self.policy.worktree,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            exit_code=exit_code,
            timed_out=timed_out,
            output_path=output_path.relative_to(self.evidence.root).as_posix(),
            output_sha256=sha256_file(output_path),
            executable=resolved.executable,
            sandbox_backend=self.policy.backend,
            sandbox_policy_path=policy_artifact.relative_path,
            sandbox_policy_sha256=policy_artifact.sha256,
            environment=environment_evidence(self.environment),
        )
        self.evidence.write_independent_json(
            f"gates/{normalized_name}.result.json",
            result.as_dict(),
        )
        if raise_on_failure and not result.passed:
            reason = "timed out" if result.timed_out else f"exited {result.exit_code}"
            raise GateFailureError(f"Verification gate {reason}")
        return result


def backend_version(backend: str, executable: str) -> str:
    """Read a bounded, local backend version string."""

    flags = ["--version"] if backend == "bwrap" else ["-h"]
    try:
        completed = subprocess.run(
            [executable, *flags],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
            text=True,
            env={"PATH": os.defpath},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PreconditionError(f"Cannot execute sandbox backend: {backend}") from error
    output = completed.stdout.strip().splitlines()
    return (output[0] if output else f"{backend}:exit-{completed.returncode}")[:200]


def probe_sandbox(
    *,
    policy: SandboxPolicy,
    environment: Mapping[str, str],
    repository_git_dir: str | os.PathLike[str],
    credential_directories: Iterable[str | os.PathLike[str]],
    run_probe: Callable[[str, SandboxPolicy, Mapping[str, str]], str] | None = None,
) -> SandboxProbeResult:
    """Run positive and negative backend probes.

    ``run_probe`` exists so unit tests can model a backend without weakening
    production behavior.  It receives a named, fixed probe and must return
    ``allowed``, ``denied``, or ``inconclusive``.
    """

    version = backend_version(policy.backend, policy.executable)
    if run_probe is None:
        run_probe = _run_fixed_probe
    credential_paths = tuple(
        sorted(
            set(policy.sensitive_paths)
            | set(trusted_sensitive_paths(repository_git_dir))
            | {
                str(Path(path).expanduser().resolve(strict=False))
                for path in credential_directories
            }
        )
    )
    check_specs = [
        ("worktree-read", "allowed"),
        ("worktree-write", "allowed"),
        ("network", "denied"),
        ("outside-worktree-write", "denied"),
        ("repository-git-read", "denied"),
    ]
    if credential_paths:
        check_specs.append(("provider-credential-read", "denied"))

    probe_environment = dict(environment)
    probe_environment["CROSSFORGE_PROBE_GIT_DIR"] = str(Path(repository_git_dir).resolve())
    probe_environment["CROSSFORGE_PROBE_CREDENTIAL_DIRS"] = os.pathsep.join(
        str(Path(path).resolve()) for path in credential_paths
    )
    checks = tuple(
        ProbeCheck(
            name=name,
            expected=expected,
            observed=(observed := run_probe(name, policy, probe_environment)),
            passed=observed == expected,
        )
        for name, expected in check_specs
    )
    return SandboxProbeResult(policy.backend, version, checks, policy.sha256)


def _run_fixed_probe(
    name: str,
    policy: SandboxPolicy,
    environment: Mapping[str, str],
) -> str:
    """Execute one fixed probe.  No repository-controlled code is evaluated."""

    worktree = Path(policy.worktree)
    cleanup_target: Path | None = None
    outside_probe: Path | None = None
    network_listener: socket.socket | None = None
    if name == "worktree-read":
        descriptor, target_name = tempfile.mkstemp(prefix=".crossforge-probe-read-", dir=worktree)
        os.write(descriptor, b"crossforge")
        os.close(descriptor)
        cleanup_target = Path(target_name)
        script = "import pathlib,sys;sys.exit(0 if pathlib.Path(sys.argv[1]).read_bytes()==b'crossforge' else 2)"
        argument = str(cleanup_target)
    elif name == "worktree-write":
        descriptor, target_name = tempfile.mkstemp(prefix=".crossforge-probe-write-", dir=worktree)
        os.close(descriptor)
        cleanup_target = Path(target_name)
        cleanup_target.unlink()
        argument = str(cleanup_target)
        script = "import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b'ok')"
    elif name == "outside-worktree-write":
        descriptor, target_name = tempfile.mkstemp(
            prefix=".crossforge-outside-probe-",
            dir=Path(policy.worktree).parent,
        )
        os.close(descriptor)
        outside_probe = Path(target_name)
        outside_probe.unlink()
        argument = str(outside_probe)
        script = "import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b'bad')"
    elif name == "repository-git-read":
        argument = environment["CROSSFORGE_PROBE_GIT_DIR"]
        script = "import pathlib,sys;list(pathlib.Path(sys.argv[1]).iterdir())"
    elif name == "provider-credential-read":
        directories = environment.get("CROSSFORGE_PROBE_CREDENTIAL_DIRS", "").split(os.pathsep)
        argument = next((item for item in directories if item), str(Path.home()))
        script = "import pathlib,sys;list(pathlib.Path(sys.argv[1]).iterdir())"
    elif name == "network":
        network_listener = socket.socket()
        try:
            network_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            network_listener.bind(("127.0.0.1", 0))
            network_listener.listen(1)
        except OSError:
            network_listener.close()
            return "inconclusive"
        argument = str(network_listener.getsockname()[1])
        script = (
            "import socket,sys;"
            "s=socket.socket();"
            "s.settimeout(.25);"
            "s.connect(('127.0.0.1',int(sys.argv[1])))"
        )
    else:
        return "inconclusive"

    invocation: list[str]
    # sandbox-exec requires a saved profile; production callers use bwrap here
    # or provide a test probe runner.  A profile is generated in a private
    # temporary directory for the macOS path.
    temporary_profile: tempfile.TemporaryDirectory[str] | None = None
    if policy.backend == "sandbox-exec":
        temporary_profile = tempfile.TemporaryDirectory(prefix="crossforge-probe-")
        profile = Path(temporary_profile.name) / "probe.sb"
        profile.write_text(sandbox_exec_profile(policy), encoding="utf-8")
        os.chmod(profile, 0o600)
        invocation = sandboxed_argv(
            policy,
            [sys.executable, "-I", "-c", script, argument],
            environment,
            profile_path=profile,
        )
    else:
        invocation = sandboxed_argv(
            policy,
            [sys.executable, "-I", "-c", script, argument],
            environment,
        )
    try:
        completed = subprocess.run(
            invocation,
            cwd=policy.worktree,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
            start_new_session=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "inconclusive"
    finally:
        if network_listener is not None:
            network_listener.close()
        if outside_probe is not None:
            try:
                outside_probe.unlink()
            except FileNotFoundError:
                pass
        if cleanup_target is not None:
            try:
                cleanup_target.unlink()
            except FileNotFoundError:
                pass
        if temporary_profile is not None:
            temporary_profile.cleanup()
    if name.startswith("worktree-"):
        return "allowed" if completed.returncode == 0 else "inconclusive"
    return "denied" if completed.returncode != 0 else "allowed"
