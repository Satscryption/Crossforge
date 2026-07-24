"""Local runtime and explicitly authorized provider preflight checks."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .errors import ConsentError, InvalidInputError, PreconditionError
from .gates import (
    SandboxPolicy,
    SandboxProbeResult,
    create_sandbox_policy,
    minimal_gate_environment,
    probe_sandbox,
)
from .providers.base import ProviderAdapter, ProviderProbe, run_process, sanitize_message
from .util import sha256_bytes

MINIMUM_PYTHON = (3, 11)
MINIMUM_GIT = (2, 39)
MINIMUM_CLAUDE = (2, 1, 216)
_VERSION = re.compile(r"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?")
SOURCE_FREE_PROVIDER_PROBE_CONTRACT = (
    b"crossforge-provider-probe-v1: fixed provider-owned readiness operation; "
    b"no repository path, remote, file name, source, task brief, or prior output"
)


@dataclass(frozen=True, slots=True)
class PreflightCheck:
    name: str
    passed: bool
    required: bool
    category: str
    message: str
    executable_path: str | None = None
    version: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "passed": self.passed,
            "required": self.required,
            "category": self.category,
            "message": self.message,
            "executablePath": self.executable_path,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class PreflightReport:
    mode: str
    checks: tuple[PreflightCheck, ...]
    provider_probes: tuple[ProviderProbe, ...] = ()
    source_free_provider_probes: tuple["SourceFreeProviderProbeResult", ...] = ()
    gate_sandbox_probe: SandboxProbeResult | None = None

    @property
    def blockers(self) -> tuple[PreflightCheck, ...]:
        return tuple(check for check in self.checks if check.required and not check.passed)

    @property
    def passed(self) -> bool:
        return not self.blockers

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "passed": self.passed,
            "checks": [check.to_dict() for check in self.checks],
            "providers": [probe.to_dict() for probe in self.provider_probes],
            "sourceFreeProviderProbes": [
                probe.to_dict() for probe in self.source_free_provider_probes
            ],
            "gateSandboxProbe": (
                self.gate_sandbox_probe.as_dict()
                if self.gate_sandbox_probe is not None
                else None
            ),
        }


@dataclass(frozen=True, slots=True)
class SourceFreeProviderProbeResult:
    """Consent-bound result for the adapter's source-free probe operation.

    The API deliberately accepts no repository, remote, path, prompt, source,
    or task-brief argument. Provider adapters must keep their ``probe`` method
    source-free; Crossforge records this contract identity with the result.
    """

    provider_probe: ProviderProbe
    operation: str = "probe"
    source_free_contract_sha256: str = sha256_bytes(
        SOURCE_FREE_PROVIDER_PROBE_CONTRACT
    )

    @property
    def passed(self) -> bool:
        return self.provider_probe.available

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "operation": self.operation,
            "sourceFree": True,
            "contractSha256": self.source_free_contract_sha256,
            "providerResult": self.provider_probe.to_dict(),
        }


def parse_version(value: str) -> tuple[int, ...] | None:
    match = _VERSION.search(value)
    if match is None:
        return None
    return tuple(int(part or 0) for part in match.groups())


def path_is_safe(path_value: str) -> bool:
    """Reject PATH values with empty or relative components."""

    if not path_value:
        return False
    return all(component and Path(component).is_absolute() for component in path_value.split(os.pathsep))


def resolve_executable(name: str, *, path_value: str | None = None) -> Path | None:
    if not name or "/" in name or "\\" in name:
        return None
    search_path = path_value if path_value is not None else os.environ.get("PATH", "")
    if not path_is_safe(search_path):
        return None
    located = shutil.which(name, path=search_path)
    if located is None:
        return None
    resolved = Path(located).resolve()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        return None
    return resolved


def _version_check(
    name: str,
    *,
    argv: Sequence[str],
    minimum: tuple[int, ...],
    path_value: str,
    env: Mapping[str, str] | None,
    required: bool,
) -> PreflightCheck:
    executable = resolve_executable(argv[0], path_value=path_value)
    if executable is None:
        return PreflightCheck(
            name=name,
            passed=False,
            required=required,
            category="missing_executable",
            message=f"{name} executable is unavailable through the approved PATH",
        )
    with tempfile.TemporaryDirectory(prefix="crossforge-local-preflight-") as tmp:
        root = Path(tmp)
        result = run_process(
            (str(executable), *argv[1:]),
            cwd=root,
            stdin_bytes=None,
            timeout_seconds=10,
            stdout_path=root / "stdout.raw",
            stderr_path=root / "stderr.raw",
            env=env,
        )
        output = sanitize_message(
            result.stdout_preview or result.stderr_preview,
            sensitive_paths=(executable, root),
        )
    if result.timed_out or result.exit_code != 0:
        return PreflightCheck(
            name=name,
            passed=False,
            required=required,
            category="version_check_failed",
            message=output or f"{name} version check failed",
            executable_path=str(executable),
        )
    parsed = parse_version(output)
    if parsed is None:
        return PreflightCheck(
            name=name,
            passed=False,
            required=required,
            category="unparseable_version",
            message=f"{name} returned an unparseable version",
            executable_path=str(executable),
        )
    return PreflightCheck(
        name=name,
        passed=parsed >= minimum,
        required=required,
        category="ok" if parsed >= minimum else "unsupported_version",
        message=(
            f"{name} version is supported"
            if parsed >= minimum
            else f"{name} requires version {'.'.join(map(str, minimum))} or newer"
        ),
        executable_path=str(executable),
        version=output,
    )


def discover_sandbox_backend(
    *,
    path_value: str,
    system: str | None = None,
) -> tuple[str, Path] | None:
    system = (system or platform.system()).lower()
    if system == "darwin":
        backend = resolve_executable("sandbox-exec", path_value=path_value)
        return ("sandbox-exec", backend) if backend else None
    if system == "linux":
        backend = resolve_executable("bwrap", path_value=path_value)
        return ("bwrap", backend) if backend else None
    return None


def trusted_gate_read_only_paths(
    additional: Sequence[str | os.PathLike[str]] = (),
) -> tuple[Path, ...]:
    """Return canonical provider-independent system/toolchain mounts.

    User homes and repository paths are never inferred. Callers may add exact
    toolchain directories, which remain visible in the resulting sandbox
    policy and its hash.
    """

    candidates = [
        Path(sys.base_prefix),
        Path(sys.executable).parent,
        Path("/usr"),
        Path("/bin"),
        Path("/lib"),
        Path("/lib64"),
        Path("/etc"),
        Path("/System"),
    ]
    candidates.extend(Path(path) for path in additional)
    resolved: dict[str, Path] = {}
    for candidate in candidates:
        try:
            path = candidate.resolve(strict=True)
        except OSError:
            continue
        if path.is_dir():
            resolved[str(path)] = path
    return tuple(resolved[key] for key in sorted(resolved))


def probe_gate_sandbox(
    *,
    backend: str,
    executable: str | os.PathLike[str],
    environment: Mapping[str, str],
    repository_git_dir: str | os.PathLike[str],
    credential_directories: Sequence[str | os.PathLike[str]],
    read_only_paths: Sequence[str | os.PathLike[str]] = (),
    environment_allowlist: Sequence[str] = ("PATH", "LANG", "LC_ALL", "CI"),
    run_probe: Callable[[str, SandboxPolicy, Mapping[str, str]], str] | None = None,
) -> SandboxProbeResult:
    """Run the concrete positive and negative gate-sandbox capability probe."""

    git_directory = Path(repository_git_dir).resolve(strict=True)
    if not git_directory.is_dir():
        raise PreconditionError("Repository common Git path must be a directory")
    credential_paths: list[Path] = []
    for value in credential_directories:
        path = Path(value).resolve(strict=True)
        if not path.is_dir():
            raise PreconditionError("Provider credential probe path must be a directory")
        credential_paths.append(path)
    if not credential_paths:
        raise PreconditionError(
            "At least one provider credential directory is required for denial probing"
        )

    with tempfile.TemporaryDirectory(prefix="crossforge-gate-preflight-") as temporary:
        root = Path(temporary)
        worktree = root / "worktree"
        home = root / "home"
        tmpdir = root / "tmp"
        cache = root / "cache"
        for directory in (worktree, home, tmpdir, cache):
            directory.mkdir(mode=0o700)
        gate_environment = minimal_gate_environment(
            environment,
            allowlist=environment_allowlist,
            home=home,
            tmpdir=tmpdir,
            cache=cache,
        )
        trusted_paths = trusted_gate_read_only_paths(read_only_paths)
        for protected in (git_directory, *credential_paths):
            for mounted in trusted_paths:
                try:
                    protected.relative_to(mounted)
                except ValueError:
                    continue
                raise PreconditionError(
                    "A trusted read-only mount would expose a protected probe path"
                )
        policy = create_sandbox_policy(
            backend=backend,
            executable=str(Path(executable).resolve(strict=True)),
            worktree=worktree,
            home=home,
            tmpdir=tmpdir,
            cache=cache,
            read_only_paths=trusted_paths,
            environment=gate_environment,
        )
        return probe_sandbox(
            policy=policy,
            environment=gate_environment,
            repository_git_dir=git_directory,
            credential_directories=credential_paths,
            run_probe=run_probe,
        )


def run_source_free_provider_probe(
    adapter: ProviderAdapter,
    *,
    requested_model: str,
    effort: str,
    consent_confirmed: bool,
) -> SourceFreeProviderProbeResult:
    """Run one adapter readiness probe after caller-validated ``probe`` consent."""

    if consent_confirmed is not True:
        raise ConsentError("Provider probe requires validated repository-bound consent")
    if not isinstance(requested_model, str) or not requested_model:
        raise InvalidInputError("Provider probe requested model must be non-empty")
    if effort not in {"low", "medium", "high", "xhigh"}:
        raise InvalidInputError("Provider probe effort is invalid")
    return SourceFreeProviderProbeResult(adapter.probe(requested_model, effort))


def run_preflight(
    mode: str,
    *,
    env: Mapping[str, str] | None = None,
    require_claude: bool = True,
    sandbox_capability: Callable[[str, Path], bool] | None = None,
    sandbox_probe: SandboxProbeResult | None = None,
    provider_adapters: Sequence[ProviderAdapter] = (),
    provider_requests: Mapping[str, str] | None = None,
    effort: str = "high",
    probe_providers: bool = False,
    provider_probe_consent_confirmed: bool = False,
) -> PreflightReport:
    """Run deterministic local checks and optionally consent-gated probes.

    ``sandbox_probe`` is the preferred, policy-bound capability evidence from
    :func:`probe_gate_sandbox`; the boolean callback remains for compatibility.
    ``probe_providers`` requires explicit confirmation that the caller already
    validated repository-bound ``probe`` consent. Provider checks are never
    implicit in local preflight.
    """

    if mode not in {"plan", "build", "review", "resume", "status", "ship"}:
        raise ValueError(f"unknown preflight mode: {mode}")
    effective_env = dict(os.environ if env is None else env)
    path_value = effective_env.get("PATH", "")
    checks: list[PreflightCheck] = []
    checks.append(
        PreflightCheck(
            name="python",
            passed=sys.version_info[:2] >= MINIMUM_PYTHON,
            required=True,
            category=(
                "ok"
                if sys.version_info[:2] >= MINIMUM_PYTHON
                else "unsupported_version"
            ),
            message=(
                "Python runtime is supported"
                if sys.version_info[:2] >= MINIMUM_PYTHON
                else "Python 3.11 or newer is required"
            ),
            executable_path=str(Path(sys.executable).resolve()),
            version=platform.python_version(),
        )
    )
    checks.append(
        PreflightCheck(
            name="PATH",
            passed=path_is_safe(path_value),
            required=True,
            category="ok" if path_is_safe(path_value) else "unsafe_path",
            message=(
                "PATH contains only absolute non-empty components"
                if path_is_safe(path_value)
                else "PATH contains an empty or relative component"
            ),
        )
    )
    checks.append(
        _version_check(
            "git",
            argv=("git", "--version"),
            minimum=MINIMUM_GIT,
            path_value=path_value,
            env=effective_env,
            required=True,
        )
    )
    if require_claude:
        checks.append(
            _version_check(
                "claude",
                argv=("claude", "--version"),
                minimum=MINIMUM_CLAUDE,
                path_value=path_value,
                env=effective_env,
                required=True,
            )
        )
    sandbox_required = mode in {"build", "resume", "ship"}
    backend = discover_sandbox_backend(path_value=path_value)
    if backend is None:
        checks.append(
            PreflightCheck(
                name="gate-sandbox",
                passed=False,
                required=sandbox_required,
                category="missing_sandbox_backend",
                message="No supported local gate sandbox backend was found",
            )
        )
    else:
        backend_name, backend_path = backend
        if sandbox_probe is not None:
            proven = sandbox_probe.backend == backend_name and sandbox_probe.passed
        else:
            proven = (
                sandbox_capability(backend_name, backend_path)
                if sandbox_capability is not None
                else False
            )
        checks.append(
            PreflightCheck(
                name="gate-sandbox",
                passed=proven,
                required=sandbox_required,
                category="ok" if proven else "sandbox_inconclusive",
                message=(
                    f"{backend_name} mandatory capabilities passed"
                    if proven
                    else f"{backend_name} exists but mandatory capabilities are unproven"
                ),
                executable_path=str(backend_path),
            )
        )
    provider_probes: list[ProviderProbe] = []
    source_free_provider_probes: list[SourceFreeProviderProbeResult] = []
    if probe_providers:
        if provider_probe_consent_confirmed is not True:
            raise ConsentError(
                "Provider probes require validated repository-bound probe consent"
            )
        requests = dict(provider_requests or {})
        for adapter in provider_adapters:
            provider = getattr(adapter, "provider", type(adapter).__name__.lower())
            result = run_source_free_provider_probe(
                adapter,
                requested_model=requests.get(provider, "auto"),
                effort=effort,
                consent_confirmed=True,
            )
            source_free_provider_probes.append(result)
            provider_probes.append(result.provider_probe)
    return PreflightReport(
        mode=mode,
        checks=tuple(checks),
        provider_probes=tuple(provider_probes),
        source_free_provider_probes=tuple(source_free_provider_probes),
        gate_sandbox_probe=sandbox_probe,
    )
