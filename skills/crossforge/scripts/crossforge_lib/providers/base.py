"""Provider adapter contracts and safe subprocess execution primitives."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Mapping, Sequence

from ..models import ProviderStatus

MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
_TRUNCATION_MARKER = b"\n[Crossforge: output truncated]\n"
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(bearer\s+)[^\s]+"),
    re.compile(r"\b(?:gh[opusr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,})\b"),
    re.compile(
        r"(?i)\b(token|password|secret|api[_-]?key)\s*[:=]\s*([^\s,;]+)"
    ),
)


@dataclass(frozen=True, slots=True)
class CapabilityProbe:
    """Trusted, policy-level evidence for a provider sandbox.

    Merely observing CLI flags is not sufficient.  A caller must obtain this
    result from the platform-specific capability probe before a provider is
    considered safe for unattended execution.
    """

    sandbox_enforced: bool
    network_denied: bool
    outside_write_denied: bool
    credential_read_denied: bool
    orchestration_read_denied: bool
    git_common_dir_read_denied: bool
    outside_sentinel_read_denied: bool
    final_output_protected: bool
    conclusive: bool = True
    message: str = ""

    @property
    def safe(self) -> bool:
        return self.conclusive and all(
            (
                self.sandbox_enforced,
                self.network_denied,
                self.outside_write_denied,
                self.credential_read_denied,
                self.orchestration_read_denied,
                self.git_common_dir_read_denied,
                self.outside_sentinel_read_denied,
                self.final_output_protected,
            )
        )


@dataclass(frozen=True, slots=True)
class ProviderProbe:
    provider: str
    available: bool
    cli_path: str | None
    cli_version: str | None
    authenticated: bool
    requested_model: str
    resolved_model: str | None
    effort: str
    failure_category: str | None = None
    message: str = ""
    capability_probe: CapabilityProbe | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "available": self.available,
            "cliPath": self.cli_path,
            "cliVersion": self.cli_version,
            "authenticated": self.authenticated,
            "requestedModel": self.requested_model,
            "resolvedModel": self.resolved_model,
            "effort": self.effort,
            "failureCategory": self.failure_category,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ProviderInvocation:
    provider: str
    status: ProviderStatus
    requested_model: str
    resolved_model: str
    argv: tuple[str, ...]
    exit_code: int | None
    timed_out: bool
    duration_ms: int
    raw_stdout_path: Path
    raw_stderr_path: Path
    final_output_path: Path
    message: str

    @property
    def succeeded(self) -> bool:
        return self.status is ProviderStatus.COMPLETE

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "status": self.status.value,
            "requestedModel": self.requested_model,
            "resolvedModel": self.resolved_model,
            "argv": list(self.argv),
            "exitCode": self.exit_code,
            "timedOut": self.timed_out,
            "durationMs": self.duration_ms,
            "rawStdoutPath": str(self.raw_stdout_path),
            "rawStderrPath": str(self.raw_stderr_path),
            "finalOutputPath": str(self.final_output_path),
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ProcessResult:
    argv: tuple[str, ...]
    exit_code: int | None
    timed_out: bool
    duration_ms: int
    stdout_path: Path
    stderr_path: Path
    stdout_preview: bytes
    stderr_preview: bytes


class ProviderAdapter(ABC):
    @abstractmethod
    def probe(self, requested_model: str, effort: str) -> ProviderProbe:
        """Probe the provider after the control layer has checked consent."""

    @abstractmethod
    def implement(
        self,
        *,
        spec_path: Path,
        worktree: Path,
        requested_model: str,
        effort: str,
        timeout_seconds: int,
        final_output_path: Path,
    ) -> ProviderInvocation:
        """Run a write-capable provider invocation in an isolated worktree."""

    @abstractmethod
    def review(
        self,
        *,
        spec_path: Path,
        worktree: Path,
        requested_model: str,
        effort: str,
        timeout_seconds: int,
        final_output_path: Path,
    ) -> ProviderInvocation:
        """Run a read-only provider invocation in an isolated worktree."""


def sanitize_message(
    value: str | bytes,
    *,
    sensitive_paths: Sequence[Path | str] = (),
    limit: int = 512,
) -> str:
    """Return bounded, one-line diagnostics without credentials or local paths."""

    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    else:
        text = value
    for pattern in _SECRET_PATTERNS:
        if pattern.groups == 2:
            text = pattern.sub(lambda match: f"{match.group(1)}=<redacted>", text)
        elif pattern.groups == 1:
            text = pattern.sub(lambda match: f"{match.group(1)}<redacted>", text)
        else:
            text = pattern.sub("<redacted>", text)
    paths = [str(Path.home()), *(str(Path(path)) for path in sensitive_paths)]
    for path in sorted(set(paths), key=len, reverse=True):
        if path:
            text = text.replace(path, "<path>")
    text = "".join(char if char >= " " else " " for char in text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: max(0, limit - 1)] + "…"
    return text


def secure_parent(path: Path) -> Path:
    """Create an owner-only evidence directory and return an absolute path."""

    absolute = path.expanduser().resolve(strict=False)
    absolute.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(absolute.parent, 0o700)
    except OSError:
        pass
    return absolute


def validate_evidence_path(path: Path, *, worktree: Path) -> Path:
    """Require trusted provider output to live outside the candidate worktree."""

    evidence = path.expanduser().resolve(strict=False)
    candidate = worktree.resolve(strict=True)
    try:
        evidence.relative_to(candidate)
    except ValueError:
        return secure_parent(evidence)
    raise ValueError("provider evidence path must be outside the candidate worktree")


def _drain_stream(
    stream: BinaryIO,
    destination: Path,
    *,
    maximum_bytes: int,
    preview_limit: int,
    preview: bytearray,
) -> None:
    written = 0
    truncated = False
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as output:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                if len(preview) < preview_limit:
                    preview.extend(chunk[: preview_limit - len(preview)])
                remaining = maximum_bytes - written
                if remaining > 0:
                    selected = chunk[:remaining]
                    output.write(selected)
                    written += len(selected)
                if len(chunk) > remaining:
                    truncated = True
            if truncated:
                if written + len(_TRUNCATION_MARKER) > maximum_bytes:
                    keep = max(0, maximum_bytes - len(_TRUNCATION_MARKER))
                    output.seek(keep)
                    output.truncate()
                output.write(_TRUNCATION_MARKER)
            output.flush()
            os.fsync(output.fileno())
    finally:
        stream.close()


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    process.wait()


def run_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    stdin_bytes: bytes | None,
    timeout_seconds: float,
    stdout_path: Path,
    stderr_path: Path,
    env: Mapping[str, str] | None = None,
    maximum_evidence_bytes: int = MAX_EVIDENCE_BYTES,
) -> ProcessResult:
    """Run one argv-only process with bounded concurrent stream draining."""

    if not argv or any("\x00" in item for item in argv):
        raise ValueError("provider argv must be non-empty and contain no NUL bytes")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    cwd = cwd.resolve(strict=True)
    stdout_path = secure_parent(stdout_path)
    stderr_path = secure_parent(stderr_path)
    started = time.monotonic()
    process = subprocess.Popen(
        tuple(argv),
        cwd=cwd,
        stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(env) if env is not None else None,
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_preview = bytearray()
    stderr_preview = bytearray()
    threads = (
        threading.Thread(
            target=_drain_stream,
            args=(process.stdout, stdout_path),
            kwargs={
                "maximum_bytes": maximum_evidence_bytes,
                "preview_limit": 16 * 1024,
                "preview": stdout_preview,
            },
            daemon=True,
        ),
        threading.Thread(
            target=_drain_stream,
            args=(process.stderr, stderr_path),
            kwargs={
                "maximum_bytes": maximum_evidence_bytes,
                "preview_limit": 16 * 1024,
                "preview": stderr_preview,
            },
            daemon=True,
        ),
    )
    for thread in threads:
        thread.start()
    if process.stdin is not None:
        try:
            process.stdin.write(stdin_bytes or b"")
            process.stdin.close()
        except BrokenPipeError:
            pass
    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_group(process)
    except BaseException:
        _terminate_process_group(process)
        raise
    for thread in threads:
        thread.join()
    duration_ms = round((time.monotonic() - started) * 1000)
    return ProcessResult(
        argv=tuple(argv),
        exit_code=process.returncode,
        timed_out=timed_out,
        duration_ms=duration_ms,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        stdout_preview=bytes(stdout_preview),
        stderr_preview=bytes(stderr_preview),
    )


def read_task_brief(path: Path) -> bytes:
    """Read a regular, non-symlink task brief without implicit decoding."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("task brief must be a regular non-symlink file")
    return path.read_bytes()


def write_final_from_output(path: Path, content: bytes) -> Path:
    path = secure_parent(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    return path
