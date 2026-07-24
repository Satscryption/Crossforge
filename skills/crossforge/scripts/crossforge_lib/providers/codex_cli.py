"""Safe adapter for the OpenAI Codex CLI."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Callable, Mapping

from ..models import ProviderStatus
from .base import (
    CapabilityProbe,
    ProviderAdapter,
    ProviderInvocation,
    ProviderProbe,
    read_task_brief,
    run_process,
    sanitize_message,
    validate_evidence_path,
    write_final_from_output,
)

CapabilitySource = Callable[[str], CapabilityProbe]


class CodexCLIAdapter(ProviderAdapter):
    """Invoke Codex with approval bypasses forbidden and sandboxing mandatory."""

    provider = "codex"

    def __init__(
        self,
        *,
        executable: str = "codex",
        env: Mapping[str, str] | None = None,
        capability_source: CapabilitySource | None = None,
        probe_timeout_seconds: int = 20,
    ) -> None:
        self._executable_name = executable
        self._env = dict(env) if env is not None else None
        self._capability_source = capability_source
        self._probe_timeout = probe_timeout_seconds
        self._last_probe: ProviderProbe | None = None

    def _find_executable(self) -> Path | None:
        candidate = shutil.which(self._executable_name, path=(self._env or {}).get("PATH"))
        if candidate is None:
            return None
        resolved = Path(candidate).resolve()
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            return None
        return resolved

    def _failed_probe(
        self,
        *,
        requested_model: str,
        effort: str,
        category: str,
        message: str,
        executable: Path | None = None,
        version: str | None = None,
        authenticated: bool = False,
        capability: CapabilityProbe | None = None,
    ) -> ProviderProbe:
        result = ProviderProbe(
            provider=self.provider,
            available=False,
            cli_path=str(executable) if executable else None,
            cli_version=version,
            authenticated=authenticated,
            requested_model=requested_model,
            resolved_model=None,
            effort=effort,
            failure_category=category,
            message=sanitize_message(message, sensitive_paths=(executable,) if executable else ()),
            capability_probe=capability,
        )
        self._last_probe = result
        return result

    def probe(self, requested_model: str, effort: str) -> ProviderProbe:
        executable = self._find_executable()
        if executable is None:
            return self._failed_probe(
                requested_model=requested_model,
                effort=effort,
                category="missing_executable",
                message="Codex CLI was not found on PATH",
            )
        with tempfile.TemporaryDirectory(prefix="crossforge-codex-preflight-") as tmp:
            root = Path(tmp)
            probe_worktree = root / "worktree"
            probe_worktree.mkdir()
            version_result = run_process(
                (str(executable), "--version"),
                cwd=root,
                stdin_bytes=None,
                timeout_seconds=self._probe_timeout,
                stdout_path=root / "version.stdout",
                stderr_path=root / "version.stderr",
                env=self._env,
            )
            version = sanitize_message(
                version_result.stdout_preview or version_result.stderr_preview,
                sensitive_paths=(executable, root),
            )
            if version_result.timed_out:
                return self._failed_probe(
                    requested_model=requested_model,
                    effort=effort,
                    category="version_timeout",
                    message="Codex version check timed out",
                    executable=executable,
                )
            if version_result.exit_code != 0:
                return self._failed_probe(
                    requested_model=requested_model,
                    effort=effort,
                    category="version_failed",
                    message=version or "Codex version check failed",
                    executable=executable,
                )
            auth_result = run_process(
                (str(executable), "login", "status"),
                cwd=root,
                stdin_bytes=None,
                timeout_seconds=self._probe_timeout,
                stdout_path=root / "auth.stdout",
                stderr_path=root / "auth.stderr",
                env=self._env,
            )
            if auth_result.timed_out or auth_result.exit_code != 0:
                message = auth_result.stderr_preview or auth_result.stdout_preview
                return self._failed_probe(
                    requested_model=requested_model,
                    effort=effort,
                    category="authentication_failed",
                    message=message or b"Codex is not authenticated",
                    executable=executable,
                    version=version,
                )
            if self._capability_source is None:
                return self._failed_probe(
                    requested_model=requested_model,
                    effort=effort,
                    category="sandbox_inconclusive",
                    message="No trusted Codex sandbox capability evidence is available",
                    executable=executable,
                    version=version,
                    authenticated=True,
                )
            capability = self._capability_source("workspace-write")
            if not capability.safe:
                return self._failed_probe(
                    requested_model=requested_model,
                    effort=effort,
                    category="sandbox_incompatible",
                    message=capability.message
                    or "Codex sandbox capability checks did not all pass",
                    executable=executable,
                    version=version,
                    authenticated=True,
                    capability=capability,
                )
            resolved_model = "cli-default"
            if requested_model != "auto":
                probe_output = root / "model-final.txt"
                argv = self._build_argv(
                    executable=executable,
                    worktree=probe_worktree,
                    requested_model=requested_model,
                    effort=effort,
                    sandbox="read-only",
                    final_output_path=probe_output,
                )
                model_result = run_process(
                    argv,
                    cwd=probe_worktree,
                    stdin_bytes=(
                        b"Crossforge source-free readiness probe. "
                        b"Reply with the exact active model identifier only."
                    ),
                    timeout_seconds=self._probe_timeout,
                    stdout_path=root / "model.stdout",
                    stderr_path=root / "model.stderr",
                    env=self._env,
                )
                if model_result.timed_out or model_result.exit_code != 0:
                    message = model_result.stderr_preview or model_result.stdout_preview
                    return self._failed_probe(
                        requested_model=requested_model,
                        effort=effort,
                        category=(
                            "model_probe_timeout"
                            if model_result.timed_out
                            else "model_unavailable"
                        ),
                        message=message or b"Requested Codex model is unavailable",
                        executable=executable,
                        version=version,
                        authenticated=True,
                        capability=capability,
                    )
                resolved_model = requested_model
                if probe_output.is_file():
                    reported = sanitize_message(
                        probe_output.read_bytes(), sensitive_paths=(root, executable)
                    )
                    if reported:
                        resolved_model = reported.split()[0]
            result = ProviderProbe(
                provider=self.provider,
                available=True,
                cli_path=str(executable),
                cli_version=version,
                authenticated=True,
                requested_model=requested_model,
                resolved_model=resolved_model,
                effort=effort,
                message="Codex CLI and mandatory sandbox capabilities are available",
                capability_probe=capability,
            )
            self._last_probe = result
            return result

    @staticmethod
    def _build_argv(
        *,
        executable: Path,
        worktree: Path,
        requested_model: str,
        effort: str,
        sandbox: str,
        final_output_path: Path,
    ) -> tuple[str, ...]:
        argv = [str(executable), "exec"]
        if requested_model != "auto":
            argv.extend(("--model", requested_model))
        argv.extend(
            (
                "-c",
                f"model_reasoning_effort={effort}",
                "--sandbox",
                sandbox,
                "--ask-for-approval",
                "never",
                "--ephemeral",
                "--strict-config",
                "--cd",
                str(worktree.resolve()),
                "--output-last-message",
                str(final_output_path.resolve(strict=False)),
                "-",
            )
        )
        return tuple(argv)

    def _invoke(
        self,
        *,
        review: bool,
        spec_path: Path,
        worktree: Path,
        requested_model: str,
        effort: str,
        timeout_seconds: int,
        final_output_path: Path,
    ) -> ProviderInvocation:
        probe = self._last_probe
        if (
            probe is None
            or probe.requested_model != requested_model
            or probe.effort != effort
        ):
            probe = self.probe(requested_model, effort)
        final_output_path = validate_evidence_path(
            final_output_path, worktree=worktree
        )
        raw_parent = final_output_path.parent
        stdout_path = raw_parent / "stdout.raw"
        stderr_path = raw_parent / "stderr.raw"
        if not probe.available or probe.cli_path is None:
            return ProviderInvocation(
                provider=self.provider,
                status=ProviderStatus.UNAVAILABLE,
                requested_model=requested_model,
                resolved_model=probe.resolved_model or "unknown",
                argv=(),
                exit_code=None,
                timed_out=False,
                duration_ms=0,
                raw_stdout_path=stdout_path,
                raw_stderr_path=stderr_path,
                final_output_path=final_output_path.resolve(strict=False),
                message=probe.message,
            )
        brief = read_task_brief(spec_path)
        if review:
            brief = (
                b"READ-ONLY REVIEW. Do not edit, create, delete, or rename files. "
                b"Report findings only.\n\n" + brief
            )
        executable = Path(probe.cli_path)
        argv = self._build_argv(
            executable=executable,
            worktree=worktree,
            requested_model=requested_model,
            effort=effort,
            sandbox="read-only" if review else "workspace-write",
            final_output_path=final_output_path,
        )
        result = run_process(
            argv,
            cwd=worktree,
            stdin_bytes=brief,
            timeout_seconds=timeout_seconds,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            env=self._env,
        )
        if not final_output_path.is_file():
            write_final_from_output(final_output_path, result.stdout_path.read_bytes())
        else:
            try:
                os.chmod(final_output_path, 0o600)
            except OSError:
                pass
        if result.timed_out:
            status = ProviderStatus.TIMEOUT
            message = "Codex invocation timed out"
        elif result.exit_code != 0:
            status = ProviderStatus.FAILED
            message = sanitize_message(
                result.stderr_preview or result.stdout_preview,
                sensitive_paths=(worktree, spec_path, executable, final_output_path),
            ) or "Codex invocation failed"
        else:
            status = ProviderStatus.COMPLETE
            message = "Codex invocation completed"
        return ProviderInvocation(
            provider=self.provider,
            status=status,
            requested_model=requested_model,
            resolved_model=probe.resolved_model or "unknown",
            argv=argv,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            duration_ms=result.duration_ms,
            raw_stdout_path=result.stdout_path,
            raw_stderr_path=result.stderr_path,
            final_output_path=final_output_path,
            message=message,
        )

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
        return self._invoke(
            review=False,
            spec_path=spec_path,
            worktree=worktree,
            requested_model=requested_model,
            effort=effort,
            timeout_seconds=timeout_seconds,
            final_output_path=final_output_path,
        )

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
        return self._invoke(
            review=True,
            spec_path=spec_path,
            worktree=worktree,
            requested_model=requested_model,
            effort=effort,
            timeout_seconds=timeout_seconds,
            final_output_path=final_output_path,
        )
