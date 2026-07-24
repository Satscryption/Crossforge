"""Safe adapter for the xAI Grok CLI."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Callable, Mapping, Sequence

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
_SAFE_PREFIX_PART = re.compile(r"^[A-Za-z0-9_./:=+@%,-]+$")
_REQUIRED_HELP_FLAGS = (
    "--no-auto-update",
    "--cwd",
    "--model",
    "--output-format",
    "--permission-mode",
    "--allow",
    "--disallow",
    "--sandbox",
    "--prompt",
)


class GrokCLIAdapter(ProviderAdapter):
    """Invoke Grok in fail-closed, explicitly allowlisted headless mode."""

    provider = "grok"

    def __init__(
        self,
        *,
        executable: str = "grok",
        env: Mapping[str, str] | None = None,
        capability_source: CapabilitySource | None = None,
        verification_command_prefixes: Sequence[Sequence[str]] = (),
        probe_timeout_seconds: int = 20,
    ) -> None:
        self._executable_name = executable
        self._env = dict(env) if env is not None else None
        self._capability_source = capability_source
        self._verification_prefixes = tuple(
            self._validate_prefix(prefix) for prefix in verification_command_prefixes
        )
        self._probe_timeout = probe_timeout_seconds
        self._last_probe: ProviderProbe | None = None

    @staticmethod
    def _validate_prefix(prefix: Sequence[str]) -> tuple[str, ...]:
        if not prefix or any(not part or not _SAFE_PREFIX_PART.fullmatch(part) for part in prefix):
            raise ValueError("verification command prefixes contain an unsafe argument")
        return tuple(prefix)

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
        message: str | bytes,
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
            message=sanitize_message(
                message, sensitive_paths=(executable,) if executable else ()
            ),
            capability_probe=capability,
        )
        self._last_probe = result
        return result

    @staticmethod
    def _parse_models(output: bytes) -> tuple[set[str], str | None]:
        text = output.decode("utf-8", "replace").strip()
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            models = {
                line.strip().split()[0]
                for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            }
            return models, None
        if isinstance(value, dict):
            raw_models = value.get("models", ())
            models = {
                str(item.get("id") if isinstance(item, dict) else item)
                for item in raw_models
            }
            default = value.get("defaultModel") or value.get("default")
            return {item for item in models if item and item != "None"}, (
                str(default) if default else None
            )
        if isinstance(value, list):
            return {str(item) for item in value}, None
        return set(), None

    def probe(self, requested_model: str, effort: str) -> ProviderProbe:
        executable = self._find_executable()
        if executable is None:
            return self._failed_probe(
                requested_model=requested_model,
                effort=effort,
                category="missing_executable",
                message="Grok CLI was not found on PATH",
            )
        with tempfile.TemporaryDirectory(prefix="crossforge-grok-preflight-") as tmp:
            root = Path(tmp)
            version_result = run_process(
                (str(executable), "version"),
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
            if version_result.timed_out or version_result.exit_code != 0:
                return self._failed_probe(
                    requested_model=requested_model,
                    effort=effort,
                    category=(
                        "version_timeout"
                        if version_result.timed_out
                        else "version_failed"
                    ),
                    message=version or "Grok version check failed",
                    executable=executable,
                )
            help_result = run_process(
                (str(executable), "--help"),
                cwd=root,
                stdin_bytes=None,
                timeout_seconds=self._probe_timeout,
                stdout_path=root / "help.stdout",
                stderr_path=root / "help.stderr",
                env=self._env,
            )
            help_text = help_result.stdout_preview.decode("utf-8", "replace")
            missing = tuple(flag for flag in _REQUIRED_HELP_FLAGS if flag not in help_text)
            if help_result.timed_out or help_result.exit_code != 0 or missing:
                detail = (
                    "missing required safe headless flags: " + ", ".join(missing)
                    if missing
                    else "Grok help inspection failed"
                )
                return self._failed_probe(
                    requested_model=requested_model,
                    effort=effort,
                    category="incompatible_cli",
                    message=detail,
                    executable=executable,
                    version=version,
                )
            if self._capability_source is None:
                return self._failed_probe(
                    requested_model=requested_model,
                    effort=effort,
                    category="sandbox_inconclusive",
                    message="No trusted Grok sandbox capability evidence is available",
                    executable=executable,
                    version=version,
                )
            capability = self._capability_source("workspace-write")
            if not capability.safe:
                return self._failed_probe(
                    requested_model=requested_model,
                    effort=effort,
                    category="sandbox_incompatible",
                    message=capability.message
                    or "Grok sandbox capability checks did not all pass",
                    executable=executable,
                    version=version,
                    capability=capability,
                )
            models_result = run_process(
                (str(executable), "models"),
                cwd=root,
                stdin_bytes=None,
                timeout_seconds=self._probe_timeout,
                stdout_path=root / "models.stdout",
                stderr_path=root / "models.stderr",
                env=self._env,
            )
            if models_result.timed_out or models_result.exit_code != 0:
                return self._failed_probe(
                    requested_model=requested_model,
                    effort=effort,
                    category="authentication_failed",
                    message=models_result.stderr_preview
                    or models_result.stdout_preview
                    or b"Grok model/authentication check failed",
                    executable=executable,
                    version=version,
                    capability=capability,
                )
            models, default_model = self._parse_models(models_result.stdout_preview)
            if requested_model != "auto" and requested_model not in models:
                return self._failed_probe(
                    requested_model=requested_model,
                    effort=effort,
                    category="model_unavailable",
                    message="Requested Grok model is not available",
                    executable=executable,
                    version=version,
                    authenticated=True,
                    capability=capability,
                )
            resolved_model = (
                requested_model
                if requested_model != "auto"
                else default_model or "cli-default"
            )
            result = ProviderProbe(
                provider=self.provider,
                available=True,
                cli_path=str(executable),
                cli_version=version,
                authenticated=True,
                requested_model=requested_model,
                resolved_model=resolved_model,
                effort=effort,
                message="Grok CLI and mandatory sandbox capabilities are available",
                capability_probe=capability,
            )
            self._last_probe = result
            return result

    def _build_argv(
        self,
        *,
        executable: Path,
        worktree: Path,
        requested_model: str,
        review: bool,
        prompt: str,
    ) -> tuple[str, ...]:
        argv = [
            str(executable),
            "--no-auto-update",
            "--cwd",
            str(worktree.resolve()),
            "--output-format",
            "json",
            "--permission-mode",
            "dontAsk",
            "--sandbox",
            "read-only" if review else "workspace-write",
        ]
        if requested_model != "auto":
            argv.extend(("--model", requested_model))
        for tool in ("Read", "Grep", "Glob"):
            argv.extend(("--allow", tool))
        if not review:
            argv.extend(("--allow", "Edit"))
            for prefix in self._verification_prefixes:
                argv.extend(("--allow", f"Bash({' '.join(prefix)}:*)"))
        for tool in ("WebSearch", "RemoteMCP", "Computer", "Network"):
            argv.extend(("--disallow", tool))
        argv.extend(("--prompt", prompt))
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
        brief = read_task_brief(spec_path).decode("utf-8", "strict")
        if review:
            brief = (
                "READ-ONLY REVIEW. Do not edit, create, delete, rename, or execute "
                "repository files. Report findings only.\n\n" + brief
            )
        executable = Path(probe.cli_path)
        argv = self._build_argv(
            executable=executable,
            worktree=worktree,
            requested_model=requested_model,
            review=review,
            prompt=brief,
        )
        result = run_process(
            argv,
            cwd=worktree,
            stdin_bytes=None,
            timeout_seconds=timeout_seconds,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            env=self._env,
        )
        write_final_from_output(final_output_path, result.stdout_path.read_bytes())
        if result.timed_out:
            status = ProviderStatus.TIMEOUT
            message = "Grok invocation timed out"
        elif result.exit_code != 0:
            status = ProviderStatus.FAILED
            message = sanitize_message(
                result.stderr_preview or result.stdout_preview,
                sensitive_paths=(worktree, spec_path, executable, final_output_path),
            ) or "Grok invocation failed"
        else:
            status = ProviderStatus.COMPLETE
            message = "Grok invocation completed"
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
