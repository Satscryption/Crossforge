"""Strict Crossforge configuration loading, merging, and normalization."""

from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .errors import ConfigError
from .models import (
    ArchitectConfig,
    Budget,
    CommitsConfig,
    ConsentConfig,
    CrossforgeConfig,
    Effort,
    GatesConfig,
    MicroFixConfig,
    NetworkPolicy,
    ProviderConfig,
    RetentionConfig,
    RoutingConfig,
    SandboxBackend,
    Strategy,
)


DEFAULT_CONFIG: dict[str, Any] = {
    "schemaVersion": 1,
    "budget": "balanced",
    "strategy": "auto",
    "providers": {
        "codex": {
            "enabled": True,
            "model": "auto",
            "effort": "high",
            "timeoutSeconds": 600,
        },
        "grok": {
            "enabled": True,
            "model": "auto",
            "effort": "high",
            "timeoutSeconds": 600,
        },
    },
    "architect": {
        "lean": "opusplan",
        "balanced": "opusplan",
        "quality": "fable",
        "highRisk": "fable",
        "fallback": "opusplan",
    },
    "microFix": {"enabled": True, "maximumChangedLines": 5},
    "commits": {"enabled": True},
    "consent": {"ttlDays": 90},
    "gates": {
        "timeoutSeconds": 900,
        "sandboxBackend": "auto",
        "network": "deny",
        "executableAllowlist": [],
    },
    "routing": {
        "minimumEvidenceTasks": 10,
        "grokPreferredClasses": [
            "boilerplate",
            "fixtures",
            "repetitive-wiring",
            "crud",
            "straightforward-ui",
        ],
    },
    "retention": {"keepWorktrees": False},
    "denyPaths": [
        "**/.env",
        "**/.env.*",
        "**/secrets/**",
        "**/*credential*",
        "**/*private-key*",
        "**/*.pem",
        "**/*.p12",
        "**/*.key",
    ],
    "gateEnvironmentAllowlist": ["PATH", "LANG", "LC_ALL", "CI"],
}

_SCHEMA: dict[str, Any] = {
    "schemaVersion": None,
    "budget": None,
    "strategy": None,
    "providers": {
        "codex": {
            "enabled": None,
            "model": None,
            "effort": None,
            "timeoutSeconds": None,
        },
        "grok": {
            "enabled": None,
            "model": None,
            "effort": None,
            "timeoutSeconds": None,
        },
    },
    "architect": {
        "lean": None,
        "balanced": None,
        "quality": None,
        "highRisk": None,
        "fallback": None,
    },
    "microFix": {"enabled": None, "maximumChangedLines": None},
    "commits": {"enabled": None},
    "consent": {"ttlDays": None},
    "gates": {
        "timeoutSeconds": None,
        "sandboxBackend": None,
        "network": None,
        "executableAllowlist": None,
    },
    "routing": {"minimumEvidenceTasks": None, "grokPreferredClasses": None},
    "retention": {"keepWorktrees": None},
    "denyPaths": None,
    "gateEnvironmentAllowlist": None,
}

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_ENVIRONMENT_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _reject_unknown_keys(
    value: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    location: str = "config",
) -> None:
    unknown = sorted(set(value) - set(schema))
    if unknown:
        raise ConfigError(f"{location} contains unknown key(s): {', '.join(unknown)}")
    for key, child_schema in schema.items():
        if key not in value or child_schema is None:
            continue
        child = value[key]
        if not isinstance(child, Mapping):
            raise ConfigError(f"{location}.{key} must be an object")
        _reject_unknown_keys(child, child_schema, location=f"{location}.{key}")


def _require_complete_shape(
    value: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    location: str = "config",
) -> None:
    missing = sorted(set(schema) - set(value))
    if missing:
        raise ConfigError(f"{location} is missing key(s): {', '.join(missing)}")
    for key, child_schema in schema.items():
        if child_schema is None:
            continue
        child = value[key]
        if not isinstance(child, Mapping):
            raise ConfigError(f"{location}.{key} must be an object")
        _require_complete_shape(child, child_schema, location=f"{location}.{key}")


def merge_config(
    lower: Mapping[str, Any],
    higher: Mapping[str, Any],
) -> dict[str, Any]:
    """Recursively merge objects; higher-precedence arrays replace in full."""

    if not isinstance(lower, Mapping) or not isinstance(higher, Mapping):
        raise ConfigError("Configuration merge inputs must be objects")
    result = copy.deepcopy(dict(lower))
    for key, higher_value in higher.items():
        lower_value = result.get(key)
        if isinstance(lower_value, Mapping) and isinstance(higher_value, Mapping):
            result[key] = merge_config(lower_value, higher_value)
        else:
            result[key] = copy.deepcopy(higher_value)
    return result


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError(f"Configuration contains duplicate key: {key}")
        result[key] = value
    return result


def load_config_file(path: str | os.PathLike[str]) -> dict[str, Any]:
    source = Path(path)
    try:
        raw = source.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ConfigError(f"Could not read configuration {source}: {error}") from error
    try:
        value = json.loads(raw, object_pairs_hook=_json_object)
    except ConfigError:
        raise
    except json.JSONDecodeError as error:
        raise ConfigError(
            f"Invalid JSON in configuration {source}: line {error.lineno}, "
            f"column {error.colno}"
        ) from error
    if not isinstance(value, dict):
        raise ConfigError(f"Configuration {source} must contain a JSON object")
    _reject_unknown_keys(value, _SCHEMA)
    return value


def _require_bool(value: Any, location: str) -> bool:
    if type(value) is not bool:
        raise ConfigError(f"{location} must be a boolean")
    return value


def _require_integer(
    value: Any,
    location: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        raise ConfigError(f"{location} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        upper = f" through {maximum}" if maximum is not None else " or greater"
        raise ConfigError(f"{location} must be {minimum}{upper}")
    return value


def _require_enum(enum_type: type[Any], value: Any, location: str) -> Any:
    if not isinstance(value, str):
        raise ConfigError(f"{location} must be a string")
    try:
        return enum_type(value)
    except ValueError as error:
        allowed = ", ".join(item.value for item in enum_type)
        raise ConfigError(f"{location} must be one of: {allowed}") from error


def _require_clean_string(value: Any, location: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or _CONTROL_RE.search(value)
    ):
        raise ConfigError(
            f"{location} must be a non-empty string without surrounding "
            "whitespace or control characters"
        )
    return value


def _require_string_array(
    value: Any,
    location: str,
    *,
    clean: bool = True,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError(f"{location} must be an array")
    result = []
    for index, item in enumerate(value):
        if clean:
            result.append(_require_clean_string(item, f"{location}[{index}]"))
        elif not isinstance(item, str):
            raise ConfigError(f"{location}[{index}] must be a string")
        else:
            result.append(item)
    return tuple(result)


def _validate_model(value: Any, location: str) -> str:
    return _require_clean_string(value, location)


def _validate_deny_pattern(value: str, location: str) -> str:
    value = _require_clean_string(value, location)
    if "\\" in value:
        raise ConfigError(f"{location} must use POSIX '/' separators")
    path = PurePosixPath(value)
    if path.is_absolute() or value.startswith("/"):
        raise ConfigError(f"{location} must be a relative glob pattern")
    if any(component in ("", ".", "..") for component in value.split("/")):
        raise ConfigError(f"{location} contains an invalid path component")
    return value


def _validate_executable(value: str, location: str) -> str:
    value = _require_clean_string(value, location)
    if "/" in value or "\\" in value:
        raise ConfigError(f"{location} must be an executable basename")
    return value


def normalize_config(value: Mapping[str, Any]) -> CrossforgeConfig:
    """Validate a complete merged config and return an immutable model."""

    if not isinstance(value, Mapping):
        raise ConfigError("Configuration must be an object")
    _reject_unknown_keys(value, _SCHEMA)
    _require_complete_shape(value, _SCHEMA)
    if value["schemaVersion"] != 1 or type(value["schemaVersion"]) is not int:
        raise ConfigError("config.schemaVersion must be integer 1")

    providers = value["providers"]
    def provider(name: str) -> ProviderConfig:
        item = providers[name]
        return ProviderConfig(
            enabled=_require_bool(item["enabled"], f"config.providers.{name}.enabled"),
            model=_validate_model(item["model"], f"config.providers.{name}.model"),
            effort=_require_enum(
                Effort, item["effort"], f"config.providers.{name}.effort"
            ),
            timeout_seconds=_require_integer(
                item["timeoutSeconds"],
                f"config.providers.{name}.timeoutSeconds",
                minimum=10,
                maximum=7200,
            ),
        )

    architect = value["architect"]
    micro_fix = value["microFix"]
    commits = value["commits"]
    consent = value["consent"]
    gates = value["gates"]
    routing = value["routing"]
    retention = value["retention"]

    executable_allowlist = _require_string_array(
        gates["executableAllowlist"], "config.gates.executableAllowlist"
    )
    executable_allowlist = tuple(
        _validate_executable(item, f"config.gates.executableAllowlist[{index}]")
        for index, item in enumerate(executable_allowlist)
    )
    deny_paths = _require_string_array(value["denyPaths"], "config.denyPaths")
    deny_paths = tuple(
        _validate_deny_pattern(item, f"config.denyPaths[{index}]")
        for index, item in enumerate(deny_paths)
    )
    environment = _require_string_array(
        value["gateEnvironmentAllowlist"], "config.gateEnvironmentAllowlist"
    )
    for index, name in enumerate(environment):
        if not _ENVIRONMENT_NAME_RE.fullmatch(name):
            raise ConfigError(
                f"config.gateEnvironmentAllowlist[{index}] is not a valid "
                "environment variable name"
            )

    return CrossforgeConfig(
        schema_version=1,
        budget=_require_enum(Budget, value["budget"], "config.budget"),
        strategy=_require_enum(Strategy, value["strategy"], "config.strategy"),
        codex=provider("codex"),
        grok=provider("grok"),
        architect=ArchitectConfig(
            lean=_validate_model(architect["lean"], "config.architect.lean"),
            balanced=_validate_model(
                architect["balanced"], "config.architect.balanced"
            ),
            quality=_validate_model(architect["quality"], "config.architect.quality"),
            high_risk=_validate_model(
                architect["highRisk"], "config.architect.highRisk"
            ),
            fallback=_validate_model(
                architect["fallback"], "config.architect.fallback"
            ),
        ),
        micro_fix=MicroFixConfig(
            enabled=_require_bool(micro_fix["enabled"], "config.microFix.enabled"),
            maximum_changed_lines=_require_integer(
                micro_fix["maximumChangedLines"],
                "config.microFix.maximumChangedLines",
                minimum=0,
                maximum=10,
            ),
        ),
        commits=CommitsConfig(
            enabled=_require_bool(commits["enabled"], "config.commits.enabled")
        ),
        consent=ConsentConfig(
            ttl_days=_require_integer(
                consent["ttlDays"],
                "config.consent.ttlDays",
                minimum=1,
                maximum=365,
            )
        ),
        gates=GatesConfig(
            timeout_seconds=_require_integer(
                gates["timeoutSeconds"],
                "config.gates.timeoutSeconds",
                minimum=10,
                maximum=7200,
            ),
            sandbox_backend=_require_enum(
                SandboxBackend,
                gates["sandboxBackend"],
                "config.gates.sandboxBackend",
            ),
            network=_require_enum(
                NetworkPolicy, gates["network"], "config.gates.network"
            ),
            executable_allowlist=executable_allowlist,
        ),
        routing=RoutingConfig(
            minimum_evidence_tasks=_require_integer(
                routing["minimumEvidenceTasks"],
                "config.routing.minimumEvidenceTasks",
                minimum=0,
            ),
            grok_preferred_classes=_require_string_array(
                routing["grokPreferredClasses"],
                "config.routing.grokPreferredClasses",
            ),
        ),
        retention=RetentionConfig(
            keep_worktrees=_require_bool(
                retention["keepWorktrees"], "config.retention.keepWorktrees"
            )
        ),
        deny_paths=deny_paths,
        gate_environment_allowlist=environment,
    )


def config_to_dict(config: CrossforgeConfig) -> dict[str, Any]:
    """Convert the immutable normalized config to its public JSON shape."""

    def provider(value: ProviderConfig) -> dict[str, Any]:
        return {
            "enabled": value.enabled,
            "model": value.model,
            "effort": value.effort.value,
            "timeoutSeconds": value.timeout_seconds,
        }

    return {
        "schemaVersion": config.schema_version,
        "budget": config.budget.value,
        "strategy": config.strategy.value,
        "providers": {
            "codex": provider(config.codex),
            "grok": provider(config.grok),
        },
        "architect": {
            "lean": config.architect.lean,
            "balanced": config.architect.balanced,
            "quality": config.architect.quality,
            "highRisk": config.architect.high_risk,
            "fallback": config.architect.fallback,
        },
        "microFix": {
            "enabled": config.micro_fix.enabled,
            "maximumChangedLines": config.micro_fix.maximum_changed_lines,
        },
        "commits": {"enabled": config.commits.enabled},
        "consent": {"ttlDays": config.consent.ttl_days},
        "gates": {
            "timeoutSeconds": config.gates.timeout_seconds,
            "sandboxBackend": config.gates.sandbox_backend.value,
            "network": config.gates.network.value,
            "executableAllowlist": list(config.gates.executable_allowlist),
        },
        "routing": {
            "minimumEvidenceTasks": config.routing.minimum_evidence_tasks,
            "grokPreferredClasses": list(config.routing.grok_preferred_classes),
        },
        "retention": {"keepWorktrees": config.retention.keep_worktrees},
        "denyPaths": list(config.deny_paths),
        "gateEnvironmentAllowlist": list(config.gate_environment_allowlist),
    }


def _enforce_tighten_only_project_policy(
    trusted: CrossforgeConfig,
    proposed: CrossforgeConfig,
) -> None:
    """Reject repository config that weakens user/default trust boundaries."""

    trusted_environment = set(trusted.gate_environment_allowlist)
    proposed_environment = set(proposed.gate_environment_allowlist)
    added_environment = proposed_environment - trusted_environment
    if added_environment:
        raise ConfigError(
            "Project configuration cannot widen gateEnvironmentAllowlist: "
            + ", ".join(sorted(added_environment))
        )

    removed_deny_paths = set(trusted.deny_paths) - set(proposed.deny_paths)
    if removed_deny_paths:
        raise ConfigError(
            "Project configuration cannot shrink denyPaths: "
            + ", ".join(sorted(removed_deny_paths))
        )

    trusted_executables = set(trusted.gates.executable_allowlist)
    proposed_executables = set(proposed.gates.executable_allowlist)
    if trusted_executables and (
        not proposed_executables
        or not proposed_executables <= trusted_executables
    ):
        added_executables = proposed_executables - trusted_executables
        detail = (
            ", ".join(sorted(added_executables))
            if added_executables
            else "removing the user executable restriction"
        )
        raise ConfigError(
            "Project configuration cannot widen gates.executableAllowlist: "
            + detail
        )


def load_config(
    *,
    user_path: str | os.PathLike[str] | None = None,
    project_path: str | os.PathLike[str] | None = None,
    cli_overrides: Mapping[str, Any] | None = None,
    discover_defaults: bool = True,
) -> CrossforgeConfig:
    """Load config while treating repository policy as tighten-only."""

    merged: dict[str, Any] = copy.deepcopy(DEFAULT_CONFIG)
    if user_path is not None:
        user_source: Path | None = Path(user_path)
    elif discover_defaults:
        user_source = Path.home() / ".claude/crossforge.json"
    else:
        user_source = None
    if project_path is not None:
        project_source: Path | None = Path(project_path)
    elif discover_defaults:
        project_source = Path.cwd() / ".claude/crossforge.json"
    else:
        project_source = None
    if user_source is not None:
        if user_source.exists():
            merged = merge_config(merged, load_config_file(user_source))
        elif user_path is not None:
            raise ConfigError(
                f"Configuration file does not exist: {user_source}"
            )

    if project_source is not None:
        if project_source.exists():
            trusted = normalize_config(merged)
            project_merged = merge_config(
                merged,
                load_config_file(project_source),
            )
            proposed = normalize_config(project_merged)
            _enforce_tighten_only_project_policy(trusted, proposed)
            merged = project_merged
        elif project_path is not None:
            raise ConfigError(
                f"Configuration file does not exist: {project_source}"
            )

    if cli_overrides is not None:
        if not isinstance(cli_overrides, Mapping):
            raise ConfigError("CLI configuration overrides must be an object")
        _reject_unknown_keys(cli_overrides, _SCHEMA)
        merged = merge_config(merged, cli_overrides)
    return normalize_config(merged)
