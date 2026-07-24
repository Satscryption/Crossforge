"""Operational errors and stable process exit codes for Crossforge."""

from __future__ import annotations

from enum import IntEnum
from typing import Any, Mapping


class ExitCode(IntEnum):
    """Exit codes defined by the Crossforge command-line contract."""

    SUCCESS = 0
    INVALID_INPUT = 2
    PRECONDITION_FAILED = 3
    PROVIDER_UNAVAILABLE = 4
    SCOPE_VIOLATION = 5
    GATE_FAILED = 6
    STATE_INCONSISTENCY = 7
    POLICY_FAILED = 8


class CrossforgeError(Exception):
    """Base class for expected, user-facing operational failures."""

    exit_code = ExitCode.PRECONDITION_FAILED

    def __init__(
        self,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = dict(details or {})

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "error": type(self).__name__,
            "message": self.message,
            "exitCode": int(self.exit_code),
        }
        if self.details:
            result["details"] = self.details
        return result


class InvalidInputError(CrossforgeError):
    """Invalid arguments or input data."""

    exit_code = ExitCode.INVALID_INPUT


class ConfigError(InvalidInputError):
    """Invalid or unreadable Crossforge configuration."""


class PlanValidationError(InvalidInputError):
    """A canonical plan does not satisfy the plan contract."""


class PreconditionError(CrossforgeError):
    """A required local precondition or blocker check failed."""

    exit_code = ExitCode.PRECONDITION_FAILED


class ProviderUnavailableError(CrossforgeError):
    """A selected provider is unavailable."""

    exit_code = ExitCode.PROVIDER_UNAVAILABLE


class ScopeViolationError(CrossforgeError):
    """A candidate changed content outside its exact allowlist."""

    exit_code = ExitCode.SCOPE_VIOLATION


class GateFailureError(CrossforgeError):
    """A required verification gate failed."""

    exit_code = ExitCode.GATE_FAILED


class StateInconsistencyError(CrossforgeError):
    """Durable state is inconsistent or has an invalid transition."""

    exit_code = ExitCode.STATE_INCONSISTENCY


class PolicyError(CrossforgeError):
    """A consent, privacy, or secret-handling policy failed."""

    exit_code = ExitCode.POLICY_FAILED


class ConsentError(PolicyError):
    """Provider consent is absent, expired, or mismatched."""


class SecretPolicyError(PolicyError):
    """Secret screening or deny-path policy failed."""
