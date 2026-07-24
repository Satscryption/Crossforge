"""Immutable typed models shared by the Crossforge control layer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Any


class Budget(StrEnum):
    LEAN = "lean"
    BALANCED = "balanced"
    QUALITY = "quality"


class Strategy(StrEnum):
    AUTO = "auto"
    CODEX = "codex"
    GROK = "grok"
    RACE = "race"


class Effort(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RunMode(StrEnum):
    PLAN = "plan"
    BUILD = "build"
    REVIEW = "review"


class RunStatus(StrEnum):
    ACTIVE = "active"
    BLOCKED = "blocked"
    COMPLETE = "complete"
    SHIPPED = "shipped"
    ABANDONED = "abandoned"


class TaskStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    CANDIDATE_READY = "candidate_ready"
    BLOCKED = "blocked"
    ACCEPTED = "accepted"
    COMMITTED = "committed"
    COMPLETE = "complete"


class ProviderStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    SPEC_GAP = "spec_gap"
    SCOPE_VIOLATION = "scope_violation"
    GATE_FAILED = "gate_failed"


class ShippingIntent(StrEnum):
    LOCAL_ONLY = "local-only"
    PUBLISH_LATER = "publish-on-later-explicit-request"


class SandboxBackend(StrEnum):
    AUTO = "auto"
    SANDBOX_EXEC = "sandbox-exec"
    BWRAP = "bwrap"


class NetworkPolicy(StrEnum):
    DENY = "deny"


class FileChangeStatus(StrEnum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    MODE_CHANGED = "mode_changed"


class ProcessExit(IntEnum):
    """Common subprocess outcomes used by adapter result models."""

    SUCCESS = 0


@dataclass(frozen=True, slots=True)
class GateCommand:
    argv: tuple[str, ...]
    timeout_seconds: int

    def to_dict(self) -> dict[str, Any]:
        return {"argv": list(self.argv), "timeoutSeconds": self.timeout_seconds}


@dataclass(frozen=True, slots=True)
class BinaryContext:
    path: str
    sha256: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class ApprovedSymlink:
    path: str
    target: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "target": self.target}


@dataclass(frozen=True, slots=True)
class BranchIntent:
    requested: str | None
    target_remote: str | None
    target_branch: str
    shipping_intent: ShippingIntent

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "targetRemote": self.target_remote,
            "targetBranch": self.target_branch,
            "shippingIntent": self.shipping_intent.value,
        }


@dataclass(frozen=True, slots=True)
class PlanTask:
    id: str
    title: str
    risk: Risk
    task_class: str
    depends_on: tuple[str, ...]
    suggested_strategy: Strategy
    allowed_files: tuple[str, ...]
    objective: str
    interfaces: tuple[str, ...]
    constraints: tuple[str, ...]
    approved_binary_context: tuple[BinaryContext, ...]
    approved_symlinks: tuple[ApprovedSymlink, ...]
    verification_commands: tuple[GateCommand, ...]
    done_when: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "risk": self.risk.value,
            "taskClass": self.task_class,
            "dependsOn": list(self.depends_on),
            "suggestedStrategy": self.suggested_strategy.value,
            "allowedFiles": list(self.allowed_files),
            "objective": self.objective,
            "interfaces": list(self.interfaces),
            "constraints": list(self.constraints),
            "approvedBinaryContext": [
                item.to_dict() for item in self.approved_binary_context
            ],
            "approvedSymlinks": [item.to_dict() for item in self.approved_symlinks],
            "verificationCommands": [
                command.to_dict() for command in self.verification_commands
            ],
            "doneWhen": list(self.done_when),
        }


@dataclass(frozen=True, slots=True)
class Plan:
    schema_version: int
    title: str
    objective: str
    user_visible_outcome: str
    context: tuple[str, ...]
    assumptions: tuple[str, ...]
    non_goals: tuple[str, ...]
    architecture_decisions: tuple[str, ...]
    security_privacy_constraints: tuple[str, ...]
    branch: BranchIntent
    global_verification_commands: tuple[GateCommand, ...]
    tasks: tuple[PlanTask, ...]
    decision_log: tuple[str, ...]
    deferred_work: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "title": self.title,
            "objective": self.objective,
            "userVisibleOutcome": self.user_visible_outcome,
            "context": list(self.context),
            "assumptions": list(self.assumptions),
            "nonGoals": list(self.non_goals),
            "architectureDecisions": list(self.architecture_decisions),
            "securityPrivacyConstraints": list(self.security_privacy_constraints),
            "branch": self.branch.to_dict(),
            "globalVerificationCommands": [
                command.to_dict() for command in self.global_verification_commands
            ],
            "tasks": [task.to_dict() for task in self.tasks],
            "decisionLog": list(self.decision_log),
            "deferredWork": list(self.deferred_work),
        }


@dataclass(frozen=True, slots=True)
class PlanApproval:
    approved: bool
    approved_by: str
    approved_at: str
    approved_plan_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "approvedBy": self.approved_by,
            "approvedAt": self.approved_at,
            "approvedPlanSha256": self.approved_plan_sha256,
        }


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    enabled: bool
    model: str
    effort: Effort
    timeout_seconds: int


@dataclass(frozen=True, slots=True)
class ArchitectConfig:
    lean: str
    balanced: str
    quality: str
    high_risk: str
    fallback: str


@dataclass(frozen=True, slots=True)
class MicroFixConfig:
    enabled: bool
    maximum_changed_lines: int


@dataclass(frozen=True, slots=True)
class CommitsConfig:
    enabled: bool


@dataclass(frozen=True, slots=True)
class ConsentConfig:
    ttl_days: int


@dataclass(frozen=True, slots=True)
class GatesConfig:
    timeout_seconds: int
    sandbox_backend: SandboxBackend
    network: NetworkPolicy
    executable_allowlist: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RoutingConfig:
    minimum_evidence_tasks: int
    grok_preferred_classes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RetentionConfig:
    keep_worktrees: bool


@dataclass(frozen=True, slots=True)
class CrossforgeConfig:
    schema_version: int
    budget: Budget
    strategy: Strategy
    codex: ProviderConfig
    grok: ProviderConfig
    architect: ArchitectConfig
    micro_fix: MicroFixConfig
    commits: CommitsConfig
    consent: ConsentConfig
    gates: GatesConfig
    routing: RoutingConfig
    retention: RetentionConfig
    deny_paths: tuple[str, ...]
    gate_environment_allowlist: tuple[str, ...]
