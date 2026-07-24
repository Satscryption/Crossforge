"""Private, hash-addressed evidence storage.

Provider reports are claims made by an implementation lane.  Gate results are
facts produced independently by the trusted control layer.  This module gives
the two classes of data distinct namespaces and refuses paths which could make
one masquerade as the other.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .errors import InvalidInputError, PolicyError, PreconditionError
from .util import (
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    canonical_json_bytes,
    ensure_private_directory,
    sha256_bytes,
    sha256_file,
)

_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def normalize_evidence_path(value: str) -> str:
    """Return a canonical POSIX evidence path, rejecting escapes and aliases."""

    if not isinstance(value, str) or not value:
        raise InvalidInputError("Evidence path must be a non-empty string")
    if "\\" in value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise InvalidInputError("Evidence path contains a backslash or control character")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix():
        raise InvalidInputError("Evidence path must be canonical and relative")
    if any(component in {"", ".", ".."} for component in path.parts):
        raise InvalidInputError("Evidence path contains an unsafe component")
    return path.as_posix()


def _validate_component(value: str, label: str) -> str:
    if not isinstance(value, str) or not _COMPONENT.fullmatch(value):
        raise InvalidInputError(f"{label} contains unsupported characters")
    return value


def contained_evidence_path(root: str | os.PathLike[str], relative: str) -> Path:
    """Resolve *relative* beneath *root* without following a symlink escape."""

    normalized = normalize_evidence_path(relative)
    base = Path(root).resolve(strict=False)
    cursor = base
    for component in PurePosixPath(normalized).parts:
        cursor = cursor / component
        if cursor.exists() and cursor.is_symlink():
            raise PolicyError(f"Evidence path traverses a symlink: {normalized}")
        resolved = cursor.resolve(strict=False)
        try:
            resolved.relative_to(base)
        except ValueError as error:
            raise PolicyError(f"Evidence path escapes its root: {normalized}") from error
    return cursor


@dataclass(frozen=True)
class EvidenceArtifact:
    """A durable evidence file and its independently calculated identity."""

    relative_path: str
    sha256: str
    size_bytes: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.relative_path,
            "sha256": self.sha256,
            "sizeBytes": self.size_bytes,
        }


class EvidenceStore:
    """Write owner-private evidence beneath one task evidence directory."""

    PROVIDER_NAMESPACE = "provider-claims"
    INDEPENDENT_NAMESPACE = "independent"

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = ensure_private_directory(root).resolve()

    def path(self, relative: str) -> Path:
        return contained_evidence_path(self.root, relative)

    def provider_claim_path(self, provider: str, name: str) -> Path:
        provider = _validate_component(provider, "Provider")
        return self.path(f"{self.PROVIDER_NAMESPACE}/{provider}/{normalize_evidence_path(name)}")

    def independent_path(self, name: str) -> Path:
        return self.path(f"{self.INDEPENDENT_NAMESPACE}/{normalize_evidence_path(name)}")

    def classify(self, path: str | os.PathLike[str]) -> str:
        candidate = Path(path).resolve(strict=False)
        try:
            relative = candidate.relative_to(self.root).as_posix()
        except ValueError as error:
            raise PolicyError("Evidence file is outside the evidence root") from error
        first = PurePosixPath(relative).parts[0] if relative != "." else ""
        if first == self.PROVIDER_NAMESPACE:
            return "provider_claim"
        if first == self.INDEPENDENT_NAMESPACE:
            return "independent"
        return "shared"

    def write_bytes(self, relative: str, data: bytes) -> EvidenceArtifact:
        target = self.path(relative)
        atomic_write_bytes(target, data, mode=0o600)
        return EvidenceArtifact(
            relative_path=target.relative_to(self.root).as_posix(),
            sha256=sha256_bytes(data),
            size_bytes=len(data),
        )

    def write_text(self, relative: str, text: str) -> EvidenceArtifact:
        target = self.path(relative)
        atomic_write_text(target, text, mode=0o600)
        encoded = text.encode("utf-8")
        return EvidenceArtifact(
            relative_path=target.relative_to(self.root).as_posix(),
            sha256=sha256_bytes(encoded),
            size_bytes=len(encoded),
        )

    def write_json(self, relative: str, value: Any) -> EvidenceArtifact:
        target = self.path(relative)
        encoded = canonical_json_bytes(value)
        atomic_write_json(target, value, mode=0o600)
        return EvidenceArtifact(
            relative_path=target.relative_to(self.root).as_posix(),
            sha256=sha256_bytes(encoded),
            size_bytes=len(encoded),
        )

    def write_provider_json(
        self,
        provider: str,
        name: str,
        value: Any,
    ) -> EvidenceArtifact:
        target = self.provider_claim_path(provider, name)
        relative = target.relative_to(self.root).as_posix()
        return self.write_json(relative, value)

    def write_independent_json(self, name: str, value: Any) -> EvidenceArtifact:
        target = self.independent_path(name)
        relative = target.relative_to(self.root).as_posix()
        return self.write_json(relative, value)

    def verify(self, artifact: EvidenceArtifact) -> bool:
        path = self.path(artifact.relative_path)
        if not path.is_file() or path.is_symlink():
            return False
        return path.stat().st_size == artifact.size_bytes and sha256_file(path) == artifact.sha256


def evidence_manifest(
    root: str | os.PathLike[str],
    paths: Iterable[str | os.PathLike[str]],
) -> dict[str, Any]:
    """Create a deterministic manifest without including file contents."""

    base_input = Path(root).absolute()
    base = base_input.resolve()
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in paths:
        supplied = Path(value)
        lexical = supplied.absolute()
        try:
            lexical_relative = lexical.relative_to(base_input)
        except ValueError as error:
            raise PolicyError("Evidence manifest entry is outside its root") from error
        cursor = base_input
        for component in lexical_relative.parts:
            cursor /= component
            if cursor.is_symlink():
                raise PolicyError("Evidence manifest entries cannot traverse symlinks")
        candidate = supplied.resolve(strict=True)
        try:
            relative = candidate.relative_to(base).as_posix()
        except ValueError as error:
            raise PolicyError("Evidence manifest entry is outside its root") from error
        normalized = normalize_evidence_path(relative)
        if normalized in seen:
            raise InvalidInputError(f"Duplicate evidence manifest entry: {normalized}")
        if not candidate.is_file() or candidate.is_symlink():
            raise PreconditionError(f"Evidence manifest entry is not a regular file: {normalized}")
        seen.add(normalized)
        entries.append(
            {
                "path": normalized,
                "sha256": sha256_file(candidate),
                "sizeBytes": candidate.stat().st_size,
            }
        )
    entries.sort(key=lambda entry: entry["path"])
    body = {"schemaVersion": 1, "files": entries}
    body["manifestSha256"] = sha256_bytes(canonical_json_bytes(body))
    return body


def safe_user_summary(value: Any) -> str:
    """Return a non-content summary suitable for terminal output.

    Secret findings, provider stdout, gaps, risks, and arbitrary exception
    strings are deliberately never echoed by this helper.
    """

    if isinstance(value, dict):
        status = value.get("status")
        provider = value.get("provider")
        changed = value.get("changedFiles")
        parts = []
        if isinstance(provider, str):
            parts.append(f"provider={provider}")
        if isinstance(status, str):
            parts.append(f"status={status}")
        if isinstance(changed, list):
            parts.append(f"changedFiles={len(changed)}")
        return "Evidence summary: " + (", ".join(parts) if parts else "recorded")
    return "Evidence summary: recorded"


def load_json_evidence(path: str | os.PathLike[str]) -> Any:
    """Load a regular owner-private JSON evidence file."""

    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise PreconditionError(f"Evidence is missing or not a regular file: {candidate}")
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InvalidInputError(f"Evidence is not valid UTF-8 JSON: {candidate}") from error
