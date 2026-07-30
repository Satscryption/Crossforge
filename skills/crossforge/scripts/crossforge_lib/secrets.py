"""Provider-readable context inventory, deny matching, and secret screening."""

from __future__ import annotations

import codecs
import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence

from .errors import SecretPolicyError
from .util import atomic_write_json

MAX_TEXT_BYTES = 10 * 1024 * 1024
MANIFEST_NAME = "quarantine-manifest.json"
PLACEHOLDERS = frozenset(
    {
        "example",
        "placeholder",
        "changeme",
        "test",
        "dummy",
        "redacted",
        "<value>",
        "your_api_key",
    }
)
DETECTOR_NAMES = (
    "pem-private-key",
    "openssh-private-key",
    "api-token-prefix",
    "credential-assignment",
    "credential-high-entropy",
    "unscannable-large-text",
)

_KEY_FRAGMENT = r"(?:token|secret|password|api[_-]?key|private[_-]?key)"
_ASSIGNMENT_RE = re.compile(
    rf"""(?ix)
    (?P<key>[A-Za-z0-9_.-]*{_KEY_FRAGMENT}[A-Za-z0-9_.-]*)
    \s*(?::|=)\s*
    (?P<quote>["']?)
    (?P<value>[^\s,"'\]\}}]+|[^"']{{8,}})
    (?P=quote)
    """
)
_TOKEN_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{16,}\b"),
)


@dataclass(frozen=True, order=True, slots=True)
class SecretFinding:
    """A finding deliberately containing no matched secret value."""

    path: str
    line: int
    detector: str
    severity: str

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "detector": self.detector,
            "severity": self.severity,
        }


def _normalize_relative_path(path: str | os.PathLike[str]) -> str:
    raw = os.fspath(path).replace("\\", "/")
    candidate = PurePosixPath(raw)
    if (
        not raw
        or raw.startswith("/")
        or raw.endswith("/")
        or "//" in raw
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or "\x00" in raw
    ):
        raise SecretPolicyError(f"invalid repository-relative path: {raw!r}")
    return candidate.as_posix()


def _translate_deny_glob(pattern: str) -> re.Pattern[str]:
    normalized = _normalize_relative_path(pattern)
    index = 0
    parts: list[str] = ["^"]
    while index < len(normalized):
        character = normalized[index]
        if character == "*":
            if index + 1 < len(normalized) and normalized[index + 1] == "*":
                if index + 2 < len(normalized) and normalized[index + 2] == "/":
                    parts.append("(?:.*/)?")
                    index += 3
                else:
                    parts.append(".*")
                    index += 2
            else:
                parts.append("[^/]*")
                index += 1
        elif character == "?":
            parts.append("[^/]")
            index += 1
        else:
            parts.append(re.escape(character))
            index += 1
    parts.append("$")
    return re.compile("".join(parts), re.IGNORECASE)


def match_deny_path(
    path: str | os.PathLike[str], patterns: Iterable[str]
) -> bool:
    """Match a path using Crossforge's fixed, platform-independent semantics."""

    normalized = _normalize_relative_path(path)
    return any(_translate_deny_glob(pattern).fullmatch(normalized) for pattern in patterns)


def denied_paths(paths: Iterable[str], patterns: Iterable[str]) -> list[str]:
    """Return normalized matching paths in deterministic order."""

    compiled_patterns = tuple(patterns)
    return sorted(
        {
            normalized
            for path in paths
            if match_deny_path(
                normalized := _normalize_relative_path(path), compiled_patterns
            )
        }
    )


def sha256_path(path: str | os.PathLike[str]) -> str:
    """Hash a regular file, or the link text of a symlink, without following it."""

    source = Path(path)
    if source.is_symlink():
        data = os.readlink(source).encode("utf-8", errors="surrogateescape")
        return hashlib.sha256(data).hexdigest()
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_type(path: Path) -> str:
    mode = path.lstat().st_mode
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    return "unsupported"


def _git_mode(path: Path) -> str:
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        return "120000"
    if stat.S_ISREG(mode):
        return "100755" if mode & stat.S_IXUSR else "100644"
    return format(stat.S_IFMT(mode), "o")


def _safe_path(root: Path, relative: str, *, allow_missing: bool = False) -> Path:
    normalized = _normalize_relative_path(relative)
    root = root.resolve()
    current = root
    components = PurePosixPath(normalized).parts
    for index, component in enumerate(components):
        current = current / component
        final = index == len(components) - 1
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            if allow_missing:
                continue
            raise SecretPolicyError(f"context path does not exist: {normalized}")
        if not final and stat.S_ISLNK(mode):
            raise SecretPolicyError(
                f"intermediate symlink is not allowed: {normalized}"
            )
    return current


def _symlink_is_internal(path: Path, root: Path) -> bool:
    try:
        target = (path.parent / os.readlink(path)).resolve(strict=False)
        target.relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def build_context_manifest(
    root: str | os.PathLike[str],
    *,
    output_path: str | os.PathLike[str] | None = None,
    excluded_paths: Sequence[str] = (".git",),
) -> dict[str, object]:
    """Inventory every regular file and symlink readable below ``root``.

    Symlinks are recorded but never followed.  A link escaping the root, an
    intermediate link, or a special filesystem object blocks the manifest.
    """

    root_path = Path(root).resolve()
    excluded = {_normalize_relative_path(item) for item in excluded_paths}
    excluded_roots = tuple(root_path / Path(item) for item in excluded)
    entries: list[dict[str, object]] = []
    for directory, directory_names, file_names in os.walk(
        root_path, topdown=True, followlinks=False
    ):
        directory_path = Path(directory)
        relative_directory = directory_path.relative_to(root_path)
        retained_directories: list[str] = []
        for name in sorted(directory_names):
            candidate = directory_path / name
            relative = (relative_directory / name).as_posix()
            if relative in excluded or any(
                relative.startswith(item + "/") for item in excluded
            ):
                continue
            if candidate.is_symlink():
                file_names.append(name)
            else:
                retained_directories.append(name)
        directory_names[:] = retained_directories

        for name in sorted(file_names):
            candidate = directory_path / name
            relative = (relative_directory / name).as_posix()
            if relative in excluded or any(
                relative.startswith(item + "/") for item in excluded
            ):
                continue
            kind = _file_type(candidate)
            if kind == "unsupported":
                raise SecretPolicyError(f"unsupported provider context: {relative}")
            if kind == "directory":
                continue
            if kind == "symlink":
                if not _symlink_is_internal(candidate, root_path):
                    raise SecretPolicyError(f"symlink escapes candidate root: {relative}")
                resolved_target = (candidate.parent / os.readlink(candidate)).resolve(
                    strict=False
                )
                if any(
                    resolved_target == excluded_root
                    or excluded_root in resolved_target.parents
                    for excluded_root in excluded_roots
                ):
                    raise SecretPolicyError(
                        f"symlink exposes excluded provider context: {relative}"
                    )
                size = len(os.readlink(candidate).encode("utf-8", "surrogateescape"))
            else:
                size = candidate.lstat().st_size
            entries.append(
                {
                    "path": relative,
                    "fileType": kind,
                    "size": size,
                    "sha256": sha256_path(candidate),
                }
            )
    entries.sort(key=lambda entry: str(entry["path"]))
    manifest: dict[str, object] = {
        "schemaVersion": 1,
        "files": entries,
        "fileCount": len(entries),
        "totalBytes": sum(int(entry["size"]) for entry in entries),
    }
    if output_path is not None:
        atomic_write_json(Path(output_path), manifest)
    return manifest


def _looks_binary(data: bytes) -> bool:
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _file_is_binary(path: Path) -> bool:
    """Classify a file without retaining arbitrarily large content in memory."""

    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                if b"\x00" in chunk:
                    return True
                decoder.decode(chunk, final=False)
        decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        return True
    return False


def _is_placeholder(value: str) -> bool:
    cleaned = value.strip().strip("\"'").strip()
    normalized = cleaned.lower()
    if normalized in PLACEHOLDERS:
        return True
    return (
        normalized.startswith("${")
        or normalized.startswith("env:")
        or "example" in normalized
        or "placeholder" in normalized
        or normalized.startswith("your_")
        or set(normalized) <= {"*", "x", "-"} and bool(normalized)
    )


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    probabilities = [
        value.count(character) / len(value) for character in set(value)
    ]
    return -sum(probability * math.log2(probability) for probability in probabilities)


def scan_text(text: str, path: str) -> list[SecretFinding]:
    """Scan text and return metadata-only findings."""

    normalized_path = _normalize_relative_path(path)
    findings: set[SecretFinding] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if "-----BEGIN PRIVATE KEY-----" in line or re.search(
            r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", line
        ):
            findings.add(
                SecretFinding(
                    normalized_path, line_number, "pem-private-key", "critical"
                )
            )
        if "-----BEGIN OPENSSH PRIVATE KEY-----" in line:
            findings.add(
                SecretFinding(
                    normalized_path, line_number, "openssh-private-key", "critical"
                )
            )
        for token_pattern in _TOKEN_PATTERNS:
            if token_pattern.search(line):
                findings.add(
                    SecretFinding(
                        normalized_path, line_number, "api-token-prefix", "high"
                    )
                )
                break
        for assignment in _ASSIGNMENT_RE.finditer(line):
            value = assignment.group("value").strip()
            if len(value) < 8 or _is_placeholder(value):
                continue
            findings.add(
                SecretFinding(
                    normalized_path,
                    line_number,
                    "credential-assignment",
                    "high",
                )
            )
            if len(value) > 32 and _entropy(value) >= 3.5:
                findings.add(
                    SecretFinding(
                        normalized_path,
                        line_number,
                        "credential-high-entropy",
                        "high",
                    )
                )
    return sorted(findings)


def scan_file(
    root: str | os.PathLike[str],
    relative_path: str,
    *,
    max_text_bytes: int = MAX_TEXT_BYTES,
) -> list[SecretFinding]:
    """Secret-scan one regular text file without following symlinks."""

    root_path = Path(root).resolve()
    normalized = _normalize_relative_path(relative_path)
    candidate = _safe_path(root_path, normalized)
    mode = candidate.lstat().st_mode
    if stat.S_ISLNK(mode):
        return []
    if not stat.S_ISREG(mode):
        raise SecretPolicyError(f"not a regular context file: {normalized}")
    size = candidate.lstat().st_size
    if size > max_text_bytes:
        with candidate.open("rb") as handle:
            prefix = handle.read(min(8192, max_text_bytes))
        if not _looks_binary(prefix):
            raise SecretPolicyError(f"unscannable_large_text:{normalized}")
        return []
    data = candidate.read_bytes()
    if _looks_binary(data):
        return []
    return scan_text(data.decode("utf-8"), normalized)


def _parse_expiry(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def load_allow_entries(
    path: str | os.PathLike[str], *, now: datetime | None = None
) -> list[dict[str, object]]:
    """Load valid, unexpired, hash-bound local secret exceptions."""

    allow_path = Path(path)
    try:
        raw = json.loads(allow_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError) as exc:
        raise SecretPolicyError(f"invalid secret allow file: {exc}") from exc
    entries = raw.get("entries") if isinstance(raw, Mapping) else raw
    if not isinstance(entries, list):
        raise SecretPolicyError("secret allow file must contain an entries array")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    valid: list[dict[str, object]] = []
    required = {"path", "detector", "line", "justification", "expiresAt", "sha256"}
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != required:
            raise SecretPolicyError("invalid secret allow entry")
        try:
            normalized_path = _normalize_relative_path(str(entry["path"]))
        except SecretPolicyError:
            raise
        expiry = _parse_expiry(entry["expiresAt"])
        digest = entry["sha256"]
        line_is_valid = (
            isinstance(entry["line"], int)
            and not isinstance(entry["line"], bool)
            and (
                entry["line"] >= 1
                or (
                    entry["line"] == 0
                    and entry["detector"] == "unscannable-large-text"
                )
            )
        )
        if (
            entry["detector"] not in DETECTOR_NAMES
            or not line_is_valid
            or not isinstance(entry["justification"], str)
            or not entry["justification"].strip()
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or expiry is None
        ):
            raise SecretPolicyError("invalid secret allow entry")
        if expiry <= current:
            continue
        valid.append(
            {
                "path": normalized_path,
                "detector": entry["detector"],
                "line": entry["line"],
                "justification": entry["justification"],
                "expiresAt": expiry.isoformat(timespec="seconds").replace(
                    "+00:00", "Z"
                ),
                "sha256": digest,
            }
        )
    return sorted(
        valid,
        key=lambda entry: (
            str(entry["path"]),
            str(entry["detector"]),
            int(entry["line"]),
        ),
    )


def filter_allowed_findings(
    findings: Iterable[SecretFinding],
    allow_entries: Iterable[Mapping[str, object]],
    file_hashes: Mapping[str, str],
) -> list[SecretFinding]:
    """Remove findings covered by exact detector/line/file-hash exceptions."""

    allowed = {
        (
            str(entry.get("path")),
            str(entry.get("detector")),
            int(entry.get("line", -1)),
            str(entry.get("sha256")),
        )
        for entry in allow_entries
    }
    return [
        finding
        for finding in findings
        if (
            finding.path,
            finding.detector,
            finding.line,
            file_hashes.get(finding.path, ""),
        )
        not in allowed
    ]


def scan_context(
    root: str | os.PathLike[str],
    manifest: Mapping[str, object],
    *,
    allow_entries: Iterable[Mapping[str, object]] = (),
    approved_binary_context: Iterable[Mapping[str, object]] = (),
    max_text_bytes: int = MAX_TEXT_BYTES,
) -> list[SecretFinding]:
    """Validate and secret-scan all regular files in a context manifest."""

    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise SecretPolicyError("context manifest has no files array")
    approved_binary = {
        (str(entry.get("path")), str(entry.get("sha256")))
        for entry in approved_binary_context
    }
    allows = tuple(allow_entries)
    allowed_large_text = {
        (str(entry.get("path")), str(entry.get("sha256")))
        for entry in allows
        if entry.get("detector") == "unscannable-large-text"
        and entry.get("line") == 0
    }
    findings: list[SecretFinding] = []
    file_hashes: dict[str, str] = {}
    root_path = Path(root).resolve()
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise SecretPolicyError("invalid context manifest entry")
        relative = _normalize_relative_path(str(entry.get("path", "")))
        expected_hash = str(entry.get("sha256", ""))
        candidate = _safe_path(root_path, relative)
        actual_hash = sha256_path(candidate)
        if actual_hash != expected_hash:
            raise SecretPolicyError(f"context_changed:{relative}")
        file_hashes[relative] = actual_hash
        if entry.get("fileType") == "symlink":
            continue
        if _file_is_binary(candidate):
            if (relative, actual_hash) not in approved_binary:
                raise SecretPolicyError(f"unapproved_binary_context:{relative}")
            continue
        if candidate.lstat().st_size > max_text_bytes:
            if (relative, actual_hash) not in allowed_large_text:
                raise SecretPolicyError(f"unscannable_large_text:{relative}")
            continue
        findings.extend(
            scan_file(root_path, relative, max_text_bytes=max_text_bytes)
        )
    return filter_allowed_findings(findings, allows, file_hashes)


def quarantine_paths(
    root: str | os.PathLike[str],
    paths: Iterable[str],
    quarantine_dir: str | os.PathLike[str],
    *,
    git_modes: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Move trusted paths to owner-only evidence and record restoration data."""

    root_path = Path(root).resolve()
    quarantine_path = Path(quarantine_dir).resolve()
    try:
        quarantine_path.relative_to(root_path)
    except ValueError:
        pass
    else:
        raise SecretPolicyError("quarantine directory must be outside candidate root")
    quarantine_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(quarantine_path, 0o700)
    entries: list[dict[str, object]] = []
    planned: list[tuple[str, Path, str, int, str, str]] = []
    for relative in sorted({_normalize_relative_path(path) for path in paths}):
        source = _safe_path(root_path, relative)
        kind = _file_type(source)
        if kind not in {"regular", "symlink"}:
            raise SecretPolicyError(f"cannot quarantine {kind} path: {relative}")
        planned.append(
            (
                relative,
                source,
                kind,
                stat.S_IMODE(source.lstat().st_mode),
                sha256_path(source),
                (git_modes or {}).get(relative, _git_mode(source)),
            )
        )
    for relative, source, kind, mode, digest, git_mode in planned:
        destination = quarantine_path / "objects" / Path(relative)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.replace(source, destination)
        entries.append(
            {
                "path": relative,
                "gitMode": git_mode,
                "fileType": kind,
                "sha256": digest,
                "mode": mode,
                "quarantinePath": f"objects/{relative}",
            }
        )
    manifest: dict[str, object] = {"schemaVersion": 1, "entries": entries}
    atomic_write_json(quarantine_path / MANIFEST_NAME, manifest)
    return manifest


def restore_quarantine(
    root: str | os.PathLike[str],
    quarantine_dir: str | os.PathLike[str],
    manifest: Mapping[str, object] | None = None,
    *,
    conflict_dir: str | os.PathLike[str] | None = None,
) -> dict[str, object]:
    """Restore quarantined objects, retaining provider conflicts as evidence."""

    root_path = Path(root).resolve()
    quarantine_path = Path(quarantine_dir).resolve()
    if manifest is None:
        try:
            manifest = json.loads(
                (quarantine_path / MANIFEST_NAME).read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise SecretPolicyError(f"invalid quarantine manifest: {exc}") from exc
    raw_entries = manifest.get("entries") if isinstance(manifest, Mapping) else None
    if not isinstance(raw_entries, list):
        raise SecretPolicyError("quarantine manifest has no entries array")
    conflict_root = (
        Path(conflict_dir).resolve()
        if conflict_dir is not None
        else quarantine_path / "provider-conflicts"
    )
    restored: list[str] = []
    conflicts: list[str] = []
    for entry in raw_entries:
        if not isinstance(entry, Mapping):
            raise SecretPolicyError("invalid quarantine manifest entry")
        relative = _normalize_relative_path(str(entry.get("path", "")))
        quarantined_relative = str(entry.get("quarantinePath", ""))
        expected_quarantined = f"objects/{relative}"
        if quarantined_relative != expected_quarantined:
            raise SecretPolicyError("quarantine manifest path mismatch")
        trusted = _safe_path(quarantine_path, quarantined_relative)
        if sha256_path(trusted) != entry.get("sha256"):
            raise SecretPolicyError(f"quarantined object changed: {relative}")
        destination = _safe_path(root_path, relative, allow_missing=True)
        if destination.exists() or destination.is_symlink():
            conflict = conflict_root / Path(relative)
            conflict.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            conflict_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.replace(destination, conflict)
            conflicts.append(relative)
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.replace(trusted, destination)
        if not destination.is_symlink():
            os.chmod(destination, int(entry.get("mode", 0o600)))
        if sha256_path(destination) != entry.get("sha256"):
            raise SecretPolicyError(f"restored object hash mismatch: {relative}")
        restored.append(relative)
    return {
        "restored": restored,
        "conflicts": conflicts,
        "scopeViolation": bool(conflicts),
    }
__all__ = [
    "DETECTOR_NAMES",
    "MANIFEST_NAME",
    "MAX_TEXT_BYTES",
    "SecretFinding",
    "SecretPolicyError",
    "build_context_manifest",
    "denied_paths",
    "filter_allowed_findings",
    "load_allow_entries",
    "match_deny_path",
    "quarantine_paths",
    "restore_quarantine",
    "scan_context",
    "scan_file",
    "scan_text",
    "sha256_path",
]
