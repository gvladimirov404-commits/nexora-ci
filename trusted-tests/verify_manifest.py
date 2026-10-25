"""Fail-closed integrity checks for the reviewed trusted-test bundle.

The manifest is a canonical, sorted list of every regular file that the runner
may import or read. Any parse error, duplicate key, unexpected file, symlink,
path escape, missing required file, or hash mismatch is a hard failure.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping

MANIFEST_NAME = "trusted-tests.manifest.json"
POLICY_NAME = "trusted-tests.policy.json"
SCHEMA_VERSION = 1
REQUIRED_FILES = (
    "verify_manifest.py",
    "run_trusted_tests.py",
    POLICY_NAME,
    "tests/test_attestation_policy.py",
    "verifier/__init__.py",
    "verifier/attestation_policy.py",
    "verifier/gh_attestation_adapter.py",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TEST_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")
_MANIFEST_KEYS = frozenset({"schema_version", "policy_id", "files"})
_FILE_KEYS = frozenset({"path", "sha256"})
_POLICY_KEYS = frozenset({"schema_version", "policy_id", "expected_test_names"})


class ManifestError(ValueError):
    """Raised when the trusted suite cannot be proven to match its policy."""


class _DuplicateJsonKey(ValueError):
    pass


class _InvalidJsonConstant(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedSuite:
    root: Path
    policy_id: str
    expected_test_names: tuple[str, ...]
    manifest_sha256: str
    files: Mapping[str, str]


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise _InvalidJsonConstant(f"non-standard JSON constant: {value}")


def _load_json(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_pairs_hook,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, _DuplicateJsonKey, _InvalidJsonConstant) as exc:
        raise ManifestError(f"cannot read trusted {label}: {exc}") from exc


def _read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ManifestError(f"cannot read trusted {label}: {exc}") from exc


def _require_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{where} must be a JSON object")
    return value


def _require_exact_keys(value: Mapping[str, Any], keys: frozenset[str], where: str) -> None:
    if set(value) != keys:
        raise ManifestError(f"{where} has unexpected or missing fields")


def _require_schema_version(value: Any, where: str) -> None:
    if type(value) is not int or value != SCHEMA_VERSION:
        raise ManifestError(f"{where}.schema_version must be {SCHEMA_VERSION}")


def _require_policy_id(value: Any, where: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(character.isspace() for character in value)
    ):
        raise ManifestError(f"{where}.policy_id must be a non-empty string without whitespace")
    return value


def _validate_relative_path(raw: Any) -> PurePosixPath:
    if not isinstance(raw, str) or not raw:
        raise ManifestError("manifest path must stay inside the trusted suite")
    if "\\" in raw or "\x00" in raw or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in raw
    ):
        raise ManifestError(f"manifest path must stay inside the trusted suite: {raw!r}")
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or raw != path.as_posix()
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ManifestError(f"manifest path must stay inside the trusted suite: {raw!r}")
    if raw == MANIFEST_NAME or "__pycache__" in path.parts:
        raise ManifestError(f"manifest path is not an approved mutable path: {raw!r}")
    return path


def _validate_test_name(raw: Any) -> str:
    if not isinstance(raw, str) or not _TEST_NAME_RE.fullmatch(raw):
        raise ManifestError(f"invalid expected test name: {raw!r}")
    return raw


def _load_policy(root: Path) -> tuple[str, tuple[str, ...]]:
    document = _load_json(_read_bytes(root / POLICY_NAME, "policy"), "policy")
    payload = _require_mapping(document, "policy")
    _require_exact_keys(payload, _POLICY_KEYS, "policy")
    _require_schema_version(payload.get("schema_version"), "policy")
    policy_id = _require_policy_id(payload.get("policy_id"), "policy")

    raw_names = payload.get("expected_test_names")
    if not isinstance(raw_names, list) or not raw_names:
        raise ManifestError("policy.expected_test_names must be a non-empty JSON array")
    names = tuple(_validate_test_name(name) for name in raw_names)
    if len(set(names)) != len(names):
        raise ManifestError("policy.expected_test_names contains duplicates")
    return policy_id, names


def _load_manifest(root: Path) -> tuple[str, tuple[tuple[PurePosixPath, str], ...], str]:
    raw_bytes = _read_bytes(root / MANIFEST_NAME, "manifest")
    document = _load_json(raw_bytes, "manifest")
    payload = _require_mapping(document, "manifest")
    _require_exact_keys(payload, _MANIFEST_KEYS, "manifest")
    _require_schema_version(payload.get("schema_version"), "manifest")
    policy_id = _require_policy_id(payload.get("policy_id"), "manifest")

    raw_files = payload.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise ManifestError("manifest.files must be a non-empty JSON array")

    entries: list[tuple[PurePosixPath, str]] = []
    for index, raw_entry in enumerate(raw_files):
        entry = _require_mapping(raw_entry, f"manifest.files[{index}]")
        _require_exact_keys(entry, _FILE_KEYS, f"manifest.files[{index}]")
        path = _validate_relative_path(entry.get("path"))
        digest = entry.get("sha256")
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise ManifestError(f"manifest.files[{index}].sha256 must be 64 lowercase hex characters")
        entries.append((path, digest))

    path_strings = [path.as_posix() for path, _ in entries]
    if len(set(path_strings)) != len(path_strings):
        raise ManifestError("duplicate manifest path")
    if path_strings != sorted(path_strings):
        raise ManifestError("manifest paths must be sorted")

    present = set(path_strings)
    missing_required = sorted(set(REQUIRED_FILES) - present)
    if missing_required:
        raise ManifestError(f"missing required files: {missing_required}")

    return policy_id, tuple(entries), hashlib.sha256(raw_bytes).hexdigest()


def _assert_no_symlink_components(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ManifestError(f"symlink path component in trusted file: {relative.as_posix()}")
    return current


def _verify_files(root: Path, entries: tuple[tuple[PurePosixPath, str], ...]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative, expected_digest in entries:
        path = _assert_no_symlink_components(root, relative)
        if not path.exists():
            raise ManifestError(f"missing trusted file: {relative.as_posix()}")
        try:
            mode = path.stat(follow_symlinks=False).st_mode
        except OSError as exc:
            raise ManifestError(f"cannot stat trusted file: {relative.as_posix()}: {exc}") from exc
        if not stat.S_ISREG(mode):
            raise ManifestError(f"trusted file is not a regular file: {relative.as_posix()}")
        data = _read_bytes(path, f"file {relative.as_posix()}")
        actual_digest = hashlib.sha256(data).hexdigest()
        if actual_digest != expected_digest:
            raise ManifestError(f"hash mismatch for trusted file: {relative.as_posix()}")
        hashes[relative.as_posix()] = actual_digest
    return hashes


def _scan_unapproved(root: Path, approved: frozenset[str]) -> None:
    unapproved: list[str] = []

    def walk(directory: Path, prefix: str) -> None:
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as exc:
            raise ManifestError(f"cannot scan trusted suite: {exc}") from exc
        for entry in entries:
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            if entry.is_symlink():
                raise ManifestError(f"symlink in trusted suite: {relative}")
            if entry.is_dir(follow_symlinks=False):
                if entry.name == "__pycache__":
                    continue
                walk(Path(entry.path), relative)
            elif entry.is_file(follow_symlinks=False):
                if relative == MANIFEST_NAME:
                    continue
                if relative not in approved:
                    unapproved.append(relative)
            else:
                raise ManifestError(f"unsupported file type in trusted suite: {relative}")

    walk(root, "")
    if unapproved:
        raise ManifestError(f"unapproved trusted-suite file(s): {sorted(unapproved)}")


def verify_trusted_suite(root: str | Path) -> VerifiedSuite:
    """Return verified metadata or raise ManifestError. Never partially trust."""
    try:
        root_path = Path(root).resolve(strict=True)
    except OSError as exc:
        raise ManifestError(f"cannot resolve trusted suite root: {exc}") from exc
    if not root_path.is_dir():
        raise ManifestError("trusted suite root must be a directory")

    manifest_policy_id, entries, manifest_sha256 = _load_manifest(root_path)
    hashes = _verify_files(root_path, entries)

    policy_id, expected_test_names = _load_policy(root_path)
    if manifest_policy_id != policy_id:
        raise ManifestError("trusted manifest and policy IDs do not match")

    _scan_unapproved(root_path, frozenset(hashes))
    return VerifiedSuite(
        root=root_path,
        policy_id=policy_id,
        expected_test_names=expected_test_names,
        manifest_sha256=manifest_sha256,
        files=MappingProxyType(hashes),
    )
