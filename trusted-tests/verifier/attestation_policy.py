"""Fail-closed policy validation for normalized attestation evidence.

This module does not verify signatures, certificates, or signer identity. Run an
approved verification tool first, normalize its output with a reviewed adapter,
then validate the normalized evidence here. Any error means FAIL.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_TEST_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
_PASS_RESULT = "PASS"
_PREDICATE_KEYS = frozenset(
    {
        "repository",
        "source_sha",
        "policy_id",
        "test_manifest_sha256",
        "test_names",
        "result",
    }
)


class PolicyError(ValueError):
    """Raised when verification evidence does not satisfy the local policy."""


@dataclass(frozen=True)
class AttestationPolicy:
    repository: str
    source_sha: str
    policy_id: str
    predicate_type: str
    test_manifest_sha256: str
    expected_test_names: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not _REPOSITORY_RE.fullmatch(self.repository):
            raise PolicyError("repository must be OWNER/REPO")
        if not isinstance(self.source_sha, str) or not _GIT_SHA_RE.fullmatch(self.source_sha):
            raise PolicyError("source_sha must be a full lowercase 40-character Git SHA")
        if (
            not isinstance(self.policy_id, str)
            or not self.policy_id
            or any(character.isspace() for character in self.policy_id)
        ):
            raise PolicyError("policy_id must be a non-empty string without whitespace")
        if (
            not isinstance(self.predicate_type, str)
            or any(character.isspace() for character in self.predicate_type)
        ):
            raise PolicyError("predicate_type must be an HTTPS URI")
        try:
            parsed_type = urlsplit(self.predicate_type)
        except ValueError as exc:
            raise PolicyError("predicate_type must be an HTTPS URI") from exc
        if parsed_type.scheme != "https" or not parsed_type.netloc:
            raise PolicyError("predicate_type must be an HTTPS URI")
        if not isinstance(self.test_manifest_sha256, str) or not _SHA256_RE.fullmatch(
            self.test_manifest_sha256
        ):
            raise PolicyError("test_manifest_sha256 must be 64 lowercase hex characters")
        if not isinstance(self.expected_test_names, tuple) or not self.expected_test_names:
            raise PolicyError("expected_test_names must be a non-empty tuple")
        if any(
            not isinstance(name, str) or not _TEST_NAME_RE.fullmatch(name)
            for name in self.expected_test_names
        ):
            raise PolicyError("expected_test_names must contain valid test names")
        if len(set(self.expected_test_names)) != len(self.expected_test_names):
            raise PolicyError("expected_test_names contains duplicates")


@dataclass(frozen=True)
class NormalizedAttestation:
    """Adapter-defined evidence, not a GitHub attestation JSON schema."""

    subject_sha256: str
    predicate_type: str
    predicate: Any
    certificate: Any
    verified_timestamps: Any


def _require_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be a JSON object")
    return value


def _require_text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{where} must be a non-empty string")
    return value


def _require_equal(value: Any, expected: Any, message: str) -> None:
    if value != expected:
        raise PolicyError(message)


def validate_attestation(
    attestation: NormalizedAttestation,
    *,
    policy: AttestationPolicy,
    subject_sha256: str,
) -> Mapping[str, Any]:
    """Validate normalized evidence against the approved policy.

    This is a policy check, not cryptographic verification. The caller must
    treat every PolicyError as FAIL and must not issue an attestation.
    """
    if not isinstance(attestation, NormalizedAttestation):
        raise PolicyError("attestation must be NormalizedAttestation")
    if not isinstance(subject_sha256, str) or not _SHA256_RE.fullmatch(subject_sha256):
        raise PolicyError("subject_sha256 must be 64 lowercase hex characters")

    attested_subject = _require_text(attestation.subject_sha256, "attestation.subject_sha256")
    if not _SHA256_RE.fullmatch(attested_subject):
        raise PolicyError("attested subject SHA-256 must be 64 lowercase hex characters")
    if attested_subject != subject_sha256:
        raise PolicyError("attested subject SHA-256 mismatch")

    predicate_type = _require_text(attestation.predicate_type, "attestation.predicate_type")
    _require_equal(predicate_type, policy.predicate_type, "predicate type mismatch")

    predicate = _require_mapping(attestation.predicate, "attestation.predicate")
    if set(predicate) != _PREDICATE_KEYS:
        raise PolicyError("predicate fields do not match the approved schema")

    _require_equal(predicate.get("repository"), policy.repository, "predicate repository mismatch")
    _require_equal(predicate.get("source_sha"), policy.source_sha, "predicate source SHA mismatch")
    _require_equal(predicate.get("policy_id"), policy.policy_id, "predicate policy ID mismatch")
    _require_equal(
        predicate.get("test_manifest_sha256"),
        policy.test_manifest_sha256,
        "trusted test manifest hash mismatch",
    )

    test_names = predicate.get("test_names")
    if not isinstance(test_names, list):
        raise PolicyError("predicate.test_names must be a list of non-empty strings")
    for name in test_names:
        if not isinstance(name, str) or not name:
            raise PolicyError("predicate.test_names must be a list of non-empty strings")
        if not _TEST_NAME_RE.fullmatch(name):
            raise PolicyError("predicate.test_names contains an invalid test name")
    if len(test_names) != len(set(test_names)):
        raise PolicyError("predicate.test_names contains duplicates")
    if len(test_names) != len(policy.expected_test_names) or set(test_names) != set(
        policy.expected_test_names
    ):
        raise PolicyError("executed test set does not match the approved test set")

    _require_equal(predicate.get("result"), _PASS_RESULT, "predicate result is not PASS")

    certificate = _require_mapping(attestation.certificate, "attestation.certificate")
    if not certificate:
        raise PolicyError("attestation certificate evidence is empty")

    timestamps = attestation.verified_timestamps
    if not isinstance(timestamps, tuple) or not timestamps:
        raise PolicyError("verified timestamp evidence is missing or empty")
    for index, timestamp in enumerate(timestamps):
        entry = _require_mapping(timestamp, f"verified_timestamps[{index}]")
        if not entry:
            raise PolicyError(f"verified_timestamps[{index}] must not be empty")

    return predicate


def validate_gh_attestation_json(
    document: Any,
    *,
    policy: AttestationPolicy,
    subject_sha256: str,
    allow_unconfirmed_schema: bool = False,
) -> Mapping[str, Any]:
    """Compatibility wrapper around the unconfirmed GitHub CLI adapter.

    The adapter refuses by default until its real output schema is confirmed.
    """
    from .gh_attestation_adapter import parse_gh_attestation_json

    attestation = parse_gh_attestation_json(
        document,
        allow_unconfirmed_schema=allow_unconfirmed_schema,
    )
    return validate_attestation(attestation, policy=policy, subject_sha256=subject_sha256)


def validate_gh_attestation_json_file(
    path: str | Path,
    *,
    policy: AttestationPolicy,
    subject_sha256: str,
    allow_unconfirmed_schema: bool = False,
) -> Mapping[str, Any]:
    from .gh_attestation_adapter import load_gh_attestation_json

    attestation = load_gh_attestation_json(
        path,
        allow_unconfirmed_schema=allow_unconfirmed_schema,
    )
    return validate_attestation(attestation, policy=policy, subject_sha256=subject_sha256)
