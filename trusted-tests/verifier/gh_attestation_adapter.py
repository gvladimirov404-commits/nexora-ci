"""Unconfirmed adapter for `gh attestation verify --format json` output.

BLOCKER: the envelope shape assumed here has not been confirmed against a real
GitHub attestation. The assumed fields are:

    [ { "verificationResult": {
          "statement": { "predicateType": ..., "subject": [...], "predicate": ... },
          "signature": { "certificate": ... },
          "verifiedTimestamps": [ ... ] } } ]

The semantics of `--signer-workflow` / `--signer-digest` and the exact
certificate and timestamp fields are also unconfirmed. This adapter therefore
refuses to run unless a reviewed change sets SCHEMA_CONFIRMED to True. The
`allow_unconfirmed_schema` switch exists only for synthetic local tests and
must never be used for a production decision.

Parsing is strict on purpose: duplicate JSON keys and non-standard constants
(NaN, Infinity) are rejected so that one field cannot have two interpretations.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .attestation_policy import NormalizedAttestation, PolicyError

SCHEMA_CONFIRMED = False

_SCHEMA_BLOCKER = (
    "gh attestation JSON adapter is disabled: the real output schema and "
    "signer-digest semantics have not been confirmed"
)


class _DuplicateJsonKey(ValueError):
    pass


class _InvalidJsonConstant(ValueError):
    pass


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise _InvalidJsonConstant(f"non-standard JSON constant: {value}")


def _require_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be a JSON object")
    return value


def _require_list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise PolicyError(f"{where} must be a JSON array")
    return value


def parse_gh_attestation_json(
    document: Any,
    *,
    allow_unconfirmed_schema: bool = False,
) -> NormalizedAttestation:
    """Normalize assumed `gh` output into internal evidence.

    This function does not verify the attestation. It only converts the assumed
    structure so that policy checks can be applied separately.
    """
    if not SCHEMA_CONFIRMED and allow_unconfirmed_schema is not True:
        raise PolicyError(_SCHEMA_BLOCKER)

    results = _require_list(document, "attestation results")
    if len(results) != 1:
        raise PolicyError("expected exactly one verified attestation result")

    item = _require_mapping(results[0], "result[0]")
    result = _require_mapping(item.get("verificationResult"), "verificationResult")
    statement = _require_mapping(result.get("statement"), "verificationResult.statement")

    predicate_type = statement.get("predicateType")
    if not isinstance(predicate_type, str) or not predicate_type:
        raise PolicyError("statement.predicateType must be a non-empty string")

    subjects = _require_list(statement.get("subject"), "statement.subject")
    if len(subjects) != 1:
        raise PolicyError("expected exactly one attested subject")
    subject = _require_mapping(subjects[0], "statement.subject[0]")
    digest = _require_mapping(subject.get("digest"), "statement.subject[0].digest")
    subject_sha256 = digest.get("sha256")
    if not isinstance(subject_sha256, str) or not subject_sha256:
        raise PolicyError("statement.subject[0].digest.sha256 must be a non-empty string")

    predicate = _require_mapping(statement.get("predicate"), "statement.predicate")

    signature = _require_mapping(result.get("signature"), "verificationResult.signature")
    certificate = _require_mapping(
        signature.get("certificate"), "verificationResult.signature.certificate"
    )

    raw_timestamps = _require_list(
        result.get("verifiedTimestamps"), "verificationResult.verifiedTimestamps"
    )
    timestamps = tuple(
        _require_mapping(timestamp, f"verificationResult.verifiedTimestamps[{index}]")
        for index, timestamp in enumerate(raw_timestamps)
    )

    return NormalizedAttestation(
        subject_sha256=subject_sha256,
        predicate_type=predicate_type,
        predicate=predicate,
        certificate=certificate,
        verified_timestamps=timestamps,
    )


def load_gh_attestation_json(
    path: str | Path,
    *,
    allow_unconfirmed_schema: bool = False,
) -> NormalizedAttestation:
    try:
        document = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=_pairs_hook,
            parse_constant=_reject_constant,
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        _InvalidJsonConstant,
    ) as exc:
        raise PolicyError(f"cannot read valid attestation JSON: {exc}") from exc
    return parse_gh_attestation_json(
        document,
        allow_unconfirmed_schema=allow_unconfirmed_schema,
    )
