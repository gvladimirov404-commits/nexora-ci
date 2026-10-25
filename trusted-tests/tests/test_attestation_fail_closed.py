"""Independent trusted-suite tests for the fail-closed attestation contract."""
import unittest

from verifier.attestation_policy import (
    AttestationPolicy,
    NormalizedAttestation,
    PolicyError,
    validate_attestation,
)
from verifier.gh_attestation_adapter import SCHEMA_CONFIRMED, parse_gh_attestation_json

REPOSITORY = "owner/trusted-repo"
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
POLICY_ID = "trusted-fail-closed-v1"
PREDICATE_TYPE = "https://nexora.invalid/attestations/trusted-test/v1"
MANIFEST_SHA = "ab" * 32
SUBJECT_SHA = "cd" * 32
TEST_NAMES = (
    "tests.test_contract.ContractTests.test_deposit",
    "tests.test_contract.ContractTests.test_release",
)


def approved_policy(**overrides):
    values = {
        "repository": REPOSITORY,
        "source_sha": SOURCE_SHA,
        "policy_id": POLICY_ID,
        "predicate_type": PREDICATE_TYPE,
        "test_manifest_sha256": MANIFEST_SHA,
        "expected_test_names": TEST_NAMES,
    }
    values.update(overrides)
    return AttestationPolicy(**values)


def predicate(**overrides):
    values = {
        "repository": REPOSITORY,
        "source_sha": SOURCE_SHA,
        "policy_id": POLICY_ID,
        "test_manifest_sha256": MANIFEST_SHA,
        "test_names": list(TEST_NAMES),
        "result": "PASS",
    }
    values.update(overrides)
    return values


def evidence(**overrides):
    values = {
        "subject_sha256": SUBJECT_SHA,
        "predicate_type": PREDICATE_TYPE,
        "predicate": predicate(),
        "certificate": {"synthetic": True},
        "verified_timestamps": ({"synthetic": True},),
    }
    values.update(overrides)
    return NormalizedAttestation(**values)


class TrustedFailClosedTests(unittest.TestCase):
    def test_exact_evidence_allows_reordered_approved_names(self):
        result = validate_attestation(
            evidence(predicate=predicate(test_names=list(reversed(TEST_NAMES)))),
            policy=approved_policy(),
            subject_sha256=SUBJECT_SHA,
        )
        self.assertEqual(result["result"], "PASS")

    def test_predicate_schema_drift_fails_closed(self):
        cases = (
            predicate(unexpected="value"),
            {key: value for key, value in predicate().items() if key != "result"},
        )
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaisesRegex(
                PolicyError, "predicate fields do not match"
            ):
                validate_attestation(
                    evidence(predicate=candidate),
                    policy=approved_policy(),
                    subject_sha256=SUBJECT_SHA,
                )

    def test_unsafe_test_names_fail_closed(self):
        for name in ("tests..test", "tests/test", "tests test", "tests/test.py"):
            with self.subTest(name=name), self.assertRaises(PolicyError):
                validate_attestation(
                    evidence(predicate=predicate(test_names=[name, TEST_NAMES[0]])),
                    policy=approved_policy(),
                    subject_sha256=SUBJECT_SHA,
                )

    def test_non_https_predicate_type_fails_closed(self):
        for predicate_type in ("http://nexora.invalid/type", "https://", "file:///tmp/x"):
            with self.subTest(predicate_type=predicate_type), self.assertRaises(
                PolicyError
            ):
                approved_policy(predicate_type=predicate_type)

    def test_non_tuple_timestamps_fail_closed(self):
        with self.assertRaisesRegex(PolicyError, "timestamp evidence"):
            validate_attestation(
                evidence(verified_timestamps=[{"synthetic": True}]),
                policy=approved_policy(),
                subject_sha256=SUBJECT_SHA,
            )

    @unittest.skipIf(SCHEMA_CONFIRMED, "schema is marked confirmed")
    def test_unconfirmed_override_must_be_exactly_true(self):
        for value in (1, "true", [True]):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_gh_attestation_json([], allow_unconfirmed_schema=value)

    @unittest.skipIf(SCHEMA_CONFIRMED, "schema is marked confirmed")
    def test_non_array_document_fails_closed(self):
        for document in (None, {}, "[]"):
            with self.subTest(document=document), self.assertRaisesRegex(
                PolicyError, "JSON array"
            ):
                parse_gh_attestation_json(
                    document, allow_unconfirmed_schema=True
                )


if __name__ == "__main__":
    unittest.main()
