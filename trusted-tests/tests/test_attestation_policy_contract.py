import unittest

from verifier.attestation_policy import (
    AttestationPolicy,
    NormalizedAttestation,
    PolicyError,
    validate_attestation,
)
from verifier.gh_attestation_adapter import SCHEMA_CONFIRMED, parse_gh_attestation_json

REPOSITORY = "acme/trusted-target"
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
POLICY_ID = "trusted-contract-suite-v1"
PREDICATE_TYPE = "https://nexora.invalid/attestations/test-result/v1"
MANIFEST_SHA = "0f" * 32
SUBJECT_SHA = "9a" * 32
TEST_NAMES = ("test_deposit_and_release", "test_unauthorized_release_reverts")


def policy(**overrides):
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
        "certificate": {"subjectAlternativeName": "synthetic"},
        "verified_timestamps": ({"kind": "synthetic"},),
    }
    values.update(overrides)
    return NormalizedAttestation(**values)


class AttestationPolicyContractTests(unittest.TestCase):
    def test_exact_evidence_passes(self):
        result = validate_attestation(
            evidence(), policy=policy(), subject_sha256=SUBJECT_SHA
        )
        self.assertEqual(result["result"], "PASS")

    def test_identity_mismatches_fail_closed(self):
        cases = (
            ("subject", evidence(subject_sha256="cd" * 32), policy(), SUBJECT_SHA),
            (
                "repository",
                evidence(predicate=predicate(repository="attacker/repo")),
                policy(),
                SUBJECT_SHA,
            ),
            (
                "source SHA",
                evidence(predicate=predicate(source_sha="2" * 40)),
                policy(),
                SUBJECT_SHA,
            ),
            (
                "policy ID",
                evidence(predicate=predicate(policy_id="other-policy")),
                policy(),
                SUBJECT_SHA,
            ),
            (
                "manifest hash",
                evidence(predicate=predicate(test_manifest_sha256="3" * 64)),
                policy(),
                SUBJECT_SHA,
            ),
            (
                "predicate type",
                evidence(predicate_type="https://attacker.invalid/type"),
                policy(),
                SUBJECT_SHA,
            ),
            (
                "result",
                evidence(predicate=predicate(result="FAIL")),
                policy(),
                SUBJECT_SHA,
            ),
            ("certificate", evidence(certificate=None), policy(), SUBJECT_SHA),
            ("timestamp", evidence(verified_timestamps=()), policy(), SUBJECT_SHA),
            ("expected subject", evidence(), policy(), "4" * 64),
        )
        for label, attestation, approved, expected_subject in cases:
            with self.subTest(label=label), self.assertRaises(PolicyError):
                validate_attestation(
                    attestation,
                    policy=approved,
                    subject_sha256=expected_subject,
                )

    def test_test_set_drift_fails_closed(self):
        cases = (
            [TEST_NAMES[0]],
            [TEST_NAMES[0], TEST_NAMES[1], "test_extra"],
            [TEST_NAMES[0], TEST_NAMES[0], TEST_NAMES[1]],
        )
        for test_names in cases:
            with self.subTest(test_names=test_names), self.assertRaises(PolicyError):
                validate_attestation(
                    evidence(predicate=predicate(test_names=test_names)),
                    policy=policy(),
                    subject_sha256=SUBJECT_SHA,
                )

    @unittest.skipIf(SCHEMA_CONFIRMED, "schema is marked confirmed")
    def test_unconfirmed_gh_schema_is_disabled(self):
        with self.assertRaises(PolicyError):
            parse_gh_attestation_json([])


if __name__ == "__main__":
    unittest.main()
