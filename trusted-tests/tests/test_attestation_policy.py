import json
import tempfile
import unittest
from pathlib import Path

from verifier.attestation_policy import (
    AttestationPolicy,
    NormalizedAttestation,
    PolicyError,
    validate_attestation,
    validate_gh_attestation_json,
    validate_gh_attestation_json_file,
)
from verifier.gh_attestation_adapter import (
    SCHEMA_CONFIRMED,
    load_gh_attestation_json,
    parse_gh_attestation_json,
)

REPO = "example-owner/example-repo"  # synthetic fixture, not a real policy
SOURCE_SHA = "1" * 40  # synthetic fixture, not a real commit
POLICY_ID = "nexora-forge-tests-v1"
PREDICATE_TYPE = "https://nexora.example/attestations/test-result/v1"
MANIFEST_SHA = "a" * 64
SUBJECT_SHA = "b" * 64
TEST_NAMES = ("test_release", "test_refund")


def make_policy(**overrides):
    values = {
        "repository": REPO,
        "source_sha": SOURCE_SHA,
        "policy_id": POLICY_ID,
        "predicate_type": PREDICATE_TYPE,
        "test_manifest_sha256": MANIFEST_SHA,
        "expected_test_names": TEST_NAMES,
    }
    values.update(overrides)
    return AttestationPolicy(**values)


def make_predicate(**overrides):
    values = {
        "repository": REPO,
        "source_sha": SOURCE_SHA,
        "policy_id": POLICY_ID,
        "test_manifest_sha256": MANIFEST_SHA,
        "test_names": list(TEST_NAMES),
        "result": "PASS",
    }
    values.update(overrides)
    return values


def make_evidence(**overrides):
    values = {
        "subject_sha256": SUBJECT_SHA,
        "predicate_type": PREDICATE_TYPE,
        "predicate": make_predicate(),
        "certificate": {"subjectAlternativeName": "example"},
        "verified_timestamps": ({"kind": "transparency-log"},),
    }
    values.update(overrides)
    return NormalizedAttestation(**values)


def make_gh_document():
    return [
        {
            "verificationResult": {
                "statement": {
                    "predicateType": PREDICATE_TYPE,
                    "subject": [
                        {"name": "test-results.json", "digest": {"sha256": SUBJECT_SHA}}
                    ],
                    "predicate": make_predicate(),
                },
                "signature": {"certificate": {"subjectAlternativeName": "example"}},
                "verifiedTimestamps": [{"kind": "transparency-log"}],
            }
        }
    ]


class PolicyConstructionTests(unittest.TestCase):
    def test_rejects_invalid_repository(self):
        for repository in (
            "",
            "owner",
            "owner/repo/extra",
            "owner /repo",
            "../..",
            "../repo",
            "owner/..",
            "./repo",
            "owner/.",
        ):
            with self.subTest(repository=repository), self.assertRaisesRegex(
                PolicyError, "repository"
            ):
                make_policy(repository=repository)

    def test_rejects_invalid_source_sha(self):
        for source_sha in ("", "1" * 39, "A" * 40, "g" * 40):
            with self.subTest(source_sha=source_sha), self.assertRaisesRegex(
                PolicyError, "source_sha"
            ):
                make_policy(source_sha=source_sha)

    def test_rejects_invalid_policy_id(self):
        for policy_id in ("", "has space"):
            with self.subTest(policy_id=policy_id), self.assertRaisesRegex(
                PolicyError, "policy_id"
            ):
                make_policy(policy_id=policy_id)

    def test_rejects_non_https_predicate_type(self):
        for predicate_type in (
            "http://example.test/type",
            "https://exa mple.test/type",
            "https://",
            "https://[::1",
            "relative/type",
        ):
            with self.subTest(predicate_type=predicate_type), self.assertRaisesRegex(
                PolicyError, "predicate_type"
            ):
                make_policy(predicate_type=predicate_type)

    def test_rejects_invalid_manifest_hash(self):
        for digest in ("a" * 63, "A" * 64, "g" * 64):
            with self.subTest(digest=digest), self.assertRaisesRegex(
                PolicyError, "test_manifest_sha256"
            ):
                make_policy(test_manifest_sha256=digest)

    def test_rejects_invalid_expected_test_names(self):
        cases = (
            (),
            ["test_release"],
            ("",),
            ("test_release", "test_release"),
            (1,),
            ("has space", "test_refund"),
            ("tests/test_release", "test_refund"),
            ("..", "test_refund"),
            ("test..release", "test_refund"),
        )
        for names in cases:
            with self.subTest(names=names), self.assertRaisesRegex(
                PolicyError, "expected_test_names"
            ):
                make_policy(expected_test_names=names)


class NormalizedAttestationTests(unittest.TestCase):
    def test_accepts_exact_expected_evidence(self):
        predicate = validate_attestation(
            make_evidence(), policy=make_policy(), subject_sha256=SUBJECT_SHA
        )
        self.assertEqual(predicate["result"], "PASS")

    def test_accepts_reordered_test_names(self):
        evidence = make_evidence(
            predicate=make_predicate(test_names=[TEST_NAMES[1], TEST_NAMES[0]])
        )
        validate_attestation(evidence, policy=make_policy(), subject_sha256=SUBJECT_SHA)

    def test_rejects_invalid_expected_subject_digest_argument(self):
        for subject_sha256 in (None, "A" * 64, "b" * 63, "g" * 64):
            with self.subTest(subject_sha256=subject_sha256), self.assertRaisesRegex(
                PolicyError, "subject_sha256"
            ):
                validate_attestation(
                    make_evidence(),
                    policy=make_policy(),
                    subject_sha256=subject_sha256,
                )

    def test_rejects_malformed_attested_subject_digest(self):
        with self.assertRaisesRegex(PolicyError, "attested subject SHA-256 must be 64"):
            validate_attestation(
                make_evidence(subject_sha256="A" * 64),
                policy=make_policy(),
                subject_sha256=SUBJECT_SHA,
            )

    def test_rejects_wrong_subject_digest(self):
        with self.assertRaisesRegex(PolicyError, "attested subject SHA-256 mismatch"):
            validate_attestation(
                make_evidence(subject_sha256="c" * 64),
                policy=make_policy(),
                subject_sha256=SUBJECT_SHA,
            )

    def test_rejects_wrong_predicate_type(self):
        with self.assertRaisesRegex(PolicyError, "predicate type mismatch"):
            validate_attestation(
                make_evidence(predicate_type="https://wrong.example/type"),
                policy=make_policy(),
                subject_sha256=SUBJECT_SHA,
            )

    def test_rejects_non_mapping_predicate(self):
        with self.assertRaisesRegex(PolicyError, "predicate must be a JSON object"):
            validate_attestation(
                make_evidence(predicate="not-a-mapping"),
                policy=make_policy(),
                subject_sha256=SUBJECT_SHA,
            )

    def test_rejects_extra_or_missing_predicate_fields(self):
        cases = (
            make_predicate(extra="unexpected"),
            {key: value for key, value in make_predicate().items() if key != "result"},
        )
        for predicate in cases:
            with self.subTest(predicate=predicate), self.assertRaisesRegex(
                PolicyError, "predicate fields do not match"
            ):
                validate_attestation(
                    make_evidence(predicate=predicate),
                    policy=make_policy(),
                    subject_sha256=SUBJECT_SHA,
                )

    def test_rejects_identity_field_mismatches(self):
        cases = (
            ("repository", "other-owner/other-repo", "repository mismatch"),
            ("source_sha", "2" * 40, "source SHA mismatch"),
            ("policy_id", "other-policy", "policy ID mismatch"),
            ("test_manifest_sha256", "c" * 64, "manifest hash mismatch"),
        )
        for field, value, message in cases:
            with self.subTest(field=field), self.assertRaisesRegex(PolicyError, message):
                validate_attestation(
                    make_evidence(predicate=make_predicate(**{field: value})),
                    policy=make_policy(),
                    subject_sha256=SUBJECT_SHA,
                )

    def test_rejects_invalid_test_sets(self):
        cases = (
            ("not-a-list", "must be a list of non-empty strings"),
            ([1, "test_refund"], "must be a list of non-empty strings"),
            (["", "test_refund"], "must be a list of non-empty strings"),
            (["test release", "test_refund"], "invalid test name"),
            (["test/release", "test_refund"], "invalid test name"),
            (["test..release", "test_refund"], "invalid test name"),
            (["test_release", "test_release"], "contains duplicates"),
            (["test_release"], "does not match the approved test set"),
            (["test_release", "test_refund", "test_extra"], "does not match the approved test set"),
            ([], "does not match the approved test set"),
        )
        for test_names, message in cases:
            with self.subTest(test_names=test_names), self.assertRaisesRegex(
                PolicyError, message
            ):
                validate_attestation(
                    make_evidence(predicate=make_predicate(test_names=test_names)),
                    policy=make_policy(),
                    subject_sha256=SUBJECT_SHA,
                )

    def test_rejects_non_pass_result(self):
        for result in ("FAIL", "PASS ", None, True):
            with self.subTest(result=result), self.assertRaisesRegex(
                PolicyError, "result is not PASS"
            ):
                validate_attestation(
                    make_evidence(predicate=make_predicate(result=result)),
                    policy=make_policy(),
                    subject_sha256=SUBJECT_SHA,
                )

    def test_rejects_missing_or_empty_certificate(self):
        for certificate, message in (
            (None, "certificate"),
            ("pem-string", "certificate"),
            ({}, "certificate evidence is empty"),
        ):
            with self.subTest(certificate=certificate), self.assertRaisesRegex(
                PolicyError, message
            ):
                validate_attestation(
                    make_evidence(certificate=certificate),
                    policy=make_policy(),
                    subject_sha256=SUBJECT_SHA,
                )

    def test_rejects_missing_or_invalid_timestamps(self):
        cases = (
            (None, "timestamp evidence"),
            ([], "timestamp evidence"),
            (({},), "must not be empty"),
            (("not-a-mapping",), "must be a JSON object"),
            ([{"kind": "transparency-log"}], "timestamp evidence"),
        )
        for timestamps, message in cases:
            with self.subTest(timestamps=timestamps), self.assertRaisesRegex(
                PolicyError, message
            ):
                validate_attestation(
                    make_evidence(verified_timestamps=timestamps),
                    policy=make_policy(),
                    subject_sha256=SUBJECT_SHA,
                )

    def test_rejects_wrong_evidence_type(self):
        with self.assertRaisesRegex(PolicyError, "NormalizedAttestation"):
            validate_attestation(
                {"subject_sha256": SUBJECT_SHA},
                policy=make_policy(),
                subject_sha256=SUBJECT_SHA,
            )


class GhAdapterTests(unittest.TestCase):
    def test_schema_confirmation_requires_explicit_reviewed_change(self):
        # Flipping SCHEMA_CONFIRMED disables the refusal tests below via skipIf.
        # Fail loudly instead of silently skipping the negative coverage.
        self.assertIs(SCHEMA_CONFIRMED, False)

    @unittest.skipIf(SCHEMA_CONFIRMED, "schema is marked confirmed")
    def test_adapter_refuses_unconfirmed_schema_by_default(self):
        with self.assertRaisesRegex(PolicyError, "disabled.*schema"):
            parse_gh_attestation_json(make_gh_document())

    @unittest.skipIf(SCHEMA_CONFIRMED, "schema is marked confirmed")
    def test_wrapper_refuses_unconfirmed_schema_by_default(self):
        with self.assertRaisesRegex(PolicyError, "disabled.*schema"):
            validate_gh_attestation_json(
                make_gh_document(), policy=make_policy(), subject_sha256=SUBJECT_SHA
            )

    @unittest.skipIf(SCHEMA_CONFIRMED, "schema is marked confirmed")
    def test_adapter_rejects_truthy_non_boolean_schema_override(self):
        for value in (1, "yes", [True]):
            with self.subTest(value=value), self.assertRaisesRegex(
                PolicyError, "disabled.*schema"
            ):
                parse_gh_attestation_json(
                    make_gh_document(), allow_unconfirmed_schema=value
                )

    def test_adapter_normalizes_synthetic_document_when_explicitly_allowed(self):
        evidence = parse_gh_attestation_json(
            make_gh_document(), allow_unconfirmed_schema=True
        )
        self.assertEqual(evidence.subject_sha256, SUBJECT_SHA)
        self.assertEqual(evidence.predicate_type, PREDICATE_TYPE)
        self.assertEqual(evidence.predicate["result"], "PASS")
        self.assertEqual(evidence.verified_timestamps, ({"kind": "transparency-log"},))

    def test_wrapper_validates_synthetic_document_when_explicitly_allowed(self):
        predicate = validate_gh_attestation_json(
            make_gh_document(),
            policy=make_policy(),
            subject_sha256=SUBJECT_SHA,
            allow_unconfirmed_schema=True,
        )
        self.assertEqual(predicate["result"], "PASS")

    def test_adapter_rejects_ambiguous_result_count(self):
        for document in ([], make_gh_document() * 2):
            with self.subTest(document=document), self.assertRaisesRegex(
                PolicyError, "exactly one verified attestation"
            ):
                parse_gh_attestation_json(document, allow_unconfirmed_schema=True)

    def test_adapter_rejects_ambiguous_subject_count(self):
        document = make_gh_document()
        statement = document[0]["verificationResult"]["statement"]
        statement["subject"] = []
        with self.assertRaisesRegex(PolicyError, "exactly one attested subject"):
            parse_gh_attestation_json(document, allow_unconfirmed_schema=True)

    def test_adapter_rejects_missing_subject_digest(self):
        document = make_gh_document()
        subject = document[0]["verificationResult"]["statement"]["subject"][0]
        subject["digest"] = {}
        with self.assertRaisesRegex(PolicyError, "digest.sha256"):
            parse_gh_attestation_json(document, allow_unconfirmed_schema=True)

    def test_adapter_rejects_missing_certificate(self):
        document = make_gh_document()
        document[0]["verificationResult"]["signature"] = {}
        with self.assertRaisesRegex(PolicyError, "signature.certificate"):
            parse_gh_attestation_json(document, allow_unconfirmed_schema=True)

    def test_adapter_rejects_invalid_timestamp_shape(self):
        document = make_gh_document()
        document[0]["verificationResult"]["verifiedTimestamps"] = {}
        with self.assertRaisesRegex(PolicyError, "verifiedTimestamps must be a JSON array"):
            parse_gh_attestation_json(document, allow_unconfirmed_schema=True)

        document = make_gh_document()
        document[0]["verificationResult"]["verifiedTimestamps"] = ["not-a-mapping"]
        with self.assertRaisesRegex(PolicyError, "verifiedTimestamps\\[0\\]"):
            parse_gh_attestation_json(document, allow_unconfirmed_schema=True)

    def test_file_loader_rejects_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                ("missing.json", None),
                ("malformed.json", b"{"),
                ("not-utf8.json", b"\xff\xfe\xfa"),
            )
            for name, content in cases:
                path = root / name
                if content is not None:
                    path.write_bytes(content)
                with self.subTest(name=name), self.assertRaisesRegex(
                    PolicyError, "cannot read valid attestation JSON"
                ):
                    load_gh_attestation_json(path, allow_unconfirmed_schema=True)

    def test_file_loader_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            documents = (
                '[{"verificationResult": {}, "verificationResult": {}}]',
                '[{"verificationResult": {"statement": {"predicateType": "a", '
                '"predicateType": "b"}}}]',
            )
            for index, text in enumerate(documents):
                path = root / f"duplicate-{index}.json"
                path.write_text(text, encoding="utf-8")
                with self.subTest(index=index), self.assertRaisesRegex(
                    PolicyError, "duplicate JSON key"
                ):
                    load_gh_attestation_json(path, allow_unconfirmed_schema=True)

    def test_file_loader_rejects_nonstandard_json_constants(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nan.json"
            path.write_text('[{"verificationResult": NaN}]', encoding="utf-8")
            with self.assertRaisesRegex(PolicyError, "non-standard JSON constant"):
                load_gh_attestation_json(path, allow_unconfirmed_schema=True)

    def test_file_loader_accepts_synthetic_document_when_explicitly_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "attestation.json"
            path.write_text(json.dumps(make_gh_document()), encoding="utf-8")
            evidence = load_gh_attestation_json(path, allow_unconfirmed_schema=True)
            self.assertEqual(evidence.subject_sha256, SUBJECT_SHA)

    def test_file_wrapper_rejects_non_array_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "attestation.json"
            path.write_text("null", encoding="utf-8")
            with self.assertRaisesRegex(PolicyError, "JSON array"):
                validate_gh_attestation_json_file(
                    path,
                    policy=make_policy(),
                    subject_sha256=SUBJECT_SHA,
                    allow_unconfirmed_schema=True,
                )


if __name__ == "__main__":
    unittest.main()
