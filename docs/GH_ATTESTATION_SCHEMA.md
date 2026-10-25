# GitHub attestation schema — unverified

## Status

**Unverified. Do not treat any field layout in this repository as the GitHub
attestation schema.** No real attestation was created, downloaded, or verified
during this work. The exact output of `gh attestation verify --format json`,
the meaning of `--signer-workflow` / `--signer-digest`, certificate fields,
timestamp fields, and failure behavior have not been confirmed.

The adapter at `trusted-tests/verifier/gh_attestation_adapter.py` contains an
internal hypothesis only:

```text
[
  {
    "verificationResult": {
      "statement": {
        "predicateType": ...,
        "subject": [...],
        "predicate": ...
      },
      "signature": {"certificate": ...},
      "verifiedTimestamps": [...]
    }
  }
]
```

This shape must not be used to justify a production decision. The adapter has
`SCHEMA_CONFIRMED = False` and refuses by default. The
`allow_unconfirmed_schema=True` argument exists only for synthetic local tests;
it must be exactly `True` to bypass the block and must never appear in a
workflow or production caller.

## What the local verifier does and does not do

`trusted-tests/verifier/attestation_policy.py` validates **normalized evidence**
supplied by a reviewed adapter:

- exact subject SHA-256 match;
- exact predicate type, repository, source SHA, policy ID, trusted manifest
  SHA-256, test-name set, and `PASS` result;
- non-empty certificate and timestamp evidence supplied by the adapter.

It does **not** verify signatures, certificate chains, OIDC issuer identity,
transparency-log inclusion, or signer workflow. Those checks must be performed
by an independently approved tool whose real behavior and schema have been
confirmed.

## Unknowns that must be confirmed

- Top-level JSON type and whether multiple verification results are possible.
- Exact wrapper key names and nesting for the statement, signature, and
  certificate.
- Subject/digest representation and how the digest is matched to the artifact.
- Certificate representation (raw PEM versus parsed fields), SAN contents, and
  issuer fields.
- `verifiedTimestamps` entry shape and meaning.
- `--signer-workflow` and `--signer-digest` matching semantics.
- Exit codes, stdout/stderr layout, and behavior for zero, one, or many
  attestations.
- Behavior when the attestation is missing, expired, revoked, malformed, or
  signed by an unexpected workflow.

## Confirmation procedure

1. Use a disposable test repository that contains no NEXORA code, keys, or
   secrets.
2. Record the exact `gh` version and the exact command used.
3. Produce a test attestation with a file whose SHA-256 is known.
4. Capture the verification output in JSON and preserve it as a redacted
   fixture after review.
5. Confirm each unknown above against that captured output, not from memory or
   documentation guesses.
6. Update the adapter and its negative tests, then have the change reviewed by
   someone other than the author.
7. Set `SCHEMA_CONFIRMED = True` only as part of that reviewed change.
8. Add a separate signing job with `id-token: write` and
   `attestations: write`; keep the test job without those permissions. Require
   artifact digest, manifest digest, test-set, and result checks before signing.

Until all steps are complete, this repository must not issue an attestation and
must not describe the prototype run as an attested NEXORA test result.
