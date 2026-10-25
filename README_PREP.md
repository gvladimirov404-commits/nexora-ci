# NEXORA CI trust prototype — local preparation only

This is a **non-deployable minimal prototype**, not a completed security system
and not an attestation product. It is intended for `~/nexora-ci` only. It does
not modify `~/nexora`, install dependencies, create commits, push, or run a
GitHub workflow.

## What is included

- `trusted-tests/verifier/attestation_policy.py`: fail-closed validation of
  normalized attestation evidence against an explicit policy. It checks exact
  predicate fields, subject digest, test set, result, certificate presence, and
  timestamp presence. It does not verify signatures.
- `trusted-tests/verifier/gh_attestation_adapter.py`: disabled-by-default
  adapter for an **unconfirmed** `gh attestation verify --format json` shape. It
  rejects duplicate JSON keys and non-standard constants.
- `trusted-tests/tests/test_attestation_policy.py`: reviewed negative and
  positive tests for the policy and adapter. The verifier code and these tests
  are covered by the trusted manifest.
- `trusted-tests/`: independent reviewed tests for the trust mechanism, a
  policy, a canonical SHA-256 manifest, a fail-closed manifest verifier, and a
  runner that executes only approved unittest IDs.
- `.github/workflows/verify-nexora.yml`: minimal main-gated, read-only prototype
  that verifies the pinned trusted manifest and runs trusted tests. It never
  executes candidate files, installs dependencies, runs Forge, requests OIDC, or
  issues an attestation.
- `.github/workflows/nexora-verify-tests.yml.disabled`: disabled attestation
  design draft. Keep it disabled until the schema and signing design are
  reviewed.
- `docs/SECURITY_DESIGN.md`: trust boundaries and activation blockers.
- `docs/VERIFY_NEXORA_REVIEW.md`: review of the pre-change workflow for
  candidate-controlled config, FFI, dependencies, test provenance, and
  attestation generation.
- `docs/GH_ATTESTATION_SCHEMA.md`: explicit record that the GitHub attestation
  schema and signer semantics are unverified.

## Run the local tests

From this directory:

```sh
python3 trusted-tests/run_trusted_tests.py
```

The trusted runner prints the manifest SHA-256, verifies every approved file
hash including the verifier modules and tests, and rejects the suite unless
every expected unittest ID matches. The tests use only the Python standard
library.

## Workflow behavior

The candidate NEXORA commit is checked out at an exact 40-character SHA and its
`HEAD` is confirmed, but no candidate file is executed. Trusted tests and the
verifier come from this repository at `github.sha`. The workflow pins the
manifest digest in YAML and verifies it before running tests.

Running the workflow does **not** create evidence that NEXORA passed its own
tests, does **not** test NEXORA contracts, and does **not** produce an
attestation.

## Blockers before any attestation claim

1. Confirm the real `gh attestation verify` JSON schema, certificate/timestamp
   fields, and signer semantics with a real test attestation.
2. Add a separate trusted signing job with OIDC and attestation permissions,
   after review, while keeping the test job free of those permissions.
3. Approve independent contract tests for NEXORA and pin their manifest digest.
4. Protect `main` and require review for changes to workflows, trusted tests,
   and the pinned digest.
5. Run tampering and failure-path tests on GitHub before integrating anything
   into NEXORA.

Until then, do not claim that NEXORA has a verified or attested test result.
