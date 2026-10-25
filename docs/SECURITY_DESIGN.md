# NEXORA CI trust design — minimal prototype

## Goal

Produce a verifiable statement that a fixed, approved test suite was executed
against an exact NEXORA commit in a controlled GitHub-hosted environment. This
is evidence of the test run, not proof that the contract is correct or that the
test suite is complete.

The current implementation is a **minimal prototype**. It does not generate an
attestation, does not execute candidate code, and does not yet test NEXORA
Solidity contracts.

## Trust boundaries

1. **Untrusted input:** the requested NEXORA commit and all files in that
   checkout, including its workflow files, `foundry.toml`, tests, scripts,
   submodules/libraries, and dependency manifests.
2. **Trusted policy:** workflow code from the protected `main` branch of
   `nexora-ci`, reviewed trusted tests, the canonical test manifest, the Python
   verifier, and the manifest digest pinned in the workflow.
3. **Unprivileged execution:** the prototype job has read-only source access and
   no `id-token: write`, no `attestations: write`, no deployment credentials, and
   no secrets. It checks out the candidate but never executes candidate files.
4. **Future trusted decision/signing:** a separate trusted job must validate the
   exact artifact digest, source repository and commit, policy version, trusted
   test manifest, test set, result schema, and successful exit status before
   issuing an attestation.
5. **Future consumer verification:** `gh attestation verify` must validate the
   signer identity and predicate type; a local policy verifier then checks the
   subject digest and required predicate fields. Any error, missing field,
   mismatch, ambiguity, or tool failure means FAIL.

## Implemented minimal prototype

- `.github/workflows/verify-nexora.yml` is main-gated, read-only, and has no OIDC
  or attestation permission. It validates an exact 40-character commit SHA,
  checks out the trusted repository and the candidate separately, confirms the
  candidate `HEAD`, verifies the pinned manifest SHA-256, and runs the approved
  trusted suite, which includes the verifier policy tests.
- The candidate checkout is never built, imported, or tested. Candidate
  `foundry.toml`, FFI settings, remappings, libraries, tests, scripts, and
  dependencies cannot influence the result.
- `trusted-tests/verify_manifest.py` enforces a sorted, duplicate-free manifest
  of every trusted regular file; rejects symlinks, path traversal, unlisted
  files, missing required files, invalid JSON, duplicate JSON keys, and hash
  mismatches; and validates the policy ID and expected unittest IDs.
- `trusted-tests/run_trusted_tests.py` verifies the suite and requires the
  discovered unittest IDs to match the approved policy exactly before running.
- `trusted-tests/verifier/attestation_policy.py` and its adapter reject missing,
  malformed, extra, mismatched, ambiguously typed, or non-`PASS` evidence.
  Strict JSON parsing rejects duplicate keys and non-standard constants. The
  unconfirmed `gh` adapter stays disabled unless a local synthetic test passes
  exactly `allow_unconfirmed_schema=True`. The verifier code and its tests are
  covered by the trusted manifest.
- No package installation is performed. The verifier and tests use only the
  Python standard library.
- See `docs/VERIFY_NEXORA_REVIEW.md` for the pre-change workflow findings and
  `docs/GH_ATTESTATION_SCHEMA.md` for the schema blocker.

## Must be addressed before any attestation

- Confirm the real `gh attestation verify --format json` schema, certificate
  fields, timestamp fields, and `--signer-workflow` / `--signer-digest`
  semantics with a real test attestation. Do not guess them.
- Keep the test job completely separate from OIDC and attestation permissions.
- The signing job must not treat arbitrary JSON fields from the test job as
  truth. It must verify artifact digest and schema and derive the decision under
  trusted code.
- Approve and copy independent trusted tests for the NEXORA contracts. The
  current trusted suite tests the trust mechanism only.
- If Foundry is introduced later, pin the toolchain and compiler, verify release
  provenance, apply a trusted `foundry.toml`, set `FOUNDRY_FFI=false`, and pin
  all compiler/library dependencies. The current workflow runs no Foundry step.
- Protect `main`, require review for workflow/test changes, and ensure only
  workflow definitions from the protected branch can run. The YAML gate alone
  is not a substitute for repository settings.
- Test missing/corrupt artifacts, changed result JSON, wrong
  repo/SHA/workflow/policy/test-manifest hash, failed tests, incomplete test
  list, missing `gh`, timeouts, invalid signatures, and self-hosted runner
  attestations. All must fail closed.

## Current state

The repository contains a local, uncommitted minimal prototype. The trusted
manifest digest is pinned in the workflow. No GitHub workflow has been run as
part of this work, no candidate code is executed, no dependency is installed,
and no attestation is generated or claimed.
