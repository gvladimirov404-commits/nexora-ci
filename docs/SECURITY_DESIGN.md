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
   submodules/libraries, and dependency manifests. Submodules are not
   initialized or executed.
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
  or attestation permission. A `ref-guard` job fails closed unless the run is in
  the canonical `nexora-ci` repository on `refs/heads/main`, and the verification
  job cannot run unless the guard succeeds.
- It validates an exact 40-character candidate SHA, passes it to checkout only
  through the validated step output, checks out the trusted repository and the
  candidate separately, and confirms both `HEAD` values (`GITHUB_SHA` for the
  trusted checkout and the requested SHA for the candidate).
- Both checkouts disable credential persistence and submodules. The candidate
  clean-tree check ignores uninitialized submodule state because submodules are
  never initialized or executed.
- It verifies the pinned trusted manifest SHA-256 and runs the approved trusted
  suite under `python3 -I`, which ignores `PYTHONPATH` and user site-packages.
- The candidate checkout is never built, imported, or tested. Candidate
  `foundry.toml`, FFI settings, remappings, libraries, tests, scripts,
  submodules, and dependencies cannot influence the result.
- `trusted-tests/tests/test_workflow_contract.py` is a text-level regression
  guard for the committed workflow configuration. It does not prove
  GitHub-hosted execution or branch protection.
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
- Treat the pinned manifest digest, not the suite path, as suite identity. A
  symlinked `trusted-tests` root is resolved before scanning; internal symlinks,
  path escapes, bytecode caches, and unlisted files are rejected.
- Pin the candidate repository to an immutable repository ID, not only an
  owner/name string, before treating the recorded SHA as durable evidence. The
  candidate is never executed, so a rename does not change the test result, but
  it changes what the SHA refers to.
- Revalidate the pinned `actions/checkout` SHA when upgrading. During the
  2026-10-28 local audit it matched the commit referenced by the upstream `v6`
  and `v6.1.0` tags via `git ls-remote`; tag and release provenance were not
  independently attested.
- Test missing/corrupt artifacts, changed result JSON, wrong
  repo/SHA/workflow/policy/test-manifest hash, failed tests, incomplete test
  list, missing `gh`, timeouts, invalid signatures, and self-hosted runner
  attestations. All must fail closed.

## Current state

The repository contains a local, uncommitted minimal prototype. The trusted
manifest digest is pinned in the workflow. No GitHub workflow has been run as
part of this work, no candidate code is executed, no dependency is installed,
and no attestation is generated or claimed.
