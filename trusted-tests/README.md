# Trusted tests

This directory contains the independent, reviewed test suite used by the
minimal trusted-CI prototype. It is loaded from the trusted `nexora-ci`
checkout, never from the candidate NEXORA checkout.

## Contents

- `verify_manifest.py` — fail-closed integrity verifier for this directory.
- `trusted-tests.policy.json` — approved policy ID and exact expected unittest IDs.
- `trusted-tests.manifest.json` — canonical, sorted SHA-256 manifest of every
  trusted regular file except the manifest itself. The manifest SHA-256 is
  printed by the runner and must be pinned in the workflow and in any future
  attestation policy.
- `run_trusted_tests.py` — verifies the manifest and test set, then executes
  only the approved tests.
- `tests/` — independent tests for the attestation policy and manifest trust
  boundary, including the reviewed verifier policy and adapter tests. These
  tests do not execute or import candidate code.
- `tests/test_workflow_contract.py` — text-level regression guards for the
  committed workflow: read-only permissions, SHA-pinned checkouts, disabled
  credential persistence and submodules, canonical-main guard, validated
  candidate SHA, isolated Python invocation, and the manifest digest pin. These
  checks do not prove GitHub-hosted execution or branch protection.
- `verifier/` — trusted attestation policy and GitHub adapter code imported by
  the approved tests. Every file is listed in the manifest and verified before
  the tests are imported.
- `foundry.toml` — reserved trusted baseline for a future reviewed Forge run.
  The current workflow does not execute Forge, so this file is not yet applied.

## Run locally

From the repository root:

```sh
python3 -I trusted-tests/run_trusted_tests.py
```

The workflow uses `python3 -I` so `PYTHONPATH` and user site-packages cannot
influence the run; use the same invocation locally.

The runner prints `TRUSTED SUITE VERIFIED` with the manifest digest before
executing any test. Any manifest, policy, path, symlink, file-set, or hash
mismatch is a hard rejection.

## Approval rules

- Review the semantics of every test, not only its hash.
- A hash pins bytes; it does not prove test adequacy or coverage.
- Any change to a listed file requires a new reviewed manifest, a new manifest
  digest, and an update to the digest pinned in the workflow.
- The workflow must run from the protected `main` branch of the canonical
  `nexora-ci` repository with read-only permissions, no OIDC token, and no
  attestation permission. The `ref-guard` job fails closed on any other
  repository or ref.
- Candidate files, tests, `foundry.toml`, scripts, submodules, and dependencies
  are never the authority for a PASS result. Submodules are not initialized or
  executed, and the workflow ignores uninitialized submodule state when
  confirming the candidate checkout.
- The current suite tests the trust mechanism itself. It does **not** yet test
  NEXORA Solidity contracts; such tests must be independently reviewed and
  copied here before any contract-level claim is made.

## Limits

- `verify_manifest.py` resolves the suite root before scanning. A symlinked
  `trusted-tests` root is followed; internal symlinks, path escapes, bytecode
  caches, and unlisted files are rejected. The pinned manifest digest in the
  workflow is the authority for suite identity.
- The workflow contract tests read the committed YAML as text. They catch
  configuration regressions, not GitHub-hosted behavior, branch protection,
  runner image drift, or attestation.
