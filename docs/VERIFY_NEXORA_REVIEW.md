# Review of `.github/workflows/verify-nexora.yml`

## Scope

Reviewed the pre-change workflow at
`audit-backup-20261025T124859Z/.github/workflows/verify-nexora.yml.bak`
(repository copy from 2026-10-25). The review covers candidate-controlled
configuration, FFI, dependencies, test provenance, and attestation generation.

## Findings

| ID | Finding | Severity | Resolution |
| --- | --- | --- | --- |
| W1 | `forge build` and `forge test` ran against the candidate checkout with no trusted `foundry.toml` override. The candidate controlled remappings, library paths, test paths, compiler selection, and `ffi`. | High | The prototype no longer runs Forge. Candidate configuration is never applied. |
| W2 | Candidate tests are arbitrary code. If the candidate enabled `ffi = true`, test execution could invoke host commands on the runner. Even with FFI disabled, candidate code and build tooling executed on the runner. | High | No candidate file, test, script, or toolchain is executed. The candidate is checkout-only. |
| W3 | Test provenance was candidate-controlled: the workflow ran the candidate's own `verifier_tests` and Foundry tests. A candidate could weaken or delete tests and still pass. | High | Tests now come only from `trusted-tests/`, are enumerated in the approved policy, and are SHA-256 pinned. |
| W4 | Python dependencies were installed unpinned (`pip install --upgrade pip`, `pytest web3 requests`). The Foundry action was pinned by commit SHA but no toolchain version was selected, and candidate Solidity libraries/remappings were unpinned. | High | The prototype installs nothing and uses only the Python standard library. No Foundry action or candidate dependency is used. |
| W5 | The workflow had no main-only gate. A `workflow_dispatch` run could execute a workflow definition from a non-main branch if that branch contained one. | Medium | The job is gated on `github.ref == 'refs/heads/main'` and checks out the trusted workflow repository at `github.sha`. Protected `main` remains mandatory. |
| W6 | No attestation was generated: there was no `id-token: write`, no `attestations: write`, and no attestation step. This avoided unauthorized signing but meant the run produced no verifiable evidence. | Informational | The prototype explicitly generates no attestation. Issue only after the `gh` schema and signer semantics are confirmed and a separate trusted signing job is reviewed. |
| W7 | The requested commit was validated as 40 lowercase hex characters, but there was no check that the checkout actually matched it. | Low | The prototype runs `git rev-parse HEAD` and requires an exact match with the requested SHA. |

## Controls in the replacement prototype

- Main-only job gate and top-level/job-level `permissions: contents: read`.
- Exact 40-character lowercase SHA validation before checkout.
- Trusted tests and verifier checked out from this repository at `github.sha`.
- Candidate checked out at the exact requested SHA but never executed.
- Candidate working tree must be clean and `HEAD` must equal the requested SHA.
- Trusted manifest SHA-256 is pinned in the workflow and checked with
  `sha256sum --check --strict`.
- The trusted runner verifies every approved file hash, requires a sorted and
  duplicate-free manifest, rejects symlinks, path traversal, unlisted files,
  fake schema versions, missing required files, and duplicate JSON keys.
- The approved test set is fixed by `trusted-tests.policy.json` and compared
  with the discovered unittest IDs before execution.
- No package installation, no Foundry invocation, no FFI, no OIDC, no
  attestation permission, and no secret access.
- No `allow_unconfirmed_schema` use in the workflow.

## Remaining risks

1. The trusted suite tests the trust mechanism. It does **not** execute NEXORA
   Solidity contracts or reproduce the candidate's contract tests.
2. Branch protection for `main`, required reviewers, and workflow approval are
   repository settings, not enforceable by this YAML. Without them, a writer to
   `main` can change the workflow and tests.
3. The pinned `actions/checkout` commit SHA was retained from the prior draft.
   Its upstream tag and release provenance were not independently revalidated
   in this local review.
4. `ubuntu-24.04` and its Python patch version are runner-provided and can
   change. The prototype uses only the standard library, but runtime drift is
   possible.
5. A commit SHA identifies candidate content but is not a cryptographic
   attestation of build reproducibility. This workflow does not build or
   reproduce candidate artifacts.
6. No real GitHub attestation has been produced or verified. See
   `docs/GH_ATTESTATION_SCHEMA.md`.
7. Repository-side compromise of `main` defeats the manifest pin and the tests.
   The pin defends against candidate-repository influence, not against trusted
   branch compromise.
