# NEXORA-CI — Local Audit Handoff

Date: 2026-10-28
Repository: gvladimirov404-commits/nexora-ci
Path: ~/nexora-ci
Branch: main
Starting HEAD reported by audit:
61acea9fc88d1952f5386a5df2925c620a2b6cbb

## Current state

Qoder completed a local audit and hardening pass.
The work remains uncommitted and must not be pushed
without explicit approval.

Reported final checks:
- 86 trusted tests passed with:
  python3 -I trusted-tests/run_trusted_tests.py
- Manifest SHA-256 check passed.
- Manifest contains 14 files.
- Approved test set grew from 71 to 86; no tests dropped.
- YAML parsed successfully with PyYAML.
- git diff --check passed.
- No __pycache__ or .pyc remained under trusted-tests.
- The policy_id remains nexora-ci-trusted-prototype-v2.
- No GitHub-hosted workflow run or attestation was produced.

Manifest SHA-256 reported by Qoder:
610c10e32c756b890917ab76dc6ee50781ab73e0d384a260f1a6d76d5df65521

## Main changes

- .github/workflows/verify-nexora.yml
  Adds a canonical repository/main-ref guard, trusted
  checkout HEAD verification, disabled credential
  persistence and submodules, candidate SHA validation,
  ignored uninitialized submodule state, and isolated
  Python execution.
- trusted-tests/verifier/attestation_policy.py
  Rejects invalid repository path components such as
  "." and "..".
- trusted-tests/tests/test_attestation_policy.py
  Adds invalid repository cases and a guard against
  silently skipping refusal tests.
- trusted-tests/tests/test_trust_boundary.py
  Adds manifest, path, bytecode-cache and test-set-drift
  regression tests.
- trusted-tests/tests/test_workflow_contract.py
  Adds text-level workflow regression checks.
- trusted-tests/trusted-tests.policy.json
  Approved test names increased from 71 to 86.
- trusted-tests/trusted-tests.manifest.json
  Regenerated for 14 trusted files.
- README_PREP.md, docs/SECURITY_DESIGN.md,
  trusted-tests/README.md
  Updated to document controls and limitations.

## Important limitations

- No cryptographic attestation is generated yet.
- No GitHub-hosted workflow execution was validated.
- Workflow contract tests are text-level checks, not proof
  of GitHub execution semantics.
- Branch protection and required reviews are not enabled
  by this audit.
- The candidate is identified by owner/repository name,
  not an immutable repository ID.
- Runner image and Python patch versions may drift.
- The policy_id was deliberately not bumped to v3.
- Existing ignored directories outside the trusted suite
  were not modified.

## Safety rules for continuing

- Do not commit or push without explicit approval.
- Do not trigger GitHub Actions without explicit approval.
- Do not change the separate ~/nexora application.
- Do not regenerate the manifest or change policy IDs
  unless a specific approved change requires it.
- Preserve the current working tree and inspect diffs
  before any further edits.

## Suggested next step

First verify git status, HEAD, the workflow-pinned manifest
digest, and the local test suite. Do not assume the report
is proof of hosted CI behavior. After the local state is
confirmed, decide separately whether to configure branch
protection and perform a controlled GitHub-hosted run.
