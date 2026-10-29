"""Text-level regression guards for the committed trusted workflow.

These checks do not prove GitHub-hosted execution, branch protection, runner
immutability, or attestation. They only catch accidental regressions in the
committed trust-boundary configuration.
"""
import hashlib
import re
import unittest
from pathlib import Path

TRUSTED_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = TRUSTED_ROOT.parent / ".github" / "workflows" / "verify-nexora.yml"
MANIFEST_PATH = TRUSTED_ROOT / "trusted-tests.manifest.json"
CANONICAL_REPOSITORY = "gvladimirov404-commits/nexora-ci"


class WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.code = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )

    def test_declares_only_read_permissions(self):
        self.assertNotRegex(self.code, r"(?m)^\s*[A-Za-z-]+:\s*write\s*$")
        self.assertNotIn("write-all", self.code)
        self.assertGreaterEqual(self.code.count("contents: read"), 2)

    def test_checkout_actions_are_pinned_to_full_commit_shas(self):
        uses = re.findall(r"(?m)^\s*-?\s*uses:\s*(\S+)\s*$", self.code)
        self.assertGreaterEqual(len(uses), 2)
        for entry in uses:
            self.assertRegex(entry, r"^[^@\s]+@[0-9a-f]{40}$")
        checkouts = [entry for entry in uses if entry.startswith("actions/checkout@")]
        self.assertEqual(len(checkouts), 2)

    def test_checkouts_disable_credentials_and_submodules(self):
        self.assertEqual(self.code.count("persist-credentials: false"), 2)
        self.assertEqual(self.code.count("submodules: false"), 2)

    def test_requires_canonical_repository_main(self):
        self.assertIn(CANONICAL_REPOSITORY, self.code)
        self.assertIn("refs/heads/main", self.code)
        self.assertIn("needs: ref-guard", self.code)
        self.assertIn("repository: gvladimirov404-commits/nexora", self.code)

    def test_validates_candidate_sha_before_checkout(self):
        self.assertIn("NEXORA_REF: ${{ inputs.nexora_ref }}", self.code)
        self.assertIn("^[0-9a-f]{40}$", self.code)
        self.assertIn("ref: ${{ steps.validate.outputs.sha }}", self.code)

    def test_candidate_cleanliness_ignores_uninitialized_submodules(self):
        self.assertIn("--ignore-submodules=all", self.code)

    def test_confirms_both_checkout_heads(self):
        self.assertIn('test "$(git rev-parse HEAD)" = "$NEXORA_REF"', self.code)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', self.code)

    def test_runner_uses_isolated_python_and_disables_bytecode(self):
        self.assertIn("python3 -I trusted-tests/run_trusted_tests.py", self.code)
        self.assertIn("PYTHONDONTWRITEBYTECODE", self.code)

    def test_pinned_manifest_digest_matches_committed_manifest(self):
        expected = hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()
        pinned = re.search(
            r'TRUSTED_MANIFEST_SHA256:\s*"([0-9a-f]{64})"', self.code
        )
        self.assertIsNotNone(pinned)
        self.assertEqual(pinned.group(1), expected)
        self.assertIn("sha256sum --check --strict", self.code)


if __name__ == "__main__":
    unittest.main()
