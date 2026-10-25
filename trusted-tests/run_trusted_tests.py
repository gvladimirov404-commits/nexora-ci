"""Run only manifest-approved tests from the trusted suite."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from verify_manifest import ManifestError, verify_trusted_suite  # noqa: E402


def _iter_tests(suite: unittest.TestSuite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from _iter_tests(test)
        else:
            yield test


def main() -> int:
    try:
        verified = verify_trusted_suite(ROOT)
    except ManifestError as exc:
        print(f"TRUSTED SUITE REJECTED: {exc}", file=sys.stderr)
        return 1

    print(
        "TRUSTED SUITE VERIFIED: "
        f"policy={verified.policy_id} "
        f"manifest_sha256={verified.manifest_sha256} "
        f"files={len(verified.files)}"
    )

    loader = unittest.TestLoader()
    suite = loader.discover(
        str(ROOT / "tests"),
        pattern="test_*.py",
        top_level_dir=str(ROOT),
    )
    discovered = tuple(sorted(test.id() for test in _iter_tests(suite)))
    expected = tuple(sorted(verified.expected_test_names))
    if not discovered or discovered != expected:
        print("TRUSTED SUITE REJECTED: test set does not match policy", file=sys.stderr)
        print(f"expected: {expected}", file=sys.stderr)
        print(f"discovered: {discovered}", file=sys.stderr)
        return 1

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
