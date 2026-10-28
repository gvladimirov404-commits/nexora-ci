import hashlib
import importlib.util
import json
import marshal
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TRUSTED_ROOT = Path(__file__).resolve().parents[1]
if str(TRUSTED_ROOT) not in sys.path:
    sys.path.insert(0, str(TRUSTED_ROOT))

import verify_manifest  # noqa: E402

FIXTURE_POLICY_ID = "fixture-trusted-suite-v1"
FIXTURE_TEST_NAME = "tests.test_ok.OkTests.test_ok"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_timestamp_pyc(source_path, code_source):
    code = compile(code_source, str(source_path), "exec")
    stat_result = source_path.stat()
    header = importlib.util.MAGIC_NUMBER + struct.pack(
        "<III", 0, int(stat_result.st_mtime), stat_result.st_size
    )
    cache_path = Path(importlib.util.cache_from_source(str(source_path)))
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(header + marshal.dumps(code))
    return cache_path


def file_entries(root):
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_dir() or path.name == verify_manifest.MANIFEST_NAME:
            continue
        if "__pycache__" in path.parts:
            continue
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256(path),
            }
        )
    return entries


def write_manifest(root, entries=None):
    payload = {
        "schema_version": 1,
        "policy_id": FIXTURE_POLICY_ID,
        "files": file_entries(root) if entries is None else entries,
    }
    (root / verify_manifest.MANIFEST_NAME).write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )


def write_policy(root, *, policy_id=FIXTURE_POLICY_ID, expected=None):
    payload = {
        "schema_version": 1,
        "policy_id": policy_id,
        "expected_test_names": [FIXTURE_TEST_NAME] if expected is None else expected,
    }
    (root / verify_manifest.POLICY_NAME).write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )


def build_suite(root):
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "__init__.py").write_text("", encoding="utf-8")
    (root / "tests" / "test_ok.py").write_text(
        "import unittest\n\n"
        "class OkTests(unittest.TestCase):\n"
        "    def test_ok(self):\n"
        "        pass\n",
        encoding="utf-8",
    )
    for name in (
        "verify_manifest.py",
        "run_trusted_tests.py",
        "tests/test_attestation_policy.py",
        "verifier/__init__.py",
        "verifier/attestation_policy.py",
        "verifier/gh_attestation_adapter.py",
    ):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# fixture placeholder\n", encoding="utf-8")
    (root / "trusted-foundry.toml").write_text("ffi = false\n", encoding="utf-8")
    write_policy(root)
    write_manifest(root)


class TrustedSuiteManifestTests(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        build_suite(self.root)

    def tearDown(self):
        self._temporary.cleanup()

    def _fresh_suite(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        build_suite(root)
        return root

    def test_accepts_manifest_approved_suite(self):
        verified = verify_manifest.verify_trusted_suite(self.root)
        self.assertEqual(verified.policy_id, FIXTURE_POLICY_ID)
        self.assertEqual(verified.expected_test_names, (FIXTURE_TEST_NAME,))

    def test_rejects_modified_approved_file(self):
        for name in ("tests/test_ok.py", *verify_manifest.REQUIRED_FILES):
            with self.subTest(name=name):
                root = self._fresh_suite()
                (root / name).write_text("# changed\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    verify_manifest.ManifestError, "hash mismatch"
                ):
                    verify_manifest.verify_trusted_suite(root)

    def test_rejects_missing_approved_file(self):
        (self.root / "tests" / "test_ok.py").unlink()
        with self.assertRaisesRegex(verify_manifest.ManifestError, "missing"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_unlisted_python_file(self):
        (self.root / "tests" / "test_extra.py").write_text(
            "import unittest\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(verify_manifest.ManifestError, "unapproved"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_symlinked_approved_file(self):
        target = self.root / "tests" / "test_ok.py"
        target.unlink()
        os.symlink(self.root / "tests" / "__init__.py", target)
        with self.assertRaisesRegex(verify_manifest.ManifestError, "symlink"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_symlinked_directory_component(self):
        moved = self.root / "moved-tests"
        shutil.move(str(self.root / "tests"), str(moved))
        os.symlink(moved, self.root / "tests", target_is_directory=True)
        with self.assertRaisesRegex(verify_manifest.ManifestError, "symlink"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_path_traversal(self):
        entries = file_entries(self.root)
        entries[0]["path"] = "../outside.py"
        write_manifest(self.root, entries)
        with self.assertRaisesRegex(verify_manifest.ManifestError, "inside the trusted suite"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_duplicate_manifest_paths(self):
        entries = file_entries(self.root)
        entries.insert(1, dict(entries[0]))
        write_manifest(self.root, entries)
        with self.assertRaisesRegex(verify_manifest.ManifestError, "duplicate manifest path"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_unsorted_manifest(self):
        entries = list(reversed(file_entries(self.root)))
        write_manifest(self.root, entries)
        with self.assertRaisesRegex(verify_manifest.ManifestError, "sorted"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_missing_required_file(self):
        for name in verify_manifest.REQUIRED_FILES:
            with self.subTest(name=name):
                root = self._fresh_suite()
                (root / name).unlink()
                write_manifest(root)
                with self.assertRaisesRegex(
                    verify_manifest.ManifestError, "missing required files"
                ):
                    verify_manifest.verify_trusted_suite(root)

    def test_rejects_invalid_manifest_json(self):
        (self.root / verify_manifest.MANIFEST_NAME).write_text("{", encoding="utf-8")
        with self.assertRaisesRegex(verify_manifest.ManifestError, "cannot read trusted manifest"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_duplicate_manifest_json_keys(self):
        (self.root / verify_manifest.MANIFEST_NAME).write_text(
            '{"schema_version": 1, "policy_id": "a", "policy_id": "b", "files": []}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(verify_manifest.ManifestError, "duplicate JSON key"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_policy_id_mismatch(self):
        write_policy(self.root, policy_id="other-policy")
        write_manifest(self.root)
        with self.assertRaisesRegex(verify_manifest.ManifestError, "IDs do not match"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_invalid_expected_test_set(self):
        for expected in ([], ["tests.test_ok.OkTests.test_ok", "tests.test_ok.OkTests.test_ok"]):
            with self.subTest(expected=expected):
                write_policy(self.root, expected=expected)
                write_manifest(self.root)
                with self.assertRaises(verify_manifest.ManifestError):
                    verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_invalid_policy_json(self):
        (self.root / verify_manifest.POLICY_NAME).write_text("{", encoding="utf-8")
        write_manifest(self.root)
        with self.assertRaisesRegex(verify_manifest.ManifestError, "cannot read trusted policy"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_absolute_manifest_path(self):
        entries = file_entries(self.root)
        entries[0]["path"] = "/etc/passwd"
        write_manifest(self.root, entries)
        with self.assertRaisesRegex(
            verify_manifest.ManifestError, "inside the trusted suite"
        ):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_backslash_manifest_path(self):
        entries = file_entries(self.root)
        entries[0]["path"] = "tests\\test_ok.py"
        entries.sort(key=lambda entry: entry["path"])
        write_manifest(self.root, entries)
        with self.assertRaisesRegex(
            verify_manifest.ManifestError, "inside the trusted suite"
        ):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_manifest_listing_itself(self):
        entries = file_entries(self.root)
        entries.append({"path": verify_manifest.MANIFEST_NAME, "sha256": "0" * 64})
        entries.sort(key=lambda entry: entry["path"])
        write_manifest(self.root, entries)
        with self.assertRaisesRegex(verify_manifest.ManifestError, "manifest path"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_unlisted_non_python_file(self):
        (self.root / "notes.txt").write_text("unapproved\n", encoding="utf-8")
        with self.assertRaisesRegex(verify_manifest.ManifestError, "unapproved"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_empty_pycache_directory(self):
        (self.root / "tests" / "__pycache__").mkdir()
        with self.assertRaisesRegex(
            verify_manifest.ManifestError, "unapproved __pycache__ directory"
        ):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_poisoned_pycache_directory(self):
        cache = self.root / "tests" / "__pycache__"
        cache.mkdir()
        (cache / "test_ok.cpython-999.pyc").write_bytes(b"poisoned bytecode")
        with self.assertRaisesRegex(
            verify_manifest.ManifestError, "unapproved __pycache__ directory"
        ):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_duplicate_policy_json_keys(self):
        (self.root / verify_manifest.POLICY_NAME).write_text(
            '{"schema_version": 1, "policy_id": "a", "policy_id": "b", '
            '"expected_test_names": []}',
            encoding="utf-8",
        )
        write_manifest(self.root)
        with self.assertRaisesRegex(verify_manifest.ManifestError, "duplicate JSON key"):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_tampered_policy_before_policy_parse(self):
        (self.root / verify_manifest.POLICY_NAME).write_text("{", encoding="utf-8")
        with self.assertRaisesRegex(
            verify_manifest.ManifestError,
            r"hash mismatch for trusted file: trusted-tests\.policy\.json",
        ):
            verify_manifest.verify_trusted_suite(self.root)

    def test_rejects_invalid_policy_test_name(self):
        write_policy(self.root, expected=["not a test"])
        write_manifest(self.root)
        with self.assertRaisesRegex(
            verify_manifest.ManifestError, "invalid expected test name"
        ):
            verify_manifest.verify_trusted_suite(self.root)

    def test_runner_ignores_poisoned_verifier_bytecode(self):
        root = self._fresh_suite()
        shutil.copyfile(
            TRUSTED_ROOT / "run_trusted_tests.py", root / "run_trusted_tests.py"
        )
        shutil.copyfile(
            TRUSTED_ROOT / "verify_manifest.py", root / "verify_manifest.py"
        )
        write_manifest(root)

        poison = (
            "MARKER = 'poison-loaded'\n"
            "from types import SimpleNamespace\n"
            "class ManifestError(ValueError):\n"
            "    pass\n"
            "def verify_trusted_suite(root):\n"
            "    return SimpleNamespace(\n"
            "        policy_id='poisoned-fixture',\n"
            f"        expected_test_names=({FIXTURE_TEST_NAME!r},),\n"
            "        manifest_sha256='0' * 64,\n"
            "        files={},\n"
            "    )\n"
        )
        write_timestamp_pyc(root / "verify_manifest.py", poison)

        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        probe = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                "import sys; sys.path.insert(0, '.'); "
                "import verify_manifest; print(verify_manifest.MARKER)",
            ],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertEqual(probe.stdout.strip(), "poison-loaded")

        run = subprocess.run(
            [sys.executable, str(root / "run_trusted_tests.py")],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(run.returncode, 0, run.stdout)
        self.assertIn("__pycache__", run.stderr)


if __name__ == "__main__":
    unittest.main()
