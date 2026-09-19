"""Unit tests for Qrypta Validation module."""

import difflib
import tempfile
import unittest
from pathlib import Path
from qrypta.validate.validator import (
    validate_patches,
    CHECK_STATUS_PASSED,
    CHECK_STATUS_FAILED,
    CHECK_STATUS_MANUAL_REVIEW,
)


def _make_diff(orig: str, patched: str) -> str:
    """Helper to generate standard unified diff."""
    return "".join(
        difflib.unified_diff(
            orig.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile="original",
            tofile="patched",
        )
    )


class TestPatchValidator(unittest.TestCase):
    """Test suite for Patch Validator."""

    def test_1_valid_patched_python_file_passes_syntax(self):
        """1. Valid patched Python file passes syntax validation."""
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as sb_dir:
            repo_path = Path(repo_dir)
            sb_path = Path(sb_dir)

            orig_code = "import hashlib\ndef h(d):\n    return hashlib.sha1(d)\n"
            patched_code = "import hashlib\ndef h(d):\n    return hashlib.sha256(d)\n"

            (repo_path / "app.py").write_text(orig_code, encoding="utf-8")
            (sb_path / "app.py").write_text(patched_code, encoding="utf-8")

            diff = _make_diff(orig_code, patched_code)
            patch_result = {
                "sandbox_path": str(sb_path),
                "original_repository_modified": False,
                "files_changed": 1,
                "patches": [
                    {
                        "file": "app.py",
                        "status": "patched",
                        "changes": [{"description": "Replace hashlib.sha1 with hashlib.sha256", "line_before": 3, "line_after": 3}],
                        "diff": diff,
                    }
                ],
            }
            res = validate_patches(repo_path, patch_result)
            self.assertTrue(res["validation_passed"])
            self.assertEqual(res["files_failed"], 0)
            syntax_checks = [c for c in res["checks"] if c["name"] == "syntax_validation:app.py"]
            self.assertEqual(len(syntax_checks), 1)
            self.assertEqual(syntax_checks[0]["status"], CHECK_STATUS_PASSED)

    def test_2_invalid_patched_python_file_fails_syntax(self):
        """2. Invalid patched Python file fails syntax validation."""
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as sb_dir:
            repo_path = Path(repo_dir)
            sb_path = Path(sb_dir)

            orig_code = "import hashlib\ndef h(d):\n    return hashlib.sha1(d)\n"
            # Invalid syntax in patched code
            patched_code = "import hashlib\ndef h(d):\n    return hashlib.sha256(d\n"

            (repo_path / "app.py").write_text(orig_code, encoding="utf-8")
            (sb_path / "app.py").write_text(patched_code, encoding="utf-8")

            diff = _make_diff(orig_code, patched_code)
            patch_result = {
                "sandbox_path": str(sb_path),
                "original_repository_modified": False,
                "files_changed": 1,
                "patches": [
                    {
                        "file": "app.py",
                        "status": "patched",
                        "changes": [{"description": "Replace hashlib.sha1 with hashlib.sha256", "line_before": 3, "line_after": 3}],
                        "diff": diff,
                    }
                ],
            }
            res = validate_patches(repo_path, patch_result)
            self.assertFalse(res["validation_passed"])
            self.assertIn("app.py", [c["name"].split(":")[-1] for c in res["checks"] if c["status"] == CHECK_STATUS_FAILED])
            syntax_checks = [c for c in res["checks"] if c["name"] == "syntax_validation:app.py"]
            self.assertEqual(len(syntax_checks), 1)
            self.assertEqual(syntax_checks[0]["status"], CHECK_STATUS_FAILED)

    def test_3_original_repository_remains_unchanged(self):
        """3. Original repository remains unchanged."""
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as sb_dir:
            repo_path = Path(repo_dir)
            sb_path = Path(sb_dir)

            orig_code = "import hashlib\ndef h(d):\n    return hashlib.sha1(d)\n"
            patched_code = "import hashlib\ndef h(d):\n    return hashlib.sha256(d)\n"

            orig_file = repo_path / "app.py"
            orig_file.write_text(orig_code, encoding="utf-8")
            (sb_path / "app.py").write_text(patched_code, encoding="utf-8")

            diff = _make_diff(orig_code, patched_code)
            patch_result = {
                "sandbox_path": str(sb_path),
                "original_repository_modified": False,
                "files_changed": 1,
                "patches": [
                    {
                        "file": "app.py",
                        "status": "patched",
                        "changes": [{"description": "Replace hashlib.sha1 with hashlib.sha256", "line_before": 3, "line_after": 3}],
                        "diff": diff,
                    }
                ],
            }
            res = validate_patches(repo_path, patch_result)
            self.assertFalse(res["original_repository_modified"])
            self.assertEqual(orig_file.read_text(encoding="utf-8"), orig_code)

    def test_4_missing_sandbox_is_detected(self):
        """4. Missing sandbox is detected."""
        with tempfile.TemporaryDirectory() as repo_dir:
            repo_path = Path(repo_dir)
            patch_result = {
                "sandbox_path": str(repo_path / "non_existent_sandbox_dir"),
                "original_repository_modified": False,
                "files_changed": 1,
                "patches": [],
            }
            res = validate_patches(repo_path, patch_result)
            self.assertFalse(res["validation_passed"])
            sb_check = [c for c in res["checks"] if c["name"] == "sandbox_existence"]
            self.assertEqual(len(sb_check), 1)
            self.assertEqual(sb_check[0]["status"], CHECK_STATUS_FAILED)

    def test_5_patched_file_with_valid_sha256_passes_hash_validation(self):
        """5. Patched file with valid SHA-256 transformation passes static hash validation."""
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as sb_dir:
            repo_path = Path(repo_dir)
            sb_path = Path(sb_dir)

            orig_code = "import hashlib\nh = hashlib.sha1(d)\n"
            patched_code = "import hashlib\nh = hashlib.sha256(d)\n"

            (repo_path / "hash.py").write_text(orig_code, encoding="utf-8")
            (sb_path / "hash.py").write_text(patched_code, encoding="utf-8")

            diff = _make_diff(orig_code, patched_code)
            patch_result = {
                "sandbox_path": str(sb_path),
                "original_repository_modified": False,
                "files_changed": 1,
                "patches": [
                    {
                        "file": "hash.py",
                        "status": "patched",
                        "changes": [{"description": "Replace hashlib.sha1 with hashlib.sha256", "line_before": 2, "line_after": 2}],
                        "diff": diff,
                    }
                ],
            }
            res = validate_patches(repo_path, patch_result)
            self.assertTrue(res["validation_passed"])
            hash_checks = [c for c in res["checks"] if c["name"] == "hash_migration_validation:hash.py"]
            self.assertEqual(len(hash_checks), 1)
            self.assertEqual(hash_checks[0]["status"], CHECK_STATUS_PASSED)

    def test_6_incorrect_hash_transformation_fails_validation(self):
        """6. Incorrect hash transformation fails validation."""
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as sb_dir:
            repo_path = Path(repo_dir)
            sb_path = Path(sb_dir)

            orig_code = "import hashlib\nh = hashlib.sha1(d)\n"
            # Patched code still has sha1 and did not put sha256
            patched_code = "import hashlib\nh = hashlib.sha1(d)\n"

            (repo_path / "hash.py").write_text(orig_code, encoding="utf-8")
            (sb_path / "hash.py").write_text(patched_code, encoding="utf-8")

            diff = "--- original\n+++ patched\n@@ -2,1 +2,1 @@\n-h = hashlib.sha1(d)\n+h = hashlib.sha1(d)\n"
            patch_result = {
                "sandbox_path": str(sb_path),
                "original_repository_modified": False,
                "files_changed": 1,
                "patches": [
                    {
                        "file": "hash.py",
                        "status": "patched",
                        "changes": [{"description": "Replace hashlib.sha1 with hashlib.sha256", "line_before": 2, "line_after": 2}],
                        "diff": diff,
                    }
                ],
            }
            res = validate_patches(repo_path, patch_result)
            self.assertFalse(res["validation_passed"])
            hash_checks = [c for c in res["checks"] if c["name"] == "hash_migration_validation:hash.py"]
            self.assertEqual(len(hash_checks), 1)
            self.assertEqual(hash_checks[0]["status"], CHECK_STATUS_FAILED)

    def test_7_manual_review_reported_correctly(self):
        """7. manual_review is reported correctly and does not fail validation."""
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as sb_dir:
            repo_path = Path(repo_dir)
            sb_path = Path(sb_dir)

            patch_result = {
                "sandbox_path": str(sb_path),
                "original_repository_modified": False,
                "files_changed": 0,
                "patches": [
                    {
                        "file": "sign.py",
                        "status": "manual_review",
                        "changes": [],
                        "diff": "",
                    }
                ],
            }
            res = validate_patches(repo_path, patch_result)
            self.assertTrue(res["validation_passed"])
            self.assertTrue(res["manual_review_required"])
            mr_checks = [c for c in res["checks"] if c["name"] == "manual_review:sign.py"]
            self.assertEqual(len(mr_checks), 1)
            self.assertEqual(mr_checks[0]["status"], CHECK_STATUS_MANUAL_REVIEW)

    def test_8_no_change_reported_correctly(self):
        """8. no_change is reported correctly and does not fail validation."""
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as sb_dir:
            repo_path = Path(repo_dir)
            sb_path = Path(sb_dir)

            patch_result = {
                "sandbox_path": str(sb_path),
                "original_repository_modified": False,
                "files_changed": 0,
                "patches": [
                    {
                        "file": "aes.py",
                        "status": "no_change",
                        "changes": [],
                        "diff": "",
                    }
                ],
            }
            res = validate_patches(repo_path, patch_result)
            self.assertTrue(res["validation_passed"])
            self.assertFalse(res["manual_review_required"])
            nc_checks = [c for c in res["checks"] if c["name"] == "no_change:aes.py"]
            self.assertEqual(len(nc_checks), 1)
            self.assertEqual(nc_checks[0]["status"], CHECK_STATUS_PASSED)

    def test_9_empty_diff_for_patched_file_fails_validation(self):
        """9. Empty diff for a patched file fails validation."""
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as sb_dir:
            repo_path = Path(repo_dir)
            sb_path = Path(sb_dir)

            (repo_path / "app.py").write_text("orig", encoding="utf-8")
            (sb_path / "app.py").write_text("patched", encoding="utf-8")

            patch_result = {
                "sandbox_path": str(sb_path),
                "original_repository_modified": False,
                "files_changed": 1,
                "patches": [
                    {
                        "file": "app.py",
                        "status": "patched",
                        "changes": [{"description": "some change", "line_before": 1, "line_after": 1}],
                        "diff": "",
                    }
                ],
            }
            res = validate_patches(repo_path, patch_result)
            self.assertFalse(res["validation_passed"])
            consistency_checks = [c for c in res["checks"] if c["name"] == "patch_consistency:app.py"]
            self.assertEqual(len(consistency_checks), 1)
            self.assertEqual(consistency_checks[0]["status"], CHECK_STATUS_FAILED)

    def test_10_output_schema_is_correct(self):
        """10. Output schema strictly conforms to specifications."""
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as sb_dir:
            repo_path = Path(repo_dir)
            sb_path = Path(sb_dir)

            patch_result = {
                "sandbox_path": str(sb_path),
                "original_repository_modified": False,
                "files_changed": 0,
                "patches": [
                    {"file": "a.py", "status": "no_change", "changes": [], "diff": ""},
                    {"file": "b.py", "status": "manual_review", "changes": [], "diff": ""},
                ],
            }
            res = validate_patches(repo_path, patch_result)
            self.assertIsInstance(res, dict)
            self.assertIn("validation_passed", res)
            self.assertIn("original_repository_modified", res)
            self.assertIn("checks", res)
            self.assertIn("files_validated", res)
            self.assertIn("files_failed", res)
            self.assertIn("manual_review_required", res)

            self.assertIsInstance(res["validation_passed"], bool)
            self.assertIsInstance(res["original_repository_modified"], bool)
            self.assertIsInstance(res["checks"], list)
            self.assertIsInstance(res["files_validated"], int)
            self.assertIsInstance(res["files_failed"], int)
            self.assertIsInstance(res["manual_review_required"], bool)

            for check in res["checks"]:
                self.assertIsInstance(check, dict)
                self.assertIn("name", check)
                self.assertIn("status", check)
                self.assertIn("message", check)

    def test_11_deterministic_validation_ordering(self):
        """11. Checks and file results are ordered deterministically."""
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as sb_dir:
            repo_path = Path(repo_dir)
            sb_path = Path(sb_dir)

            patch_result = {
                "sandbox_path": str(sb_path),
                "original_repository_modified": False,
                "files_changed": 0,
                "patches": [
                    {"file": "z.py", "status": "no_change", "changes": [], "diff": ""},
                    {"file": "a.py", "status": "manual_review", "changes": [], "diff": ""},
                    {"file": "m.py", "status": "no_change", "changes": [], "diff": ""},
                ],
            }
            res1 = validate_patches(repo_path, patch_result)
            res2 = validate_patches(repo_path, patch_result)

            self.assertEqual(res1["checks"], res2["checks"])
            check_names = [c["name"] for c in res1["checks"]]
            self.assertEqual(check_names, sorted(check_names))

    def test_12_original_repo_modified_detected(self):
        """12. Original repository modification differs from diff snapshot."""
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as sb_dir:
            repo_path = Path(repo_dir)
            sb_path = Path(sb_dir)

            # Original repo file was altered after diff was generated
            (repo_path / "app.py").write_text("altered content", encoding="utf-8")
            (sb_path / "app.py").write_text("patched content", encoding="utf-8")

            diff = "--- original\n+++ patched\n@@ -1,1 +1,1 @@\n-initial content\n+patched content\n"
            patch_result = {
                "sandbox_path": str(sb_path),
                "original_repository_modified": False,
                "files_changed": 1,
                "patches": [
                    {
                        "file": "app.py",
                        "status": "patched",
                        "changes": [{"description": "some change", "line_before": 1, "line_after": 1}],
                        "diff": diff,
                    }
                ],
            }
            res = validate_patches(repo_path, patch_result)
            self.assertFalse(res["validation_passed"])
            self.assertTrue(res["original_repository_modified"])


if __name__ == "__main__":
    unittest.main()
