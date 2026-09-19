"""Unit tests for Qrypta Patch Generator module."""

import tempfile
import unittest
from pathlib import Path
from qrypta.patch.generator import (
    generate_patches,
    STATUS_PATCHED,
    STATUS_NO_CHANGE,
    STATUS_MANUAL_REVIEW,
)


class TestPatchGenerator(unittest.TestCase):
    """Test suite for Patch Generator."""

    def test_1_sha1_hashlib_call_patched(self):
        """1. SHA-1 hashlib call is patched to SHA-256."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            code_file = repo_path / "hasher.py"
            code_file.write_text(
                "import hashlib\n\n"
                "# This comment mentions hashlib.sha1(data)\n"
                "def compute_hash(data):\n"
                "    return hashlib.sha1(data).hexdigest()\n",
                encoding="utf-8",
            )
            finding = {
                "algorithm": "SHA-1",
                "primitive": "hash_function",
                "file": "hasher.py",
                "line": 5,
                "migration_type": "symmetric_upgrade",
            }
            res = generate_patches(repo_path, [finding])
            self.assertEqual(res["files_changed"], 1)
            self.assertEqual(len(res["patches"]), 1)
            patch = res["patches"][0]
            self.assertEqual(patch["status"], STATUS_PATCHED)
            self.assertEqual(len(patch["changes"]), 1)
            self.assertEqual(patch["changes"][0]["description"], "Replace hashlib.sha1 with hashlib.sha256")
            self.assertEqual(patch["changes"][0]["line_before"], 5)
            self.assertIn("hashlib.sha256(data)", patch["diff"])

    def test_2_md5_hashlib_call_patched(self):
        """2. MD5 hashlib call is patched to SHA-256."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            code_file = repo_path / "md5_util.py"
            code_file.write_text(
                "import hashlib\n\n"
                "def get_digest(val):\n"
                "    return hashlib.md5(val).hexdigest()\n",
                encoding="utf-8",
            )
            finding = {
                "algorithm": "MD5",
                "primitive": "hash_function",
                "file": "md5_util.py",
                "line": 4,
                "migration_type": "symmetric_upgrade",
            }
            res = generate_patches(repo_path, [finding])
            self.assertEqual(res["files_changed"], 1)
            patch = res["patches"][0]
            self.assertEqual(patch["status"], STATUS_PATCHED)
            self.assertEqual(patch["changes"][0]["description"], "Replace hashlib.md5 with hashlib.sha256")
            self.assertIn("hashlib.sha256(val)", patch["diff"])

    def test_3_rsa_signature_returns_manual_review(self):
        """3. RSA signature returns manual_review."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            finding = {
                "algorithm": "RSA",
                "recommended_algorithm": "ML-DSA",
                "migration_type": "pqc_replacement",
                "context": "digital_signature",
                "file": "sign.py",
                "line": 10,
            }
            res = generate_patches(repo_path, [finding])
            self.assertEqual(res["files_changed"], 0)
            self.assertEqual(res["patches"][0]["status"], STATUS_MANUAL_REVIEW)
            self.assertEqual(res["patches"][0]["changes"], [])
            self.assertEqual(res["patches"][0]["diff"], "")

    def test_4_ecdh_key_exchange_returns_manual_review(self):
        """4. ECDH key exchange returns manual_review."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            finding = {
                "algorithm": "ECDH",
                "recommended_algorithm": "ML-KEM",
                "migration_type": "pqc_replacement",
                "context": "key_exchange",
                "file": "kex.py",
                "line": 15,
            }
            res = generate_patches(repo_path, [finding])
            self.assertEqual(res["files_changed"], 0)
            self.assertEqual(res["patches"][0]["status"], STATUS_MANUAL_REVIEW)
            self.assertEqual(res["patches"][0]["changes"], [])
            self.assertEqual(res["patches"][0]["diff"], "")

    def test_5_aes_returns_no_change(self):
        """5. AES returns no_change."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            finding = {
                "algorithm": "AES",
                "migration_type": "no_pqc_replacement",
                "context": "encryption",
                "file": "encrypt.py",
                "line": 20,
            }
            res = generate_patches(repo_path, [finding])
            self.assertEqual(res["files_changed"], 0)
            self.assertEqual(res["patches"][0]["status"], STATUS_NO_CHANGE)
            self.assertEqual(res["patches"][0]["changes"], [])
            self.assertEqual(res["patches"][0]["diff"], "")

    def test_6_sha256_returns_no_change(self):
        """6. SHA-256 returns no_change."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            finding = {
                "algorithm": "SHA-256",
                "migration_type": "no_pqc_replacement",
                "context": "hashing",
                "file": "hash.py",
                "line": 5,
            }
            res = generate_patches(repo_path, [finding])
            self.assertEqual(res["files_changed"], 0)
            self.assertEqual(res["patches"][0]["status"], STATUS_NO_CHANGE)
            self.assertEqual(res["patches"][0]["changes"], [])
            self.assertEqual(res["patches"][0]["diff"], "")

    def test_7_unknown_migration_returns_manual_review(self):
        """7. Unknown migration returns manual_review."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            finding = {
                "algorithm": "CustomCrypto",
                "migration_type": "manual_review",
                "context": "unknown",
                "file": "custom.py",
                "line": 1,
            }
            res = generate_patches(repo_path, [finding])
            self.assertEqual(res["files_changed"], 0)
            self.assertEqual(res["patches"][0]["status"], STATUS_MANUAL_REVIEW)
            self.assertEqual(res["patches"][0]["changes"], [])
            self.assertEqual(res["patches"][0]["diff"], "")

    def test_8_unified_diff_generated_for_supported_patch(self):
        """8. Unified diff is generated for a supported patch."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            code_file = repo_path / "app.py"
            code_file.write_text("import hashlib\nh = hashlib.sha1(data)\n", encoding="utf-8")
            finding = {
                "algorithm": "SHA-1",
                "file": "app.py",
                "line": 2,
            }
            res = generate_patches(repo_path, [finding])
            diff = res["patches"][0]["diff"]
            self.assertTrue(diff.startswith("--- original\n+++ patched\n@@"))
            self.assertIn("-h = hashlib.sha1(data)", diff)
            self.assertIn("+h = hashlib.sha256(data)", diff)

    def test_9_original_repository_is_unchanged(self):
        """9. Original repository is completely unchanged."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            code_file = repo_path / "app.py"
            initial_content = "import hashlib\nh = hashlib.sha1(data)\n"
            code_file.write_text(initial_content, encoding="utf-8")
            finding = {
                "algorithm": "SHA-1",
                "file": "app.py",
                "line": 2,
            }
            res = generate_patches(repo_path, [finding])
            self.assertFalse(res["original_repository_modified"])
            # Verify file in original repository was untouched
            self.assertEqual(code_file.read_text(encoding="utf-8"), initial_content)

    def test_10_path_traversal_is_rejected(self):
        """10. Path traversal is rejected safely."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            findings = [
                {"algorithm": "SHA-1", "file": "../../etc/passwd", "line": 1},
                {"algorithm": "SHA-1", "file": "../outside.py", "line": 1},
            ]
            res = generate_patches(repo_path, findings)
            self.assertEqual(res["files_changed"], 0)
            self.assertFalse(res["original_repository_modified"])
            for patch in res["patches"]:
                self.assertEqual(patch["status"], STATUS_MANUAL_REVIEW)
                self.assertEqual(patch["diff"], "")

    def test_11_ignored_directories_not_modified(self):
        """11. Ignored directories (.git, node_modules, venv, etc.) are ignored."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            git_dir = repo_path / ".git"
            git_dir.mkdir()
            git_file = git_dir / "config"
            git_file.write_text("hashlib.sha1(data)\n", encoding="utf-8")

            finding = {
                "algorithm": "SHA-1",
                "file": ".git/config",
                "line": 1,
            }
            res = generate_patches(repo_path, [finding])
            self.assertEqual(res["files_changed"], 0)
            self.assertEqual(res["patches"][0]["status"], STATUS_MANUAL_REVIEW)
            self.assertEqual(git_file.read_text(encoding="utf-8"), "hashlib.sha1(data)\n")

    def test_12_multiple_files_handled_deterministically(self):
        """12. Multiple files are handled deterministically."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            (repo_path / "b.py").write_text("import hashlib\nh = hashlib.sha1(d)\n", encoding="utf-8")
            (repo_path / "a.py").write_text("import hashlib\nh = hashlib.md5(d)\n", encoding="utf-8")

            findings = [
                {"algorithm": "SHA-1", "file": "b.py", "line": 2},
                {"algorithm": "MD5", "file": "a.py", "line": 2},
            ]
            res1 = generate_patches(repo_path, findings)
            res2 = generate_patches(repo_path, findings)

            self.assertEqual(res1["files_changed"], 2)
            self.assertEqual(res1["patches"][0]["file"], "a.py")
            self.assertEqual(res1["patches"][1]["file"], "b.py")
            self.assertEqual(res1["patches"], res2["patches"])

    def test_13_output_schema_is_correct(self):
        """13. Output schema strictly adheres to specifications."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            (repo_path / "app.py").write_text("import hashlib\nh = hashlib.sha1(d)\n", encoding="utf-8")
            findings = [
                {"algorithm": "SHA-1", "file": "app.py", "line": 2},
                {"algorithm": "AES", "file": "aes.py", "line": 1},
            ]
            res = generate_patches(repo_path, findings)
            self.assertIsInstance(res, dict)
            self.assertIn("sandbox_path", res)
            self.assertIn("original_repository_modified", res)
            self.assertIn("files_changed", res)
            self.assertIn("patches", res)
            self.assertIsInstance(res["sandbox_path"], str)
            self.assertIsInstance(res["original_repository_modified"], bool)
            self.assertFalse(res["original_repository_modified"])
            self.assertIsInstance(res["files_changed"], int)
            self.assertIsInstance(res["patches"], list)

            for patch in res["patches"]:
                self.assertIsInstance(patch, dict)
                self.assertIn("file", patch)
                self.assertIn("status", patch)
                self.assertIn("changes", patch)
                self.assertIn("diff", patch)
                self.assertIn(patch["status"], [STATUS_PATCHED, STATUS_NO_CHANGE, STATUS_MANUAL_REVIEW])
                self.assertIsInstance(patch["changes"], list)
                self.assertIsInstance(patch["diff"], str)


if __name__ == "__main__":
    unittest.main()
