"""Unit tests for Qrypta Human Approval stage."""

import unittest
from pathlib import Path
import tempfile
import shutil

from qrypta.pipeline import run_pipeline
from qrypta.approval import (
    create_approval_request,
    approve_migration,
    reject_migration,
    STATUS_AWAITING_APPROVAL,
    STATUS_APPROVED,
    STATUS_REJECTED,
    STATUS_UNMODIFIED,
)


class TestHumanApproval(unittest.TestCase):
    """Test suite for human approval workflow."""

    def setUp(self):
        self.fixtures_dir = Path(__file__).parent / "fixtures"
        self.sample_file = self.fixtures_dir / "python_sample.py"

    def test_approval_request_creation(self):
        """Verify pipeline output correctly synthesizes an approval request."""
        pipeline_result = run_pipeline(self.fixtures_dir)
        approval_req = create_approval_request(
            pipeline_result=pipeline_result,
            repository_path=self.fixtures_dir,
        )

        # 1. State check
        self.assertEqual(approval_req["status"], STATUS_AWAITING_APPROVAL)
        self.assertFalse(approval_req["original_repository_modified"])
        self.assertEqual(approval_req["original_repository_status"], STATUS_UNMODIFIED)

        # 2. Summary structure
        summary = approval_req["summary"]
        self.assertIn("proposed_changes", summary)
        self.assertIn("automatic_patches", summary)
        self.assertIn("manual_review_items", summary)
        self.assertIn("affected_files", summary)
        self.assertIn("validation_status", summary)
        self.assertGreater(summary["affected_files"], 0)

        # 3. Review items list
        review_items = approval_req["review_items"]
        self.assertGreater(len(review_items), 0)
        first_item = review_items[0]
        self.assertIn("finding_id", first_item)
        self.assertIn("file", first_item)
        self.assertIn("algorithm", first_item)
        self.assertIn("recommended_algorithm", first_item)
        self.assertIn("patch_status", first_item)
        self.assertIn("validation_status", first_item)

    def test_approve_migration_workflow(self):
        """Verify approval workflow updates status, re-validates, and preserves original repo."""
        with tempfile.TemporaryDirectory() as temp_repo, tempfile.TemporaryDirectory() as temp_sb:
            repo_path = Path(temp_repo)
            sb_path = Path(temp_sb)

            # Copy sample file into temp repo
            target_file = repo_path / "app.py"
            shutil.copy(self.sample_file, target_file)
            orig_bytes = target_file.read_bytes()

            pipeline_result = run_pipeline(repo_path)
            approval_req = create_approval_request(
                pipeline_result=pipeline_result,
                repository_path=repo_path,
                sandbox_path=sb_path,
            )

            # Approve
            approve_result = approve_migration(
                approval_request=approval_req,
                repository_path=repo_path,
                sandbox_path=sb_path,
            )

            # Check approval response
            self.assertEqual(approve_result["status"], STATUS_APPROVED)
            self.assertEqual(approve_result["approval_status"], "approved")
            self.assertFalse(approve_result["original_repository_modified"])
            self.assertTrue(approve_result["sandbox_applied"])
            self.assertIn("validation", approve_result)

            # Verify original repository is completely untouched
            self.assertEqual(target_file.read_bytes(), orig_bytes)

    def test_reject_migration_workflow(self):
        """Verify rejection workflow marks status as rejected without applying changes."""
        with tempfile.TemporaryDirectory() as temp_repo:
            repo_path = Path(temp_repo)
            target_file = repo_path / "app.py"
            shutil.copy(self.sample_file, target_file)
            orig_bytes = target_file.read_bytes()

            pipeline_result = run_pipeline(repo_path)
            approval_req = create_approval_request(
                pipeline_result=pipeline_result,
                repository_path=repo_path,
            )

            # Reject
            reject_result = reject_migration(approval_request=approval_req)

            self.assertEqual(reject_result["status"], STATUS_REJECTED)
            self.assertEqual(reject_result["approval_status"], "rejected")
            self.assertFalse(reject_result["original_repository_modified"])
            self.assertFalse(reject_result["sandbox_applied"])

            # Verify original repository is untouched
            self.assertEqual(target_file.read_bytes(), orig_bytes)

    def test_manual_review_items_explicitly_flagged(self):
        """Verify manual review items are not auto-approved and remain explicitly flagged."""
        pipeline_result = run_pipeline(self.fixtures_dir)
        approval_req = create_approval_request(
            pipeline_result=pipeline_result,
            repository_path=self.fixtures_dir,
        )

        manual_items = [
            item for item in approval_req["review_items"]
            if item["patch_status"] == "MANUAL REVIEW REQUIRED"
        ]
        self.assertGreater(len(manual_items), 0)
        for item in manual_items:
            self.assertEqual(item["validation_status"], "MANUAL REVIEW REQUIRED")
            self.assertTrue(bool(item["migration_plan"]))

    def test_patched_findings_classified_as_automatic(self):
        """Verify patched findings are classified as AUTOMATIC PATCH."""
        mock_pipeline_result = {
            "migration": [
                {
                    "file": "app/hasher.py",
                    "line": 10,
                    "algorithm": "MD5",
                    "status": "patched",
                    "migration_plan": {"action": "Replace MD5 with SHA-256"},
                }
            ],
            "patch": {
                "files_changed": 1,
                "patches": [
                    {
                        "file": "app/hasher.py",
                        "status": "patched",
                        "diff": "--- original\n+++ patched\n@@ -10 +10 @@\n-hashlib.md5(\n+hashlib.sha256(\n",
                        "changes": [{"line_before": 10}],
                    }
                ],
            },
            "validation": {"validation_passed": True},
        }

        approval_req = create_approval_request(mock_pipeline_result)
        summary = approval_req["summary"]
        review_items = approval_req["review_items"]

        self.assertEqual(summary["automatic_patches"], 1)
        self.assertEqual(summary["proposed_changes"], 1)
        self.assertEqual(len(review_items), 1)
        self.assertEqual(review_items[0]["patch_status"], "AUTOMATIC PATCH")
        self.assertEqual(review_items[0]["validation_status"], "PASSED")

    def test_manual_review_findings_classified_as_manual(self):
        """Verify manual_review findings are classified as MANUAL REVIEW REQUIRED."""
        mock_pipeline_result = {
            "migration": [
                {
                    "file": "app/auth.py",
                    "line": 59,
                    "algorithm": "RSA",
                    "context": "unknown",
                    "status": "manual_review",
                    "recommended_algorithm": "ML-DSA",
                    "migration_plan": {"action": "Replace RSA key generation with ML-DSA"},
                }
            ],
            "patch": {
                "files_changed": 0,
                "patches": [{"file": "app/auth.py", "status": "manual_review", "diff": "", "changes": []}],
            },
            "validation": {"validation_passed": True},
        }

        approval_req = create_approval_request(mock_pipeline_result)
        summary = approval_req["summary"]
        review_items = approval_req["review_items"]

        self.assertEqual(summary["manual_review_items"], 1)
        self.assertEqual(summary["automatic_patches"], 0)
        self.assertEqual(len(review_items), 1)
        self.assertEqual(review_items[0]["patch_status"], "MANUAL REVIEW REQUIRED")
        self.assertEqual(review_items[0]["validation_status"], "MANUAL REVIEW REQUIRED")

    def test_no_change_findings_classified_as_no_change(self):
        """Verify no_change findings are classified as NO CHANGE REQUIRED."""
        mock_pipeline_result = {
            "migration": [
                {
                    "file": "app/cipher.py",
                    "line": 40,
                    "algorithm": "AES-256-GCM",
                    "context": "encryption",
                    "status": "no_change",
                    "migration_plan": {"action": "Modern symmetric cipher is quantum-resistant; retain current usage."},
                }
            ],
            "patch": {
                "files_changed": 0,
                "patches": [{"file": "app/cipher.py", "status": "no_change", "diff": "", "changes": []}],
            },
            "validation": {"validation_passed": True},
        }

        approval_req = create_approval_request(mock_pipeline_result)
        summary = approval_req["summary"]
        review_items = approval_req["review_items"]

        self.assertEqual(summary["no_change_findings"], 1)
        self.assertEqual(summary["automatic_patches"], 0)
        self.assertEqual(summary["manual_review_items"], 0)
        self.assertEqual(len(review_items), 1)
        self.assertEqual(review_items[0]["patch_status"], "NO CHANGE REQUIRED")
        self.assertEqual(review_items[0]["validation_status"], "PASSED")

    def test_approval_does_not_apply_manual_review_items(self):
        """Verify approval applies only automatic patches and leaves manual-review code unmodified."""
        with tempfile.TemporaryDirectory() as temp_repo, tempfile.TemporaryDirectory() as temp_sb:
            repo_path = Path(temp_repo)
            sb_path = Path(temp_sb)

            # Create sample file containing MD5 (auto patchable) and RSA (manual review)
            test_file = repo_path / "mixed.py"
            original_code = (
                "import hashlib\n"
                "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                "def do_crypto():\n"
                "    h = hashlib.md5(b'test').hexdigest()\n"
                "    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
                "    return h, k\n"
            )
            test_file.write_text(original_code, encoding="utf-8")

            pipeline_result = run_pipeline(repo_path)
            from qrypta.patch.generator import generate_patches
            from qrypta.validate.validator import validate_patches

            patch_result = generate_patches(repo_path, pipeline_result.get("migration", []), sandbox_path=sb_path)
            validation_result = validate_patches(repo_path, patch_result)
            pipeline_result["patch"] = patch_result
            pipeline_result["validation"] = validation_result

            approval_req = create_approval_request(
                pipeline_result=pipeline_result,
                repository_path=repo_path,
                sandbox_path=sb_path,
            )

            # Check classifications: MD5 -> AUTOMATIC PATCH, RSA -> MANUAL REVIEW REQUIRED
            review_map = {item["algorithm"]: item["patch_status"] for item in approval_req["review_items"]}
            self.assertIn("MD5", review_map)
            self.assertEqual(review_map["MD5"], "AUTOMATIC PATCH")
            self.assertIn("RSA", review_map)
            self.assertEqual(review_map["RSA"], "MANUAL REVIEW REQUIRED")

            # Execute approve
            approve_res = approve_migration(approval_req, repository_path=repo_path, sandbox_path=sb_path)
            self.assertEqual(approve_res["status"], STATUS_APPROVED)
            self.assertFalse(approve_res["original_repository_modified"])

            # Verify original repository is untouched
            self.assertEqual(test_file.read_text(encoding="utf-8"), original_code)

            # Verify sandbox has MD5 replaced with SHA-256, but RSA key gen is intact (not modified)
            sb_file = sb_path / "mixed.py"
            sb_code = sb_file.read_text(encoding="utf-8")
            self.assertIn("hashlib.sha256(b'test')", sb_code)
            self.assertNotIn("hashlib.md5(b'test')", sb_code)
            self.assertIn("rsa.generate_private_key", sb_code)  # Manual review item preserved intact


if __name__ == "__main__":
    unittest.main()
