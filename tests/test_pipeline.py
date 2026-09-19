"""Unit tests for Qrypta End-to-End Orchestration Pipeline."""

import tempfile
import unittest
from pathlib import Path
from qrypta.pipeline import run_pipeline


class TestPipeline(unittest.TestCase):
    """Test suite for Qrypta pipeline orchestration."""

    def setUp(self):
        self.fixtures_dir = Path(__file__).parent / "fixtures"

    def test_1_pipeline_runs_on_fixture_repository(self):
        """1. End-to-end pipeline runs on the existing test fixture repository."""
        result = run_pipeline(self.fixtures_dir)
        self.assertIsInstance(result, dict)
        self.assertGreater(len(result["findings"]), 0)
        self.assertGreater(result["inventory"]["summary"]["total_findings"], 0)
        self.assertIsInstance(result["validation"], dict)
        self.assertIn("validation_passed", result["validation"])

    def test_2_pipeline_output_contains_all_stages(self):
        """2. Pipeline output contains all required stage keys."""
        required_keys = {
            "inventory",
            "findings",
            "risk",
            "pqc",
            "migration",
            "patch",
            "validation",
        }
        result = run_pipeline(self.fixtures_dir)
        self.assertEqual(set(result.keys()), required_keys)
        self.assertIsInstance(result["inventory"], dict)
        self.assertIsInstance(result["findings"], list)
        self.assertIsInstance(result["risk"], list)
        self.assertIsInstance(result["pqc"], list)
        self.assertIsInstance(result["migration"], list)
        self.assertIsInstance(result["patch"], dict)
        self.assertIsInstance(result["validation"], dict)

    def test_3_scanner_findings_reach_context_analysis(self):
        """3. Scanner findings reach Context Analysis (propagated into risk stage)."""
        result = run_pipeline(self.fixtures_dir)
        risk_items = result["risk"]
        self.assertGreater(len(risk_items), 0)
        for item in risk_items:
            self.assertIn("context", item)
            self.assertIn("context_reason", item)
            self.assertIn("context_confidence", item)

    def test_4_risk_results_reach_pqc_mapper(self):
        """4. Risk results reach PQC Mapper."""
        result = run_pipeline(self.fixtures_dir)
        pqc_items = result["pqc"]
        self.assertGreater(len(pqc_items), 0)
        for item in pqc_items:
            self.assertIn("recommended_algorithm", item)
            self.assertIn("migration_type", item)
            self.assertIn("mapping_reason", item)
            self.assertIn("risk_score", item)
            self.assertIn("risk_level", item)

    def test_5_pqc_results_reach_migration_plan(self):
        """5. PQC results reach Migration Plan."""
        result = run_pipeline(self.fixtures_dir)
        migration_items = result["migration"]
        self.assertGreater(len(migration_items), 0)
        for item in migration_items:
            self.assertIn("migration_plan", item)
            plan = item["migration_plan"]
            self.assertIn("action", plan)
            self.assertIn("steps", plan)
            self.assertIn("validation", plan)

    def test_6_migration_results_reach_patch_generator(self):
        """6. Migration results reach Patch Generator."""
        result = run_pipeline(self.fixtures_dir)
        patch_res = result["patch"]
        self.assertIn("patches", patch_res)
        self.assertIn("files_changed", patch_res)
        self.assertIn("original_repository_modified", patch_res)
        self.assertFalse(patch_res["original_repository_modified"])
        self.assertGreater(len(patch_res["patches"]), 0)

    def test_7_patch_results_reach_validation(self):
        """7. Patch results reach Validation."""
        result = run_pipeline(self.fixtures_dir)
        val_res = result["validation"]
        self.assertIn("validation_passed", val_res)
        self.assertIn("checks", val_res)
        self.assertIn("files_validated", val_res)
        self.assertIn("files_failed", val_res)
        self.assertIn("manual_review_required", val_res)
        self.assertTrue(val_res["validation_passed"])

    def test_8_original_repository_remains_unchanged(self):
        """8. Original repository remains unchanged throughout pipeline execution."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_file = temp_path / "app.py"
            initial_content = "import hashlib\nh = hashlib.sha1(b'immutability_check')\n"
            test_file.write_text(initial_content, encoding="utf-8")

            res = run_pipeline(temp_path)
            self.assertFalse(res["patch"]["original_repository_modified"])
            self.assertFalse(res["validation"]["original_repository_modified"])
            self.assertEqual(test_file.read_text(encoding="utf-8"), initial_content)

    def test_9_empty_repository_handled(self):
        """9. Empty repository is handled gracefully without errors."""
        with tempfile.TemporaryDirectory() as empty_dir:
            empty_path = Path(empty_dir)
            result = run_pipeline(empty_path)

            self.assertEqual(result["findings"], [])
            self.assertEqual(result["inventory"]["summary"]["total_findings"], 0)
            self.assertEqual(result["inventory"]["algorithms"], [])
            self.assertEqual(result["risk"], [])
            self.assertEqual(result["pqc"], [])
            self.assertEqual(result["migration"], [])
            self.assertEqual(result["patch"]["files_changed"], 0)
            self.assertEqual(result["patch"]["patches"], [])
            self.assertTrue(result["validation"]["validation_passed"])
            self.assertEqual(result["validation"]["files_validated"], 0)

    def test_10_pipeline_output_is_deterministic(self):
        """10. Pipeline output is deterministic on identical inputs."""
        res1 = run_pipeline(self.fixtures_dir)
        res2 = run_pipeline(self.fixtures_dir)

        self.assertEqual(res1["inventory"], res2["inventory"])
        self.assertEqual([f.to_dict() for f in res1["findings"]], [f.to_dict() for f in res2["findings"]])
        self.assertEqual(res1["risk"], res2["risk"])
        self.assertEqual(res1["pqc"], res2["pqc"])
        self.assertEqual(res1["migration"], res2["migration"])
        self.assertEqual(res1["patch"]["patches"], res2["patch"]["patches"])
        self.assertEqual(res1["patch"]["files_changed"], res2["patch"]["files_changed"])
        self.assertEqual(res1["validation"]["checks"], res2["validation"]["checks"])
        self.assertEqual(res1["validation"]["validation_passed"], res2["validation"]["validation_passed"])


if __name__ == "__main__":
    unittest.main()
