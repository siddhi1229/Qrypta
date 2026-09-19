"""Tests for unified engine and CLI."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from qrypta.scanner.engine import scan_repository
from qrypta.scanner.models import Finding


class TestEngineAndCLI(unittest.TestCase):
    """Test suite for repository traversal, ignored directories, and CLI."""

    def setUp(self):
        self.fixtures_dir = Path(__file__).parent / "fixtures"

    def test_scan_repository_fixtures(self):
        """Verify scan_repository finds items across python, js, and ts fixtures."""
        findings = scan_repository(self.fixtures_dir)
        self.assertGreater(len(findings), 0)

        # Check relative paths
        files_scanned = {f.file for f in findings}
        self.assertIn("python_sample.py", files_scanned)
        self.assertIn("js_sample.js", files_scanned)
        self.assertIn("ts_sample.ts", files_scanned)

    def test_finding_schema_conformity(self):
        """Verify all findings conform strictly to required JSON schema."""
        required_keys = {
            "algorithm",
            "variant",
            "primitive",
            "usage",
            "file",
            "line",
            "evidence",
            "library",
            "confidence",
        }
        findings = scan_repository(self.fixtures_dir)
        for finding in findings:
            data = finding.to_dict()
            self.assertEqual(set(data.keys()), required_keys)
            self.assertIsInstance(data["algorithm"], str)
            self.assertTrue(data["variant"] is None or isinstance(data["variant"], str))
            self.assertIsInstance(data["primitive"], str)
            self.assertIsInstance(data["usage"], str)
            self.assertIsInstance(data["file"], str)
            self.assertIsInstance(data["line"], int)
            self.assertIsInstance(data["evidence"], str)
            self.assertTrue(data["library"] is None or isinstance(data["library"], str))
            self.assertIsInstance(data["confidence"], (float, int))
            self.assertGreaterEqual(data["confidence"], 0.0)
            self.assertLessEqual(data["confidence"], 1.0)

    def test_ignored_directories(self):
        """Verify that files inside ignored directories (.git, node_modules, venv, etc.) are skipped."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Normal file
            (temp_path / "valid.py").write_text("import hashlib\nhashlib.sha256(b'ok')", encoding="utf-8")

            # Ignored directories
            for ignored in [".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"]:
                ignored_dir = temp_path / ignored
                ignored_dir.mkdir(parents=True, exist_ok=True)
                (ignored_dir / "crypto_leak.py").write_text("import hashlib\nhashlib.md5(b'bad')", encoding="utf-8")
                (ignored_dir / "leak.js").write_text("const crypto = require('crypto'); crypto.createHash('sha1');", encoding="utf-8")

            findings = scan_repository(temp_path)
            # Only valid.py should be detected
            files = [f.file for f in findings]
            self.assertEqual(files, ["valid.py"])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].algorithm, "SHA-256")

    def test_repository_not_modified(self):
        """Verify scanning does not modify any files in the repository."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_file = temp_path / "code.py"
            initial_content = "import hashlib\nh = hashlib.sha256(b'immutable')\n"
            test_file.write_text(initial_content, encoding="utf-8")
            mtime_before = test_file.stat().st_mtime_ns

            scan_repository(temp_path)

            self.assertEqual(test_file.read_text(encoding="utf-8"), initial_content)
            self.assertEqual(test_file.stat().st_mtime_ns, mtime_before)

    def test_cli_execution_stdout(self):
        """Verify CLI prints valid JSON list of findings to stdout."""
        repo_root = Path(__file__).parent.parent
        cmd = [sys.executable, "-m", "qrypta.cli", str(self.fixtures_dir), "--pretty"]
        result = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"CLI stderr: {result.stderr}")
        parsed = json.loads(result.stdout)
        self.assertIsInstance(parsed, list)
        self.assertGreater(len(parsed), 0)

    def test_cli_execution_output_file(self):
        """Verify CLI writes JSON to --output file when specified."""
        repo_root = Path(__file__).parent.parent
        with tempfile.TemporaryDirectory() as temp_dir:
            out_file = Path(temp_dir) / "output.json"
            cmd = [
                sys.executable,
                "-m",
                "qrypta.cli",
                str(self.fixtures_dir),
                "--output",
                str(out_file),
            ]
            result = subprocess.run(
                cmd,
                cwd=str(repo_root),
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, f"CLI stderr: {result.stderr}")
            self.assertTrue(out_file.exists())
            parsed = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertIsInstance(parsed, list)
            self.assertGreater(len(parsed), 0)


if __name__ == "__main__":
    unittest.main()
