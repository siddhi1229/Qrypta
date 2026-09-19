"""Tests for Python AST scanner."""

import unittest
from pathlib import Path

from qrypta.scanner.python_scanner import scan_python_file, scan_python_code


class TestPythonScanner(unittest.TestCase):
    """Test suite for Python cryptographic scanner."""

    def setUp(self):
        self.fixtures_dir = Path(__file__).parent / "fixtures"
        self.sample_file = self.fixtures_dir / "python_sample.py"

    def test_scan_python_fixtures(self):
        """Verify Python scanner detects algorithms in fixture file."""
        findings = scan_python_file(self.sample_file)
        self.assertGreater(len(findings), 0)

        # Collect detected algorithms
        detected_algos = {f.algorithm for f in findings}
        detected_jwt = {f.algorithm for f in findings if f.primitive == "jwt_signature"}
        detected_tls = {f.algorithm for f in findings if f.primitive == "protocol"}

        # Verify Asymmetric
        self.assertIn("RSA", detected_algos)
        self.assertIn("ECDSA", detected_algos)
        self.assertIn("Ed25519", detected_algos)
        self.assertIn("Diffie-Hellman", detected_algos)

        # Verify Symmetric
        self.assertIn("AES", detected_algos)
        self.assertIn("ChaCha20", detected_algos)
        self.assertIn("DES", detected_algos)
        self.assertIn("3DES", detected_algos)

        # Verify Hashes
        self.assertIn("MD5", detected_algos)
        self.assertIn("SHA-1", detected_algos)
        self.assertIn("SHA-256", detected_algos)
        self.assertIn("SHA-384", detected_algos)
        self.assertIn("SHA-512", detected_algos)

        # Verify JWT
        self.assertIn("RS256", detected_jwt)
        self.assertIn("HS256", detected_jwt)
        self.assertIn("ES256", detected_jwt)

        # Verify TLS
        self.assertTrue(any(f.primitive == "protocol" for f in findings))

    def test_finding_fields_and_evidence(self):
        """Verify findings have accurate line numbers, evidence, and confidence."""
        findings = scan_python_file(self.sample_file)
        with open(self.sample_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for finding in findings:
            # Check confidence range
            self.assertGreaterEqual(finding.confidence, 0.0)
            self.assertLessEqual(finding.confidence, 1.0)

            # Check line number valid
            self.assertGreaterEqual(finding.line, 1)
            self.assertLessEqual(finding.line, len(lines))

            # Check evidence matches the line
            expected_line = lines[finding.line - 1].strip()
            self.assertEqual(finding.evidence, expected_line)

            # Check required fields are non-empty strings
            self.assertTrue(bool(finding.algorithm))
            self.assertTrue(bool(finding.primitive))
            self.assertTrue(bool(finding.usage))
            self.assertTrue(bool(finding.file))
            self.assertTrue(bool(finding.evidence))

    def test_syntax_error_fallback(self):
        """Verify fallback regex scanner works when AST parsing fails."""
        invalid_python = """
        def broken_func(
            hashlib.sha256(b"test")
            jwt.encode(p, s, algorithm="RS256")
            ssl.PROTOCOL_TLSv1_2
        """
        findings = scan_python_code(invalid_python, filename="invalid.py")
        algos = {f.algorithm for f in findings}
        self.assertIn("SHA-256", algos)
        self.assertIn("RS256", algos)
        self.assertIn("TLS", algos)


if __name__ == "__main__":
    unittest.main()
