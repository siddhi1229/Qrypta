"""Tests for JavaScript and TypeScript scanner."""

import unittest
from pathlib import Path

from qrypta.scanner.js_ts_scanner import scan_js_ts_file, scan_js_ts_code


class TestJsTsScanner(unittest.TestCase):
    """Test suite for JS/TS cryptographic scanner."""

    def setUp(self):
        self.fixtures_dir = Path(__file__).parent / "fixtures"
        self.js_sample = self.fixtures_dir / "js_sample.js"
        self.ts_sample = self.fixtures_dir / "ts_sample.ts"

    def test_scan_js_fixture(self):
        """Verify JS scanner detects all cryptographic constructs in js_sample.js."""
        findings = scan_js_ts_file(self.js_sample)
        self.assertGreater(len(findings), 0)

        algos = {f.algorithm for f in findings}
        jwt_algos = {f.algorithm for f in findings if f.primitive == "jwt_signature"}
        tls_findings = [f for f in findings if f.primitive == "protocol"]

        # Asymmetric
        self.assertIn("RSA", algos)
        self.assertIn("Ed25519", algos)
        self.assertIn("Diffie-Hellman", algos)
        self.assertIn("ECDH", algos)

        # Symmetric
        self.assertIn("AES", algos)
        self.assertIn("ChaCha20", algos)
        self.assertIn("DES", algos)
        self.assertIn("3DES", algos)

        # Hashes
        self.assertIn("SHA-256", algos)
        self.assertIn("MD5", algos)
        self.assertIn("SHA-512", algos)

        # JWT
        self.assertIn("RS256", jwt_algos)
        self.assertIn("HS384", jwt_algos)
        self.assertIn("ES256", jwt_algos)

        # TLS
        self.assertGreater(len(tls_findings), 0)

    def test_scan_ts_fixture(self):
        """Verify TS scanner detects WebCrypto, Jose, and TLS in ts_sample.ts."""
        findings = scan_js_ts_file(self.ts_sample)
        self.assertGreater(len(findings), 0)

        algos = {f.algorithm for f in findings}
        jwt_algos = {f.algorithm for f in findings if f.primitive == "jwt_signature"}

        self.assertIn("RSA", algos)
        self.assertIn("ECDSA", algos)
        self.assertIn("AES", algos)
        self.assertIn("SHA-384", algos)
        self.assertIn("HS256", jwt_algos)
        self.assertTrue(any(f.primitive == "protocol" for f in findings))

    def test_finding_fields_and_evidence(self):
        """Verify findings match file line numbers and evidence content."""
        findings = scan_js_ts_file(self.js_sample)
        with open(self.js_sample, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for finding in findings:
            self.assertGreaterEqual(finding.confidence, 0.0)
            self.assertLessEqual(finding.confidence, 1.0)
            self.assertGreaterEqual(finding.line, 1)
            self.assertLessEqual(finding.line, len(lines))

            expected_line = lines[finding.line - 1].strip()
            self.assertEqual(finding.evidence, expected_line)


if __name__ == "__main__":
    unittest.main()
