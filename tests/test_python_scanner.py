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

    def test_jwt_local_variable_resolution(self):
        """1. Verify JWT algorithms are detected when assigned to local variables or parameter defaults."""
        code = """
import jwt

def generate_token(payload, key):
    algorithm = "RS256"
    return jwt.encode(payload, key, algorithm=algorithm)

def verify_token(token, key):
    algorithms = ["RS256", "ES256"]
    return jwt.decode(token, key, algorithms=algorithms)

def default_param_token(payload, key, algorithm: str = "RS256"):
    return jwt.encode(payload, key, algorithm=algorithm)
        """
        findings = scan_python_code(code, filename="auth.py")
        jwt_findings = [f for f in findings if f.primitive == "jwt_signature"]
        self.assertGreaterEqual(len(jwt_findings), 4)

        # Verify RS256 resolution
        rs256_findings = [f for f in jwt_findings if f.algorithm == "RS256"]
        self.assertTrue(any(f.usage == "token_signing" for f in rs256_findings))
        self.assertTrue(any(f.usage == "token_verification" for f in rs256_findings))

        # Verify ES256 list resolution
        es256_findings = [f for f in jwt_findings if f.algorithm == "ES256"]
        self.assertEqual(len(es256_findings), 1)
        self.assertEqual(es256_findings[0].usage, "token_verification")

    def test_jwt_direct_literal_preserved(self):
        """Verify direct literal JWT algorithm detection is preserved."""
        code = """
import jwt
t = jwt.encode({"sub": "123"}, "secret", algorithm="RS256")
jwt.decode(t, "secret", algorithms=["RS256"])
        """
        findings = scan_python_code(code, filename="direct_jwt.py")
        jwt_findings = [f for f in findings if f.primitive == "jwt_signature"]
        self.assertEqual(len(jwt_findings), 2)
        self.assertEqual(jwt_findings[0].algorithm, "RS256")
        self.assertEqual(jwt_findings[0].primitive, "jwt_signature")
        self.assertEqual(jwt_findings[0].usage, "token_signing")
        self.assertEqual(jwt_findings[1].algorithm, "RS256")
        self.assertEqual(jwt_findings[1].primitive, "jwt_signature")
        self.assertEqual(jwt_findings[1].usage, "token_verification")

    def test_aesgcm_detection(self):
        """2. Verify AESGCM usage is classified as AES / symmetric_encryption / encryption."""
        code = """
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
        """
        findings = scan_python_code(code, filename="crypto_aesgcm.py")
        aes_findings = [f for f in findings if f.algorithm == "AES"]
        self.assertEqual(len(aes_findings), 2)
        for f in aes_findings:
            self.assertEqual(f.algorithm, "AES")
            self.assertEqual(f.primitive, "symmetric_encryption")
            self.assertEqual(f.usage, "encryption")
            self.assertIn("AESGCM", f.evidence)

    def test_bcrypt_detection(self):
        """3. Verify bcrypt hashpw and checkpw are classified as bcrypt / password_hashing / authentication."""
        code = """
import bcrypt

hashed = bcrypt.hashpw(b"supersecret", bcrypt.gensalt())
is_valid = bcrypt.checkpw(b"supersecret", hashed)
        """
        findings = scan_python_code(code, filename="auth_bcrypt.py")
        bcrypt_findings = [f for f in findings if f.algorithm == "bcrypt"]
        self.assertEqual(len(bcrypt_findings), 2)
        for f in bcrypt_findings:
            self.assertEqual(f.algorithm, "bcrypt")
            self.assertEqual(f.primitive, "password_hashing")
            self.assertEqual(f.usage, "authentication")
            self.assertEqual(f.library, "bcrypt")

    def test_ecdsa_sign_verify_context(self):
        """4. Verify ECDSA signing/verification operations are detected and get digital_signature context."""
        from qrypta.context.analyzer import analyze_context, CONTEXT_DIGITAL_SIGNATURE

        code = """
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

private_key = ec.generate_private_key(ec.SECP256R1())
sig = private_key.sign(b"data", ec.ECDSA(hashes.SHA256()))
public_key = private_key.public_key()
public_key.verify(sig, b"data", ec.ECDSA(hashes.SHA256()))
        """
        findings = scan_python_code(code, filename="ecdsa_ops.py")

        # Verify keygen is preserved as key_generation
        keygen = [f for f in findings if f.algorithm == "ECDSA" and f.usage == "key_generation"]
        self.assertEqual(len(keygen), 1)

        # Verify sign/verify usages
        sig_findings = [f for f in findings if f.algorithm == "ECDSA" and f.usage == "signature"]
        self.assertEqual(len(sig_findings), 2)

        # Context analysis should map ECDSA signature operations to digital_signature
        ctx_results = analyze_context(sig_findings)
        for r in ctx_results:
            self.assertEqual(r["context"], CONTEXT_DIGITAL_SIGNATURE)

    def test_suppress_pure_crypto_imports(self):
        """5. Verify pure cryptographic import statements do not generate standalone findings."""
        code = """
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import bcrypt
import hashlib
import ssl
import jwt
        """
        findings = scan_python_code(code, filename="imports_only.py")
        self.assertEqual(len(findings), 0)

    def test_deduplicate_identical_findings(self):
        """6. Verify identical findings on the same line are deduplicated while distinct operations are preserved."""
        code = """
import hashlib
digest = hashlib.sha256(b"hello").hexdigest()
        """
        findings = scan_python_code(code, filename="dedup.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].algorithm, "SHA-256")
        self.assertEqual(findings[0].line, 3)


if __name__ == "__main__":
    unittest.main()
