"""Unit tests for Qrypta Risk Engine module."""

import unittest
from qrypta.risk.engine import (
    calculate_risk,
    RISK_LEVEL_CRITICAL,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_MEDIUM,
    RISK_LEVEL_LOW,
)


class TestRiskEngine(unittest.TestCase):
    """Test suite for Risk Engine."""

    def test_1_rsa_jwt_signature_critical(self):
        """1. RSA JWT signature yields critical risk level."""
        finding = {
            "algorithm": "RS256",
            "variant": "RSA-SHA256",
            "primitive": "jwt_signature",
            "usage": "token_signing",
            "context": "jwt_signature",
            "context_reason": "JWT token signing detected",
            "context_confidence": 0.95,
            "file": "auth.py",
            "line": 10,
            "evidence": "jwt.encode(payload, key, algorithm='RS256')",
            "library": "PyJWT",
            "confidence": 0.95,
        }
        results = calculate_risk([finding])
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r["risk_level"], RISK_LEVEL_CRITICAL)
        self.assertGreaterEqual(r["risk_score"], 80)
        self.assertIn("quantum", r["risk_reason"].lower())

    def test_2_ecdh_key_exchange_critical(self):
        """2. ECDH key exchange yields critical risk level."""
        finding = {
            "algorithm": "ECDH",
            "variant": "P-256",
            "primitive": "asymmetric_key_exchange",
            "usage": "key_exchange",
            "context": "key_exchange",
            "context_reason": "ECDH key agreement detected",
            "context_confidence": 1.0,
            "file": "kex.py",
            "line": 20,
            "evidence": "crypto.createECDH('prime256v1')",
            "library": "crypto",
            "confidence": 1.0,
        }
        results = calculate_risk([finding])
        r = results[0]
        self.assertEqual(r["risk_level"], RISK_LEVEL_CRITICAL)
        self.assertEqual(r["risk_score"], 95)

    def test_3_aes_encryption_low(self):
        """3. AES encryption yields low risk level."""
        finding = {
            "algorithm": "AES",
            "variant": "AES-256-GCM",
            "primitive": "symmetric_encryption",
            "usage": "encryption",
            "context": "encryption",
            "context_reason": "AES cipher operation detected",
            "context_confidence": 1.0,
            "file": "cipher.py",
            "line": 30,
            "evidence": "Cipher(algorithms.AES(key), modes.GCM(iv))",
            "library": "cryptography",
            "confidence": 1.0,
        }
        results = calculate_risk([finding])
        r = results[0]
        self.assertEqual(r["risk_level"], RISK_LEVEL_LOW)
        self.assertEqual(r["risk_score"], 35)

    def test_4_sha1_hashing_critical(self):
        """4. SHA-1 hashing yields critical risk level."""
        finding = {
            "algorithm": "SHA-1",
            "variant": None,
            "primitive": "hash_function",
            "usage": "hashing",
            "context": "hashing",
            "context_reason": "Hash digest computation detected",
            "context_confidence": 1.0,
            "file": "hash.py",
            "line": 15,
            "evidence": "hashlib.sha1(data)",
            "library": "hashlib",
            "confidence": 1.0,
        }
        results = calculate_risk([finding])
        r = results[0]
        self.assertEqual(r["risk_level"], RISK_LEVEL_CRITICAL)
        self.assertEqual(r["risk_score"], 95)
        self.assertIn("broken", r["risk_reason"].lower())

    def test_5_tls_1_0_critical(self):
        """5. TLS 1.0 yields critical risk level."""
        finding = {
            "algorithm": "TLS",
            "variant": "TLS 1.0",
            "primitive": "protocol",
            "usage": "protocol_configuration",
            "context": "tls",
            "context_reason": "TLS protocol configuration detected",
            "context_confidence": 1.0,
            "file": "server.js",
            "line": 5,
            "evidence": "minVersion: 'TLSv1'",
            "library": "tls",
            "confidence": 1.0,
        }
        results = calculate_risk([finding])
        r = results[0]
        self.assertEqual(r["risk_level"], RISK_LEVEL_CRITICAL)
        self.assertEqual(r["risk_score"], 95)
        self.assertIn("deprecated", r["risk_reason"].lower())

    def test_6_tls_1_3_low(self):
        """6. TLS 1.3 yields low risk level."""
        finding = {
            "algorithm": "TLS",
            "variant": "TLS 1.3",
            "primitive": "protocol",
            "usage": "protocol_configuration",
            "context": "tls",
            "context_reason": "TLS protocol configuration detected",
            "context_confidence": 1.0,
            "file": "server.ts",
            "line": 8,
            "evidence": "minVersion: 'TLSv1.3'",
            "library": "tls",
            "confidence": 1.0,
        }
        results = calculate_risk([finding])
        r = results[0]
        self.assertEqual(r["risk_level"], RISK_LEVEL_LOW)
        self.assertEqual(r["risk_score"], 35)

    def test_7_unknown_algorithm_medium(self):
        """7. Unknown algorithm yields medium risk level."""
        finding = {
            "algorithm": "CustomCipher128",
            "variant": None,
            "primitive": "unknown",
            "usage": "encryption",
            "context": "unknown",
            "context_reason": "Insufficient evidence",
            "context_confidence": 1.0,
            "file": "custom.py",
            "line": 50,
            "evidence": "CustomCipher128.encrypt()",
            "library": None,
            "confidence": 1.0,
        }
        results = calculate_risk([finding])
        r = results[0]
        self.assertEqual(r["risk_level"], RISK_LEVEL_MEDIUM)
        self.assertEqual(r["risk_score"], 50)

    def test_8_confidence_adjustment(self):
        """8. Risk score is adjusted based on scanner and context confidence."""
        # Base score for RSA in digital_signature is 95
        finding = {
            "algorithm": "RSA",
            "variant": "2048-bit",
            "primitive": "asymmetric_signature",
            "usage": "signature",
            "context": "digital_signature",
            "context_reason": "Signature operation detected",
            "context_confidence": 0.8,
            "file": "sig.py",
            "line": 12,
            "evidence": "private_key.sign(data)",
            "library": "cryptography",
            "confidence": 0.8,
        }
        # avg confidence = (0.8 + 0.8) / 2 = 0.8
        # adjusted = round(95 * 0.8) = 76
        results = calculate_risk([finding])
        r = results[0]
        self.assertEqual(r["risk_score"], 76)
        self.assertEqual(r["risk_level"], RISK_LEVEL_HIGH)

    def test_9_output_schema_preservation(self):
        """9. All original finding fields are preserved with new risk fields added."""
        finding = {
            "algorithm": "ChaCha20",
            "variant": None,
            "primitive": "symmetric_encryption",
            "usage": "encryption",
            "context": "encryption",
            "context_reason": "ChaCha20 cipher detected",
            "context_confidence": 0.95,
            "file": "stream.py",
            "line": 45,
            "evidence": "Cipher(algorithms.ChaCha20(key, nonce), mode=None)",
            "library": "cryptography",
            "confidence": 0.95,
        }
        results = calculate_risk([finding])
        r = results[0]

        # Verify original fields preserved
        self.assertEqual(r["algorithm"], "ChaCha20")
        self.assertEqual(r["variant"], None)
        self.assertEqual(r["primitive"], "symmetric_encryption")
        self.assertEqual(r["usage"], "encryption")
        self.assertEqual(r["context"], "encryption")
        self.assertEqual(r["context_reason"], "ChaCha20 cipher detected")
        self.assertEqual(r["context_confidence"], 0.95)
        self.assertEqual(r["file"], "stream.py")
        self.assertEqual(r["line"], 45)
        self.assertEqual(r["evidence"], "Cipher(algorithms.ChaCha20(key, nonce), mode=None)")
        self.assertEqual(r["library"], "cryptography")
        self.assertEqual(r["confidence"], 0.95)

        # Verify added risk fields
        self.assertIn("risk_score", r)
        self.assertIn("risk_level", r)
        self.assertIn("risk_reason", r)
        self.assertIsInstance(r["risk_score"], int)
        self.assertIsInstance(r["risk_level"], str)
        self.assertIsInstance(r["risk_reason"], str)

    def test_10_deterministic_ordering(self):
        """10. Results are deterministically sorted by file, line, algorithm."""
        findings = [
            {
                "algorithm": "SHA-256",
                "variant": None,
                "file": "b.py",
                "line": 10,
                "confidence": 1.0,
                "context": "hashing",
                "context_confidence": 1.0,
            },
            {
                "algorithm": "RSA",
                "variant": None,
                "file": "a.py",
                "line": 10,
                "confidence": 1.0,
                "context": "digital_signature",
                "context_confidence": 1.0,
            },
            {
                "algorithm": "AES",
                "variant": None,
                "file": "a.py",
                "line": 10,
                "confidence": 1.0,
                "context": "encryption",
                "context_confidence": 1.0,
            },
            {
                "algorithm": "AES",
                "variant": None,
                "file": "a.py",
                "line": 5,
                "confidence": 1.0,
                "context": "encryption",
                "context_confidence": 1.0,
            },
        ]
        results = calculate_risk(findings)
        self.assertEqual(results[0]["file"], "a.py")
        self.assertEqual(results[0]["line"], 5)
        self.assertEqual(results[0]["algorithm"], "AES")

        self.assertEqual(results[1]["file"], "a.py")
        self.assertEqual(results[1]["line"], 10)
        self.assertEqual(results[1]["algorithm"], "AES")

        self.assertEqual(results[2]["file"], "a.py")
        self.assertEqual(results[2]["line"], 10)
        self.assertEqual(results[2]["algorithm"], "RSA")

        self.assertEqual(results[3]["file"], "b.py")
        self.assertEqual(results[3]["line"], 10)
        self.assertEqual(results[3]["algorithm"], "SHA-256")


if __name__ == "__main__":
    unittest.main()
