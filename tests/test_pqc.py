"""Unit tests for Qrypta PQC Mapper module."""

import unittest
from qrypta.pqc.mapper import (
    map_to_pqc,
    PQC_ALGO_ML_DSA,
    PQC_ALGO_ML_KEM,
    MIGRATION_PQC_REPLACEMENT,
    MIGRATION_SYMMETRIC_UPGRADE,
    MIGRATION_NO_PQC_REPLACEMENT,
    MIGRATION_MANUAL_REVIEW,
)


class TestPQCMapper(unittest.TestCase):
    """Test suite for PQC Mapper."""

    def test_1_rsa_digital_signature(self):
        """1. RSA digital signature maps to ML-DSA."""
        finding = {
            "algorithm": "RSA",
            "variant": "2048-bit",
            "primitive": "asymmetric_signature",
            "usage": "signature",
            "context": "digital_signature",
            "context_reason": "Signature operation detected",
            "context_confidence": 0.95,
            "risk_score": 90,
            "risk_level": "critical",
            "risk_reason": "Quantum vulnerable",
            "file": "sign.py",
            "line": 10,
            "evidence": "key.sign(data)",
            "library": "cryptography",
            "confidence": 0.95,
        }
        results = map_to_pqc([finding])
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r["recommended_algorithm"], PQC_ALGO_ML_DSA)
        self.assertEqual(r["migration_type"], MIGRATION_PQC_REPLACEMENT)
        self.assertIn("ML-DSA", r["mapping_reason"])

    def test_2_ecdsa_digital_signature(self):
        """2. ECDSA digital signature maps to ML-DSA."""
        finding = {
            "algorithm": "ECDSA",
            "variant": "P-256",
            "primitive": "asymmetric_signature",
            "usage": "signature",
            "context": "digital_signature",
            "context_reason": "Signature operation detected",
            "context_confidence": 0.95,
            "risk_score": 90,
            "risk_level": "critical",
            "risk_reason": "Quantum vulnerable",
            "file": "ecdsa_sign.py",
            "line": 15,
            "evidence": "signer.sign(data)",
            "library": "cryptography",
            "confidence": 0.95,
        }
        results = map_to_pqc([finding])
        r = results[0]
        self.assertEqual(r["recommended_algorithm"], PQC_ALGO_ML_DSA)
        self.assertEqual(r["migration_type"], MIGRATION_PQC_REPLACEMENT)

    def test_3_ecdh_key_exchange(self):
        """3. ECDH key exchange maps to ML-KEM."""
        finding = {
            "algorithm": "ECDH",
            "variant": "P-256",
            "primitive": "asymmetric_key_exchange",
            "usage": "key_exchange",
            "context": "key_exchange",
            "context_reason": "Key exchange detected",
            "context_confidence": 0.95,
            "risk_score": 90,
            "risk_level": "critical",
            "risk_reason": "Quantum vulnerable",
            "file": "kex.js",
            "line": 20,
            "evidence": "crypto.createECDH('prime256v1')",
            "library": "crypto",
            "confidence": 0.95,
        }
        results = map_to_pqc([finding])
        r = results[0]
        self.assertEqual(r["recommended_algorithm"], PQC_ALGO_ML_KEM)
        self.assertEqual(r["migration_type"], MIGRATION_PQC_REPLACEMENT)
        self.assertIn("ML-KEM", r["mapping_reason"])

    def test_4_dh_key_exchange(self):
        """4. DH key exchange maps to ML-KEM."""
        finding = {
            "algorithm": "Diffie-Hellman",
            "variant": "2048-bit",
            "primitive": "asymmetric_key_exchange",
            "usage": "key_generation",
            "context": "key_exchange",
            "context_reason": "Key exchange detected",
            "context_confidence": 0.95,
            "risk_score": 90,
            "risk_level": "critical",
            "risk_reason": "Quantum vulnerable",
            "file": "dh.py",
            "line": 30,
            "evidence": "dh.generate_parameters(2, 2048)",
            "library": "cryptography",
            "confidence": 0.95,
        }
        results = map_to_pqc([finding])
        r = results[0]
        self.assertEqual(r["recommended_algorithm"], PQC_ALGO_ML_KEM)
        self.assertEqual(r["migration_type"], MIGRATION_PQC_REPLACEMENT)

    def test_5_rsa_jwt_signature(self):
        """5. RSA JWT signature maps to ML-DSA."""
        finding = {
            "algorithm": "RS256",
            "variant": "RSA-SHA256",
            "primitive": "jwt_signature",
            "usage": "token_signing",
            "context": "jwt_signature",
            "context_reason": "JWT token signing detected",
            "context_confidence": 0.95,
            "risk_score": 90,
            "risk_level": "critical",
            "risk_reason": "Quantum vulnerable",
            "file": "auth.py",
            "line": 40,
            "evidence": "jwt.encode(payload, key, algorithm='RS256')",
            "library": "PyJWT",
            "confidence": 0.95,
        }
        results = map_to_pqc([finding])
        r = results[0]
        self.assertEqual(r["recommended_algorithm"], PQC_ALGO_ML_DSA)
        self.assertEqual(r["migration_type"], MIGRATION_PQC_REPLACEMENT)

    def test_6_aes_encryption_no_pqc(self):
        """6. AES encryption has no direct PQC replacement."""
        finding = {
            "algorithm": "AES",
            "variant": "AES-256-GCM",
            "primitive": "symmetric_encryption",
            "usage": "encryption",
            "context": "encryption",
            "context_reason": "Cipher operation detected",
            "context_confidence": 1.0,
            "risk_score": 35,
            "risk_level": "low",
            "risk_reason": "Symmetric cipher",
            "file": "encrypt.py",
            "line": 50,
            "evidence": "Cipher(algorithms.AES(key), modes.GCM(iv))",
            "library": "cryptography",
            "confidence": 1.0,
        }
        results = map_to_pqc([finding])
        r = results[0]
        self.assertIsNone(r["recommended_algorithm"])
        self.assertEqual(r["migration_type"], MIGRATION_NO_PQC_REPLACEMENT)

    def test_7_sha1_hashing_symmetric_upgrade(self):
        """7. SHA-1 hashing maps to symmetric upgrade."""
        finding = {
            "algorithm": "SHA-1",
            "variant": None,
            "primitive": "hash_function",
            "usage": "hashing",
            "context": "hashing",
            "context_reason": "Digest operation detected",
            "context_confidence": 1.0,
            "risk_score": 95,
            "risk_level": "critical",
            "risk_reason": "Broken hash",
            "file": "hash.py",
            "line": 60,
            "evidence": "hashlib.sha1(data)",
            "library": "hashlib",
            "confidence": 1.0,
        }
        results = map_to_pqc([finding])
        r = results[0]
        self.assertIsNone(r["recommended_algorithm"])
        self.assertEqual(r["migration_type"], MIGRATION_SYMMETRIC_UPGRADE)
        self.assertIn("SHA-256", r["mapping_reason"])

    def test_8_sha256_hashing_no_pqc(self):
        """8. SHA-256 hashing has no PQC replacement required."""
        finding = {
            "algorithm": "SHA-256",
            "variant": None,
            "primitive": "hash_function",
            "usage": "hashing",
            "context": "hashing",
            "context_reason": "Digest operation detected",
            "context_confidence": 1.0,
            "risk_score": 30,
            "risk_level": "low",
            "risk_reason": "Secure hash",
            "file": "secure_hash.py",
            "line": 70,
            "evidence": "hashlib.sha256(data)",
            "library": "hashlib",
            "confidence": 1.0,
        }
        results = map_to_pqc([finding])
        r = results[0]
        self.assertIsNone(r["recommended_algorithm"])
        self.assertEqual(r["migration_type"], MIGRATION_NO_PQC_REPLACEMENT)

    def test_9_ambiguous_usage_manual_review(self):
        """9. Ambiguous / unknown usage maps to manual review."""
        finding = {
            "algorithm": "CustomCrypto",
            "variant": None,
            "primitive": "unknown",
            "usage": "unknown",
            "context": "unknown",
            "context_reason": "Insufficient evidence",
            "context_confidence": 0.0,
            "risk_score": 50,
            "risk_level": "medium",
            "risk_reason": "Unknown algorithm",
            "file": "custom.py",
            "line": 80,
            "evidence": "import CustomCrypto",
            "library": None,
            "confidence": 0.5,
        }
        results = map_to_pqc([finding])
        r = results[0]
        self.assertIsNone(r["recommended_algorithm"])
        self.assertEqual(r["migration_type"], MIGRATION_MANUAL_REVIEW)

    def test_10_output_field_preservation(self):
        """10. All input fields are preserved in the PQC output."""
        finding = {
            "algorithm": "Ed25519",
            "variant": None,
            "primitive": "asymmetric_signature",
            "usage": "key_generation",
            "context": "digital_signature",
            "context_reason": "Digital signature key operation",
            "context_confidence": 0.95,
            "risk_score": 90,
            "risk_level": "critical",
            "risk_reason": "Quantum vulnerable signature",
            "file": "keys.py",
            "line": 90,
            "evidence": "ed25519.Ed25519PrivateKey.generate()",
            "library": "cryptography",
            "confidence": 0.95,
        }
        results = map_to_pqc([finding])
        r = results[0]

        # Verify all input fields preserved
        for key in finding:
            self.assertEqual(r[key], finding[key])

        # Verify new fields present
        self.assertIn("recommended_algorithm", r)
        self.assertIn("migration_type", r)
        self.assertIn("mapping_reason", r)

    def test_11_deterministic_ordering(self):
        """11. Results are deterministically sorted by file, line, algorithm."""
        findings = [
            {"algorithm": "SHA-256", "file": "b.py", "line": 10, "context": "hashing"},
            {"algorithm": "RSA", "file": "a.py", "line": 10, "context": "digital_signature"},
            {"algorithm": "AES", "file": "a.py", "line": 10, "context": "encryption"},
            {"algorithm": "AES", "file": "a.py", "line": 5, "context": "encryption"},
        ]
        results = map_to_pqc(findings)
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
