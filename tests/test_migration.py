"""Unit tests for Qrypta Migration Plan module."""

import unittest
from qrypta.migration.planner import (
    create_migration_plan,
    PLAN_ML_DSA_ACTION,
    PLAN_ML_DSA_STEPS,
    PLAN_ML_DSA_VALIDATION,
    PLAN_ML_KEM_ACTION,
    PLAN_ML_KEM_STEPS,
    PLAN_ML_KEM_VALIDATION,
    PLAN_LEGACY_ACTION,
    PLAN_LEGACY_STEPS,
    PLAN_LEGACY_VALIDATION,
    PLAN_MODERN_SYMMETRIC_ACTION,
    PLAN_MODERN_SYMMETRIC_STEPS,
    PLAN_MODERN_SYMMETRIC_VALIDATION,
    PLAN_SECURE_HASH_ACTION,
    PLAN_SECURE_HASH_STEPS,
    PLAN_SECURE_HASH_VALIDATION,
    PLAN_MANUAL_REVIEW_ACTION,
    PLAN_MANUAL_REVIEW_STEPS,
    PLAN_MANUAL_REVIEW_VALIDATION,
)


class MockFinding:
    """Mock finding object implementing to_dict()."""

    def __init__(self, data):
        self.data = data

    def to_dict(self):
        return dict(self.data)


class TestMigrationPlanner(unittest.TestCase):
    """Test suite for Migration Planner."""

    def test_1_ml_dsa_migration_plan(self):
        """1. ML-DSA migration plan generated for signature findings."""
        findings = [
            {
                "algorithm": "RSA",
                "variant": "2048-bit",
                "primitive": "asymmetric_signature",
                "usage": "signature",
                "context": "digital_signature",
                "context_reason": "Signature operation detected",
                "context_confidence": 0.95,
                "risk_score": 90,
                "risk_level": "critical",
                "recommended_algorithm": "ML-DSA",
                "migration_type": "pqc_replacement",
                "mapping_reason": "Asymmetric digital signature is vulnerable to Shor's algorithm",
                "file": "sign.py",
                "line": 10,
                "evidence": "key.sign(data)",
                "library": "cryptography",
                "confidence": 0.95,
            },
            {
                "algorithm": "ECDSA",
                "variant": "P-256",
                "primitive": "asymmetric_signature",
                "usage": "signature",
                "context": "digital_signature",
                "context_reason": "ECDSA signature detected",
                "context_confidence": 0.95,
                "risk_score": 90,
                "risk_level": "critical",
                "recommended_algorithm": "ML-DSA",
                "migration_type": "pqc_replacement",
                "mapping_reason": "Asymmetric digital signature is vulnerable to Shor's algorithm",
                "file": "ecdsa.py",
                "line": 20,
                "evidence": "signer.sign(data)",
                "library": "cryptography",
                "confidence": 0.95,
            },
            {
                "algorithm": "RS256",
                "variant": "RSA-SHA256",
                "primitive": "jwt_signature",
                "usage": "token_signing",
                "context": "jwt_signature",
                "context_reason": "JWT token signing detected",
                "context_confidence": 0.95,
                "risk_score": 90,
                "risk_level": "critical",
                "recommended_algorithm": "ML-DSA",
                "migration_type": "pqc_replacement",
                "mapping_reason": "Asymmetric JWT signing algorithm is vulnerable to Shor's algorithm",
                "file": "auth.py",
                "line": 30,
                "evidence": "jwt.encode(payload, key, algorithm='RS256')",
                "library": "PyJWT",
                "confidence": 0.95,
            },
            {
                "algorithm": "Ed25519",
                "variant": None,
                "primitive": "asymmetric_signature",
                "usage": "certificate",
                "context": "certificate",
                "context_reason": "Certificate signature detected",
                "context_confidence": 0.95,
                "risk_score": 90,
                "risk_level": "critical",
                "recommended_algorithm": "ML-DSA",
                "migration_type": "pqc_replacement",
                "mapping_reason": "X.509 certificate signature is vulnerable to quantum cryptanalysis",
                "file": "cert.py",
                "line": 40,
                "evidence": "builder.sign(key)",
                "library": "cryptography",
                "confidence": 0.95,
            },
        ]
        results = create_migration_plan(findings)
        self.assertEqual(len(results), 4)
        for r in results:
            plan = r["migration_plan"]
            self.assertEqual(plan["action"], PLAN_ML_DSA_ACTION)
            self.assertEqual(plan["action"], "Replace the existing signature mechanism with ML-DSA.")
            self.assertEqual(plan["steps"], PLAN_ML_DSA_STEPS)
            self.assertEqual(plan["validation"], PLAN_ML_DSA_VALIDATION)

    def test_2_ml_kem_migration_plan(self):
        """2. ML-KEM migration plan generated for key exchange findings."""
        findings = [
            {
                "algorithm": "ECDH",
                "variant": "P-256",
                "primitive": "asymmetric_key_exchange",
                "usage": "key_exchange",
                "context": "key_exchange",
                "context_reason": "Key exchange detected",
                "context_confidence": 0.95,
                "risk_score": 90,
                "risk_level": "critical",
                "recommended_algorithm": "ML-KEM",
                "migration_type": "pqc_replacement",
                "mapping_reason": "Asymmetric key exchange is vulnerable to Shor's algorithm",
                "file": "kex.js",
                "line": 20,
                "evidence": "crypto.createECDH('prime256v1')",
                "library": "crypto",
                "confidence": 0.95,
            },
            {
                "algorithm": "Diffie-Hellman",
                "variant": "2048-bit",
                "primitive": "asymmetric_key_exchange",
                "usage": "key_generation",
                "context": "key_exchange",
                "context_reason": "Key exchange detected",
                "context_confidence": 0.95,
                "risk_score": 90,
                "risk_level": "critical",
                "recommended_algorithm": "ML-KEM",
                "migration_type": "pqc_replacement",
                "mapping_reason": "Asymmetric key exchange is vulnerable to Shor's algorithm",
                "file": "dh.py",
                "line": 30,
                "evidence": "dh.generate_parameters(2, 2048)",
                "library": "cryptography",
                "confidence": 0.95,
            },
        ]
        results = create_migration_plan(findings)
        self.assertEqual(len(results), 2)
        for r in results:
            plan = r["migration_plan"]
            self.assertEqual(plan["action"], PLAN_ML_KEM_ACTION)
            self.assertEqual(plan["action"], "Replace the existing key-establishment mechanism with ML-KEM.")
            self.assertEqual(plan["steps"], PLAN_ML_KEM_STEPS)
            self.assertEqual(plan["validation"], PLAN_ML_KEM_VALIDATION)

    def test_3_legacy_cryptography_migration_plan(self):
        """3. Legacy cryptography migration plan generated for DES, 3DES, MD5, SHA-1."""
        findings = [
            {
                "algorithm": "DES",
                "variant": None,
                "primitive": "symmetric_encryption",
                "usage": "encryption",
                "context": "encryption",
                "context_reason": "Cipher operation detected",
                "context_confidence": 1.0,
                "risk_score": 95,
                "risk_level": "critical",
                "recommended_algorithm": None,
                "migration_type": "symmetric_upgrade",
                "mapping_reason": "Legacy symmetric cipher vulnerable to classical cryptanalysis",
                "file": "des_cipher.py",
                "line": 15,
                "evidence": "DES.new(key, DES.MODE_ECB)",
                "library": "pycryptodome",
                "confidence": 1.0,
            },
            {
                "algorithm": "3DES",
                "variant": None,
                "primitive": "symmetric_encryption",
                "usage": "encryption",
                "context": "encryption",
                "context_reason": "Cipher operation detected",
                "context_confidence": 1.0,
                "risk_score": 95,
                "risk_level": "critical",
                "recommended_algorithm": None,
                "migration_type": "symmetric_upgrade",
                "mapping_reason": "Legacy symmetric cipher vulnerable to classical cryptanalysis",
                "file": "triple_des.py",
                "line": 25,
                "evidence": "DES3.new(key, DES3.MODE_CBC)",
                "library": "pycryptodome",
                "confidence": 1.0,
            },
            {
                "algorithm": "MD5",
                "variant": None,
                "primitive": "hash_function",
                "usage": "hashing",
                "context": "hashing",
                "context_reason": "Digest operation detected",
                "context_confidence": 1.0,
                "risk_score": 95,
                "risk_level": "critical",
                "recommended_algorithm": None,
                "migration_type": "symmetric_upgrade",
                "mapping_reason": "Broken cryptographic hash function with classical collision vulnerability",
                "file": "md5_hash.py",
                "line": 35,
                "evidence": "hashlib.md5(data)",
                "library": "hashlib",
                "confidence": 1.0,
            },
            {
                "algorithm": "SHA-1",
                "variant": None,
                "primitive": "hash_function",
                "usage": "hashing",
                "context": "hashing",
                "context_reason": "Digest operation detected",
                "context_confidence": 1.0,
                "risk_score": 95,
                "risk_level": "critical",
                "recommended_algorithm": None,
                "migration_type": "symmetric_upgrade",
                "mapping_reason": "Broken cryptographic hash function with classical collision vulnerability",
                "file": "sha1_hash.py",
                "line": 45,
                "evidence": "hashlib.sha1(data)",
                "library": "hashlib",
                "confidence": 1.0,
            },
        ]
        results = create_migration_plan(findings)
        self.assertEqual(len(results), 4)
        for r in results:
            plan = r["migration_plan"]
            self.assertEqual(plan["action"], PLAN_LEGACY_ACTION)
            self.assertEqual(
                plan["action"],
                "Replace the legacy cryptographic primitive with a modern secure alternative.",
            )
            self.assertEqual(plan["steps"], PLAN_LEGACY_STEPS)
            self.assertEqual(plan["validation"], PLAN_LEGACY_VALIDATION)

    def test_4_aes_no_pqc_plan(self):
        """4. AES and ChaCha20 no-PQC plan generated for modern symmetric ciphers."""
        findings = [
            {
                "algorithm": "AES",
                "variant": "AES-256-GCM",
                "primitive": "symmetric_encryption",
                "usage": "encryption",
                "context": "encryption",
                "context_reason": "Cipher operation detected",
                "context_confidence": 1.0,
                "risk_score": 35,
                "risk_level": "low",
                "recommended_algorithm": None,
                "migration_type": "no_pqc_replacement",
                "mapping_reason": "Modern symmetric ciphers are not vulnerable to Shor's algorithm",
                "file": "encrypt.py",
                "line": 50,
                "evidence": "Cipher(algorithms.AES(key), modes.GCM(iv))",
                "library": "cryptography",
                "confidence": 1.0,
            },
            {
                "algorithm": "ChaCha20",
                "variant": "ChaCha20-Poly1305",
                "primitive": "symmetric_encryption",
                "usage": "encryption",
                "context": "encryption",
                "context_reason": "Stream cipher detected",
                "context_confidence": 1.0,
                "risk_score": 30,
                "risk_level": "low",
                "recommended_algorithm": None,
                "migration_type": "no_pqc_replacement",
                "mapping_reason": "Modern symmetric ciphers are not vulnerable to Shor's algorithm",
                "file": "chacha_encrypt.py",
                "line": 60,
                "evidence": "ChaCha20Poly1305(key)",
                "library": "cryptography",
                "confidence": 1.0,
            },
        ]
        results = create_migration_plan(findings)
        self.assertEqual(len(results), 2)
        for r in results:
            plan = r["migration_plan"]
            self.assertEqual(plan["action"], PLAN_MODERN_SYMMETRIC_ACTION)
            self.assertEqual(plan["action"], "No direct PQC replacement is required.")
            self.assertEqual(plan["steps"], PLAN_MODERN_SYMMETRIC_STEPS)
            self.assertEqual(plan["validation"], PLAN_MODERN_SYMMETRIC_VALIDATION)

    def test_5_secure_hash_no_pqc_plan(self):
        """5. Secure hash no-PQC plan generated for SHA-256, SHA-384, SHA-512, HS256."""
        findings = [
            {
                "algorithm": "SHA-256",
                "variant": None,
                "primitive": "hash_function",
                "usage": "hashing",
                "context": "hashing",
                "context_reason": "Digest operation detected",
                "context_confidence": 1.0,
                "risk_score": 30,
                "risk_level": "low",
                "recommended_algorithm": None,
                "migration_type": "no_pqc_replacement",
                "mapping_reason": "Modern SHA-2 hash family provides adequate collision resistance",
                "file": "secure_hash.py",
                "line": 70,
                "evidence": "hashlib.sha256(data)",
                "library": "hashlib",
                "confidence": 1.0,
            },
            {
                "algorithm": "HS256",
                "variant": "HMAC-SHA256",
                "primitive": "jwt_signature",
                "usage": "token_signing",
                "context": "jwt_signature",
                "context_reason": "HMAC token signing detected",
                "context_confidence": 0.95,
                "risk_score": 30,
                "risk_level": "low",
                "recommended_algorithm": None,
                "migration_type": "no_pqc_replacement",
                "mapping_reason": "Symmetric HMAC-based token signing is not vulnerable to Shor's algorithm",
                "file": "jwt_hmac.py",
                "line": 80,
                "evidence": "jwt.encode(payload, secret, algorithm='HS256')",
                "library": "PyJWT",
                "confidence": 0.95,
            },
        ]
        results = create_migration_plan(findings)
        self.assertEqual(len(results), 2)
        for r in results:
            plan = r["migration_plan"]
            self.assertEqual(plan["action"], PLAN_SECURE_HASH_ACTION)
            self.assertEqual(plan["action"], "No direct PQC replacement is required.")
            self.assertEqual(plan["steps"], PLAN_SECURE_HASH_STEPS)
            self.assertEqual(plan["validation"], PLAN_SECURE_HASH_VALIDATION)

    def test_6_manual_review_plan(self):
        """6. Manual review plan generated for manual_review migration type or unknown."""
        findings = [
            {
                "algorithm": "CustomCrypto",
                "variant": None,
                "primitive": "unknown",
                "usage": "unknown",
                "context": "unknown",
                "context_reason": "Insufficient evidence",
                "context_confidence": 0.0,
                "risk_score": 50,
                "risk_level": "medium",
                "recommended_algorithm": None,
                "migration_type": "manual_review",
                "mapping_reason": "Ambiguous or unrecognized cryptographic usage",
                "file": "custom.py",
                "line": 80,
                "evidence": "import CustomCrypto",
                "library": None,
                "confidence": 0.5,
            },
        ]
        results = create_migration_plan(findings)
        self.assertEqual(len(results), 1)
        plan = results[0]["migration_plan"]
        self.assertEqual(plan["action"], PLAN_MANUAL_REVIEW_ACTION)
        self.assertEqual(plan["action"], "Manually review the cryptographic usage before migration.")
        self.assertEqual(plan["steps"], PLAN_MANUAL_REVIEW_STEPS)
        self.assertEqual(plan["validation"], PLAN_MANUAL_REVIEW_VALIDATION)

    def test_7_existing_field_preservation(self):
        """7. All existing fields from PQC findings are preserved unchanged."""
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
            "recommended_algorithm": "ML-DSA",
            "migration_type": "pqc_replacement",
            "mapping_reason": "Asymmetric digital signature is vulnerable to Shor's algorithm",
            "file": "keys.py",
            "line": 90,
            "evidence": "ed25519.Ed25519PrivateKey.generate()",
            "library": "cryptography",
            "confidence": 0.95,
        }
        results = create_migration_plan([finding])
        self.assertEqual(len(results), 1)
        r = results[0]

        for key, value in finding.items():
            self.assertEqual(r[key], value, f"Field {key} mismatch")

        self.assertIn("migration_plan", r)

    def test_8_required_migration_plan_schema(self):
        """8. migration_plan adheres strictly to the required schema."""
        findings = [
            {
                "algorithm": "RSA",
                "recommended_algorithm": "ML-DSA",
                "migration_type": "pqc_replacement",
                "context": "digital_signature",
                "file": "a.py",
                "line": 1,
            },
            {
                "algorithm": "ECDH",
                "recommended_algorithm": "ML-KEM",
                "migration_type": "pqc_replacement",
                "context": "key_exchange",
                "file": "b.py",
                "line": 2,
            },
            {
                "algorithm": "AES",
                "recommended_algorithm": None,
                "migration_type": "no_pqc_replacement",
                "context": "encryption",
                "file": "c.py",
                "line": 3,
            },
        ]
        results = create_migration_plan(findings)
        for r in results:
            self.assertIn("migration_plan", r)
            plan = r["migration_plan"]
            self.assertIsInstance(plan, dict)
            self.assertIn("action", plan)
            self.assertIn("steps", plan)
            self.assertIn("validation", plan)
            self.assertIsInstance(plan["action"], str)
            self.assertIsInstance(plan["steps"], list)
            self.assertIsInstance(plan["validation"], list)
            self.assertTrue(len(plan["action"]) > 0)
            self.assertTrue(len(plan["steps"]) > 0)
            self.assertTrue(len(plan["validation"]) > 0)
            for step in plan["steps"]:
                self.assertIsInstance(step, str)
            for val in plan["validation"]:
                self.assertIsInstance(val, str)

    def test_9_deterministic_ordering(self):
        """9. Results are deterministically sorted by file, line, algorithm."""
        findings = [
            {"algorithm": "SHA-256", "file": "b.py", "line": 10, "migration_type": "no_pqc_replacement"},
            {"algorithm": "RSA", "file": "a.py", "line": 10, "migration_type": "pqc_replacement", "recommended_algorithm": "ML-DSA"},
            {"algorithm": "AES", "file": "a.py", "line": 10, "migration_type": "no_pqc_replacement"},
            {"algorithm": "AES", "file": "a.py", "line": 5, "migration_type": "no_pqc_replacement"},
        ]
        results = create_migration_plan(findings)
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

    def test_10_object_with_to_dict_and_invalid_items(self):
        """10. Objects implementing to_dict() are supported, invalid items ignored."""
        mock = MockFinding({
            "algorithm": "RSA",
            "file": "mock.py",
            "line": 12,
            "recommended_algorithm": "ML-DSA",
            "migration_type": "pqc_replacement",
        })
        results = create_migration_plan([mock, None, "invalid_string", 123])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["file"], "mock.py")
        self.assertEqual(results[0]["migration_plan"]["action"], PLAN_ML_DSA_ACTION)


if __name__ == "__main__":
    unittest.main()
