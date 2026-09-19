"""Unit tests for Qrypta Context Analysis module."""

import unittest
from qrypta.scanner.models import Finding
from qrypta.context.analyzer import (
    analyze_context,
    CONTEXT_DIGITAL_SIGNATURE,
    CONTEXT_KEY_EXCHANGE,
    CONTEXT_ENCRYPTION,
    CONTEXT_HASHING,
    CONTEXT_AUTHENTICATION,
    CONTEXT_JWT_SIGNATURE,
    CONTEXT_TLS,
    CONTEXT_CERTIFICATE,
    CONTEXT_UNKNOWN,
)


class TestContextAnalysis(unittest.TestCase):
    """Test suite for Context Analysis."""

    def test_1_jwt_signature_detection(self):
        """1. JWT signature detection."""
        f = Finding(
            algorithm="RS256",
            variant="RSA-SHA256",
            primitive="jwt_signature",
            usage="token_signing",
            file="auth.py",
            line=10,
            evidence="jwt.encode(payload, secret, algorithm='RS256')",
            library="PyJWT",
            confidence=0.95,
        )
        results = analyze_context([f])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["context"], CONTEXT_JWT_SIGNATURE)
        self.assertIn("jwt", results[0]["context_reason"].lower())
        self.assertGreaterEqual(results[0]["context_confidence"], 0.9)

    def test_2_digital_signature_detection(self):
        """2. Digital signature detection."""
        f = Finding(
            algorithm="Ed25519",
            variant=None,
            primitive="asymmetric_signature",
            usage="signature",
            file="signer.py",
            line=25,
            evidence="signature = private_key.sign(data)",
            library="cryptography",
            confidence=0.95,
        )
        results = analyze_context([f])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["context"], CONTEXT_DIGITAL_SIGNATURE)
        self.assertIn("signature", results[0]["context_reason"].lower())

    def test_3_key_exchange_detection(self):
        """3. Key exchange detection."""
        f = Finding(
            algorithm="Diffie-Hellman",
            variant="2048-bit",
            primitive="asymmetric_key_exchange",
            usage="key_generation",
            file="dh_kex.py",
            line=40,
            evidence="dh_params = dh.generate_parameters(generator=2, key_size=2048)",
            library="cryptography",
            confidence=0.95,
        )
        results = analyze_context([f])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["context"], CONTEXT_KEY_EXCHANGE)
        self.assertIn("key", results[0]["context_reason"].lower())

    def test_4_encryption_detection(self):
        """4. Encryption detection."""
        f = Finding(
            algorithm="AES",
            variant="AES-256-GCM",
            primitive="symmetric_encryption",
            usage="encryption",
            file="crypto.js",
            line=50,
            evidence="const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);",
            library="crypto",
            confidence=0.95,
        )
        results = analyze_context([f])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["context"], CONTEXT_ENCRYPTION)
        self.assertIn("encryption", results[0]["context_reason"].lower())

    def test_5_hashing_detection(self):
        """5. Hashing detection."""
        f = Finding(
            algorithm="SHA-256",
            variant=None,
            primitive="hash_function",
            usage="hashing",
            file="hash.py",
            line=12,
            evidence="digest = hashlib.sha256(data).hexdigest()",
            library="hashlib",
            confidence=0.95,
        )
        results = analyze_context([f])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["context"], CONTEXT_HASHING)
        self.assertIn("hash", results[0]["context_reason"].lower())

    def test_6_tls_detection(self):
        """6. TLS detection."""
        f = Finding(
            algorithm="TLS",
            variant="TLS 1.3",
            primitive="protocol",
            usage="protocol_configuration",
            file="server.ts",
            line=80,
            evidence="const options = { minVersion: 'TLSv1.3' };",
            library="tls",
            confidence=0.95,
        )
        results = analyze_context([f])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["context"], CONTEXT_TLS)
        self.assertIn("tls", results[0]["context_reason"].lower())

    def test_7_certificate_detection(self):
        """7. Certificate detection where explicit evidence exists."""
        f = Finding(
            algorithm="RSA",
            variant="2048-bit",
            primitive="asymmetric_encryption",
            usage="signature",
            file="pki.py",
            line=65,
            evidence="cert = x509.CertificateBuilder().sign(private_key, hashes.SHA256())",
            library="cryptography",
            confidence=0.95,
        )
        results = analyze_context([f])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["context"], CONTEXT_CERTIFICATE)
        self.assertIn("certificate", results[0]["context_reason"].lower())

    def test_8_unknown_context_insufficient_evidence(self):
        """8. Unknown context when evidence is insufficient."""
        f = Finding(
            algorithm="AES",
            variant=None,
            primitive="symmetric_encryption",
            usage="import",
            file="imports.py",
            line=1,
            evidence="from Crypto.Cipher import AES",
            library="pycryptodome",
            confidence=0.85,
        )
        results = analyze_context([f])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["context"], CONTEXT_UNKNOWN)
        self.assertEqual(results[0]["context_confidence"], 0.0)

    def test_9_preservation_of_fields(self):
        """9. Preservation of all original finding fields."""
        f = Finding(
            algorithm="ECDSA",
            variant="P-256",
            primitive="asymmetric_signature",
            usage="signature",
            file="ecdsa.py",
            line=33,
            evidence="verifier.verify(sig, msg)",
            library="cryptography",
            confidence=0.91,
        )
        results = analyze_context([f])
        r = results[0]

        self.assertEqual(r["algorithm"], "ECDSA")
        self.assertEqual(r["variant"], "P-256")
        self.assertEqual(r["primitive"], "asymmetric_signature")
        self.assertEqual(r["usage"], "signature")
        self.assertEqual(r["file"], "ecdsa.py")
        self.assertEqual(r["line"], 33)
        self.assertEqual(r["evidence"], "verifier.verify(sig, msg)")
        self.assertEqual(r["library"], "cryptography")
        self.assertEqual(r["confidence"], 0.91)
        self.assertIn("context", r)
        self.assertIn("context_reason", r)
        self.assertIn("context_confidence", r)

    def test_10_deterministic_ordering(self):
        """10. Deterministic ordering sorted by file and line."""
        findings = [
            Finding(
                algorithm="SHA-256",
                variant=None,
                primitive="hash_function",
                usage="hashing",
                file="b.py",
                line=50,
                evidence="hashlib.sha256()",
                library="hashlib",
                confidence=0.9,
            ),
            Finding(
                algorithm="AES",
                variant=None,
                primitive="symmetric_encryption",
                usage="encryption",
                file="a.py",
                line=100,
                evidence="AES.new(k)",
                library="pycryptodome",
                confidence=0.9,
            ),
            Finding(
                algorithm="RSA",
                variant=None,
                primitive="asymmetric_encryption",
                usage="key_generation",
                file="a.py",
                line=10,
                evidence="rsa.generate_private_key()",
                library="cryptography",
                confidence=0.9,
            ),
        ]
        results = analyze_context(findings)
        self.assertEqual(results[0]["file"], "a.py")
        self.assertEqual(results[0]["line"], 10)
        self.assertEqual(results[1]["file"], "a.py")
        self.assertEqual(results[1]["line"], 100)
        self.assertEqual(results[2]["file"], "b.py")
        self.assertEqual(results[2]["line"], 50)

    def test_11_context_confidence_range(self):
        """11. Context confidence range is strictly between 0 and 1."""
        findings = [
            Finding(
                algorithm="RS256",
                variant=None,
                primitive="jwt_signature",
                usage="token_signing",
                file="1.py",
                line=1,
                evidence="jwt.sign()",
                library="jwt",
                confidence=0.9,
            ),
            Finding(
                algorithm="UnknownAlgo",
                variant=None,
                primitive="unknown",
                usage="import",
                file="2.py",
                line=2,
                evidence="import UnknownAlgo",
                library=None,
                confidence=0.5,
            ),
        ]
        results = analyze_context(findings)
        for r in results:
            self.assertGreaterEqual(r["context_confidence"], 0.0)
            self.assertLessEqual(r["context_confidence"], 1.0)


if __name__ == "__main__":
    unittest.main()
