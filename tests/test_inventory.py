"""Unit tests for Qrypta Crypto Inventory module."""

import json
import unittest
from qrypta.scanner.models import Finding
from qrypta.inventory.builder import build_inventory


class TestCryptoInventory(unittest.TestCase):
    """Test suite for Crypto Inventory builder."""

    def test_1_empty_findings(self):
        """1. Empty findings produces empty inventory structure with zero counts."""
        inventory = build_inventory([])
        self.assertEqual(
            inventory,
            {
                "summary": {
                    "total_findings": 0,
                    "unique_algorithms": 0,
                    "unique_primitives": 0,
                },
                "algorithms": [],
            },
        )

    def test_2_one_finding(self):
        """2. Single finding produces correct inventory summary and algorithm entry."""
        finding = Finding(
            algorithm="RSA",
            variant="2048-bit",
            primitive="asymmetric_encryption",
            usage="key_generation",
            file="auth.py",
            line=42,
            evidence="rsa.generate_private_key(65537, 2048)",
            library="cryptography",
            confidence=0.95,
        )
        inventory = build_inventory([finding])

        self.assertEqual(inventory["summary"]["total_findings"], 1)
        self.assertEqual(inventory["summary"]["unique_algorithms"], 1)
        self.assertEqual(inventory["summary"]["unique_primitives"], 1)

        self.assertEqual(len(inventory["algorithms"]), 1)
        algo_entry = inventory["algorithms"][0]
        self.assertEqual(algo_entry["algorithm"], "RSA")
        self.assertEqual(algo_entry["variants"], ["2048-bit"])
        self.assertEqual(algo_entry["primitive"], "asymmetric_encryption")
        self.assertEqual(algo_entry["occurrence_count"], 1)
        self.assertEqual(algo_entry["libraries"], ["cryptography"])
        self.assertEqual(
            algo_entry["locations"],
            [
                {
                    "file": "auth.py",
                    "line": 42,
                    "evidence": "rsa.generate_private_key(65537, 2048)",
                    "confidence": 0.95,
                }
            ],
        )

    def test_3_multiple_findings_same_algorithm(self):
        """3. Multiple findings of the same algorithm increment occurrence count."""
        f1 = Finding(
            algorithm="AES",
            variant="AES-GCM",
            primitive="symmetric_encryption",
            usage="encryption",
            file="c1.py",
            line=10,
            evidence="AES.new(k, AES.MODE_GCM)",
            library="pycryptodome",
            confidence=0.95,
        )
        f2 = Finding(
            algorithm="AES",
            variant="AES-CBC",
            primitive="symmetric_encryption",
            usage="encryption",
            file="c2.py",
            line=20,
            evidence="AES.new(k, AES.MODE_CBC)",
            library="pycryptodome",
            confidence=0.95,
        )
        inventory = build_inventory([f1, f2])

        self.assertEqual(inventory["summary"]["total_findings"], 2)
        self.assertEqual(inventory["summary"]["unique_algorithms"], 1)
        self.assertEqual(inventory["summary"]["unique_primitives"], 1)

        self.assertEqual(len(inventory["algorithms"]), 1)
        algo_entry = inventory["algorithms"][0]
        self.assertEqual(algo_entry["algorithm"], "AES")
        self.assertEqual(algo_entry["occurrence_count"], 2)
        self.assertEqual(len(algo_entry["locations"]), 2)

    def test_4_multiple_variants(self):
        """4. Multiple variants are aggregated and sorted alphabetically."""
        f1 = Finding(
            algorithm="AES",
            variant="AES-256-GCM",
            primitive="symmetric_encryption",
            usage="encryption",
            file="f1.js",
            line=5,
            evidence="createCipheriv('aes-256-gcm', k, iv)",
            library="crypto",
            confidence=0.95,
        )
        f2 = Finding(
            algorithm="AES",
            variant="AES-128-CBC",
            primitive="symmetric_encryption",
            usage="encryption",
            file="f2.js",
            line=12,
            evidence="createCipheriv('aes-128-cbc', k, iv)",
            library="crypto",
            confidence=0.95,
        )
        f3 = Finding(
            algorithm="AES",
            variant=None,
            primitive="symmetric_encryption",
            usage="encryption",
            file="f3.js",
            line=18,
            evidence="CryptoJS.AES.encrypt()",
            library="crypto-js",
            confidence=0.90,
        )
        inventory = build_inventory([f1, f2, f3])
        algo_entry = inventory["algorithms"][0]
        # None should be omitted and remaining sorted alphabetically
        self.assertEqual(algo_entry["variants"], ["AES-128-CBC", "AES-256-GCM"])

    def test_5_multiple_libraries(self):
        """5. Multiple libraries are aggregated and sorted alphabetically."""
        f1 = Finding(
            algorithm="SHA-256",
            variant=None,
            primitive="hash_function",
            usage="hashing",
            file="a.py",
            line=1,
            evidence="hashlib.sha256()",
            library="hashlib",
            confidence=0.95,
        )
        f2 = Finding(
            algorithm="SHA-256",
            variant=None,
            primitive="hash_function",
            usage="hashing",
            file="b.py",
            line=2,
            evidence="hashes.SHA256()",
            library="cryptography",
            confidence=0.95,
        )
        inventory = build_inventory([f1, f2])
        algo_entry = inventory["algorithms"][0]
        self.assertEqual(algo_entry["libraries"], ["cryptography", "hashlib"])

    def test_6_multiple_source_locations(self):
        """6. Multiple source locations are sorted by file path then line number."""
        f1 = Finding(
            algorithm="RSA",
            variant="2048-bit",
            primitive="asymmetric_encryption",
            usage="key_generation",
            file="z_file.py",
            line=50,
            evidence="line 50",
            library="cryptography",
            confidence=0.95,
        )
        f2 = Finding(
            algorithm="RSA",
            variant="2048-bit",
            primitive="asymmetric_encryption",
            usage="key_generation",
            file="a_file.py",
            line=100,
            evidence="line 100",
            library="cryptography",
            confidence=0.95,
        )
        f3 = Finding(
            algorithm="RSA",
            variant="2048-bit",
            primitive="asymmetric_encryption",
            usage="key_generation",
            file="a_file.py",
            line=10,
            evidence="line 10",
            library="cryptography",
            confidence=0.95,
        )
        inventory = build_inventory([f1, f2, f3])
        locations = inventory["algorithms"][0]["locations"]

        self.assertEqual(len(locations), 3)
        self.assertEqual(locations[0]["file"], "a_file.py")
        self.assertEqual(locations[0]["line"], 10)
        self.assertEqual(locations[1]["file"], "a_file.py")
        self.assertEqual(locations[1]["line"], 100)
        self.assertEqual(locations[2]["file"], "z_file.py")
        self.assertEqual(locations[2]["line"], 50)

    def test_7_duplicate_identical_findings(self):
        """7. Completely identical findings are deduplicated to a single instance."""
        f1 = Finding(
            algorithm="SHA-256",
            variant=None,
            primitive="hash_function",
            usage="hashing",
            file="app.py",
            line=15,
            evidence="hashlib.sha256(data)",
            library="hashlib",
            confidence=0.95,
        )
        # Duplicate of f1
        f2 = Finding(
            algorithm="SHA-256",
            variant=None,
            primitive="hash_function",
            usage="hashing",
            file="app.py",
            line=15,
            evidence="hashlib.sha256(data)",
            library="hashlib",
            confidence=0.95,
        )
        # Different line number -> not duplicate
        f3 = Finding(
            algorithm="SHA-256",
            variant=None,
            primitive="hash_function",
            usage="hashing",
            file="app.py",
            line=16,
            evidence="hashlib.sha256(data)",
            library="hashlib",
            confidence=0.95,
        )

        inventory = build_inventory([f1, f2, f3])
        self.assertEqual(inventory["summary"]["total_findings"], 2)
        self.assertEqual(inventory["algorithms"][0]["occurrence_count"], 2)

    def test_8_preservation_of_fields(self):
        """8. File, line, evidence, and confidence values are exactly preserved."""
        f = Finding(
            algorithm="Ed25519",
            variant=None,
            primitive="asymmetric_signature",
            usage="signature",
            file="src/crypto/signer.ts",
            line=88,
            evidence="crypto.generateKeyPairSync('ed25519')",
            library="crypto",
            confidence=0.92,
        )
        inventory = build_inventory([f])
        loc = inventory["algorithms"][0]["locations"][0]

        self.assertEqual(loc["file"], "src/crypto/signer.ts")
        self.assertEqual(loc["line"], 88)
        self.assertEqual(loc["evidence"], "crypto.generateKeyPairSync('ed25519')")
        self.assertEqual(loc["confidence"], 0.92)

    def test_9_deterministic_ordering(self):
        """9. Algorithms, variants, libraries, and locations are all deterministically ordered."""
        findings = [
            Finding(
                algorithm="SHA-512",
                variant=None,
                primitive="hash_function",
                usage="hashing",
                file="b.py",
                line=2,
                evidence="sha512",
                library="libB",
                confidence=0.9,
            ),
            Finding(
                algorithm="AES",
                variant="AES-GCM",
                primitive="symmetric_encryption",
                usage="encryption",
                file="c.py",
                line=1,
                evidence="aes-gcm",
                library="libC",
                confidence=0.9,
            ),
            Finding(
                algorithm="AES",
                variant="AES-CBC",
                primitive="symmetric_encryption",
                usage="encryption",
                file="a.py",
                line=1,
                evidence="aes-cbc",
                library="libA",
                confidence=0.9,
            ),
        ]
        inventory = build_inventory(findings)
        algo_names = [a["algorithm"] for a in inventory["algorithms"]]
        self.assertEqual(algo_names, ["AES", "SHA-512"])

        aes_entry = inventory["algorithms"][0]
        self.assertEqual(aes_entry["variants"], ["AES-CBC", "AES-GCM"])
        self.assertEqual(aes_entry["libraries"], ["libA", "libC"])
        self.assertEqual(aes_entry["locations"][0]["file"], "a.py")
        self.assertEqual(aes_entry["locations"][1]["file"], "c.py")

    def test_10_json_serialization(self):
        """10. Inventory output serializes to valid JSON matching the exact schema."""
        finding = {
            "algorithm": "RS256",
            "variant": "RSA-SHA256",
            "primitive": "jwt_signature",
            "usage": "token_signing",
            "file": "src/auth.py",
            "line": 42,
            "evidence": "jwt.encode(payload, key, algorithm='RS256')",
            "library": "PyJWT",
            "confidence": 0.98,
        }
        inventory = build_inventory([finding])
        json_str = json.dumps(inventory, indent=2)
        parsed = json.loads(json_str)

        self.assertIn("summary", parsed)
        self.assertIn("algorithms", parsed)
        self.assertEqual(parsed["summary"]["total_findings"], 1)
        self.assertEqual(parsed["summary"]["unique_algorithms"], 1)
        self.assertEqual(parsed["summary"]["unique_primitives"], 1)

        algo = parsed["algorithms"][0]
        self.assertEqual(algo["algorithm"], "RS256")
        self.assertEqual(algo["variants"], ["RSA-SHA256"])
        self.assertEqual(algo["primitive"], "jwt_signature")
        self.assertEqual(algo["occurrence_count"], 1)
        self.assertEqual(algo["libraries"], ["PyJWT"])
        self.assertEqual(len(algo["locations"]), 1)


if __name__ == "__main__":
    unittest.main()
