"""Migration Planner module for Qrypta."""

from typing import List, Dict, Any, Union, Sequence

# Standard migration plan actions, steps, and validations

PLAN_ML_DSA_ACTION = "Replace the existing signature mechanism with ML-DSA."
PLAN_ML_DSA_STEPS = [
    "Identify all code and configuration paths using the existing signature algorithm.",
    "Introduce ML-DSA using a supported cryptographic library.",
    "Update key generation, signing, verification, and dependent configuration.",
    "Update affected tests and interoperability checks.",
]
PLAN_ML_DSA_VALIDATION = [
    "Verify signatures can be generated and verified successfully.",
    "Run existing application tests.",
    "Verify dependent authentication/certificate/JWT flows remain functional.",
]

PLAN_ML_KEM_ACTION = "Replace the existing key-establishment mechanism with ML-KEM."
PLAN_ML_KEM_STEPS = [
    "Identify all key-establishment code and configuration paths.",
    "Introduce ML-KEM using a supported cryptographic library.",
    "Update key generation, encapsulation, and decapsulation logic.",
    "Update affected tests and interoperability checks.",
]
PLAN_ML_KEM_VALIDATION = [
    "Verify key establishment succeeds.",
    "Verify both parties derive the expected shared secret.",
    "Run existing application tests.",
]

PLAN_LEGACY_ACTION = "Replace the legacy cryptographic primitive with a modern secure alternative."
PLAN_LEGACY_STEPS = [
    "Identify all uses of the legacy primitive.",
    "Select a modern cryptographic alternative appropriate to the usage.",
    "Update affected code and configuration.",
    "Update tests and dependent integrations.",
]
PLAN_LEGACY_VALIDATION = [
    "Verify the new primitive produces the expected security behavior.",
    "Run existing application tests.",
    "Verify dependent functionality remains operational.",
]

PLAN_MODERN_SYMMETRIC_ACTION = "No direct PQC replacement is required."
PLAN_MODERN_SYMMETRIC_STEPS = [
    "Retain the existing symmetric primitive.",
    "Review key sizes and implementation configuration for quantum security.",
    "Monitor future cryptographic guidance.",
]
PLAN_MODERN_SYMMETRIC_VALIDATION = [
    "Verify current encryption/decryption functionality.",
    "Run existing application tests.",
]

PLAN_SECURE_HASH_ACTION = "No direct PQC replacement is required."
PLAN_SECURE_HASH_STEPS = [
    "Retain the existing hash or HMAC primitive.",
    "Review the usage and security configuration.",
    "Monitor future cryptographic guidance.",
]
PLAN_SECURE_HASH_VALIDATION = [
    "Verify current hashing or authentication behavior.",
    "Run existing application tests.",
]

PLAN_MANUAL_REVIEW_ACTION = "Manually review the cryptographic usage before migration."
PLAN_MANUAL_REVIEW_STEPS = [
    "Inspect the source context around the finding.",
    "Determine the cryptographic role and security requirement.",
    "Select an appropriate migration strategy.",
]
PLAN_MANUAL_REVIEW_VALIDATION = [
    "Confirm the cryptographic role before making changes.",
    "Validate the selected migration strategy.",
]

PLAN_TLS_PROTOCOL_STEPS = [
    "Retain the existing protocol configuration.",
    "Review cipher suites and protocol settings for quantum security.",
    "Monitor future cryptographic guidance.",
]
PLAN_TLS_PROTOCOL_VALIDATION = [
    "Verify current network security and connection functionality.",
    "Run existing application tests.",
]

ASYMMETRIC_SIGNATURE_ALGORITHMS = {
    "RSA",
    "ECDSA",
    "ED25519",
    "EDDSA",
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
}

ASYMMETRIC_KEX_ALGORITHMS = {
    "RSA",
    "ECDH",
    "DH",
    "DIFFIE-HELLMAN",
}

LEGACY_BROKEN_ALGORITHMS = {
    "DES",
    "3DES",
    "TRIPLEDES",
    "MD5",
    "SHA-1",
    "SHA1",
}

MODERN_SYMMETRIC_ALGORITHMS = {
    "AES",
    "AES-128",
    "AES-192",
    "AES-256",
    "AES-GCM",
    "AES-CBC",
    "AES-CTR",
    "CHACHA20",
    "CHACHA20-POLY1305",
}

SECURE_HASH_ALGORITHMS = {
    "SHA-256",
    "SHA256",
    "SHA-384",
    "SHA384",
    "SHA-512",
    "SHA512",
    "HS256",
    "HS384",
    "HS512",
}


def _generate_plan_for_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate deterministic migration plan dictionary for a single finding.

    Returns:
        {
            "action": str,
            "steps": List[str],
            "validation": List[str]
        }
    """
    algo_upper = str(finding.get("algorithm", "")).upper().strip()
    mig_type = str(finding.get("migration_type", "")).lower().strip()
    rec_algo = str(finding.get("recommended_algorithm", "") or "").strip()
    context = str(finding.get("context", "")).lower().strip()
    primitive = str(finding.get("primitive", "")).lower().strip()

    # 1. Manual review required (unknown context/primitive or explicit manual review)
    if mig_type == "manual_review" or context == "unknown" or primitive == "unknown":
        return {
            "action": PLAN_MANUAL_REVIEW_ACTION,
            "steps": list(PLAN_MANUAL_REVIEW_STEPS),
            "validation": list(PLAN_MANUAL_REVIEW_VALIDATION),
        }

    # 2. PQC replacement with ML-DSA
    if rec_algo == "ML-DSA" or (
        mig_type == "pqc_replacement"
        and (
            context in {"digital_signature", "jwt_signature", "certificate"}
            or algo_upper in ASYMMETRIC_SIGNATURE_ALGORITHMS
            or algo_upper.startswith(("RSA", "ECDSA", "ED25519", "EDDSA", "RS", "ES"))
        )
    ):
        return {
            "action": PLAN_ML_DSA_ACTION,
            "steps": list(PLAN_ML_DSA_STEPS),
            "validation": list(PLAN_ML_DSA_VALIDATION),
        }

    # 3. PQC replacement with ML-KEM
    if rec_algo == "ML-KEM" or (
        mig_type == "pqc_replacement"
        and (
            context == "key_exchange"
            or algo_upper in ASYMMETRIC_KEX_ALGORITHMS
            or algo_upper.startswith(("ECDH", "DH", "DIFFIE-HELLMAN"))
        )
    ):
        return {
            "action": PLAN_ML_KEM_ACTION,
            "steps": list(PLAN_ML_KEM_STEPS),
            "validation": list(PLAN_ML_KEM_VALIDATION),
        }

    # 4. Legacy / broken cryptography
    if (
        mig_type == "symmetric_upgrade"
        or algo_upper in LEGACY_BROKEN_ALGORITHMS
        or algo_upper.startswith(("DES", "3DES", "TRIPLEDES", "MD5", "SHA-1", "SHA1"))
    ):
        return {
            "action": PLAN_LEGACY_ACTION,
            "steps": list(PLAN_LEGACY_STEPS),
            "validation": list(PLAN_LEGACY_VALIDATION),
        }

    # 5. Modern symmetric cryptography (AES, ChaCha20)
    if (
        algo_upper in MODERN_SYMMETRIC_ALGORITHMS
        or algo_upper.startswith(("AES", "CHACHA20"))
    ):
        return {
            "action": PLAN_MODERN_SYMMETRIC_ACTION,
            "steps": list(PLAN_MODERN_SYMMETRIC_STEPS),
            "validation": list(PLAN_MODERN_SYMMETRIC_VALIDATION),
        }

    # 6. Secure hashes / HMAC (SHA-256, SHA-384, SHA-512, HS256, HS384, HS512)
    if (
        algo_upper in SECURE_HASH_ALGORITHMS
        or algo_upper.startswith(("SHA-256", "SHA-384", "SHA-512", "SHA256", "SHA384", "SHA512", "HS256", "HS384", "HS512", "HMAC"))
    ):
        return {
            "action": PLAN_SECURE_HASH_ACTION,
            "steps": list(PLAN_SECURE_HASH_STEPS),
            "validation": list(PLAN_SECURE_HASH_VALIDATION),
        }

    # 7. No PQC replacement
    if mig_type == "no_pqc_replacement":
        if algo_upper.startswith(("TLS", "SSL")) or context == "tls":
            return {
                "action": PLAN_MODERN_SYMMETRIC_ACTION,
                "steps": list(PLAN_TLS_PROTOCOL_STEPS),
                "validation": list(PLAN_TLS_PROTOCOL_VALIDATION),
            }
        return {
            "action": PLAN_MODERN_SYMMETRIC_ACTION,
            "steps": [
                "Retain the existing cryptographic primitive.",
                "Review the usage and security configuration.",
                "Monitor future cryptographic guidance.",
            ],
            "validation": [
                "Verify current functionality remains operational.",
                "Run existing application tests.",
            ],
        }

    # 8. Fallback
    return {
        "action": PLAN_MANUAL_REVIEW_ACTION,
        "steps": list(PLAN_MANUAL_REVIEW_STEPS),
        "validation": list(PLAN_MANUAL_REVIEW_VALIDATION),
    }


def create_migration_plan(findings: Sequence[Union[Dict[str, Any], Any]]) -> List[Dict[str, Any]]:
    """
    Generate deterministic migration plans for PQC Mapper findings.

    Args:
        findings: Sequence of finding dictionaries from PQC Mapper.

    Returns:
        List of findings preserving all input fields and augmented with migration_plan,
        sorted deterministically by file, line, algorithm.
    """
    results: List[Dict[str, Any]] = []

    for item in findings:
        if hasattr(item, "to_dict"):
            d = item.to_dict()
        elif isinstance(item, dict):
            d = dict(item)
        else:
            continue

        result_item = dict(d)
        result_item["migration_plan"] = _generate_plan_for_finding(d)
        results.append(result_item)

    # Sort results deterministically by file, line, algorithm
    results.sort(key=lambda r: (str(r.get("file", "")), int(r.get("line", 0)), str(r.get("algorithm", ""))))
    return results
