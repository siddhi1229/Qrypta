"""PQC Mapper module for Qrypta."""

from typing import List, Dict, Any, Union, Sequence, Tuple, Optional

# Standard migration types
MIGRATION_PQC_REPLACEMENT = "pqc_replacement"
MIGRATION_SYMMETRIC_UPGRADE = "symmetric_upgrade"
MIGRATION_NO_PQC_REPLACEMENT = "no_pqc_replacement"
MIGRATION_MANUAL_REVIEW = "manual_review"

# Standard recommended PQC algorithms
PQC_ALGO_ML_DSA = "ML-DSA"
PQC_ALGO_ML_KEM = "ML-KEM"

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


def _map_finding_to_pqc(finding: Dict[str, Any]) -> Tuple[Optional[str], str, str]:
    """
    Map a single cryptographic finding to its PQC recommendation.

    Returns:
        (recommended_algorithm, migration_type, mapping_reason)
    """
    algo_upper = str(finding.get("algorithm", "")).upper().strip()
    context = str(finding.get("context", "unknown")).lower().strip()
    primitive = str(finding.get("primitive", "")).lower().strip()

    # 1. Unknown context or ambiguous usage -> manual review
    if context == "unknown" or primitive == "unknown":
        return (
            None,
            MIGRATION_MANUAL_REVIEW,
            "Ambiguous or unrecognized cryptographic usage requiring manual architectural review before migration",
        )

    # 2. Digital Signatures (RSA, ECDSA, Ed25519, EdDSA in digital_signature context)
    if context == "digital_signature" and (
        algo_upper in ASYMMETRIC_SIGNATURE_ALGORITHMS or algo_upper.startswith("RSA") or algo_upper.startswith("ECDSA") or algo_upper.startswith("ED25519")
    ):
        return (
            PQC_ALGO_ML_DSA,
            MIGRATION_PQC_REPLACEMENT,
            "Asymmetric digital signature is vulnerable to Shor's algorithm; replace with NIST post-quantum standard ML-DSA (FIPS 204)",
        )

    # 3. JWT Signatures
    if context == "jwt_signature":
        if algo_upper in ASYMMETRIC_SIGNATURE_ALGORITHMS or algo_upper.startswith("RSA") or algo_upper.startswith("ECDSA") or algo_upper.startswith("RS") or algo_upper.startswith("ES"):
            return (
                PQC_ALGO_ML_DSA,
                MIGRATION_PQC_REPLACEMENT,
                "Asymmetric JWT signing algorithm is vulnerable to Shor's algorithm; replace with post-quantum signature algorithm ML-DSA",
            )
        elif algo_upper in {"HS256", "HS384", "HS512"} or "HMAC" in algo_upper:
            return (
                None,
                MIGRATION_NO_PQC_REPLACEMENT,
                "Symmetric HMAC-based token signing is not vulnerable to Shor's algorithm; no PQC replacement required",
            )

    # 4. Key Exchange (ECDH, DH, RSA in key_exchange context)
    if context == "key_exchange" and (
        algo_upper in ASYMMETRIC_KEX_ALGORITHMS or algo_upper.startswith("ECDH") or algo_upper.startswith("DH") or algo_upper.startswith("RSA")
    ):
        return (
            PQC_ALGO_ML_KEM,
            MIGRATION_PQC_REPLACEMENT,
            "Asymmetric key exchange/agreement is vulnerable to Shor's algorithm; replace with NIST post-quantum standard ML-KEM (FIPS 203)",
        )

    # 5. Certificates (RSA, ECDSA, Ed25519 in certificate context)
    if context == "certificate" and (
        algo_upper in ASYMMETRIC_SIGNATURE_ALGORITHMS or algo_upper.startswith("RSA") or algo_upper.startswith("ECDSA") or algo_upper.startswith("ED25519")
    ):
        return (
            PQC_ALGO_ML_DSA,
            MIGRATION_PQC_REPLACEMENT,
            "X.509 certificate asymmetric signature is vulnerable to quantum cryptanalysis; replace with post-quantum signature algorithm ML-DSA",
        )

    # 6. TLS Protocol Usage
    if context == "tls":
        if algo_upper in {"ECDH", "DH", "DIFFIE-HELLMAN"}:
            return (
                PQC_ALGO_ML_KEM,
                MIGRATION_PQC_REPLACEMENT,
                "TLS key exchange mechanism is vulnerable to quantum cryptanalysis; upgrade to post-quantum key encapsulation ML-KEM",
            )
        elif algo_upper in {"ECDSA", "RSA", "ED25519"}:
            return (
                PQC_ALGO_ML_DSA,
                MIGRATION_PQC_REPLACEMENT,
                "TLS certificate and authentication signature is vulnerable to Shor's algorithm; replace with ML-DSA",
            )
        else:
            # Generic TLS protocol configuration without specific asymmetric role
            return (
                None,
                MIGRATION_NO_PQC_REPLACEMENT,
                "TLS protocol configuration detected without specific asymmetric cryptographic role; no direct PQC algorithm replacement",
            )

    # 7. Modern Symmetric Ciphers (AES, ChaCha20)
    if algo_upper in MODERN_SYMMETRIC_ALGORITHMS or algo_upper.startswith("AES") or algo_upper.startswith("CHACHA20"):
        return (
            None,
            MIGRATION_NO_PQC_REPLACEMENT,
            "Modern symmetric ciphers are not vulnerable to Shor's algorithm; utilize 256-bit key sizes for post-quantum Grover resistance",
        )

    # 8. Legacy / Broken Symmetric & Hashes (DES, 3DES, MD5, SHA-1)
    if algo_upper in {"DES", "3DES", "TRIPLEDES"}:
        return (
            None,
            MIGRATION_SYMMETRIC_UPGRADE,
            "Legacy symmetric cipher vulnerable to classical cryptanalysis; migrate to modern symmetric cipher AES-256-GCM",
        )
    if algo_upper in {"MD5", "SHA-1", "SHA1"}:
        return (
            None,
            MIGRATION_SYMMETRIC_UPGRADE,
            "Broken cryptographic hash function with classical collision vulnerability; upgrade to SHA-256 or SHA-512",
        )

    # 9. Modern Secure Hashes & HMAC (SHA-256, SHA-384, SHA-512)
    if algo_upper in SECURE_HASH_ALGORITHMS:
        return (
            None,
            MIGRATION_NO_PQC_REPLACEMENT,
            "Modern SHA-2 hash family provides adequate classical and quantum collision resistance; no PQC replacement required",
        )

    # 10. Fallback for unrecognized algorithms
    return (
        None,
        MIGRATION_MANUAL_REVIEW,
        f"Unrecognized or ambiguous cryptographic usage ({algo_upper}) requiring manual architectural review before migration",
    )


def map_to_pqc(findings: Sequence[Union[Dict[str, Any], Any]]) -> List[Dict[str, Any]]:
    """
    Deterministically map Risk Engine findings to post-quantum cryptography recommendations.

    Args:
        findings: Sequence of finding dictionaries from Risk Engine.

    Returns:
        List of findings augmented with recommended_algorithm, migration_type, and mapping_reason,
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

        pqc_algo, mig_type, map_reason = _map_finding_to_pqc(d)

        result_item = dict(d)
        result_item["recommended_algorithm"] = pqc_algo
        result_item["migration_type"] = mig_type
        result_item["mapping_reason"] = map_reason

        results.append(result_item)

    # Sort results deterministically by file, line, algorithm
    results.sort(key=lambda r: (str(r.get("file", "")), int(r.get("line", 0)), str(r.get("algorithm", ""))))
    return results
