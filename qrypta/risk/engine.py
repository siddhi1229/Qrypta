"""Risk Engine module for Qrypta."""

from typing import List, Dict, Any, Union, Sequence, Tuple

# Risk level constants
RISK_LEVEL_CRITICAL = "critical"
RISK_LEVEL_HIGH = "high"
RISK_LEVEL_MEDIUM = "medium"
RISK_LEVEL_LOW = "low"

# Asymmetric quantum-vulnerable algorithm sets
ASYMMETRIC_ALGORITHMS = {
    "RSA",
    "ECDSA",
    "ECDH",
    "DH",
    "DIFFIE-HELLMAN",
    "ED25519",
    "EDDSA",
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
}

ASYM_CONTEXT_SCORES = {
    "digital_signature": 95,
    "jwt_signature": 95,
    "key_exchange": 95,
    "certificate": 90,
    "tls": 90,
    "encryption": 85,
    "authentication": 80,
    "unknown": 70,
}

# Legacy/broken algorithms
BROKEN_ALGORITHMS = {"DES", "3DES", "TRIPLEDES", "MD5", "SHA-1", "SHA1"}

# Symmetric algorithms
AES_ALGORITHMS = {"AES", "AES-128", "AES-192", "AES-256", "AES-GCM", "AES-CBC", "AES-CTR"}
CHACHA_ALGORITHMS = {"CHACHA20", "CHACHA20-POLY1305"}

# Hashes and HMAC
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


def _get_base_risk(algorithm: str, variant: str, context: str) -> Tuple[int, str]:
    """
    Calculate base risk score and deterministic reason based on algorithm, variant, and context.

    Returns:
        (base_score, risk_reason)
    """
    algo_upper = algorithm.upper().strip()
    var_upper = (variant or "").upper().strip()
    ctx_lower = (context or "").lower().strip()

    # 1. TLS / SSL protocols (check variant or algorithm)
    if algo_upper in {"TLS", "SSL", "TLS/SSL"}:
        check_str = f"{algo_upper} {var_upper}"
        if any(v in check_str for v in ["TLS 1.0", "TLS 1.1", "TLSV1.0", "TLSV1.1", "TLSV1_0", "TLSV1_1", "TLSV1", "SSLV2", "SSLV3", "SSLV23"]):
            return 95, "Deprecated and insecure transport protocol version vulnerable to known cryptographic attacks"
        elif "TLS 1.2" in check_str or "TLSV1.2" in check_str or "TLSV1_2" in check_str:
            return 60, "Legacy TLS 1.2 protocol version without post-quantum or modern zero-RTT forward secrecy guarantees"
        elif "TLS 1.3" in check_str or "TLSV1.3" in check_str or "TLSV1_3" in check_str:
            return 35, "Modern TLS 1.3 transport protocol with forward secrecy, subject to future post-quantum key exchange migration"
        else:
            return 50, "Generic TLS/SSL protocol configuration without explicit version restriction"

    # 2. Legacy / broken algorithms
    if algo_upper in BROKEN_ALGORITHMS:
        return 95, f"Legacy cryptographic primitive ({algorithm}) broken by classical cryptanalysis with inadequate security margins"

    # 3. Asymmetric / Quantum-vulnerable algorithms
    if algo_upper in ASYMMETRIC_ALGORITHMS or algo_upper.startswith("RSA") or algo_upper.startswith("ECDSA") or algo_upper.startswith("ED25519"):
        score = ASYM_CONTEXT_SCORES.get(ctx_lower, 70)
        return score, f"Asymmetric algorithm ({algorithm}) vulnerable to quantum cryptanalysis (Shor's algorithm) in {ctx_lower or 'general'} context"

    # 4. AES
    if algo_upper in AES_ALGORITHMS or algo_upper.startswith("AES"):
        if ctx_lower == "encryption":
            return 35, "Modern symmetric cipher (AES) providing strong classical security margins"
        else:
            return 45, f"Symmetric cipher (AES) configured in {ctx_lower or 'secondary'} context"

    # 5. ChaCha20
    if algo_upper in CHACHA_ALGORITHMS or algo_upper.startswith("CHACHA20"):
        if ctx_lower == "encryption":
            return 30, "Modern stream cipher (ChaCha20) providing robust symmetric encryption security"
        else:
            return 40, f"Stream cipher (ChaCha20) configured in {ctx_lower or 'secondary'} context"

    # 6. Secure Hashes & HMAC (SHA-256, SHA-384, SHA-512, HS256, HS384, HS512)
    if algo_upper in SECURE_HASH_ALGORITHMS:
        if ctx_lower == "hashing":
            return 30, f"Secure cryptographic hash function ({algorithm}) with adequate collision resistance"
        else:
            return 40, f"Cryptographic hash/HMAC ({algorithm}) utilized in {ctx_lower or 'general'} context"

    # 7. Unknown / Unrecognized algorithm
    return 50, f"Unrecognized or ambiguous cryptographic algorithm ({algorithm}) requiring manual security assessment"


def _score_to_level(score: int) -> str:
    """Map numeric risk score (0-100) to standard risk level category."""
    if score >= 80:
        return RISK_LEVEL_CRITICAL
    elif score >= 60:
        return RISK_LEVEL_HIGH
    elif score >= 40:
        return RISK_LEVEL_MEDIUM
    else:
        return RISK_LEVEL_LOW


def calculate_risk(findings: Sequence[Union[Dict[str, Any], Any]]) -> List[Dict[str, Any]]:
    """
    Calculate deterministic risk assessment for Context Analysis findings.

    Args:
        findings: Sequence of finding dictionaries containing context analysis fields.

    Returns:
        List of findings augmented with risk_score, risk_level, and risk_reason,
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

        algorithm = str(d.get("algorithm", ""))
        variant = d.get("variant")
        context = str(d.get("context", "unknown"))
        confidence = float(d.get("confidence", 1.0))
        context_confidence = float(d.get("context_confidence", 1.0))

        base_score, risk_reason = _get_base_risk(algorithm, variant, context)

        # Apply confidence adjustment
        avg_confidence = (confidence + context_confidence) / 2.0
        adjusted_score = round(base_score * avg_confidence)

        # Clamp result strictly to 0 - 100
        clamped_score = max(0, min(100, int(adjusted_score)))
        risk_level = _score_to_level(clamped_score)

        result_item = dict(d)
        result_item["risk_score"] = clamped_score
        result_item["risk_level"] = risk_level
        result_item["risk_reason"] = risk_reason

        results.append(result_item)

    # Sort results deterministically by file, line, algorithm
    results.sort(key=lambda r: (str(r.get("file", "")), int(r.get("line", 0)), str(r.get("algorithm", ""))))
    return results
