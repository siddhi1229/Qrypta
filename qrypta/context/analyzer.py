"""Context Analysis module for Qrypta."""

import re
from typing import List, Dict, Any, Union, Sequence, Tuple
from qrypta.scanner.models import Finding

# Standard context categories
CONTEXT_DIGITAL_SIGNATURE = "digital_signature"
CONTEXT_KEY_EXCHANGE = "key_exchange"
CONTEXT_ENCRYPTION = "encryption"
CONTEXT_HASHING = "hashing"
CONTEXT_AUTHENTICATION = "authentication"
CONTEXT_JWT_SIGNATURE = "jwt_signature"
CONTEXT_TLS = "tls"
CONTEXT_CERTIFICATE = "certificate"
CONTEXT_UNKNOWN = "unknown"

VALID_CONTEXTS = {
    CONTEXT_DIGITAL_SIGNATURE,
    CONTEXT_KEY_EXCHANGE,
    CONTEXT_ENCRYPTION,
    CONTEXT_HASHING,
    CONTEXT_AUTHENTICATION,
    CONTEXT_JWT_SIGNATURE,
    CONTEXT_TLS,
    CONTEXT_CERTIFICATE,
    CONTEXT_UNKNOWN,
}

# Regex patterns for deterministic context classification
RE_JWT = re.compile(
    r"""\b(jwt\.sign|jwt\.verify|jwt\.encode|jwt\.decode|SignJWT|jsonwebtoken|jose|authlib|RS256|RS384|RS512|ES256|ES384|ES512|HS256|HS384|HS512)\b""",
    re.IGNORECASE,
)
RE_CERT = re.compile(
    r"""\b(x509|CertificateBuilder|load_pem_x509_certificate|load_der_x509_certificate|createCertificate|certificateFromPem|CertificateSigningRequest|sign_csr|pkcs12|\.crt|\.pem|SubjectAlternativeName)\b""",
    re.IGNORECASE,
)
RE_TLS = re.compile(
    r"""\b(create_default_context|SSLContext|minVersion|maxVersion|secureProtocol|createServer|tls\.connect|https\.request|TLSv1_3|TLSv1_2|TLSv1_1|TLSv1|SSLv3|SSLv2|PROTOCOL_TLS)\b""",
    re.IGNORECASE,
)
RE_KEY_EXCHANGE = re.compile(
    r"""\b(createDiffieHellman|createECDH|generate_parameters|derive_key|exchange|compute_secret|computeSecret|Diffie-Hellman|ECDH)\b""",
    re.IGNORECASE,
)
RE_AUTH = re.compile(
    r"""\b(hmac\.new|createHmac|HMAC|pbkdf2|scrypt|bcrypt|argon2|authenticate|verify_password|auth_tag|check_password)\b""",
    re.IGNORECASE,
)
RE_SIGNATURE = re.compile(
    r"""\b(sign|verify|signer|verifier|signatures|Signer|Verifier|Ed25519PrivateKey|Ed25519PublicKey|ECDSA|RSASSA|EdDSA|ed25519)\b""",
    re.IGNORECASE,
)
RE_ENCRYPTION = re.compile(
    r"""\b(Cipher|createCipheriv|createDecipheriv|AES\.new|DES\.new|DES3\.new|encrypt|decrypt|AES-GCM|AES-CBC|AES-CTR|ChaCha20|TripleDES|RSA-OAEP|OAEP|public_encrypt|private_decrypt|generate_private_key|generateKeyPairSync|generateKeyPair)\b""",
    re.IGNORECASE,
)
RE_HASHING = re.compile(
    r"""\b(hashlib\.(?:sha256|sha384|sha512|sha1|md5|new)|createHash|CryptoJS\.(?:SHA256|SHA384|SHA512|SHA1|MD5)|forge\.md|hashes\.(?:SHA256|SHA384|SHA512|SHA1|MD5)|subtle\.digest|digest|hexdigest)\b""",
    re.IGNORECASE,
)


def _classify_context(finding: Dict[str, Any]) -> Tuple[str, str, float]:
    """
    Determine the most specific applicable usage context, reason, and confidence.

    Returns:
        (context, context_reason, context_confidence)
    """
    algorithm = str(finding.get("algorithm", ""))
    primitive = str(finding.get("primitive", ""))
    usage = str(finding.get("usage", "")).lower()
    evidence = str(finding.get("evidence", ""))
    variant = str(finding.get("variant") or "")

    combined_text = f"{algorithm} {variant} {primitive} {usage} {evidence}"
    evidence_clean = evidence.strip()

    # 1. Bare imports with no invocation/operation evidence -> unknown context
    is_import_only = usage == "import" or evidence_clean.startswith(("import ", "from ", "require("))
    has_operation = "(" in evidence_clean and not evidence_clean.startswith(("import ", "from ")) and not (evidence_clean.startswith("require(") and "create" not in evidence_clean and "sign" not in evidence_clean)
    if is_import_only and not ("=" in evidence_clean or "new" in evidence_clean or has_operation):
        return (
            CONTEXT_UNKNOWN,
            "Insufficient contextual evidence to determine specific cryptographic usage from import statement",
            0.0,
        )

    # 2. JWT signature
    if primitive == "jwt_signature" or RE_JWT.search(algorithm) or (
        usage in {"token_signing", "token_verification"} or "jwt" in combined_text.lower()
    ):
        if RE_JWT.search(combined_text):
            return (
                CONTEXT_JWT_SIGNATURE,
                "JWT token signing, verification, or algorithm header configuration detected in evidence",
                0.95,
            )

    # 3. Certificate
    if RE_CERT.search(evidence):
        return (
            CONTEXT_CERTIFICATE,
            "X.509 certificate generation, signing, or certificate parsing detected in evidence",
            0.95,
        )

    # 4. TLS / SSL
    if primitive == "protocol" or algorithm in {"TLS", "SSL", "TLS/SSL"} or RE_TLS.search(evidence):
        if RE_TLS.search(combined_text):
            return (
                CONTEXT_TLS,
                "TLS/SSL protocol configuration, context creation, or secure transport detected",
                0.95,
            )

    # 5. Key Exchange
    if primitive == "asymmetric_key_exchange" or algorithm in {"Diffie-Hellman", "ECDH"} or RE_KEY_EXCHANGE.search(evidence):
        if RE_KEY_EXCHANGE.search(combined_text) and usage != "import":
            return (
                CONTEXT_KEY_EXCHANGE,
                "Diffie-Hellman or ECDH key agreement or parameter generation detected",
                0.95,
            )

    # 6. Authentication / HMAC / Password hashing
    if RE_AUTH.search(evidence):
        return (
            CONTEXT_AUTHENTICATION,
            "Message authentication code (MAC) or credential verification operation detected",
            0.95,
        )

    # 7. Digital Signature
    if (primitive == "asymmetric_signature" and usage != "import") or (
        algorithm in {"ECDSA", "Ed25519", "EdDSA"} and usage in {"signature", "key_generation", "signature_verification"}
    ) or ("sign" in usage or "verify" in usage):
        if RE_SIGNATURE.search(evidence) or "sign" in usage or "verify" in usage:
            return (
                CONTEXT_DIGITAL_SIGNATURE,
                "Digital signature generation, verification, or asymmetric signing key operation detected",
                0.95,
            )

    # 8. Encryption (Symmetric / Asymmetric cipher operations)
    if (primitive == "symmetric_encryption" and usage != "import") or (
        algorithm in {"AES", "ChaCha20", "DES", "3DES"} and usage in {"encryption", "decryption", "key_generation"}
    ) or (algorithm == "RSA" and usage in {"encryption", "key_generation"} and not RE_SIGNATURE.search(evidence)):
        if RE_ENCRYPTION.search(evidence) or usage in {"encryption", "decryption", "key_generation"}:
            return (
                CONTEXT_ENCRYPTION,
                "Symmetric or asymmetric encryption/decryption cipher operation detected",
                0.95,
            )

    # 9. Hashing
    if (primitive == "hash_function" and usage != "import") or algorithm in {"MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"}:
        if RE_HASHING.search(evidence) or usage == "hashing":
            return (
                CONTEXT_HASHING,
                "Cryptographic hash digest computation detected",
                0.95,
            )

    # Fallback to unknown if evidence is insufficient
    return (
        CONTEXT_UNKNOWN,
        "Insufficient contextual evidence to determine specific cryptographic usage",
        0.0,
    )


def analyze_context(findings: Sequence[Union[Finding, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Perform deterministic context analysis on Scanner findings.

    Args:
        findings: Sequence of Finding objects or finding dictionaries.

    Returns:
        List of context analysis results sorted deterministically by file and line.
    """
    results: List[Dict[str, Any]] = []

    for item in findings:
        if hasattr(item, "to_dict"):
            finding_dict = item.to_dict()
        elif isinstance(item, dict):
            variant_val = item.get("variant")
            lib_val = item.get("library")
            finding_dict = {
                "algorithm": str(item["algorithm"]),
                "variant": str(variant_val) if variant_val is not None else None,
                "primitive": str(item["primitive"]),
                "usage": str(item.get("usage", "")),
                "file": str(item["file"]),
                "line": int(item["line"]),
                "evidence": str(item["evidence"]),
                "library": str(lib_val) if lib_val is not None else None,
                "confidence": round(float(item["confidence"]), 2),
            }
        else:
            continue

        context, reason, ctx_confidence = _classify_context(finding_dict)

        results.append(
            {
                "algorithm": finding_dict["algorithm"],
                "variant": finding_dict["variant"],
                "primitive": finding_dict["primitive"],
                "usage": finding_dict["usage"],
                "context": context,
                "context_reason": reason,
                "context_confidence": round(float(ctx_confidence), 2),
                "file": finding_dict["file"],
                "line": finding_dict["line"],
                "evidence": finding_dict["evidence"],
                "library": finding_dict["library"],
                "confidence": finding_dict["confidence"],
            }
        )

    # Sort results deterministically by file path and line number
    results.sort(key=lambda r: (r["file"], r["line"]))
    return results
