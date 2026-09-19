"""JavaScript and TypeScript static analysis scanner using deterministic source-pattern analysis."""

import re
from pathlib import Path
from typing import List, Optional, Set, Tuple, Dict

from qrypta.scanner.models import Finding
from qrypta.scanner.rules import (
    ALGORITHM_RULES,
    NAME_TO_RULE_KEY,
    PRIMITIVE_ASYMMETRIC_ENCRYPTION,
    PRIMITIVE_ASYMMETRIC_SIGNATURE,
    PRIMITIVE_ASYMMETRIC_KEY_EXCHANGE,
    PRIMITIVE_SYMMETRIC_ENCRYPTION,
    PRIMITIVE_HASH_FUNCTION,
    PRIMITIVE_JWT_SIGNATURE,
    PRIMITIVE_PROTOCOL,
)

# Known libraries in JS/TS
KNOWN_JS_LIBRARIES: Dict[str, str] = {
    "crypto": "crypto",
    "node:crypto": "crypto",
    "jsonwebtoken": "jsonwebtoken",
    "jose": "jose",
    "crypto-js": "crypto-js",
    "node-forge": "node-forge",
    "tls": "tls",
    "https": "https",
    "elliptic": "elliptic",
    "@noble/hashes": "@noble/hashes",
    "@noble/ciphers": "@noble/ciphers",
    "@noble/curves": "@noble/curves",
}

# Regex pattern definitions for deterministic JS/TS analysis
PATTERNS = [
    # 1. Hashes - Node.js crypto / subtle / CryptoJS / forge / property declarations
    {
        "regex": re.compile(r"""(?:createHash|createHmac)\s*\(\s*['"`](sha(?:256|384|512|1)|md5)['"`]""", re.IGNORECASE),
        "primitive": PRIMITIVE_HASH_FUNCTION,
        "usage": "hashing",
        "default_lib": "crypto",
        "confidence": 0.95,
    },
    {
        "regex": re.compile(r"""subtle\.digest\s*\(\s*['"`](SHA-(?:256|384|512|1))['"`]""", re.IGNORECASE),
        "primitive": PRIMITIVE_HASH_FUNCTION,
        "usage": "hashing",
        "default_lib": "webcrypto",
        "confidence": 0.95,
    },
    {
        "regex": re.compile(r"""CryptoJS\.(SHA256|SHA384|SHA512|SHA1|MD5)\s*\(""", re.IGNORECASE),
        "primitive": PRIMITIVE_HASH_FUNCTION,
        "usage": "hashing",
        "default_lib": "crypto-js",
        "confidence": 0.95,
    },
    {
        "regex": re.compile(r"""forge\.md\.(sha256|sha384|sha512|sha1|md5)\.create\s*\(""", re.IGNORECASE),
        "primitive": PRIMITIVE_HASH_FUNCTION,
        "usage": "hashing",
        "default_lib": "node-forge",
        "confidence": 0.95,
    },

    # 2. Symmetric Ciphers - Node.js crypto / CryptoJS / forge / subtle
    {
        "regex": re.compile(r"""(?:createCipheriv|createDecipheriv)\s*\(\s*['"`](aes-(?:128|192|256)-(?:gcm|cbc|ctr|ecb|cfb)|chacha20-poly1305|chacha20|des-ede3-cbc|des-ede3|des-cbc|des)['"`]""", re.IGNORECASE),
        "primitive": PRIMITIVE_SYMMETRIC_ENCRYPTION,
        "usage": "encryption",
        "default_lib": "crypto",
        "confidence": 0.95,
    },
    {
        "regex": re.compile(r"""CryptoJS\.(AES|DES|TripleDES|Rabbit|RC4)\.(?:encrypt|decrypt)\s*\(""", re.IGNORECASE),
        "primitive": PRIMITIVE_SYMMETRIC_ENCRYPTION,
        "usage": "encryption",
        "default_lib": "crypto-js",
        "confidence": 0.95,
    },
    {
        "regex": re.compile(r"""forge\.cipher\.createCipher\s*\(\s*['"`](AES-CBC|AES-GCM|3DES-ECB|3DES-CBC)['"`]""", re.IGNORECASE),
        "primitive": PRIMITIVE_SYMMETRIC_ENCRYPTION,
        "usage": "encryption",
        "default_lib": "node-forge",
        "confidence": 0.95,
    },
    {
        "regex": re.compile(r"""name:\s*['"`](AES-GCM|AES-CBC|AES-CTR)['"`]""", re.IGNORECASE),
        "primitive": PRIMITIVE_SYMMETRIC_ENCRYPTION,
        "usage": "key_generation",
        "default_lib": "webcrypto",
        "confidence": 0.95,
    },

    # 3. Asymmetric - Key Generation & Key Exchange
    {
        "regex": re.compile(r"""(?:generateKeyPair|generateKeyPairSync)\s*\(\s*['"`](rsa|ec|ed25519|ed448|dsa|dh)['"`]""", re.IGNORECASE),
        "primitive": PRIMITIVE_ASYMMETRIC_ENCRYPTION,
        "usage": "key_generation",
        "default_lib": "crypto",
        "confidence": 0.95,
    },
    {
        "regex": re.compile(r"""(?:createDiffieHellman|createDiffieHellmanGroup)\s*\(""", re.IGNORECASE),
        "algorithm": "Diffie-Hellman",
        "primitive": PRIMITIVE_ASYMMETRIC_KEY_EXCHANGE,
        "usage": "key_exchange",
        "default_lib": "crypto",
        "confidence": 0.95,
    },
    {
        "regex": re.compile(r"""createECDH\s*\(\s*['"`]([a-zA-Z0-9_\-]+)['"`]""", re.IGNORECASE),
        "algorithm": "ECDH",
        "primitive": PRIMITIVE_ASYMMETRIC_KEY_EXCHANGE,
        "usage": "key_exchange",
        "default_lib": "crypto",
        "confidence": 0.95,
    },
    {
        "regex": re.compile(r"""forge\.pki\.rsa\.generateKeyPair\s*\(""", re.IGNORECASE),
        "algorithm": "RSA",
        "primitive": PRIMITIVE_ASYMMETRIC_ENCRYPTION,
        "usage": "key_generation",
        "default_lib": "node-forge",
        "confidence": 0.95,
    },
    {
        "regex": re.compile(r"""name:\s*['"`](RSASSA-PKCS1-v1_5|RSA-PSS|RSA-OAEP|RSA|ECDSA|ECDH|Ed25519|EdDSA)['"`]""", re.IGNORECASE),
        "usage": "key_generation",
        "default_lib": "webcrypto",
        "confidence": 0.95,
    },

    # 4. JWT Algorithms
    {
        "regex": re.compile(r"""(?:algorithm|algorithms|alg)\s*:\s*(?:\[\s*)?['"`](RS256|RS384|RS512|ES256|ES384|ES512|HS256|HS384|HS512)['"`]""", re.IGNORECASE),
        "primitive": PRIMITIVE_JWT_SIGNATURE,
        "usage": "token_signing",
        "default_lib": "jsonwebtoken",
        "confidence": 0.95,
    },
    {
        "regex": re.compile(r"""setProtectedHeader\s*\(\s*\{\s*alg:\s*['"`](RS256|RS384|RS512|ES256|ES384|ES512|HS256|HS384|HS512)['"`]""", re.IGNORECASE),
        "primitive": PRIMITIVE_JWT_SIGNATURE,
        "usage": "token_signing",
        "default_lib": "jose",
        "confidence": 0.95,
    },

    # 5. TLS / SSL usage and protocol versions
    {
        "regex": re.compile(r"""(?:minVersion|maxVersion)\s*:\s*['"`](TLSv1\.3|TLSv1\.2|TLSv1\.1|TLSv1|SSLv3|SSLv2)['"`]""", re.IGNORECASE),
        "primitive": PRIMITIVE_PROTOCOL,
        "usage": "protocol_configuration",
        "default_lib": "tls",
        "confidence": 0.95,
    },
    {
        "regex": re.compile(r"""secureProtocol\s*:\s*['"`](TLSv1_3_method|TLSv1_2_method|TLSv1_1_method|TLSv1_method|SSLv23_method|SSLv3_method|SSLv2_method)['"`]""", re.IGNORECASE),
        "primitive": PRIMITIVE_PROTOCOL,
        "usage": "protocol_configuration",
        "default_lib": "tls",
        "confidence": 0.95,
    },
    {
        "regex": re.compile(r"""(?:tls|https)\.createServer\s*\(""", re.IGNORECASE),
        "algorithm": "TLS",
        "primitive": PRIMITIVE_PROTOCOL,
        "usage": "secure_channel",
        "default_lib": "tls",
        "confidence": 0.90,
    },
]


def _detect_imported_libraries(source_lines: List[str]) -> Set[str]:
    """Scan import and require statements to detect loaded libraries."""
    detected_libs: Set[str] = set()
    import_regex = re.compile(
        r"""(?:import\s+.*?\s+from\s+['"`]([^'"`]+)['"`]|require\s*\(\s*['"`]([^'"`]+)['"`]\))"""
    )
    for line in source_lines:
        for match in import_regex.finditer(line):
            module_name = match.group(1) or match.group(2)
            if module_name:
                base_pkg = module_name.split("/")[0]
                if module_name in KNOWN_JS_LIBRARIES:
                    detected_libs.add(KNOWN_JS_LIBRARIES[module_name])
                elif base_pkg in KNOWN_JS_LIBRARIES:
                    detected_libs.add(KNOWN_JS_LIBRARIES[base_pkg])
    return detected_libs


def scan_js_ts_code(source_code: str, filename: str = "source.js") -> List[Finding]:
    """Scan JavaScript / TypeScript source code using deterministic pattern analysis."""
    findings: List[Finding] = []
    source_lines = source_code.splitlines()
    reported_lines: Set[Tuple[int, str]] = set()

    imported_libs = _detect_imported_libraries(source_lines)

    for line_idx, line in enumerate(source_lines, 1):
        clean_line = line.strip()
        # Skip pure comment lines
        if clean_line.startswith("//") or clean_line.startswith("/*") or clean_line.startswith("*"):
            continue

        for rule_item in PATTERNS:
            regex = rule_item["regex"]
            match = regex.search(line)
            if not match:
                continue

            # Determine algorithm, variant, and primitive
            if "algorithm" in rule_item:
                algorithm = rule_item["algorithm"]
                variant = rule_item.get("variant")
                primitive = rule_item["primitive"]
            else:
                raw_match = match.group(1) if match.groups() else match.group(0)
                raw_lower = raw_match.lower()

                # Check TLS / SSL versions
                if "tlsv1.3" in raw_lower or "tlsv1_3" in raw_lower:
                    algorithm = "TLS"
                    variant = "TLS 1.3"
                    primitive = PRIMITIVE_PROTOCOL
                elif "tlsv1.2" in raw_lower or "tlsv1_2" in raw_lower:
                    algorithm = "TLS"
                    variant = "TLS 1.2"
                    primitive = PRIMITIVE_PROTOCOL
                elif "tlsv1.1" in raw_lower or "tlsv1_1" in raw_lower:
                    algorithm = "TLS"
                    variant = "TLS 1.1"
                    primitive = PRIMITIVE_PROTOCOL
                elif "tlsv1" in raw_lower or "tlsv1_method" in raw_lower:
                    algorithm = "TLS"
                    variant = "TLS 1.0"
                    primitive = PRIMITIVE_PROTOCOL
                elif "sslv3" in raw_lower:
                    algorithm = "SSL"
                    variant = "SSLv3"
                    primitive = PRIMITIVE_PROTOCOL
                elif "sslv2" in raw_lower or "sslv23" in raw_lower:
                    algorithm = "SSL"
                    variant = "SSLv2"
                    primitive = PRIMITIVE_PROTOCOL
                elif raw_lower.startswith("aes-"):
                    algorithm = "AES"
                    variant = raw_match.upper()
                    primitive = PRIMITIVE_SYMMETRIC_ENCRYPTION
                elif raw_lower.startswith("chacha20"):
                    algorithm = "ChaCha20"
                    variant = raw_match.upper()
                    primitive = PRIMITIVE_SYMMETRIC_ENCRYPTION
                elif "des-ede3" in raw_lower or "tripledes" in raw_lower or "3des" in raw_lower:
                    algorithm = "3DES"
                    variant = raw_match.upper()
                    primitive = PRIMITIVE_SYMMETRIC_ENCRYPTION
                elif "des" in raw_lower:
                    algorithm = "DES"
                    variant = raw_match.upper()
                    primitive = PRIMITIVE_SYMMETRIC_ENCRYPTION
                elif raw_lower in {"rsa", "rsassa-pkcs1-v1_5", "rsa-pss", "rsa-oaep"}:
                    algorithm = "RSA"
                    variant = raw_match if raw_match.upper() != "RSA" else None
                    primitive = PRIMITIVE_ASYMMETRIC_ENCRYPTION
                elif raw_lower in {"ec", "ecdsa"}:
                    algorithm = "ECDSA"
                    variant = None
                    primitive = PRIMITIVE_ASYMMETRIC_SIGNATURE
                elif raw_lower == "ecdh":
                    algorithm = "ECDH"
                    variant = None
                    primitive = PRIMITIVE_ASYMMETRIC_KEY_EXCHANGE
                elif raw_lower == "ed25519":
                    algorithm = "Ed25519"
                    variant = None
                    primitive = PRIMITIVE_ASYMMETRIC_SIGNATURE
                elif raw_lower in {"ed448", "eddsa"}:
                    algorithm = "EdDSA"
                    variant = None
                    primitive = PRIMITIVE_ASYMMETRIC_SIGNATURE
                elif raw_lower in NAME_TO_RULE_KEY:
                    rule_key = NAME_TO_RULE_KEY[raw_lower]
                    target_rule = ALGORITHM_RULES[rule_key]
                    algorithm = target_rule["algorithm"]
                    variant = target_rule.get("variant")
                    primitive = target_rule["primitive"]
                else:
                    algorithm = raw_match.upper()
                    variant = None
                    primitive = rule_item.get("primitive", PRIMITIVE_HASH_FUNCTION)

            # Check for modulusLength or namedCurve in surrounding context
            if algorithm == "RSA" and not variant:
                mod_match = re.search(r"""modulusLength\s*:\s*(\d+)""", line)
                if mod_match:
                    variant = f"{mod_match.group(1)}-bit"
            elif algorithm in {"ECDSA", "ECDH"} and not variant:
                curve_match = re.search(r"""(?:namedCurve|curve)\s*:\s*['"`]([a-zA-Z0-9_\-]+)['"`]""", line)
                if curve_match:
                    variant = curve_match.group(1)

            # Determine library
            default_lib = rule_item.get("default_lib")
            library = default_lib
            for imp_lib in imported_libs:
                if default_lib and imp_lib == default_lib:
                    library = imp_lib
                    break
                elif imp_lib in {"jsonwebtoken", "jose"} and primitive == PRIMITIVE_JWT_SIGNATURE:
                    library = imp_lib
                elif imp_lib in {"tls", "https"} and primitive == PRIMITIVE_PROTOCOL:
                    library = imp_lib
                elif imp_lib in {"crypto-js", "node-forge"} and default_lib in {imp_lib, "crypto"}:
                    library = imp_lib

            dedup_key = (line_idx, algorithm)
            if dedup_key in reported_lines:
                continue
            reported_lines.add(dedup_key)

            findings.append(
                Finding(
                    algorithm=algorithm,
                    variant=variant,
                    primitive=primitive,
                    usage=rule_item["usage"],
                    file=filename,
                    line=line_idx,
                    evidence=clean_line,
                    library=library,
                    confidence=rule_item.get("confidence", 0.90),
                )
            )

    return findings


def scan_js_ts_file(file_path: Path, repo_root: Optional[Path] = None) -> List[Finding]:
    """Read and scan a JavaScript/TypeScript file from disk in read-only mode."""
    rel_path = file_path.relative_to(repo_root).as_posix() if repo_root else file_path.as_posix()
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return scan_js_ts_code(content, filename=rel_path)
    except Exception:
        return []
