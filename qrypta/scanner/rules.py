"""Cryptographic detection definitions, primitives, and standard rules."""

from typing import Dict, Any, Optional

# Standard primitives
PRIMITIVE_ASYMMETRIC_ENCRYPTION = "asymmetric_encryption"
PRIMITIVE_ASYMMETRIC_SIGNATURE = "asymmetric_signature"
PRIMITIVE_ASYMMETRIC_KEY_EXCHANGE = "asymmetric_key_exchange"
PRIMITIVE_SYMMETRIC_ENCRYPTION = "symmetric_encryption"
PRIMITIVE_HASH_FUNCTION = "hash_function"
PRIMITIVE_PASSWORD_HASHING = "password_hashing"
PRIMITIVE_JWT_SIGNATURE = "jwt_signature"
PRIMITIVE_PROTOCOL = "protocol"

# Algorithm definition mappings
ALGORITHM_RULES: Dict[str, Dict[str, Any]] = {
    # Password hashing
    "bcrypt": {
        "algorithm": "bcrypt",
        "primitive": PRIMITIVE_PASSWORD_HASHING,
        "default_usage": "authentication",
    },
    # Asymmetric
    "RSA": {
        "algorithm": "RSA",
        "primitive": PRIMITIVE_ASYMMETRIC_ENCRYPTION,
        "default_usage": "encryption_or_signature",
    },
    "ECDSA": {
        "algorithm": "ECDSA",
        "primitive": PRIMITIVE_ASYMMETRIC_SIGNATURE,
        "default_usage": "signature",
    },
    "ECDH": {
        "algorithm": "ECDH",
        "primitive": PRIMITIVE_ASYMMETRIC_KEY_EXCHANGE,
        "default_usage": "key_exchange",
    },
    "Ed25519": {
        "algorithm": "Ed25519",
        "primitive": PRIMITIVE_ASYMMETRIC_SIGNATURE,
        "default_usage": "signature",
    },
    "EdDSA": {
        "algorithm": "EdDSA",
        "primitive": PRIMITIVE_ASYMMETRIC_SIGNATURE,
        "default_usage": "signature",
    },
    "Diffie-Hellman": {
        "algorithm": "Diffie-Hellman",
        "primitive": PRIMITIVE_ASYMMETRIC_KEY_EXCHANGE,
        "default_usage": "key_exchange",
    },
    # Symmetric
    "AES": {
        "algorithm": "AES",
        "primitive": PRIMITIVE_SYMMETRIC_ENCRYPTION,
        "default_usage": "encryption",
    },
    "ChaCha20": {
        "algorithm": "ChaCha20",
        "primitive": PRIMITIVE_SYMMETRIC_ENCRYPTION,
        "default_usage": "encryption",
    },
    "DES": {
        "algorithm": "DES",
        "primitive": PRIMITIVE_SYMMETRIC_ENCRYPTION,
        "default_usage": "encryption",
    },
    "3DES": {
        "algorithm": "3DES",
        "primitive": PRIMITIVE_SYMMETRIC_ENCRYPTION,
        "default_usage": "encryption",
    },
    # Hashes
    "MD5": {
        "algorithm": "MD5",
        "primitive": PRIMITIVE_HASH_FUNCTION,
        "default_usage": "hashing",
    },
    "SHA-1": {
        "algorithm": "SHA-1",
        "primitive": PRIMITIVE_HASH_FUNCTION,
        "default_usage": "hashing",
    },
    "SHA-256": {
        "algorithm": "SHA-256",
        "primitive": PRIMITIVE_HASH_FUNCTION,
        "default_usage": "hashing",
    },
    "SHA-384": {
        "algorithm": "SHA-384",
        "primitive": PRIMITIVE_HASH_FUNCTION,
        "default_usage": "hashing",
    },
    "SHA-512": {
        "algorithm": "SHA-512",
        "primitive": PRIMITIVE_HASH_FUNCTION,
        "default_usage": "hashing",
    },
    # JWT Algorithms
    "RS256": {
        "algorithm": "RS256",
        "primitive": PRIMITIVE_JWT_SIGNATURE,
        "default_usage": "token_signing",
        "variant": "RSA-SHA256",
    },
    "RS384": {
        "algorithm": "RS384",
        "primitive": PRIMITIVE_JWT_SIGNATURE,
        "default_usage": "token_signing",
        "variant": "RSA-SHA384",
    },
    "RS512": {
        "algorithm": "RS512",
        "primitive": PRIMITIVE_JWT_SIGNATURE,
        "default_usage": "token_signing",
        "variant": "RSA-SHA512",
    },
    "ES256": {
        "algorithm": "ES256",
        "primitive": PRIMITIVE_JWT_SIGNATURE,
        "default_usage": "token_signing",
        "variant": "ECDSA-SHA256",
    },
    "ES384": {
        "algorithm": "ES384",
        "primitive": PRIMITIVE_JWT_SIGNATURE,
        "default_usage": "token_signing",
        "variant": "ECDSA-SHA384",
    },
    "ES512": {
        "algorithm": "ES512",
        "primitive": PRIMITIVE_JWT_SIGNATURE,
        "default_usage": "token_signing",
        "variant": "ECDSA-SHA512",
    },
    "HS256": {
        "algorithm": "HS256",
        "primitive": PRIMITIVE_JWT_SIGNATURE,
        "default_usage": "token_signing",
        "variant": "HMAC-SHA256",
    },
    "HS384": {
        "algorithm": "HS384",
        "primitive": PRIMITIVE_JWT_SIGNATURE,
        "default_usage": "token_signing",
        "variant": "HMAC-SHA384",
    },
    "HS512": {
        "algorithm": "HS512",
        "primitive": PRIMITIVE_JWT_SIGNATURE,
        "default_usage": "token_signing",
        "variant": "HMAC-SHA512",
    },
    # Protocols
    "TLS 1.0": {
        "algorithm": "TLS",
        "variant": "TLS 1.0",
        "primitive": PRIMITIVE_PROTOCOL,
        "default_usage": "secure_channel",
    },
    "TLS 1.1": {
        "algorithm": "TLS",
        "variant": "TLS 1.1",
        "primitive": PRIMITIVE_PROTOCOL,
        "default_usage": "secure_channel",
    },
    "TLS 1.2": {
        "algorithm": "TLS",
        "variant": "TLS 1.2",
        "primitive": PRIMITIVE_PROTOCOL,
        "default_usage": "secure_channel",
    },
    "TLS 1.3": {
        "algorithm": "TLS",
        "variant": "TLS 1.3",
        "primitive": PRIMITIVE_PROTOCOL,
        "default_usage": "secure_channel",
    },
    "SSLv2": {
        "algorithm": "SSL",
        "variant": "SSLv2",
        "primitive": PRIMITIVE_PROTOCOL,
        "default_usage": "secure_channel",
    },
    "SSLv3": {
        "algorithm": "SSL",
        "variant": "SSLv3",
        "primitive": PRIMITIVE_PROTOCOL,
        "default_usage": "secure_channel",
    },
    "TLS": {
        "algorithm": "TLS",
        "variant": None,
        "primitive": PRIMITIVE_PROTOCOL,
        "default_usage": "secure_channel",
    },
    "SSL": {
        "algorithm": "SSL",
        "variant": None,
        "primitive": PRIMITIVE_PROTOCOL,
        "default_usage": "secure_channel",
    },
}

# Mapping normalized names / strings to rule keys
NAME_TO_RULE_KEY: Dict[str, str] = {
    # Hash
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha384": "SHA-384",
    "sha-384": "SHA-384",
    "sha512": "SHA-512",
    "sha-512": "SHA-512",
    # Symmetric
    "aes": "AES",
    "aes-128": "AES",
    "aes-192": "AES",
    "aes-256": "AES",
    "aes-gcm": "AES",
    "aes-cbc": "AES",
    "aes-ctr": "AES",
    "chacha20": "ChaCha20",
    "chacha20-poly1305": "ChaCha20",
    "des": "DES",
    "3des": "3DES",
    "tripledes": "3DES",
    "des-ede3": "3DES",
    "des-ede3-cbc": "3DES",
    "des3": "3DES",
    # Asymmetric
    "rsa": "RSA",
    "ecdsa": "ECDSA",
    "ecdh": "ECDH",
    "ed25519": "Ed25519",
    "eddsa": "EdDSA",
    "dh": "Diffie-Hellman",
    "diffie-hellman": "Diffie-Hellman",
    # JWT
    "rs256": "RS256",
    "rs384": "RS384",
    "rs512": "RS512",
    "es256": "ES256",
    "es384": "ES384",
    "es512": "ES512",
    "hs256": "HS256",
    "hs384": "HS384",
    "hs512": "HS512",
    # Password Hashing
    "bcrypt": "bcrypt",
}

# Directories to ignore
IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
}
