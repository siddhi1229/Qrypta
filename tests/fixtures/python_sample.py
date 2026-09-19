"""Sample Python file containing deliberate cryptographic usages for testing."""

import hashlib
import ssl
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES, DES, DES3


def hash_operations(data: bytes):
    h1 = hashlib.sha256(data).hexdigest()
    h2 = hashlib.md5(data).hexdigest()
    h3 = hashlib.sha1(data).hexdigest()
    h4 = hashlib.sha384(data).hexdigest()
    h5 = hashlib.sha512(data).hexdigest()
    h6 = hashlib.new("sha256", data).hexdigest()
    return h1, h2, h3, h4, h5, h6


def asymmetric_keys():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ed_key = ed25519.Ed25519PrivateKey.generate()
    dh_params = dh.generate_parameters(generator=2, key_size=2048)
    return rsa_key, ec_key, ed_key, dh_params


def symmetric_ciphers(key: bytes, iv: bytes, nonce: bytes):
    aes_cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    chacha_cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    des_cipher = DES.new(key[:8], DES.MODE_ECB)
    triple_des = DES3.new(key[:16], DES3.MODE_CBC)
    return aes_cipher, chacha_cipher, des_cipher, triple_des


def jwt_tokens():
    token1 = jwt.encode({"sub": "admin"}, "secret", algorithm="RS256")
    token2 = jwt.encode({"sub": "user"}, "secret", algorithm="HS256")
    token3 = jwt.encode({"sub": "guest"}, "secret", algorithm="ES256")
    jwt.decode(token1, "secret", algorithms=["RS256", "HS512"])
    return token1, token2, token3


def tls_setup():
    ctx1 = ssl.create_default_context()
    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx3 = ssl.SSLContext(ssl.PROTOCOL_TLSv1_3)
    return ctx1, ctx2, ctx3
