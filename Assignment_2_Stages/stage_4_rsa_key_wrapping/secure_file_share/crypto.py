from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def canonical_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True).encode("utf-8")


def generate_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def rsa_oaep_wrap(public_key, aes_key: bytes) -> bytes:
    return public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))


def rsa_oaep_unwrap(private_key, wrapped_key: bytes) -> bytes:
    return private_key.decrypt(wrapped_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
