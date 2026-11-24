"""Cryptographic helper functions.

Appendix B contribution: [Student 2] implemented AES and RSA primitives;
[Student 4] reviewed their use in the hardened final integration.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_GCM_NONCE_BYTES = 12


def canonical_json(data: Any) -> bytes:
    """Return stable UTF-8 JSON bytes for signatures and AEAD associated data."""

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def b64e(data: bytes) -> str:
    """Encode raw bytes as ASCII Base64 text for JSON bundle storage."""

    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Decode ASCII Base64 text and reject malformed bundle data."""

    return base64.b64decode(text.encode("ascii"), validate=True)


def generate_aes256_key() -> bytes:
    """Generate a fresh 256-bit AES key from the cryptography library's secure source."""

    return AESGCM.generate_key(bit_length=256)


def generate_aes_gcm_nonce() -> bytes:
    """Generate a fresh 96-bit AES-GCM nonce from the operating system CSPRNG."""

    return os.urandom(AES_GCM_NONCE_BYTES)


def aes_gcm_encrypt_with_key(key: bytes, plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
    """Encrypt one payload with a caller-owned AES key and a fresh unique nonce."""

    nonce = generate_aes_gcm_nonce()
    return nonce, AESGCM(key).encrypt(nonce, plaintext, associated_data)


def aes_gcm_encrypt(plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt bytes with a fresh AES-256-GCM key, 96-bit nonce, and authenticated metadata."""

    key = generate_aes256_key()
    nonce, ciphertext = aes_gcm_encrypt_with_key(key, plaintext, associated_data)
    return key, nonce, ciphertext


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes,
) -> bytes:
    """Decrypt AES-GCM ciphertext and fail if the key, nonce, ciphertext, or metadata changed."""

    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


def rsa_oaep_wrap(public_key, secret: bytes) -> bytes:
    """Wrap a short secret, such as an AES file key, using RSA-OAEP with SHA-256."""

    return public_key.encrypt(
        secret,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_oaep_unwrap(private_key, wrapped_secret: bytes) -> bytes:
    """Unwrap an RSA-OAEP encrypted secret with the matching recipient private key."""

    return private_key.decrypt(
        wrapped_secret,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_pss_sign(private_key, message: bytes) -> bytes:
    """Sign exact message bytes using RSA-PSS with SHA-256 for sender approval evidence."""

    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_pss_verify(public_key, signature: bytes, message: bytes) -> None:
    """Verify an RSA-PSS signature over exact message bytes or raise on mismatch."""

    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
