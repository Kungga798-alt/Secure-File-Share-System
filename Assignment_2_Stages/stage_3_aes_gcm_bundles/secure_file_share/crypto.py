from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def load_shared_key(stage_root: Path) -> bytes:
    return (Path(stage_root) / "demo_key.bin").read_bytes()


def ensure_shared_key(stage_root: Path) -> Path:
    key_path = Path(stage_root) / "demo_key.bin"
    if not key_path.exists():
        key_path.write_bytes(os.urandom(32))
    return key_path


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
