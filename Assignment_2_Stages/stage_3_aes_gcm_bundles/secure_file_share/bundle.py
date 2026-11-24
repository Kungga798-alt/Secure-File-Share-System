from __future__ import annotations

from pathlib import Path

from .crypto import aes_gcm_decrypt, aes_gcm_encrypt, b64d, b64e, load_shared_key


def create_bundle(path: Path, stage_root: Path) -> dict:
    file_path = Path(path)
    key = load_shared_key(stage_root)
    aad = file_path.name.encode("utf-8")
    nonce, ciphertext = aes_gcm_encrypt(key, file_path.read_bytes(), aad)
    return {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "filename": file_path.name,
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
    }


def decrypt_bundle(bundle: dict, stage_root: Path) -> tuple[str, bytes]:
    key = load_shared_key(stage_root)
    aad = bundle["filename"].encode("utf-8")
    plaintext = aes_gcm_decrypt(key, b64d(bundle["nonce"]), b64d(bundle["ciphertext"]), aad)
    return Path(bundle["filename"]).name, plaintext
