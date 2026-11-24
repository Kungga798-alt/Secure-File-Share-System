from __future__ import annotations

from pathlib import Path

from .certs import load_private_key, load_public_key
from .crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    b64d,
    b64e,
    canonical_json,
    generate_aes_key,
    rsa_oaep_unwrap,
    rsa_oaep_wrap,
)


def create_bundle(path: Path, stage_root: Path, sender: str, recipients: list[str]) -> dict:
    unique_recipients = list(dict.fromkeys([sender, *recipients]))
    aes_key = generate_aes_key()
    header = {
        "filename": Path(path).name,
        "sender": sender,
        "recipients": unique_recipients,
        "algorithm": "AES-256-GCM + RSA-OAEP-SHA256",
    }
    nonce, ciphertext = aes_gcm_encrypt(aes_key, Path(path).read_bytes(), canonical_json(header))
    return {
        **header,
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "wrapped_keys": {user: b64e(rsa_oaep_wrap(load_public_key(stage_root, user), aes_key)) for user in unique_recipients},
    }


def decrypt_bundle(bundle: dict, stage_root: Path, user: str) -> tuple[str, bytes]:
    if user not in bundle["wrapped_keys"]:
        raise PermissionError(f"{user} is not a recipient")
    header = {key: bundle[key] for key in ("filename", "sender", "recipients", "algorithm")}
    aes_key = rsa_oaep_unwrap(load_private_key(stage_root, user), b64d(bundle["wrapped_keys"][user]))
    plaintext = aes_gcm_decrypt(aes_key, b64d(bundle["nonce"]), b64d(bundle["ciphertext"]), canonical_json(header))
    return Path(bundle["filename"]).name, plaintext
