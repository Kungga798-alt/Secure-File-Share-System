from __future__ import annotations

from pathlib import Path

from .certs import cert_fingerprint, user_cert, user_key
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


def create_bundle(path: Path, deployment: Path, sender: str, recipients: list[str]) -> dict:
    unique = list(dict.fromkeys([sender, *recipients]))
    aes_key = generate_aes_key()
    header = {
        "filename": Path(path).name,
        "sender": {"user": sender, "fingerprint": cert_fingerprint(user_cert(deployment, sender))},
        "recipients": [{"user": user, "fingerprint": cert_fingerprint(user_cert(deployment, user))} for user in unique],
        "algorithm": "AES-256-GCM + RSA-OAEP-SHA256",
    }
    nonce, ciphertext = aes_gcm_encrypt(aes_key, Path(path).read_bytes(), canonical_json(header))
    wrapped = []
    for item in header["recipients"]:
        cert = user_cert(deployment, item["user"])
        wrapped.append({"user": item["user"], "fingerprint": item["fingerprint"], "wrapped_key": b64e(rsa_oaep_wrap(cert.public_key(), aes_key))})
    return {**header, "nonce": b64e(nonce), "ciphertext": b64e(ciphertext), "wrapped_keys": wrapped}


def decrypt_bundle(bundle: dict, deployment: Path, user: str) -> tuple[str, bytes]:
    fp = cert_fingerprint(user_cert(deployment, user))
    wrapped = next((entry for entry in bundle["wrapped_keys"] if entry["fingerprint"] == fp), None)
    if wrapped is None:
        raise PermissionError(f"{user} is not a recipient")
    header = {key: bundle[key] for key in ("filename", "sender", "recipients", "algorithm")}
    aes_key = rsa_oaep_unwrap(user_key(deployment, user), b64d(wrapped["wrapped_key"]))
    plaintext = aes_gcm_decrypt(aes_key, b64d(bundle["nonce"]), b64d(bundle["ciphertext"]), canonical_json(header))
    return Path(bundle["filename"]).name, plaintext
