from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import InvalidSignature

from .certs import (
    cert_fingerprint,
    cert_pem,
    common_name,
    load_cert,
    load_cert_from_pem,
    user_cert,
    user_key,
    verify_cert_signed_by_ca,
)
from .crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    b64d,
    b64e,
    canonical_json,
    generate_aes_key,
    rsa_oaep_unwrap,
    rsa_oaep_wrap,
    rsa_pss_sign,
    rsa_pss_verify,
    sha256_hex,
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


def signed_payload(bundle: dict) -> dict:
    return {
        "filename": bundle["filename"],
        "sender": bundle["sender"],
        "recipients": bundle["recipients"],
        "algorithm": bundle["algorithm"],
        "wrapped_keys": bundle["wrapped_keys"],
        "nonce": bundle["nonce"],
        "ciphertext_sha256": bundle["ciphertext_sha256"],
    }


def create_signed_bundle(path: Path, deployment: Path, sender: str, recipients: list[str]) -> dict:
    bundle = create_bundle(path, deployment, sender, recipients)
    ciphertext = b64d(bundle["ciphertext"])
    bundle["ciphertext_sha256"] = sha256_hex(ciphertext)
    bundle["sender_certificate_pem"] = b64e(cert_pem(user_cert(deployment, sender)))
    signature = rsa_pss_sign(user_key(deployment, sender), canonical_json(signed_payload(bundle)))
    bundle["signature"] = {"algorithm": "RSA-PSS-SHA256", "signature": b64e(signature)}
    return bundle


def verify_signed_bundle(bundle: dict, deployment: Path) -> None:
    cert = load_cert_from_pem(b64d(bundle["sender_certificate_pem"]))
    if cert_fingerprint(cert) != bundle["sender"]["fingerprint"]:
        raise ValueError("sender certificate fingerprint does not match bundle metadata")
    if common_name(cert) != bundle["sender"]["user"]:
        raise ValueError("sender certificate common name does not match bundle metadata")
    ciphertext = b64d(bundle["ciphertext"])
    if sha256_hex(ciphertext) != bundle["ciphertext_sha256"]:
        raise ValueError("ciphertext hash does not match")
    verify_cert_signed_by_ca(cert, load_cert(deployment / "ca" / "ca_cert.pem"))
    try:
        rsa_pss_verify(cert.public_key(), b64d(bundle["signature"]["signature"]), canonical_json(signed_payload(bundle)))
    except InvalidSignature as exc:
        raise ValueError("bundle signature is invalid") from exc


def decrypt_signed_bundle(bundle: dict, deployment: Path, user: str) -> tuple[str, bytes]:
    verify_signed_bundle(bundle, deployment)
    return decrypt_bundle(bundle, deployment, user)
