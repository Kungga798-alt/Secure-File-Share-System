"""Encrypted file bundle creation, verification, and decryption.

Appendix B contribution placeholder:
Replace this block with the group member name(s) responsible for secure file
packaging, non-repudiation, and integrity checks.
"""

from __future__ import annotations

import copy
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtendedKeyUsageOID

from .certs import (
    CertificateError,
    cert_fingerprint,
    cert_pem,
    common_name,
    load_cert_from_pem,
    verify_cert_signed_by_ca,
)
from .crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    b64d,
    b64e,
    canonical_json,
    rsa_oaep_unwrap,
    rsa_oaep_wrap,
    rsa_pss_sign,
    rsa_pss_verify,
    sha256_hex,
)


ALGORITHMS = {
    "file_encryption": "AES-256-GCM",
    "key_wrap": "RSA-OAEP-SHA256",
    "signature": "RSA-PSS-SHA256",
    "hash": "SHA-256",
    "transport": "TLS-1.3-mutual-auth",
}


class BundleError(ValueError):
    """Raised when an encrypted file bundle fails validation."""


def _utc_now() -> str:
    """Return a UTC timestamp string so all machines interpret bundle creation time consistently."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _recipient_identity(user: str, cert) -> dict[str, str]:
    """Build recipient metadata with a display name and certificate fingerprint."""

    return {
        "user": user,
        "cert_fingerprint": cert_fingerprint(cert),
    }


def _unique_recipients(recipients: Iterable[tuple[str, object]]) -> list[tuple[str, object]]:
    """Deduplicate recipients by certificate fingerprint and sort them for stable signatures."""

    by_fingerprint: dict[str, tuple[str, object]] = {}
    for user, cert in recipients:
        by_fingerprint[cert_fingerprint(cert)] = (user, cert)
    return sorted(by_fingerprint.values(), key=lambda item: item[0].lower())


def _signing_payload_from_bundle(bundle: dict) -> dict:
    """Extract the security-critical bundle fields covered by the sender signature."""

    return {
        "protected_header": bundle["protected_header"],
        "wrapped_keys": bundle["wrapped_keys"],
        "nonce": bundle["nonce"],
        "ciphertext_sha256": bundle["ciphertext_sha256"],
        "plaintext_sha256": bundle["plaintext_sha256"],
        "ciphertext_size": bundle["ciphertext_size"],
    }


def create_bundle(
    file_path: Path,
    *,
    sender_user: str,
    sender_private_key,
    sender_cert,
    recipient_certs: Iterable[tuple[str, object]],
) -> dict:
    """Create an encrypted .sfs bundle with authenticated metadata and an RSA-PSS signature.

    The file is encrypted once with AES-GCM, the AES key is wrapped once per
    unique recipient certificate, and the sender signs the manifest fields that
    must not be changed.
    """

    path = Path(file_path)
    plaintext = path.read_bytes()
    recipients = _unique_recipients(recipient_certs)
    if not recipients:
        raise BundleError("at least one recipient certificate is required")

    sender_fingerprint = cert_fingerprint(sender_cert)
    protected_header = {
        "version": 1,
        "file_id": uuid.uuid4().hex,
        "original_filename": path.name,
        "created_at_utc": _utc_now(),
        "sender": {
            "user": sender_user,
            "cert_fingerprint": sender_fingerprint,
        },
        "recipients": [_recipient_identity(user, cert) for user, cert in recipients],
        "algorithms": ALGORITHMS,
    }

    associated_data = canonical_json(protected_header)
    aes_key, nonce, ciphertext = aes_gcm_encrypt(plaintext, associated_data)
    wrapped_keys = [
        {
            "user": user,
            "cert_fingerprint": cert_fingerprint(cert),
            "wrapped_key": b64e(rsa_oaep_wrap(cert.public_key(), aes_key)),
        }
        for user, cert in recipients
    ]

    bundle = {
        "protected_header": protected_header,
        "wrapped_keys": wrapped_keys,
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "ciphertext_sha256": sha256_hex(ciphertext),
        "plaintext_sha256": sha256_hex(plaintext),
        "ciphertext_size": len(ciphertext),
        "sender_certificate_pem": b64e(cert_pem(sender_cert)),
    }
    payload = _signing_payload_from_bundle(bundle)
    signature = rsa_pss_sign(sender_private_key, canonical_json(payload))
    bundle["signature"] = {
        "signer_user": sender_user,
        "signer_cert_fingerprint": sender_fingerprint,
        "signature": b64e(signature),
    }
    return bundle


def verify_bundle(bundle: dict, ca_cert=None) -> None:
    """Validate bundle structure, hashes, sender certificate identity, CA trust, and signature."""

    try:
        sender_cert = load_cert_from_pem(b64d(bundle["sender_certificate_pem"]))
        protected_header = bundle["protected_header"]
        sender = protected_header["sender"]
        signature_block = bundle["signature"]
        ciphertext = b64d(bundle["ciphertext"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BundleError("bundle is missing required fields") from exc

    actual_fingerprint = cert_fingerprint(sender_cert)
    if actual_fingerprint != sender["cert_fingerprint"]:
        raise BundleError("sender certificate fingerprint does not match protected header")
    if signature_block["signer_cert_fingerprint"] != actual_fingerprint:
        raise BundleError("signature signer fingerprint does not match sender certificate")
    if common_name(sender_cert) != sender["user"]:
        raise BundleError("sender certificate common name does not match sender user")
    if sha256_hex(ciphertext) != bundle["ciphertext_sha256"]:
        raise BundleError("ciphertext hash does not match bundle metadata")
    if len(ciphertext) != bundle["ciphertext_size"]:
        raise BundleError("ciphertext size does not match bundle metadata")

    if ca_cert is not None:
        try:
            verify_cert_signed_by_ca(
                sender_cert,
                ca_cert,
                expected_eku=ExtendedKeyUsageOID.CLIENT_AUTH,
            )
        except CertificateError as exc:
            raise BundleError(str(exc)) from exc

    payload = _signing_payload_from_bundle(bundle)
    try:
        rsa_pss_verify(
            sender_cert.public_key(),
            b64d(signature_block["signature"]),
            canonical_json(payload),
        )
    except InvalidSignature as exc:
        raise BundleError("sender signature is invalid") from exc


def decrypt_bundle(
    bundle: dict,
    *,
    recipient_private_key,
    recipient_cert,
    ca_cert=None,
) -> tuple[str, bytes]:
    """Verify a bundle, unwrap the recipient's AES key, and return filename plus plaintext."""

    verify_bundle(bundle, ca_cert=ca_cert)
    recipient_fingerprint = cert_fingerprint(recipient_cert)
    wrapped_entry = None
    for entry in bundle["wrapped_keys"]:
        if entry["cert_fingerprint"] == recipient_fingerprint:
            wrapped_entry = entry
            break
    if wrapped_entry is None:
        raise PermissionError("this recipient certificate is not authorized for the bundle")

    aes_key = rsa_oaep_unwrap(recipient_private_key, b64d(wrapped_entry["wrapped_key"]))
    protected_header = bundle["protected_header"]
    plaintext = aes_gcm_decrypt(
        aes_key,
        b64d(bundle["nonce"]),
        b64d(bundle["ciphertext"]),
        canonical_json(protected_header),
    )
    if sha256_hex(plaintext) != bundle["plaintext_sha256"]:
        raise BundleError("plaintext hash does not match bundle metadata")
    return protected_header["original_filename"], plaintext


def save_bundle(path: Path, bundle: dict) -> None:
    """Write an encrypted bundle as readable JSON without exposing plaintext."""

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        json.dumps(bundle, sort_keys=True, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )


def load_bundle(path: Path) -> dict:
    """Load an encrypted bundle JSON file without performing verification."""

    return json.loads(Path(path).read_text(encoding="utf-8"))


def clone_bundle(bundle: dict) -> dict:
    """Return a deep copy suitable for tests that mutate bundle contents."""

    return copy.deepcopy(bundle)
