"""Version-2 encrypted file bundles with a minimal public envelope.

Appendix B contribution: [Student 2] implemented the AES/RSA bundle design;
[Student 4] reviewed its integration, integrity, and final hardening.
"""

from __future__ import annotations

import copy
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.x509.oid import ExtendedKeyUsageOID

from .certs import (
    CertificateError,
    cert_fingerprint,
    cert_pem,
    load_cert_from_pem,
    verify_cert_signed_by_ca,
)
from .crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt_with_key,
    b64d,
    b64e,
    canonical_json,
    generate_aes256_key,
    rsa_oaep_unwrap,
    rsa_oaep_wrap,
    rsa_pss_sign,
    rsa_pss_verify,
)


BUNDLE_VERSION = 2
FINGERPRINT_LENGTH = 64
BUNDLE_FIELDS = frozenset(
    {
        "version",
        "file_id",
        "original_filename",
        "sender_cert_fingerprint",
        "wrapped_keys",
        "file_nonce",
        "metadata_nonce",
        "ciphertext",
        "encrypted_metadata",
        "sender_certificate_pem",
        "signature",
    }
)
WRAPPED_KEY_FIELDS = frozenset({"cert_fingerprint", "wrapped_key"})
METADATA_FIELDS = frozenset({"created_at_utc", "sender_user", "recipients"})
MAX_FILENAME_LENGTH = 255
WINDOWS_RESERVED_BASENAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", *(f"COM{number}" for number in range(1, 10)), *(f"LPT{number}" for number in range(1, 10))}
)


class BundleError(ValueError):
    """Raised when an encrypted file bundle fails validation."""


def _utc_now() -> str:
    """Return a UTC timestamp string so all machines interpret bundle creation time consistently."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _unique_recipients(recipients: Iterable[tuple[str, object]]) -> list[tuple[str, object]]:
    """Deduplicate recipients by certificate fingerprint and sort them for stable signatures."""

    by_fingerprint: dict[str, tuple[str, object]] = {}
    for user, cert in recipients:
        by_fingerprint[cert_fingerprint(cert)] = (user, cert)
    return sorted(by_fingerprint.values(), key=lambda item: item[0].lower())


def _outer_header(bundle: dict) -> dict:
    """Return the small public header authenticated as AES-GCM associated data."""

    return {
        "version": bundle["version"],
        "file_id": bundle["file_id"],
        "original_filename": bundle["original_filename"],
        "sender_cert_fingerprint": bundle["sender_cert_fingerprint"],
    }


def _signing_payload_from_bundle(bundle: dict) -> dict:
    """Return every security-relevant public field that the sender signs."""

    return {field: bundle[field] for field in BUNDLE_FIELDS if field != "signature"}


def _is_fingerprint(value: object) -> bool:
    """Return whether a value is a lowercase SHA-256 certificate fingerprint."""

    return (
        isinstance(value, str)
        and len(value) == FINGERPRINT_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_safe_filename(value: object) -> bool:
    """Accept one portable basename for the deliberate plaintext listing field."""

    if not isinstance(value, str):
        return False
    stem = value.split(".", 1)[0].upper()
    return (
        0 < len(value) <= MAX_FILENAME_LENGTH
        and value not in {".", ".."}
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
        and stem not in WINDOWS_RESERVED_BASENAMES
    )


def _validate_public_shape(bundle: dict) -> None:
    """Reject legacy, malformed, or metadata-rich public envelopes before verification."""

    if not isinstance(bundle, dict) or set(bundle) != BUNDLE_FIELDS:
        raise BundleError("bundle does not match the version-2 minimal envelope")
    if bundle["version"] != BUNDLE_VERSION:
        raise BundleError("unsupported bundle version")
    if not isinstance(bundle["file_id"], str) or len(bundle["file_id"]) != 32:
        raise BundleError("bundle has an invalid file id")
    if not _is_safe_filename(bundle["original_filename"]):
        raise BundleError("bundle has an invalid original filename")
    if not _is_fingerprint(bundle["sender_cert_fingerprint"]):
        raise BundleError("bundle has an invalid sender certificate fingerprint")
    if not isinstance(bundle["wrapped_keys"], list) or not bundle["wrapped_keys"]:
        raise BundleError("bundle must contain at least one wrapped key")
    fingerprints: set[str] = set()
    for entry in bundle["wrapped_keys"]:
        if not isinstance(entry, dict) or set(entry) != WRAPPED_KEY_FIELDS:
            raise BundleError("bundle has an invalid wrapped-key entry")
        if not _is_fingerprint(entry["cert_fingerprint"]) or not isinstance(entry["wrapped_key"], str):
            raise BundleError("bundle has an invalid wrapped-key entry")
        if entry["cert_fingerprint"] in fingerprints:
            raise BundleError("bundle contains duplicate recipient fingerprints")
        fingerprints.add(entry["cert_fingerprint"])
    for field in ("file_nonce", "metadata_nonce", "ciphertext", "encrypted_metadata", "sender_certificate_pem", "signature"):
        if not isinstance(bundle[field], str):
            raise BundleError(f"bundle field {field} must be a Base64 string")
    if len(bundle["file_nonce"]) == 0 or len(bundle["metadata_nonce"]) == 0:
        raise BundleError("bundle is missing an AES-GCM nonce")


def create_bundle(
    file_path: Path,
    *,
    sender_user: str,
    sender_private_key,
    sender_cert,
    recipient_certs: Iterable[tuple[str, object]],
) -> dict:
    """Create a v2 bundle with one signed plaintext filename for authorized listings."""

    path = Path(file_path)
    if not _is_safe_filename(path.name):
        raise BundleError("file path has an invalid filename")
    plaintext = path.read_bytes()
    recipients = _unique_recipients(recipient_certs)
    if not recipients:
        raise BundleError("at least one recipient certificate is required")

    sender_fingerprint = cert_fingerprint(sender_cert)
    bundle = {
        "version": BUNDLE_VERSION,
        "file_id": uuid.uuid4().hex,
        "original_filename": path.name,
        "sender_cert_fingerprint": sender_fingerprint,
        "wrapped_keys": [],
        "file_nonce": "",
        "metadata_nonce": "",
        "ciphertext": "",
        "encrypted_metadata": "",
        "sender_certificate_pem": b64e(cert_pem(sender_cert)),
        "signature": "",
    }
    associated_data = canonical_json(_outer_header(bundle))
    aes_key = generate_aes256_key()
    file_nonce, ciphertext = aes_gcm_encrypt_with_key(aes_key, plaintext, associated_data)
    metadata = {
        "created_at_utc": _utc_now(),
        "sender_user": sender_user,
        "recipients": [user for user, _ in recipients],
    }
    metadata_nonce, encrypted_metadata = aes_gcm_encrypt_with_key(
        aes_key,
        canonical_json(metadata),
        associated_data,
    )
    wrapped_keys = [
        {
            "cert_fingerprint": cert_fingerprint(cert),
            "wrapped_key": b64e(rsa_oaep_wrap(cert.public_key(), aes_key)),
        }
        for user, cert in recipients
    ]

    bundle.update(
        {
            "wrapped_keys": wrapped_keys,
            "file_nonce": b64e(file_nonce),
            "metadata_nonce": b64e(metadata_nonce),
            "ciphertext": b64e(ciphertext),
            "encrypted_metadata": b64e(encrypted_metadata),
        }
    )
    payload = _signing_payload_from_bundle(bundle)
    bundle["signature"] = b64e(rsa_pss_sign(sender_private_key, canonical_json(payload)))
    return bundle


def verify_bundle(bundle: dict, ca_cert=None) -> None:
    """Validate a v2 envelope, its sender certificate, and its sender signature."""

    try:
        _validate_public_shape(bundle)
        sender_cert = load_cert_from_pem(b64d(bundle["sender_certificate_pem"]))
        file_nonce = b64d(bundle["file_nonce"])
        metadata_nonce = b64d(bundle["metadata_nonce"])
        b64d(bundle["ciphertext"])
        b64d(bundle["encrypted_metadata"])
        b64d(bundle["signature"])
        for entry in bundle["wrapped_keys"]:
            b64d(entry["wrapped_key"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BundleError("bundle contains malformed public data") from exc

    actual_fingerprint = cert_fingerprint(sender_cert)
    if actual_fingerprint != bundle["sender_cert_fingerprint"]:
        raise BundleError("sender certificate fingerprint does not match the envelope")
    if len(file_nonce) != 12 or len(metadata_nonce) != 12 or file_nonce == metadata_nonce:
        raise BundleError("bundle has invalid AES-GCM nonces")

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
            b64d(bundle["signature"]),
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
    """Verify a bundle, decrypt hidden metadata, and return the signed filename plus bytes."""

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
    associated_data = canonical_json(_outer_header(bundle))
    try:
        metadata = json.loads(
            aes_gcm_decrypt(
                aes_key,
                b64d(bundle["metadata_nonce"]),
                b64d(bundle["encrypted_metadata"]),
                associated_data,
            ).decode("utf-8")
        )
        if not isinstance(metadata, dict) or set(metadata) != METADATA_FIELDS:
            raise BundleError("bundle contains invalid encrypted metadata")
        if not isinstance(metadata["created_at_utc"], str) or not isinstance(metadata["sender_user"], str):
            raise BundleError("bundle contains invalid encrypted identity metadata")
        if not isinstance(metadata["recipients"], list) or not all(isinstance(user, str) for user in metadata["recipients"]):
            raise BundleError("bundle contains invalid encrypted recipient metadata")
        plaintext = aes_gcm_decrypt(
            aes_key,
            b64d(bundle["file_nonce"]),
            b64d(bundle["ciphertext"]),
            associated_data,
        )
    except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise BundleError("bundle decryption or encrypted metadata validation failed") from exc
    return bundle["original_filename"], plaintext


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
