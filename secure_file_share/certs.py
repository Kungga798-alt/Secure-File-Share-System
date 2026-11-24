"""Certificate and key management helpers.

Appendix B contribution: [Student 3] implemented certificate issuance and
validation; [Student 4] integrated PKI into the final project.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class CertificateError(ValueError):
    """Raised when a certificate fails project-level validation."""


def generate_private_key():
    """Generate an RSA-3072 private key for the assignment's TLS and bundle operations."""

    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def load_private_key(path: Path, password: str | None):
    """Load a PEM private key, using the password locally when the key is encrypted."""

    data = Path(path).read_bytes()
    password_bytes = password.encode("utf-8") if password else None
    return serialization.load_pem_private_key(data, password=password_bytes)


def save_private_key(path: Path, private_key, password: str | None) -> None:
    """Save a PEM private key with password encryption when a password is provided."""

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    encryption = (
        serialization.BestAvailableEncryption(password.encode("utf-8"))
        if password
        else serialization.NoEncryption()
    )
    data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    Path(path).write_bytes(data)


def load_cert(path: Path) -> x509.Certificate:
    """Load a PEM certificate containing the public key, subject, usage fields, and issuer signature."""

    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def load_cert_from_pem(data: bytes) -> x509.Certificate:
    """Parse a PEM certificate embedded in a bundle for sender verification."""

    return x509.load_pem_x509_certificate(data)


def save_cert(path: Path, cert: x509.Certificate) -> None:
    """Write a public certificate as plain PEM."""

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def cert_pem(cert: x509.Certificate) -> bytes:
    """Serialize a certificate to PEM bytes for bundle storage and later verification."""

    return cert.public_bytes(serialization.Encoding.PEM)


def cert_fingerprint(cert: x509.Certificate) -> str:
    """Return the SHA-256 certificate fingerprint used as the access-control identity."""

    return cert.fingerprint(hashes.SHA256()).hex()


def common_name(cert: x509.Certificate) -> str:
    """Return the certificate Common Name used as the human-readable demo identity."""

    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        raise CertificateError("certificate has no common name")
    return attrs[0].value


def _utc(dt: datetime) -> datetime:
    """Normalize certificate validity datetimes to timezone-aware UTC values."""

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _not_before(cert: x509.Certificate) -> datetime:
    """Return the certificate not-before time using UTC-aware fields when available."""

    value = getattr(cert, "not_valid_before_utc", None)
    if value is not None:
        return value
    return _utc(cert.not_valid_before)


def _not_after(cert: x509.Certificate) -> datetime:
    """Return the certificate not-after time using UTC-aware fields when available."""

    value = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    return _utc(cert.not_valid_after)


def create_ca(subject_name: str, valid_days: int = 3650):
    """Create a self-signed CA certificate that can issue demo server and user certificates."""

    key = generate_private_key()
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SG"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ST2504 Assignment Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return key, cert


def _subject_alt_names(values: Iterable[str]) -> x509.SubjectAlternativeName:
    """Convert DNS names and IP strings into X.509 Subject Alternative Name entries."""

    names: list[x509.GeneralName] = []
    for value in values:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(value)))
        except ValueError:
            names.append(x509.DNSName(value))
    return x509.SubjectAlternativeName(names)


def create_signed_cert(
    common_name_value: str,
    public_key,
    ca_key,
    ca_cert: x509.Certificate,
    *,
    is_server: bool,
    alt_names: Iterable[str] = (),
    valid_days: int = 825,
) -> x509.Certificate:
    """Create a CA-signed end-entity certificate for TLS server or client authentication.

    The subject identifies the user or server, Extended Key Usage separates
    server certificates from client certificates, and optional SANs enable TLS
    hostname verification for local server names.
    """

    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SG"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ST2504 Secure File Share"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name_value),
        ]
    )
    eku = ExtendedKeyUsageOID.SERVER_AUTH if is_server else ExtendedKeyUsageOID.CLIENT_AUTH
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    if alt_names:
        builder = builder.add_extension(_subject_alt_names(alt_names), critical=False)
    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


def verify_cert_signed_by_ca(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    *,
    expected_eku=None,
) -> None:
    """Verify issuer, validity window, CA signature, and optional Extended Key Usage."""

    if cert.issuer != ca_cert.subject:
        raise CertificateError("certificate was not issued by the configured CA")

    now = datetime.now(timezone.utc)
    if now < _not_before(cert) or now > _not_after(cert):
        raise CertificateError("certificate is outside its validity period")

    ca_public_key = ca_cert.public_key()
    ca_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )

    if expected_eku is not None:
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound as exc:
            raise CertificateError("certificate has no extended key usage") from exc
        if expected_eku not in eku:
            raise CertificateError("certificate has the wrong extended key usage")


def peer_cert_from_ssl(ssl_socket) -> x509.Certificate:
    """Parse the peer certificate from a completed TLS handshake."""

    der = ssl_socket.getpeercert(binary_form=True)
    if not der:
        raise CertificateError("peer did not provide a certificate")
    return x509.load_der_x509_certificate(der)
