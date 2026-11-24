from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


USERS = ("alice", "bob", "charlie")


def cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def common_name(cert: x509.Certificate) -> str:
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def load_cert_from_pem(data: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(data)


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def load_private_key(path: Path):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def save_key(path: Path, key) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def save_cert(path: Path, cert: x509.Certificate) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def make_ca(deployment: Path) -> None:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Stage 6 Demo CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    save_key(deployment / "ca" / "ca_key.pem", ca_key)
    save_cert(deployment / "ca" / "ca_cert.pem", ca_cert)

    def issue(name: str, key, is_server: bool) -> x509.Certificate:
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if is_server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        )
        if is_server:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(IPv4Address("127.0.0.1"))]), critical=False)
        return builder.sign(ca_key, hashes.SHA256())

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    save_key(deployment / "server" / "server_key.pem", server_key)
    save_cert(deployment / "server" / "server_cert.pem", issue("localhost", server_key, True))
    for user in USERS:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        save_key(deployment / "users" / user / "key.pem", key)
        save_cert(deployment / "users" / user / "cert.pem", issue(user, key, False))


def user_cert(deployment: Path, user: str) -> x509.Certificate:
    return load_cert(deployment / "users" / user / "cert.pem")


def user_key(deployment: Path, user: str):
    return load_private_key(deployment / "users" / user / "key.pem")


def verify_cert_signed_by_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)


def build_client_context(deployment: Path, user: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=deployment / "ca" / "ca_cert.pem")
    ctx.load_cert_chain(deployment / "users" / user / "cert.pem", deployment / "users" / user / "key.pem")
    return ctx


def build_server_context(deployment: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(deployment / "server" / "server_cert.pem", deployment / "server" / "server_key.pem")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=deployment / "ca" / "ca_cert.pem")
    return ctx


def peer_cert_from_ssl(sock) -> x509.Certificate:
    return x509.load_der_x509_certificate(sock.getpeercert(binary_form=True))
