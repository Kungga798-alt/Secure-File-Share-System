from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


USERS = ("alice", "bob", "charlie")


def key_root(stage_root: Path) -> Path:
    return Path(stage_root) / "keys"


def load_private_key(stage_root: Path, user: str):
    return serialization.load_pem_private_key((key_root(stage_root) / user / "private_key.pem").read_bytes(), password=None)


def load_public_key(stage_root: Path, user: str):
    return serialization.load_pem_public_key((key_root(stage_root) / user / "public_key.pem").read_bytes())


def generate_user_keys(stage_root: Path, users: tuple[str, ...] = USERS) -> Path:
    root = key_root(stage_root)
    root.mkdir(exist_ok=True)
    for user in users:
        user_dir = root / user
        user_dir.mkdir(exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        (user_dir / "private_key.pem").write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        (user_dir / "public_key.pem").write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    return root
