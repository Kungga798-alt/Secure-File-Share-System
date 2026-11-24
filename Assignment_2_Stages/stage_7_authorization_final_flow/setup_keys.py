"""Generate demo CA, server, and user certificates.

Appendix B contribution placeholder:
Replace this block with the group member name(s) responsible for deployment
files and key management tooling.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from secure_file_share.certs import (
    cert_fingerprint,
    create_ca,
    create_signed_cert,
    generate_private_key,
    save_cert,
    save_private_key,
)


DEFAULT_PASSWORD = "changeit"
DEFAULT_USERS = ("alice", "bob", "charlie")


def _contains_pem_files(path: Path) -> bool:
    """Return whether a deployment folder already contains PEM credentials."""

    return path.exists() and any(path.rglob("*.pem"))


def initialize_demo(
    deployment_dir: Path,
    *,
    password: str = DEFAULT_PASSWORD,
    users: tuple[str, ...] = DEFAULT_USERS,
    force: bool = False,
) -> dict:
    """Generate the demo CA, server certificate, user certificates, and identity registry."""

    deployment_dir = Path(deployment_dir)
    if _contains_pem_files(deployment_dir) and not force:
        raise FileExistsError(
            f"{deployment_dir} already contains PEM files; rerun with --force to overwrite"
        )

    ca_key, ca_cert = create_ca("ACG Assignment 2 Demo CA")
    save_private_key(deployment_dir / "ca" / "ca_key.pem", ca_key, password)
    save_cert(deployment_dir / "ca" / "ca_cert.pem", ca_cert)

    server_key = generate_private_key()
    server_cert = create_signed_cert(
        "localhost",
        server_key.public_key(),
        ca_key,
        ca_cert,
        is_server=True,
        alt_names=("localhost", "127.0.0.1"),
    )
    save_private_key(deployment_dir / "server" / "server_key.pem", server_key, password)
    save_cert(deployment_dir / "server" / "server_cert.pem", server_cert)

    registry: dict[str, dict[str, str]] = {
        "ca": {
            "cert": "ca/ca_cert.pem",
            "fingerprint": cert_fingerprint(ca_cert),
        },
        "server": {
            "cert": "server/server_cert.pem",
            "fingerprint": cert_fingerprint(server_cert),
        },
        "users": {},
    }

    for user in users:
        user_key = generate_private_key()
        user_cert = create_signed_cert(
            user,
            user_key.public_key(),
            ca_key,
            ca_cert,
            is_server=False,
        )
        save_private_key(deployment_dir / "users" / user / "key.pem", user_key, password)
        save_cert(deployment_dir / "users" / user / "cert.pem", user_cert)
        registry["users"][user] = {
            "cert": f"users/{user}/cert.pem",
            "key": f"users/{user}/key.pem",
            "fingerprint": cert_fingerprint(user_cert),
        }

    (deployment_dir / "registry.json").write_text(
        json.dumps(registry, sort_keys=True, indent=2),
        encoding="utf-8",
    )
    return registry


def build_parser() -> argparse.ArgumentParser:
    """Build the setup CLI parser for reproducible demo deployment generation."""

    parser = argparse.ArgumentParser(description="Generate demo deployment keys and certificates.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init-demo")
    init.add_argument("--deployment", default="deployment")
    init.add_argument("--password", default=DEFAULT_PASSWORD)
    init.add_argument("--users", nargs="+", default=list(DEFAULT_USERS))
    init.add_argument("--force", action="store_true")
    return parser


def main() -> None:
    """Run the requested setup command and print generated deployment details."""

    args = build_parser().parse_args()
    if args.command == "init-demo":
        registry = initialize_demo(
            Path(args.deployment),
            password=args.password,
            users=tuple(args.users),
            force=args.force,
        )
        print(f"generated deployment files in {Path(args.deployment).resolve()}")
        print(f"users: {', '.join(registry['users'])}")
        print("demo private-key password: changeit")


if __name__ == "__main__":
    main()
