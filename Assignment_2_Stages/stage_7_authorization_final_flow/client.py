"""Secure file-sharing client CLI.

Appendix B contribution placeholder:p
Replace this block with the group member name(s) responsible for the client
program.
"""

from __future__ import annotations

import argparse
import socket
from pathlib import Path

from secure_file_share.bundle import create_bundle, decrypt_bundle, load_bundle, save_bundle, verify_bundle
from secure_file_share.certs import build_client_context, load_cert, load_user_credentials, user_cert_path
from secure_file_share.protocol import recv_message, send_message


DEFAULT_PASSWORD = "changeit"


def request_server(
    host: str,
    port: int,
    *,
    deployment_dir: Path,
    user: str,
    password: str,
    message: dict,
    server_name: str | None = None,
) -> dict:
    """Send one JSON request over a mutually authenticated TLS connection and return the response."""

    context = build_client_context(deployment_dir, user, password)
    with socket.create_connection((host, port), timeout=10) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=server_name or host) as tls_socket:
            send_message(tls_socket, message)
            response = recv_message(tls_socket)
    return response


def fail_if_error(response: dict) -> None:
    """Abort a CLI command when the server returns a non-ok status."""

    if response.get("status") != "ok":
        raise SystemExit(f"server error: {response.get('error', 'unknown error')}")


def cmd_upload(args) -> None:
    """Encrypt, sign, and upload a file bundle for the sender and requested recipients."""

    deployment_dir = Path(args.deployment)
    sender_key, sender_cert = load_user_credentials(deployment_dir, args.user, args.password)
    recipient_names = list(dict.fromkeys([args.user, *args.to]))
    recipients = [(name, load_cert(user_cert_path(deployment_dir, name))) for name in recipient_names]
    bundle = create_bundle(
        Path(args.file),
        sender_user=args.user,
        sender_private_key=sender_key,
        sender_cert=sender_cert,
        recipient_certs=recipients,
    )
    response = request_server(
        args.host,
        args.port,
        deployment_dir=deployment_dir,
        user=args.user,
        password=args.password,
        message={"action": "upload", "bundle": bundle},
        server_name=args.server_name,
    )
    fail_if_error(response)
    print(f"uploaded file_id={response['file_id']}")


def cmd_list(args) -> None:
    """List server-side bundle metadata authorized for the authenticated user's certificate."""

    response = request_server(
        args.host,
        args.port,
        deployment_dir=Path(args.deployment),
        user=args.user,
        password=args.password,
        message={"action": "list"},
        server_name=args.server_name,
    )
    fail_if_error(response)
    files = response["files"]
    if not files:
        print("no authorized files")
        return
    for item in files:
        recipients = ",".join(item["recipients"])
        print(
            f"{item['file_id']} | {item['original_filename']} | "
            f"sender={item['sender']} | recipients={recipients} | "
            f"created={item['created_at_utc']}"
        )


def cmd_download(args) -> None:
    """Download an authorized encrypted bundle, verify it, decrypt it locally, and write plaintext."""

    deployment_dir = Path(args.deployment)
    response = request_server(
        args.host,
        args.port,
        deployment_dir=deployment_dir,
        user=args.user,
        password=args.password,
        message={"action": "download", "file_id": args.file_id},
        server_name=args.server_name,
    )
    fail_if_error(response)
    bundle = response["bundle"]
    ca_cert = load_cert(deployment_dir / "ca" / "ca_cert.pem")
    private_key, cert = load_user_credentials(deployment_dir, args.user, args.password)
    filename, plaintext = decrypt_bundle(
        bundle,
        recipient_private_key=private_key,
        recipient_cert=cert,
        ca_cert=ca_cert,
    )
    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / filename
    output_path.write_bytes(plaintext)
    if args.save_bundle:
        save_bundle(output_dir / f"{args.file_id}.sfs", bundle)
    print(f"downloaded and decrypted to {output_path}")


def cmd_verify(args) -> None:
    """Verify a stored .sfs bundle offline against the configured CA certificate."""

    bundle = load_bundle(Path(args.bundle))
    ca_cert = load_cert(Path(args.ca))
    verify_bundle(bundle, ca_cert=ca_cert)
    header = bundle["protected_header"]
    print(
        f"bundle verified: file_id={header['file_id']} "
        f"sender={header['sender']['user']} filename={header['original_filename']}"
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the client CLI parser for upload, list, download, and verify workflows."""

    parser = argparse.ArgumentParser(description="Secure file-sharing client.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--deployment", default="deployment")
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--server-name", default=None)
    subparsers = parser.add_subparsers(dest="command", required=True)

    upload = subparsers.add_parser("upload", help="encrypt, sign, and upload a file")
    upload.add_argument("--user", required=True)
    upload.add_argument("--to", nargs="+", required=True)
    upload.add_argument("--file", required=True)
    upload.set_defaults(func=cmd_upload)

    list_cmd = subparsers.add_parser("list", help="list files authorized for this user")
    list_cmd.add_argument("--user", required=True)
    list_cmd.set_defaults(func=cmd_list)

    download = subparsers.add_parser("download", help="download and decrypt a file")
    download.add_argument("--user", required=True)
    download.add_argument("--file-id", required=True)
    download.add_argument("--out", default="downloads")
    download.add_argument("--save-bundle", action="store_true")
    download.set_defaults(func=cmd_download)

    verify = subparsers.add_parser("verify", help="verify an encrypted .sfs bundle")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--ca", default="deployment/ca/ca_cert.pem")
    verify.set_defaults(func=cmd_verify)
    return parser


def main() -> None:
    """Parse the selected subcommand and execute its handler."""

    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
