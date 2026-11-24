from __future__ import annotations

import argparse
import json
import socket
from pathlib import Path

from secure_file_share.bundle import create_signed_bundle, decrypt_signed_bundle
from secure_file_share.certs import build_client_context
from secure_file_share.protocol import recv_message, send_message


def request(host: str, port: int, deployment: Path, user: str, message: dict) -> dict:
    with socket.create_connection((host, port), timeout=10) as raw:
        with build_client_context(deployment, user).wrap_socket(raw, server_hostname="localhost") as sock:
            send_message(sock, message)
            return recv_message(sock)


def main() -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parent
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9106)
    parser.add_argument("--deployment", default=str(root / "deployment"))
    parser.add_argument("--user", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    upload = sub.add_parser("upload")
    upload.add_argument("file")
    upload.add_argument("--to", nargs="+", required=True)
    sub.add_parser("list")
    download = sub.add_parser("download")
    download.add_argument("file_id")
    download.add_argument("--out", default="downloads")
    args = parser.parse_args()
    deployment = Path(args.deployment)

    if args.command == "upload":
        bundle = create_signed_bundle(Path(args.file), deployment, args.user, args.to)
        print(request(args.host, args.port, deployment, args.user, {"action": "upload", "bundle": bundle}))
    elif args.command == "list":
        print(json.dumps(request(args.host, args.port, deployment, args.user, {"action": "list"}), indent=2))
    else:
        response = request(args.host, args.port, deployment, args.user, {"action": "download", "file_id": args.file_id})
        if response.get("status") != "ok":
            raise SystemExit(response)
        filename, plaintext = decrypt_signed_bundle(response["bundle"], deployment, args.user)
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / Path(filename).name
        out_path.write_bytes(plaintext)
        print(f"verified and decrypted to {out_path}")


if __name__ == "__main__":
    main()
