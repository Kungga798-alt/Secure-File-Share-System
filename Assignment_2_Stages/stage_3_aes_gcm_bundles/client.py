from __future__ import annotations

import argparse
import socket
from pathlib import Path

from secure_file_share.bundle import create_bundle, decrypt_bundle
from secure_file_share.protocol import recv_message, send_message


def request(host: str, port: int, message: dict) -> dict:
    with socket.create_connection((host, port), timeout=10) as sock:
        send_message(sock, message)
        return recv_message(sock)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9103)
    sub = parser.add_subparsers(dest="command", required=True)
    upload = sub.add_parser("upload")
    upload.add_argument("file")
    sub.add_parser("list")
    download = sub.add_parser("download")
    download.add_argument("file_id")
    download.add_argument("--out", default="downloads")
    args = parser.parse_args()
    stage_root = Path(__file__).resolve().parent

    if args.command == "upload":
        print(request(args.host, args.port, {"action": "upload", "bundle": create_bundle(Path(args.file), stage_root)}))
    elif args.command == "list":
        print(request(args.host, args.port, {"action": "list"}))
    else:
        response = request(args.host, args.port, {"action": "download", "file_id": args.file_id})
        if response.get("status") != "ok":
            raise SystemExit(response)
        filename, plaintext = decrypt_bundle(response["bundle"], stage_root)
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / Path(filename).name
        out_path.write_bytes(plaintext)
        print(f"decrypted to {out_path}")


if __name__ == "__main__":
    main()
