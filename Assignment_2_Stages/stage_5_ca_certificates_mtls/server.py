from __future__ import annotations

import argparse
import socket
from pathlib import Path

from secure_file_share.certs import build_server_context, cert_fingerprint, common_name, peer_cert_from_ssl
from secure_file_share.protocol import recv_message, send_message
from secure_file_share.storage import handle_request


def serve(host: str, port: int, deployment: Path, storage: Path, once: bool = False) -> None:
    storage.mkdir(parents=True, exist_ok=True)
    tls_context = build_server_context(deployment)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_server:
        raw_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_server.bind((host, port))
        raw_server.listen()
        print(f"stage 5 mTLS server listening on {host}:{raw_server.getsockname()[1]}")
        while True:
            raw_client, _ = raw_server.accept()
            with tls_context.wrap_socket(raw_client, server_side=True) as client:
                cert = peer_cert_from_ssl(client)
                peer = {"user": common_name(cert), "fingerprint": cert_fingerprint(cert)}
                try:
                    send_message(client, handle_request(recv_message(client), storage, peer))
                except Exception as exc:
                    send_message(client, {"status": "error", "error": str(exc)})
            if once:
                break


def main() -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parent
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9105)
    parser.add_argument("--deployment", default=str(root / "deployment"))
    parser.add_argument("--storage", default="server_storage")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    serve(args.host, args.port, Path(args.deployment), Path(args.storage), args.once)


if __name__ == "__main__":
    main()
