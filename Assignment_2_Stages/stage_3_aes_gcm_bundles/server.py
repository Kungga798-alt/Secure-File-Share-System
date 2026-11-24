from __future__ import annotations

import argparse
import socket
from pathlib import Path

from secure_file_share.protocol import recv_message, send_message
from secure_file_share.storage import handle_request


def serve(host: str, port: int, storage: Path, once: bool = False) -> None:
    storage.mkdir(parents=True, exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen()
        print(f"stage 3 server listening on {host}:{server.getsockname()[1]}")
        while True:
            client, _ = server.accept()
            with client:
                try:
                    send_message(client, handle_request(recv_message(client), storage))
                except Exception as exc:
                    send_message(client, {"status": "error", "error": str(exc)})
            if once:
                break


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9103)
    parser.add_argument("--storage", default="server_storage")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    serve(args.host, args.port, Path(args.storage), args.once)


if __name__ == "__main__":
    main()
