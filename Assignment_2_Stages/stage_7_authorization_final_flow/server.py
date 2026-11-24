"""Secure TLS file-sharing server.

Appendix B contribution placeholder:
Replace this block with the group member name(s) responsible for the server
program.
"""

from __future__ import annotations

import argparse
import socket
import threading
from pathlib import Path
from typing import Any

from cryptography.x509.oid import ExtendedKeyUsageOID

from secure_file_share.bundle import BundleError, verify_bundle
from secure_file_share.certs import (
    build_server_context,
    cert_fingerprint,
    common_name,
    load_cert,
    peer_cert_from_ssl,
    verify_cert_signed_by_ca,
)
from secure_file_share.protocol import recv_message, send_message
from secure_file_share.storage import BundleStorage, StorageError


DEFAULT_PASSWORD = "changeit"


class SecureFileServer:
    """Mutual-TLS file-sharing server that stores only verified encrypted bundles."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        deployment_dir: Path,
        storage_dir: Path,
        password: str = DEFAULT_PASSWORD,
    ):
        self.host = host
        self.port = port
        self.deployment_dir = Path(deployment_dir)
        self.storage = BundleStorage(Path(storage_dir))
        self.password = password
        self._stop = threading.Event()
        self._server_socket: socket.socket | None = None
        self.ca_cert = load_cert(self.deployment_dir / "ca" / "ca_cert.pem")

    def stop(self) -> None:
        """Stop the accept loop and close the listening socket for clean shutdown."""

        self._stop.set()
        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except OSError:
                pass

    def serve_forever(self, *, max_connections: int | None = None, ready_event=None) -> None:
        """Accept TCP clients, wrap each in TLS, and dispatch each request in a worker thread."""

        context = build_server_context(self.deployment_dir, self.password)
        handled = 0
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(20)
            server_socket.settimeout(0.5)
            self._server_socket = server_socket
            self.port = server_socket.getsockname()[1]
            if ready_event is not None:
                ready_event.set()
            print(f"secure file-sharing server listening on {self.host}:{self.port}")

            while not self._stop.is_set():
                if max_connections is not None and handled >= max_connections:
                    break
                try:
                    client_socket, address = server_socket.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                handled += 1
                thread = threading.Thread(
                    target=self._handle_raw_client,
                    args=(context, client_socket, address),
                    daemon=True,
                )
                thread.start()

    def _handle_raw_client(self, context: ssl.SSLContext, client_socket: socket.socket, address) -> None:
        """Complete the TLS handshake for a raw socket before handling application JSON."""

        try:
            with context.wrap_socket(client_socket, server_side=True) as tls_socket:
                self._handle_tls_client(tls_socket, address)
        except Exception as exc:
            print(f"connection from {address} failed: {exc}")

    def _handle_tls_client(self, tls_socket, address) -> None:
        """Authenticate the peer certificate, route one request, and return a JSON response."""

        try:
            peer_cert = peer_cert_from_ssl(tls_socket)
            verify_cert_signed_by_ca(
                peer_cert,
                self.ca_cert,
                expected_eku=ExtendedKeyUsageOID.CLIENT_AUTH,
            )
            peer_identity = {
                "user": common_name(peer_cert),
                "cert_fingerprint": cert_fingerprint(peer_cert),
            }
            request = recv_message(tls_socket)
            response = self._dispatch(request, peer_identity)
        except Exception as exc:
            response = {"status": "error", "error": str(exc)}
        send_message(tls_socket, response)

    def _dispatch(self, request: dict[str, Any], peer_identity: dict[str, str]) -> dict[str, Any]:
        """Route the requested upload, list, or download action for an authenticated user."""

        action = request.get("action")
        if action == "upload":
            return self._upload(request, peer_identity)
        if action == "list":
            return self._list(peer_identity)
        if action == "download":
            return self._download(request, peer_identity)
        raise ValueError("unknown action")

    def _upload(self, request: dict[str, Any], peer_identity: dict[str, str]) -> dict[str, Any]:
        """Verify a signed encrypted bundle and store it only if TLS identity matches the sender."""

        bundle = request.get("bundle")
        if not isinstance(bundle, dict):
            raise ValueError("upload request must include a bundle object")
        verify_bundle(bundle, ca_cert=self.ca_cert)
        sender = bundle["protected_header"]["sender"]
        if sender["user"] != peer_identity["user"]:
            raise PermissionError("TLS client identity does not match bundle sender")
        if sender["cert_fingerprint"] != peer_identity["cert_fingerprint"]:
            raise PermissionError("TLS client certificate does not match bundle sender")
        file_id = self.storage.save(bundle)
        return {"status": "ok", "file_id": file_id}

    def _list(self, peer_identity: dict[str, str]) -> dict[str, Any]:
        """Return metadata for bundles where the peer fingerprint is sender or recipient."""

        return {
            "status": "ok",
            "files": self.storage.list_for(peer_identity["cert_fingerprint"]),
        }

    def _download(self, request: dict[str, Any], peer_identity: dict[str, str]) -> dict[str, Any]:
        """Return an encrypted bundle only when the peer fingerprint is authorized."""

        file_id = request.get("file_id")
        if not isinstance(file_id, str):
            raise ValueError("download request must include file_id")
        bundle = self.storage.load(file_id)
        if not self.storage.is_authorized(bundle, peer_identity["cert_fingerprint"]):
            raise PermissionError("authenticated user is not authorized for this file")
        return {"status": "ok", "bundle": bundle}


def build_parser() -> argparse.ArgumentParser:
    """Build the server CLI parser with explicit host, deployment, storage, and password options."""

    parser = argparse.ArgumentParser(description="Start the secure file-sharing server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--deployment", default="deployment")
    parser.add_argument("--storage", default="server_storage")
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    return parser


def main() -> None:
    """Create the server from CLI arguments and run until interrupted or stopped."""

    args = build_parser().parse_args()
    server = SecureFileServer(
        args.host,
        args.port,
        deployment_dir=Path(args.deployment),
        storage_dir=Path(args.storage),
        password=args.password,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("server stopped")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
