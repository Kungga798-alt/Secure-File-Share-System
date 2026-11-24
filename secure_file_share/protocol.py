"""Length-prefixed JSON protocol over TLS sockets.

Appendix B contribution: [Student 1] implemented the client/server protocol;
[Student 4] reviewed final message-boundary and size-limit handling.
"""

from __future__ import annotations

import json
import struct
from typing import Any


MAX_MESSAGE_SIZE = 100 * 1024 * 1024


class ProtocolError(ValueError):
    """Raised when a protocol message is malformed or too large."""


def _recv_exact(sock, size: int) -> bytes:
    """Read exactly the requested byte count from a TCP stream or raise on early close."""

    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProtocolError("connection closed while reading message")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_message(sock, message: dict[str, Any]) -> None:
    """Send one bounded JSON object with a four-byte network-order length prefix."""

    payload = json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ProtocolError(f"message is too large: {len(payload)} bytes")
    sock.sendall(struct.pack("!I", len(payload)))
    sock.sendall(payload)


def recv_message(sock) -> dict[str, Any]:
    """Receive one bounded length-prefixed JSON object from a TCP stream."""

    header = _recv_exact(sock, 4)
    (size,) = struct.unpack("!I", header)
    if size > MAX_MESSAGE_SIZE:
        raise ProtocolError(f"message exceeds maximum size: {size} bytes")
    payload = _recv_exact(sock, size)
    data = json.loads(payload.decode("utf-8"))
    if not isinstance(data, dict):
        raise ProtocolError("top-level JSON message must be an object")
    return data
