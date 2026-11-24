from __future__ import annotations

import json
import struct
from typing import Any


def _recv_exact(sock, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("socket closed early")
        data.extend(chunk)
    return bytes(data)


def send_message(sock, message: dict[str, Any]) -> None:
    payload = json.dumps(message, sort_keys=True).encode("utf-8")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_message(sock) -> dict[str, Any]:
    size = struct.unpack("!I", _recv_exact(sock, 4))[0]
    message = json.loads(_recv_exact(sock, size).decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("message must be a JSON object")
    return message
