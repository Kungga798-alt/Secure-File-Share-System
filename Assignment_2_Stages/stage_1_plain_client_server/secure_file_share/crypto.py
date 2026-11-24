from __future__ import annotations

import base64


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def educational_note() -> str:
    return "Stage 1 has no cryptography; data is plaintext on the wire and at rest."
