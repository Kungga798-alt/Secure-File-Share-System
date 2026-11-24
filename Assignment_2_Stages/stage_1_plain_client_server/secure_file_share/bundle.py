from __future__ import annotations

from pathlib import Path

from .crypto import b64d, b64e


def plaintext_upload_message(path: Path) -> dict:
    file_path = Path(path)
    return {
        "action": "upload",
        "filename": file_path.name,
        "content": b64e(file_path.read_bytes()),
    }


def decode_download(response: dict) -> tuple[str, bytes]:
    return Path(response["filename"]).name, b64d(response["content"])
