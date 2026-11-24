from __future__ import annotations

import uuid
from pathlib import Path

from .crypto import b64d, b64e


def handle_request(request: dict, storage: Path) -> dict:
    action = request.get("action")
    if action == "upload":
        file_id = uuid.uuid4().hex
        filename = Path(request["filename"]).name
        (storage / f"{file_id}__{filename}").write_bytes(b64d(request["content"]))
        return {"status": "ok", "file_id": file_id}
    if action == "list":
        files = []
        for path in sorted(storage.glob("*__*")):
            file_id, filename = path.name.split("__", 1)
            files.append({"file_id": file_id, "filename": filename, "size": path.stat().st_size})
        return {"status": "ok", "files": files}
    if action == "download":
        matches = list(storage.glob(f"{request['file_id']}__*"))
        if not matches:
            return {"status": "error", "error": "file not found"}
        path = matches[0]
        _, filename = path.name.split("__", 1)
        return {"status": "ok", "filename": filename, "content": b64e(path.read_bytes())}
    return {"status": "error", "error": "unknown action"}
