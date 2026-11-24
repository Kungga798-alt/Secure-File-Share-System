from __future__ import annotations

import json
import uuid
from pathlib import Path


BUNDLE_SUFFIX = ".s5bundle"


def handle_request(request: dict, storage: Path, peer: dict) -> dict:
    action = request.get("action")
    if action == "upload":
        file_id = uuid.uuid4().hex
        bundle = dict(request["bundle"])
        bundle["file_id"] = file_id
        (storage / f"{file_id}{BUNDLE_SUFFIX}").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        return {"status": "ok", "file_id": file_id, "authenticated_as": peer["user"]}
    if action == "list":
        files = []
        for path in sorted(storage.glob(f"*{BUNDLE_SUFFIX}")):
            bundle = json.loads(path.read_text(encoding="utf-8"))
            files.append({"file_id": bundle["file_id"], "filename": bundle["filename"], "sender": bundle["sender"]["user"]})
        return {"status": "ok", "authenticated_as": peer["user"], "files": files}
    if action == "download":
        path = storage / f"{request['file_id']}{BUNDLE_SUFFIX}"
        if not path.exists():
            return {"status": "error", "error": "file not found"}
        return {"status": "ok", "bundle": json.loads(path.read_text(encoding="utf-8"))}
    return {"status": "error", "error": "unknown action"}
