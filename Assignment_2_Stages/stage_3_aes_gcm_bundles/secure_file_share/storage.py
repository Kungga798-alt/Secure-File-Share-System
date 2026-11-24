from __future__ import annotations

import json
import uuid
from pathlib import Path


BUNDLE_SUFFIX = ".s3bundle"


def save_bundle(storage: Path, bundle: dict) -> str:
    file_id = uuid.uuid4().hex
    bundle = dict(bundle)
    bundle["file_id"] = file_id
    (storage / f"{file_id}{BUNDLE_SUFFIX}").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return file_id


def load_bundle(storage: Path, file_id: str) -> dict | None:
    path = storage / f"{file_id}{BUNDLE_SUFFIX}"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def list_bundles(storage: Path) -> list[dict]:
    files = []
    for path in sorted(storage.glob(f"*{BUNDLE_SUFFIX}")):
        bundle = json.loads(path.read_text(encoding="utf-8"))
        files.append({
            "file_id": bundle["file_id"],
            "filename": bundle["filename"],
            "ciphertext_size": len(bundle["ciphertext"]),
        })
    return files


def handle_request(request: dict, storage: Path) -> dict:
    action = request.get("action")
    if action == "upload":
        return {"status": "ok", "file_id": save_bundle(storage, request["bundle"])}
    if action == "list":
        return {"status": "ok", "files": list_bundles(storage)}
    if action == "download":
        bundle = load_bundle(storage, request["file_id"])
        if bundle is None:
            return {"status": "error", "error": "file not found"}
        return {"status": "ok", "bundle": bundle}
    return {"status": "error", "error": "unknown action"}
