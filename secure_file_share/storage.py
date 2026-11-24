"""Server-side encrypted bundle storage.

Appendix B contribution: [Student 1] implemented the baseline server flow;
[Student 4] integrated fingerprint-based authorization and final hardening.
"""

from __future__ import annotations

import re
from pathlib import Path

from .bundle import load_bundle, save_bundle


FILE_ID_RE = re.compile(r"^[a-f0-9]{32}$")


class StorageError(ValueError):
    """Raised when server storage cannot serve a requested file."""


class BundleStorage:
    """Store encrypted .sfs bundles and authorize access by certificate fingerprint."""

    def __init__(self, root: Path):
        """Create the storage root for encrypted bundle files."""

        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, file_id: str) -> Path:
        """Validate a UUID-hex file ID before mapping it to a bundle path."""

        if not FILE_ID_RE.fullmatch(file_id):
            raise StorageError("invalid file id")
        return self.root / f"{file_id}.sfs"

    def save(self, bundle: dict) -> str:
        """Save a verified encrypted bundle under its signed file ID."""

        file_id = bundle["file_id"]
        path = self._path_for(file_id)
        if path.exists():
            raise StorageError("file id already exists")
        save_bundle(path, bundle)
        return file_id

    def load(self, file_id: str) -> dict:
        """Load an encrypted bundle by file ID while leaving decryption to the client."""

        path = self._path_for(file_id)
        if not path.exists():
            raise StorageError("file id not found")
        return load_bundle(path)

    @staticmethod
    def is_authorized(bundle: dict, cert_fingerprint: str) -> bool:
        """Return whether a certificate fingerprint is the sender or a listed recipient."""

        if bundle["sender_cert_fingerprint"] == cert_fingerprint:
            return True
        return any(
            entry["cert_fingerprint"] == cert_fingerprint
            for entry in bundle["wrapped_keys"]
        )

    @staticmethod
    def metadata(bundle: dict) -> dict:
        """Return the signed listing fields visible to an authorized TLS client."""

        return {
            "file_id": bundle["file_id"],
            "original_filename": bundle["original_filename"],
        }

    def list_for(self, cert_fingerprint: str) -> list[dict]:
        """List metadata for readable bundles authorized to a certificate fingerprint."""

        items: list[dict] = []
        for path in sorted(self.root.glob("*.sfs")):
            try:
                bundle = load_bundle(path)
            except Exception:
                continue
            if self.is_authorized(bundle, cert_fingerprint):
                items.append(self.metadata(bundle))
        return items
