from __future__ import annotations

from pathlib import Path

from secure_file_share.crypto import ensure_shared_key


def main() -> None:
    key_path = ensure_shared_key(Path(__file__).resolve().parent)
    print(f"wrote shared AES-256 key: {key_path}")


if __name__ == "__main__":
    main()
