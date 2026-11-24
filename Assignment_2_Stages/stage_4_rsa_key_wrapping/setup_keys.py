from __future__ import annotations

from pathlib import Path

from secure_file_share.certs import generate_user_keys


def main() -> None:
    root = generate_user_keys(Path(__file__).resolve().parent)
    print(f"wrote demo RSA keys under {root}")


if __name__ == "__main__":
    main()
