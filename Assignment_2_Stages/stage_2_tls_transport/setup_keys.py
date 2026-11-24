from __future__ import annotations

from pathlib import Path

from secure_file_share.certs import create_self_signed_server_cert


def main() -> None:
    root = Path(__file__).resolve().parent / "deployment"
    key_path, cert_path = create_self_signed_server_cert(root)
    print(f"wrote {key_path} and {cert_path}")


if __name__ == "__main__":
    main()
