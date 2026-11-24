from __future__ import annotations

from pathlib import Path

from secure_file_share.certs import make_ca


def main() -> None:
    deployment = Path(__file__).resolve().parent / "deployment"
    make_ca(deployment)
    print(f"wrote local CA, server cert, and user certs under {deployment}")


if __name__ == "__main__":
    main()
