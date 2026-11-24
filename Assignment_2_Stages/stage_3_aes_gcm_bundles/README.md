# Stage 3 - AES-GCM Bundles

This stage adds encrypted file bundles. The client encrypts the file with AES-GCM before upload and decrypts after download. The server stores only encrypted `.s3bundle` JSON files.

Relation to the final project:
- This introduces client-side encryption at rest, which is a core final-project idea.
- It still uses one shared demo key for all users. That is intentionally weak but easy to understand.
- The final project replaces the shared key with per-file AES keys wrapped to recipients.

Security in this stage:
- Has: file confidentiality and integrity at rest if the shared key remains secret.
- Does not have: secure key distribution, identity, TLS, signatures, non-repudiation, or authorization.
- Anyone with `demo_key.bin` can decrypt every bundle.

Run it:

```powershell
pip install -r requirements.txt
python setup_keys.py
python server.py
python client.py upload sample_files\example.txt
python client.py list
python client.py download <file_id>
```

Key files:
- `setup_keys.py` - thin entrypoint that creates the shared 256-bit AES key.
- `client.py` - thin CLI for upload/list/download.
- `server.py` - thin server entrypoint that stores encrypted bundles.
- `secure_file_share/protocol.py` - length-prefixed JSON framing over TCP.
- `secure_file_share/storage.py` - encrypted bundle save, load, and list logic.
- `secure_file_share/crypto.py` - AES-GCM, Base64, and shared demo-key helpers.
- `secure_file_share/certs.py` - explicit no-certificate placeholder for this stage.
- `secure_file_share/bundle.py` - AES-GCM bundle creation and decryption.
