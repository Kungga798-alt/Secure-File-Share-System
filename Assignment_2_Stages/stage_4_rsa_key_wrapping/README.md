# Stage 4 - RSA Key Wrapping

This stage replaces the shared AES key with a hybrid-encryption design. Each file gets a fresh random AES-GCM key. That small AES key is wrapped with RSA-OAEP to each recipient.

Relation to the final project:
- This is the final project's at-rest encryption model: encrypt the file once with AES-GCM, then wrap the AES key per recipient.
- It still lacks certificates, TLS identity, signatures, and server-side authorization.
- User names map directly to public-key files in this teaching stage; the final project binds keys to CA-signed certificates.

Security in this stage:
- Has: per-file AES keys, recipient-specific RSA-OAEP key wrapping, AES-GCM integrity.
- Does not have: authenticated user identity, non-repudiation, certificate trust, or access-control enforcement.
- The server may return any encrypted bundle to anyone, but only listed recipients can unwrap the AES key.

Run it:

```powershell
pip install -r requirements.txt
python setup_keys.py
python server.py
python client.py --user alice upload sample_files\example.txt --to bob
python client.py --user bob list
python client.py --user bob download <file_id>
```

Key files:
- `setup_keys.py` - thin entrypoint that creates RSA keys for `alice`, `bob`, and `charlie`.
- `client.py` - thin CLI for upload/list/download.
- `server.py` - thin server entrypoint that stores encrypted bundles only.
- `secure_file_share/protocol.py` - length-prefixed JSON framing over TCP.
- `secure_file_share/storage.py` - encrypted bundle save, load, and list logic.
- `secure_file_share/crypto.py` - AES-GCM, RSA-OAEP, Base64, and canonical JSON helpers.
- `secure_file_share/certs.py` - per-user RSA key generation and loading helpers.
- `secure_file_share/bundle.py` - hybrid bundle creation and recipient decryption.
