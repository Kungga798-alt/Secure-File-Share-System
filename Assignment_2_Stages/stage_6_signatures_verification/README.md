# Stage 6 - Signatures and Verification

This stage adds RSA-PSS signatures over the encrypted bundle metadata. The sender signs the bundle after encryption and key wrapping. The server verifies the signature before storing the bundle, and the client verifies it again before decrypting.

Relation to the final project:
- This introduces non-repudiation and stronger integrity evidence.
- It keeps the stage 5 mTLS and certificate setup.
- It still does not implement final server-side authorization filtering; that arrives in stage 7.

Security in this stage:
- Has: TLS 1.3 mutual authentication, CA-issued certificates, AES-GCM bundles, RSA-OAEP key wrapping, SHA-256 hashes, and RSA-PSS signatures.
- Does not have: final certificate-fingerprint authorization on list/download.
- A valid signature proves that the sender private key approved the exact encrypted bundle fields.

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
- `setup_keys.py` - thin entrypoint that creates a stage-local CA, server certificate, and user certificates.
- `client.py` - thin mTLS client CLI.
- `server.py` - thin signed-bundle server entrypoint.
- `secure_file_share/protocol.py` - length-prefixed JSON framing over TLS sockets.
- `secure_file_share/storage.py` - encrypted bundle save, load, list, and upload-time signature verification.
- `secure_file_share/crypto.py` - AES-GCM, RSA-OAEP, RSA-PSS, SHA-256, Base64, and canonical JSON helpers.
- `secure_file_share/certs.py` - CA, certificate, key, mTLS context, and peer-certificate helpers.
- `secure_file_share/bundle.py` - signed bundle creation, verification, and recipient decryption.
