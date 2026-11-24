# Stage 7 - Authorization and Final Flow

This stage is the integrated secure file-sharing flow. It contains a local copy of the final runtime modules and keeps deployment files, server storage, samples, and downloads inside this folder.

What this stage integrates:
- TLS 1.3 mutual authentication.
- CA certificates.
- AES-GCM bundles.
- RSA-OAEP key wrapping.
- RSA-PSS signatures.
- SHA-256 hashes.
- Certificate-fingerprint authorization.

Security in this stage:
- Has: TLS 1.3 mTLS, local CA trust, client-side encrypted bundles, per-recipient RSA-OAEP wrapped AES keys, RSA-PSS signatures, sender verification, and certificate-fingerprint authorization for list/download.
- Does not have: production-grade key custody, revocation, audit logging, rate limiting, or hardened operational deployment.
- Forward secrecy applies to TLS network sessions. Stored bundles do not have at-rest forward secrecy if a recipient private key is later compromised.

Run it:

```powershell
pip install -r requirements.txt
python setup_keys.py init-demo --force
python server.py
python client.py upload --user alice --file sample_files\example.txt --to bob
python client.py list --user bob
python client.py download --user bob --file-id <file_id>
python client.py download --user charlie --file-id <file_id>
```

Expected behavior:
- Bob can list and download Alice's file when Alice included Bob as a recipient.
- Charlie is authenticated by mTLS but is rejected by authorization if Charlie is not in the bundle recipient metadata.

Key files:
- `setup_keys.py` - thin entrypoint that generates this stage's local CA, server certificate, and user certificates.
- `client.py` - thin CLI for upload, list, download, and offline verify.
- `server.py` - mTLS server entrypoint with stage-local storage defaults.
- `secure_file_share/protocol.py` - length-prefixed JSON framing over TLS sockets.
- `secure_file_share/storage.py` - encrypted bundle storage and certificate-fingerprint authorization.
- `secure_file_share/crypto.py` - AES-GCM, RSA-OAEP, RSA-PSS, SHA-256, Base64, and canonical JSON helpers.
- `secure_file_share/certs.py` - CA, certificate, key, TLS context, fingerprint, and CA validation helpers.
- `secure_file_share/bundle.py` - encrypted bundle creation, verification, save/load, and decryption.
