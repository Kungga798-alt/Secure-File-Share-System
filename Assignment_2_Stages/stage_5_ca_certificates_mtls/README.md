# Stage 5 - CA Certificates and Mutual TLS

This stage adds a local certificate authority, a server certificate, and client certificates for `alice`, `bob`, and `charlie`. The client and server use mutual TLS: the client verifies the server certificate, and the server requires a client certificate.

Relation to the final project:
- This introduces CA-backed identity and mutual TLS, matching the transport-authentication model of the final project.
- It keeps the stage 4 encrypted bundle design: files are still encrypted client-side and AES keys are wrapped to recipients.
- It intentionally does not yet enforce final authorization rules. That distinction matters: authentication proves who connected; authorization decides what that identity may access.

Security in this stage:
- Has: TLS 1.3 transport encryption, server authentication, client authentication, CA trust, AES-GCM encrypted bundles, RSA-OAEP key wrapping.
- Does not have: signed bundle metadata, non-repudiation, or strict server-side file authorization.
- The server can identify the TLS client but still returns any encrypted bundle in this teaching stage.

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
- `setup_keys.py` - thin entrypoint that creates the CA, server certificate, and user certificates.
- `client.py` - thin mTLS client CLI.
- `server.py` - thin mTLS server entrypoint.
- `secure_file_share/protocol.py` - length-prefixed JSON framing over TLS sockets.
- `secure_file_share/storage.py` - encrypted bundle save, load, and list logic without final authorization filtering.
- `secure_file_share/crypto.py` - AES-GCM, RSA-OAEP, Base64, and canonical JSON helpers.
- `secure_file_share/certs.py` - CA, certificate, key, mTLS context, and peer-certificate helpers.
- `secure_file_share/bundle.py` - certificate-bound encrypted bundle creation and recipient decryption.
