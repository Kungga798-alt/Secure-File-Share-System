# Stage 1 - Plain TCP Client/Server

This stage is the bare file-sharing idea before cryptography is added. A client sends JSON messages over a plain TCP socket to upload, list, or download files. The server stores the uploaded bytes directly in `server_storage/`.

Relation to the final project:
- This introduces the client/server workflow used by the final project.
- It deliberately omits TLS, certificates, encryption at rest, signatures, and authorization.
- Anyone who can connect can upload, list, and download every file.

Security in this stage:
- Has: basic filename cleanup to avoid obvious path traversal.
- Does not have: confidentiality, integrity, authentication, non-repudiation, or access control.
- Network traffic and stored files are plaintext.

Run it:

```powershell
python server.py
python client.py upload sample_files\example.txt
python client.py list
python client.py download <file_id>
```

Key files:
- `client.py` - thin CLI entrypoint for upload/list/download.
- `server.py` - thin plain-TCP server entrypoint.
- `secure_file_share/protocol.py` - length-prefixed JSON framing over TCP.
- `secure_file_share/storage.py` - plaintext server-side save, load, and list logic.
- `secure_file_share/crypto.py` - Base64 helpers plus an explicit no-cryptography note.
- `secure_file_share/certs.py` - explicit no-certificate placeholder for this stage.
- `secure_file_share/bundle.py` - plaintext upload/download message helpers.
