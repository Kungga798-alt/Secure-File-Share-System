# Stage 2: TLS-Protected File Transfer

Stage 2 improves the Stage 1 client-server file-sharing prototype by protecting the network connection with TLS 1.3. The client and server can still upload, list, and download files, but the data sent between them is encrypted while it is travelling over the network.

This is an intermediate learning stage, not the final secure file-sharing system. Files are still saved on the server in plaintext, and users are not yet authenticated with client certificates.

## Assignment relevance

The project is developed in support of the [ST2504 Applied Cryptography Assignment 2 brief](../../assignment_brief.txt). This stage addresses the brief's requirement to protect the confidentiality and integrity of data during transit:

- **Confidentiality in transit:** TLS encrypts the connection, so an attacker who captures network traffic should not be able to read the file contents.
- **Integrity in transit:** TLS detects unauthorised changes to data while it is being sent between the client and server.
- **Server authentication:** the client trusts the generated server certificate before connecting.

The final project extends this work with protection for data at rest, stronger key management, user authentication, digital signatures, and authorisation.

## What this stage does

1. Generates a self-signed TLS certificate for the local server.
2. Starts a TLS 1.3 server on `127.0.0.1:9102`.
3. Lets a client upload, list, and download files through the encrypted connection.
4. Saves uploaded files as plaintext in `server_storage`.

## Requirements

- Python 3.10 or later
- The `cryptography` Python package

## How to run

Open PowerShell in this `stage_2_tls_transport` folder.

Install the dependency and generate the local server certificate:

```powershell
pip install -r requirements.txt
python setup_keys.py
```

Start the server in the first PowerShell window. Leave it running:

```powershell
python server.py
```

Open a second PowerShell window in the same folder. You can then use the client commands below.

Upload the sample file:

```powershell
python client.py upload sample_files\example.txt
```

List the uploaded files. Copy the returned `file_id` for the download command:

```powershell
python client.py list
```

Download a file using its `file_id`:

```powershell
python client.py download <file_id>
```

Downloaded files are placed in the `downloads` folder by default. To choose another folder, add `--out <folder_name>` to the download command.

## Security scope and limitations

TLS 1.3 protects the connection only while data is moving between the client and server. It does not encrypt files after the server stores them. The certificate in this stage is self-signed and is intended only for local demonstration; it is not suitable for deployment on a public network. This stage also does not provide client authentication, access control, encrypted file storage, or non-repudiation.

## Important files

- `client.py` — command-line TLS client.
- `server.py` — TLS server and plaintext file storage entry point.
- `setup_keys.py` — creates `deployment/server_key.pem` and `deployment/server_cert.pem`.
- `secure_file_share/certs.py` — certificate generation and TLS-context setup.
- `secure_file_share/protocol.py` — length-prefixed JSON messaging over the TLS socket.
- `secure_file_share/storage.py` — server-side plaintext file storage.

## Expected demonstration result

When the server and client run successfully, the server reports a TLS connection and the client can upload, list, and download a file. This demonstrates protected data transmission, while also showing why the later stages are needed to protect stored files and identify authorised users.
