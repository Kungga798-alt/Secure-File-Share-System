ST2504 Applied Cryptography Assignment 2
Secure File-Sharing Client/Server

Overview
This project implements a client/server file-sharing system with:
- Mutual TLS 1.3 for authenticated, confidential transport.
- A local CA and RSA-3072 certificates for server and client identity.
- AES-256-GCM for file bytes and sensitive file metadata while stored.
- RSA-OAEP-SHA256 to wrap a fresh per-file AES key to each authorised recipient.
- RSA-PSS-SHA256 signatures over the complete public .sfs envelope.
- Certificate-fingerprint authorisation for server-side access control.

Security and privacy properties
The server stores version-2 .sfs bundles only. The public envelope contains
the version, a random file ID, the original filename, certificate fingerprints,
wrapped keys, nonces, encrypted payloads, sender certificate, and signature.
The original filename is deliberately plaintext and signed so an authorised
user can identify a listed file before downloading it. This is a usability
trade-off: the server and anyone who reads a bundle can see the filename. User
certificates use opaque random subject labels. The envelope does not contain a
username, timestamp, algorithm list, plaintext SHA-256, ciphertext SHA-256, or
ciphertext size.

TLS 1.3 provides forward secrecy for transport sessions. Stored RSA-wrapped
file keys do not provide at-rest forward secrecy after a recipient private key
compromise. This is an intentional, documented limitation of the assignment
scope.

Requirements
Install the dependency if needed:
  python -m pip install -r requirements.txt

Setup
No private keys are included in the submitted package. Generate fresh demo
credentials and enter a new passphrase of at least 12 characters when prompted:
  python tools/setup_keys.py init-demo --force

This creates encrypted PEM keys under deployment/. Do not commit or share the
generated private keys or the passphrase.

Run the server
  python server.py --host 127.0.0.1 --port 9000

Enter the server-key passphrase when prompted.

Upload a file from Alice to Bob
  python client.py upload --user alice --to bob --file sample_files/example.txt

Enter Alice's passphrase when prompted. Alice is automatically added as a
recipient so she can later decrypt her own upload.

List Bob's authorised files
  python client.py list --user bob

The command prints each authorised file ID and its signed original filename.

Download and decrypt as Bob
  python client.py download --user bob --file-id FILE_ID --out downloads

Enter Bob's passphrase when prompted. The signed filename is used after bundle
verification; file bytes are written only after local decryption succeeds.

Verify a stored bundle
  python client.py verify --bundle server_storage/FILE_ID.sfs

Authorization demonstration
Charlie has a valid client certificate but is not a recipient of an Alice-to-
Bob upload. This request must fail:
  python client.py download --user charlie --file-id FILE_ID --out downloads

Testing
  python -m unittest discover -s tests -v

The tests cover v2 envelope minimisation, legacy v1 rejection, tamper detection,
RSA-3072 credential generation, mutual TLS, recipient authorisation, and local
decryption.

Submission structure
- readme.txt: this file.
- client.py, server.py, secure_file_share/, tools/, tests/: source and tests.
- deployment/: created by setup_keys.py at demonstration time; no credentials
  are included in the submitted package.
- Proposal_Report.docx: final proposal report.

Appendix B contribution comments
Python source files identify the relevant work using [Student 1] through
[Student 4] placeholders. Replace these placeholders with the actual names
before submission.
