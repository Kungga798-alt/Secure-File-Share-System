"""Security regression tests.

Appendix B contribution: [Student 4] led final test integration; all members
reviewed test scenarios relevant to their implementation areas.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from client import load_user_credentials, request_server, user_cert_path
from secure_file_share.bundle import (
    BUNDLE_FIELDS,
    BundleError,
    clone_bundle,
    create_bundle,
    decrypt_bundle,
    verify_bundle,
)
from secure_file_share.certs import common_name, load_cert
from secure_file_share.crypto import b64d, b64e
from server import SecureFileServer
from tools.setup_keys import initialize_demo


PASSWORD = "correct-horse-battery-staple"


class SecureFileShareTests(unittest.TestCase):
    """Integration and security-regression tests for the version-2 file-sharing format."""

    def setUp(self) -> None:
        """Create isolated 3072-bit credentials, storage, and a small sample file."""

        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.deployment = self.root / "deployment"
        self.storage = self.root / "server_storage"
        initialize_demo(self.deployment, password=PASSWORD, force=True)
        self.sample = self.root / "secret.txt"
        self.sample.write_text("confidential assignment demo content", encoding="utf-8")
        self.ca_cert = load_cert(self.deployment / "ca" / "ca_cert.pem")

    def tearDown(self) -> None:
        """Remove temporary credentials, storage, and sample data."""

        self.tmp.cleanup()

    def _bundle_for_bob(self) -> dict:
        """Build a valid Alice-to-Bob encrypted bundle that includes Alice as a recipient."""

        alice_key, alice_cert = load_user_credentials(self.deployment, "alice", PASSWORD)
        bob_cert = load_cert(user_cert_path(self.deployment, "bob"))
        return create_bundle(
            self.sample,
            sender_user="alice",
            sender_private_key=alice_key,
            sender_cert=alice_cert,
            recipient_certs=[("alice", alice_cert), ("bob", bob_cert)],
        )

    def test_bundle_has_signed_plaintext_filename_and_decrypts(self) -> None:
        """Expose one signed filename for listings while keeping other metadata private."""

        bundle = self._bundle_for_bob()
        self.assertEqual(set(bundle), BUNDLE_FIELDS)
        self.assertNotIn("plaintext_sha256", bundle)
        self.assertNotIn("ciphertext_sha256", bundle)
        self.assertNotIn("ciphertext_size", bundle)
        self.assertNotIn("protected_header", bundle)
        self.assertTrue(all(set(entry) == {"cert_fingerprint", "wrapped_key"} for entry in bundle["wrapped_keys"]))
        public_json = json.dumps(bundle, sort_keys=True)
        self.assertEqual(bundle["original_filename"], "secret.txt")
        self.assertIn("original_filename", public_json)
        self.assertNotIn("created_at_utc", public_json)
        self.assertNotIn("sender_user", public_json)
        self.assertNotIn("recipients", public_json)
        self.assertNotIn("sha256", public_json.lower())
        self.assertNotEqual(bundle["file_nonce"], bundle["metadata_nonce"])

        verify_bundle(bundle, ca_cert=self.ca_cert)
        bob_key, bob_cert = load_user_credentials(self.deployment, "bob", PASSWORD)
        filename, plaintext = decrypt_bundle(
            bundle,
            recipient_private_key=bob_key,
            recipient_cert=bob_cert,
            ca_cert=self.ca_cert,
        )
        self.assertEqual(filename, "secret.txt")
        self.assertEqual(plaintext, self.sample.read_bytes())

    def test_bundle_rejects_tampering_of_signed_ciphertext_and_metadata(self) -> None:
        """Reject changed encrypted file bytes and changed encrypted metadata before decryption."""

        bundle = self._bundle_for_bob()
        for field in ("ciphertext", "encrypted_metadata"):
            with self.subTest(field=field):
                tampered = clone_bundle(bundle)
                value = bytearray(b64d(tampered[field]))
                value[0] ^= 0x01
                tampered[field] = b64e(bytes(value))
                with self.assertRaises(BundleError):
                    verify_bundle(tampered, ca_cert=self.ca_cert)

    def test_bundle_rejects_signed_header_and_wrapped_key_tampering(self) -> None:
        """Reject tampering of authorization or identity data covered by the sender signature."""

        bundle = self._bundle_for_bob()
        for field, value in (("file_id", "f" * 32), ("original_filename", "renamed.txt")):
            with self.subTest(field=field):
                tampered = clone_bundle(bundle)
                tampered[field] = value
                with self.assertRaises(BundleError):
                    verify_bundle(tampered, ca_cert=self.ca_cert)

        altered_wrapped_key = clone_bundle(bundle)
        wrapped_key = bytearray(b64d(altered_wrapped_key["wrapped_keys"][0]["wrapped_key"]))
        wrapped_key[0] ^= 0x01
        altered_wrapped_key["wrapped_keys"][0]["wrapped_key"] = b64e(bytes(wrapped_key))
        with self.assertRaises(BundleError):
            verify_bundle(altered_wrapped_key, ca_cert=self.ca_cert)

    def test_v1_bundle_is_rejected(self) -> None:
        """Reject the retired v1 structure instead of retaining a weaker compatibility path."""

        with self.assertRaises(BundleError):
            verify_bundle({"version": 1}, ca_cert=self.ca_cert)

    def test_unauthorized_recipient_cannot_decrypt(self) -> None:
        """Reject Charlie because his valid certificate has no wrapped AES file key."""

        bundle = self._bundle_for_bob()
        charlie_key, charlie_cert = load_user_credentials(self.deployment, "charlie", PASSWORD)
        with self.assertRaises(PermissionError):
            decrypt_bundle(
                bundle,
                recipient_private_key=charlie_key,
                recipient_cert=charlie_cert,
                ca_cert=self.ca_cert,
            )

    def test_generated_private_keys_are_rsa_3072(self) -> None:
        """Require RSA-3072 credentials and opaque certificate subjects for demo users."""

        alice_key, alice_cert = load_user_credentials(self.deployment, "alice", PASSWORD)
        self.assertEqual(alice_key.key_size, 3072)
        self.assertEqual(self.ca_cert.public_key().key_size, 3072)
        self.assertTrue(common_name(alice_cert).startswith("client-"))
        self.assertNotIn("alice", common_name(alice_cert).lower())

    def test_tls_server_upload_list_download_and_authorization(self) -> None:
        """Exercise mutual TLS listing by signed filename and recipient authorization."""

        ready = threading.Event()
        server = SecureFileServer(
            "127.0.0.1",
            0,
            deployment_dir=self.deployment,
            storage_dir=self.storage,
            password=PASSWORD,
        )
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"max_connections": 4, "ready_event": ready},
            daemon=True,
        )
        thread.start()
        self.assertTrue(ready.wait(10), "server did not start")
        port = server.port

        try:
            bundle = self._bundle_for_bob()
            upload = request_server(
                "127.0.0.1",
                port,
                deployment_dir=self.deployment,
                user="alice",
                password=PASSWORD,
                message={"action": "upload", "bundle": bundle},
            )
            self.assertEqual(upload["status"], "ok")
            file_id = upload["file_id"]

            bob_list = request_server(
                "127.0.0.1",
                port,
                deployment_dir=self.deployment,
                user="bob",
                password=PASSWORD,
                message={"action": "list"},
            )
            self.assertEqual(
                bob_list,
                {
                    "status": "ok",
                    "files": [{"file_id": file_id, "original_filename": "secret.txt"}],
                },
            )

            bob_download = request_server(
                "127.0.0.1",
                port,
                deployment_dir=self.deployment,
                user="bob",
                password=PASSWORD,
                message={"action": "download", "file_id": file_id},
            )
            self.assertEqual(bob_download["status"], "ok")
            self.assertEqual(set(bob_download["bundle"]), BUNDLE_FIELDS)

            charlie_download = request_server(
                "127.0.0.1",
                port,
                deployment_dir=self.deployment,
                user="charlie",
                password=PASSWORD,
                message={"action": "download", "file_id": file_id},
            )
            self.assertEqual(charlie_download["status"], "error")
            self.assertIn("not authorized", charlie_download["error"])
        finally:
            server.stop()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
