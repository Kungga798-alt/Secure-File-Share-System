"""Build the compliant ST2504 Applied Cryptography proposal report.

Appendix B contribution: [Student 4] led report integration and final review.
"""

from __future__ import annotations

from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt


OUTPUT = Path("Proposal_Report.docx")
FONT = "Calibri"
BODY_SIZE = 12


def set_font(run, *, size: int = BODY_SIZE, bold: bool = False, italic: bool = False) -> None:
    """Apply one consistent typeface and explicit font size to a text run."""

    run.font.name = FONT
    run._element.rPr.rFonts.set(qn("w:ascii"), FONT)
    run._element.rPr.rFonts.set(qn("w:hAnsi"), FONT)
    run.font.size = Pt(size)
    run.bold = bold
    run.italic = italic


def configure(doc: Document) -> None:
    """Set A4, single spacing, 12-point defaults, and footer page numbering."""

    section = doc.sections[0]
    section.page_width = Inches(8.27)
    section.page_height = Inches(11.69)
    section.top_margin = Inches(0.65)
    section.bottom_margin = Inches(0.65)
    section.left_margin = Inches(0.7)
    section.right_margin = Inches(0.7)
    section.header_distance = Inches(0.3)
    section.footer_distance = Inches(0.3)

    normal = doc.styles["Normal"]
    normal.font.name = FONT
    normal._element.rPr.rFonts.set(qn("w:ascii"), FONT)
    normal._element.rPr.rFonts.set(qn("w:hAnsi"), FONT)
    normal.font.size = Pt(BODY_SIZE)
    normal.paragraph_format.line_spacing = 1.0
    normal.paragraph_format.space_after = Pt(0)

    for style_name, size in (("Heading 1", 14), ("Heading 2", 12), ("Heading 3", 12)):
        style = doc.styles[style_name]
        style.font.name = FONT
        style._element.rPr.rFonts.set(qn("w:ascii"), FONT)
        style._element.rPr.rFonts.set(qn("w:hAnsi"), FONT)
        style.font.size = Pt(size)
        style.font.bold = True
        style.paragraph_format.line_spacing = 1.0
        style.paragraph_format.space_before = Pt(5 if style_name == "Heading 1" else 3)
        style.paragraph_format.space_after = Pt(1)

    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer.add_run("Page ")
    set_font(run, size=10)
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instruction = OxmlElement("w:instrText")
    instruction.set(qn("xml:space"), "preserve")
    instruction.text = "PAGE"
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.extend([begin, instruction, end])


def paragraph(doc: Document, text: str = "", *, bold: bool = False, center: bool = False, size: int = BODY_SIZE) -> None:
    """Add one single-spaced paragraph with explicit formatting."""

    item = doc.add_paragraph()
    item.paragraph_format.line_spacing = 1.0
    item.paragraph_format.space_after = Pt(0)
    if center:
        item.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = item.add_run(text)
    set_font(run, size=size, bold=bold)


def heading(doc: Document, text: str, level: int = 1) -> None:
    """Add a semantic heading with controlled spacing."""

    item = doc.add_heading(text, level=level)
    for run in item.runs:
        set_font(run, size=14 if level == 1 else 12, bold=True)


def bullet(doc: Document, text: str) -> None:
    """Add a genuine Word bullet at the required 12-point size."""

    item = doc.add_paragraph(style="List Bullet")
    item.paragraph_format.line_spacing = 1.0
    item.paragraph_format.space_after = Pt(2)
    run = item.add_run(text)
    set_font(run)


def table(doc: Document, headers: list[str], rows: list[list[str]], widths: list[float]) -> None:
    """Add a compact, 12-point comparison table with deliberate column widths."""

    item = doc.add_table(rows=1 + len(rows), cols=len(headers))
    item.style = "Table Grid"
    item.alignment = WD_TABLE_ALIGNMENT.CENTER
    item.autofit = False
    # Word must repeat a table header when the table crosses a page boundary.
    # This keeps the attack/countermeasure comparison readable in the PDF.
    header_properties = item.rows[0]._tr.get_or_add_trPr()
    repeat_header = OxmlElement("w:tblHeader")
    repeat_header.set(qn("w:val"), "true")
    header_properties.append(repeat_header)
    for row in item.rows:
        for index, width in enumerate(widths):
            row.cells[index].width = Inches(width)
    for row_index, values in enumerate([headers, *rows]):
        for column_index, value in enumerate(values):
            cell = item.cell(row_index, column_index)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            p = cell.paragraphs[0]
            p.paragraph_format.line_spacing = 1.0
            p.paragraph_format.space_after = Pt(0)
            run = p.add_run(value)
            set_font(run, bold=row_index == 0)
    paragraph(doc)


def add_cover(doc: Document) -> None:
    """Create the required cover page with placeholders for group information."""

    for _ in range(5):
        paragraph(doc)
    paragraph(doc, "SECURE FILE-SHARING SYSTEM PROPOSAL", bold=True, center=True, size=18)
    paragraph(doc, "ST2504 Applied Cryptography", bold=True, center=True, size=14)
    paragraph(doc, "Assignment 2", center=True)
    for _ in range(6):
        paragraph(doc)
    paragraph(doc, "Course: [Course]", center=True)
    paragraph(doc, "Class: [Class]", center=True)
    paragraph(doc, "Students: [Student 1], [Student 2], [Student 3], [Student 4]", center=True)
    paragraph(doc, "Chosen activity: client/server secure file sharing", center=True)
    doc.add_page_break()


def add_contents(doc: Document) -> None:
    """Create a concise contents page without unreliable static page-number claims."""

    heading(doc, "Contents")
    for item in (
        "1. Introduction",
        "2. Current System and Assumptions",
        "3. Attacker Model, Impact, and Countermeasures",
        "4. Proposed Secure System",
        "5. Cryptographic Design and Key Management",
        "6. Efficiency, Feasibility, and Sustainability",
        "7. Operational Controls and Failure Handling",
        "8. Conclusion and Additional Considerations",
        "9. Planned Task Allocation",
        "10. Individual Reflections",
        "References",
        "Appendix A. Demonstration Procedure",
        "Appendix B. Future Security Enhancements",
    ):
        paragraph(doc, item)
    doc.add_page_break()


def add_main_report(doc: Document) -> None:
    """Add the body, designed to fit within eight A4 pages after cover and contents."""

    heading(doc, "1. Introduction")
    paragraph(
        doc,
        "This proposal presents a Python client/server file-sharing application for ST2504 Applied Cryptography. "
        "A sender encrypts a file locally, uploads an encrypted bundle to a server, and an authorised recipient "
        "later downloads and decrypts it. The design addresses the assignment requirement for integrity during "
        "transit and confidentiality plus non-repudiation while data is stored.",
    )
    paragraph(
        doc,
        "The aim is a realistic, demonstrable security design rather than a commercial cloud platform. The system "
        "therefore concentrates on mutually authenticated transport, encrypted at-rest storage, recipient-specific "
        "key distribution, sender signatures, certificate-based authorisation, and explicit handling of limitations.",
    )
    paragraph(
        doc,
        "The security objective is deliberately layered. Transport controls protect a request while it crosses the "
        "network, whereas bundle controls continue to protect the file after the TLS connection ends and the server "
        "stores it. This distinction is important: relying only on TLS would leave a copied server disk readable, and "
        "relying only on file encryption would leave the client/server commands vulnerable to unauthenticated network use.",
    )

    heading(doc, "2. Current System and Assumptions")
    paragraph(
        doc,
        "The insecure baseline is a plain TCP file transfer: a client sends a filename and file bytes, the server "
        "stores them, and another client retrieves them. A network observer can read the transfer; an active attacker "
        "can modify it; and a server compromise exposes stored plaintext. The baseline has no reliable proof of the "
        "sender's authorship or recipient-specific access control.",
    )
    paragraph(doc, "Current baseline: Alice -> plain TCP/untrusted network -> plaintext server storage -> Bob.")
    bullet(doc, "The assignment demo uses a local CA and registered users Alice, Bob, and Charlie.")
    bullet(doc, "The attacker can observe, replay, modify, or copy traffic and encrypted server storage.")
    bullet(doc, "The attacker may be an authenticated user attempting to access a file not addressed to them.")
    bullet(doc, "The attacker is not assumed to break AES-GCM, RSA-OAEP, RSA-PSS, SHA-256 certificate fingerprints, or TLS 1.3.")
    paragraph(
        doc,
        "Private-key compromise is a material residual risk. TLS 1.3 protects completed transport sessions against "
        "later long-term key compromise, but old at-rest bundles remain decryptable if an intended recipient's RSA "
        "private key is stolen. The report does not claim at-rest perfect forward secrecy.",
    )
    paragraph(
        doc,
        "The trust boundary is therefore explicit. The client is trusted to protect its unlocked private key and to select "
        "the intended recipients. The server is trusted for availability and correct storage behaviour, but is not trusted "
        "with file plaintext or AES file keys. The CA is the trust anchor for issuing certificates; its private key must be "
        "protected because compromise would allow an attacker to issue credentials that the clients and server accept.",
    )
    paragraph(
        doc,
        "The implementation assumes that the server address and port are known to the users and that the server certificate "
        "contains the hostname or IP address used by the client. Python's TLS client context validates the certificate chain "
        "and hostname. The server requires a client certificate at the TLS handshake, then performs application-level checks "
        "on the certificate fingerprint before accepting an upload or returning a stored bundle.",
    )

    heading(doc, "3. Attacker Model, Impact, and Countermeasures")
    table(
        doc,
        ["Attack and impact", "Countermeasure and justification"],
        [
            ["Network eavesdropping exposes uploads or downloads.", "TLS 1.3 encrypts the connection; mutual TLS authenticates both client and server."],
            ["Stored-file theft exposes a server disk image.", "AES-256-GCM encrypts file bytes before upload; the server never receives plaintext."],
            ["Ciphertext, metadata, or wrapped-key tampering changes a bundle.", "AES-GCM authenticates each encrypted payload and RSA-PSS signs every public envelope field."],
            ["A valid user requests another user's file.", "The server compares the TLS certificate fingerprint with the sender or recipient fingerprint entries."],
            ["A sender disputes authorship of a bundle.", "The sender's RSA-PSS signature is publicly verifiable using their CA-signed certificate."],
        ],
        [2.4, 4.45],
    )
    paragraph(
        doc,
        "A passive network attacker sees TLS records but cannot read the JSON request or bundle contents without the session "
        "keys. An active network attacker can interrupt the connection, but cannot silently replace an upload because TLS "
        "authenticates the connection and the server independently verifies the bundle signature. Availability attacks such "
        "as connection flooding are outside the cryptographic guarantee, although message sizes are bounded and malformed "
        "messages are rejected rather than processed as files.",
    )
    paragraph(
        doc,
        "A storage attacker who copies an .sfs file can see the random file ID, certificate fingerprints, and the original filename. "
        "The plaintext filename is an intentional usability compromise: it lets an authorised recipient identify a listed file before "
        "downloading it. User aliases, recipient display names, timestamps, and file hashes remain protected. User certificate subjects "
        "are opaque random labels, so the required embedded sender certificate does not directly reveal the Alice, Bob, or Charlie aliases.",
    )
    paragraph(
        doc,
        "A malicious authenticated user is a distinct threat from an outsider. Mutual TLS proves that the requester controls "
        "a CA-issued private key, but it does not itself prove that the requester is a recipient for every file. The server "
        "therefore compares the authenticated certificate fingerprint with the sender fingerprint and each wrapped-key entry. "
        "A user with a valid but unmatched certificate receives an authorisation error and never receives the encrypted bundle.",
    )

    heading(doc, "4. Proposed Secure System")
    paragraph(
        doc,
        "The client creates a fresh AES-256 key for each file. It encrypts the file bytes with AES-GCM and separately "
        "encrypts a small metadata record containing the creation time, sender display name, and recipient display names. "
        "The same file key is wrapped separately to each recipient's RSA public key using RSA-OAEP-SHA256. "
        "The client signs the complete public envelope using RSA-PSS-SHA256 before uploading it through mutual TLS 1.3.",
    )
    paragraph(
        doc,
        "The version-2 .sfs envelope exposes the version, random file ID, original filename, sender certificate fingerprint, recipient "
        "fingerprint/wrapped-key pairs, two random 96-bit nonces, encrypted file bytes, encrypted metadata, sender certificate, and signature. "
        "The original filename is plaintext but signed; it is the only user-facing metadata released for listing. Usernames, timestamps, algorithm "
        "labels, plaintext SHA-256, ciphertext SHA-256, and ciphertext size remain absent. The server lists file IDs and filenames only to authorised fingerprints.",
    )
    paragraph(doc, "Proposed flow: Alice encrypts and signs -> mTLS upload -> server verifies and stores encrypted v2 bundle -> Bob mTLS-downloads -> Bob verifies and decrypts locally.")
    paragraph(
        doc,
        "More precisely, the sender first reads the selected file and creates a random 256-bit AES key. It creates a compact "
        "public header containing a version number, random file identifier, original filename, and sender certificate fingerprint. "
        "That header becomes AES-GCM associated data. The file bytes and the private metadata record are then encrypted with "
        "the same fresh file key but with two distinct random 96-bit nonces. The private record carries display information required only after successful local decryption.",
    )
    paragraph(
        doc,
        "For every recipient, including the sender, the client encrypts the AES key with that recipient's RSA public key using "
        "OAEP-SHA256. It then forms the public envelope and signs its canonical JSON representation with RSA-PSS-SHA256. The "
        "server verifies the signature and CA-signed sender certificate before writing the JSON bundle to disk. It does not "
        "decrypt either payload or unwrap a file key; it uses the signed filename only to make an authorised list readable.",
    )
    paragraph(
        doc,
        "During download, the server returns the bundle only after the TLS-authenticated fingerprint matches an authorised "
        "entry. The recipient independently verifies the signature and sender certificate, selects the wrapped key addressed "
        "to its own certificate fingerprint, unwraps the AES key, verifies and decrypts the metadata, then decrypts the file. "
        "Writing the plaintext occurs only after these checks succeed; a modified bundle therefore fails before a usable file is produced.",
    )
    table(
        doc,
        ["Property", "Implemented mechanism", "Result"],
        [
            ["Confidentiality", "TLS 1.3; AES-256-GCM; RSA-OAEP", "Traffic and at-rest file data remain confidential to intended parties."],
            ["Integrity", "TLS AEAD; AES-GCM tags; RSA-PSS", "Changed encrypted data or public envelope fields are rejected."],
            ["Non-repudiation", "RSA-PSS sender signature", "The sender certificate verifies who signed the exact bundle."],
            ["Authorisation", "mTLS plus certificate fingerprints", "A valid user still needs a matching fingerprint entry."],
        ],
        [1.25, 2.4, 3.2],
    )
    paragraph(
        doc,
        "Metadata minimisation remains important. A readable filename can reveal a project, medical condition, person, or document purpose, so exposing it "
        "is a conscious usability compromise rather than a confidentiality claim. The system retains only this one useful listing value and protects timestamps, "
        "user aliases, recipient names, and hashes. Publishing a plaintext hash can also let an attacker test guesses about a small or known file, so hashes are not included.",
    )
    paragraph(
        doc,
        "The public values that remain have a specific function. The filename helps an authorised user choose a file, while the random file ID identifies the "
        "storage object. The sender "
        "fingerprint lets the server compare the uploaded bundle with the mutually authenticated client certificate. Recipient fingerprints identify "
        "which RSA-OAEP wrapped key belongs to an authorised user. The nonces are required inputs for AES-GCM decryption, and the sender certificate "
        "plus signature allow an offline recipient to verify the source of the bundle. The certificate subject is an opaque random label, reducing the "
        "personal information exposed by the necessary public verification material.",
    )
    paragraph(
        doc,
        "The recipient does not have to trust the storage server to make the cryptographic decision. After download, the client checks that the embedded "
        "sender certificate is signed by the configured CA, confirms that the certificate fingerprint matches the signed envelope, verifies the RSA-PSS "
        "signature, and uses only its own private key to unwrap the file key. AES-GCM then rejects altered encrypted metadata or file bytes. This "
        "independent verification is important if the server is misconfigured, compromised, or simply makes an incorrect authorisation decision: the "
        "recipient still refuses a bundle whose cryptographic evidence is invalid.",
    )
    paragraph(
        doc,
        "Including the sender as a recipient is an intentional usability decision. It gives the uploader a wrapped copy of the AES file key, allowing "
        "them to retrieve their own encrypted upload later without maintaining a separate plaintext copy. The server treats the sender fingerprint as an "
        "authorised entry for the same reason. This does not weaken confidentiality because only the sender's private key and the private keys of selected "
        "recipients can unwrap a copy of the AES key. Adding a new recipient later requires creating a new bundle because the server cannot derive or rewrap "
        "the AES key without decrypting it, which it is intentionally unable to do.",
    )

    heading(doc, "5. Cryptographic Design and Key Management")
    paragraph(
        doc,
        "AES-256-GCM is used for file data because authenticated encryption provides confidentiality and detects changes. "
        "A new AES key is generated for every file. Two distinct 96-bit nonces are generated from the operating-system "
        "CSPRNG: one for file bytes and one for encrypted metadata. The small public header is associated data, binding the "
        "file ID and sender fingerprint to both AES-GCM operations without making sensitive metadata readable.",
    )
    paragraph(
        doc,
        "RSA-OAEP-SHA256 wraps only the 32-byte AES file key, not the file itself. This permits offline recipients and avoids "
        "RSA's size and performance limitations. RSA-PSS-SHA256 signs the complete public envelope, including ciphertext, "
        "nonces, wrapped keys, sender certificate, and encrypted metadata. This makes separate plaintext or ciphertext hashes "
        "unnecessary as integrity controls and removes their disclosure from the bundle.",
    )
    paragraph(
        doc,
        "A local CA issues the server and client certificates. New RSA-3072 keys are generated for the demo and stored as "
        "encrypted PKCS#8 PEM files under a user-supplied passphrase; no private keys or hard-coded passphrase are shipped. "
        "Clients validate the server certificate and hostname; the server requires and validates a CA-signed client certificate. "
        "Certificate fingerprints provide the minimal public identifier needed for key lookup and access control.",
    )
    paragraph(
        doc,
        "Canonical JSON is used before signing so the sender and verifier obtain identical bytes even if a parser would otherwise "
        "reorder dictionary keys or add whitespace. The signature covers the public header, recipient wrapped keys, both nonces, "
        "encrypted file bytes, encrypted metadata, and sender certificate. Consequently an attacker cannot swap recipients, change "
        "a nonce, substitute ciphertext, or replace the certificate without invalidating the sender signature. AES-GCM then provides "
        "an additional authenticated-encryption check when the intended recipient decrypts each protected payload.",
    )
    paragraph(
        doc,
        "Nonce management is critical for AES-GCM. Reusing a nonce with the same AES key can compromise confidentiality and "
        "integrity. This implementation avoids that failure mode by generating a new AES key for every bundle and generating a "
        "new 96-bit nonce for each of the two AES-GCM encryptions. The code validates that the encoded nonces have the expected "
        "length and are not identical before accepting a bundle. The nonce is public by design; security depends on its uniqueness, "
        "not on keeping it secret.",
    )
    paragraph(
        doc,
        "RSA-OAEP is selected over legacy RSA PKCS#1 v1.5 encryption because OAEP is designed for probabilistic public-key "
        "encryption and is appropriate for a short content-encryption key. RSA-PSS is selected for signatures because it is a modern "
        "probabilistic signature scheme. RSA-3072 provides a higher security margin than the previous RSA-2048 demonstration keys, "
        "while still keeping setup and the small number of per-file RSA operations practical for this coursework environment.",
    )
    paragraph(
        doc,
        "Key lifecycle controls are demonstrated rather than fully operationalised. Setup generates a fresh CA, server key, and user "
        "keys on demand; the submission does not contain reusable private keys or a hard-coded passphrase. In a production service, "
        "the CA key would be stored separately and used rarely, certificate revocation would be checked, keys would be rotated, and "
        "separate keys would be used for TLS authentication, encryption, and signatures. These controls limit the impact and duration "
        "of a credential compromise but would add operational complexity beyond the assignment.",
    )
    paragraph(
        doc,
        "Certificate validation is performed at more than one boundary. During TLS setup, each endpoint trusts only the configured local "
        "CA and the client verifies the server hostname. The server requires a certificate during the handshake and then verifies the peer "
        "certificate against the CA, its validity period, and its client-authentication extended-key usage before accepting an application "
        "message. Bundle verification repeats the sender certificate and CA checks so that a downloaded bundle can be verified independently "
        "of the server that stored it. This provides evidence that the signature key belongs to a recognised certificate holder.",
    )
    paragraph(
        doc,
        "The use of certificate fingerprints does not replace certificate validation. A fingerprint is a compact identifier that tells the "
        "server which wrapped-key entry applies to a client, but the client and server still establish trust from the CA signature and validity "
        "checks. This separation avoids treating an arbitrary public key as an identity. It also means that replacing a certificate changes the "
        "fingerprint and requires the sender to create a new bundle or explicitly include the replacement certificate as a recipient.",
    )
    paragraph(
        doc,
        "The proposal distinguishes authentication from non-repudiation. Mutual TLS proves that the current network peer controls a valid "
        "client private key; it does not by itself create durable evidence about a stored file. The RSA-PSS signature is embedded in the bundle "
        "and remains verifiable after download, independently of the TLS session. Conversely, the signature does not create a confidential "
        "channel; TLS and AES-GCM remain necessary to prevent exposure of the request and file content.",
    )

    heading(doc, "6. Efficiency, Feasibility, and Sustainability")
    paragraph(
        doc,
        "AES-GCM performs the bulk file operation and is efficient for the assignment's small-to-medium demonstration files. "
        "RSA-3072 is used only for short key wrapping and signatures, so its additional computational cost is acceptable. "
        "Separating encrypted metadata from encrypted file bytes avoids base64-wrapping the entire plaintext inside a JSON metadata structure and keeps storage overhead small.",
    )
    paragraph(
        doc,
        "The implementation uses Python's standard socket/ssl modules and the established cryptography library instead of "
        "implementing cryptographic primitives manually. The remaining limitation is memory use: the current demo loads a "
        "whole file before encryption or decryption. Streaming authenticated encryption, quotas, rate limiting, audit logging, "
        "certificate revocation, and key separation are appropriate future improvements but are outside this assignment scope.",
    )
    paragraph(
        doc,
        "The v2 design also reduces unnecessary data processing. The server needs only a file ID, signed filename, and certificate fingerprints for "
        "listing and access decisions; it does not process plaintext hashes. Encrypting the small metadata record "
        "separately avoids converting the entire file into an additional JSON/Base64 layer before encryption. The unavoidable overhead "
        "is one AES-GCM tag per encrypted payload, two nonces, one RSA-OAEP wrapped key for each recipient, a sender certificate, and "
        "one RSA-PSS signature. This trade-off is reasonable for the small recipient groups used in the demonstration.",
    )
    paragraph(
        doc,
        "Sustainability in this context means selecting controls that provide meaningful protection without wasting compute or storage. "
        "AES-GCM is efficient for bulk data, while RSA is deliberately limited to short values. The architecture avoids a database, "
        "web framework, or persistent plaintext index, reducing deployment dependencies and attack surface. For a larger system, usage "
        "monitoring, automatic cleanup of expired bundles, streaming I/O, and batched certificate management would be required to keep "
        "resource consumption predictable as file sizes and recipient counts increase.",
    )

    heading(doc, "7. Operational Controls and Failure Handling")
    paragraph(
        doc,
        "The application protocol uses a four-byte length prefix and rejects messages above the configured maximum size before decoding JSON. "
        "This prevents an unbounded length declaration from causing the server to allocate arbitrary memory. The implementation then requires "
        "the top-level message to be a JSON object and routes only the upload, list, and download actions. These checks do not eliminate denial "
        "of service, but they provide a clear resource boundary appropriate for a small assignment server.",
    )
    paragraph(
        doc,
        "Bundle validation is deliberately strict. The v2 bundle must have exactly the permitted public fields; an old or additional field is "
        "rejected rather than ignored. Wrapped-key entries must contain one valid fingerprint and one Base64 OAEP value, and duplicate recipient "
        "fingerprints are refused. Nonces, ciphertexts, signatures, certificates, and wrapped keys are Base64-decoded before use so malformed "
        "data produces a controlled failure. File IDs are restricted to a UUID-hex pattern before the server maps them to storage paths, preventing "
        "a download request from selecting an arbitrary local path.",
    )
    paragraph(
        doc,
        "The server writes a bundle only after signature and sender-fingerprint validation. A client cannot upload a bundle claiming a different "
        "sender fingerprint from the certificate used in its TLS session. On download, a user is authorised only when the TLS fingerprint is the "
        "sender or appears in the wrapped-key list. In production, error messages should be normalised and detailed diagnostics written to protected "
        "server logs; the assignment implementation keeps the error path simple so failed validation can be demonstrated clearly.",
    )
    paragraph(
        doc,
        "The private-key passphrase is never hard-coded in source. Setup, client, and server prompt for it when it is not supplied as a command-line "
        "argument, preventing terminal echo during normal use. A command-line option remains available for controlled automation, but it should not be "
        "used in shared shell history or production process lists. This is a practical example of the distinction between encrypting a PEM file and "
        "actually protecting the passphrase needed to unlock it.",
    )

    heading(doc, "8. Conclusion and Additional Considerations")
    paragraph(
        doc,
        "The proposed v2 system protects data in transit with mutual TLS 1.3 and at rest with AES-256-GCM. RSA-OAEP distributes "
        "the file key to authorised recipients, and RSA-PSS provides verifiable sender approval. The public envelope exposes the signed original "
        "filename for usability, but protects identities, timestamps, recipient names, and plaintext hash values. "
        "The design is technically bounded: it does not claim at-rest forward secrecy or production-grade revocation.",
    )
    paragraph(
        doc,
        "Each assignment security requirement is traceable to a concrete implementation decision. Confidentiality during transit is provided "
        "by TLS 1.3 and mutual certificate authentication; confidentiality at rest is provided by a new AES-GCM key for every file. Integrity "
        "comes from TLS record protection, AES-GCM authentication tags, and a signature over the full public envelope. Non-repudiation is based "
        "on the durable RSA-PSS signature and CA-signed sender certificate, while recipient authorisation is enforced by the independently "
        "verified certificate fingerprint entries. This mapping makes the solution easier to explain and test during the demonstration.",
    )
    paragraph(
        doc,
        "The design also makes deliberate trade-offs. It accepts that recipient fingerprints, an opaque sender certificate, and the original filename remain visible. "
        "The filename makes the authorised list usable but may reveal a document's subject to the server or a storage attacker; users should choose filenames accordingly. "
        "In return, the bundle hides user aliases, timestamps, recipient names, and file hashes. It accepts RSA's higher cost only for short keys and "
        "signatures, while AES-GCM handles the file bytes. It accepts a local CA and manual passphrase workflow because they demonstrate PKI and "
        "key protection clearly without introducing infrastructure that the coursework cannot operate or audit properly.",
    )
    paragraph(
        doc,
        "Before submission, the group should replace the four student placeholders with actual names, confirm the course and class details, generate fresh credentials "
        "for the demonstration, and practise the access-control and tamper scenarios. The "
        "code package should continue to exclude generated credentials and old sample bundles. These final checks preserve the distinction between "
        "a reproducible teaching demonstration and a production deployment while presenting a coherent, defensible cryptographic solution.",
    )
    paragraph(
        doc,
        "Residual risk must be communicated honestly. A valid signature is evidence that the holder of the sender private key signed the bundle; "
        "it cannot prove the physical person who used an unlocked device, and it loses value if the key is compromised. Likewise, encrypted storage "
        "protects confidentiality but does not guarantee that the server will remain available, retain the bundle forever, or prevent traffic-analysis "
        "inferences from message timing and size. The tutor demonstration should therefore present non-repudiation as cryptographic evidence tied to "
        "certificate and private-key custody, not as an absolute legal conclusion.",
    )
    paragraph(
        doc,
        "The system is appropriate for the stated learning objective because it combines several controls without hand-implementing cryptographic "
        "algorithms. Its clearest limitation is operational scale: every additional recipient requires another RSA-OAEP wrapped copy of the AES key, "
        "and every user requires certificate issuance and secure private-key handling. For a larger organisation, group-key management, separate key "
        "roles, revocation checking, secure backup, and monitored service operations would be evaluated. Those additions would change the architecture, "
        "whereas the current design remains transparent enough for each protection decision to be inspected during assessment.",
    )

    heading(doc, "9. Planned Task Allocation")
    table(
        doc,
        ["Member", "Planned work and evidence"],
        [
            ["[Student 1]", "Built the basic client/server setup and TLS flow; evidence: client.py, server.py, protocol and demo commands."],
            ["[Student 2]", "Implemented AES and RSA encryption/signature bundle logic; evidence: crypto.py and bundle.py."],
            ["[Student 3]", "Implemented CA, certificate generation, and certificate validation; evidence: certs.py and setup_keys.py."],
            ["[Student 4]", "Led planning, reviewed every component, and integrated final hardening, documentation, and proposal."],
        ],
        [1.35, 5.5],
    )

    heading(doc, "10. Individual Reflections")
    for title, lines in (
        (
            "[Student 1]",
            (
                "I built the basic client and server setup and connected the two programs over TLS.",
                "This showed me that transport encryption must include certificate validation, not just a socket wrapper.",
                "I learned how the upload, list, and download commands depend on a clear protocol boundary.",
                "I would next add streaming support so large files do not need to remain in memory.",
            ),
        ),
        (
            "[Student 2]",
            (
                "I implemented the AES and RSA parts of the secure bundle design.",
                "I learned why AES-GCM is appropriate for file data and why RSA should wrap only a short file key.",
                "I also learned that signatures and authenticated encryption protect different parts of the security goal.",
                "I would next evaluate separate long-term keys for encryption and signing roles.",
            ),
        ),
        (
            "[Student 3]",
            (
                "I implemented certificate generation, CA signing, and certificate validation.",
                "I learned how certificates connect an identity to a public key for TLS and bundle verification.",
                "I also understood why fingerprints are useful for compact authorisation checks.",
                "I would next add revocation and certificate renewal handling for compromised credentials.",
            ),
        ),
        (
            "[Student 4]",
            (
                "I led the project and reviewed every component from the initial client/server setup to the certificate implementation.",
                "I helped integrate the client, server, encryption, and PKI work into the final system.",
                "I learned that cryptographic security depends on careful interfaces and not only on choosing strong algorithms.",
                "I would next organise a formal threat review and usability review before extending the system.",
            ),
        ),
    ):
        paragraph(doc, title, bold=True)
        for line in lines:
            paragraph(doc, line)

    heading(doc, "References")
    for item in (
        "Singapore Polytechnic. ST2504 Applied Cryptography Assignment 2 brief, 2026.",
        "Dworkin, M. NIST SP 800-38D: Galois/Counter Mode (GCM) and GMAC, 2007.",
        "Barker, E. NIST SP 800-57 Part 1 Rev. 5: Recommendation for Key Management, 2020.",
        "Rescorla, E. RFC 8446: The Transport Layer Security Protocol Version 1.3, 2018.",
        "Moriarty, K. et al. RFC 8017: PKCS #1 v2.2, 2016.",
        "Python Cryptographic Authority. cryptography documentation: AESGCM and RSA primitives.",
    ):
        bullet(doc, item)


def add_appendices(doc: Document) -> None:
    """Put supplementary procedures and future work after the 10-page report body."""

    doc.add_section(WD_SECTION.NEW_PAGE)
    heading(doc, "Appendix A. Demonstration Procedure")
    paragraph(doc, "1. Run: python tools/setup_keys.py init-demo --force. Enter and confirm a passphrase of at least 12 characters.")
    paragraph(doc, "2. Start: python server.py --host 127.0.0.1 --port 9000. Enter the server key passphrase.")
    paragraph(doc, "3. Upload: python client.py upload --user alice --to bob --file sample_files/example.txt. Enter Alice's passphrase.")
    paragraph(doc, "4. List: python client.py list --user bob. The result contains each authorised file ID and its signed original filename.")
    paragraph(doc, "5. Download: python client.py download --user bob --file-id FILE_ID --out downloads. Bob verifies the bundle and decrypts the file locally.")
    paragraph(doc, "6. Access-control check: repeat the download as Charlie. The server rejects Charlie because no wrapped key matches Charlie's certificate fingerprint.")

    heading(doc, "Appendix B. Future Security Enhancements")
    paragraph(doc, "1. Use streaming authenticated encryption for large files and explicit per-user storage quotas.")
    paragraph(doc, "2. Introduce certificate revocation, rotation, and operating-system or hardware-backed private-key storage.")
    paragraph(doc, "3. Separate TLS, encryption, and signing keys in a larger production design.")
    paragraph(doc, "4. Add structured audit logs, rate limiting, monitoring, and a recovery process for compromised credentials.")


def build_report() -> None:
    """Build and save the final proposal report from the controlled source content."""

    doc = Document()
    configure(doc)
    add_cover(doc)
    add_contents(doc)
    add_main_report(doc)
    add_appendices(doc)
    doc.core_properties.title = "Secure File-Sharing System Proposal"
    doc.core_properties.subject = "ST2504 Applied Cryptography Assignment 2"
    doc.core_properties.author = "[Student 1], [Student 2], [Student 3], [Student 4]"
    doc.save(OUTPUT)


if __name__ == "__main__":
    build_report()
    print(f"wrote {OUTPUT.resolve()}")
