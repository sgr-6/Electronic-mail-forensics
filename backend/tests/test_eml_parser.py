"""
Unit tests for the EML Parser service.

Tests:
- Hash computation correctness
- Header extraction from all sample email types
- Body extraction (plain + HTML)
- Attachment extraction with SHA-256
- URL extraction and de-fanging
- Full parse pipeline integration
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from app.services.eml_parser import EMLParser, _defang_url

# Path to sample emails
SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "samples"


def _load_sample(name: str) -> bytes:
    """Load a sample .eml file as raw bytes."""
    filepath = SAMPLES_DIR / name
    assert filepath.exists(), f"Sample file not found: {filepath}"
    return filepath.read_bytes()


# ========================================================================= #
# Test: Hash Computation                                                     #
# ========================================================================= #

class TestHashComputation:
    """Verify cryptographic hash calculations for evidence integrity."""

    def test_hashes_are_deterministic(self):
        raw = _load_sample("legitimate_email.eml")
        parser = EMLParser(raw, "legitimate_email.eml")
        hashes = parser.compute_hashes()

        # Independently compute expected hashes
        assert hashes["md5"] == hashlib.md5(raw).hexdigest()
        assert hashes["sha1"] == hashlib.sha1(raw).hexdigest()
        assert hashes["sha256"] == hashlib.sha256(raw).hexdigest()
        assert hashes["size"] == len(raw)

    def test_different_emails_have_different_hashes(self):
        h1 = EMLParser(_load_sample("legitimate_email.eml")).compute_hashes()
        h2 = EMLParser(_load_sample("phishing_urgent.eml")).compute_hashes()
        assert h1["sha256"] != h2["sha256"]
        assert h1["md5"] != h2["md5"]

    def test_hash_format(self):
        raw = _load_sample("bec_ceo_fraud.eml")
        hashes = EMLParser(raw).compute_hashes()
        assert len(hashes["md5"]) == 32
        assert len(hashes["sha1"]) == 40
        assert len(hashes["sha256"]) == 64
        assert all(c in "0123456789abcdef" for c in hashes["sha256"])


# ========================================================================= #
# Test: Header Extraction                                                    #
# ========================================================================= #

class TestHeaderExtraction:
    """Verify header parsing across different email types."""

    def test_legitimate_email_headers(self):
        parser = EMLParser(_load_sample("legitimate_email.eml"))
        headers = parser.extract_headers()

        assert "From" in headers
        assert "To" in headers
        assert "Subject" in headers
        assert "Date" in headers
        assert "Message-ID" in headers
        assert "DKIM-Signature" in headers

    def test_address_parsing_with_display_name(self):
        parser = EMLParser(_load_sample("legitimate_email.eml"))
        addresses = parser.extract_addresses()

        assert addresses["from_address"] == "john.smith@techcorp.com"
        assert addresses["from_display"] == "John Smith"
        assert "analyst@example.com" in addresses["to_address"]
        assert "Q4 2024 Budget" in addresses["subject"]

    def test_phishing_email_headers(self):
        parser = EMLParser(_load_sample("phishing_urgent.eml"))
        addresses = parser.extract_addresses()

        assert "secure-verify.net" in addresses["from_address"]
        assert "URGENT" in addresses["subject"]

    def test_bec_fraud_reply_to_mismatch(self):
        parser = EMLParser(_load_sample("bec_ceo_fraud.eml"))
        headers = parser.extract_headers()
        addresses = parser.extract_addresses()

        # From and Reply-To should differ (BEC indicator)
        assert "techcorp-inc.com" in addresses["from_address"]
        assert "Reply-To" in headers
        assert "gmail.com" in headers["Reply-To"]

    def test_spoofed_from_sender_mismatch(self):
        parser = EMLParser(_load_sample("spoofed_headers.eml"))
        headers = parser.extract_headers()
        addresses = parser.extract_addresses()

        # From claims to be AICTE but Sender is mass-mailer
        assert "aicte-india.org" in addresses["from_address"]
        assert "Sender" in headers
        assert "mass-mailer.xyz" in headers["Sender"]

    def test_received_headers_extracted(self):
        parser = EMLParser(_load_sample("legitimate_email.eml"))
        received = parser.get_received_headers()

        assert len(received) >= 3  # Legitimate email has 3 Received headers
        assert all(isinstance(h, str) for h in received)

    def test_return_path_extraction(self):
        parser = EMLParser(_load_sample("spoofed_headers.eml"))
        addresses = parser.extract_addresses()

        assert "mass-mailer.xyz" in addresses["return_path"]


# ========================================================================= #
# Test: Body Extraction                                                      #
# ========================================================================= #

class TestBodyExtraction:
    """Verify plain text and HTML body parsing."""

    def test_legitimate_multipart_body(self):
        parser = EMLParser(_load_sample("legitimate_email.eml"))
        body = parser.extract_body()

        assert body["body_plain"]
        assert body["body_html"]
        assert "budget review" in body["body_plain"].lower()
        assert "<html>" in body["body_html"].lower()

    def test_phishing_body_contains_urgency(self):
        parser = EMLParser(_load_sample("phishing_urgent.eml"))
        body = parser.extract_body()

        assert body["body_plain"]
        assert "urgent" in body["body_plain"].lower()
        assert "suspend" in body["body_plain"].lower()

    def test_bec_plaintext_only(self):
        parser = EMLParser(_load_sample("bec_ceo_fraud.eml"))
        body = parser.extract_body()

        assert body["body_plain"]
        assert "wire transfer" in body["body_plain"].lower()
        assert "$487,000" in body["body_plain"]

    def test_spoofed_has_html_body(self):
        parser = EMLParser(_load_sample("spoofed_headers.eml"))
        body = parser.extract_body()

        assert body["body_html"]
        assert "credential" in body["body_html"].lower()


# ========================================================================= #
# Test: Attachment Extraction                                                #
# ========================================================================= #

class TestAttachmentExtraction:
    """Verify attachment metadata and hash computation."""

    def test_spoofed_email_has_attachment(self):
        parser = EMLParser(_load_sample("spoofed_headers.eml"))
        attachments = parser.extract_attachments()

        assert len(attachments) >= 1
        pdf_att = attachments[0]
        assert pdf_att["filename"] == "AICTE_Credential_Update_Form.pdf"
        assert pdf_att["content_type"] == "application/pdf"
        assert pdf_att["size"] > 0
        assert len(pdf_att["sha256"]) == 64

    def test_legitimate_email_no_attachments(self):
        parser = EMLParser(_load_sample("legitimate_email.eml"))
        attachments = parser.extract_attachments()

        assert len(attachments) == 0

    def test_attachment_hash_is_deterministic(self):
        parser1 = EMLParser(_load_sample("spoofed_headers.eml"))
        parser2 = EMLParser(_load_sample("spoofed_headers.eml"))

        att1 = parser1.extract_attachments()
        att2 = parser2.extract_attachments()

        assert att1[0]["sha256"] == att2[0]["sha256"]


# ========================================================================= #
# Test: URL Extraction                                                       #
# ========================================================================= #

class TestURLExtraction:
    """Verify URL extraction from HTML and plain text bodies."""

    def test_phishing_urls_extracted(self):
        parser = EMLParser(_load_sample("phishing_urgent.eml"))
        urls = parser.extract_urls()

        assert len(urls) >= 1
        url_strings = [u["url"] for u in urls]
        assert any("secure-check.xyz" in u for u in url_strings)

    def test_urls_have_defanged_form(self):
        parser = EMLParser(_load_sample("phishing_urgent.eml"))
        urls = parser.extract_urls()

        for url_entry in urls:
            assert url_entry["defanged"]
            assert "hxxp" in url_entry["defanged"] or "hxxps" in url_entry["defanged"]

    def test_spoofed_email_urls(self):
        parser = EMLParser(_load_sample("spoofed_headers.eml"))
        urls = parser.extract_urls()

        url_strings = [u["url"] for u in urls]
        assert any("mass-mailer.xyz" in u for u in url_strings)

    def test_legitimate_email_minimal_urls(self):
        parser = EMLParser(_load_sample("legitimate_email.eml"))
        urls = parser.extract_urls()

        # Legitimate email has no external links
        assert len(urls) == 0


# ========================================================================= #
# Test: De-fanging utility                                                   #
# ========================================================================= #

class TestDefanging:
    """Verify URL de-fanging for safe sharing."""

    def test_http_defanged(self):
        assert "hxxp://" in _defang_url("http://evil.com/path")

    def test_https_defanged(self):
        assert "hxxps://" in _defang_url("https://evil.com/path")

    def test_dots_defanged_in_domain(self):
        result = _defang_url("http://evil.example.com/path")
        assert "[.]" in result


# ========================================================================= #
# Test: Full Parse Pipeline                                                  #
# ========================================================================= #

class TestFullParse:
    """Integration tests for the complete parse pipeline."""

    def test_full_parse_legitimate(self):
        raw = _load_sample("legitimate_email.eml")
        result = EMLParser(raw, "legitimate_email.eml").parse_full()

        assert result["filename"] == "legitimate_email.eml"
        assert result["hashes"]["sha256"]
        assert result["headers"]
        assert result["addresses"]["from_address"] == "john.smith@techcorp.com"
        assert result["body"]["body_plain"]
        assert len(result["received_headers"]) >= 3

    def test_full_parse_phishing(self):
        raw = _load_sample("phishing_urgent.eml")
        result = EMLParser(raw, "phishing_urgent.eml").parse_full()

        assert result["filename"] == "phishing_urgent.eml"
        assert "secure-verify.net" in result["addresses"]["from_address"]
        assert len(result["urls"]) >= 1
        assert len(result["received_headers"]) >= 2

    def test_full_parse_bec(self):
        raw = _load_sample("bec_ceo_fraud.eml")
        result = EMLParser(raw, "bec_ceo_fraud.eml").parse_full()

        assert "techcorp-inc.com" in result["addresses"]["from_address"]
        assert "$487,000" in result["body"]["body_plain"]

    def test_full_parse_spoofed(self):
        raw = _load_sample("spoofed_headers.eml")
        result = EMLParser(raw, "spoofed_headers.eml").parse_full()

        assert "aicte-india.org" in result["addresses"]["from_address"]
        assert len(result["attachments"]) >= 1
        assert len(result["urls"]) >= 1

    def test_all_samples_parse_without_error(self):
        """Smoke test: every sample file should parse successfully."""
        for eml_file in SAMPLES_DIR.glob("*.eml"):
            raw = eml_file.read_bytes()
            result = EMLParser(raw, eml_file.name).parse_full()
            assert result["hashes"]["sha256"], f"Parse failed for {eml_file.name}"
            assert result["headers"], f"No headers parsed for {eml_file.name}"
