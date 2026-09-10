"""
Unit tests for HashService cryptographic evidence hashing & integrity verification.

Tests:
1. Same file -> same SHA-256 hash (deterministic)
2. Different file -> different SHA-256 hash
3. Known test vector string ("hello") produces exact expected SHA-256 digest
4. Modified .eml file produces a different hash
5. Hash is calculated from original raw bytes, not parsed/reconstructed email content
6. Verification returns success for identical file and failure for tampered file
7. Empty file handling raises ValueError
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app.services.hash_service import HashService, hash_service
from app.services.eml_parser import EMLParser

SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "samples"


def _load_sample(name: str) -> bytes:
    """Load sample file bytes."""
    filepath = SAMPLES_DIR / name
    assert filepath.exists(), f"Sample file missing: {filepath}"
    return filepath.read_bytes()


class TestHashService:
    """Test suite for HashService cryptographic evidence hashing."""

    def font_test_known_test_vector(self):
        """Test C: Known test string 'hello' produces exact SHA-256 digest."""
        raw_input = b"hello"
        expected_sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        actual_sha256 = HashService.calculate_sha256(raw_input)
        assert actual_sha256 == expected_sha256

    def test_known_test_vector(self):
        """Test C: Known test vector string produces exact SHA-256 digest."""
        input_bytes = b"hello"
        expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        digest = HashService.calculate_sha256(input_bytes)
        assert digest == expected

    def test_same_file_same_sha256(self):
        """Test A: Same file -> same SHA-256 hash."""
        raw = _load_sample("legitimate_email.eml")
        hash1 = HashService.calculate_sha256(raw)
        hash2 = HashService.calculate_sha256(raw)
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_different_files_different_sha256(self):
        """Test B: Different file -> different SHA-256 hash."""
        raw1 = _load_sample("legitimate_email.eml")
        raw2 = _load_sample("phishing_urgent.eml")
        hash1 = HashService.calculate_sha256(raw1)
        hash2 = HashService.calculate_sha256(raw2)
        assert hash1 != hash2

    def test_modified_eml_produces_different_hash(self):
        """Test D: Modified .eml file produces a different hash."""
        original_raw = _load_sample("legitimate_email.eml")
        # Tamper with 1 byte by appending a space
        tampered_raw = original_raw + b" "
        
        original_hash = HashService.calculate_sha256(original_raw)
        tampered_hash = HashService.calculate_sha256(tampered_raw)
        
        assert original_hash != tampered_hash

    def test_hash_calculated_from_original_bytes(self):
        """Test E: Hash is calculated from original raw bytes, not reconstructed content."""
        raw = _load_sample("bec_ceo_fraud.eml")
        # Direct hash of original raw bytes
        direct_sha256 = HashService.calculate_sha256(raw)
        
        # Verify parser uses raw bytes
        parser = EMLParser(raw, "bec_ceo_fraud.eml")
        parsed = parser.parse_full()
        
        assert parsed["hashes"]["sha256"] == direct_sha256
        assert direct_sha256 == hashlib.sha256(raw).hexdigest()

    def test_empty_file_raises_error(self):
        """Test error handling for 0-byte or empty inputs."""
        with pytest.raises(ValueError, match="empty or missing file"):
            HashService.calculate_sha256(b"")

    def test_verification_matching_file(self):
        """Verify evidence verification logic for matching files."""
        raw = _load_sample("legitimate_email.eml")
        expected_hash = HashService.calculate_sha256(raw)
        
        res = HashService.verify_evidence_integrity(raw, expected_hash)
        assert res["verified"] is True
        assert res["status"] == "VERIFIED"
        assert res["expected_sha256"] == expected_hash
        assert res["actual_sha256"] == expected_hash

    def test_verification_tampered_file(self):
        """Verify evidence verification logic for tampered files."""
        original_raw = _load_sample("legitimate_email.eml")
        expected_hash = HashService.calculate_sha256(original_raw)
        
        tampered_raw = original_raw + b"\nX-Tampered: true\n"
        actual_hash = HashService.calculate_sha256(tampered_raw)
        
        res = HashService.verify_evidence_integrity(tampered_raw, expected_hash)
        assert res["verified"] is False
        assert res["status"] == "EVIDENCE INTEGRITY FAILED"
        assert res["expected_sha256"] == expected_hash
        assert res["actual_sha256"] == actual_hash
        assert res["expected_sha256"] != res["actual_sha256"]
