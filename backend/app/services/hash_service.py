"""
Cryptographic Evidence Hashing Service.

Computes SHA-256 evidence digests directly from original uploaded file bytes
for digital forensics evidence integrity verification.
"""

from __future__ import annotations

import hashlib
from typing import Any


class HashService:
    """
    Service for calculating and verifying cryptographic evidence hashes.

    Integrity principles:
    - Hashes are calculated directly from original uploaded bytes before parsing.
    - Standard 64-character hexadecimal SHA-256 digest is produced.
    - SHA-256 is a non-reversible cryptographic hash function (not encryption).
    """

    @staticmethod
    def calculate_sha256(raw_bytes: bytes) -> str:
        """
        Calculate standard 64-character hexadecimal SHA-256 hash digest.

        Raises ValueError if raw_bytes is empty or None.
        """
        if not raw_bytes:
            raise ValueError("Cannot calculate SHA-256 hash of empty or missing file bytes")

        return hashlib.sha256(raw_bytes).hexdigest()

    @staticmethod
    def calculate_evidence_hashes(raw_bytes: bytes, filename: str = "evidence.eml") -> dict[str, Any]:
        """
        Calculate full set of evidence integrity hashes (SHA-256 primary, SHA-1, MD5, size).

        Returns:
            dict containing sha256, sha1, md5, size, algorithm, status, filename
        """
        sha256_hash = HashService.calculate_sha256(raw_bytes)
        sha1_hash = hashlib.sha1(raw_bytes).hexdigest()
        md5_hash = hashlib.md5(raw_bytes).hexdigest()

        return {
            "filename": filename,
            "hash_algorithm": "SHA-256",
            "sha256": sha256_hash,
            "sha1": sha1_hash,
            "md5": md5_hash,
            "size": len(raw_bytes),
            "status": "Hash Generated",
        }

    @staticmethod
    def verify_evidence_integrity(raw_bytes: bytes, expected_sha256: str) -> dict[str, Any]:
        """
        Verify an uploaded file against a stored expected SHA-256 evidence fingerprint.

        Returns:
            dict containing verified (bool), expected_sha256, actual_sha256, status, message
        """
        actual_sha256 = HashService.calculate_sha256(raw_bytes)
        expected_clean = expected_sha256.strip().lower()
        actual_clean = actual_sha256.strip().lower()

        is_verified = expected_clean == actual_clean

        if is_verified:
            return {
                "verified": True,
                "hash_algorithm": "SHA-256",
                "expected_sha256": expected_clean,
                "actual_sha256": actual_clean,
                "status": "VERIFIED",
                "message": "✓ Evidence Integrity Verified. File matches stored SHA-256 fingerprint exactly.",
            }
        else:
            return {
                "verified": False,
                "hash_algorithm": "SHA-256",
                "expected_sha256": expected_clean,
                "actual_sha256": actual_clean,
                "status": "EVIDENCE INTEGRITY FAILED",
                "message": "❌ EVIDENCE INTEGRITY FAILED. File content has been modified or corrupted.",
            }


# Singleton instance for convenience import
hash_service = HashService()
