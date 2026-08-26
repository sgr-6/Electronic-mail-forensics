"""
Unit tests for the GeoIP Resolver and Auth Engine services.

Tests:
- GeoIP mock resolver consistency and coverage
- SPF evaluation logic
- DKIM header parsing
- DMARC alignment checking
- IP reputation mock scoring
"""

from __future__ import annotations

import pytest

from app.services.geo_resolver import GeoResolver, geo_resolver
from app.services.auth_engine import (
    _check_alignment,
    _parse_dkim_tags,
    _extract_dkim_header,
    validate_spf,
    validate_dkim,
    validate_dmarc,
    validate_all,
)
from app.services.reputation import ReputationChecker, reputation_checker
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "samples"


def _load_sample(name: str) -> bytes:
    return (SAMPLES_DIR / name).read_bytes()


# ========================================================================= #
# Test: GeoIP Mock Resolver                                                  #
# ========================================================================= #

class TestGeoResolver:
    """Verify GeoIP mock resolver produces consistent, valid data."""

    def test_resolver_is_mock_by_default(self):
        """Without a .mmdb file, resolver should use mock mode."""
        assert geo_resolver.is_mock is True

    def test_resolve_known_ip(self):
        """Sample email IPs should resolve to specific mock locations."""
        result = geo_resolver.resolve("203.0.113.50")
        assert result["latitude"] is not None
        assert result["longitude"] is not None
        assert result["city"] is not None
        assert result["country"] is not None
        assert result["isp"] is not None
        assert result["asn"] is not None

    def test_resolve_russian_ip(self):
        """Russian VPS IPs from phishing sample should resolve to Russia."""
        result = geo_resolver.resolve("91.215.85.123")
        assert result["country"] == "Russia"

    def test_resolve_brazilian_ip(self):
        """Brazilian VPS from BEC sample should resolve to Brazil."""
        result = geo_resolver.resolve("45.227.253.109")
        assert result["country"] == "Brazil"

    def test_resolve_is_deterministic(self):
        """Same IP should always resolve to same location."""
        r1 = geo_resolver.resolve("8.8.8.8")
        r2 = geo_resolver.resolve("8.8.8.8")
        assert r1 == r2

    def test_resolve_different_ips_may_differ(self):
        """Different IPs should potentially resolve to different locations."""
        r1 = geo_resolver.resolve("1.1.1.1")
        r2 = geo_resolver.resolve("9.9.9.9")
        # They *could* collide by hash, but very unlikely
        # At minimum, both should return valid data
        assert r1["city"] is not None
        assert r2["city"] is not None

    def test_resolve_many(self):
        """Bulk resolution should return dict keyed by IP."""
        ips = ["203.0.113.50", "91.215.85.123", "45.227.253.109"]
        results = geo_resolver.resolve_many(ips)
        assert len(results) == 3
        for ip in ips:
            assert ip in results
            assert results[ip]["latitude"] is not None

    def test_all_required_fields_present(self):
        """Every resolve result must have all required fields."""
        required_fields = {"latitude", "longitude", "city", "country", "country_iso", "isp", "asn"}
        result = geo_resolver.resolve("185.234.72.19")
        assert required_fields.issubset(set(result.keys()))


# ========================================================================= #
# Test: DKIM Header Parsing                                                  #
# ========================================================================= #

class TestDKIMParsing:
    """Verify DKIM-Signature header extraction and tag parsing."""

    def test_extract_dkim_from_legitimate(self):
        raw = _load_sample("legitimate_email.eml")
        header = _extract_dkim_header(raw)
        assert header is not None
        assert "rsa-sha256" in header

    def test_extract_dkim_tags(self):
        header = "v=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to:subject"
        tags = _parse_dkim_tags(header)
        assert tags["v"] == "1"
        assert tags["a"] == "rsa-sha256"
        assert tags["d"] == "example.com"
        assert tags["s"] == "selector1"

    def test_no_dkim_in_phishing(self):
        raw = _load_sample("phishing_urgent.eml")
        header = _extract_dkim_header(raw)
        # Phishing email has no DKIM-Signature
        assert header is None

    def test_validate_dkim_returns_none_for_unsigned(self):
        raw = _load_sample("phishing_urgent.eml")
        result = validate_dkim(raw)
        assert result["result"] == "none"
        assert "No DKIM-Signature" in result["details"]


# ========================================================================= #
# Test: DMARC Alignment                                                     #
# ========================================================================= #

class TestDMARCAlignment:
    """Verify DMARC domain alignment logic."""

    def test_strict_exact_match(self):
        assert _check_alignment("example.com", "example.com", "s") is True

    def test_strict_subdomain_fails(self):
        assert _check_alignment("example.com", "sub.example.com", "s") is False

    def test_relaxed_exact_match(self):
        assert _check_alignment("example.com", "example.com", "r") is True

    def test_relaxed_subdomain_passes(self):
        assert _check_alignment("example.com", "sub.example.com", "r") is True

    def test_relaxed_parent_passes(self):
        assert _check_alignment("sub.example.com", "example.com", "r") is True

    def test_relaxed_different_domain_fails(self):
        assert _check_alignment("example.com", "different.com", "r") is False

    def test_case_insensitive(self):
        assert _check_alignment("Example.COM", "example.com", "s") is True


# ========================================================================= #
# Test: SPF Validation                                                      #
# ========================================================================= #

class TestSPFValidation:
    """Verify SPF validation logic."""

    def test_spf_no_domain(self):
        result = validate_spf("1.2.3.4", None)
        assert result["result"] == "none"
        assert "No sender domain" in result["details"]

    def test_spf_no_ip(self):
        result = validate_spf(None, "example.com")
        assert result["result"] == "none"
        assert "No originating IP" in result["details"]

    def test_spf_returns_structured_result(self):
        """SPF result should always have required fields."""
        result = validate_spf("1.2.3.4", "nonexistent-domain-xyz123.com")
        assert "result" in result
        assert "record" in result
        assert "details" in result
        assert result["result"] in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror")


# ========================================================================= #
# Test: Full Auth Validation                                                 #
# ========================================================================= #

class TestFullAuth:
    """Verify the combined auth validation orchestrator."""

    def test_validate_all_returns_all_three(self):
        raw = _load_sample("legitimate_email.eml")
        result = validate_all(
            raw_email=raw,
            sender_ip="203.0.113.50",
            from_domain="techcorp.com",
        )
        assert "spf" in result
        assert "dkim" in result
        assert "dmarc" in result
        assert "result" in result["spf"]
        assert "result" in result["dkim"]
        assert "result" in result["dmarc"]

    def test_validate_all_phishing(self):
        raw = _load_sample("phishing_urgent.eml")
        result = validate_all(
            raw_email=raw,
            sender_ip="185.234.72.19",
            from_domain="secure-verify.net",
        )
        # Phishing email should have no DKIM
        assert result["dkim"]["result"] in ("none", "fail")


# ========================================================================= #
# Test: IP Reputation                                                        #
# ========================================================================= #

class TestReputation:
    """Verify IP reputation mock checker."""

    def test_reputation_is_mock_by_default(self):
        assert reputation_checker.is_mock is True

    def test_suspicious_ip_high_score(self):
        """IPs in suspicious ranges should get high abuse scores."""
        result = reputation_checker.check("91.215.85.123")
        assert result["abuse_confidence_score"] >= 50
        assert result["threat_level"] in ("medium", "high")

    def test_clean_ip_low_score(self):
        """Normal IPs should get low/zero abuse scores."""
        result = reputation_checker.check("8.8.8.8")
        assert result["abuse_confidence_score"] < 10
        assert result["threat_level"] == "clean"

    def test_hosting_ip_moderate(self):
        """Hosting IPs should get moderate scores."""
        result = reputation_checker.check("209.85.220.41")
        assert result["is_hosting"] is True

    def test_check_returns_all_fields(self):
        """Reputation result must have all required fields."""
        required = {
            "ip_address", "abuse_confidence_score", "total_reports",
            "is_tor_exit", "is_proxy", "threat_level", "details",
        }
        result = reputation_checker.check("1.2.3.4")
        assert required.issubset(set(result.keys()))

    def test_check_many(self):
        """Bulk check should return dict keyed by IP."""
        ips = ["91.215.85.123", "8.8.8.8"]
        results = reputation_checker.check_many(ips)
        assert len(results) == 2
        assert results["91.215.85.123"]["abuse_confidence_score"] > results["8.8.8.8"]["abuse_confidence_score"]

    def test_deterministic_results(self):
        """Same IP should always get same reputation score."""
        r1 = reputation_checker.check("45.227.253.109")
        r2 = reputation_checker.check("45.227.253.109")
        assert r1["abuse_confidence_score"] == r2["abuse_confidence_score"]
