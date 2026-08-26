"""
Unit tests for the Hop-by-Hop SMTP Relay Tracer.

Tests:
- Private IP detection (RFC 1918)
- Single hop parsing
- Full Received header chain reconstruction
- Originating IP identification
- Edge cases (empty headers, missing IPs, malformed timestamps)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.hop_tracer import (
    find_originating_ip,
    get_public_ips,
    is_private_ip,
    parse_received_headers,
    parse_single_hop,
    summarize_route,
)
from app.services.eml_parser import EMLParser

SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "samples"


def _load_sample(name: str) -> bytes:
    filepath = SAMPLES_DIR / name
    return filepath.read_bytes()


# ========================================================================= #
# Test: Private IP Classification                                           #
# ========================================================================= #

class TestPrivateIPDetection:
    """Verify RFC 1918 and reserved address space detection."""

    @pytest.mark.parametrize("ip", [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
        "127.0.0.1",
        "127.0.0.100",
    ])
    def test_private_ips(self, ip: str):
        assert is_private_ip(ip) is True

    @pytest.mark.parametrize("ip", [
        "8.8.8.8",
        "203.0.113.50",
        "91.215.85.123",
        "185.234.72.19",
        "1.1.1.1",
        "45.227.253.109",
    ])
    def test_public_ips(self, ip: str):
        assert is_private_ip(ip) is False

    def test_invalid_ip_returns_false(self):
        assert is_private_ip("not-an-ip") is False
        assert is_private_ip("") is False
        assert is_private_ip("999.999.999.999") is False


# ========================================================================= #
# Test: Single Hop Parsing                                                   #
# ========================================================================= #

class TestSingleHopParsing:
    """Verify extraction of individual Received header fields."""

    def test_standard_received_header(self):
        header = (
            "from mail-out.techcorp.com (mail-out.techcorp.com [203.0.113.50]) "
            "by mx.example.com (Postfix) with ESMTPS id ABC12345 "
            "for <analyst@example.com>; Mon, 15 Jan 2024 09:30:00 +0000 (UTC)"
        )
        hop = parse_single_hop(header, sequence=1)

        assert hop["sequence"] == 1
        assert hop["from_host"] == "mail-out.techcorp.com"
        assert hop["by_host"] == "mx.example.com"
        assert hop["ip_address"] == "203.0.113.50"
        assert hop["is_private"] is False
        assert hop["timestamp"] is not None
        assert hop["protocol"] == "ESMTPS"

    def test_private_ip_hop(self):
        header = (
            "from internal-relay.techcorp.com (internal-relay.techcorp.com [10.0.1.5]) "
            "by mail-out.techcorp.com (Postfix) with ESMTP id DEF45678; "
            "Mon, 15 Jan 2024 09:29:55 +0000 (UTC)"
        )
        hop = parse_single_hop(header, sequence=2)

        assert hop["ip_address"] == "10.0.1.5"
        assert hop["is_private"] is True
        assert hop["from_host"] == "internal-relay.techcorp.com"

    def test_localhost_hop(self):
        header = (
            "from localhost (localhost [127.0.0.1]) "
            "by vps-node.hostingservice.ru with ESMTP id PHISH001; "
            "Wed, 20 Mar 2024 14:22:00 +0000"
        )
        hop = parse_single_hop(header, sequence=1)

        assert hop["ip_address"] == "127.0.0.1"
        assert hop["is_private"] is True

    def test_helo_format(self):
        header = (
            "from unknown (HELO mail.secure-verify.net) (185.234.72.19) "
            "by mx.example.com with SMTP; Wed, 20 Mar 2024 14:22:10 +0000"
        )
        hop = parse_single_hop(header, sequence=3)

        assert hop["ip_address"] == "185.234.72.19"
        assert hop["is_private"] is False

    def test_raw_header_preserved(self):
        header = "from server.example.com by relay.example.com; Mon, 1 Jan 2024 00:00:00 +0000"
        hop = parse_single_hop(header, sequence=1)
        assert hop["raw_header"] == header


# ========================================================================= #
# Test: Full Chain Parsing                                                   #
# ========================================================================= #

class TestChainParsing:
    """Verify full Received header chain reconstruction."""

    def test_legitimate_email_chain(self):
        raw = _load_sample("legitimate_email.eml")
        parser = EMLParser(raw)
        received = parser.get_received_headers()
        hops = parse_received_headers(received)

        # Should have 3 hops in chronological order
        assert len(hops) == 3

        # First hop (chronologically) should be from internal network
        assert hops[0]["is_private"] is True  # 192.168.1.100
        assert hops[0]["sequence"] == 1

        # Second hop should also be private
        assert hops[1]["is_private"] is True  # 10.0.1.5
        assert hops[1]["sequence"] == 2

        # Third hop should be public (mail-out)
        assert hops[2]["ip_address"] == "203.0.113.50"
        assert hops[2]["is_private"] is False
        assert hops[2]["sequence"] == 3

    def test_phishing_email_chain(self):
        raw = _load_sample("phishing_urgent.eml")
        parser = EMLParser(raw)
        received = parser.get_received_headers()
        hops = parse_received_headers(received)

        assert len(hops) >= 2

        # Should find public IPs from Russian hosting
        public_ips = get_public_ips(hops)
        assert len(public_ips) >= 1

    def test_originating_ip_identified(self):
        raw = _load_sample("legitimate_email.eml")
        parser = EMLParser(raw)
        received = parser.get_received_headers()
        hops = parse_received_headers(received)

        # Originating IP should be the first PUBLIC IP
        orig_ip = find_originating_ip(hops)
        assert orig_ip is not None
        assert is_private_ip(orig_ip) is False

    def test_bec_originating_ip(self):
        raw = _load_sample("bec_ceo_fraud.eml")
        parser = EMLParser(raw)
        received = parser.get_received_headers()
        hops = parse_received_headers(received)

        orig_ip = find_originating_ip(hops)
        assert orig_ip is not None
        # BEC email originates from cheap VPS
        assert orig_ip in ["45.227.253.109", "209.85.220.41"]

    def test_empty_headers(self):
        hops = parse_received_headers([])
        assert hops == []

    def test_chronological_ordering(self):
        """Hops should be in chronological order (oldest = sequence 1)."""
        raw = _load_sample("legitimate_email.eml")
        parser = EMLParser(raw)
        received = parser.get_received_headers()
        hops = parse_received_headers(received)

        sequences = [h["sequence"] for h in hops]
        assert sequences == sorted(sequences)
        assert sequences[0] == 1


# ========================================================================= #
# Test: Route Summarization                                                  #
# ========================================================================= #

class TestRouteSummary:
    """Verify route summary generation."""

    def test_legitimate_route_summary(self):
        raw = _load_sample("legitimate_email.eml")
        parser = EMLParser(raw)
        received = parser.get_received_headers()
        hops = parse_received_headers(received)
        summary = summarize_route(hops)

        assert summary["total_hops"] == 3
        assert summary["private_hops"] >= 2
        assert summary["public_hops"] >= 1
        assert summary["originating_ip"] is not None
        assert isinstance(summary["protocol_chain"], list)

    def test_empty_route_summary(self):
        summary = summarize_route([])
        assert summary["total_hops"] == 0
        assert summary["originating_ip"] is None


# ========================================================================= #
# Test: Public IP Extraction                                                 #
# ========================================================================= #

class TestPublicIPExtraction:
    """Verify extraction of unique public IPs from hop chains."""

    def test_public_ips_from_legitimate(self):
        raw = _load_sample("legitimate_email.eml")
        parser = EMLParser(raw)
        received = parser.get_received_headers()
        hops = parse_received_headers(received)
        public_ips = get_public_ips(hops)

        assert "203.0.113.50" in public_ips
        # Private IPs should NOT be in the list
        assert "10.0.1.5" not in public_ips
        assert "192.168.1.100" not in public_ips

    def test_no_duplicate_public_ips(self):
        raw = _load_sample("phishing_urgent.eml")
        parser = EMLParser(raw)
        received = parser.get_received_headers()
        hops = parse_received_headers(received)
        public_ips = get_public_ips(hops)

        assert len(public_ips) == len(set(public_ips))
