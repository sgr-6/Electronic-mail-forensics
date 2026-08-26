"""
IP Reputation & Threat Intelligence Service.

Checks IP addresses against:
- AbuseIPDB for abuse confidence scores and report counts
- Known Tor exit node characteristics
- Public proxy / VPN / hosting indicators

Falls back to deterministic mock data when no AbuseIPDB API key is configured,
enabling zero-config local development with realistic threat intelligence demo data.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

import requests

from app.config import settings

logger = logging.getLogger(__name__)

# IP ranges commonly associated with suspicious infrastructure (for mock)
_SUSPICIOUS_PREFIXES = [
    "91.215", "185.234", "45.227", "103.45",  # Common VPS/hosting ranges
    "5.188", "194.87", "176.119", "77.247",    # Known abuse-heavy ranges
]

_HOSTING_PREFIXES = [
    "209.85", "172.217",  # Google
    "198.51.100",         # Documentation/test range
]


class ReputationChecker:
    """
    Check IP reputation against threat intelligence sources.

    Automatically uses AbuseIPDB when API key is configured,
    otherwise provides deterministic mock data for demo/dev.
    """

    def __init__(self) -> None:
        self._api_key = settings.abuseipdb_api_key
        self._using_mock = not bool(self._api_key)
        if self._using_mock:
            logger.info("Reputation: No AbuseIPDB API key configured. Using mock data.")
        else:
            logger.info("Reputation: AbuseIPDB API key configured. Using real lookups.")

    @property
    def is_mock(self) -> bool:
        return self._using_mock

    def check(self, ip_address: str) -> dict[str, Any]:
        """
        Check reputation for a single IP address.

        Returns:
            Dict with: abuse_confidence_score (0-100), total_reports,
                       is_tor_exit, is_proxy, is_vpn, is_hosting,
                       country_code, isp, domain, usage_type, details.
        """
        if self._using_mock:
            return self._mock_check(ip_address)
        return self._real_check(ip_address)

    def check_many(self, ip_addresses: list[str]) -> dict[str, dict[str, Any]]:
        """Check reputation for multiple IPs. Returns dict keyed by IP."""
        return {ip: self.check(ip) for ip in ip_addresses}

    # ----------------------------------------------------------------- #
    # Real AbuseIPDB lookup                                              #
    # ----------------------------------------------------------------- #

    def _real_check(self, ip_address: str) -> dict[str, Any]:
        """Query AbuseIPDB API v2."""
        result = _empty_result(ip_address)

        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": self._api_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip_address,
                    "maxAgeInDays": 90,
                    "verbose": True,
                },
                timeout=10,
            )
            response.raise_for_status()
            data = response.json().get("data", {})

            result["abuse_confidence_score"] = data.get("abuseConfidenceScore", 0)
            result["total_reports"] = data.get("totalReports", 0)
            result["is_tor_exit"] = data.get("isTor", False)
            result["is_proxy"] = data.get("isProxy", False) if "isProxy" in data else False
            result["country_code"] = data.get("countryCode", "")
            result["isp"] = data.get("isp", "")
            result["domain"] = data.get("domain", "")
            result["usage_type"] = data.get("usageType", "")
            result["is_hosting"] = "hosting" in result["usage_type"].lower() if result["usage_type"] else False

            # Determine threat level
            score = result["abuse_confidence_score"]
            if score >= 75:
                result["threat_level"] = "high"
            elif score >= 40:
                result["threat_level"] = "medium"
            elif score > 0:
                result["threat_level"] = "low"
            else:
                result["threat_level"] = "clean"

            result["details"] = (
                f"AbuseIPDB: confidence={score}%, reports={result['total_reports']}, "
                f"tor={result['is_tor_exit']}, hosting={result['is_hosting']}"
            )

        except requests.exceptions.Timeout:
            result["details"] = "AbuseIPDB: Request timed out"
            result["threat_level"] = "unknown"
        except requests.exceptions.RequestException as e:
            result["details"] = f"AbuseIPDB: Request failed: {str(e)}"
            result["threat_level"] = "unknown"

        return result

    # ----------------------------------------------------------------- #
    # Mock fallback                                                      #
    # ----------------------------------------------------------------- #

    def _mock_check(self, ip_address: str) -> dict[str, Any]:
        """
        Deterministic mock reputation data.

        Uses IP characteristics to generate realistic threat intelligence:
        - Known suspicious prefixes get high abuse scores
        - Hosting IPs get medium scores
        - All others get clean scores
        """
        result = _empty_result(ip_address)

        # Check if IP is in suspicious ranges
        is_suspicious = any(ip_address.startswith(prefix) for prefix in _SUSPICIOUS_PREFIXES)
        is_hosting = any(ip_address.startswith(prefix) for prefix in _HOSTING_PREFIXES)

        # Generate deterministic but varying scores based on IP hash
        ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest()[:8], 16)

        if is_suspicious:
            result["abuse_confidence_score"] = 50 + (ip_hash % 50)  # 50-99
            result["total_reports"] = 10 + (ip_hash % 200)
            result["is_tor_exit"] = (ip_hash % 5) == 0  # 20% chance
            result["is_proxy"] = (ip_hash % 3) == 0      # 33% chance
            result["is_hosting"] = True
            result["threat_level"] = "high" if result["abuse_confidence_score"] >= 75 else "medium"
        elif is_hosting:
            result["abuse_confidence_score"] = 5 + (ip_hash % 20)  # 5-24
            result["total_reports"] = ip_hash % 10
            result["is_hosting"] = True
            result["threat_level"] = "low"
        else:
            result["abuse_confidence_score"] = ip_hash % 5  # 0-4
            result["total_reports"] = 0
            result["threat_level"] = "clean"

        result["is_vpn"] = result["is_proxy"]  # Simplified
        result["details"] = (
            f"Mock reputation: confidence={result['abuse_confidence_score']}%, "
            f"reports={result['total_reports']}, tor={result['is_tor_exit']}"
        )

        return result


def _empty_result(ip_address: str) -> dict[str, Any]:
    """Return an empty reputation result."""
    return {
        "ip_address": ip_address,
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "is_tor_exit": False,
        "is_proxy": False,
        "is_vpn": False,
        "is_hosting": False,
        "country_code": "",
        "isp": "",
        "domain": "",
        "usage_type": "",
        "threat_level": "unknown",
        "details": "",
    }


# Singleton instance
reputation_checker = ReputationChecker()
