"""
IP Geolocation Resolver.

Resolves public IP addresses to geographic coordinates using MaxMind GeoLite2.
Falls back to a deterministic mock resolver when no .mmdb file is available,
enabling zero-config local development.

Mock fallback generates plausible geographic data seeded from the IP address
for consistent, reproducible results across demo sessions.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Any

from app.config import settings

logger = logging.getLogger(__name__)

# Known geographic locations for mock resolution (seeded by IP hash)
_MOCK_LOCATIONS = [
    {"city": "New York", "country": "United States", "country_iso": "US", "lat": 40.7128, "lon": -74.0060, "isp": "Verizon Business", "asn": "AS701"},
    {"city": "London", "country": "United Kingdom", "country_iso": "GB", "lat": 51.5074, "lon": -0.1278, "isp": "BT Group", "asn": "AS2856"},
    {"city": "Moscow", "country": "Russia", "country_iso": "RU", "lat": 55.7558, "lon": 37.6173, "isp": "Rostelecom", "asn": "AS12389"},
    {"city": "Beijing", "country": "China", "country_iso": "CN", "lat": 39.9042, "lon": 116.4074, "isp": "China Telecom", "asn": "AS4134"},
    {"city": "Singapore", "country": "Singapore", "country_iso": "SG", "lat": 1.3521, "lon": 103.8198, "isp": "SingTel", "asn": "AS3758"},
    {"city": "São Paulo", "country": "Brazil", "country_iso": "BR", "lat": -23.5505, "lon": -46.6333, "isp": "Vivo", "asn": "AS26599"},
    {"city": "Mumbai", "country": "India", "country_iso": "IN", "lat": 19.0760, "lon": 72.8777, "isp": "Reliance Jio", "asn": "AS55836"},
    {"city": "Frankfurt", "country": "Germany", "country_iso": "DE", "lat": 50.1109, "lon": 8.6821, "isp": "Deutsche Telekom", "asn": "AS3320"},
    {"city": "Tokyo", "country": "Japan", "country_iso": "JP", "lat": 35.6762, "lon": 139.6503, "isp": "NTT Communications", "asn": "AS4713"},
    {"city": "Sydney", "country": "Australia", "country_iso": "AU", "lat": -33.8688, "lon": 151.2093, "isp": "Telstra", "asn": "AS1221"},
    {"city": "Amsterdam", "country": "Netherlands", "country_iso": "NL", "lat": 52.3676, "lon": 4.9041, "isp": "KPN", "asn": "AS1136"},
    {"city": "Lagos", "country": "Nigeria", "country_iso": "NG", "lat": 6.5244, "lon": 3.3792, "isp": "MTN Nigeria", "asn": "AS29465"},
    {"city": "Dubai", "country": "United Arab Emirates", "country_iso": "AE", "lat": 25.2048, "lon": 55.2708, "isp": "Etisalat", "asn": "AS8966"},
    {"city": "Toronto", "country": "Canada", "country_iso": "CA", "lat": 43.6532, "lon": -79.3832, "isp": "Bell Canada", "asn": "AS577"},
    {"city": "Stockholm", "country": "Sweden", "country_iso": "SE", "lat": 59.3293, "lon": 18.0686, "isp": "Telia Company", "asn": "AS1299"},
    {"city": "Seoul", "country": "South Korea", "country_iso": "KR", "lat": 37.5665, "lon": 126.9780, "isp": "Korea Telecom", "asn": "AS4766"},
]

# Map specific IP prefixes to specific locations for demo realism
_IP_PREFIX_MAP = {
    "203.0.113": 0,   # US (documentation range, used in legitimate sample)
    "91.215": 2,       # Russia (used in phishing sample)
    "185.234": 2,      # Russia (used in phishing sample)
    "45.227": 5,       # Brazil (used in BEC sample)
    "209.85.220": 0,   # US / Google (used in BEC sample)
    "103.45": 6,       # India region (used in spoofed sample)
    "198.51.100": 0,   # US (documentation range, used in spoofed sample)
}


class GeoResolver:
    """
    Resolve IP addresses to geographic locations.

    Automatically uses MaxMind GeoLite2 when available,
    otherwise falls back to deterministic mock data.
    """

    def __init__(self) -> None:
        self._reader = None
        self._using_mock = True
        self._init_reader()

    def _init_reader(self) -> None:
        """Try to initialize MaxMind GeoIP reader."""
        db_path = settings.geoip_db_path
        if os.path.exists(db_path):
            try:
                import geoip2.database
                self._reader = geoip2.database.Reader(db_path)
                self._using_mock = False
                logger.info("GeoIP: Using MaxMind database at %s", db_path)
            except Exception as e:
                logger.warning("GeoIP: Failed to load MaxMind database: %s. Using mock.", e)
        else:
            logger.info("GeoIP: No MaxMind database found at %s. Using mock resolver.", db_path)

    @property
    def is_mock(self) -> bool:
        """Whether the resolver is using mock data."""
        return self._using_mock

    def resolve(self, ip_address: str) -> dict[str, Any]:
        """
        Resolve an IP address to geographic data.

        Args:
            ip_address: The IP to resolve (must be a public IP).

        Returns:
            Dict with: latitude, longitude, city, country, country_iso, isp, asn.
            Returns None values for unresolvable IPs.
        """
        if self._using_mock:
            return self._mock_resolve(ip_address)
        return self._real_resolve(ip_address)

    def _real_resolve(self, ip_address: str) -> dict[str, Any]:
        """Resolve using MaxMind GeoLite2 database."""
        result = _empty_result()
        try:
            response = self._reader.city(ip_address)
            result["latitude"] = response.location.latitude
            result["longitude"] = response.location.longitude
            result["city"] = response.city.name or "Unknown"
            result["country"] = response.country.name or "Unknown"
            result["country_iso"] = response.country.iso_code or "XX"

            # Try ASN lookup if available
            try:
                asn_response = self._reader.asn(ip_address)
                result["isp"] = asn_response.autonomous_system_organization or "Unknown"
                result["asn"] = f"AS{asn_response.autonomous_system_number}" if asn_response.autonomous_system_number else "Unknown"
            except Exception:
                pass

        except Exception as e:
            logger.debug("GeoIP lookup failed for %s: %s", ip_address, e)

        return result

    def _mock_resolve(self, ip_address: str) -> dict[str, Any]:
        """
        Deterministic mock resolver.

        Uses IP prefix mapping for known sample IPs, otherwise
        hashes the IP to pick a consistent location from the pool.
        """
        # Check prefix map first (for sample email demo consistency)
        for prefix, idx in _IP_PREFIX_MAP.items():
            if ip_address.startswith(prefix):
                loc = _MOCK_LOCATIONS[idx]
                return {
                    "latitude": loc["lat"],
                    "longitude": loc["lon"],
                    "city": loc["city"],
                    "country": loc["country"],
                    "country_iso": loc["country_iso"],
                    "isp": loc["isp"],
                    "asn": loc["asn"],
                }

        # Hash-based deterministic fallback for unknown IPs
        ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest(), 16)
        loc = _MOCK_LOCATIONS[ip_hash % len(_MOCK_LOCATIONS)]
        return {
            "latitude": loc["lat"],
            "longitude": loc["lon"],
            "city": loc["city"],
            "country": loc["country"],
            "country_iso": loc["country_iso"],
            "isp": loc["isp"],
            "asn": loc["asn"],
        }

    def resolve_many(self, ip_addresses: list[str]) -> dict[str, dict[str, Any]]:
        """Resolve multiple IPs. Returns dict keyed by IP address."""
        return {ip: self.resolve(ip) for ip in ip_addresses}

    def close(self) -> None:
        """Close the MaxMind reader if open."""
        if self._reader:
            self._reader.close()


def _empty_result() -> dict[str, Any]:
    """Return an empty geolocation result dict."""
    return {
        "latitude": None,
        "longitude": None,
        "city": None,
        "country": None,
        "country_iso": None,
        "isp": None,
        "asn": None,
    }


# Singleton instance
geo_resolver = GeoResolver()
