"""
Obfuscated URL Analyzer.

Detects IP-based hostnames, suspicious TLDs, URL shorteners,
length anomalies, and anchor text mismatches.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse, unquote
from typing import Any

logger = logging.getLogger(__name__)

# Known URL shortener services
_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "rebrand.ly"
}

# Suspicious TLDs commonly used in phishing/spam
_SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz",
    ".club", ".info", ".su", ".cn", ".ru", ".site", ".online"
}

# Regex to detect IP addresses in hostnames
_IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


class URLAnalyzer:
    """Analyze URLs extracted from emails for suspicious patterns."""

    def analyze_urls(self, urls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Analyze a list of URL dictionaries.
        Input format: [{"url": "...", "defanged": "...", "anchor_text": "...", "is_suspicious": False, "suspicion_reason": None}]
        Updates is_suspicious and suspicion_reason in place.
        """
        for url_data in urls:
            url = url_data.get("url", "")
            anchor_text = url_data.get("anchor_text")
            
            if not url:
                continue

            reasons = []

            try:
                parsed = urlparse(url)
                hostname = parsed.hostname or ""
                hostname = hostname.lower()

                # 1. IP-based hostname
                if _IP_REGEX.match(hostname):
                    reasons.append("IP-based hostname used instead of domain")

                # 2. Suspicious TLD
                if any(hostname.endswith(tld) for tld in _SUSPICIOUS_TLDS):
                    reasons.append("Uses a suspicious TLD")

                # 3. URL shortener
                if hostname in _URL_SHORTENERS:
                    reasons.append("Uses a known URL shortener service")

                # 4. Extremely long URL (>200 chars)
                if len(url) > 200:
                    reasons.append(f"Unusually long URL ({len(url)} chars)")

                # 5. Excessive subdomains (>3)
                if len(hostname.split(".")) > 4:  # e.g., a.b.c.example.com
                    reasons.append("Excessive number of subdomains")

                # 6. Encoded characters in URL
                decoded_url = unquote(url)
                if decoded_url != url and "%" in url:
                    # Some encoding is normal, but excessive encoding in hostname/path can be evasion
                    reasons.append("Contains URL-encoded characters")

                # 7. Anchor text mismatch
                if anchor_text:
                    anchor_lower = anchor_text.lower().strip()
                    # If anchor text looks like a domain or URL
                    if "." in anchor_lower and not any(s in anchor_lower for s in (" ", "\n")):
                        # Check if the anchor domain matches the actual domain
                        # e.g., Anchor is "microsoft.com", but hostname is "evil.com"
                        anchor_parsed = urlparse(f"http://{anchor_lower}")
                        anchor_host = anchor_parsed.hostname or anchor_lower
                        
                        # Simplified check: if the main words don't match
                        if anchor_host != hostname and anchor_host not in hostname:
                            # Heuristic: Only flag if it looks like they are trying to spoof a different domain
                            if anchor_host.count(".") >= 1:
                                reasons.append(f"Anchor text ({anchor_host}) does not match URL hostname ({hostname})")

            except Exception as e:
                logger.debug("Failed to analyze URL %s: %s", url, e)
                reasons.append("Malformed URL could not be parsed")

            if reasons:
                url_data["is_suspicious"] = True
                url_data["suspicion_reason"] = "; ".join(reasons)

        return urls


# Singleton instance
url_analyzer = URLAnalyzer()
