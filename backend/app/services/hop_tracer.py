"""
Hop-by-Hop SMTP Relay Chain Tracer.

Parses the `Received:` header chain from a raw email to reconstruct
the full transmission path. Identifies:
- Each relay hop with extracted hostname, IP, and timestamp
- Private (RFC 1918) vs public IP addresses
- The first trusted originating public IP
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Any

from email.utils import parsedate_to_datetime


# RFC 1918 private and reserved networks
PRIVATE_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("::1/128"),
    ip_network("fe80::/10"),
    ip_network("fc00::/7"),
]

# Regex patterns for parsing Received headers
_IP_V4_PATTERN = re.compile(
    r"""
    \[?                           # optional opening bracket
    (                             # capture group
        (?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.   # first octet
        (?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.   # second octet
        (?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.   # third octet
        (?:25[0-5]|2[0-4]\d|[01]?\d\d?)     # fourth octet
    )
    \]?                           # optional closing bracket
    """,
    re.VERBOSE,
)

_FROM_HOST_PATTERN = re.compile(r"from\s+([\w.\-]+)", re.IGNORECASE)
_BY_HOST_PATTERN = re.compile(r"by\s+([\w.\-]+)", re.IGNORECASE)
_TIMESTAMP_PATTERN = re.compile(r";\s*(.+)$", re.MULTILINE)
_WITH_PROTOCOL_PATTERN = re.compile(r"with\s+(\w+)", re.IGNORECASE)


def is_private_ip(ip_str: str) -> bool:
    """
    Check whether an IP address falls within RFC 1918 private or
    reserved address space.
    """
    try:
        addr = ip_address(ip_str)
        return any(addr in network for network in PRIVATE_NETWORKS)
    except (ValueError, TypeError):
        return False


def parse_single_hop(raw_header: str, sequence: int) -> dict[str, Any]:
    """
    Parse a single Received: header value into structured hop data.

    Args:
        raw_header: The raw Received header string.
        sequence: The chronological sequence number (1 = first hop).

    Returns:
        Dict with: sequence, from_host, by_host, ip_address, timestamp,
                   raw_header, is_private, is_originating, protocol.
    """
    hop: dict[str, Any] = {
        "sequence": sequence,
        "from_host": None,
        "by_host": None,
        "ip_address": None,
        "timestamp": None,
        "raw_header": raw_header.strip(),
        "is_private": False,
        "is_originating": False,
        "protocol": None,
    }

    # Extract "from" hostname
    from_match = _FROM_HOST_PATTERN.search(raw_header)
    if from_match:
        hop["from_host"] = from_match.group(1)

    # Extract "by" hostname
    by_match = _BY_HOST_PATTERN.search(raw_header)
    if by_match:
        hop["by_host"] = by_match.group(1)

    # Extract IP addresses — use the first valid IPv4 found
    ip_matches = _IP_V4_PATTERN.findall(raw_header)
    for ip_candidate in ip_matches:
        try:
            ip_address(ip_candidate)  # validate
            hop["ip_address"] = ip_candidate
            hop["is_private"] = is_private_ip(ip_candidate)
            break
        except ValueError:
            continue

    # Extract timestamp (after the semicolon)
    ts_match = _TIMESTAMP_PATTERN.search(raw_header)
    if ts_match:
        raw_ts = ts_match.group(1).strip()
        try:
            dt = parsedate_to_datetime(raw_ts)
            hop["timestamp"] = dt.isoformat()
        except Exception:
            hop["timestamp"] = raw_ts

    # Extract protocol (SMTP, ESMTP, ESMTPS, etc.)
    proto_match = _WITH_PROTOCOL_PATTERN.search(raw_header)
    if proto_match:
        hop["protocol"] = proto_match.group(1).upper()

    return hop


def parse_received_headers(received_headers: list[str]) -> list[dict[str, Any]]:
    """
    Parse all Received: headers into a chronological hop chain.

    Email stores Received headers in reverse chronological order
    (most recent first). This function reverses them to produce
    a chronological sequence where hop 1 = the originating server.

    Args:
        received_headers: List of Received header values in email order.

    Returns:
        List of hop dicts ordered chronologically (oldest first).
    """
    if not received_headers:
        return []

    # Reverse to chronological order (oldest = first)
    reversed_headers = list(reversed(received_headers))

    hops = []
    for seq, header in enumerate(reversed_headers, start=1):
        hop = parse_single_hop(header, sequence=seq)
        hops.append(hop)

    # Mark the first public IP as the originating hop
    _mark_originating_ip(hops)

    return hops


def _mark_originating_ip(hops: list[dict[str, Any]]) -> None:
    """
    Find and flag the first trusted originating public IP in the hop chain.

    The originating IP is the first hop with a public (non-RFC-1918) IP address.
    This is the most reliable indicator of the true sender's network origin.
    """
    for hop in hops:
        if hop["ip_address"] and not hop["is_private"]:
            hop["is_originating"] = True
            return  # Only mark the first one


def find_originating_ip(hops: list[dict[str, Any]]) -> str | None:
    """
    Extract the originating public IP from a parsed hop chain.

    Returns:
        The IP address string of the originating hop, or None if
        all hops are private/internal.
    """
    for hop in hops:
        if hop.get("is_originating"):
            return hop["ip_address"]
    return None


def get_public_ips(hops: list[dict[str, Any]]) -> list[str]:
    """Return all unique public IPs from the hop chain."""
    seen: set[str] = set()
    public_ips: list[str] = []
    for hop in hops:
        ip = hop.get("ip_address")
        if ip and not hop.get("is_private") and ip not in seen:
            seen.add(ip)
            public_ips.append(ip)
    return public_ips


def summarize_route(hops: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Generate a summary of the complete transmission route.

    Returns:
        Dict with total_hops, public_hops, private_hops, originating_ip,
        and protocol_chain.
    """
    public_count = sum(1 for h in hops if h.get("ip_address") and not h.get("is_private"))
    private_count = sum(1 for h in hops if h.get("is_private"))
    protocols = [h.get("protocol") for h in hops if h.get("protocol")]

    return {
        "total_hops": len(hops),
        "public_hops": public_count,
        "private_hops": private_count,
        "originating_ip": find_originating_ip(hops),
        "protocol_chain": protocols,
    }
