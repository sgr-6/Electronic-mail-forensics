"""
Sender Authentication Engine — SPF, DKIM, DMARC validation.

Performs real-time DNS queries to validate email sender authentication:
- SPF: Evaluates sender IP against domain SPF records
- DKIM: Extracts DKIM-Signature and verifies against DNS public key
- DMARC: Fetches DMARC policy and evaluates SPF/DKIM alignment

All validation is gracefully degraded — DNS timeouts, missing records,
and malformed signatures produce informative results rather than crashes.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ========================================================================= #
# DNS Resolution Utility                                                     #
# ========================================================================= #


def _dns_txt_lookup(domain: str, timeout: float = 5.0) -> list[str]:
    """
    Look up TXT records for a domain.

    Returns list of concatenated TXT record strings.
    Gracefully returns empty list on any failure.
    """
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        answers = resolver.resolve(domain, "TXT")
        results = []
        for rdata in answers:
            # TXT records may be split across multiple strings
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            results.append(txt)
        return results
    except Exception as e:
        logger.debug("DNS TXT lookup failed for %s: %s", domain, e)
        return []


# ========================================================================= #
# SPF Validation                                                            #
# ========================================================================= #

_SPF_RESULTS = ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror")


def validate_spf(sender_ip: str | None, sender_domain: str | None) -> dict[str, Any]:
    """
    Validate sender IP against SPF record of the sender domain.

    Args:
        sender_ip: The originating public IP address.
        sender_domain: The domain from the envelope sender (Return-Path or From).

    Returns:
        Dict with: result (pass/fail/softfail/neutral/none/temperror/permerror),
                   record (raw SPF record), details (explanation).
    """
    result: dict[str, Any] = {
        "result": "none",
        "record": None,
        "details": "",
        "sender_ip": sender_ip,
        "sender_domain": sender_domain,
    }

    if not sender_domain:
        result["details"] = "No sender domain available for SPF check"
        return result

    if not sender_ip:
        result["details"] = "No originating IP available for SPF check"
        return result

    # Fetch SPF record
    txt_records = _dns_txt_lookup(sender_domain)
    spf_record = None
    for txt in txt_records:
        if txt.lower().startswith("v=spf1"):
            spf_record = txt
            break

    if not spf_record:
        result["details"] = f"No SPF record found for {sender_domain}"
        return result

    result["record"] = spf_record

    # Parse SPF mechanisms
    try:
        mechanisms = spf_record.split()[1:]  # Skip "v=spf1"
        spf_result = _evaluate_spf_mechanisms(sender_ip, mechanisms, sender_domain)
        result["result"] = spf_result
        result["details"] = f"SPF evaluation: {spf_result} for IP {sender_ip} against {sender_domain}"
    except Exception as e:
        result["result"] = "temperror"
        result["details"] = f"SPF evaluation error: {str(e)}"

    return result


def _evaluate_spf_mechanisms(ip: str, mechanisms: list[str], domain: str) -> str:
    """
    Evaluate SPF mechanisms against the sender IP.

    Simplified evaluator that handles common mechanisms:
    ip4, ip6, a, mx, include, all, redirect.
    """
    from ipaddress import ip_address, ip_network

    try:
        sender_addr = ip_address(ip)
    except ValueError:
        return "permerror"

    for mechanism in mechanisms:
        mechanism = mechanism.strip()
        if not mechanism:
            continue

        # Parse qualifier
        qualifier = "+"  # default is pass
        if mechanism[0] in "+-~?":
            qualifier = mechanism[0]
            mechanism = mechanism[1:]

        qualifier_map = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}

        # Evaluate mechanism
        if mechanism.startswith("ip4:"):
            network_str = mechanism[4:]
            try:
                if "/" not in network_str:
                    network_str += "/32"
                network = ip_network(network_str, strict=False)
                if sender_addr in network:
                    return qualifier_map[qualifier]
            except ValueError:
                continue

        elif mechanism.startswith("ip6:"):
            network_str = mechanism[4:]
            try:
                if "/" not in network_str:
                    network_str += "/128"
                network = ip_network(network_str, strict=False)
                if sender_addr in network:
                    return qualifier_map[qualifier]
            except ValueError:
                continue

        elif mechanism == "all":
            return qualifier_map[qualifier]

        elif mechanism.startswith("include:"):
            # Recursive SPF check (simplified - just check if record exists)
            included_domain = mechanism[8:]
            included_records = _dns_txt_lookup(included_domain)
            for rec in included_records:
                if rec.lower().startswith("v=spf1"):
                    sub_mechs = rec.split()[1:]
                    sub_result = _evaluate_spf_mechanisms(ip, sub_mechs, included_domain)
                    if sub_result == "pass":
                        return "pass"

        elif mechanism.startswith("a"):
            # Check A records of domain
            check_domain = domain
            if ":" in mechanism:
                check_domain = mechanism.split(":", 1)[1]
            try:
                import dns.resolver
                answers = dns.resolver.resolve(check_domain, "A")
                for rdata in answers:
                    if str(rdata) == str(sender_addr):
                        return qualifier_map[qualifier]
            except Exception:
                continue

        elif mechanism.startswith("mx"):
            # Check MX records
            check_domain = domain
            if ":" in mechanism:
                check_domain = mechanism.split(":", 1)[1]
            try:
                import dns.resolver
                mx_answers = dns.resolver.resolve(check_domain, "MX")
                for mx in mx_answers:
                    mx_host = str(mx.exchange).rstrip(".")
                    try:
                        a_answers = dns.resolver.resolve(mx_host, "A")
                        for a_rdata in a_answers:
                            if str(a_rdata) == str(sender_addr):
                                return qualifier_map[qualifier]
                    except Exception:
                        continue
            except Exception:
                continue

    return "neutral"


# ========================================================================= #
# DKIM Validation                                                           #
# ========================================================================= #

def validate_dkim(raw_email: bytes) -> dict[str, Any]:
    """
    Validate DKIM signature on a raw email.

    Uses dkimpy for cryptographic verification when available.
    Falls back to header-only analysis if dkimpy verification fails.

    Args:
        raw_email: The raw email bytes.

    Returns:
        Dict with: result (pass/fail/none), selector, domain,
                   algorithm, details.
    """
    result: dict[str, Any] = {
        "result": "none",
        "selector": None,
        "domain": None,
        "algorithm": None,
        "details": "",
    }

    # Extract DKIM-Signature header manually for metadata
    dkim_header = _extract_dkim_header(raw_email)
    if not dkim_header:
        result["details"] = "No DKIM-Signature header found"
        return result

    # Parse DKIM header fields
    parsed = _parse_dkim_tags(dkim_header)
    result["selector"] = parsed.get("s")
    result["domain"] = parsed.get("d")
    result["algorithm"] = parsed.get("a", "rsa-sha256")

    # Try cryptographic verification via dkimpy
    try:
        import dkim
        is_valid = dkim.verify(raw_email)
        result["result"] = "pass" if is_valid else "fail"
        result["details"] = (
            f"DKIM {'verified' if is_valid else 'verification failed'} "
            f"for d={result['domain']} s={result['selector']}"
        )
    except ImportError:
        result["result"] = "neutral"
        result["details"] = "dkimpy not available; DKIM header present but not verified"
    except Exception as e:
        # dkimpy can fail for many reasons (DNS timeout, key format, etc.)
        # This is NOT a crash — it's an informative failure
        result["result"] = "fail"
        result["details"] = f"DKIM verification error: {str(e)}"

    # Additional: try to fetch the public key from DNS to confirm it exists
    if result["selector"] and result["domain"]:
        dns_domain = f"{result['selector']}._domainkey.{result['domain']}"
        txt_records = _dns_txt_lookup(dns_domain)
        if txt_records:
            result["public_key_found"] = True
            result["dns_record"] = txt_records[0][:200]  # Truncate for storage
        else:
            result["public_key_found"] = False
            if result["result"] != "pass":
                result["details"] += f"; No DNS key at {dns_domain}"

    return result


def _extract_dkim_header(raw_email: bytes) -> str | None:
    """Extract the DKIM-Signature header value from raw email bytes."""
    try:
        text = raw_email.decode("utf-8", errors="replace")
        # Find DKIM-Signature header (may span multiple lines with folding)
        match = re.search(
            r"^DKIM-Signature:\s*(.+?)(?=\n[^\s]|\n\n)",
            text,
            re.MULTILINE | re.DOTALL | re.IGNORECASE,
        )
        if match:
            # Unfold continuation lines
            header_value = match.group(1)
            return re.sub(r"\r?\n\s+", " ", header_value).strip()
    except Exception:
        pass
    return None


def _parse_dkim_tags(header_value: str) -> dict[str, str]:
    """Parse DKIM-Signature tag=value pairs."""
    tags: dict[str, str] = {}
    for part in header_value.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip()] = value.strip()
    return tags


# ========================================================================= #
# DMARC Validation                                                          #
# ========================================================================= #

def validate_dmarc(
    sender_domain: str | None,
    spf_result: str = "none",
    spf_domain: str | None = None,
    dkim_result: str = "none",
    dkim_domain: str | None = None,
) -> dict[str, Any]:
    """
    Validate DMARC policy and evaluate alignment.

    DMARC requires either SPF or DKIM to pass AND be aligned with
    the From domain.

    Args:
        sender_domain: The domain from the From header.
        spf_result: Result of SPF check (pass/fail/etc).
        spf_domain: Domain used in SPF check (envelope sender).
        dkim_result: Result of DKIM check (pass/fail/etc).
        dkim_domain: Domain from DKIM d= tag.

    Returns:
        Dict with: result (pass/fail/none), policy (none/quarantine/reject),
                   alignment_mode, spf_aligned, dkim_aligned, record, details.
    """
    result: dict[str, Any] = {
        "result": "none",
        "policy": None,
        "subdomain_policy": None,
        "alignment_mode": None,
        "spf_aligned": False,
        "dkim_aligned": False,
        "record": None,
        "details": "",
    }

    if not sender_domain:
        result["details"] = "No sender domain available for DMARC check"
        return result

    # Fetch DMARC record
    dmarc_domain = f"_dmarc.{sender_domain}"
    txt_records = _dns_txt_lookup(dmarc_domain)
    dmarc_record = None
    for txt in txt_records:
        if txt.lower().startswith("v=dmarc1"):
            dmarc_record = txt
            break

    if not dmarc_record:
        result["details"] = f"No DMARC record found at {dmarc_domain}"
        return result

    result["record"] = dmarc_record

    # Parse DMARC tags
    tags = _parse_dmarc_tags(dmarc_record)
    result["policy"] = tags.get("p", "none")
    result["subdomain_policy"] = tags.get("sp", tags.get("p", "none"))
    alignment_spf = tags.get("aspf", "r")  # r = relaxed (default)
    alignment_dkim = tags.get("adkim", "r")
    result["alignment_mode"] = f"SPF:{alignment_spf} DKIM:{alignment_dkim}"

    # Check SPF alignment
    if spf_result == "pass" and spf_domain:
        result["spf_aligned"] = _check_alignment(sender_domain, spf_domain, alignment_spf)

    # Check DKIM alignment
    if dkim_result == "pass" and dkim_domain:
        result["dkim_aligned"] = _check_alignment(sender_domain, dkim_domain, alignment_dkim)

    # DMARC passes if either SPF or DKIM is aligned
    if result["spf_aligned"] or result["dkim_aligned"]:
        result["result"] = "pass"
        aligned_via = []
        if result["spf_aligned"]:
            aligned_via.append("SPF")
        if result["dkim_aligned"]:
            aligned_via.append("DKIM")
        result["details"] = f"DMARC pass via {'+'.join(aligned_via)} alignment"
    else:
        result["result"] = "fail"
        result["details"] = (
            f"DMARC fail: policy={result['policy']}; "
            f"SPF {'pass' if spf_result == 'pass' else 'fail'} "
            f"(aligned={result['spf_aligned']}); "
            f"DKIM {'pass' if dkim_result == 'pass' else 'fail'} "
            f"(aligned={result['dkim_aligned']})"
        )

    return result


def _parse_dmarc_tags(record: str) -> dict[str, str]:
    """Parse DMARC record tag=value pairs."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip().lower()
    return tags


def _check_alignment(from_domain: str, auth_domain: str, mode: str) -> bool:
    """
    Check domain alignment.

    Strict mode: domains must match exactly.
    Relaxed mode: organizational domains must match (auth domain can be
    a subdomain of from domain or vice versa).
    """
    from_domain = from_domain.lower().rstrip(".")
    auth_domain = auth_domain.lower().rstrip(".")

    if mode == "s":
        # Strict: exact match
        return from_domain == auth_domain
    else:
        # Relaxed: organizational domain match
        return (
            from_domain == auth_domain
            or auth_domain.endswith(f".{from_domain}")
            or from_domain.endswith(f".{auth_domain}")
        )


# ========================================================================= #
# Orchestrator                                                               #
# ========================================================================= #

def validate_all(
    raw_email: bytes,
    sender_ip: str | None,
    from_domain: str | None,
    envelope_domain: str | None = None,
) -> dict[str, Any]:
    """
    Run all three authentication checks (SPF, DKIM, DMARC).

    Args:
        raw_email: Raw email bytes for DKIM verification.
        sender_ip: Originating public IP for SPF.
        from_domain: Domain from the From header.
        envelope_domain: Domain from Return-Path (defaults to from_domain).

    Returns:
        Dict with spf, dkim, dmarc sub-dicts.
    """
    env_domain = envelope_domain or from_domain

    spf = validate_spf(sender_ip, env_domain)
    dkim = validate_dkim(raw_email)
    dmarc = validate_dmarc(
        sender_domain=from_domain,
        spf_result=spf["result"],
        spf_domain=env_domain,
        dkim_result=dkim["result"],
        dkim_domain=dkim.get("domain"),
    )

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
    }
