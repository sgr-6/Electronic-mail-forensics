"""
Raw EML Parser & Digital Forensics Engine.

Parses RFC 822 / MIME email files to extract:
- Cryptographic evidence hashes (MD5, SHA-1, SHA-256)
- All standard and non-standard MIME headers
- Body content (plain text + HTML)
- Attachment metadata with SHA-256 integrity hashes
- Embedded hyperlinks from HTML body and plain text
"""

from __future__ import annotations

import hashlib
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any

from bs4 import BeautifulSoup


# Regex for extracting URLs from plain text
_URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'{}|\\^`\[\]()]+',
    re.IGNORECASE,
)


class EMLParser:
    """
    Full-featured parser for raw .eml / RFC 822 email files.

    Usage:
        parser = EMLParser(raw_bytes, filename="suspect.eml")
        result = parser.parse_full()
    """

    def __init__(self, raw_bytes: bytes, filename: str = "unknown.eml") -> None:
        self.raw_bytes = raw_bytes
        self.filename = filename
        self._msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    # --------------------------------------------------------------------- #
    # Evidence integrity                                                     #
    # --------------------------------------------------------------------- #

    def compute_hashes(self) -> dict[str, Any]:
        """Compute MD5, SHA-1, SHA-256 of the raw email bytes."""
        return {
            "md5": hashlib.md5(self.raw_bytes).hexdigest(),
            "sha1": hashlib.sha1(self.raw_bytes).hexdigest(),
            "sha256": hashlib.sha256(self.raw_bytes).hexdigest(),
            "size": len(self.raw_bytes),
        }

    # --------------------------------------------------------------------- #
    # Header extraction                                                      #
    # --------------------------------------------------------------------- #

    def extract_headers(self) -> dict[str, Any]:
        """
        Extract all headers into a dict.

        Multi-valued headers (e.g. Received) are stored as lists.
        Single-valued headers are stored as plain strings.
        """
        headers: dict[str, Any] = {}
        for key in set(self._msg.keys()):
            values = self._msg.get_all(key, [])
            str_values = [str(v) for v in values]
            headers[key] = str_values if len(str_values) > 1 else str_values[0]
        return headers

    def extract_addresses(self) -> dict[str, str | None]:
        """
        Parse key addressing headers: From, To, Subject, Date, Message-ID, Return-Path.

        Splits From into display name and email address.
        """
        from_raw = str(self._msg.get("From", ""))
        display_name, email_addr = parseaddr(from_raw)

        return {
            "from_address": email_addr or from_raw.strip(),
            "from_display": display_name or None,
            "to_address": str(self._msg.get("To", "")),
            "subject": str(self._msg.get("Subject", "")),
            "date_header": str(self._msg.get("Date", "")),
            "message_id": str(self._msg.get("Message-ID", "")),
            "return_path": str(self._msg.get("Return-Path", "")),
        }

    def get_received_headers(self) -> list[str]:
        """Return all Received: header values as a list (email order = reverse chronological)."""
        return [str(v) for v in self._msg.get_all("Received", [])]

    # --------------------------------------------------------------------- #
    # Body extraction                                                        #
    # --------------------------------------------------------------------- #

    def extract_body(self) -> dict[str, str]:
        """
        Extract plain text and HTML body parts.

        Walks the MIME tree for multipart messages.
        """
        body_plain = ""
        body_html = ""

        if self._msg.is_multipart():
            for part in self._msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))

                # Skip attachments
                if "attachment" in disposition.lower():
                    continue

                try:
                    payload = part.get_content()
                except Exception:
                    continue

                if not isinstance(payload, str):
                    continue

                if content_type == "text/plain" and not body_plain:
                    body_plain = payload
                elif content_type == "text/html" and not body_html:
                    body_html = payload
        else:
            try:
                content = self._msg.get_content()
                if isinstance(content, str):
                    ct = self._msg.get_content_type()
                    if ct == "text/plain":
                        body_plain = content
                    elif ct == "text/html":
                        body_html = content
            except Exception:
                pass

        return {"body_plain": body_plain, "body_html": body_html}

    # --------------------------------------------------------------------- #
    # Attachment extraction                                                  #
    # --------------------------------------------------------------------- #

    def extract_attachments(self) -> list[dict[str, Any]]:
        """
        Extract attachment metadata and compute SHA-256 for each.

        Returns a list of dicts with: filename, content_type, size, sha256.
        """
        attachments: list[dict[str, Any]] = []

        for part in self._msg.walk():
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" not in disposition.lower():
                continue

            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""

            attachments.append({
                "filename": part.get_filename() or "unnamed_attachment",
                "content_type": part.get_content_type(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })

        return attachments

    # --------------------------------------------------------------------- #
    # URL extraction                                                         #
    # --------------------------------------------------------------------- #

    def extract_urls(self) -> list[dict[str, Any]]:
        """
        Extract all URLs from both HTML body (href/src) and plain text.

        Each URL is returned with its de-fanged form and anchor text (if from HTML).
        """
        url_entries: dict[str, dict[str, Any]] = {}  # keyed by URL to deduplicate
        body = self.extract_body()

        # --- Extract from HTML ---
        if body["body_html"]:
            try:
                soup = BeautifulSoup(body["body_html"], "html.parser")

                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    if href and href.startswith(("http://", "https://")):
                        anchor_text = a_tag.get_text(strip=True) or None
                        url_entries[href] = {
                            "url": href,
                            "defanged": _defang_url(href),
                            "anchor_text": anchor_text,
                            "is_suspicious": False,
                            "suspicion_reason": None,
                        }

                for img in soup.find_all("img", src=True):
                    src = img["src"].strip()
                    if src and src.startswith(("http://", "https://")):
                        url_entries.setdefault(src, {
                            "url": src,
                            "defanged": _defang_url(src),
                            "anchor_text": None,
                            "is_suspicious": False,
                            "suspicion_reason": None,
                        })
            except Exception:
                pass

        # --- Extract from plain text ---
        if body["body_plain"]:
            for match in _URL_PATTERN.finditer(body["body_plain"]):
                url = match.group(0).rstrip(".,;:!?)")
                url_entries.setdefault(url, {
                    "url": url,
                    "defanged": _defang_url(url),
                    "anchor_text": None,
                    "is_suspicious": False,
                    "suspicion_reason": None,
                })

        return list(url_entries.values())

    # --------------------------------------------------------------------- #
    # Full parse (orchestrator)                                              #
    # --------------------------------------------------------------------- #

    def parse_full(self) -> dict[str, Any]:
        """
        Execute complete email forensic parse.

        Returns a structured dict with all extracted data ready for
        database insertion and downstream analysis.
        """
        hashes = self.compute_hashes()
        headers = self.extract_headers()
        addresses = self.extract_addresses()
        body = self.extract_body()
        attachments = self.extract_attachments()
        urls = self.extract_urls()
        received_headers = self.get_received_headers()

        return {
            "filename": self.filename,
            "hashes": hashes,
            "headers": headers,
            "addresses": addresses,
            "body": body,
            "attachments": attachments,
            "urls": urls,
            "received_headers": received_headers,
        }


# ========================================================================= #
# Utility functions                                                          #
# ========================================================================= #

def _defang_url(url: str) -> str:
    """
    De-fang a URL for safe display/sharing.

    Replaces protocol separators and dots to prevent accidental clicks.
    """
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Only defang dots in the domain portion, not the path
    parts = defanged.split("/", 3)
    if len(parts) >= 3:
        parts[2] = parts[2].replace(".", "[.]")
        return "/".join(parts)
    return defanged.replace(".", "[.]")
