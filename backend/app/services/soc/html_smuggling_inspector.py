"""
Module 2: HTML Smuggling & Base64 Payload Inspector

Parses HTML body to detect client-side payload assembly vectors
(URL.createObjectURL(), hidden IFrames, Base64 Data URIs).
Decodes chunks, calculates hashes, and inspects magic bytes.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import re
from typing import Any
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Common magic bytes
_MAGIC_BYTES = {
    b"MZ": "Executable (EXE/DLL)",
    b"PK\x03\x04": "Zip Archive (ZIP/DOCX)",
    b"%PDF": "PDF Document",
    b"\x89PNG": "PNG Image",
    b"\xFF\xD8\xFF": "JPEG Image",
    b"Rar!\x1A\x07\x00": "RAR Archive",
    b"\x7FELF": "ELF Executable"
}

class HTMLSmugglingInspector:
    def __init__(self):
        pass

    def analyze(self, html_body: str) -> dict[str, Any]:
        if not html_body:
            return {"indicators": [], "smuggled_files": []}

        indicators = []
        smuggled_files = []

        # 1. Heuristic regex for JS smuggling techniques
        if re.search(r"URL\.createObjectURL", html_body, re.IGNORECASE):
            indicators.append("JavaScript Blob/Object URL creation detected (potential smuggling)")
        if re.search(r"new Blob\(", html_body, re.IGNORECASE):
            indicators.append("JavaScript Blob instantiation detected")
        if re.search(r"atob\(", html_body, re.IGNORECASE):
            indicators.append("Base64 decoding via atob() detected")
        if re.search(r"document\.createElement\(['\"]a['\"]\)", html_body, re.IGNORECASE) and re.search(r"\.download", html_body, re.IGNORECASE):
            indicators.append("Auto-download anchor tag generation detected")

        # 2. Extract Base64 chunks (data URIs or large JS strings)
        # Match data:[<mediatype>][;base64],<data>
        data_uri_regex = re.compile(r"data:([a-zA-Z0-9/\-\.]+)?;base64,([a-zA-Z0-9+/=]+)")
        matches = data_uri_regex.findall(html_body)

        for mime_type, b64_data in matches:
            try:
                # Discard very small base64 strings (likely icons)
                if len(b64_data) < 1000:
                    continue
                
                raw_bytes = base64.b64decode(b64_data)
                file_size = len(raw_bytes)
                file_hash = hashlib.sha256(raw_bytes).hexdigest()
                
                # Magic bytes inspection
                detected_type = "Unknown Data"
                for magic, ftype in _MAGIC_BYTES.items():
                    if raw_bytes.startswith(magic):
                        detected_type = ftype
                        break
                        
                # Check for MIME-type spoofing
                spoofed = False
                if mime_type and mime_type != "application/octet-stream":
                    if detected_type != "Unknown Data":
                        # Simplistic spoof check (e.g. claims image/png but is MZ)
                        if "image" in mime_type.lower() and "Executable" in detected_type:
                            spoofed = True
                            indicators.append(f"MIME Spoofing: Claims {mime_type} but is {detected_type}")

                smuggled_files.append({
                    "claimed_mime": mime_type,
                    "detected_type": detected_type,
                    "size_bytes": file_size,
                    "sha256": file_hash,
                    "is_spoofed": spoofed
                })
            except Exception as e:
                logger.debug(f"Failed to decode base64 chunk: {e}")

        # 3. Hidden IFrames
        try:
            soup = BeautifulSoup(html_body, "lxml")
            iframes = soup.find_all("iframe")
            for iframe in iframes:
                style = iframe.get("style", "").lower()
                if "display:none" in style or "display: none" in style or "visibility:hidden" in style or "width:0" in style:
                    indicators.append("Hidden IFrame detected (potential exploit kit / smuggling)")
        except Exception:
            pass

        return {
            "indicators": list(set(indicators)),
            "smuggled_files": smuggled_files
        }

# Singleton
html_smuggling_inspector = HTMLSmugglingInspector()
