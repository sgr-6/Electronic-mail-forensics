"""
Module 4: Mailer, TLS & Infrastructure Fingerprinting

Parses User-Agent, X-Mailer, and TLS cipher mentions from Received headers.
Injects Mailer Fingerprints and Cipher Suites as nodes into NetworkX graph.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from app.services.graph_engine import graph_engine

logger = logging.getLogger(__name__)

class InfraFingerprinter:
    def __init__(self):
        # Common Regex to extract TLS Info from Received headers
        self.tls_pattern = re.compile(r"TLS[v\.\d\s]+(with cipher|cipher) ([\w\-]+)")

    def analyze(self, case_id: str, headers: dict[str, Any], received_headers: list[str]) -> dict[str, Any]:
        """
        Analyze headers for infra fingerprints and update the graph.
        """
        fingerprints = {
            "x_mailer": None,
            "user_agent": None,
            "tls_ciphers": []
        }

        # 1. Direct Headers
        x_mailer = headers.get("X-Mailer")
        if isinstance(x_mailer, list): x_mailer = x_mailer[0]
        if x_mailer:
            fingerprints["x_mailer"] = str(x_mailer).strip()
            # Add to graph
            graph_engine.add_node(fingerprints["x_mailer"], label=fingerprints["x_mailer"], type="Mailer")
            graph_engine.add_edge(case_id, fingerprints["x_mailer"], label="USES_MAILER")

        user_agent = headers.get("User-Agent")
        if isinstance(user_agent, list): user_agent = user_agent[0]
        if user_agent:
            fingerprints["user_agent"] = str(user_agent).strip()
            # Add to graph
            graph_engine.add_node(fingerprints["user_agent"], label=fingerprints["user_agent"], type="UserAgent")
            graph_engine.add_edge(case_id, fingerprints["user_agent"], label="USES_USERAGENT")

        # 2. TLS Ciphers from Received Chain
        ciphers_found = set()
        for r_hdr in received_headers:
            matches = self.tls_pattern.findall(str(r_hdr))
            for match in matches:
                if len(match) > 1:
                    cipher = match[1].strip()
                    ciphers_found.add(cipher)

        fingerprints["tls_ciphers"] = list(ciphers_found)
        
        for cipher in ciphers_found:
            graph_engine.add_node(cipher, label=cipher, type="TLSCipher")
            graph_engine.add_edge(case_id, cipher, label="USES_CIPHER")

        return fingerprints

# Singleton
infra_fingerprinter = InfraFingerprinter()
