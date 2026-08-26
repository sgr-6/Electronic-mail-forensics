"""
Module 6: I4C National Cyber Crime Portal Docket Exporter

Generates a structured JSON incident package matching the Indian 
Cyber Crime Coordination Centre (I4C) reporting structure.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

class I4CDocketExporter:
    def __init__(self):
        self.portal_schema_version = "v1.2.0-BSA"

    def export_json(self, case: Any, hops: list[Any], crypto_wallets: list[dict], smuggled_files: list[dict]) -> str:
        """
        Generate I4C compliant JSON structure for National Cyber Crime Portal injection.
        """
        docket = {
            "metadata": {
                "schema_version": self.portal_schema_version,
                "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "exporting_agency": "AI-SOC-Platform"
            },
            "incident": {
                "case_id": case.id,
                "category": self._map_category(case.risk_category),
                "severity_score": case.risk_score,
                "date_of_receipt": case.date_header or "Unknown"
            },
            "chain_of_custody": {
                "original_sha256": case.raw_hash_sha256,
                "original_md5": case.raw_hash_md5
            },
            "suspect_relay_trace": [],
            "financial_indicators": crypto_wallets,
            "smuggled_payloads": smuggled_files,
            "domain_inconsistencies": {
                "from_address": case.from_address,
                "reply_to": case.headers_json # Simplified for mockup
            }
        }

        # Format Hops
        for hop in hops:
            docket["suspect_relay_trace"].append({
                "sequence": hop.sequence,
                "ip_address": hop.ip_address,
                "country": hop.country,
                "isp": hop.isp,
                "is_public_origin": hop.is_public_origin
            })

        return json.dumps(docket, indent=2)

    def _map_category(self, risk_category: str) -> str:
        """Map internal categories to I4C taxonomy."""
        mapping = {
            "Phishing": "1001_PHISHING_VISHING",
            "BEC/CEO Fraud": "1002_BUSINESS_EMAIL_COMPROMISE",
            "Credential Harvesting": "1003_CREDENTIAL_THEFT",
            "Malicious Infrastructure": "1005_MALWARE_DELIVERY",
            "Suspicious": "1099_OTHER_CYBER_CRIME",
            "Clean": "0000_FALSE_POSITIVE"
        }
        return mapping.get(risk_category, "1099_OTHER_CYBER_CRIME")

# Singleton
i4c_docket_exporter = I4CDocketExporter()
