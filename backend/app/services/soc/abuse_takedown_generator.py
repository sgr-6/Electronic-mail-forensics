"""
Module 7: Automated ISP & Registrar Abuse Takedown Dispatcher

Auto-drafts an RFC-compliant takedown notice for an offending IP/Domain.
"""
from __future__ import annotations

from typing import Any
from datetime import datetime

class AbuseTakedownGenerator:
    def __init__(self):
        # Mock abuse contacts for zero-config run
        self.mock_contacts = {
            "US": "abuse@mock-isp.us",
            "RU": "abuse@host.ru",
            "IN": "cert-in-report@gov.in",
            "DEFAULT": "abuse@registrar.com"
        }

    def generate_notice(self, case: Any, originating_ip: str, originating_country: str) -> dict[str, str]:
        """
        Generate a templated takedown notice.
        """
        contact = self.mock_contacts.get(originating_country, self.mock_contacts["DEFAULT"])
        
        subject = f"URGENT ABUSE REPORT: Malicious Activity Originating from {originating_ip}"
        
        body = f"""To Whom It May Concern,

This is an automated notification from our Security Operations Center.
We have detected malicious activity originating from an IP address under your network/AS allocation.

Offending IP Address: {originating_ip}
Incident Type: {case.risk_category}
First Detected: {datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}
Severity Score: {case.risk_score}/100

EVIDENCE CHAIN:
Original Sender Address: {case.from_address}
Email Subject: {case.subject}

We request that you investigate this activity and suspend the associated hosting/domain services immediately pursuant to your Terms of Service and applicable cyber laws.

Please contact us if you require full PCAP or Raw EML evidence.

Sincerely,
Automated Threat Response Team
"""
        return {
            "to": contact,
            "subject": subject,
            "body": body
        }

# Singleton
abuse_takedown_generator = AbuseTakedownGenerator()
