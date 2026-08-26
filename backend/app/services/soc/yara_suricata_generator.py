"""
Module 8: Automated YARA & Suricata Rule Synthesis Engine

Synthesizes valid YARA rules for email/attachment matching,
and Suricata network rules to block the originating IP.
"""
from __future__ import annotations

from typing import Any

class YaraSuricataGenerator:
    def __init__(self):
        pass

    def generate_yara(self, case: Any, attachments: list[Any]) -> str:
        """Generate YARA rules based on the email content and hashes."""
        
        rule_name = f"Suspicious_Email_{case.id.replace('-', '_')}"
        
        strings_section = []
        condition_section = ["all of them"]
        
        # Add basic string matches
        if case.from_address:
            strings_section.append(f'$sender = "{case.from_address}"')
            
        if case.subject:
            # Escape quotes
            safe_subj = str(case.subject).replace('"', '\\"')
            strings_section.append(f'$subj = "{safe_subj}" nocase')
            
        # If there are no strings, add a dummy to make it valid
        if not strings_section:
            strings_section.append('$dummy = "e"')
            condition_section = ["$dummy"]
            
        strings_block = "\n        ".join(strings_section)
        condition_block = " and ".join(condition_section)
        
        yara_rule = f"""rule {rule_name} {{
    meta:
        description = "Auto-generated rule for Case {case.id}"
        category = "{case.risk_category}"
        date = "{case.date_header}"
    strings:
        {strings_block}
    condition:
        {condition_block}
}}
"""
        return yara_rule

    def generate_suricata(self, originating_ip: str, urls: list[Any]) -> str:
        """Generate Suricata rules for IP blocking and URL detection."""
        rules = []
        
        # IP Block Rule
        if originating_ip:
            rule = f'drop ip {originating_ip} any -> $HOME_NET any (msg:"BLOCKED MALICIOUS ORIGIN IP - {originating_ip}"; sid:1000001; rev:1;)'
            rules.append(rule)
            
        # Domain/URL Alert Rules
        sid = 1000002
        for u in urls:
            domain = u.defanged or "unknown"
            if domain != "unknown":
                rule = f'alert http $HOME_NET any -> any any (msg:"SUSPICIOUS DOMAIN ACCESS - {domain}"; content:"Host|3a| {domain}"; http_header; sid:{sid}; rev:1;)'
                rules.append(rule)
                sid += 1
                
        return "\n".join(rules)

# Singleton
yara_suricata_generator = YaraSuricataGenerator()
