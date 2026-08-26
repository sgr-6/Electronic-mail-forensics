"""
NLP-based Threat Classification Engine.

Classifies emails using TF-IDF style keyword/pattern heuristics into:
'Legitimate', 'Phishing', 'BEC/CEO Fraud', 'Credential Harvesting'.
No external pickle models required.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Heuristic keyword patterns (case-insensitive)
_URGENCY_PATTERNS = [
    r"\burgent(ly)?\b", r"\bimmediately\b", r"\bwithin \d+ hours\b", 
    r"\bsuspended\b", r"\bpermanently\b", r"\bact now\b", 
    r"\btime-sensitive\b", r"\bimportant\b", r"\bcritical\b"
]

_FINANCIAL_PATTERNS = [
    r"\bwire transfer\b", r"\bbank account\b", r"\bswift\b", 
    r"\bpayment\b", r"\$\d+[,\.]?\d+", r"\bconfidential acquisition\b",
    r"\binvoice\b", r"\btransfer funds\b"
]

_CREDENTIAL_PATTERNS = [
    r"\bverify your account\b", r"\bupdate credentials\b", r"\blogin\b", 
    r"\bpassword\b", r"\busername\b", r"\baadhaar\b", r"\botp\b",
    r"\bverify identity\b", r"\bsecure portal\b"
]

_SOCIAL_ENGINEERING_PATTERNS = [
    r"\bdo not discuss\b", r"\bconfidential\b", r"\bnda\b", 
    r"\bboard meeting\b", r"\bceo\b", r"\bcfo\b", r"\bdirector\b",
    r"\blast chance\b", r"\blimited time\b"
]


class NLPThreatEngine:
    """Analyze email content for threats using pattern heuristics."""

    def analyze(
        self,
        subject: str | None,
        body_plain: str | None,
        body_html: str | None,
        from_address: str | None,
        from_display: str | None,
        to_address: str | None,
        headers: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """
        Classify email into one of 4 categories and return confidence + indicators.
        """
        subject = subject or ""
        body_plain = body_plain or ""
        body_html = body_html or ""
        from_address = from_address or ""
        from_display = from_display or ""
        to_address = to_address or ""
        headers = headers or {}

        # Combine text for analysis
        full_text = f"{subject}\n{body_plain}\n{body_html}".lower()

        # 1. Scoring
        urgency_score, urgency_indicators = self._score_patterns(full_text, _URGENCY_PATTERNS)
        financial_score, financial_indicators = self._score_patterns(full_text, _FINANCIAL_PATTERNS)
        credential_score, credential_indicators = self._score_patterns(full_text, _CREDENTIAL_PATTERNS)
        soc_eng_score, soc_eng_indicators = self._score_patterns(full_text, _SOCIAL_ENGINEERING_PATTERNS)

        impersonation_score, impersonation_indicators = self._check_impersonation(
            from_address, from_display, headers
        )

        indicators = (
            urgency_indicators + financial_indicators + credential_indicators +
            soc_eng_indicators + impersonation_indicators
        )

        # 2. Classification Logic
        classification = "Legitimate"
        confidence = 0.0

        # Heuristic rules
        if financial_score > 0.4 and (impersonation_score > 0.5 or soc_eng_score > 0.4):
            classification = "BEC/CEO Fraud"
            confidence = min(1.0, (financial_score + impersonation_score + soc_eng_score) / 2.5)
            
        elif credential_score > 0.4 and (urgency_score > 0.3 or impersonation_score > 0.3):
            classification = "Credential Harvesting"
            confidence = min(1.0, (credential_score + urgency_score + impersonation_score) / 2.0)
            
        elif urgency_score > 0.5 or financial_score > 0.5 or credential_score > 0.5 or impersonation_score > 0.5:
            classification = "Phishing"
            confidence = min(1.0, max(urgency_score, financial_score, credential_score, impersonation_score))

        else:
            classification = "Legitimate"
            # Higher confidence in legitimacy if scores are very low
            confidence = 1.0 - min(1.0, max(urgency_score, financial_score, credential_score, soc_eng_score, impersonation_score))

        return {
            "classification": classification,
            "confidence": round(confidence, 4),
            "indicators": list(set(indicators)),  # Deduplicate
            "details": {
                "urgency_score": round(urgency_score, 4),
                "financial_score": round(financial_score, 4),
                "credential_score": round(credential_score, 4),
                "impersonation_score": round(impersonation_score, 4),
                "social_engineering_score": round(soc_eng_score, 4),
            }
        }

    def _score_patterns(self, text: str, patterns: list[str]) -> tuple[float, list[str]]:
        """
        Score a text based on presence of regex patterns.
        Returns score (0.0 to 1.0) and list of matched indicator names.
        """
        matches = 0
        indicators = []
        for pat in patterns:
            # Reconstruct readable indicator from regex (simplified)
            indicator_name = pat.replace(r"\b", "").replace(r"\d+", "X").replace("?", "")
            
            if re.search(pat, text):
                matches += 1
                indicators.append(f"Keyword match: '{indicator_name}'")

        # Normalize score (e.g. 3 matches = 0.75 score)
        score = min(1.0, matches / 4.0)
        return score, indicators

    def _check_impersonation(
        self, from_address: str, from_display: str, headers: dict[str, Any]
    ) -> tuple[float, list[str]]:
        """Check for display name spoofing and reply-to mismatches."""
        score = 0.0
        indicators = []

        from_address = from_address.lower()
        from_display = from_display.lower()

        # 1. Reply-To Mismatch
        reply_to = headers.get("Reply-To", "")
        if isinstance(reply_to, list):
            reply_to = reply_to[0]
        reply_to = str(reply_to).lower()

        if reply_to:
            import email.utils
            _, reply_to_addr = email.utils.parseaddr(reply_to)
            
            if reply_to_addr and from_address:
                try:
                    from_domain = from_address.split("@")[1]
                    reply_domain = reply_to_addr.split("@")[1]
                    if from_domain != reply_domain:
                        score += 0.8
                        indicators.append(f"Reply-To domain ({reply_domain}) mismatches From domain ({from_domain})")
                except IndexError:
                    pass

        # 2. Executive titles in display name (often used in BEC)
        if any(title in from_display for title in ["ceo", "cfo", "director", "president", "chief"]):
            score += 0.4
            indicators.append("Executive title found in display name")

        # 3. Domain in display name (e.g. "Microsoft Support <hacker@evil.com>")
        if "microsoft" in from_display and "microsoft.com" not in from_address:
            score += 0.5
            indicators.append("Display name impersonates Microsoft")

        return min(1.0, score), indicators


# Singleton instance
nlp_engine = NLPThreatEngine()
