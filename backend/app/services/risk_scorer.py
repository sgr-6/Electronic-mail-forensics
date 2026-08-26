"""
Composite Risk Scoring Engine.

Calculates an explainable risk score (0-100) from weighted multi-factor analysis:
    - Authentication failures (SPF/DKIM/DMARC):  30%
    - NLP / BEC social engineering score:          30%
    - Originating IP reputation & proxy/Tor flags: 25%
    - Domain age, homoglyphs & inconsistencies:    15%

Outputs a risk category: "Clean", "Suspicious", "Phishing / BEC Attack",
"Malicious Infrastructure" — with per-factor breakdown for explainability.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Weight configuration
WEIGHT_AUTH = 0.30
WEIGHT_NLP = 0.30
WEIGHT_REPUTATION = 0.25
WEIGHT_DOMAIN = 0.15

# Risk category thresholds
THRESHOLD_CLEAN = 25.0
THRESHOLD_SUSPICIOUS = 50.0
THRESHOLD_PHISHING = 75.0


class RiskScorer:
    """
    Calculate composite risk scores with explainable breakdowns.

    Each factor is scored independently (0-100), then combined via
    weighted average to produce the final composite score.
    """

    def score(
        self,
        auth_results: dict[str, Any] | None = None,
        nlp_results: dict[str, Any] | None = None,
        reputation_data: dict[str, dict[str, Any]] | None = None,
        domain_analysis: dict[str, Any] | None = None,
        url_analysis: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Calculate the composite risk score.

        Args:
            auth_results: SPF/DKIM/DMARC validation results from auth_engine.
            nlp_results: NLP threat classification from nlp_engine.
            reputation_data: IP reputation data keyed by IP address.
            domain_analysis: Homoglyph/typosquatting analysis results.
            url_analysis: List of analyzed URLs with suspicion flags.

        Returns:
            Dict with: composite_score, category, threat_type,
                       and per-factor breakdown scores.
        """
        # Score each factor independently (0-100 scale)
        auth_score = self._score_authentication(auth_results or {})
        nlp_score = self._score_nlp(nlp_results or {})
        rep_score = self._score_reputation(reputation_data or {})
        domain_score = self._score_domain(domain_analysis or {}, url_analysis or [])

        # Weighted composite
        composite = (
            auth_score * WEIGHT_AUTH
            + nlp_score * WEIGHT_NLP
            + rep_score * WEIGHT_REPUTATION
            + domain_score * WEIGHT_DOMAIN
        )

        # Clamp to 0-100
        composite = max(0.0, min(100.0, round(composite, 2)))

        # Determine category
        category = self._categorize(composite)

        # Determine primary threat type
        threat_type = self._determine_threat_type(
            auth_score, nlp_score, rep_score, domain_score,
            nlp_results or {},
        )

        result = {
            "composite_score": composite,
            "category": category,
            "threat_type": threat_type,
            "breakdown": {
                "authentication_score": round(auth_score, 2),
                "authentication_weight": WEIGHT_AUTH,
                "nlp_score": round(nlp_score, 2),
                "nlp_weight": WEIGHT_NLP,
                "ip_reputation_score": round(rep_score, 2),
                "ip_reputation_weight": WEIGHT_REPUTATION,
                "domain_score": round(domain_score, 2),
                "domain_weight": WEIGHT_DOMAIN,
            },
        }

        logger.debug(
            "Risk score: %.1f%% (%s) — auth=%.0f, nlp=%.0f, rep=%.0f, domain=%.0f",
            composite, category, auth_score, nlp_score, rep_score, domain_score,
        )

        return result

    # ----------------------------------------------------------------- #
    # Factor scoring methods                                             #
    # ----------------------------------------------------------------- #

    def _score_authentication(self, auth: dict[str, Any]) -> float:
        """
        Score authentication results (0-100, higher = more suspicious).

        Scoring:
        - SPF fail/softfail: +35, none: +15
        - DKIM fail: +35, none: +15
        - DMARC fail: +30, none: +15
        """
        score = 0.0

        spf = auth.get("spf", {})
        spf_result = spf.get("result", "none") if isinstance(spf, dict) else "none"
        if spf_result == "fail":
            score += 35
        elif spf_result == "softfail":
            score += 25
        elif spf_result == "none":
            score += 15
        elif spf_result in ("temperror", "permerror"):
            score += 20

        dkim = auth.get("dkim", {})
        dkim_result = dkim.get("result", "none") if isinstance(dkim, dict) else "none"
        if dkim_result == "fail":
            score += 35
        elif dkim_result == "none":
            score += 15

        dmarc = auth.get("dmarc", {})
        dmarc_result = dmarc.get("result", "none") if isinstance(dmarc, dict) else "none"
        if dmarc_result == "fail":
            score += 30
        elif dmarc_result == "none":
            score += 15

        return min(100.0, score)

    def _score_nlp(self, nlp: dict[str, Any]) -> float:
        """
        Score NLP threat classification (0-100, higher = more suspicious).

        Uses classification and confidence to determine score.
        """
        classification = nlp.get("classification", "Legitimate")
        confidence = nlp.get("confidence", 0.0)

        classification_weights = {
            "Legitimate": 0.0,
            "Phishing": 85.0,
            "BEC/CEO Fraud": 95.0,
            "Credential Harvesting": 80.0,
        }

        base_score = classification_weights.get(classification, 50.0)

        # Scale by confidence
        score = base_score * confidence

        # Boost from specific indicators
        details = nlp.get("details", {})
        if isinstance(details, dict):
            urgency = details.get("urgency_score", 0.0)
            financial = details.get("financial_score", 0.0)

            # Strong urgency + financial indicators boost score
            if urgency > 0.6 and financial > 0.6:
                score = max(score, 80.0)

        return min(100.0, score)

    def _score_reputation(self, reputation: dict[str, dict[str, Any]]) -> float:
        """
        Score IP reputation (0-100, higher = more suspicious).

        Uses the worst-scoring IP from the reputation data.
        """
        if not reputation:
            return 20.0  # Unknown = mild concern

        max_score = 0.0
        for ip, data in reputation.items():
            abuse_score = data.get("abuse_confidence_score", 0)
            ip_score = float(abuse_score)

            # Boost for special flags
            if data.get("is_tor_exit"):
                ip_score = max(ip_score, 70.0)
            if data.get("is_proxy"):
                ip_score = max(ip_score, 50.0)
            if data.get("is_hosting") and abuse_score > 10:
                ip_score += 10

            max_score = max(max_score, ip_score)

        return min(100.0, max_score)

    def _score_domain(
        self,
        domain: dict[str, Any],
        urls: list[dict[str, Any]],
    ) -> float:
        """
        Score domain and URL analysis (0-100, higher = more suspicious).

        Considers homoglyph detection, URL suspiciousness, and header inconsistencies.
        """
        score = 0.0

        # Homoglyph detection
        if domain.get("is_suspicious"):
            similarity = domain.get("similarity_score", 0.0)
            score += 40 + (similarity * 40)  # 40-80 based on similarity
            if domain.get("homoglyphs_found"):
                score += 20

        # Suspicious URLs
        if urls:
            suspicious_count = sum(1 for u in urls if u.get("is_suspicious"))
            if suspicious_count > 0:
                score += min(40.0, suspicious_count * 15.0)

        return min(100.0, score)

    # ----------------------------------------------------------------- #
    # Classification methods                                             #
    # ----------------------------------------------------------------- #

    def _categorize(self, score: float) -> str:
        """Map composite score to risk category."""
        if score <= THRESHOLD_CLEAN:
            return "Clean"
        elif score <= THRESHOLD_SUSPICIOUS:
            return "Suspicious"
        elif score <= THRESHOLD_PHISHING:
            return "Phishing / BEC Attack"
        else:
            return "Malicious Infrastructure"

    def _determine_threat_type(
        self,
        auth_score: float,
        nlp_score: float,
        rep_score: float,
        domain_score: float,
        nlp: dict[str, Any],
    ) -> str | None:
        """Determine the primary threat type based on dominant signals."""
        composite = (
            auth_score * WEIGHT_AUTH
            + nlp_score * WEIGHT_NLP
            + rep_score * WEIGHT_REPUTATION
            + domain_score * WEIGHT_DOMAIN
        )

        if composite <= THRESHOLD_CLEAN:
            return None

        # Use NLP classification as primary when it has high confidence
        nlp_class = nlp.get("classification", "Legitimate")
        nlp_conf = nlp.get("confidence", 0.0)

        if nlp_conf > 0.6 and nlp_class != "Legitimate":
            return nlp_class

        # Fall back to dominant signal
        scores = {
            "Authentication Spoofing": auth_score,
            "Social Engineering": nlp_score,
            "Malicious Infrastructure": rep_score,
            "Domain Impersonation": domain_score,
        }

        return max(scores, key=scores.get)


# Singleton instance
risk_scorer = RiskScorer()
