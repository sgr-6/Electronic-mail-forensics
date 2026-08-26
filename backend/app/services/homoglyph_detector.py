"""
Unicode Homoglyph and Typosquatting Detection Engine.

Detects confusable characters and computes Levenshtein distance
against protected organizational domains.
"""

from __future__ import annotations

import logging
from typing import Any

from rapidfuzz.distance import Levenshtein

logger = logging.getLogger(__name__)

# Common Unicode confusable mapping (Latin -> Cyrillic/Greek/etc.)
_CONFUSABLES = {
    'a': ['а', 'ɑ', 'ä', 'á', 'à', 'â', 'ã', 'å', 'æ', 'α'],
    'b': ['Ь', 'ß', 'β'],
    'c': ['с', 'ç', 'ć', 'ĉ', 'ċ', 'č', '¢', '©'],
    'd': ['ԁ', 'ď', 'đ', 'ð'],
    'e': ['е', 'ё', 'é', 'è', 'ê', 'ë', 'ę', 'ě', 'є', 'ε'],
    'g': ['ɡ', 'ġ', 'ğ', 'ģ', 'ĝ'],
    'h': ['һ', 'հ', 'ĥ', 'ħ'],
    'i': ['і', 'í', 'ì', 'î', 'ï', 'ĩ', 'ī', 'ĭ', 'į', 'ı', '1', 'l', '!', '|'],
    'j': ['ј', 'ĵ'],
    'k': ['κ', 'ķ', 'ĸ'],
    'l': ['ӏ', '1', 'i', '!', '|', 'ĺ', 'ļ', 'ľ', 'ŀ', 'ł'],
    'm': ['м', 'm'],
    'n': ['п', 'ñ', 'ń', 'ņ', 'ň', 'ŉ', 'ŋ'],
    'o': ['о', '0', 'ó', 'ò', 'ô', 'õ', 'ö', 'ø', 'ō', 'ŏ', 'ő', 'ο'],
    'p': ['р', 'ρ'],
    'q': ['q'],
    'r': ['г', 'ŕ', 'ŗ', 'ř'],
    's': ['ѕ', 'ś', 'ŝ', 'ş', 'š', '5', '$'],
    't': ['т', 'ţ', 'ť', 'ŧ'],
    'u': ['и', 'u', 'ú', 'ù', 'û', 'ü', 'ũ', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'μ'],
    'v': ['ѵ', 'ν'],
    'w': ['ѡ', 'ŵ'],
    'x': ['х', 'x'],
    'y': ['у', 'ý', 'ÿ', 'ŷ', 'γ'],
    'z': ['z', 'ź', 'ż', 'ž'],
}

# Reverse mapping: Confusable -> Base ASCII
_CONFUSABLES_REVERSE: dict[str, str] = {}
for base_char, confusables in _CONFUSABLES.items():
    for confusable in confusables:
        _CONFUSABLES_REVERSE[confusable] = base_char


class HomoglyphDetector:
    """Detect homoglyphs and typosquatting in domains."""

    def __init__(self, protected_domains: list[str] | None = None) -> None:
        self.protected_domains = protected_domains or [
            "aicte-india.org",
            "microsoft.com",
            "google.com",
            "apple.com",
            "paypal.com",
            "amazon.com",
        ]

    def _normalize(self, domain: str) -> tuple[str, list[str]]:
        """
        Normalize domain by replacing confusable characters with their ASCII base.
        Returns the normalized domain and a list of found homoglyphs.
        """
        normalized_chars = []
        found_homoglyphs = []

        for char in domain.lower():
            if char in _CONFUSABLES_REVERSE and char not in _CONFUSABLES:
                # E.g. char is 'а' (Cyrillic a)
                base = _CONFUSABLES_REVERSE[char]
                normalized_chars.append(base)
                found_homoglyphs.append(f"{char}->{base}")
            else:
                normalized_chars.append(char)

        return "".join(normalized_chars), found_homoglyphs

    def check_domain(self, domain: str) -> dict[str, Any]:
        """
        Check domain against protected domains using Levenshtein distance
        and homoglyph normalization.
        """
        if not domain:
            return {
                "is_suspicious": False,
                "similarity_score": 0.0,
                "closest_match": None,
                "homoglyphs_found": [],
                "details": "Empty domain",
            }

        domain = domain.lower()
        normalized_domain, homoglyphs = self._normalize(domain)

        best_score = 0.0
        closest_match = None

        for protected in self.protected_domains:
            # Exact match is not typosquatting
            if domain == protected:
                continue

            # Calculate normalized similarity using RapidFuzz Levenshtein
            # Returns a value between 0 and 100
            sim = Levenshtein.normalized_similarity(normalized_domain, protected)
            
            if sim > best_score:
                best_score = sim
                closest_match = protected

        # Similarity threshold > 0.75 is suspicious
        is_suspicious = bool(homoglyphs) or (best_score > 0.75)
        
        details = []
        if homoglyphs:
            details.append(f"Found confusable characters: {', '.join(homoglyphs)}")
        if best_score > 0.75:
            details.append(f"Highly similar ({best_score:.2f}) to protected domain: {closest_match}")

        return {
            "is_suspicious": is_suspicious,
            "similarity_score": round(best_score, 4),
            "closest_match": closest_match,
            "homoglyphs_found": homoglyphs,
            "details": "; ".join(details) if details else "Clean",
        }


# Singleton instance
homoglyph_detector = HomoglyphDetector()
