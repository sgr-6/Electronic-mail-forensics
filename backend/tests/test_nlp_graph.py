"""
Unit tests for NLP, Homoglyph, URL Analyzer, Graph Engine, and Risk Scorer.
"""

import pytest

from app.services.nlp_engine import nlp_engine
from app.services.homoglyph_detector import homoglyph_detector
from app.services.url_analyzer import url_analyzer
from app.services.risk_scorer import risk_scorer
from app.services.graph_engine import graph_engine

# ========================================================================= #
# Test: NLP Engine                                                          #
# ========================================================================= #

def test_nlp_bec_fraud():
    result = nlp_engine.analyze(
        subject="URGENT: Confidential Acquisition Wire Transfer",
        body_plain="Please initiate a wire transfer immediately. Do not discuss.",
        body_html="",
        from_address="ceo@evil-domain.com",
        from_display="CEO",
        to_address="cfo@company.com",
        headers={}
    )
    assert result["classification"] == "BEC/CEO Fraud"
    assert result["confidence"] > 0.5
    assert result["details"]["urgency_score"] > 0
    assert result["details"]["financial_score"] > 0
    assert result["details"]["social_engineering_score"] > 0
    assert result["details"]["impersonation_score"] > 0

def test_nlp_phishing_credential_harvesting():
    result = nlp_engine.analyze(
        subject="Action Required: Verify your account",
        body_plain="Click here to login and update credentials.",
        body_html="",
        from_address="support@verify-portal.com",
        from_display="Support",
        to_address="user@company.com",
        headers={}
    )
    assert result["classification"] in ("Credential Harvesting", "Phishing")
    assert result["confidence"] > 0.4
    assert result["details"]["credential_score"] > 0

def test_nlp_legitimate():
    result = nlp_engine.analyze(
        subject="Project update meeting",
        body_plain="Let's meet at 10 AM tomorrow to discuss the new feature.",
        body_html="",
        from_address="colleague@company.com",
        from_display="Colleague",
        to_address="me@company.com",
        headers={}
    )
    assert result["classification"] == "Legitimate"
    assert result["confidence"] > 0.7


# ========================================================================= #
# Test: Homoglyph Detector                                                  #
# ========================================================================= #

def test_homoglyph_clean():
    res = homoglyph_detector.check_domain("safe-domain.com")
    assert not res["is_suspicious"]
    assert len(res["homoglyphs_found"]) == 0

def test_homoglyph_confusables():
    # Cyrillic 'a' (а) inside apple.com
    res = homoglyph_detector.check_domain("аpple.com")
    assert res["is_suspicious"]
    assert len(res["homoglyphs_found"]) > 0

def test_homoglyph_typosquatting():
    res = homoglyph_detector.check_domain("micros0ft.com")
    assert res["is_suspicious"]
    assert res["closest_match"] == "microsoft.com"
    assert res["similarity_score"] > 0.75


# ========================================================================= #
# Test: URL Analyzer                                                        #
# ========================================================================= #

def test_url_analyzer_clean():
    urls = [{"url": "https://google.com/search", "defanged": "google[.]com", "anchor_text": "Search"}]
    res = url_analyzer.analyze_urls(urls)
    assert not res[0].get("is_suspicious")

def test_url_analyzer_ip_hostname():
    urls = [{"url": "http://192.168.1.100/login", "defanged": "192[.]168[.]1[.]100", "anchor_text": "Login"}]
    res = url_analyzer.analyze_urls(urls)
    assert res[0]["is_suspicious"]
    assert "IP-based hostname" in res[0]["suspicion_reason"]

def test_url_analyzer_shortener():
    urls = [{"url": "https://bit.ly/12345", "defanged": "bit[.]ly", "anchor_text": "Click"}]
    res = url_analyzer.analyze_urls(urls)
    assert res[0]["is_suspicious"]
    assert "URL shortener" in res[0]["suspicion_reason"]

def test_url_analyzer_anchor_mismatch():
    urls = [{"url": "https://evil.com/login", "defanged": "evil[.]com", "anchor_text": "microsoft.com"}]
    res = url_analyzer.analyze_urls(urls)
    assert res[0]["is_suspicious"]
    assert "does not match" in res[0]["suspicion_reason"]


# ========================================================================= #
# Test: Risk Scorer                                                         #
# ========================================================================= #

def test_risk_scorer_clean():
    auth = {"spf": {"result": "pass"}, "dkim": {"result": "pass"}, "dmarc": {"result": "pass"}}
    nlp = {"classification": "Legitimate", "confidence": 0.9}
    rep = {"8.8.8.8": {"abuse_confidence_score": 0, "is_tor_exit": False}}
    dom = {"is_suspicious": False}
    urls = [{"is_suspicious": False}]

    res = risk_scorer.score(auth, nlp, rep, dom, urls)
    assert res["category"] == "Clean"
    assert res["composite_score"] < 25.0

def test_risk_scorer_phishing():
    auth = {"spf": {"result": "fail"}, "dkim": {"result": "fail"}, "dmarc": {"result": "fail"}}
    nlp = {"classification": "Credential Harvesting", "confidence": 0.8}
    rep = {"185.234.72.19": {"abuse_confidence_score": 85, "is_tor_exit": False}}
    dom = {"is_suspicious": True, "similarity_score": 0.9}
    urls = [{"is_suspicious": True}, {"is_suspicious": True}]

    res = risk_scorer.score(auth, nlp, rep, dom, urls)
    assert res["category"] in ("Phishing / BEC Attack", "Malicious Infrastructure")
    assert res["composite_score"] > 75.0


# ========================================================================= #
# Test: Graph Engine                                                        #
# ========================================================================= #

def test_graph_engine():
    graph_engine.add_email_case({
        "case_id": 1,
        "subject": "Test Email",
        "from_address": "test@evil.com",
        "from_domain": "evil.com",
        "sender_ip": "1.2.3.4",
        "asn": "AS1234",
        "risk_category": "Suspicious"
    })
    
    graph = graph_engine.get_case_graph(1)
    
    # Check if nodes exist
    nodes = {n["id"]: n for n in graph["nodes"]}
    assert 1 in nodes
    assert "test@evil.com" in nodes
    assert "evil.com" in nodes
    assert "1.2.3.4" in nodes
    assert "AS1234" in nodes
    
    # Check edges
    edges = {(e["source"], e["target"]): e["label"] for e in graph["edges"]}
    assert ("test@evil.com", 1) in edges
    assert edges[("test@evil.com", 1)] == "SENT"
    assert (1, "1.2.3.4") in edges
    assert edges[(1, "1.2.3.4")] == "ORIGINATED_FROM"
    assert ("1.2.3.4", "AS1234") in edges
    assert edges[("1.2.3.4", "AS1234")] == "RESOLVES_TO"
    assert ("test@evil.com", "evil.com") in edges
    assert edges[("test@evil.com", "evil.com")] == "USES_DOMAIN"
