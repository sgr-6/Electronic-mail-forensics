"""
NLP-based Threat Classification Engine.

Uses TF-IDF + Gradient Boosting (scikit-learn) trained and serialized
for lightweight, instant CPU inference. 
"""

from __future__ import annotations

import logging
import os
import pickle
import re
from typing import Any

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import GradientBoostingClassifier
import numpy as np

logger = logging.getLogger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
TFIDF_PATH = os.path.join(MODEL_DIR, "tfidf.pkl")
GBC_PATH = os.path.join(MODEL_DIR, "gbc_model.pkl")

# Heuristic patterns used as extra features for the ML model
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
    def __init__(self) -> None:
        self.classes = ['Legitimate', 'Phishing', 'BEC/CEO Fraud', 'Credential Harvesting']
        self._load_or_train_model()

    def _load_or_train_model(self) -> None:
        if not os.path.exists(MODEL_DIR):
            os.makedirs(MODEL_DIR)

        if os.path.exists(TFIDF_PATH) and os.path.exists(GBC_PATH):
            logger.info("Loading serialized TF-IDF and Gradient Boosting models...")
            with open(TFIDF_PATH, "rb") as f:
                self.vectorizer = pickle.load(f)
            with open(GBC_PATH, "rb") as f:
                self.model = pickle.load(f)
        else:
            logger.info("Training and serializing new TF-IDF and Gradient Boosting models...")
            self._train_dummy_model()

    def _train_dummy_model(self) -> None:
        """Trains a small model on synthetic data so we have a serialized artifact."""
        corpus = [
            "We are having a board meeting tomorrow. Please review the attached agenda.", # Legitimate
            "Weekly newsletter and updates from the HR department.", # Legitimate
            "URGENT: Your account has been suspended. Please login to verify your credentials immediately.", # Credential Harvesting
            "Please click here to update your password and verify identity.", # Credential Harvesting
            "Are you at your desk? I need you to process a confidential wire transfer to our new vendor.", # BEC/CEO Fraud
            "I am the CEO. Please do not discuss this confidential acquisition. Transfer funds now.", # BEC/CEO Fraud
            "You have won a lottery! Click here to claim your prize.", # Phishing
            "Last chance to get 50% off on these items. Act now!" # Phishing
        ]
        y = [
            'Legitimate', 'Legitimate', 
            'Credential Harvesting', 'Credential Harvesting', 
            'BEC/CEO Fraud', 'BEC/CEO Fraud', 
            'Phishing', 'Phishing'
        ]

        self.vectorizer = TfidfVectorizer(stop_words='english', max_features=100)
        X_tfidf = self.vectorizer.fit_transform(corpus).toarray()
        
        # Add heuristic features (4 dimensions)
        X_features = np.array([self._extract_heuristic_features(text) for text in corpus])
        X_combined = np.hstack((X_tfidf, X_features))

        self.model = GradientBoostingClassifier(n_estimators=50, random_state=42)
        self.model.fit(X_combined, y)

        with open(TFIDF_PATH, "wb") as f:
            pickle.dump(self.vectorizer, f)
        with open(GBC_PATH, "wb") as f:
            pickle.dump(self.model, f)
            
        logger.info("Models serialized successfully.")

    def _extract_heuristic_features(self, text: str) -> list[float]:
        text = text.lower()
        def score(patterns):
            matches = sum(1 for p in patterns if re.search(p, text))
            return min(1.0, matches / 2.0)
            
        return [
            score(_URGENCY_PATTERNS),
            score(_FINANCIAL_PATTERNS),
            score(_CREDENTIAL_PATTERNS),
            score(_SOCIAL_ENGINEERING_PATTERNS)
        ]

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
        
        subject = subject or ""
        body_plain = body_plain or ""
        body_html = body_html or ""
        from_address = (from_address or "").lower()
        from_display = (from_display or "").lower()
        headers = headers or {}

        full_text = f"{subject}\n{body_plain}\n{body_html}"
        
        # 1. Feature Extraction
        X_tfidf = self.vectorizer.transform([full_text]).toarray()
        X_heuristics = np.array([self._extract_heuristic_features(full_text)])
        
        impersonation_score = 0.0
        reply_to = headers.get("Reply-To", "")
        if isinstance(reply_to, list):
            reply_to = reply_to[0]
        if reply_to:
            import email.utils
            _, reply_to_addr = email.utils.parseaddr(str(reply_to))
            if reply_to_addr and from_address:
                if from_address.split("@")[-1] != reply_to_addr.split("@")[-1]:
                    impersonation_score = 1.0
        
        if any(t in from_display for t in ["ceo", "cfo", "director"]):
            impersonation_score = max(impersonation_score, 0.5)

        X_heuristics[0][3] = max(X_heuristics[0][3], impersonation_score) # Fold into social engineering for model
        
        X_combined = np.hstack((X_tfidf, X_heuristics))

        # 2. ML Inference
        proba = self.model.predict_proba(X_combined)[0]
        class_idx = np.argmax(proba)
        classification = self.model.classes_[class_idx]
        confidence = float(proba[class_idx])

        # Overrides for extremely obvious indicators
        if impersonation_score == 1.0 and classification == "Legitimate":
            classification = "Phishing"
            confidence = 0.85

        # 3. Indicators for Explainability
        indicators = []
        h_scores = X_heuristics[0]
        if h_scores[0] > 0: indicators.append("Urgency indicators detected")
        if h_scores[1] > 0: indicators.append("Financial request indicators detected")
        if h_scores[2] > 0: indicators.append("Credential harvesting indicators detected")
        if h_scores[3] > 0: indicators.append("Social engineering / Impersonation detected")
        
        return {
            "classification": classification,
            "confidence": round(confidence, 4),
            "indicators": indicators,
            "details": {
                "urgency_score": round(h_scores[0], 4),
                "financial_score": round(h_scores[1], 4),
                "credential_score": round(h_scores[2], 4),
                "impersonation_score": round(impersonation_score, 4),
                "social_engineering_score": round(h_scores[3], 4),
            }
        }

nlp_engine = NLPThreatEngine()
