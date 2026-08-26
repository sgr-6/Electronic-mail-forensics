"""
Pydantic v2 schemas for API request/response serialization.

These schemas are the single source of truth for the frontend/backend contract.
Every field here maps exactly to the ORM models and the frontend TypeScript types.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# =============================================================================
# Sub-schemas (embedded in case responses)
# =============================================================================

class HopSchema(BaseModel):
    """Single SMTP relay hop with optional geolocation."""
    sequence: int
    from_host: str | None = None
    by_host: str | None = None
    ip_address: str | None = None
    timestamp: str | None = None
    raw_header: str
    is_private: bool = False
    is_originating: bool = False
    latitude: float | None = None
    longitude: float | None = None
    city: str | None = None
    country: str | None = None
    country_iso: str | None = None
    isp: str | None = None
    asn: str | None = None

    model_config = {"from_attributes": True}


class AttachmentSchema(BaseModel):
    """Email attachment metadata with integrity hash."""
    filename: str
    content_type: str | None = None
    size: int
    sha256: str

    model_config = {"from_attributes": True}


class URLSchema(BaseModel):
    """Extracted URL from email body."""
    url: str
    defanged: str | None = None
    anchor_text: str | None = None
    is_suspicious: bool = False
    suspicion_reason: str | None = None

    model_config = {"from_attributes": True}


class AuthResultSchema(BaseModel):
    """Email authentication (SPF/DKIM/DMARC) results."""
    spf: dict[str, Any] = Field(default_factory=dict)
    dkim: dict[str, Any] = Field(default_factory=dict)
    dmarc: dict[str, Any] = Field(default_factory=dict)


class NLPResultSchema(BaseModel):
    """AI/NLP threat classification results."""
    classification: str | None = None
    confidence: float | None = None
    indicators: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class RiskBreakdownSchema(BaseModel):
    """Detailed risk score breakdown by factor."""
    authentication_score: float = 0.0
    nlp_score: float = 0.0
    ip_reputation_score: float = 0.0
    domain_score: float = 0.0
    composite_score: float = 0.0
    category: str = "Clean"
    threat_type: str | None = None


# =============================================================================
# Case response schemas
# =============================================================================

class CaseSummary(BaseModel):
    """Lightweight case summary for list views."""
    id: str
    filename: str
    submitted_at: datetime
    subject: str | None = None
    from_address: str | None = None
    to_address: str | None = None
    risk_score: float | None = None
    risk_category: str | None = None
    threat_type: str | None = None
    spf_result: str | None = None
    dkim_result: str | None = None
    dmarc_result: str | None = None

    model_config = {"from_attributes": True}


class CaseDetail(BaseModel):
    """Full case detail including all analysis results."""
    id: str
    filename: str
    submitted_at: datetime

    # Evidence integrity
    raw_hash_md5: str
    raw_hash_sha1: str
    raw_hash_sha256: str
    raw_size: int

    # Parsed headers
    subject: str | None = None
    from_address: str | None = None
    from_display: str | None = None
    to_address: str | None = None
    date_header: str | None = None
    message_id: str | None = None
    return_path: str | None = None

    # Body
    body_plain: str | None = None
    body_html: str | None = None

    # All headers as dict
    headers: dict[str, Any] = Field(default_factory=dict)

    # Nested analysis data
    hops: list[HopSchema] = Field(default_factory=list)
    attachments: list[AttachmentSchema] = Field(default_factory=list)
    urls: list[URLSchema] = Field(default_factory=list)

    # Authentication
    spf_result: str | None = None
    dkim_result: str | None = None
    dmarc_result: str | None = None
    auth_details: AuthResultSchema | None = None

    # NLP / AI
    nlp_classification: str | None = None
    nlp_confidence: float | None = None
    nlp_details: NLPResultSchema | None = None

    # Risk score
    risk_score: float | None = None
    risk_category: str | None = None
    threat_type: str | None = None
    risk_breakdown: RiskBreakdownSchema | None = None

    model_config = {"from_attributes": True}


# =============================================================================
# API response wrappers
# =============================================================================

class AnalysisResponse(BaseModel):
    """Response returned after submitting an email for analysis."""
    case_id: str
    status: str = "completed"
    message: str = "Analysis complete"
    risk_score: float | None = None
    risk_category: str | None = None


class StatsResponse(BaseModel):
    """Dashboard statistics."""
    total_cases: int = 0
    clean_count: int = 0
    suspicious_count: int = 0
    phishing_count: int = 0
    malicious_count: int = 0
    recent_cases: list[CaseSummary] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    """Standard error response."""
    detail: str
    error_code: str | None = None
