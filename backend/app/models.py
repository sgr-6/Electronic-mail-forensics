"""
SQLAlchemy ORM models for the Email Forensics Platform.

Models:
    - EmailCase: Core case record with parsed email metadata and analysis results
    - EmailHop: Individual SMTP relay hop with geolocation data
    - Attachment: Email attachment metadata with SHA-256 hash
    - ExtractedURL: URLs extracted from email body
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


def _generate_uuid() -> str:
    return str(uuid.uuid4())


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EmailCase(Base):
    """Core forensic case for an analyzed email."""

    __tablename__ = "email_cases"

    id = Column(String(36), primary_key=True, default=_generate_uuid)
    filename = Column(String(255), nullable=False)
    submitted_at = Column(DateTime, default=_utc_now, nullable=False)

    # --- Evidence integrity hashes ---
    raw_hash_md5 = Column(String(32), nullable=False)
    raw_hash_sha1 = Column(String(40), nullable=False)
    raw_hash_sha256 = Column(String(64), nullable=False)
    raw_size = Column(Integer, nullable=False)

    # --- Parsed header fields ---
    subject = Column(Text)
    from_address = Column(String(320))
    from_display = Column(String(255))
    to_address = Column(Text)
    date_header = Column(String(255))
    message_id = Column(String(255))
    return_path = Column(String(320))

    # --- Body content ---
    body_plain = Column(Text)
    body_html = Column(Text)

    # --- All headers stored as JSON ---
    headers_json = Column(Text)

    # --- Authentication results ---
    spf_result = Column(String(20))
    dkim_result = Column(String(20))
    dmarc_result = Column(String(20))
    auth_details_json = Column(Text)

    # --- NLP / AI results ---
    nlp_classification = Column(String(50))
    nlp_confidence = Column(Float)
    nlp_details_json = Column(Text)

    # --- Composite risk score ---
    risk_score = Column(Float)
    risk_category = Column(String(50))
    threat_type = Column(String(100))

    # --- Relationships ---
    hops = relationship("EmailHop", back_populates="case", cascade="all, delete-orphan", order_by="EmailHop.sequence")
    attachments = relationship("Attachment", back_populates="case", cascade="all, delete-orphan")
    urls = relationship("ExtractedURL", back_populates="case", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<EmailCase id={self.id} subject='{self.subject}' risk={self.risk_score}>"


class EmailHop(Base):
    """Single SMTP relay hop extracted from Received headers."""

    __tablename__ = "email_hops"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(36), ForeignKey("email_cases.id", ondelete="CASCADE"), nullable=False)
    sequence = Column(Integer, nullable=False)

    # --- Hop metadata ---
    from_host = Column(String(255))
    by_host = Column(String(255))
    ip_address = Column(String(45))
    timestamp = Column(String(255))
    raw_header = Column(Text, nullable=False)

    # --- IP classification ---
    is_private = Column(Boolean, default=False, nullable=False)
    is_originating = Column(Boolean, default=False, nullable=False)

    # --- Geolocation (populated by geo_resolver) ---
    latitude = Column(Float)
    longitude = Column(Float)
    city = Column(String(100))
    country = Column(String(100))
    country_iso = Column(String(3))
    isp = Column(String(255))
    asn = Column(String(20))

    # --- Relationship ---
    case = relationship("EmailCase", back_populates="hops")

    def __repr__(self) -> str:
        return f"<EmailHop seq={self.sequence} ip={self.ip_address} private={self.is_private}>"


class Attachment(Base):
    """Metadata for an email attachment with integrity hash."""

    __tablename__ = "attachments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(36), ForeignKey("email_cases.id", ondelete="CASCADE"), nullable=False)

    filename = Column(String(255), nullable=False)
    content_type = Column(String(100))
    size = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False)

    # --- Relationship ---
    case = relationship("EmailCase", back_populates="attachments")

    def __repr__(self) -> str:
        return f"<Attachment name='{self.filename}' size={self.size}>"


class ExtractedURL(Base):
    """URL extracted from email body content."""

    __tablename__ = "extracted_urls"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(36), ForeignKey("email_cases.id", ondelete="CASCADE"), nullable=False)

    url = Column(Text, nullable=False)
    defanged = Column(Text)
    anchor_text = Column(Text)
    is_suspicious = Column(Boolean, default=False, nullable=False)
    suspicion_reason = Column(String(255))

    # --- Relationship ---
    case = relationship("EmailCase", back_populates="urls")

    def __repr__(self) -> str:
        return f"<ExtractedURL url='{self.url[:50]}' suspicious={self.is_suspicious}>"
