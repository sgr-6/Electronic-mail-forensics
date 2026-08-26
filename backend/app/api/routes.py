"""
REST API routes for the Email Forensics Platform.

Phase 1 endpoints:
    POST /api/analyze     - Upload and analyze an .eml file
    GET  /api/cases       - List all analyzed cases
    GET  /api/cases/{id}  - Get full case detail
    GET  /api/stats       - Dashboard statistics
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_session
from app.models import Attachment, EmailCase, EmailHop, ExtractedURL
from app.schemas import (
    AnalysisResponse,
    CaseDetail,
    CaseSummary,
    ErrorResponse,
    HopSchema,
    StatsResponse,
)
from app.services.eml_parser import EMLParser
from app.services.hop_tracer import parse_received_headers, find_originating_ip, get_public_ips
from app.services.geo_resolver import geo_resolver
from app.services.auth_engine import validate_all as validate_auth
from app.services.reputation import reputation_checker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["forensics"])


# ========================================================================= #
# POST /api/analyze — Upload and analyze an .eml file                       #
# ========================================================================= #

@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    responses={400: {"model": ErrorResponse}},
    summary="Upload and analyze an email file",
)
async def analyze_email(
    file: UploadFile = File(..., description="Raw .eml or RFC 822 email file"),
    session: AsyncSession = Depends(get_session),
) -> AnalysisResponse:
    """
    Ingest a raw .eml file, perform full forensic analysis, and store results.

    Pipeline:
    1. Parse email (headers, body, attachments, URLs)
    2. Compute evidence hashes (MD5, SHA-1, SHA-256)
    3. Extract and analyze hop-by-hop relay chain
    4. Store case in database
    """
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Empty file uploaded")

    if len(raw_bytes) > 50 * 1024 * 1024:  # 50MB limit
        raise HTTPException(status_code=400, detail="File too large (max 50MB)")

    try:
        # --- Step 1: Parse the email ---
        parser = EMLParser(raw_bytes, filename=file.filename)
        parsed = parser.parse_full()

        # --- Step 2: Trace hops ---
        hops = parse_received_headers(parsed["received_headers"])

        # --- Step 3: Geo-resolve public IPs ---
        originating_ip = find_originating_ip(hops)
        public_ips = get_public_ips(hops)
        geo_data = geo_resolver.resolve_many(public_ips)

        # --- Step 4: Run sender authentication ---
        from_domain = None
        from_addr = parsed["addresses"].get("from_address", "")
        if "@" in from_addr:
            from_domain = from_addr.split("@", 1)[1]

        envelope_domain = None
        return_path = parsed["addresses"].get("return_path", "")
        if "@" in return_path:
            envelope_domain = return_path.split("@", 1)[1].rstrip(">")

        auth_results = validate_auth(
            raw_email=raw_bytes,
            sender_ip=originating_ip,
            from_domain=from_domain,
            envelope_domain=envelope_domain,
        )

        # --- Step 5: Check IP reputation ---
        reputation_data = reputation_checker.check_many(public_ips)

        # --- Step 6: Create case record ---
        case = EmailCase(
            filename=parsed["filename"],
            raw_hash_md5=parsed["hashes"]["md5"],
            raw_hash_sha1=parsed["hashes"]["sha1"],
            raw_hash_sha256=parsed["hashes"]["sha256"],
            raw_size=parsed["hashes"]["size"],
            subject=parsed["addresses"].get("subject"),
            from_address=parsed["addresses"].get("from_address"),
            from_display=parsed["addresses"].get("from_display"),
            to_address=parsed["addresses"].get("to_address"),
            date_header=parsed["addresses"].get("date_header"),
            message_id=parsed["addresses"].get("message_id"),
            return_path=parsed["addresses"].get("return_path"),
            body_plain=parsed["body"].get("body_plain"),
            body_html=parsed["body"].get("body_html"),
            headers_json=json.dumps(parsed["headers"], default=str),
            spf_result=auth_results["spf"]["result"],
            dkim_result=auth_results["dkim"]["result"],
            dmarc_result=auth_results["dmarc"]["result"],
            auth_details_json=json.dumps(auth_results, default=str),
            risk_score=None,
            risk_category="Pending",
            threat_type=None,
        )
        session.add(case)

        # --- Step 7: Store hops with geo data ---
        for hop_data in hops:
            ip = hop_data.get("ip_address")
            geo = geo_data.get(ip, {}) if ip and not hop_data.get("is_private") else {}
            hop_record = EmailHop(
                case_id=case.id,
                sequence=hop_data["sequence"],
                from_host=hop_data.get("from_host"),
                by_host=hop_data.get("by_host"),
                ip_address=ip,
                timestamp=hop_data.get("timestamp"),
                raw_header=hop_data["raw_header"],
                is_private=hop_data.get("is_private", False),
                is_originating=hop_data.get("is_originating", False),
                latitude=geo.get("latitude"),
                longitude=geo.get("longitude"),
                city=geo.get("city"),
                country=geo.get("country"),
                country_iso=geo.get("country_iso"),
                isp=geo.get("isp"),
                asn=geo.get("asn"),
            )
            session.add(hop_record)

        # --- Step 8: Store attachments ---
        for att_data in parsed["attachments"]:
            att_record = Attachment(
                case_id=case.id,
                filename=att_data["filename"],
                content_type=att_data.get("content_type"),
                size=att_data["size"],
                sha256=att_data["sha256"],
            )
            session.add(att_record)

        # --- Step 9: Store URLs ---
        for url_data in parsed["urls"]:
            url_record = ExtractedURL(
                case_id=case.id,
                url=url_data["url"],
                defanged=url_data.get("defanged"),
                anchor_text=url_data.get("anchor_text"),
                is_suspicious=url_data.get("is_suspicious", False),
                suspicion_reason=url_data.get("suspicion_reason"),
            )
            session.add(url_record)

        await session.commit()
        await session.refresh(case)

        logger.info("Analysis complete for case %s (%s)", case.id, case.filename)

        return AnalysisResponse(
            case_id=case.id,
            status="completed",
            message=f"Analysis complete for {case.filename}",
            risk_score=case.risk_score,
            risk_category=case.risk_category,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Analysis failed for %s", file.filename)
        await session.rollback()
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# ========================================================================= #
# GET /api/cases — List all cases                                           #
# ========================================================================= #

@router.get(
    "/cases",
    response_model=list[CaseSummary],
    summary="List all analyzed cases",
)
async def list_cases(
    session: AsyncSession = Depends(get_session),
    limit: int = 50,
    offset: int = 0,
) -> list[CaseSummary]:
    """Return a paginated list of analyzed email cases, newest first."""
    stmt = (
        select(EmailCase)
        .order_by(EmailCase.submitted_at.desc())
        .offset(offset)
        .limit(limit)
    )
    result = await session.execute(stmt)
    cases = result.scalars().all()
    return [CaseSummary.model_validate(c) for c in cases]


# ========================================================================= #
# GET /api/cases/{case_id} — Full case detail                               #
# ========================================================================= #

@router.get(
    "/cases/{case_id}",
    response_model=CaseDetail,
    responses={404: {"model": ErrorResponse}},
    summary="Get full case detail",
)
async def get_case(
    case_id: str,
    session: AsyncSession = Depends(get_session),
) -> CaseDetail:
    """Return full forensic analysis detail for a specific case."""
    stmt = (
        select(EmailCase)
        .options(
            selectinload(EmailCase.hops),
            selectinload(EmailCase.attachments),
            selectinload(EmailCase.urls),
        )
        .where(EmailCase.id == case_id)
    )
    result = await session.execute(stmt)
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    # Build response with nested data
    headers = {}
    if case.headers_json:
        try:
            headers = json.loads(case.headers_json)
        except json.JSONDecodeError:
            headers = {}

    auth_details = None
    if case.auth_details_json:
        try:
            auth_details = json.loads(case.auth_details_json)
        except json.JSONDecodeError:
            pass

    nlp_details = None
    if case.nlp_details_json:
        try:
            nlp_details = json.loads(case.nlp_details_json)
        except json.JSONDecodeError:
            pass

    return CaseDetail(
        id=case.id,
        filename=case.filename,
        submitted_at=case.submitted_at,
        raw_hash_md5=case.raw_hash_md5,
        raw_hash_sha1=case.raw_hash_sha1,
        raw_hash_sha256=case.raw_hash_sha256,
        raw_size=case.raw_size,
        subject=case.subject,
        from_address=case.from_address,
        from_display=case.from_display,
        to_address=case.to_address,
        date_header=case.date_header,
        message_id=case.message_id,
        return_path=case.return_path,
        body_plain=case.body_plain,
        body_html=case.body_html,
        headers=headers,
        hops=[HopSchema.model_validate(h) for h in case.hops],
        attachments=[
            {"filename": a.filename, "content_type": a.content_type, "size": a.size, "sha256": a.sha256}
            for a in case.attachments
        ],
        urls=[
            {
                "url": u.url,
                "defanged": u.defanged,
                "anchor_text": u.anchor_text,
                "is_suspicious": u.is_suspicious,
                "suspicion_reason": u.suspicion_reason,
            }
            for u in case.urls
        ],
        spf_result=case.spf_result,
        dkim_result=case.dkim_result,
        dmarc_result=case.dmarc_result,
        auth_details=auth_details,
        nlp_classification=case.nlp_classification,
        nlp_confidence=case.nlp_confidence,
        nlp_details=nlp_details,
        risk_score=case.risk_score,
        risk_category=case.risk_category,
        threat_type=case.threat_type,
    )


# ========================================================================= #
# GET /api/stats — Dashboard statistics                                     #
# ========================================================================= #

@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Get dashboard statistics",
)
async def get_stats(
    session: AsyncSession = Depends(get_session),
) -> StatsResponse:
    """Return aggregate statistics for the dashboard."""
    # Total count
    total_result = await session.execute(select(func.count(EmailCase.id)))
    total = total_result.scalar() or 0

    # Count by category
    category_counts = {"Clean": 0, "Suspicious": 0, "Phishing / BEC Attack": 0, "Malicious Infrastructure": 0}
    for category in category_counts:
        count_result = await session.execute(
            select(func.count(EmailCase.id)).where(EmailCase.risk_category == category)
        )
        category_counts[category] = count_result.scalar() or 0

    # Recent cases
    recent_stmt = select(EmailCase).order_by(EmailCase.submitted_at.desc()).limit(10)
    recent_result = await session.execute(recent_stmt)
    recent = [CaseSummary.model_validate(c) for c in recent_result.scalars().all()]

    return StatsResponse(
        total_cases=total,
        clean_count=category_counts["Clean"],
        suspicious_count=category_counts["Suspicious"],
        phishing_count=category_counts["Phishing / BEC Attack"],
        malicious_count=category_counts["Malicious Infrastructure"],
        recent_cases=recent,
    )
