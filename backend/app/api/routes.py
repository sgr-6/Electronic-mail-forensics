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
from app.models import Attachment, EmailCase, EmailHop, ExtractedURL, EvidenceCustodyEvent
from app.schemas import (
    AnalysisResponse,
    CaseDetail,
    CaseSummary,
    CustodyEventSchema,
    CustodyHistoryResponse,
    ErrorResponse,
    EvidenceIntegritySchema,
    HopSchema,
    StatsResponse,
    VerificationResponse,
)
from app.services.hash_service import hash_service
from app.services.custody_service import (
    log_custody_event,
    EVIDENCE_ACQUIRED,
    SHA256_FINGERPRINT_CREATED,
    FORENSIC_ANALYSIS_STARTED,
    FORENSIC_ANALYSIS_COMPLETED,
    REPORT_GENERATED,
    EVIDENCE_INTEGRITY_VERIFIED,
    EVIDENCE_INTEGRITY_FAILED,
)
from app.services.eml_parser import EMLParser
from app.services.hop_tracer import parse_received_headers, find_originating_ip, get_public_ips
from app.services.geo_resolver import geo_resolver
from app.services.auth_engine import validate_all as validate_auth
from app.services.reputation import reputation_checker
from app.services.nlp_engine import nlp_engine
from app.services.homoglyph_detector import homoglyph_detector
from app.services.url_analyzer import url_analyzer
from app.services.risk_scorer import risk_scorer
from app.services.graph_engine import graph_engine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["forensics"])

from pydantic import BaseModel
class IMAPRequest(BaseModel):
    imap_server: str
    email_user: str
    app_password: str
    limit: int = 5

from app.services.imap_ingester import imap_ingester

@router.post("/imap/fetch")
async def fetch_imap_emails(req: IMAPRequest, session: AsyncSession = Depends(get_session)):
    """Fetch emails via IMAP and analyze them."""
    try:
        raw_emails = imap_ingester.fetch_recent_emails(
            req.imap_server, req.email_user, req.app_password, req.limit
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    if not raw_emails:
        return {"message": "No emails found.", "cases": []}
        
    # Analyze each fetched email
    processed_cases = []
    
    from io import BytesIO
    import uuid
    
    for raw_bytes in raw_emails:
        # Create a fake UploadFile object in memory
        fake_file = UploadFile(
            filename=f"imap_{uuid.uuid4().hex[:8]}.eml",
            file=BytesIO(raw_bytes)
        )
        
        try:
            res = await analyze_email(file=fake_file, session=session)
            processed_cases.append({
                "id": res.case_id,
                "subject": res.subject,
                "risk_category": res.risk_category,
                "risk_score": res.risk_score
            })
        except Exception as e:
            logger.error(f"Failed to analyze IMAP email: {e}")
            
    return {"message": f"Successfully fetched and analyzed {len(processed_cases)} emails.", "cases": processed_cases}



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

        # --- Step 6: NLP Threat Analysis ---
        nlp_results = nlp_engine.analyze(
            subject=parsed["addresses"].get("subject"),
            body_plain=parsed["body"].get("body_plain"),
            body_html=parsed["body"].get("body_html"),
            from_address=from_addr,
            from_display=parsed["addresses"].get("from_display"),
            to_address=parsed["addresses"].get("to_address"),
            headers=parsed["headers"],
        )

        # --- Step 7: Domain & Typosquatting Analysis ---
        domain_analysis = homoglyph_detector.check_domain(from_domain or "")

        # --- Step 8: URL Analysis ---
        analyzed_urls = url_analyzer.analyze_urls(parsed["attachments"] if "attachments" in parsed else parsed["urls"]) # Actually parsed["urls"]
        analyzed_urls = url_analyzer.analyze_urls(parsed["urls"])

        # --- Step 9: Composite Risk Scoring ---
        risk_results = risk_scorer.score(
            auth_results=auth_results,
            nlp_results=nlp_results,
            reputation_data=reputation_data,
            domain_analysis=domain_analysis,
            url_analysis=analyzed_urls,
        )

        # --- Step 10: Create case record ---
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
            risk_score=risk_results["composite_score"],
            risk_category=risk_results["category"],
            threat_type=risk_results["threat_type"],
            nlp_details_json=json.dumps(nlp_results, default=str),
        )
        session.add(case)
        await session.flush()  # To get case.id for graph and relationships

        # --- Step 10b: Chain of Custody — Evidence Acquired + SHA-256 Fingerprint ---
        # Only logged AFTER case + SHA-256 are confirmed in DB
        await log_custody_event(
            session, case.id, EVIDENCE_ACQUIRED,
            description=f"Evidence file '{case.filename}' acquired ({case.raw_size} bytes)",
            evidence_sha256=case.raw_hash_sha256,
        )
        await log_custody_event(
            session, case.id, SHA256_FINGERPRINT_CREATED,
            description="SHA-256 evidence fingerprint recorded from original file bytes",
            evidence_sha256=case.raw_hash_sha256,
        )
        await log_custody_event(
            session, case.id, FORENSIC_ANALYSIS_STARTED,
            description="Automated forensic analysis pipeline initiated",
        )

        # --- Step 11: Add to Graph Engine ---
        graph_engine.add_email_case({
            "case_id": case.id,
            "subject": case.subject,
            "from_address": case.from_address,
            "from_domain": from_domain,
            "sender_ip": originating_ip,
            "asn": reputation_data.get(originating_ip, {}).get("asn") if originating_ip else None,
            "risk_category": case.risk_category,
        })

        # --- Step 12: Store hops with geo data ---
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

        # --- Step 13: Store attachments ---
        for att_data in parsed["attachments"]:
            att_record = Attachment(
                case_id=case.id,
                filename=att_data["filename"],
                content_type=att_data.get("content_type"),
                size=att_data["size"],
                sha256=att_data["sha256"],
            )
            session.add(att_record)

        # --- Step 14: Store URLs ---
        for url_data in analyzed_urls:
            url_record = ExtractedURL(
                case_id=case.id,
                url=url_data["url"],
                defanged=url_data["defanged"],
                anchor_text=url_data.get("anchor_text"),
                is_suspicious=url_data.get("is_suspicious", False),
                suspicion_reason=url_data.get("suspicion_reason"),
            )
            session.add(url_record)

        await session.commit()
        await session.refresh(case)

        # --- Chain of Custody: Analysis Completed ---
        await log_custody_event(
            session, case.id, FORENSIC_ANALYSIS_COMPLETED,
            description="Forensic analysis pipeline completed successfully",
        )
        await session.commit()

        logger.info("Analysis complete for case %s (%s)", case.id, case.filename)

        evidence_data = hash_service.calculate_evidence_hashes(raw_bytes, case.filename)
        evidence_schema = EvidenceIntegritySchema(
            filename=evidence_data["filename"],
            hash_algorithm=evidence_data["hash_algorithm"],
            sha256=evidence_data["sha256"],
            sha1=evidence_data["sha1"],
            md5=evidence_data["md5"],
            submitted_at=case.submitted_at,
            size=evidence_data["size"],
            status=evidence_data["status"],
        )

        return AnalysisResponse(
            case_id=case.id,
            status="completed",
            message=f"Analysis complete for {case.filename}",
            risk_score=case.risk_score,
            risk_category=case.risk_category,
            evidence=evidence_schema,
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
# GET /api/graph — Full Campaign Attribution Graph                          #
# ========================================================================= #

@router.get("/graph")
async def get_campaign_graph():
    """Return the full NetworkX attribution graph for Cytoscape visualization."""
    from app.services.graph_engine import graph_engine
    return graph_engine.get_full_graph()

# ========================================================================= #
# GET /api/cases/{case_id}/report — Download PDF                            #
# ========================================================================= #

from fastapi.responses import Response

@router.get("/cases/{case_id}/report")
async def download_case_report(case_id: str, session: AsyncSession = Depends(get_session)):
    """Download a forensic PDF report for a case."""
    # Fetch case data
    result = await session.execute(select(EmailCase).where(EmailCase.id == case_id))
    case = result.scalar_one_or_none()
    
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Fetch relations
    hops = (await session.execute(select(EmailHop).where(EmailHop.case_id == case_id).order_by(EmailHop.sequence))).scalars().all()
    attachments = (await session.execute(select(Attachment).where(Attachment.case_id == case_id))).scalars().all()
    urls = (await session.execute(select(ExtractedURL).where(ExtractedURL.case_id == case_id))).scalars().all()
    custody_events = (await session.execute(
        select(EvidenceCustodyEvent)
        .where(EvidenceCustodyEvent.case_id == case_id)
        .order_by(EvidenceCustodyEvent.timestamp)
    )).scalars().all()

    # Generate PDF (with custody history)
    from app.services.report_generator import report_generator
    pdf_bytes = report_generator.generate_pdf(case, list(hops), list(attachments), list(urls), list(custody_events))

    # --- Chain of Custody: Report Generated ---
    await log_custody_event(
        session, case_id, REPORT_GENERATED,
        description="Forensic PDF report generated and downloaded",
    )
    await session.commit()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="forensic_report_case_{case.id}.pdf"'
        }
    )

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

    evidence_schema = EvidenceIntegritySchema(
        filename=case.filename,
        hash_algorithm="SHA-256",
        sha256=case.raw_hash_sha256,
        sha1=case.raw_hash_sha1,
        md5=case.raw_hash_md5,
        submitted_at=case.submitted_at,
        size=case.raw_size,
        status="Hash Generated",
    )

    return CaseDetail(
        id=case.id,
        filename=case.filename,
        submitted_at=case.submitted_at,
        raw_hash_md5=case.raw_hash_md5,
        raw_hash_sha1=case.raw_hash_sha1,
        raw_hash_sha256=case.raw_hash_sha256,
        raw_size=case.raw_size,
        evidence=evidence_schema,
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
# POST /api/cases/{case_id}/verify — Verify Evidence Integrity              #
# ========================================================================= #

@router.post(
    "/cases/{case_id}/verify",
    response_model=VerificationResponse,
    responses={400: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    summary="Verify evidence file integrity against stored SHA-256 fingerprint",
)
async def verify_case_evidence(
    case_id: str,
    file: UploadFile = File(..., description="Uploaded evidence file to verify"),
    session: AsyncSession = Depends(get_session),
) -> VerificationResponse:
    """
    Verify an uploaded file against the original stored SHA-256 evidence fingerprint.
    Calculates a fresh SHA-256 directly from raw file bytes without modifying database.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided for verification")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Empty file uploaded for verification")

    result = await session.execute(select(EmailCase).where(EmailCase.id == case_id))
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    verification = hash_service.verify_evidence_integrity(raw_bytes, case.raw_hash_sha256)

    # --- Chain of Custody: Record verification outcome ---
    if verification["verified"]:
        await log_custody_event(
            session, case_id, EVIDENCE_INTEGRITY_VERIFIED,
            description="Evidence file matches stored SHA-256 fingerprint",
            evidence_sha256=case.raw_hash_sha256,
        )
    else:
        await log_custody_event(
            session, case_id, EVIDENCE_INTEGRITY_FAILED,
            description=(
                f"Evidence integrity check FAILED. "
                f"Expected: {verification['expected_sha256'][:16]}... "
                f"Actual: {verification['actual_sha256'][:16]}..."
            ),
            evidence_sha256=case.raw_hash_sha256,  # Original hash preserved
        )
    await session.commit()

    return VerificationResponse(
        case_id=case.id,
        filename=case.filename,
        hash_algorithm=verification["hash_algorithm"],
        expected_sha256=verification["expected_sha256"],
        actual_sha256=verification["actual_sha256"],
        verified=verification["verified"],
        status=verification["status"],
        message=verification["message"],
    )


# ========================================================================= #
# GET /api/cases/{case_id}/custody — Chain of Custody History               #
# ========================================================================= #

@router.get(
    "/cases/{case_id}/custody",
    response_model=CustodyHistoryResponse,
    responses={404: {"model": ErrorResponse}},
    summary="Get Chain of Custody history for a case",
)
async def get_custody_history(
    case_id: str,
    session: AsyncSession = Depends(get_session),
) -> CustodyHistoryResponse:
    """
    Return the chronological, append-only Chain of Custody event history
    for a specific email evidence case. Events are ordered by timestamp.
    """
    # Verify case exists
    case_result = await session.execute(select(EmailCase).where(EmailCase.id == case_id))
    if not case_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    # Fetch custody events in chronological order
    stmt = (
        select(EvidenceCustodyEvent)
        .where(EvidenceCustodyEvent.case_id == case_id)
        .order_by(EvidenceCustodyEvent.timestamp)
    )
    result = await session.execute(stmt)
    events = result.scalars().all()

    return CustodyHistoryResponse(
        case_id=case_id,
        events=[CustodyEventSchema.model_validate(e) for e in events],
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
