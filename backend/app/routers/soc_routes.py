"""
Unified FastAPI router for SOC operations.
"""
from __future__ import annotations

import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_session
from app.models import EmailCase, EmailHop, Attachment, ExtractedURL

from app.services.soc.quishing_ocr_engine import quishing_ocr_engine
from app.services.soc.html_smuggling_inspector import html_smuggling_inspector
from app.services.soc.crypto_wallet_tracker import crypto_wallet_tracker
from app.services.soc.infra_fingerprinter import infra_fingerprinter
from app.services.soc.bsa_sec63_dossier import bsa_sec63_dossier
from app.services.soc.i4c_docket_exporter import i4c_docket_exporter
from app.services.soc.abuse_takedown_generator import abuse_takedown_generator
from app.services.soc.yara_suricata_generator import yara_suricata_generator

router = APIRouter(prefix="/soc", tags=["soc"])

async def get_case_full(case_id: str, session: AsyncSession):
    case = await session.get(EmailCase, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
        
    result_hops = await session.execute(
        select(EmailHop).where(EmailHop.case_id == case_id).order_by(EmailHop.sequence)
    )
    hops = result_hops.scalars().all()
    
    result_atts = await session.execute(
        select(Attachment).where(Attachment.case_id == case_id)
    )
    atts = result_atts.scalars().all()
    
    result_urls = await session.execute(
        select(ExtractedURL).where(ExtractedURL.case_id == case_id)
    )
    urls = result_urls.scalars().all()
    
    return case, hops, atts, urls

@router.post("/analyze-extended/{case_id}")
async def analyze_extended(case_id: str, session: AsyncSession = Depends(get_session)):
    """Run Phase 1 and Phase 2 deep extractors manually."""
    case, hops, atts, urls = await get_case_full(case_id, session)
    
    # In a real app we'd load the raw bytes, here we mock the payload for OCR
    # or rely on the HTML body.
    
    # 1. HTML Smuggling
    smuggling_res = html_smuggling_inspector.analyze(case.body_html)
    
    # 2. Crypto Extortion
    text_content = f"{case.body_plain} {case.body_html}"
    crypto_res = crypto_wallet_tracker.analyze(text_content)
    
    # 3. Infra Fingerprinting
    headers_dict = json.loads(case.headers_json) if case.headers_json else {}
    received_headers = [h.raw_header for h in hops if h.raw_header]
    fingerprints = infra_fingerprinter.analyze(case_id, headers_dict, received_headers)
    
    # (Quishing requires raw attachment bytes which we didn't store fully in SQLite 
    # to save space, but the engine is available to be called if bytes are provided).

    return {
        "smuggling": smuggling_res,
        "crypto": crypto_res,
        "fingerprints": fingerprints
    }

@router.get("/bsa-certificate/{case_id}")
async def get_bsa_cert(case_id: str, session: AsyncSession = Depends(get_session)):
    case, _, _, _ = await get_case_full(case_id, session)
    pdf_bytes = bsa_sec63_dossier.generate_certificate(case)
    return Response(
        content=pdf_bytes, 
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=BSA_Sec63_{case_id}.pdf"}
    )

@router.get("/i4c-docket/{case_id}")
async def get_i4c_docket(case_id: str, session: AsyncSession = Depends(get_session)):
    case, hops, _, _ = await get_case_full(case_id, session)
    
    # Re-run extraction for the docket payload
    text_content = f"{case.body_plain} {case.body_html}"
    crypto_res = crypto_wallet_tracker.analyze(text_content)
    smuggling_res = html_smuggling_inspector.analyze(case.body_html)
    
    json_data = i4c_docket_exporter.export_json(
        case, 
        list(hops), 
        crypto_res.get("extracted_wallets", []),
        smuggling_res.get("smuggled_files", [])
    )
    return JSONResponse(content=json.loads(json_data))

@router.get("/takedown-notice/{case_id}")
async def get_takedown(case_id: str, session: AsyncSession = Depends(get_session)):
    case, hops, _, _ = await get_case_full(case_id, session)
    
    # Find origin IP
    origin_ip = "Unknown"
    country = "Unknown"
    for h in hops:
        if h.is_public_origin:
            origin_ip = h.ip_address
            country = h.country_iso or "Unknown"
            break
            
    notice = abuse_takedown_generator.generate_notice(case, origin_ip, country)
    return notice

@router.get("/rules/{case_id}")
async def get_rules(case_id: str, session: AsyncSession = Depends(get_session)):
    case, hops, atts, urls = await get_case_full(case_id, session)
    
    yara_rule = yara_suricata_generator.generate_yara(case, list(atts))
    
    origin_ip = ""
    for h in hops:
        if h.is_public_origin:
            origin_ip = h.ip_address
            break
            
    suricata_rule = yara_suricata_generator.generate_suricata(origin_ip, list(urls))
    
    return {
        "yara": yara_rule,
        "suricata": suricata_rule
    }
