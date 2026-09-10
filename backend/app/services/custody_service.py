"""
Evidence Chain of Custody Service.

Provides append-only logging of important evidence-handling events
(acquisition, analysis, report generation, integrity verification).

Events are recorded chronologically and designed for future integration
with a permissioned blockchain evidence ledger.
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import EvidenceCustodyEvent

logger = logging.getLogger(__name__)


# ── Event type constants ──────────────────────────────────────────────────── #
EVIDENCE_ACQUIRED = "Evidence Acquired"
SHA256_FINGERPRINT_CREATED = "SHA-256 Fingerprint Created"
FORENSIC_ANALYSIS_STARTED = "Forensic Analysis Started"
FORENSIC_ANALYSIS_COMPLETED = "Forensic Analysis Completed"
REPORT_GENERATED = "Report Generated"
EVIDENCE_INTEGRITY_VERIFIED = "Evidence Integrity Verified"
EVIDENCE_INTEGRITY_FAILED = "Evidence Integrity Verification Failed"


async def log_custody_event(
    session: AsyncSession,
    case_id: str,
    event_type: str,
    actor: str = "System",
    description: Optional[str] = None,
    evidence_sha256: Optional[str] = None,
) -> EvidenceCustodyEvent:
    """
    Create and persist an append-only Chain of Custody event.

    Args:
        session: Active async database session.
        case_id: UUID of the associated EmailCase.
        event_type: One of the event type constants defined above.
        actor: Identity of who/what performed the action (default "System").
        description: Optional human-readable description.
        evidence_sha256: Optional SHA-256 hash associated with this event.

    Returns:
        The created EvidenceCustodyEvent instance.

    Raises:
        Exception: Propagated if database write fails — custody events
                   must not silently fail.
    """
    try:
        event = EvidenceCustodyEvent(
            case_id=case_id,
            event_type=event_type,
            actor=actor,
            description=description,
            evidence_sha256=evidence_sha256,
        )
        session.add(event)
        await session.flush()
        logger.info(
            "Custody event recorded: [%s] %s for case %s",
            event_type, actor, case_id,
        )
        return event
    except Exception:
        logger.exception(
            "FAILED to record custody event [%s] for case %s — "
            "this is a forensic integrity concern",
            event_type, case_id,
        )
        raise
