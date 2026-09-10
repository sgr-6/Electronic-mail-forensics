"""
Unit tests for Evidence Chain of Custody functionality.

Tests:
A. Evidence acquisition creates a custody event.
B. SHA-256 creation creates the appropriate event.
C. Analysis creates start/completion events.
D. Report generation creates a report-generated event.
E. Successful integrity verification creates a verification-success event.
F. Failed integrity verification creates a verification-failure event.
G. Failed verification does NOT overwrite the original SHA-256.
H. Custody events are returned in chronological order.
I. Custody events cannot be modified/deleted through the normal API.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.main import create_app
from app.database import engine, Base, async_session_factory

SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "samples"


def _sample_path(name: str) -> Path:
    """Resolve a sample .eml file path."""
    p = SAMPLES_DIR / name
    assert p.exists(), f"Sample file missing: {p}"
    return p


@pytest_asyncio.fixture(scope="module")
def event_loop():
    """Create a shared event loop for the module."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="module")
async def app():
    """Create a fresh app instance with clean database tables."""
    application = create_app()

    # Recreate tables for a clean test database
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    yield application

    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


@pytest_asyncio.fixture(scope="module")
async def client(app):
    """Create an async HTTP test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture(scope="module")
async def analyzed_case_id(client):
    """Upload a sample .eml file and return the case_id for reuse across tests."""
    sample = _sample_path("legitimate_email.eml")
    with open(sample, "rb") as f:
        response = await client.post(
            "/api/analyze",
            files={"file": ("legitimate_email.eml", f, "message/rfc822")},
        )
    assert response.status_code == 200, f"Analyze failed: {response.text}"
    data = response.json()
    assert data["case_id"], "No case_id returned"
    return data["case_id"]


class TestCustodyEventCreation:
    """Tests A-D: Custody events created during analysis workflow."""

    @pytest.mark.asyncio
    async def test_a_evidence_acquired_event(self, client, analyzed_case_id):
        """Test A: Evidence acquisition creates a custody event."""
        res = await client.get(f"/api/cases/{analyzed_case_id}/custody")
        assert res.status_code == 200
        events = res.json()["events"]
        event_types = [e["event_type"] for e in events]
        assert "Evidence Acquired" in event_types

    @pytest.mark.asyncio
    async def test_b_sha256_fingerprint_event(self, client, analyzed_case_id):
        """Test B: SHA-256 creation creates the appropriate event."""
        res = await client.get(f"/api/cases/{analyzed_case_id}/custody")
        events = res.json()["events"]
        event_types = [e["event_type"] for e in events]
        assert "SHA-256 Fingerprint Created" in event_types

        # Verify the event contains the SHA-256 hash
        sha_event = next(e for e in events if e["event_type"] == "SHA-256 Fingerprint Created")
        assert sha_event["evidence_sha256"] is not None
        assert len(sha_event["evidence_sha256"]) == 64

    @pytest.mark.asyncio
    async def test_c_analysis_start_completion_events(self, client, analyzed_case_id):
        """Test C: Analysis creates start and completion events."""
        res = await client.get(f"/api/cases/{analyzed_case_id}/custody")
        events = res.json()["events"]
        event_types = [e["event_type"] for e in events]
        assert "Forensic Analysis Started" in event_types
        assert "Forensic Analysis Completed" in event_types

    @pytest.mark.asyncio
    async def test_d_report_generated_event(self, client, analyzed_case_id):
        """Test D: Report generation creates a report-generated event."""
        # First generate the report
        report_res = await client.get(f"/api/cases/{analyzed_case_id}/report")
        assert report_res.status_code == 200
        assert report_res.headers["content-type"] == "application/pdf"

        # Now check the custody events
        res = await client.get(f"/api/cases/{analyzed_case_id}/custody")
        events = res.json()["events"]
        event_types = [e["event_type"] for e in events]
        assert "Report Generated" in event_types


class TestVerificationCustody:
    """Tests E-G: Custody events for integrity verification."""

    @pytest.mark.asyncio
    async def test_e_successful_verification_event(self, client, analyzed_case_id):
        """Test E: Successful integrity verification creates a verification-success event."""
        sample = _sample_path("legitimate_email.eml")
        with open(sample, "rb") as f:
            verify_res = await client.post(
                f"/api/cases/{analyzed_case_id}/verify",
                files={"file": ("legitimate_email.eml", f, "message/rfc822")},
            )
        assert verify_res.status_code == 200
        assert verify_res.json()["verified"] is True

        # Check custody events
        res = await client.get(f"/api/cases/{analyzed_case_id}/custody")
        events = res.json()["events"]
        event_types = [e["event_type"] for e in events]
        assert "Evidence Integrity Verified" in event_types

    @pytest.mark.asyncio
    async def test_f_failed_verification_event(self, client, analyzed_case_id):
        """Test F: Failed integrity verification creates a verification-failure event."""
        sample = _sample_path("legitimate_email.eml")
        tampered = sample.read_bytes() + b"\nX-Tampered: true\n"

        verify_res = await client.post(
            f"/api/cases/{analyzed_case_id}/verify",
            files={"file": ("tampered.eml", tampered, "message/rfc822")},
        )
        assert verify_res.status_code == 200
        assert verify_res.json()["verified"] is False

        # Check custody events
        res = await client.get(f"/api/cases/{analyzed_case_id}/custody")
        events = res.json()["events"]
        event_types = [e["event_type"] for e in events]
        assert "Evidence Integrity Verification Failed" in event_types

    @pytest.mark.asyncio
    async def test_g_failed_verification_does_not_overwrite_sha256(self, client, analyzed_case_id):
        """Test G: Failed verification does NOT overwrite the original SHA-256."""
        # Get original case SHA-256
        case_res = await client.get(f"/api/cases/{analyzed_case_id}")
        original_sha256 = case_res.json()["raw_hash_sha256"]

        # Verify with tampered file
        sample = _sample_path("legitimate_email.eml")
        tampered = sample.read_bytes() + b"TAMPERED_DATA"

        await client.post(
            f"/api/cases/{analyzed_case_id}/verify",
            files={"file": ("tampered.eml", tampered, "message/rfc822")},
        )

        # Re-fetch case and check SHA-256 is unchanged
        case_res2 = await client.get(f"/api/cases/{analyzed_case_id}")
        assert case_res2.json()["raw_hash_sha256"] == original_sha256


class TestCustodyIntegrity:
    """Tests H-I: Ordering and immutability constraints."""

    @pytest.mark.asyncio
    async def test_h_events_in_chronological_order(self, client, analyzed_case_id):
        """Test H: Custody events are returned in chronological order."""
        res = await client.get(f"/api/cases/{analyzed_case_id}/custody")
        events = res.json()["events"]
        assert len(events) >= 4  # At least: acquired, sha256, started, completed

        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps), "Events are not in chronological order"

    @pytest.mark.asyncio
    async def test_i_no_delete_endpoint(self, client, analyzed_case_id):
        """Test I: Custody events cannot be deleted through the normal API."""
        # Attempt DELETE on custody endpoint — should return 405 Method Not Allowed
        res = await client.delete(f"/api/cases/{analyzed_case_id}/custody")
        assert res.status_code == 405

    @pytest.mark.asyncio
    async def test_i_no_put_endpoint(self, client, analyzed_case_id):
        """Test I: Custody events cannot be modified through the normal API."""
        # Attempt PUT on custody endpoint — should return 405 Method Not Allowed
        res = await client.put(
            f"/api/cases/{analyzed_case_id}/custody",
            json={"event_type": "Fake Event"},
        )
        assert res.status_code == 405

    @pytest.mark.asyncio
    async def test_custody_for_nonexistent_case(self, client):
        """Custody endpoint returns 404 for nonexistent case."""
        res = await client.get("/api/cases/nonexistent-case-id/custody")
        assert res.status_code == 404


class TestCustodyEventContent:
    """Verify custody event content is accurate."""

    @pytest.mark.asyncio
    async def test_actor_is_system(self, client, analyzed_case_id):
        """All automated events should have actor 'System'."""
        res = await client.get(f"/api/cases/{analyzed_case_id}/custody")
        events = res.json()["events"]
        for evt in events:
            assert evt["actor"] == "System"

    @pytest.mark.asyncio
    async def test_evidence_acquired_has_sha256(self, client, analyzed_case_id):
        """Evidence Acquired event should contain the SHA-256 fingerprint."""
        res = await client.get(f"/api/cases/{analyzed_case_id}/custody")
        events = res.json()["events"]
        acquired = next(e for e in events if e["event_type"] == "Evidence Acquired")
        assert acquired["evidence_sha256"] is not None
        assert len(acquired["evidence_sha256"]) == 64

    @pytest.mark.asyncio
    async def test_analysis_events_no_sha256(self, client, analyzed_case_id):
        """Analysis start/completion events don't need SHA-256 (it's about the process, not the hash)."""
        res = await client.get(f"/api/cases/{analyzed_case_id}/custody")
        events = res.json()["events"]
        started = next(e for e in events if e["event_type"] == "Forensic Analysis Started")
        assert started["evidence_sha256"] is None
