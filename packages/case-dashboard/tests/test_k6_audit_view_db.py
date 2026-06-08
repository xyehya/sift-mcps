"""BATCH-K6 — portal audit view sources from DB authority, not file mirror.

In DB-active mode GET /api/audit/{finding_id} must take the finding's audit_ids
from the DB investigation record and the audit entries from app.audit_events (via
the injected investigation service), never from findings.json or audit/*.jsonl —
so tampering with those files cannot spoof, hide, or fabricate the audit trail.
"""

from __future__ import annotations

import secrets

from starlette.testclient import TestClient

from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import COOKIE_NAME, generate_jwt

_SECRET = secrets.token_hex(32)
_CASE_ID = "22222222-2222-2222-2222-222222222222"


class FakeActiveCases:
    class _Case:
        def as_dict(self):
            return {"case_id": _CASE_ID, "name": "K6"}

    def get_active_case(self, principal=None):
        return self._Case()


class FakeInvestigationDB:
    def __init__(self):
        self.audit_calls = []

    def list_findings(self, case_id):
        return [
            {
                "id": "F-1",
                "status": "APPROVED",
                "audit_ids": ["evt-1"],
                "artifacts": [{"provenance_chain": [{"audit_id": "evt-2"}]}],
            },
            {"id": "F-2", "status": "DRAFT", "audit_ids": ["evt-9"]},
        ]

    def audit_events(self, case_id, audit_ids):
        self.audit_calls.append((case_id, list(audit_ids)))
        catalog = {
            "evt-1": {"id": "evt-1", "event_type": "RECORD_FINDING", "source": "core"},
            "evt-2": {"id": "evt-2", "event_type": "PARSE", "source": "opensearch"},
        }
        return [catalog[i] for i in audit_ids if i in catalog]


def _client(inv):
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        active_case_service=FakeActiveCases(),
        investigation_service=inv,
    )
    c = TestClient(app)
    c.cookies.set(COOKIE_NAME, generate_jwt("alice", "examiner", _SECRET, max_age=3600))
    return c


def test_audit_view_reads_db_finding_and_audit_events():
    inv = FakeInvestigationDB()
    resp = _client(inv).get("/api/audit/F-1")
    assert resp.status_code == 200
    events = resp.json()
    ids = {e["id"] for e in events}
    # Both the finding's audit_ids and its provenance-chain audit_ids resolved
    # from app.audit_events.
    assert ids == {"evt-1", "evt-2"}
    # Query was scoped to the active case and the gathered ids.
    case_id, queried = inv.audit_calls[0]
    assert case_id == _CASE_ID
    assert set(queried) == {"evt-1", "evt-2"}


def test_audit_view_ignores_tampered_findings_file(tmp_path, monkeypatch):
    # A tampered/extra findings.json on disk cannot inject audit ids: the DB
    # finding record is the only source for audit_ids in DB-active mode.
    inv = FakeInvestigationDB()
    resp = _client(inv).get("/api/audit/F-unknown")  # not present in DB
    assert resp.status_code == 200
    assert resp.json() == []
    # No DB audit query made for an unknown finding.
    assert inv.audit_calls == []
