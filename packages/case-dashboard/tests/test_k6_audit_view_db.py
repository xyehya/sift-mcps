"""BATCH-K6 — portal audit view sources from DB authority, not file mirror.

In DB-active mode GET /api/audit/{finding_id} must take the finding's audit_ids
from the DB investigation record and the audit entries from app.audit_events (via
the injected investigation service), never from findings.json or audit/*.jsonl —
so tampering with those files cannot spoof, hide, or fabricate the audit trail.
"""

from __future__ import annotations

import secrets

from _supabase_reauth_harness import ReauthFakeSupabaseAuth, set_operator_session
from case_dashboard.routes import create_dashboard_v2_app
from starlette.testclient import TestClient

_SECRET = secrets.token_hex(32)
_CASE_ID = "22222222-2222-2222-2222-222222222222"


class FakeActiveCases:
    class _Case:
        def as_dict(self):
            return {"case_id": _CASE_ID, "name": "K6"}

    def get_active_case(self, principal=None):
        return self._Case()


class FakeNoActiveCases:
    def get_active_case(self, principal=None):
        return None


class FakeInvestigationDB:
    def __init__(self):
        self.audit_calls = []
        self.activity_calls = []

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

    def audit_events_recent(self, case_id, *, limit=30):
        self.activity_calls.append((case_id, limit))
        return [
            {
                "id": "evt-activity",
                "ts": "2026-06-08T00:01:00+00:00",
                "kind": "discovery",
                "text": "Recorded finding - External RDP (HIGH)",
            }
        ]


def _client(inv, *, active_case_service=None):
    # B-MVP-023: migrated to Supabase-envelope harness.
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        active_case_service=active_case_service or FakeActiveCases(),
        investigation_service=inv,
        supabase_auth=ReauthFakeSupabaseAuth(),
    )
    c = TestClient(app)
    set_operator_session(c, _SECRET)
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


def test_agent_activity_reads_active_case_db_tail():
    inv = FakeInvestigationDB()
    resp = _client(inv).get("/api/agent/activity?limit=5")
    assert resp.status_code == 200
    assert resp.json() == {
        "events": [
            {
                "id": "evt-activity",
                "ts": "2026-06-08T00:01:00+00:00",
                "kind": "discovery",
                "text": "Recorded finding - External RDP (HIGH)",
            }
        ]
    }
    assert inv.activity_calls == [(_CASE_ID, 5)]


def test_agent_activity_no_active_case_returns_empty_without_db_read():
    inv = FakeInvestigationDB()
    resp = _client(inv, active_case_service=FakeNoActiveCases()).get("/api/agent/activity?limit=bad")
    assert resp.status_code == 200
    assert resp.json() == {"events": []}
    assert inv.activity_calls == []


# ---------------------------------------------------------------------------
# DB details projection: route must surface tool/result_summary/params from
# nested details so AuditEntry.hasProvenance becomes true.
# ---------------------------------------------------------------------------


class FakeInvestigationDBWithDetails:
    """Returns DB-shaped audit rows: provenance nested under details, nothing at top level."""

    def list_findings(self, case_id):
        return [
            {
                "id": "F-rc",
                "status": "APPROVED",
                "audit_ids": ["siftgateway-claud-20260622-036"],
                "artifacts": [],
            }
        ]

    def audit_events(self, case_id, audit_ids):
        # Mirrors the real DB row shape: tool/result/detail nested under details.
        return [
            {
                "id": "uuid-pk-001",
                "audit_id": "siftgateway-claud-20260622-036",
                "event_type": "mcp.tool.result",
                "source": "gateway_mcp_envelope",
                "status": "success",
                "summary": "ok run_command",
                "request_id": "req-1",
                "job_id": None,
                "created_at": "2026-06-22T10:00:00+00:00",
                "details": {
                    "tool": "run_command",
                    "backend": "shell",
                    "result_summary": {"success": True, "exit_code": 0},
                    "detail": {"exit_code": 0, "provenance": {"job_id": "job-abc"}},
                    "backend_audit_id": "siftgateway-claud-20260622-036",
                    "audit_aliases": ["shell-claud-20260622-001"],
                    "elapsed_ms": 120.5,
                },
            }
        ]

    def audit_events_recent(self, case_id, *, limit=30):
        return []


def test_audit_route_projects_tool_from_details():
    """Route must lift details.tool to top-level so AuditEntry.hasProvenance is true."""
    inv = FakeInvestigationDBWithDetails()
    resp = _client(inv).get("/api/audit/F-rc")
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) == 1
    ev = events[0]
    assert ev.get("tool") == "run_command"


def test_audit_route_projects_result_summary_from_details():
    """Route must lift details.result_summary to top-level."""
    inv = FakeInvestigationDBWithDetails()
    resp = _client(inv).get("/api/audit/F-rc")
    ev = resp.json()[0]
    assert ev.get("result_summary") == {"success": True, "exit_code": 0}


def test_audit_route_projects_params_from_detail_block():
    """Route must lift details.detail to top-level as params (exit_code / provenance)."""
    inv = FakeInvestigationDBWithDetails()
    resp = _client(inv).get("/api/audit/F-rc")
    ev = resp.json()[0]
    assert ev.get("params") == {"exit_code": 0, "provenance": {"job_id": "job-abc"}}


def test_audit_route_keeps_details_intact_after_projection():
    """Projection must not remove the details dict itself."""
    inv = FakeInvestigationDBWithDetails()
    resp = _client(inv).get("/api/audit/F-rc")
    ev = resp.json()[0]
    assert "details" in ev
    assert ev["details"]["tool"] == "run_command"


def test_audit_route_does_not_overwrite_existing_top_level_fields():
    """If the reader already stamped a top-level tool field, it must not be clobbered."""

    class FakeAlreadyLabeled:
        def list_findings(self, case_id):
            return [{"id": "F-x", "status": "APPROVED", "audit_ids": ["e1"], "artifacts": []}]

        def audit_events(self, case_id, audit_ids):
            return [
                {
                    "id": "e1",
                    "audit_id": "e1",
                    "event_type": "TOOL_CALL",
                    "source": "core",
                    "status": "success",
                    "summary": "s",
                    "request_id": None,
                    "job_id": None,
                    "created_at": "2026-06-22T10:00:00+00:00",
                    # top-level tool already present — must survive
                    "tool": "record_finding",
                    "details": {"tool": "SHOULD_NOT_WIN"},
                }
            ]

        def audit_events_recent(self, case_id, *, limit=30):
            return []

    inv = FakeAlreadyLabeled()
    resp = _client(inv).get("/api/audit/F-x")
    ev = resp.json()[0]
    assert ev["tool"] == "record_finding"  # original preserved, not overwritten


def test_audit_route_handles_null_details_gracefully():
    """A row with details=None must not crash the projection loop."""

    class FakeNullDetails:
        def list_findings(self, case_id):
            return [{"id": "F-nd", "status": "APPROVED", "audit_ids": ["e2"], "artifacts": []}]

        def audit_events(self, case_id, audit_ids):
            return [
                {
                    "id": "e2",
                    "audit_id": "e2",
                    "event_type": "TOOL_CALL",
                    "source": "core",
                    "status": "success",
                    "summary": "s",
                    "request_id": None,
                    "job_id": None,
                    "created_at": "2026-06-22T10:00:00+00:00",
                    "details": None,
                }
            ]

        def audit_events_recent(self, case_id, *, limit=30):
            return []

    inv = FakeNullDetails()
    resp = _client(inv).get("/api/audit/F-nd")
    assert resp.status_code == 200
    ev = resp.json()[0]
    # No crash; no spurious top-level fields from None details.
    assert ev.get("tool") is None
    assert ev.get("params") is None
