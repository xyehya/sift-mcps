"""Digit-bearing ingest-id citations resolve as provenance (Gap B regression).

The opensearch ingest scheme embeds the worker PID in the audit-id prefix:
``opensearchingest<PID>-sift-service-YYYYMMDD-NNN`` — e.g.
``opensearchingest1018805-sift-service-20260623-040``. In the DB-authority model
a cited id is accepted iff it resolves to a gateway-written
``app.audit_events`` row (`list_audit_provenance_db`), matched against
{audit_id} ∪ audit_aliases ∪ {envelope_event_id}. There is no scheme/format
regex gate anymore — DB membership is the authority, so a digit-bearing prefix
is no longer a special case, and a forged/malformed id simply never resolves.
"""

from __future__ import annotations

import pytest
import sift_core.case_manager as cm
from sift_core.active_case_context import AuthorityContext, use_active_case_context
from sift_core.case_manager import CaseManager

INGEST_ID = "opensearchingest1018805-sift-service-20260623-040"
CASE_UUID = "44444444-4444-4444-4444-444444444444"


def _audit_row(audit_id, *, tool="opensearch_ingest", backend="opensearch-mcp"):
    return {
        "audit_id": audit_id,
        "tool": tool,
        "backend": backend,
        "evidence_refs": [],
        "audit_aliases": [audit_id],
        "envelope_event_id": "",
        "input_files": [],
        "result_summary": {},
        "params": {},
        "case_id": CASE_UUID,
    }


def _finding(audit_ids: list[str]) -> dict:
    return {
        "title": "Ingested-evidence finding",
        "type": "finding",
        "host": "WS01",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "MEDIUM",
        "confidence_justification": "cited an ingest result",
        "event_timestamp": "2026-06-23T00:00:00Z",
        "audit_ids": list(audit_ids),
    }


class _InMemoryStore:
    def __init__(self):
        self.findings = {}

    def upsert_finding(self, case_id, item_id, payload, *, actor=None):
        self.findings[item_id] = dict(payload)
        return {"applied": True}

    def upsert_timeline_event(self, case_id, item_id, payload, *, actor=None):
        return {"applied": True}

    def upsert_ioc(self, case_id, item_id, payload, *, actor=None):
        return {"applied": True}

    def upsert_todo(self, case_id, todo_id, payload, *, actor=None):
        return {"applied": True}

    def list_findings(self, case_id):
        return list(self.findings.values())

    def list_timeline(self, case_id):
        return []

    def list_iocs(self, case_id):
        return []

    def list_todos(self, case_id):
        return []


@pytest.fixture
def db_manager(tmp_path, monkeypatch):
    case_dir = tmp_path / "case-ingest-cite"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-ingest-cite\nstatus: active\n")
    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
    monkeypatch.delenv("SIFT_AUDIT_DIR", raising=False)
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)

    state: dict = {"audit": []}
    store = _InMemoryStore()
    monkeypatch.setattr(cm.CaseManager, "_investigation_store", lambda self: store)
    monkeypatch.setattr(
        "sift_core.investigation_store.resolve_case_metadata",
        lambda: {"case_id": "case-ingest-cite", "status": "open"},
    )
    monkeypatch.setattr(
        "sift_core.investigation_store.list_audit_provenance_db",
        lambda cid: list(state["audit"]),
    )
    monkeypatch.setattr(
        "sift_core.investigation_store.list_sealed_evidence_db", lambda cid: []
    )
    monkeypatch.setattr(cm, "_declared_reference_backends", lambda: ["forensic-rag-mcp"])

    ctx = AuthorityContext(
        case_id=CASE_UUID,
        case_key="case-ingest-cite",
        artifact_path=str(case_dir),
        db_active=True,
    )
    with use_active_case_context(ctx):
        yield CaseManager(), store, state


def test_ingest_id_in_db_trail_is_accepted(db_manager):
    """A digit-bearing ingest id that the DB recorded resolves and stages, and an
    opensearch_* citation engages Axis A (REFERENCED)."""
    mgr, store, state = db_manager
    state["audit"] = [_audit_row(INGEST_ID, tool="opensearch_ingest")]
    res = mgr.record_finding(_finding([INGEST_ID]), examiner_override="alice")
    assert res["status"] == "STAGED", res
    f = next(iter(store.findings.values()))
    assert f["provenance_grade"] == "REFERENCED"


def test_ingest_id_not_in_db_trail_is_rejected(db_manager):
    """Fail-closed: an ingest id the DB does NOT know does not resolve -> REJECTED."""
    mgr, store, state = db_manager
    state["audit"] = []  # DB knows nothing
    res = mgr.record_finding(_finding([INGEST_ID]), examiner_override="alice")
    assert res["status"] == "REJECTED", res
    assert "no evidence trail" in res["error"]


def test_injection_prefix_id_never_resolves(db_manager):
    """A malformed/injection id cannot be a gateway-written row, so it never
    resolves and a finding citing only it is rejected."""
    mgr, store, state = db_manager
    state["audit"] = [_audit_row(INGEST_ID)]  # a real row exists, but...
    res = mgr.record_finding(
        _finding(["../etc-passwd-20260101-001"]), examiner_override="alice"
    )
    assert res["status"] == "REJECTED", res
    assert "no evidence trail" in res["error"]
