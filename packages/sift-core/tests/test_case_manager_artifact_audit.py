"""record_finding artifact audit_id custody (DB-authority model).

Every artifact must cite an audit_id that resolves in the DB audit trail
(`list_audit_provenance_db`, matched against {audit_id} ∪ audit_aliases ∪
{envelope_event_id}); the `rc-<audit_id>` receipt form canonicalizes to the base
id. A missing or unresolvable id is REJECTED (fail-closed). There is no file-mode
JSONL scan and no multi-dir candidate search anymore — the single reader is the
DB trail.
"""

from __future__ import annotations

import pytest
import sift_core.case_manager as cm
from sift_core.active_case_context import AuthorityContext, use_active_case_context
from sift_core.case_manager import CaseManager

CASE_UUID = "22222222-2222-2222-2222-222222222222"
AUDIT_ID = "siftcore-alice-20260610-001"


def _audit_row(audit_id, *, tool="run_command", backend="sift-core", evidence_refs=None):
    return {
        "audit_id": audit_id,
        "tool": tool,
        "backend": backend,
        "evidence_refs": list(evidence_refs or []),
        "audit_aliases": [audit_id],
        "envelope_event_id": "",
        "input_files": [],
        "result_summary": {},
        "params": {},
        "case_id": CASE_UUID,
    }


def _finding(audit_id: str) -> dict:
    return {
        "title": "Suspicious logon burst",
        "type": "finding",
        "host": "WS01",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "MEDIUM",
        "confidence_justification": "single corroborated source",
        "event_timestamp": "2026-06-10T00:00:00Z",
        "artifacts": [
            {
                "source": "evidence/auth.log",
                "extraction": "grep failed logons",
                "content": "Failed password for root",
                "audit_id": audit_id,
            }
        ],
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
    case_dir = tmp_path / "case-aut2-db"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-aut2-db\nstatus: active\n")
    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
    monkeypatch.delenv("SIFT_AUDIT_DIR", raising=False)
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)

    state: dict = {"audit": []}
    store = _InMemoryStore()
    monkeypatch.setattr(cm.CaseManager, "_investigation_store", lambda self: store)
    monkeypatch.setattr(
        "sift_core.investigation_store.resolve_case_metadata",
        lambda: {"case_id": "case-aut2-db", "status": "open"},
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
        case_key="case-aut2-db",
        artifact_path=str(case_dir),
        db_active=True,
    )
    with use_active_case_context(ctx):
        yield CaseManager(), store, state


class TestArtifactCustody:
    def test_accepts_audit_id_resolved_in_db_trail(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = [_audit_row(AUDIT_ID)]
        res = mgr.record_finding(_finding(AUDIT_ID), examiner_override="alice")
        assert res["status"] == "STAGED", res

    def test_accepts_rc_receipt_form_and_canonicalizes(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = [_audit_row(AUDIT_ID)]
        res = mgr.record_finding(_finding(f"rc-{AUDIT_ID}"), examiner_override="alice")
        assert res["status"] == "STAGED", res
        staged = next(iter(store.findings.values()))
        assert staged["artifacts"][0]["audit_id"] == AUDIT_ID  # rc- canonicalized

    def test_rejects_unknown_audit_id_with_recent_hint(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = [_audit_row(AUDIT_ID)]
        res = mgr.record_finding(
            _finding("siftcore-alice-20260610-999"), examiner_override="alice"
        )
        assert res["status"] == "REJECTED"
        assert "not found in audit trail" in res["error"]
        assert AUDIT_ID in res["error"]  # lists a known-good recent id

    def test_rejects_missing_audit_id(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = [_audit_row(AUDIT_ID)]
        finding = _finding(AUDIT_ID)
        finding["artifacts"][0].pop("audit_id")
        res = mgr.record_finding(finding, examiner_override="alice")
        assert res["status"] == "REJECTED"
        assert "missing audit_id" in res["error"]

    def test_unknown_id_rejected_when_trail_empty(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = []  # fail-closed: nothing resolves
        res = mgr.record_finding(_finding(AUDIT_ID), examiner_override="alice")
        assert res["status"] == "REJECTED"
        assert "not found in audit trail" in res["error"]

    def test_db_read_error_fails_closed(self, db_manager, monkeypatch):
        mgr, store, state = db_manager

        def boom(cid):
            raise RuntimeError("db down")

        monkeypatch.setattr(
            "sift_core.investigation_store.list_audit_provenance_db", boom
        )
        res = mgr.record_finding(_finding(AUDIT_ID), examiner_override="alice")
        assert res["status"] == "REJECTED"
