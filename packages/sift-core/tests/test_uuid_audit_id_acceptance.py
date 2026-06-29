"""Gateway canonical UUID citations resolve in DB-authority provenance.

The gateway envelope middleware assigns each tool call an ``envelope_event_id``
(a UUID) and proxied add-on tools return that UUID as their canonical audit_id.
Agents cite the UUID. In the DB-authority model the cited UUID resolves when a
``list_audit_provenance_db`` row carries it as ``audit_id`` / an alias /
``envelope_event_id``; otherwise the finding is rejected (fail-closed). Malformed
ids never correspond to a gateway-written row, so they never resolve.
"""

from __future__ import annotations

import pytest
import sift_core.case_manager as cm
from sift_core.active_case_context import AuthorityContext, use_active_case_context
from sift_core.case_manager import CaseManager

ENVELOPE_UUID = "550e8400-e29b-41d4-a716-446655440000"
CASE_UUID = "33333333-3333-3333-3333-333333333333"


def _row_with_uuid(uuid: str) -> dict:
    """A proxied add-on result row whose canonical is the native id and whose
    envelope/alias is the UUID the agent receives."""
    return {
        "audit_id": "forensicrag-alice-20260625-001",
        "tool": "kb_search_knowledge",
        "backend": "forensic-rag-mcp",
        "evidence_refs": [],
        "audit_aliases": [uuid],
        "envelope_event_id": uuid,
        "input_files": [],
        "result_summary": {},
        "params": {},
        "case_id": CASE_UUID,
    }


def _finding_with_audit_id(audit_id: str) -> dict:
    return {
        "title": "Adversary lateral movement detected",
        "type": "finding",
        "host": "SRL-FORGE",
        "observation": "timeline query revealed RDP pivot",
        "interpretation": "attacker pivoted to internal host",
        "confidence": "MEDIUM",
        "confidence_justification": "corroborated by a knowledge-base lookup",
        "event_timestamp": "2026-06-23T10:00:00Z",
        "audit_ids": [audit_id],
    }


class _InMemoryStore:
    def __init__(self):
        self.findings: dict = {}

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
    case_dir = tmp_path / "case-uuid-prov"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-uuid-prov\nstatus: active\n")
    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
    monkeypatch.delenv("SIFT_AUDIT_DIR", raising=False)
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)

    state: dict = {"audit": []}
    store = _InMemoryStore()
    monkeypatch.setattr(cm.CaseManager, "_investigation_store", lambda self: store)
    monkeypatch.setattr(
        "sift_core.investigation_store.resolve_case_metadata",
        lambda: {"case_id": "case-uuid-prov", "status": "open"},
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
        case_key="case-uuid-prov",
        artifact_path=str(case_dir),
        db_active=True,
    )
    with use_active_case_context(ctx):
        yield CaseManager(), store, state


class TestUUIDAccepted:
    def test_uuid_resolving_in_db_is_staged(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = [_row_with_uuid(ENVELOPE_UUID)]
        res = mgr.record_finding(
            _finding_with_audit_id(ENVELOPE_UUID), examiner_override="alice"
        )
        assert res["status"] == "STAGED", res
        staged = next(iter(store.findings.values()))
        assert ENVELOPE_UUID in staged.get("audit_ids", [])

    def test_uuid_case_insensitive_match(self, db_manager):
        """The row carries the lowercase UUID; the agent cites it (UUIDs are
        compared by exact string, the gateway emits canonical lowercase)."""
        mgr, store, state = db_manager
        state["audit"] = [_row_with_uuid(ENVELOPE_UUID)]
        res = mgr.record_finding(
            _finding_with_audit_id(ENVELOPE_UUID), examiner_override="alice"
        )
        assert res["status"] == "STAGED", res

    def test_uuid_credits_grounding_backend(self, db_manager):
        """The UUID-aliased row is a forensic-rag result -> grounding credit."""
        mgr, store, state = db_manager
        state["audit"] = [_row_with_uuid(ENVELOPE_UUID)]
        res = mgr.record_finding(
            _finding_with_audit_id(ENVELOPE_UUID), examiner_override="alice"
        )
        assert res["status"] == "STAGED", res
        staged = next(iter(store.findings.values()))
        assert "forensic-rag-mcp" in staged["grounding"]["sources_consulted"]


class TestUUIDRejectedWhenNotInDB:
    def test_uuid_absent_from_db_rejected(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = []  # the UUID does not resolve
        res = mgr.record_finding(
            _finding_with_audit_id(ENVELOPE_UUID), examiner_override="alice"
        )
        assert res["status"] == "REJECTED", res
        assert "no evidence trail" in res["error"]


class TestMalformedIdsRejected:
    @pytest.mark.parametrize(
        "bad_id",
        [
            "../etc/passwd",
            "/etc/shadow",
            "550e8400-e29b-41d4-a716-' OR '1'='1",
            "550e8400-e29b-41d4-a716-446655440000-extra",
            "a" * 300,
        ],
    )
    def test_malformed_id_never_resolves(self, db_manager, bad_id):
        """A malformed/injection id cannot be a gateway-written row, so a finding
        citing only it is rejected (fail-closed) — even though a real row exists
        for a different id."""
        mgr, store, state = db_manager
        state["audit"] = [_row_with_uuid(ENVELOPE_UUID)]
        res = mgr.record_finding(
            _finding_with_audit_id(bad_id), examiner_override="alice"
        )
        assert res["status"] == "REJECTED", res
        assert "no evidence trail" in res["error"]
