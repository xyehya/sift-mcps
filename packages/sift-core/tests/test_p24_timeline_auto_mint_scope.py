"""P2.4 fail-on-revert: timeline auto-mint is scoped to type=="finding" ONLY.

`CaseManager.record_finding` auto-creates a linked timeline event when (and only
when) the finding's ``type`` is ``"finding"`` and it carries an
``event_timestamp``. The other finding types — ``exclusion``, ``conclusion``,
and ``attribution`` — are DELIBERATELY excluded from auto-minting even if an
``event_timestamp`` is supplied, because they describe a ruled-out possibility,
a synthesized judgement, or an actor attribution rather than a discrete observed
event that belongs on the chronological reconstruction (see the mint-site
comment in ``case_manager.py``).

This test pins that behavior. It fails if the type guard at the mint site is
loosened (e.g. reverted to ``if event_ts:``), which would silently start
polluting the timeline with non-events.
"""

from __future__ import annotations

import pytest
import sift_core.case_manager as cm
from sift_core.case_manager import CaseManager

CASE_UUID = "33333333-3333-3333-3333-333333333333"


def _audit_row(audit_id: str) -> dict:
    """A run_command (Axis-A evidence) audit row so a cited id resolves in the
    DB trail — record_finding rejects findings with no evidence trail upstream."""
    return {
        "audit_id": audit_id,
        "tool": "run_command",
        "backend": "sift-core",
        "evidence_refs": [],
        "audit_aliases": [],
        "envelope_event_id": "",
        "input_files": [],
        "result_summary": {},
        "params": {},
        "case_id": CASE_UUID,
    }


class _CapturingStore:
    """Minimal investigation store double capturing DB-authority upserts."""

    def __init__(self):
        self.findings: dict = {}
        self.timeline: dict = {}
        self.iocs: dict = {}
        self.todos: dict = {}
        self.order: list[str] = []

    def upsert_finding(self, case_id, item_id, payload, *, actor=None):
        if item_id not in self.findings:
            self.order.append(item_id)
        self.findings[item_id] = dict(payload)
        return {"applied": True}

    def upsert_timeline_event(self, case_id, item_id, payload, *, actor=None):
        self.timeline[item_id] = dict(payload)
        return {"applied": True}

    def upsert_ioc(self, case_id, item_id, payload, *, actor=None):
        self.iocs[item_id] = dict(payload)
        return {"applied": True}

    def upsert_todo(self, case_id, item_id, payload, *, actor=None):
        self.todos[item_id] = dict(payload)
        return {"applied": True}

    def list_findings(self, case_id):
        return list(self.findings.values())

    def list_timeline(self, case_id):
        return list(self.timeline.values())

    def list_iocs(self, case_id):
        return list(self.iocs.values())

    def list_todos(self, case_id):
        return list(self.todos.values())

    def last(self) -> dict:
        return self.findings[self.order[-1]]


@pytest.fixture
def db_manager(tmp_path, monkeypatch):
    from sift_core.active_case_context import AuthorityContext, use_active_case_context

    case_dir = tmp_path / "case-p24-db"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-p24-db\nstatus: active\n")
    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
    monkeypatch.delenv("SIFT_AUDIT_DIR", raising=False)
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    monkeypatch.setattr(
        "sift_core.investigation_store.resolve_case_metadata",
        lambda: {"case_id": "case-p24-db", "status": "open"},
    )
    store = _CapturingStore()
    monkeypatch.setattr(cm.CaseManager, "_investigation_store", lambda self: store)
    monkeypatch.setattr(
        "sift_core.investigation_store.list_audit_provenance_db",
        lambda cid: [_audit_row("rc-1"), _audit_row("rc-2"), _audit_row("rc-3")],
    )
    monkeypatch.setattr(
        "sift_core.investigation_store.list_sealed_evidence_db",
        lambda cid: [],
    )
    monkeypatch.setattr(cm, "_declared_reference_backends", lambda: [])
    ctx = AuthorityContext(
        case_id=CASE_UUID,
        case_key="case-p24-db",
        artifact_path=str(case_dir),
        db_active=True,
    )
    with use_active_case_context(ctx):
        yield CaseManager(), store


def _base(finding_type: str, *, audit_ids=None, **extra) -> dict:
    f = {
        "title": "t",
        "type": finding_type,
        "host": "WS01",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "LOW",
        "confidence_justification": "single corroborated source",
        # event_timestamp is supplied for EVERY type so the ONLY variable that
        # decides auto-minting is `type` — that is what pins the guard.
        "event_timestamp": "2026-06-10T00:00:00Z",
        "audit_ids": list(audit_ids or ["rc-1"]),
    }
    f.update(extra)
    return f


class TestAutoMintScopedToFinding:
    def test_finding_type_auto_mints_timeline(self, db_manager):
        """Positive control: type==finding WITH event_timestamp DOES mint.

        This proves the test can observe a mint at all — a fail-on-revert test
        that can never see the behavior it guards is theater.
        """
        mgr, store = db_manager
        res = mgr.record_finding(_base("finding"), examiner_override="alice")
        assert res["status"] == "STAGED", res
        assert res.get("timeline_event_id"), res
        assert len(store.timeline) == 1
        (event,) = store.timeline.values()
        assert event["auto_created_from"] == res["finding_id"]
        assert store.last().get("timeline_event_id") == res["timeline_event_id"]

    def test_exclusion_type_does_not_auto_mint_timeline(self, db_manager):
        mgr, store = db_manager
        res = mgr.record_finding(_base("exclusion"), examiner_override="alice")
        assert res["status"] == "STAGED", res
        # No timeline id surfaced on the agent-facing result...
        assert "timeline_event_id" not in res
        # ...and no timeline row was ever persisted to DB authority.
        assert store.timeline == {}
        # ...and the finding record itself carries no timeline linkage.
        assert "timeline_event_id" not in store.last()

    def test_conclusion_type_does_not_auto_mint_timeline(self, db_manager):
        mgr, store = db_manager
        res = mgr.record_finding(_base("conclusion"), examiner_override="alice")
        assert res["status"] == "STAGED", res
        assert "timeline_event_id" not in res
        assert store.timeline == {}
        assert "timeline_event_id" not in store.last()

    def test_attribution_type_does_not_auto_mint_timeline(self, db_manager):
        mgr, store = db_manager
        # Attribution requires 3+ audit_ids (FD-003) to validate.
        res = mgr.record_finding(
            _base("attribution", audit_ids=["rc-1", "rc-2", "rc-3"]),
            examiner_override="alice",
        )
        assert res["status"] == "STAGED", res
        assert "timeline_event_id" not in res
        assert store.timeline == {}
        assert "timeline_event_id" not in store.last()
