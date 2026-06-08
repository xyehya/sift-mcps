"""BATCH-K2 — Gateway InvestigationService DB-authority behavior.

Verifies the Gateway-side adapter:
  * defaults to legacy_sync=False so case JSON is never re-imported into DB rows
    (file tampering cannot enter the read model);
  * delegates list/apply_review/report_inputs to the core PostgresInvestigationStore.
"""

from __future__ import annotations

from sift_gateway.portal_services import InvestigationService


class _RecordingStore:
    def __init__(self):
        self.calls = []

    def list_findings(self, case_id):
        self.calls.append(("list_findings", case_id))
        return [{"id": "F-1", "status": "DRAFT"}]

    def apply_review(self, case_id, actions, *, examiner, reauth_audit_event_id, actor=None):
        self.calls.append(("apply_review", case_id, examiner, reauth_audit_event_id,
                           [a.item_id for a in actions], [a.action for a in actions]))

        class _R:
            def as_dict(self_inner):
                return {"approved": 1, "rejected": 0, "edited": 0, "skipped": []}

        return _R()

    def report_inputs(self, case_id):
        self.calls.append(("report_inputs", case_id))
        return {"findings": [{"id": "F-1", "status": "APPROVED"}], "timeline": [], "iocs": []}


def _service(store):
    svc = InvestigationService("postgresql://fake")
    svc._store = lambda: store  # type: ignore[assignment]
    return svc


def test_legacy_sync_off_by_default():
    svc = InvestigationService("postgresql://fake")
    assert svc._legacy_sync is False


def test_sync_findings_noop_without_legacy_sync(monkeypatch):
    svc = InvestigationService("postgresql://fake")
    called = {"read": False}

    def _boom(*a, **k):
        called["read"] = True
        return [{"id": "F-evil"}]

    monkeypatch.setattr(svc, "_read_json_list", _boom)
    svc._sync_findings("case-1")
    svc._sync_timeline("case-1")
    svc._sync_iocs("case-1")
    svc._sync_todos("case-1")
    assert called["read"] is False  # JSON never read in DB-active default


def test_legacy_sync_opt_in_reads_json(monkeypatch):
    svc = InvestigationService("postgresql://fake", legacy_sync=True)
    assert svc._legacy_sync is True


def test_list_findings_delegates_to_store():
    store = _RecordingStore()
    svc = _service(store)
    rows = svc.list_findings("case-1")
    assert rows[0]["id"] == "F-1"
    assert ("list_findings", "case-1") in store.calls


def test_apply_review_parses_actions_and_delegates():
    store = _RecordingStore()
    svc = _service(store)
    result = svc.apply_review(
        case_id="case-1",
        actions=[
            {"id": "F-1", "action": "approve"},
            {"action": "reject"},  # missing id -> dropped
            {"id": "F-2", "action": "reject", "reason": "noise"},
        ],
        examiner="alice",
        reauth_audit_event_id="evt-9",
    )
    assert result == {"approved": 1, "rejected": 0, "edited": 0, "skipped": []}
    call = next(c for c in store.calls if c[0] == "apply_review")
    # Only the two well-formed actions reach the store, in order.
    assert call[4] == ["F-1", "F-2"]
    assert call[2] == "alice" and call[3] == "evt-9"


def test_report_inputs_delegates_to_store():
    store = _RecordingStore()
    svc = _service(store)
    inputs = svc.report_inputs("case-1")
    assert inputs["findings"][0]["status"] == "APPROVED"
    assert ("report_inputs", "case-1") in store.calls
