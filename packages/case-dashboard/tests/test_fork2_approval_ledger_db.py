"""FORK-2 — approval-commit ledger is DB-only (file HMAC ledger retired).

Verifies that the portal DB-authority commit path (`_apply_delta_db`) appends an
approval-commit event to the DB hash-chain ledger
(`sift_core.verification.append_approval_commit_event_db`) for each APPROVED
item, binding it to the DB content_hash and the re-auth audit event id — and that
NO file HMAC ledger is written. The DB RPC/trigger SQL is exercised against live
Postgres separately (see the unit report).
"""

from __future__ import annotations

import json

import case_dashboard.routes as routes_mod
import pytest

_CASE_ID = "11111111-1111-1111-1111-111111111111"


class FakeActiveCases:
    class _Case:
        def as_dict(self):
            return {"case_id": _CASE_ID, "name": "FORK2"}

    def get_active_case(self, principal=None):
        return self._Case()


class FakeEvidenceDB:
    def record_reauth_event(self, *, case_id, actor, examiner, action):
        return "audit-evt-FORK2"


class FakeInvestigationDB:
    def __init__(self):
        self.rows = {
            "F-1": {"id": "F-1", "status": "APPROVED", "content_hash": "sha256:" + "1" * 64},
            "F-2": {"id": "F-2", "status": "REJECTED", "content_hash": "sha256:" + "2" * 64},
            "T-9": {"id": "T-9", "status": "APPROVED", "content_hash": "sha256:" + "9" * 64},
        }

    def apply_review(self, *, case_id, actions, examiner, reauth_audit_event_id, actor=None):
        approved = sum(1 for a in actions if a["action"] == "approve")
        rejected = sum(1 for a in actions if a["action"] == "reject")
        return {"approved": approved, "rejected": rejected, "edited": 0, "skipped": []}

    def list_findings(self, case_id):
        return [r for r in self.rows.values() if not r["id"].startswith("T-")]

    def list_timeline(self, case_id):
        return [r for r in self.rows.values() if r["id"].startswith("T-")]


class _Req:
    def __init__(self):
        class _State:
            pass

        self.state = _State()


@pytest.fixture
def patched(monkeypatch):
    inv = FakeInvestigationDB()
    appended: list[dict] = []

    def _fake_append(case_id, *, item_id, item_type, content_hash, action="APPROVED",
                     reauth_audit_event_id=None, approved_by=None, **kw):
        appended.append({
            "case_id": case_id, "item_id": item_id, "item_type": item_type,
            "content_hash": content_hash, "action": action,
            "reauth": reauth_audit_event_id, "approved_by": approved_by,
        })
        return f"evt-{item_id}"

    monkeypatch.setattr(routes_mod, "_INVESTIGATION_DB", inv)
    monkeypatch.setattr(routes_mod, "_EVIDENCE_DB", FakeEvidenceDB())
    monkeypatch.setattr(routes_mod, "_ACTIVE_CASES", FakeActiveCases())
    monkeypatch.setattr(routes_mod, "_request_principal", lambda r: {"principal_type": "user"})
    monkeypatch.setattr(routes_mod, "append_approval_commit_event_db", _fake_append)
    return inv, appended


def test_apply_delta_db_appends_db_ledger_for_approved(patched, tmp_path):
    inv, appended = patched
    delta = {
        "items": [
            {"id": "F-1", "action": "approve"},
            {"id": "F-2", "action": "reject", "rejection_reason": "noise"},
            {"id": "T-9", "action": "approve"},
        ],
    }
    (tmp_path / "pending-reviews.json").write_text(json.dumps(delta))

    result = routes_mod._apply_delta_db(_Req(), tmp_path, "alice", inv.apply_review)

    assert result["authority"] == "db"
    assert result["approved"] == 2
    # Only the two APPROVED items produce ledger events (the REJECTED one does not).
    ids = sorted(a["item_id"] for a in appended)
    assert ids == ["F-1", "T-9"]
    by_id = {a["item_id"]: a for a in appended}
    # Each event binds to the DB content_hash and the re-auth audit event id.
    assert by_id["F-1"]["content_hash"] == "sha256:" + "1" * 64
    assert by_id["F-1"]["item_type"] == "finding"
    assert by_id["T-9"]["content_hash"] == "sha256:" + "9" * 64
    assert by_id["T-9"]["item_type"] == "timeline"
    for a in appended:
        assert a["reauth"] == "audit-evt-FORK2"
        assert a["approved_by"] == "alice"
        assert a["action"] == "APPROVED"
        assert a["case_id"] == _CASE_ID
    # Staged delta cleared.
    assert not (tmp_path / "pending-reviews.json").exists()
    # No file ledger module is reachable from the commit path anymore.
    assert not hasattr(routes_mod, "write_ledger_entry")
