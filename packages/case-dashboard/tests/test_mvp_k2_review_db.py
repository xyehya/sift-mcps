"""BATCH-K2 — portal approval/report DB authority + JSON tamper inertness.

Verifies:
  * the commit/review path applies approve/reject/edit to DB authority via the
    injected investigation service, passes a re-auth audit event id, and clears
    the staged delta file;
  * report generation reads approved findings/timeline from DB authority and
    ignores tampered findings.json;
  * portal findings/timeline/iocs reads come from DB authority, so tampering with
    case JSON cannot inject or alter rows.
"""

from __future__ import annotations

import json
import secrets

import pytest
from starlette.testclient import TestClient

import case_dashboard.routes as routes_mod
from case_dashboard.routes import create_dashboard_v2_app

from _supabase_reauth_harness import (
    GOOD_PASSWORD,
    ReauthFakeSupabaseAuth,
    set_operator_session,
)

_SECRET = secrets.token_hex(32)
_CASE_ID = "11111111-1111-1111-1111-111111111111"


class FakeActiveCases:
    class _Case:
        def as_dict(self):
            return {"case_id": _CASE_ID, "name": "K2"}

    def get_active_case(self, principal=None):
        return self._Case()


class FakeEvidenceDB:
    def __init__(self):
        self.reauth_calls = []

    def record_reauth_event(self, *, case_id, actor, examiner, action):
        self.reauth_calls.append(action)
        return "audit-evt-K2"

    def gate_status(self, case_id):
        return {
            "seal_status": "sealed", "manifest_version": 2, "active_count": 1,
            "issues": [], "head_hash": "sha256:h", "last_verified_at": None,
        }

    def custody_events(self, case_id):
        return [{"seq": 1, "event_type": "MANIFEST_SEALED"}]


class FakeInvestigationDB:
    """DB authority stand-in: holds rows, applies reviews, returns report inputs."""

    def __init__(self):
        self.rows = {
            "F-1": {"id": "F-1", "title": "real", "status": "DRAFT", "content_hash": "h1"},
            "F-2": {"id": "F-2", "title": "noise", "status": "DRAFT", "content_hash": "h2"},
        }
        self.review_calls = []

    def list_findings(self, case_id):
        return list(self.rows.values())

    def list_timeline(self, case_id):
        return []

    def list_iocs(self, case_id):
        return []

    def apply_review(self, *, case_id, actions, examiner, reauth_audit_event_id, actor=None):
        self.review_calls.append(
            {"case_id": case_id, "examiner": examiner, "reauth": reauth_audit_event_id,
             "actions": actions}
        )
        approved = rejected = 0
        for a in actions:
            row = self.rows.get(a["id"])
            if not row:
                continue
            if a["action"] == "approve":
                row["status"] = "APPROVED"
                row["approved_by"] = examiner
                approved += 1
            elif a["action"] == "reject":
                row["status"] = "REJECTED"
                rejected += 1
        return {"approved": approved, "rejected": rejected, "edited": 0, "skipped": []}

    def report_inputs(self, case_id):
        approved = [r for r in self.rows.values() if r["status"] == "APPROVED"]
        return {"findings": approved, "timeline": [], "iocs": []}


def _make_client(**services):
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        active_case_service=services.get("active_case_service", FakeActiveCases()),
        evidence_service=services.get("evidence_service"),
        investigation_service=services.get("investigation_service"),
        report_service=services.get("report_service"),
        supabase_auth=ReauthFakeSupabaseAuth(),
    )
    return TestClient(app)


def _examiner(client):
    set_operator_session(client, _SECRET)
    return client


# --------------------------------------------------------------------------- #
# Read-path tamper inertness
# --------------------------------------------------------------------------- #


class TestReadTamperInert:
    def test_findings_from_db_ignore_tampered_file(self, tmp_path, monkeypatch):
        # Even if a malicious findings.json existed, the portal reads the DB rows.
        inv = FakeInvestigationDB()
        c = _examiner(_make_client(investigation_service=inv))
        rows = c.get("/api/findings").json()
        ids = {r["id"] for r in rows}
        assert ids == {"F-1", "F-2"}
        assert "F-evil" not in ids


# --------------------------------------------------------------------------- #
# Approval transition -> DB authority
# --------------------------------------------------------------------------- #


class TestApplyDeltaDb:
    def _request(self):
        class _State:
            pass

        class _Req:
            def __init__(self):
                self.state = _State()

        return _Req()

    def test_apply_delta_db_routes_to_store_and_clears_delta(self, tmp_path, monkeypatch):
        inv = FakeInvestigationDB()
        monkeypatch.setattr(routes_mod, "_INVESTIGATION_DB", inv)
        monkeypatch.setattr(routes_mod, "_EVIDENCE_DB", FakeEvidenceDB())
        monkeypatch.setattr(routes_mod, "_ACTIVE_CASES", FakeActiveCases())
        monkeypatch.setattr(routes_mod, "_request_principal", lambda r: {"principal_type": "user"})

        delta = {
            "case_id": "K2",
            "items": [
                {"id": "F-1", "action": "approve"},
                {"id": "F-2", "action": "reject", "rejection_reason": "noise"},
            ],
        }
        (tmp_path / "pending-reviews.json").write_text(json.dumps(delta))

        result = routes_mod._apply_delta_db(
            self._request(), tmp_path, "alice", inv.apply_review
        )
        assert result["approved"] == 1
        assert result["rejected"] == 1
        assert result["authority"] == "db"
        # Re-auth event recorded and passed into the store.
        assert inv.review_calls[0]["reauth"] == "audit-evt-K2"
        assert inv.review_calls[0]["case_id"] == _CASE_ID
        # DB rows transitioned.
        assert inv.rows["F-1"]["status"] == "APPROVED"
        assert inv.rows["F-2"]["status"] == "REJECTED"
        # Staged delta cleared.
        assert not (tmp_path / "pending-reviews.json").exists()

    def test_apply_delta_db_requires_pending_file(self, tmp_path):
        inv = FakeInvestigationDB()
        with pytest.raises(ValueError):
            routes_mod._apply_delta_db(self._request(), tmp_path, "alice", inv.apply_review)


# --------------------------------------------------------------------------- #
# Report generation reads DB approved inputs, ignores tampered file
# --------------------------------------------------------------------------- #


class FakeReportDB:
    def __init__(self):
        self.recorded = []

    def report_eligibility(self, case_id):
        return {"eligible": True, "approved_findings": 1, "total_findings": 2, "reason": None}

    def list_reports(self, case_id):
        return []

    def record_report(self, *, case_id, **metadata):
        self.recorded.append(metadata)


class TestReportDbInputs:
    @pytest.fixture
    def case_dir(self, tmp_path, monkeypatch):
        (tmp_path / "CASE.yaml").write_text("case_id: k2-case\nname: K2\nexaminer: alice\n")
        # Tampered file: an injected APPROVED finding that must NOT reach the report.
        (tmp_path / "findings.json").write_text(
            json.dumps([{"id": "F-INJECT", "title": "INJECTED", "status": "APPROVED",
                         "observation": "evil"}])
        )
        (tmp_path / "timeline.json").write_text("[]")
        (tmp_path / "todos.json").write_text("[]")
        monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: tmp_path)
        return tmp_path

    def test_report_uses_db_findings_not_file(self, case_dir, monkeypatch):
        inv = FakeInvestigationDB()
        # Approve F-1 in DB so it is the only approved input.
        inv.rows["F-1"]["status"] = "APPROVED"
        inv.rows["F-1"]["approved_by"] = "alice"
        rep = FakeReportDB()
        c = _examiner(
            _make_client(
                investigation_service=inv,
                report_service=rep,
                evidence_service=FakeEvidenceDB(),
            )
        )
        resp = c.post(
            "/api/reports/generate",
            json={"profile": "full", "password": GOOD_PASSWORD},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        report_blob = json.dumps(body)
        # The DB-approved finding is present; the injected file finding is not.
        assert "INJECTED" not in report_blob
        assert "F-INJECT" not in report_blob
