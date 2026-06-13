"""Report generation re-auth + custody persistence (BATCH-J1 / F-MVP-4).

Verifies the portal-side J1 deliverables on top of E1's eligibility/409 gate:
  - report generation requires operator re-auth when DB evidence authority is
    wired (consistent with C1 seal/ignore/retire);
  - a successful re-auth yields a recorded re-auth audit event, stamped into the
    report's custody appendix;
  - report metadata is persisted via the report_service.record_report seam so
    DB authority reflects generated reports;
  - the generated report payload carries the custody/provenance appendix;
  - the response JSON never leaks absolute paths.
"""

from __future__ import annotations

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


class FakeActiveCases:
    class _Case:
        def as_dict(self):
            return {"case_id": "11111111-1111-1111-1111-111111111111", "name": "J1"}

    def get_active_case(self, principal=None):
        return self._Case()


class FakeEvidenceDB:
    def __init__(self, *, reauth_ok=True):
        self._reauth_ok = reauth_ok
        self.reauth_calls = []

    def record_reauth_event(self, *, case_id, actor, examiner, action):
        self.reauth_calls.append(action)
        return "audit-evt-J1" if self._reauth_ok else None

    def gate_status(self, case_id):
        return {
            "seal_status": "sealed",
            "manifest_version": 2,
            "active_count": 1,
            "issues": [],
            "head_hash": "sha256:headhash",
            "last_verified_at": None,
        }

    def custody_events(self, case_id):
        return [{"seq": 1, "event_type": "MANIFEST_SEALED"}]


class FakeReportDB:
    def __init__(self, *, eligible=True, approved=2):
        self._eligible = eligible
        self._approved = approved
        self.recorded = []

    def list_reports(self, case_id):
        return [{"id": r["report_id"], "profile": r["profile"]} for r in self.recorded]

    def report_eligibility(self, case_id):
        return {
            "eligible": self._eligible,
            "approved_findings": self._approved,
            "total_findings": 5,
            "reason": None if self._eligible else "no approved findings",
        }

    def record_report(self, *, case_id, **metadata):
        self.recorded.append(metadata)


def _make_client(*, fake_auth=None, **services):
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        active_case_service=services.get("active_case_service", FakeActiveCases()),
        evidence_service=services.get("evidence_service"),
        report_service=services.get("report_service"),
        supabase_auth=fake_auth or ReauthFakeSupabaseAuth(),
    )
    return TestClient(app)


def _examiner(client):
    set_operator_session(client, _SECRET)
    return client


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    import json

    (tmp_path / "CASE.yaml").write_text(
        "case_id: j1-case\nname: J1 Case\nexaminer: alice\n"
    )
    findings = [
        {"id": "F-1", "title": "Approved", "status": "APPROVED",
         "content_hash": "h1", "approved_by": "alice", "observation": "ok"},
        {"id": "F-2", "title": "Draft secret", "status": "draft",
         "observation": "DRAFTSECRET"},
    ]
    (tmp_path / "findings.json").write_text(json.dumps(findings))
    (tmp_path / "timeline.json").write_text("[]")
    (tmp_path / "todos.json").write_text("[]")
    monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: tmp_path)
    return tmp_path


class TestReportReauth:
    def test_generate_refused_without_reauth_when_db_wired(self, case_dir):
        ev = FakeEvidenceDB()
        rep = FakeReportDB()
        c = _examiner(_make_client(evidence_service=ev, report_service=rep))
        resp = c.post("/api/reports/generate", json={"profile": "full"})
        assert resp.status_code == 403
        assert "Re-auth" in resp.json()["error"]
        assert rep.recorded == []

    def test_generate_with_reauth_records_event_and_metadata(self, case_dir):
        ev = FakeEvidenceDB()
        rep = FakeReportDB()
        c = _examiner(_make_client(evidence_service=ev, report_service=rep))
        resp = c.post(
            "/api/reports/generate",
            json={"profile": "full", "password": GOOD_PASSWORD},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # Re-auth event recorded for report generation.
        assert "report_generate" in ev.reauth_calls
        # Appendix present and authorized by the re-auth event.
        appendix = body["custody_appendix"]
        assert appendix["authorized_by_reauth_event"] == "audit-evt-J1"
        # Report metadata persisted to DB authority.
        assert len(rep.recorded) == 1
        assert rep.recorded[0]["reauth_audit_event_id"] == "audit-evt-J1"
        assert rep.recorded[0]["seal_status"] == "sealed"

    def test_generate_rejects_bad_password(self, case_dir):
        ev = FakeEvidenceDB()
        rep = FakeReportDB()
        c = _examiner(_make_client(evidence_service=ev, report_service=rep))
        resp = c.post(
            "/api/reports/generate",
            json={"profile": "full", "password": "wrong-password"},
        )
        assert resp.status_code == 401
        assert rep.recorded == []

    def test_generate_control_plane_down_fails_closed(self, case_dir):
        ev = FakeEvidenceDB()
        rep = FakeReportDB()
        c = _examiner(_make_client(
            evidence_service=ev, report_service=rep,
            fake_auth=ReauthFakeSupabaseAuth(control_plane_down=True),
        ))
        resp = c.post(
            "/api/reports/generate",
            json={"profile": "full", "password": GOOD_PASSWORD},
        )
        assert resp.status_code == 503
        assert rep.recorded == []


class TestApprovedOnlyAndSanitization:
    def test_draft_text_absent_from_response(self, case_dir):
        ev = FakeEvidenceDB()
        c = _examiner(_make_client(evidence_service=ev, report_service=FakeReportDB()))
        resp = c.post(
            "/api/reports/generate",
            json={"profile": "full", "password": GOOD_PASSWORD},
        )
        assert resp.status_code == 200
        assert "DRAFTSECRET" not in resp.text
        assert "F-2" not in resp.text

    def test_response_has_no_absolute_paths(self, case_dir):
        ev = FakeEvidenceDB()
        c = _examiner(_make_client(evidence_service=ev, report_service=FakeReportDB()))
        resp = c.post(
            "/api/reports/generate",
            json={"profile": "full", "password": GOOD_PASSWORD},
        )
        assert str(case_dir) not in resp.text
        assert "/tmp/" not in resp.text

    def test_eligibility_409_still_enforced(self, case_dir):
        # E1's approved-only gate must not be reverted: ineligible -> 409 before
        # any re-auth or generation.
        rep = FakeReportDB(eligible=False, approved=0)
        c = _examiner(_make_client(report_service=rep, evidence_service=FakeEvidenceDB()))
        resp = c.post("/api/reports/generate", json={"profile": "full"})
        assert resp.status_code == 409
