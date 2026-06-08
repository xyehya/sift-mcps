"""BATCH-E1 — portal DB-authority migration tests.

Covers the Gateway-injected DB-authority seams in case_dashboard.routes:

  * evidence read + seal/ignore/retire move to DB authority (C1 RPCs) and pass a
    re-auth audit event id produced by the portal's password/HMAC re-auth;
  * findings/timeline/iocs/todos read + todo mutations move to DB authority,
    with agent-authored rows surfaced as proposed/draft until a human acts;
  * approved-only report eligibility is visible (GET /api/portal/state) and
    testable (POST /api/reports/generate is refused when no approved finding);
  * job status flows through the D2 Gateway adapter (GET /api/jobs/{id});
  * auth, re-auth, and rejected unauthorized mutations are enforced.

The services are injected the same way the Gateway injects them in production;
case_dashboard never imports sift_gateway. Fakes here stand in for the
Gateway-side adapters over Postgres.
"""

from __future__ import annotations

import secrets

import case_dashboard.routes as routes_mod
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import COOKIE_NAME, generate_jwt
from starlette.testclient import TestClient

_SECRET = secrets.token_hex(32)


# --------------------------------------------------------------------------- #
# Fake DB-authority services (stand-ins for the Gateway-side adapters)
# --------------------------------------------------------------------------- #


class FakeActiveCases:
    """Minimal active-case service exposing a stable opaque case_id."""

    class _Case:
        def as_dict(self):
            return {"case_id": "11111111-1111-1111-1111-111111111111", "name": "E1"}

    def get_active_case(self, principal=None):
        return self._Case()


class FakeEvidenceDB:
    def __init__(self, *, seal_status="unsealed"):
        self.seal_status = seal_status
        self.reauth_calls = []
        self.seal_calls = []
        self.ignore_calls = []
        self.retire_calls = []

    def record_reauth_event(self, *, case_id, actor, examiner, action):
        self.reauth_calls.append((case_id, examiner, action))
        return "audit-evt-001"

    def gate_status(self, case_id):
        return {
            "seal_status": self.seal_status,
            "manifest_version": 2,
            "active_count": 1,
            "issues": [],
            "head_hash": "sha256:abc",
            "last_verified_at": None,
        }

    def list_evidence(self, case_id):
        return [
            {
                "evidence_id": "ev-1",
                "display_path": "evidence/disk.E01",
                "display_name": "disk.E01",
                "current_sha256": "sha256:" + "0" * 64,
                "current_bytes": 1024,
                "status": "sealed",
                "seal_status": "sealed",
            }
        ]

    def custody_events(self, case_id):
        return [{"seq": 1, "event_type": "MANIFEST_SEALED"}]

    def seal(self, *, case_id, file_specs, reauth_audit_event_id, actor, examiner):
        assert reauth_audit_event_id, "seal must receive a re-auth audit event id"
        self.seal_calls.append((case_id, file_specs, reauth_audit_event_id))
        return {"manifest_version": 3, "seal_status": "sealed"}

    def ignore(self, *, case_id, display_path, reason, reauth_audit_event_id, actor, examiner):
        assert reauth_audit_event_id
        self.ignore_calls.append((display_path, reason, reauth_audit_event_id))

    def retire(self, *, case_id, display_path, reason, reauth_audit_event_id, actor, examiner):
        assert reauth_audit_event_id
        self.retire_calls.append((display_path, reason, reauth_audit_event_id))


class FakeEvidenceDBNoReauth(FakeEvidenceDB):
    def record_reauth_event(self, *, case_id, actor, examiner, action):
        return None  # simulate no DB audit sink -> seal must be refused


class FakeInvestigationDB:
    def __init__(self):
        self.todos = []
        self._next = 1

    def list_findings(self, case_id):
        return [
            {"id": "F-1", "title": "Agent proposal", "status": "DRAFT"},
            {"id": "F-2", "title": "Approved by human", "status": "APPROVED"},
        ]

    def list_timeline(self, case_id):
        return [{"id": "T-1", "status": "PROPOSED"}]

    def list_iocs(self, case_id):
        return [{"id": "IOC-1", "value": "1.2.3.4", "status": "DRAFT"}]

    def list_todos(self, case_id):
        return list(self.todos)

    def create_todo(self, *, case_id, examiner, actor, description, priority, assignee, related_findings):
        todo = {
            "todo_id": f"TODO-{examiner}-{self._next:03d}",
            "description": description,
            "priority": priority,
            "status": "open",
            "examiner": examiner,
        }
        self._next += 1
        self.todos.append(todo)
        return todo

    def update_todo(self, *, case_id, todo_id, examiner, actor, patch):
        for t in self.todos:
            if t["todo_id"] == todo_id:
                t.update({k: v for k, v in patch.items() if k != "note"})
                return t
        return None

    def delete_todo(self, *, case_id, todo_id, examiner, actor):
        before = len(self.todos)
        self.todos = [t for t in self.todos if t["todo_id"] != todo_id]
        return len(self.todos) != before


class FakeReportDB:
    def __init__(self, *, eligible=True, approved=2):
        self._eligible = eligible
        self._approved = approved

    def list_reports(self, case_id):
        return [{"id": "rep-1", "profile": "full", "created_at": "2026-06-08T00:00:00Z"}]

    def report_eligibility(self, case_id):
        return {
            "eligible": self._eligible,
            "approved_findings": self._approved,
            "total_findings": 5,
            "reason": None if self._eligible else "no approved findings",
        }


class FakeJobService:
    def job_status_public(self, job_id, principal=None):
        return {"job_id": job_id, "status": "succeeded", "job_type": "ingest"}


def _make_client(**services):
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        active_case_service=services.get("active_case_service", FakeActiveCases()),
        evidence_service=services.get("evidence_service"),
        investigation_service=services.get("investigation_service"),
        report_service=services.get("report_service"),
        job_service=services.get("job_service"),
    )
    return TestClient(app)


def _examiner(client):
    client.cookies.set(COOKIE_NAME, generate_jwt("alice", "examiner", _SECRET, max_age=3600))
    return client


def _readonly(client):
    client.cookies.set(COOKIE_NAME, generate_jwt("bob", "readonly", _SECRET, max_age=3600))
    return client


# --------------------------------------------------------------------------- #
# Evidence DB authority + re-auth
# --------------------------------------------------------------------------- #


class TestEvidenceDBAuthority:
    def test_chain_status_from_db(self):
        ev = FakeEvidenceDB(seal_status="sealed")
        c = _examiner(_make_client(evidence_service=ev))
        resp = c.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["authority"] == "db"
        assert body["seal_status"] == "sealed"
        assert body["manifest_version"] == 2

    def test_evidence_list_from_db_uses_relative_paths(self):
        ev = FakeEvidenceDB()
        c = _examiner(_make_client(evidence_service=ev))
        resp = c.get("/api/evidence")
        assert resp.status_code == 200
        items = resp.json()
        assert items[0]["evidence_id"] == "ev-1"
        assert items[0]["path"] == "evidence/disk.E01"
        # No absolute path leaks.
        assert not items[0]["path"].startswith("/")

    def test_seal_passes_reauth_event_id(self, monkeypatch):
        ev = FakeEvidenceDB()
        c = _examiner(_make_client(evidence_service=ev))
        # Bypass the HMAC password check; the DB seal path is what we exercise.
        monkeypatch.setattr(
            routes_mod, "_verify_evidence_hmac",
            lambda *a, **k: (None, b"key"),
        )
        resp = c.post("/api/evidence/chain/seal", json={
            "challenge_id": "x", "response": "y",
            "file_specs": [{"path": "evidence/disk.E01"}],
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["sealed"] is True and body["authority"] == "db"
        assert body["reauth_method"] == "local_hmac_mvp_bridge"
        assert body["registration_mode"] == "atomic_register_and_seal"
        assert ev.seal_calls and ev.seal_calls[0][2] == "audit-evt-001"
        assert ev.reauth_calls and ev.reauth_calls[0][2] == "evidence_seal"

    def test_seal_refused_without_reauth_event(self, monkeypatch):
        ev = FakeEvidenceDBNoReauth()
        c = _examiner(_make_client(evidence_service=ev))
        monkeypatch.setattr(
            routes_mod, "_verify_evidence_hmac",
            lambda *a, **k: (None, b"key"),
        )
        resp = c.post("/api/evidence/chain/seal", json={
            "challenge_id": "x", "response": "y",
            "file_specs": [{"path": "evidence/disk.E01"}],
        })
        assert resp.status_code == 403
        assert "Re-auth" in resp.json()["error"]
        assert not ev.seal_calls

    def test_seal_rejects_bad_hmac(self, monkeypatch):
        ev = FakeEvidenceDB()
        c = _examiner(_make_client(evidence_service=ev))
        monkeypatch.setattr(
            routes_mod, "_verify_evidence_hmac",
            lambda *a, **k: ("Incorrect password", None),
        )
        resp = c.post("/api/evidence/chain/seal", json={
            "challenge_id": "x", "response": "y", "file_specs": [{"path": "evidence/d"}],
        })
        assert resp.status_code == 401
        assert not ev.seal_calls

    def test_ignore_and_retire_pass_reauth(self, monkeypatch):
        ev = FakeEvidenceDB()
        c = _examiner(_make_client(evidence_service=ev))
        monkeypatch.setattr(
            routes_mod, "_verify_evidence_hmac", lambda *a, **k: (None, b"key")
        )
        r1 = c.post("/api/evidence/chain/ignore", json={
            "challenge_id": "x", "response": "y", "path": "evidence/junk", "reason": "noise",
        })
        assert r1.status_code == 200 and r1.json()["authority"] == "db"
        assert r1.json()["reauth_method"] == "local_hmac_mvp_bridge"
        assert ev.ignore_calls[0][2] == "audit-evt-001"

        r2 = c.post("/api/evidence/chain/retire", json={
            "challenge_id": "x", "response": "y", "path": "evidence/old", "reason": "dupe",
        })
        assert r2.status_code == 200 and r2.json()["authority"] == "db"
        assert r2.json()["reauth_method"] == "local_hmac_mvp_bridge"
        assert ev.retire_calls[0][2] == "audit-evt-001"

    def test_readonly_cannot_seal(self):
        ev = FakeEvidenceDB()
        c = _readonly(_make_client(evidence_service=ev))
        resp = c.post("/api/evidence/chain/seal", json={
            "challenge_id": "x", "response": "y", "file_specs": [{"path": "evidence/d"}],
        })
        assert resp.status_code == 403
        assert not ev.seal_calls

    def test_unauthenticated_cannot_seal(self):
        ev = FakeEvidenceDB()
        c = TestClient(_make_client(evidence_service=ev).app)
        resp = c.post("/api/evidence/chain/seal", json={"file_specs": []})
        assert resp.status_code in (401, 403)
        assert not ev.seal_calls


# --------------------------------------------------------------------------- #
# Investigation DB authority — agent proposals stay proposed/draft
# --------------------------------------------------------------------------- #


class TestInvestigationDBAuthority:
    def test_findings_from_db_preserve_proposal_status(self):
        inv = FakeInvestigationDB()
        c = _examiner(_make_client(investigation_service=inv))
        rows = c.get("/api/findings").json()
        by_id = {r["id"]: r for r in rows}
        assert by_id["F-1"]["status"] == "DRAFT"      # agent proposal, not yet human-acted
        assert by_id["F-2"]["status"] == "APPROVED"

    def test_timeline_and_iocs_from_db(self):
        inv = FakeInvestigationDB()
        c = _examiner(_make_client(investigation_service=inv))
        assert c.get("/api/timeline").json()[0]["status"] == "PROPOSED"
        assert c.get("/api/iocs").json()[0]["status"] == "DRAFT"

    def test_todo_create_update_delete_via_db(self):
        inv = FakeInvestigationDB()
        c = _examiner(_make_client(investigation_service=inv))
        created = c.post("/api/todos", json={"description": "do it", "priority": "high"})
        assert created.status_code == 201
        tid = created.json()["todo_id"]
        assert c.get("/api/todos").json()[0]["todo_id"] == tid

        patched = c.patch(f"/api/todos/{tid}", json={"status": "completed"})
        assert patched.status_code == 200 and patched.json()["status"] == "completed"

        deleted = c.delete(f"/api/todos/{tid}")
        assert deleted.status_code == 200
        assert c.get("/api/todos").json() == []

    def test_todo_update_missing_returns_404(self):
        inv = FakeInvestigationDB()
        c = _examiner(_make_client(investigation_service=inv))
        assert c.patch("/api/todos/TODO-nope-001", json={"status": "open"}).status_code == 404

    def test_readonly_cannot_create_todo(self):
        inv = FakeInvestigationDB()
        c = _readonly(_make_client(investigation_service=inv))
        assert c.post("/api/todos", json={"description": "x"}).status_code == 403
        assert inv.todos == []

    def test_todo_invalid_priority_rejected_before_db(self):
        inv = FakeInvestigationDB()
        c = _examiner(_make_client(investigation_service=inv))
        assert c.post("/api/todos", json={"description": "x", "priority": "bogus"}).status_code == 400
        assert inv.todos == []


# --------------------------------------------------------------------------- #
# Report eligibility (approved-only) + portal state + jobs
# --------------------------------------------------------------------------- #


class TestReportEligibility:
    def test_eligibility_visible_in_portal_state(self):
        rep = FakeReportDB(eligible=True, approved=2)
        c = _examiner(_make_client(report_service=rep, evidence_service=FakeEvidenceDB()))
        state = c.get("/api/portal/state").json()
        assert state["report_eligibility"]["eligible"] is True
        assert state["report_eligibility"]["approved_findings"] == 2
        assert state["evidence"]["seal_status"] == "unsealed"

    def test_reports_list_from_db(self):
        rep = FakeReportDB()
        c = _examiner(_make_client(report_service=rep))
        rows = c.get("/api/reports").json()
        assert rows[0]["id"] == "rep-1"

    def test_generate_refused_when_no_approved_findings(self):
        rep = FakeReportDB(eligible=False, approved=0)
        c = _examiner(_make_client(report_service=rep))
        resp = c.post("/api/reports/generate", json={"profile": "full"})
        assert resp.status_code == 409
        assert resp.json()["eligibility"]["eligible"] is False

    def test_generate_eligible_passes_gate_then_resolves_case(self, monkeypatch):
        # Eligible -> the eligibility gate passes; generation then proceeds to the
        # (file-backed) generator, which 404s with no case dir. We only assert the
        # eligibility gate did not 409.
        rep = FakeReportDB(eligible=True, approved=1)
        c = _examiner(_make_client(report_service=rep))
        monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: None)
        resp = c.post("/api/reports/generate", json={"profile": "full"})
        assert resp.status_code != 409

    def test_readonly_blocked_from_portal_state_mutation_paths(self):
        # /api/portal/state is read-only and allows readonly role.
        c = _readonly(_make_client(report_service=FakeReportDB(), evidence_service=FakeEvidenceDB()))
        assert c.get("/api/portal/state").status_code == 200


class TestJobStatusAdapter:
    def test_job_status_via_adapter(self):
        c = _examiner(_make_client(job_service=FakeJobService()))
        resp = c.get("/api/jobs/job-123")
        assert resp.status_code == 200
        assert resp.json()["status"] == "succeeded"

    def test_job_status_503_when_unwired(self):
        c = _examiner(_make_client())
        assert c.get("/api/jobs/job-123").status_code == 503

    def test_job_status_requires_auth(self):
        c = TestClient(_make_client(job_service=FakeJobService()).app)
        assert c.get("/api/jobs/job-123").status_code == 401
