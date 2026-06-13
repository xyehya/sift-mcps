"""Tests for evidence chain HMAC verify (DB-authority).

Covers:
  GET /api/evidence/chain/status surfaces verify-reminder fields
    (hmac_last_verified_at, hmac_last_verified_by, hmac_verify_needed) from the
    DB gate — never from a file verify-state side file.
  POST /api/evidence/chain/verify-hmac — auth, happy path, DB verify call.

The file-backed verify-state mechanism (evidence-verify-state.json) and the
file ledger HMAC verify have been removed; the DB gate's last_verified_at is the
single source for the reminder, and _EVIDENCE_DB.verify is the only verifier.
"""

from __future__ import annotations

import secrets

import case_dashboard.routes as routes_mod
import pytest
from case_dashboard.routes import create_dashboard_v2_app
from starlette.testclient import TestClient

from _supabase_reauth_harness import (
    GOOD_PASSWORD,
    ReauthFakeSupabaseAuth,
    operator_principal,
    set_operator_session,
)

_SECRET = secrets.token_hex(32)
_CASE_ID = "11111111-1111-1111-1111-111111111111"


# ---------------------------------------------------------------------------
# Fake DB-authority services
# ---------------------------------------------------------------------------


class FakeActiveCases:
    class _Case:
        def as_dict(self):
            return {"case_id": _CASE_ID, "name": "verify-remind"}

    def get_active_case(self, principal=None):
        return self._Case()


class FakeEvidenceDB:
    def __init__(self, *, last_verified_at=None, verify_result=None):
        self.last_verified_at = last_verified_at
        self.verify_result = verify_result if verify_result is not None else {
            "verified": True, "issues": [],
        }
        self.verify_calls: list = []

    def gate_status(self, case_id):
        return {
            "seal_status": "sealed",
            "manifest_version": 1,
            "active_count": 1,
            "issues": [],
            "head_hash": "sha256:abc",
            "last_verified_at": self.last_verified_at,
        }

    def list_evidence(self, case_id):
        return []

    def verify(self, *, case_id, actor=None):
        self.verify_calls.append((case_id, actor))
        return dict(self.verify_result)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def passwords_dir(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", d)
    return d


def _build_client(passwords_dir, tmp_path, monkeypatch, evidence_db, *, fake_auth=None):
    routes_mod._evidence_challenges.clear()
    routes_mod._challenges.clear()
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        active_case_service=FakeActiveCases(),
        evidence_service=evidence_db,
        supabase_auth=fake_auth or ReauthFakeSupabaseAuth(),
    )
    c = TestClient(app, raise_server_exceptions=True)
    set_operator_session(c, _SECRET)
    return c


# ---------------------------------------------------------------------------
# Chain status surfaces verify-reminder fields from the DB gate
# ---------------------------------------------------------------------------


class TestChainStatusIncludesVerifyFields:
    def test_no_verify_state_hmac_needed_true(self, passwords_dir, tmp_path, monkeypatch):
        c = _build_client(passwords_dir, tmp_path, monkeypatch, FakeEvidenceDB(last_verified_at=None))
        resp = c.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "hmac_verify_needed" in data
        assert data["hmac_verify_needed"] is True
        assert data["hmac_last_verified_at"] is None
        assert data["hmac_last_verified_by"] is None

    def test_recent_verify_state_hmac_needed_false(self, passwords_dir, tmp_path, monkeypatch):
        ts = "2026-06-08T10:00:00+00:00"
        c = _build_client(passwords_dir, tmp_path, monkeypatch, FakeEvidenceDB(last_verified_at=ts))
        resp = c.get("/api/evidence/chain/status")
        data = resp.json()
        assert data["hmac_verify_needed"] is False
        assert data["hmac_last_verified_at"] == ts


# ---------------------------------------------------------------------------
# POST /api/evidence/chain/verify-hmac
# ---------------------------------------------------------------------------


class TestVerifyHmacEndpoint:
    def test_no_auth_returns_403(self, passwords_dir, tmp_path, monkeypatch):
        routes_mod._evidence_challenges.clear()
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            active_case_service=FakeActiveCases(), evidence_service=FakeEvidenceDB(),
            supabase_auth=ReauthFakeSupabaseAuth(),
        )
        c = TestClient(app, raise_server_exceptions=True)
        resp = c.post("/api/evidence/chain/verify-hmac", json={})
        assert resp.status_code == 403

    def test_agent_principal_returns_403(self, passwords_dir, tmp_path, monkeypatch):
        agent = dict(operator_principal(), principal_type="agent",
                     auth_user_id="auth-user-agent-1")
        c = _build_client(passwords_dir, tmp_path, monkeypatch, FakeEvidenceDB(),
                          fake_auth=ReauthFakeSupabaseAuth(principal=agent))
        resp = c.post("/api/evidence/chain/verify-hmac", json={})
        assert resp.status_code in (401, 403)

    def test_missing_password_returns_400(self, passwords_dir, tmp_path, monkeypatch):
        c = _build_client(passwords_dir, tmp_path, monkeypatch, FakeEvidenceDB())
        resp = c.post("/api/evidence/chain/verify-hmac", json={})
        assert resp.status_code == 400

    def test_wrong_password_returns_401(self, passwords_dir, tmp_path, monkeypatch):
        ev = FakeEvidenceDB()
        c = _build_client(passwords_dir, tmp_path, monkeypatch, ev)
        resp2 = c.post("/api/evidence/chain/verify-hmac", json={
            "password": "wrong-password",
        })
        assert resp2.status_code == 401
        assert not ev.verify_calls

    def test_control_plane_down_fails_closed(self, passwords_dir, tmp_path, monkeypatch):
        ev = FakeEvidenceDB()
        c = _build_client(passwords_dir, tmp_path, monkeypatch, ev,
                          fake_auth=ReauthFakeSupabaseAuth(control_plane_down=True))
        resp = c.post("/api/evidence/chain/verify-hmac", json={"password": GOOD_PASSWORD})
        assert resp.status_code == 503
        assert not ev.verify_calls

    def test_happy_path_ok_result(self, passwords_dir, tmp_path, monkeypatch):
        ev = FakeEvidenceDB(verify_result={"verified": True, "issues": []})
        c = _build_client(passwords_dir, tmp_path, monkeypatch, ev)
        resp = c.post("/api/evidence/chain/verify-hmac", json={
            "password": GOOD_PASSWORD,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["verified"] is True
        assert data["authority"] == "db"
        assert data["verified_by"] == "alice"
        assert "verified_at" in data
        # CL3a: the Supabase-envelope session populates request.state.principal,
        # so verify carries the operator actor (was None under legacy cookie).
        assert len(ev.verify_calls) == 1
        case_id, actor = ev.verify_calls[0]
        assert case_id == _CASE_ID
        assert isinstance(actor, dict) and actor["principal_type"] == "operator"

    def test_failed_verify_reports_not_ok(self, passwords_dir, tmp_path, monkeypatch):
        ev = FakeEvidenceDB(verify_result={"verified": False, "issues": ["Modified: evidence/x"]})
        c = _build_client(passwords_dir, tmp_path, monkeypatch, ev)
        resp = c.post("/api/evidence/chain/verify-hmac", json={
            "password": GOOD_PASSWORD,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is False
        assert data["issues"] == ["Modified: evidence/x"]

    def test_invalid_json_returns_400(self, passwords_dir, tmp_path, monkeypatch):
        c = _build_client(passwords_dir, tmp_path, monkeypatch, FakeEvidenceDB())
        resp = c.post(
            "/api/evidence/chain/verify-hmac",
            content=b"not json",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400

    def test_fresh_install_graceful_no_case(self, passwords_dir, tmp_path, monkeypatch):
        """No DB service: verify-hmac degrades to no-case, never reads a file ledger."""
        routes_mod._evidence_challenges.clear()
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            supabase_auth=ReauthFakeSupabaseAuth(),
        )
        c = TestClient(app, raise_server_exceptions=True)
        set_operator_session(c, _SECRET)
        resp = c.post("/api/evidence/chain/verify-hmac", json={"password": GOOD_PASSWORD})
        assert resp.status_code == 404
