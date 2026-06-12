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

import hashlib
import hmac as hmac_mod
import json
import secrets
from pathlib import Path

import case_dashboard.routes as routes_mod
import pytest
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import COOKIE_NAME, generate_jwt
from starlette.testclient import TestClient

_SECRET = secrets.token_hex(32)
_PBKDF2_ITERS = 600_000
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


def _make_evidence_response(stored_hash_hex: str, nonce: str) -> str:
    return hmac_mod.new(bytes.fromhex(stored_hash_hex), nonce.encode(), "sha256").hexdigest()


def _setup_examiner(passwords_dir: Path, examiner: str, password: str) -> dict:
    passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS).hex()
    entry = {"hash": pw_hash, "salt": salt.hex(), "must_reset_password": False}
    (passwords_dir / f"{examiner}.json").write_text(json.dumps(entry))
    return entry


def _session_cookie(examiner: str = "alice", role: str = "examiner") -> str:
    return generate_jwt(examiner, role, _SECRET, max_age=3600)


def _full_challenge(client: TestClient, passwords_dir: Path, examiner: str = "alice") -> tuple[str, str]:
    entry = json.loads((passwords_dir / f"{examiner}.json").read_text())
    resp = client.get("/api/evidence/chain/challenge")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    response = _make_evidence_response(entry["hash"], data["nonce"])
    return data["challenge_id"], response


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def passwords_dir(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", d)
    return d


def _build_client(passwords_dir, tmp_path, monkeypatch, evidence_db):
    routes_mod._evidence_challenges.clear()
    routes_mod._challenges.clear()
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        active_case_service=FakeActiveCases(),
        evidence_service=evidence_db,
    )
    c = TestClient(app, raise_server_exceptions=True)
    _setup_examiner(passwords_dir, "alice", "password123")
    c.cookies[COOKIE_NAME] = _session_cookie()
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
        )
        c = TestClient(app, raise_server_exceptions=True)
        resp = c.post("/api/evidence/chain/verify-hmac", json={})
        assert resp.status_code == 403

    def test_agent_role_returns_403(self, passwords_dir, tmp_path, monkeypatch):
        c = _build_client(passwords_dir, tmp_path, monkeypatch, FakeEvidenceDB())
        c.cookies[COOKIE_NAME] = _session_cookie(role="agent")
        resp = c.post("/api/evidence/chain/verify-hmac", json={})
        assert resp.status_code == 403

    def test_missing_fields_returns_400(self, passwords_dir, tmp_path, monkeypatch):
        c = _build_client(passwords_dir, tmp_path, monkeypatch, FakeEvidenceDB())
        resp = c.post("/api/evidence/chain/verify-hmac", json={})
        assert resp.status_code == 400

    def test_wrong_password_returns_401(self, passwords_dir, tmp_path, monkeypatch):
        ev = FakeEvidenceDB()
        c = _build_client(passwords_dir, tmp_path, monkeypatch, ev)
        resp = c.get("/api/evidence/chain/challenge")
        cid = resp.json()["challenge_id"]
        resp2 = c.post("/api/evidence/chain/verify-hmac", json={
            "challenge_id": cid, "response": "deadbeef" * 8,
        })
        assert resp2.status_code == 401
        assert not ev.verify_calls

    def test_happy_path_ok_result(self, passwords_dir, tmp_path, monkeypatch):
        ev = FakeEvidenceDB(verify_result={"verified": True, "issues": []})
        c = _build_client(passwords_dir, tmp_path, monkeypatch, ev)
        cid, response = _full_challenge(c, passwords_dir)
        resp = c.post("/api/evidence/chain/verify-hmac", json={
            "challenge_id": cid, "response": response,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["verified"] is True
        assert data["authority"] == "db"
        assert data["verified_by"] == "alice"
        assert "verified_at" in data
        assert ev.verify_calls == [(_CASE_ID, None)]

    def test_failed_verify_reports_not_ok(self, passwords_dir, tmp_path, monkeypatch):
        ev = FakeEvidenceDB(verify_result={"verified": False, "issues": ["Modified: evidence/x"]})
        c = _build_client(passwords_dir, tmp_path, monkeypatch, ev)
        cid, response = _full_challenge(c, passwords_dir)
        resp = c.post("/api/evidence/chain/verify-hmac", json={
            "challenge_id": cid, "response": response,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is False
        assert data["issues"] == ["Modified: evidence/x"]

    def test_challenge_consumed_after_use(self, passwords_dir, tmp_path, monkeypatch):
        c = _build_client(passwords_dir, tmp_path, monkeypatch, FakeEvidenceDB())
        cid, response = _full_challenge(c, passwords_dir)
        c.post("/api/evidence/chain/verify-hmac", json={"challenge_id": cid, "response": response})
        resp2 = c.post("/api/evidence/chain/verify-hmac", json={"challenge_id": cid, "response": response})
        assert resp2.status_code == 401

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
        app = create_dashboard_v2_app(session_secret=_SECRET, session_max_age=28800)
        c = TestClient(app, raise_server_exceptions=True)
        _setup_examiner(passwords_dir, "alice", "password123")
        c.cookies[COOKIE_NAME] = _session_cookie()
        monkeypatch.setattr(routes_mod, "_verify_evidence_hmac", lambda *a, **k: (None, b"key"))
        resp = c.post("/api/evidence/chain/verify-hmac", json={"challenge_id": "x", "response": "y"})
        assert resp.status_code == 404
