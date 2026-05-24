"""Tests for Approach C — response-guard portal endpoints.

Covers: GET /api/response-guard/status, POST /api/response-guard/override,
        POST /api/response-guard/override/cancel.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import secrets
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import case_dashboard.routes as routes_mod
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import COOKIE_NAME, generate_jwt

_SECRET = secrets.token_hex(32)
_PBKDF2_ITERS = 600_000
_CASE_DIR = "/tmp/case-rg-portal-test"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_password(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), _PBKDF2_ITERS).hex()


def _make_evidence_response(stored_hash_hex: str, nonce: str) -> str:
    return hmac_mod.new(bytes.fromhex(stored_hash_hex), nonce.encode(), "sha256").hexdigest()


def _setup_examiner(passwords_dir: Path, examiner: str = "alice", password: str = "password123") -> dict:
    passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS).hex()
    entry = {"hash": pw_hash, "salt": salt.hex(), "must_reset_password": False}
    (passwords_dir / f"{examiner}.json").write_text(json.dumps(entry))
    return entry


def _session_cookie(examiner: str = "alice", role: str = "examiner") -> str:
    return generate_jwt(examiner, role, _SECRET, max_age=3600)


# ---------------------------------------------------------------------------
# Override state stubs (replace sift_gateway.response_guard in tests)
# ---------------------------------------------------------------------------

_stub_state: dict[str, dict] = {}


def _stub_get_status(case_dir_str: str) -> dict:
    s = _stub_state.get(case_dir_str)
    if not s:
        return {"active": False, "seconds_remaining": 0, "enabled_by": None}
    remaining = max(0, int(s["expires_at"] - time.monotonic()))
    if remaining == 0:
        _stub_state.pop(case_dir_str, None)
        return {"active": False, "seconds_remaining": 0, "enabled_by": None}
    return {"active": True, "seconds_remaining": remaining, "enabled_by": s["enabled_by"]}


def _stub_enable(case_dir_str: str, examiner: str, ttl: int) -> dict:
    _stub_state[case_dir_str] = {
        "expires_at": time.monotonic() + ttl,
        "enabled_by": examiner,
    }
    return _stub_get_status(case_dir_str)


def _stub_cancel(case_dir_str: str) -> None:
    _stub_state.pop(case_dir_str, None)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_state(monkeypatch):
    _stub_state.clear()
    routes_mod._evidence_challenges.clear()
    routes_mod._challenges.clear()
    routes_mod._login_challenges.clear()


@pytest.fixture()
def passwords_dir(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", d)
    return d


@pytest.fixture()
def app(passwords_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTIR_CASE_DIR", _CASE_DIR)
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    return create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        on_override_get_status=_stub_get_status,
        on_override_enable=_stub_enable,
        on_override_cancel=_stub_cancel,
    )


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def authed_client(client, passwords_dir):
    _setup_examiner(passwords_dir)
    client.cookies[COOKIE_NAME] = _session_cookie()
    return client


def _full_evidence_challenge(client: TestClient, passwords_dir: Path) -> tuple[str, str]:
    entry = json.loads((passwords_dir / "alice.json").read_text())
    resp = client.get("/api/evidence/chain/challenge")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    response = _make_evidence_response(entry["hash"], data["nonce"])
    return data["challenge_id"], response


# ---------------------------------------------------------------------------
# GET /api/response-guard/status
# ---------------------------------------------------------------------------


class TestResponseGuardStatus:
    def test_no_auth_returns_403(self, client):
        resp = client.get("/api/response-guard/status")
        assert resp.status_code == 403

    def test_agent_role_returns_403(self, client, passwords_dir):
        _setup_examiner(passwords_dir)
        client.cookies[COOKIE_NAME] = _session_cookie(role="agent")
        resp = client.get("/api/response-guard/status")
        assert resp.status_code == 403

    def test_inactive_returns_correct_structure(self, authed_client):
        resp = authed_client.get("/api/response-guard/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["active"] is False
        assert data["seconds_remaining"] == 0
        assert data["enabled_by"] is None

    def test_active_override_reflected_in_status(self, authed_client):
        _stub_enable(_CASE_DIR, "alice", 300)
        resp = authed_client.get("/api/response-guard/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["active"] is True
        assert data["enabled_by"] == "alice"
        assert data["seconds_remaining"] > 0

    def test_no_callbacks_returns_warning(self, passwords_dir, tmp_path, monkeypatch):
        monkeypatch.setenv("AGENTIR_CASE_DIR", _CASE_DIR)
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        _setup_examiner(passwords_dir)
        app = create_dashboard_v2_app(session_secret=_SECRET)  # no override callbacks
        c = TestClient(app)
        c.cookies[COOKIE_NAME] = _session_cookie()
        resp = c.get("/api/response-guard/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "warning" in data


# ---------------------------------------------------------------------------
# POST /api/response-guard/override
# ---------------------------------------------------------------------------


class TestResponseGuardOverride:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/response-guard/override", json={})
        assert resp.status_code == 403

    def test_missing_challenge_returns_400(self, authed_client):
        resp = authed_client.post("/api/response-guard/override", json={"ttl_seconds": 60})
        assert resp.status_code == 400

    def test_invalid_challenge_returns_401(self, authed_client):
        resp = authed_client.post(
            "/api/response-guard/override",
            json={"challenge_id": "bad", "response": "bad", "ttl_seconds": 60},
        )
        assert resp.status_code == 401

    def test_successful_override_enable(self, authed_client, passwords_dir):
        cid, response = _full_evidence_challenge(authed_client, passwords_dir)
        resp = authed_client.post(
            "/api/response-guard/override",
            json={"challenge_id": cid, "response": response, "ttl_seconds": 120},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled"] is True
        assert data["active"] is True
        assert data["enabled_by"] == "alice"
        assert _stub_state.get(_CASE_DIR) is not None

    def test_ttl_out_of_range_returns_400(self, authed_client, passwords_dir):
        cid, response = _full_evidence_challenge(authed_client, passwords_dir)
        resp = authed_client.post(
            "/api/response-guard/override",
            json={"challenge_id": cid, "response": response, "ttl_seconds": 9999},
        )
        assert resp.status_code == 400

    def test_wrong_password_returns_401(self, authed_client):
        resp = authed_client.get("/api/evidence/chain/challenge")
        data = resp.json()
        resp2 = authed_client.post(
            "/api/response-guard/override",
            json={"challenge_id": data["challenge_id"], "response": "00" * 32, "ttl_seconds": 60},
        )
        assert resp2.status_code == 401

    def test_must_reset_password_blocked(self, client, passwords_dir, monkeypatch):
        monkeypatch.setenv("AGENTIR_CASE_DIR", _CASE_DIR)
        _setup_examiner(passwords_dir)
        (passwords_dir / "alice.json").write_text(
            json.dumps({"hash": "aa" * 32, "salt": "bb" * 32, "must_reset_password": True})
        )
        client.cookies[COOKIE_NAME] = _session_cookie()
        resp = client.post(
            "/api/response-guard/override",
            json={"challenge_id": "x", "response": "y"},
        )
        assert resp.status_code == 403

    def test_challenge_single_use(self, authed_client, passwords_dir):
        cid, response = _full_evidence_challenge(authed_client, passwords_dir)
        resp1 = authed_client.post(
            "/api/response-guard/override",
            json={"challenge_id": cid, "response": response},
        )
        assert resp1.status_code == 200
        resp2 = authed_client.post(
            "/api/response-guard/override",
            json={"challenge_id": cid, "response": response},
        )
        assert resp2.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/response-guard/override/cancel
# ---------------------------------------------------------------------------


class TestResponseGuardOverrideCancel:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/response-guard/override/cancel")
        assert resp.status_code == 403

    def test_cancel_clears_active_override(self, authed_client, passwords_dir):
        _stub_enable(_CASE_DIR, "alice", 300)
        resp = authed_client.post("/api/response-guard/override/cancel")
        assert resp.status_code == 200
        assert resp.json()["cancelled"] is True
        assert not _stub_state.get(_CASE_DIR)

    def test_cancel_when_inactive_is_safe(self, authed_client):
        resp = authed_client.post("/api/response-guard/override/cancel")
        assert resp.status_code == 200
        assert resp.json()["cancelled"] is True
