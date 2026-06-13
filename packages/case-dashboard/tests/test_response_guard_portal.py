"""Tests for Approach C — response-guard portal endpoints.

Covers: GET /api/response-guard/status, POST /api/response-guard/override,
        POST /api/response-guard/override/cancel.
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

import case_dashboard.routes as routes_mod
import pytest
from _supabase_reauth_harness import (
    GOOD_PASSWORD,
    ReauthFakeSupabaseAuth,
    operator_principal,
    set_operator_session,
)
from case_dashboard.routes import create_dashboard_v2_app
from starlette.testclient import TestClient

_SECRET = secrets.token_hex(32)
_CASE_DIR = "/tmp/case-rg-portal-test"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_examiner(passwords_dir: Path, examiner: str = "alice", *, must_reset: bool = False) -> dict:
    """Seed the local must_reset flag file the R1 gate still reads (CL3a)."""
    passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    entry = {"hash": "aa" * 32, "salt": "bb" * 32, "must_reset_password": must_reset}
    (passwords_dir / f"{examiner}.json").write_text(json.dumps(entry))
    return entry


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


@pytest.fixture()
def passwords_dir(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", d)
    return d


@pytest.fixture()
def fake_auth():
    return ReauthFakeSupabaseAuth()


@pytest.fixture()
def app(passwords_dir, tmp_path, monkeypatch, fake_auth):
    monkeypatch.setenv("SIFT_CASE_DIR", _CASE_DIR)
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    return create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        on_override_get_status=_stub_get_status,
        on_override_enable=_stub_enable,
        on_override_cancel=_stub_cancel,
        supabase_auth=fake_auth,
    )


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def authed_client(client):
    set_operator_session(client, _SECRET)
    return client


# ---------------------------------------------------------------------------
# GET /api/response-guard/status
# ---------------------------------------------------------------------------


class TestResponseGuardStatus:
    def test_no_auth_returns_403(self, client):
        resp = client.get("/api/response-guard/status")
        assert resp.status_code == 403

    def test_agent_principal_returns_403(self, passwords_dir, tmp_path, monkeypatch):
        agent = dict(operator_principal(), principal_type="agent",
                     auth_user_id="auth-user-agent-1")
        monkeypatch.setenv("SIFT_CASE_DIR", _CASE_DIR)
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            on_override_get_status=_stub_get_status,
            on_override_enable=_stub_enable, on_override_cancel=_stub_cancel,
            supabase_auth=ReauthFakeSupabaseAuth(principal=agent),
        )
        c = TestClient(app, raise_server_exceptions=True)
        set_operator_session(c, _SECRET)
        resp = c.get("/api/response-guard/status")
        assert resp.status_code in (401, 403)

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
        monkeypatch.setenv("SIFT_CASE_DIR", _CASE_DIR)
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, supabase_auth=ReauthFakeSupabaseAuth(),
        )  # no override callbacks
        c = TestClient(app)
        set_operator_session(c, _SECRET)
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

    def test_missing_password_returns_400(self, authed_client):
        resp = authed_client.post("/api/response-guard/override", json={"ttl_seconds": 60})
        assert resp.status_code == 400

    def test_successful_override_enable(self, authed_client):
        resp = authed_client.post(
            "/api/response-guard/override",
            json={"password": GOOD_PASSWORD, "ttl_seconds": 120},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled"] is True
        assert data["active"] is True
        assert data["enabled_by"] == "alice"
        assert _stub_state.get(_CASE_DIR) is not None

    def test_ttl_out_of_range_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/response-guard/override",
            json={"password": GOOD_PASSWORD, "ttl_seconds": 9999},
        )
        assert resp.status_code == 400

    def test_wrong_password_returns_401(self, authed_client):
        resp2 = authed_client.post(
            "/api/response-guard/override",
            json={"password": "wrong-password", "ttl_seconds": 60},
        )
        assert resp2.status_code == 401

    def test_control_plane_down_fails_closed(self, authed_client, fake_auth):
        fake_auth.control_plane_down = True
        resp = authed_client.post(
            "/api/response-guard/override",
            json={"password": GOOD_PASSWORD, "ttl_seconds": 60},
        )
        assert resp.status_code == 503
        assert _stub_state.get(_CASE_DIR) is None

    def test_must_reset_password_blocked(self, passwords_dir, tmp_path, monkeypatch):
        # CL3b: forced-reset now derives from the Supabase 'invited' status on
        # the session principal, not a file flag.
        monkeypatch.setenv("SIFT_CASE_DIR", _CASE_DIR)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            supabase_auth=ReauthFakeSupabaseAuth(
                principal=operator_principal(status="invited"),
            ),
        )
        c = TestClient(app, raise_server_exceptions=True)
        set_operator_session(c, _SECRET)
        resp = c.post(
            "/api/response-guard/override",
            json={"password": GOOD_PASSWORD},
        )
        assert resp.status_code == 403


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
