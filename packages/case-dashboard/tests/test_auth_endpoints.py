"""Tests for portal auth endpoints (Supabase-only login).

B-MVP-011: the local examiner.json PBKDF2 login fallback (setup-required /
setup / challenge / login / reset-password) was removed. Supabase Auth is the
only portal login path. The legacy login/setup/challenge/reset test classes were
removed with the endpoints they covered. What remains:

  * setup-required is now a no-op that always reports no local setup.
  * /api/auth/login fails closed (503) when no Supabase callback is injected,
    instead of silently logging in from a local password file.
  * logout / me / must-reset write blocking still work over the sift_session
    cookie session (the test harness forges that cookie directly).
"""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import case_dashboard.routes as routes_mod
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import SESSION_ENVELOPE_COOKIE_NAME

from _supabase_reauth_harness import (
    ReauthFakeSupabaseAuth,
    set_operator_session,
)

_SECRET = secrets.token_hex(32)
_PBKDF2_ITERS = 600_000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_examiner(passwords_dir: Path, examiner: str, password: str, *, must_reset: bool = False):
    """Write a local re-auth password entry directly (bypassing the API).

    These entries back the sensitive-action HMAC re-auth bridge (commit /
    evidence / case-activate / report), not login — login is Supabase-only.
    """
    passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS).hex()
    entry = {"hash": pw_hash, "salt": salt.hex(), "must_reset_password": must_reset}
    path = passwords_dir / f"{examiner}.json"
    path.write_text(json.dumps(entry))
    return entry


@pytest.fixture()
def passwords_dir(tmp_path, monkeypatch):
    """Redirect _PASSWORDS_DIR to a temp directory for test isolation."""
    d = tmp_path / "passwords"
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", d)
    return d


@pytest.fixture()
def app(passwords_dir, tmp_path, monkeypatch):
    routes_mod._challenges.clear()
    # Redirect Path.home() so lockout files land in tmp, not ~/.sift
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    # No Supabase callback wired here: the login-fail-closed test relies on it.
    return create_dashboard_v2_app(session_secret=_SECRET, session_max_age=28800)


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def authed_client(passwords_dir, tmp_path, monkeypatch):
    """A client whose Supabase-envelope session resolves to operator 'alice'."""
    routes_mod._challenges.clear()
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    app = create_dashboard_v2_app(
        session_secret=_SECRET, session_max_age=28800,
        supabase_auth=ReauthFakeSupabaseAuth(),
    )
    c = TestClient(app, raise_server_exceptions=True)
    set_operator_session(c, _SECRET)
    return c


# ---------------------------------------------------------------------------
# setup-required (B-MVP-011: now a no-op — no local setup path exists)
# ---------------------------------------------------------------------------


class TestSetupRequired:
    def test_always_reports_no_local_setup(self, client):
        resp = client.get("/api/auth/setup-required")
        assert resp.status_code == 200
        assert resp.json() == {"required": False, "setup_required": False}

    def test_no_auth_required_for_this_endpoint(self, client):
        resp = client.get("/api/auth/setup-required")
        assert resp.status_code == 200

    def test_local_password_presence_is_irrelevant(self, client, passwords_dir):
        # Even if a local re-auth password file exists, setup is never required —
        # login is Supabase-only.
        _setup_examiner(passwords_dir, "alice", "password123")
        resp = client.get("/api/auth/setup-required")
        assert resp.json() == {"required": False, "setup_required": False}


# ---------------------------------------------------------------------------
# login — Supabase is the only path; no local fallback
# ---------------------------------------------------------------------------


class TestLogin:
    def test_login_fails_closed_without_supabase_callback(self, client):
        """B-MVP-011: with no Supabase callback injected, login returns 503 with a
        clear, actionable error — never a silent local fallback."""
        resp = client.post(
            "/api/auth/login",
            json={"email": "examiner@operators.sift.local", "password": "whatever"},
        )
        assert resp.status_code == 503
        body = resp.json()
        assert "Control plane unavailable" in body["error"]

    def test_legacy_challenge_endpoint_is_gone(self, client):
        resp = client.get("/api/auth/challenge?examiner=alice")
        assert resp.status_code == 404

    def test_legacy_setup_endpoint_is_gone(self, client):
        resp = client.post(
            "/api/auth/setup", json={"examiner": "alice", "password": "securepass1"}
        )
        assert resp.status_code == 404

    def test_legacy_reset_password_endpoint_is_gone(self, client):
        resp = client.post(
            "/api/auth/reset-password",
            json={"challenge_id": "x", "response": "y", "new_password": "newpass12"},
        )
        assert resp.status_code == 404


class TestSupabaseLogin:
    """The Supabase login path is exercised end-to-end in
    test_pr03_supabase_portal_auth.py; here we only confirm the route is wired
    to the Supabase callback when one is injected."""

    def test_login_uses_supabase_callback_when_present(self, passwords_dir, tmp_path, monkeypatch):
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)

        class FakeAuth:
            async def login(self, email, password, source_ip):
                return {
                    "principal": {
                        "principal_type": "operator",
                        "display_name": "alice",
                        "email": email,
                        "status": "active",
                    },
                    "access_token": "at",
                    "refresh_token": "rt",
                    "expires_at": 0,
                    "sub": "sub-1",
                    "fingerprint": "fp",
                }

        app = create_dashboard_v2_app(
            session_secret=_SECRET,
            session_max_age=28800,
            supabase_auth=FakeAuth(),
        )
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post(
            "/api/auth/login",
            json={"email": "examiner@operators.sift.local", "password": "pw"},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert resp.json()["principal"]["principal_type"] == "operator"


# ---------------------------------------------------------------------------
# R1: must_reset blocks writes (re-auth bridge still file-backed)
# ---------------------------------------------------------------------------


@pytest.fixture()
def active_case_dir(tmp_path, monkeypatch):
    """Create a minimal active case dir and set SIFT_CASE_DIR for the test."""
    case_dir = tmp_path / "cases" / "test-case"
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: test-case\n")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    return case_dir


class TestR1MustResetBlocks:
    def test_must_reset_examiner_cannot_post_delta(
        self, authed_client, passwords_dir, active_case_dir
    ):
        """R1: must_reset_password=true prevents delta writes."""
        _setup_examiner(passwords_dir, "alice", "password123", must_reset=True)
        resp = authed_client.post("/api/delta", json={"items": []})
        assert resp.status_code == 403

    def test_must_reset_examiner_cannot_delete_delta(
        self, authed_client, passwords_dir, active_case_dir
    ):
        """R1: must_reset_password=true prevents delta item deletion."""
        _setup_examiner(passwords_dir, "alice", "password123", must_reset=True)
        resp = authed_client.delete("/api/delta/someid")
        assert resp.status_code == 403

    def test_non_reset_examiner_can_access_write_routes(
        self, authed_client, passwords_dir, active_case_dir
    ):
        """R1: Normal examiner (no must_reset) is allowed through auth check."""
        _setup_examiner(passwords_dir, "alice", "password123", must_reset=False)
        # Case dir exists but no delta file → 404, but that means auth passed.
        resp = authed_client.post("/api/delta", json={"items": []})
        assert resp.status_code not in (401, 403)


# ---------------------------------------------------------------------------
# logout
# ---------------------------------------------------------------------------


class TestLogout:
    def test_logout_returns_200(self, client):
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200

    def test_logout_clears_envelope_cookie(self, authed_client):
        resp = authed_client.post("/api/auth/logout")
        cookie_header = resp.headers.get("set-cookie", "")
        assert SESSION_ENVELOPE_COOKIE_NAME in cookie_header
        assert "max-age=0" in cookie_header.lower()


# ---------------------------------------------------------------------------
# me
# ---------------------------------------------------------------------------


class TestMe:
    def test_me_returns_401_without_session(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_me_returns_operator_profile_with_supabase_session(self, authed_client):
        resp = authed_client.get("/api/auth/me")
        assert resp.status_code == 200
        data = resp.json()
        # Supabase plane returns the token-free operator profile.
        assert data["principal_type"] == "operator"
        assert data["display_name"] == "alice"
        # No token material in the profile.
        assert "access_token" not in data and "refresh_token" not in data

    def test_me_no_session_no_bearer(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401
        assert "error" in resp.json()
