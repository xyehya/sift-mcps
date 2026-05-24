"""Tests for Phase 15 — portal session security hardening.

Covers:
- 15a: JWT JTI revocation list (in-memory) upon logout.
- 15b: Sliding session refreshes with age check (>10% elapsed) and time throttling (>300s).
- 15c: Login lockout (429) after 5 attempts.
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
from case_dashboard.session_jwt import COOKIE_NAME, generate_jwt, verify_jwt, is_revoked

_SECRET = secrets.token_hex(32)
_PBKDF2_ITERS = 600_000


def _setup_examiner(passwords_dir: Path, examiner: str, password: str):
    passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS).hex()
    entry = {"hash": pw_hash, "salt": salt.hex(), "must_reset_password": False}
    path = passwords_dir / f"{examiner}.json"
    path.write_text(json.dumps(entry))
    return entry


@pytest.fixture()
def passwords_dir(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", d)
    return d


@pytest.fixture()
def app(passwords_dir, tmp_path, monkeypatch):
    routes_mod._login_challenges.clear()
    routes_mod._challenges.clear()
    # Redirect Path.home() so lockout files land in tmp, not ~/.agentir
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    return create_dashboard_v2_app(session_secret=_SECRET, session_max_age=1000)


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# 15a: JWT revocation on logout
# ---------------------------------------------------------------------------

class TestJWTLogoutRevocation:
    def test_logout_revokes_token_jti(self, client, passwords_dir):
        _setup_examiner(passwords_dir, "alice", "password123")

        # Generate a valid token
        token = generate_jwt("alice", "examiner", _SECRET, max_age=1000)
        payload = verify_jwt(token, _SECRET)
        assert payload is not None
        jti = payload["jti"]

        # Logout with the cookie
        client.cookies.set(COOKIE_NAME, token)
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200

        # Verify token is now revoked
        assert is_revoked(jti) is True
        assert verify_jwt(token, _SECRET) is None

        # Verify /api/auth/me rejects it
        resp_me = client.get("/api/auth/me")
        assert resp_me.status_code == 401


# ---------------------------------------------------------------------------
# 15b: Sliding session refresh
# ---------------------------------------------------------------------------

class TestSlidingSessionRefresh:
    def test_sliding_refresh_triggered_after_elapsed_and_throttle(self, client, passwords_dir, monkeypatch):
        _setup_examiner(passwords_dir, "alice", "password123")

        start_time = 1000000000
        monkeypatch.setattr(time, "time", lambda: start_time)

        # max_age = 1000. 10% is 100s.
        token = generate_jwt("alice", "examiner", _SECRET, max_age=1000)

        # Case 1: Hitting /me immediately (0 seconds elapsed) -> no refresh cookie
        client.cookies.set(COOKIE_NAME, token)
        resp = client.get("/api/auth/me")
        assert resp.status_code == 200
        assert COOKIE_NAME not in resp.cookies

        # Case 2: Hitting /me at start_time + 200 (200s elapsed).
        # This is > 10% elapsed (exp - now = 800 < 900), but not throttled (200s < 300s).
        # Wait, the throttle checks: now - iat > 300. Here 200s < 300s, so should NOT refresh.
        monkeypatch.setattr(time, "time", lambda: start_time + 200)
        resp = client.get("/api/auth/me")
        assert resp.status_code == 200
        assert COOKIE_NAME not in resp.cookies

        # Case 3: Hitting /me at start_time + 400 (400s elapsed).
        # This is > 10% elapsed and >300s since iat. Should refresh!
        monkeypatch.setattr(time, "time", lambda: start_time + 400)
        resp = client.get("/api/auth/me")
        assert resp.status_code == 200
        assert COOKIE_NAME in resp.cookies
        new_token = resp.cookies[COOKIE_NAME]

        # Decode new token and verify its iat is start_time + 400
        new_payload = verify_jwt(new_token, _SECRET)
        assert new_payload is not None
        assert new_payload["iat"] == start_time + 400

        # Case 4: Hitting again at start_time + 410 (10s since new iat).
        # This is < 300s since new iat, so it should not refresh again immediately.
        client.cookies.set(COOKIE_NAME, new_token)
        monkeypatch.setattr(time, "time", lambda: start_time + 410)
        resp = client.get("/api/auth/me")
        assert resp.status_code == 200
        assert COOKIE_NAME not in resp.cookies


# ---------------------------------------------------------------------------
# 15c: Login Lockout Rates (429)
# ---------------------------------------------------------------------------

class TestLoginLockoutRateLimiting:
    def test_five_login_failures_causes_lockout(self, client, passwords_dir, tmp_path):
        _setup_examiner(passwords_dir, "bob", "correct_pass")

        # 5 unsuccessful logins
        for i in range(5):
            # Get challenge
            resp = client.get("/api/auth/challenge?examiner=bob")
            assert resp.status_code == 200
            data = resp.json()
            # Send invalid response
            payload = {
                "challenge_id": data["challenge_id"],
                "examiner": "bob",
                "response": "bad_response_hex_" + str(i)
            }
            resp_login = client.post("/api/auth/login", json=payload)
            assert resp_login.status_code == 401

        # 6th attempt to get challenge or login must return 429
        resp_challenge = client.get("/api/auth/challenge?examiner=bob")
        assert resp_challenge.status_code == 429
        assert "Too many failed attempts" in resp_challenge.json()["error"]

        resp_login_block = client.post("/api/auth/login", json={
            "challenge_id": "any_id",
            "examiner": "bob",
            "response": "any_response"
        })
        assert resp_login_block.status_code == 429
        assert "Too many failed attempts" in resp_login_block.json()["error"]
