"""Portal session security hardening (Supabase-envelope plane).

CL3a (B-MVP-017): migrated off the legacy ``sift_session`` JWT plane (JTI
revocation + sliding-refresh + login-lockout), which is sunset and deleted in
CL3b, to the Supabase session-envelope plane the live portal uses. The
fail-closed envelope behaviors (logout clears + revokes upstream, refresh fails
closed and drops the cookie, absolute lifetime cap) are the hardening guarantees
now under test. The deep refresh/absolute-cap matrix lives in
test_pr03_supabase_portal_auth.py::TestC10RefreshHardening; here we assert the
load-bearing logout/refresh fail-closed behaviors against the shared harness.
"""

from __future__ import annotations

import secrets

import pytest
from starlette.testclient import TestClient

from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import (
    SESSION_ENVELOPE_COOKIE_NAME,
    generate_session_envelope,
)

from _supabase_reauth_harness import (
    ReauthFakeSupabaseAuth,
    operator_principal,
    operator_envelope,
    set_operator_session,
)

_SECRET = secrets.token_hex(32)


class _LogoutTrackingAuth(ReauthFakeSupabaseAuth):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.logged_out: list[str] = []

    async def logout(self, access_token, source_ip):
        self.logged_out.append(access_token or "")
        return None


@pytest.fixture()
def fake_auth():
    return _LogoutTrackingAuth()


@pytest.fixture()
def app(fake_auth):
    return create_dashboard_v2_app(
        session_secret=_SECRET, session_max_age=1000, supabase_auth=fake_auth,
    )


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


class TestLogoutHardening:
    def test_logout_clears_envelope_cookie(self, client):
        set_operator_session(client, _SECRET)
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200
        set_cookie = resp.headers.get("set-cookie", "")
        assert SESSION_ENVELOPE_COOKIE_NAME in set_cookie
        assert "max-age=0" in set_cookie.lower()

    def test_logout_revokes_upstream_session(self, client, fake_auth):
        set_operator_session(client, _SECRET)
        client.post("/api/auth/logout")
        # The access token was handed to the upstream revoke callback.
        assert fake_auth.logged_out

    def test_me_after_logout_is_401(self, client):
        set_operator_session(client, _SECRET)
        client.post("/api/auth/logout")
        # Cookie cleared client-side by the logout response; /me has no session.
        client.cookies.clear()
        assert client.get("/api/auth/me").status_code == 401


class TestRefreshFailClosed:
    def test_refresh_without_cookie_401(self, client):
        assert client.post("/api/auth/refresh").status_code == 401

    def test_refresh_unresolvable_clears_cookie(self, client):
        # An envelope whose refresh token the fake cannot refresh -> fail closed.
        env = generate_session_envelope(
            access_token="dead-at", refresh_token="dead-rt", expires_at=1,
            sub="x", fingerprint="fp", secret=_SECRET,
        )
        client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, env)
        resp = client.post("/api/auth/refresh")
        assert resp.status_code == 401
        assert "max-age=0" in resp.headers.get("set-cookie", "").lower()


class TestAbsoluteLifetimeCap:
    def test_envelope_past_absolute_cap_is_rejected(self, client):
        from case_dashboard.session_jwt import (
            ABSOLUTE_ENVELOPE_LIFETIME_SECONDS,
            verify_session_envelope,
        )
        import time as _time

        old_eiat = int(_time.time()) - ABSOLUTE_ENVELOPE_LIFETIME_SECONDS - 10
        env = operator_envelope(_SECRET)
        # Re-stamp issued-at past the cap (rebuild with explicit issued_at).
        env_capped = generate_session_envelope(
            access_token="reauth-access", refresh_token="r", expires_at=9999999999,
            sub="auth-user-op-alice", fingerprint="fp", secret=_SECRET,
            issued_at=old_eiat,
        )
        assert verify_session_envelope(env_capped, _SECRET) is None
        client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, env_capped)
        assert client.get("/api/auth/me").status_code == 401
