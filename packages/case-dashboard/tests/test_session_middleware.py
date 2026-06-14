"""Tests for case_dashboard.auth.PortalSessionMiddleware (Supabase-envelope plane).

CL3a (B-MVP-017): migrated off the legacy ``sift_session`` JWT cookie + Bearer
API-key plane (sunset; deleted in CL3b) to the Supabase session-envelope plane
that the live portal uses. The middleware resolves the envelope's access token to
an app principal via the injected Supabase callback and stamps
``request.state.principal/examiner/role``; only operator principals get an
examiner identity, and an unresolved/agent envelope leaves state cleared so route
handlers enforce 401/403.
"""

from __future__ import annotations

import secrets

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from case_dashboard.auth import PortalSessionMiddleware
from case_dashboard.session_jwt import (
    SESSION_ENVELOPE_COOKIE_NAME,
    generate_session_envelope,
)

from _supabase_reauth_harness import operator_principal

_SECRET = secrets.token_hex(32)
_ACCESS_TOKEN = "mw-access-" + secrets.token_hex(8)


class _FakeSupabaseAuth:
    """Minimal C3 resolver: maps the known access token to ``principal``."""

    def __init__(self, principal):
        self._principal = principal

    async def resolve(self, access_token, source_ip):
        return self._principal if access_token == _ACCESS_TOKEN else None

    async def refresh(self, refresh_token, source_ip):
        return None


def _make_app(principal) -> Starlette:
    async def endpoint(request: Request):
        return JSONResponse(
            {
                "examiner": getattr(request.state, "examiner", "MISSING"),
                "role": getattr(request.state, "role", "MISSING"),
                "has_principal": getattr(request.state, "principal", None) is not None,
            }
        )

    return Starlette(
        routes=[Route("/api/test", endpoint)],
        middleware=[
            Middleware(
                PortalSessionMiddleware,
                session_secret=_SECRET,
                api_keys={},
                supabase_auth=_FakeSupabaseAuth(principal),
            )
        ],
    )


def _envelope(sub: str = "auth-user-op-alice") -> str:
    return generate_session_envelope(
        access_token=_ACCESS_TOKEN,
        refresh_token="mw-refresh",
        expires_at=9999999999,
        sub=sub,
        fingerprint="fp",
        secret=_SECRET,
    )


class TestSupabaseEnvelopeAuth:
    def test_operator_envelope_sets_examiner_and_role(self):
        client = TestClient(_make_app(operator_principal()))
        client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, _envelope())
        data = client.get("/api/test").json()
        assert data["examiner"] == "alice"
        assert data["role"] == "examiner"
        assert data["has_principal"] is True

    def test_readonly_operator_gets_readonly_role(self):
        principal = operator_principal(display_name="bob", system_role="readonly")
        client = TestClient(_make_app(principal))
        client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, _envelope())
        data = client.get("/api/test").json()
        assert data["examiner"] == "bob"
        assert data["role"] == "readonly"

    def test_agent_principal_gets_no_examiner_identity(self):
        agent = dict(operator_principal(), principal_type="agent")
        client = TestClient(_make_app(agent))
        client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, _envelope())
        data = client.get("/api/test").json()
        # Agent principals are intentionally left without (examiner, role).
        assert data["examiner"] is None
        assert data["role"] is None

    def test_tampered_envelope_falls_through_to_none(self):
        client = TestClient(_make_app(operator_principal()))
        env = _envelope()
        client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, env[:-4] + "AAAA")
        data = client.get("/api/test").json()
        assert data["examiner"] is None
        assert data["role"] is None
        assert data["has_principal"] is False

    def test_unresolvable_token_clears_state(self):
        # The fake only resolves _ACCESS_TOKEN; a different one resolves to None.
        client = TestClient(_make_app(operator_principal()))
        env = generate_session_envelope(
            access_token="some-other-token", refresh_token="r",
            expires_at=9999999999, sub="x", fingerprint="fp", secret=_SECRET,
        )
        client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, env)
        data = client.get("/api/test").json()
        assert data["examiner"] is None
        assert data["has_principal"] is False


class TestNoAuth:
    def test_no_cookie_sets_none(self):
        client = TestClient(_make_app(operator_principal()))
        data = client.get("/api/test").json()
        assert data["examiner"] is None
        assert data["role"] is None
        assert data["has_principal"] is False

    def test_middleware_never_returns_401_itself(self):
        client = TestClient(_make_app(operator_principal()))
        resp = client.get("/api/test")
        assert resp.status_code == 200  # endpoint returns 200 even with examiner=None

    def test_legacy_disabled_ignores_bearer(self):
        client = TestClient(_make_app(operator_principal()))
        resp = client.get(
            "/api/test", headers={"Authorization": "Bearer anything"}
        )
        data = resp.json()
        assert data["examiner"] is None


class TestR9StateAccess:
    def test_examiner_accessible_via_getattr(self):
        client = TestClient(_make_app(operator_principal()))
        client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, _envelope())
        resp = client.get("/api/test")
        assert resp.status_code == 200
        assert resp.json()["examiner"] == "alice"
