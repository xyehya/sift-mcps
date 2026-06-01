"""Tests for case_dashboard.auth.PortalSessionMiddleware — Phase 12c.

Drivers: SIFT-MCPS-PLAN.md §Phase 12 / TASKS.md §12c.
"""

from __future__ import annotations

import secrets

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from case_dashboard.auth import PortalSessionMiddleware
from case_dashboard.session_jwt import generate_jwt

_SECRET = secrets.token_hex(32)

_EXAMINER_KEY = "sift_gw_" + secrets.token_hex(24)
_AGENT_KEY = "sift_svc_" + secrets.token_hex(24)

_API_KEYS = {
    _EXAMINER_KEY: {"examiner": "alice", "role": "examiner"},
    _AGENT_KEY: {"examiner": "hermes", "role": "agent"},
}


def _make_app(session_secret=_SECRET, api_keys=None) -> Starlette:
    """Minimal Starlette app wrapped with PortalSessionMiddleware for testing."""

    async def endpoint(request: Request):
        return JSONResponse(
            {
                "examiner": getattr(request.state, "examiner", "MISSING"),
                "role": getattr(request.state, "role", "MISSING"),
            }
        )

    return Starlette(
        routes=[Route("/api/test", endpoint)],
        middleware=[
            Middleware(
                PortalSessionMiddleware,
                session_secret=session_secret,
                api_keys=api_keys if api_keys is not None else _API_KEYS,
            )
        ],
    )


class TestCookieAuth:
    def test_valid_cookie_sets_examiner_and_role(self):
        token = generate_jwt("alice", "examiner", _SECRET)
        client = TestClient(_make_app(), cookies={"sift_session": token})
        resp = client.get("/api/test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["examiner"] == "alice"
        assert data["role"] == "examiner"

    def test_valid_cookie_readonly_role(self):
        token = generate_jwt("bob", "readonly", _SECRET)
        client = TestClient(_make_app(), cookies={"sift_session": token})
        resp = client.get("/api/test")
        data = resp.json()
        assert data["examiner"] == "bob"
        assert data["role"] == "readonly"

    def test_tampered_cookie_falls_through_to_none(self):
        token = generate_jwt("alice", "examiner", _SECRET)
        parts = token.split(".")
        bad = f"{parts[0]}.{parts[1]}." + ("A" * len(parts[2]))
        client = TestClient(_make_app(), cookies={"sift_session": bad})
        resp = client.get("/api/test")
        data = resp.json()
        assert data["examiner"] is None

    def test_expired_cookie_falls_through_to_none(self):
        token = generate_jwt("alice", "examiner", _SECRET, max_age=0)
        client = TestClient(_make_app(), cookies={"sift_session": token})
        resp = client.get("/api/test")
        data = resp.json()
        assert data["examiner"] is None

    def test_cookie_with_wrong_secret_falls_through_to_none(self):
        wrong_secret = secrets.token_hex(32)
        token = generate_jwt("alice", "examiner", wrong_secret)
        client = TestClient(_make_app(), cookies={"sift_session": token})
        resp = client.get("/api/test")
        data = resp.json()
        assert data["examiner"] is None


class TestBearerFallback:
    def test_examiner_bearer_token_sets_state(self):
        client = TestClient(_make_app())
        resp = client.get("/api/test", headers={"Authorization": f"Bearer {_EXAMINER_KEY}"})
        data = resp.json()
        assert data["examiner"] == "alice"
        assert data["role"] == "examiner"

    def test_agent_bearer_token_does_not_authenticate(self):
        """Agent tokens must never be accepted by the portal middleware — examiner only."""
        client = TestClient(_make_app())
        resp = client.get("/api/test", headers={"Authorization": f"Bearer {_AGENT_KEY}"})
        data = resp.json()
        assert data["examiner"] is None
        assert data["role"] is None

    def test_invalid_bearer_token_sets_none(self):
        client = TestClient(_make_app())
        resp = client.get("/api/test", headers={"Authorization": "Bearer invalid_token_xyz"})
        data = resp.json()
        assert data["examiner"] is None

    def test_bearer_fallback_not_used_when_valid_cookie_present(self):
        """Cookie takes priority over Bearer token."""
        token = generate_jwt("cookie-user", "examiner", _SECRET)
        client = TestClient(
            _make_app(),
            cookies={"sift_session": token},
        )
        resp = client.get(
            "/api/test", headers={"Authorization": f"Bearer {_EXAMINER_KEY}"}
        )
        data = resp.json()
        assert data["examiner"] == "cookie-user"


class TestNoAuth:
    def test_no_cookie_no_bearer_sets_none(self):
        client = TestClient(_make_app())
        resp = client.get("/api/test")
        data = resp.json()
        assert data["examiner"] is None
        assert data["role"] is None

    def test_middleware_never_returns_401_itself(self):
        """Middleware sets state to None; it does NOT return 401 — route handlers do that."""
        client = TestClient(_make_app())
        resp = client.get("/api/test")
        assert resp.status_code == 200  # endpoint returns 200 even with examiner=None

    def test_no_api_keys_configured_bearer_falls_through(self):
        """With empty api_keys, Bearer tokens produce examiner=None."""
        client = TestClient(_make_app(api_keys={}))
        resp = client.get("/api/test", headers={"Authorization": f"Bearer {_EXAMINER_KEY}"})
        data = resp.json()
        assert data["examiner"] is None

    def test_empty_session_secret_cookie_auth_skipped(self):
        """Empty session_secret means cookie auth is bypassed entirely."""
        token = generate_jwt("alice", "examiner", _SECRET)
        client = TestClient(_make_app(session_secret=""), cookies={"sift_session": token})
        resp = client.get("/api/test")
        data = resp.json()
        # Cookie auth skipped (no secret), Bearer also absent → None
        assert data["examiner"] is None


class TestR9StateAccess:
    def test_examiner_accessible_via_getattr(self):
        """Route handlers must use getattr(request.state, 'examiner', None) — R9."""
        token = generate_jwt("alice", "examiner", _SECRET)
        client = TestClient(_make_app(), cookies={"sift_session": token})
        resp = client.get("/api/test")
        # The test endpoint uses getattr — must not raise AttributeError
        assert resp.status_code == 200
        assert resp.json()["examiner"] == "alice"
