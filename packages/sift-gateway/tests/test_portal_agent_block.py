"""Tests for Phase 12f — R4 agent token block on portal API endpoints.

Drivers: SIFT-MCPS-PLAN.md §Phase 12 Security Requirements R4 / TASKS.md §12f.

Verifies:
- Agent tokens (agentir_svc_*) → 403 on any /portal/api/ endpoint
- Examiner bearer tokens (agentir_gw_*) → pass through to portal
- Requests without bearer token → pass through (portal handles 401)
"""

from __future__ import annotations

import secrets

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.testclient import TestClient

from sift_gateway.auth import AuthMiddleware

_EXAMINER_KEY = "agentir_gw_" + secrets.token_hex(24)
_AGENT_KEY = "agentir_svc_" + secrets.token_hex(24)
_READONLY_KEY = "agentir_gw_" + secrets.token_hex(24)

_API_KEYS = {
    _EXAMINER_KEY: {"examiner": "alice", "role": "examiner"},
    _AGENT_KEY: {"examiner": "hermes", "role": "agent"},
    _READONLY_KEY: {"examiner": "reader", "role": "readonly", "token_id": "readonly-1"},
}


async def _portal_api_endpoint(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "examiner": getattr(request.state, "examiner", None),
            "role": getattr(request.state, "role", None),
            "reached": True,
        }
    )


async def _other_endpoint(request: Request) -> JSONResponse:
    return JSONResponse({"reached": True})


def _make_app(api_keys=None) -> Starlette:
    """Minimal gateway app with AuthMiddleware for testing R4."""
    from starlette.applications import Starlette

    # Simulate the portal sub-app mounted at /portal
    portal_app = Starlette(
        routes=[
            Route("/api/findings", _portal_api_endpoint, methods=["GET"]),
            Route("/api/delta", _portal_api_endpoint, methods=["GET", "POST"]),
        ]
    )

    app = Starlette(
        routes=[
            Mount("/portal", app=portal_app),
            Route("/api/v1/other", _other_endpoint, methods=["GET"]),
        ],
        middleware=[
            Middleware(AuthMiddleware, api_keys=api_keys if api_keys is not None else _API_KEYS)
        ],
    )
    return app


@pytest.fixture()
def client():
    return TestClient(_make_app(), raise_server_exceptions=True)


class TestR4AgentPortalBlock:
    def test_agent_token_blocked_on_portal_api(self, client):
        """R4: Agent token must get 403 on /portal/api/ endpoints."""
        resp = client.get(
            "/portal/api/findings",
            headers={"Authorization": f"Bearer {_AGENT_KEY}"},
        )
        assert resp.status_code == 403
        assert "portal" in resp.json()["error"].lower()

    def test_agent_token_blocked_on_portal_api_post(self, client):
        resp = client.post(
            "/portal/api/delta",
            json={},
            headers={"Authorization": f"Bearer {_AGENT_KEY}"},
        )
        assert resp.status_code == 403

    def test_readonly_token_blocked_on_portal_api_post(self, client):
        resp = client.post(
            "/portal/api/delta",
            json={},
            headers={"Authorization": f"Bearer {_READONLY_KEY}"},
        )
        assert resp.status_code == 403
        assert "readonly" in resp.json()["error"].lower()

    def test_readonly_token_passes_through_on_portal_api_get(self, client):
        resp = client.get(
            "/portal/api/findings",
            headers={"Authorization": f"Bearer {_READONLY_KEY}"},
        )
        assert resp.status_code == 200
        assert resp.json()["reached"] is True

    def test_examiner_token_passes_through_to_portal(self, client):
        """Examiner bearer token → reaches portal sub-app (not blocked at gateway)."""
        resp = client.get(
            "/portal/api/findings",
            headers={"Authorization": f"Bearer {_EXAMINER_KEY}"},
        )
        # Portal sub-app reached (not blocked at gateway level)
        assert resp.status_code == 200
        assert resp.json()["reached"] is True

    def test_no_token_passes_through_to_portal(self, client):
        """Browser request (JWT cookie, no bearer) → reaches portal (portal handles auth)."""
        resp = client.get("/portal/api/findings")
        # Gateway lets it through; portal sub-app handles 200 in our test app
        assert resp.status_code == 200
        assert resp.json()["reached"] is True

    def test_agent_token_allowed_on_non_portal_paths(self, client):
        """Agent tokens must NOT be blocked on non-portal paths like /api/v1/other."""
        # (that path goes through normal gateway auth — agent tokens are valid there)
        resp = client.get(
            "/api/v1/other",
            headers={"Authorization": f"Bearer {_AGENT_KEY}"},
        )
        # This reaches the normal gateway auth — agent token has a valid role so it passes
        assert resp.status_code == 200

    def test_agent_token_not_blocked_on_portal_html_root(self, client):
        """R4 block only applies to /portal/api/ paths, not /portal/ root HTML."""
        resp = client.get(
            "/portal/",
            headers={"Authorization": f"Bearer {_AGENT_KEY}"},
        )
        # /portal/ passes through (it's in _PUBLIC_PATHS), portal handles it
        assert resp.status_code != 403


class TestPortalPathPassthrough:
    def test_portal_paths_bypass_gateway_auth_for_jwt_browser_flow(self):
        """Portal sub-paths must reach the portal app even without a bearer token."""
        app = _make_app()
        c = TestClient(app)
        # No bearer token — browser with JWT cookie scenario
        resp = c.get("/portal/api/findings")
        assert resp.status_code == 200

    def test_examiner_token_state_not_set_by_gateway_for_portal(self, client):
        """Gateway sets examiner=None for portal paths (portal sets it via SessionMiddleware)."""
        resp = client.get(
            "/portal/api/findings",
            headers={"Authorization": f"Bearer {_EXAMINER_KEY}"},
        )
        # In our test portal app, the endpoint returns request.state values
        # The gateway sets examiner=None for portal paths (portal handles its own auth)
        data = resp.json()
        assert data["reached"] is True
        # examiner should be None since AuthMiddleware doesn't set it for portal paths
        assert data["examiner"] is None
