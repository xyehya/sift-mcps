"""Tests for Phase 15d — SecureHeadersMiddleware.

Verifies:
- Standard security headers (HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) on all responses.
- Content-Security-Policy only on HTML responses served under /portal paths.
"""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from sift_gateway.server import SecureHeadersMiddleware


async def _html_endpoint(request: Request) -> HTMLResponse:
    return HTMLResponse("<html><body>Portal</body></html>")


async def _json_endpoint(request: Request) -> JSONResponse:
    return JSONResponse({"ok": True})


async def _plain_endpoint(request: Request) -> PlainTextResponse:
    return PlainTextResponse("health check")


def _make_app() -> Starlette:
    routes = [
        Route("/portal/index.html", _html_endpoint, methods=["GET"]),
        Route("/portal/api/data", _json_endpoint, methods=["GET"]),
        Route("/health", _plain_endpoint, methods=["GET"]),
    ]
    return Starlette(
        routes=routes,
        middleware=[Middleware(SecureHeadersMiddleware)],
    )


@pytest.fixture()
def client():
    return TestClient(_make_app())


def test_standard_security_headers_on_all_responses(client):
    for path in ["/portal/index.html", "/portal/api/data", "/health"]:
        resp = client.get(path)
        assert resp.status_code == 200
        
        # Verify HSTS
        assert resp.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
        # Verify X-Content-Type-Options
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        # Verify X-Frame-Options
        assert resp.headers["X-Frame-Options"] == "DENY"
        # Verify Referrer-Policy
        assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_csp_only_on_portal_html_responses(client):
    # HTML page under /portal -> should have CSP
    resp_portal_html = client.get("/portal/index.html")
    assert resp_portal_html.status_code == 200
    assert "Content-Security-Policy" in resp_portal_html.headers
    assert resp_portal_html.headers["Content-Security-Policy"] == (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    )

    # JSON API response under /portal -> should NOT have CSP
    resp_portal_json = client.get("/portal/api/data")
    assert resp_portal_json.status_code == 200
    assert "Content-Security-Policy" not in resp_portal_json.headers

    # Plain text /health -> should NOT have CSP
    resp_health = client.get("/health")
    assert resp_health.status_code == 200
    assert "Content-Security-Policy" not in resp_health.headers
