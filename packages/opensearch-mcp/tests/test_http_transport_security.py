"""DNS-rebinding protection regression tests for the HTTP transport.

FastMCP 3's ``http_app()`` no longer plumbs ``TransportSecuritySettings`` into
the streamable-HTTP session manager, so ``create_http_app`` re-establishes the
Host-header allowlist with Starlette's ``TrustedHostMiddleware``. These tests
lock that control in place so it cannot be silently dropped again.
"""

from __future__ import annotations

from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.testclient import TestClient

from opensearch_mcp.http_server import ALLOWED_HOSTS, create_http_app


def test_create_http_app_wraps_with_trusted_host_middleware() -> None:
    app = create_http_app()
    assert isinstance(app, TrustedHostMiddleware)
    assert app.allowed_hosts == ALLOWED_HOSTS


def test_rejects_foreign_host_header() -> None:
    with TestClient(create_http_app(), base_url="http://attacker.example.com") as client:
        resp = client.post("/mcp/", headers={"host": "attacker.example.com"})
    assert resp.status_code == 400
    assert resp.text == "Invalid host header"


def test_allows_localhost_host_header() -> None:
    # A loopback Host (port stripped before matching) passes the allowlist. The
    # request still fails downstream on MCP content negotiation, but the failure
    # is NOT the Host rejection — proving the host was accepted.
    with TestClient(create_http_app(), base_url="http://127.0.0.1:4625") as client:
        resp = client.post("/mcp/", headers={"host": "127.0.0.1:4625"})
    assert resp.text != "Invalid host header"
