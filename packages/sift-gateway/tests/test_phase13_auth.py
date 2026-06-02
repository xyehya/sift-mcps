"""Phase 13 gateway auth and token behavior.

Drivers: SIFT-MCPS-PLAN.md Phase 13 / TASKS.md 13a-13b.
"""

from __future__ import annotations

import secrets

from sift_gateway.auth import verify_api_key
from sift_gateway.mcp_endpoint import MCPAuthASGIApp
from sift_gateway.server import _NormalizeMCPPath
from sift_gateway.token_gen import generate_gateway_token, generate_service_token
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount
from starlette.testclient import TestClient


class _FakeSessionManager:
    def __init__(self) -> None:
        self.called = False

    async def handle_request(self, scope, receive, send) -> None:
        self.called = True


def test_generate_gateway_token_uses_sift_prefix_and_192_bits():
    token = generate_gateway_token()
    assert token.startswith("sift_gw_")
    assert len(token.removeprefix("sift_gw_")) == 48
    int(token.removeprefix("sift_gw_"), 16)


def test_generate_service_token_uses_sift_prefix_and_192_bits():
    token = generate_service_token()
    assert token.startswith("sift_svc_")
    assert len(token.removeprefix("sift_svc_")) == 48
    int(token.removeprefix("sift_svc_"), 16)


def test_verify_api_key_rejects_revoked_token():
    token = "sift_svc_" + secrets.token_hex(24)
    assert verify_api_key(token, {token: {"role": "agent", "revoked_at": "2026-01-01T00:00:00Z"}}) is None


def test_exact_mcp_path_is_rewritten_without_redirect():
    async def endpoint(scope, receive, send):
        response = PlainTextResponse(scope["path"])
        await response(scope, receive, send)

    app = Starlette(routes=[Mount("/mcp", app=endpoint)])
    app.add_middleware(_NormalizeMCPPath)

    client = TestClient(app, follow_redirects=False)
    response = client.get("/mcp")

    assert response.status_code == 200
    assert response.text == "/mcp/"
    assert "location" not in response.headers


async def test_mcp_rejects_readonly_role_before_session_manager():
    token = "sift_gw_" + secrets.token_hex(24)
    session = _FakeSessionManager()
    app = MCPAuthASGIApp(
        session,
        api_keys={token: {"examiner": "reader", "role": "readonly"}},
    )
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await app(
        {
            "type": "http",
            "method": "GET",
            "path": "/mcp",
            "headers": [(b"authorization", f"Bearer {token}".encode("latin-1"))],
            "client": ("127.0.0.1", 12345),
        },
        receive,
        send,
    )

    start = next(message for message in messages if message["type"] == "http.response.start")
    body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    assert start["status"] == 403
    assert b"Readonly" in body
    assert session.called is False
