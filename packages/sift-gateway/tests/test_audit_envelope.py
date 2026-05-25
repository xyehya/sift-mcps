"""Tests for the gateway transport audit envelope (Audit Invariant).

Covers:
- _hash_token fingerprinting (never stores raw token)
- MCPAuthASGIApp populates source_ip and token_id in scope state
- _extract_request_context reads all four fields from request state
"""

from __future__ import annotations

import hashlib
import secrets
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from sift_gateway.mcp_endpoint import (
    MCPAuthASGIApp,
    _extract_request_context,
    _hash_token,
)


# ---------------------------------------------------------------------------
# _hash_token
# ---------------------------------------------------------------------------


class TestHashToken:
    def test_returns_16_hex_chars(self):
        result = _hash_token("agentir_svc_" + secrets.token_hex(24))
        assert len(result) == 16
        int(result, 16)  # valid hex

    def test_deterministic(self):
        token = "agentir_gw_" + secrets.token_hex(24)
        assert _hash_token(token) == _hash_token(token)

    def test_matches_sha256_prefix(self):
        token = "test_token_value"
        expected = hashlib.sha256(token.encode()).hexdigest()[:16]
        assert _hash_token(token) == expected

    def test_different_tokens_differ(self):
        a = _hash_token("agentir_svc_" + secrets.token_hex(24))
        b = _hash_token("agentir_svc_" + secrets.token_hex(24))
        assert a != b

    def test_fingerprint_never_equals_raw_token(self):
        raw = "agentir_svc_" + secrets.token_hex(24)
        assert _hash_token(raw) != raw


# ---------------------------------------------------------------------------
# _extract_request_context
# ---------------------------------------------------------------------------


class TestExtractRequestContext:
    def _make_server(self, examiner=None, role=None, token_id=None, source_ip=None):
        state = SimpleNamespace(
            examiner=examiner, role=role, token_id=token_id, source_ip=source_ip
        )
        server = MagicMock()
        server.request_context = SimpleNamespace(request=SimpleNamespace(state=state))
        return server

    def test_extracts_all_four_fields(self):
        server = self._make_server(
            examiner="hermes", role="agent", token_id="abc123ef", source_ip="10.0.0.1"
        )
        ctx = _extract_request_context(server)
        assert ctx == {
            "examiner": "hermes",
            "role": "agent",
            "token_id": "abc123ef",
            "source_ip": "10.0.0.1",
        }

    def test_null_request_returns_safe_defaults(self):
        server = MagicMock()
        server.request_context = SimpleNamespace(request=None)
        ctx = _extract_request_context(server)
        assert ctx["examiner"] is None
        assert ctx["role"] == "unknown"
        assert ctx["token_id"] is None
        assert ctx["source_ip"] is None

    def test_lookup_error_returns_safe_defaults(self):
        server = MagicMock()
        type(server).request_context = property(
            lambda self: (_ for _ in ()).throw(LookupError())
        )
        ctx = _extract_request_context(server)
        assert ctx["examiner"] is None
        assert ctx["role"] == "unknown"

    def test_analyst_alias_resolved(self):
        state = SimpleNamespace(examiner=None, analyst="bob", role="examiner", token_id=None, source_ip=None)
        server = MagicMock()
        server.request_context = SimpleNamespace(request=SimpleNamespace(state=state))
        ctx = _extract_request_context(server)
        assert ctx["examiner"] == "bob"


# ---------------------------------------------------------------------------
# MCPAuthASGIApp — scope state population
# ---------------------------------------------------------------------------


class _CapturingSessionManager:
    def __init__(self):
        self.captured_scope: dict | None = None

    async def handle_request(self, scope, receive, send) -> None:
        self.captured_scope = scope


async def _run_asgi(app, token: str | None, client_ip: str = "10.0.0.1"):
    headers = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode("latin-1")))
    messages: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/mcp",
        "headers": headers,
        "client": (client_ip, 54321),
    }
    await app(scope, receive, send)
    return scope, messages


class TestScopeStatePopulation:
    async def test_authed_sets_source_ip_and_token_id(self):
        token = "agentir_svc_" + secrets.token_hex(24)
        session = _CapturingSessionManager()
        app = MCPAuthASGIApp(
            session, api_keys={token: {"examiner": "hermes", "role": "agent"}}
        )
        await _run_asgi(app, token, client_ip="192.168.1.5")
        state = session.captured_scope["state"]
        assert state["source_ip"] == "192.168.1.5"
        assert state["token_id"] == _hash_token(token)
        assert state["examiner"] == "hermes"
        assert state["role"] == "agent"

    async def test_anonymous_sets_source_ip_token_id_none(self):
        session = _CapturingSessionManager()
        app = MCPAuthASGIApp(session, api_keys={})
        await _run_asgi(app, token=None, client_ip="127.0.0.1")
        state = session.captured_scope["state"]
        assert state["source_ip"] == "127.0.0.1"
        assert state["token_id"] is None

    async def test_token_id_is_fingerprint_not_raw(self):
        token = "agentir_gw_" + secrets.token_hex(24)
        session = _CapturingSessionManager()
        app = MCPAuthASGIApp(
            session, api_keys={token: {"examiner": "alice", "role": "examiner"}}
        )
        await _run_asgi(app, token)
        state = session.captured_scope["state"]
        assert state["token_id"] != token
        assert state["token_id"] == _hash_token(token)

    async def test_readonly_rejected_session_manager_never_reached(self):
        token = "agentir_gw_" + secrets.token_hex(24)
        session = _CapturingSessionManager()
        app = MCPAuthASGIApp(
            session, api_keys={token: {"examiner": "reader", "role": "readonly"}}
        )
        _, messages = await _run_asgi(app, token)
        start = next(m for m in messages if m["type"] == "http.response.start")
        assert start["status"] == 403
        assert session.captured_scope is None

    async def test_x_forwarded_for_trusted_from_loopback(self):
        token = "agentir_svc_" + secrets.token_hex(24)
        session = _CapturingSessionManager()
        app = MCPAuthASGIApp(
            session, api_keys={token: {"examiner": "hermes", "role": "agent"}}
        )
        headers = [
            (b"authorization", f"Bearer {token}".encode("latin-1")),
            (b"x-forwarded-for", b"10.20.30.40"),
        ]
        messages: list[dict] = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(m):
            messages.append(m)

        await app(
            {
                "type": "http", "method": "GET", "path": "/mcp",
                "headers": headers, "client": ("127.0.0.1", 54321),
            },
            receive, send,
        )
        state = session.captured_scope["state"]
        assert state["source_ip"] == "10.20.30.40"

    async def test_x_forwarded_for_ignored_from_non_loopback(self):
        token = "agentir_svc_" + secrets.token_hex(24)
        session = _CapturingSessionManager()
        app = MCPAuthASGIApp(
            session, api_keys={token: {"examiner": "hermes", "role": "agent"}}
        )
        headers = [
            (b"authorization", f"Bearer {token}".encode("latin-1")),
            (b"x-forwarded-for", b"1.2.3.4"),
        ]
        messages: list[dict] = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(m):
            messages.append(m)

        await app(
            {
                "type": "http", "method": "GET", "path": "/mcp",
                "headers": headers, "client": ("5.6.7.8", 54321),
            },
            receive, send,
        )
        state = session.captured_scope["state"]
        # X-Forwarded-For not trusted from non-loopback client
        assert state["source_ip"] == "5.6.7.8"
