"""Phase 13 gateway auth and token behavior.

Drivers: SIFT-MCPS-PLAN.md Phase 13 / TASKS.md 13a-13b.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from sift_gateway.auth import verify_api_key
from sift_gateway.identity import resolve_identity
from sift_gateway.mcp_endpoint import MCPAuthASGIApp
from sift_gateway.server import _NormalizeMCPPath
from sift_gateway.token_gen import (
    generate_gateway_token,
    generate_service_token,
    token_fingerprint,
    token_hash,
)
from sift_gateway.token_registry import PostgresTokenRegistry, RegistryToken
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount
from starlette.testclient import TestClient


class _FakeSessionManager:
    def __init__(self) -> None:
        self.called = False

    async def handle_request(self, scope, receive, send) -> None:
        self.called = True


class _FakeRegistry:
    def __init__(self, mapping):
        self.mapping = mapping
        self.lookups = 0

    def lookup_token(self, token):
        self.lookups += 1
        return self.mapping.get(token)


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


def test_token_hash_uses_pepper_and_fingerprint_is_non_secret():
    token = "sift_svc_" + secrets.token_hex(24)
    assert token_hash(token, "pepper-a") != token_hash(token, "pepper-b")
    assert token_hash(token, "pepper-a") != token
    fingerprint = token_fingerprint(token)
    assert fingerprint == token_fingerprint(token)
    assert len(fingerprint) == 16
    int(fingerprint, 16)
    assert fingerprint != token


def test_db_token_validation_accepts_active_unexpired_scoped_token():
    token = "sift_svc_" + secrets.token_hex(24)
    record = RegistryToken(
        id="11111111-1111-1111-1111-111111111111",
        token_fingerprint=token_fingerprint(token),
        role="agent",
        principal="hermes",
        principal_type="agent",
        agent_id="hermes",
        service_identity_id=None,
        created_by="alice",
        case_id=None,
        label="Hermes",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        scopes=frozenset({"mcp:*"}),
    )
    identity = resolve_identity(
        token,
        api_keys={},
        token_registry=_FakeRegistry({token: record}),
    )
    assert identity is not None
    assert identity.principal == "hermes"
    assert identity.principal_type == "agent"
    assert identity.token_id == record.id
    assert identity.tool_scopes == frozenset({"mcp:*"})


def test_db_token_validation_rejects_unscoped_token():
    registry = PostgresTokenRegistry(dsn="postgresql://example", pepper="pepper")
    row = (
        "11111111-1111-1111-1111-111111111111",
        "0123456789abcdef",
        "active",
        None,
        None,
        None,
        None,
        "label",
        datetime.now(timezone.utc) + timedelta(days=1),
        None,
        '{"role":"agent","legacy_agent_id":"hermes"}',
        [],
    )
    assert registry._row_to_registry_token(row) is None


def test_db_token_validation_rejects_revoked_expired_or_disabled_rows():
    registry = PostgresTokenRegistry(dsn="postgresql://example", pepper="pepper")
    base = (
        "11111111-1111-1111-1111-111111111111",
        "0123456789abcdef",
        "active",
        None,
        None,
        None,
        None,
        "label",
        datetime.now(timezone.utc) + timedelta(days=1),
        None,
        '{"role":"agent","legacy_agent_id":"hermes"}',
        ["mcp:*"],
    )
    assert registry._row_to_registry_token(base[:2] + ("disabled",) + base[3:]) is None
    expired = base[:8] + (datetime.now(timezone.utc) - timedelta(seconds=1),) + base[9:]
    assert registry._row_to_registry_token(expired) is None
    revoked = base[:9] + (datetime.now(timezone.utc),) + base[10:]
    assert registry._row_to_registry_token(revoked) is None


def test_legacy_gateway_yaml_fallback_still_works_when_db_misses():
    token = "sift_svc_" + secrets.token_hex(24)
    registry = _FakeRegistry({})
    identity = resolve_identity(
        token,
        api_keys={token: {"examiner": "legacy-agent", "role": "agent", "token_id": "legacy-1"}},
        token_registry=registry,
    )
    assert identity is not None
    assert identity.token_id == "legacy-1"
    assert identity.principal == "legacy-agent"
    assert registry.lookups == 1


def test_db_token_precedes_legacy_fallback():
    token = "sift_svc_" + secrets.token_hex(24)
    record = RegistryToken(
        id="22222222-2222-2222-2222-222222222222",
        token_fingerprint=token_fingerprint(token),
        role="agent",
        principal="db-agent",
        principal_type="agent",
        agent_id="db-agent",
        service_identity_id=None,
        created_by="alice",
        case_id=None,
        label="DB",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        scopes=frozenset({"mcp:*"}),
    )
    identity = resolve_identity(
        token,
        api_keys={token: {"examiner": "legacy-agent", "role": "agent", "token_id": "legacy-1"}},
        token_registry=_FakeRegistry({token: record}),
    )
    assert identity is not None
    assert identity.token_id == record.id
    assert identity.principal == "db-agent"


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
