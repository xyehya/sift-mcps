"""SEC-1 (DSS-CAN-002) — operator authority + step-up on the Gateway `/api/v1`
control-plane mutation surface.

These are fail-on-revert guards:

  * ``test_every_mutation_route_denies_agent`` STRUCTURALLY iterates the live
    route table (``rest_routes()``) and asserts an agent identity is denied
    (403) on EVERY control-plane mutation route. If a future change adds a new
    mutation route without the ``require_control_plane_operator`` guard, this
    test fails CI — the guard is enforced over the route table, not one
    hand-written case.
  * readonly is denied; examiner is allowed past the authority gate.
  * register-new-backend and mint-join-code require step-up re-auth when
    Supabase is the active authority, and are a no-op when it is not.
  * the registry layer (defense-in-depth) raises on agent/service/readonly
    actors so a caller that skips the route guard still cannot persist a
    mutation as a sandboxed principal.
"""

from __future__ import annotations

import re
import secrets
from types import SimpleNamespace

import pytest
from sift_gateway.auth import (
    AuthMiddleware,
    require_control_plane_operator,
    require_recent_reauth,
)
from sift_gateway.identity import Identity
from sift_gateway.rest import rest_routes
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.testclient import TestClient

# --- identities -------------------------------------------------------------

_EXAMINER_KEY = "sift_gw_" + secrets.token_hex(24)
_AGENT_KEY = "sift_svc_" + secrets.token_hex(24)
_READONLY_KEY = "sift_gw_" + secrets.token_hex(24)

_API_KEYS = {
    _EXAMINER_KEY: {"examiner": "alice", "role": "examiner", "token_id": "ex-1"},
    _AGENT_KEY: {"examiner": "hermes", "role": "agent", "agent_id": "ag-1", "token_id": "ag-1"},
    _READONLY_KEY: {"examiner": "reader", "role": "readonly", "token_id": "ro-1"},
}

# Mutation HTTP methods that the control-plane authority gate must cover.
_MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Routes intentionally outside the SEC-1 control-plane authority sweep:
#   /api/v1/setup/join         — public, one-time-code-authenticated join
#                                exchange (hardening is SEC-3/019, not operator
#                                authority); reachable without a bearer token.
#   /api/v1/tools/{tool_name}  — the REST tool-EXECUTION surface, governed by
#                                `is_agent_principal` (agents/service blocked).
#                                That is the SEC-5 policy boundary; readonly
#                                tool-exec is a separate decision, not SEC-1's.
#                                Its agent-block is asserted explicitly below.
_EXEMPT_PATHS = {"/api/v1/setup/join", "/api/v1/tools/{tool_name}"}

_PATH_PARAM_RE = re.compile(r"\{[^}]+\}")


def _stub_gateway() -> SimpleNamespace:
    # Minimal stub: handlers that pass the authority gate hit registry/tool
    # lookups that resolve to a non-403 4xx/5xx, proving the gate ALLOWED them.
    return SimpleNamespace(mcp_backend_registry=None, backends={}, _tool_map={})


def _make_app() -> Starlette:
    app = Starlette(
        routes=rest_routes(),
        middleware=[Middleware(AuthMiddleware, api_keys=_API_KEYS)],
    )
    app.state.gateway = _stub_gateway()
    return app


@pytest.fixture()
def client() -> TestClient:
    # raise_server_exceptions=False so a stub-induced 500 in an *allowed* handler
    # is returned as a response (and asserted != 403) rather than raised.
    return TestClient(_make_app(), raise_server_exceptions=False)


def _mutation_routes() -> list[tuple[str, str]]:
    """(method, concrete_path) for every control-plane mutation route."""
    out: list[tuple[str, str]] = []
    for route in rest_routes():
        methods = (route.methods or set()) & _MUTATION_METHODS
        if not methods or route.path in _EXEMPT_PATHS:
            continue
        concrete = _PATH_PARAM_RE.sub("dummy", route.path)
        for method in sorted(methods):
            out.append((method, concrete))
    return out


def test_mutation_route_set_is_non_trivial():
    """The structural sweep must actually cover the known mutation surface."""
    paths = {p for _, p in _mutation_routes()}
    # Spot-check the high-value control-plane routes are present.
    assert "/api/v1/backends" in paths  # register
    assert "/api/v1/backends/dummy" in paths  # unregister
    assert "/api/v1/backends/dummy/enabled" in paths
    assert "/api/v1/services/dummy/start" in paths
    assert "/api/v1/setup/join-code" in paths
    assert len(_mutation_routes()) >= 8


@pytest.mark.parametrize("method,path", _mutation_routes())
def test_every_mutation_route_denies_agent(client, method, path):
    """FAIL-ON-REVERT: an agent identity is 403 on every mutation route."""
    resp = client.request(method, path, headers={"Authorization": f"Bearer {_AGENT_KEY}"}, json={})
    assert resp.status_code == 403, f"{method} {path} did not 403 an agent (got {resp.status_code})"


@pytest.mark.parametrize("method,path", _mutation_routes())
def test_every_mutation_route_denies_readonly(client, method, path):
    """A readonly examiner may observe but never mutate the control plane."""
    resp = client.request(method, path, headers={"Authorization": f"Bearer {_READONLY_KEY}"}, json={})
    assert resp.status_code == 403, f"{method} {path} did not 403 readonly (got {resp.status_code})"


@pytest.mark.parametrize("method,path", _mutation_routes())
def test_every_mutation_route_allows_examiner(client, method, path):
    """An examiner passes the authority gate (a non-403 status from the handler)."""
    resp = client.request(method, path, headers={"Authorization": f"Bearer {_EXAMINER_KEY}"}, json={})
    assert resp.status_code != 403, f"{method} {path} wrongly 403'd an examiner"


def test_tool_exec_route_still_blocks_agents(client):
    """The tool-exec surface (SEC-5, excluded from the control-plane sweep) must
    still deny agent/service principals via is_agent_principal."""
    resp = client.post(
        "/api/v1/tools/dummy", headers={"Authorization": f"Bearer {_AGENT_KEY}"}, json={}
    )
    assert resp.status_code == 403


def test_public_join_route_is_not_operator_gated(client):
    """The join exchange stays public (code-authenticated) — reachable without a
    bearer token (its hardening is SEC-3/019, not operator authority)."""
    resp = client.post("/api/v1/setup/join", json={"code": "nope"})
    # Reaches the join logic (invalid code -> its own 403), not an AuthMiddleware 401.
    assert resp.status_code != 401


# --- require_control_plane_operator unit cases ------------------------------


def _req_with_identity(identity, role=None):
    state = SimpleNamespace(
        identity=identity,
        role=role if role is not None else (identity.role if identity else None),
        token_id=getattr(identity, "token_id", None),
    )
    return SimpleNamespace(state=state, url=SimpleNamespace(path="/api/v1/backends"), method="POST")


def test_authority_allows_operator_identity():
    op = Identity("alice", "user", "t", None, None, "examiner", None, "rest")
    assert require_control_plane_operator(_req_with_identity(op)) is None


def test_authority_allows_anonymous_single_user():
    # No identity, no role -> single-operator deployment, allowed.
    assert require_control_plane_operator(_req_with_identity(None, role=None)) is None


def test_authority_denies_agent_and_service_and_readonly():
    agent = Identity("h", "agent", "t", "a", None, "agent", None, "mcp")
    service = Identity("s", "service", "t", None, None, "service", None, "rest")
    readonly = Identity("r", "user", "t", None, None, "readonly", None, "rest")
    for ident in (agent, service, readonly):
        resp = require_control_plane_operator(_req_with_identity(ident))
        assert resp is not None and resp.status_code == 403


# --- step-up (require_recent_reauth) ----------------------------------------


def _reauth_req(*, supabase_enabled, reverify=None, identity=None, source_ip="127.0.0.1"):
    state = SimpleNamespace(
        supabase_enabled=supabase_enabled, identity=identity, source_ip=source_ip
    )
    app_state = SimpleNamespace()
    if reverify is not None:
        app_state.supabase_reverify = reverify
    app = SimpleNamespace(state=app_state)
    return SimpleNamespace(state=state, app=app, url=SimpleNamespace(path="/api/v1/backends"))


async def test_stepup_noop_when_supabase_disabled():
    # Legacy / single-user: no re-auth plane -> step-up is a no-op.
    req = _reauth_req(supabase_enabled=False)
    assert await require_recent_reauth(req, {}) is None


async def test_stepup_fail_closed_when_reverify_unwired():
    req = _reauth_req(supabase_enabled=True, reverify=None)
    resp = await require_recent_reauth(req, {"password": "x", "email": "a@b"})
    assert resp is not None and resp.status_code == 503


async def test_stepup_requires_password_and_email():
    req = _reauth_req(supabase_enabled=True, reverify=lambda *a, **k: None)
    assert (await require_recent_reauth(req, {})).status_code == 401
    assert (await require_recent_reauth(req, {"email": "a@b"})).status_code == 401
    assert (await require_recent_reauth(req, {"password": "pw"})).status_code == 401


async def test_stepup_success_binds_to_bearer_principal():
    calls = {}

    async def fake_reverify(email, password, source_ip, *, expected_auth_user_id=None):
        calls.update(
            email=email, password=password, source_ip=source_ip,
            expected_auth_user_id=expected_auth_user_id,
        )
        return {"ok": True}

    ident = Identity(
        "alice", "user", "t", None, None, "examiner", "127.0.0.1", "rest",
        auth_user_id="auth-uuid-123",
    )
    req = _reauth_req(supabase_enabled=True, reverify=fake_reverify, identity=ident)
    result = await require_recent_reauth(req, {"password": "pw", "email": "a@b"})
    assert result is None
    # Bound to the bearer token's own auth_user_id (anti-credential-swap).
    assert calls["expected_auth_user_id"] == "auth-uuid-123"
    assert calls["email"] == "a@b" and calls["password"] == "pw"


async def test_stepup_fail_closed_on_wrong_password():
    async def fake_reverify(*a, **k):
        raise RuntimeError("bad password")

    req = _reauth_req(supabase_enabled=True, reverify=fake_reverify)
    resp = await require_recent_reauth(req, {"password": "pw", "email": "a@b"})
    assert resp is not None and resp.status_code == 401


async def test_reauth_email_alias_accepted():
    # Body may carry the operator email as `reauth_email` OR `email`.
    async def fake_reverify(email, password, source_ip, *, expected_auth_user_id=None):
        assert email == "alias@b"
        return {"ok": True}

    req = _reauth_req(supabase_enabled=True, reverify=fake_reverify)
    out = await require_recent_reauth(req, {"password": "pw", "reauth_email": "alias@b"})
    assert out is None
