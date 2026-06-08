"""PR03A / Batch A — Supabase JWT auth for REST and FastMCP /mcp.

All Supabase HTTP is mocked and the principal repository is faked; no live
network or DB. Verifies the shared resolver, REST AuthMiddleware Supabase-first
behavior with explicit legacy flags, the FastMCP TokenVerifier, the B-14 raw
ASGI no-duplicate-lookup guarantee, and that raw token material never reaches
logs or audit.
"""

from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from sift_gateway.auth import AuthMiddleware
from sift_gateway.identity import CaseMembership, Identity
from sift_gateway.mcp_endpoint import MCPAuthASGIApp, SiftTokenVerifier
from sift_gateway.supabase_auth import (
    AmbiguousPrincipalError,
    PrincipalDisabledError,
    PrincipalNotMappedError,
    PrincipalRecord,
    SupabaseAuthConfig,
    SupabaseIdentityResolver,
    SupabaseUnavailableError,
    InvalidTokenError,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


_OPERATOR_TOKEN = "supabase.jwt.operator"
_AGENT_TOKEN = "supabase.jwt.agent"
_DISABLED_TOKEN = "supabase.jwt.disabled"
_UNMAPPED_TOKEN = "supabase.jwt.unmapped"
_INVALID_TOKEN = "supabase.jwt.invalid"

_USER_BY_TOKEN = {
    _OPERATOR_TOKEN: {"id": "auth-operator"},
    _AGENT_TOKEN: {"id": "auth-agent"},
    _DISABLED_TOKEN: {"id": "auth-disabled"},
    _UNMAPPED_TOKEN: {"id": "auth-unmapped"},
}

_RECORDS = {
    "auth-operator": PrincipalRecord(
        principal_type="operator", principal_id="op-1", auth_user_id="auth-operator",
        display_name="Alice", email="alice@example.com", status="active",
        system_role="owner", default_case_id="case-1",
        case_memberships=(CaseMembership(case_id="case-1", role="lead"),),
        tool_scopes=("mcp:*",),
    ),
    "auth-agent": PrincipalRecord(
        principal_type="agent", principal_id="ag-1", auth_user_id="auth-agent",
        display_name="Hermes", email=None, status="active", system_role="ai",
        default_case_id="case-1", case_memberships=(),
        tool_scopes=("mcp:*",),
    ),
    "auth-disabled": PrincipalRecord(
        principal_type="agent", principal_id="ag-2", auth_user_id="auth-disabled",
        display_name="OldBot", email=None, status="disabled", system_role="ai",
        default_case_id=None, case_memberships=(), tool_scopes=("mcp:*",),
    ),
    # auth-unmapped intentionally absent from repo.
}


class _FakeClient:
    def __init__(self):
        self.calls = 0

    async def get_user(self, access_token):
        self.calls += 1
        user = _USER_BY_TOKEN.get(access_token)
        if user is None:
            raise InvalidTokenError("rejected")
        return user


class _FakeRepo:
    def __init__(self):
        self.lookups = 0

    def lookup_by_auth_user_id(self, auth_user_id):
        self.lookups += 1
        return _RECORDS.get(auth_user_id)


def _resolver(ttl=30):
    cfg = SupabaseAuthConfig(enabled=True, url="http://supabase.local",
                             anon_key="anon", principal_cache_ttl_seconds=ttl)
    return SupabaseIdentityResolver(cfg, client=_FakeClient(), repository=_FakeRepo())


def _config(**kw):
    base = dict(enabled=True, url="http://supabase.local", anon_key="anon")
    base.update(kw)
    return SupabaseAuthConfig(**base)


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


async def test_resolver_resolves_operator():
    identity = await _resolver().resolve(_OPERATOR_TOKEN, auth_surface="rest")
    assert identity.principal_id == "op-1"
    assert identity.principal_type == "user"
    assert identity.auth_user_id == "auth-operator"
    assert identity.system_role == "owner"
    assert identity.role == "examiner"
    assert identity.tool_scopes == frozenset({"mcp:*"})
    assert identity.case_memberships == (CaseMembership(case_id="case-1", role="lead"),)
    # Non-secret fingerprint only; never the raw token.
    assert identity.token_fingerprint and identity.token_fingerprint != _OPERATOR_TOKEN


async def test_resolver_resolves_agent_on_mcp():
    identity = await _resolver().resolve(_AGENT_TOKEN, auth_surface="mcp")
    assert identity.principal_type == "agent"
    assert identity.role == "agent"
    assert identity.auth_surface == "mcp"


async def test_resolver_rejects_invalid_token():
    with pytest.raises(InvalidTokenError):
        await _resolver().resolve(_INVALID_TOKEN)


async def test_resolver_unmapped_is_403():
    with pytest.raises(PrincipalNotMappedError) as exc:
        await _resolver().resolve(_UNMAPPED_TOKEN)
    assert exc.value.http_status == 403


async def test_resolver_disabled_is_403():
    with pytest.raises(PrincipalDisabledError) as exc:
        await _resolver().resolve(_DISABLED_TOKEN)
    assert exc.value.http_status == 403


async def test_resolver_positive_cache_avoids_second_user_call():
    resolver = _resolver(ttl=60)
    await resolver.resolve(_OPERATOR_TOKEN)
    await resolver.resolve(_OPERATOR_TOKEN)
    assert resolver._client.calls == 1  # cached second time
    assert resolver._repository.lookups == 1


async def test_resolver_ttl_zero_disables_cache():
    resolver = _resolver(ttl=0)
    await resolver.resolve(_OPERATOR_TOKEN)
    await resolver.resolve(_OPERATOR_TOKEN)
    assert resolver._client.calls == 2


# ---------------------------------------------------------------------------
# REST AuthMiddleware
# ---------------------------------------------------------------------------


async def _whoami(request: Request) -> JSONResponse:
    ident = getattr(request.state, "identity", None)
    return JSONResponse({
        "principal_id": getattr(ident, "principal_id", None),
        "principal_type": getattr(ident, "principal_type", None),
        "reached": True,
    })


def _rest_app(*, resolver=None, auth_config=None, api_keys=None, token_registry=None):
    return Starlette(
        routes=[Route("/api/v1/protected", _whoami, methods=["GET", "POST"])],
        middleware=[Middleware(
            AuthMiddleware, api_keys=api_keys, token_registry=token_registry,
            resolver=resolver, auth_config=auth_config,
        )],
    )


def test_rest_valid_jwt_resolves_operator():
    app = _rest_app(resolver=_resolver(), auth_config=_config())
    client = TestClient(app)
    resp = client.get("/api/v1/protected", headers={"Authorization": f"Bearer {_OPERATOR_TOKEN}"})
    assert resp.status_code == 200
    assert resp.json()["principal_id"] == "op-1"


def test_rest_missing_token_is_401():
    app = _rest_app(resolver=_resolver(), auth_config=_config())
    resp = TestClient(app).get("/api/v1/protected")
    assert resp.status_code == 401


def test_rest_unmapped_jwt_is_403():
    app = _rest_app(resolver=_resolver(), auth_config=_config())
    resp = TestClient(app).get("/api/v1/protected",
                               headers={"Authorization": f"Bearer {_UNMAPPED_TOKEN}"})
    assert resp.status_code == 403


def test_rest_disabled_principal_is_403():
    app = _rest_app(resolver=_resolver(), auth_config=_config())
    resp = TestClient(app).get("/api/v1/protected",
                               headers={"Authorization": f"Bearer {_DISABLED_TOKEN}"})
    assert resp.status_code == 403


def test_rest_invalid_jwt_is_403_when_no_fallback():
    app = _rest_app(resolver=_resolver(),
                    auth_config=_config(legacy_token_fallback_enabled=False))
    resp = TestClient(app).get("/api/v1/protected",
                               headers={"Authorization": f"Bearer {_INVALID_TOKEN}"})
    assert resp.status_code == 403


def test_rest_pr02_fallback_only_when_legacy_flag_enabled():
    api_keys = {"legacy-key": {"examiner": "bob", "role": "examiner", "token_id": "t-bob"}}
    # Fallback ENABLED → legacy key works.
    app_on = _rest_app(resolver=_resolver(),
                       auth_config=_config(legacy_token_fallback_enabled=True),
                       api_keys=api_keys)
    resp = TestClient(app_on).get("/api/v1/protected",
                                  headers={"Authorization": "Bearer legacy-key"})
    assert resp.status_code == 200
    # Fallback DISABLED → legacy key rejected.
    app_off = _rest_app(resolver=_resolver(),
                        auth_config=_config(legacy_token_fallback_enabled=False),
                        api_keys=api_keys)
    resp = TestClient(app_off).get("/api/v1/protected",
                                   headers={"Authorization": "Bearer legacy-key"})
    assert resp.status_code == 403


def test_rest_anonymous_examiner_only_when_explicitly_enabled():
    # No keys, no registry, Supabase off, anonymous DISABLED (PR03 default) → 401.
    app_deny = _rest_app(auth_config=_config(enabled=False,
                                             legacy_anonymous_examiner_enabled=False))
    resp = TestClient(app_deny).get("/api/v1/protected")
    assert resp.status_code == 401
    # Anonymous explicitly ENABLED → anonymous examiner reaches the route.
    app_allow = _rest_app(auth_config=_config(enabled=False,
                                              legacy_anonymous_examiner_enabled=True))
    resp = TestClient(app_allow).get("/api/v1/protected")
    assert resp.status_code == 200


def test_rest_no_token_material_in_logs(caplog):
    app = _rest_app(resolver=_resolver(), auth_config=_config())
    with caplog.at_level(logging.DEBUG):
        TestClient(app).get("/api/v1/protected",
                            headers={"Authorization": f"Bearer {_OPERATOR_TOKEN}"})
        TestClient(app).get("/api/v1/protected",
                            headers={"Authorization": f"Bearer {_INVALID_TOKEN}"})
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert _OPERATOR_TOKEN not in blob
    assert _INVALID_TOKEN not in blob


# ---------------------------------------------------------------------------
# FastMCP TokenVerifier
# ---------------------------------------------------------------------------


async def test_verifier_accepts_agent_jwt():
    verifier = SiftTokenVerifier(resolver=_resolver(), legacy_fallback_enabled=False)
    token = await verifier.verify_token(_AGENT_TOKEN)
    assert token is not None
    assert token.client_id == "ag-1"
    assert token.scopes == ["mcp:*"]
    assert token.claims["sift_identity"]["principal_type"] == "agent"
    # Raw token round-trips as AccessToken.token (FastMCP contract) but the SIFT
    # identity claims never carry it.
    assert _AGENT_TOKEN not in str(token.claims)


async def test_verifier_rejects_invalid_jwt():
    verifier = SiftTokenVerifier(resolver=_resolver(), legacy_fallback_enabled=False)
    assert await verifier.verify_token(_INVALID_TOKEN) is None


async def test_verifier_rejects_disabled_principal():
    verifier = SiftTokenVerifier(resolver=_resolver(), legacy_fallback_enabled=False)
    assert await verifier.verify_token(_DISABLED_TOKEN) is None


async def test_verifier_pr02_fallback_gated_by_flag():
    from datetime import datetime, timedelta, timezone

    from sift_gateway.token_gen import token_fingerprint
    from sift_gateway.token_registry import RegistryToken

    raw = "sift_svc_" + "a" * 48
    record = RegistryToken(
        id="reg-1", token_fingerprint=token_fingerprint(raw), role="agent",
        principal="legacy", principal_type="agent", agent_id="legacy",
        service_identity_id=None, created_by="op", case_id=None, label="L",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        scopes=frozenset({"mcp:*"}),
    )

    class _Reg:
        def lookup_token(self, t):
            return record if t == raw else None

    # Fallback OFF → registry token rejected.
    off = SiftTokenVerifier(resolver=_resolver(), token_registry=_Reg(),
                            legacy_fallback_enabled=False)
    assert await off.verify_token(raw) is None
    # Fallback ON → registry token accepted.
    on = SiftTokenVerifier(resolver=_resolver(), token_registry=_Reg(),
                           legacy_fallback_enabled=True)
    assert (await on.verify_token(raw)) is not None


# ---------------------------------------------------------------------------
# B-14: raw ASGI path does NOT do a duplicate token lookup
# ---------------------------------------------------------------------------


class _FakeSession:
    def __init__(self):
        self.called = False

    async def handle_request(self, scope, receive, send):
        self.called = True


class _CountingRegistry:
    def __init__(self):
        self.lookups = 0

    def lookup_token(self, token):
        self.lookups += 1
        return None


async def _drive(app, headers):
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m):
        messages.append(m)

    await app(
        {"type": "http", "method": "GET", "path": "/mcp",
         "headers": headers, "client": ("127.0.0.1", 1234)},
        receive, send,
    )
    return messages


async def test_b14_raw_asgi_does_not_resolve_when_verifier_owns_identity():
    registry = _CountingRegistry()
    session = _FakeSession()
    app = MCPAuthASGIApp(
        session,
        token_registry=registry,
        verifier_owns_identity=True,
    )
    await _drive(app, [(b"authorization", b"Bearer supabase.jwt.agent")])
    # The raw ASGI guard delegated WITHOUT calling the token registry — the
    # FastMCP verifier owns the single lookup (B-14).
    assert registry.lookups == 0
    assert session.called is True


async def test_b14_legacy_mode_still_resolves_in_raw_asgi():
    # Backward-compat: when the verifier does not own identity, the raw guard
    # keeps doing its own resolution (one lookup), preserving pre-PR03 behavior.
    registry = _CountingRegistry()
    session = _FakeSession()
    app = MCPAuthASGIApp(session, token_registry=registry, verifier_owns_identity=False)
    await _drive(app, [(b"authorization", b"Bearer some-token")])
    assert registry.lookups == 1


# ---------------------------------------------------------------------------
# Remediation: B2 — ambiguous principal fails CLOSED
# ---------------------------------------------------------------------------


class _AmbiguousRepo:
    """Simulates SupabasePrincipalRepository raising on >1 linked principal."""

    def lookup_by_auth_user_id(self, auth_user_id):
        raise AmbiguousPrincipalError("auth user maps to multiple app principals")


def _ambiguous_resolver():
    cfg = SupabaseAuthConfig(enabled=True, url="http://supabase.local", anon_key="anon")
    return SupabaseIdentityResolver(cfg, client=_FakeClient(), repository=_AmbiguousRepo())


async def test_b2_ambiguous_principal_denied_403():
    with pytest.raises(AmbiguousPrincipalError) as exc:
        await _ambiguous_resolver().resolve(_OPERATOR_TOKEN)
    assert exc.value.http_status == 403


def test_b2_ambiguous_principal_rest_is_403():
    app = _rest_app(resolver=_ambiguous_resolver(),
                    auth_config=_config(legacy_token_fallback_enabled=False))
    resp = TestClient(app).get("/api/v1/protected",
                               headers={"Authorization": f"Bearer {_OPERATOR_TOKEN}"})
    assert resp.status_code == 403


def test_b2_repository_raises_on_multiple_rows():
    # Unit-test the real repository's fail-closed path with a fake cursor that
    # returns two rows for one auth_user_id.
    from sift_gateway.supabase_auth import SupabasePrincipalRepository

    repo = SupabasePrincipalRepository.__new__(SupabasePrincipalRepository)

    class _Cur:
        def execute(self, *a, **k):
            pass

        def fetchall(self):
            return [
                ("operator", "op-1", "auth-x", "Op", "o@x", "active", "owner", None),
                ("agent", "ag-1", "auth-x", "Ag", None, "active", "ai", None),
            ]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Conn:
        def cursor(self):
            return _Cur()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    repo._connect = lambda: _Conn()  # type: ignore[method-assign]
    with pytest.raises(AmbiguousPrincipalError):
        repo.lookup_by_auth_user_id("auth-x")


# ---------------------------------------------------------------------------
# Remediation: B5 — case-scoped grant is inert at PR03 (only global scopes)
# ---------------------------------------------------------------------------


def _scope_repo(rows):
    from sift_gateway.supabase_auth import SupabasePrincipalRepository

    repo = SupabasePrincipalRepository.__new__(SupabasePrincipalRepository)
    captured = {}

    class _Cur:
        def execute(self, sql, params=None):
            captured["sql"] = sql

        def fetchall(self):
            return rows

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    repo._cur = _Cur()  # type: ignore[attr-defined]
    return repo, captured


def test_b5_load_scopes_query_filters_to_global_only():
    repo, captured = _scope_repo([("mcp:*",)])
    scopes = repo._load_scopes(repo._cur, "agent", "ag-1")
    assert scopes == ("mcp:*",)
    # The query must constrain to global (case_id is null) scopes.
    assert "case_id is null" in captured["sql"]


def _identity_with_scopes(scopes):
    return Identity(
        principal="p", principal_type="agent", token_id="t", agent_id="a",
        created_by=None, role="agent", source_ip=None, auth_surface="mcp",
        tool_scopes=frozenset(scopes),
    )


def test_b5_global_scope_grants_case_scoped_inert():
    from sift_gateway.supabase_auth import is_tool_allowed

    # Only a global mcp:* row is loaded (case-scoped rows are filtered out by SQL).
    assert is_tool_allowed(_identity_with_scopes(("mcp:*",)), "run_command")
    # A principal whose only grant is case-scoped loads NO scopes at PR03.
    assert not is_tool_allowed(_identity_with_scopes(()), "run_command")


# ---------------------------------------------------------------------------
# Remediation: B8 — cache keyed on full digest, not 16-hex fingerprint
# ---------------------------------------------------------------------------


async def test_b8_cache_uses_full_digest_key():
    from sift_gateway.token_gen import token_digest, token_fingerprint

    resolver = _resolver(ttl=60)
    await resolver.resolve(_OPERATOR_TOKEN)
    # The cache is keyed on the full 64-hex digest, never the 16-hex fingerprint.
    keys = list(resolver._cache.keys())
    assert keys == [token_digest(_OPERATOR_TOKEN)]
    assert token_fingerprint(_OPERATOR_TOKEN) not in resolver._cache
    assert all(len(k) == 64 for k in keys)


# ---------------------------------------------------------------------------
# Remediation: B9 — outage vs invalid; legacy-disabled + 5xx => 503
# ---------------------------------------------------------------------------


class _OutageClient:
    async def get_user(self, access_token):
        raise SupabaseUnavailableError("backend down")


def _outage_resolver():
    cfg = SupabaseAuthConfig(enabled=True, url="http://supabase.local", anon_key="anon")
    return SupabaseIdentityResolver(cfg, client=_OutageClient(), repository=_FakeRepo())


def test_b9b_legacy_disabled_supabase_5xx_is_503():
    app = _rest_app(resolver=_outage_resolver(),
                    auth_config=_config(legacy_token_fallback_enabled=False))
    resp = TestClient(app).get("/api/v1/protected",
                               headers={"Authorization": f"Bearer {_OPERATOR_TOKEN}"})
    assert resp.status_code == 503


def test_b9b_legacy_enabled_supabase_5xx_falls_through_to_bridge():
    api_keys = {"legacy-key": {"examiner": "bob", "role": "examiner", "token_id": "t-bob"}}
    app = _rest_app(resolver=_outage_resolver(),
                    auth_config=_config(legacy_token_fallback_enabled=True),
                    api_keys=api_keys)
    # Supabase is down, but legacy fallback is enabled → the bridge authenticates.
    resp = TestClient(app).get("/api/v1/protected",
                               headers={"Authorization": "Bearer legacy-key"})
    assert resp.status_code == 200


async def test_b9a_verifier_logs_outage_distinctly(caplog):
    verifier = SiftTokenVerifier(resolver=_outage_resolver(), legacy_fallback_enabled=False)
    with caplog.at_level(logging.WARNING):
        result = await verifier.verify_token(_OPERATOR_TOKEN)
    assert result is None  # no fallback, outage => deny
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert "unavailable" in blob.lower()
    # No token material in the outage log.
    assert _OPERATOR_TOKEN not in blob


# ---------------------------------------------------------------------------
# Remediation: B4 — revoke of a non-existent principal fails (no false success)
# ---------------------------------------------------------------------------


class _FakeAdminClient:
    def __init__(self):
        self.revoked = []

    async def admin_revoke_user(self, user_id, *, delete=True):
        self.revoked.append(user_id)


def _issuance_with_rows(update_returns):
    """Build an AgentServiceIssuance whose UPDATE returns ``update_returns``.

    ``update_returns`` is the fetchone() result of the principal UPDATE:
    None => zero-row (no such principal); a 1-tuple => matched row.
    """
    from sift_gateway.supabase_auth import (
        AgentServiceIssuance,
        SupabaseAuthConfig,
    )

    cfg = SupabaseAuthConfig(enabled=True, url="http://supabase.local", anon_key="anon",
                             service_role_key="svc")
    issuance = AgentServiceIssuance.__new__(AgentServiceIssuance)
    issuance._config = cfg
    issuance._client = _FakeAdminClient()
    issuance._dsn = "postgresql://example"
    audit = MagicMock()
    audit.log = MagicMock()
    issuance._audit = audit

    committed = {"commit": 0, "rollback": 0}

    class _Cur:
        def __init__(self):
            self._fetch = update_returns

        def execute(self, sql, params=None):
            # First execute is the principal UPDATE; later are scope updates.
            if "update app.principal_tool_scopes" not in sql:
                self._fetch = update_returns

        def fetchone(self):
            return self._fetch

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Conn:
        def cursor(self):
            return _Cur()

        def commit(self):
            committed["commit"] += 1

        def rollback(self):
            committed["rollback"] += 1

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    issuance._connect = lambda: _Conn()  # type: ignore[method-assign]
    return issuance, committed


async def test_b4_revoke_unknown_principal_raises_404_no_success():
    from sift_gateway.supabase_auth import PrincipalNotFoundError

    issuance, committed = _issuance_with_rows(None)  # zero-row update
    creator = {"system_role": "admin", "principal_id": "op-1"}
    with pytest.raises(PrincipalNotFoundError) as exc:
        await issuance.revoke_principal(creator, "agent", "does-not-exist", None)
    assert exc.value.http_status == 404
    # No Supabase session revoke, no false-success audit, no commit.
    assert issuance._client.revoked == []
    assert issuance._audit.log.call_count == 0
    assert committed["commit"] == 0
    assert committed["rollback"] == 1


async def test_b4_revoke_existing_principal_succeeds():
    issuance, committed = _issuance_with_rows(("auth-agent-1",))  # matched row
    creator = {"system_role": "owner", "principal_id": "op-1"}
    await issuance.revoke_principal(creator, "agent", "ag-1", None)
    # Supabase user revoked and a success audited.
    assert issuance._client.revoked == ["auth-agent-1"]
    assert issuance._audit.log.call_count == 1
    assert issuance._audit.log.call_args.kwargs["result_summary"].startswith("agent")
    assert committed["commit"] == 1


# ---------------------------------------------------------------------------
# D31 — revocation model: pinned Supabase v1.26.05 lacks admin session logout
# (POST /admin/users/{id}/logout 404), so revoke DELETEs the auth user and the
# resolver cache is invalidated proactively.
# ---------------------------------------------------------------------------


class _FakeResp:
    def __init__(self, status_code):
        self.status_code = status_code


class _RecordingHttpx:
    def __init__(self, delete_status=200):
        self.calls = []
        self._delete_status = delete_status

    async def delete(self, url, headers=None):
        self.calls.append(("DELETE", url))
        return _FakeResp(self._delete_status)

    async def post(self, url, headers=None, json=None):
        self.calls.append(("POST", url))
        return _FakeResp(404)


def _admin_client(delete_status=200):
    from sift_gateway.supabase_auth import SupabaseAuthConfig, SupabaseAuthClient

    cfg = SupabaseAuthConfig(enabled=True, url="http://supabase.local", anon_key="anon",
                             service_role_key="svc")
    http = _RecordingHttpx(delete_status=delete_status)
    return SupabaseAuthClient(cfg, client=http), http


async def test_d31_admin_revoke_deletes_user_and_never_calls_logout():
    client, http = _admin_client(delete_status=200)
    await client.admin_revoke_user("u-1", delete=True)
    methods = [m for m, _ in http.calls]
    urls = [u for _, u in http.calls]
    assert methods == ["DELETE"]  # exactly one call, no /logout POST
    assert urls == ["http://supabase.local/auth/v1/admin/users/u-1"]
    assert not any("/logout" in u for u in urls)


async def test_d31_admin_revoke_idempotent_on_404():
    client, http = _admin_client(delete_status=404)
    await client.admin_revoke_user("already-gone", delete=True)  # no raise
    assert [m for m, _ in http.calls] == ["DELETE"]


async def test_d31_admin_revoke_raises_on_server_error():
    from sift_gateway.supabase_auth import SupabaseAuthError

    client, _ = _admin_client(delete_status=500)
    with pytest.raises(SupabaseAuthError):
        await client.admin_revoke_user("u-2", delete=True)


async def test_d31_admin_revoke_delete_false_is_noop():
    client, http = _admin_client(delete_status=200)
    await client.admin_revoke_user("u-3", delete=False)
    assert http.calls == []  # no Supabase-side call


async def test_d31_revoke_invalidates_resolver_cache():
    from sift_gateway.supabase_auth import SupabaseAuthConfig, SupabaseAuthCallbacks

    cfg = SupabaseAuthConfig(enabled=True, url="http://supabase.local", anon_key="anon",
                             service_role_key="svc")
    cb = SupabaseAuthCallbacks.__new__(SupabaseAuthCallbacks)
    cb._config = cfg
    cb._audit = None
    cb._resolver = MagicMock()

    class _Iss:
        async def revoke_principal(self, creator, ptype, pid, ip):
            return "auth-xyz"

    cb._issuance = _Iss()
    await cb.revoke_principal({"system_role": "admin", "principal_id": "op-1"},
                              "agent", "ag-1", None)
    cb._resolver.invalidate_principal.assert_called_once_with("auth-xyz")


async def test_d31_invalidate_principal_drops_only_matching_entries():
    import time as _t
    from sift_gateway.supabase_auth import (
        SupabaseIdentityResolver, SupabaseAuthConfig, _CacheEntry,
    )
    from sift_gateway.identity import Identity

    cfg = SupabaseAuthConfig(enabled=True, url="http://x", anon_key="a",
                             principal_cache_ttl_seconds=30)
    r = SupabaseIdentityResolver(cfg)

    def _id(name, auth_user_id):
        return Identity(principal=name, principal_type="agent", token_id=None,
                        agent_id=None, created_by=None, role="agent",
                        source_ip=None, auth_surface="mcp", auth_user_id=auth_user_id)

    r._cache["k1"] = _CacheEntry(identity=_id("a", "U1"), expires_at=_t.monotonic() + 30)
    r._cache["k2"] = _CacheEntry(identity=_id("b", "U2"), expires_at=_t.monotonic() + 30)
    r.invalidate_principal("U1")
    assert "k1" not in r._cache
    assert "k2" in r._cache


# ---------------------------------------------------------------------------
# C3 completion: list_principals (operator roster, no token material)
# ---------------------------------------------------------------------------


_SECRET_KEYS = {"access_token", "refresh_token", "token", "password",
                "temp_password", "token_hash", "service_role_key", "anon_key"}


class _RosterRepo:
    """Fake repository: returns agents owned by a given operator + services."""

    def __init__(self):
        self.calls = []

    def list_principals(self, *, owner_operator_profile_id=None):
        self.calls.append(owner_operator_profile_id)
        agents = [
            {"principal_type": "agent", "principal_id": "ag-1", "display_name": "Hermes",
             "status": "active", "type": "ai", "auth_user_id": "auth-ag-1",
             "owner_user_id": "op-1", "tool_scopes": ["mcp:*"]},
            {"principal_type": "agent", "principal_id": "ag-2", "display_name": "Other",
             "status": "active", "type": "ai", "auth_user_id": "auth-ag-2",
             "owner_user_id": "op-2", "tool_scopes": []},
        ]
        services = [
            {"principal_type": "service", "principal_id": "sv-1", "display_name": "worker",
             "status": "active", "type": "worker", "auth_user_id": "auth-sv-1",
             "owner_user_id": None, "tool_scopes": ["namespace:opensearch"]},
        ]
        if owner_operator_profile_id is None:
            return agents + services
        return [a for a in agents if a["owner_user_id"] == owner_operator_profile_id]


def _roster_callbacks():
    from sift_gateway.supabase_auth import SupabaseAuthCallbacks

    cb = SupabaseAuthCallbacks.__new__(SupabaseAuthCallbacks)
    cb._repository = _RosterRepo()
    audit = MagicMock()
    audit.log = MagicMock()
    cb._audit = audit
    return cb


def _assert_no_secret_keys(items):
    for item in items:
        leaked = _SECRET_KEYS & set(item.keys())
        assert not leaked, f"principal dict leaked secret keys: {leaked}"


async def test_list_principals_owner_lists_all():
    cb = _roster_callbacks()
    creator = {"principal_type": "operator", "system_role": "owner", "principal_id": "op-1"}
    result = await cb.list_principals(creator, "1.2.3.4")
    # owner/admin => all agents + services, no owner filter.
    assert cb._repository.calls == [None]
    ids = {(p["principal_type"], p["principal_id"]) for p in result}
    assert ids == {("agent", "ag-1"), ("agent", "ag-2"), ("service", "sv-1")}
    _assert_no_secret_keys(result)


async def test_list_principals_admin_lists_all():
    cb = _roster_callbacks()
    creator = {"principal_type": "operator", "system_role": "admin", "principal_id": "op-9"}
    result = await cb.list_principals(creator, None)
    assert cb._repository.calls == [None]
    assert len(result) == 3


async def test_list_principals_non_owner_lists_only_owned():
    cb = _roster_callbacks()
    creator = {"principal_type": "operator", "system_role": "operator", "principal_id": "op-1"}
    result = await cb.list_principals(creator, "1.2.3.4")
    # Non-owner operator => filtered to principals they own (op-1 owns ag-1 only).
    assert cb._repository.calls == ["op-1"]
    assert [(p["principal_type"], p["principal_id"]) for p in result] == [("agent", "ag-1")]
    _assert_no_secret_keys(result)


async def test_list_principals_audits_without_secrets():
    cb = _roster_callbacks()
    creator = {"principal_type": "operator", "system_role": "owner", "principal_id": "op-1"}
    await cb.list_principals(creator, "1.2.3.4")
    assert cb._audit.log.call_count == 1
    call = cb._audit.log.call_args
    assert call.kwargs["tool"] == "principals_listed"
    serialized = json.dumps(call.kwargs, default=str)
    for key in _SECRET_KEYS:
        assert key not in serialized
    assert "Bearer" not in serialized


async def test_list_principals_non_operator_denied():
    from sift_gateway.supabase_auth import PrincipalForbiddenError

    cb = _roster_callbacks()
    creator = {"principal_type": "agent", "system_role": None, "principal_id": "ag-1"}
    with pytest.raises(PrincipalForbiddenError) as exc:
        await cb.list_principals(creator, None)
    assert exc.value.http_status == 403


async def test_list_principals_operator_without_id_denied():
    from sift_gateway.supabase_auth import PrincipalForbiddenError

    cb = _roster_callbacks()
    creator = {"principal_type": "operator", "system_role": "operator", "principal_id": None}
    with pytest.raises(PrincipalForbiddenError):
        await cb.list_principals(creator, None)


def test_repository_list_principals_global_scopes_and_owner_filter():
    # Exercise the real SupabasePrincipalRepository.list_principals with a fake
    # cursor, verifying it never reads mcp_tokens and uses global-only scopes.
    from sift_gateway.supabase_auth import SupabasePrincipalRepository

    repo = SupabasePrincipalRepository.__new__(SupabasePrincipalRepository)
    executed = []

    class _Cur:
        def __init__(self):
            self._mode = None

        def execute(self, sql, params=None):
            executed.append(sql)
            if "from app.agents" in sql:
                self._mode = "agents"
            elif "from app.service_identities" in sql:
                self._mode = "services"
            elif "principal_tool_scopes" in sql:
                self._mode = "scopes"

        def fetchall(self):
            if self._mode == "agents":
                return [
                    (
                        "ag-1",
                        "Hermes",
                        "ai",
                        "active",
                        "auth-ag-1",
                        "op-1",
                        "11111111-1111-1111-1111-111111111111",
                    )
                ]
            if self._mode == "services":
                return [("sv-1", "worker", "worker", "active", "auth-sv-1")]
            if self._mode == "scopes":
                return [("mcp:*",)]
            return []

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Conn:
        def cursor(self):
            return _Cur()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    repo._connect = lambda: _Conn()  # type: ignore[method-assign]
    out = repo.list_principals(owner_operator_profile_id=None)
    assert {p["principal_type"] for p in out} == {"agent", "service"}
    assert all("mcp_tokens" not in s for s in executed)  # never touches raw tokens
    assert any("case_id is null" in s for s in executed)  # global-only scopes
    _assert_no_secret_keys(out)


def test_b_mvp9_agent_issuance_binds_default_case_but_global_scopes():
    from sift_gateway.supabase_auth import AgentServiceIssuance

    issuance = AgentServiceIssuance.__new__(AgentServiceIssuance)
    executed = []

    class _Cur:
        def execute(self, sql, params=None):
            executed.append((sql, params))

        def fetchone(self):
            return ("agent-db-id",)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Conn:
        def cursor(self):
            return _Cur()

        def commit(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    issuance._connect = lambda: _Conn()  # type: ignore[method-assign]
    principal_id = issuance._insert_principal_row(
        "agent",
        "Hermes case agent",
        "auth-agent-1",
        None,
        ["mcp:*"],
        "11111111-1111-1111-1111-111111111111",
        {"principal_id": "op-1"},
    )

    assert principal_id == "agent-db-id"
    agent_insert = executed[0]
    assert "insert into app.agents" in agent_insert[0]
    assert agent_insert[1][3] == "11111111-1111-1111-1111-111111111111"
    scope_insert = executed[1]
    assert "insert into app.principal_tool_scopes" in scope_insert[0]
    assert scope_insert[1] == ("agent-db-id", None, "mcp:*")
