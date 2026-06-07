"""PR03A / Batch A — B-10 per-principal tool authorization.

Verifies the single is_tool_allowed helper grammar, that list filtering and
call denial use the SAME helper, that a denied call does not invoke the tool
(local or proxied), and that denials are audited without secrets.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import FastMCP
from fastmcp.server import create_proxy
from fastmcp.tools import ToolResult
from mcp.types import TextContent

from sift_core.evidence_chain import ChainStatus
from sift_gateway.identity import Identity
from sift_gateway.policy_middleware import (
    ToolAuthorizationMiddleware,
    gateway_policy_middlewares,
)
from sift_gateway.supabase_auth import is_tool_allowed


def _identity(scopes):
    return Identity(
        principal="hermes", principal_type="agent", token_id="ag-1", agent_id="ag-1",
        created_by=None, role="agent", source_ip="127.0.0.1", auth_surface="mcp",
        tool_scopes=frozenset(scopes), token_fingerprint="abc123",
        principal_id="ag-1", auth_user_id="auth-agent",
    )


# ---------------------------------------------------------------------------
# Grammar
# ---------------------------------------------------------------------------


def test_mcp_star_allows_all():
    ident = _identity({"mcp:*"})
    assert is_tool_allowed(ident, "run_command")
    assert is_tool_allowed(ident, "opensearch_search")


def test_tool_scope_matches_exact_only():
    ident = _identity({"tool:run_command"})
    assert is_tool_allowed(ident, "run_command")
    assert not is_tool_allowed(ident, "run_command_extra")
    assert not is_tool_allowed(ident, "record_finding")


def test_namespace_scope_matches_prefix_only():
    ident = _identity({"namespace:opensearch"})
    assert is_tool_allowed(ident, "opensearch_search")
    assert not is_tool_allowed(ident, "opensearchsearch")  # needs underscore boundary
    assert not is_tool_allowed(ident, "run_command")


def test_no_scope_denies_ordinary_tools():
    assert not is_tool_allowed(_identity(set()), "run_command")


def test_unknown_scope_grants_nothing():
    assert not is_tool_allowed(_identity({"capability:triage"}), "run_command")


def test_none_identity_denied():
    assert not is_tool_allowed(None, "run_command")


# ---------------------------------------------------------------------------
# list / call consistency (same helper)
# ---------------------------------------------------------------------------


def _fake_gateway():
    gw = MagicMock()
    gw._audit = MagicMock()
    gw._audit.log = MagicMock(return_value="aid-1")
    gw._tool_map = {}
    return gw


class _FakeTool:
    def __init__(self, name):
        self.name = name


class _ListCtx:
    pass


async def test_list_filtering_uses_same_helper_as_call():
    gw = _fake_gateway()
    mw = ToolAuthorizationMiddleware(gw)
    all_tools = [_FakeTool("run_command"), _FakeTool("opensearch_search"),
                 _FakeTool("record_finding")]

    async def call_next(ctx):
        return all_tools

    ident = _identity({"tool:run_command", "namespace:opensearch"})
    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=ident):
        filtered = await mw.on_list_tools(_ListCtx(), call_next)
    listed = {t.name for t in filtered}
    assert listed == {"run_command", "opensearch_search"}
    # Every listed tool is is_tool_allowed; every excluded tool is not.
    for t in all_tools:
        assert (t.name in listed) == is_tool_allowed(ident, t.name)


async def test_denied_call_does_not_invoke_local_tool():
    gw = _fake_gateway()
    ran = False
    mcp = FastMCP("parent", middleware=[ToolAuthorizationMiddleware(gw)])

    @mcp.tool(name="record_finding")
    async def record_finding():
        nonlocal ran
        ran = True
        return "ran"

    ident = _identity({"tool:run_command"})  # not allowed to call record_finding
    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=ident):
        result = await mcp.call_tool("record_finding", {})

    assert ran is False
    assert result.is_error
    assert "tool_not_authorized" in result.content[0].text
    # Denial audited, with no secret material.
    assert gw._audit.log.call_count == 1
    call = gw._audit.log.call_args
    assert call.kwargs["source"] == "gateway_tool_authz"
    serialized = json.dumps(call.kwargs, default=str)
    assert "token_fingerprint" not in serialized or "abc123" in serialized
    assert "Bearer" not in serialized


async def test_denied_call_does_not_invoke_proxied_tool():
    gw = _fake_gateway()
    ran = False
    child = FastMCP("child")

    @child.tool(name="search")
    async def search():
        nonlocal ran
        ran = True
        return "results"

    parent = FastMCP("parent", middleware=[ToolAuthorizationMiddleware(gw)])
    parent.mount(create_proxy(child), namespace="addon")

    ident = _identity({"tool:run_command"})  # may not call addon_search
    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=ident):
        result = await parent.call_tool("addon_search", {})

    assert ran is False
    assert result.is_error
    assert "tool_not_authorized" in result.content[0].text


async def test_allowed_call_proceeds_through_full_policy_stack(monkeypatch, tmp_path):
    monkeypatch.setenv("SIFT_CASE_DIR", str(tmp_path))
    gw = _fake_gateway()
    ran = False
    mcp = FastMCP("parent", middleware=gateway_policy_middlewares(gw))

    @mcp.tool(name="record_finding")
    async def record_finding():
        nonlocal ran
        ran = True
        return "ok"

    ident = _identity({"mcp:*"})
    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=ident), \
         patch("sift_gateway.policy_middleware.check_evidence_gate",
               return_value={"blocked": False, "status": ChainStatus.OK, "issues": [],
                             "manifest_version": 1}):
        result = await mcp.call_tool("record_finding", {})

    assert ran is True
    assert not result.is_error


async def test_anonymous_principal_not_filtered():
    # No authenticated principal (anonymous single-user mode): list is untouched.
    gw = _fake_gateway()
    mw = ToolAuthorizationMiddleware(gw)
    tools = [_FakeTool("run_command")]

    async def call_next(ctx):
        return tools

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None):
        out = await mw.on_list_tools(_ListCtx(), call_next)
    assert [t.name for t in out] == ["run_command"]


# ---------------------------------------------------------------------------
# Remediation: B6 — fail CLOSED on missing identity when auth is configured
# ---------------------------------------------------------------------------


async def test_b6_list_fails_closed_when_auth_enabled_and_no_identity():
    gw = _fake_gateway()
    mw = ToolAuthorizationMiddleware(gw, auth_enabled=True)
    tools = [_FakeTool("run_command"), _FakeTool("opensearch_search")]

    async def call_next(ctx):
        return tools

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None):
        out = await mw.on_list_tools(_ListCtx(), call_next)
    # No identity + auth configured => advertise nothing.
    assert out == []


async def test_b6_call_fails_closed_when_auth_enabled_and_no_identity():
    gw = _fake_gateway()
    ran = False
    mcp = FastMCP("parent", middleware=[ToolAuthorizationMiddleware(gw, auth_enabled=True)])

    @mcp.tool(name="run_command")
    async def run_command():
        nonlocal ran
        ran = True
        return "ran"

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None):
        result = await mcp.call_tool("run_command", {})

    assert ran is False
    assert result.is_error
    assert "tool_not_authorized" in result.content[0].text
    # Denial audited with reason no_identity, no secrets.
    assert gw._audit.log.call_count == 1
    call = gw._audit.log.call_args
    assert call.kwargs["source"] == "gateway_tool_authz"
    assert "no_identity" in call.kwargs["result_summary"]
    assert "Bearer" not in json.dumps(call.kwargs, default=str)


async def test_b6_anonymous_mode_still_open_when_auth_disabled():
    # auth_enabled=False (no verifier/keys/registry): genuine single-user mode.
    gw = _fake_gateway()
    mw = ToolAuthorizationMiddleware(gw, auth_enabled=False)
    tools = [_FakeTool("run_command")]

    async def call_next(ctx):
        return tools

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None):
        out = await mw.on_list_tools(_ListCtx(), call_next)
    assert [t.name for t in out] == ["run_command"]


def test_b6_factory_threads_auth_enabled_flag():
    gw = _fake_gateway()
    mws = gateway_policy_middlewares(gw, auth_enabled=True)
    authz = next(m for m in mws if isinstance(m, ToolAuthorizationMiddleware))
    assert authz.auth_enabled is True


# ---------------------------------------------------------------------------
# Remediation: B3 — per-principal rate limit fires on the verifier path
# ---------------------------------------------------------------------------


async def test_b3_per_principal_rate_limit_denies_in_policy_middleware():
    from sift_gateway.rate_limit import (
        get_examiner_rate_limiter,
        reset_examiner_rate_limiter,
    )

    reset_examiner_rate_limiter()
    # Limit the per-principal quota to 1 call/window.
    get_examiner_rate_limiter(limit=1, window=60.0)
    try:
        gw = _fake_gateway()
        calls = 0
        mcp = FastMCP("parent",
                      middleware=[ToolAuthorizationMiddleware(gw, auth_enabled=True)])

        @mcp.tool(name="run_command")
        async def run_command():
            nonlocal calls
            calls += 1
            return "ok"

        ident = _identity({"mcp:*"})
        with patch("sift_gateway.policy_middleware.current_mcp_identity",
                   return_value=ident):
            first = await mcp.call_tool("run_command", {})
            second = await mcp.call_tool("run_command", {})

        assert calls == 1  # second call never reached the tool
        assert not first.is_error
        assert second.is_error
        assert "rate_limit_exceeded" in second.content[0].text
    finally:
        reset_examiner_rate_limiter()
