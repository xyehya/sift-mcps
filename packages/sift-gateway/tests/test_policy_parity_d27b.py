"""D27b FastMCP gateway policy parity tests."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import FastMCP
from fastmcp.server import create_proxy
from fastmcp.tools import ToolResult
from mcp.types import TextContent
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.testclient import TestClient

from sift_core.evidence_chain import ChainStatus
from sift_gateway.auth import AuthMiddleware
from sift_gateway.mcp_endpoint import SiftTokenVerifier
from sift_gateway.mcp_server import _validate_egress_url
from sift_gateway.policy_middleware import gateway_policy_middlewares
from sift_gateway.response_guard import guard_tool_result
from sift_gateway.rest import rest_routes
from sift_gateway.server import Gateway
from sift_gateway.token_gen import token_fingerprint
from sift_gateway.token_registry import RegistryToken


def _execute_security():
    return {"execute": {"security": {"denied_binaries": ["env"]}}}


def _gate(status):
    return {
        "blocked": status != ChainStatus.OK,
        "status": status,
        "issues": [] if status == ChainStatus.OK else [f"issue:{status}"],
        "manifest_version": 1,
    }


def _fake_gateway():
    gateway = MagicMock()
    gateway._audit = MagicMock()
    gateway._audit.log = MagicMock(return_value="aid-1")
    gateway._tool_map = {"addon_leak": "addon"}
    return gateway


# BU3 (XYE-21): the evidence gate is DB-authority only and governs a *bound*
# active case (no-case denial is CaseContextMiddleware's job, which runs first).
# A real (non-mock) active-case service is needed so the gate path engages.
class _BoundCaseService:
    def __init__(self, case):
        self._case = case

    def require_active_case_for_principal(self, principal):
        return self._case


def _bound_case(tmp_path):
    from sift_gateway.active_case import ActiveCase

    return ActiveCase(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="db-case",
        title="DB Case",
        description=None,
        status="active",
        artifact_path=str(tmp_path),
        metadata={},
        membership_role="agent",
    )


def _case_bound_gateway(tmp_path):
    gateway = _fake_gateway()
    gateway.control_plane_dsn = "postgresql://service@localhost/sift"
    gateway.active_case_service = _BoundCaseService(_bound_case(tmp_path))
    return gateway


async def test_f6_parent_policy_wraps_proxied_structured_result(monkeypatch, tmp_path):
    monkeypatch.setenv("SIFT_CASE_DIR", str(tmp_path))
    secret = "AKIAIOSFODNN7EXAMPLE"
    gateway = _fake_gateway()
    child = FastMCP("child")

    @child.tool(name="leak")
    def leak():
        return ToolResult(
            structured_content={
                "token": secret,
                "nested": {"authorization": f"Bearer {secret}"},
            },
            meta={"upstream": "preserved"},
        )

    parent = FastMCP("parent", middleware=gateway_policy_middlewares(gateway))
    parent.mount(create_proxy(child), namespace="addon")

    with patch(
        "sift_gateway.policy_middleware.check_evidence_gate_db",
        return_value=_gate(ChainStatus.OK),
    ):
        result = await parent.call_tool("addon_leak", {})

    serialized = json.dumps(
        {
            "content": [item.model_dump(mode="json") for item in result.content],
            "structured": result.structured_content,
            "meta": result.meta,
        },
        default=str,
    )
    assert secret not in serialized
    assert "[REDACTED:AWS Access Key]" in serialized
    assert result.meta["upstream"] == "preserved"
    sources = [call.kwargs["source"] for call in gateway._audit.log.call_args_list]
    assert "gateway_response_guard" in sources
    assert "gateway_mcp_envelope" in sources


async def test_gate_block_skips_tool_and_records_envelope(monkeypatch, tmp_path):
    gateway = _case_bound_gateway(tmp_path)
    ran = False
    mcp = FastMCP("parent", middleware=gateway_policy_middlewares(gateway))

    @mcp.tool(name="record_finding")
    async def record_finding():
        nonlocal ran
        ran = True
        return "ran"

    with patch(
        "sift_gateway.policy_middleware.check_evidence_gate_db",
        return_value=_gate(ChainStatus.UNSEALED),
    ):
        result = await mcp.call_tool("record_finding", {})

    assert ran is False
    assert "evidence_chain_unsealed" in result.content[0].text
    sources = [call.kwargs["source"] for call in gateway._audit.log.call_args_list]
    assert "gateway_evidence_gate" in sources
    assert "gateway_mcp_envelope" in sources


def test_guard_tool_result_redacts_and_caps_structured_content(tmp_path):
    secret = "AKIAIOSFODNN7EXAMPLE"
    result = ToolResult(
        content=[TextContent(type="text", text="clean text")],
        structured_content={"rows": [{"secret": secret, "blob": "X" * 2000}]},
    )

    guarded, findings, cap_events = guard_tool_result(
        result,
        override_active=False,
        case_dir=str(tmp_path),
        tool_name="cti_lookup_ioc",
        cap_bytes=512,
    )

    serialized = json.dumps(
        {
            "content": [item.model_dump(mode="json") for item in guarded.content],
            "structured": guarded.structured_content,
        },
        default=str,
    )
    assert secret not in serialized
    assert findings
    assert cap_events
    assert "_sift_output_capped" in guarded.structured_content


def test_rest_tool_path_keeps_unredacted_examiner_output():
    from sift_gateway.server import ToolSurfaceSnapshot
    gateway = Gateway({"backends": {}, **_execute_security()})
    secret = "AKIAIOSFODNN7EXAMPLE"
    # D7: inject test state via the atomic snapshot rather than direct attribute.
    gateway._tool_surface = ToolSurfaceSnapshot(
        tool_map={"addon_leak": "addon"}, tool_cache={}, manifest_meta={}
    )

    async def call_tool(name, arguments, examiner=None):
        return [TextContent(type="text", text=f"examiner sees {secret}")]

    gateway.call_tool = call_tool
    app = Starlette(
        routes=rest_routes(),
        middleware=[Middleware(AuthMiddleware, api_keys={})],
    )
    app.state.gateway = gateway
    client = TestClient(app)

    response = client.post("/api/v1/tools/addon_leak", json={"arguments": {}})

    assert response.status_code == 200
    assert secret in json.dumps(response.json())


def test_gateway_app_exposes_only_aggregate_mcp_route():
    gateway = Gateway({"backends": {}, **_execute_security()})
    app = gateway.create_app()

    mcp_paths = sorted(
        route.path for route in app.routes if getattr(route, "path", "").startswith("/mcp")
    )

    assert mcp_paths == ["/mcp"]


def test_http_proxy_egress_guard_blocks_loopback_targets():
    with pytest.raises(ValueError, match="blocked private/link-local"):
        _validate_egress_url("https://127.0.0.1:9000/mcp", label="backend.url")


async def test_sift_token_verifier_rejects_hash_registry_token():
    # SEC-6 (DSS-CAN-015): the legacy PR02 hash-registry fallback is removed —
    # the verifier NEVER accepts a registry/api-key token, even when a registry
    # is wired. Supabase JWT is the sole credential authority on /mcp.
    token = "sift_svc_" + "a" * 48
    record = RegistryToken(
        id="11111111-1111-1111-1111-111111111111",
        token_fingerprint=token_fingerprint(token),
        role="agent",
        principal="hermes",
        principal_type="agent",
        agent_id="hermes",
        service_identity_id=None,
        created_by="alice",
        case_id="case-1",
        label="Hermes",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        scopes=frozenset({"mcp:*"}),
    )

    class Registry:
        def __init__(self):
            self.lookups = 0

        def lookup_token(self, candidate):
            self.lookups += 1
            return record if candidate == token else None

    registry = Registry()
    verifier = SiftTokenVerifier(api_keys={}, token_registry=registry)

    # No resolver and no legacy fallback => the token is denied and the registry
    # is never consulted.
    assert await verifier.verify_token(token) is None
    assert registry.lookups == 0
