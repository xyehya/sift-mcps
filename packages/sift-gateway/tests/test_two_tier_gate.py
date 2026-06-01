"""Tests for Phase 16-gate-tier — two-tier evidence gate in _call_tool.

Verifies the decision logic:
  UNSEALED + readOnlyHint=True  → allowed through with _agentir_context warning
  UNSEALED + readOnlyHint=False → blocked (evidence_chain_unsealed)
  UNSEALED + no annotation      → blocked
  VIOLATION + readOnlyHint=True → blocked (violations block everything)
  OK                            → allowed, no warning
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sift_core.evidence_chain import ChainStatus


# ---------------------------------------------------------------------------
# Helpers to build mock Tool objects with annotations
# ---------------------------------------------------------------------------

def _make_tool(read_only: bool | None = None):
    """Build a minimal mock Tool-like object with annotations."""
    annotations = None
    if read_only is not None:
        annotations = SimpleNamespace(readOnlyHint=read_only)
    return SimpleNamespace(annotations=annotations)


def _gate_result(status: ChainStatus, blocked: bool | None = None) -> dict:
    return {
        "blocked": (status != ChainStatus.OK) if blocked is None else blocked,
        "status": status,
        "issues": [] if status == ChainStatus.OK else [f"Issue: {status}"],
        "manifest_version": 1,
    }


# ---------------------------------------------------------------------------
# Unit-test the two-tier decision helpers directly
# ---------------------------------------------------------------------------

from sift_gateway.evidence_gate import (
    VIOLATION_STATUSES,
    build_unsealed_warning,
    is_violation,
)


class TestTwoTierHelpers:
    """Whitebox tests on the pure helper functions."""

    @pytest.mark.parametrize("status", list(VIOLATION_STATUSES))
    def test_violation_statuses_blocked(self, status):
        assert is_violation(status) is True

    @pytest.mark.parametrize("status", [ChainStatus.OK, ChainStatus.UNSEALED])
    def test_non_violation_statuses_pass(self, status):
        assert is_violation(status) is False

    def test_unsealed_warning_contains_agentir_context_fields(self):
        gate = _gate_result(ChainStatus.UNSEALED)
        w = build_unsealed_warning("list_findings", gate)
        assert w["evidence_gate_warning"] is True
        assert "list_findings" in w["message"]
        assert "remediation" in w
        # Must be JSON-safe
        json.dumps({"_agentir_context": w})


# ---------------------------------------------------------------------------
# Integration: _call_tool gate branching via mocked check_evidence_gate
# ---------------------------------------------------------------------------

_TOOL_RESULT = [SimpleNamespace(type="text", text='{"result": "ok"}')]


def _make_gateway(tool_name: str, read_only: bool | None = None):
    """Return a minimal mock gateway with a _tool_cache entry."""
    gw = MagicMock()
    gw._tool_cache = {tool_name: _make_tool(read_only)}
    gw._tool_map = {tool_name: "sift-core"}
    gw.call_tool = AsyncMock(return_value=_TOOL_RESULT)
    # get_tools_list is awaited by Server._get_cached_tool_definition on cache miss
    gw.get_tools_list = AsyncMock(return_value=[])
    # _audit.log must be synchronous (called via asyncio.to_thread)
    gw._audit = MagicMock()
    gw._audit.log = MagicMock(return_value="audit-id-123")
    return gw


async def _invoke_call_tool(gateway, tool_name: str, gate_status: ChainStatus):
    """Invoke the _call_tool handler through create_mcp_server."""
    from sift_gateway.mcp_endpoint import create_mcp_server

    server = create_mcp_server(gateway)
    # Patch: evidence gate, case dir, request context
    with (
        patch(
            "sift_gateway.mcp_endpoint.check_evidence_gate",
            return_value=_gate_result(gate_status),
        ),
        patch(
            "sift_gateway.mcp_endpoint.os.environ.get",
            side_effect=lambda k, d="": "/tmp/case" if k == "SIFT_CASE_DIR" else d,
        ),
        patch(
            "sift_gateway.mcp_endpoint._extract_request_context",
            return_value={"examiner": "alice", "role": "examiner", "token_id": None, "source_ip": "127.0.0.1"},
        ),
        patch("sift_gateway.mcp_endpoint.is_override_active", return_value=False),
        patch("sift_gateway.mcp_endpoint.redact_tool_result", side_effect=lambda t, **kw: (t, [])),
        patch("sift_gateway.mcp_endpoint.check_rate_limit", return_value=None),
        patch("sift_gateway.mcp_endpoint.check_examiner_rate_limit", return_value=None),
    ):
        # Access the registered call_tool handler directly
        handler = server._tool_handlers.get(None) or server.request_handlers.get("tools/call")
        # FastMCP/low-level Server stores call_tool under its own registry
        # Access the inner function via the server's tool call registry
        for attr in ("_call_tool_handler", "_tool_call_handler"):
            if hasattr(server, attr):
                return await getattr(server, attr)(tool_name, {})

        # Fallback: find via handler registration
        from mcp.server.lowlevel import Server as LowServer
        assert isinstance(server, LowServer)
        # The handler is stored in _request_handlers under CallToolRequest
        from mcp.types import CallToolRequest
        raw_handler = server._request_handlers.get(CallToolRequest)
        if raw_handler:
            req = CallToolRequest(
                method="tools/call",
                params=SimpleNamespace(name=tool_name, arguments={}),
            )
            return await raw_handler(req)
        return None


class TestTwoTierGateIntegration:
    """Test the two-tier gate decision via create_mcp_server._call_tool."""

    async def _call(self, tool_name: str, gate_status: ChainStatus, read_only: bool | None):
        """Run _call_tool and return the list of TextContent items."""
        from sift_gateway.mcp_endpoint import create_mcp_server
        from mcp.types import CallToolRequest, CallToolRequestParams

        gateway = _make_gateway(tool_name, read_only)

        with (
            patch(
                "sift_gateway.mcp_endpoint.check_evidence_gate",
                return_value=_gate_result(gate_status),
            ),
            patch(
                "sift_gateway.mcp_endpoint.os.environ.get",
                side_effect=lambda k, d="": "/tmp/case" if k == "SIFT_CASE_DIR" else d,
            ),
            patch(
                "sift_gateway.mcp_endpoint._extract_request_context",
                return_value={"examiner": "alice", "role": "examiner",
                              "token_id": None, "source_ip": "127.0.0.1"},
            ),
            patch("sift_gateway.mcp_endpoint.is_override_active", return_value=False),
            patch("sift_gateway.mcp_endpoint.redact_tool_result",
                  side_effect=lambda t, **kw: (t, [])),
            patch("sift_gateway.mcp_endpoint.check_rate_limit", return_value=None),
            patch("sift_gateway.mcp_endpoint.check_examiner_rate_limit", return_value=None),
        ):
            server = create_mcp_server(gateway)
            req = CallToolRequest(
                method="tools/call",
                params=CallToolRequestParams(name=tool_name, arguments={}),
            )
            raw_handler = server.request_handlers.get(CallToolRequest)
            if raw_handler is None:
                pytest.skip("Cannot locate _call_tool handler via request_handlers")
            result = await raw_handler(req)
            # ServerResult wraps CallToolResult via .root
            call_result = result.root if hasattr(result, "root") else result
            contents = call_result.content if hasattr(call_result, "content") else []
            return [tc.text if hasattr(tc, "text") else str(tc) for tc in contents]

    async def test_ok_status_allows_all_tools(self):
        texts = await self._call("list_findings", ChainStatus.OK, read_only=False)
        assert any("ok" in t for t in texts)
        assert not any("blocked" in t for t in texts)

    async def test_ok_status_injects_case_context(self):
        texts = await self._call("list_findings", ChainStatus.OK, read_only=True)
        case_texts = [t for t in texts if '"_case"' in t]
        assert len(case_texts) == 1
        parsed = json.loads(case_texts[0])
        assert parsed["_case"]["id"] == "case"
        assert parsed["_case"]["dir"] == "/tmp/case"
        assert parsed["_case"]["evidence_dir"] == "/tmp/case/evidence"

    async def test_unsealed_blocks_non_readonly_tool(self):
        texts = await self._call("sift_run_command", ChainStatus.UNSEALED, read_only=False)
        combined = " ".join(texts)
        assert "blocked" in combined

    async def test_unsealed_blocks_tool_with_no_annotation(self):
        texts = await self._call("sift_run_command", ChainStatus.UNSEALED, read_only=None)
        combined = " ".join(texts)
        assert "blocked" in combined

    async def test_unsealed_allows_readonly_tool_with_warning(self):
        texts = await self._call("list_findings", ChainStatus.UNSEALED, read_only=True)
        combined = " ".join(texts)
        assert "blocked" not in combined
        assert "evidence_gate_warning" in combined

    async def test_violation_blocks_readonly_tool(self):
        texts = await self._call("list_findings", ChainStatus.MODIFIED, read_only=True)
        combined = " ".join(texts)
        assert "blocked" in combined

    async def test_violation_blocks_non_readonly_tool(self):
        texts = await self._call("sift_run_command", ChainStatus.MISSING, read_only=False)
        combined = " ".join(texts)
        assert "blocked" in combined

    async def test_unsealed_readonly_warning_is_valid_json(self):
        texts = await self._call("list_findings", ChainStatus.UNSEALED, read_only=True)
        warning_texts = [t for t in texts if "evidence_gate_warning" in t]
        assert len(warning_texts) >= 1
        parsed = json.loads(warning_texts[0])
        assert parsed["_agentir_context"]["evidence_gate_warning"] is True
