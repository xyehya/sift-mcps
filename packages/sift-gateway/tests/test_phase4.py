import os
import json
import time
import pytest
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

from sift_gateway.identity import resolve_identity, Identity
from sift_gateway.backends import load_and_validate_manifest, create_backend
from sift_gateway.server import Gateway
from sift_gateway.evidence_gate import build_block_response
from sift_gateway.mcp_endpoint import log_rate_limit_violation, _LAST_429_AUDIT
from sift_core.case_manager import set_reference_backend_provider

def _execute_security():
    return {"execute": {"security": {"denied_binaries": ["env"]}}}


def _manifest_tool(
    name: str,
    *,
    description: str = "test tool",
    read_only: bool = True,
    evidence_class: str = "read_only",
    category: str = "search-analysis",
    recommended_phase: str = "SURVEY",
    health: bool = False,
) -> dict:
    tool = {
        "name": name,
        "description": description,
        "read_only": read_only,
        "readOnlyHint": read_only,
        "evidence_class": evidence_class,
        "category": category,
        "recommended_phase": recommended_phase,
    }
    if health:
        tool["health"] = True
    return tool


# Test identity resolution mapping
def test_resolve_identity():
    api_keys = {
        "user_key": {"examiner": "alice", "role": "examiner", "token_id": "u1"},
        "agent_key": {"agent_id": "agent-007", "created_by": "alice", "role": "agent", "token_id": "a1"},
        "service_key": {"examiner": "backup-svc", "role": "service", "token_id": "s1"}
    }
    
    # 1. Dev/no keys mode
    ident = resolve_identity(None, {})
    assert ident.principal == "anonymous"
    assert ident.principal_type == "user"
    assert ident.role == "examiner"
    
    # 2. User key
    ident = resolve_identity("user_key", api_keys)
    assert ident.principal == "alice"
    assert ident.principal_type == "user"
    assert ident.role == "examiner"
    
    # 3. Agent key
    ident = resolve_identity("agent_key", api_keys)
    assert ident.principal == "agent-007"
    assert ident.principal_type == "agent"
    assert ident.agent_id == "agent-007"
    assert ident.created_by == "alice"
    
    # 4. Service key
    ident = resolve_identity("service_key", api_keys)
    assert ident.principal == "backup-svc"
    assert ident.principal_type == "service"
    assert ident.role == "service"


# Test 429 rate limit auditing and throttling
def test_log_rate_limit_violation():
    _LAST_429_AUDIT.clear()
    gateway = MagicMock()
    gateway._audit = MagicMock()
    
    # Call first time -> should log
    log_rate_limit_violation(gateway, "ip:127.0.0.1", "127.0.0.1")
    assert gateway._audit.log.call_count == 1
    
    # Call second time immediately -> should not log (throttled)
    log_rate_limit_violation(gateway, "ip:127.0.0.1", "127.0.0.1")
    assert gateway._audit.log.call_count == 1
    
    # Call with a different key -> should log
    log_rate_limit_violation(gateway, "ip:10.0.0.1", "10.0.0.1")
    assert gateway._audit.log.call_count == 2


# Test strict binary evidence gate blocks all tools on non-OK status
def test_strict_binary_evidence_gate():
    gate_unsealed = {
        "blocked": True,
        "status": "unsealed",
        "issues": ["No manifest sealed"],
        "manifest_version": 0
    }
    
    resp = build_block_response("run_command", gate_unsealed)
    assert resp["blocked"] is True
    assert resp["reason"] == "evidence_chain_unsealed"
    assert resp["status"] == "unsealed"


# Test manifest validation compatibility checks
def test_manifest_validation(tmp_path):
    # 1. Invalid spec version (v2.x)
    invalid_manifest = {
        "spec_version": "2.0",
        "name": "test-addon",
        "version": "1.0.0",
        "tier": "addon",
        "transport": "stdio",
        "namespace": "test",
        "capabilities": {
            "provides": [],
            "requires": [],
            "enriches_responses": False
        },
        "tools": [_manifest_tool("test_health", health=True)],
        "health": "test_health"
    }
    
    manifest_path = tmp_path / "sift-backend.json"
    manifest_path.write_text(json.dumps(invalid_manifest))
    
    config = {
        "type": "stdio",
        "command": "true",
        "manifest_path": str(manifest_path)
    }
    
    with pytest.raises(ValueError, match="Unsupported spec_version"):
        load_and_validate_manifest("test-addon", config)


# Test namespace rule collision & missing prefix errors on boot
def test_namespace_enforcement(tmp_path):
    # Manifest declaring namespace "cti", but tool named "search" (no prefix)
    bad_manifest = {
        "spec_version": "1.0",
        "name": "bad-addon",
        "version": "1.0.0",
        "tier": "addon",
        "transport": "stdio",
        "namespace": "cti",
        "capabilities": {
            "provides": [],
            "requires": [],
            "enriches_responses": False
        },
        "tools": [_manifest_tool("search", description="bad tool", health=True)],
        "health": "search"
    }
    
    manifest_path = tmp_path / "sift-backend.json"
    manifest_path.write_text(json.dumps(bad_manifest))
    
    # Build a fake started backend
    class FakeBackend:
        started = True
        manifest = bad_manifest
        async def list_tools(self):
            class ToolStub:
                name = "search"
                title = "bad tool"
                description = "bad tool"
                inputSchema = {}
                outputSchema = None
                icons = None
                annotations = None
                meta = None
                execution = None
            return [ToolStub()]
            
    gateway = Gateway({"backends": {}, **_execute_security()})
    gateway.backends["bad-addon"] = FakeBackend()
    
    with pytest.raises(ValueError, match="does not start with declared namespace prefix"):
        import asyncio
        asyncio.run(gateway._build_tool_map())


# Test requirements availability gating
def test_requirements_gating(tmp_path):
    # Manifest requiring host:port that doesn't exist
    gated_manifest = {
        "spec_version": "1.0",
        "name": "gated-addon",
        "version": "1.0.0",
        "tier": "addon",
        "transport": "stdio",
        "namespace": "gated",
        "capabilities": {
            "provides": [],
            "requires": ["127.0.0.1:9999"],  # unreachable tcp port
            "enriches_responses": False
        },
        "tools": [_manifest_tool("gated_tool", description="gated tool", health=True)],
        "health": "gated_tool"
    }
    
    manifest_path = tmp_path / "sift-backend.json"
    manifest_path.write_text(json.dumps(gated_manifest))
    
    class FakeBackend:
        started = True
        manifest = gated_manifest
        async def list_tools(self):
            class ToolStub:
                name = "gated_tool"
                title = "gated tool"
                description = "gated tool"
                inputSchema = {}
                outputSchema = None
                icons = None
                annotations = None
                meta = None
                execution = None
            return [ToolStub()]
            
    gateway = Gateway({"backends": {}, **_execute_security()})
    gateway.backends["gated-addon"] = FakeBackend()
    
    import asyncio
    asyncio.run(gateway._build_tool_map())
    
    # Since requirement wasn't met, the backend should NOT be in self._available_backends
    # and its tools should not be in the tool map
    assert "gated-addon" not in gateway._available_backends
    assert "gated_tool" not in gateway._tool_map


# Test grounding reference provider registration
def test_reference_provider(tmp_path):
    ref_manifest = {
        "spec_version": "1.0",
        "name": "ref-addon",
        "version": "1.0.0",
        "tier": "addon",
        "transport": "stdio",
        "namespace": "ref",
        "capabilities": {
            "provides": ["reference"],
            "requires": [],
            "enriches_responses": False
        },
        "tools": [_manifest_tool("ref_tool", description="ref tool", health=True)],
        "health": "ref_tool"
    }
    
    manifest_path = tmp_path / "sift-backend.json"
    manifest_path.write_text(json.dumps(ref_manifest))
    
    class FakeBackend:
        started = True
        manifest = ref_manifest
        async def list_tools(self):
            class ToolStub:
                name = "ref_tool"
                title = "ref tool"
                description = "ref tool"
                inputSchema = {}
                outputSchema = None
                icons = None
                annotations = None
                meta = None
                execution = None
            return [ToolStub()]
            
    gateway = Gateway({"backends": {}, **_execute_security()})
    gateway.backends["ref-addon"] = FakeBackend()
    
    import asyncio
    asyncio.run(gateway._build_tool_map())
    
    # Verify the reference backends lists the registered one
    ref_list = gateway.get_reference_backends()
    assert "ref-addon" in ref_list


# Test per-call examiner stamping over a single global sequence counter (F-F).
# The per-call principal varies the audit-id prefix and the entry's `examiner`,
# while a single monotonic counter keeps IDs unique (one sidecar, not one per
# principal — avoids unbounded sidecar growth).
def test_per_call_examiner_stamping(tmp_path):
    from sift_common.audit import AuditWriter

    writer = AuditWriter(mcp_name="test-seq", audit_dir=str(tmp_path))
    writer.reset_counter()

    id_a1 = writer.log(tool="test", params={}, result_summary="ok", examiner_override="alice")
    id_b1 = writer.log(tool="test", params={}, result_summary="ok", examiner_override="bob")
    id_a2 = writer.log(tool="test", params={}, result_summary="ok", examiner_override="alice")

    # Per-call examiner is stamped into the audit-id prefix...
    assert "-alice-" in id_a1 and "-alice-" in id_a2
    assert "-bob-" in id_b1

    # ...and into the entry body.
    by_id = {e["audit_id"]: e for e in writer.get_entries()}
    assert by_id[id_a1]["examiner"] == "alice"
    assert by_id[id_b1]["examiner"] == "bob"

    # Single global, monotonic counter — IDs are unique and strictly increasing.
    seqs = [int(i.rsplit("-", 1)[1]) for i in (id_a1, id_b1, id_a2)]
    assert seqs == [1, 2, 3]
    assert len({id_a1, id_b1, id_a2}) == 3

    # Exactly one sidecar — not one per examiner.
    sidecars = list(tmp_path.glob("test-seq*.seq"))
    assert sidecars == [tmp_path / "test-seq.seq"]


# Test requirement-evaluation fails closed on an unrecognized format (4.8 hardening)
def test_unknown_requirement_fails_closed():
    gateway = Gateway({"backends": {}, **_execute_security()})
    # Well-known forms still evaluate normally
    assert gateway.evaluate_requirement("docker") in (True, False)
    # An unparseable/typo'd requirement is treated as UNMET (gates the backend)
    assert gateway.evaluate_requirement("ths-is-not-a-real-requirement") is False
    assert gateway.evaluate_requirement("opensearchh::badport") is False


# --- B-MVP-038 gateway-side defense: one backend's invalid outputSchema must
# --- not poison the aggregate tools/list. ---------------------------------

def _bad_output_schema_manifest() -> dict:
    return {
        "spec_version": "1.0",
        "name": "tri-addon",
        "version": "1.0.0",
        "tier": "addon",
        "transport": "stdio",
        "namespace": "tri",
        "capabilities": {"provides": [], "requires": [], "enriches_responses": False},
        "tools": [
            _manifest_tool("tri_bad", description="invalid outputSchema"),
            _manifest_tool("tri_none", description="no outputSchema"),
            _manifest_tool("tri_good", description="valid object outputSchema"),
        ],
        "health": "tri_good",
    }


class _TriOutputSchemaBackend:
    """Started backend advertising three tools: one with an invalid
    ``outputSchema`` (``type: null`` — exactly the windows-triage shape that
    took down LV1 tools/list), one with no outputSchema, one valid."""

    started = True
    manifest = _bad_output_schema_manifest()

    async def list_tools(self):
        from mcp.types import Tool

        return [
            Tool(
                name="tri_bad",
                description="invalid outputSchema",
                inputSchema={"type": "object", "properties": {}},
                outputSchema={"type": None},
            ),
            Tool(
                name="tri_none",
                description="no outputSchema",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="tri_good",
                description="valid object outputSchema",
                inputSchema={"type": "object", "properties": {}},
                outputSchema={"type": "object", "properties": {"k": {"type": "string"}}},
            ),
        ]


def test_invalid_output_schema_sanitized_in_get_tools_list():
    import asyncio

    gateway = Gateway({"backends": {}, **_execute_security()})
    gateway.backends["tri-addon"] = _TriOutputSchemaBackend()

    # Aggregation must not raise on the invalid schema...
    asyncio.run(gateway._build_tool_map())
    tools = asyncio.run(gateway.get_tools_list())
    by_name = {t.name: t for t in tools}

    # ...all three tools still surface (we repair/strip, never drop the tool).
    for name in ("tri_bad", "tri_none", "tri_good"):
        assert name in by_name, f"{name} missing from aggregate tools/list"

    # The invalid outputSchema is stripped (type:null -> None), not propagated.
    assert by_name["tri_bad"].outputSchema is None
    # A tool that never had an outputSchema stays None.
    assert by_name["tri_none"].outputSchema is None
    # A valid object schema passes through untouched.
    assert by_name["tri_good"].outputSchema == {
        "type": "object",
        "properties": {"k": {"type": "string"}},
    }


def test_invalid_output_schema_sanitized_in_tool_cache():
    import asyncio

    gateway = Gateway({"backends": {}, **_execute_security()})
    gateway.backends["tri-addon"] = _TriOutputSchemaBackend()
    asyncio.run(gateway._build_tool_map())

    # The cached Tool objects (served when the live backend list_tools is
    # unavailable / on the run_middleware=False warm path) are also clean.
    cache = gateway._tool_cache
    assert cache["tri_bad"].outputSchema is None
    assert cache["tri_none"].outputSchema is None
    assert cache["tri_good"].outputSchema == {
        "type": "object",
        "properties": {"k": {"type": "string"}},
    }


def test_failing_backend_is_isolated_from_tools_list():
    """server.py:338 contract — if a backend's list_tools raises, it is omitted
    from the aggregate and the core surface stays up (no propagation)."""
    import asyncio

    raising_manifest = {
        "spec_version": "1.0",
        "name": "boom-addon",
        "version": "1.0.0",
        "tier": "addon",
        "transport": "stdio",
        "namespace": "boom",
        "capabilities": {"provides": [], "requires": [], "enriches_responses": False},
        "tools": [_manifest_tool("boom_tool", description="explodes on list")],
        "health": "boom_tool",
    }

    class _RaisingBackend:
        started = True
        manifest = raising_manifest

        async def list_tools(self):
            raise RuntimeError("backend list_tools blew up")

    gateway = Gateway({"backends": {}, **_execute_security()})
    gateway.backends["boom-addon"] = _RaisingBackend()

    # Must NOT raise — the failing backend is isolated...
    asyncio.run(gateway._build_tool_map())
    assert "boom_tool" not in gateway._tool_map

    # ...and the aggregate tools/list builds with the core tools intact.
    tools = asyncio.run(gateway.get_tools_list())
    names = {t.name for t in tools}
    assert "boom_tool" not in names
    assert names, "core tools should still be present after backend isolation"


# Test probe_backends.py script execution and validation logic
def test_probe_backends_script_offline(tmp_path):
    import subprocess
    import sys
    
    repo_root = Path(__file__).resolve().parents[3]
    
    # 1. Valid manifest
    valid_manifest = {
        "spec_version": "1.0",
        "name": "test-valid",
        "version": "1.0.0",
        "tier": "addon",
        "transport": "stdio",
        "namespace": "testvalid",
        "capabilities": {
            "provides": [],
            "requires": [],
            "enriches_responses": False
        },
        "tools": [
            _manifest_tool("testvalid_tool", description="A valid tool", health=True)
        ],
        "health": "testvalid_tool"
    }
    
    manifest_path = tmp_path / "sift-backend.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(valid_manifest, f)
        
    res = subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts/probe_backends.py"),
            "--manifest",
            str(manifest_path),
            "--skip-mcp"
        ],
        capture_output=True,
        text=True
    )
    
    assert res.returncode == 0, f"Probe script failed on valid manifest: {res.stderr}"
    assert "JSON schema validation passed." in res.stdout
    
    # 2. Invalid manifest (bad spec_version)
    invalid_manifest = valid_manifest.copy()
    invalid_manifest["spec_version"] = "2.0"
    
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(invalid_manifest, f)
        
    res = subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts/probe_backends.py"),
            "--manifest",
            str(manifest_path),
            "--skip-mcp"
        ],
        capture_output=True,
        text=True
    )
    
    assert res.returncode != 0
    assert "Unsupported spec_version: 2.0" in res.stdout


# ---------------------------------------------------------------------------
# 4.3 — strict binary evidence gate, enforcement path through _call_tool.
# Proves block-all on any non-OK status (incl. the synthetic environment_summary),
# allow-through on OK, and a single audit line on block (no double-count with the
# transport envelope). This is the §4 regression guard at unit level.
# ---------------------------------------------------------------------------
from types import SimpleNamespace  # noqa: E402
from unittest.mock import AsyncMock  # noqa: E402

from fastmcp import FastMCP  # noqa: E402
from mcp.types import TextContent  # noqa: E402
from fastmcp.tools import ToolResult  # noqa: E402
from sift_core.evidence_chain import ChainStatus  # noqa: E402
from sift_gateway.policy_middleware import gateway_policy_middlewares  # noqa: E402


def _gate(status):
    return {
        "blocked": status != ChainStatus.OK,
        "status": status,
        "issues": [] if status == ChainStatus.OK else [f"issue:{status}"],
        "manifest_version": 1,
    }


# BU3 (XYE-21): the evidence gate is DB-authority only and governs a *bound*
# active case (no-case denial is CaseContextMiddleware's job). A real (non-mock)
# active-case service is required so the gate path engages for these tests.
class _BoundCaseService:
    def __init__(self, case):
        self._case = case

    def require_active_case_for_principal(self, principal):
        return self._case


def _bound_case():
    from sift_gateway.active_case import ActiveCase

    return ActiveCase(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="db-case",
        title="DB Case",
        description=None,
        status="active",
        artifact_path="/tmp/sift-phase4-case",
        metadata={},
        membership_role="agent",
    )


def _gate_test_gateway():
    gw = MagicMock()
    gw._tool_map = {"record_finding": "sift-core"}
    gw._tool_cache = {}
    gw.call_tool = AsyncMock(return_value=[TextContent(type="text", text='{"result": "ok"}')])
    gw.get_tools_list = AsyncMock(return_value=[])
    gw._audit = MagicMock()
    gw._audit.log = MagicMock(return_value="aid-1")
    # BU3: tool-serving gateway carries a control-plane DSN and binds a case.
    gw.control_plane_dsn = "postgresql://service@localhost/sift"
    gw.active_case_service = _BoundCaseService(_bound_case())
    return gw


async def _drive_call_tool(gateway, tool_name, gate_status):
    """Invoke the gated FastMCP policy path."""

    mcp = FastMCP("test", middleware=gateway_policy_middlewares(gateway))

    @mcp.tool(name=tool_name)
    async def _synthetic_tool():
        result = await gateway.call_tool(tool_name, {}, examiner=None)
        return ToolResult(content=result)

    with (
        patch("sift_gateway.policy_middleware.check_evidence_gate_db", return_value=_gate(gate_status)),
        patch("sift_gateway.policy_middleware.is_override_active", return_value=False),
    ):
        result = await mcp.call_tool(tool_name, {})
        contents = getattr(result, "content", []) or []
        return " ".join(tc.text if hasattr(tc, "text") else str(tc) for tc in contents)


async def test_gate_ok_allows_tool():
    gw = _gate_test_gateway()
    combined = await _drive_call_tool(gw, "record_finding", ChainStatus.OK)
    assert "ok" in combined
    assert "blocked" not in combined
    gw.call_tool.assert_awaited()  # the tool actually ran


async def test_gate_unsealed_blocks_tool():
    gw = _gate_test_gateway()
    combined = await _drive_call_tool(gw, "record_finding", ChainStatus.UNSEALED)
    assert "blocked" in combined
    gw.call_tool.assert_not_awaited()  # tool never ran
    # K1 authority cutover: the gate denial remains logged, and the transport
    # envelope now wraps the denied attempt so Postgres can record the result.
    sources = [call.kwargs["source"] for call in gw._audit.log.call_args_list]
    assert "gateway_evidence_gate" in sources
    assert "gateway_mcp_envelope" in sources


async def test_gate_violation_blocks_tool():
    gw = _gate_test_gateway()
    combined = await _drive_call_tool(gw, "record_finding", ChainStatus.MODIFIED)
    assert "blocked" in combined
    gw.call_tool.assert_not_awaited()


async def test_gate_blocks_environment_summary_when_unsealed():
    # F-A regression: the synthetic environment_summary must be gated like any
    # other agent tool — it must not aggregate backend health on an unsealed case.
    gw = _gate_test_gateway()
    combined = await _drive_call_tool(gw, "environment_summary", ChainStatus.UNSEALED)
    assert "blocked" in combined
    gw.call_tool.assert_not_awaited()


async def test_gate_allows_environment_summary_when_ok():
    gw = _gate_test_gateway()
    combined = await _drive_call_tool(gw, "environment_summary", ChainStatus.OK)
    assert "blocked" not in combined
