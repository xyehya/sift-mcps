"""Fail-on-revert coverage for the first-party gateway-owned RAG pack."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from sift_common.testing.surface import assert_passes_output_schema
from sift_gateway.backends import create_backend
from sift_gateway.mcp_backends_registry import (
    BackendRegistryError,
    normalize_connection_config,
)
from sift_gateway.mcp_server import create_gateway_mcp_server
from sift_gateway.rag_tools import rag_tool_catalog
from sift_gateway.server import Gateway

_MANIFEST = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "forensic-rag-mcp"
        / "sift-backend.json"
    ).read_text(encoding="utf-8")
)
_TOOL_NAMES = {tool["name"] for tool in _MANIFEST["tools"]}


class _FakeGatewayRagService:
    control_plane_dsn = "postgresql://gateway-only"

    def _get_stats(self) -> dict[str, object]:
        return {
            "status": "ok",
            "chunk_count": 26586,
            "document_count": 44,
            "collection_count": 2,
            "source_count": 23,
            "embedding_dim": 768,
            "embedding_model": "BAAI/bge-base-en-v1.5",
        }


def _gateway() -> Gateway:
    gateway = Gateway(
        {"backends": {}, "execute": {"security": {"denied_binaries": ["env"]}}}
    )
    gateway.control_plane_dsn = "postgresql://gateway-only"
    gateway._rag_knowledge_server = _FakeGatewayRagService()
    gateway.backends["forensic-rag-mcp"] = create_backend(
        "forensic-rag-mcp", {"type": "gateway"}, manifest=_MANIFEST
    )
    return gateway


def test_gateway_rag_transport_is_narrow_and_carries_no_child_environment():
    """Only a credential-free, process-local RAG connection may be registered."""
    assert _MANIFEST["transport"] == "gateway"
    stored = normalize_connection_config(
        {
            "type": "gateway",
            "manifest_path": "/opt/sift-mcps/packages/forensic-rag-mcp/sift-backend.json",
        }
    )
    assert stored == {
        "type": "gateway",
        "manifest_path": "/opt/sift-mcps/packages/forensic-rag-mcp/sift-backend.json",
    }
    assert "env_refs" not in stored
    assert "command" not in stored

    for forbidden in ("command", "url", "env_refs", "args"):
        value = {"type": "gateway", forbidden: [] if forbidden == "args" else "x"}
        with pytest.raises(BackendRegistryError, match="cannot accept"):
            normalize_connection_config(value)

    with pytest.raises(ValueError, match="reserved for first-party RAG"):
        create_backend("not-rag", {"type": "gateway"}, manifest=_MANIFEST)


def test_first_party_registry_reconcile_is_allowlisted():
    source = (Path(__file__).resolve().parents[3] / "lib" / "examiner.sh").read_text(
        encoding="utf-8"
    )
    assert '"$backend_name" != "forensic-rag-mcp"' in source
    assert 'manifest.get("transport") != "gateway"' in source


def test_rag_server_never_discovers_a_dsn_from_its_environment(monkeypatch):
    """The RAG package cannot regain a DB-credential fallback as a subprocess."""
    from rag_mcp.server import RAGServer

    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://must-not-be-read")
    server = RAGServer()
    with pytest.raises(RuntimeError, match="rag_gateway_owned"):
        server._get_store()


def test_gateway_owned_rag_tools_reach_agent_catalog_with_typed_output_surface():
    """The registry-backed kb health tool must surface typed structured content."""
    gateway = _gateway()

    async def _run() -> None:
        await gateway._build_tool_map()
        mcp = create_gateway_mcp_server(gateway)
        advertised = {tool.name: tool for tool in await mcp.list_tools()}
        assert set(advertised) >= _TOOL_NAMES
        health = advertised["kb_get_knowledge_stats"]
        assert isinstance(health.output_schema, dict)

        result = await mcp.call_tool("kb_get_knowledge_stats", {})
        assert result.structured_content is not None
        assert result.structured_content["chunk_count"] == 26586
        assert_passes_output_schema(
            health.output_schema, result, tool_name="kb_get_knowledge_stats"
        )

    asyncio.run(_run())


def test_rag_tool_catalog_matches_manifest_declarations():
    """No agent-facing gateway RAG tool may drift from the trusted manifest."""
    catalog = {tool.name for tool in rag_tool_catalog()}
    assert catalog == _TOOL_NAMES
