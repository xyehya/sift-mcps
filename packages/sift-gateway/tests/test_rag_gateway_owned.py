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

# Keep the optional-output contract explicit.  These are the fields most likely
# to be lost if a gateway-owned handler is changed to reconstruct results by
# hand without passing through the typed *Out model.
SURFACE_OPTIONAL_KEYS = {
    "kb_search_knowledge": {
        "technique_filter": "T1003",
        "warning": "corpus is stale",
        "source_ref": "knowledge/sigma/rule.yml",
        "evidence_object_id": "knowledge-obj-1",
    }
}


class _FakeGatewayRagService:
    control_plane_dsn = "postgresql://gateway-only"

    def _get_stats(self) -> dict[str, object]:
        return {
            "status": "ok",
            "chunk_count": 26586,
            "document_count": 44,
            "collection_count": 2,
            "source_count": 23,
            "embedding_dim": 1024,
            "embedding_model": "Qwen/Qwen3-Embedding-0.6B",
        }

    def _search(self, **_: object) -> dict[str, object]:
        return {
            "status": "ok",
            "query": "credential dumping",
            "results": [
                {
                    "chunk_id": "chunk-1",
                    "provenance_id": "prov-1",
                    "document_provenance_id": "doc-prov-1",
                    "document_title": "Credential Dumping",
                    "collection_name": "sigma",
                    "content": "Use a credential-dumping detection.",
                    "kind": "knowledge",
                    "case_id": None,
                    "distance": 0.12,
                    "source_ref": SURFACE_OPTIONAL_KEYS["kb_search_knowledge"]["source_ref"],
                    "evidence_object_id": SURFACE_OPTIONAL_KEYS["kb_search_knowledge"]["evidence_object_id"],
                }
            ],
            "technique_filter": SURFACE_OPTIONAL_KEYS["kb_search_knowledge"]["technique_filter"],
            "warning": SURFACE_OPTIONAL_KEYS["kb_search_knowledge"]["warning"],
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


def test_rag_optional_keys_surface_through_typed_dispatch():
    """Fail if conditional RAG output fields disappear before the agent surface."""
    from sift_gateway.rag_tools import dispatch_gateway_rag_tool

    async def _run() -> None:
        result = await dispatch_gateway_rag_tool(
            _gateway(), "kb_search_knowledge", {"query": "credential dumping"}
        )
        assert result.structured_content is not None
        content = result.structured_content
        assert content["technique_filter"] == SURFACE_OPTIONAL_KEYS["kb_search_knowledge"]["technique_filter"]
        assert content["warning"] == SURFACE_OPTIONAL_KEYS["kb_search_knowledge"]["warning"]
        hit = content["results"][0]
        assert hit["source_ref"] == SURFACE_OPTIONAL_KEYS["kb_search_knowledge"]["source_ref"]
        assert hit["evidence_object_id"] == SURFACE_OPTIONAL_KEYS["kb_search_knowledge"]["evidence_object_id"]

    asyncio.run(_run())


def test_rag_tool_catalog_matches_manifest_declarations():
    """No agent-facing gateway RAG tool may drift from the trusted manifest."""
    catalog = {tool.name for tool in rag_tool_catalog()}
    assert catalog == _TOOL_NAMES
