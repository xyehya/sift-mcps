"""BATCH-G1 Gateway RAG bridge tests.

Verifies the RAG (forensic-rag-mcp) plane wires through the Gateway correctly:

  1. The real ``forensic-rag-mcp/sift-backend.json`` tools aggregate and survive
     namespacing under the ``kb_`` prefix.
  2. The manifest declares RAG as a non-authoritative REFERENCE add-on (no
     evidence seal / approval / report capability, read-only tools).
  3. The Gateway agent-path response guard strips any absolute evidence/case/
     mount path that a RAG result might carry, while preserving provenance IDs —
     so case-scoped, provenance-linked context reaches the agent and host paths
     never do.

This test introduces NO change to any Gateway source file or shared backend-
registry test; it only adds a new bridge test (BATCH-F1 owns the registry).
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp.types import Tool
from sift_gateway.response_guard import redact_paths_structured, redact_structured
from sift_gateway.server import Gateway

_MANIFEST = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "forensic-rag-mcp"
        / "sift-backend.json"
    ).read_text()
)
_RAG_TOOLS = {t["name"] for t in _MANIFEST["tools"]}


class _FakeRagBackend:
    started = True
    manifest = _MANIFEST

    async def list_tools(self):
        return [
            Tool(name=name, description="", inputSchema={"type": "object"})
            for name in _RAG_TOOLS
        ]


async def test_gateway_lists_rag_tools_under_kb_namespace():
    gateway = Gateway(
        {"backends": {}, "execute": {"security": {"denied_binaries": ["env"]}}}
    )
    gateway.backends["forensic-rag-mcp"] = _FakeRagBackend()
    await gateway._build_tool_map()

    tool_names = {tool.name for tool in await gateway.get_tools_list()}
    assert _RAG_TOOLS.issubset(tool_names)
    # Manifest namespace is kb; every RAG tool is exposed under it.
    assert _MANIFEST["namespace"] == "kb"
    assert all(name.startswith("kb_") for name in _RAG_TOOLS)


def test_rag_manifest_is_non_authoritative_reference_addon():
    # Tier/capabilities mark RAG as a reference plane, not an authority.
    assert _MANIFEST["tier"] == "addon"
    assert _MANIFEST["capabilities"]["provides"] == ["reference"]
    assert _MANIFEST["capabilities"]["enriches_responses"] is False

    # No RAG tool may seal evidence, approve findings/reports, or create cases.
    forbidden = ("seal", "approve", "report", "create_case", "activate", "retire")
    for tool in _MANIFEST["tools"]:
        assert tool.get("read_only") is True
        assert tool.get("readOnlyHint") is True
        assert tool.get("evidence_class") == "read_only"
        assert not any(token in tool["name"].lower() for token in forbidden)


def test_response_guard_strips_paths_but_keeps_provenance_from_rag_result():
    # A RAG hit that (incorrectly) carried a host path: the agent-path guard
    # collapses the in-case path to a relative display path and redacts any
    # other absolute path, while the opaque provenance_id is untouched.
    case_dir = "/cases/case-x-01020304"
    rag_result = {
        "status": "ok",
        "case_id": "11111111-1111-1111-1111-111111111111",
        "results": [
            {
                "provenance_id": "prov-chunk-abc",
                "document_provenance_id": "prov-doc-xyz",
                "document_title": "Lateral Movement Analyst Reference",
                "collection_name": "SANS",
                "content": f"acquired {case_dir}/evidence/disk.E01 and /mnt/host/secret.key",
                "source_ref": "evidence/disk.E01",
                "distance": 0.12,
            }
        ],
    }

    rewritten, findings = redact_paths_structured(
        rag_result, case_dir_resolved=case_dir
    )
    hit = rewritten["results"][0]

    # Provenance IDs and labels survive untouched.
    assert hit["provenance_id"] == "prov-chunk-abc"
    assert hit["document_provenance_id"] == "prov-doc-xyz"
    assert hit["collection_name"] == "SANS"
    # In-case absolute path collapses to a relative display path.
    assert "/cases/case-x-01020304" not in hit["content"]
    assert "evidence/disk.E01" in hit["content"]
    # A foreign/host absolute path is redacted and flagged for audit.
    assert "/mnt/host/secret.key" not in hit["content"]
    assert any(f["pattern_name"] == "Absolute Path" for f in findings)


def test_response_guard_redacts_secret_in_rag_result():
    # Secret-redaction pass also applies to bridged RAG output.
    rag_result = {
        "results": [{"content": "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}]
    }
    rewritten, findings = redact_structured(rag_result)
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" not in rewritten["results"][0]["content"]
    assert findings
