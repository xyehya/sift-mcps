"""Typed, gateway-owned MCP surface for the first-party RAG pack.

The RAG corpus is in the Postgres control plane.  These handlers execute in
the gateway process, whose control-plane DSN is already the authenticated
authority, so the ``rag-mcp`` package never needs a DB credential as a stdio
subprocess.  They remain registry-backed through the ``gateway`` transport and
therefore traverse the normal catalog, authorization, audit, response-guard,
and capability-guide path.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Literal

from fastmcp.tools import ToolResult
from mcp.types import Tool, ToolAnnotations
from pydantic import BaseModel, Field, ValidationError, field_validator
from sift_common.contracts import ErrorCode
from sift_common.registry_helpers import (
    error_result,
    success_result,
    tool_output_schema,
)


class RagSearchIn(BaseModel):
    query: str = Field(..., min_length=1, max_length=1000)
    top_k: int = Field(5, ge=1, le=50)
    source: str = Field("", max_length=100)
    source_ids: list[str] | None = Field(None, max_length=20)
    technique: str = Field("", max_length=100)
    platform: str = Field("", max_length=100)

    @field_validator("source_ids")
    @classmethod
    def _validate_source_ids(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return value
        if any(len(item.strip()) > 100 for item in value):
            raise ValueError("source_ids items must be at most 100 characters")
        return [item.strip() for item in value if item.strip()] or None

    @field_validator("platform")
    @classmethod
    def _validate_platform(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and clean not in {"windows", "linux", "macos"}:
            raise ValueError("platform must be one of windows, linux, macos")
        return clean


class _EmptyIn(BaseModel):
    pass


class RagHitOut(BaseModel):
    chunk_id: str
    provenance_id: str
    document_provenance_id: str
    document_title: str
    collection_name: str
    content: str
    kind: Literal["knowledge"]
    case_id: None = None
    distance: float
    source_ref: str | None = None
    evidence_object_id: str | None = None


class RagSearchOut(BaseModel):
    status: Literal["ok"]
    query: str
    results: list[RagHitOut]
    technique_filter: str | None = None
    warning: str | None = None


class RagSourcesOut(BaseModel):
    status: Literal["ok"]
    sources: list[str]
    count: int


class RagStatsOut(BaseModel):
    status: Literal["ok"]
    chunk_count: int
    document_count: int
    collection_count: int
    source_count: int
    embedding_dim: int
    embedding_model: str


@dataclass(frozen=True)
class RagToolSpec:
    name: str
    title: str
    description: str
    in_model: type[BaseModel]
    out_model: type[BaseModel]
    phase: str
    health: bool = False


_READ_ONLY = ToolAnnotations(readOnlyHint=True)
_SPECS: tuple[RagToolSpec, ...] = (
    RagToolSpec(
        name="kb_search_knowledge",
        title="Search Knowledge",
        description=(
            "Semantic search across the shared IR/DFIR knowledge corpus. "
            "Results are supporting reference context, never case evidence."
        ),
        in_model=RagSearchIn,
        out_model=RagSearchOut,
        phase="CORRELATE",
    ),
    RagToolSpec(
        name="kb_list_knowledge_sources",
        title="List Knowledge Sources",
        description="List distinct shared-knowledge source labels.",
        in_model=_EmptyIn,
        out_model=RagSourcesOut,
        phase="SURVEY",
    ),
    RagToolSpec(
        name="kb_get_knowledge_stats",
        title="Knowledge Corpus Status",
        description="Return shared knowledge corpus counts and embedding-model contract.",
        in_model=_EmptyIn,
        out_model=RagStatsOut,
        phase="SURVEY",
        health=True,
    ),
)


def rag_tool_specs() -> tuple[RagToolSpec, ...]:
    """Return the immutable typed RAG contract used by catalog and dispatcher."""
    return _SPECS


def rag_tool_catalog() -> list[Tool]:
    """Build catalog tools without opening the DB or loading the embedding model."""
    return [
        Tool(
            name=spec.name,
            title=spec.title,
            description=spec.description,
            inputSchema=spec.in_model.model_json_schema(),
            outputSchema=tool_output_schema(spec.out_model),
            annotations=_READ_ONLY,
            meta={"category": "enrichment", "recommended_for_phase": spec.phase},
        )
        for spec in _SPECS
    ]


def _spec(name: str) -> RagToolSpec:
    for spec in _SPECS:
        if spec.name == name:
            return spec
    raise ValueError(f"unsupported gateway RAG tool: {name}")


def _service(gateway: Any):
    dsn = str(getattr(gateway, "control_plane_dsn", "") or "").strip()
    if not dsn:
        raise RuntimeError("rag_control_plane_dsn_unavailable")
    existing = getattr(gateway, "_rag_knowledge_server", None)
    if existing is not None and getattr(existing, "control_plane_dsn", None) == dsn:
        return existing

    from rag_mcp.server import RAGServer

    service = RAGServer(control_plane_dsn=dsn)
    gateway._rag_knowledge_server = service
    return service


async def dispatch_gateway_rag_tool(
    gateway: Any, name: str, arguments: dict[str, Any]
) -> ToolResult:
    """Validate and invoke a RAG tool inside the gateway authority process."""
    spec = _spec(name)
    try:
        params = spec.in_model.model_validate(arguments)
    except ValidationError as exc:
        return error_result(
            ErrorCode.invalid_input,
            "Input did not match the RAG tool schema.",
            "Correct the invalid argument values and retry.",
            details={"errors": exc.errors(include_url=False)},
        )

    try:
        service = _service(gateway)
        if name == "kb_search_knowledge":
            raw = await asyncio.to_thread(
                service._search,
                query=params.query,
                top_k=params.top_k,
                source=params.source,
                source_ids=params.source_ids,
                technique=params.technique,
                platform=params.platform,
            )
        elif name == "kb_list_knowledge_sources":
            raw = await asyncio.to_thread(service._list_sources)
        else:
            raw = await asyncio.to_thread(service._get_stats)
    except RuntimeError as exc:
        return error_result(
            ErrorCode.not_configured,
            "The gateway RAG control-plane connection is unavailable.",
            "Configure the gateway control-plane DSN, then rerun the RAG pack.",
            details={"reason": str(exc)},
        )
    except Exception:
        return error_result(
            ErrorCode.upstream_unavailable,
            "The shared RAG knowledge store is unavailable.",
            "Check the gateway and control-plane health, then retry.",
            retryable=True,
        )

    if not isinstance(raw, dict) or raw.get("error"):
        return error_result(
            ErrorCode.upstream_unavailable,
            "The shared RAG knowledge store is unavailable.",
            "Check the gateway and control-plane health, then retry.",
            retryable=True,
        )
    return success_result(raw, spec.out_model)
