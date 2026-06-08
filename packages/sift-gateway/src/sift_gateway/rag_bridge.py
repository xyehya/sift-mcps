"""Gateway-owned case-scoped pgvector RAG bridge."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Sequence
from typing import Any

from mcp.types import TextContent

logger = logging.getLogger(__name__)

RAG_SEARCH_CASE_TOOL = "rag_search_case"


class RagBridgeError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class PgVectorRagQueryService:
    """Thin Gateway service over G1's PgVectorRagStore.

    The store requires a 768-dimensional embedding. The bridge accepts a caller
    supplied `query_embedding` for deterministic automation/tests, and can also
    compute one locally with the allowed RAG embedding model when rag-mcp's
    optional dependencies are installed on the SIFT VM.
    """

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._model = None

    async def search(
        self,
        *,
        case_id: str,
        query: str,
        query_embedding: Sequence[float] | None = None,
        top_k: int = 5,
        include_knowledge: bool = True,
        include_derived: bool = True,
    ) -> dict[str, Any]:
        embedding = list(query_embedding) if query_embedding is not None else None
        if embedding is None:
            embedding = await asyncio.to_thread(self._embed_query, query)
        return await asyncio.to_thread(
            self._search_sync,
            case_id,
            embedding,
            int(top_k),
            bool(include_knowledge),
            bool(include_derived),
        )

    def _search_sync(
        self,
        case_id: str,
        embedding: list[float],
        top_k: int,
        include_knowledge: bool,
        include_derived: bool,
    ) -> dict[str, Any]:
        try:
            from rag_mcp.pgvector_store import PgVectorRagStore
        except ImportError as exc:  # pragma: no cover - deployment env
            raise RagBridgeError("rag_pgvector_store_unavailable") from exc
        store = PgVectorRagStore(self._dsn)
        return store.search(
            query_embedding=embedding,
            case_id=case_id,
            top_k=top_k,
            include_knowledge=include_knowledge,
            include_derived=include_derived,
        ).public_dict()

    def _embed_query(self, query: str) -> list[float]:
        if not query or len(query) > 1000:
            raise RagBridgeError("rag_query_required")
        try:
            from rag_mcp.utils import DEFAULT_MODEL_NAME, ALLOWED_MODELS
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover - deployment env
            raise RagBridgeError("rag_embedding_model_unavailable") from exc
        model_name = DEFAULT_MODEL_NAME
        if model_name not in ALLOWED_MODELS:
            raise RagBridgeError("rag_embedding_model_not_allowed")
        if self._model is None:
            self._model = SentenceTransformer(model_name)
        vector = self._model.encode(query)
        return [float(v) for v in vector.tolist()]


def rag_search_case_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Natural language DFIR/RAG query.",
            },
            "query_embedding": {
                "type": "array",
                "items": {"type": "number"},
                "description": "Optional precomputed 768-dimensional embedding.",
            },
            "top_k": {"type": "integer", "default": 5},
            "include_knowledge": {"type": "boolean", "default": True},
            "include_derived": {"type": "boolean", "default": True},
        },
        "anyOf": [
            {"required": ["query"]},
            {"required": ["query_embedding"]},
        ],
    }


async def handle_rag_search_case(
    gateway: Any, arguments: dict[str, Any], examiner: str | None
) -> list[TextContent]:
    del examiner
    from sift_gateway.mcp_endpoint import current_mcp_identity

    identity = current_mcp_identity()
    case = None
    service = getattr(gateway, "active_case_service", None)
    if service is not None:
        case = service.require_active_case_for_principal(identity)
    if case is None or not getattr(case, "case_id", None):
        payload = {"error": "active_case_required", "tool": RAG_SEARCH_CASE_TOOL}
        return [TextContent(type="text", text=json.dumps(payload))]
    rag_service = getattr(gateway, "rag_query_service", None)
    if rag_service is None:
        payload = {"error": "rag_pgvector_not_wired", "tool": RAG_SEARCH_CASE_TOOL}
        return [TextContent(type="text", text=json.dumps(payload))]

    embedding = arguments.get("query_embedding")
    if embedding is not None:
        if not isinstance(embedding, list) or not all(
            isinstance(v, int | float) for v in embedding
        ):
            payload = {"error": "query_embedding_must_be_numeric_array"}
            return [TextContent(type="text", text=json.dumps(payload))]
        if len(embedding) != 768:
            payload = {"error": "query_embedding_must_be_768_dimensional"}
            return [TextContent(type="text", text=json.dumps(payload))]
    try:
        result = await rag_service.search(
            case_id=case.case_id,
            query=str(arguments.get("query") or ""),
            query_embedding=embedding,
            top_k=int(arguments.get("top_k") or 5),
            include_knowledge=bool(arguments.get("include_knowledge", True)),
            include_derived=bool(arguments.get("include_derived", True)),
        )
    except Exception as exc:
        reason = getattr(exc, "reason", None) or str(exc) or type(exc).__name__
        logger.warning("rag_search_case failed: %s", reason)
        result = {"error": reason, "tool": RAG_SEARCH_CASE_TOOL}
    return [TextContent(type="text", text=json.dumps(result, default=str))]
