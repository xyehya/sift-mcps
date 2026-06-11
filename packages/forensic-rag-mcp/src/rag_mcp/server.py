#!/usr/bin/env python3
"""
forensic-rag-mcp — semantic search over the shared IR/DFIR knowledge corpus.

BATCH-OSX-RAG: the original forensic-rag tool surface is restored, now backed
by the Supabase pgvector store (PgVectorRagStore).

BATCH-NW4 (B-MVP-RAG-DERIVED REJECTED): the store is KNOWLEDGE ONLY. There is
no per-case derived RAG. Case-sensitive derived text must never enter or exit
the vector store. The kb tools here query shared knowledge only — no case_id,
no include_derived parameter, no derived path exists.

Agent-facing tools (registered under the manifest ``kb`` namespace):
    kb_search_knowledge       semantic search with source/source_ids/technique/platform filters
    kb_list_knowledge_sources list distinct knowledge source labels
    kb_get_knowledge_stats    corpus statistics (also the backend health probe)

Configuration:
    SIFT_CONTROL_PLANE_DSN / DATABASE_URL / POSTGRES_DSN: Postgres service DSN.
    RAG_MODEL_NAME: query embedding model (default BAAI/bge-base-en-v1.5).

Security:
    - Model allowlist prevents arbitrary model loading.
    - Input length / list-size limits prevent DoS.
    - Output is provenance-linked and PATH-FREE (the pgvector store sanitizes
      hits before they leave the process); internal DSN/paths are never returned.
    - The DB function app.rag_search (BATCH-NW4 migration) enforces
      kind='knowledge' unconditionally; derived content is unreachable at SQL level.
"""

from __future__ import annotations

import logging
import os
import sys

from mcp.server.fastmcp import FastMCP
from sift_common.instructions import FORENSIC_RAG as _INSTRUCTIONS

from .oplog import setup_logging
from .query_embedding import QueryEmbedder, QueryEmbeddingError
from .utils import DEFAULT_MODEL_NAME, MAX_TOP_K

logger = logging.getLogger(__name__)

# Input validation constants (mirror the original forensic-rag server).
MAX_QUERY_LENGTH = 1000
MAX_FILTER_LENGTH = 100
MAX_SOURCE_IDS = 20
_PLATFORM_ENUM = ("windows", "linux", "macos")


def _dsn_from_env() -> str | None:
    return (
        os.environ.get("SIFT_CONTROL_PLANE_DSN")
        or os.environ.get("DATABASE_URL")
        or os.environ.get("POSTGRES_DSN")
    )


class RAGServer:
    """forensic-rag-mcp server: pgvector-backed knowledge search tools."""

    def __init__(self) -> None:
        self.mcp = FastMCP("forensic-rag-mcp", instructions=_INSTRUCTIONS)
        self._store = None
        self._embedder: QueryEmbedder | None = None
        self._model_name = os.environ.get("RAG_MODEL_NAME", DEFAULT_MODEL_NAME)
        self._register_tools()

    # -- lazy resources ------------------------------------------------------

    def _get_store(self):
        if self._store is None:
            from .pgvector_store import PgVectorRagStore

            dsn = _dsn_from_env()
            if not dsn:
                raise RuntimeError("rag_control_plane_dsn_unavailable")
            self._store = PgVectorRagStore(dsn)
        return self._store

    def _get_embedder(self) -> QueryEmbedder:
        if self._embedder is None:
            self._embedder = QueryEmbedder(self._model_name)
        return self._embedder

    # -- tool registration ---------------------------------------------------

    def _register_tools(self) -> None:
        mcp = self.mcp

        @mcp.tool(annotations={"readOnlyHint": True})
        def kb_search_knowledge(
            query: str,
            top_k: int = 5,
            source: str = "",
            source_ids: list[str] | None = None,
            technique: str = "",
            platform: str = "",
        ) -> dict:
            """Semantic search across the shared IR/DFIR knowledge corpus.

            Sources include Sigma rules, MITRE ATT&CK, Atomic Red Team, Splunk
            Security, KAPE, Velociraptor, LOLBAS, GTFOBins, and more. Returns
            ranked, provenance-linked results (lower ``distance`` = closer match).
            This is shared reference knowledge, not case evidence.

            Args:
                query: Natural language search query (e.g. 'credential dumping
                    detection', 'lateral movement windows', or a MITRE ID 'T1003').
                top_k: Number of results (default 5, max 50; clamped).
                source: Filter by source (partial/substring match, e.g. 'sigma',
                    'mitre', 'atomic'). Use source_ids for exact matching.
                source_ids: Filter by exact source IDs (<=20 items). Takes
                    precedence over `source`. Use kb_list_knowledge_sources to
                    discover valid IDs.
                technique: Filter by MITRE technique ID (e.g. 'T1003', 'T1059.001').
                platform: Filter by platform: one of windows, linux, macos.

            Returns: {status, query, results[], matched_sources? | warning?}
            """
            return self._search(
                query=query,
                top_k=top_k,
                source=source,
                source_ids=source_ids,
                technique=technique,
                platform=platform,
            )

        @mcp.tool(annotations={"readOnlyHint": True})
        def kb_list_knowledge_sources() -> dict:
            """List all available knowledge sources in the corpus.

            Use this to discover what values can be passed to the `source` /
            `source_ids` filters of kb_search_knowledge.

            Returns: {status, sources[], count}
            """
            return self._list_sources()

        @mcp.tool(annotations={"readOnlyHint": True})
        def kb_get_knowledge_stats() -> dict:
            """Get knowledge corpus statistics and backend health.

            Reports the embedded chunk count, document/collection/source counts,
            and the embedding model contract. Also serves as this backend's
            health probe.

            Returns: {status, chunk_count, document_count, collection_count,
                source_count, embedding_dim, embedding_model}
            """
            return self._get_stats()

    # -- tool bodies ---------------------------------------------------------

    def _search(
        self,
        *,
        query: str,
        top_k: int,
        source: str,
        source_ids: list[str] | None,
        technique: str,
        platform: str,
    ) -> dict:
        query = (query or "").strip()
        if not query:
            return {"error": "validation_error", "message": "query is required"}
        if len(query) > MAX_QUERY_LENGTH:
            return {
                "error": "validation_error",
                "message": f"query exceeds maximum length of {MAX_QUERY_LENGTH}",
            }
        source = (source or "").strip()
        technique = (technique or "").strip()
        platform = (platform or "").strip()
        for field, value in (
            ("source", source),
            ("technique", technique),
            ("platform", platform),
        ):
            if len(value) > MAX_FILTER_LENGTH:
                return {
                    "error": "validation_error",
                    "message": f"{field} exceeds maximum length of {MAX_FILTER_LENGTH}",
                }
        if platform and platform.lower() not in _PLATFORM_ENUM:
            return {
                "error": "validation_error",
                "message": f"platform must be one of {list(_PLATFORM_ENUM)}",
            }

        clean_source_ids: list[str] | None = None
        if source_ids is not None:
            if not isinstance(source_ids, list):
                return {
                    "error": "validation_error",
                    "message": "source_ids must be a list of strings",
                }
            if len(source_ids) > MAX_SOURCE_IDS:
                return {
                    "error": "validation_error",
                    "message": f"source_ids cannot contain more than {MAX_SOURCE_IDS} items",
                }
            clean_source_ids = []
            for sid in source_ids:
                sid_text = str(sid).strip()
                if len(sid_text) > MAX_FILTER_LENGTH:
                    return {
                        "error": "validation_error",
                        "message": f"source_ids item exceeds maximum length of {MAX_FILTER_LENGTH}",
                    }
                if sid_text:
                    clean_source_ids.append(sid_text)
            clean_source_ids = clean_source_ids or None

        # Clamp top_k (the store clamps again as defense in depth).
        if not isinstance(top_k, int) or top_k < 1:
            top_k = 5
        elif top_k > MAX_TOP_K:
            top_k = MAX_TOP_K

        try:
            embedding = self._get_embedder().embed(query)
        except QueryEmbeddingError as exc:
            return {"error": exc.reason, "message": "query embedding failed"}

        try:
            store = self._get_store()
        except RuntimeError as exc:
            return {"error": str(exc), "message": "knowledge store unavailable"}

        # BATCH-NW4: store.search is knowledge-only; no case_id / include_derived.
        result = store.search(
            query_embedding=embedding,
            top_k=top_k,
            source=source or None,
            source_ids=clean_source_ids,
            technique=technique or None,
            platform=platform or None,
        )
        public = result.public_dict()
        response: dict = {
            "status": "ok",
            "query": query,
            "results": public.get("results", []),
        }
        # Filter feedback parity with the original tool: when a source filter was
        # applied but matched nothing, hint at kb_list_knowledge_sources.
        applied_source = clean_source_ids or ([source] if source else None)
        if applied_source and not response["results"]:
            response["warning"] = (
                "No knowledge chunks match the requested source filter. "
                "Use kb_list_knowledge_sources to see available sources."
            )
        return response

    def _list_sources(self) -> dict:
        try:
            store = self._get_store()
        except RuntimeError as exc:
            return {"error": str(exc), "message": "knowledge store unavailable"}
        sources = store.list_knowledge_sources()
        return {"status": "ok", "sources": sources, "count": len(sources)}

    def _get_stats(self) -> dict:
        try:
            store = self._get_store()
        except RuntimeError as exc:
            return {"error": str(exc), "message": "knowledge store unavailable"}
        stats = store.knowledge_stats()
        return {"status": "ok", **stats}

    def run(self) -> None:
        logger.info("forensic-rag-mcp started (pgvector knowledge tools).")
        self.mcp.run()


_server = RAGServer()
mcp = _server.mcp


def main() -> None:
    """Entry point."""
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        print("Usage: rag-mcp [--help]")
        print()
        print("forensic-rag-mcp: pgvector-backed knowledge search MCP server.")
        print()
        print("Knowledge load commands:")
        print("  python -m rag_mcp.pgvector_chroma_import  # Chroma->pgvector import")
        print("  python -m rag_mcp.pgvector_seed            # Seed knowledge documents")
        return

    setup_logging("forensic-rag-mcp")
    _server.run()


if __name__ == "__main__":
    main()
