#!/usr/bin/env python3
"""
RAG MCP Server - Semantic search over IR knowledge base.

Exposes the RAG knowledge base (23K+ records from 23 authoritative security
sources) as MCP tools for Claude Code integration.

Tools:
    search_knowledge: Semantic search with optional filters (source, technique, platform)
    list_knowledge_sources: Get available knowledge sources
    get_knowledge_stats: Get index statistics

Usage:
    # Run directly
    python -m rag_mcp.server

    # Or via entry point after install
    rag-mcp

Configuration:
    RAG_INDEX_DIR: Path to ChromaDB index (default: ./data)
    RAG_MODEL_NAME: Embedding model (default: BAAI/bge-base-en-v1.5)

Security:
    - Model allowlist prevents arbitrary model loading
    - Input length limits prevent DoS
    - Internal paths not disclosed in responses
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP
from sift_common.instructions import FORENSIC_RAG as _INSTRUCTIONS

from .audit import AuditWriter, resolve_examiner
from .index import RAGIndex
from .oplog import setup_logging
from .tool_metadata import DEFAULT_METADATA, TOOL_METADATA
from .utils import MAX_TOP_K

logger = logging.getLogger(__name__)

# Input validation constants
MAX_QUERY_LENGTH = 1000
MAX_FILTER_LENGTH = 100


def _validate_length(value: Any, max_length: int, field: str) -> None:
    """Validate input length to prevent DoS."""
    if value is not None and isinstance(value, str) and len(value) > max_length:
        raise ValueError(f"{field} exceeds maximum length of {max_length}")


class RAGServer:
    """
    MCP Server for RAG knowledge base search.

    Keeps the embedding model and ChromaDB index loaded in memory
    for fast query responses (~50ms).
    """

    def __init__(self) -> None:
        self.mcp = FastMCP("forensic-rag-mcp", instructions=_INSTRUCTIONS)
        self.index = RAGIndex()
        self._audit = AuditWriter("forensic-rag-mcp")
        self._register_tools()

    def _wrap_response(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        audit_id: str | None = None,
        elapsed_ms: float | None = None,
    ) -> dict[str, Any]:
        """Wrap tool result with evidence ID, caveats, and audit trail.

        Always generates audit_id and writes audit — including for errors.
        """
        summary = result if "error" not in result else {"error": result["error"]}
        audit_id = self._audit.log(
            tool=tool_name,
            params=arguments,
            result_summary=summary,
            audit_id=audit_id,
            elapsed_ms=elapsed_ms,
        )
        if audit_id is None:
            audit_warn = "Audit write failed — action not recorded"
            existing = result.get("warning")
            result["warning"] = f"{existing} | {audit_warn}" if existing else audit_warn
        meta = TOOL_METADATA.get(tool_name, DEFAULT_METADATA)

        result["audit_id"] = audit_id
        result["examiner"] = resolve_examiner()
        if "error" not in result:
            result["caveats"] = meta["caveats"]
            result["interpretation_constraint"] = meta["interpretation_constraint"]
        return result

    def _register_tools(self) -> None:
        """Register MCP tools."""

        @self.mcp.tool(annotations={"readOnlyHint": True})
        async def search_knowledge(
            query: str,
            top_k: int = 5,
            source: str | None = None,
            source_ids: list[str] | None = None,
            technique: str | None = None,
            platform: str | None = None,
        ) -> dict[str, Any]:
            """Semantic search across 23K+ incident response knowledge records.

            Sources include Sigma rules, MITRE ATT&CK, Atomic Red Team, Splunk
            Security, KAPE, Velociraptor, LOLBAS, GTFOBins, and more. Returns
            ranked results with relevance scores from 0-1, where higher is better.
            Scores above 0.85 are excellent matches; 0.75-0.84 are good.
            """
            arguments = {
                "query": query,
                "top_k": top_k,
                "source": source,
                "source_ids": source_ids,
                "technique": technique,
                "platform": platform,
            }
            return await self._call_tool("search_knowledge", arguments, self._search)

        @self.mcp.tool(annotations={"readOnlyHint": True})
        async def list_knowledge_sources() -> dict[str, Any]:
            """List all available knowledge sources in the RAG index."""
            return await self._call_tool(
                "list_knowledge_sources", {}, lambda _: self._list_sources()
            )

        @self.mcp.tool(annotations={"readOnlyHint": True})
        async def get_knowledge_stats() -> dict[str, Any]:
            """Get RAG index statistics: document count, sources, and model info."""
            return await self._call_tool(
                "get_knowledge_stats", {}, lambda _: self._get_stats()
            )

    async def _call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        handler: Any,
    ) -> dict[str, Any]:
        """Run a FastMCP tool handler with the legacy audit/error envelope."""
        import time

        audit_id = self._audit._next_audit_id()
        start = time.monotonic()
        try:
            result = await handler(arguments)
            elapsed_ms = (time.monotonic() - start) * 1000
            return self._wrap_response(
                name,
                arguments,
                result,
                audit_id=audit_id,
                elapsed_ms=elapsed_ms,
            )
        except ValueError as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.warning(f"Tool {name} validation failed: {e}")
            error_result = {"error": "validation_error", "message": str(e)}
            return self._wrap_response(
                name,
                arguments,
                error_result,
                audit_id=audit_id,
                elapsed_ms=elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.exception(f"Tool {name} internal error")
            # Surface the actual error so LLMs can diagnose
            msg = str(exc)
            if isinstance(exc, FileNotFoundError):
                msg = f"Index not found: {exc}. Run 'python -m rag_mcp.build' to build the knowledge index."
            elif isinstance(exc, ImportError):
                msg = f"Missing dependency: {exc}"
            error_result = {
                "error": "internal_error",
                "message": msg or "An unexpected error occurred. Check server logs.",
            }
            return self._wrap_response(
                name,
                arguments,
                error_result,
                audit_id=audit_id,
                elapsed_ms=elapsed_ms,
            )

    async def _search(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """
        Execute search tool.

        Args:
            arguments: Tool arguments (query, top_k, source, technique, platform)

        Returns:
            Search results with status, query echo, and ranked matches
        """
        query = arguments.get("query", "")
        top_k = arguments.get("top_k", 5)
        source = arguments.get("source")
        source_ids = arguments.get("source_ids")
        technique = arguments.get("technique")
        platform = arguments.get("platform")

        # Validate inputs
        _validate_length(query, MAX_QUERY_LENGTH, "query")
        _validate_length(source, MAX_FILTER_LENGTH, "source")
        _validate_length(technique, MAX_FILTER_LENGTH, "technique")
        _validate_length(platform, MAX_FILTER_LENGTH, "platform")

        # Validate source_ids if provided
        if source_ids is not None:
            if not isinstance(source_ids, list):
                raise ValueError("source_ids must be a list of strings")
            if len(source_ids) > 20:
                raise ValueError("source_ids cannot contain more than 20 items")
            for sid in source_ids:
                _validate_length(sid, MAX_FILTER_LENGTH, "source_ids item")

        if not query:
            raise ValueError("query is required")

        # Validate top_k is a positive integer
        if not isinstance(top_k, int) or top_k < 1:
            top_k = 5
        elif top_k > MAX_TOP_K:
            top_k = MAX_TOP_K

        # Run search (CPU-bound, so run in thread pool)
        loop = asyncio.get_running_loop()
        search_result = await loop.run_in_executor(
            None,
            lambda: self.index.search(
                query=query,
                top_k=top_k,
                source=source,
                source_ids=source_ids,
                technique=technique,
                platform=platform,
            ),
        )

        response = {"status": "ok", "query": query, "results": search_result["results"]}

        # Add context about filters
        if search_result["source_filter"]:
            if search_result["matched_sources"]:
                response["matched_sources"] = search_result["matched_sources"]
            else:
                response["warning"] = (
                    f"No sources match filter '{source}'. "
                    "Use list_knowledge_sources tool to see available sources."
                )

        return response

    async def _list_sources(self) -> dict[str, Any]:
        """List available sources."""
        if not self.index.is_loaded:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self.index.load)

        return {
            "status": "ok",
            "sources": self.index.available_sources,
            "count": len(self.index.available_sources),
        }

    async def _get_stats(self) -> dict[str, Any]:
        """Get index statistics."""
        loop = asyncio.get_running_loop()
        stats = await loop.run_in_executor(None, self.index.get_stats)
        return {"status": "ok", **stats}

    def run(self) -> None:
        """Run the MCP server.

        Index loads lazily on first tool call (search/list_sources/get_stats)
        so the stdio handshake completes immediately.
        """
        logger.info("Starting MCP server (index loads on first query)...")
        self.mcp.run()


_server = RAGServer()
mcp = _server.mcp


def _print_help() -> None:
    """Print CLI help without starting the stdio MCP transport."""
    print("Usage: rag-mcp [--help]")
    print()
    print("RAG MCP Server - Semantic search over IR knowledge base.")
    print()
    print("Tools:")
    for tool in mcp._tool_manager.list_tools():
        print(f"  {tool.name}")
        if tool.description:
            print(f"    {tool.description}")


def main() -> None:
    """Entry point."""
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        _print_help()
        return

    setup_logging("forensic-rag-mcp")
    _server.run()


if __name__ == "__main__":
    main()
