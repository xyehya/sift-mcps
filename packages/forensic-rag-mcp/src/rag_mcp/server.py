#!/usr/bin/env python3
"""
RAG MCP Server — importer/seed CLI harness.

BATCH-PMI2: The three Chroma-backed agent-facing tools (kb_search_knowledge,
kb_list_knowledge_sources, kb_get_knowledge_stats) have been removed.  RAG
has a single agent-facing home: the gateway core tool ``rag_search_case``
backed by Supabase pgvector.

This module and its entry point (``rag-mcp``) remain as the CLI harness for
the Chroma->pgvector import/seed pipeline:

    python -m rag_mcp.pgvector_chroma_import
    python -m rag_mcp.pgvector_seed

The FastMCP instance is kept so the entry point starts cleanly, but it
exposes zero agent-facing tools.
"""

from __future__ import annotations

import logging
import sys

from mcp.server.fastmcp import FastMCP
from sift_common.instructions import FORENSIC_RAG as _INSTRUCTIONS

from .oplog import setup_logging

logger = logging.getLogger(__name__)


class RAGServer:
    """
    MCP Server harness — no agent-facing tools after BATCH-PMI2.

    The pgvector importers (pgvector_chroma_import, pgvector_seed) are
    still importable and runnable as CLI modules for the knowledge load step.
    """

    def __init__(self) -> None:
        self.mcp = FastMCP("forensic-rag-mcp", instructions=_INSTRUCTIONS)

    def run(self) -> None:
        """Run the MCP server (zero tools — import/seed path only)."""
        logger.info(
            "forensic-rag-mcp started (zero agent-facing tools after BATCH-PMI2). "
            "Use pgvector_chroma_import / pgvector_seed for knowledge loading."
        )
        self.mcp.run()


_server = RAGServer()
mcp = _server.mcp


def _print_help() -> None:
    """Print CLI help without starting the stdio MCP transport."""
    print("Usage: rag-mcp [--help]")
    print()
    print("RAG importer/seed harness (BATCH-PMI2: agent-facing tools removed).")
    print()
    print("Knowledge load commands:")
    print("  python -m rag_mcp.pgvector_chroma_import  # Chroma->pgvector import")
    print("  python -m rag_mcp.pgvector_seed            # Seed knowledge documents")


def main() -> None:
    """Entry point."""
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        _print_help()
        return

    setup_logging("forensic-rag-mcp")
    _server.run()


if __name__ == "__main__":
    main()
