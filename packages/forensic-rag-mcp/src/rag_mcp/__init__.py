"""
RAG MCP Server - Semantic search over IR knowledge base.

This package provides an MCP server for semantic search across
incident response knowledge from 23 authoritative online sources
plus user-provided documents.

Architecture:
    - 23 online sources (Sigma, MITRE ATT&CK, Atomic Red Team, etc.)
    - User documents via knowledge/ folder (auto-watched)
    - One-time document ingestion with friendly names
    - ChromaDB vector store with BGE embeddings
    - Filesystem safety guardrails (sentinel-based deletion)
    - Network fetch hardening (HTTPS, size limits, retry)

Modules:
    server: MCP server exposing kb_search_knowledge, kb_list_knowledge_sources, kb_get_knowledge_stats tools
    index: ChromaDB and embedding model wrapper
    sources: Online source management (23 authoritative sources)
    ingest: User document ingestion (watched and one-time)
    build: Full index builder
    refresh: Incremental index updates
    status: Index status reporting
    config: Centralized configuration management
    fs_safety: Filesystem safety guardrails
    constants: Project-wide constants
    utils: Shared utility functions

Usage:
    # Run MCP server
    python -m rag_mcp.server

    # Build index (first time or full rebuild)
    python -m rag_mcp.build

    # Incremental update
    python -m rag_mcp.refresh

    # Check status
    python -m rag_mcp.status
"""

__version__ = "0.6.1"

# NOTE: ``pgvector_store`` (the BATCH-G1 Supabase pgvector RAG adapter) is a
# dependency-light module and is intentionally NOT eagerly imported here so it
# can be used without loading the ChromaDB knowledge index. Import it directly:
#     from rag_mcp.pgvector_store import PgVectorRagStore
__all__ = ["RAGIndex", "RAGServer", "get_config", "Config", "__version__"]


def __getattr__(name: str):
    """Lazy-load legacy Chroma-backed symbols only when callers request them."""
    if name in {"Config", "get_config"}:
        from .config import Config, get_config

        return {"Config": Config, "get_config": get_config}[name]
    if name == "RAGIndex":
        from .index import RAGIndex

        return RAGIndex
    if name == "RAGServer":
        from .server import RAGServer

        return RAGServer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
