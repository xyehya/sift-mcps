"""
RAG MCP — pgvector-backed knowledge search MCP server + import/seed package.

BATCH-OSX-RAG: the three knowledge tools (kb_search_knowledge,
kb_list_knowledge_sources, kb_get_knowledge_stats) are restored as a
forensic-rag-mcp add-on, now backed by the Supabase pgvector store
(``app.rag_chunks``) instead of ChromaDB. The gateway ``rag_search_case`` shim
that PMI2 introduced has been removed; RAG has a single agent-facing home again
in this add-on.

Modules available for the knowledge load pipeline:
    pgvector_store: Supabase pgvector adapter (PgVectorRagStore)
    pgvector_chroma_import: Chroma->pgvector batch importer
    pgvector_seed: Seed knowledge documents from the knowledge/ directory

Legacy Chroma-backed modules (refresh, sources, ingest, config) remain on disk
as internal helpers for the Chroma->pgvector import/download step only (the
bundle-fetch entrypoint ``scripts/download_index.py`` lazily re-embeds user
docs via ``refresh``) and are NOT part of the public API. The Chroma
index-build/refresh/analyze tooling (index, build, status, analyze_queries,
tuning_config, fs_safety, scripts/build_release) was removed in BATCH-OSX-PURGE
as dead after the pgvector port.

Usage:
    # Import Chroma collection into pgvector
    python -m rag_mcp.pgvector_chroma_import

    # Seed knowledge documents
    python -m rag_mcp.pgvector_seed

    # Use pgvector store directly
    from rag_mcp.pgvector_store import PgVectorRagStore
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("rag-mcp")
except PackageNotFoundError:  # source tree / dist not installed — avoid import-time crash
    __version__ = "0.0.0.dev0"

# NOTE: ``pgvector_store`` is dependency-light and is intentionally NOT eagerly
# imported so it can be used without loading ChromaDB. Import it directly:
#     from rag_mcp.pgvector_store import PgVectorRagStore
__all__ = ["__version__"]
