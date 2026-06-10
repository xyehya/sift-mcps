"""
RAG MCP — pgvector importer/seed package.

BATCH-PMI2: The three Chroma-backed agent-facing tools (kb_search_knowledge,
kb_list_knowledge_sources, kb_get_knowledge_stats) have been removed.

The agent-facing RAG surface is the gateway core tool ``rag_search_case``
backed by Supabase pgvector (``app.rag_chunks``).

Modules available for the knowledge load pipeline:
    pgvector_store: Supabase pgvector adapter (PgVectorRagStore)
    pgvector_chroma_import: Chroma->pgvector batch importer
    pgvector_seed: Seed knowledge documents from the knowledge/ directory

Legacy Chroma-backed modules (index, build, refresh, status, sources, ingest,
config) remain on disk as internal helpers for the Chroma->pgvector import
step only and are NOT part of the public API.

Usage:
    # Import Chroma collection into pgvector
    python -m rag_mcp.pgvector_chroma_import

    # Seed knowledge documents
    python -m rag_mcp.pgvector_seed

    # Use pgvector store directly
    from rag_mcp.pgvector_store import PgVectorRagStore
"""

__version__ = "0.6.1"

# NOTE: ``pgvector_store`` is dependency-light and is intentionally NOT eagerly
# imported so it can be used without loading ChromaDB. Import it directly:
#     from rag_mcp.pgvector_store import PgVectorRagStore
__all__ = ["__version__"]
