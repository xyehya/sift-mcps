#!/usr/bin/env python3
"""CLI compatibility wrapper for the installed Qwen pgvector importer."""

from rag_mcp.pgvector_snapshot_import import main

if __name__ == "__main__":
    raise SystemExit(main())
