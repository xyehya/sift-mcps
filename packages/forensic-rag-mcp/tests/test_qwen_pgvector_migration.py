from __future__ import annotations

from pathlib import Path

BASELINE = (
    Path(__file__).resolve().parents[3]
    / "supabase"
    / "migrations"
    / "202606081400_rag_pgvector.sql"
)
KNOWLEDGE_ONLY = (
    Path(__file__).resolve().parents[3]
    / "supabase"
    / "migrations"
    / "202606111200_rag_knowledge_only.sql"
)


def test_qwen_migration_replaces_dimension_and_ann_index():
    sql = BASELINE.read_text(encoding="utf-8").lower()
    assert "embedding vector(1024)" in sql
    assert "using hnsw (embedding vector_cosine_ops)" in sql
    assert "p_query_embedding vector(1024)" in sql


def test_qwen_migration_keeps_only_knowledge_search_surface():
    sql = KNOWLEDGE_ONLY.read_text(encoding="utf-8").lower()
    assert "and p.kind = 'knowledge'" in sql
    assert "drop function if exists app.rag_search(vector, uuid" in sql
    assert "p_query_embedding vector(1024)" in sql
