"""BATCH-OSX-RAG: static checks on the rag_search filters migration.

No live Postgres: assert the new append-only migration extends app.rag_search
with the source/source_ids/technique/platform filter params (defaulted, so the
existing 5-arg signature stays valid) while preserving the case-isolation,
no-embedding-output, and shared-knowledge contracts.
"""

from __future__ import annotations

from pathlib import Path

_MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "supabase"
    / "migrations"
    / "202606101100_rag_search_filters.sql"
)
_ORIGINAL = (
    Path(__file__).resolve().parents[3]
    / "supabase"
    / "migrations"
    / "202606081400_rag_pgvector.sql"
)


def _sql() -> str:
    return _MIGRATION.read_text()


def test_migration_exists():
    assert _MIGRATION.exists()


def test_does_not_edit_original_migration():
    # The original RPC must still carry only the 5-arg signature comment so we
    # know this change is append-only (the new params live in the new file).
    orig = _ORIGINAL.read_text()
    assert "p_source text default null" not in orig


def test_new_filter_params_are_defaulted_for_backward_safety():
    sql = _sql()
    for param in (
        "p_source text default null",
        "p_source_ids text[] default null",
        "p_technique text default null",
        "p_platform text default null",
    ):
        assert param in sql


def test_create_or_replace_keeps_existing_params():
    sql = _sql()
    # The first five params (unchanged contract) must still be present.
    for param in (
        "p_query_embedding vector(768)",
        "p_case_id uuid default null",
        "p_top_k int default 5",
        "p_include_knowledge boolean default true",
        "p_include_derived boolean default true",
    ):
        assert param in sql
    assert "create or replace function app.rag_search(" in sql


def test_filters_read_chunk_metadata_keys():
    sql = _sql()
    assert "ch.metadata->>'source'" in sql
    assert "ch.metadata->>'mitre_techniques'" in sql
    assert "ch.metadata->>'platform'" in sql


def test_source_ids_takes_precedence_over_source():
    sql = _sql()
    # source filter is only applied when source_ids is null.
    assert "p_source_ids is not null" in sql
    assert "= any (p_source_ids)" in sql


def test_case_isolation_and_no_embedding_output_preserved():
    sql = _sql()
    # Derived branch still bound to the querying case only.
    assert "p.kind = 'derived'" in sql
    assert "p.case_id = p_case_id" in sql
    # RETURNS TABLE must not surface the embedding column.
    returns_block = sql.split("returns table (", 1)[1].split(")", 1)[0]
    assert "embedding" not in returns_block
    assert "distance double precision" in returns_block
