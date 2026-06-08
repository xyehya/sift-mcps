"""BATCH-G1 static checks on the pgvector RAG migration.

No live Postgres: these assert the schema/RPC text encodes the load-bearing
isolation and non-authority invariants, so a future edit that weakens them
fails CI.
"""

from __future__ import annotations

from pathlib import Path

_MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "supabase"
    / "migrations"
    / "202606081400_rag_pgvector.sql"
)


def _sql() -> str:
    return _MIGRATION.read_text()


def test_migration_exists():
    assert _MIGRATION.exists()


def test_pgvector_extension_and_dim():
    sql = _sql()
    assert "create extension if not exists vector" in sql
    assert "vector(768)" in sql


def test_kind_case_invariant_present_on_all_tables():
    sql = _sql()
    # knowledge => case-less ; derived => case-bound, on each table.
    assert sql.count("rag_collections_kind_case_check") >= 1
    assert sql.count("rag_documents_kind_case_check") >= 1
    assert sql.count("rag_chunks_kind_case_check") >= 1


def test_rag_search_binds_derived_to_querying_case_only():
    sql = _sql()
    # The derived branch is gated on p_case_id match; there is no unconditional
    # derived branch.
    assert "p.kind = 'derived'" in sql
    assert "p.case_id = p_case_id" in sql
    assert "p_case_id is not null" in sql


def test_derived_content_path_guard_present():
    sql = _sql()
    assert "rag_chunks_derived_no_abs_path_check" in sql
    # source_ref relative-only guard on documents.
    assert "rag_documents_source_ref_relative_check" in sql


def test_search_output_excludes_embedding():
    sql = _sql()
    # The RETURNS TABLE of rag_search must not surface the embedding column.
    # (It returns a distance, never the vector itself.)
    returns_block = sql.split("returns table (", 1)[1].split(")", 1)[0]
    assert "embedding" not in returns_block
    assert "distance double precision" in returns_block


def test_no_authority_over_evidence_or_reports():
    sql = _sql().lower()
    # RAG migration must not mutate evidence/approval/report/job authority.
    for forbidden in (
        "app.evidence_seal",
        "app.evidence_register",
        "update app.evidence_objects",
        "app.enqueue_job",
        "insert into app.findings",
        "app.reports",
    ):
        assert forbidden not in sql


def test_rls_enabled_with_case_member_or_knowledge_policy():
    sql = _sql()
    assert "alter table app.rag_chunks enable row level security" in sql
    assert "rag_chunks_case_member_or_knowledge_select" in sql
    # Shared knowledge (case_id IS NULL) is readable; case rows require membership.
    assert "case_id is null" in sql
    assert "auth.uid()" in sql
