from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "supabase" / "migrations" / "202606070400_active_case_authority.sql"
FOUNDATION = ROOT / "supabase" / "migrations" / "202606070101_identity_foundation.sql"


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8").lower()


def test_active_case_migration_is_comments_and_read_helper_only() -> None:
    sql = _sql()
    assert "comment on column app.cases.legacy_case_dir" in sql
    assert "not active-case authority" in sql
    assert "create or replace view app.deployment_active_case" in sql
    assert "from app.active_case_state" in sql


def test_no_historical_data_or_deferred_runtime_tables() -> None:
    sql = _sql()
    assert "insert into app.cases" not in sql
    assert "copy app.cases" not in sql
    for deferred_table in (
        "evidence_objects",
        "findings",
        "timeline",
        "todos",
        "reports",
        "jobs",
        "rag",
        "mcp_backends",
        "opensearch",
    ):
        assert f"create table" not in sql or f"app.{deferred_table}" not in sql


def test_rls_still_enabled_on_case_authority_tables() -> None:
    foundation = FOUNDATION.read_text(encoding="utf-8").lower()
    for table in ("cases", "case_members", "active_case_state"):
        assert f"alter table app.{table} enable row level security" in foundation


def test_no_raw_secret_or_file_fixtures() -> None:
    sql = _sql()
    forbidden = ("service_role_key", "anon_key", "jwt_secret", "raw_token", "plaintext")
    assert all(term not in sql for term in forbidden)
