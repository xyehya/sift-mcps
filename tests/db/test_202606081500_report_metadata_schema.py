"""Structural checks for the B-MVP-5 report/investigation metadata migration."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "supabase" / "migrations" / "202606081500_report_metadata.sql"


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_report_metadata_migration_exists_and_is_additive():
    sql = _sql()
    for table in (
        "app.investigation_findings",
        "app.investigation_timeline_events",
        "app.investigation_iocs",
        "app.investigation_todos",
        "app.report_metadata",
    ):
        assert f"create table if not exists {table}" in sql


def test_rls_enabled_on_all_new_tables():
    sql = _sql()
    assert "policyname = v_table || '_case_member_select'" in sql
    for table in (
        "investigation_findings",
        "investigation_timeline_events",
        "investigation_iocs",
        "investigation_todos",
        "report_metadata",
    ):
        assert f"alter table app.{table} enable row level security" in sql
        assert f"'{table}'" in sql


def test_report_id_is_text_to_match_portal_contract():
    sql = _sql()
    assert "report_id text not null" in sql
    assert "report_metadata_report_id_check" in sql
