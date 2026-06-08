"""Structural checks for the BATCH-K2 investigation authority migration."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "supabase" / "migrations" / "202606081600_investigation_authority.sql"


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_migration_exists():
    assert MIGRATION.is_file()


def test_version_and_reauth_columns_added_additively():
    sql = _sql()
    for table in (
        "app.investigation_findings",
        "app.investigation_timeline_events",
        "app.investigation_iocs",
    ):
        assert f"alter table {table}" in sql
    # version optimistic-lock column on all four investigation tables.
    assert sql.count("add column if not exists version integer not null default 1") == 4
    # re-auth provenance link on findings/timeline/iocs (not todos).
    assert sql.count("reauth_audit_event_id uuid null") == 3
    assert "references app.audit_events(id) on delete set null" in sql


def test_human_locked_predicate_defined():
    sql = _sql()
    assert "function app.investigation_human_locked" in sql
    assert "'APPROVED', 'REJECTED'" in sql
