"""Structural checks for the BATCH-K4 host-identity / ingest-status migration."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "supabase" / "migrations" / "202606081601_host_identity.sql"


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_host_identity_table_is_additive():
    sql = _sql()
    assert "create table if not exists app.host_identity_decisions" in sql


def test_records_decision_provenance_and_audit_linkage():
    sql = _sql()
    # The decision ledger links source/canonical/actor/tool/affected IDs/audit id.
    for column in (
        "raw text not null",
        "canonical text not null",
        "decision text not null",
        "source text",
        "tool text",
        "provenance_id uuid",
        "index_names text[]",
        "audit_event_id uuid",
    ):
        assert column in sql, f"missing column declaration: {column!r}"


def test_decision_check_constraint_covers_discovery_and_correction():
    sql = _sql()
    for token in (
        "discovery_already_mapped",
        "discovery_auto_alias",
        "discovery_auto_new_canonical",
        "correction",
    ):
        assert token in sql


def test_recorder_and_status_rpcs_present():
    sql = _sql()
    assert "create or replace function app.record_host_identity_decision" in sql
    assert "create or replace function app.opensearch_ingest_status" in sql
    # The status RPC derives from durable job state, not local files, and joins
    # the F1 provenance receipt.
    assert "from app.job_status_public" in sql
    assert "app.opensearch_ingest_provenance" in sql


def test_rls_enabled_on_host_identity_decisions():
    sql = _sql()
    assert "alter table app.host_identity_decisions enable row level security" in sql
    assert "host_identity_decisions_case_member_select" in sql


def test_no_security_definer_on_rpcs():
    # The comment documents the intent ("No SECURITY DEFINER"); assert the
    # actual function bodies declare language but not the definer clause.
    sql = _sql().lower()
    assert "language plpgsql\nas $$" in sql
    assert "language sql\nstable\nas $$" in sql
    # Strip line comments before checking for an active SECURITY DEFINER clause.
    code = "\n".join(
        line for line in sql.splitlines() if not line.lstrip().startswith("--")
    )
    assert "security definer" not in code
