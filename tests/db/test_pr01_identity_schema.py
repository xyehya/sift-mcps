from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "supabase" / "migrations" / "202606070101_identity_foundation.sql"

FOUNDATION_TABLES = {
    "operator_profiles",
    "cases",
    "case_members",
    "active_case_state",
    "agents",
    "service_identities",
    "audit_events",
    "mcp_tokens",
    "mcp_token_scopes",
}


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def _normalized_sql() -> str:
    return re.sub(r"\s+", " ", _sql().lower())


def _table_block(table: str) -> str:
    match = re.search(
        rf"create table if not exists app\.{table}\s*\((.*?)\n\);",
        _sql(),
        re.IGNORECASE | re.DOTALL,
    )
    assert match, f"missing create table block for app.{table}"
    return match.group(1).lower()


def _column_names(table: str) -> set[str]:
    names: set[str] = set()
    for line in _table_block(table).splitlines():
        line = line.strip().rstrip(",")
        if not line or line.startswith(("constraint ", "--")):
            continue
        names.add(line.split()[0])
    return names


def test_identity_foundation_tables_exist_with_uuid_primary_keys() -> None:
    sql = _normalized_sql()

    assert "create schema if not exists app" in sql
    assert "create extension if not exists pgcrypto" in sql

    for table in FOUNDATION_TABLES:
        block = _table_block(table)
        assert re.search(
            r"\bid\s+uuid\s+primary key\s+default\s+gen_random_uuid\(\)",
            block,
        ), f"app.{table} must use a UUID primary key"


def test_case_membership_roles_and_active_case_constraints() -> None:
    sql = _normalized_sql()

    assert (
        "constraint case_members_role_check check (role in "
        "('readonly', 'operator', 'lead', 'owner', 'admin'))"
    ) in sql
    assert (
        "constraint case_members_status_check check (status in "
        "('active', 'suspended', 'removed', 'expired'))"
    ) in sql
    assert "constraint active_case_state_scope_check check (scope in ('deployment'))" in sql
    assert (
        "create unique index if not exists active_case_state_scope_key "
        "on app.active_case_state (scope)"
    ) in sql
    assert (
        "create unique index if not exists case_members_active_member_key "
        "on app.case_members (case_id, operator_profile_id) where status = 'active'"
    ) in sql


def test_mcp_tokens_are_hash_only_and_scoped() -> None:
    sql = _normalized_sql()
    token_columns = _column_names("mcp_tokens")

    assert {"token_hash", "token_fingerprint"} <= token_columns
    assert {
        "token",
        "raw_token",
        "plaintext_token",
        "secret",
        "token_secret",
        "api_key",
        "raw_secret",
    }.isdisjoint(token_columns)
    assert (
        "create unique index if not exists mcp_tokens_token_hash_key "
        "on app.mcp_tokens (token_hash)"
    ) in sql
    assert "token_id uuid not null references app.mcp_tokens(id) on delete cascade" in sql
    assert "case_id uuid null references app.cases(id) on delete cascade" in _table_block(
        "mcp_token_scopes"
    )
    assert (
        "create unique index if not exists mcp_token_scopes_case_key "
        "on app.mcp_token_scopes (token_id, scope, case_id) where case_id is not null"
    ) in sql
    assert (
        "create unique index if not exists mcp_token_scopes_global_key "
        "on app.mcp_token_scopes (token_id, scope) where case_id is null"
    ) in sql


def test_audit_events_identity_references_are_optional_and_indexed() -> None:
    audit_columns = _column_names("audit_events")
    sql = _normalized_sql()

    assert {
        "case_id",
        "actor_user_id",
        "actor_agent_id",
        "actor_token_id",
        "actor_service_identity_id",
        "job_id",
        "request_id",
    } <= audit_columns
    assert "case_id uuid null references app.cases(id) on delete set null" in _table_block(
        "audit_events"
    )
    assert (
        "constraint audit_events_actor_type_check check "
        "(actor_type in ('user', 'agent', 'token', 'service', 'system'))"
    ) in sql
    for index_name in (
        "audit_events_case_created_at_idx",
        "audit_events_event_type_created_at_idx",
        "audit_events_actor_user_id_idx",
        "audit_events_actor_agent_id_idx",
        "audit_events_actor_token_id_idx",
        "audit_events_actor_service_identity_id_idx",
        "audit_events_job_id_idx",
        "audit_events_request_id_idx",
    ):
        assert f"create index if not exists {index_name}" in sql


def test_rls_enabled_and_no_deferred_runtime_tables_added() -> None:
    sql = _normalized_sql()

    for table in FOUNDATION_TABLES:
        assert f"alter table app.{table} enable row level security" in sql

    for deferred_table in (
        "jobs",
        "job_steps",
        "job_logs",
        "workers",
        "evidence_objects",
        "opensearch_indexes",
        "findings",
        "reports",
        "rag_collections",
        "mcp_backends",
    ):
        assert f"create table if not exists app.{deferred_table}" not in sql
