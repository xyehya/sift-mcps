from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "supabase" / "migrations" / "202606070500_mcp_backends_registry.sql"


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


def test_mcp_backends_table_columns_and_constraints() -> None:
    sql = _normalized_sql()
    columns = _column_names("mcp_backends")

    assert {
        "id",
        "name",
        "namespace",
        "transport",
        "enabled",
        "connection",
        "data_plane",
        "default_case_scoped",
        "manifest",
        "manifest_source",
        "manifest_sha256",
        "health_status",
        "health_detail",
        "health_checked_at",
        "registered_by",
        "created_at",
        "updated_at",
    } <= columns
    assert "id uuid primary key default gen_random_uuid()" in _table_block(
        "mcp_backends"
    )
    assert "constraint mcp_backends_transport_check check (transport in ('stdio', 'http'))" in sql
    assert "constraint mcp_backends_namespace_check check (length(btrim(namespace)) > 0)" in sql
    assert "name not in ('forensic-mcp', 'case-mcp', 'sift-mcp', 'report-mcp', 'sift-core')" in sql


def test_mcp_backends_no_raw_secret_shape() -> None:
    sql = _normalized_sql()
    columns = _column_names("mcp_backends")

    forbidden_columns = {
        "bearer_token",
        "raw_token",
        "plaintext_token",
        "password",
        "secret",
        "api_key",
        "tls_cert",
        "env",
    }
    assert forbidden_columns.isdisjoint(columns)
    assert "constraint mcp_backends_no_raw_secret_keys_check" in sql
    for key in forbidden_columns:
        assert f"'{key}'" in sql
    assert "bearer_token_env" in sql
    assert "tls_cert_env" in sql
    assert "env_refs" in sql


def test_mcp_backends_indexes_rls_and_policy() -> None:
    sql = _normalized_sql()

    assert "create unique index if not exists mcp_backends_name_key" in sql
    assert "on app.mcp_backends (name)" in sql
    assert "alter table app.mcp_backends enable row level security" in sql
    assert "policyname = 'mcp_backends_operator_select'" in sql
    assert "create policy mcp_backends_operator_select" in sql
    assert "op.auth_user_id = auth.uid()" in sql


def test_mcp_backends_v1_does_not_add_health_events_or_vault_secrets() -> None:
    sql = _normalized_sql()

    assert "mcp_backend_health_events" not in sql
    assert "create extension supabase_vault" not in sql
    assert "vault.decrypted_secrets" not in sql
    assert "vault.create_secret" not in sql
