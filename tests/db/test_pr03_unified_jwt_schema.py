from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "supabase" / "migrations" / "202606070300_unified_jwt_principals.sql"


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


def test_migration_file_exists_with_exact_name() -> None:
    assert MIGRATION.name == "202606070300_unified_jwt_principals.sql"
    assert MIGRATION.exists(), "PR03A migration file must exist with the exact name"
    assert _sql().strip(), "PR03A migration must not be empty"


def test_principal_auth_links_have_fk_and_partial_unique_index() -> None:
    sql = _normalized_sql()

    for table in ("agents", "service_identities"):
        assert (
            f"alter table app.{table} add column if not exists auth_user_id uuid null "
            "references auth.users(id) on delete set null"
        ) in sql, f"app.{table}.auth_user_id FK link missing"

    assert (
        "create unique index if not exists agents_auth_user_id_key "
        "on app.agents (auth_user_id) where auth_user_id is not null"
    ) in sql
    assert (
        "create unique index if not exists service_identities_auth_user_id_key "
        "on app.service_identities (auth_user_id) where auth_user_id is not null"
    ) in sql


def test_operator_system_role_with_role_check_constraint() -> None:
    sql = _normalized_sql()

    assert (
        "alter table app.operator_profiles add column if not exists system_role text "
        "not null default 'operator'"
    ) in sql
    assert (
        "operator_profiles_system_role_check check (system_role in "
        "('readonly', 'operator', 'lead', 'owner', 'admin'))"
    ) in sql


def test_principal_tool_scopes_columns_present() -> None:
    columns = _column_names("principal_tool_scopes")
    expected = {
        "id",
        "operator_profile_id",
        "agent_id",
        "service_identity_id",
        "case_id",
        "scope",
        "status",
        "constraints",
        "created_at",
        "updated_at",
    }
    assert expected <= columns, f"missing columns: {expected - columns}"


def test_principal_tool_scopes_exactly_one_principal_check() -> None:
    block = _table_block("principal_tool_scopes")
    normalized = re.sub(r"\s+", " ", block)

    assert "principal_tool_scopes_principal_check" in normalized
    # exactly-one (= 1) over the three principal-ref columns
    assert (
        "(case when operator_profile_id is null then 0 else 1 end) + "
        "(case when agent_id is null then 0 else 1 end) + "
        "(case when service_identity_id is null then 0 else 1 end) = 1"
    ) in normalized


def test_principal_tool_scopes_status_check() -> None:
    block = re.sub(r"\s+", " ", _table_block("principal_tool_scopes"))
    assert (
        "principal_tool_scopes_status_check check (status in "
        "('active', 'disabled', 'revoked'))"
    ) in block


def test_principal_tool_scopes_per_principal_ref_indexes() -> None:
    sql = _normalized_sql()
    for col in (
        "operator_profile_id",
        "agent_id",
        "service_identity_id",
        "case_id",
    ):
        assert (
            f"create index if not exists principal_tool_scopes_{col}_idx "
            f"on app.principal_tool_scopes ({col})"
        ) in sql, f"missing index on {col}"


def test_principal_tool_scopes_active_unique_null_and_nonnull_case_indexes() -> None:
    sql = _normalized_sql()

    # Non-null case_id partial unique index, scoped to active rows.
    assert (
        "create unique index if not exists principal_tool_scopes_active_case_key "
        "on app.principal_tool_scopes ( coalesce(operator_profile_id, agent_id, "
        "service_identity_id), scope, case_id ) "
        "where status = 'active' and case_id is not null"
    ) in sql

    # Null case_id partial unique index, scoped to active rows.
    assert (
        "create unique index if not exists principal_tool_scopes_active_global_key "
        "on app.principal_tool_scopes ( coalesce(operator_profile_id, agent_id, "
        "service_identity_id), scope ) "
        "where status = 'active' and case_id is null"
    ) in sql


def test_principal_identities_view_exists() -> None:
    sql = _normalized_sql()
    assert "create or replace view app.principal_identities" in sql
    # union all across the three principal sources
    assert sql.count("union all") >= 2
    assert "'operator'::text as principal_type" in sql
    assert "'agent'::text as principal_type" in sql
    assert "'service'::text as principal_type" in sql


def test_principal_identities_view_uses_security_invoker() -> None:
    sql = _normalized_sql()
    # The view must honor the querying role's RLS rather than defaulting to the
    # RLS-bypassing view-owner's rights.
    assert (
        "create or replace view app.principal_identities "
        "with (security_invoker = true) as"
    ) in sql


def test_principal_tool_scopes_rls_enabled() -> None:
    sql = _normalized_sql()
    assert (
        "alter table app.principal_tool_scopes enable row level security" in sql
    )


def test_operator_self_read_and_case_read_policies_exist() -> None:
    sql = _normalized_sql()

    # operator self-read on operator_profiles by auth.uid()
    assert "create policy operator_profiles_self_select on app.operator_profiles" in sql
    assert "auth.uid() = auth_user_id" in sql

    # operator may read cases where it has an active membership
    assert "create policy cases_member_select on app.cases" in sql

    # operator may read its own active case_members rows
    assert "create policy case_members_self_select on app.case_members" in sql

    # operator may read tool scopes it owns or for lead/owner cases
    assert (
        "create policy principal_tool_scopes_owner_or_lead_select "
        "on app.principal_tool_scopes" in sql
    )
    assert "cm.role in ('lead', 'owner')" in sql


def test_agents_owner_select_policy_exists() -> None:
    sql = _normalized_sql()
    # Required so the owner branch of the tool-scopes policy is not a dead
    # subquery against RLS-enabled app.agents.
    assert "create policy agents_owner_select on app.agents" in sql
    assert "op.id = app.agents.owner_user_id" in sql


def test_no_broad_direct_write_policies_added() -> None:
    sql = _normalized_sql()
    # PR03A adds read-only policies only; no insert/update/delete/all grants.
    for write_kind in ("for insert", "for update", "for delete", "for all"):
        assert write_kind not in sql, f"unexpected {write_kind!r} policy in PR03A migration"


def test_mcp_tokens_marked_compatibility_bridge() -> None:
    sql = _normalized_sql()
    assert "comment on table app.mcp_tokens is" in sql
    assert "compatibility bridge" in sql
    assert "not the" in sql and "target credential authority" in sql
