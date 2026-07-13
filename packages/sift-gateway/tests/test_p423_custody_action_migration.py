from __future__ import annotations

from pathlib import Path

MIGRATION = (
    Path(__file__).parents[3]
    / "supabase/migrations/202607141200_custody_operation_actions.sql"
).read_text(encoding="utf-8")
BASE_MIGRATION = (
    Path(__file__).parents[3]
    / "supabase/migrations/202607132100_custody_operations.sql"
).read_text(encoding="utf-8")
SPEC = (
    Path(__file__).parents[3] / "docs/architecture/EVIDENCE-CUSTODY-SPEC.md"
).read_text(encoding="utf-8")
ADR = (Path(__file__).parents[3] / ".codebase-memory/adr.md").read_text(
    encoding="utf-8"
)


def test_action_vocabulary_is_closed_and_add_seal_rpc_remains_compatible():
    for action in (
        "ADD_SEAL",
        "REPLACE_REACQUIRE",
        "RESTORE_EXACT",
        "IGNORE",
        "DELETE_STRAY",
        "RETIRE",
    ):
        assert f"'{action}'" in MIGRATION
    assert "create or replace function app.custody_operation_begin_or_resume(" in MIGRATION
    assert "uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid" in MIGRATION


def test_server_derives_action_reauth_and_exact_object_binding():
    for event_type in (
        "reauth.evidence_replace_begin",
        "reauth.evidence_replace_complete",
        "reauth.evidence_replace_resume",
        "reauth.evidence_restore",
        "reauth.evidence_ignore",
        "reauth.evidence_delete",
        "reauth.evidence_retire",
    ):
        assert event_type in MIGRATION
    assert "p_command->>'action' is distinct from p_action" in MIGRATION
    assert "custody_operation_reauth_event(p_action,'BEGIN')" in MIGRATION
    assert "custody_operation_reauth_event(p_action,'RESUME')" in MIGRATION
    assert "where id=(p_command->>'evidence_object_id')::uuid and case_id=p_case_id" in MIGRATION
    assert "v_reauth.details->'binding' is distinct from v_binding" in MIGRATION
    assert "jsonb_build_object('operation_id',v_op.id::text)" in MIGRATION
    assert "where key not in ('schema_version','action','evidence_object_id')" in MIGRATION


def test_case_advisory_precedes_begin_and_finalizer_row_locks():
    begin = MIGRATION.split(
        "create or replace function app.custody_operation_begin_or_resume(", 1
    )[1].split("alter function app.custody_operation_commit_verified_seal", 1)[0]
    advisory = begin.index("pg_advisory_xact_lock")
    assert advisory < begin.index("from app.evidence_objects")
    assert advisory < begin.index("from app.audit_events")
    assert advisory < begin.index("from app.custody_operations")

    finalizer = MIGRATION.split(
        "create or replace function app.custody_operation_commit_verified_seal(", 1
    )[1].split("revoke execute", 1)[0]
    assert finalizer.index("pg_advisory_xact_lock") < finalizer.index("for update")

    advance = BASE_MIGRATION.split(
        "create or replace function app.custody_operation_advance(", 1
    )[1].split("create or replace function app.custody_operation_fail(", 1)[0]
    fail = BASE_MIGRATION.split(
        "create or replace function app.custody_operation_fail(", 1
    )[1].split("create or replace function app.evidence_append_canonical_event_v1", 1)[0]
    assert "pg_advisory_xact_lock" not in advance
    assert "pg_advisory_xact_lock" not in fail

    combined = "\n".join((MIGRATION, SPEC, ADR))
    for stale in (
        "case, operation, then",
        "lock first, then audit",
        "before every custody row lock",
        "precedes every custody row lock",
        "all custody transactions",
        "Custody transactions acquire",
    ):
        assert stale not in combined
    assert "Generalized begin and each action-specific finalizer" in ADR
    assert "Operation-local `advance`/`fail` phase-CAS helpers are outside" in ADR
    assert "operation-local `advance` and\n`fail` phase-CAS helpers" in SPEC


def test_add_seal_finalizer_rejects_every_other_action_before_inner_mutation():
    finalizer = MIGRATION.split(
        "create or replace function app.custody_operation_commit_verified_seal(", 1
    )[1].split("revoke execute", 1)[0]
    guard = finalizer.index("v_op.action<>'ADD_SEAL'")
    dispatch = finalizer.index("custody_operation_commit_verified_add_seal_v1(")
    assert guard < dispatch
    assert "custody_operation_finalizer_action_mismatch" in finalizer
    assert "rename to custody_operation_commit_verified_add_seal_v1" in MIGRATION
    assert "from service_role" in MIGRATION


def test_shared_operation_security_contract_remains_fail_closed():
    assert "security definer set search_path=pg_catalog,app" in MIGRATION
    assert "pg_advisory_xact_lock" in MIGRATION
    assert "custody_operation_not_resumable" in MIGRATION
    assert "retired_runner_instance_ids ? p_runner_instance_id" in MIGRATION
    assert "phase='GATE_BLOCKED'" in MIGRATION
    assert "from public,anon,authenticated" in MIGRATION
    assert "grant execute" in MIGRATION and "to service_role" in MIGRATION
    assert "to authenticated" not in MIGRATION
    assert "/mcp" not in MIGRATION.lower()


def test_widening_preserves_single_runner_rls_and_append_only_controls():
    assert "custody_operations_one_nonterminal_per_case" in BASE_MIGRATION
    assert "alter table app.custody_operations force row level security" in BASE_MIGRATION
    assert "custody_operation_history_no_update_delete" in BASE_MIGRATION
    assert "custody_operation_history_no_truncate" in BASE_MIGRATION
    assert "drop index custody_operations_one_nonterminal_per_case" not in MIGRATION
    assert "disable row level security" not in MIGRATION
    assert "drop trigger" not in MIGRATION
