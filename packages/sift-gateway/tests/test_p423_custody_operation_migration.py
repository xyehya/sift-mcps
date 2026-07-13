from pathlib import Path

MIGRATION = (
    Path(__file__).parents[3]
    / "supabase/migrations/202607132100_custody_operations.sql"
).read_text(encoding="utf-8")


def test_migration_freezes_durable_phases_and_exactly_once_keys():
    for phase in (
        "REQUESTED", "GATE_BLOCKED", "FILESYSTEM_APPLYING", "FILESYSTEM_VERIFIED",
        "LEDGER_COMMITTED", "COMPLETED", "FAILED_RECOVERABLE",
    ):
        assert phase in MIGRATION
    assert "unique (case_id, idempotency_key)" in MIGRATION
    assert "custody_operations_one_nonterminal_per_case" in MIGRATION
    assert "unique (reauth_audit_event_id)" in MIGRATION
    assert "evidence_versions_operation_object_key" in MIGRATION
    assert "evidence_events_operation_type_object_key" in MIGRATION


def test_final_rpc_derives_manifest_under_locks_and_preserves_siblings():
    body = MIGRATION.split("create or replace function app.custody_operation_commit_verified_seal", 1)[1]
    assert "where id=p_operation_id for update" in body
    assert "where case_id=v_op.case_id for update" in body
    assert "v_manifest_version:=coalesce(v_head.manifest_version,0)+1" in body
    assert "preserved_sibling" in body
    assert "phase='LEDGER_COMMITTED'" in body
    assert "phase='COMPLETED'" in body
    assert "seal_status='sealed'" in body


def test_canonical_event_v1_and_append_only_controls_are_explicit():
    assert "canonical_event_v1" in MIGRATION
    for field in (
        "operation_id", "case_id", "action", "evidence_object_id", "manifest_version",
        "actor_user_id", "actor_service_identity_id", "reason", "reauth_audit_event_id",
        "before", "after", "db_timestamp",
    ):
        assert f"'{field}'" in MIGRATION
    for table in (
        "custody_operation_history", "evidence_manifests", "evidence_versions",
        "evidence_custody_events",
    ):
        assert f"create trigger {table}_no_truncate" in MIGRATION


def test_new_security_definers_pin_search_path_and_revoke_public():
    assert "set search_path=app,public" not in MIGRATION
    assert MIGRATION.count("security definer set search_path=pg_catalog,app") == 5
    for fn in (
        "custody_operation_begin_or_resume", "custody_operation_advance",
        "custody_operation_fail", "evidence_append_canonical_event_v1",
        "custody_operation_commit_verified_seal",
    ):
        assert f"revoke execute on function app.{fn}" in MIGRATION
    assert "from public,anon,authenticated" in MIGRATION
