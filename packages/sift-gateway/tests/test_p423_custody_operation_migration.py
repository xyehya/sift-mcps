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
    for table in ("custody_operation_history", "evidence_manifests"):
        assert f"create trigger {table}_no_truncate" in MIGRATION
    assert "already have the canonical\n-- no-TRUNCATE guards from 202606141400" in MIGRATION
    assert "create trigger evidence_versions_no_truncate" not in MIGRATION
    assert "create trigger evidence_custody_events_no_truncate" not in MIGRATION


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
    assert "grant select on app.custody_operations,app.custody_operation_history,app.evidence_manifests to authenticated" not in MIGRATION


def test_restart_ownership_recovery_is_atomic_and_same_runner_conflicts():
    begin = MIGRATION.split("create or replace function app.custody_operation_begin_or_resume", 1)[1]
    assert "p_runner_instance_id text" in begin
    assert "v_op.runner_instance_id=p_runner_instance_id" in begin
    assert "errcode='P4232'" in begin
    assert "phase='FAILED_RECOVERABLE'" in begin
    assert "'failed_from',v_op.failed_from_phase" in begin
    assert "runner_instance_id=p_runner_instance_id" in begin
    assert "when failed_from_phase='FILESYSTEM_VERIFIED'" in begin
    assert "then '{}'::jsonb else verified_facts end" in begin
    assert "phase='GATE_BLOCKED'" in begin
    assert "prepared_facts_mismatch" in MIGRATION
    assert "verified_facts_mismatch" in MIGRATION
    assert "v_op.phase='GATE_BLOCKED' and v_op.runner_instance_id<>p_runner_instance_id" in begin
    assert MIGRATION.count("runner_instance_id<>p_runner_instance_id") >= 3
    assert "and runner_instance_id=p_runner_instance_id" in MIGRATION
    assert "retired_runner_instance_ids ? p_runner_instance_id" in begin
    assert "retired_runner_instance_ids||jsonb_build_array" in begin


def test_reauth_violation_and_verified_items_are_db_authority_checks():
    assert "v_reauth.event_type<>'reauth.evidence_seal'" in MIGRATION
    assert "v_reauth.source<>'portal_reauth'" in MIGRATION
    assert "v_reauth.actor_type<>'user'" in MIGRATION
    assert "v_reauth.details->'binding' is distinct from v_binding" in MIGRATION
    assert MIGRATION.count("custody_violation_requires_recovery") >= 2
    assert "p_items is distinct from v_op.verified_facts->'items'" in MIGRATION
    assert "v_obj.display_path is distinct from v_item->>'path'" in MIGRATION
    assert "issues='[]'" not in MIGRATION
    for fragment in (
        "p_resume_reauth_audit_event_id uuid",
        "v_resume.event_type<>'reauth.evidence_seal_resume'",
        "v_resume.source<>'portal_reauth'",
        "v_resume.status<>'success'",
        "v_resume.actor_user_id is distinct from v_op.actor_user_id",
        "jsonb_build_object('operation_id',v_op.id::text)",
        "resume_reauth_audit_event_id uuid null unique",
        "resume_reauth_reused",
        "when unique_violation then",
        "resume_reauth_required",
    ):
        assert fragment in MIGRATION


def test_failure_is_expected_phase_cas_and_never_downgrades_violation():
    fail = MIGRATION.split("create or replace function app.custody_operation_fail", 1)[1].split(
        "create or replace function app.evidence_append_canonical_event_v1", 1
    )[0]
    assert "where id=p_operation_id and phase=p_expected" in fail
    assert "custody_operation_phase_conflict" in fail
    assert "case when seal_status='violated' then 'violated' else 'unsealed' end" in fail
