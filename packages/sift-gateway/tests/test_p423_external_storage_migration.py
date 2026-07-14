from pathlib import Path

MIGRATION = Path(
    "supabase/migrations/202607144000_external_read_only_storage.sql"
).read_text(encoding="utf-8")


def _function(name: str) -> str:
    return MIGRATION.split(f"create function app.{name}(", 1)[1].split("end $$;", 1)[0]


def test_storage_authority_and_receipts_are_service_only_append_only_authority() -> (
    None
):
    assert (
        "alter table app.evidence_storage_authorities force row level security"
        in MIGRATION
    )
    assert (
        "alter table app.evidence_storage_verifications force row level security"
        in MIGRATION
    )
    assert "evidence_storage_verifications_no_update_delete" in MIGRATION
    assert "evidence_storage_verifications_no_truncate" in MIGRATION
    assert "evidence_storage_profile_transitions_no_update_delete" in MIGRATION
    assert "evidence_storage_profile_transitions_no_truncate" in MIGRATION
    assert (
        "revoke all on app.evidence_storage_authorities from public,anon,authenticated"
        in MIGRATION
    )
    assert (
        "revoke all on app.evidence_storage_verifications from public,anon,authenticated"
        in MIGRATION
    )
    assert "to authenticated" not in MIGRATION
    assert "create trigger cases_evidence_storage_authority" in MIGRATION
    assert "after insert on app.cases" in MIGRATION


def test_v3_seal_is_profile_bound_and_rejects_retired_runner_replay() -> None:
    begin = _function("custody_operation_begin_or_resume_storage_v3")
    assert "'storage_profile',p_command->>'storage_profile'" in begin
    assert "v_reauth.details->'binding' is distinct from v_binding" in begin
    assert "v_storage.profile is distinct from p_command->>'storage_profile'" in begin
    assert "v_op.retired_runner_instance_ids ? p_runner_instance_id" in begin
    assert begin.index(
        "v_op.retired_runner_instance_ids ? p_runner_instance_id"
    ) < begin.index(
        "insert into app.custody_operation_history(operation_id,phase,facts,resume_reauth_audit_event_id)"
    )
    assert "custody_violation_requires_recovery" in begin


def test_external_finalizer_requires_source_mount_read_only_hash_and_single_link() -> (
    None
):
    finalizer = _function("custody_operation_commit_verified_seal_storage_v3")
    for invariant in (
        "storage_source_identity",
        "mount_instance_identity",
        "read_only",
        "st_nlink",
        "sha256",
        "bytes",
    ):
        assert invariant in finalizer
    assert "x ? 'owner' or x ? 'mode' or x ? 'immutable'" in finalizer
    assert (
        "v_storage.source_identity is not null and v_storage.source_identity<>v_source"
        in finalizer
    )
    assert "unique(case_id,correlation_id)" in MIGRATION


def test_source_change_is_not_collapsed_into_reconnectable_mount_change() -> None:
    observation = _function("evidence_storage_record_observation")
    classification = _function("evidence_record_inventory_classification_v2")
    assert "remediation='AUTHORIZE_SOURCE_CHANGE'" in observation
    assert "remediation='RECONNECT_AND_VERIFY'" in observation
    assert "'STORAGE_SOURCE_CHANGED'" in classification
    assert "'STORAGE_FULL_VERIFY_REQUIRED'" in classification
    assert "'AUTHORIZE_STORAGE_SOURCE_CHANGE'" in classification
    assert "'MOUNT_IDENTITY_CHANGED'" in classification
    assert "v_row.state in ('UNAVAILABLE','FULL_VERIFY_REQUIRED','IDENTITY_DRIFT','READ_WRITE_DRIFT')" in observation
    assert "state='FULL_VERIFY_REQUIRED'" in observation


def test_full_verify_is_generation_manifest_and_exact_active_version_bound() -> None:
    verify = _function("evidence_storage_commit_full_verify")
    assert "v_row.generation<>p_generation" in verify
    assert "v_head.manifest_version is distinct from p_manifest_version" in verify
    assert "(x->>'evidence_version_id')::uuid=v.id" in verify
    assert "x->>'sha256'=v.sha256" in verify
    assert "(x->>'bytes')::bigint=v.bytes" in verify
    assert "jsonb_array_length(p_items)<>(select count(*)" in verify
    assert "insert into app.evidence_storage_verifications" in verify
    assert "and (status='violated' or seal_status='violated')) then 'violated'" in verify
    assert "issue->>'code' not in ('STORAGE_UNAVAILABLE','MOUNT_IDENTITY_CHANGED'" in verify
    assert "(issue->>'storage_generation')::bigint is distinct from p_generation" in verify
    assert "else 'sealed'" in verify
    assert "storage_full_verify_operator_required" in verify
    assert "x->>'storage_source_identity'<>p_source_identity" in verify
    assert "x->>'mount_instance_identity'<>p_mount_instance" in verify
    assert "x ? 'owner' or x ? 'mode' or x ? 'immutable'" in verify
    assert "nullif(p_note,'')" in verify


def test_failed_full_verify_is_append_only_path_free_and_cannot_reopen_gate() -> None:
    failure = _function("evidence_storage_record_verify_failure")
    assert "insert into app.evidence_storage_verifications" in failure
    assert "'FAILED'" in failure
    assert "when seal_status='violated' then 'violated'" in failure
    assert (
        "when p_failure_code='STORAGE_UNAVAILABLE' then seal_status else 'violated'"
        in failure
    )
    assert "p_failure_code not in ('STORAGE_UNAVAILABLE','READ_WRITE_DRIFT'" in failure
    assert "display_path" not in failure
    assert "'RESTORE_REACQUIRE_RETIRE'" in failure
    assert "'CUSTODY_VIOLATION'" in failure
    assert "nullif(p_note,'')" in failure


def test_profile_transition_is_scoped_reauthenticated_and_preserves_violation() -> None:
    transition = _function("evidence_storage_change_profile")
    assert "v_reauth.event_type<>'reauth.evidence_storage_profile_change'" in transition
    assert (
        "v_reauth.details->'binding' is distinct from jsonb_build_object(" in transition
    )
    assert "'idempotency_key',btrim(p_idempotency_key)" in transition
    assert "storage_profile_reauth_reused" in transition
    assert "app.evidence_storage_profile_transitions" in transition
    assert "return v_existing.result" in transition
    assert "storage_profile_idempotency_conflict" in transition
    assert "storage_profile_retry_receipt_mismatch" in transition
    assert "generation=app.evidence_storage_authorities.generation+1" in transition
    assert "and (status='violated' or seal_status='violated'))" in transition
    assert "issue->>'code' not in (" in transition


def test_storage_only_source_and_rw_recovery_can_open_but_unrelated_violation_cannot() -> None:
    verify = _function("evidence_storage_commit_full_verify")
    transition = _function("evidence_storage_change_profile")
    for recoverable in (
        "STORAGE_SOURCE_CHANGED",
        "STORAGE_FULL_VERIFY_REQUIRED",
        "POSTURE_DRIFT",
        "READ_WRITE_DRIFT",
        "STORAGE_PROFILE_CHANGED",
    ):
        assert recoverable in verify
        assert recoverable in transition
    assert "(issue->>'storage_generation')::bigint is distinct from p_generation" in verify
    assert "and (status='violated' or seal_status='violated')) then 'violated'" in verify
    assert "issue->>'code' not in (" in verify
    assert "else 'sealed'" in verify
    assert "then 'violated' else 'unsealed'" in transition
    assert "app.evidence_append_custody_event" in transition
    assert "'storage_generation',v_row.generation" in transition
    assert "issue->>'code' not in (" in transition


def test_seal_receipt_contains_generated_versions_for_current_manifest_resolution() -> (
    None
):
    finalizer = _function("custody_operation_commit_verified_seal_storage_v3")
    assert "v_verification_facts" in finalizer
    assert "o.current_version_id=(x->>'evidence_version_id')::uuid" in finalizer
    assert "v_manifest_version,v_manifest_hash,v_verification_facts" in finalizer
    assert "v_manifest_version,v_manifest_hash,p_items" not in finalizer


def test_migration_exposes_no_mcp_storage_mutation_surface() -> None:
    lowered = MIGRATION.lower()
    assert "/mcp" not in lowered
    assert "tool_registry" not in lowered
    assert "mcp_tool" not in lowered


def test_every_storage_authority_transition_takes_exclusive_case_lock() -> None:
    lock = "pg_advisory_xact_lock(hashtextextended("
    for name in (
        "custody_operation_begin_or_resume_storage_v3",
        "evidence_storage_record_verify_failure",
        "custody_operation_commit_verified_seal_storage_v3",
        "evidence_storage_change_profile",
        "evidence_storage_record_observation",
        "evidence_storage_commit_full_verify",
    ):
        assert lock in _function(name), name
