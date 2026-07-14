from pathlib import Path

MIGRATION = Path(
    "supabase/migrations/202607145500_external_bootstrap_projection.sql"
).read_text(encoding="utf-8")
NORMALIZED = "".join(MIGRATION.lower().split())


def _function(name: str) -> str:
    body = MIGRATION.split(f"create or replace function app.{name}(", 1)[1]
    if "language sql" in body.split(";", 1)[0]:
        return body.split("\n$$;", 1)[0]
    return body.split("end $$;", 1)[0]


def test_virgin_external_predicate_is_exact_and_current_generation_bound() -> None:
    predicate = _function("evidence_is_virgin_external_bootstrap")
    for invariant in (
        "profile='EXTERNALLY_READ_ONLY'",
        "state='FULL_VERIFY_REQUIRED'",
        "source_identity is null",
        "verified_mount_instance is null",
        "observed_mount_instance is not null",
        "read_only is true",
        "verified_generation is null",
        "coalesce(h.manifest_version,0)=0",
        "h.manifest_hash is null",
        "coalesce(h.active_count,0)=0",
        "issue->>'storage_generation'",
        "a.generation",
        "status<>'detected'",
    ):
        assert invariant in predicate
    assert "app.evidence_manifests" in predicate
    assert "app.evidence_versions" in predicate
    assert "outcome='SUCCESS'" in predicate
    assert "not in ('STORAGE_PROFILE_CHANGED','STORAGE_FULL_VERIFY_REQUIRED','PERSISTED_VIOLATION')" in predicate
    assert "issue->>'code'='UNSAFE_PENDING_ITEM'" in predicate


def test_projection_preserves_storage_causes_and_removes_only_synthetic_latch() -> None:
    wrapper = _function("evidence_record_inventory_classification_v2")
    assert "evidence_record_inventory_classification_v2_pre_external_bootstrap" in wrapper
    assert "evidence_is_virgin_external_bootstrap(p_case_id)" in wrapper
    assert "where issue->>'code'<>'PERSISTED_VIOLATION'" in wrapper
    assert "seal_status='unsealed'" in wrapper
    assert "delete from app.evidence_inventory_observations" not in wrapper.lower()
    assert "delete from app.evidence_custody_events" not in wrapper.lower()


def test_begin_and_finalizer_revalidate_exact_target_set_under_case_lock() -> None:
    begin = _function("custody_operation_begin_or_resume_storage_v3")
    finalizer = _function("custody_operation_commit_verified_seal_storage_v3")
    lock = "pg_advisory_xact_lock(hashtextextended(p_case_id::text,0))"
    assert lock in begin
    assert "external_bootstrap_state_mismatch" in begin
    assert "external_bootstrap_target_set_mismatch" in begin
    assert "status='detected'" in begin
    assert "jsonb_array_length(p_command->'files')" in begin
    assert "custody_operation_begin_or_resume_storage_v3_pre_external_bootstrap" in begin
    assert "pg_advisory_xact_lock(hashtextextended(v_case_id::text,0))" in finalizer
    assert "external_bootstrap_finalizer_state_mismatch" in finalizer
    assert "external_bootstrap_verified_set_mismatch" in finalizer
    assert "custody_operation_commit_verified_seal_storage_v3_pre_external_bootstrap" in finalizer


def test_backfill_changes_only_chain_head_projection() -> None:
    backfill = MIGRATION.split("-- Backfill", 1)[1].split("-- Runtime grants", 1)[0]
    assert "update app.evidence_chain_heads h" in backfill
    assert "evidence_is_virgin_external_bootstrap(h.case_id)" in backfill
    assert "where issue->>'code'<>'PERSISTED_VIOLATION'" in backfill
    for append_only_table in (
        "app.evidence_inventory_observations",
        "app.evidence_custody_events",
        "app.evidence_storage_verifications",
    ):
        assert f"update {append_only_table}" not in backfill.lower()
        assert f"delete from {append_only_table}" not in backfill.lower()


def test_new_functions_are_service_only_and_add_no_agent_surface() -> None:
    for function in (
        "evidence_record_inventory_classification_v2(uuid,text,text,jsonb)",
        "custody_operation_begin_or_resume_storage_v3(uuid,jsonb,text,text,uuid,text,uuid,text,uuid)",
        "custody_operation_commit_verified_seal_storage_v3(uuid,jsonb,text,text)",
    ):
        assert f"revokeexecuteonfunctionapp.{function}frompublic,anon,authenticated;" in NORMALIZED
        assert f"grantexecuteonfunctionapp.{function}toservice_role;" in NORMALIZED
    assert "mcp" not in MIGRATION.lower()
    assert "authenticated" in MIGRATION.lower()
    assert "to authenticated" not in MIGRATION.lower()
