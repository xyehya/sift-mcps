from pathlib import Path

MIGRATION = (
    Path(__file__).parents[3]
    / "supabase/migrations/202607143000_drift_disposition.sql"
)


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8").lower()


def test_inventory_observations_are_path_free_append_only_and_force_rls() -> None:
    sql = _sql()
    assert "create table app.evidence_inventory_observations" in sql
    assert "force row level security" in sql
    assert "evidence_inventory_observations_no_update_delete" in sql
    assert "for select to authenticated" not in sql
    assert "inventory_correlation_reused" in sql
    assert "inventory_gate_findings_mismatch" in sql
    assert "f->>'recovery' not in" in sql
    assert "jsonb_typeof(f->'full_verification_required')<>'boolean'" in sql
    assert "not (f ?& array['code','gate_state','recovery','evidence_object_id'" in sql
    assert "jsonb_typeof(f->'code')<>'string'" in sql
    assert "display_path" not in sql.split(
        "create function app.evidence_record_inventory_classification", 1
    )[0]
    assert "blocked_unavailable" in sql


def test_disposition_finalizer_is_gate_bound_idempotent_and_least_privilege() -> None:
    sql = _sql()
    finalizer = sql.split(
        "create function app.custody_operation_commit_verified_disposition", 1
    )[1]
    assert "pg_advisory_xact_lock" in finalizer
    assert "phase<>'filesystem_verified'" in finalizer
    assert "p_item is distinct from v_op.verified_facts->'item'" in finalizer
    assert "if v_op.phase='completed' then return v_op" in finalizer
    assert "v_op.action not in ('ignore','delete_stray','retire')" in finalizer
    assert "revoke execute on function app.evidence_ignore" in sql
    assert "revoke execute on function app.evidence_retire" in sql
    assert "'disposition',v_op.action" in finalizer
    assert "coalesce(p_item->>'sha256','') !~" in finalizer
    assert "coalesce(p_item->>'bytes','') ~ '^[0-9]+$'" in finalizer
    assert ") is not true" in finalizer


def test_disposition_resume_preserves_preunlink_phase_and_facts() -> None:
    sql = _sql()
    resume = sql.split(
        "create function app.custody_operation_resume_disposition", 1
    )[1].split(
        "create function app.custody_operation_commit_verified_disposition", 1
    )[0]
    assert "coalesce(v_op.failed_from_phase,'gate_blocked')" in resume
    assert "prepared_facts" in resume
    assert "verified_facts" in resume
    assert "phase='gate_blocked'" not in resume


def test_retire_creates_manifest_without_unlinking_evidence() -> None:
    sql = _sql()
    finalizer = sql.split(
        "create function app.custody_operation_commit_verified_disposition", 1
    )[1]
    assert "insert into app.evidence_manifests" in finalizer
    assert "o.id<>v_obj.id" in finalizer
    assert "file_removed')::boolean,false)" in finalizer
    assert "unlink" not in finalizer
