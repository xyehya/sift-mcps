from pathlib import Path

SQL = Path("supabase/migrations/202607142100_replace_restore_operations.sql").read_text()


def test_recovery_begin_validates_object_before_inner_operation_creation():
    wrapper = SQL.split("create function app.custody_operation_begin_or_resume(", 1)[1]
    assert wrapper.index("pg_advisory_xact_lock") < wrapper.index("for share")
    assert wrapper.index("current_version_id is null") < wrapper.index(
        "custody_operation_begin_or_resume_v2("
    )
    assert "v_obj.status not in ('sealed','violated')" in wrapper


def test_completion_is_fresh_actor_operation_bound_and_single_use():
    body = SQL.split(
        "create function app.custody_operation_authorize_recovery_completion(", 1
    )[1]
    assert "custody_operation_reauth_event(v_op.action,'COMPLETE')" in body
    assert "jsonb_build_object('operation_id',v_op.id::text)" in body
    assert "v_reauth.actor_user_id is distinct from v_op.actor_user_id" in body
    assert "completion_reauth_audit_event_id uuid null" in SQL
    assert "unique references app.audit_events(id)" in SQL


def test_finalizer_independently_enforces_restore_and_replace_invariants():
    body = SQL.split(
        "create function app.custody_operation_commit_verified_recovery(", 1
    )[1]
    assert "v_obj.current_version_id::text is distinct from p_item->>'original_version_id'" in body
    assert "v_obj.current_sha256 is distinct from p_item->>'original_sha256'" in body
    assert "p_item->>'sha256' is distinct from v_obj.current_sha256" in body
    assert "p_item->>'sha256' is not distinct from v_obj.current_sha256" in body
    assert "preserved_sibling',true" in body
    assert "insert into app.evidence_versions" in body


def test_exact_restore_has_event_but_no_version_or_manifest_insert_branch():
    restore = SQL.split("if v_op.action='RESTORE_EXACT' then", 1)[1].split("else", 1)[0]
    assert "evidence_append_canonical_event_v1" in restore
    assert "'restored_exact',true" in restore
    assert "insert into app.evidence_versions" not in restore
    assert "insert into app.evidence_manifests" not in restore
    assert "current_version_id=" not in restore
    assert "manifest_version=" not in restore


def test_legacy_unsafe_rpcs_and_owner_only_helpers_are_not_runtime_granted():
    assert "alter function app.custody_operation_commit_verified_add_seal_v1" in SQL
    assert "security invoker" in SQL
    assert "revoke execute on function app.evidence_unseal" in SQL
    assert "revoke execute on function app.evidence_reacquire" in SQL
    assert "from service_role" in SQL
    assert "grant execute on function app.custody_operation_commit_verified_recovery" in SQL
    assert "to service_role" in SQL
