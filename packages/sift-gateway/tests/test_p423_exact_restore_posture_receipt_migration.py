from __future__ import annotations

from pathlib import Path

MIGRATION = (
    Path(__file__).parents[3]
    / "supabase/migrations/202607145000_exact_restore_posture_receipt.sql"
).read_text()


def test_exact_restore_uses_narrow_append_only_posture_authority():
    assert "create table app.evidence_exact_restore_posture_receipts" in MIGRATION
    assert "evidence_exact_restore_posture_receipts_no_update_delete" in MIGRATION
    assert "evidence_exact_restore_posture_receipts_no_truncate" in MIGRATION
    assert "insert into app.evidence_exact_restore_posture_receipts" in MIGRATION
    assert "insert into app.evidence_storage_verifications" not in MIGRATION
    wrapper = MIGRATION.split(
        "create function app.custody_operation_commit_verified_recovery(", 1
    )[1]
    assert "update app.evidence_versions" not in wrapper
    assert "insert into app.evidence_versions" not in wrapper
    assert "insert into app.evidence_manifests" not in wrapper


def test_exact_restore_receipt_binds_completion_and_descriptor_facts():
    for authority in (
        "case_id",
        "evidence_object_id",
        "evidence_version_id",
        "custody_operation_id",
        "custody_event_id",
        "completion_reauth_audit_event_id",
        "runner_instance_id",
        "storage_generation",
        "storage_profile",
        "sha256",
        "bytes",
        "st_dev",
        "st_ino",
        "st_mtime_ns",
        "st_ctime_ns",
        "st_nlink",
        "owner_name",
        "mode",
        "immutable",
    ):
        assert authority in MIGRATION
    assert "v_op.verified_facts->'item'" in MIGRATION
    assert "v_item->>'sha256' is distinct from v_item->>'original_sha256'" in MIGRATION
    assert "event_type='CHAIN_VERIFIED'" in MIGRATION
    assert "v_event_count <> 1" in MIGRATION
    assert "v_storage.profile <> 'LOCAL_IMMUTABLE'" in MIGRATION


def test_exact_restore_receipt_is_replay_safe_and_ungranted():
    assert "where custody_operation_id=v_op.id" in MIGRATION
    assert "revoke all on app.evidence_exact_restore_posture_receipts" in MIGRATION
    assert (
        "custody_operation_commit_verified_recovery_pre_posture_receipt(\n"
        "  uuid,jsonb,text,text) from public,anon,authenticated"
    ) in MIGRATION
    assert "from service_role;" in MIGRATION
    assert "grant select on app.evidence_exact_restore_posture_receipts" in MIGRATION
