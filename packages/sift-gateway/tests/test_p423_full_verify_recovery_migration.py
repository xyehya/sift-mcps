import re
from pathlib import Path

MIGRATION = Path(
    "supabase/migrations/202607145100_full_verify_posture_recovery.sql"
).read_text(encoding="utf-8")
SERVICE = Path(
    "packages/sift-gateway/src/sift_gateway/portal_services.py"
).read_text(encoding="utf-8")


def _function(name: str) -> str:
    return MIGRATION.split(f"create function app.{name}(", 1)[1].split(
        "end $$;", 1
    )[0]


def test_full_verify_recovery_is_forward_only_and_reuses_proven_verifier() -> None:
    assert "202607144000" not in MIGRATION
    assert "202607145000" not in MIGRATION
    assert (
        "rename to evidence_storage_commit_full_verify_pre_posture_recovery"
        in MIGRATION
    )
    wrapper = _function("evidence_storage_commit_full_verify")
    assert "pg_advisory_xact_lock(hashtextextended(p_case_id::text,0))" in wrapper
    assert "app.evidence_storage_commit_full_verify_pre_posture_recovery(" in wrapper
    assert "select coalesce(issues,'[]'::jsonb) into v_original_issues" in wrapper
    assert wrapper.index("into v_original_issues") < wrapper.index(
        "app.evidence_storage_commit_full_verify_pre_posture_recovery("
    )


def test_success_clears_only_current_storage_and_posture_findings() -> None:
    wrapper = _function("evidence_storage_commit_full_verify")
    for recoverable in (
        "STORAGE_UNAVAILABLE",
        "MOUNT_IDENTITY_CHANGED",
        "STORAGE_FULL_VERIFY_REQUIRED",
        "POSTURE_DRIFT",
        "READ_WRITE_DRIFT",
        "STORAGE_PROFILE_CHANGED",
        "FULL_VERIFY_REQUIRED",
    ):
        assert recoverable in wrapper
    assert "PERSISTED_VIOLATION" in wrapper
    assert "from jsonb_array_elements(v_original_issues) issue" in wrapper
    assert "coalesce(issue->>'storage_generation','') ~ '^[0-9]+$'" in wrapper
    for preserved in (
        "CONTENT_CHANGED",
        "SEALED_EVIDENCE_MISSING",
        "LEDGER_INVALID",
        "IDENTITY_CHANGED",
        "INVENTORY_SCAN_FAILED",
        "CONFLICTING_AUTHORITY",
        "STORAGE_SOURCE_CHANGED",
    ):
        assert f"'{preserved}'" not in wrapper
    assert "status='violated' or seal_status='violated'" in wrapper
    assert "status in ('detected','registered')" in wrapper


def test_wrapper_binds_recovery_to_the_exact_success_receipt() -> None:
    wrapper = _function("evidence_storage_commit_full_verify")
    assert "outcome='SUCCESS'" in wrapper
    assert "generation=p_generation" in wrapper
    assert "profile=p_profile" in wrapper
    assert "manifest_version=p_manifest_version" in wrapper
    assert "manifest_hash=(select manifest_hash" in wrapper
    assert "item_facts=p_items" in wrapper
    assert "correlation_id=p_correlation_id" in wrapper
    assert "full_verify_success_receipt_missing" in wrapper


def test_unwrapped_function_is_not_runtime_reachable() -> None:
    compact = re.sub(r"\s+", "", MIGRATION)
    signature = (
        "uuid,bigint,text,text,text,boolean,integer,jsonb,text,uuid,text"
    )
    assert (
        "revokeexecuteonfunction"
        "app.evidence_storage_commit_full_verify_pre_posture_recovery("
        f"{signature})frompublic,anon,authenticated"
    ) in compact
    assert (
        "revokeexecuteonfunction"
        "app.evidence_storage_commit_full_verify_pre_posture_recovery("
        f"{signature})fromservice_role"
    ) in compact
    assert (
        "grantexecuteonfunctionapp.evidence_storage_commit_full_verify("
        f"{signature})toservice_role"
    ) in compact
    assert "/mcp" not in MIGRATION.lower()
    assert "mcp_tool" not in MIGRATION.lower()


def test_every_success_receipt_read_requires_the_exact_whole_active_set() -> None:
    assert SERVICE.count(
        "jsonb_array_length(v.item_facts)=(select count(*)"
    ) == 3
    assert SERVICE.count(
        "not exists(select 1 from jsonb_array_elements(v.item_facts)"
    ) == 2
    assert (
        "not exists(select 1\n"
        "                                       from jsonb_array_elements(v.item_facts) x"
    ) in SERVICE
