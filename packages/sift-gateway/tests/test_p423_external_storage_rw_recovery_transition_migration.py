import re
from pathlib import Path

MIGRATION = Path(
    "supabase/migrations/202607145850_external_storage_rw_recovery_transition.sql"
).read_text(encoding="utf-8")
NORMALIZED = "".join(MIGRATION.lower().split())


def _wrapper() -> str:
    return MIGRATION.split(
        "create function app.evidence_record_inventory_classification_v2(", 1
    )[1].split("end $$;", 1)[0]


def test_rw_recovery_is_exact_storage_generation_source_and_mount_bound() -> None:
    wrapper = _wrapper()
    assert "pg_advisory_xact_lock(hashtextextended(p_case_id::text,0))" in wrapper
    assert "v_head.seal_status='violated'" in wrapper
    assert "v_storage.profile='EXTERNALLY_READ_ONLY'" in wrapper
    assert "v_storage.generation=v_storage.verified_generation" in wrapper
    assert "v_storage.observed_mount_instance=v_storage.verified_mount_instance" in wrapper
    assert "ev.storage_profile is distinct from 'EXTERNALLY_READ_ONLY'" in wrapper
    assert "ev.storage_source_identity is distinct from v_storage.source_identity" in wrapper
    assert "ev.storage_mount_instance is distinct from v_storage.verified_mount_instance" in wrapper
    assert "o.status='violated' or o.seal_status='violated'" in wrapper
    assert "o.status in ('detected','registered')" in wrapper
    assert "op.phase<>'COMPLETED'" in wrapper


def test_only_exact_rw_repeat_and_ro_full_verify_transition_are_admitted() -> None:
    wrapper = _wrapper()
    for required in (
        "v_storage.state='READ_WRITE_DRIFT'",
        "v_storage.remediation='RESTORE_READ_ONLY'",
        "v_storage.read_only is false",
        "p_gate_state='BLOCKED_VIOLATION'",
        "'code','POSTURE_DRIFT'",
        "'recovery','RESTORE_READ_ONLY'",
        "v_storage.state='FULL_VERIFY_REQUIRED'",
        "v_storage.remediation='FULL_VERIFY'",
        "v_storage.read_only is true",
        "p_gate_state='BLOCKED_UNAVAILABLE'",
        "'code','STORAGE_FULL_VERIFY_REQUIRED'",
        "'recovery','FULL_VERIFY_AND_REPAIR'",
        "'storage_generation',v_storage.generation",
    ):
        assert required in wrapper
    assert "v_rw_repeat := true" in wrapper
    assert "v_ro_transition := true" in wrapper
    assert "v_ro_repeat := true" in wrapper


def test_transition_is_append_only_except_for_chain_head_projection() -> None:
    lane = _wrapper().split(
        "if v_rw_repeat or v_ro_transition or v_ro_repeat then", 1
    )[1].split("select * into v_row\n  from app.evidence_record", 1)[0]
    assert "insert into app.evidence_inventory_observations" in lane
    assert "on conflict(case_id,correlation_id) do nothing" in lane
    assert "inventory_correlation_reused" in lane
    assert "if v_ro_transition then" in lane
    assert "update app.evidence_chain_heads" in lane
    assert not re.search(
        r"\b(update|delete)\s+app\.(evidence_storage_authorities|evidence_objects|"
        r"evidence_versions|evidence_manifests|evidence_custody_events|"
        r"evidence_storage_verifications)\b",
        lane,
        flags=re.IGNORECASE,
    )


def test_every_noncausal_case_delegates_and_predecessor_is_private() -> None:
    wrapper = _wrapper()
    delegate = "app.evidence_record_inventory_classification_v2_pre_rw_transition("
    assert delegate in wrapper
    assert wrapper.index(
        "if v_rw_repeat or v_ro_transition or v_ro_repeat then"
    ) < wrapper.index(delegate)
    signature = "uuid,text,text,jsonb"
    for roles in ("public,anon,authenticated", "service_role"):
        assert (
            "revokeexecuteonfunctionapp."
            "evidence_record_inventory_classification_v2_pre_rw_transition("
            f"{signature})from{roles};"
        ) in NORMALIZED
    assert (
        "grantexecuteonfunctionapp.evidence_record_inventory_classification_v2("
        f"{signature})toservice_role;"
    ) in NORMALIZED
    assert "mcp" not in MIGRATION.lower()
    assert "to authenticated" not in MIGRATION.lower()
