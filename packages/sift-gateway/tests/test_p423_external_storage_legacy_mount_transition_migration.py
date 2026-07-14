import re
from pathlib import Path

MIGRATION = Path(
    "supabase/migrations/202607145875_external_storage_legacy_mount_transition.sql"
).read_text(encoding="utf-8")
NORMALIZED = "".join(MIGRATION.lower().split())


def _wrapper() -> str:
    return MIGRATION.split(
        "create function app.evidence_record_inventory_classification_v2(", 1
    )[1].split("end $$;", 1)[0]


def test_legacy_lane_keeps_three_mount_identities_distinct_and_blocked() -> None:
    wrapper = _wrapper()
    assert "pg_advisory_xact_lock(hashtextextended(p_case_id::text,0))" in wrapper
    assert "v_storage.profile='EXTERNALLY_READ_ONLY'" in wrapper
    assert "v_storage.state='FULL_VERIFY_REQUIRED'" in wrapper
    assert "v_storage.remediation='FULL_VERIFY'" in wrapper
    assert "v_storage.generation=v_storage.verified_generation" in wrapper
    assert "v_storage.observed_mount_instance<>v_storage.verified_mount_instance" in wrapper
    assert "v_storage.read_only is true" in wrapper
    assert "coalesce(ev.storage_mount_instance,'') !~ '^[0-9a-f]{64}$'" in wrapper
    assert (
        "ev.storage_mount_instance is distinct from v_storage.verified_mount_instance"
        not in wrapper
    )
    assert "p_gate_state='BLOCKED_UNAVAILABLE'" in wrapper
    assert "'code','STORAGE_FULL_VERIFY_REQUIRED'" in wrapper
    assert "'recovery','FULL_VERIFY_AND_REPAIR'" in wrapper
    assert "seal_status='violated'" in wrapper


def test_transition_requires_exact_complete_posture_cause_and_active_set() -> None:
    wrapper = _wrapper()
    for required in (
        "jsonb_array_length(v_prior_issues)=v_head.active_count",
        "'code','POSTURE_DRIFT'",
        "'gate_state','BLOCKED_VIOLATION'",
        "'recovery','RESTORE_READ_ONLY'",
        "'storage_generation',v_storage.generation",
        "count(distinct issue->>'evidence_object_id')",
        "o.status='violated' or o.seal_status='violated'",
        "o.status in ('detected','registered')",
        "ev.entry_status is distinct from 'ACTIVE'",
        "ev.storage_profile is distinct from 'EXTERNALLY_READ_ONLY'",
        "ev.storage_source_identity is distinct from v_storage.source_identity",
        "op.phase<>'COMPLETED'",
    ):
        assert required in wrapper


def test_transition_requires_current_success_receipt_and_exact_items() -> None:
    wrapper = _wrapper()
    for required in (
        "v.outcome='SUCCESS'",
        "v.generation=v_storage.generation",
        "v.profile=v_storage.profile",
        "v.source_identity is not distinct from v_storage.source_identity",
        "v.mount_instance is not distinct from v_storage.verified_mount_instance",
        "v.manifest_version=v_head.manifest_version",
        "v.manifest_hash=v_head.manifest_hash",
        "jsonb_array_length(v.item_facts)=v_head.active_count",
        "count(distinct x->>'evidence_object_id')",
        "x->>'evidence_version_id'=ev.id::text",
        "x->>'sha256'=ev.sha256",
        "x->>'bytes'=ev.bytes::text",
        "x->>'storage_source_identity'=v_storage.source_identity",
        "x->>'mount_instance_identity'=v_storage.verified_mount_instance",
        "x->'read_only'='true'::jsonb",
        "x->>'st_nlink'='1'",
    ):
        assert required in wrapper


def test_transition_appends_observation_and_updates_only_chain_head_projection() -> None:
    lane = _wrapper().split("if v_transition then", 1)[1].split(
        "select * into v_row\n  from app.evidence_record", 1
    )[0]
    assert "insert into app.evidence_inventory_observations" in lane
    assert "on conflict(case_id,correlation_id) do nothing" in lane
    assert "inventory_correlation_reused" in lane
    assert "update app.evidence_chain_heads" in lane
    assert "'storage_generation',v_storage.generation" in lane
    assert not re.search(
        r"\b(update|delete)\s+app\.(evidence_storage_authorities|evidence_objects|"
        r"evidence_versions|evidence_manifests|evidence_custody_events|"
        r"evidence_storage_verifications)\b",
        lane,
        flags=re.IGNORECASE,
    )


def test_every_other_state_delegates_and_predecessor_is_private() -> None:
    wrapper = _wrapper()
    delegate = (
        "app.evidence_record_inventory_classification_v2_"
        "pre_legacy_mount_transition("
    )
    assert delegate in wrapper
    assert wrapper.index("if v_transition then") < wrapper.index(delegate)
    signature = "uuid,text,text,jsonb"
    for roles in ("public,anon,authenticated", "service_role"):
        assert (
            "revokeexecuteonfunctionapp."
            "evidence_record_inventory_classification_v2_pre_legacy_mount_transition("
            f"{signature})from{roles};"
        ) in NORMALIZED
    assert (
        "grantexecuteonfunctionapp.evidence_record_inventory_classification_v2("
        f"{signature})toservice_role;"
    ) in NORMALIZED
    assert "mcp" not in MIGRATION.lower()
    assert "to authenticated" not in MIGRATION.lower()
