import re
from pathlib import Path

MIGRATION = Path(
    "supabase/migrations/202607145800_external_storage_reconnect_transition.sql"
).read_text(encoding="utf-8")
NORMALIZED = "".join(MIGRATION.lower().split())


def _wrapper() -> str:
    return MIGRATION.split(
        "create function app.evidence_record_inventory_classification_v2(", 1
    )[1].split("end $$;", 1)[0]


def test_reconnect_lane_is_exact_source_generation_and_read_only_bound() -> None:
    wrapper = _wrapper()
    assert "pg_advisory_xact_lock(hashtextextended(p_case_id::text,0))" in wrapper
    assert "v_head.seal_status='violated'" in wrapper
    assert "v_storage.profile='EXTERNALLY_READ_ONLY'" in wrapper
    assert "v_storage.state='FULL_VERIFY_REQUIRED'" in wrapper
    assert "v_storage.remediation='FULL_VERIFY'" in wrapper
    assert "v_storage.generation=v_storage.verified_generation" in wrapper
    assert "coalesce(v_storage.source_identity,'') ~ '^[0-9a-f]{64}$'" in wrapper
    assert "coalesce(v_storage.verified_mount_instance,'') ~ '^[0-9a-f]{64}$'" in wrapper
    assert "coalesce(v_storage.observed_mount_instance,'') ~ '^[0-9a-f]{64}$'" in wrapper
    assert "v_storage.read_only is true" in wrapper
    assert "p_gate_state='BLOCKED_UNAVAILABLE'" in wrapper
    assert "'code','STORAGE_FULL_VERIFY_REQUIRED'" in wrapper
    assert "'recovery','FULL_VERIFY_AND_REPAIR'" in wrapper


def test_only_exact_prior_unavailable_cause_can_advance() -> None:
    wrapper = _wrapper()
    assert "jsonb_array_length(coalesce(v_head.issues,'[]'::jsonb))=1" in wrapper
    assert "issue->>'code'<>'STORAGE_UNAVAILABLE'" in wrapper
    assert "issue->>'recovery'<>'RECONNECT_AND_VERIFY'" in wrapper
    assert "issue->'evidence_object_id'<>'null'::jsonb" in wrapper
    assert "issue->'observation_id'<>'null'::jsonb" in wrapper
    assert "issue->'full_verification_required'<>'false'::jsonb" in wrapper
    assert "(issue->>'storage_generation')::numeric<>v_storage.generation" in wrapper
    assert "o.status='violated' or o.seal_status='violated'" in wrapper
    assert "o.seal_status is distinct from 'sealed'" in wrapper
    assert "o.status in ('detected','registered')" in wrapper
    assert "ev.storage_profile is distinct from 'EXTERNALLY_READ_ONLY'" in wrapper
    assert "ev.storage_source_identity is distinct from v_storage.source_identity" in wrapper
    assert "op.phase<>'COMPLETED'" in wrapper
    for forbidden in (
        "CONTENT_CHANGED",
        "SEALED_EVIDENCE_MISSING",
        "IDENTITY_CHANGED",
        "STORAGE_SOURCE_CHANGED",
        "READ_WRITE_DRIFT",
        "LEDGER_INVALID",
    ):
        assert forbidden not in wrapper


def test_reconnect_appends_observation_and_only_updates_chain_head_projection() -> None:
    lane = _wrapper().split("if v_transition or v_repeat then", 1)[1].split(
        "select * into v_row\n  from app.evidence_record", 1
    )[0]
    assert "insert into app.evidence_inventory_observations" in lane
    assert "on conflict(case_id,correlation_id) do nothing" in lane
    assert "inventory_correlation_reused" in lane
    assert "update app.evidence_chain_heads" in lane
    assert "if v_transition then" in lane
    assert "'storage_generation',v_storage.generation" in lane
    assert not re.search(
        r"\b(update|delete)\s+app\.(evidence_storage_authorities|evidence_objects|"
        r"evidence_versions|evidence_manifests|evidence_custody_events|"
        r"evidence_storage_verifications)\b",
        lane,
        flags=re.IGNORECASE,
    )


def test_every_noncausal_transition_delegates_and_predecessor_is_private() -> None:
    wrapper = _wrapper()
    delegate = (
        "app.evidence_record_inventory_classification_v2_"
        "pre_reconnect_transition("
    )
    assert delegate in wrapper
    assert "v_repeat := true" in wrapper
    assert wrapper.index("if v_transition or v_repeat then") < wrapper.index(delegate)
    signature = "uuid,text,text,jsonb"
    for roles in ("public,anon,authenticated", "service_role"):
        assert (
            "revokeexecuteonfunctionapp."
            "evidence_record_inventory_classification_v2_pre_reconnect_transition("
            f"{signature})from{roles};"
        ) in NORMALIZED
    assert (
        "grantexecuteonfunctionapp.evidence_record_inventory_classification_v2("
        f"{signature})toservice_role;"
    ) in NORMALIZED
    assert "mcp" not in MIGRATION.lower()
    assert "to authenticated" not in MIGRATION.lower()
