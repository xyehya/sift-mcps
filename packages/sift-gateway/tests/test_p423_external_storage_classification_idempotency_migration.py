import re
from pathlib import Path

MIGRATION = Path(
    "supabase/migrations/202607145700_external_storage_classification_idempotency.sql"
).read_text(encoding="utf-8")
NORMALIZED = "".join(MIGRATION.lower().split())


def _wrapper() -> str:
    return MIGRATION.split(
        "create function app.evidence_record_inventory_classification_v2(", 1
    )[1].split("end $$;", 1)[0]


def test_repeated_unavailable_projection_is_exact_and_generation_bound() -> None:
    wrapper = _wrapper()
    assert "pg_advisory_xact_lock(hashtextextended(p_case_id::text,0))" in wrapper
    assert "v_head.seal_status='violated'" in wrapper
    assert "v_storage.profile='EXTERNALLY_READ_ONLY'" in wrapper
    assert "v_storage.state='UNAVAILABLE'" in wrapper
    assert "v_storage.remediation='RECONNECT_AND_VERIFY'" in wrapper
    assert "v_storage.generation=v_storage.verified_generation" in wrapper
    assert "p_gate_state='BLOCKED_UNAVAILABLE'" in wrapper
    assert "p_findings=jsonb_build_array(jsonb_build_object(" in wrapper
    assert "issue - 'storage_generation'" in wrapper
    assert "coalesce(issue->>'storage_generation','') ~ '^[0-9]+$'" in wrapper
    assert "(issue->>'storage_generation')::numeric<>v_storage.generation" in wrapper
    assert "issue->>'code'<>'STORAGE_UNAVAILABLE'" in wrapper
    for excluded in (
        "MOUNT_IDENTITY_CHANGED",
        "STORAGE_SOURCE_CHANGED",
        "STORAGE_FULL_VERIFY_REQUIRED",
        "POSTURE_DRIFT",
    ):
        assert excluded not in wrapper


def test_object_and_nonstorage_violations_delegate_to_causal_guard() -> None:
    wrapper = _wrapper()
    assert "o.status='violated' or o.seal_status='violated'" in wrapper
    assert "jsonb_array_length(coalesce(v_head.issues,'[]'::jsonb))=1" in wrapper
    assert "issue->>'code'<>'STORAGE_UNAVAILABLE'" in wrapper
    assert "PERSISTED_VIOLATION" not in wrapper
    delegate = (
        "app.evidence_record_inventory_classification_v2_"
        "pre_storage_repeat_idempotency("
    )
    assert delegate in wrapper
    assert wrapper.index("if v_repeat then") < wrapper.index(delegate)


def test_repeat_appends_exact_observation_without_rewriting_authority() -> None:
    repeat = (
        _wrapper()
        .split("if v_repeat then", 1)[1]
        .split("select * into v_row\n  from app.evidence_record", 1)[0]
    )
    assert "insert into app.evidence_inventory_observations" in repeat
    assert "on conflict(case_id,correlation_id) do nothing" in repeat
    assert "inventory_correlation_reused" in repeat
    assert not re.search(r"\b(update|delete)\s+app\.", repeat, flags=re.IGNORECASE)


def test_predecessor_is_not_runtime_reachable_and_no_agent_surface_is_added() -> None:
    signature = "uuid,text,text,jsonb"
    for roles in ("public,anon,authenticated", "service_role"):
        assert (
            "revokeexecuteonfunctionapp."
            "evidence_record_inventory_classification_v2_"
            "pre_storage_repeat_idempotency("
            f"{signature})from{roles};"
        ) in NORMALIZED
    assert (
        "revokeexecuteonfunctionapp.evidence_record_inventory_classification_v2("
        f"{signature})frompublic,anon,authenticated;"
    ) in NORMALIZED
    assert (
        "grantexecuteonfunctionapp.evidence_record_inventory_classification_v2("
        f"{signature})toservice_role;"
    ) in NORMALIZED
    assert "mcp" not in MIGRATION.lower()
    assert "to authenticated" not in MIGRATION.lower()
