from pathlib import Path

MIGRATION = Path(
    "supabase/migrations/202607145880_external_storage_legacy_replay_scope.sql"
).read_text(encoding="utf-8")
NORMALIZED = "".join(MIGRATION.lower().split())


def _wrapper() -> str:
    return MIGRATION.split(
        "create function app.evidence_record_inventory_classification_v2(", 1
    )[1].split("end $$;", 1)[0]


def test_new_rows_retain_145875_transition_while_existing_rows_are_scoped() -> None:
    wrapper = _wrapper()
    assert "pg_advisory_xact_lock(hashtextextended(p_case_id::text,0))" in wrapper
    head_lock = "select * into v_head from app.evidence_chain_heads"
    storage_lock = "select * into v_storage from app.evidence_storage_authorities"
    existing_read = "select * into v_row from app.evidence_inventory_observations"
    assert wrapper.index(head_lock) < wrapper.index(existing_read)
    assert wrapper.index(storage_lock) < wrapper.index(existing_read)
    assert (
        "app.evidence_record_inventory_classification_v2_"
        "pre_legacy_replay_scope(" in wrapper
    )
    assert wrapper.index("if not found then") < wrapper.index(
        "pre_legacy_replay_scope("
    )


def test_legacy_candidate_requires_exact_receipt_and_safe_active_set() -> None:
    wrapper = _wrapper()
    for required in (
        "v_row.gate_state='BLOCKED_UNAVAILABLE'",
        "v_row.findings=jsonb_build_array(v_expected_finding)",
        "v_storage.profile='EXTERNALLY_READ_ONLY'",
        "v_storage.generation=v_storage.verified_generation",
        "v_storage.observed_mount_instance<>v_storage.verified_mount_instance",
        "v_storage.read_only is true",
        "o.status='violated' or o.seal_status='violated'",
        "o.status in ('detected','registered')",
        "op.phase<>'COMPLETED'",
        "v.outcome='SUCCESS'",
        "v.source_identity is not distinct from v_storage.source_identity",
        "v.mount_instance is not distinct from v_storage.verified_mount_instance",
        "v.manifest_version=v_head.manifest_version",
        "v.manifest_hash=v_head.manifest_hash",
        "jsonb_array_length(v.item_facts)=v_head.active_count",
        "x->>'evidence_version_id'=ev.id::text",
        "x->>'sha256'=ev.sha256",
        "x->>'bytes'=ev.bytes::text",
        "x->>'mount_instance_identity'=v_storage.verified_mount_instance",
        "x->'read_only'='true'::jsonb",
        "x->>'st_nlink'='1'",
    ):
        assert required in wrapper


def test_legacy_replay_requires_exact_current_head_and_storage_state() -> None:
    wrapper = _wrapper()
    candidate = wrapper.split("if v_candidate then", 1)[1].split(
        "-- This existing observation is not", 1
    )[0]
    assert "v_row.gate_state is distinct from p_gate_state" in candidate
    assert "v_row.findings is distinct from p_findings" in candidate
    assert "v_head.seal_status='violated'" in candidate
    assert "v_storage.state='FULL_VERIFY_REQUIRED'" in candidate
    assert "v_storage.remediation='FULL_VERIFY'" in candidate
    assert "v_storage.read_only is true" in candidate
    assert "coalesce(v_head.issues,'[]'::jsonb)=jsonb_build_array(" in candidate
    assert candidate.count("inventory_correlation_reused") == 2
    assert "if v_repeat then\n      return v_row;" in candidate


def test_nonlegacy_existing_rows_bypass_145875_to_predecessor_chain() -> None:
    wrapper = _wrapper()
    legacy_impl = (
        "app.evidence_record_inventory_classification_v2_"
        "pre_legacy_replay_scope("
    )
    predecessor = (
        "app.evidence_record_inventory_classification_v2_"
        "pre_legacy_mount_transition("
    )
    assert legacy_impl in wrapper
    assert predecessor in wrapper
    assert wrapper.index("if v_candidate then") < wrapper.index(predecessor)
    assert wrapper.index(legacy_impl) < wrapper.index(predecessor)


def test_helpers_are_private_and_only_public_wrapper_is_service_granted() -> None:
    signature = "uuid,text,text,jsonb"
    for helper in (
        "pre_legacy_replay_scope",
        "pre_legacy_mount_transition",
    ):
        for roles in ("public,anon,authenticated", "service_role"):
            assert (
                "revokeexecuteonfunctionapp."
                "evidence_record_inventory_classification_v2_"
                f"{helper}({signature})from{roles};"
            ) in NORMALIZED
    assert (
        "grantexecuteonfunctionapp.evidence_record_inventory_classification_v2("
        f"{signature})toservice_role;"
    ) in NORMALIZED
    assert "mcp" not in MIGRATION.lower()
    assert "to authenticated" not in MIGRATION.lower()
