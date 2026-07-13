import re
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
    assert "custody_operation_completion_reauth_history" in body
    assert "recovery_completion_receipt_already_used" in body
    assert "recovery_completion_already_completed" in body


def test_completion_receipt_rotates_only_from_authorized_recoverable_phases():
    body = SQL.split(
        "create function app.custody_operation_authorize_recovery_completion(", 1
    )[1]
    assert "v_op.phase='FAILED_RECOVERABLE'" in body
    assert "v_op.failed_from_phase in ('FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED')" in body
    assert "v_op.completion_reauth_audit_event_id is not null and not v_rotating" in body
    assert "failed_from_phase=null" in body
    assert "'previous_completion_reauth_audit_event_id',v_previous_receipt" in body
    assert "runner_instance_id is null or runner_instance_id=p_runner_instance_id" in body


def test_completion_receipt_history_is_force_rls_append_only_and_ungranted():
    assert "completion_reauth_history enable row level security" in SQL
    assert "completion_reauth_history force row level security" in SQL
    assert "completion_reauth_history_no_update_delete" in SQL
    assert "execute function app.evidence_block_mutation()" in SQL
    assert "completion_reauth_history_no_truncate" in SQL
    assert "execute function app.evidence_block_truncate()" in SQL
    assert "revoke all on table app.custody_operation_completion_reauth_history" in SQL


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


def test_current_docs_do_not_restore_removed_unseal_or_one_shot_reacquire_contracts():
    current_docs = [
        Path("packages/case-dashboard/frontend/AGENTS.md"),
        Path("packages/case-dashboard/frontend/CLAUDE.md"),
        Path("packages/case-dashboard/frontend/design-system/MASTER.md"),
        Path("packages/case-dashboard/frontend/design-system/COVERAGE.md"),
        Path("docs/latest/00 - Architecture Overview.md"),
        Path("docs/latest/06 - Portal.md"),
        Path("docs/latest/09 - API Contract.md"),
        Path("docs/latest/11 - Authentication for API and MCP.md"),
        Path("docs/new-docs/PORTAL_V3_REBUILD_SPEC.md"),
        Path("docs/new-docs/PORTAL_V3_CLAUDE_DESIGN_BRIEF.md"),
        Path("docs/new-docs/SYSTEM_OVERVIEW.md"),
        Path("docs/new-docs/DEVELOPER_ENTRYPOINT.md"),
        Path("docs/examples/01 - Monorepo entrypoints and package manifests.md"),
        Path("docs/examples/03 - Contributor automation and AI-agent guidance.md"),
        Path("docs/examples/07 - Dashboard backend, auth, and static delivery.md"),
    ]
    combined = "\n".join(path.read_text() for path in current_docs)
    assert "EvidenceUnseal.test" not in combined
    assert "/api/evidence/chain/unseal" not in combined
    assert "/api/evidence/chain/reacquire" not in combined
    for stale_phrase in (
        "seal/unseal evidence",
        "unseal requires re-auth",
        "evidence list/unseal/seal",
        "evidence seal/unseal/re-acquisition",
        "evidence seal and unseal",
        "unseal windows",
    ):
        assert stale_phrase not in combined
    assert not re.search(
        r"(?:index|EvidenceTab|BackendsTab|OverviewTab|ReportsTab|AccountsTab|"
        r"EntityBadges|EntityShell|FilterBar|FindingsTab|HostsTab|IocsTab|"
        r"SettingsTab|TimelineTab|TodosTab)-[A-Za-z0-9_-]+\.(?:js|css)",
        combined,
    )
