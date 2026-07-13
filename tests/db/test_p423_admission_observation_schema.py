from pathlib import Path

MIGRATION = (
    Path(__file__).parents[2]
    / "supabase/migrations/202607131900_evidence_admission_observation.sql"
)


def test_admission_observation_rpc_is_append_only_correlated_and_compatibly_scoped():
    sql = MIGRATION.read_text(encoding="utf-8").lower()
    assert "create or replace function app.evidence_observe_admission(" in sql
    assert "p_correlation_id text default null" in sql
    assert "'correlation_id', v_correlation_id" in sql
    assert "app.evidence_append_custody_event(" in sql
    assert "'evidence_detected'" in sql
    assert "security definer" in sql
    assert "set search_path = app, public" in sql
    assert "revoke all on function app.evidence_observe_admission(" in sql
    assert "grant execute on function app.evidence_observe_admission(" in sql
    assert "to service_role" in sql
    assert "create or replace function app.evidence_detect(" not in sql
    assert "reauth_audit_event_id" not in sql
