"""Fail-on-revert contract for P4.23.6 signed-ledger database controls."""

from pathlib import Path

MIGRATION = Path(__file__).parents[2] / "supabase/migrations/202607145900_signed_custody_ledger.sql"


def test_signed_ledger_migration_has_service_only_latch_and_append_only_checkpoint():
    sql = MIGRATION.read_text()
    assert "custody_signature_checkpoints" in sql
    assert "PENDING_SIGNATURE" in sql
    assert "custody_operations_phase_check" in sql
    assert "custody_signature_finalize" in sql
    assert "app.custody_signature_finalizer" in sql
    assert "custody_signature_checkpoint_append_only" in sql
    assert "custody_signature_history_latch" in sql
    assert "Ed25519" in sql
    assert "grant execute on function app.custody_signature_finalize" in sql


def test_signed_ledger_migration_rejects_private_material_columns():
    sql = MIGRATION.read_text()
    assert "private_key" in sql  # forbidden-key checks, not a stored key column
    assert "not (canonical_payload ?&" in sql
