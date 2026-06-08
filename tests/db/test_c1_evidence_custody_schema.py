from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "supabase" / "migrations" / "202606081000_evidence_custody.sql"


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def _normalized_sql() -> str:
    return re.sub(r"\s+", " ", _sql().lower())


def _table_block(table: str) -> str:
    match = re.search(
        rf"create table if not exists app\.{table}\s*\((.*?)\n\);",
        _sql(),
        re.IGNORECASE | re.DOTALL,
    )
    assert match, f"missing create table block for app.{table}"
    return match.group(1).lower()


def _column_names(table: str) -> set[str]:
    names: set[str] = set()
    for line in _table_block(table).splitlines():
        line = line.strip().rstrip(",")
        if not line or line.startswith(("constraint ", "--")):
            continue
        names.add(line.split()[0])
    return names


# ---------------------------------------------------------------------------
# Tables represent the full evidence lifecycle
# ---------------------------------------------------------------------------

def test_all_evidence_tables_present() -> None:
    sql = _normalized_sql()
    for table in (
        "evidence_objects",
        "evidence_versions",
        "evidence_custody_events",
        "evidence_chain_heads",
        "evidence_proof_exports",
    ):
        assert f"create table if not exists app.{table}" in sql


def test_evidence_objects_lifecycle_states() -> None:
    block = _table_block("evidence_objects")
    columns = _column_names("evidence_objects")
    assert {
        "id",
        "case_id",
        "display_name",
        "display_path",
        "description",
        "status",
        "seal_status",
        "current_version_id",
        "current_sha256",
    } <= columns
    # detected / registered / sealed / ignored / retired / violated
    for state in ("detected", "registered", "sealed", "ignored", "retired", "violated"):
        assert f"'{state}'" in block
    assert "seal_status in ('unsealed', 'sealed', 'violated')" in block


def test_display_path_is_relative_only_no_absolute_paths() -> None:
    block = _table_block("evidence_objects")
    # Reject absolute/traversal/drive-letter paths so no absolute OS/mount path
    # is ever persisted as evidence display metadata.
    assert "evidence_objects_display_path_relative_check" in block
    assert "left(display_path, 1) <> '/'" in block
    assert "\\.\\." in block or "\\.\\.(" in block


def test_no_absolute_path_or_mount_columns() -> None:
    columns = _column_names("evidence_objects")
    for forbidden in ("abs_path", "absolute_path", "mount_path", "case_dir", "local_path"):
        assert forbidden not in columns


# ---------------------------------------------------------------------------
# Custody ledger is append-only and hash-linked
# ---------------------------------------------------------------------------

def test_custody_events_hash_chain_columns() -> None:
    columns = _column_names("evidence_custody_events")
    assert {"seq", "event_type", "prev_hash", "event_hash", "reauth_audit_event_id"} <= columns


def test_custody_event_types_cover_transitions() -> None:
    block = _table_block("evidence_custody_events")
    for ev in (
        "EVIDENCE_DETECTED",
        "EVIDENCE_REGISTERED",
        "MANIFEST_SEALED",
        "CHAIN_VERIFIED",
        "FILE_IGNORED",
        "FILE_RETIRED",
        "CHAIN_VIOLATION",
    ):
        assert ev.lower() in block


def test_custody_and_versions_are_append_only() -> None:
    sql = _normalized_sql()
    assert "create or replace function app.evidence_block_mutation()" in sql
    assert "before update or delete on app.evidence_custody_events" in sql
    assert "before update or delete on app.evidence_versions" in sql


def test_per_case_seq_is_unique() -> None:
    sql = _normalized_sql()
    assert "evidence_custody_events_case_seq_key" in sql
    assert "on app.evidence_custody_events (case_id, seq)" in sql


# ---------------------------------------------------------------------------
# Transition RPCs exist and are service-only / re-auth gated
# ---------------------------------------------------------------------------

def test_all_transition_rpcs_present() -> None:
    sql = _normalized_sql()
    for fn in (
        "app.evidence_detect(",
        "app.evidence_register(",
        "app.evidence_seal(",
        "app.evidence_verify(",
        "app.evidence_ignore(",
        "app.evidence_retire(",
        "app.evidence_mark_violation(",
        "app.evidence_gate_status(",
        "app.evidence_record_proof_export(",
    ):
        assert f"create or replace function {fn}" in sql


def test_transition_rpcs_are_security_definer() -> None:
    sql = _sql()
    # Every transition function declares security definer with pinned search_path.
    assert sql.lower().count("security definer") >= 9
    assert "set search_path = app, public" in sql.lower()


def test_seal_ignore_retire_require_reauth() -> None:
    sql = _normalized_sql()
    assert "seal_requires_reauth" in sql
    assert "ignore_requires_reauth" in sql
    assert "retire_requires_reauth" in sql
    assert "p_reauth_audit_event_id is null" in sql


def test_gate_status_is_fail_closed() -> None:
    sql = _normalized_sql()
    # Missing head row coalesces to unsealed (blocked).
    assert "coalesce(h.seal_status, 'unsealed')" in sql


def test_custody_hash_uses_builtin_sha256_not_pgcrypto_digest() -> None:
    sql = _normalized_sql()
    assert "encode(sha256(v_payload::bytea), 'hex')" in sql
    assert "digest(v_payload" not in sql


# ---------------------------------------------------------------------------
# RLS, grants, and proof-as-export posture
# ---------------------------------------------------------------------------

def test_rls_enabled_on_all_new_tables() -> None:
    sql = _normalized_sql()
    for table in (
        "evidence_objects",
        "evidence_versions",
        "evidence_custody_events",
        "evidence_chain_heads",
        "evidence_proof_exports",
    ):
        assert f"alter table app.{table} enable row level security" in sql


def test_execute_granted_to_service_role_only() -> None:
    sql = _normalized_sql()
    assert "grant execute on function app.evidence_seal" in sql
    assert "to service_role" in sql
    # No broad grant to anon/authenticated (check for an actual grant statement,
    # not the explanatory comment that mentions those roles).
    assert "grant execute on function" in sql
    assert not re.search(r"grant\s+execute\s+on\s+function[^;]*to\s+authenticated", sql)
    assert not re.search(r"grant\s+execute\s+on\s+function[^;]*to\s+anon\b", sql)


def test_proof_export_is_metadata_not_authority() -> None:
    block = _table_block("evidence_proof_exports")
    columns = _column_names("evidence_proof_exports")
    assert {"manifest_version", "export_kind", "verified", "manifest_hash"} <= columns
    # No raw bytes / file blobs stored as authority.
    for forbidden in ("bytes_blob", "file_bytes", "raw_bytes", "content"):
        assert forbidden not in columns
    assert "exports are artifacts" in _normalized_sql()
    _ = block


def test_no_raw_secrets_or_data_fixtures() -> None:
    sql = _normalized_sql()
    for term in ("service_role_key", "anon_key", "jwt_secret", "raw_token", "plaintext", "insert into app.cases"):
        assert term not in sql
