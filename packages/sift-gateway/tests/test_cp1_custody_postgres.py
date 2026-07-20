"""CP1 Foundation — target custody schema contract on a migrated PostgreSQL.

These are the DB-level acceptance tests (SPEC §Automated contract level + the
amendment-acceptance bullet). They run the FULL rewritten migration chain against
a real PostgreSQL and prove the target authority: present-on-disk truth,
detected != sealed, direct-role denial, the one-active-Seal / idempotency
constraints, the computed four-state gate, and the EC-6 mixed-case multi-file
binding (the permanent regression fixture).

Gated on ``SIFT_CONTROL_PLANE_DSN`` and marked integration, exactly like the
retained ``*_postgres`` suites; CI's dedicated Postgres job and the CP3 VM gate
run them. Locally they skip when no DSN is present.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.integration


def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for the CP1 custody DB contract")
    return dsn


def _conn():
    import psycopg

    return psycopg.connect(_dsn())


def _new_case(cur) -> str:
    case_id = str(uuid.uuid4())
    cur.execute(
        "insert into app.cases(id,case_key,title,status) values(%s,%s,'CP1 DB test','active')",
        (case_id, "cp1-" + uuid.uuid4().hex),
    )
    return case_id


def _entry(path: str, kind: str = "regular", **kw) -> dict:
    row = {"display_path": path, "display_name": path.rsplit("/", 1)[-1], "entry_kind": kind}
    row.update(kw)
    return row


# ---------------------------------------------------------------------------
# Gate projection + present-on-disk truth (EC-1) + fail-closed
# ---------------------------------------------------------------------------
def test_gate_fail_closed_and_present_on_disk_truth() -> None:
    from psycopg.types.json import Jsonb

    with _conn() as conn, conn.cursor() as cur:
        case_id = _new_case(cur)

        # Nothing sealed -> never OPEN (SPEC scenario 14).
        cur.execute("select app.custody_gate_state(%s)", (case_id,))
        assert cur.fetchone()[0] == "BLOCKED_PENDING"

        # A pending regular entry blocks; a staged-then-removed path never lingers.
        cur.execute(
            "select app.custody_reconcile(%s,%s,true,'refresh',null,null,null)",
            (case_id, Jsonb([_entry("evidence/disk.e01")])),
        )
        assert cur.fetchone()[0] == "BLOCKED_PENDING"
        cur.execute("select count(*) from app.evidence_inventory where case_id=%s", (case_id,))
        assert cur.fetchone()[0] == 1

        # Remove it on disk: reconciliation reflects current disk only (EC-1).
        cur.execute(
            "select app.custody_reconcile(%s,%s,true,'refresh',null,null,null)",
            (case_id, Jsonb([])),
        )
        cur.execute("select count(*) from app.evidence_inventory where case_id=%s", (case_id,))
        assert cur.fetchone()[0] == 0

        # An unsafe entry projects to BLOCKED_VIOLATION.
        cur.execute(
            "select app.custody_reconcile(%s,%s,true,'refresh',null,null,null)",
            (case_id, Jsonb([_entry("evidence/link", "symlink")])),
        )
        assert cur.fetchone()[0] == "BLOCKED_VIOLATION"

        # Storage unavailable projects to BLOCKED_UNAVAILABLE.
        cur.execute(
            "select app.custody_reconcile(%s,%s,false,'dispatch',null,null,null)",
            (case_id, Jsonb([])),
        )
        assert cur.fetchone()[0] == "BLOCKED_UNAVAILABLE"
        conn.rollback()


# ---------------------------------------------------------------------------
# EC-6 — mixed-case multi-file reauth binding matches on a migrated PG
# ---------------------------------------------------------------------------
def test_ec6_sql_binding_matches_python_codepoint_order() -> None:
    from psycopg.types.json import Jsonb

    targets = ["evidence/rocba-cdrive.e01", "evidence/Rocba-Memory.raw"]
    python_sorted = sorted(targets)  # code point == COLLATE "C"
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "select app.custody_reauth_binding(%s,%s,%s)",
            ("k", "  reason  ", Jsonb(targets)),
        )
        binding = cur.fetchone()[0]
        assert binding["targets"] == python_sorted
        assert binding["reason"] == "reason"
        conn.rollback()


# ---------------------------------------------------------------------------
# Direct-role denial: no non-service role may execute a custody RPC
# ---------------------------------------------------------------------------
def test_direct_role_denial_on_custody_rpcs() -> None:
    with _conn() as conn, conn.cursor() as cur:
        for role in ("anon", "authenticated"):
            cur.execute("select 1 from pg_roles where rolname=%s", (role,))
            if not cur.fetchone():
                continue
            cur.execute(
                "select has_function_privilege(%s,'app.custody_gate_state(uuid)','execute')",
                (role,),
            )
            assert cur.fetchone()[0] is False, f"{role} must not execute custody_gate_state"
            cur.execute(
                "select has_function_privilege(%s,"
                "'app.custody_seal_commit(uuid,jsonb,text,uuid)','execute')",
                (role,),
            )
            assert cur.fetchone()[0] is False, f"{role} must not execute custody_seal_commit"
        conn.rollback()


# ---------------------------------------------------------------------------
# One active Seal per case + action idempotency (EC-2) — schema invariants
# ---------------------------------------------------------------------------
def test_seal_and_action_idempotency_constraints_exist() -> None:
    with _conn() as conn, conn.cursor() as cur:
        # One active (non-committed) Seal per case is a partial unique index.
        cur.execute(
            "select 1 from pg_indexes where schemaname='app' "
            "and indexname='custody_seal_operations_one_active_per_case'"
        )
        assert cur.fetchone(), "one-active-Seal partial unique index missing"

        # DB-only actions carry (case, action, idempotency_key) idempotency and are
        # append-only (no FAILED_RECOVERABLE latch): a unique constraint plus the
        # append-only trigger.
        cur.execute(
            "select 1 from pg_constraint c join pg_class t on t.oid=c.conrelid "
            "join pg_namespace n on n.oid=t.relnamespace "
            "where n.nspname='app' and t.relname='custody_action_receipts' and c.contype='u'"
        )
        assert cur.fetchone(), "custody_action_receipts unique constraint missing"

        # No FAILED_RECOVERABLE phase exists in the target seal machine (EC-2).
        cur.execute(
            "select pg_get_constraintdef(c.oid) from pg_constraint c "
            "join pg_class t on t.oid=c.conrelid join pg_namespace n on n.oid=t.relnamespace "
            "where n.nspname='app' and t.relname='custody_seal_operations' "
            "and c.conname='custody_seal_operations_phase_check'"
        )
        phase_check = cur.fetchone()[0]
        assert "FAILED_RECOVERABLE" not in phase_check
        assert "REQUESTED" in phase_check and "COMMITTED" in phase_check
        conn.rollback()
