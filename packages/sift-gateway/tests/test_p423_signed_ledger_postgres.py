"""Live migrated-Postgres semantic contract for P4.23.6.

This intentionally runs only against the disposable migrated custody database.
It proves the migration is present before exercising the privilege/immutability
surface; unit tests cover cryptographic known-answer material separately.
"""

from __future__ import annotations

import os

import pytest


@pytest.mark.integration
def test_signed_ledger_migrated_postgres_semantics() -> None:
    dsn = os.environ.get("SIFT_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("SIFT_TEST_POSTGRES_DSN is required for migrated-Postgres proof")
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("select to_regclass('app.custody_signature_checkpoints')")
        assert cur.fetchone()[0] == "custody_signature_checkpoints"
        cur.execute("select to_regclass('app.custody_signing_key_rotations')")
        assert cur.fetchone()[0] == "custody_signing_key_rotations"
        cur.execute(
            """select pg_get_functiondef(p.oid) from pg_proc p
               join pg_namespace n on n.oid=p.pronamespace
               where n.nspname='app' and p.proname='evidence_verify_signed_ledger'"""
        )
        definition = cur.fetchone()[0]
        assert "canonical_material::text" in definition
        assert "CUSTODY_LEDGER_CHAIN_INVALID" in definition
        cur.execute(
            """select t.tgname from pg_trigger t
               join pg_class c on c.oid=t.tgrelid join pg_namespace n on n.oid=c.relnamespace
               where n.nspname='app' and c.relname='custody_signing_key_rotations'
                 and not t.tgisinternal"""
        )
        assert {row[0] for row in cur.fetchall()} >= {
            "custody_signing_key_rotations_append_only",
            "custody_signing_key_rotations_no_truncate",
        }
