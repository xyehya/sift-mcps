"""Live migrated-Postgres semantic contract for P4.23.6.

This intentionally runs only against the disposable migrated custody database.
It proves the migration is present before exercising the privilege/immutability
surface; unit tests cover cryptographic known-answer material separately.
"""

from __future__ import annotations

import os
import uuid

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


@pytest.mark.integration
def test_signed_ledger_rotation_is_immutable() -> None:
    """Execute the rotation append-only rejection in a rollback transaction."""
    dsn = os.environ.get("SIFT_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("SIFT_TEST_POSTGRES_DSN is required for migrated-Postgres proof")
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("select id from app.operator_profiles limit 1")
        actor = cur.fetchone()
        cur.execute("select id from app.audit_events limit 1")
        audit = cur.fetchone()
        if not actor or not audit:
            pytest.skip("live DB has no operator/audit fixture for isolated rotation proof")
        new_key = "ed25519:sha256:" + uuid.uuid4().hex + uuid.uuid4().hex
        cur.execute(
            "insert into app.custody_signing_keys(key_id,algorithm,public_key) values(%s,'Ed25519',%s)",
            (new_key, "A" * 44),
        )
        cur.execute(
            """insert into app.custody_signing_key_rotations(new_key_id,reason,reauth_audit_event_id,actor_user_id)
               values(%s,'test rotation',%s,%s) returning id""",
            (new_key, audit[0], actor[0]),
        )
        rotation = cur.fetchone()[0]
        with pytest.raises(psycopg.Error):
            cur.execute("update app.custody_signing_key_rotations set reason='changed' where id=%s", (rotation,))
        conn.rollback()
    # The rollback is the cleanup proof: no live test authority rows persist.
