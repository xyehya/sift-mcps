"""Live migrated-Postgres semantic contract for P4.23.6.

This intentionally runs only against the disposable migrated custody database.
It proves the migration is present before exercising the privilege/immutability
surface; unit tests cover cryptographic known-answer material separately.
"""

from __future__ import annotations

import os
import uuid

import pytest


def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for migrated-Postgres proof")
    return dsn


def _admin_dsn() -> str:
    dsn = os.environ.get("SIFT_CUSTODY_TEST_ADMIN_DSN", "").strip()
    if not dsn:
        pytest.skip(
            "SIFT_CUSTODY_TEST_ADMIN_DSN is required for canonical-tamper proof"
        )
    return dsn


@pytest.mark.integration
def test_signed_ledger_migrated_postgres_semantics() -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        cur.execute("select to_regclass('app.custody_signature_checkpoints')")
        assert cur.fetchone()[0] == "app.custody_signature_checkpoints"
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
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
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


@pytest.mark.integration
def test_signed_ledger_latch_finalizer_and_canonical_tamper_detection() -> None:
    """Prove the database-enforced signing lifecycle and tamper detection.

    The test owns every fixture row and always rolls the transaction back.  The
    admin-only DSN is deliberate: a canonical-material change must bypass the
    append-only trigger in order to prove that the verifier detects a forged
    stored row rather than merely relying on mutation prevention.
    """
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    case_id, actor_id, audit_id, operation_id = (uuid.uuid4() for _ in range(4))
    key_id = "ed25519:sha256:" + uuid.uuid4().hex + uuid.uuid4().hex

    with psycopg.connect(_admin_dsn()) as conn:
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "insert into app.operator_profiles(id,display_name,status) "
                    "values(%s,'P423 ledger test operator','active')",
                    (actor_id,),
                )
                cur.execute(
                    "insert into app.cases(id,case_key,title,status) values(%s,%s,'P423 ledger test','active')",
                    (case_id, "p423-ledger-" + uuid.uuid4().hex),
                )
                cur.execute(
                    """insert into app.audit_events
                       (id,case_id,event_type,actor_type,actor_user_id,source,status,details)
                       values(%s,%s,'reauth.evidence_seal','user',%s,'portal_reauth','success',%s)""",
                    (
                        audit_id,
                        case_id,
                        actor_id,
                        Jsonb({"binding": {"idempotency_key": "ledger-test"}}),
                    ),
                )
                cur.execute("insert into app.evidence_chain_heads(case_id) values(%s)", (case_id,))
                cur.execute(
                    """insert into app.custody_operations(
                         id,case_id,action,phase,idempotency_key,request_digest,command,reason,
                         reauth_audit_event_id,actor_user_id,runner_instance_id
                       ) values(%s,%s,'ADD_SEAL','GATE_BLOCKED',%s,%s,%s,'ledger lifecycle test',%s,%s,'ledger-test')""",
                    (
                        operation_id,
                        case_id,
                        "ledger-" + uuid.uuid4().hex,
                        "sha256:" + "1" * 64,
                        Jsonb({"schema_version": 1, "action": "ADD_SEAL", "files": []}),
                        audit_id,
                        actor_id,
                    ),
                )

                # This produces a canonical_event_v1 row and advances the fresh
                # case head.  The checkpoint latch must bind exactly that head.
                cur.execute(
                    """select app.evidence_append_canonical_event_v1(
                         %s,null,'MANIFEST_SEALED',0,null,%s,%s,%s
                       )""",
                    (operation_id, Jsonb({}), Jsonb({}), Jsonb({"fixture": "signed-ledger"})),
                )
                event_id = cur.fetchone()[0]
                cur.execute(
                    "update app.custody_operations set phase='LEDGER_COMMITTED' where id=%s",
                    (operation_id,),
                )
                cur.execute(
                    """select state,ledger_tip_hash,canonical_payload->>'operation_id'
                       from app.custody_signature_checkpoints where custody_operation_id=%s""",
                    (operation_id,),
                )
                checkpoint = cur.fetchone()
                assert checkpoint is not None
                assert checkpoint[0] == "PENDING_SIGNATURE"
                cur.execute("select head_hash from app.evidence_chain_heads where case_id=%s", (case_id,))
                assert checkpoint[1] == cur.fetchone()[0]
                assert checkpoint[2] == str(operation_id)

                # The legacy direct completion edge must be latched, not accepted.
                cur.execute(
                    "update app.custody_operations set phase='COMPLETED' where id=%s",
                    (operation_id,),
                )
                cur.execute("select phase,completed_at from app.custody_operations where id=%s", (operation_id,))
                assert cur.fetchone() == ("PENDING_SIGNATURE", None)

                cur.execute(
                    "insert into app.custody_signing_keys(key_id,algorithm,public_key) values(%s,'Ed25519',%s)",
                    (key_id, "A" * 44),
                )
                cur.execute(
                    "select (app.custody_signature_finalize(%s,%s,%s)).phase",
                    (operation_id, key_id, "A" * 86 + "=="),
                )
                assert cur.fetchone()[0] == "COMPLETED"
                cur.execute(
                    """select state,key_id,signature is not null,signed_at is not null
                       from app.custody_signature_checkpoints where custody_operation_id=%s""",
                    (operation_id,),
                )
                assert cur.fetchone() == ("SIGNED", key_id, True, True)

                cur.execute("select valid,issue_code from app.evidence_verify_signed_ledger(%s)", (case_id,))
                assert cur.fetchone() == (True, None)

                # Deliberately forge canonical material while retaining the old
                # hash/head.  Trigger bypass is confined to this rolled-back
                # admin transaction and demonstrates verifier, not ACL, defense.
                cur.execute("set local session_replication_role=replica")
                cur.execute(
                    """update app.evidence_custody_events
                       set canonical_material=jsonb_set(canonical_material,'{reason}',to_jsonb('tampered'::text))
                       where id=%s""",
                    (event_id,),
                )
                cur.execute("set local session_replication_role=origin")
                cur.execute("select valid,issue_code from app.evidence_verify_signed_ledger(%s)", (case_id,))
                assert cur.fetchone() == (False, "CUSTODY_LEDGER_CHAIN_INVALID")
        finally:
            conn.rollback()
