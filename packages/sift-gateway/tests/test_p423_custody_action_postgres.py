from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.integration


def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for migrated-Postgres custody proof")
    return dsn


def _setup_action(conn, *, action: str = "RETIRE", binding_action: str | None = None):
    from psycopg.types.json import Jsonb

    case_id, actor_id, audit_id, object_id = (uuid.uuid4() for _ in range(4))
    key = "action-" + uuid.uuid4().hex
    reason = "database action contract test"
    command = {
        "schema_version": 2,
        "action": action,
        "evidence_object_id": str(object_id),
    }
    binding = {
        "action": binding_action if binding_action is not None else action,
        "evidence_object_id": str(object_id),
        "idempotency_key": key,
        "reason": reason,
    }
    event_type = {
        "REPLACE_REACQUIRE": "reauth.evidence_replace_begin",
        "RESTORE_EXACT": "reauth.evidence_restore",
        "IGNORE": "reauth.evidence_ignore",
        "DELETE_STRAY": "reauth.evidence_delete",
        "RETIRE": "reauth.evidence_retire",
    }.get(action, "reauth.evidence_retire")
    with conn.cursor() as cur:
        cur.execute(
            "insert into app.operator_profiles(id,display_name,status) values(%s,'P423 action operator','active')",
            (actor_id,),
        )
        cur.execute(
            "insert into app.cases(id,case_key,title,status) values(%s,%s,'P423 action test','active')",
            (case_id, "p423-action-" + uuid.uuid4().hex),
        )
        cur.execute(
            """insert into app.evidence_objects
               (id,case_id,display_name,display_path,status,seal_status)
               values(%s,%s,'disk.raw','evidence/disk.raw','sealed','sealed')""",
            (object_id, case_id),
        )
        cur.execute(
            """insert into app.audit_events
               (id,case_id,event_type,actor_type,actor_user_id,source,status,details)
               values(%s,%s,%s,'user',%s,'portal_reauth','success',%s)""",
            (audit_id, case_id, event_type, actor_id, Jsonb({"binding": binding})),
        )
    conn.commit()
    return case_id, actor_id, audit_id, object_id, key, reason, command


def _begin(cur, intent, *, action: str, runner: str = "action-runner"):
    from psycopg.types.json import Jsonb

    case_id, actor_id, audit_id, _object_id, key, reason, command = intent
    cur.execute(
        """select id,action,phase from app.custody_operation_begin_or_resume(
           %s,%s,%s,%s,%s,%s,%s,%s,null,%s,null)""",
        (
            case_id,
            action,
            Jsonb(command),
            "sha256:" + "d" * 64,
            reason,
            audit_id,
            key,
            actor_id,
            runner,
        ),
    )
    return cur.fetchone()


def test_action_rpc_binds_object_blocks_gate_and_preserves_add_seal_authority():
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        intent = _setup_action(conn)
        with conn.cursor() as cur:
            operation_id, action, phase = _begin(cur, intent, action="RETIRE")
            assert action == "RETIRE"
            assert phase == "GATE_BLOCKED"
            assert _begin(cur, intent, action="RETIRE") == (
                operation_id,
                "RETIRE",
                "GATE_BLOCKED",
            )
            cur.execute(
                "select seal_status from app.evidence_chain_heads where case_id=%s",
                (intent[0],),
            )
            assert cur.fetchone()[0] == "unsealed"
            cur.execute(
                "select relrowsecurity,relforcerowsecurity from pg_class where oid='app.custody_operations'::regclass"
            )
            assert cur.fetchone() == (True, True)
            cur.execute(
                "select has_function_privilege('public','app.custody_operation_begin_or_resume(uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid)','EXECUTE')"
            )
            assert cur.fetchone()[0] is False
            cur.execute(
                "select has_function_privilege('authenticated','app.custody_operation_begin_or_resume(uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid)','EXECUTE')"
            )
            assert cur.fetchone()[0] is False
            cur.execute(
                "select has_function_privilege('service_role','app.custody_operation_begin_or_resume(uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid)','EXECUTE')"
            )
            assert cur.fetchone()[0] is True
            cur.execute(
                "select has_function_privilege('service_role','app.custody_operation_commit_verified_add_seal_v1(uuid,jsonb,text,text)','EXECUTE')"
            )
            assert cur.fetchone()[0] is False
        conn.rollback()


def test_unknown_action_and_mismatched_binding_create_no_operation():
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        unknown = _setup_action(conn, action="CUSTOM_ACTION")
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.InvalidParameterValue):
                _begin(cur, unknown, action="CUSTOM_ACTION")
        conn.rollback()

        mismatched = _setup_action(conn, binding_action="IGNORE")
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                _begin(cur, mismatched, action="RETIRE")
        conn.rollback()

        with conn.cursor() as cur:
            cur.execute(
                "select count(*) from app.custody_operations where case_id in (%s,%s)",
                (unknown[0], mismatched[0]),
            )
            assert cur.fetchone()[0] == 0


def test_non_add_operation_cannot_reach_add_seal_finalizer_or_mutate_custody():
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        intent = _setup_action(conn, action="RETIRE")
        with conn.cursor() as cur:
            operation_id, _action, _phase = _begin(cur, intent, action="RETIRE")
            cur.execute(
                """select phase from app.custody_operation_advance(
                   %s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'action-runner')""",
                (operation_id, Jsonb({"selection": "retire"})),
            )
            cur.execute(
                """select phase from app.custody_operation_advance(
                   %s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'action-runner')""",
                (operation_id, Jsonb({"verified": True})),
            )
            cur.execute(
                """select status,seal_status,current_version_id,current_sha256,current_bytes
                   from app.evidence_objects where id=%s""",
                (intent[3],),
            )
            object_before = cur.fetchone()
            cur.execute(
                """select manifest_version,manifest_hash,seal_status,head_seq,head_hash
                   from app.evidence_chain_heads where case_id=%s""",
                (intent[0],),
            )
            head_before = cur.fetchone()
            cur.execute(
                """select
                     (select count(*) from app.evidence_manifests where operation_id=%s),
                     (select count(*) from app.evidence_versions where custody_operation_id=%s),
                     (select count(*) from app.evidence_custody_events where custody_operation_id=%s)""",
                (operation_id, operation_id, operation_id),
            )
            counts_before = cur.fetchone()

            cur.execute("savepoint wrong_finalizer")
            with pytest.raises(psycopg.errors.InvalidParameterValue):
                cur.execute(
                    """select phase from app.custody_operation_commit_verified_seal(
                       %s,%s,'test examiner','action-runner')""",
                    (operation_id, Jsonb([])),
                )
            cur.execute("rollback to savepoint wrong_finalizer")

            cur.execute(
                """select status,seal_status,current_version_id,current_sha256,current_bytes
                   from app.evidence_objects where id=%s""",
                (intent[3],),
            )
            assert cur.fetchone() == object_before
            cur.execute(
                """select manifest_version,manifest_hash,seal_status,head_seq,head_hash
                   from app.evidence_chain_heads where case_id=%s""",
                (intent[0],),
            )
            assert cur.fetchone() == head_before
            cur.execute(
                """select
                     (select count(*) from app.evidence_manifests where operation_id=%s),
                     (select count(*) from app.evidence_versions where custody_operation_id=%s),
                     (select count(*) from app.evidence_custody_events where custody_operation_id=%s)""",
                (operation_id, operation_id, operation_id),
            )
            assert cur.fetchone() == counts_before == (0, 0, 0)
            cur.execute(
                "select phase from app.custody_operations where id=%s",
                (operation_id,),
            )
            assert cur.fetchone()[0] == "FILESYSTEM_VERIFIED"
        conn.rollback()
