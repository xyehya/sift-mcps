from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.integration


def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip(
            "SIFT_CONTROL_PLANE_DSN is required for migrated-Postgres storage proof"
        )
    return dsn


def _audit(conn, *, case_id, actor_id, event_type, binding):
    from psycopg.types.json import Jsonb

    event_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            """insert into app.audit_events
               (id,case_id,event_type,actor_type,actor_user_id,source,status,details)
               values(%s,%s,%s,'user',%s,'portal_reauth','success',%s)""",
            (event_id, case_id, event_type, actor_id, Jsonb({"binding": binding})),
        )
    return event_id


def _case_actor(conn):
    case_id, actor_id = uuid.uuid4(), uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "insert into app.operator_profiles(id,display_name,status) values(%s,'P423 storage operator','active')",
            (actor_id,),
        )
        cur.execute(
            "insert into app.cases(id,case_key,title,status) values(%s,%s,'P423 storage case','active')",
            (case_id, "p423-storage-" + uuid.uuid4().hex),
        )
        cur.execute(
            "select profile,state from app.evidence_storage_authorities where case_id=%s",
            (case_id,),
        )
        assert cur.fetchone() == ("LOCAL_IMMUTABLE", "AVAILABLE")
    return case_id, actor_id


def test_v3_resume_rejects_every_retired_runner_and_profile_is_reauth_bound():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn:
        case_id, actor_id = _case_actor(conn)
        key = "seal-" + uuid.uuid4().hex
        reason = "external storage runner replay proof"
        command = {
            "schema_version": 3,
            "action": "ADD_SEAL",
            "storage_profile": "LOCAL_IMMUTABLE",
            "files": [{"path": "evidence/test.img"}],
        }
        binding = {
            "idempotency_key": key,
            "reason": reason,
            "storage_profile": "LOCAL_IMMUTABLE",
            "targets": ["evidence/test.img"],
        }
        initial_reauth = _audit(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            event_type="reauth.evidence_seal",
            binding=binding,
        )
        with conn.cursor() as cur:
            cur.execute(
                """select id from app.custody_operation_begin_or_resume_storage_v3(
                     %s,%s,%s,%s,%s,%s,%s,%s,null)""",
                (
                    case_id,
                    Jsonb(command),
                    "sha256:" + "a" * 64,
                    reason,
                    initial_reauth,
                    key,
                    actor_id,
                    "runner-a",
                ),
            )
            operation_id = cur.fetchone()[0]
        resume_reauth = _audit(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            event_type="reauth.evidence_seal_resume",
            binding={"operation_id": str(operation_id)},
        )
        with conn.cursor() as cur:
            cur.execute(
                """select runner_instance_id from app.custody_operation_begin_or_resume_storage_v3(
                     %s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    case_id,
                    Jsonb(command),
                    "sha256:" + "a" * 64,
                    reason,
                    initial_reauth,
                    key,
                    actor_id,
                    "runner-b",
                    resume_reauth,
                ),
            )
            assert cur.fetchone()[0] == "runner-b"
        replay_reauth = _audit(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            event_type="reauth.evidence_seal_resume",
            binding={"operation_id": str(operation_id)},
        )
        with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """select app.custody_operation_begin_or_resume_storage_v3(
                             %s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (
                            case_id,
                            Jsonb(command),
                            "sha256:" + "a" * 64,
                            reason,
                            initial_reauth,
                            key,
                            actor_id,
                            "runner-a",
                            replay_reauth,
                        ),
                    )


def test_storage_observation_distinguishes_reconnect_source_change_and_rw_drift():
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        case_id, _actor_id = _case_actor(conn)
        source_a, source_b = "a" * 64, "b" * 64
        mount_a, mount_b = "c" * 64, "d" * 64
        with conn.cursor() as cur:
            cur.execute(
                """update app.evidence_storage_authorities set profile='EXTERNALLY_READ_ONLY',
                   source_identity=%s,verified_mount_instance=%s,observed_mount_instance=%s,
                   state='AVAILABLE',generation=2,verified_generation=2,read_only=true
                   where case_id=%s""",
                (source_a, mount_a, mount_a, case_id),
            )
            cur.execute(
                "select state,remediation from app.evidence_storage_record_observation(%s,'EXTERNALLY_READ_ONLY',true,%s,%s,true)",
                (case_id, source_a, mount_b),
            )
            assert cur.fetchone() == ("FULL_VERIFY_REQUIRED", "RECONNECT_AND_VERIFY")
            cur.execute(
                "select state,remediation from app.evidence_storage_record_observation(%s,'EXTERNALLY_READ_ONLY',true,%s,%s,true)",
                (case_id, source_b, mount_b),
            )
            assert cur.fetchone() == ("IDENTITY_DRIFT", "AUTHORIZE_SOURCE_CHANGE")
            cur.execute(
                "select state,remediation from app.evidence_storage_record_observation(%s,'EXTERNALLY_READ_ONLY',true,%s,%s,false)",
                (case_id, source_a, mount_a),
            )
            assert cur.fetchone() == ("READ_WRITE_DRIFT", "RESTORE_READ_ONLY")


def test_passwordless_full_verify_still_requires_operator_actor():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn:
        with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """select app.evidence_storage_commit_full_verify(
                             %s,1,'LOCAL_IMMUTABLE',null,null,null,0,%s,%s,null)""",
                        (uuid.uuid4(), Jsonb([]), "full-verify:" + uuid.uuid4().hex),
                    )
