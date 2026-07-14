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
            cur.execute(
                "select state,remediation from app.evidence_storage_record_observation(%s,'EXTERNALLY_READ_ONLY',true,%s,%s,true)",
                (case_id, source_a, mount_a),
            )
            assert cur.fetchone() == ("FULL_VERIFY_REQUIRED", "FULL_VERIFY")
            cur.execute(
                """update app.evidence_storage_authorities set state='AVAILABLE',
                   verified_generation=generation,read_only=true where case_id=%s""",
                (case_id,),
            )
            cur.execute(
                "select state from app.evidence_storage_record_observation(%s,'EXTERNALLY_READ_ONLY',true,%s,%s,true)",
                (case_id, source_b, mount_a),
            )
            assert cur.fetchone() == ("IDENTITY_DRIFT",)
            cur.execute(
                "select state,remediation from app.evidence_storage_record_observation(%s,'EXTERNALLY_READ_ONLY',true,%s,%s,true)",
                (case_id, source_a, mount_a),
            )
            assert cur.fetchone() == ("FULL_VERIFY_REQUIRED", "FULL_VERIFY")


def test_storage_profile_transition_exact_retry_is_durable_and_conflicts_reject():
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        case_id, actor_id = _case_actor(conn)
        key = "storage-" + uuid.uuid4().hex
        binding = {
            "profile": "EXTERNALLY_READ_ONLY",
            "reason": "move to operator mounted media",
            "idempotency_key": key,
        }
        receipt = _audit(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            event_type="reauth.evidence_storage_profile_change",
            binding=binding,
        )
        with conn.cursor() as cur:
            params = (
                case_id,
                binding["profile"],
                binding["reason"],
                key,
                receipt,
                actor_id,
            )
            cur.execute(
                "select app.evidence_storage_change_profile(%s,%s,%s,%s,%s,%s)", params
            )
            first = cur.fetchone()[0]
            cur.execute(
                "select app.evidence_storage_change_profile(%s,%s,%s,%s,%s,%s)", params
            )
            assert cur.fetchone()[0] == first
            cur.execute(
                "select generation from app.evidence_storage_authorities where case_id=%s",
                (case_id,),
            )
            assert cur.fetchone()[0] == first["generation"]
            cur.execute(
                """select count(*) from app.evidence_custody_events
                   where case_id=%s and event_type='STORAGE_PROFILE_CHANGED'""",
                (case_id,),
            )
            assert cur.fetchone()[0] == 1
        conflicting = dict(binding, reason="different transition")
        conflicting_receipt = _audit(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            event_type="reauth.evidence_storage_profile_change",
            binding=conflicting,
        )
        with pytest.raises(psycopg.errors.UniqueViolation):
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        "select app.evidence_storage_change_profile(%s,%s,%s,%s,%s,%s)",
                        (
                            case_id,
                            conflicting["profile"],
                            conflicting["reason"],
                            key,
                            conflicting_receipt,
                            actor_id,
                        ),
                    )
        fresh_receipt = _audit(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            event_type="reauth.evidence_storage_profile_change",
            binding=binding,
        )
        with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        "select app.evidence_storage_change_profile(%s,%s,%s,%s,%s,%s)",
                        (
                            case_id,
                            binding["profile"],
                            binding["reason"],
                            key,
                            fresh_receipt,
                            actor_id,
                        ),
                    )


def test_passwordless_full_verify_still_requires_operator_actor():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn:
        with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """select app.evidence_storage_commit_full_verify(
                             %s,1,'LOCAL_IMMUTABLE',null,null,null,0,%s,%s,null,null)""",
                        (uuid.uuid4(), Jsonb([]), "full-verify:" + uuid.uuid4().hex),
                    )
