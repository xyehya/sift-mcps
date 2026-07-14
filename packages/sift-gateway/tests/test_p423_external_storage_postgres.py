from __future__ import annotations

import os
import threading
import time
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


def _blocked_operation(conn, case_id, actor_id):
    from psycopg.types.json import Jsonb

    key = "lock-operation-" + uuid.uuid4().hex
    reason = "execution lease operation contention proof"
    command = {
        "schema_version": 3,
        "action": "ADD_SEAL",
        "storage_profile": "LOCAL_IMMUTABLE",
        "files": [{"path": "evidence/lock-operation.raw"}],
    }
    reauth = _audit(
        conn,
        case_id=case_id,
        actor_id=actor_id,
        event_type="reauth.evidence_seal",
        binding={
            "idempotency_key": key,
            "reason": reason,
            "storage_profile": "LOCAL_IMMUTABLE",
            "targets": ["evidence/lock-operation.raw"],
        },
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
                reauth,
                key,
                actor_id,
                "lock-runner",
            ),
        )
        return cur.fetchone()[0]


@pytest.mark.parametrize(
    "writer",
    (
        "evidence_observe_admission",
        "evidence_mark_admission_violation",
        "evidence_detect",
        "evidence_mark_violation",
    ),
)
def test_execution_shared_lock_blocks_actual_custody_writer_until_release(writer):
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as setup_conn:
        case_id, _actor_id = _case_actor(setup_conn)
    started = threading.Event()
    finished = threading.Event()
    errors = []

    def invoke_writer():
        try:
            with psycopg.connect(_dsn()) as transition_conn:
                with transition_conn.cursor() as cur:
                    started.set()
                    correlation = "p423-lock-" + uuid.uuid4().hex
                    if writer == "evidence_observe_admission":
                        cur.execute(
                            "select app.evidence_observe_admission(%s,%s,%s,0,%s,null,null)",
                            (case_id, "evidence/lock-observe.raw", "lock-observe.raw", correlation),
                        )
                    elif writer == "evidence_mark_admission_violation":
                        cur.execute(
                            "select app.evidence_mark_admission_violation(%s,null,%s,'[]'::jsonb,%s,null,null)",
                            (case_id, "lock contention proof", correlation),
                        )
                    elif writer == "evidence_detect":
                        cur.execute(
                            "select app.evidence_detect(%s,%s,%s,0,null,null)",
                            (case_id, "evidence/lock-detect.raw", "lock-detect.raw"),
                        )
                    else:
                        cur.execute(
                            "select app.evidence_mark_violation(%s,null,%s,'[]'::jsonb,null,null)",
                            (case_id, "lock contention proof"),
                        )
        except Exception as exc:  # pragma: no cover - reported by assertion
            errors.append(exc)
        finally:
            finished.set()

    with psycopg.connect(_dsn()) as execution_conn:
        with execution_conn.cursor() as cur:
            cur.execute(
                "select pg_advisory_xact_lock_shared("
                "hashtextextended(%s::text, 0))",
                (case_id,),
            )
        worker = threading.Thread(target=invoke_writer, daemon=True)
        worker.start()
        assert started.wait(timeout=2)
        time.sleep(0.15)
        assert not finished.is_set(), f"{writer} bypassed the shared execution lock"
        execution_conn.commit()
        worker.join(timeout=3)
    assert finished.is_set(), f"{writer} did not proceed after lock release"
    assert errors == []


def test_execution_shared_lock_blocks_operation_derived_writer_until_release():
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as setup_conn:
        case_id, actor_id = _case_actor(setup_conn)
        operation_id = _blocked_operation(setup_conn, case_id, actor_id)
    started = threading.Event()
    finished = threading.Event()
    errors = []

    def advance_operation():
        try:
            with psycopg.connect(_dsn()) as transition_conn:
                with transition_conn.cursor() as cur:
                    started.set()
                    cur.execute(
                        """select app.custody_operation_advance(
                             %s,'GATE_BLOCKED','FILESYSTEM_APPLYING','{}'::jsonb,'lock-runner')""",
                        (operation_id,),
                    )
        except Exception as exc:  # pragma: no cover - reported by assertion
            errors.append(exc)
        finally:
            finished.set()

    with psycopg.connect(_dsn()) as execution_conn:
        with execution_conn.cursor() as cur:
            cur.execute(
                "select pg_advisory_xact_lock_shared(hashtextextended(%s::text,0))",
                (case_id,),
            )
        worker = threading.Thread(target=advance_operation, daemon=True)
        worker.start()
        assert started.wait(timeout=2)
        time.sleep(0.15)
        assert not finished.is_set()
        execution_conn.commit()
        worker.join(timeout=3)
    assert finished.is_set()
    assert errors == []


def test_service_role_cannot_execute_unlocked_custody_helpers():
    psycopg = pytest.importorskip("psycopg")
    helpers = (
        "app.evidence_detect_impl_pre_execution_lock(uuid,text,text,bigint,uuid,uuid)",
        "app.evidence_register_impl_pre_execution_lock(uuid,text,text,text,uuid,uuid)",
        "app.evidence_seal_impl_pre_execution_lock(uuid,jsonb,integer,text,uuid,uuid,uuid)",
        "app.evidence_verify_impl_pre_execution_lock(uuid,boolean,integer,jsonb,uuid,uuid)",
        "app.evidence_mark_violation_impl_pre_execution_lock(uuid,uuid,text,jsonb,uuid,uuid)",
        "app.evidence_observe_admission_impl_pre_execution_lock(uuid,text,text,bigint,text,uuid,uuid)",
        "app.evidence_mark_admission_violation_impl_pre_execution_lock(uuid,uuid,text,jsonb,text,uuid,uuid)",
        "app.evidence_record_proof_export_impl_pre_execution_lock(uuid,integer,text,text,text,boolean,uuid,jsonb)",
        "app.custody_operation_advance_impl_pre_execution_lock(uuid,text,text,jsonb,text)",
        "app.custody_operation_fail_impl_pre_execution_lock(uuid,text,text,text)",
        "app.evidence_append_custody_event(uuid,uuid,text,integer,text,uuid,uuid,uuid,jsonb)",
        "app.evidence_recompute_seal_status(uuid)",
    )
    with psycopg.connect(_dsn()) as conn:
        with conn.cursor() as cur:
            for helper in helpers:
                cur.execute(
                    "select has_function_privilege('service_role',%s,'EXECUTE')",
                    (helper,),
                )
                assert cur.fetchone() == (False,), helper


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
        # The append-only re-auth ledger binds one intent per scoped
        # idempotency key, so a conflicting ceremony is rejected before the
        # transition function can observe it.
        with pytest.raises(psycopg.errors.UniqueViolation):
            with conn.transaction():
                _audit(
                    conn,
                    case_id=case_id,
                    actor_id=actor_id,
                    event_type="reauth.evidence_storage_profile_change",
                    binding=conflicting,
                )
        mismatched_binding = dict(binding, idempotency_key=key + "-different")
        fresh_receipt = _audit(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            event_type="reauth.evidence_storage_profile_change",
            binding=mismatched_binding,
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
        with conn.cursor() as cur:
            cur.execute(
                "select generation from app.evidence_storage_authorities where case_id=%s",
                (case_id,),
            )
            assert cur.fetchone()[0] == first["generation"]
            cur.execute(
                """select count(*) from app.evidence_storage_profile_transitions
                   where case_id=%s and idempotency_key=%s""",
                (case_id, key),
            )
            assert cur.fetchone()[0] == 1
            cur.execute(
                """select count(*) from app.evidence_custody_events
                   where case_id=%s and event_type='STORAGE_PROFILE_CHANGED'""",
                (case_id,),
            )
            assert cur.fetchone()[0] == 1


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
