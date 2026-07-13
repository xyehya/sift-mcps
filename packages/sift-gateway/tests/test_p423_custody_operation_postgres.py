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


def _setup_intent(
    conn,
    *,
    reason: str = "database contract test",
    binding_reason: str | None = None,
    violated: bool = False,
):
    from psycopg.types.json import Jsonb

    case_id, actor_id, audit_id, object_id = (uuid.uuid4() for _ in range(4))
    key = "test-" + uuid.uuid4().hex
    path = "evidence/" + uuid.uuid4().hex + ".raw"
    binding = {
        "idempotency_key": key,
        "reason": binding_reason if binding_reason is not None else reason,
        "targets": [path],
    }
    with conn.cursor() as cur:
        cur.execute(
            "insert into app.operator_profiles(id,display_name,status) values(%s,'P423 operator','active')",
            (actor_id,),
        )
        cur.execute(
            "insert into app.cases(id,case_key,title,status) values(%s,%s,'P423 DB test','active')",
            (case_id, "p423-db-" + uuid.uuid4().hex),
        )
        cur.execute(
            """insert into app.audit_events
               (id,case_id,event_type,actor_type,actor_user_id,source,status,details)
               values(%s,%s,'reauth.evidence_seal','user',%s,'portal_reauth','success',%s)""",
            (audit_id, case_id, actor_id, Jsonb({"examiner": "test", "action": "evidence_seal", "binding": binding})),
        )
        cur.execute(
            """insert into app.evidence_objects
               (id,case_id,display_name,display_path,status,seal_status)
               values(%s,%s,%s,%s,'detected','unsealed')""",
            (object_id, case_id, path.rsplit("/", 1)[-1], path),
        )
        if violated:
            cur.execute(
                """insert into app.evidence_objects
                   (case_id,display_name,display_path,status,seal_status)
                   values(%s,'violated.raw',%s,'violated','violated')""",
                (case_id, "evidence/violated-" + uuid.uuid4().hex + ".raw"),
            )
            cur.execute(
                "insert into app.evidence_chain_heads(case_id,seal_status,issues) values(%s,'violated','[\"digest_changed\"]')",
                (case_id,),
            )
    conn.commit()
    command = {"schema_version": 1, "action": "ADD_SEAL", "files": [{"path": path, "description": None, "source": None}]}
    return case_id, actor_id, audit_id, object_id, key, path, command


def _begin(cur, intent, runner: str, *, digest: str = "sha256:" + "1" * 64, resume_audit_id=None):
    from psycopg.types.json import Jsonb

    case_id, actor_id, audit_id, _object_id, key, _path, command = intent
    cur.execute(
        """select id,phase from app.custody_operation_begin_or_resume(
           %s,'ADD_SEAL',%s,%s,'database contract test',%s,%s,%s,null,%s,%s)""",
        (case_id, Jsonb(command), digest, audit_id, key, actor_id, runner, resume_audit_id),
    )
    return cur.fetchone()


def _facts(intent):
    case_id, _actor_id, _audit_id, object_id, _key, path, _command = intent
    del case_id
    item = {
        "evidence_object_id": str(object_id), "path": path, "display_path": path,
        "display_name": path.rsplit("/", 1)[-1], "description": None, "source": None,
        "sha256": "sha256:" + "a" * 64, "bytes": 17, "owner": "sift-service",
        "mode": "0644", "immutable": True, "st_dev": 1, "st_ino": 2,
        "st_nlink": 1, "st_mtime_ns": 3, "st_ctime_ns": 4,
    }
    prepared = {"items": [{k: v for k, v in item.items() if k not in {"owner", "mode", "immutable", "st_mtime_ns", "st_ctime_ns"}}]}
    return prepared, {"items": [item]}, item


def _resume_audit(cur, intent, operation_id, **overrides):
    from psycopg.types.json import Jsonb

    audit_id = uuid.uuid4()
    values = {
        "case_id": intent[0], "actor_id": intent[1],
        "event_type": "reauth.evidence_seal_resume", "source": "portal_reauth",
        "status": "success", "binding": {"operation_id": str(operation_id)},
    }
    values.update(overrides)
    cur.execute(
        """insert into app.audit_events
           (id,case_id,event_type,actor_type,actor_user_id,source,status,details)
           values(%s,%s,%s,'user',%s,%s,%s,%s)""",
        (audit_id, values["case_id"], values["event_type"], values["actor_id"],
         values["source"], values["status"], Jsonb({"binding": values["binding"]})),
    )
    return audit_id


def test_accumulated_migrations_reuse_triggers_and_lock_cases_independently():
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as setup:
        setup.autocommit = False
        first = _setup_intent(setup)
        second = _setup_intent(setup)
        with setup.cursor() as cur:
            cur.execute(
                """select tgname,count(*) from pg_trigger where not tgisinternal
                   and tgname in ('evidence_versions_no_truncate','evidence_custody_events_no_truncate')
                   group by tgname order by tgname"""
            )
            assert cur.fetchall() == [
                ("evidence_custody_events_no_truncate", 1),
                ("evidence_versions_no_truncate", 1),
            ]

    with psycopg.connect(_dsn()) as c1, psycopg.connect(_dsn()) as c2:
        c1.autocommit = c2.autocommit = False
        with c1.cursor() as a, c2.cursor() as b:
            _begin(a, first, "runner-a")  # transaction deliberately holds case lock
            b.execute("set local lock_timeout='250ms'")
            other_case = _begin(b, second, "runner-b")
            assert other_case[1] == "GATE_BLOCKED"  # different case proceeds in parallel
            c2.commit()
            b.execute("set local lock_timeout='250ms'")
            with pytest.raises(psycopg.errors.LockNotAvailable):
                _begin(b, first, "runner-c", digest="sha256:" + "2" * 64)
            c2.rollback()
        c1.commit()
        with c2.cursor() as b:
            with pytest.raises(psycopg.Error) as loser:
                _begin(b, first, "runner-c", digest="sha256:" + "2" * 64)
            assert loser.value.sqlstate == "P4231"
            c2.rollback()
            b.execute("select count(*) from app.custody_operations where case_id=%s", (first[0],))
            assert b.fetchone()[0] == 1


def test_final_commit_rollback_replay_sibling_preservation_and_grants():
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        intent = _setup_intent(conn)
        case_id = intent[0]
        # A pre-existing sealed sibling must be carried into the next manifest.
        sibling_id, sibling_version = uuid.uuid4(), uuid.uuid4()
        with conn.cursor() as cur:
            cur.execute(
                """insert into app.evidence_objects(id,case_id,display_name,display_path,status,seal_status)
                   values(%s,%s,'sibling.raw',%s,'sealed','sealed')""",
                (sibling_id, case_id, "evidence/sibling-" + uuid.uuid4().hex + ".raw"),
            )
            cur.execute(
                """insert into app.evidence_versions(id,evidence_object_id,case_id,manifest_version,sha256,bytes,entry_status,manifest_hash)
                   values(%s,%s,%s,1,%s,9,'ACTIVE',%s)""",
                (sibling_version, sibling_id, case_id, "sha256:" + "b" * 64, "sha256:" + "c" * 64),
            )
            cur.execute("update app.evidence_objects set current_version_id=%s where id=%s", (sibling_version, sibling_id))
            cur.execute(
                """insert into app.evidence_chain_heads
                   (case_id,manifest_version,manifest_hash,seal_status,active_count)
                   values(%s,1,%s,'sealed',1)""",
                (case_id, "sha256:" + "c" * 64),
            )
            second_id = uuid.uuid4()
            while second_id.int <= intent[3].int:
                second_id = uuid.uuid4()
            second_path = "evidence/" + uuid.uuid4().hex + ".raw"
            cur.execute("insert into app.evidence_objects(id,case_id,display_name,display_path,status,seal_status) values(%s,%s,%s,%s,'detected','unsealed')", (second_id, case_id, second_path.rsplit('/', 1)[-1], second_path))
            intent[6]["files"].append({"path": second_path, "description": None, "source": None})
            cur.execute("update app.audit_events set details=jsonb_set(details,'{binding,targets}',%s) where id=%s", (Jsonb(sorted([intent[5], second_path])), intent[2]))
            op_id, _phase = _begin(cur, intent, "runner-final")
            prepared, verified, item = _facts(intent)
            second_item = {**item, "evidence_object_id": str(second_id), "path": second_path, "display_path": second_path, "display_name": second_path.rsplit('/', 1)[-1], "st_ino": 22}
            prepared["items"].append({k: v for k, v in second_item.items() if k not in {"owner", "mode", "immutable", "st_mtime_ns", "st_ctime_ns"}})
            verified["items"].append(second_item)
            cur.execute("select phase from app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'runner-final')", (op_id, Jsonb(prepared)))
            cur.execute("select phase from app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'runner-final')", (op_id, Jsonb(verified)))

            cur.execute("savepoint mismatched_verified")
            cur.execute("update app.evidence_objects set status='ignored' where id=%s", (second_id,))
            with pytest.raises(psycopg.errors.InvalidParameterValue):
                cur.execute("select phase from app.custody_operation_commit_verified_seal(%s,%s,'test','runner-final')", (op_id, Jsonb(verified["items"])))
            cur.execute("rollback to savepoint mismatched_verified")
            cur.execute("select count(*) from app.evidence_manifests where operation_id=%s", (op_id,))
            assert cur.fetchone()[0] == 0
            cur.execute("select count(*) from app.evidence_versions where custody_operation_id=%s", (op_id,))
            assert cur.fetchone()[0] == 0
            cur.execute("select count(*) from app.evidence_custody_events where custody_operation_id=%s", (op_id,))
            assert cur.fetchone()[0] == 0
            cur.execute("update app.evidence_objects set status='detected' where id=%s", (second_id,))

            cur.execute("select result from app.custody_operation_commit_verified_seal(%s,%s,'test','runner-final')", (op_id, Jsonb(verified["items"])))
            first_result = cur.fetchone()[0]
            cur.execute("select result from app.custody_operation_commit_verified_seal(%s,%s,'test','runner-final')", (op_id, Jsonb(verified["items"])))
            assert cur.fetchone()[0] == first_result  # response-loss replay
            cur.execute("select count(*) from app.evidence_manifests where operation_id=%s", (op_id,))
            assert cur.fetchone()[0] == 1
            cur.execute("select count(*) from app.evidence_versions where custody_operation_id=%s", (op_id,))
            assert cur.fetchone()[0] == 2
            cur.execute("select item_facts from app.evidence_manifests where operation_id=%s", (op_id,))
            facts = cur.fetchone()[0]
            assert any(x.get("evidence_object_id") == str(sibling_id) and x.get("preserved_sibling") for x in facts)
            cur.execute("select count(*) from app.evidence_custody_events where custody_operation_id=%s and event_type='MANIFEST_SEALED'", (op_id,))
            assert cur.fetchone()[0] == 1
            cur.execute("select has_function_privilege('public','app.custody_operation_commit_verified_seal(uuid,jsonb,text,text)','EXECUTE')")
            assert cur.fetchone()[0] is False
            cur.execute("select has_schema_privilege('authenticated','app','USAGE'),has_table_privilege('authenticated','app.custody_operations','SELECT'),has_table_privilege('authenticated','app.custody_operations','INSERT')")
            assert cur.fetchone() == (False, False, False)
            cur.execute("select id from auth.users order by created_at limit 1")
            auth_row = cur.fetchone()
            if auth_row:
                cur.execute("update app.operator_profiles set auth_user_id=%s where id=%s", (auth_row[0], intent[1]))
                cur.execute("insert into app.case_members(case_id,operator_profile_id,role,status) values(%s,%s,'operator','active')", (case_id, intent[1]))
        conn.commit()

        with conn.cursor() as cur:
            for table in ("custody_operation_history", "evidence_manifests", "evidence_versions", "evidence_custody_events"):
                for statement in (f"update app.{table} set created_at=created_at", f"delete from app.{table}", f"truncate app.{table}"):
                    cur.execute("savepoint append_only_probe")
                    with pytest.raises(psycopg.Error):
                        cur.execute(statement)
                    cur.execute("rollback to savepoint append_only_probe")

        with psycopg.connect(_dsn()) as metadata:
            with metadata.cursor() as cur:
                cur.execute("select relrowsecurity,relforcerowsecurity from pg_class where oid='app.custody_operations'::regclass")
                assert cur.fetchone() == (True, True)
                cur.execute("select count(*) from pg_policies where schemaname='app' and tablename='custody_operations' and cmd='SELECT'")
                assert cur.fetchone()[0] == 1


def test_violation_reauth_scope_and_restart_instance_recovery_fail_closed():
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        violated = _setup_intent(conn, violated=True)
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
                _begin(cur, violated, "runner-v")
        conn.rollback()

        # A violation discovered after begin remains authoritative at final commit
        # and a recoverable failure transition must not downgrade it.
        intent = _setup_intent(conn)
        prepared, verified, item = _facts(intent)
        with conn.cursor() as cur:
            op_id, _ = _begin(cur, intent, "runner-final-violation")
            cur.execute("select phase from app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'runner-final-violation')", (op_id, Jsonb(prepared)))
            cur.execute("select phase from app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'runner-final-violation')", (op_id, Jsonb(verified)))
            cur.execute("update app.evidence_chain_heads set seal_status='violated',issues='[\"changed\"]' where case_id=%s", (intent[0],))
            cur.execute("savepoint final_violation")
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
                cur.execute("select phase from app.custody_operation_commit_verified_seal(%s,%s,'test','runner-final-violation')", (op_id, Jsonb([item])))
            cur.execute("rollback to savepoint final_violation")
            cur.execute("select phase from app.custody_operation_fail(%s,'FILESYSTEM_VERIFIED','final_violation','runner-final-violation')", (op_id,))
            assert cur.fetchone()[0] == "FAILED_RECOVERABLE"
            cur.execute("select seal_status,issues from app.evidence_chain_heads where case_id=%s", (intent[0],))
            assert cur.fetchone() == ("violated", ["changed"])
            cur.execute("select count(*) from app.evidence_manifests where operation_id=%s", (op_id,))
            assert cur.fetchone()[0] == 0
        conn.rollback()

        intent = _setup_intent(conn, binding_reason="wrong")
        with conn.cursor() as cur:
            # The DB independently rejects an audit receipt whose normalized binding changed.
            with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                _begin(cur, intent, "runner-r")
        conn.rollback()

        intent = _setup_intent(conn)
        prepared, verified, _item = _facts(intent)
        with conn.cursor() as cur:
            op_id, _ = _begin(cur, intent, "invocation-1")
            conn.commit()  # hard interruption at durable GATE_BLOCKED
            with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                _begin(cur, intent, "invocation-missing")
            conn.rollback()
            other = _setup_intent(conn)
            for overrides in (
                {"case_id": other[0]},
                {"actor_id": other[1]},
                {"event_type": "reauth.evidence_seal"},
                {"binding": {}},
            ):
                bad_resume = _resume_audit(cur, intent, op_id, **overrides)
                with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                    _begin(cur, intent, "invocation-invalid", resume_audit_id=bad_resume)
                conn.rollback()
            resume2 = _resume_audit(cur, intent, op_id)
            assert _begin(cur, intent, "invocation-2", resume_audit_id=resume2)[1] == "GATE_BLOCKED"
            cur.execute("select phase from app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'invocation-2')", (op_id, Jsonb(prepared)))
            conn.commit()
            with pytest.raises(psycopg.Error) as same:
                _begin(cur, intent, "invocation-2")
            assert same.value.sqlstate == "P4232"
            conn.rollback()
            with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                _begin(cur, intent, "invocation-reused", resume_audit_id=resume2)
            conn.rollback()
            cur.execute(
                "select phase,runner_instance_id from app.custody_operations where id=%s",
                (op_id,),
            )
            assert cur.fetchone() == ("FILESYSTEM_APPLYING", "invocation-2")
            with pytest.raises(psycopg.Error) as stale_begin:
                _begin(cur, intent, "invocation-1")
            assert stale_begin.value.sqlstate == "P4232"
            conn.rollback()
            for sql, args in (
                ("select phase from app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'invocation-1')", (op_id, Jsonb(verified))),
                ("select phase from app.custody_operation_fail(%s,'FILESYSTEM_APPLYING','stale','invocation-1')", (op_id,)),
                ("select phase from app.custody_operation_commit_verified_seal(%s,%s,'test','invocation-1')", (op_id, Jsonb(verified["items"]))),
            ):
                with pytest.raises(psycopg.errors.SerializationFailure):
                    cur.execute(sql, args)
                conn.rollback()
            cur.execute("select phase,runner_instance_id from app.custody_operations where id=%s", (op_id,))
            assert cur.fetchone() == ("FILESYSTEM_APPLYING", "invocation-2")
            resume3 = _resume_audit(cur, intent, op_id)
            assert _begin(cur, intent, "invocation-3", resume_audit_id=resume3)[1] == "GATE_BLOCKED"
            cur.execute("select phase from app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'invocation-3')", (op_id, Jsonb(prepared)))
            cur.execute("select phase from app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'invocation-3')", (op_id, Jsonb(verified)))
            conn.commit()  # hard interruption after durable FILESYSTEM_VERIFIED
            resume4 = _resume_audit(cur, intent, op_id)
            assert _begin(cur, intent, "invocation-4", resume_audit_id=resume4)[1] == "GATE_BLOCKED"
            changed_verified = {
                "items": [{**verified["items"][0], "st_ctime_ns": 999}]
            }
            cur.execute("select phase from app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'invocation-4')", (op_id, Jsonb(prepared)))
            cur.execute("select phase from app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'invocation-4')", (op_id, Jsonb(changed_verified)))
            assert cur.fetchone()[0] == "FILESYSTEM_VERIFIED"
            cur.execute("select phase,facts from app.custody_operation_history where operation_id=%s order by id", (op_id,))
            history = cur.fetchall()
            assert sum(phase == "FAILED_RECOVERABLE" for phase, _facts_json in history) == 2
            assert any(facts.get("failed_from") == "FILESYSTEM_VERIFIED" for phase, facts in history if phase == "FAILED_RECOVERABLE")
            cur.execute("select seal_status from app.evidence_chain_heads where case_id=%s", (intent[0],))
            assert cur.fetchone()[0] == "unsealed"
        conn.rollback()
