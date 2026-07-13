from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.integration


def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for migrated-Postgres recovery proof")
    return dsn


def _setup(conn, action: str):
    from psycopg.types.json import Jsonb

    case_id, actor_id, object_id, version_id, audit_id = (uuid.uuid4() for _ in range(5))
    key = f"recovery-{uuid.uuid4().hex}"
    reason = "migrated database recovery proof"
    old_sha = "sha256:" + "a" * 64
    command = {"schema_version": 2, "action": action, "evidence_object_id": str(object_id)}
    binding = {
        "action": action, "evidence_object_id": str(object_id),
        "idempotency_key": key, "reason": reason,
    }
    begin_event = (
        "reauth.evidence_replace_begin"
        if action == "REPLACE_REACQUIRE" else "reauth.evidence_restore"
    )
    with conn.cursor() as cur:
        cur.execute("insert into app.operator_profiles(id,display_name,status) values(%s,'Recovery operator','active')", (actor_id,))
        cur.execute("insert into app.cases(id,case_key,title,status) values(%s,%s,'Recovery case','active')", (case_id, "recovery-" + uuid.uuid4().hex))
        cur.execute("""insert into app.evidence_objects(id,case_id,display_name,display_path,status,seal_status,current_sha256,current_bytes)
                       values(%s,%s,'disk.raw','evidence/disk.raw','sealed','sealed',%s,8)""", (object_id, case_id, old_sha))
        cur.execute("""insert into app.evidence_versions(id,evidence_object_id,case_id,manifest_version,sha256,bytes,entry_status,manifest_hash)
                       values(%s,%s,%s,1,%s,8,'ACTIVE',%s)""", (version_id, object_id, case_id, old_sha, "sha256:" + "b" * 64))
        cur.execute("update app.evidence_objects set current_version_id=%s where id=%s", (version_id, object_id))
        cur.execute("""insert into app.evidence_chain_heads(case_id,manifest_version,manifest_hash,seal_status,active_count,head_seq,head_hash,issues)
                       values(%s,1,%s,'sealed',1,0,'','[]')""", (case_id, "sha256:" + "b" * 64))
        cur.execute("""insert into app.audit_events(id,case_id,event_type,actor_type,actor_user_id,source,status,details)
                       values(%s,%s,%s,'user',%s,'portal_reauth','success',%s)""", (audit_id, case_id, begin_event, actor_id, Jsonb({"binding": binding})))
    conn.commit()
    return case_id, actor_id, object_id, version_id, audit_id, key, reason, command, old_sha


def _begin(cur, setup, action: str):
    from psycopg.types.json import Jsonb

    case_id, actor_id, _object_id, _version_id, audit_id, key, reason, command, _sha = setup
    cur.execute("""select id::text from app.custody_operation_begin_or_resume(
                   %s,%s,%s,%s,%s,%s,%s,%s,null,'recovery-runner',null)""",
                (case_id, action, Jsonb(command), "sha256:" + "c" * 64, reason, audit_id, key, actor_id))
    return cur.fetchone()[0]


def _recovery_facts(setup, sha: str):
    case_id, actor_id, object_id, version_id, _audit_id, _key, _reason, _command, old_sha = setup
    del case_id, actor_id
    prepared = {
        "item": {
            "evidence_object_id": str(object_id), "display_path": "evidence/disk.raw",
            "original_version_id": str(version_id), "original_sha256": old_sha,
            "original_bytes": 8, "observed_at_begin": {"present": False},
        }
    }
    item = {
        **prepared["item"], "path": "evidence/disk.raw", "sha256": sha, "bytes": 8,
        "owner": "sift-service", "mode": "0644", "immutable": True,
        "st_dev": 1, "st_ino": 2, "st_nlink": 1, "st_mtime_ns": 3, "st_ctime_ns": 4,
    }
    return prepared, item


def _complete(conn, setup, operation_id: str, action: str, sha: str):
    from psycopg.types.json import Jsonb

    case_id, actor_id, _object_id, _version_id, _audit_id, _key, _reason, _command, _old_sha = setup
    completion_id = uuid.uuid4()
    completion_event = (
        "reauth.evidence_replace_complete"
        if action == "REPLACE_REACQUIRE" else "reauth.evidence_restore_complete"
    )
    prepared, item = _recovery_facts(setup, sha)
    with conn.cursor() as cur:
        cur.execute("select phase from app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'recovery-runner')", (operation_id, Jsonb(prepared)))
        cur.execute("""insert into app.audit_events(id,case_id,event_type,actor_type,actor_user_id,source,status,details)
                       values(%s,%s,%s,'user',%s,'portal_reauth','success',%s)""",
                    (completion_id, case_id, completion_event, actor_id, Jsonb({"binding": {"operation_id": operation_id}})))
        cur.execute("select phase from app.custody_operation_authorize_recovery_completion(%s,%s,%s,'recovery-runner')", (operation_id, actor_id, completion_id))
        assert cur.fetchone()[0] == "FILESYSTEM_APPLYING"
        cur.execute("select phase from app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'recovery-runner')", (operation_id, Jsonb({"item": item})))
        cur.execute("select result from app.custody_operation_commit_verified_recovery(%s,%s,'examiner','recovery-runner')", (operation_id, Jsonb(item)))
        result = cur.fetchone()[0]
    conn.commit()
    return result


def test_exact_restore_preserves_version_and_manifest_counts():
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        setup = _setup(conn, "RESTORE_EXACT")
        with conn.cursor() as cur:
            operation_id = _begin(cur, setup, "RESTORE_EXACT")
            cur.execute("select count(*) from app.evidence_versions where case_id=%s", (setup[0],))
            versions_before = cur.fetchone()[0]
            cur.execute("select count(*) from app.evidence_manifests where case_id=%s", (setup[0],))
            manifests_before = cur.fetchone()[0]
        result = _complete(conn, setup, operation_id, "RESTORE_EXACT", setup[-1])
        with conn.cursor() as cur:
            cur.execute("select count(*) from app.evidence_versions where case_id=%s", (setup[0],))
            assert cur.fetchone()[0] == versions_before
            cur.execute("select count(*) from app.evidence_manifests where case_id=%s", (setup[0],))
            assert cur.fetchone()[0] == manifests_before
            cur.execute("select current_version_id::text from app.evidence_objects where id=%s", (setup[2],))
            assert cur.fetchone()[0] == str(setup[3])
        assert result["restored_exact"] is True


def test_replace_appends_one_version_and_manifest_and_replays_exactly_once():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb
    with psycopg.connect(_dsn()) as conn:
        setup = _setup(conn, "REPLACE_REACQUIRE")
        with conn.cursor() as cur:
            operation_id = _begin(cur, setup, "REPLACE_REACQUIRE")
        result = _complete(conn, setup, operation_id, "REPLACE_REACQUIRE", "sha256:" + "d" * 64)
        with conn.cursor() as cur:
            cur.execute("select count(*) from app.evidence_versions where case_id=%s", (setup[0],))
            assert cur.fetchone()[0] == 2
            cur.execute("select count(*) from app.evidence_manifests where case_id=%s", (setup[0],))
            assert cur.fetchone()[0] == 1
            cur.execute("select result from app.custody_operation_commit_verified_recovery(%s,%s,'examiner','recovery-runner')", (operation_id, Jsonb({})))
            assert cur.fetchone()[0] == result
        assert result["reacquired"] is True


@pytest.mark.parametrize(
    "failed_from", ["FILESYSTEM_APPLYING", "FILESYSTEM_VERIFIED"]
)
def test_fresh_receipt_recovers_interrupted_completion_exactly_once(failed_from):
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn:
        setup = _setup(conn, "REPLACE_REACQUIRE")
        case_id, actor_id = setup[0], setup[1]
        prepared, item = _recovery_facts(setup, "sha256:" + "d" * 64)
        receipt_one, receipt_two, wrong_receipt = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        with conn.cursor() as cur:
            operation_id = _begin(cur, setup, "REPLACE_REACQUIRE")
            cur.execute(
                "select phase from app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'runner-before-restart')",
                (operation_id, Jsonb(prepared)),
            )
            for receipt, binding in (
                (receipt_one, {"operation_id": operation_id}),
                (receipt_two, {"operation_id": operation_id}),
                (wrong_receipt, {"operation_id": str(uuid.uuid4())}),
            ):
                cur.execute(
                    """insert into app.audit_events(id,case_id,event_type,actor_type,actor_user_id,source,status,details)
                       values(%s,%s,'reauth.evidence_replace_complete','user',%s,'portal_reauth','success',%s)""",
                    (receipt, case_id, actor_id, Jsonb({"binding": binding})),
                )
            cur.execute(
                "select phase from app.custody_operation_authorize_recovery_completion(%s,%s,%s,'runner-before-restart')",
                (operation_id, actor_id, receipt_one),
            )
            if failed_from == "FILESYSTEM_VERIFIED":
                cur.execute(
                    "select phase from app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'runner-before-restart')",
                    (operation_id, Jsonb({"item": item})),
                )
            cur.execute(
                "select phase from app.custody_operation_fail(%s,%s,'injected_restart','runner-before-restart')",
                (operation_id, failed_from),
            )
            cur.execute(
                "select phase,retired_runner_instance_ids from app.custody_operation_authorize_recovery_completion(%s,%s,%s,'runner-after-restart')",
                (operation_id, actor_id, receipt_two),
            )
            phase, retired = cur.fetchone()
            assert phase == "FILESYSTEM_APPLYING"
            assert "runner-before-restart" in retired
        conn.commit()

        for denied_receipt in (receipt_one, wrong_receipt):
            with pytest.raises(psycopg.Error):
                with conn.transaction():
                    with conn.cursor() as cur:
                        cur.execute(
                            "select app.custody_operation_authorize_recovery_completion(%s,%s,%s,'runner-third')",
                            (operation_id, actor_id, denied_receipt),
                        )

        with conn.cursor() as cur:
            cur.execute(
                "select phase from app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'runner-after-restart')",
                (operation_id, Jsonb({"item": item})),
            )
            cur.execute(
                "select result from app.custody_operation_commit_verified_recovery(%s,%s,'examiner','runner-after-restart')",
                (operation_id, Jsonb(item)),
            )
            result = cur.fetchone()[0]
            cur.execute(
                "select count(*) from app.custody_operation_completion_reauth_history where operation_id=%s",
                (operation_id,),
            )
            assert cur.fetchone()[0] == 2
            cur.execute("select count(*) from app.evidence_versions where case_id=%s", (case_id,))
            assert cur.fetchone()[0] == 2
            cur.execute("select count(*) from app.evidence_manifests where case_id=%s", (case_id,))
            assert cur.fetchone()[0] == 1
            cur.execute("select count(*) from app.evidence_custody_events where custody_operation_id=%s", (operation_id,))
            assert cur.fetchone()[0] == 1
            cur.execute(
                "select relrowsecurity,relforcerowsecurity from pg_class where oid='app.custody_operation_completion_reauth_history'::regclass"
            )
            assert cur.fetchone() == (True, True)
            cur.execute(
                """select count(*) from pg_trigger
                   where tgrelid='app.custody_operation_completion_reauth_history'::regclass
                     and not tgisinternal and tgname in (
                       'custody_operation_completion_reauth_history_no_update_delete',
                       'custody_operation_completion_reauth_history_no_truncate')"""
            )
            assert cur.fetchone()[0] == 2
        assert result["reacquired"] is True
        conn.commit()

        with pytest.raises(psycopg.Error, match="append-only"):
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        "update app.custody_operation_completion_reauth_history set runner_instance_id='tampered' where operation_id=%s",
                        (operation_id,),
                    )
