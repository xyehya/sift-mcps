from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.integration


def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for migrated-Postgres drift proof")
    return dsn


def _case_and_actor(conn):
    case_id, actor_id = uuid.uuid4(), uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "insert into app.operator_profiles(id,display_name,status) values(%s,'P423 drift operator','active')",
            (actor_id,),
        )
        cur.execute(
            "insert into app.cases(id,case_key,title,status) values(%s,%s,'P423 drift case','active')",
            (case_id, "p423-drift-" + uuid.uuid4().hex),
        )
    return case_id, actor_id


def _reauth(conn, *, case_id, actor_id, event_type, binding):
    from psycopg.types.json import Jsonb

    audit_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            """insert into app.audit_events
               (id,case_id,event_type,actor_type,actor_user_id,source,status,details)
               values(%s,%s,%s,'user',%s,'portal_reauth','success',%s)""",
            (audit_id, case_id, event_type, actor_id, Jsonb({"binding": binding})),
        )
    return audit_id


def _begin(conn, *, case_id, actor_id, object_id, action, status, seal_status):
    from psycopg.types.json import Jsonb

    key = action.lower() + "-" + uuid.uuid4().hex
    reason = "migrated Postgres disposition proof"
    command = {"schema_version": 2, "action": action, "evidence_object_id": str(object_id)}
    binding = {
        "action": action,
        "evidence_object_id": str(object_id),
        "idempotency_key": key,
        "reason": reason,
    }
    audit_id = _reauth(
        conn,
        case_id=case_id,
        actor_id=actor_id,
        event_type={
            "IGNORE": "reauth.evidence_ignore",
            "DELETE_STRAY": "reauth.evidence_delete",
            "RETIRE": "reauth.evidence_retire",
        }[action],
        binding=binding,
    )
    with conn.cursor() as cur:
        cur.execute(
            """insert into app.evidence_objects
               (id,case_id,display_name,display_path,status,seal_status)
               values(%s,%s,'item.bin',%s,%s,%s)""",
            (object_id, case_id, f"evidence/{object_id}.bin", status, seal_status),
        )
        cur.execute(
            """select id from app.custody_operation_begin_or_resume(
               %s,%s,%s,%s,%s,%s,%s,%s,null,'runner-before',null)""",
            (
                case_id,
                action,
                Jsonb(command),
                "sha256:" + "d" * 64,
                reason,
                audit_id,
                key,
                actor_id,
            ),
        )
        operation_id = cur.fetchone()[0]
    return operation_id, key, reason


def test_inventory_classification_rls_validation_and_exact_replay():
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        case_id, _actor_id = _case_and_actor(conn)
        correlation = "portal-" + uuid.uuid4().hex
        finding = {
            "code": "DETECTED_NEW_ITEM",
            "gate_state": "BLOCKED_PENDING",
            "recovery": "OPERATOR_DISPOSITION",
            "evidence_object_id": None,
            "observation_id": "observation-1",
            "full_verification_required": False,
        }
        with conn.cursor() as cur:
            cur.execute(
                "select relrowsecurity,relforcerowsecurity from pg_class where oid='app.evidence_inventory_observations'::regclass"
            )
            assert cur.fetchone() == (True, True)
            for role in ("public", "anon", "authenticated"):
                cur.execute(
                    "select has_table_privilege(%s,'app.evidence_inventory_observations','SELECT')",
                    (role,),
                )
                assert cur.fetchone()[0] is False
            cur.execute(
                "select id from app.evidence_record_inventory_classification(%s,%s,'BLOCKED_PENDING',%s)",
                (case_id, correlation, Jsonb([finding])),
            )
            observation_id = cur.fetchone()[0]
            cur.execute(
                "select id from app.evidence_record_inventory_classification(%s,%s,'BLOCKED_PENDING',%s)",
                (case_id, correlation, Jsonb([finding])),
            )
            assert cur.fetchone()[0] == observation_id
            cur.execute("savepoint malformed")
            malformed = {**finding, "recovery": "ARBITRARY"}
            with pytest.raises(psycopg.errors.InvalidParameterValue):
                cur.execute(
                    "select app.evidence_record_inventory_classification(%s,%s,'OPEN',%s)",
                    (case_id, "bad-" + uuid.uuid4().hex, Jsonb([malformed])),
                )
            cur.execute("rollback to savepoint malformed")
            cur.execute("savepoint replay")
            with pytest.raises(psycopg.errors.UniqueViolation):
                cur.execute(
                    "select app.evidence_record_inventory_classification(%s,%s,'BLOCKED_PENDING',%s)",
                    (case_id, correlation, Jsonb([{**finding, "observation_id": "other"}])),
                )
            cur.execute("rollback to savepoint replay")
        conn.rollback()


def test_delete_post_unlink_resume_preserves_facts_and_commits_one_event():
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        case_id, actor_id = _case_and_actor(conn)
        object_id = uuid.uuid4()
        operation_id, _key, _reason = _begin(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            object_id=object_id,
            action="DELETE_STRAY",
            status="detected",
            seal_status="unsealed",
        )
        item = {
            "evidence_object_id": str(object_id),
            "display_path": f"evidence/{object_id}.bin",
            "prior_status": "detected",
            "prior_seal_status": "unsealed",
            "present": True,
            "sha256": "sha256:" + "a" * 64,
            "bytes": 4096,
            "st_dev": 10,
            "st_ino": 20,
            "st_nlink": 1,
        }
        with conn.cursor() as cur:
            cur.execute(
                "select phase from app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'runner-before')",
                (operation_id, Jsonb({"item": item})),
            )
            cur.execute(
                "select phase from app.custody_operation_fail(%s,'FILESYSTEM_APPLYING','process_interrupted','runner-before')",
                (operation_id,),
            )
        resume_id = _reauth(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            event_type="reauth.evidence_delete_resume",
            binding={"operation_id": str(operation_id)},
        )
        with conn.cursor() as cur:
            cur.execute(
                "select phase,prepared_facts from app.custody_operation_resume_disposition(%s,%s,%s,'runner-after')",
                (operation_id, actor_id, resume_id),
            )
            phase, prepared = cur.fetchone()
            assert phase == "FILESYSTEM_APPLYING"
            assert prepared["item"] == item
            verified = {**item, "file_removed": True}
            cur.execute(
                "select phase from app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'runner-after')",
                (operation_id, Jsonb({"item": verified})),
            )
            cur.execute(
                "select phase from app.custody_operation_commit_verified_disposition(%s,%s,'examiner','runner-after')",
                (operation_id, Jsonb(verified)),
            )
            assert cur.fetchone()[0] == "COMPLETED"
            cur.execute(
                "select phase from app.custody_operation_commit_verified_disposition(%s,%s,'examiner','runner-after')",
                (operation_id, Jsonb(verified)),
            )
            assert cur.fetchone()[0] == "COMPLETED"
            cur.execute(
                """select count(*),min(details->>'disposition')
                   from app.evidence_custody_events where custody_operation_id=%s""",
                (operation_id,),
            )
            assert cur.fetchone() == (1, "DELETE_STRAY")
        conn.rollback()


def test_delete_missing_or_unsubstantiated_facts_are_rejected():
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        case_id, actor_id = _case_and_actor(conn)
        object_id = uuid.uuid4()
        operation_id, *_ = _begin(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            object_id=object_id,
            action="DELETE_STRAY",
            status="detected",
            seal_status="unsealed",
        )
        item = {
            "evidence_object_id": str(object_id),
            "display_path": f"evidence/{object_id}.bin",
            "prior_status": "detected",
            "prior_seal_status": "unsealed",
            "present": False,
            "file_removed": False,
        }
        with conn.cursor() as cur:
            cur.execute(
                "select app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'runner-before')",
                (operation_id, Jsonb({"item": item})),
            )
            cur.execute(
                "select app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'runner-before')",
                (operation_id, Jsonb({"item": item})),
            )
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
                cur.execute(
                    "select app.custody_operation_commit_verified_disposition(%s,%s,'examiner','runner-before')",
                    (operation_id, Jsonb(item)),
                )
        conn.rollback()


def test_retire_creates_one_excluding_manifest_and_preserves_versions():
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        case_id, actor_id = _case_and_actor(conn)
        retired_id, sibling_id = uuid.uuid4(), uuid.uuid4()
        operation_id, *_ = _begin(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            object_id=retired_id,
            action="RETIRE",
            status="sealed",
            seal_status="sealed",
        )
        with conn.cursor() as cur:
            cur.execute(
                """insert into app.evidence_objects
                   (id,case_id,display_name,display_path,status,seal_status)
                   values(%s,%s,'sibling.bin',%s,'sealed','sealed')""",
                (sibling_id, case_id, f"evidence/{sibling_id}.bin"),
            )
            version_ids = [uuid.uuid4(), uuid.uuid4()]
            for object_id, version_id, digest in (
                (retired_id, version_ids[0], "b"),
                (sibling_id, version_ids[1], "c"),
            ):
                cur.execute(
                    """insert into app.evidence_versions
                       (id,evidence_object_id,case_id,manifest_version,sha256,bytes,entry_status)
                       values(%s,%s,%s,1,%s,100,'ACTIVE')""",
                    (version_id, object_id, case_id, "sha256:" + digest * 64),
                )
                cur.execute(
                    """update app.evidence_objects set current_version_id=%s,
                       current_sha256=%s,current_bytes=100 where id=%s""",
                    (version_id, "sha256:" + digest * 64, object_id),
                )
            cur.execute(
                """insert into app.evidence_chain_heads(case_id,manifest_version,manifest_hash,
                   seal_status,active_count) values(%s,1,%s,'sealed',2)
                   on conflict(case_id) do update set manifest_version=1,manifest_hash=excluded.manifest_hash,
                     seal_status='sealed',active_count=2""",
                (case_id, "sha256:" + "f" * 64),
            )
            item = {
                "evidence_object_id": str(retired_id),
                "display_path": f"evidence/{retired_id}.bin",
                "prior_status": "sealed",
                "prior_seal_status": "sealed",
                "original_version_id": str(version_ids[0]),
                "original_sha256": "sha256:" + "b" * 64,
                "original_bytes": 100,
                "present": True,
                "sha256": "sha256:" + "b" * 64,
                "bytes": 100,
                "file_removed": False,
            }
            cur.execute(
                "select app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'runner-before')",
                (operation_id, Jsonb({"item": item})),
            )
            cur.execute(
                "select app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'runner-before')",
                (operation_id, Jsonb({"item": item})),
            )
            cur.execute(
                "select phase from app.custody_operation_commit_verified_disposition(%s,%s,'examiner','runner-before')",
                (operation_id, Jsonb(item)),
            )
            assert cur.fetchone()[0] == "COMPLETED"
            cur.execute(
                "select item_facts from app.evidence_manifests where operation_id=%s",
                (operation_id,),
            )
            facts = cur.fetchone()[0]
            assert [entry["evidence_object_id"] for entry in facts] == [str(sibling_id)]
            cur.execute(
                "select count(*) from app.evidence_versions where id=any(%s)",
                (version_ids,),
            )
            assert cur.fetchone()[0] == 2
            cur.execute(
                "select status,current_version_id from app.evidence_objects where id=%s",
                (retired_id,),
            )
            assert cur.fetchone() == ("retired", version_ids[0])
        conn.rollback()
