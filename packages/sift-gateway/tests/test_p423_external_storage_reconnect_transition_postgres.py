from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.integration


def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for migrated-Postgres proof")
    return dsn


def _unavailable_finding() -> dict[str, object]:
    return {
        "code": "STORAGE_UNAVAILABLE",
        "gate_state": "BLOCKED_UNAVAILABLE",
        "recovery": "RECONNECT_AND_VERIFY",
        "evidence_object_id": None,
        "observation_id": None,
        "full_verification_required": False,
    }


def _full_verify_finding() -> dict[str, object]:
    return {
        "code": "STORAGE_FULL_VERIFY_REQUIRED",
        "gate_state": "BLOCKED_UNAVAILABLE",
        "recovery": "FULL_VERIFY_AND_REPAIR",
        "evidence_object_id": None,
        "observation_id": None,
        "full_verification_required": True,
    }


def _sealed_external_case(conn, *, version_source: str | None = None):
    case_id, object_id, version_id = (uuid.uuid4() for _ in range(3))
    source, mount = "a" * 64, "b" * 64
    digest, manifest_hash = "sha256:" + "c" * 64, "sha256:" + "d" * 64
    with conn.cursor() as cur:
        cur.execute(
            "insert into app.cases(id,case_key,title,status) "
            "values(%s,%s,'Reconnect case','active')",
            (case_id, "storage-reconnect-" + uuid.uuid4().hex),
        )
        cur.execute(
            """insert into app.evidence_objects(
                 id,case_id,display_name,display_path,status,seal_status,
                 current_sha256,current_bytes)
               values(%s,%s,'external.raw','evidence/external.raw',
                 'sealed','sealed',%s,8)""",
            (object_id, case_id, digest),
        )
        cur.execute(
            """insert into app.evidence_versions(
                 id,evidence_object_id,case_id,manifest_version,sha256,bytes,
                 entry_status,manifest_hash,storage_profile,
                 storage_source_identity,storage_mount_instance)
               values(%s,%s,%s,1,%s,8,'ACTIVE',%s,
                 'EXTERNALLY_READ_ONLY',%s,%s)""",
            (
                version_id,
                object_id,
                case_id,
                digest,
                manifest_hash,
                source if version_source is None else version_source,
                mount,
            ),
        )
        cur.execute(
            "update app.evidence_objects set current_version_id=%s where id=%s",
            (version_id, object_id),
        )
        cur.execute(
            """insert into app.evidence_chain_heads(
                 case_id,manifest_version,manifest_hash,seal_status,active_count,
                 head_seq,head_hash,issues)
               values(%s,1,%s,'sealed',1,0,'','[]'::jsonb)""",
            (case_id, manifest_hash),
        )
        cur.execute(
            """update app.evidence_storage_authorities
               set profile='EXTERNALLY_READ_ONLY',source_identity=%s,
                 verified_mount_instance=%s,observed_mount_instance=%s,
                 state='AVAILABLE',generation=2,verified_generation=2,
                 read_only=true,remediation='NONE'
               where case_id=%s""",
            (source, mount, mount, case_id),
        )
    conn.commit()
    return case_id, object_id, source, mount


def _classify(conn, case_id, correlation, finding):
    from psycopg.types.json import Jsonb

    with conn.cursor() as cur:
        cur.execute(
            """select id from app.evidence_record_inventory_classification_v2(
                 %s,%s,'BLOCKED_UNAVAILABLE',%s)""",
            (case_id, correlation, Jsonb([finding])),
        )
        return cur.fetchone()[0]


def _latch_unavailable(conn, case_id):
    with conn.cursor() as cur:
        cur.execute(
            """select state,remediation from app.evidence_storage_record_observation(
                 %s,'EXTERNALLY_READ_ONLY',false,null,null,null)""",
            (case_id,),
        )
        assert cur.fetchone() == ("UNAVAILABLE", "RECONNECT_AND_VERIFY")
    _classify(conn, case_id, "unavailable:" + uuid.uuid4().hex, _unavailable_finding())


def _counts(conn, case_id):
    with conn.cursor() as cur:
        counts = []
        for table in (
            "evidence_versions",
            "evidence_manifests",
            "evidence_custody_events",
            "evidence_storage_verifications",
        ):
            cur.execute(f"select count(*) from app.{table} where case_id=%s", (case_id,))
            counts.append(cur.fetchone()[0])
    return tuple(counts)


def test_same_source_read_only_reconnect_advances_only_to_full_verify() -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        case_id, _object_id, source, _mount = _sealed_external_case(conn)
        _latch_unavailable(conn, case_id)
        before_counts = _counts(conn, case_id)
        new_mount = "e" * 64
        with conn.cursor() as cur:
            cur.execute(
                """select state,remediation,generation,verified_generation
                   from app.evidence_storage_record_observation(
                     %s,'EXTERNALLY_READ_ONLY',true,%s,%s,true)""",
                (case_id, source, new_mount),
            )
            assert cur.fetchone() == ("FULL_VERIFY_REQUIRED", "FULL_VERIFY", 2, 2)
        correlation = "reconnect:" + uuid.uuid4().hex
        observation_id = _classify(
            conn, case_id, correlation, _full_verify_finding()
        )
        assert _classify(conn, case_id, correlation, _full_verify_finding()) == observation_id
        assert _counts(conn, case_id) == before_counts
        with conn.cursor() as cur:
            cur.execute(
                """select seal_status,issues from app.evidence_chain_heads
                   where case_id=%s""",
                (case_id,),
            )
            seal_status, issues = cur.fetchone()
            assert seal_status == "violated"
            assert issues == [{**_full_verify_finding(), "storage_generation": 2}]
            cur.execute(
                """select profile,source_identity,verified_mount_instance,
                     observed_mount_instance,state,generation,verified_generation,
                     read_only,remediation
                   from app.evidence_storage_authorities where case_id=%s""",
                (case_id,),
            )
            assert cur.fetchone() == (
                "EXTERNALLY_READ_ONLY",
                source,
                "b" * 64,
                new_mount,
                "FULL_VERIFY_REQUIRED",
                2,
                2,
                True,
                "FULL_VERIFY",
            )
            cur.execute(
                """select count(*) from app.evidence_inventory_observations
                   where case_id=%s""",
                (case_id,),
            )
            assert cur.fetchone() == (2,)


@pytest.mark.parametrize(
    "defect",
    ("object", "generation", "cause", "writable", "version_source", "pending"),
)
def test_noncausal_or_unsafe_reconnect_stays_fail_closed(defect) -> None:
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn:
        case_id, object_id, source, _mount = _sealed_external_case(
            conn,
            version_source="f" * 64 if defect == "version_source" else None,
        )
        _latch_unavailable(conn, case_id)
        with conn.cursor() as cur:
            cur.execute(
                """select app.evidence_storage_record_observation(
                     %s,'EXTERNALLY_READ_ONLY',true,%s,%s,true)""",
                (case_id, source, "e" * 64),
            )
            if defect == "object":
                cur.execute(
                    "update app.evidence_objects set status='violated' where id=%s",
                    (object_id,),
                )
            elif defect == "generation":
                cur.execute(
                    "update app.evidence_storage_authorities set generation=3 where case_id=%s",
                    (case_id,),
                )
            elif defect == "cause":
                content = {
                    "code": "CONTENT_CHANGED",
                    "gate_state": "BLOCKED_VIOLATION",
                    "recovery": "RESTORE_REACQUIRE_RETIRE",
                    "evidence_object_id": str(object_id),
                    "observation_id": None,
                    "full_verification_required": True,
                    "storage_generation": 2,
                }
                cur.execute(
                    "update app.evidence_chain_heads set issues=%s where case_id=%s",
                    (Jsonb([content]), case_id),
                )
            elif defect == "pending":
                cur.execute(
                    """insert into app.evidence_objects(
                         id,case_id,display_name,display_path,status,seal_status)
                       values(%s,%s,'pending.raw','evidence/pending.raw',
                         'detected','unsealed')""",
                    (uuid.uuid4(), case_id),
                )
            else:
                cur.execute(
                    """update app.evidence_storage_authorities
                       set state='READ_WRITE_DRIFT',read_only=false,
                         remediation='RESTORE_READ_ONLY' where case_id=%s""",
                    (case_id,),
                )
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="persisted_custody_violation_requires_recovery",
        ):
            with conn.transaction():
                _classify(
                    conn,
                    case_id,
                    defect + ":" + uuid.uuid4().hex,
                    _full_verify_finding(),
                )
