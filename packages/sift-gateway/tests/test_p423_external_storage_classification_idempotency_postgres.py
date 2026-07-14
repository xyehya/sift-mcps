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


def _sealed_external_case(conn):
    case_id, object_id, version_id = (uuid.uuid4() for _ in range(3))
    source, mount = "a" * 64, "b" * 64
    digest, manifest_hash = "sha256:" + "c" * 64, "sha256:" + "d" * 64
    with conn.cursor() as cur:
        cur.execute(
            "insert into app.cases(id,case_key,title,status) "
            "values(%s,%s,'Storage repeat case','active')",
            (case_id, "storage-repeat-" + uuid.uuid4().hex),
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
            (version_id, object_id, case_id, digest, manifest_hash, source, mount),
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
    return case_id, object_id


def _classify_unavailable(conn, case_id, correlation, *, findings=None):
    from psycopg.types.json import Jsonb

    with conn.cursor() as cur:
        cur.execute(
            """select id from app.evidence_record_inventory_classification_v2(
                 %s,%s,'BLOCKED_UNAVAILABLE',%s)""",
            (
                case_id,
                correlation,
                Jsonb([_unavailable_finding()] if findings is None else findings),
            ),
        )
        return cur.fetchone()[0]


def _first_unavailable(conn, case_id):
    with conn.cursor() as cur:
        cur.execute(
            """select state,remediation from app.evidence_storage_record_observation(
                 %s,'EXTERNALLY_READ_ONLY',false,null,null,null)""",
            (case_id,),
        )
        assert cur.fetchone() == ("UNAVAILABLE", "RECONNECT_AND_VERIFY")
    return _classify_unavailable(conn, case_id, "unavailable:" + uuid.uuid4().hex)


def _authority_snapshot(conn, case_id):
    with conn.cursor() as cur:
        cur.execute(
            """select manifest_version,manifest_hash,seal_status,active_count,
                 head_seq,head_hash,issues from app.evidence_chain_heads
               where case_id=%s""",
            (case_id,),
        )
        head = cur.fetchone()
        cur.execute(
            """select profile,source_identity,verified_mount_instance,
                 observed_mount_instance,state,generation,verified_generation,
                 read_only,last_full_verified_at,remediation
               from app.evidence_storage_authorities where case_id=%s""",
            (case_id,),
        )
        storage = cur.fetchone()
        counts = []
        for table in (
            "evidence_versions",
            "evidence_manifests",
            "evidence_custody_events",
            "evidence_storage_verifications",
        ):
            cur.execute(
                f"select count(*) from app.{table} where case_id=%s", (case_id,)
            )
            counts.append(cur.fetchone()[0])
    return head, storage, tuple(counts)


def test_repeated_current_generation_unavailable_is_append_only_and_idempotent() -> (
    None
):
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        case_id, _object_id = _sealed_external_case(conn)
        first_id = _first_unavailable(conn, case_id)
        before = _authority_snapshot(conn, case_id)
        repeat_correlation = "unavailable:" + uuid.uuid4().hex
        repeat_id = _classify_unavailable(conn, case_id, repeat_correlation)
        assert repeat_id != first_id
        assert _classify_unavailable(conn, case_id, repeat_correlation) == repeat_id
        assert _authority_snapshot(conn, case_id) == before
        with conn.cursor() as cur:
            cur.execute(
                """select seal_status,issues from app.evidence_chain_heads
                   where case_id=%s""",
                (case_id,),
            )
            seal_status, issues = cur.fetchone()
            assert seal_status == "violated"
            assert issues == [{**_unavailable_finding(), "storage_generation": 2}]
            cur.execute(
                """select state,remediation,generation,verified_generation
                   from app.evidence_storage_authorities where case_id=%s""",
                (case_id,),
            )
            assert cur.fetchone() == (
                "UNAVAILABLE",
                "RECONNECT_AND_VERIFY",
                2,
                2,
            )
            cur.execute(
                """select count(*) from app.evidence_inventory_observations
                   where case_id=%s""",
                (case_id,),
            )
            assert cur.fetchone() == (2,)


def test_repeat_rejects_conflicting_correlation_payload() -> None:
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn:
        case_id, _object_id = _sealed_external_case(conn)
        _first_unavailable(conn, case_id)
        correlation = "conflict:" + uuid.uuid4().hex
        with conn.cursor() as cur:
            cur.execute(
                """insert into app.evidence_inventory_observations(
                     case_id,correlation_id,gate_state,findings)
                   values(%s,%s,'OPEN',%s)""",
                (case_id, correlation, Jsonb([])),
            )
        with pytest.raises(
            psycopg.errors.UniqueViolation,
            match="inventory_correlation_reused",
        ):
            with conn.transaction():
                _classify_unavailable(conn, case_id, correlation)


def test_object_violation_still_requires_persisted_recovery_marker() -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        case_id, object_id = _sealed_external_case(conn)
        _first_unavailable(conn, case_id)
        with conn.cursor() as cur:
            cur.execute(
                """update app.evidence_objects
                   set status='violated',seal_status='violated' where id=%s""",
                (object_id,),
            )
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="persisted_custody_violation_requires_recovery",
        ):
            with conn.transaction():
                _classify_unavailable(conn, case_id, "object:" + uuid.uuid4().hex)


def test_nonstorage_head_cause_and_stale_generation_do_not_use_repeat_lane() -> None:
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    for defect in ("head", "generation"):
        with psycopg.connect(_dsn()) as conn:
            case_id, _object_id = _sealed_external_case(conn)
            _first_unavailable(conn, case_id)
            with conn.cursor() as cur:
                if defect == "head":
                    content = {
                        "code": "CONTENT_CHANGED",
                        "gate_state": "BLOCKED_VIOLATION",
                        "recovery": "RESTORE_REACQUIRE_RETIRE",
                        "evidence_object_id": None,
                        "observation_id": None,
                        "full_verification_required": True,
                    }
                    cur.execute(
                        """update app.evidence_chain_heads
                           set issues=issues||%s where case_id=%s""",
                        (Jsonb([content]), case_id),
                    )
                else:
                    cur.execute(
                        """update app.evidence_storage_authorities
                           set generation=3 where case_id=%s""",
                        (case_id,),
                    )
            with pytest.raises(
                psycopg.errors.ObjectNotInPrerequisiteState,
                match="persisted_custody_violation_requires_recovery",
            ):
                with conn.transaction():
                    _classify_unavailable(
                        conn,
                        case_id,
                        defect + ":" + uuid.uuid4().hex,
                    )


@pytest.mark.parametrize(
    ("column", "value"),
    (("state", "FULL_VERIFY_REQUIRED"), ("remediation", "FULL_VERIFY")),
)
def test_wrong_storage_state_or_remediation_does_not_use_repeat_lane(
    column, value
) -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        case_id, _object_id = _sealed_external_case(conn)
        _first_unavailable(conn, case_id)
        with conn.cursor() as cur:
            cur.execute(
                f"update app.evidence_storage_authorities set {column}=%s "
                "where case_id=%s",
                (value, case_id),
            )
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="persisted_custody_violation_requires_recovery",
        ):
            with conn.transaction():
                _classify_unavailable(conn, case_id, column + ":" + uuid.uuid4().hex)


@pytest.mark.parametrize("payload", ("changed", "extra"))
def test_changed_or_extra_finding_does_not_use_repeat_lane(payload) -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        case_id, _object_id = _sealed_external_case(conn)
        _first_unavailable(conn, case_id)
        finding = _unavailable_finding()
        findings = [finding]
        if payload == "changed":
            finding["recovery"] = "INVESTIGATE_AVAILABILITY"
        else:
            findings.append(dict(finding))
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="persisted_custody_violation_requires_recovery",
        ):
            with conn.transaction():
                _classify_unavailable(
                    conn,
                    case_id,
                    payload + ":" + uuid.uuid4().hex,
                    findings=findings,
                )
