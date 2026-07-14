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


def _sealed_external_case(
    conn,
    *,
    version_source: str | None = None,
    version_mount: str | None = None,
    object_count: int = 1,
):
    case_id = uuid.uuid4()
    object_ids = [uuid.uuid4() for _ in range(object_count)]
    source, mount = "a" * 64, "b" * 64
    digest, manifest_hash = "sha256:" + "c" * 64, "sha256:" + "d" * 64
    with conn.cursor() as cur:
        cur.execute(
            "insert into app.cases(id,case_key,title,status) "
            "values(%s,%s,'Reconnect case','active')",
            (case_id, "storage-reconnect-" + uuid.uuid4().hex),
        )
        for index, object_id in enumerate(object_ids):
            version_id = uuid.uuid4()
            name = f"external-{index}.raw"
            cur.execute(
                """insert into app.evidence_objects(
                     id,case_id,display_name,display_path,status,seal_status,
                     current_sha256,current_bytes)
                   values(%s,%s,%s,%s,'sealed','sealed',%s,8)""",
                (object_id, case_id, name, f"evidence/{name}", digest),
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
                    mount if version_mount is None else version_mount,
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
               values(%s,1,%s,'sealed',%s,0,'','[]'::jsonb)""",
            (case_id, manifest_hash, object_count),
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
    return case_id, object_ids[0], source, mount


def _set_legacy_posture_recovery_state(
    conn,
    case_id,
    *,
    source: str,
    verified_mount: str,
    observed_mount: str,
    receipt_defect: str | None = None,
) -> list[dict[str, object]]:
    from psycopg.types.json import Jsonb

    with conn.cursor() as cur:
        cur.execute(
            """select o.id::text,v.id::text,v.sha256,v.bytes
               from app.evidence_objects o
               join app.evidence_versions v on v.id=o.current_version_id
               where o.case_id=%s and o.status='sealed'
               order by o.id::text""",
            (case_id,),
        )
        active = cur.fetchall()
        receipt_items = [
            {
                "evidence_object_id": object_id,
                "evidence_version_id": version_id,
                "sha256": digest,
                "bytes": byte_count,
                "storage_profile": "EXTERNALLY_READ_ONLY",
                "storage_source_identity": source,
                "mount_instance_identity": verified_mount,
                "read_only": True,
                "st_nlink": 1,
            }
            for object_id, version_id, digest, byte_count in active
        ]
        if receipt_defect == "incomplete_receipt":
            receipt_items = receipt_items[:-1]
        elif receipt_defect == "item_source":
            receipt_items[0]["storage_source_identity"] = "f" * 64
        elif receipt_defect == "item_version":
            receipt_items[0]["evidence_version_id"] = str(uuid.uuid4())
        elif receipt_defect == "item_sha256":
            receipt_items[0]["sha256"] = "sha256:" + "f" * 64
        elif receipt_defect == "item_bytes":
            receipt_items[0]["bytes"] = 9
        elif receipt_defect == "item_mount":
            receipt_items[0]["mount_instance_identity"] = "f" * 64
        elif receipt_defect == "item_read_only":
            receipt_items[0]["read_only"] = False
        elif receipt_defect == "item_nlink":
            receipt_items[0]["st_nlink"] = 2
        posture = [
            {
                "code": "POSTURE_DRIFT",
                "gate_state": "BLOCKED_VIOLATION",
                "recovery": "RESTORE_READ_ONLY",
                "evidence_object_id": object_id,
                "observation_id": f"legacy-posture-{index}",
                "full_verification_required": True,
                "storage_generation": 2,
            }
            for index, (object_id, *_rest) in enumerate(active)
        ]
        if receipt_defect != "missing_receipt":
            cur.execute(
                """insert into app.evidence_storage_verifications(
                     case_id,generation,profile,source_identity,mount_instance,
                     manifest_version,manifest_hash,item_facts,outcome,correlation_id)
                   values(%s,2,'EXTERNALLY_READ_ONLY',%s,%s,1,%s,%s,
                     'SUCCESS','legacy-success:'||%s)""",
                (
                    case_id,
                    "f" * 64 if receipt_defect == "receipt_source" else source,
                    (
                        "f" * 64
                        if receipt_defect == "receipt_mount"
                        else verified_mount
                    ),
                    (
                        "sha256:" + "f" * 64
                        if receipt_defect == "receipt_manifest"
                        else "sha256:" + "d" * 64
                    ),
                    Jsonb(receipt_items),
                    uuid.uuid4().hex,
                ),
            )
        cur.execute(
            """update app.evidence_chain_heads
               set seal_status='violated',issues=%s where case_id=%s""",
            (Jsonb(posture), case_id),
        )
        cur.execute(
            """update app.evidence_storage_authorities
               set state='FULL_VERIFY_REQUIRED',remediation='FULL_VERIFY',
                 read_only=true,source_identity=%s,
                 verified_mount_instance=%s,observed_mount_instance=%s,
                 generation=2,verified_generation=2
               where case_id=%s""",
            (source, verified_mount, observed_mount, case_id),
        )
    conn.commit()
    return posture


def _classify(
    conn,
    case_id,
    correlation,
    finding,
    *,
    gate_state="BLOCKED_UNAVAILABLE",
):
    from psycopg.types.json import Jsonb

    with conn.cursor() as cur:
        cur.execute(
            """select id from app.evidence_record_inventory_classification_v2(
                 %s,%s,%s,%s)""",
            (
                case_id,
                correlation,
                gate_state,
                Jsonb(finding if isinstance(finding, list) else [finding]),
            ),
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
            "evidence_storage_authorities",
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


def test_same_source_rw_drift_restores_only_to_full_verify_required() -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        case_id, _object_id, source, mount = _sealed_external_case(
            conn, object_count=2
        )
        before_counts = _counts(conn, case_id)
        with conn.cursor() as cur:
            cur.execute(
                """select id::text from app.evidence_objects
                   where case_id=%s and status='sealed' order by id::text""",
                (case_id,),
            )
            active_ids = [row[0] for row in cur.fetchall()]
        posture = [
            {
                "code": "POSTURE_DRIFT",
                "gate_state": "BLOCKED_VIOLATION",
                "recovery": "RESTORE_READ_ONLY",
                "evidence_object_id": object_id,
                "observation_id": f"rw-posture-{index}",
                "full_verification_required": True,
            }
            for index, object_id in enumerate(active_ids)
        ]

        with conn.cursor() as cur:
            cur.execute(
                """select state,remediation,generation,verified_generation
                   from app.evidence_storage_record_observation(
                     %s,'EXTERNALLY_READ_ONLY',true,%s,%s,false)""",
                (case_id, source, mount),
            )
            assert cur.fetchone() == ("READ_WRITE_DRIFT", "RESTORE_READ_ONLY", 2, 2)

        first_rw = _classify(
            conn,
            case_id,
            "rw-first:" + uuid.uuid4().hex,
            posture,
            gate_state="BLOCKED_VIOLATION",
        )
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="persisted_custody_violation_requires_recovery",
        ):
            with conn.transaction():
                _classify(
                    conn,
                    case_id,
                    "rw-partial:" + uuid.uuid4().hex,
                    posture[:1],
                    gate_state="BLOCKED_VIOLATION",
                )
        repeated_rw = _classify(
            conn,
            case_id,
            "rw-repeat:" + uuid.uuid4().hex,
            posture,
            gate_state="BLOCKED_VIOLATION",
        )
        assert repeated_rw != first_rw

        with conn.cursor() as cur:
            cur.execute(
                """select state,remediation,generation,verified_generation
                   from app.evidence_storage_record_observation(
                     %s,'EXTERNALLY_READ_ONLY',true,%s,%s,true)""",
                (case_id, source, mount),
            )
            assert cur.fetchone() == ("FULL_VERIFY_REQUIRED", "FULL_VERIFY", 2, 2)

        first_ro = _classify(
            conn,
            case_id,
            "ro-first:" + uuid.uuid4().hex,
            _full_verify_finding(),
        )
        repeated_ro = _classify(
            conn,
            case_id,
            "ro-repeat:" + uuid.uuid4().hex,
            _full_verify_finding(),
        )
        assert repeated_ro != first_ro
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
                """select state,remediation,read_only,generation,verified_generation,
                          source_identity,verified_mount_instance,observed_mount_instance
                   from app.evidence_storage_authorities where case_id=%s""",
                (case_id,),
            )
            assert cur.fetchone() == (
                "FULL_VERIFY_REQUIRED",
                "FULL_VERIFY",
                True,
                2,
                2,
                source,
                mount,
                mount,
            )
            cur.execute(
                """select gate_state,count(*) from app.evidence_inventory_observations
                   where case_id=%s group by gate_state order by gate_state""",
                (case_id,),
            )
            assert cur.fetchall() == [
                ("BLOCKED_UNAVAILABLE", 2),
                ("BLOCKED_VIOLATION", 2),
            ]


def test_legacy_posture_drift_with_new_stable_mount_enters_full_verify_lane() -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        version_mount = "c" * 64
        observed_mount = "e" * 64
        case_id, _object_id, source, verified_mount = _sealed_external_case(
            conn, version_mount=version_mount, object_count=2
        )
        _set_legacy_posture_recovery_state(
            conn,
            case_id,
            source=source,
            verified_mount=verified_mount,
            observed_mount=observed_mount,
        )
        before_counts = _counts(conn, case_id)

        correlation = "legacy-stable-mount:" + uuid.uuid4().hex
        observation_id = _classify(
            conn,
            case_id,
            correlation,
            _full_verify_finding(),
        )
        assert (
            _classify(conn, case_id, correlation, _full_verify_finding())
            == observation_id
        )

        assert _counts(conn, case_id) == before_counts
        with conn.cursor() as cur:
            cur.execute(
                """select seal_status,issues from app.evidence_chain_heads
                   where case_id=%s""",
                (case_id,),
            )
            assert cur.fetchone() == (
                "violated",
                [{**_full_verify_finding(), "storage_generation": 2}],
            )
            cur.execute(
                """select state,remediation,read_only,source_identity,
                          verified_mount_instance,observed_mount_instance
                   from app.evidence_storage_authorities where case_id=%s""",
                (case_id,),
            )
            assert cur.fetchone() == (
                "FULL_VERIFY_REQUIRED",
                "FULL_VERIFY",
                True,
                source,
                verified_mount,
                observed_mount,
            )
            cur.execute(
                """select count(distinct storage_mount_instance)
                   from app.evidence_versions where case_id=%s""",
                (case_id,),
            )
            assert cur.fetchone() == (1,)
            cur.execute(
                """select storage_mount_instance from app.evidence_versions
                   where case_id=%s limit 1""",
                (case_id,),
            )
            assert cur.fetchone() == (version_mount,)
            cur.execute(
                """select count(*) from app.evidence_inventory_observations
                   where case_id=%s and correlation_id=%s""",
                (case_id, correlation),
            )
            assert cur.fetchone() == (1,)

        with pytest.raises(
            psycopg.errors.UniqueViolation,
            match="inventory_correlation_reused",
        ):
            with conn.transaction():
                _classify(
                    conn,
                    case_id,
                    correlation,
                    _full_verify_finding(),
                    gate_state="BLOCKED_VIOLATION",
                )


def test_stale_legacy_correlation_rolls_back_new_mount_observation() -> None:
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn:
        version_mount = "c" * 64
        first_observed_mount = "e" * 64
        next_observed_mount = "f" * 64
        case_id, _object_id, source, verified_mount = _sealed_external_case(
            conn, version_mount=version_mount, object_count=2
        )
        _set_legacy_posture_recovery_state(
            conn,
            case_id,
            source=source,
            verified_mount=verified_mount,
            observed_mount=first_observed_mount,
        )
        correlation = "legacy-stale:" + uuid.uuid4().hex
        _classify(conn, case_id, correlation, _full_verify_finding())

        with conn.cursor() as cur:
            cur.execute(
                """select o.id::text,v.id::text,v.sha256,v.bytes
                   from app.evidence_objects o
                   join app.evidence_versions v on v.id=o.current_version_id
                   where o.case_id=%s and o.status='sealed'
                   order by o.id::text""",
                (case_id,),
            )
            receipt_items = [
                {
                    "evidence_object_id": object_id,
                    "evidence_version_id": version_id,
                    "sha256": digest,
                    "bytes": byte_count,
                    "storage_profile": "EXTERNALLY_READ_ONLY",
                    "storage_source_identity": source,
                    "mount_instance_identity": first_observed_mount,
                    "read_only": True,
                    "st_nlink": 1,
                }
                for object_id, version_id, digest, byte_count in cur.fetchall()
            ]
            cur.execute(
                """insert into app.evidence_storage_verifications(
                     case_id,generation,profile,source_identity,mount_instance,
                     manifest_version,manifest_hash,item_facts,outcome,correlation_id)
                   values(%s,2,'EXTERNALLY_READ_ONLY',%s,%s,1,%s,%s,
                     'SUCCESS','simulated-full-verify:'||%s)""",
                (
                    case_id,
                    source,
                    first_observed_mount,
                    "sha256:" + "d" * 64,
                    Jsonb(receipt_items),
                    uuid.uuid4().hex,
                ),
            )
            cur.execute(
                """update app.evidence_storage_authorities
                   set state='AVAILABLE',remediation='NONE',read_only=true,
                     verified_mount_instance=%s,observed_mount_instance=%s,
                     last_full_verified_at=now()
                   where case_id=%s""",
                (first_observed_mount, first_observed_mount, case_id),
            )
            cur.execute(
                """update app.evidence_chain_heads
                   set seal_status='sealed',issues='[]'::jsonb where case_id=%s""",
                (case_id,),
            )
        conn.commit()

        with pytest.raises(
            psycopg.errors.UniqueViolation,
            match="inventory_correlation_reused",
        ):
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """select state,remediation from
                             app.evidence_storage_record_observation(
                               %s,'EXTERNALLY_READ_ONLY',true,%s,%s,true)""",
                        (case_id, source, next_observed_mount),
                    )
                    assert cur.fetchone() == (
                        "FULL_VERIFY_REQUIRED",
                        "RECONNECT_AND_VERIFY",
                    )
                _classify(conn, case_id, correlation, _full_verify_finding())

        with conn.cursor() as cur:
            cur.execute(
                """select state,remediation,read_only,source_identity,
                          verified_mount_instance,observed_mount_instance
                   from app.evidence_storage_authorities where case_id=%s""",
                (case_id,),
            )
            assert cur.fetchone() == (
                "AVAILABLE",
                "NONE",
                True,
                source,
                first_observed_mount,
                first_observed_mount,
            )
            cur.execute(
                """select seal_status,issues from app.evidence_chain_heads
                   where case_id=%s""",
                (case_id,),
            )
            assert cur.fetchone() == ("sealed", [])


@pytest.mark.parametrize(
    "defect",
    (
        "missing_receipt",
        "receipt_source",
        "receipt_mount",
        "receipt_manifest",
        "incomplete_receipt",
        "item_source",
        "item_version",
        "item_sha256",
        "item_bytes",
        "item_mount",
        "item_read_only",
        "item_nlink",
        "version_source",
        "storage_source",
        "writable",
        "same_mount",
        "pending",
        "violated_object",
        "non_storage_issue",
        "incomplete_operation",
    ),
)
def test_legacy_mount_transition_rejects_unbound_or_unsafe_state(defect: str) -> None:
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn:
        observed_mount = "e" * 64
        case_id, object_id, source, verified_mount = _sealed_external_case(
            conn,
            version_source="f" * 64 if defect == "version_source" else None,
            version_mount="c" * 64,
            object_count=2,
        )
        posture = _set_legacy_posture_recovery_state(
            conn,
            case_id,
            source=source,
            verified_mount=verified_mount,
            observed_mount=observed_mount,
            receipt_defect=(
                defect
                if defect
                in {
                    "missing_receipt",
                    "receipt_source",
                    "receipt_mount",
                    "receipt_manifest",
                    "incomplete_receipt",
                    "item_source",
                    "item_version",
                    "item_sha256",
                    "item_bytes",
                    "item_mount",
                    "item_read_only",
                    "item_nlink",
                }
                else None
            ),
        )
        with conn.cursor() as cur:
            if defect == "writable":
                cur.execute(
                    """update app.evidence_storage_authorities
                       set read_only=false where case_id=%s""",
                    (case_id,),
                )
            elif defect == "storage_source":
                cur.execute(
                    """update app.evidence_storage_authorities
                       set source_identity=%s where case_id=%s""",
                    ("f" * 64, case_id),
                )
            elif defect == "same_mount":
                cur.execute(
                    """update app.evidence_storage_authorities
                       set observed_mount_instance=verified_mount_instance
                       where case_id=%s""",
                    (case_id,),
                )
            elif defect == "pending":
                cur.execute(
                    """insert into app.evidence_objects(
                         id,case_id,display_name,display_path,status,seal_status)
                       values(%s,%s,'pending.raw','evidence/pending.raw',
                         'detected','unsealed')""",
                    (uuid.uuid4(), case_id),
                )
            elif defect == "violated_object":
                cur.execute(
                    """update app.evidence_objects
                       set status='violated',seal_status='violated' where id=%s""",
                    (object_id,),
                )
            elif defect == "non_storage_issue":
                cur.execute(
                    """update app.evidence_chain_heads set issues=%s
                       where case_id=%s""",
                    (
                        Jsonb(
                            [
                                *posture,
                                {
                                    "code": "CONTENT_CHANGED",
                                    "gate_state": "BLOCKED_VIOLATION",
                                    "recovery": "RESTORE_REACQUIRE_RETIRE",
                                    "evidence_object_id": str(object_id),
                                    "observation_id": None,
                                    "full_verification_required": True,
                                    "storage_generation": 2,
                                },
                            ]
                        ),
                        case_id,
                    ),
                )
            elif defect == "incomplete_operation":
                actor_id, audit_id = uuid.uuid4(), uuid.uuid4()
                cur.execute(
                    """insert into app.operator_profiles(id,display_name,status)
                       values(%s,'Legacy transition operator','active')""",
                    (actor_id,),
                )
                cur.execute(
                    """insert into app.audit_events(
                         id,case_id,event_type,actor_type,actor_user_id,
                         source,status,details)
                       values(%s,%s,'reauth.evidence_seal','user',%s,
                         'portal_reauth','success','{}'::jsonb)""",
                    (audit_id, case_id, actor_id),
                )
                cur.execute(
                    """insert into app.custody_operations(
                         case_id,action,phase,idempotency_key,request_digest,
                         command,reason,reauth_audit_event_id,actor_user_id,
                         runner_instance_id)
                       values(%s,'ADD_SEAL','GATE_BLOCKED',%s,%s,%s,
                         'test pending operation',%s,%s,'test-runner')""",
                    (
                        case_id,
                        "pending-op-" + uuid.uuid4().hex,
                        "sha256:" + "9" * 64,
                        Jsonb(
                            {
                                "schema_version": 1,
                                "action": "ADD_SEAL",
                                "files": [],
                            }
                        ),
                        audit_id,
                        actor_id,
                    ),
                )
        conn.commit()

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
