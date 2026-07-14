from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration
MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "supabase"
    / "migrations"
    / "202607145600_external_bootstrap_detected_bytes.sql"
)


def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for migrated-Postgres proof")
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


def _virgin_external(conn, *, paths=("evidence/alpha.raw", "evidence/beta.raw")):
    from psycopg.types.json import Jsonb

    case_id, actor_id = uuid.uuid4(), uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "insert into app.operator_profiles(id,display_name,status) values(%s,'External bootstrap operator','active')",
            (actor_id,),
        )
        cur.execute(
            "insert into app.cases(id,case_key,title,status) values(%s,%s,'External bootstrap case','active')",
            (case_id, "p423-external-bootstrap-" + uuid.uuid4().hex),
        )
    profile_key = "profile-" + uuid.uuid4().hex
    profile_reason = "authorize virgin external read-only intake"
    profile_binding = {
        "profile": "EXTERNALLY_READ_ONLY",
        "reason": profile_reason,
        "idempotency_key": profile_key,
    }
    profile_reauth = _audit(
        conn,
        case_id=case_id,
        actor_id=actor_id,
        event_type="reauth.evidence_storage_profile_change",
        binding=profile_binding,
    )
    source, mount = "a" * 64, "b" * 64
    object_ids = []
    with conn.cursor() as cur:
        cur.execute(
            "select app.evidence_storage_change_profile(%s,%s,%s,%s,%s,%s)",
            (
                case_id,
                "EXTERNALLY_READ_ONLY",
                profile_reason,
                profile_key,
                profile_reauth,
                actor_id,
            ),
        )
        for path in paths:
            cur.execute(
                "select app.evidence_detect(%s,%s,%s,%s,null,null)",
                (case_id, path, Path(path).name, 4096),
            )
            object_ids.append(cur.fetchone()[0])
        cur.execute(
            """select state from app.evidence_storage_record_observation(
                 %s,'EXTERNALLY_READ_ONLY',true,%s,%s,true)""",
            (case_id, source, mount),
        )
        assert cur.fetchone() == ("FULL_VERIFY_REQUIRED",)
        findings = [{
            "code": "STORAGE_FULL_VERIFY_REQUIRED",
            "gate_state": "BLOCKED_UNAVAILABLE",
            "recovery": "FULL_VERIFY_AND_REPAIR",
            "evidence_object_id": None,
            "observation_id": None,
            "full_verification_required": True,
        }, {
            "code": "PERSISTED_VIOLATION",
            "gate_state": "BLOCKED_VIOLATION",
            "recovery": "RESTORE_REACQUIRE_RETIRE",
            "evidence_object_id": None,
            "observation_id": None,
            "full_verification_required": False,
        }]
        cur.execute(
            "select app.evidence_record_inventory_classification_v2(%s,%s,%s,%s)",
            (
                case_id,
                "bootstrap-" + uuid.uuid4().hex,
                "BLOCKED_UNAVAILABLE",
                Jsonb(findings),
            ),
        )
    return case_id, actor_id, object_ids, tuple(paths), source, mount


def _seal_command(conn, *, case_id, actor_id, paths):
    key = "seal-" + uuid.uuid4().hex
    reason = "establish first external custody manifest"
    command = {
        "schema_version": 3,
        "action": "ADD_SEAL",
        "storage_profile": "EXTERNALLY_READ_ONLY",
        "files": [
            {"path": path, "description": "external evidence", "source": "operator mount"}
            for path in paths
        ],
    }
    receipt = _audit(
        conn,
        case_id=case_id,
        actor_id=actor_id,
        event_type="reauth.evidence_seal",
        binding={
            "idempotency_key": key,
            "reason": reason,
            "storage_profile": "EXTERNALLY_READ_ONLY",
            "targets": sorted(paths),
        },
    )
    return command, reason, key, receipt


def _verified_items(*, object_ids, paths, source, mount):
    return [
        {
            "evidence_object_id": str(object_id),
            "path": path,
            "display_path": path,
            "display_name": Path(path).name,
            "description": "external evidence",
            "source": "operator mount",
            "sha256": "sha256:" + f"{index + 1:064x}",
            "bytes": 4096,
            "storage_profile": "EXTERNALLY_READ_ONLY",
            "storage_source_identity": source,
            "mount_instance_identity": mount,
            "read_only": True,
            "st_dev": 10,
            "st_ino": 100 + index,
            "st_mtime_ns": 1000 + index,
            "st_ctime_ns": 2000 + index,
            "st_nlink": 1,
        }
        for index, (object_id, path) in enumerate(zip(object_ids, paths, strict=True))
    ]


def test_virgin_external_bootstrap_reaches_existing_atomic_v3_finalizer_once():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn:
        case_id, actor_id, object_ids, paths, source, mount = _virgin_external(conn)
        command, reason, key, receipt = _seal_command(
            conn, case_id=case_id, actor_id=actor_id, paths=paths
        )
        items = _verified_items(
            object_ids=object_ids, paths=paths, source=source, mount=mount
        )
        with conn.cursor() as cur:
            cur.execute(
                "select seal_status,manifest_version,manifest_hash,active_count,issues from app.evidence_chain_heads where case_id=%s",
                (case_id,),
            )
            head = cur.fetchone()
            assert head[0:4] == ("unsealed", 0, None, 0)
            assert {issue["code"] for issue in head[4]} == {
                "STORAGE_PROFILE_CHANGED",
                "STORAGE_FULL_VERIFY_REQUIRED",
            }
            cur.execute(
                "select state,verified_generation from app.evidence_storage_authorities where case_id=%s",
                (case_id,),
            )
            assert cur.fetchone() == ("FULL_VERIFY_REQUIRED", None)
            cur.execute(
                """select id from app.custody_operation_begin_or_resume_storage_v3(
                     %s,%s,%s,%s,%s,%s,%s,'bootstrap-runner',null)""",
                (
                    case_id,
                    Jsonb(command),
                    "sha256:" + "c" * 64,
                    reason,
                    receipt,
                    key,
                    actor_id,
                ),
            )
            operation_id = cur.fetchone()[0]
            cur.execute(
                "select phase from app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'bootstrap-runner')",
                (operation_id, Jsonb({"items": items})),
            )
            assert cur.fetchone() == ("FILESYSTEM_APPLYING",)
            cur.execute(
                "select phase from app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'bootstrap-runner')",
                (operation_id, Jsonb({"items": items})),
            )
            assert cur.fetchone() == ("FILESYSTEM_VERIFIED",)
            cur.execute(
                "select phase from app.custody_operation_commit_verified_seal_storage_v3(%s,%s,'examiner','bootstrap-runner')",
                (operation_id, Jsonb(items)),
            )
            assert cur.fetchone() == ("COMPLETED",)
            cur.execute(
                "select seal_status,manifest_version,active_count,issues from app.evidence_chain_heads where case_id=%s",
                (case_id,),
            )
            assert cur.fetchone() == ("sealed", 1, len(paths), [])
            cur.execute(
                "select state,generation,verified_generation,source_identity,verified_mount_instance from app.evidence_storage_authorities where case_id=%s",
                (case_id,),
            )
            state = cur.fetchone()
            assert state[0] == "AVAILABLE"
            assert state[1] == state[2]
            assert state[3:] == (source, mount)
            cur.execute(
                "select count(*) from app.evidence_manifests where case_id=%s",
                (case_id,),
            )
            assert cur.fetchone() == (1,)
            cur.execute(
                "select count(*) from app.evidence_versions where case_id=%s",
                (case_id,),
            )
            assert cur.fetchone() == (len(paths),)
            cur.execute(
                "select count(*) from app.evidence_storage_verifications where case_id=%s and outcome='SUCCESS'",
                (case_id,),
            )
            assert cur.fetchone() == (1,)
            cur.execute(
                "select phase from app.custody_operation_commit_verified_seal_storage_v3(%s,%s,'examiner','bootstrap-runner')",
                (operation_id, Jsonb(items)),
            )
            assert cur.fetchone() == ("COMPLETED",)
            cur.execute(
                "select count(*) from app.evidence_manifests where case_id=%s",
                (case_id,),
            )
            assert cur.fetchone() == (1,)


def test_virgin_external_bootstrap_rejects_partial_target_set_before_operation():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn:
        case_id, actor_id, _object_ids, paths, _source, _mount = _virgin_external(conn)
        command, reason, key, receipt = _seal_command(
            conn, case_id=case_id, actor_id=actor_id, paths=paths[:1]
        )
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        "select app.custody_operation_begin_or_resume_storage_v3(%s,%s,%s,%s,%s,%s,%s,'partial-runner',null)",
                        (
                            case_id,
                            Jsonb(command),
                            "sha256:" + "d" * 64,
                            reason,
                            receipt,
                            key,
                            actor_id,
                        ),
                    )
        with conn.cursor() as cur:
            cur.execute(
                "select count(*) from app.custody_operations where case_id=%s",
                (case_id,),
            )
            assert cur.fetchone() == (0,)


def _append_persisted_latch(cur, case_id):
    from psycopg.types.json import Jsonb

    cur.execute(
        "select issues from app.evidence_chain_heads where case_id=%s", (case_id,)
    )
    issues = cur.fetchone()[0]
    issues.append(
        {
            "code": "PERSISTED_VIOLATION",
            "gate_state": "BLOCKED_VIOLATION",
            "recovery": "RESTORE_REACQUIRE_RETIRE",
            "evidence_object_id": None,
            "observation_id": None,
            "full_verification_required": False,
        }
    )
    cur.execute(
        "update app.evidence_chain_heads set seal_status='violated',issues=%s where case_id=%s",
        (Jsonb(issues), case_id),
    )


def _append_only_counts(cur, case_id):
    cur.execute(
        """select
             (select count(*) from app.evidence_inventory_observations where case_id=%s),
             (select count(*) from app.evidence_custody_events where case_id=%s),
             (select count(*) from app.evidence_storage_verifications where case_id=%s)""",
        (case_id, case_id, case_id),
    )
    return cur.fetchone()


def _success_count(cur, case_id):
    cur.execute(
        "select count(*) from app.evidence_storage_verifications where case_id=%s and outcome='SUCCESS'",
        (case_id,),
    )
    return cur.fetchone()[0]


def test_backfill_repairs_only_projection_and_synthetic_latch():
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        cur.execute("savepoint external_bootstrap_backfill")
        case_id, *_rest = _virgin_external(conn)
        _append_persisted_latch(cur, case_id)
        before = _append_only_counts(cur, case_id)

        cur.execute(MIGRATION.read_text(encoding="utf-8"))

        cur.execute(
            "select seal_status,issues from app.evidence_chain_heads where case_id=%s",
            (case_id,),
        )
        seal_status, issues = cur.fetchone()
        assert seal_status == "unsealed"
        assert {issue["code"] for issue in issues} == {
            "STORAGE_PROFILE_CHANGED",
            "STORAGE_FULL_VERIFY_REQUIRED"
        }
        assert _append_only_counts(cur, case_id) == before
        cur.execute("rollback to savepoint external_bootstrap_backfill")


@pytest.mark.parametrize(
    "poison",
    ("prior_manifest", "prior_source", "violated_object", "unsafe_cause", "unsafe_pending", "stale_generation", "successful_verification"),
)
def test_backfill_never_repairs_nonvirgin_or_unsafe_head(poison):
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        cur.execute("savepoint external_bootstrap_negative")
        case_id, actor_id, object_ids, paths, _source, _mount = _virgin_external(conn)
        _append_persisted_latch(cur, case_id)
        if poison == "prior_manifest":
            cur.execute(
                "update app.evidence_chain_heads set manifest_version=1,manifest_hash=%s where case_id=%s",
                ("sha256:" + "e" * 64, case_id),
            )
        elif poison == "prior_source":
            cur.execute(
                "update app.evidence_storage_authorities set source_identity=%s where case_id=%s",
                ("f" * 64, case_id),
            )
        elif poison == "violated_object":
            cur.execute(
                "update app.evidence_objects set status='violated',seal_status='violated' where id=%s",
                (object_ids[0],),
            )
        elif poison == "unsafe_cause":
            cur.execute(
                "select issues from app.evidence_chain_heads where case_id=%s", (case_id,)
            )
            issues = cur.fetchone()[0]
            issues.append({"code": "LEDGER_INVALID", "gate_state": "BLOCKED_VIOLATION"})
            cur.execute(
                "update app.evidence_chain_heads set issues=%s where case_id=%s",
                (Jsonb(issues), case_id),
            )
        elif poison == "unsafe_pending":
            cur.execute(
                "select issues from app.evidence_chain_heads where case_id=%s", (case_id,)
            )
            issues = cur.fetchone()[0]
            issues.append(
                {
                    "code": "UNSAFE_PENDING_ITEM",
                    "gate_state": "BLOCKED_PENDING",
                    "recovery": "OPERATOR_DISPOSITION",
                    "evidence_object_id": None,
                    "observation_id": "unsafe-sibling",
                    "full_verification_required": False,
                }
            )
            cur.execute(
                "update app.evidence_chain_heads set issues=%s where case_id=%s",
                (Jsonb(issues), case_id),
            )
        elif poison == "stale_generation":
            cur.execute(
                "update app.evidence_storage_authorities set generation=generation+1 where case_id=%s",
                (case_id,),
            )
        else:
            cur.execute(
                """insert into app.evidence_storage_verifications(
                     case_id,generation,profile,manifest_version,manifest_hash,item_facts,
                     outcome,correlation_id,actor_user_id)
                   select case_id,generation,profile,0,'', '[]'::jsonb,'SUCCESS',%s,%s
                   from app.evidence_storage_authorities where case_id=%s""",
                ("negative-" + uuid.uuid4().hex, actor_id, case_id),
            )
        before = _append_only_counts(cur, case_id)
        before_success = _success_count(cur, case_id)

        cur.execute(MIGRATION.read_text(encoding="utf-8"))

        cur.execute(
            "select seal_status,issues from app.evidence_chain_heads where case_id=%s",
            (case_id,),
        )
        seal_status, issues = cur.fetchone()
        assert seal_status == "violated"
        assert "PERSISTED_VIOLATION" in {issue["code"] for issue in issues}
        assert _append_only_counts(cur, case_id) == before
        command, reason, key, receipt = _seal_command(
            conn, case_id=case_id, actor_id=actor_id, paths=paths
        )
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            with conn.transaction():
                cur.execute(
                    """select app.custody_operation_begin_or_resume_storage_v3(
                         %s,%s,%s,%s,%s,%s,%s,'negative-runner',null)""",
                    (
                        case_id,
                        Jsonb(command),
                        "sha256:" + "9" * 64,
                        reason,
                        receipt,
                        key,
                        actor_id,
                    ),
                )
        cur.execute(
            """select
                 (select count(*) from app.evidence_manifests where case_id=%s),
                 (select count(*) from app.evidence_versions where case_id=%s),
                 (select count(*) from app.evidence_storage_verifications
                    where case_id=%s and outcome='SUCCESS')""",
            (case_id, case_id, case_id),
        )
        assert cur.fetchone() == (0, 0, before_success)
        cur.execute("rollback to savepoint external_bootstrap_negative")


def test_finalizer_rejects_detected_entry_raced_after_begin_without_authority():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        case_id, actor_id, object_ids, paths, source, mount = _virgin_external(
            conn, paths=("evidence/alpha.raw",)
        )
        command, reason, key, receipt = _seal_command(
            conn, case_id=case_id, actor_id=actor_id, paths=paths
        )
        items = _verified_items(
            object_ids=object_ids, paths=paths, source=source, mount=mount
        )
        cur.execute(
            """select id from app.custody_operation_begin_or_resume_storage_v3(
                 %s,%s,%s,%s,%s,%s,%s,'race-runner',null)""",
            (
                case_id,
                Jsonb(command),
                "sha256:" + "7" * 64,
                reason,
                receipt,
                key,
                actor_id,
            ),
        )
        operation_id = cur.fetchone()[0]
        cur.execute(
            "select phase from app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'race-runner')",
            (operation_id, Jsonb({"items": items})),
        )
        cur.execute(
            "select phase from app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'race-runner')",
            (operation_id, Jsonb({"items": items})),
        )
        cur.execute(
            "select app.evidence_detect(%s,'evidence/raced.raw','raced.raw',10,null,null)",
            (case_id,),
        )

        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            with conn.transaction():
                cur.execute(
                    "select app.custody_operation_commit_verified_seal_storage_v3(%s,%s,'examiner','race-runner')",
                    (operation_id, Jsonb(items)),
                )

        cur.execute(
            """select
                 (select count(*) from app.evidence_manifests where case_id=%s),
                 (select count(*) from app.evidence_versions where case_id=%s),
                 (select count(*) from app.evidence_storage_verifications
                    where case_id=%s and outcome='SUCCESS')""",
            (case_id, case_id, case_id),
        )
        assert cur.fetchone() == (0, 0, 0)
        cur.execute(
            "select seal_status from app.evidence_chain_heads where case_id=%s",
            (case_id,),
        )
        assert cur.fetchone()[0] in ("unsealed", "violated")


def test_external_bootstrap_database_surface_is_service_role_only():
    psycopg = pytest.importorskip("psycopg")
    signatures = (
        "app.evidence_record_inventory_classification_v2(uuid,text,text,jsonb)",
        "app.custody_operation_begin_or_resume_storage_v3(uuid,jsonb,text,text,uuid,text,uuid,text,uuid)",
        "app.custody_operation_commit_verified_seal_storage_v3(uuid,jsonb,text,text)",
    )
    internal = (
        "app.evidence_is_virgin_external_bootstrap(uuid)",
        "app.evidence_record_inventory_classification_v2_pre_external_bootstrap(uuid,text,text,jsonb)",
        "app.custody_operation_begin_or_resume_storage_v3_pre_external_bootstrap(uuid,jsonb,text,text,uuid,text,uuid,text,uuid)",
        "app.custody_operation_commit_verified_seal_storage_v3_pre_external_bootstrap(uuid,jsonb,text,text)",
    )
    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        for signature in signatures + internal:
            for principal in ("public", "anon", "authenticated"):
                cur.execute(
                    "select has_function_privilege(%s,%s,'EXECUTE')",
                    (principal, signature),
                )
                assert cur.fetchone() == (False,)
        cur.execute("select 1 from pg_roles where rolname='service_role'")
        if cur.fetchone():
            for signature in signatures:
                cur.execute(
                    "select has_function_privilege('service_role',%s,'EXECUTE')",
                    (signature,),
                )
                assert cur.fetchone() == (True,)
            for signature in internal:
                cur.execute(
                    "select has_function_privilege('service_role',%s,'EXECUTE')",
                    (signature,),
                )
                assert cur.fetchone() == (False,)
