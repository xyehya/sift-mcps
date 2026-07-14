from __future__ import annotations

import hashlib
import os
import pwd
import runpy
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

AUTHORIZE_REPAIR_MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "supabase"
    / "migrations"
    / "202607145300_custody_delete_broker_authorize_shape.sql"
)
RETIRE_RECOVERY_MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "supabase"
    / "migrations"
    / "202607145400_retire_violation_recovery.sql"
)
DELETE_BROKER_ITEM_KEYS = (
    "evidence_object_id",
    "display_path",
    "prior_status",
    "prior_seal_status",
    "original_version_id",
    "original_sha256",
    "original_bytes",
    "present",
    "sha256",
    "bytes",
    "st_dev",
    "st_ino",
    "st_nlink",
)


def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for migrated-Postgres drift proof")
    return dsn


def _broker_dsn() -> str:
    dsn = os.environ.get("SIFT_CUSTODY_DELETE_BROKER_DSN", "").strip()
    if not dsn:
        pytest.skip(
            "SIFT_CUSTODY_DELETE_BROKER_DSN is required for scoped broker Postgres proof"
        )
    return dsn


def _admin_dsn() -> str:
    dsn = os.environ.get("SIFT_CUSTODY_TEST_ADMIN_DSN", "").strip()
    if not dsn:
        pytest.skip(
            "SIFT_CUSTODY_TEST_ADMIN_DSN is required to clean committed broker fixtures"
        )
    return dsn


def _app_table_counts(dsn: str) -> dict[str, int]:
    import psycopg
    from psycopg import sql

    counts: dict[str, int] = {}
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """select c.relname from pg_catalog.pg_class c
               join pg_catalog.pg_namespace n on n.oid=c.relnamespace
               where n.nspname='app' and c.relkind in ('r','p') order by c.relname"""
        )
        for (table_name,) in cur.fetchall():
            cur.execute(
                sql.SQL("select count(*) from app.{}").format(
                    sql.Identifier(table_name)
                )
            )
            count_row = cur.fetchone()
            assert count_row is not None
            counts[table_name] = count_row[0]
    return counts


def _cleanup_committed_broker_fixture(
    dsn: str, *, case_id, actor_id, before_counts: dict[str, int]
) -> None:
    import psycopg
    from psycopg import sql

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "select id from app.custody_operations where case_id=%s", (case_id,)
        )
        operation_ids = [row[0] for row in cur.fetchall()]
        cur.execute(
            "select id from app.evidence_objects where case_id=%s", (case_id,)
        )
        object_ids = [row[0] for row in cur.fetchall()]
        cur.execute(
            """select c.relname,array_agg(a.attname order by a.attname)
               from pg_catalog.pg_class c
               join pg_catalog.pg_namespace n on n.oid=c.relnamespace
               join pg_catalog.pg_attribute a on a.attrelid=c.oid
               where n.nspname='app' and c.relkind in ('r','p')
                 and a.attnum>0 and not a.attisdropped
                 and a.attname in ('case_id','operation_id','custody_operation_id',
                   'evidence_object_id','actor_user_id')
               group by c.relname order by c.relname"""
        )
        targets = cur.fetchall()
        # Test-only superuser cleanup. LOCAL confines the trigger bypass to this
        # transaction; every predicate uses freshly generated UUIDs from one test.
        cur.execute("set local session_replication_role=replica")
        for table_name, columns in targets:
            clauses = []
            params = []
            for column in columns:
                if column == "case_id":
                    clauses.append(sql.SQL("{}=%s").format(sql.Identifier(column)))
                    params.append(case_id)
                elif column == "actor_user_id":
                    clauses.append(sql.SQL("{}=%s").format(sql.Identifier(column)))
                    params.append(actor_id)
                elif column in {"operation_id", "custody_operation_id"} and operation_ids:
                    clauses.append(sql.SQL("{}=any(%s)").format(sql.Identifier(column)))
                    params.append(operation_ids)
                elif column == "evidence_object_id" and object_ids:
                    clauses.append(sql.SQL("{}=any(%s)").format(sql.Identifier(column)))
                    params.append(object_ids)
            if clauses:
                predicate = sql.SQL(" or ").join(clauses)
                cur.execute(
                    sql.SQL("delete from app.{table} where {predicate}").format(
                        table=sql.Identifier(table_name), predicate=predicate
                    ),
                    params,
                )
                cur.execute(
                    sql.SQL(
                        "select count(*) from app.{table} where {predicate}"
                    ).format(table=sql.Identifier(table_name), predicate=predicate),
                    params,
                )
                remaining_row = cur.fetchone()
                assert remaining_row is not None
                assert remaining_row[0] == 0
        cur.execute("delete from app.cases where id=%s", (case_id,))
        cur.execute("delete from app.operator_profiles where id=%s", (actor_id,))
        cur.execute(
            """select
                 (select count(*) from app.cases where id=%s),
                 (select count(*) from app.operator_profiles where id=%s)""",
            (case_id, actor_id),
        )
        assert cur.fetchone() == (0, 0)
        cur.execute("set local session_replication_role=origin")
        cur.execute("select current_setting('session_replication_role')")
        replication_role_row = cur.fetchone()
        assert replication_role_row is not None
        assert replication_role_row[0] == "origin"
    assert _app_table_counts(dsn) == before_counts


@pytest.fixture
def committed_broker_fixture_cleanup():
    admin_dsn = _admin_dsn()
    before_counts = _app_table_counts(admin_dsn)
    identities: list[tuple[object, object]] = []

    def track(case_id, actor_id) -> None:
        identities.append((case_id, actor_id))

    yield track
    for case_id, actor_id in reversed(identities):
        _cleanup_committed_broker_fixture(
            admin_dsn,
            case_id=case_id,
            actor_id=actor_id,
            before_counts=before_counts,
        )


def _case_and_actor(conn):
    case_id, actor_id = uuid.uuid4(), uuid.uuid4()
    case_key = "p423-drift-" + uuid.uuid4().hex
    with conn.cursor() as cur:
        cur.execute(
            "insert into app.operator_profiles(id,display_name,status) values(%s,'P423 drift operator','active')",
            (actor_id,),
        )
        cur.execute(
            """insert into app.cases(
                 id,case_key,title,status,legacy_case_dir)
               values(%s,%s,'P423 drift case','active',%s)""",
            (case_id, case_key, f"/cases/{case_key}"),
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


def _valid_delete_broker_item(object_id) -> dict[str, object]:
    return {
        "evidence_object_id": str(object_id),
        "display_path": f"evidence/{object_id}.bin",
        "prior_status": "detected",
        "prior_seal_status": "unsealed",
        "original_version_id": None,
        "original_sha256": None,
        "original_bytes": None,
        "present": True,
        "sha256": "sha256:" + "a" * 64,
        "bytes": 10,
        "st_dev": 11,
        "st_ino": 12,
        "st_nlink": 1,
    }


def _authorize_catalog_state(cur) -> tuple:
    cur.execute(
        """select p.proowner,p.prosecdef,p.proconfig,
                  has_function_privilege(
                    'sift_custody_delete_broker',p.oid,'EXECUTE'),
                  not exists(
                    select 1
                    from aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl
                    left join pg_roles grantee on grantee.oid=acl.grantee
                    where acl.privilege_type='EXECUTE'
                      and acl.grantee<>p.proowner
                      and coalesce(grantee.rolname,'PUBLIC')<>
                        'sift_custody_delete_broker')
             from pg_proc p
             where p.oid=
               'sift_custody_broker.authorize(uuid,text)'::regprocedure"""
    )
    state = cur.fetchone()
    assert state is not None
    return state


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
            cur.execute(
                """select to_regprocedure('app.evidence_record_inventory_classification(uuid,text,text,jsonb)') is not null,
                          to_regprocedure('app.custody_operation_resume_disposition(uuid,uuid,uuid,text)') is not null"""
            )
            assert cur.fetchone() == (True, True)
            for role in ("anon", "authenticated"):
                cur.execute(
                    "select has_table_privilege(%s,'app.evidence_inventory_observations','SELECT')",
                    (role,),
                )
                assert cur.fetchone()[0] is False
                cur.execute(
                    """select has_function_privilege(
                         %s,'app.custody_operation_resume_disposition(uuid,uuid,uuid,text)','EXECUTE')""",
                    (role,),
                )
                assert cur.fetchone()[0] is False
            cur.execute(
                """select not exists(
                     select 1 from pg_proc p,
                     lateral aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl
                     where p.oid='app.custody_operation_resume_disposition(uuid,uuid,uuid,text)'::regprocedure
                       and acl.grantee=0 and acl.privilege_type='EXECUTE')"""
            )
            assert cur.fetchone()[0] is True
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
            for label, bad_finding in (
                ("missing-id", {key: value for key, value in finding.items() if key != "observation_id"}),
                ("numeric-id", {**finding, "observation_id": 7}),
                ("boolean-object", {**finding, "evidence_object_id": True}),
            ):
                cur.execute(f"savepoint {label.replace('-', '_')}")
                with pytest.raises(psycopg.errors.InvalidParameterValue):
                    cur.execute(
                        "select app.evidence_record_inventory_classification(%s,%s,'BLOCKED_PENDING',%s)",
                        (case_id, label + uuid.uuid4().hex, Jsonb([bad_finding])),
                    )
                cur.execute(f"rollback to savepoint {label.replace('-', '_')}")
            cur.execute("savepoint gate_mismatch")
            with pytest.raises(psycopg.errors.InvalidParameterValue):
                cur.execute(
                    "select app.evidence_record_inventory_classification(%s,%s,'OPEN',%s)",
                    (case_id, "mismatch-" + uuid.uuid4().hex, Jsonb([finding])),
                )
            cur.execute("rollback to savepoint gate_mismatch")
            # Prove conflicting replay while the original pending classification is
            # still the authoritative gate cause. A persisted violation added below
            # must fail closed before correlation replay is considered.
            cur.execute("savepoint replay")
            with pytest.raises(psycopg.errors.UniqueViolation):
                cur.execute(
                    "select app.evidence_record_inventory_classification(%s,%s,'BLOCKED_PENDING',%s)",
                    (case_id, correlation, Jsonb([{**finding, "observation_id": "other"}])),
                )
            cur.execute("rollback to savepoint replay")
            violated_id = uuid.uuid4()
            cur.execute(
                """insert into app.evidence_objects
                   (id,case_id,display_name,display_path,status,seal_status)
                   values(%s,%s,'violated.bin',%s,'violated','violated')""",
                (violated_id, case_id, f"evidence/{violated_id}.bin"),
            )
            cur.execute("savepoint persisted_open")
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
                cur.execute(
                    "select app.evidence_record_inventory_classification(%s,%s,'OPEN','[]'::jsonb)",
                    (case_id, "open-" + uuid.uuid4().hex),
                )
            cur.execute("rollback to savepoint persisted_open")
            persisted_finding = {
                "code": "PERSISTED_VIOLATION",
                "gate_state": "BLOCKED_VIOLATION",
                "recovery": "RESTORE_REACQUIRE_RETIRE",
                "evidence_object_id": str(violated_id),
                "observation_id": None,
                "full_verification_required": False,
            }
            cur.execute(
                """select gate_state,findings from app.evidence_record_inventory_classification(
                   %s,%s,'BLOCKED_VIOLATION',%s)""",
                (
                    case_id,
                    "persisted-" + uuid.uuid4().hex,
                    Jsonb([persisted_finding]),
                ),
            )
            persisted_gate, persisted_findings = cur.fetchone()
            assert persisted_gate == "BLOCKED_VIOLATION"
            assert persisted_findings == [persisted_finding]
        conn.rollback()


def test_disposition_resume_rejects_scope_replay_and_runner_reuse():
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
        other_case = uuid.uuid4()
        with conn.cursor() as cur:
            cur.execute(
                "insert into app.cases(id,case_key,title,status) values(%s,%s,'Other case','active')",
                (other_case, "p423-other-" + uuid.uuid4().hex),
            )
            cur.execute(
                "select relrowsecurity,relforcerowsecurity from pg_class where oid='app.custody_operations'::regclass"
            )
            assert cur.fetchone() == (True, True)

        for label, receipt in (
            (
                "cross-case",
                _reauth(
                    conn,
                    case_id=other_case,
                    actor_id=actor_id,
                    event_type="reauth.evidence_delete_resume",
                    binding={"operation_id": str(operation_id)},
                ),
            ),
            (
                "wrong-action",
                _reauth(
                    conn,
                    case_id=case_id,
                    actor_id=actor_id,
                    event_type="reauth.evidence_retire_resume",
                    binding={"operation_id": str(operation_id)},
                ),
            ),
        ):
            with conn.cursor() as cur:
                cur.execute(f"savepoint {label.replace('-', '_')}")
                with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                    cur.execute(
                        "select app.custody_operation_resume_disposition(%s,%s,%s,'runner-after')",
                        (operation_id, actor_id, receipt),
                    )
                cur.execute(f"rollback to savepoint {label.replace('-', '_')}")

        valid_receipt = _reauth(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            event_type="reauth.evidence_delete_resume",
            binding={"operation_id": str(operation_id)},
        )
        with conn.cursor() as cur:
            cur.execute(
                "select phase from app.custody_operation_resume_disposition(%s,%s,%s,'runner-after')",
                (operation_id, actor_id, valid_receipt),
            )
            assert cur.fetchone()[0] == "GATE_BLOCKED"
            cur.execute("savepoint receipt_reuse")
            with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                cur.execute(
                    "select app.custody_operation_resume_disposition(%s,%s,%s,'runner-after')",
                    (operation_id, actor_id, valid_receipt),
                )
            cur.execute("rollback to savepoint receipt_reuse")

        retired_receipt = _reauth(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            event_type="reauth.evidence_delete_resume",
            binding={"operation_id": str(operation_id)},
        )
        with conn.cursor() as cur:
            cur.execute("savepoint retired_runner")
            with pytest.raises(psycopg.Error) as retired:
                cur.execute(
                    "select app.custody_operation_resume_disposition(%s,%s,%s,'runner-before')",
                    (operation_id, actor_id, retired_receipt),
                )
            assert retired.value.sqlstate == "P4232"
            cur.execute("rollback to savepoint retired_runner")
            cur.execute(
                "select app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING','{}'::jsonb,'runner-after')",
                (operation_id,),
            )

        same_runner_receipt = _reauth(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            event_type="reauth.evidence_delete_resume",
            binding={"operation_id": str(operation_id)},
        )
        with conn.cursor() as cur:
            with pytest.raises(psycopg.Error) as same_runner:
                cur.execute(
                    "select app.custody_operation_resume_disposition(%s,%s,%s,'runner-after')",
                    (operation_id, actor_id, same_runner_receipt),
                )
            assert same_runner.value.sqlstate == "P4232"
        conn.rollback()


def test_delete_post_unlink_resume_preserves_facts_and_commits_one_event(
    committed_broker_fixture_cleanup,
):
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    broker_dsn = _broker_dsn()
    with psycopg.connect(_dsn()) as conn:
        case_id, actor_id = _case_and_actor(conn)
        committed_broker_fixture_cleanup(case_id, actor_id)
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
            "original_version_id": None,
            "original_sha256": None,
            "original_bytes": None,
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
        conn.commit()
        with psycopg.connect(broker_dsn) as broker_conn, broker_conn.cursor() as cur:
            cur.execute(
                "select sift_custody_broker.authorize(%s,'runner-after')",
                (operation_id,),
            )
            digest = cur.fetchone()[0]["prepared_facts_sha256"]
            cur.execute(
                "select sift_custody_broker.claim(%s,'runner-after',%s)",
                (operation_id, digest),
            )
            cur.execute(
                "select sift_custody_broker.complete(%s,'runner-after',%s)",
                (operation_id, digest),
            )
        with conn.cursor() as cur:
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


def test_delete_broker_completed_receipt_is_idempotent_across_new_runner(
    tmp_path: Path,
    committed_broker_fixture_cleanup,
):
    """A lost response/advance reuses exact completion without rewriting it."""
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    broker_dsn = _broker_dsn()
    helper_path = (
        Path(__file__).resolve().parents[3]
        / "scripts"
        / "sift-custody-delete-broker"
    )
    broker = runpy.run_path(str(helper_path))
    delete_verified = broker["delete_verified"]
    delete_verified.__globals__["_immutable"] = lambda _fd: False

    with psycopg.connect(_dsn()) as conn:
        case_id, actor_id = _case_and_actor(conn)
        committed_broker_fixture_cleanup(case_id, actor_id)
        object_id, sibling_id, sibling_version = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        operation_id, *_ = _begin(
            conn,
            case_id=case_id,
            actor_id=actor_id,
            object_id=object_id,
            action="DELETE_STRAY",
            status="detected",
            seal_status="unsealed",
        )
        with conn.cursor() as cur:
            cur.execute("select case_key from app.cases where id=%s", (case_id,))
            case_key = cur.fetchone()[0]
            case_dir = tmp_path / case_key
            evidence_dir = case_dir / "evidence"
            evidence_dir.mkdir(parents=True)
            target = evidence_dir / f"{object_id}.bin"
            sibling = evidence_dir / f"{sibling_id}.bin"
            target.write_bytes(b"broker pending bytes")
            sibling.write_bytes(b"sealed sibling bytes")
            cur.execute(
                "update app.cases set legacy_case_dir=%s where id=%s",
                (str(case_dir), case_id),
            )
            cur.execute(
                """insert into app.evidence_objects
                   (id,case_id,display_name,display_path,status,seal_status)
                   values(%s,%s,'sibling.bin',%s,'sealed','sealed')""",
                (
                    sibling_id,
                    case_id,
                    f"evidence/{sibling_id}.bin",
                ),
            )
            cur.execute(
                """insert into app.evidence_versions
                   (id,evidence_object_id,case_id,manifest_version,sha256,bytes,entry_status)
                   values(%s,%s,%s,1,%s,%s,'ACTIVE')""",
                (
                    sibling_version,
                    sibling_id,
                    case_id,
                    "sha256:" + hashlib.sha256(b"sealed sibling bytes").hexdigest(),
                    len(b"sealed sibling bytes"),
                ),
            )
            cur.execute(
                """update app.evidence_objects set current_version_id=%s,
                     current_sha256=%s,current_bytes=%s where id=%s""",
                (
                    sibling_version,
                    "sha256:" + hashlib.sha256(b"sealed sibling bytes").hexdigest(),
                    len(b"sealed sibling bytes"),
                    sibling_id,
                ),
            )
            info = target.stat()
            item = {
                "evidence_object_id": str(object_id),
                "display_path": f"evidence/{object_id}.bin",
                "prior_status": "detected",
                "prior_seal_status": "unsealed",
                "original_version_id": None,
                "original_sha256": None,
                "original_bytes": None,
                "present": True,
                "sha256": "sha256:" + hashlib.sha256(b"broker pending bytes").hexdigest(),
                "bytes": len(b"broker pending bytes"),
                "st_dev": info.st_dev,
                "st_ino": info.st_ino,
                "st_nlink": info.st_nlink,
            }
            cur.execute(
                "select app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'runner-before')",
                (operation_id, Jsonb({"item": item})),
            )
        conn.commit()

        operation = broker["resolve_operation"](
            broker_dsn, str(operation_id), "runner-before", tmp_path
        )
        delete_verified(operation, tmp_path, pwd.getpwuid(os.geteuid()), broker_dsn)
        assert not target.exists()

        # Simulate loss after the broker committed its receipt but before the
        # Gateway advanced FILESYSTEM_APPLYING. A fresh runner is authorized.
        with conn.cursor() as cur:
            cur.execute(
                "select app.custody_operation_fail(%s,'FILESYSTEM_APPLYING','lost_broker_response','runner-before')",
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
                "select phase from app.custody_operation_resume_disposition(%s,%s,%s,'runner-after')",
                (operation_id, actor_id, resume_id),
            )
            assert cur.fetchone()[0] == "FILESYSTEM_APPLYING"
        conn.commit()

        resumed = broker["resolve_operation"](
            broker_dsn, str(operation_id), "runner-after", tmp_path
        )
        assert resumed["receipt_claimed"] is True
        assert resumed["receipt_completed"] is True
        delete_verified(resumed, tmp_path, pwd.getpwuid(os.geteuid()), broker_dsn)

        verified = {**item, "file_removed": True}
        with conn.cursor() as cur:
            cur.execute(
                "select app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'runner-after')",
                (operation_id, Jsonb({"item": verified})),
            )
            cur.execute(
                "select phase from app.custody_operation_commit_verified_disposition(%s,%s,'examiner','runner-after')",
                (operation_id, Jsonb(verified)),
            )
            assert cur.fetchone()[0] == "COMPLETED"
            cur.execute(
                """select count(*),count(*) filter(where completed_at is not null)
                     from app.custody_delete_broker_receipts where operation_id=%s""",
                (operation_id,),
            )
            assert cur.fetchone() == (1, 1)
            cur.execute(
                "select count(*) from app.custody_operation_history where operation_id=%s and phase='COMPLETED'",
                (operation_id,),
            )
            assert cur.fetchone()[0] == 1
            cur.execute(
                "select count(*) from app.evidence_custody_events where custody_operation_id=%s",
                (operation_id,),
            )
            assert cur.fetchone()[0] == 1
            cur.execute(
                "select count(*) from app.evidence_versions where case_id=%s",
                (case_id,),
            )
            assert cur.fetchone()[0] == 1
            cur.execute(
                "select count(*) from app.evidence_manifests where case_id=%s",
                (case_id,),
            )
            assert cur.fetchone()[0] == 0
            cur.execute(
                "select status,current_version_id from app.evidence_objects where id=%s",
                (sibling_id,),
            )
            assert cur.fetchone() == ("sealed", sibling_version)
        assert sibling.read_bytes() == b"sealed sibling bytes"
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
            with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                cur.execute(
                    "select app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'runner-before')",
                    (operation_id, Jsonb({"item": item})),
                )
        conn.rollback()


def test_delete_verified_transition_requires_scoped_completed_broker_receipt(
    committed_broker_fixture_cleanup,
):
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    broker_dsn = _broker_dsn()
    with psycopg.connect(_dsn()) as conn:
        case_id, actor_id = _case_and_actor(conn)
        committed_broker_fixture_cleanup(case_id, actor_id)
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
            "original_version_id": None,
            "original_sha256": None,
            "original_bytes": None,
            "present": True,
            "sha256": "sha256:" + "a" * 64,
            "bytes": 10,
            "st_dev": 11,
            "st_ino": 12,
            "st_nlink": 1,
        }
        verified = {**item, "file_removed": True}
        with conn.cursor() as cur:
            cur.execute(
                "select app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'runner-before')",
                (operation_id, Jsonb({"item": item})),
            )
            cur.execute(
                """select rolsuper,rolinherit,rolbypassrls,
                     has_schema_privilege('sift_custody_delete_broker','sift_custody_broker','USAGE'),
                     has_schema_privilege('sift_custody_delete_broker','app','USAGE'),
                     coalesce((select has_table_privilege('sift_custody_delete_broker',c.oid,'SELECT')
                       from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid=c.relnamespace
                       where n.nspname='app' and c.relname='custody_operations'),true),
                     coalesce((select has_table_privilege('sift_custody_delete_broker',c.oid,'SELECT')
                       from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid=c.relnamespace
                       where n.nspname='app' and c.relname='custody_delete_broker_receipts'),true),
                     has_function_privilege('sift_custody_delete_broker','sift_custody_broker.authorize(uuid,text)','EXECUTE'),
                     has_function_privilege('sift_custody_delete_broker','sift_custody_broker.claim(uuid,text,text)','EXECUTE'),
                     has_function_privilege('sift_custody_delete_broker','sift_custody_broker.complete(uuid,text,text)','EXECUTE'),
                     not exists(select 1 from pg_auth_members m join pg_roles member on member.oid=m.member
                       where member.rolname='sift_custody_delete_broker')
                     from pg_roles where rolname='sift_custody_delete_broker'"""
            )
            assert cur.fetchone() == (
                False, False, False, True, False, False, False, True, True, True, True
            )
            cur.execute("savepoint missing_receipt")
            with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                cur.execute(
                    "select app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'runner-before')",
                    (operation_id, Jsonb({"item": verified})),
                )
            cur.execute("rollback to savepoint missing_receipt")
            cur.execute("savepoint control_broker_denied")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute(
                    "select sift_custody_broker.authorize(%s,'runner-before')",
                    (operation_id,),
                )
            cur.execute("rollback to savepoint control_broker_denied")
        conn.commit()
        with psycopg.connect(broker_dsn) as broker_conn, broker_conn.cursor() as cur:
            cur.execute(
                "select sift_custody_broker.authorize(%s,'runner-before')",
                (operation_id,),
            )
            digest = cur.fetchone()[0]["prepared_facts_sha256"]
            cur.execute(
                "select sift_custody_broker.claim(%s,'runner-before',%s)",
                (operation_id, digest),
            )
        with conn.cursor() as cur:
            cur.execute("savepoint claimed_only")
            with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                cur.execute(
                    "select app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'runner-before')",
                    (operation_id, Jsonb({"item": verified})),
                )
            cur.execute("rollback to savepoint claimed_only")
        with psycopg.connect(broker_dsn) as broker_conn, broker_conn.cursor() as cur:
            cur.execute("savepoint wrong_digest")
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
                cur.execute(
                    "select sift_custody_broker.complete(%s,'runner-before',%s)",
                    (operation_id, "sha256:" + "b" * 64),
                )
            cur.execute("rollback to savepoint wrong_digest")
            cur.execute(
                "select sift_custody_broker.complete(%s,'runner-before',%s)",
                (operation_id, digest),
            )
        with conn.cursor() as cur:
            cur.execute(
                "select phase from app.custody_operation_advance(%s,'FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',%s,'runner-before')",
                (operation_id, Jsonb({"item": verified})),
            )
            assert cur.fetchone()[0] == "FILESYSTEM_VERIFIED"
        conn.rollback()


def test_broker_authorize_repair_migration_applies_and_rolls_back_cleanly():
    psycopg = pytest.importorskip("psycopg")
    repair_sql = AUTHORIZE_REPAIR_MIGRATION.read_text(encoding="utf-8")

    with psycopg.connect(_admin_dsn()) as conn, conn.cursor() as cur:
        before = _authorize_catalog_state(cur)
        cur.execute("savepoint authorize_repair_syntax")
        cur.execute(repair_sql)
        after = _authorize_catalog_state(cur)

        assert after[0] == before[0]
        assert after[1] is True
        assert set(after[2] or ()) == {"search_path=pg_catalog, app"}
        assert after[3:] == (True, True)

        cur.execute("rollback to savepoint authorize_repair_syntax")
        assert _authorize_catalog_state(cur) == before


def test_broker_authorize_accepts_exact_production_item_shape(
    committed_broker_fixture_cleanup,
):
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    broker_dsn = _broker_dsn()
    with psycopg.connect(_dsn()) as conn:
        case_id, actor_id = _case_and_actor(conn)
        committed_broker_fixture_cleanup(case_id, actor_id)
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
        item = _valid_delete_broker_item(object_id)
        item["original_bytes"] = 10
        with conn.cursor() as cur:
            cur.execute(
                "update app.evidence_objects set current_bytes=%s where id=%s",
                (item["original_bytes"], object_id),
            )
            cur.execute(
                "select app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'runner-before')",
                (operation_id, Jsonb({"item": item})),
            )
        conn.commit()

        with psycopg.connect(broker_dsn) as broker_conn, broker_conn.cursor() as cur:
            cur.execute(
                "select sift_custody_broker.authorize(%s,'runner-before')",
                (operation_id,),
            )
            authorized = cur.fetchone()
            assert authorized is not None
            assert authorized[0]["item"] == item
            assert set(authorized[0]["item"]) == set(DELETE_BROKER_ITEM_KEYS)
            cur.execute(
                "select sift_custody_broker.claim(%s,'runner-before',%s)",
                (operation_id, authorized[0]["prepared_facts_sha256"]),
            )
            claimed = cur.fetchone()
            assert claimed is not None
            assert claimed[0]["claimed"] is True


@pytest.mark.parametrize("missing_key", DELETE_BROKER_ITEM_KEYS)
def test_broker_authorize_rejects_each_missing_production_item_key(
    missing_key: str, committed_broker_fixture_cleanup
):
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    broker_dsn = _broker_dsn()
    with psycopg.connect(_dsn()) as conn:
        case_id, actor_id = _case_and_actor(conn)
        committed_broker_fixture_cleanup(case_id, actor_id)
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
        item = _valid_delete_broker_item(object_id)
        item.pop(missing_key)
        with conn.cursor() as cur:
            cur.execute(
                "select app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'runner-before')",
                (operation_id, Jsonb({"item": item})),
            )
        conn.commit()

        with psycopg.connect(broker_dsn) as broker_conn, broker_conn.cursor() as cur:
            with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                cur.execute(
                    "select sift_custody_broker.authorize(%s,'runner-before')",
                    (operation_id,),
                )
            broker_conn.rollback()


@pytest.mark.parametrize(
    "extra_key",
    [
        "unexpected",
        "case_key",
        "name",
        "operation_id",
        "runner",
        "runner_instance_id",
        "prepared_facts_sha256",
        "receipt_claimed",
        "receipt_completed",
        "receipt_runner_instance_id",
    ],
)
def test_broker_authorize_rejects_extra_or_reserved_prepared_item_keys(
    extra_key: str, committed_broker_fixture_cleanup
):
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    broker_dsn = _broker_dsn()
    with psycopg.connect(_dsn()) as conn:
        case_id, actor_id = _case_and_actor(conn)
        committed_broker_fixture_cleanup(case_id, actor_id)
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
            "original_version_id": None,
            "original_sha256": None,
            "original_bytes": None,
            "present": True,
            "sha256": "sha256:" + "a" * 64,
            "bytes": 10,
            "st_dev": 11,
            "st_ino": 12,
            "st_nlink": 1,
            extra_key: "attacker-controlled",
        }
        with conn.cursor() as cur:
            cur.execute(
                "select app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING',%s,'runner-before')",
                (operation_id, Jsonb({"item": item})),
            )
        conn.commit()
        with psycopg.connect(broker_dsn) as broker_conn, broker_conn.cursor() as cur:
            with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                cur.execute(
                    "select sift_custody_broker.authorize(%s,'runner-before')",
                    (operation_id,),
                )
            broker_conn.rollback()


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


def _prepare_retire_recovery_fixture(
    conn,
    *,
    target_code="SEALED_EVIDENCE_MISSING",
    extra_issues=(),
    other_violated=False,
):
    from psycopg.types.json import Jsonb

    case_id, actor_id = _case_and_actor(conn)
    retired_id, sibling_id = uuid.uuid4(), uuid.uuid4()
    operation_id, *_ = _begin(
        conn,
        case_id=case_id,
        actor_id=actor_id,
        object_id=retired_id,
        action="RETIRE",
        status="violated",
        seal_status="violated",
    )
    retired_version_id, sibling_version_id = uuid.uuid4(), uuid.uuid4()
    target_finding = {
        "code": target_code,
        "gate_state": "BLOCKED_VIOLATION",
        "recovery": "RESTORE_REACQUIRE_RETIRE",
        "evidence_object_id": str(retired_id),
        "observation_id": "missing-" + uuid.uuid4().hex,
        "full_verification_required": False,
    }
    issues = [
        {"code": "PERSISTED_VIOLATION"},
        target_finding,
        *extra_issues,
    ]
    with conn.cursor() as cur:
        cur.execute(
            """insert into app.evidence_objects
               (id,case_id,display_name,display_path,status,seal_status)
               values(%s,%s,'sibling.bin',%s,'sealed','sealed')""",
            (sibling_id, case_id, f"evidence/{sibling_id}.bin"),
        )
        for object_id, version_id, digest in (
            (retired_id, retired_version_id, "b"),
            (sibling_id, sibling_version_id, "c"),
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
        if other_violated:
            other_id = uuid.uuid4()
            cur.execute(
                """insert into app.evidence_objects
                   (id,case_id,display_name,display_path,status,seal_status)
                   values(%s,%s,'other.bin',%s,'violated','violated')""",
                (other_id, case_id, f"evidence/{other_id}.bin"),
            )
        cur.execute(
            """insert into app.evidence_chain_heads(case_id,manifest_version,manifest_hash,
               seal_status,active_count,issues) values(%s,1,%s,'violated',2,%s)
               on conflict(case_id) do update set manifest_version=1,
                 manifest_hash=excluded.manifest_hash,seal_status='violated',
                 active_count=2,issues=excluded.issues""",
            (case_id, "sha256:" + "f" * 64, Jsonb(issues)),
        )
        cur.execute(
            """insert into app.evidence_inventory_observations(
               case_id,correlation_id,gate_state,findings)
               values(%s,%s,'BLOCKED_VIOLATION',%s)""",
            (case_id, "retire-" + uuid.uuid4().hex, Jsonb([target_finding])),
        )
        item = {
            "evidence_object_id": str(retired_id),
            "display_path": f"evidence/{retired_id}.bin",
            "prior_status": "violated",
            "prior_seal_status": "violated",
            "original_version_id": str(retired_version_id),
            "original_sha256": "sha256:" + "b" * 64,
            "original_bytes": 100,
            "present": False,
            "sha256": "sha256:" + "b" * 64,
            "bytes": 100,
            "file_removed": False,
        }
        for prior_phase, next_phase in (
            ("GATE_BLOCKED", "FILESYSTEM_APPLYING"),
            ("FILESYSTEM_APPLYING", "FILESYSTEM_VERIFIED"),
        ):
            cur.execute(
                "select app.custody_operation_advance(%s,%s,%s,%s,'runner-before')",
                (operation_id, prior_phase, next_phase, Jsonb({"item": item})),
            )
    return case_id, retired_id, operation_id, item


@pytest.mark.parametrize(
    "target_code", ["SEALED_EVIDENCE_MISSING", "CONTENT_CHANGED", "IDENTITY_CHANGED"]
)
def test_retire_recovery_clears_only_target_cause_and_synthetic_latch(target_code):
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_admin_dsn()) as conn, conn.cursor() as cur:
        cur.execute("savepoint retire_recovery")
        cur.execute(RETIRE_RECOVERY_MIGRATION.read_text(encoding="utf-8"))
        case_id, retired_id, operation_id, item = _prepare_retire_recovery_fixture(
            conn, target_code=target_code
        )
        cur.execute(
            "select phase from app.custody_operation_commit_verified_disposition(%s,%s,'examiner','runner-before')",
            (operation_id, Jsonb(item)),
        )
        assert cur.fetchone()[0] == "COMPLETED"
        cur.execute(
            "select status,seal_status from app.evidence_objects where id=%s",
            (retired_id,),
        )
        assert cur.fetchone() == ("retired", "unsealed")
        cur.execute(
            "select seal_status,issues from app.evidence_chain_heads where case_id=%s",
            (case_id,),
        )
        assert cur.fetchone() == ("sealed", [])
        cur.execute(
            "select count(*) from app.evidence_inventory_observations where case_id=%s",
            (case_id,),
        )
        assert cur.fetchone()[0] == 1
        cur.execute("rollback to savepoint retire_recovery")


def test_retire_recovery_preserves_unrelated_and_security_violations():
    from psycopg.types.json import Jsonb

    psycopg = pytest.importorskip("psycopg")
    target_id = uuid.uuid4()
    # The exact target is filled by the fixture; this deliberately remains an
    # unrelated binding even when the code is otherwise retirement-recoverable.
    extra_issues = (
        {
            "code": "CONTENT_CHANGED",
            "evidence_object_id": str(target_id),
        },
        {"code": "LEDGER_INVALID", "evidence_object_id": None},
        {"code": "CONFLICTING_AUTHORITY", "evidence_object_id": None},
        {"code": "UNSAFE_SEALED_ENTRY", "evidence_object_id": None},
    )
    with psycopg.connect(_admin_dsn()) as conn, conn.cursor() as cur:
        cur.execute("savepoint retire_recovery_negative")
        cur.execute(RETIRE_RECOVERY_MIGRATION.read_text(encoding="utf-8"))
        case_id, _retired_id, operation_id, item = _prepare_retire_recovery_fixture(
            conn, extra_issues=extra_issues, other_violated=True
        )
        cur.execute(
            "select phase from app.custody_operation_commit_verified_disposition(%s,%s,'examiner','runner-before')",
            (operation_id, Jsonb(item)),
        )
        assert cur.fetchone()[0] == "COMPLETED"
        cur.execute(
            "select seal_status,issues from app.evidence_chain_heads where case_id=%s",
            (case_id,),
        )
        seal_status, issues = cur.fetchone()
        assert seal_status == "violated"
        assert {issue["code"] for issue in issues} == {
            "PERSISTED_VIOLATION",
            "CONTENT_CHANGED",
            "LEDGER_INVALID",
            "CONFLICTING_AUTHORITY",
            "UNSAFE_SEALED_ENTRY",
        }
        cur.execute("rollback to savepoint retire_recovery_negative")


def test_retire_recovery_wrapper_is_service_only_and_hardened():
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_admin_dsn()) as conn, conn.cursor() as cur:
        cur.execute("savepoint retire_recovery_acl")
        cur.execute(RETIRE_RECOVERY_MIGRATION.read_text(encoding="utf-8"))
        cur.execute(
            """select p.prosecdef,p.proconfig,
                      has_function_privilege('service_role',p.oid,'EXECUTE'),
                      has_function_privilege('anon',p.oid,'EXECUTE'),
                      has_function_privilege('authenticated',p.oid,'EXECUTE')
               from pg_proc p where p.oid=
                 'app.custody_operation_commit_verified_disposition(uuid,jsonb,text,text)'::regprocedure"""
        )
        assert cur.fetchone() == (True, ["search_path=pg_catalog, app"], True, False, False)
        cur.execute(
            """select has_function_privilege(
                 'service_role',
                 'app.custody_operation_commit_disposition_pre_retire_recovery(uuid,jsonb,text,text)',
                 'EXECUTE')"""
        )
        assert cur.fetchone()[0] is False
        cur.execute("rollback to savepoint retire_recovery_acl")
