from __future__ import annotations

import os
import uuid
from collections.abc import Mapping, Sequence

import pytest

pytestmark = pytest.mark.integration


def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip(
            "SIFT_CONTROL_PLANE_DSN is required for migrated-Postgres Full Verify proof"
        )
    return dsn


def _setup(conn, issues: Sequence[Mapping[str, object]]):
    from psycopg.types.json import Jsonb

    case_id, actor_id, object_id, version_id = (uuid.uuid4() for _ in range(4))
    manifest_hash = "sha256:" + "b" * 64
    sha256 = "sha256:" + "a" * 64
    with conn.cursor() as cur:
        cur.execute(
            "insert into app.operator_profiles(id,display_name,status) "
            "values(%s,'Full Verify operator','active')",
            (actor_id,),
        )
        cur.execute(
            "insert into app.cases(id,case_key,title,status) "
            "values(%s,%s,'Full Verify recovery','active')",
            (case_id, "full-verify-" + uuid.uuid4().hex),
        )
        cur.execute(
            """insert into app.evidence_objects(
                 id,case_id,display_name,display_path,status,seal_status,
                 current_sha256,current_bytes)
               values(%s,%s,'disk.raw','evidence/disk.raw','sealed','sealed',%s,8)""",
            (object_id, case_id, sha256),
        )
        cur.execute(
            """insert into app.evidence_versions(
                 id,evidence_object_id,case_id,manifest_version,sha256,bytes,
                 entry_status,manifest_hash)
               values(%s,%s,%s,1,%s,8,'ACTIVE',%s)""",
            (version_id, object_id, case_id, sha256, manifest_hash),
        )
        cur.execute(
            "update app.evidence_objects set current_version_id=%s where id=%s",
            (version_id, object_id),
        )
        cur.execute(
            """insert into app.evidence_chain_heads(
                 case_id,manifest_version,manifest_hash,seal_status,active_count,
                 head_seq,head_hash,issues)
               values(%s,1,%s,'violated',1,0,'',%s)""",
            (case_id, manifest_hash, Jsonb(issues)),
        )
    conn.commit()
    items = [
        {
            "path": "evidence/disk.raw",
            "evidence_object_id": str(object_id),
            "evidence_version_id": str(version_id),
            "sha256": sha256,
            "bytes": 8,
            "st_dev": 1,
            "st_ino": 2,
            "st_mtime_ns": 3,
            "st_ctime_ns": 4,
            "st_nlink": 1,
            "owner": "sift-service",
            "mode": "0644",
            "immutable": True,
        }
    ]
    return case_id, actor_id, object_id, items


def _verify(conn, setup, *, generation=1, profile="LOCAL_IMMUTABLE", items=None, correlation=None):
    from psycopg.types.json import Jsonb

    case_id, actor_id, _object_id, expected_items = setup
    correlation = correlation or "full-verify:" + uuid.uuid4().hex
    with conn.cursor() as cur:
        cur.execute(
            """select state from app.evidence_storage_commit_full_verify(
                 %s,%s,%s,null,null,null,1,%s,%s,%s,null)""",
            (
                case_id,
                generation,
                profile,
                Jsonb(expected_items if items is None else items),
                correlation,
                actor_id,
            ),
        )
        state = cur.fetchone()[0]
    return state, correlation


def _reconcile_persisted_only(conn, setup) -> None:
    from psycopg.types.json import Jsonb

    findings = [{
        "code": "PERSISTED_VIOLATION",
        "gate_state": "BLOCKED_VIOLATION",
        "recovery": "RESTORE_REACQUIRE_RETIRE",
        "evidence_object_id": None,
        "observation_id": None,
        "full_verification_required": False,
    }]
    with conn.cursor() as cur:
        cur.execute(
            "select id from app.evidence_record_inventory_classification_v2(%s,%s,%s,%s)",
            (setup[0], "reconcile:" + uuid.uuid4().hex, "BLOCKED_VIOLATION", Jsonb(findings)),
        )
        assert cur.fetchone() is not None


def test_posture_only_success_opens_and_writes_one_receipt() -> None:
    psycopg = pytest.importorskip("psycopg")
    issues = [
        {"code": "PERSISTED_VIOLATION"},
        {"code": "FULL_VERIFY_REQUIRED"},
        {"code": "POSTURE_DRIFT", "storage_generation": 1},
    ]
    with psycopg.connect(_dsn()) as conn:
        setup = _setup(conn, issues)
        with conn.cursor() as cur:
            cur.execute(
                "select count(*) from app.evidence_versions where case_id=%s",
                (setup[0],),
            )
            before_version_count = cur.fetchone()
            cur.execute(
                "select count(*) from app.evidence_manifests where case_id=%s",
                (setup[0],),
            )
            before_manifest_count = cur.fetchone()
            cur.execute(
                "select current_version_id,status,seal_status from app.evidence_objects where id=%s",
                (setup[2],),
            )
            before_object = cur.fetchone()
        state, correlation = _verify(conn, setup)
        assert state == "AVAILABLE"
        with conn.cursor() as cur:
            cur.execute(
                "select seal_status,issues from app.evidence_chain_heads where case_id=%s",
                (setup[0],),
            )
            assert cur.fetchone() == ("sealed", [])
            cur.execute(
                """select count(*) from app.evidence_storage_verifications
                   where case_id=%s and correlation_id=%s and outcome='SUCCESS'""",
                (setup[0], correlation),
            )
            assert cur.fetchone() == (1,)
            cur.execute(
                "select count(*) from app.evidence_versions where case_id=%s",
                (setup[0],),
            )
            assert cur.fetchone() == before_version_count == (1,)
            cur.execute(
                "select count(*) from app.evidence_manifests where case_id=%s",
                (setup[0],),
            )
            assert cur.fetchone() == before_manifest_count
            cur.execute(
                "select current_version_id,status,seal_status from app.evidence_objects where id=%s",
                (setup[2],),
            )
            assert cur.fetchone() == before_object


@pytest.mark.parametrize(
    "blocking_code",
    (
        "CONTENT_CHANGED",
        "SEALED_EVIDENCE_MISSING",
        "LEDGER_INVALID",
        "IDENTITY_CHANGED",
        "CONFLICTING_AUTHORITY",
        "FUTURE_UNKNOWN_VIOLATION",
    ),
)
def test_substantive_or_unknown_issue_remains_blocked(blocking_code: str) -> None:
    psycopg = pytest.importorskip("psycopg")
    issues = [
        {"code": "PERSISTED_VIOLATION"},
        {"code": "FULL_VERIFY_REQUIRED"},
        {"code": blocking_code},
    ]
    with psycopg.connect(_dsn()) as conn:
        setup = _setup(conn, issues)
        _verify(conn, setup)
        with conn.cursor() as cur:
            cur.execute(
                "select seal_status,issues from app.evidence_chain_heads where case_id=%s",
                (setup[0],),
            )
            seal_status, remaining = cur.fetchone()
        assert seal_status == "violated"
        assert {issue["code"] for issue in remaining} == {
            "PERSISTED_VIOLATION",
            blocking_code,
        }


def test_violated_object_prevents_synthetic_latch_recovery() -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        setup = _setup(
            conn,
            [{"code": "PERSISTED_VIOLATION"}, {"code": "FULL_VERIFY_REQUIRED"}],
        )
        with conn.cursor() as cur:
            cur.execute(
                "update app.evidence_objects set seal_status='violated' where id=%s",
                (setup[2],),
            )
            cur.execute(
                "select seal_status,issues from app.evidence_chain_heads where case_id=%s",
                (setup[0],),
            )
            before_head = cur.fetchone()
            cur.execute(
                "select count(*) from app.evidence_storage_verifications where case_id=%s",
                (setup[0],),
            )
            before_receipts = cur.fetchone()
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            with conn.transaction():
                _verify(conn, setup)
        with conn.cursor() as cur:
            cur.execute(
                "select seal_status,issues from app.evidence_chain_heads where case_id=%s",
                (setup[0],),
            )
            assert cur.fetchone() == before_head
            cur.execute(
                "select count(*) from app.evidence_storage_verifications where case_id=%s",
                (setup[0],),
            )
            assert cur.fetchone() == before_receipts == (0,)


@pytest.mark.parametrize(
    "blocking_code",
    ("LEDGER_INVALID", "CONFLICTING_AUTHORITY", "FUTURE_UNKNOWN_VIOLATION"),
)
def test_reconciliation_and_second_verify_cannot_launder_cause(blocking_code: str) -> None:
    psycopg = pytest.importorskip("psycopg")
    issues = [
        {"code": "PERSISTED_VIOLATION"},
        {"code": "FULL_VERIFY_REQUIRED"},
        {"code": "INVENTORY_SCAN_FAILED"},
        {"code": blocking_code},
    ]
    with psycopg.connect(_dsn()) as conn:
        setup = _setup(conn, issues)
        _verify(conn, setup)
        _reconcile_persisted_only(conn, setup)
        _verify(conn, setup)
        with conn.cursor() as cur:
            cur.execute(
                "select seal_status,issues from app.evidence_chain_heads where case_id=%s",
                (setup[0],),
            )
            seal_status, remaining = cur.fetchone()
        assert seal_status == "violated"
        assert {issue["code"] for issue in remaining} == {
            "PERSISTED_VIOLATION", blocking_code,
        }


def test_complete_reconciliation_clears_transient_inventory_scan_failure() -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        setup = _setup(conn, [{"code": "INVENTORY_SCAN_FAILED"}])
        _reconcile_persisted_only(conn, setup)
        with conn.cursor() as cur:
            cur.execute(
                "select seal_status,issues from app.evidence_chain_heads where case_id=%s",
                (setup[0],),
            )
            assert cur.fetchone() == ("sealed", [])


def test_pending_only_issue_remains_unsealed_after_full_verify() -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        setup = _setup(conn, [
            {"code": "FULL_VERIFY_REQUIRED"},
            {"code": "DETECTED_NEW_ITEM"},
        ])
        with conn.cursor() as cur:
            cur.execute(
                """insert into app.evidence_objects(
                     id,case_id,display_name,display_path,status,seal_status)
                   values(%s,%s,'pending.raw','evidence/pending.raw','detected','unsealed')""",
                (uuid.uuid4(), setup[0]),
            )
        _verify(conn, setup)
        with conn.cursor() as cur:
            cur.execute(
                "select seal_status,issues from app.evidence_chain_heads where case_id=%s",
                (setup[0],),
            )
            seal_status, remaining = cur.fetchone()
        assert seal_status == "unsealed"
        assert {issue["code"] for issue in remaining} == {"DETECTED_NEW_ITEM"}


def test_wrong_generation_and_unauthorized_source_change_remain_blocked() -> None:
    psycopg = pytest.importorskip("psycopg")
    issues = [
        {"code": "PERSISTED_VIOLATION"},
        {"code": "FULL_VERIFY_REQUIRED"},
        {"code": "POSTURE_DRIFT", "storage_generation": 2},
        {"code": "STORAGE_SOURCE_CHANGED", "storage_generation": 1},
    ]
    with psycopg.connect(_dsn()) as conn:
        setup = _setup(conn, issues)
        _verify(conn, setup)
        with conn.cursor() as cur:
            cur.execute(
                "select seal_status,issues from app.evidence_chain_heads where case_id=%s",
                (setup[0],),
            )
            seal_status, remaining = cur.fetchone()
        assert seal_status == "violated"
        assert {issue["code"] for issue in remaining} == {
            "PERSISTED_VIOLATION",
            "POSTURE_DRIFT",
            "STORAGE_SOURCE_CHANGED",
        }


def test_stale_generation_wrong_profile_and_changed_bytes_fail_closed() -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        setup = _setup(
            conn,
            [{"code": "PERSISTED_VIOLATION"}, {"code": "FULL_VERIFY_REQUIRED"}],
        )
        with pytest.raises(psycopg.errors.SerializationFailure):
            with conn.transaction():
                _verify(conn, setup, generation=2)
        with pytest.raises(psycopg.errors.SerializationFailure):
            with conn.transaction():
                _verify(conn, setup, profile="EXTERNALLY_READ_ONLY")
        changed_items = [
            {**setup[3][0], "sha256": "sha256:" + "c" * 64}
        ]
        with pytest.raises(psycopg.errors.InvalidParameterValue):
            with conn.transaction():
                _verify(conn, setup, items=changed_items)
        with conn.cursor() as cur:
            cur.execute(
                "select seal_status from app.evidence_chain_heads where case_id=%s",
                (setup[0],),
            )
            assert cur.fetchone() == ("violated",)
            cur.execute(
                "select count(*) from app.evidence_storage_verifications where case_id=%s",
                (setup[0],),
            )
            assert cur.fetchone() == (0,)


def test_duplicate_correlation_rolls_back_without_second_receipt() -> None:
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(_dsn()) as conn:
        setup = _setup(
            conn,
            [{"code": "PERSISTED_VIOLATION"}, {"code": "FULL_VERIFY_REQUIRED"}],
        )
        _state, correlation = _verify(conn, setup)
        conn.commit()
        with pytest.raises(psycopg.errors.UniqueViolation):
            with conn.transaction():
                _verify(conn, setup, correlation=correlation)
        with conn.cursor() as cur:
            cur.execute(
                "select count(*) from app.evidence_storage_verifications "
                "where case_id=%s and correlation_id=%s",
                (setup[0], correlation),
            )
            assert cur.fetchone() == (1,)


def test_runtime_roles_cannot_execute_pre_recovery_verifier() -> None:
    psycopg = pytest.importorskip("psycopg")
    signature = (
        "app.evidence_storage_commit_full_verify_pre_posture_recovery"
        "(uuid,bigint,text,text,text,boolean,integer,jsonb,text,uuid,text)"
    )
    with psycopg.connect(_dsn()) as conn:
        with conn.cursor() as cur:
            for role in ("public", "anon", "authenticated", "service_role"):
                cur.execute(
                    "select has_function_privilege(%s,%s,'EXECUTE')",
                    (role, signature),
                )
                assert cur.fetchone() == (False,), role
