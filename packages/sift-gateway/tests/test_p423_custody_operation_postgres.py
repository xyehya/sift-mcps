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


def test_real_postgres_begin_lock_cas_replay_append_only_and_grants():
    psycopg = pytest.importorskip("psycopg")
    case_id = uuid.uuid4()
    audit_id = uuid.uuid4()
    key = "test-" + uuid.uuid4().hex
    digest = "sha256:" + "1" * 64
    with psycopg.connect(_dsn()) as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute("select to_regclass('app.custody_operations')")
            if cur.fetchone()[0] is None:
                pytest.skip("P4.23.2 custody migration is not applied")
            cur.execute(
                "insert into app.cases(id,case_key,title,status) values(%s,%s,'P423 DB test','active')",
                (case_id, "p423-db-" + uuid.uuid4().hex),
            )
            cur.execute(
                """insert into app.audit_events(id,case_id,event_type,actor_type,source,status,details)
                   values(%s,%s,'reauth.evidence_seal','system','portal_reauth','success','{}')""",
                (audit_id, case_id),
            )
            args = (case_id, "ADD_SEAL", '{"schema_version":1,"files":[]}', digest,
                    "database contract test", audit_id, key, None, None)
            cur.execute("select id,phase from app.custody_operation_begin_or_resume(%s,%s,%s::jsonb,%s,%s,%s,%s,%s,%s)", args)
            op_id, phase = cur.fetchone()
            assert phase == "GATE_BLOCKED"
            cur.execute("select id,phase from app.custody_operation_begin_or_resume(%s,%s,%s::jsonb,%s,%s,%s,%s,%s,%s)", args)
            assert cur.fetchone() == (op_id, "GATE_BLOCKED")
            cur.execute("select phase from app.custody_operation_history where operation_id=%s order by id", (op_id,))
            assert [r[0] for r in cur.fetchall()] == ["REQUESTED", "GATE_BLOCKED"]
            cur.execute("select seal_status from app.evidence_chain_heads where case_id=%s", (case_id,))
            assert cur.fetchone()[0] == "unsealed"
            cur.execute("select phase from app.custody_operation_advance(%s,'GATE_BLOCKED','FILESYSTEM_APPLYING','{}')", (op_id,))
            assert cur.fetchone()[0] == "FILESYSTEM_APPLYING"
            cur.execute("select phase from app.custody_operation_fail(%s,'FILESYSTEM_APPLYING','injected_failure')", (op_id,))
            assert cur.fetchone()[0] == "FAILED_RECOVERABLE"

            cur.execute("savepoint append_only")
            with pytest.raises(psycopg.Error):
                cur.execute("update app.custody_operation_history set facts='{}' where operation_id=%s", (op_id,))
            cur.execute("rollback to savepoint append_only")
            cur.execute("savepoint no_truncate")
            with pytest.raises(psycopg.Error):
                cur.execute("truncate app.custody_operation_history")
            cur.execute("rollback to savepoint no_truncate")

            cur.execute(
                """select p.oid,has_function_privilege('public',p.oid,'EXECUTE')
                   from pg_proc p join pg_namespace n on n.oid=p.pronamespace
                   where n.nspname='app' and p.proname like 'custody_operation_%'"""
            )
            rows = cur.fetchall()
            assert rows and not any(public for _oid, public in rows)
        conn.rollback()
