"""BATCH-K2 — core investigation DB authority store + cutover behavior.

Covers:
  * PostgresInvestigationStore against a faithful in-memory fake connection:
    agent upsert cannot overwrite human-APPROVED/REJECTED rows; approve/reject/
    edit transitions are version/content-hash guarded; report_inputs returns
    only APPROVED rows with DB columns as authority.
  * CaseManager in DB-active mode writes findings/timeline/iocs/todos to the
    store first and reads them back from the store (case JSON tampering is inert).
"""

from __future__ import annotations

import pytest

from sift_core.investigation_store import (
    PostgresInvestigationStore,
    ReviewAction,
    StaleVersionError,
    compute_content_hash,
    is_human_locked,
)


# --------------------------------------------------------------------------- #
# In-memory fake psycopg connection backing the store's SQL.
# --------------------------------------------------------------------------- #


class _Row(dict):
    pass


class FakeDB:
    """Holds rows keyed by (table, case_id, item_id)."""

    def __init__(self):
        # table -> {(case_id, item_id): dict}
        self.tables = {
            "app.investigation_findings": {},
            "app.investigation_timeline_events": {},
            "app.investigation_iocs": {},
            "app.investigation_todos": {},
        }


class FakeCursor:
    def __init__(self, db: FakeDB):
        self._db = db
        self._result = None
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def _id_col(self, table):
        return "todo_id" if table.endswith("todos") else "item_id"

    def execute(self, sql, params=()):
        s = " ".join(sql.split())
        self._result = None
        self.rowcount = 0
        table = next((t for t in self._db.tables if t in s), None)
        if table is None:
            return
        idc = self._id_col(table)
        store = self._db.tables[table]

        if s.startswith("select status, version from") and "for update" in s:
            case_id, item_id = params
            row = store.get((case_id, item_id))
            self._result = [(row["status"], row["version"])] if row else []
        elif s.startswith("select payload, status, version from") and "for update" in s:
            case_id, item_id = params
            row = store.get((case_id, item_id))
            self._result = (
                [(row["payload"], row["status"], row["version"])] if row else []
            )
        elif s.startswith("select payload, status, version from"):
            case_id = params[0]
            self._result = [
                (r["payload"], r["status"], r["version"])
                for (cid, _iid), r in store.items()
                if cid == case_id
            ]
        elif s.startswith("select payload, content_hash, approved_by, version from"):
            case_id = params[0]
            self._result = [
                (r["payload"], r.get("content_hash"), r.get("approved_by"), r["version"])
                for (cid, _iid), r in store.items()
                if cid == case_id and str(r["status"]).upper() == "APPROVED"
            ]
        elif s.startswith("insert into"):
            self._do_insert(table, idc, s, params, store)
        elif s.startswith("update"):
            self._do_update(table, idc, s, params, store)

    def _do_insert(self, table, idc, s, params, store):
        # IOC inserts carry value+ioc_type; others carry content_hash.
        if table.endswith("iocs"):
            case_id, item_id, status, value, ioc_type, payload, created_by = params[:7]
            key = (case_id, item_id)
            existing = store.get(key)
            if existing:
                existing.update(
                    status=status, value=value, ioc_type=ioc_type, payload=payload,
                    version=existing["version"] + 1,
                )
                row = existing
            else:
                row = dict(
                    status=status, value=value, ioc_type=ioc_type, payload=payload,
                    created_by=created_by, version=1,
                )
                store[key] = row
            self._result = [(row["status"], row["version"])]
        elif table.endswith("todos"):
            case_id, item_id, status, priority, assignee, payload, created_by = params[:7]
            key = (case_id, item_id)
            existing = store.get(key)
            if existing:
                existing.update(status=status, payload=payload, version=existing["version"] + 1)
                row = existing
            else:
                row = dict(status=status, payload=payload, version=1)
                store[key] = row
            self._result = [(row["status"], row["version"])]
        else:
            case_id, item_id, status, content_hash, payload, created_by = params[:6]
            key = (case_id, item_id)
            existing = store.get(key)
            if existing:
                existing.update(
                    status=status, content_hash=content_hash, payload=payload,
                    version=existing["version"] + 1,
                )
                row = existing
            else:
                row = dict(
                    status=status, content_hash=content_hash, payload=payload,
                    created_by=created_by, version=1,
                )
                store[key] = row
            self._result = [(row["status"], row["version"])]

    def _do_update(self, table, idc, s, params, store):
        # Review update ends with: where case_id = %s and <id> = %s and version = %s
        case_id, item_id, version = params[-3], params[-2], params[-1]
        key = (case_id, item_id)
        row = store.get(key)
        if not row or row["version"] != version:
            self.rowcount = 0
            return
        if table.endswith("iocs"):
            status, value, ioc_type, payload, content_hash, approved_by, rejected_by, reauth = params[:8]
            row.update(value=value, ioc_type=ioc_type)
        else:
            status, payload, content_hash, approved_by, rejected_by, reauth = params[:6]
        row.update(
            status=status, payload=payload, content_hash=content_hash,
            approved_by=approved_by, rejected_by=rejected_by,
            reauth_audit_event_id=reauth, version=row["version"] + 1,
        )
        self.rowcount = 1

    def fetchone(self):
        if self._result:
            return self._result[0]
        return None

    def fetchall(self):
        return list(self._result or [])


class FakeConn:
    def __init__(self, db):
        self._db = db

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return FakeCursor(self._db)

    def commit(self):
        pass

    def rollback(self):
        pass


def _store_with_db():
    db = FakeDB()
    store = PostgresInvestigationStore("postgresql://fake")
    store._connect = lambda: FakeConn(db)  # type: ignore[assignment]
    return store, db


CASE = "11111111-1111-1111-1111-111111111111"


def _jsonb_passthrough(monkeypatch):
    # Avoid importing real psycopg Jsonb; store the dict directly so the fake DB
    # can round-trip it.
    import sift_core.investigation_store as mod

    monkeypatch.setattr(mod, "_jsonb", lambda v: v)


# --------------------------------------------------------------------------- #
# Store unit tests
# --------------------------------------------------------------------------- #


def test_human_locked_predicate():
    assert is_human_locked("APPROVED")
    assert is_human_locked("rejected")
    assert not is_human_locked("DRAFT")
    assert not is_human_locked(None)


def test_agent_upsert_creates_draft_and_lists(monkeypatch):
    _jsonb_passthrough(monkeypatch)
    store, _ = _store_with_db()
    res = store.upsert_finding(CASE, "F-a-001", {"title": "x", "status": "DRAFT"})
    assert res["applied"] is True
    rows = store.list_findings(CASE)
    assert rows[0]["title"] == "x"
    assert rows[0]["status"] == "DRAFT"


def test_agent_cannot_assert_approved_status(monkeypatch):
    _jsonb_passthrough(monkeypatch)
    store, _ = _store_with_db()
    # Agent tries to self-approve; store forces DRAFT.
    res = store.upsert_finding(CASE, "F-a-001", {"title": "x", "status": "APPROVED"})
    assert res["status"] == "DRAFT"


def test_agent_cannot_overwrite_human_locked_row(monkeypatch):
    _jsonb_passthrough(monkeypatch)
    store, _ = _store_with_db()
    store.upsert_finding(CASE, "F-a-001", {"title": "x"})
    # Human approves.
    r = store.apply_review(
        CASE,
        [ReviewAction(item_id="F-a-001", action="approve")],
        examiner="alice",
        reauth_audit_event_id="evt-1",
    )
    assert r.approved == 1
    # Agent tries to overwrite — refused, row unchanged.
    res = store.upsert_finding(CASE, "F-a-001", {"title": "tampered"})
    assert res["applied"] is False
    assert res["reason"] == "human_locked"
    rows = store.list_findings(CASE)
    assert rows[0]["status"] == "APPROVED"
    assert rows[0]["title"] == "x"


def test_approve_recomputes_content_hash_and_records_reauth(monkeypatch):
    _jsonb_passthrough(monkeypatch)
    store, db = _store_with_db()
    store.upsert_finding(CASE, "F-a-001", {"title": "x", "observation": "o"})
    store.apply_review(
        CASE,
        [ReviewAction(item_id="F-a-001", action="approve")],
        examiner="alice",
        reauth_audit_event_id="evt-7",
    )
    row = db.tables["app.investigation_findings"][(CASE, "F-a-001")]
    assert row["status"] == "APPROVED"
    assert row["approved_by"] == "alice"
    assert row["reauth_audit_event_id"] == "evt-7"
    assert row["content_hash"] == compute_content_hash(row["payload"])


def test_stale_version_skips_approval(monkeypatch):
    _jsonb_passthrough(monkeypatch)
    store, _ = _store_with_db()
    store.upsert_finding(CASE, "F-a-001", {"title": "x"})  # version 1
    store.upsert_finding(CASE, "F-a-001", {"title": "x2"})  # version 2
    # Operator reviewed version 1 — stale.
    r = store.apply_review(
        CASE,
        [ReviewAction(item_id="F-a-001", action="approve", version_at_review=1)],
        examiner="alice",
        reauth_audit_event_id="evt-1",
    )
    assert r.approved == 0
    assert r.skipped and r.skipped[0][1] == "stale version"


def test_stale_content_hash_skips_approval(monkeypatch):
    _jsonb_passthrough(monkeypatch)
    store, _ = _store_with_db()
    store.upsert_finding(CASE, "F-a-001", {"title": "x"})
    r = store.apply_review(
        CASE,
        [ReviewAction(item_id="F-a-001", action="approve", content_hash_at_review="deadbeef")],
        examiner="alice",
        reauth_audit_event_id="evt-1",
    )
    assert r.approved == 0
    assert r.skipped[0][1] == "stale content hash"


def test_reject_then_report_inputs_excludes_it(monkeypatch):
    _jsonb_passthrough(monkeypatch)
    store, _ = _store_with_db()
    store.upsert_finding(CASE, "F-a-001", {"title": "keep"})
    store.upsert_finding(CASE, "F-a-002", {"title": "drop"})
    store.apply_review(
        CASE,
        [
            ReviewAction(item_id="F-a-001", action="approve"),
            ReviewAction(item_id="F-a-002", action="reject", rejection_reason="noise"),
        ],
        examiner="alice",
        reauth_audit_event_id="evt-1",
    )
    inputs = store.report_inputs(CASE)
    titles = [f["title"] for f in inputs["findings"]]
    assert titles == ["keep"]
    assert all(f["status"] == "APPROVED" for f in inputs["findings"])


def test_edit_applies_modifications_and_keeps_status(monkeypatch):
    _jsonb_passthrough(monkeypatch)
    store, db = _store_with_db()
    store.upsert_finding(CASE, "F-a-001", {"title": "x", "confidence": "LOW"})
    r = store.apply_review(
        CASE,
        [
            ReviewAction(
                item_id="F-a-001",
                action="edit",
                modifications={"confidence": {"original": "LOW", "modified": "HIGH"}},
            )
        ],
        examiner="alice",
        reauth_audit_event_id="evt-1",
    )
    assert r.edited == 1
    row = db.tables["app.investigation_findings"][(CASE, "F-a-001")]
    assert row["payload"]["confidence"] == "HIGH"
    assert row["status"] == "DRAFT"  # edit does not approve


def test_edit_conflict_when_original_changed(monkeypatch):
    _jsonb_passthrough(monkeypatch)
    store, _ = _store_with_db()
    store.upsert_finding(CASE, "F-a-001", {"title": "x", "confidence": "MEDIUM"})
    r = store.apply_review(
        CASE,
        [
            ReviewAction(
                item_id="F-a-001",
                action="edit",
                modifications={"confidence": {"original": "LOW", "modified": "HIGH"}},
            )
        ],
        examiner="alice",
        reauth_audit_event_id="evt-1",
    )
    assert r.edited == 0
    assert "changed since review" in r.skipped[0][1]


# --------------------------------------------------------------------------- #
# CaseManager DB-active cutover: writes/reads go to the store, files are inert
# --------------------------------------------------------------------------- #


class InMemoryStore:
    """Minimal in-memory InvestigationAuthorityStore for core integration."""

    def __init__(self):
        self.findings = {}
        self.timeline = {}
        self.iocs = {}
        self.todos = {}

    def _up(self, bucket, item_id, payload):
        if is_human_locked(bucket.get(item_id, {}).get("status")):
            return {"applied": False, "reason": "human_locked"}
        row = dict(payload)
        bucket[item_id] = row
        return {"applied": True, "status": row.get("status")}

    def upsert_finding(self, case_id, item_id, payload, *, actor=None):
        return self._up(self.findings, item_id, payload)

    def upsert_timeline_event(self, case_id, item_id, payload, *, actor=None):
        return self._up(self.timeline, item_id, payload)

    def upsert_ioc(self, case_id, item_id, payload, *, actor=None):
        return self._up(self.iocs, item_id, payload)

    def upsert_todo(self, case_id, todo_id, payload, *, actor=None):
        return self._up(self.todos, todo_id, payload)

    def list_findings(self, case_id):
        return list(self.findings.values())

    def list_timeline(self, case_id):
        return list(self.timeline.values())

    def list_iocs(self, case_id):
        return list(self.iocs.values())

    def list_todos(self, case_id):
        return list(self.todos.values())

    def apply_review(self, *a, **k):  # pragma: no cover - not used here
        raise NotImplementedError

    def report_inputs(self, case_id):  # pragma: no cover
        raise NotImplementedError


@pytest.fixture
def db_active_manager(tmp_path, monkeypatch):
    """A CaseManager bound to a DB-active AuthorityContext + in-memory store."""
    from sift_core.active_case_context import AuthorityContext, use_active_case_context
    from sift_core.case_manager import CaseManager
    import sift_core.case_manager as cm

    case_dir = tmp_path / "case-k2-06080000"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-k2-06080000\nstatus: active\n")

    store = InMemoryStore()
    monkeypatch.setattr(
        cm.CaseManager, "_investigation_store", lambda self: store
    )

    ctx = AuthorityContext(
        case_id=CASE,
        case_key="case-k2-06080000",
        artifact_path=str(case_dir),
        db_active=True,
    )
    mgr = CaseManager()
    with use_active_case_context(ctx):
        yield mgr, store, case_dir


def test_record_finding_writes_to_db_store(db_active_manager):
    mgr, store, case_dir = db_active_manager
    finding = {
        "title": "Suspicious PowerShell",
        "type": "finding",
        "host": "WS01",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "HIGH",
        "confidence_justification": "because",
        "supporting_commands": [
            {"command": "analytical reasoning", "purpose": "p", "output_excerpt": "e"}
        ],
    }
    res = mgr.record_finding(finding, examiner_override="alice")
    assert res["status"] == "STAGED"
    fid = res["finding_id"]
    # Finding landed in the DB store, not just the file.
    assert fid in store.findings
    assert store.findings[fid]["status"] == "DRAFT"
    # get_findings reads from the store.
    assert any(f.get("id") == fid for f in mgr.get_findings())


def test_db_active_read_ignores_tampered_file(db_active_manager):
    mgr, store, case_dir = db_active_manager
    # Seed a DB finding.
    store.findings["F-alice-001"] = {"id": "F-alice-001", "title": "real", "status": "APPROVED"}
    # Tamper the case JSON with a fake APPROVED finding.
    (case_dir / "findings.json").write_text(
        '[{"id": "F-evil-999", "title": "INJECTED", "status": "APPROVED"}]'
    )
    findings = mgr.get_findings()
    ids = {f.get("id") for f in findings}
    assert "F-alice-001" in ids
    assert "F-evil-999" not in ids  # file tampering is inert in DB-active mode


def test_record_timeline_event_writes_to_db_store(db_active_manager):
    mgr, store, case_dir = db_active_manager
    res = mgr.record_timeline_event(
        {
            "title": "Logon",
            "timestamp": "2026-06-08T00:00:00Z",
            "description": "d",
            "host": "WS01",
            "source": "evtx",
        },
        examiner_override="alice",
    )
    assert res["status"] == "STAGED"
    assert res["event_id"] in store.timeline


def test_add_todo_writes_to_db_store(db_active_manager):
    mgr, store, case_dir = db_active_manager
    res = mgr.add_todo("check lateral movement", examiner_override="alice")
    assert res["status"] == "created"
    assert res["todo_id"] in store.todos
    assert mgr.list_todos()[0]["todo_id"] == res["todo_id"]
