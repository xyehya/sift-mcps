"""BU3 (XYE-21): with a control-plane DSN, the file-authority readers must be
unreachable for DFIR tool calls; with DB authority active but no DSN, the core
resolvers must fail closed instead of silently downgrading to the file mirror.

These are the sift-core half of the cross-cutting BU3 regression: the file
readers (CASE.yaml, JSON finding/timeline/todo mirrors) are patched to *raise*,
and the orientation/status reader (``case_status_data`` — the data behind the
``case_info`` DFIR tool) must still succeed entirely from DB authority. If any
file reader were still on the path, the call would raise instead of returning
the DB-sourced snapshot.
"""

from __future__ import annotations

import pytest

from sift_core import case_ops, investigation_store
from sift_core.active_case_context import AuthorityContext, use_active_case_context
from sift_core.investigation_store import (
    InvestigationStoreError,
    resolve_case_metadata,
    resolve_investigation_store,
)


_DSN = "postgresql://service@localhost/sift"
_CASE_ID = "11111111-1111-1111-1111-111111111111"


def _boom(*args, **kwargs):  # pragma: no cover - only invoked if a file reader runs
    raise AssertionError("file-authority reader must be unreachable with a DSN")


class _FakeCaseStore:
    def __init__(self, dsn):
        assert dsn == _DSN

    def get_case_metadata(self, case_id):
        assert case_id == _CASE_ID
        return {
            "case_id": "inc-2026-09",
            "name": "DB Case",
            "status": "open",
            "examiner": "alice",
            "description": "from DB authority",
        }


class _FakeInvestigationStore:
    def __init__(self, dsn):
        assert dsn == _DSN

    def list_findings(self, case_id):
        return [{"status": "APPROVED"}, {"status": "DRAFT"}]

    def list_timeline(self, case_id):
        return [{"status": "APPROVED"}]

    def list_todos(self, case_id):
        return [{"status": "open"}, {"status": "done"}]


@pytest.fixture
def db_active_with_dsn(monkeypatch, tmp_path):
    """DB-active context + DSN + DB stores; every file reader raises if touched."""
    monkeypatch.setattr(investigation_store, "control_plane_dsn", lambda: _DSN)
    monkeypatch.setattr(investigation_store, "PostgresCaseStore", _FakeCaseStore)
    monkeypatch.setattr(
        investigation_store, "PostgresInvestigationStore", _FakeInvestigationStore
    )
    # Any attempt to read the file mirror is a hard failure.
    monkeypatch.setattr(case_ops, "load_findings", _boom)
    monkeypatch.setattr(case_ops, "load_timeline", _boom)
    monkeypatch.setattr(case_ops, "load_todos", _boom)
    ctx = AuthorityContext(
        case_id=_CASE_ID,
        case_key="db-case",
        artifact_path=str(tmp_path),
        db_active=True,
    )
    return ctx, tmp_path


class TestFileReadersUnreachableWithDsn:
    def test_case_status_data_serves_db_not_files(self, db_active_with_dsn):
        ctx, case_dir = db_active_with_dsn
        # Deliberately do NOT create CASE.yaml: the file branch would raise
        # ValueError("Not a SIFT case directory"); the DB path must be taken.
        with use_active_case_context(ctx):
            status = case_ops.case_status_data(case_dir)
        assert status["counters_authority"] == "db"
        assert status["name"] == "DB Case"
        assert status["status"] == "open"
        assert status["finding_count"] == 2
        assert status["finding_approved"] == 1
        assert status["timeline_count"] == 1
        assert status["todo_open"] == 1

    def test_resolve_case_metadata_serves_db(self, db_active_with_dsn):
        ctx, _ = db_active_with_dsn
        with use_active_case_context(ctx):
            meta = resolve_case_metadata()
        assert meta is not None
        assert meta["name"] == "DB Case"

    def test_resolve_investigation_store_is_db_store(self, db_active_with_dsn):
        ctx, _ = db_active_with_dsn
        with use_active_case_context(ctx):
            store = resolve_investigation_store()
        assert isinstance(store, _FakeInvestigationStore)


class TestDbActiveWithoutDsnFailsClosed:
    """BU3: DB-active + no DSN is a misconfiguration → fail closed, never file."""

    def test_resolve_case_metadata_raises(self, monkeypatch, tmp_path):
        monkeypatch.setattr(investigation_store, "control_plane_dsn", lambda: None)
        ctx = AuthorityContext(
            case_id=_CASE_ID, case_key="k", artifact_path=str(tmp_path), db_active=True
        )
        with use_active_case_context(ctx):
            with pytest.raises(InvestigationStoreError):
                resolve_case_metadata()

    def test_resolve_investigation_store_raises(self, monkeypatch):
        monkeypatch.setattr(investigation_store, "control_plane_dsn", lambda: None)
        ctx = AuthorityContext(case_id=_CASE_ID, case_key="k", db_active=True)
        with use_active_case_context(ctx):
            with pytest.raises(InvestigationStoreError):
                resolve_investigation_store()

    def test_file_mode_still_returns_none(self, monkeypatch):
        """Genuine file mode (DB authority not active) is preserved: no raise."""
        monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
        # No active-case context bound → db_authority_active() is False.
        assert resolve_case_metadata() is None
        assert resolve_investigation_store() is None
