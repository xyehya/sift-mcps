"""Tests for sift_core.verification — DB-only approval-commit ledger (FORK-2).

The file HMAC ledger writer (``write_ledger_entry`` + ``compute_hmac``) was
RETIRED: the approval-commit ledger is now an append-only, per-case hash-linked
DB table (``app.approval_commit_events``) written via
``app.approval_append_commit_event``. These tests cover the Python helpers that
drive that RPC, using the repo's fake-psycopg idiom (an in-memory connection that
simulates the chain RPC) so no live database is required. The trigger/RPC SQL
itself is exercised against live Postgres (see the unit report).
"""

from __future__ import annotations

import hashlib

import pytest
from sift_core.verification import (
    _validate_case_id,
    append_approval_commit_event_db,
    read_approval_commit_tip_db,
)

_DSN = "postgresql://service@localhost/sift"
_CASE = "11111111-1111-1111-1111-111111111111"


# --------------------------------------------------------------------------- #
# Fake psycopg connection that simulates app.approval_append_commit_event /
# app.approval_commit_tip, including the prev_hash/event_hash chain math so a
# test can assert the chain links exactly as the SQL does.
# --------------------------------------------------------------------------- #


def _sql_event_hash(prev_hash, case_id, seq, item_id, item_type, action,
                    content_hash, reauth, details):
    payload = "|".join([
        prev_hash or "",
        str(case_id),
        str(seq),
        item_id,
        item_type,
        action,
        content_hash or "",
        str(reauth or ""),
        details or "{}",
    ])
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


class FakeLedgerDB:
    """In-memory mirror of app.approval_commit_events + app.approval_commit_heads."""

    def __init__(self):
        # case_id -> list of event dicts (append-only)
        self.events: dict[str, list[dict]] = {}
        # case_id -> (head_seq, head_hash)
        self.heads: dict[str, tuple[int, str]] = {}
        self.committed = 0


class FakeCursor:
    def __init__(self, db: FakeLedgerDB):
        self._db = db
        self._result = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):
        s = " ".join(sql.split())
        if "approval_append_commit_event" in s:
            (case_id, item_id, item_type, action, content_hash, reauth,
             approved_by, actor_user, actor_service, details) = params
            prev_seq, prev_hash = self._db.heads.get(case_id, (0, ""))
            seq = prev_seq + 1
            event_hash = _sql_event_hash(
                prev_hash, case_id, seq, item_id, item_type, action,
                content_hash, reauth, details,
            )
            row = {
                "id": f"evt-{case_id}-{seq}",
                "seq": seq,
                "item_id": item_id,
                "item_type": item_type,
                "action": action,
                "content_hash": content_hash,
                "prev_hash": prev_hash,
                "event_hash": event_hash,
                "approved_by": approved_by,
            }
            self._db.events.setdefault(case_id, []).append(row)
            self._db.heads[case_id] = (seq, event_hash)
            self._result = (row["id"],)
        elif "approval_commit_tip" in s:
            (case_id,) = params
            seq, head_hash = self._db.heads.get(case_id, (0, ""))
            count = len(self._db.events.get(case_id, []))
            self._result = (seq, head_hash, count)
        else:  # pragma: no cover - defensive
            self._result = None

    def fetchone(self):
        return self._result


class FakeConnection:
    def __init__(self, db: FakeLedgerDB):
        self._db = db

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return FakeCursor(self._db)

    def commit(self):
        self._db.committed += 1


def _make_connect(db: FakeLedgerDB):
    def _connect(dsn):
        assert dsn == _DSN
        return FakeConnection(db)
    return _connect


# --------------------------------------------------------------------------- #
# append_approval_commit_event_db — DB hash-chain authority
# --------------------------------------------------------------------------- #


class TestAppendApprovalCommitEvent:
    def test_append_writes_chained_rows(self):
        """Two appends form a prev_hash/event_hash chain: event2.prev == event1.event."""
        db = FakeLedgerDB()
        connect = _make_connect(db)

        eid1 = append_approval_commit_event_db(
            _CASE, item_id="F-001", item_type="finding",
            content_hash="sha256:" + "a" * 64, action="APPROVED",
            reauth_audit_event_id="audit-1", approved_by="alice",
            dsn=_DSN, connect=connect,
        )
        eid2 = append_approval_commit_event_db(
            _CASE, item_id="T-002", item_type="timeline",
            content_hash="sha256:" + "b" * 64, action="APPROVED",
            reauth_audit_event_id="audit-1", approved_by="alice",
            dsn=_DSN, connect=connect,
        )

        assert eid1 and eid2 and eid1 != eid2
        events = db.events[_CASE]
        assert len(events) == 2
        # Genesis event links from the empty prev_hash.
        assert events[0]["prev_hash"] == ""
        assert events[0]["seq"] == 1
        # Second event's prev_hash is the first event's event_hash — chain link.
        assert events[1]["prev_hash"] == events[0]["event_hash"]
        assert events[1]["seq"] == 2
        # event_hash is a sha256:<hex> over canonical fields.
        for ev in events:
            assert ev["event_hash"].startswith("sha256:")
            assert len(ev["event_hash"].split(":", 1)[1]) == 64
        # The write is committed.
        assert db.committed == 2

    def test_no_dsn_is_noop(self, monkeypatch):
        """With no control-plane DSN, the helper is a no-op (returns None) and never
        falls back to a file ledger."""
        monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
        result = append_approval_commit_event_db(
            _CASE, item_id="F-001", item_type="finding", content_hash=None,
        )
        assert result is None


# --------------------------------------------------------------------------- #
# read_approval_commit_tip_db — reconciliation reads the DB ledger as authority
# --------------------------------------------------------------------------- #


class TestReadApprovalCommitTip:
    def test_tip_reflects_chain_head(self):
        db = FakeLedgerDB()
        connect = _make_connect(db)
        append_approval_commit_event_db(
            _CASE, item_id="F-001", item_type="finding", content_hash=None,
            dsn=_DSN, connect=connect,
        )
        append_approval_commit_event_db(
            _CASE, item_id="F-002", item_type="finding", content_hash=None,
            dsn=_DSN, connect=connect,
        )
        tip = read_approval_commit_tip_db(_CASE, dsn=_DSN, connect=connect)
        assert tip["head_seq"] == 2
        assert tip["event_count"] == 2
        # Tip hash equals the last appended event's event_hash (authority tip).
        assert tip["head_hash"] == db.events[_CASE][-1]["event_hash"]

    def test_tip_no_dsn_is_none(self, monkeypatch):
        monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
        assert read_approval_commit_tip_db(_CASE) is None


# --------------------------------------------------------------------------- #
# Retained: case-id validation guard (kept for the legacy backup export path)
# --------------------------------------------------------------------------- #


class TestCaseIdValidation:
    def test_rejects_traversal_and_empty(self):
        with pytest.raises(ValueError, match="path traversal"):
            _validate_case_id("../evil")
        with pytest.raises(ValueError, match="path traversal"):
            _validate_case_id("../../etc/passwd")
        with pytest.raises(ValueError, match="empty"):
            _validate_case_id("")
