"""E1 (XYE-34): per-process connection reuse for the case-metadata authority read.

These prove the spec §4 design:
  * one connection is reused per process (the socket is cached, never the result);
  * the created connection is pooler-safe + read-only + autocommit (no isolation
    raise) — fail-closed posture preserved;
  * a dead socket triggers exactly one reconnect + retry, then succeeds;
  * a query/programming error fails closed immediately with NO retry;
  * the fork hook drops inherited entries WITHOUT closing them.

All fakes avoid a live database; the real :func:`_connection_for` is exercised by
monkeypatching ``psycopg.connect`` so the actual connect kwargs are asserted.
"""

from __future__ import annotations

import os

import pytest

from sift_core import investigation_store
from sift_core.active_case_context import (
    AuthorityContext,
    use_active_case_context,
)
from sift_core.investigation_store import (
    InvestigationStoreError,
    PostgresCaseStore,
    resolve_case_metadata,
)

_DSN = "postgresql://service@localhost/sift"

# A valid app.cases row in _CASE_ROW_COLUMNS order:
# (id, case_key, title, description, status, legacy_case_dir, metadata)
_ROW = (
    "11111111-1111-1111-1111-111111111111",
    "inc-1",
    "DB Case",
    "from DB authority",
    "active",
    "/cases/inc-1",
    {"examiner": "alice"},
)


class FakeCursor:
    def __init__(self, conn: "FakeConn") -> None:
        self._conn = conn

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def execute(self, sql, params=None) -> None:
        self._conn.executes.append((sql, params))
        err = self._conn.execute_error
        if err is not None:
            # Raise only once so a reconnect+retry can succeed.
            self._conn.execute_error = None
            raise err

    def fetchone(self):
        return self._conn.row


class FakeConn:
    """Minimal psycopg3-Connection stand-in for the case-metadata read path."""

    def __init__(self, row=None, execute_error=None) -> None:
        self.row = row
        self.execute_error = execute_error
        self.closed = False
        self.executes: list = []

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _isolate_conn_cache():
    """Each test starts and ends with an empty module connection cache."""
    investigation_store._clear_cache()
    yield
    investigation_store._clear_cache()


class TestConnectionReuse:
    def test_factory_called_once_across_many_reads(self):
        calls: list[str] = []
        conn = FakeConn(row=_ROW)

        def provider(dsn):
            calls.append(dsn)
            return conn

        store = PostgresCaseStore(_DSN, connection_provider=provider)
        m1 = store.get_case_metadata("cid")
        m2 = store.get_case_metadata("cid")
        m3 = store.get_case_metadata("cid")

        assert len(calls) == 1, "connection must be created exactly once and reused"
        assert m1 == m2 == m3
        assert m1["name"] == "DB Case"
        assert m1["status"] == "open"  # active -> open
        # Re-queried each call (socket cached, result not): three executes.
        assert len(conn.executes) == 3

    def test_resolve_case_metadata_reuses_default_provider(self, monkeypatch):
        """The full contract path (default provider) reuses one connection."""
        calls: list[str] = []
        conn = FakeConn(row=_ROW)

        def provider(dsn):
            calls.append(dsn)
            return conn

        # Patch the module default provider + DSN + a bound DB-active context.
        monkeypatch.setattr(investigation_store, "_connection_for", provider)
        monkeypatch.setattr(investigation_store, "control_plane_dsn", lambda: _DSN)
        ctx = AuthorityContext(case_id="cid", case_key="inc-1", db_active=True)
        with use_active_case_context(ctx):
            m1 = resolve_case_metadata()
            m2 = resolve_case_metadata()

        assert len(calls) == 1
        assert m1 == m2
        assert m1["name"] == "DB Case"


class TestConnectionParameters:
    def test_pooler_safe_readonly_autocommit_kwargs(self, monkeypatch):
        import psycopg

        captured: dict = {}

        class FakeRealConn:
            def __init__(self) -> None:
                self.sets: list[str] = []

            def execute(self, sql) -> None:
                self.sets.append(sql)

            def close(self) -> None:  # pragma: no cover - not hit on success
                pass

        def fake_connect(dsn, **kwargs):
            captured["dsn"] = dsn
            captured["kwargs"] = kwargs
            return FakeRealConn()

        monkeypatch.setattr(psycopg, "connect", fake_connect)
        conn = investigation_store._connection_for(_DSN)
        kw = captured["kwargs"]

        assert captured["dsn"] == _DSN
        # prepare_threshold=None ⇒ no client prepared statements (pooler-safe).
        assert kw["prepare_threshold"] is None
        # autocommit ⇒ fresh MVCC snapshot per statement; no idle-in-txn.
        assert kw["autocommit"] is True
        assert kw["connect_timeout"] == 5
        assert kw["application_name"] == "sift-case-store"
        assert "statement_timeout=5000" in kw["options"]
        assert "idle_in_transaction_session_timeout=10000" in kw["options"]
        # Read-only posture applied on the session.
        assert any("default_transaction_read_only = on" in s for s in conn.sets)

    def test_isolation_never_raised_above_read_committed(self, monkeypatch):
        """Guard: the store must never set a non-default isolation level.

        A raised isolation level would hold a transaction open and freeze the
        snapshot — which could serve a stale 'open' for a closed case. The store
        relies on autocommit + the server default (READ COMMITTED) only.
        """
        import psycopg

        captured: dict = {}

        class FakeRealConn:
            def execute(self, sql) -> None:
                pass

            def close(self) -> None:  # pragma: no cover
                pass

        def fake_connect(dsn, **kwargs):
            captured["kwargs"] = kwargs
            return FakeRealConn()

        monkeypatch.setattr(psycopg, "connect", fake_connect)
        investigation_store._connection_for(_DSN)

        assert "isolation_level" not in captured["kwargs"]
        assert captured["kwargs"]["autocommit"] is True


class TestErrorHandling:
    def test_dead_socket_reconnects_once_then_succeeds(self):
        import psycopg

        calls: list[str] = []
        conn1 = FakeConn(
            row=_ROW, execute_error=psycopg.OperationalError("server closed connection")
        )
        conn2 = FakeConn(row=_ROW)
        conns = [conn1, conn2]

        def provider(dsn):
            calls.append(dsn)
            return conns[len(calls) - 1]

        store = PostgresCaseStore(_DSN, connection_provider=provider)
        meta = store.get_case_metadata("cid")

        assert meta["name"] == "DB Case"
        assert len(calls) == 2, "exactly one reconnect after a connection-level error"
        assert conn1.closed is True, "the dead connection must be evicted + closed"
        assert conn2.closed is False, "the live replacement stays cached (not closed)"

    def test_interface_error_also_reconnects_once(self):
        import psycopg

        calls: list[str] = []
        conn1 = FakeConn(
            row=_ROW, execute_error=psycopg.InterfaceError("connection already closed")
        )
        conn2 = FakeConn(row=_ROW)
        conns = [conn1, conn2]

        def provider(dsn):
            calls.append(dsn)
            return conns[len(calls) - 1]

        store = PostgresCaseStore(_DSN, connection_provider=provider)
        meta = store.get_case_metadata("cid")

        assert meta is not None
        assert len(calls) == 2

    def test_persistent_connection_error_fails_closed(self):
        import psycopg

        calls: list[str] = []

        def provider(dsn):
            calls.append(dsn)
            # Both the first borrow's read AND the retry's read fail.
            return FakeConn(
                row=_ROW, execute_error=psycopg.OperationalError("still down")
            )

        store = PostgresCaseStore(_DSN, connection_provider=provider)
        with pytest.raises(InvestigationStoreError):
            store.get_case_metadata("cid")
        # Initial attempt + exactly one retry = two provider calls, no more.
        assert len(calls) == 2

    def test_query_error_fails_closed_without_retry(self):
        import psycopg

        calls: list[str] = []
        conn = FakeConn(row=_ROW, execute_error=psycopg.ProgrammingError("bad column"))

        def provider(dsn):
            calls.append(dsn)
            return conn

        store = PostgresCaseStore(_DSN, connection_provider=provider)
        with pytest.raises(InvestigationStoreError):
            store.get_case_metadata("cid")

        assert len(calls) == 1, "a query/programming error must NOT trigger a retry"
        assert conn.closed is True, "the connection is evicted on any error"

    def test_missing_row_returns_none_not_error(self):
        conn = FakeConn(row=None)

        def provider(dsn):
            return conn

        store = PostgresCaseStore(_DSN, connection_provider=provider)
        # None (missing row) is a normal return here; resolve_case_metadata() is
        # the layer that turns a missing row into a fail-closed raise.
        assert store.get_case_metadata("cid") is None


class TestForkHook:
    def test_clear_cache_drops_entries_without_closing(self):
        conn = FakeConn(row=_ROW)
        investigation_store._CONN_CACHE[(os.getpid(), _DSN)] = conn

        investigation_store._clear_cache()

        assert investigation_store._CONN_CACHE == {}, "inherited entries are dropped"
        assert conn.closed is False, (
            "the fork hook must NOT close: closing a fd duplicated across fork "
            "would send a Terminate on the parent's shared server connection"
        )

    def test_clear_cache_resets_lock_usable_after_fork(self):
        # After the hook the lock must be acquirable (a fork can leave the old
        # lock held with no owner in the single-threaded child).
        investigation_store._clear_cache()
        acquired = investigation_store._CACHE_LOCK.acquire(blocking=False)
        assert acquired is True
        investigation_store._CACHE_LOCK.release()
