"""Unit 2 / Gap B-D2: ingest subprocess forward-writes one app.audit_events row
per artifact, keyed by the per-artifact ``opensearchingest*`` id as
``details.backend_audit_id`` so a finding that cites that id resolves in the
DB-mode portal panel.

These exercise ``_persist_ingest_audit_event`` directly with a faithful in-memory
fake ``psycopg`` so no real Postgres is needed. The contract under test:

  * a correct INSERT (event_type / actor_type=service / status / case_id uuid /
    backend_audit_id) is emitted when a DSN AND a case UUID are available;
  * the helper is a no-op (NO connect attempt) when the DSN is absent, when no
    case UUID can be determined, or when the audit_id is empty — never a row with
    a wrong/NULL case_id that would not resolve;
  * any connect / insert error is swallowed (fail-soft) and never raised, so an
    ingest can never be blocked by a provenance-write failure;
  * no absolute path lands in the stored ``details``.
"""

from __future__ import annotations

import sys
import types

import pytest

from opensearch_mcp import ingest as ing


class _FakeCursor:
    def __init__(self, store):
        self._store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, values):
        self._store["sql"] = sql
        self._store["values"] = values


class _FakeConn:
    def __init__(self, store):
        self._store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return _FakeCursor(self._store)

    def commit(self):
        self._store["committed"] = True


def _install_fake_psycopg(monkeypatch, store, *, raise_on_connect=False):
    """Inject a fake ``psycopg`` (with ``.types.json.Jsonb``) into sys.modules."""
    mod = types.ModuleType("psycopg")

    def connect(dsn):
        store["dsn"] = dsn
        if raise_on_connect:
            raise RuntimeError("boom: unreachable db")
        return _FakeConn(store)

    mod.connect = connect
    types_mod = types.ModuleType("psycopg.types")
    json_mod = types.ModuleType("psycopg.types.json")

    class Jsonb:
        def __init__(self, value):
            self.value = value

    json_mod.Jsonb = Jsonb
    types_mod.json = json_mod
    monkeypatch.setitem(sys.modules, "psycopg", mod)
    monkeypatch.setitem(sys.modules, "psycopg.types", types_mod)
    monkeypatch.setitem(sys.modules, "psycopg.types.json", json_mod)


def test_writes_row_with_backend_audit_id_and_case_uuid(monkeypatch):
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://svc:pw@db/sift")
    monkeypatch.setenv("SIFT_CASE_UUID", "11111111-1111-1111-1111-111111111111")

    ing._persist_ingest_audit_event(
        "opensearchingest4242-examiner-20260624-007",
        tool="ingest_evtx",
        status="success",
        run_id="run-9",
        mcp_name="opensearch-ingest-4242",
        hostname="DC01",
        index_name="case-1-evtx-dc01",
        result_summary="1800 indexed, 0 skipped",
    )

    assert store.get("committed") is True
    cols = store["sql"]
    assert "insert into app.audit_events" in cols
    vals = store["values"]
    # positional: event_type, actor_type, source, status, case_id, summary, details
    assert vals[0] == "opensearch.ingest.artifact"
    assert vals[1] == "service"
    assert vals[3] == "success"
    assert vals[4] == "11111111-1111-1111-1111-111111111111"
    details = vals[6].value  # fake Jsonb wraps the dict
    assert details["backend_audit_id"] == "opensearchingest4242-examiner-20260624-007"
    assert details["tool"] == "ingest_evtx"
    assert details["hostname"] == "DC01"
    assert details["index_name"] == "case-1-evtx-dc01"
    # No absolute path leaked into details.
    assert "/" not in str(details.get("result_summary", ""))


def test_failure_status_maps_to_failure(monkeypatch):
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://x@db/s")
    monkeypatch.setenv("SIFT_CASE_UUID", "22222222-2222-2222-2222-222222222222")
    ing._persist_ingest_audit_event(
        "aid-1", tool="ingest_mft", status="failure", result_summary="FAILED: ValueError"
    )
    assert store["values"][3] == "failure"


def test_noop_without_dsn(monkeypatch):
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    monkeypatch.setenv("SIFT_CASE_UUID", "33333333-3333-3333-3333-333333333333")
    ing._persist_ingest_audit_event("aid-1", tool="ingest_evtx", status="success")
    # No connect attempt at all.
    assert "dsn" not in store
    assert "committed" not in store


def test_noop_without_case_uuid(monkeypatch):
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://x@db/s")
    monkeypatch.delenv("SIFT_CASE_UUID", raising=False)
    # No case uuid passed and none in env -> must NOT write a row (a NULL/wrong
    # case_id would never resolve in the case-scoped resolver).
    ing._persist_ingest_audit_event("aid-1", tool="ingest_evtx", status="success", case_id=None)
    assert "dsn" not in store


def test_noop_without_audit_id(monkeypatch):
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://x@db/s")
    monkeypatch.setenv("SIFT_CASE_UUID", "44444444-4444-4444-4444-444444444444")
    ing._persist_ingest_audit_event(None, tool="ingest_evtx", status="success")
    ing._persist_ingest_audit_event("", tool="ingest_evtx", status="success")
    assert "dsn" not in store


def test_connect_error_is_swallowed(monkeypatch):
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store, raise_on_connect=True)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://x@db/s")
    monkeypatch.setenv("SIFT_CASE_UUID", "55555555-5555-5555-5555-555555555555")
    # Must NOT raise — ingest can never be blocked by a provenance write failure.
    ing._persist_ingest_audit_event("aid-1", tool="ingest_evtx", status="success")
    assert store.get("committed") is None


def test_explicit_case_id_arg_wins(monkeypatch):
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://x@db/s")
    monkeypatch.delenv("SIFT_CASE_UUID", raising=False)
    ing._persist_ingest_audit_event(
        "aid-1", tool="ingest_evtx", status="success",
        case_id="66666666-6666-6666-6666-666666666666",
    )
    assert store["values"][4] == "66666666-6666-6666-6666-666666666666"


def test_summary_is_bounded(monkeypatch):
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://x@db/s")
    monkeypatch.setenv("SIFT_CASE_UUID", "77777777-7777-7777-7777-777777777777")
    ing._persist_ingest_audit_event(
        "aid-1", tool="ingest_evtx", status="success", result_summary="X" * 5000
    )
    details = store["values"][6].value
    assert len(details["result_summary"]) <= ing._INGEST_AUDIT_SUMMARY_MAX + 20
    assert details["result_summary"].endswith("...[truncated]")
