"""Tests for the DB-authority evidence gate resolution path (BATCH-C1).

check_evidence_gate_db() resolves seal status from Postgres
(app.evidence_gate_status) by opaque case_id, NOT from files. Postgres is the
authority; file manifests/proofs are exports. The path is fail-closed.

psycopg is imported lazily inside the function, so these tests inject a fake
psycopg module via sys.modules to drive the mapping and error paths without a
live database.
"""

from __future__ import annotations

import sys
import types

import pytest

from sift_core.evidence_chain import ChainStatus
from sift_gateway.evidence_gate import check_evidence_gate_db


_DSN = "postgresql://service@localhost/sift"
_CASE = "11111111-1111-1111-1111-111111111111"


class _Cursor:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.conn.statements.append((sql, params))

    def fetchone(self):
        return self.conn.row


class _Connection:
    def __init__(self, row):
        self.row = row
        self.statements = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self):
        return _Cursor(self)


def _install_fake_psycopg(monkeypatch, *, row=None, raise_on_connect=None):
    module = types.ModuleType("psycopg")

    def connect(dsn):
        if raise_on_connect is not None:
            raise raise_on_connect
        connect.last_dsn = dsn
        return _Connection(row)

    module.connect = connect
    monkeypatch.setitem(sys.modules, "psycopg", module)
    return module


# ---------------------------------------------------------------------------
# Fail-closed without inputs
# ---------------------------------------------------------------------------

class TestFailClosedInputs:
    def test_no_case_id_is_blocked(self):
        result = check_evidence_gate_db(None, _DSN)
        assert result["blocked"] is True
        assert result["status"] == ChainStatus.UNSEALED

    def test_no_dsn_is_blocked(self):
        result = check_evidence_gate_db(_CASE, None)
        assert result["blocked"] is True
        assert result["status"] == ChainStatus.UNSEALED


# ---------------------------------------------------------------------------
# Status mapping from DB authority
# ---------------------------------------------------------------------------

class TestStatusMapping:
    def test_sealed_passes(self, monkeypatch):
        _install_fake_psycopg(monkeypatch, row=("sealed", 3, []))
        result = check_evidence_gate_db(_CASE, _DSN)
        assert result["blocked"] is False
        assert result["status"] == ChainStatus.OK
        assert result["manifest_version"] == 3

    def test_unsealed_is_blocked(self, monkeypatch):
        _install_fake_psycopg(monkeypatch, row=("unsealed", 0, []))
        result = check_evidence_gate_db(_CASE, _DSN)
        assert result["blocked"] is True
        assert result["status"] == ChainStatus.UNSEALED
        assert result["issues"]

    def test_violated_is_blocked(self, monkeypatch):
        _install_fake_psycopg(monkeypatch, row=("violated", 2, ["Modified: evidence/x"]))
        result = check_evidence_gate_db(_CASE, _DSN)
        assert result["blocked"] is True
        assert result["status"] == ChainStatus.LEDGER_ERROR
        assert "Modified: evidence/x" in result["issues"]

    def test_missing_head_row_is_blocked(self, monkeypatch):
        _install_fake_psycopg(monkeypatch, row=None)
        result = check_evidence_gate_db(_CASE, _DSN)
        assert result["blocked"] is True
        assert result["status"] == ChainStatus.UNSEALED

    def test_unknown_status_defaults_to_unsealed(self, monkeypatch):
        _install_fake_psycopg(monkeypatch, row=("weird", 1, []))
        result = check_evidence_gate_db(_CASE, _DSN)
        assert result["blocked"] is True
        assert result["status"] == ChainStatus.UNSEALED


# ---------------------------------------------------------------------------
# Fail-closed on DB error
# ---------------------------------------------------------------------------

class TestFailClosedErrors:
    def test_connect_error_is_blocked(self, monkeypatch):
        _install_fake_psycopg(monkeypatch, raise_on_connect=RuntimeError("boom"))
        result = check_evidence_gate_db(_CASE, _DSN)
        assert result["blocked"] is True
        assert result["status"] == ChainStatus.LEDGER_ERROR

    def test_query_calls_gate_status_rpc_with_case_id(self, monkeypatch):
        conn_holder = {}

        module = types.ModuleType("psycopg")

        def connect(dsn):
            conn = _Connection(("sealed", 1, []))
            conn_holder["conn"] = conn
            return conn

        module.connect = connect
        monkeypatch.setitem(sys.modules, "psycopg", module)

        check_evidence_gate_db(_CASE, _DSN)
        stmts = conn_holder["conn"].statements
        assert stmts, "expected a query to be issued"
        sql, params = stmts[0]
        assert "app.evidence_gate_status" in sql
        assert params == (_CASE,)


# ---------------------------------------------------------------------------
# Result shape parity with the file-backed gate
# ---------------------------------------------------------------------------

def test_result_shape_matches_file_gate(monkeypatch):
    _install_fake_psycopg(monkeypatch, row=("sealed", 1, []))
    result = check_evidence_gate_db(_CASE, _DSN)
    assert set(result.keys()) == {"blocked", "status", "issues", "manifest_version"}
    assert isinstance(result["issues"], list)
