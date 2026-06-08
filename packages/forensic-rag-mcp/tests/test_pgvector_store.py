"""BATCH-G1 unit tests for the pgvector RAG store.

These exercise case isolation and provenance-only / path-free output without a
live Postgres: a fake connection records the SQL/params and returns scripted
rows. The DB-side guarantees (RLS, the rag_search UNION, CHECK constraints) live
in the migration; here we verify the Python adapter's contract and its
defense-in-depth scrubbing.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

# Load pgvector_store.py directly from file, bypassing rag_mcp/__init__ (which
# eagerly imports ChromaDB via index/server and is not installed in this test
# env). The module under test has no heavy dependencies.
_MOD_PATH = (
    Path(__file__).resolve().parents[1] / "src" / "rag_mcp" / "pgvector_store.py"
)
import sys  # noqa: E402

_spec = importlib.util.spec_from_file_location("rag_mcp_pgvector_store", _MOD_PATH)
_pg = importlib.util.module_from_spec(_spec)
sys.modules["rag_mcp_pgvector_store"] = _pg
_spec.loader.exec_module(_pg)

EMBEDDING_DIM = _pg.EMBEDDING_DIM
PgVectorRagStore = _pg.PgVectorRagStore
PgVectorStoreError = _pg.PgVectorStoreError
_sanitize_hit = _pg._sanitize_hit

CASE_A = "11111111-1111-1111-1111-111111111111"
CASE_B = "22222222-2222-2222-2222-222222222222"


def _emb(val: float = 0.1) -> list[float]:
    return [val] * EMBEDDING_DIM


def _row(*, kind: str, case_id, content="ref text", title="Doc", source_ref=None):
    # Mirrors app.rag_search RETURNS TABLE column order.
    return (
        "chunk-id",
        case_id,
        kind,
        "prov-chunk",
        "doc-id",
        "prov-doc",
        title,
        source_ref,
        None,
        "SANS",
        content,
        0.12,
    )


class _FakeCursor:
    def __init__(self, rows):
        self._rows = rows
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return ("new-chunk-id",)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeConn:
    def __init__(self, rows):
        self._cursor = _FakeCursor(rows)
        self.committed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.committed = True

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _store_with_rows(monkeypatch, rows):
    store = PgVectorRagStore("postgresql://service@db/app")
    conn = _FakeConn(rows)
    monkeypatch.setattr(store, "_connect", lambda: conn)
    return store, conn


# ---------------------------------------------------------------------------
# case isolation
# ---------------------------------------------------------------------------


def test_search_with_case_passes_case_scope_to_rpc(monkeypatch):
    store, conn = _store_with_rows(monkeypatch, [_row(kind="derived", case_id=CASE_A)])
    store.search(query_embedding=_emb(), case_id=CASE_A, top_k=3)
    sql, params = conn._cursor.executed[0]
    assert "app.rag_search" in sql
    # params: (embedding, case_id, top_k, include_knowledge, include_derived)
    assert params[1] == CASE_A
    assert params[2] == 3
    assert params[4] is True  # derived enabled with a case


def test_search_without_case_forces_derived_off(monkeypatch):
    store, conn = _store_with_rows(monkeypatch, [_row(kind="knowledge", case_id=None)])
    store.search(query_embedding=_emb(), case_id=None)
    _sql, params = conn._cursor.executed[0]
    assert params[1] is None
    assert params[4] is False  # derived retrieval force-disabled without a case


def test_cross_case_derived_rows_are_dropped(monkeypatch):
    # Even if the DB somehow returned case B's derived chunk while querying case A,
    # the adapter drops it. (The DB-side rag_search makes this unreachable; this is
    # the belt-and-suspenders Python guard.)
    rows = [
        _row(kind="knowledge", case_id=None),
        _row(kind="derived", case_id=CASE_A),
        _row(kind="derived", case_id=CASE_B),  # foreign case — must be dropped
    ]
    store, _ = _store_with_rows(monkeypatch, rows)
    result = store.search(query_embedding=_emb(), case_id=CASE_A)
    kinds_cases = {(h.kind, h.case_id) for h in result.hits}
    assert ("derived", CASE_B) not in kinds_cases
    assert ("derived", CASE_A) in kinds_cases
    assert ("knowledge", None) in kinds_cases


# ---------------------------------------------------------------------------
# provenance-only / path-free output
# ---------------------------------------------------------------------------


def test_hits_carry_provenance_ids(monkeypatch):
    store, _ = _store_with_rows(monkeypatch, [_row(kind="knowledge", case_id=None)])
    result = store.search(query_embedding=_emb(), case_id=CASE_A)
    pub = result.public_dict()
    assert pub["status"] == "ok"
    assert pub["results"][0]["provenance_id"] == "prov-chunk"
    assert pub["results"][0]["document_provenance_id"] == "prov-doc"


def test_output_has_no_embedding_field(monkeypatch):
    store, _ = _store_with_rows(monkeypatch, [_row(kind="knowledge", case_id=None)])
    result = store.search(query_embedding=_emb(), case_id=CASE_A)
    for hit in result.public_dict()["results"]:
        assert "embedding" not in hit


def test_leaked_absolute_path_in_content_is_scrubbed():
    # Defense in depth: if a derived chunk ever carried a host path, the
    # sanitizer redacts it before it leaves the module.
    raw = {
        "provenance_id": "p1",
        "content": "see /home/yk/cases/secret/evidence/disk.E01 for details",
        "source_ref": "evidence/disk.E01",
    }
    out = _sanitize_hit(raw)
    assert "/home/yk/cases" not in out["content"]
    assert "[redacted-path]" in out["content"]
    # A legitimate RELATIVE display ref is preserved.
    assert out["source_ref"] == "evidence/disk.E01"


def test_windows_abs_path_in_content_is_scrubbed():
    out = _sanitize_hit({"content": r"dump at C:\cases\evidence\mem.raw now"})
    assert r"C:\cases" not in out["content"]


# ---------------------------------------------------------------------------
# embedding dimension contract
# ---------------------------------------------------------------------------


def test_search_rejects_wrong_embedding_dim(monkeypatch):
    store, _ = _store_with_rows(monkeypatch, [])
    with pytest.raises(PgVectorStoreError):
        store.search(query_embedding=[0.1, 0.2, 0.3], case_id=CASE_A)


def test_upsert_rejects_wrong_embedding_dim(monkeypatch):
    store, _ = _store_with_rows(monkeypatch, [])
    with pytest.raises(PgVectorStoreError):
        store.upsert_chunk(
            document_id="d", chunk_index=0, content="x", embedding=[0.1, 0.2]
        )


def test_upsert_commits_and_returns_chunk_id(monkeypatch):
    store, conn = _store_with_rows(monkeypatch, [])
    chunk_id = store.upsert_chunk(
        document_id="doc-id", chunk_index=0, content="ref text", embedding=_emb()
    )
    assert chunk_id == "new-chunk-id"
    assert conn.committed is True
    sql, _params = conn._cursor.executed[0]
    assert "app.rag_upsert_chunk" in sql
