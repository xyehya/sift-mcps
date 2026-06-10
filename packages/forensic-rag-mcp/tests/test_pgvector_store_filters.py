"""BATCH-OSX-RAG: pgvector store knowledge-filter + introspection tests.

These verify that ``PgVectorRagStore.search`` forwards the restored
forensic-rag filters (source / source_ids / technique / platform) to the
extended ``app.rag_search`` RPC, and that ``list_knowledge_sources`` /
``knowledge_stats`` query the shared-knowledge plane. A fake connection records
SQL/params and returns scripted rows (no live Postgres).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_MOD_PATH = (
    Path(__file__).resolve().parents[1] / "src" / "rag_mcp" / "pgvector_store.py"
)
_spec = importlib.util.spec_from_file_location("rag_mcp_pgvector_store_filters", _MOD_PATH)
_pg = importlib.util.module_from_spec(_spec)
sys.modules["rag_mcp_pgvector_store_filters"] = _pg
_spec.loader.exec_module(_pg)

EMBEDDING_DIM = _pg.EMBEDDING_DIM
PgVectorRagStore = _pg.PgVectorRagStore


def _emb(val: float = 0.1) -> list[float]:
    return [val] * EMBEDDING_DIM


def _row():
    return (
        "chunk-id",
        None,
        "knowledge",
        "prov-chunk",
        "doc-id",
        "prov-doc",
        "Doc",
        None,
        None,
        "sigma",
        "ref text",
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
        return self._rows[0] if self._rows else None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeConn:
    def __init__(self, rows):
        self._cursor = _FakeCursor(rows)

    def cursor(self):
        return self._cursor

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _store(monkeypatch, rows):
    store = PgVectorRagStore("postgresql://service@db/app")
    conn = _FakeConn(rows)
    monkeypatch.setattr(store, "_connect", lambda: conn)
    return store, conn


# The 9-arg app.rag_search params:
# (embedding, case_id, top_k, include_knowledge, include_derived,
#  source, source_ids, technique, platform)


def test_search_forwards_source_filter(monkeypatch):
    store, conn = _store(monkeypatch, [_row()])
    store.search(query_embedding=_emb(), case_id=None, source="sigma")
    _sql, params = conn._cursor.executed[0]
    assert params[5] == "sigma"
    assert params[6] is None  # source_ids


def test_search_forwards_source_ids_and_drops_blanks(monkeypatch):
    store, conn = _store(monkeypatch, [_row()])
    store.search(
        query_embedding=_emb(),
        case_id=None,
        source="sigma",
        source_ids=["mitre_attack", "", "  ", "lolbas"],
    )
    _sql, params = conn._cursor.executed[0]
    # source_ids cleaned of blank entries.
    assert params[6] == ["mitre_attack", "lolbas"]
    # The SQL itself enforces source_ids precedence over source; both are passed.
    assert params[5] == "sigma"


def test_search_empty_source_ids_becomes_null(monkeypatch):
    store, conn = _store(monkeypatch, [_row()])
    store.search(query_embedding=_emb(), case_id=None, source_ids=["", "  "])
    _sql, params = conn._cursor.executed[0]
    assert params[6] is None


def test_search_forwards_technique_and_platform(monkeypatch):
    store, conn = _store(monkeypatch, [_row()])
    store.search(
        query_embedding=_emb(),
        case_id=None,
        technique="T1003",
        platform="windows",
    )
    _sql, params = conn._cursor.executed[0]
    assert params[7] == "T1003"
    assert params[8] == "windows"


def test_search_clamps_top_k(monkeypatch):
    store, conn = _store(monkeypatch, [_row()])
    store.search(query_embedding=_emb(), case_id=None, top_k=999)
    _sql, params = conn._cursor.executed[0]
    assert params[2] == 50  # MAX_TOP_K clamp


def test_search_uses_nine_arg_rag_search(monkeypatch):
    store, conn = _store(monkeypatch, [_row()])
    store.search(query_embedding=_emb(), case_id=None)
    sql, params = conn._cursor.executed[0]
    assert "app.rag_search(" in sql
    assert len(params) == 9


def test_list_knowledge_sources(monkeypatch):
    store, conn = _store(monkeypatch, [("sigma",), ("mitre_attack",), (None,)])
    sources = store.list_knowledge_sources()
    assert sources == ["sigma", "mitre_attack"]
    sql, _ = conn._cursor.executed[0]
    assert "kind = 'knowledge'" in sql


def test_knowledge_stats(monkeypatch):
    store, conn = _store(monkeypatch, [(26586, 26586, 12, 23)])
    stats = store.knowledge_stats()
    assert stats["chunk_count"] == 26586
    assert stats["document_count"] == 26586
    assert stats["collection_count"] == 12
    assert stats["source_count"] == 23
    assert stats["embedding_dim"] == EMBEDDING_DIM
    assert stats["embedding_model"] == "BAAI/bge-base-en-v1.5"
