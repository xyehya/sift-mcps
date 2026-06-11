"""BATCH-G1 unit tests for the pgvector RAG store.

Updated for BATCH-NW4 (B-MVP-RAG-DERIVED REJECTED): the store is knowledge-only.
Tests that assumed case_id / include_derived params have been updated to reflect
the new knowledge-only API.

These exercise provenance-only / path-free output without a live Postgres: a fake
connection records the SQL/params and returns scripted rows. The DB-side guarantees
(triggers, the knowledge-only rag_search function) live in the migration; here we
verify the Python adapter's contract and its defense-in-depth scrubbing.
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
deterministic_embedding = _pg.deterministic_embedding
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
    def __init__(self, rows, one_rows=None):
        self._rows = rows
        self._one_rows = list(one_rows) if one_rows is not None else [("new-chunk-id",)]
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchall(self):
        return self._rows

    def fetchone(self):
        if self._one_rows:
            return self._one_rows.pop(0)
        return None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeConn:
    def __init__(self, rows, one_rows=None):
        self._cursor = _FakeCursor(rows, one_rows=one_rows)
        self.committed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.committed = True

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _store_with_rows(monkeypatch, rows, *, one_rows=None):
    store = PgVectorRagStore("postgresql://service@db/app")
    conn = _FakeConn(rows, one_rows=one_rows)
    monkeypatch.setattr(store, "_connect", lambda: conn)
    return store, conn


# ---------------------------------------------------------------------------
# BATCH-NW4: knowledge-only — no case_id / derived params on search()
# ---------------------------------------------------------------------------


def test_search_uses_six_arg_rpc(monkeypatch):
    """BATCH-NW4: search() calls the 6-arg knowledge-only app.rag_search."""
    store, conn = _store_with_rows(monkeypatch, [_row(kind="knowledge", case_id=None)])
    store.search(query_embedding=_emb(), top_k=3)
    sql, params = conn._cursor.executed[0]
    assert "app.rag_search" in sql
    # params: (embedding, top_k, source, source_ids, technique, platform) — 6 args
    assert len(params) == 6
    assert params[1] == 3  # top_k at position 1


def test_search_returns_only_knowledge_hits(monkeypatch):
    """BATCH-NW4: any non-knowledge row the DB returns is dropped."""
    rows = [
        _row(kind="knowledge", case_id=None),
        _row(kind="derived", case_id=CASE_A),  # should be dropped
    ]
    store, _ = _store_with_rows(monkeypatch, rows)
    result = store.search(query_embedding=_emb())
    kinds = [h.kind for h in result.hits]
    assert "derived" not in kinds
    assert "knowledge" in kinds


def test_search_result_has_no_case_id(monkeypatch):
    """BATCH-NW4: result.case_id is always None (knowledge-only)."""
    store, _ = _store_with_rows(monkeypatch, [_row(kind="knowledge", case_id=None)])
    result = store.search(query_embedding=_emb())
    assert result.case_id is None


# ---------------------------------------------------------------------------
# provenance-only / path-free output
# ---------------------------------------------------------------------------


def test_hits_carry_provenance_ids(monkeypatch):
    store, _ = _store_with_rows(monkeypatch, [_row(kind="knowledge", case_id=None)])
    result = store.search(query_embedding=_emb())
    pub = result.public_dict()
    assert pub["status"] == "ok"
    assert pub["results"][0]["provenance_id"] == "prov-chunk"
    assert pub["results"][0]["document_provenance_id"] == "prov-doc"


def test_output_has_no_embedding_field(monkeypatch):
    store, _ = _store_with_rows(monkeypatch, [_row(kind="knowledge", case_id=None)])
    result = store.search(query_embedding=_emb())
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
        store.search(query_embedding=[0.1, 0.2, 0.3])


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


# ---------------------------------------------------------------------------
# shared knowledge population helpers
# ---------------------------------------------------------------------------


def test_ensure_collection_inserts_shared_knowledge_collection(monkeypatch):
    store, conn = _store_with_rows(monkeypatch, [], one_rows=[None, ("collection-id",)])
    collection_id = store.ensure_collection(
        name="Forensic Case Studies",
        kind="knowledge",
        case_id=None,
        metadata={"seed_source": "test"},
    )

    assert collection_id == "collection-id"
    insert_sql, params = conn._cursor.executed[1]
    assert "insert into app.rag_collections" in insert_sql
    assert params[1] == "knowledge"
    assert params[2] is None
    assert conn.committed is True


def test_ensure_collection_rejects_case_bound_knowledge(monkeypatch):
    store, _ = _store_with_rows(monkeypatch, [])
    with pytest.raises(PgVectorStoreError):
        store.ensure_collection(name="shared", kind="knowledge", case_id=CASE_A)


def test_upsert_document_rejects_absolute_source_ref(monkeypatch):
    store, _ = _store_with_rows(monkeypatch, [])
    with pytest.raises(PgVectorStoreError):
        store.upsert_document(
            collection_id="collection-id",
            title="bad",
            kind="knowledge",
            source_ref="/cases/secret/evidence.txt",
        )


def test_deterministic_embedding_is_stable_and_768_dimensional():
    first = deterministic_embedding("credential theft case study")
    second = deterministic_embedding("credential theft case study")
    assert first == second
    assert len(first) == EMBEDDING_DIM
