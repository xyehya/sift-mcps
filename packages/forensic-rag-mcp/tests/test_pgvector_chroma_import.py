from __future__ import annotations

import json

from rag_mcp.pgvector_chroma_import import (
    import_chroma_collection,
    import_chroma_from_dir,
    iter_chroma_records,
)
from rag_mcp.pgvector_store import EMBEDDING_DIM


class _FakeArray:
    def __init__(self, values):
        self._values = values

    def tolist(self):
        return self._values


class _FakeCollection:
    def __init__(self, records):
        self.records = records
        self.calls = []

    def count(self):
        return len(self.records)

    def get(self, *, limit, offset, include):
        self.calls.append({"limit": limit, "offset": offset, "include": include})
        rows = self.records[offset : offset + limit]
        return {
            "ids": [r["id"] for r in rows],
            "documents": [r["document"] for r in rows],
            "metadatas": [r.get("metadata", {}) for r in rows],
            "embeddings": _FakeArray([r.get("embedding", []) for r in rows]),
        }


class _FakeStore:
    def __init__(self):
        self.collections = []
        self.documents = []
        self.chunks = []

    def ensure_collection(self, **kwargs):
        assert kwargs["kind"] == "knowledge"
        assert kwargs["case_id"] is None
        self.collections.append(kwargs)
        return f"collection-{len(self.collections)}"

    def upsert_document(self, **kwargs):
        assert kwargs["kind"] == "knowledge"
        assert kwargs["case_id"] is None
        self.documents.append(kwargs)
        return f"document-{len(self.documents)}"

    def upsert_chunk(self, **kwargs):
        assert len(kwargs["embedding"]) == EMBEDDING_DIM
        self.chunks.append(kwargs)
        return f"chunk-{len(self.chunks)}"


def _embedding(value=0.01):
    return [value] * EMBEDDING_DIM


def test_iter_chroma_records_pages_and_limits():
    collection = _FakeCollection(
        [
            {"id": "a", "document": "alpha", "embedding": _embedding()},
            {"id": "b", "document": "beta", "embedding": _embedding(0.02)},
            {"id": "c", "document": "gamma", "embedding": _embedding(0.03)},
        ]
    )

    records = list(iter_chroma_records(collection, batch_size=2, limit=3))

    assert [r.chroma_id for r in records] == ["a", "b", "c"]
    assert records[0].embedding == _embedding()
    assert collection.calls == [
        {"limit": 2, "offset": 0, "include": ["documents", "metadatas", "embeddings"]},
        {"limit": 1, "offset": 2, "include": ["documents", "metadatas", "embeddings"]},
    ]


def test_import_chroma_collection_writes_shared_knowledge_with_real_embeddings():
    collection = _FakeCollection(
        [
            {
                "id": "sans-1",
                "document": "MCP-sourced evidence has stronger provenance.",
                "metadata": {
                    "source": "SANS",
                    "title": "Finding Provenance",
                    "path": "/cases/should-not-store",
                },
                "embedding": _embedding(0.04),
            }
        ]
    )
    store = _FakeStore()

    result = import_chroma_collection(
        store=store,
        collection=collection,
        collection_name="ir_knowledge",
        source_model="BAAI/bge-base-en-v1.5",
    )

    assert result.public_dict()["source"] == "chroma_release_bundle"
    assert result.collections == 1
    assert result.documents == 1
    assert result.chunks == 1
    assert store.collections[0]["name"] == "SANS"
    assert store.documents[0]["source_ref"] == "chroma/SANS/sans-1"
    assert store.documents[0]["metadata"]["chroma_id"] == "sans-1"
    assert "path" not in store.documents[0]["metadata"]
    assert store.chunks[0]["embedding"] == _embedding(0.04)
    assert store.chunks[0]["metadata"]["seed_source"] == "chroma_release_pgvector"


def test_import_chroma_collection_reports_bad_embedding_dimension():
    collection = _FakeCollection(
        [
            {
                "id": "bad",
                "document": "bad embedding",
                "metadata": {"source": "bad"},
                "embedding": [0.1, 0.2],
            }
        ]
    )
    store = _FakeStore()

    result = import_chroma_collection(store=store, collection=collection)

    assert result.status == "error"
    assert result.skipped == 1
    assert "embedding dimension mismatch" in result.errors[0]
    assert store.documents == []


def test_import_chroma_from_dir_rejects_model_mismatch(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    chroma_dir = data_dir / "chroma"
    chroma_dir.mkdir(parents=True)
    (data_dir / "metadata.json").write_text(
        json.dumps({"model": "sentence-transformers/all-MiniLM-L6-v2"}),
        encoding="utf-8",
    )
    opened = False

    def _open(*_args, **_kwargs):
        nonlocal opened
        opened = True

    monkeypatch.setattr("rag_mcp.pgvector_chroma_import.open_chroma_collection", _open)

    try:
        import_chroma_from_dir(dsn="postgres://x", chroma_dir=chroma_dir)
    except ValueError as exc:
        assert "does not match pgvector model" in str(exc)
    else:
        raise AssertionError("expected model mismatch")
    assert opened is False
