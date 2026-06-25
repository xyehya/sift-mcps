"""BATCH-OSX-RAG / BATCH-NW4: forensic-rag-mcp kb_ tool surface tests.

Exercises the restored knowledge tools (kb_search_knowledge,
kb_list_knowledge_sources, kb_get_knowledge_stats) through the RAGServer tool
bodies with a mocked BGE embedder and a mocked PgVectorRagStore — no model
download, no live Postgres.

BATCH-NW4 update: store.search() no longer takes case_id / include_derived /
include_knowledge params.  The _FakeStore.search() signature reflects this.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure the worktree's rag_mcp package takes precedence over any installed copy.
# This is necessary because uv/pip may have the old (pre-NW4) package installed in
# the root venv; we must test against the edited source in this worktree.
_WORKTREE_SRC = str(Path(__file__).resolve().parents[1] / "src")
if _WORKTREE_SRC not in sys.path:
    sys.path.insert(0, _WORKTREE_SRC)

# Evict any already-cached rag_mcp modules so sys.path insert takes effect.
for _key in list(sys.modules):
    if _key == "rag_mcp" or _key.startswith("rag_mcp."):
        del sys.modules[_key]

pytest.importorskip("mcp.server.fastmcp")

from rag_mcp import server as srv  # noqa: E402
from rag_mcp.pgvector_store import RagHit, RagSearchResult  # noqa: E402


class _FakeStore:
    def __init__(self):
        self.calls = []
        self.sources = ["mitre_attack", "sigma"]
        self.stats = {
            "chunk_count": 26586,
            "document_count": 26586,
            "collection_count": 12,
            "source_count": 23,
            "embedding_dim": 768,
            "embedding_model": "BAAI/bge-base-en-v1.5",
        }
        self.hits = [
            RagHit(
                chunk_id="c1",
                provenance_id="prov-1",
                document_provenance_id="dprov-1",
                document_title="Credential Dumping",
                collection_name="sigma",
                content="lsass dump detection",
                kind="knowledge",
                case_id=None,
                distance=0.1,
                source_ref="chroma/sigma/abc",
            )
        ]

    def search(self, **kwargs):
        self.calls.append(kwargs)
        return RagSearchResult(case_id=None, hits=list(self.hits))

    def list_knowledge_sources(self):
        return list(self.sources)

    def knowledge_stats(self):
        return dict(self.stats)


class _FakeEmbedder:
    def __init__(self):
        self.queries = []

    def embed(self, query):
        self.queries.append(query)
        return [0.1] * 768


@pytest.fixture
def server(monkeypatch):
    s = srv.RAGServer()
    fake_store = _FakeStore()
    fake_embedder = _FakeEmbedder()
    monkeypatch.setattr(s, "_get_store", lambda: fake_store)
    monkeypatch.setattr(s, "_get_embedder", lambda: fake_embedder)
    return s, fake_store, fake_embedder


def test_search_returns_ok_shape_and_queries_knowledge_only(server):
    s, store, embedder = server
    out = s._search(
        query="credential dumping",
        top_k=5,
        source="",
        source_ids=None,
        technique="",
        platform="",
    )
    assert out["status"] == "ok"
    assert out["query"] == "credential dumping"
    assert out["results"][0]["provenance_id"] == "prov-1"
    assert "embedding" not in out["results"][0]
    assert embedder.queries == ["credential dumping"]
    # BATCH-NW4: knowledge-only store — no case_id / include_derived kwargs.
    call = store.calls[0]
    assert "case_id" not in call
    assert "include_derived" not in call
    assert "include_knowledge" not in call


def test_search_forwards_source_filter(server):
    s, store, _ = server
    s._search(query="q", top_k=5, source="sigma", source_ids=None, technique="", platform="")
    assert store.calls[0]["source"] == "sigma"
    assert store.calls[0]["source_ids"] is None


def test_search_source_ids_precedence_and_cap(server):
    s, store, _ = server
    s._search(
        query="q",
        top_k=5,
        source="sigma",
        source_ids=["mitre_attack", "lolbas"],
        technique="",
        platform="",
    )
    assert store.calls[0]["source_ids"] == ["mitre_attack", "lolbas"]


def test_search_rejects_too_many_source_ids(server):
    s, _, _ = server
    out = s._search(
        query="q",
        top_k=5,
        source="",
        source_ids=[str(i) for i in range(21)],
        technique="",
        platform="",
    )
    assert out["error"] == "validation_error"
    assert "20" in out["message"]


def test_search_forwards_technique_and_platform(server):
    s, store, _ = server
    s._search(query="q", top_k=5, source="", source_ids=None, technique="T1003", platform="linux")
    assert store.calls[0]["technique"] == "T1003"
    assert store.calls[0]["platform"] == "linux"


def test_search_rejects_bad_platform(server):
    s, _, _ = server
    out = s._search(query="q", top_k=5, source="", source_ids=None, technique="", platform="solaris")
    assert out["error"] == "validation_error"
    assert "platform" in out["message"]


def test_search_clamps_top_k(server):
    s, store, _ = server
    s._search(query="q", top_k=999, source="", source_ids=None, technique="", platform="")
    assert store.calls[0]["top_k"] == 50


def test_search_requires_query(server):
    s, _, _ = server
    out = s._search(query="   ", top_k=5, source="", source_ids=None, technique="", platform="")
    assert out["error"] == "validation_error"
    assert "query is required" in out["message"]


def test_search_rejects_overlong_query(server):
    s, _, _ = server
    out = s._search(query="x" * 1001, top_k=5, source="", source_ids=None, technique="", platform="")
    assert out["error"] == "validation_error"


def test_search_warns_when_source_filter_matches_nothing(server):
    s, store, _ = server
    store.hits = []
    out = s._search(query="q", top_k=5, source="does-not-exist", source_ids=None, technique="", platform="")
    assert out["status"] == "ok"
    assert out["results"] == []
    assert "kb_list_knowledge_sources" in out["warning"]


def test_list_sources(server):
    s, _, _ = server
    out = s._list_sources()
    assert out["status"] == "ok"
    assert out["sources"] == ["mitre_attack", "sigma"]
    assert out["count"] == 2


def test_get_stats(server):
    s, _, _ = server
    out = s._get_stats()
    assert out["status"] == "ok"
    assert out["chunk_count"] == 26586
    assert out["embedding_model"] == "BAAI/bge-base-en-v1.5"


def test_kb_tools_registered_on_mcp():
    s = srv.RAGServer()
    import asyncio

    tools = {t.name for t in asyncio.run(s.mcp.list_tools())}
    assert {
        "kb_search_knowledge",
        "kb_list_knowledge_sources",
        "kb_get_knowledge_stats",
    } <= tools


# ---------------------------------------------------------------------------
# F10: technique-filter fallback (corpus not technique-tagged)
# ---------------------------------------------------------------------------


class _TechniqueAwareStore(_FakeStore):
    """Returns hits ONLY when no technique filter is applied — models a corpus
    whose chunks are not tagged with the requested (sub-)technique id."""

    def search(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs.get("technique"):
            return RagSearchResult(case_id=None, hits=[])
        return RagSearchResult(case_id=None, hits=list(self.hits))


class _TechniqueMatchStore(_FakeStore):
    """Returns hits regardless of technique — models a corpus where the
    technique filter DOES match (no relaxation should occur)."""

    def search(self, **kwargs):
        self.calls.append(kwargs)
        return RagSearchResult(case_id=None, hits=list(self.hits))


@pytest.fixture
def server_technique_aware(monkeypatch):
    s = srv.RAGServer()
    store = _TechniqueAwareStore()
    monkeypatch.setattr(s, "_get_store", lambda: store)
    monkeypatch.setattr(s, "_get_embedder", lambda: _FakeEmbedder())
    return s, store


def test_technique_filter_relaxes_when_zero_results(server_technique_aware):
    """F10: technique filter that matches nothing → fall back to unfiltered
    semantic search and annotate the relaxation."""
    s, store = server_technique_aware
    out = s._search(
        query="RDP lateral movement remote desktop",
        top_k=5,
        source="",
        source_ids=None,
        technique="T1021.001",
        platform="",
    )
    assert out["status"] == "ok"
    # The fallback returned the unfiltered hits.
    assert out["results"], out
    assert out["results"][0]["provenance_id"] == "prov-1"
    # Annotated as relaxed.
    assert "technique_filter" in out
    assert "relaxed" in out["technique_filter"]
    assert "T1021.001" in out["technique_filter"]
    # Two store calls: first with technique, second relaxed to None.
    assert len(store.calls) == 2
    assert store.calls[0]["technique"] == "T1021.001"
    assert store.calls[1]["technique"] is None


def test_technique_relaxation_preserves_other_filters(server_technique_aware):
    """Source/platform filters must survive the relaxation; only technique drops."""
    s, store = server_technique_aware
    s._search(
        query="q",
        top_k=5,
        source="sigma",
        source_ids=None,
        technique="T1003",
        platform="windows",
    )
    relaxed_call = store.calls[1]
    assert relaxed_call["technique"] is None
    assert relaxed_call["source"] == "sigma"
    assert relaxed_call["platform"] == "windows"


def test_technique_filter_honoured_when_it_matches(monkeypatch):
    """When the technique filter DOES match, no relaxation and no annotation."""
    s = srv.RAGServer()
    store = _TechniqueMatchStore()
    monkeypatch.setattr(s, "_get_store", lambda: store)
    monkeypatch.setattr(s, "_get_embedder", lambda: _FakeEmbedder())
    out = s._search(
        query="credential dumping",
        top_k=5,
        source="",
        source_ids=None,
        technique="T1003",
        platform="",
    )
    assert out["results"], out
    assert "technique_filter" not in out  # no relaxation
    assert len(store.calls) == 1  # only one search, technique honoured
    assert store.calls[0]["technique"] == "T1003"


def test_no_technique_no_relaxation_path(server):
    """Without a technique filter, the relaxation branch never runs."""
    s, store, _ = server
    out = s._search(query="q", top_k=5, source="", source_ids=None, technique="", platform="")
    assert "technique_filter" not in out
    assert len(store.calls) == 1
