from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import tomllib
from rag_mcp.pgvector_seed import plan_knowledge_seed, seed_knowledge_documents


class _FakeStore:
    def __init__(self):
        self.collections = []
        self.documents = []
        self.chunks = []

    def ensure_collection(self, **kwargs):
        assert kwargs["kind"] == "knowledge"
        assert kwargs["case_id"] is None
        self.collections.append(kwargs)
        return "collection-id"

    def upsert_document(self, **kwargs):
        assert kwargs["kind"] == "knowledge"
        assert kwargs["case_id"] is None
        self.documents.append(kwargs)
        return "document-id"

    def upsert_chunk(self, **kwargs):
        assert len(kwargs["embedding"]) == 768
        self.chunks.append(kwargs)
        return f"chunk-{len(self.chunks)}"


def test_seed_knowledge_documents_are_shared_case_study_collection(tmp_path):
    knowledge_dir = tmp_path / "knowledge"
    case_studies = knowledge_dir / "ForensicCases"
    case_studies.mkdir(parents=True)
    source = case_studies / "credential-theft.jsonl"
    source.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "text": "Case study: attacker used LSASS dumping.",
                        "metadata": {"title": "Credential Theft Case"},
                    }
                ),
                json.dumps(
                    {
                        "text": "Case study: timeline showed remote service creation.",
                        "metadata": {"title": "Credential Theft Case"},
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    documents = plan_knowledge_seed(knowledge_dir)
    store = _FakeStore()
    def _embed_texts(texts: list[str]) -> list[list[float]]:
        return [[float(idx)] * 768 for idx, _text in enumerate(texts, start=1)]

    result = seed_knowledge_documents(
        cast(Any, store), documents, embed_texts=_embed_texts
    )

    assert result.public_dict()["store"] == "supabase_pgvector"
    assert result.collections == 1
    assert result.documents == 1
    assert result.chunks == 2
    assert store.collections[0]["name"] == "ForensicCases"
    assert store.documents[0]["source_ref"] == "ForensicCases/credential-theft.jsonl"
    assert all(call["case_id"] is None for call in store.documents)
    assert [chunk["embedding"] for chunk in store.chunks] == [
        [1.0] * 768,
        [2.0] * 768,
    ]


def test_pgvector_seed_dependencies_do_not_reintroduce_chromadb():
    pyproject = (
        Path(__file__).resolve().parents[1] / "pyproject.toml"
    )
    metadata = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    dependencies = metadata["project"]["dependencies"]
    optional_dependencies = metadata["project"].get("optional-dependencies", {})
    all_declared = [*dependencies]
    for values in optional_dependencies.values():
        all_declared.extend(values)

    assert any(dep.startswith("sentence-transformers") for dep in dependencies)
    assert not any(dep.startswith("chromadb") for dep in all_declared)
