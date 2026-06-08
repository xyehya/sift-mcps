from __future__ import annotations

import json

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
    result = seed_knowledge_documents(store, documents)

    assert result.public_dict()["store"] == "supabase_pgvector"
    assert result.collections == 1
    assert result.documents == 1
    assert result.chunks == 2
    assert store.collections[0]["name"] == "ForensicCases"
    assert store.documents[0]["source_ref"] == "ForensicCases/credential-theft.jsonl"
    assert all(call["case_id"] is None for call in store.documents)
