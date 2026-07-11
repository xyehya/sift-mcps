from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest
from rag_mcp.pgvector_snapshot_import import (
    EXPECTED_DIMENSION,
    EXPECTED_FORMAT,
    EXPECTED_MODEL,
    EXPECTED_REVISION,
    SnapshotError,
    load_snapshot,
    sha256,
    verify_query_model,
)
from rag_mcp.utils import QUERY_INSTRUCTION


def _snapshot(tmp_path: Path) -> Path:
    records = tmp_path / "records.jsonl"
    records.write_text(
        "\n".join(
            json.dumps(
                {
                    "id": str(index),
                    "upstream_id": f"source:{index}",
                    "source_file": "sources/test.jsonl",
                    "text": f"record {index}",
                    "metadata": {"source": "test"},
                    "embedding_row": index,
                }
            )
            for index in range(2)
        )
        + "\n",
        encoding="utf-8",
    )
    vectors = tmp_path / "embeddings.f32.npy"
    np.save(vectors, np.ones((2, EXPECTED_DIMENSION), dtype=np.float32))
    manifest = {
        "format": EXPECTED_FORMAT,
        "model": EXPECTED_MODEL,
        "model_revision": EXPECTED_REVISION,
        "embedding_dimension": EXPECTED_DIMENSION,
        "record_count": 2,
        "query_instruction": QUERY_INSTRUCTION,
        "document_transform": "raw-source-text-v1",
        "artifacts": {
            "records.jsonl": sha256(records),
            "embeddings.f32.npy": sha256(vectors),
        },
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tmp_path


def test_snapshot_loader_accepts_only_pinned_shape_hashes_and_order(tmp_path):
    manifest, records, vectors = load_snapshot(_snapshot(tmp_path))
    assert manifest["format"] == EXPECTED_FORMAT
    assert len(records) == 2
    assert vectors.shape == (2, EXPECTED_DIMENSION)


def test_snapshot_loader_rejects_changed_records(tmp_path):
    root = _snapshot(tmp_path)
    with (root / "records.jsonl").open("a", encoding="utf-8") as handle:
        handle.write("{}\n")
    with pytest.raises(SnapshotError, match="snapshot_hash_mismatch"):
        load_snapshot(root)


def test_snapshot_loader_rejects_nonfinite_vectors(tmp_path):
    root = _snapshot(tmp_path)
    vectors = np.load(root / "embeddings.f32.npy")
    vectors[0, 0] = np.nan
    np.save(root / "embeddings.f32.npy", vectors)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["embeddings.f32.npy"] = sha256(
        root / "embeddings.f32.npy"
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(SnapshotError, match="snapshot_vectors_invalid"):
        load_snapshot(root)


def test_runtime_model_smoke_requires_normalized_1024_vector(monkeypatch):
    class Model:
        def encode(self, _query, *, normalize_embeddings):
            assert normalize_embeddings is True
            vector = np.ones(EXPECTED_DIMENSION, dtype=np.float32)
            return vector / np.linalg.norm(vector)

    monkeypatch.setattr(
        "rag_mcp.utils.load_sentence_transformer", lambda _model_name: Model()
    )
    verify_query_model({"query_instruction": QUERY_INSTRUCTION})


def test_importer_refuses_nonempty_mismatched_database_by_contract():
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "rag_mcp"
        / "pgvector_snapshot_import.py"
    ).read_text(encoding="utf-8")
    assert "database_rag_not_empty_or_snapshot_mismatch" in source
    assert "snapshot_manifest_sha256" in source
    assert "sift_upstream_id" in source
