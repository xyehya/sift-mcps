"""Verify and atomically import the portable Qwen RAG snapshot into pgvector."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import numpy as np  # pyright: ignore[reportMissingImports]
import psycopg  # pyright: ignore[reportMissingImports]

from .utils import QUERY_INSTRUCTION

EXPECTED_MODEL = "Qwen/Qwen3-Embedding-0.6B"
EXPECTED_REVISION = "97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3"
EXPECTED_DIMENSION = 1024
EXPECTED_FORMAT = "sift-rag-qwen-portable-v1"
NAMESPACE = uuid.UUID("fbe9c786-32dc-4b23-88d5-33c58f6aaf27")


class SnapshotError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_relative(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not value:
        raise SnapshotError("snapshot_source_ref_invalid")
    return path.as_posix()


def load_snapshot(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]], np.ndarray]:
    root = root.resolve()
    manifest_path = root / "manifest.json"
    records_path = root / "records.jsonl"
    vectors_path = root / "embeddings.f32.npy"
    if not all(path.is_file() for path in (manifest_path, records_path, vectors_path)):
        raise SnapshotError("snapshot_files_missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != EXPECTED_FORMAT:
        raise SnapshotError("snapshot_format_mismatch")
    if manifest.get("query_instruction") != QUERY_INSTRUCTION:
        raise SnapshotError("snapshot_query_instruction_mismatch")
    if manifest.get("model") != EXPECTED_MODEL or manifest.get("model_revision") != EXPECTED_REVISION:
        raise SnapshotError("snapshot_model_pin_mismatch")
    if manifest.get("embedding_dimension") != EXPECTED_DIMENSION:
        raise SnapshotError("snapshot_dimension_mismatch")
    file_hashes = manifest.get("artifacts", {})
    for name, path in (("records.jsonl", records_path), ("embeddings.f32.npy", vectors_path)):
        expected = file_hashes.get(name)
        if not expected or sha256(path) != expected:
            raise SnapshotError("snapshot_hash_mismatch")
    vectors = np.load(vectors_path, mmap_mode="r", allow_pickle=False)
    if vectors.ndim != 2 or vectors.shape[1] != EXPECTED_DIMENSION or not np.isfinite(vectors).all():
        raise SnapshotError("snapshot_vectors_invalid")
    records: list[dict[str, Any]] = []
    with records_path.open(encoding="utf-8") as handle:
        for row, line in enumerate(handle):
            record = json.loads(line)
            if record.get("embedding_row") != row or not record.get("text", "").strip():
                raise SnapshotError("snapshot_record_invalid")
            safe_relative(str(record.get("source_file", "")))
            records.append(record)
    if len(records) != vectors.shape[0] or len(records) != manifest.get("record_count"):
        raise SnapshotError("snapshot_record_count_mismatch")
    return manifest, records, vectors


def uid(kind: str, value: str) -> uuid.UUID:
    return uuid.uuid5(NAMESPACE, f"{kind}:{value}")


def vector_text(vector: np.ndarray) -> str:
    return "[" + ",".join(format(float(value), ".9g") for value in vector) + "]"


def verify_query_model(manifest: dict[str, Any]) -> None:
    """Preload the pinned runtime model and prove its query-vector contract."""
    from .utils import load_sentence_transformer

    os.environ["RAG_MODEL_REVISION"] = EXPECTED_REVISION
    model = load_sentence_transformer(EXPECTED_MODEL)
    query = (
        f"Instruct: {manifest['query_instruction']}\n"
        "Query: verify the SIFT forensic knowledge index"
    )
    vector = np.asarray(model.encode(query, normalize_embeddings=True))
    if vector.shape != (EXPECTED_DIMENSION,) or not np.isfinite(vector).all():
        raise SnapshotError("runtime_model_vector_invalid")
    norm = float(np.linalg.norm(vector))
    # SentenceTransformers' Qwen pooling returns float32 values whose measured
    # CPU norm can drift by ~0.25% after normalization; cosine remains invariant.
    if not 0.99 <= norm <= 1.01:
        raise SnapshotError("runtime_model_vector_not_normalized")


def _source_count(records: list[dict[str, Any]]) -> int:
    return len(
        {
            str(
                (record.get("metadata") or {}).get("source")
                or Path(record["source_file"]).stem
            )
            for record in records
        }
    )


def import_snapshot(dsn: str, root: Path) -> dict[str, object]:
    manifest, records, vectors = load_snapshot(root)
    manifest_digest = sha256(root.resolve() / "manifest.json")
    expected_counts = (_source_count(records), len(records), len(records))
    with psycopg.connect(dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            "select format_type(atttypid, atttypmod) from pg_attribute "
            "where attrelid='app.rag_chunks'::regclass and attname='embedding'"
        )
        row = cursor.fetchone()
        if row != ("vector(1024)",):
            raise SnapshotError("database_dimension_mismatch")
        cursor.execute(
            "select (select count(*) from app.rag_collections),"
            "(select count(*) from app.rag_documents),"
            "(select count(*) from app.rag_chunks)"
        )
        existing = cursor.fetchone()
        if existing is None:
            raise SnapshotError("database_count_unavailable")
        if existing != (0, 0, 0):
            cursor.execute(
                "select count(*) from app.rag_collections where "
                "metadata->>'snapshot_manifest_sha256' = %s and "
                "metadata->>'embedding_model' = %s and "
                "metadata->>'embedding_revision' = %s",
                (manifest_digest, EXPECTED_MODEL, EXPECTED_REVISION),
            )
            matching = cursor.fetchone()
            if existing == expected_counts and matching == (expected_counts[0],):
                return {
                    "current": True,
                    "collections": existing[0],
                    "documents": existing[1],
                    "chunks": existing[2],
                }
            raise SnapshotError("database_rag_not_empty_or_snapshot_mismatch")
        cursor.execute(
            "create temporary table rag_qwen_stage (collection_id uuid, "
            "collection_name text, document_id uuid, provenance_id uuid, "
            "title text, source_ref text, content text, metadata jsonb, "
            "embedding vector(1024)) on commit drop"
        )
        with cursor.copy("copy rag_qwen_stage from stdin") as copy:
            for index, record in enumerate(records):
                metadata = dict(record.get("metadata") or {})
                source = str(metadata.get("source") or Path(record["source_file"]).stem)
                record_id = str(record["id"])
                metadata.update(
                    {
                        "sift_record_id": record_id,
                        "sift_upstream_id": str(record["upstream_id"]),
                        "sift_source_file": safe_relative(str(record["source_file"])),
                        "sift_embedding_row": index,
                        "sift_snapshot_manifest_sha256": manifest_digest,
                        "sift_embedding_revision": EXPECTED_REVISION,
                        "sift_document_transform": str(manifest["document_transform"]),
                    }
                )
                copy.write_row(
                    (
                        uid("collection", source),
                        source,
                        uid("document", record_id),
                        uid("provenance", record_id),
                        str(metadata.get("title") or record["upstream_id"]),
                        safe_relative(str(record["source_file"])),
                        record["text"],
                        json.dumps(metadata, separators=(",", ":")),
                        vector_text(vectors[index]),
                    )
                )
        cursor.execute(
            "insert into app.rag_collections "
            "(id,name,kind,description,metadata) select distinct "
            "collection_id,collection_name,'knowledge',"
            "'Canonical Qwen3 forensic reference corpus',"
            "jsonb_build_object('embedding_model',%s::text,"
            "'embedding_revision',%s::text,'snapshot_manifest_sha256',%s::text,"
            "'snapshot_format',%s::text,'query_instruction_sha256',%s::text) "
            "from rag_qwen_stage",
            (
                EXPECTED_MODEL,
                EXPECTED_REVISION,
                manifest_digest,
                EXPECTED_FORMAT,
                hashlib.sha256(str(manifest["query_instruction"]).encode()).hexdigest(),
            ),
        )
        cursor.execute(
            "insert into app.rag_documents "
            "(id,collection_id,kind,title,provenance_id,source_ref,metadata) "
            "select document_id,collection_id,'knowledge',title,provenance_id,"
            "source_ref,metadata from rag_qwen_stage"
        )
        cursor.execute(
            "insert into app.rag_chunks "
            "(document_id,collection_id,kind,chunk_index,content,provenance_id,"
            "embedding,metadata) select document_id,collection_id,'knowledge',0,"
            "content,provenance_id,embedding,metadata from rag_qwen_stage"
        )
        cursor.execute("analyze app.rag_chunks")
        cursor.execute("select (select count(*) from app.rag_collections),(select count(*) from app.rag_documents),(select count(*) from app.rag_chunks)")
        counts = cursor.fetchone()
    if counts is None:
        raise SnapshotError("database_count_unavailable")
    if counts != expected_counts:
        raise SnapshotError("database_count_mismatch")
    return {
        "current": False,
        "collections": counts[0],
        "documents": counts[1],
        "chunks": counts[2],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path)
    args = parser.parse_args()
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        print("error: SIFT_CONTROL_PLANE_DSN is required", file=sys.stderr)
        return 2
    try:
        manifest, _records, _vectors = load_snapshot(args.snapshot)
        verify_query_model(manifest)
        result = import_snapshot(dsn, args.snapshot)
    except (SnapshotError, OSError, ValueError, psycopg.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "ok", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
