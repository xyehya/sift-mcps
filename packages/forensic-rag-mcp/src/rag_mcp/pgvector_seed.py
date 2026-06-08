"""MVP pgvector population path for bundled forensic RAG knowledge.

This module seeds ``app.rag_collections`` / ``app.rag_documents`` /
``app.rag_chunks`` directly through :mod:`rag_mcp.pgvector_store`. It does not
build or query the legacy Chroma index. Embeddings are deterministic local
vectors so the live VM can prove Supabase pgvector retrieval without model
downloads.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ingest import DEFAULT_KNOWLEDGE_DIR, get_document_records, scan_knowledge_folder
from .pgvector_store import (
    PgVectorRagStore,
    deterministic_embedding,
    stable_rag_uuid,
)


@dataclass(frozen=True)
class KnowledgeSeedChunk:
    content: str
    provenance_id: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class KnowledgeSeedDocument:
    collection_name: str
    title: str
    source_ref: str
    provenance_id: str
    metadata: dict[str, Any] = field(default_factory=dict)
    chunks: list[KnowledgeSeedChunk] = field(default_factory=list)


@dataclass
class KnowledgeSeedResult:
    status: str
    collections: int = 0
    documents: int = 0
    chunks: int = 0
    dry_run: bool = False
    errors: list[str] = field(default_factory=list)

    def public_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "collections": self.collections,
            "documents": self.documents,
            "chunks": self.chunks,
            "dry_run": self.dry_run,
            "errors": self.errors,
            "store": "supabase_pgvector",
        }


def plan_knowledge_seed(
    knowledge_dir: Path,
    *,
    max_files: int | None = None,
    max_records_per_file: int | None = None,
) -> list[KnowledgeSeedDocument]:
    """Read supported knowledge files and build a pgvector seed plan."""
    root = knowledge_dir.resolve()
    scan = scan_knowledge_folder(root, skip_bundled=False)
    documents: list[KnowledgeSeedDocument] = []
    files = sorted(scan.supported, key=lambda p: p.relative_to(root).as_posix())
    if max_files is not None:
        files = files[: max(0, int(max_files))]

    for path in files:
        rel_ref = path.relative_to(root).as_posix()
        records = get_document_records(path, source_prefix="knowledge")
        if max_records_per_file is not None:
            records = records[: max(0, int(max_records_per_file))]
        chunks: list[KnowledgeSeedChunk] = []
        for idx, record in enumerate(records):
            content = str(record.get("text") or "").strip()
            if not content:
                continue
            chunks.append(
                KnowledgeSeedChunk(
                    content=content,
                    provenance_id=stable_rag_uuid("knowledge-chunk", rel_ref, idx),
                    metadata=_chunk_metadata(record, rel_ref, idx),
                )
            )
        if not chunks:
            continue
        collection_name = _collection_name(path, root)
        documents.append(
            KnowledgeSeedDocument(
                collection_name=collection_name,
                title=_document_title(path, records),
                source_ref=rel_ref,
                provenance_id=stable_rag_uuid("knowledge-document", rel_ref),
                metadata={
                    "seed_path": rel_ref,
                    "seed_source": "bundled_knowledge_pgvector",
                    "record_count": len(chunks),
                },
                chunks=chunks,
            )
        )
    return documents


def seed_knowledge_documents(
    store: PgVectorRagStore | None,
    documents: list[KnowledgeSeedDocument],
    *,
    dry_run: bool = False,
) -> KnowledgeSeedResult:
    """Populate pgvector RAG tables from a prepared knowledge seed plan."""
    result = KnowledgeSeedResult(status="ok", dry_run=dry_run)
    result.collections = len({doc.collection_name for doc in documents})
    result.documents = len(documents)
    result.chunks = sum(len(doc.chunks) for doc in documents)
    if dry_run:
        return result
    if store is None:
        raise ValueError("store is required unless dry_run=True")

    collection_ids: dict[str, str] = {}
    for doc in documents:
        collection_id = collection_ids.get(doc.collection_name)
        if collection_id is None:
            collection_id = store.ensure_collection(
                name=doc.collection_name,
                kind="knowledge",
                case_id=None,
                description="Bundled forensic reference knowledge",
                metadata={"seed_source": "bundled_knowledge_pgvector"},
            )
            collection_ids[doc.collection_name] = collection_id
        document_id = store.upsert_document(
            collection_id=collection_id,
            title=doc.title,
            kind="knowledge",
            case_id=None,
            provenance_id=doc.provenance_id,
            source_ref=doc.source_ref,
            metadata=doc.metadata,
        )
        for idx, chunk in enumerate(doc.chunks):
            store.upsert_chunk(
                document_id=document_id,
                chunk_index=idx,
                content=chunk.content,
                embedding=deterministic_embedding(chunk.content),
                provenance_id=chunk.provenance_id,
                metadata=chunk.metadata,
            )
    return result


def seed_knowledge_from_dir(
    *,
    dsn: str | None,
    knowledge_dir: Path = DEFAULT_KNOWLEDGE_DIR,
    max_files: int | None = None,
    max_records_per_file: int | None = None,
    dry_run: bool = False,
) -> KnowledgeSeedResult:
    documents = plan_knowledge_seed(
        knowledge_dir,
        max_files=max_files,
        max_records_per_file=max_records_per_file,
    )
    store = None if dry_run else PgVectorRagStore(_require_dsn(dsn))
    return seed_knowledge_documents(store, documents, dry_run=dry_run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed SIFT RAG pgvector tables")
    parser.add_argument(
        "--dsn",
        default=_dsn_from_env(),
        help="Postgres service DSN, or use SIFT_CONTROL_PLANE_DSN/DATABASE_URL/POSTGRES_DSN",
    )
    parser.add_argument(
        "--knowledge-dir",
        type=Path,
        default=Path(os.environ.get("RAG_KNOWLEDGE_DIR", DEFAULT_KNOWLEDGE_DIR)),
    )
    parser.add_argument("--max-files", type=int, default=None)
    parser.add_argument("--max-records-per-file", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    try:
        result = seed_knowledge_from_dir(
            dsn=args.dsn,
            knowledge_dir=args.knowledge_dir,
            max_files=args.max_files,
            max_records_per_file=args.max_records_per_file,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        result = KnowledgeSeedResult(status="error", errors=[str(exc)])
        print(json.dumps(result.public_dict(), indent=2))
        return 2

    print(json.dumps(result.public_dict(), indent=2))
    return 0


def _collection_name(path: Path, root: Path) -> str:
    rel = path.relative_to(root)
    if len(rel.parts) > 1:
        return rel.parts[0]
    return "knowledge"


def _document_title(path: Path, records: list[dict[str, Any]]) -> str:
    for record in records:
        metadata = record.get("metadata")
        if isinstance(metadata, dict) and metadata.get("title"):
            return str(metadata["title"]).strip()
    return path.stem.replace("_", " ").replace("-", " ").strip() or path.name


def _chunk_metadata(
    record: dict[str, Any], source_ref: str, chunk_index: int
) -> dict[str, Any]:
    metadata = record.get("metadata") if isinstance(record, dict) else {}
    clean = _safe_metadata(metadata if isinstance(metadata, dict) else {})
    clean["source_ref"] = source_ref
    clean["chunk_index"] = chunk_index
    record_id = record.get("id") if isinstance(record, dict) else None
    if record_id:
        clean["record_id"] = str(record_id)
    return clean


def _safe_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in metadata.items():
        if key in {"file", "path", "absolute_path"}:
            continue
        clean[str(key)] = _json_safe(value)
    return clean


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    return str(value)


def _dsn_from_env() -> str | None:
    return (
        os.environ.get("SIFT_CONTROL_PLANE_DSN")
        or os.environ.get("DATABASE_URL")
        or os.environ.get("POSTGRES_DSN")
    )


def _require_dsn(dsn: str | None) -> str:
    if not dsn:
        raise ValueError(
            "Postgres DSN required: pass --dsn or set SIFT_CONTROL_PLANE_DSN"
        )
    return dsn


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
