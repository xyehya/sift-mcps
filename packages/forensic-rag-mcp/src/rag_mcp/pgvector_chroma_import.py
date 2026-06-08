"""Import the downloaded Chroma RAG bundle into Supabase pgvector.

The legacy RAG release bundle stores the large, model-backed knowledge corpus in
ChromaDB. The MVP Gateway queries Supabase pgvector instead. This importer treats
Chroma as a local source artifact and copies its documents, metadata, and
768-dimensional BGE embeddings into ``app.rag_*`` as shared knowledge rows
(``kind='knowledge'``, ``case_id NULL``). Query serving remains Supabase-only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .constants import get_chroma_path
from .pgvector_store import EMBEDDING_DIM, PgVectorRagStore, stable_rag_uuid
from .utils import DEFAULT_MODEL_NAME

DEFAULT_COLLECTION = "ir_knowledge"
_DROP_METADATA_KEYS = frozenset(
    {
        "absolute_path",
        "case_path",
        "dsn",
        "evidence_path",
        "file",
        "input_path",
        "local_path",
        "mount_path",
        "path",
        "service_role",
        "source_file",
        "token",
    }
)
_SAFE_REF_RE = re.compile(r"[^a-zA-Z0-9._/-]+")


@dataclass(frozen=True)
class ChromaKnowledgeRecord:
    chroma_id: str
    document: str
    metadata: dict[str, Any] = field(default_factory=dict)
    embedding: list[float] = field(default_factory=list)


@dataclass
class ChromaImportResult:
    status: str
    collection_name: str = DEFAULT_COLLECTION
    chroma_records: int = 0
    collections: int = 0
    documents: int = 0
    chunks: int = 0
    skipped: int = 0
    dry_run: bool = False
    errors: list[str] = field(default_factory=list)

    def public_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "collection_name": self.collection_name,
            "chroma_records": self.chroma_records,
            "collections": self.collections,
            "documents": self.documents,
            "chunks": self.chunks,
            "skipped": self.skipped,
            "dry_run": self.dry_run,
            "errors": self.errors,
            "store": "supabase_pgvector",
            "source": "chroma_release_bundle",
        }


def open_chroma_collection(chroma_dir: Path, collection_name: str = DEFAULT_COLLECTION):
    """Open a local Chroma collection lazily so tests need no Chroma import."""
    try:
        import chromadb
    except ImportError as exc:  # pragma: no cover - deployment dependency
        raise RuntimeError("chromadb is required to import a Chroma RAG bundle") from exc
    if not chroma_dir.is_dir():
        raise FileNotFoundError(
            f"Chroma index not found at {chroma_dir}; "
            "run rag_mcp.scripts.download_index first"
        )
    client = chromadb.PersistentClient(path=str(chroma_dir))
    return client.get_collection(collection_name)


def iter_chroma_records(
    collection: Any,
    *,
    batch_size: int = 500,
    limit: int | None = None,
):
    """Yield Chroma records with documents, metadata, and embeddings."""
    total = int(collection.count())
    remaining = total if limit is None else min(total, max(0, int(limit)))
    offset = 0
    page_size = max(1, int(batch_size))
    while remaining > 0:
        size = min(page_size, remaining)
        page = collection.get(
            limit=size,
            offset=offset,
            include=["documents", "metadatas", "embeddings"],
        )
        ids = _page_list(page, "ids")
        docs = _page_list(page, "documents")
        metas = _page_list(page, "metadatas")
        embeddings = _page_list(page, "embeddings")
        if not ids:
            break
        for idx, chroma_id in enumerate(ids):
            yield ChromaKnowledgeRecord(
                chroma_id=str(chroma_id),
                document=str(
                    docs[idx] if idx < len(docs) and docs[idx] is not None else ""
                ),
                metadata=dict(metas[idx] or {}) if idx < len(metas) else {},
                embedding=_embedding_list(
                    embeddings[idx] if idx < len(embeddings) else []
                ),
            )
        consumed = len(ids)
        offset += consumed
        remaining -= consumed
        if consumed < size:
            break


def import_chroma_collection(
    *,
    store: PgVectorRagStore | None,
    collection: Any,
    collection_name: str = DEFAULT_COLLECTION,
    batch_size: int = 500,
    limit: int | None = None,
    dry_run: bool = False,
    source_model: str = DEFAULT_MODEL_NAME,
) -> ChromaImportResult:
    """Copy a Chroma collection into pgvector shared knowledge tables."""
    result = ChromaImportResult(
        status="ok",
        collection_name=collection_name,
        dry_run=dry_run,
    )
    if not dry_run and store is None:
        raise ValueError("store is required unless dry_run=True")

    collection_ids: dict[str, str] = {}
    seen_collections: set[str] = set()
    for record in iter_chroma_records(collection, batch_size=batch_size, limit=limit):
        result.chroma_records += 1
        content = record.document.strip()
        if not content:
            result.skipped += 1
            result.errors.append(f"empty document skipped: {record.chroma_id}")
            continue
        if len(record.embedding) != EMBEDDING_DIM:
            result.skipped += 1
            result.errors.append(
                f"embedding dimension mismatch for {record.chroma_id}: "
                f"got {len(record.embedding)}, expected {EMBEDDING_DIM}"
            )
            continue

        pg_collection = _collection_name(record.metadata)
        seen_collections.add(pg_collection)
        result.documents += 1
        result.chunks += 1
        if dry_run:
            continue

        assert store is not None
        collection_id = collection_ids.get(pg_collection)
        if collection_id is None:
            collection_id = store.ensure_collection(
                name=pg_collection,
                kind="knowledge",
                case_id=None,
                description="Downloaded forensic RAG release knowledge",
                metadata={
                    "seed_source": "chroma_release_pgvector",
                    "chroma_collection": collection_name,
                    "embedding_model": source_model,
                },
            )
            collection_ids[pg_collection] = collection_id
        source_ref = _source_ref(pg_collection, record.chroma_id)
        document_id = store.upsert_document(
            collection_id=collection_id,
            title=_document_title(record),
            kind="knowledge",
            case_id=None,
            provenance_id=stable_rag_uuid(
                "chroma-document", collection_name, record.chroma_id
            ),
            source_ref=source_ref,
            metadata={
                **_safe_metadata(record.metadata),
                "chroma_id": record.chroma_id,
                "seed_source": "chroma_release_pgvector",
                "embedding_model": source_model,
            },
        )
        store.upsert_chunk(
            document_id=document_id,
            chunk_index=0,
            content=content,
            embedding=record.embedding,
            provenance_id=stable_rag_uuid(
                "chroma-chunk", collection_name, record.chroma_id
            ),
            metadata={
                **_safe_metadata(record.metadata),
                "chroma_id": record.chroma_id,
                "source_ref": source_ref,
                "seed_source": "chroma_release_pgvector",
            },
        )

    result.collections = len(seen_collections)
    if result.errors:
        result.status = "partial" if result.documents else "error"
    return result


def import_chroma_from_dir(
    *,
    dsn: str | None,
    chroma_dir: Path = get_chroma_path(),
    collection_name: str = DEFAULT_COLLECTION,
    batch_size: int = 500,
    limit: int | None = None,
    dry_run: bool = False,
    allow_model_mismatch: bool = False,
) -> ChromaImportResult:
    model = _read_bundle_model(chroma_dir.parent)
    if model and model != DEFAULT_MODEL_NAME and not allow_model_mismatch:
        raise ValueError(
            f"Chroma bundle model '{model}' does not match pgvector model "
            f"'{DEFAULT_MODEL_NAME}'. Rebuild/import with matching 768-d embeddings."
        )
    collection = open_chroma_collection(chroma_dir, collection_name)
    store = None if dry_run else PgVectorRagStore(_require_dsn(dsn))
    return import_chroma_collection(
        store=store,
        collection=collection,
        collection_name=collection_name,
        batch_size=batch_size,
        limit=limit,
        dry_run=dry_run,
        source_model=model or DEFAULT_MODEL_NAME,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import downloaded Chroma RAG knowledge into Supabase pgvector"
    )
    parser.add_argument(
        "--dsn",
        default=_dsn_from_env(),
        help="Postgres service DSN, or use SIFT_CONTROL_PLANE_DSN/DATABASE_URL/POSTGRES_DSN",
    )
    parser.add_argument(
        "--chroma-dir",
        type=Path,
        default=Path(os.environ.get("RAG_CHROMA_DIR", get_chroma_path())),
    )
    parser.add_argument("--collection", default=DEFAULT_COLLECTION)
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--allow-model-mismatch", action="store_true")
    args = parser.parse_args(argv)

    try:
        result = import_chroma_from_dir(
            dsn=args.dsn,
            chroma_dir=args.chroma_dir,
            collection_name=args.collection,
            batch_size=args.batch_size,
            limit=args.limit,
            dry_run=args.dry_run,
            allow_model_mismatch=args.allow_model_mismatch,
        )
    except Exception as exc:
        result = ChromaImportResult(
            status="error", errors=[str(exc)], dry_run=args.dry_run
        )
        print(json.dumps(result.public_dict(), indent=2))
        return 2
    print(json.dumps(result.public_dict(), indent=2))
    return 0 if result.status in {"ok", "partial"} else 2


def _embedding_list(value: Any) -> list[float]:
    if value is None:
        return []
    if hasattr(value, "tolist"):
        value = value.tolist()
    return [float(v) for v in value]


def _page_list(page: dict[str, Any], key: str) -> list[Any]:
    value = page.get(key)
    if value is None:
        return []
    if hasattr(value, "tolist"):
        value = value.tolist()
    return list(value)


def _collection_name(metadata: dict[str, Any]) -> str:
    value = (
        metadata.get("source")
        or metadata.get("source_id")
        or metadata.get("category")
        or "chroma_release"
    )
    text = str(value).strip()
    return text[:200] if text else "chroma_release"


def _document_title(record: ChromaKnowledgeRecord) -> str:
    metadata = record.metadata
    for key in ("title", "name", "technique", "source"):
        value = metadata.get(key)
        if value:
            return str(value).strip()[:300]
    text = (
        record.document.strip().splitlines()[0]
        if record.document.strip()
        else record.chroma_id
    )
    return text[:120] or record.chroma_id


def _source_ref(collection_name: str, chroma_id: str) -> str:
    collection = _slug(collection_name, default="collection", max_len=80)
    record = _slug(
        chroma_id, default=stable_rag_uuid("chroma-ref", chroma_id), max_len=120
    )
    return f"chroma/{collection}/{record}"


def _slug(value: str, *, default: str, max_len: int) -> str:
    text = _SAFE_REF_RE.sub("-", str(value).strip()).strip("/.-_")
    text = re.sub(r"-{2,}", "-", text)
    if not text:
        text = default
    return text[:max_len].strip("/.-_") or default


def _safe_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in metadata.items():
        key_text = str(key)
        if key_text.lower() in _DROP_METADATA_KEYS:
            continue
        clean[key_text] = _json_safe(value)
    return clean


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    return str(value)


def _read_bundle_model(data_dir: Path) -> str | None:
    metadata_path = data_dir / "metadata.json"
    if not metadata_path.exists():
        return None
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    model = payload.get("model")
    return str(model) if model else None


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
