"""Supabase pgvector RAG store (BATCH-G1).

Authoritative metadata + embedding store for the forensic RAG plane, backed by
the ``app.rag_collections`` / ``app.rag_documents`` / ``app.rag_chunks`` schema
and the ``app.rag_search`` / ``app.rag_upsert_chunk`` RPCs added in
``202606081400_rag_pgvector.sql``.

Authority / isolation contract (Migration-Spec invariants):
    - RAG is a DERIVED / REFERENCE plane. This module never mutates evidence,
      approvals, jobs, findings, or reports — it only reads/writes RAG tables.
    - A retrieval is ALWAYS bound to one querying case. It returns that case's
      derived chunks UNION the shared knowledge chunks. Another case's derived
      data is unreachable both in ``app.rag_search`` and here.
    - Output is provenance-linked and PATH-FREE: every returned hit carries a
      provenance_id and document/collection labels, never an absolute
      evidence/case/mount path. A defensive sanitizer drops any path-shaped or
      embedding field before the result leaves this module.

The Gateway worker connects with a service DSN; agents never reach this module
directly. Knowledge data is stored as reference (``kind='knowledge'``,
``case_id`` NULL); derived case context is stored case-scoped
(``kind='derived'``, ``case_id`` set).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Fields that must never appear in agent-visible RAG output.
_FORBIDDEN_OUTPUT_KEYS = frozenset({"embedding", "spec_internal", "dsn", "connection"})

# Absolute-path shapes (POSIX + Windows) used to scrub any leaked path. Mirrors
# the derived-content CHECK in the migration so the Python layer fails closed
# even if a row predates the constraint.
_ABS_PATH_RE = re.compile(
    r"(^|\s)/(home|root|mnt|media|evidence|cases?|var|opt|srv)/|[a-zA-Z]:\\"
)

# Embedding dimension contract — must match vector(768) in the migration.
EMBEDDING_DIM = 768
MAX_TOP_K = 50


class PgVectorStoreError(Exception):
    """Raised on misuse of the pgvector RAG store (e.g. missing case scope)."""


def _connect(dsn: str):
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - deployment env
        raise RuntimeError("psycopg is required for the pgvector RAG store") from exc
    return psycopg.connect(dsn)


def _scrub_text(value: str) -> str:
    """Redact any absolute path that leaked into a text field."""
    return _ABS_PATH_RE.sub(" [redacted-path] ", value)


def _sanitize_hit(row: dict[str, Any]) -> dict[str, Any]:
    """Project a raw search row to the agent-safe, path-free hit shape.

    Drops embeddings/internal fields, scrubs any path-shaped text, and keeps
    only provenance + labels + content + distance.
    """
    out: dict[str, Any] = {}
    for key, val in row.items():
        if key in _FORBIDDEN_OUTPUT_KEYS:
            continue
        if isinstance(val, str):
            out[key] = _scrub_text(val)
        else:
            out[key] = val
    return out


@dataclass
class RagHit:
    """One provenance-linked, path-free retrieval result."""

    chunk_id: str
    provenance_id: str
    document_provenance_id: str
    document_title: str
    collection_name: str
    content: str
    kind: str
    case_id: str | None
    distance: float
    source_ref: str | None = None
    evidence_object_id: str | None = None

    def public_dict(self) -> dict[str, Any]:
        return _sanitize_hit(
            {
                "chunk_id": self.chunk_id,
                "provenance_id": self.provenance_id,
                "document_provenance_id": self.document_provenance_id,
                "document_title": self.document_title,
                "collection_name": self.collection_name,
                "content": self.content,
                "kind": self.kind,
                "case_id": self.case_id,
                "distance": self.distance,
                "source_ref": self.source_ref,
                "evidence_object_id": self.evidence_object_id,
            }
        )


@dataclass
class RagSearchResult:
    """Sanitized, case-scoped retrieval response."""

    case_id: str | None
    hits: list[RagHit] = field(default_factory=list)

    def public_dict(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "case_id": self.case_id,
            "results": [h.public_dict() for h in self.hits],
        }


def _row_to_hit(row: Sequence[Any]) -> RagHit:
    # Column order matches app.rag_search RETURNS TABLE.
    (
        chunk_id,
        case_id,
        kind,
        provenance_id,
        _document_id,
        document_provenance_id,
        document_title,
        source_ref,
        evidence_object_id,
        collection_name,
        content,
        distance,
    ) = row
    return RagHit(
        chunk_id=str(chunk_id),
        provenance_id=str(provenance_id),
        document_provenance_id=str(document_provenance_id),
        document_title=document_title,
        collection_name=collection_name,
        content=content,
        kind=kind,
        case_id=str(case_id) if case_id is not None else None,
        distance=float(distance) if distance is not None else 0.0,
        source_ref=source_ref,
        evidence_object_id=str(evidence_object_id) if evidence_object_id else None,
    )


class PgVectorRagStore:
    """Service-DSN adapter over the BATCH-G1 pgvector RAG schema."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    def _connect(self):
        return _connect(self._dsn)

    # -- retrieval ----------------------------------------------------------

    def search(
        self,
        *,
        query_embedding: Sequence[float],
        case_id: str | None,
        top_k: int = 5,
        include_knowledge: bool = True,
        include_derived: bool = True,
    ) -> RagSearchResult:
        """Run a case-scoped retrieval via ``app.rag_search``.

        ``case_id`` is the ONLY case whose derived chunks may be returned. When
        ``case_id`` is None, derived retrieval is force-disabled so no case's
        derived data can leak; only shared knowledge is searched.
        """
        if len(query_embedding) != EMBEDDING_DIM:
            raise PgVectorStoreError(
                f"query embedding must be {EMBEDDING_DIM}-dim, got {len(query_embedding)}"
            )
        top_k = max(1, min(int(top_k), MAX_TOP_K))
        # Defense in depth: derived retrieval is meaningless and unsafe without a
        # bound case, so disable it when no case scope is supplied.
        effective_derived = include_derived and case_id is not None

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select * from app.rag_search(%s::vector, %s, %s, %s, %s)",
                    (
                        list(query_embedding),
                        case_id,
                        top_k,
                        include_knowledge,
                        effective_derived,
                    ),
                )
                rows = cur.fetchall()

        hits = [_row_to_hit(r) for r in rows]
        # Final hard guarantee: strip any derived hit not belonging to the
        # querying case, regardless of what the DB returned.
        safe_hits = [
            h
            for h in hits
            if h.kind == "knowledge" or (h.case_id is not None and h.case_id == case_id)
        ]
        if len(safe_hits) != len(hits):  # pragma: no cover - DB enforces this
            logger.error("rag_search returned cross-case rows; dropped %d", len(hits) - len(safe_hits))
        return RagSearchResult(case_id=case_id, hits=safe_hits)

    # -- ingest -------------------------------------------------------------

    def upsert_chunk(
        self,
        *,
        document_id: str,
        chunk_index: int,
        content: str,
        embedding: Sequence[float] | None = None,
        provenance_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Upsert one chunk via ``app.rag_upsert_chunk`` (service only).

        case_id/kind/collection are inherited from the parent document by the
        RPC, so a chunk can never be mis-scoped relative to its document.
        """
        if embedding is not None and len(embedding) != EMBEDDING_DIM:
            raise PgVectorStoreError(
                f"embedding must be {EMBEDDING_DIM}-dim, got {len(embedding)}"
            )
        meta = metadata if isinstance(metadata, dict) else {}
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select app.rag_upsert_chunk(%s, %s, %s, %s::vector, %s, %s::jsonb)",
                    (
                        document_id,
                        chunk_index,
                        content,
                        list(embedding) if embedding is not None else None,
                        provenance_id,
                        _jsonb_param(meta),
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return str(row[0]) if row else ""


def _jsonb_param(value: dict[str, Any]):
    try:
        from psycopg.types.json import Jsonb
    except ImportError:  # pragma: no cover
        import json

        return json.dumps(value)
    return Jsonb(value)
