"""Supabase pgvector RAG store (BATCH-G1, hardened BATCH-NW4).

Authoritative metadata + embedding store for the forensic RAG plane, backed by
the ``app.rag_collections`` / ``app.rag_documents`` / ``app.rag_chunks`` schema
and the ``app.rag_search`` / ``app.rag_upsert_chunk`` RPCs.

Authority / isolation contract (Migration-Spec invariants):
    - RAG is a REFERENCE-ONLY plane (BATCH-NW4: B-MVP-RAG-DERIVED REJECTED).
      This module never mutates evidence, approvals, jobs, findings, or reports
      — it only reads/writes RAG tables.
    - KNOWLEDGE ONLY: derived (per-case) RAG data is permanently rejected.
      Case-sensitive derived text must never enter or exit the vector store.
      Both this Python layer and the ``app.rag_search`` DB function (BATCH-NW4
      migration) enforce knowledge-only retrieval. The DB also has BEFORE INSERT
      triggers that block kind='derived' inserts at the SQL level.
    - Output is provenance-linked and PATH-FREE: every returned hit carries a
      provenance_id and document/collection labels, never an absolute
      evidence/case/mount path. A defensive sanitizer drops any path-shaped or
      embedding field before the result leaves this module.

The Gateway worker connects with a service DSN; agents never reach this module
directly. Knowledge data is stored as reference (``kind='knowledge'``,
``case_id`` NULL). The ``kind='derived'`` value is rejected by ingest helpers
and blocked by a DB trigger.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import uuid
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
_BAD_SOURCE_REF_RE = re.compile(r"(^/)|(^|/)\.\.(/|$)|^[a-zA-Z]:[\\/]")

# Embedding dimension contract — must match vector(768) in the migration.
EMBEDDING_DIM = 768
MAX_TOP_K = 50
_ZERO_UUID = "00000000-0000-0000-0000-000000000000"
_UUID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://sift.local/rag")


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


def stable_rag_uuid(*parts: Any) -> str:
    """Return a deterministic UUID for repeatable MVP RAG seed operations."""
    name = "|".join(str(part) for part in parts)
    return str(uuid.uuid5(_UUID_NAMESPACE, name))


def deterministic_embedding(text: str, *, dim: int = EMBEDDING_DIM) -> list[float]:
    """Build a stable local embedding for pgvector smoke data.

    This is deliberately dependency-free. It is not a semantic model replacement;
    it exists so the live VM can prove that rows are populated and retrieved from
    Supabase pgvector without downloading a model or falling back to Chroma.
    """
    if dim <= 0:
        raise PgVectorStoreError("embedding dimension must be positive")
    seed = (text or "sift-rag-empty").encode("utf-8", errors="replace")
    values: list[float] = []
    counter = 0
    while len(values) < dim:
        digest = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        values.extend((byte - 127.5) / 127.5 for byte in digest)
        counter += 1
    values = values[:dim]
    norm = math.sqrt(sum(v * v for v in values)) or 1.0
    return [v / norm for v in values]


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

    # -- metadata ingest -----------------------------------------------------

    def ensure_collection(
        self,
        *,
        name: str,
        kind: str = "knowledge",
        case_id: str | None = None,
        description: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Create or update a RAG collection and return its id."""
        _validate_kind_case(kind, case_id)
        clean_name = str(name or "").strip()
        if not clean_name:
            raise PgVectorStoreError("collection name is required")
        meta = metadata if isinstance(metadata, dict) else {}
        collection_id = ""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id
                    from app.rag_collections
                    where coalesce(case_id, %s::uuid) = coalesce(%s::uuid, %s::uuid)
                      and lower(name) = lower(%s)
                    limit 1
                    """,
                    (_ZERO_UUID, case_id, _ZERO_UUID, clean_name),
                )
                row = cur.fetchone()
                if row:
                    collection_id = str(row[0])
                    cur.execute(
                        """
                        update app.rag_collections
                        set description = coalesce(%s, description),
                            metadata = metadata || %s::jsonb,
                            updated_at = now()
                        where id = %s
                        """,
                        (description, _jsonb_param(meta), collection_id),
                    )
                else:
                    cur.execute(
                        """
                        insert into app.rag_collections
                          (name, kind, case_id, description, metadata)
                        values (%s, %s, %s, %s, %s::jsonb)
                        returning id
                        """,
                        (
                            clean_name,
                            kind,
                            case_id,
                            description,
                            _jsonb_param(meta),
                        ),
                    )
                    row = cur.fetchone()
                    collection_id = str(row[0]) if row else ""
            conn.commit()
        return collection_id

    def upsert_document(
        self,
        *,
        collection_id: str,
        title: str,
        kind: str = "knowledge",
        case_id: str | None = None,
        provenance_id: str | None = None,
        source_ref: str | None = None,
        evidence_object_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Create or update a RAG document row and return its id."""
        _validate_kind_case(kind, case_id)
        clean_title = str(title or "").strip()
        if not clean_title:
            raise PgVectorStoreError("document title is required")
        if source_ref and _BAD_SOURCE_REF_RE.search(source_ref):
            raise PgVectorStoreError("source_ref must be a relative display label")
        meta = metadata if isinstance(metadata, dict) else {}
        document_id = ""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id
                    from app.rag_documents
                    where collection_id = %s
                      and title = %s
                      and source_ref is not distinct from %s
                    limit 1
                    """,
                    (collection_id, clean_title, source_ref),
                )
                row = cur.fetchone()
                if row:
                    document_id = str(row[0])
                    cur.execute(
                        """
                        update app.rag_documents
                        set metadata = metadata || %s::jsonb,
                            updated_at = now()
                        where id = %s
                        """,
                        (_jsonb_param(meta), document_id),
                    )
                else:
                    cur.execute(
                        """
                        insert into app.rag_documents (
                          collection_id, case_id, kind, title, provenance_id,
                          evidence_object_id, source_ref, metadata
                        )
                        values (%s, %s, %s, %s, coalesce(%s::uuid, gen_random_uuid()),
                                %s, %s, %s::jsonb)
                        returning id
                        """,
                        (
                            collection_id,
                            case_id,
                            kind,
                            clean_title,
                            provenance_id,
                            evidence_object_id,
                            source_ref,
                            _jsonb_param(meta),
                        ),
                    )
                    row = cur.fetchone()
                    document_id = str(row[0]) if row else ""
            conn.commit()
        return document_id

    # -- retrieval ----------------------------------------------------------

    def search(
        self,
        *,
        query_embedding: Sequence[float],
        top_k: int = 5,
        source: str | None = None,
        source_ids: Sequence[str] | None = None,
        technique: str | None = None,
        platform: str | None = None,
    ) -> RagSearchResult:
        """Run a knowledge-only retrieval via ``app.rag_search`` (BATCH-NW4).

        BATCH-NW4 (B-MVP-RAG-DERIVED REJECTED): this method is KNOWLEDGE ONLY.
        There is no ``case_id``, no ``include_derived``, and no ``include_knowledge``
        parameter — the DB function enforces kind='knowledge' unconditionally.

        The ``source`` / ``source_ids`` / ``technique`` / ``platform`` filters
        restrict shared-knowledge retrieval by the chunk ``metadata`` jsonb
        (keys ``source`` / ``mitre_techniques`` / ``platform``) — the original
        forensic-rag tool surface. ``source_ids`` (exact) takes precedence over
        ``source`` (substring); the SQL function enforces that precedence.
        """
        if len(query_embedding) != EMBEDDING_DIM:
            raise PgVectorStoreError(
                f"query embedding must be {EMBEDDING_DIM}-dim, got {len(query_embedding)}"
            )
        top_k = max(1, min(int(top_k), MAX_TOP_K))
        clean_source_ids = (
            [str(s) for s in source_ids if str(s).strip()]
            if source_ids
            else None
        ) or None

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select * from app.rag_search("
                    "%s::vector, %s, %s, %s::text[], %s, %s)",
                    (
                        list(query_embedding),
                        top_k,
                        source,
                        clean_source_ids,
                        technique,
                        platform,
                    ),
                )
                rows = cur.fetchall()

        hits = [_row_to_hit(r) for r in rows]
        # Final hard guarantee: strip any non-knowledge hit regardless of what
        # the DB returned.  The BATCH-NW4 migration makes derived rows unreachable
        # at the SQL level; this Python check fails closed defensively.
        safe_hits = [h for h in hits if h.kind == "knowledge"]
        if len(safe_hits) != len(hits):  # pragma: no cover - DB enforces this
            logger.error(
                "rag_search returned non-knowledge rows; dropped %d",
                len(hits) - len(safe_hits),
            )
        return RagSearchResult(case_id=None, hits=safe_hits)

    # -- knowledge introspection (shared reference corpus only) -------------

    def list_knowledge_sources(self) -> list[str]:
        """Return the distinct knowledge ``source`` labels in the corpus.

        Reads the shared-knowledge chunks (``kind='knowledge'``, case-less) and
        returns the distinct ``metadata->>'source'`` values — the same source
        IDs the ``source`` / ``source_ids`` filters match against. Path-free.
        """
        sources: list[str] = []
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select distinct ch.metadata->>'source' as source
                    from app.rag_chunks ch
                    where ch.kind = 'knowledge'
                      and ch.metadata->>'source' is not null
                      and length(btrim(ch.metadata->>'source')) > 0
                    order by 1
                    """
                )
                sources = [str(r[0]) for r in cur.fetchall() if r and r[0]]
        return sources

    def knowledge_stats(self) -> dict[str, Any]:
        """Return corpus statistics for the shared-knowledge plane.

        Reports the embedded chunk count, document/collection counts, distinct
        source count, and the embedding model contract. Path-free; no internal
        DSN or storage detail is surfaced.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select
                      count(*) filter (where ch.embedding is not null),
                      count(distinct ch.document_id),
                      count(distinct ch.collection_id),
                      count(distinct ch.metadata->>'source')
                        filter (where ch.metadata->>'source' is not null)
                    from app.rag_chunks ch
                    where ch.kind = 'knowledge'
                    """
                )
                row = cur.fetchone() or (0, 0, 0, 0)
        return {
            "chunk_count": int(row[0] or 0),
            "document_count": int(row[1] or 0),
            "collection_count": int(row[2] or 0),
            "source_count": int(row[3] or 0),
            "embedding_dim": EMBEDDING_DIM,
            "embedding_model": "BAAI/bge-base-en-v1.5",
        }

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


def _validate_kind_case(kind: str, case_id: str | None) -> None:
    """Validate RAG kind and case_id.

    BATCH-NW4 (B-MVP-RAG-DERIVED REJECTED): only kind='knowledge' is accepted.
    kind='derived' is permanently blocked — the RAG store is shared-knowledge only.
    """
    if kind != "knowledge":
        raise PgVectorStoreError(
            "RAG store is knowledge-only (B-MVP-RAG-DERIVED REJECTED). "
            "kind must be 'knowledge'; kind='derived' is permanently blocked."
        )
    if case_id is not None:
        raise PgVectorStoreError("knowledge RAG rows must not carry case_id")
