"""DB-active host-identity + ingest-status adapters (BATCH-K4).

In DB-active mode (Migration-Spec authority cutover), Postgres is authority for
mutable state and the local `~/.sift/ingest-status/*.json` files and the case
`host-dictionary.yaml` become parser-compatibility / debug / legacy artifacts.
This module provides the thin, injectable seams that move two derived concerns
to Postgres without changing the parser/index-name behavior:

1. ``HostIdentityRecorder`` — persists host-identity *decisions* (ingest
   preflight auto-mappings) and *corrections* (operator/agent host-mapping
   fixes) to the BATCH-K4 ``app.record_host_identity_decision`` RPC. Host
   identity is derived indexing metadata; these rows make the derived plane
   traceable and make ``host-dictionary.yaml`` tamper-irrelevant in DB-active
   mode (the DB record, not the file, is the authoritative receipt).

2. ``ingest_status_from_db`` — reads ingest/enrich status for a case from the
   durable job + provenance state via the BATCH-K4 ``app.opensearch_ingest_status``
   RPC, instead of the local status JSON files.

Security invariants (BATCH-K4 acceptance + Migration-Spec constraints):

- psycopg is imported lazily/guarded so importing this module never requires a
  DB driver and the package stays unit-testable.
- The DSN is a worker-local service credential — never agent-visible.
- Only opaque IDs and sanitized host/index names cross this boundary; no OS /
  mount / case filesystem paths and no OpenSearch credentials.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)

# A recorder persists a host-identity decision/correction to Postgres. Injected
# by the worker bootstrap / Gateway (which own the service DB connection) so this
# package never hard-depends on psycopg or a DSN. Signature mirrors the K4 RPC:
#   recorder(case_id, raw, canonical, decision, *, source, tool, confidence,
#            actor_type, job_id, provenance_id, index_names, docs_updated,
#            audit_event_id, metadata) -> str | None
HostIdentityRecorder = Callable[..., "str | None"]

# Decision tokens shared with ingest_cli preflight decision classes.
_DECISION_MAP = {
    "already_mapped": "discovery_already_mapped",
    "auto_alias": "discovery_auto_alias",
    "auto_new_canonical": "discovery_auto_new_canonical",
}


def decision_token_for(preflight_decision: str) -> str:
    """Map an ingest_cli preflight decision label to the DB decision token."""
    return _DECISION_MAP.get(preflight_decision, "discovery_auto_new_canonical")


def psycopg_host_identity_recorder(dsn: str) -> HostIdentityRecorder:
    """Build a Postgres-backed :data:`HostIdentityRecorder` from a service DSN.

    Calls the BATCH-K4 ``app.record_host_identity_decision`` RPC. Kept
    import-guarded so importing this module never requires psycopg. The DSN is a
    worker-local service credential — never agent-visible.
    """

    def _record(
        case_id: str,
        raw: str,
        canonical: str,
        decision: str,
        *,
        source: str | None = None,
        tool: str | None = None,
        confidence: float | None = None,
        actor_type: str | None = None,
        actor_user_id: str | None = None,
        actor_agent_id: str | None = None,
        actor_service_identity_id: str | None = None,
        job_id: str | None = None,
        provenance_id: str | None = None,
        index_names: list[str] | None = None,
        docs_updated: int | None = None,
        audit_event_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str | None:
        import psycopg
        from psycopg.types.json import Jsonb

        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select app.record_host_identity_decision("
                    "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        case_id,
                        raw,
                        canonical,
                        decision,
                        source,
                        tool,
                        confidence,
                        actor_type,
                        actor_user_id,
                        actor_agent_id,
                        actor_service_identity_id,
                        job_id,
                        provenance_id,
                        list(index_names or []),
                        int(docs_updated) if docs_updated is not None else None,
                        audit_event_id,
                        Jsonb(metadata or {}),
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        if row:
            return str(row[0])
        return None

    return _record


# Fields returned by app.opensearch_ingest_status that are safe to surface. The
# RPC already excludes spec_internal / worker_id / lease internals; this is the
# explicit allow-list so a future RPC change cannot silently widen the surface.
_STATUS_FIELDS = (
    "job_id",
    "job_type",
    "status",
    "case_id",
    "evidence_id",
    "provenance_id",
    "attempts",
    "max_attempts",
    "error_summary",
    "result_public",
    "step_count",
    "steps_succeeded",
    "indexed_count",
    "bulk_failed_count",
    "created_at",
    "started_at",
    "finished_at",
    "updated_at",
)


def ingest_status_from_db(dsn: str, case_id: str, *, limit: int = 25) -> list[dict[str, Any]]:
    """Read DB-active ingest/enrich status rows for ``case_id``.

    Calls the BATCH-K4 ``app.opensearch_ingest_status`` RPC and returns a list of
    sanitized status dicts (opaque IDs + sanitized counts only). psycopg is
    imported lazily. Returns an empty list on any DB error so a transient DB
    issue degrades to "no runs" rather than crashing the status tool.
    """
    try:
        import psycopg
    except ImportError:  # pragma: no cover - deployment env
        return []
    rows: list[dict[str, Any]] = []
    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select * from app.opensearch_ingest_status(%s, %s)",
                    (case_id, int(limit)),
                )
                col_names = [desc[0] for desc in cur.description] if cur.description else []
                for raw in cur.fetchall():
                    record = dict(zip(col_names, raw))
                    rows.append({k: record.get(k) for k in _STATUS_FIELDS if k in record})
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("DB ingest-status read failed (%s)", type(exc).__name__)
        return []
    return rows
