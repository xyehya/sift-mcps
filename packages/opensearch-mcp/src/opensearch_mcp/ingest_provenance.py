"""Postgres provenance for add-on direct ingests (wave8/ingest-tools).

The opensearch-mcp add-on owns the real ingest surface (``opensearch_ingest`` ->
``ingest_cli scan``). It now writes its own provenance receipt to the
authoritative control plane so a finding/report can resolve any indexed doc back
to the case, evidence, and ingest run — without a core job gatekeeper.

Two RPCs are reused as-is (the schema already permits ``job_id = NULL`` for a
non-job, direct ingest):

  - ``app.register_opensearch_index``           (one row per case-scoped index)
  - ``app.record_opensearch_ingest_provenance`` (one receipt per run)

The per-doc ``sift.provenance_id`` stamp is applied by the caller via
``opensearch_mcp.bulk.set_ingest_provenance`` around the ``ingest()`` call, so
every indexed document carries the same opaque ``provenance_id`` recorded here.

Design notes:
  - Import-guarded psycopg: importing this module never requires psycopg.
  - The DSN is a service credential read from ``SIFT_CONTROL_PLANE_DSN`` in the
    ingest subprocess environment. It is never agent-visible and never logged.
  - Best-effort: a registration failure must NOT fail an ingest that already
    wrote documents (OpenSearch is rebuildable; the receipt can be re-recorded).
  - The recorded summary carries only host/index/count shape — no paths,
    no credentials, no DB internals.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable

logger = logging.getLogger(__name__)

# A provenance recorder persists index/provenance metadata to Postgres via the
# BATCH-F1 RPCs. Signature:
#   recorder(case_id, evidence_id, job_id, provenance_id, pipeline_version,
#            indexed, bulk_failed, hosts) -> None
ProvenanceRecorder = Callable[..., None]


def psycopg_provenance_recorder(dsn: str) -> ProvenanceRecorder:
    """Build a Postgres-backed :data:`ProvenanceRecorder` from a service DSN.

    Calls ``app.register_opensearch_index`` (one row per case-scoped index) and
    ``app.record_opensearch_ingest_provenance`` (one receipt per run) in a single
    transaction. Kept import-guarded so importing this module never requires
    psycopg. The DSN is a service credential — never agent-visible.
    """

    def _record(
        *,
        case_id: str,
        evidence_id: str | None,
        job_id: str | None,
        provenance_id: str,
        pipeline_version: str | None,
        indexed: int,
        bulk_failed: int,
        hosts: list[dict],
    ) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                for host in hosts:
                    hostname = host.get("hostname") or None
                    for art in host.get("artifacts", []):
                        index_name = art.get("index")
                        if not index_name:
                            continue
                        cur.execute(
                            "select app.register_opensearch_index("
                            "%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                            (
                                case_id,
                                index_name,
                                art.get("artifact") or None,
                                hostname,
                                evidence_id,
                                provenance_id,
                                job_id,
                                int(art.get("indexed", 0) or 0),
                                pipeline_version,
                            ),
                        )
                cur.execute(
                    "select app.record_opensearch_ingest_provenance("
                    "%s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        provenance_id,
                        case_id,
                        evidence_id,
                        job_id,
                        pipeline_version,
                        int(indexed),
                        int(bulk_failed),
                        Jsonb({"hosts": hosts}),
                    ),
                )
            conn.commit()

    return _record


def _summary_hosts_from_result(result: Any) -> tuple[list[dict], int, int]:
    """Build a sanitized per-host/index summary from an ``IngestResult``.

    Index names are case-scoped derived identifiers (``case-<id>-<type>-<host>``)
    and contain no OS paths, so they are control-plane-safe. Source file paths on
    the artifact results are deliberately excluded.

    Returns ``(hosts, total_indexed, total_bulk_failed)``.
    """
    hosts: list[dict] = []
    total_indexed = 0
    total_bulk_failed = 0
    for host in getattr(result, "hosts", []) or []:
        artifacts: list[dict] = []
        for art in getattr(host, "artifacts", []) or []:
            index_name = getattr(art, "index", "") or ""
            if not index_name:
                continue
            indexed = int(getattr(art, "indexed", 0) or 0)
            bulk_failed = int(getattr(art, "bulk_failed", 0) or 0)
            total_indexed += indexed
            total_bulk_failed += bulk_failed
            artifacts.append(
                {
                    "artifact": getattr(art, "artifact", "") or "",
                    "index": index_name,
                    "indexed": indexed,
                    "bulk_failed": bulk_failed,
                }
            )
        hosts.append(
            {"hostname": getattr(host, "hostname", "") or "", "artifacts": artifacts}
        )
    return hosts, total_indexed, total_bulk_failed


def record_direct_ingest_provenance(
    *,
    case_id: str,
    provenance_id: str,
    result: Any,
    evidence_id: str | None = None,
    recorder: ProvenanceRecorder | None = None,
) -> bool:
    """Best-effort: write the provenance receipt for a direct (non-job) ingest.

    Resolves the service DSN from ``SIFT_CONTROL_PLANE_DSN`` when no ``recorder``
    is injected (tests inject a fake). Returns ``True`` when a receipt was
    written, ``False`` when skipped (no DSN / no recorder) or on any failure —
    never raises, because the documents are already indexed.
    """
    if recorder is None:
        dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
        if not dsn:
            logger.debug(
                "ingest provenance skipped: no SIFT_CONTROL_PLANE_DSN in environment"
            )
            return False
        try:
            recorder = psycopg_provenance_recorder(dsn)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "ingest provenance recorder init failed (%s); skipping receipt",
                type(exc).__name__,
            )
            return False

    hosts, total_indexed, total_bulk_failed = _summary_hosts_from_result(result)
    pipeline_version = getattr(result, "pipeline_version", None) or None
    try:
        recorder(
            case_id=str(case_id),
            evidence_id=str(evidence_id) if evidence_id else None,
            job_id=None,
            provenance_id=str(provenance_id),
            pipeline_version=pipeline_version,
            indexed=total_indexed,
            bulk_failed=total_bulk_failed,
            hosts=hosts,
        )
        return True
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "ingest provenance receipt write failed (%s); index data was written, "
            "registration can be retried",
            type(exc).__name__,
        )
        return False
