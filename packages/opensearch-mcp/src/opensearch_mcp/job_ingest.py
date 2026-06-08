"""DB-job-driven OpenSearch ingest adapter (BATCH-F1).

This is the concrete ``job_type='ingest'`` handler for the durable Postgres job
worker (``sift_core.execute.job_worker.JobWorker``). It is the minimal seam
between the D1 worker claim loop and the existing, unchanged parser/ingestor
stack in this package (``opensearch_mcp.ingest``):

    JobWorker.claim_one()  ->  ClaimedJob(job_type='ingest', ...)
    JobWorker.run_job()    ->  ingest_job_handler(job, ctx)  [this module]
                                  -> opensearch_mcp.ingest.discover / ingest
                                  -> docs indexed with case/evidence/provenance

Security invariants (BATCH-F1 acceptance + Migration-Spec technical constraints):

- The handler receives only opaque IDs (``case_id`` / ``evidence_id`` /
  ``job_id``) plus a worker-only ``spec_internal`` payload. The local evidence
  path is read from ``spec_internal`` (operator/worker-resolved) and is NEVER
  echoed back into ``JobResult`` / job logs.
- A ``provenance_id`` is generated per run and stamped onto every indexed doc
  (via ``opensearch_mcp.bulk.set_ingest_provenance``) alongside the case and
  evidence IDs. OpenSearch stays a *derived, rebuildable* plane that points back
  to authoritative Postgres state.
- OpenSearch credentials live only in the worker's local config
  (``OPENSEARCH_CONFIG`` / ``~/.sift/opensearch.yaml``); they are never placed
  in agent-visible job columns or returned by this handler.
- ``JobResult.result_public`` carries only counts, sanitized index names, and
  the opaque ``provenance_id`` — no paths, no credentials, no DB internals.

The handler is registered with a worker as::

    JobWorker(factory, handlers={"ingest": ingest_job_handler})
"""

from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:  # pragma: no cover - typing only; avoid hard sift_core dep at import
    from sift_core.execute.job_worker import ClaimedJob, JobContext, JobResult

logger = logging.getLogger(__name__)

# Keys the worker-only spec_internal payload may carry. The evidence path is
# resolved by the operator/Gateway/worker before enqueue and lives ONLY here.
_SPEC_EVIDENCE_PATH_KEYS = ("evidence_path", "scan_path", "input_path")
_JSON_FILE_SUFFIXES = frozenset({".json", ".jsonl", ".ndjson"})

# A provenance recorder persists the index/provenance metadata to Postgres via
# the BATCH-F1 RPCs (register_opensearch_index / record_opensearch_ingest_provenance).
# It is injected by the worker bootstrap (which owns the service DB connection),
# so this package never hard-depends on psycopg or a DSN. Signature:
#   recorder(case_id, evidence_id, job_id, provenance_id, pipeline_version,
#            indexed, bulk_failed, hosts) -> None
ProvenanceRecorder = Callable[..., None]


class _IngestJobError(RuntimeError):
    """Raised for a sanitized, agent-safe ingest failure summary."""


def _resolve_evidence_path(job: "ClaimedJob") -> Path:
    """Resolve the local evidence path from the worker-only spec_internal.

    The path never comes from ``spec_public`` (agent-visible) and is never
    returned to the agent. Raises a sanitized error when absent/missing so the
    failure summary carries no path text.
    """
    spec = job.spec_internal or {}
    raw: str | None = None
    for key in _SPEC_EVIDENCE_PATH_KEYS:
        value = spec.get(key)
        if value:
            raw = str(value)
            break
    if not raw:
        raise _IngestJobError("ingest job missing evidence source")
    path = Path(raw).expanduser()
    if not path.exists():
        # Do not leak the path in the message — agent-visible summary.
        raise _IngestJobError("ingest evidence source is not available on the worker")
    return path


def _result(job_result_cls, *, provenance_id: str, hosts: list[dict], indexed: int,
            bulk_failed: int) -> "JobResult":
    return job_result_cls(
        result_public={
            "provenance_id": provenance_id,
            "indexed": int(indexed),
            "bulk_failed": int(bulk_failed),
            "hosts": hosts,
        },
        provenance_id=provenance_id,
    )


def _single_file_kind(path: Path) -> str | None:
    if path.suffix.lower() in _JSON_FILE_SUFFIXES:
        return "json"
    return None


def _ingest_single_json_file(
    *,
    evidence_path: Path,
    client: Any,
    case_id: str,
    hostname: str,
    job_id: str,
    spec: dict[str, Any],
) -> Any:
    from opensearch_mcp import __version__
    from opensearch_mcp.parse_json import ingest_json
    from opensearch_mcp.paths import build_index_name
    from opensearch_mcp.results import ArtifactResult, HostResult, IngestResult

    pipeline_version = f"opensearch-mcp-{__version__}"
    index_name = build_index_name(case_id, f"json-{evidence_path.stem}", hostname)
    indexed, skipped, bulk_failed, _host_renamed = ingest_json(
        evidence_path,
        client,
        index_name,
        hostname,
        time_field=spec.get("time_field") or None,
        source_file="",
        ingest_audit_id=job_id,
        pipeline_version=pipeline_version,
        batch_size=int(spec.get("batch_size") or 1000),
    )

    result = IngestResult(pipeline_version=pipeline_version)
    host = HostResult(hostname=hostname)
    host.artifacts.append(
        ArtifactResult(
            artifact="json",
            index=index_name,
            indexed=int(indexed),
            skipped=int(skipped),
            bulk_failed=int(bulk_failed),
        )
    )
    result.hosts.append(host)
    return result


def make_ingest_job_handler(
    provenance_recorder: ProvenanceRecorder | None = None,
    host_identity_recorder: "Callable[..., Any] | None" = None,
):
    """Build a ``job_type='ingest'`` handler, optionally DB-provenance-backed.

    ``provenance_recorder`` (injected by the worker bootstrap, which owns the
    service DB connection) persists index/provenance metadata to Postgres via
    the BATCH-F1 RPCs. When omitted, ingest still runs and stamps provenance IDs
    onto documents; only the Postgres registration is skipped (keeps this
    package free of a hard psycopg/DSN dependency and unit-testable).

    ``host_identity_recorder`` (BATCH-K4) persists per-host discovery decisions
    to ``app.record_host_identity_decision`` so host identity is DB-recorded in
    DB-active mode. Optional and behind injection for the same reason.
    """

    def _handler(job: "ClaimedJob", ctx: "JobContext") -> "JobResult":
        return _run_ingest_job(job, ctx, provenance_recorder, host_identity_recorder)

    return _handler


def ingest_job_handler(job: "ClaimedJob", ctx: "JobContext") -> "JobResult":
    """Default DB-driven OpenSearch ingest handler (no Postgres provenance write).

    Resolves the evidence source internally, stamps case/evidence/provenance IDs
    onto every indexed document, and returns a sanitized result. Index names are
    already case-scoped (``case-<case_id>-<type>-<host>``) by the ingest stack,
    so OpenSearch search tools remain case-scoped through the Gateway.
    """
    return _run_ingest_job(job, ctx, None, None)


def _run_ingest_job(
    job: "ClaimedJob",
    ctx: "JobContext",
    provenance_recorder: ProvenanceRecorder | None,
    host_identity_recorder: "Callable[..., Any] | None" = None,
) -> "JobResult":
    # Imported lazily so this module never forces a hard sift_core dependency at
    # import time (mirrors the worker's own optional-dependency posture).
    from sift_core.execute.job_worker import FatalJobError, JobError, JobResult

    from sift_common.audit import AuditWriter

    from opensearch_mcp.bulk import (
        reset_circuit_breaker,
        reset_ingest_provenance,
        set_ingest_provenance,
    )
    from opensearch_mcp.client import get_client
    from opensearch_mcp.ingest import discover, ingest

    if not job.case_id:
        raise FatalJobError("ingest job missing case_id")

    spec = job.spec_public or {}
    hostname = spec.get("hostname") or None

    try:
        evidence_path = _resolve_evidence_path(job)
    except _IngestJobError as exc:
        # Missing/unavailable source is non-recoverable: no retry.
        raise FatalJobError(str(exc)) from None

    provenance_id = str(uuid.uuid4())
    ctx.record_step(0, "discover", status="running")
    ctx.heartbeat()

    single_file_kind = _single_file_kind(evidence_path) if evidence_path.is_file() else None
    hosts: list[Any] = []
    if evidence_path.is_file():
        if not single_file_kind:
            ctx.record_step(0, "discover", status="failed")
            raise FatalJobError("unsupported single-file evidence format for ingest job")
        ctx.record_step(
            0,
            "discover",
            status="succeeded",
            detail={"hosts": 1, "artifact": single_file_kind},
        )
        ctx.log(f"discovered 1 {single_file_kind} file for ingest", level="info")
    else:
        try:
            hosts = discover(evidence_path, hostname=hostname)
        except Exception as exc:
            ctx.record_step(0, "discover", status="failed")
            raise JobError(f"evidence discovery failed: {type(exc).__name__}") from exc

        if not hosts:
            ctx.record_step(0, "discover", status="succeeded",
                            detail={"hosts": 0})
            raise FatalJobError("no ingestable hosts/artifacts found in evidence source")

        ctx.record_step(0, "discover", status="succeeded", detail={"hosts": len(hosts)})
        ctx.log(f"discovered {len(hosts)} host(s) for ingest", level="info")

    try:
        client = get_client()
    except Exception as exc:
        # Config/connectivity issue — recoverable (worker may retry once OS is up).
        raise JobError(f"opensearch unavailable: {type(exc).__name__}") from exc

    audit = AuditWriter(mcp_name=f"opensearch-ingest-job-{os.getpid()}")
    reset_circuit_breaker()

    # Stamp opaque provenance IDs onto every doc indexed in this scope. The
    # evidence_id may be null (case-level ingest); only present keys are stamped.
    provenance_fields: dict[str, str] = {
        "vhir.case_id": str(job.case_id),
        "vhir.provenance_id": provenance_id,
        "vhir.job_id": str(job.job_id),
    }
    if job.evidence_id:
        provenance_fields["vhir.evidence_id"] = str(job.evidence_id)

    ctx.record_step(1, "index", status="running")
    token = set_ingest_provenance(provenance_fields)
    try:
        if single_file_kind == "json":
            result = _ingest_single_json_file(
                evidence_path=evidence_path,
                client=client,
                case_id=str(job.case_id),
                hostname=hostname or "single-file",
                job_id=str(job.job_id),
                spec=spec,
            )
        else:
            result = ingest(
                hosts=hosts,
                client=client,
                audit=audit,
                case_id=str(job.case_id),
                include=_as_set(spec.get("include")),
                exclude=_as_set(spec.get("exclude")),
                full=bool(spec.get("full", False)),
            )
    except Exception as exc:
        ctx.record_step(1, "index", status="failed")
        # type-name only; never the exception text (may carry paths).
        raise JobError(f"ingest failed: {type(exc).__name__}") from exc
    finally:
        reset_ingest_provenance(token)

    host_summaries, total_indexed, total_bulk_failed = _summarize(result)
    pipeline_version = getattr(result, "pipeline_version", None)
    ctx.record_step(
        1, "index", status="succeeded",
        detail={"indexed": total_indexed, "bulk_failed": total_bulk_failed},
    )
    ctx.log(
        f"indexed {total_indexed} document(s) across {len(host_summaries)} host(s)"
        + (f", {total_bulk_failed} bulk-failed" if total_bulk_failed else ""),
        level="info",
    )

    # Register the derived indices + provenance receipt in authoritative
    # Postgres (best-effort: a registration failure must not fail an ingest that
    # already wrote documents; OpenSearch is rebuildable and the worker can
    # re-register on retry). Never include paths in the recorded summary.
    if provenance_recorder is not None:
        try:
            provenance_recorder(
                case_id=str(job.case_id),
                evidence_id=str(job.evidence_id) if job.evidence_id else None,
                job_id=str(job.job_id),
                provenance_id=provenance_id,
                pipeline_version=pipeline_version,
                indexed=total_indexed,
                bulk_failed=total_bulk_failed,
                hosts=host_summaries,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "opensearch provenance registration failed (%s); "
                "index data was written, registration can be retried",
                type(exc).__name__,
            )

    # BATCH-K4: record per-host discovery decisions in authoritative Postgres so
    # host identity is DB-recorded (not just inferred from the local dictionary).
    # Each ingested host produces a discovery decision keyed by its sanitized
    # hostname + the case-scoped derived index names it wrote. Best-effort: a
    # recording failure must not fail an ingest that already wrote documents.
    if host_identity_recorder is not None:
        for host in host_summaries:
            hostname = (host.get("hostname") or "").strip()
            if not hostname:
                continue
            index_names = sorted(
                str(art.get("index"))
                for art in host.get("artifacts", [])
                if art.get("index")
            )
            try:
                host_identity_recorder(
                    str(job.case_id),
                    hostname,
                    hostname,
                    "discovery_auto_new_canonical",
                    source="ingest_discovery",
                    tool="opensearch_ingest",
                    job_id=str(job.job_id),
                    provenance_id=provenance_id,
                    index_names=index_names,
                    metadata={"pipeline_version": pipeline_version},
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "host-identity discovery decision write failed (%s); "
                    "ingest succeeded, decision can be re-recorded",
                    type(exc).__name__,
                )

    return _result(
        JobResult,
        provenance_id=provenance_id,
        hosts=host_summaries,
        indexed=total_indexed,
        bulk_failed=total_bulk_failed,
    )


def psycopg_provenance_recorder(dsn: str) -> ProvenanceRecorder:
    """Build a Postgres-backed :data:`ProvenanceRecorder` from a service DSN.

    Calls the BATCH-F1 RPCs ``app.register_opensearch_index`` (one row per
    case-scoped index) and ``app.record_opensearch_ingest_provenance`` (one
    receipt per run) in a single transaction. Kept import-guarded so importing
    this module never requires psycopg. The DSN is a worker-local service
    credential — never agent-visible.
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


def _as_set(value: Any) -> set[str] | None:
    if not value:
        return None
    if isinstance(value, str):
        return {v.strip().lower() for v in value.split(",") if v.strip()}
    if isinstance(value, (list, tuple, set)):
        return {str(v).strip().lower() for v in value if str(v).strip()}
    return None


def _summarize(result: Any) -> tuple[list[dict], int, int]:
    """Build a sanitized per-host/index summary from an IngestResult.

    Index names are case-scoped derived identifiers (``case-<id>-<type>-<host>``)
    and contain no OS paths, so they are agent-safe. Source file paths on the
    artifact results are deliberately excluded.
    """
    hosts: list[dict] = []
    total_indexed = 0
    total_bulk_failed = 0
    for host in getattr(result, "hosts", []) or []:
        artifacts = []
        for art in getattr(host, "artifacts", []) or []:
            total_indexed += int(getattr(art, "indexed", 0) or 0)
            total_bulk_failed += int(getattr(art, "bulk_failed", 0) or 0)
            artifacts.append(
                {
                    "artifact": getattr(art, "artifact", ""),
                    "index": getattr(art, "index", ""),
                    "indexed": int(getattr(art, "indexed", 0) or 0),
                    "skipped": int(getattr(art, "skipped", 0) or 0),
                    "bulk_failed": int(getattr(art, "bulk_failed", 0) or 0),
                    # error_summary kept short + type-level; full parser errors
                    # may contain file paths and are not surfaced to the agent.
                    "ok": not bool(getattr(art, "error", "")),
                }
            )
        hosts.append({"hostname": getattr(host, "hostname", ""), "artifacts": artifacts})
    return hosts, total_indexed, total_bulk_failed
