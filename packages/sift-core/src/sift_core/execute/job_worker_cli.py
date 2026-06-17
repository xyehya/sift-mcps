"""CLI/bootstrap for the local SIFT durable job worker."""

from __future__ import annotations

import argparse
import logging
import os

logger = logging.getLogger(__name__)

from sift_core.execute.job_worker import JobWorker, psycopg_connection_factory
from sift_core.execute.run_command_job import run_command_job_handler


def build_handlers(dsn: str, *, job_types: list[str] | None = None):
    """Build the job-type -> handler map for this worker.

    ``job_types`` (from ``--job-types``) restricts which handlers are wired so a
    dedicated worker only services its lane. ``None`` wires every available
    handler (back-compat with the single combined worker).

    feat/opensearch-workers: the OpenSearch ingest pipeline is decoupled from the
    gateway stdio child into dedicated, least-privilege ``sift-opensearch-worker@``
    units (the only place with the ``MountFlags=shared`` namespace that FUSE
    needs). The gateway enqueues ``ingest``/``enrich`` jobs; those workers run
    ``--job-types ingest,enrich`` and claim them via FOR UPDATE SKIP LOCKED, so N
    workers ingest in parallel. The default ``sift-job-worker`` keeps servicing
    ``run_command``.
    """
    wanted = set(job_types) if job_types else None

    def _want(job_type: str) -> bool:
        return wanted is None or job_type in wanted

    handlers: dict = {}
    if _want("run_command"):
        handlers["run_command"] = run_command_job_handler

    # feat/opensearch-workers: wire the decoupled ingest/enrich handlers. These
    # live in the opensearch-mcp add-on, so the import is guarded — a deployment
    # without the add-on (or a run_command-only worker) never fails to start.
    if _want("ingest") or _want("enrich"):
        try:
            from opensearch_mcp.ingest_job import (
                opensearch_enrich_job_handler,
                opensearch_ingest_job_handler,
            )

            if _want("ingest"):
                handlers["ingest"] = opensearch_ingest_job_handler
            if _want("enrich"):
                handlers["enrich"] = opensearch_enrich_job_handler
        except ImportError:
            pass

    # BATCH-K4: still wire the host-mapping correction recorder so
    # opensearch_fix_host_mapping leaves an authoritative Postgres receipt when
    # the worker (which owns the service DSN) runs in-process. Import-guarded so a
    # missing add-on module never disables the run_command worker.
    try:
        from opensearch_mcp.host_identity_db import psycopg_host_identity_recorder

        host_identity_recorder = psycopg_host_identity_recorder(dsn)
        try:
            from opensearch_mcp import server as _os_server

            _os_server.set_host_identity_recorder(host_identity_recorder)
        except Exception as exc:
            logger.warning("Failed to wire host_identity_recorder to opensearch server: %s", exc)
    except ImportError:
        pass
    return handlers


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the SIFT Postgres job worker")
    parser.add_argument("--dsn", default=os.environ.get("SIFT_CONTROL_PLANE_DSN", ""))
    parser.add_argument("--worker-id", default=os.environ.get("SIFT_WORKER_ID", ""))
    parser.add_argument("--once", action="store_true", help="Claim/run one job then exit")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--lease-seconds", type=int, default=300)
    parser.add_argument(
        "--job-types",
        default=os.environ.get("SIFT_WORKER_JOB_TYPES", ""),
        help=(
            "Comma-separated job types this worker services (e.g. "
            "'ingest,enrich' for an opensearch worker, 'run_command' for the "
            "default worker). Empty = all wired handlers."
        ),
    )
    args = parser.parse_args(argv)
    if not args.dsn:
        raise SystemExit("SIFT_CONTROL_PLANE_DSN or --dsn is required")
    requested_types = [t.strip() for t in str(args.job_types).split(",") if t.strip()] or None
    # K1: the worker only ever runs against the Postgres control plane, so it is
    # always DB-active. Mark the process so core resolvers use the per-job
    # AuthorityContext and never fall back to SIFT_CASE_DIR / ~/.sift/active_case.
    os.environ["SIFT_DB_ACTIVE"] = "1"
    handlers = build_handlers(args.dsn, job_types=requested_types)
    if not handlers:
        raise SystemExit(
            f"no handlers wired for --job-types={requested_types or 'all'} "
            "(missing add-on, or unknown job type)"
        )
    # Default a stable, human-readable worker id per lane so the realtime
    # worker_label in job_status reads e.g. ``osw-ingest-<pid>`` and N-way
    # parallelism is visible. SEC-F1: the hostname is deliberately NOT included —
    # worker_label is surfaced to case members via app.job_status_public, which
    # documents the label as non-sensitive (no host path / DSN / token); embedding
    # socket.gethostname() would leak the internal VM host. An explicit
    # --worker-id / SIFT_WORKER_ID (e.g. the systemd unit's osw-%i) overrides.
    if not args.worker_id:
        lane = "-".join(sorted(handlers)) if requested_types else "all"
        args.worker_id = f"osw-{lane}-{os.getpid()}"[:120]
    job_types = sorted(handlers)
    worker = JobWorker(
        psycopg_connection_factory(args.dsn),
        handlers,
        worker_id=args.worker_id or None,
        lease_seconds=args.lease_seconds,
        poll_interval=args.poll_interval,
    )
    if args.once:
        return 0 if worker.run_once(job_types=job_types) is not None else 2
    worker.run_forever(job_types=job_types)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
