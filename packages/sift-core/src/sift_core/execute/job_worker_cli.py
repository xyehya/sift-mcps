"""CLI/bootstrap for the local SIFT durable job worker."""

from __future__ import annotations

import argparse
import os

from sift_core.execute.job_worker import JobWorker, psycopg_connection_factory
from sift_core.execute.run_command_job import run_command_job_handler


def build_handlers(dsn: str):
    # wave8/ingest-tools: the core "ingest" job type was retired. The
    # opensearch-mcp add-on owns the real ingest surface (opensearch_ingest) and
    # runs directly through the gateway proxy, writing its own Postgres
    # provenance receipt — there is no core ingest gatekeeper. The worker now
    # only services the run_command durable-job path.
    handlers = {"run_command": run_command_job_handler}

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
        except Exception:
            pass
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
    args = parser.parse_args(argv)
    if not args.dsn:
        raise SystemExit("SIFT_CONTROL_PLANE_DSN or --dsn is required")
    # K1: the worker only ever runs against the Postgres control plane, so it is
    # always DB-active. Mark the process so core resolvers use the per-job
    # AuthorityContext and never fall back to SIFT_CASE_DIR / ~/.sift/active_case.
    os.environ["SIFT_DB_ACTIVE"] = "1"
    handlers = build_handlers(args.dsn)
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
