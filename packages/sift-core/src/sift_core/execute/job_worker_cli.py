"""CLI/bootstrap for the local SIFT durable job worker."""

from __future__ import annotations

import argparse
import os

from sift_core.execute.job_worker import JobWorker, psycopg_connection_factory
from sift_core.execute.run_command_job import run_command_job_handler


def build_handlers(dsn: str):
    handlers = {"run_command": run_command_job_handler}
    try:
        from opensearch_mcp.job_ingest import (
            make_ingest_job_handler,
            psycopg_provenance_recorder,
        )

        handlers["ingest"] = make_ingest_job_handler(
            provenance_recorder=psycopg_provenance_recorder(dsn)
        )
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
