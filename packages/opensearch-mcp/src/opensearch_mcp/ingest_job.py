"""Durable-job handlers for the decoupled OpenSearch ingest / enrich pipeline.

feat/opensearch-workers
-----------------------
The OpenSearch ingest pipeline (FUSE-mount an E01, parse Windows artifacts with
the EZ/TSK tools, run Hayabusa Sigma detection, index everything) cannot run
inside the gateway's hardened unit: ``ProtectSystem=strict`` + ``ProtectHome``
+ ``PrivateTmp`` put the gateway in a *private* (slave-propagation) mount
namespace, and the kernel refuses to create a FUSE mount there
(``fusermount: Operation not permitted``). The opensearch backend used to be a
stdio child of the gateway, so it inherited that sandbox and ingest could never
mount the disk.

The fix is to decouple: the gateway stays the thin policy boundary
(auth/active-case/audit/evidence-gate) and ENQUEUES a durable ``ingest`` /
``enrich`` job (non-blocking); a dedicated, least-privilege
``sift-opensearch-worker@`` unit — whose only relaxation vs the gateway is
CAP_SYS_ADMIN plus running in the HOST mount namespace (it omits the
private-namespace protections so fusermount works; there is no
``MountFlags=shared`` — that does not rescue a private-ns unit) — claims the job
and runs the pipeline here.

These handlers run *inside the worker process* (shared mount namespace). They:

1. read the DB-authoritative ``case_dir`` from ``spec_internal`` (the merged P0
   injection — never a client-supplied or env path) and bind it to the
   opensearch backend's ``_INJECTED_CASE_DIR`` contextvar + the child env;
2. invoke the existing, proven opensearch ingest/enrich entry points
   (``opensearch_ingest`` / ``opensearch_enrich_intel``), which spawn the
   ``ingest_cli`` subprocess — now in the worker's *shared* namespace, so the
   FUSE mount succeeds;
3. mirror the existing ``ingest_status`` progress (path-free counts: indexed
   docs, artifacts/hosts complete, hayabusa alerts) into durable per-job steps
   so ``job_status`` surfaces realtime ``worker_label`` / ``current_step``;
4. block until the run reaches a terminal state, then return a path-free
   ``result_public``.

Security: the handler never returns absolute paths or secrets. ``result_public``
and every step ``detail`` carry only opaque counts / run ids / phase names. The
case dir is read from ``spec_internal`` (gateway-injected, anti-spoofed) only.
"""

from __future__ import annotations

import os
import time
from typing import Any

from sift_core.active_case_context import ActiveCaseContext, use_active_case_context
from sift_core.execute.job_worker import ClaimedJob, FatalJobError, JobContext, JobResult

# Terminal ingest_status states (see opensearch_mcp.ingest_status).
_TERMINAL = frozenset({"complete", "failed"})
# Poll cadence + ceiling for mirroring ingest_status into job steps. A full E01
# disk ingest (mount + EZ tools + Hayabusa) can run for tens of minutes; the
# lease is heartbeated on every poll so it never expires under us.
_POLL_SECONDS = 5.0
_MAX_POLL_SECONDS = 6 * 60 * 60  # 6h hard ceiling, defensive against a hung run


def opensearch_ingest_job_handler(job: ClaimedJob, ctx: JobContext) -> JobResult:
    """Run a decoupled ``opensearch_ingest`` as a durable worker job.

    Spawns the ingest pipeline in *this* worker's (shared) mount namespace via
    the existing ``opensearch_ingest`` entry point, then mirrors ingest_status
    into job steps until terminal.
    """
    return _run_pipeline_job(job, ctx, kind="ingest")


def opensearch_enrich_job_handler(job: ClaimedJob, ctx: JobContext) -> JobResult:
    """Run a decoupled ``opensearch_enrich_intel`` as a durable worker job."""
    return _run_pipeline_job(job, ctx, kind="enrich")


# ---------------------------------------------------------------------------
# shared implementation
# ---------------------------------------------------------------------------


def _run_pipeline_job(job: ClaimedJob, ctx: JobContext, *, kind: str) -> JobResult:
    if not job.case_id:
        raise FatalJobError(f"opensearch {kind} job missing case_id")
    case_dir = str(
        job.spec_internal.get("case_dir") or job.spec_internal.get("artifact_path") or ""
    ).strip()
    case_key = str(job.spec_internal.get("case_key") or "").strip()
    if not case_dir:
        raise FatalJobError(f"opensearch {kind} job missing worker case path")

    spec = dict(job.spec_public or {})
    worker_label = _worker_label(job)

    ctx.record_step(
        0,
        f"{kind}:dispatch",
        status="running",
        detail={"worker": worker_label, "phase": "starting"},
    )

    context = ActiveCaseContext(
        case_id=str(job.case_id),
        case_key=case_key or str(job.case_id),
        artifact_path=case_dir,
        membership_role=None,
        db_active=True,
    )

    # The opensearch entry points resolve the active case from the injected
    # case_dir contextvar; the spawned ingest_cli child resolves it from
    # SIFT_CASE_DIR. Bind both so the worker child mounts/indexes the right case.
    prev_env = os.environ.get("SIFT_CASE_DIR")
    os.environ["SIFT_CASE_DIR"] = case_dir
    # B-D1 + B-D2: bind the gateway-injected control-plane DSN and the case UUID
    # into the subprocess env so the ingest_cli child can forward-write one
    # app.audit_events row per artifact (Gap B). Both are read from the
    # anti-spoofed spec_internal / job.case_id (never client-supplied); the
    # child inherits them. Mirror the same save/set/finally-restore discipline
    # as SIFT_CASE_DIR so the worker's own env is left untouched between jobs.
    dsn = str(job.spec_internal.get("control_plane_dsn") or "").strip()
    case_uuid = str(job.case_id or "").strip()
    prev_dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN")
    prev_case_uuid = os.environ.get("SIFT_CASE_UUID")
    if dsn:
        os.environ["SIFT_CONTROL_PLANE_DSN"] = dsn
    if case_uuid:
        os.environ["SIFT_CASE_UUID"] = case_uuid
    try:
        with use_active_case_context(context):
            launch = _launch(kind, spec, case_dir)
    finally:
        if prev_env is None:
            os.environ.pop("SIFT_CASE_DIR", None)
        else:
            os.environ["SIFT_CASE_DIR"] = prev_env
        if prev_dsn is None:
            os.environ.pop("SIFT_CONTROL_PLANE_DSN", None)
        else:
            os.environ["SIFT_CONTROL_PLANE_DSN"] = prev_dsn
        if prev_case_uuid is None:
            os.environ.pop("SIFT_CASE_UUID", None)
        else:
            os.environ["SIFT_CASE_UUID"] = prev_case_uuid

    launch = launch if isinstance(launch, dict) else {"status": "unknown"}

    # An immediate error / refusal from the entry point (e.g. already_indexed,
    # shard_capacity, no host artifacts) is terminal — surface it path-free and
    # fail the job so the agent sees a typed reason rather than a hung poll.
    run_ids = _run_ids(launch)
    if launch.get("error") or (launch.get("status") in {"failed", "already_indexed"} and not run_ids):
        detail = _sanitize_launch(launch)
        ctx.record_step(0, f"{kind}:dispatch", status="failed", detail=detail)
        raise FatalJobError(f"opensearch {kind} did not start: {detail.get('reason', 'no run started')}")

    if not run_ids:
        # Nothing async was launched but no explicit error either (e.g. a dry-run
        # mis-route). Treat the launch payload as the terminal result.
        result = _sanitize_launch(launch)
        ctx.record_step(0, f"{kind}:dispatch", status="succeeded", detail=result)
        return JobResult(result_public=result, provenance_id=None)

    ctx.record_step(
        0,
        f"{kind}:dispatch",
        status="succeeded",
        detail={"worker": worker_label, "phase": "launched", "runs": len(run_ids)},
    )

    final = _mirror_until_terminal(ctx, run_ids, case_dir, kind, worker_label)
    if final.get("status") == "failed":
        # Persist the path-free terminal detail, then fail the job (no retry —
        # a mount/parse failure won't fix itself on a re-claim).
        raise FatalJobError(f"opensearch {kind} failed: {final.get('error') or 'see job steps'}")
    return JobResult(result_public=final, provenance_id=None)


def _launch(kind: str, spec: dict[str, Any], case_dir: str) -> dict[str, Any]:
    """Invoke the existing opensearch entry point in-process (this worker's ns)."""
    from opensearch_mcp import server as os_server

    if kind == "enrich":
        return os_server.opensearch_enrich_intel(
            dry_run=False,
            force=bool(spec.get("force", False)),
            case_dir=case_dir,
        )
    # ingest
    return os_server.opensearch_ingest(
        path=str(spec.get("path") or ""),
        format=str(spec.get("format") or "auto"),
        hostname=str(spec.get("hostname") or ""),
        index_suffix=str(spec.get("index_suffix") or ""),
        time_field=str(spec.get("time_field") or ""),
        delimiter=str(spec.get("delimiter") or ""),
        recursive=bool(spec.get("recursive", False)),
        include=list(spec.get("include") or []) or None,
        exclude=list(spec.get("exclude") or []) or None,
        source_timezone=str(spec.get("source_timezone") or ""),
        all_logs=bool(spec.get("all_logs", False)),
        reduced_ids=bool(spec.get("reduced_ids", False)),
        full=bool(spec.get("full", False)),
        tier=int(spec.get("tier") or 1),
        plugins=list(spec.get("plugins") or []) or None,
        dry_run=False,
        force=bool(spec.get("force", False)),
        vss=bool(spec.get("vss", False)),
        no_hayabusa=bool(spec.get("no_hayabusa", False)),
        case_dir=case_dir,
    )


def _mirror_until_terminal(
    ctx: JobContext,
    run_ids: set[str],
    case_dir: str,
    kind: str,
    worker_label: str,
) -> dict[str, Any]:
    """Poll ingest_status for the launched run(s), mirror progress to job steps.

    Returns a path-free terminal result dict. Heartbeats the lease on every poll
    so a long ingest never loses its claim.
    """
    from opensearch_mcp.ingest_status import read_active_ingests

    deadline = time.monotonic() + _MAX_POLL_SECONDS
    last_sig: str | None = None
    latest_by_run: dict[str, dict[str, Any]] = {}

    while True:
        ctx.heartbeat()
        try:
            active = read_active_ingests()
        except Exception:
            active = []
        for rec in active:
            rid = str(rec.get("run_id") or "")
            if rid in run_ids:
                latest_by_run[rid] = rec

        agg = _aggregate(latest_by_run, run_ids)
        sig = _progress_signature(agg)
        if sig != last_sig:
            # step_index 1: live progress; updated in place (record_job_step
            # upserts by (job_id, step_index)) so current_step always reflects
            # the newest counts without unbounded step rows.
            ctx.record_step(
                1,
                f"{kind}:progress",
                status="running",
                detail={"worker": worker_label, **agg["detail"]},
            )
            last_sig = sig

        if agg["terminal"]:
            status = "failed" if agg["failed"] else "succeeded"
            ctx.record_step(
                1,
                f"{kind}:progress",
                status=status,
                detail={"worker": worker_label, **agg["detail"]},
            )
            result = {"status": "failed" if agg["failed"] else "complete", **agg["detail"]}
            if agg["failed"]:
                result["error"] = agg.get("error") or "ingest reported failure"
            return result

        if time.monotonic() > deadline:
            ctx.record_step(
                1,
                f"{kind}:progress",
                status="failed",
                detail={"worker": worker_label, "phase": "timeout", **agg["detail"]},
            )
            return {"status": "failed", "error": "ingest exceeded worker time ceiling", **agg["detail"]}

        time.sleep(_POLL_SECONDS)


# ---------------------------------------------------------------------------
# helpers (all path-free)
# ---------------------------------------------------------------------------


def _worker_label(job: ClaimedJob) -> str:
    """Non-sensitive liveness label, mirrors the DB worker_id (no path/secret)."""
    return str(job.worker_id or "osw")


def _run_ids(launch: dict[str, Any]) -> set[str]:
    """Collect every run_id the launch payload reports (single or multi)."""
    ids: set[str] = set()
    rid = launch.get("run_id")
    if rid:
        ids.add(str(rid))
    for c in launch.get("containers") or []:
        if isinstance(c, dict) and c.get("run_id"):
            ids.add(str(c["run_id"]))
    return ids


def _aggregate(latest_by_run: dict[str, dict[str, Any]], run_ids: set[str]) -> dict[str, Any]:
    """Reduce the per-run status records to a single path-free progress view.

    Terminal only when EVERY launched run has reached a terminal state (so a
    multi-container ingest doesn't report done while one container is still
    indexing). Counts are summed; hayabusa alerts are surfaced separately.
    """
    indexed = 0
    hayabusa_alerts = 0
    artifacts_complete = 0
    artifacts_total = 0
    hosts_complete = 0
    hosts_total = 0
    statuses: list[str] = []
    errors: list[str] = []

    for rid in run_ids:
        rec = latest_by_run.get(rid)
        if rec is None:
            statuses.append("starting")
            continue
        statuses.append(str(rec.get("status") or "running"))
        totals = rec.get("totals") or {}
        indexed += int(totals.get("indexed") or 0)
        artifacts_complete += int(totals.get("artifacts_complete") or 0)
        artifacts_total += int(totals.get("artifacts_total") or 0)
        hosts_complete += int(totals.get("hosts_complete") or 0)
        hosts_total += int(totals.get("hosts_total") or 0)
        err = str(rec.get("error") or "")
        if err:
            errors.append(_sanitize_error(err))
        for h in rec.get("hosts") or []:
            if str(h.get("hostname") or "").lower() == "hayabusa":
                for a in h.get("artifacts") or []:
                    hayabusa_alerts += int(a.get("indexed") or 0)

    terminal = all(s in _TERMINAL for s in statuses) and len(statuses) == len(run_ids)
    failed = terminal and any(s == "failed" for s in statuses)
    # Current phase: the most informative non-terminal state, else terminal.
    phase = "running"
    if terminal:
        phase = "failed" if failed else "complete"
    elif any(s == "starting" for s in statuses) and indexed == 0:
        phase = "starting"

    detail = {
        "phase": phase,
        "runs_total": len(run_ids),
        "runs_terminal": sum(1 for s in statuses if s in _TERMINAL),
        "indexed_docs": indexed,
        "artifacts_complete": artifacts_complete,
        "artifacts_total": artifacts_total,
        "hosts_complete": hosts_complete,
        "hosts_total": hosts_total,
    }
    if hayabusa_alerts:
        detail["hayabusa_alerts"] = hayabusa_alerts
    out: dict[str, Any] = {"terminal": terminal, "failed": failed, "detail": detail}
    if errors:
        out["error"] = "; ".join(errors[:3])
    return out


def _progress_signature(agg: dict[str, Any]) -> str:
    d = agg["detail"]
    return (
        f"{d['phase']}|{d['indexed_docs']}|{d['artifacts_complete']}/{d['artifacts_total']}"
        f"|{d['hosts_complete']}/{d['hosts_total']}|{d.get('hayabusa_alerts', 0)}"
        f"|{agg['terminal']}|{agg['failed']}"
    )


def _sanitize_launch(launch: dict[str, Any]) -> dict[str, Any]:
    """Path-free mirror of an immediate launch payload (no run started)."""
    out: dict[str, Any] = {"status": str(launch.get("status") or "unknown")}
    for key in ("error", "message", "reason", "doc_count", "index_count"):
        if launch.get(key) is not None:
            value = launch[key]
            out["reason" if key in {"error", "message"} else key] = (
                _sanitize_error(str(value)) if isinstance(value, str) else value
            )
    return out


def _sanitize_error(message: str) -> str:
    """Collapse any absolute path in an error string to ``<path>`` (defense in depth)."""
    import re

    return re.sub(r"(?<![\w])/[^\s\"']*", "<path>", str(message or ""))
