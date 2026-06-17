"""Durable Postgres job claim loop for the local SIFT worker (BATCH-D1).

The Gateway enqueues long-running ingest/enrich/report/run-command work as a
durable job row in Postgres (see ``supabase/migrations/202606081200_durable_jobs.sql``).
A local worker process runs :class:`JobWorker`, which:

1. claims the next eligible job atomically (``app.claim_next_job`` uses
   ``FOR UPDATE SKIP LOCKED`` so two workers can never claim the same job),
2. takes a lease and heartbeats it while running,
3. resolves opaque ``case_id``/``evidence_id`` to local paths *internally* (the
   handler does this; IDs never leave Postgres as paths), and
4. writes typed status, steps, sanitized logs, and provenance back to Postgres.

This module deliberately depends only on a small DB-connection protocol rather
than importing ``psycopg`` directly, so ``sift-core`` stays free of a hard DB
dependency and the loop is unit-testable with an in-memory fake connection
(the same pattern the Gateway tests use). The Gateway wires it to a real
``psycopg`` service connection via :func:`psycopg_connection_factory`.

Security invariants (enforced by the caller/handlers, asserted by tests):

- The worker receives only opaque IDs (``case_id``/``evidence_id``/``job_id``).
- It never returns absolute OS paths or secrets to the agent: only
  ``result_public`` and sanitized log lines are written, and those must be
  redacted by the handler before they reach Postgres.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

logger = logging.getLogger(__name__)

# Terminal statuses a job can reach.
TERMINAL_STATUSES = frozenset({"succeeded", "failed", "cancelled", "expired"})
JOB_TYPES = frozenset({"ingest", "enrich", "report", "run_command"})


class JobError(Exception):
    """Recoverable handler error. Triggers ``app.fail_job`` (retry/terminal)."""


class FatalJobError(JobError):
    """Non-recoverable handler error. Forces a terminal failure (no retry)."""


# --- DB connection protocol (duck-typed; psycopg and the test fake satisfy it) ---


class _Cursor(Protocol):
    def execute(self, sql: str, params: Any = ...) -> Any: ...
    def fetchone(self) -> Any: ...

    def __enter__(self) -> "_Cursor": ...
    def __exit__(self, *exc: Any) -> Any: ...


class _Connection(Protocol):
    def cursor(self) -> _Cursor: ...
    def commit(self) -> None: ...
    def close(self) -> None: ...

    def __enter__(self) -> "_Connection": ...
    def __exit__(self, *exc: Any) -> Any: ...


ConnectionFactory = Callable[[], _Connection]


def psycopg_connection_factory(dsn: str) -> ConnectionFactory:
    """Return a factory that opens a fresh ``psycopg`` connection per call.

    Kept import-guarded so importing this module never requires psycopg.
    """

    def _factory() -> _Connection:
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - deployment env
            raise RuntimeError("psycopg is required for the durable job worker") from exc
        return psycopg.connect(dsn)

    return _factory


def _jsonb(value: Any):
    """Wrap a dict for psycopg jsonb binding; pass through for the test fake."""
    if not isinstance(value, dict):
        return value
    try:  # pragma: no cover - exercised only with real psycopg
        from psycopg.types.json import Jsonb

        return Jsonb(value)
    except ImportError:
        return value


@dataclass
class ClaimedJob:
    """Worker-side view of a claimed job."""

    job_id: str
    job_type: str
    case_id: str | None
    evidence_id: str | None
    spec_public: dict[str, Any]
    spec_internal: dict[str, Any]
    attempts: int
    max_attempts: int
    worker_id: str

    @classmethod
    def from_row(cls, row: Any, worker_id: str) -> "ClaimedJob | None":
        if row is None:
            return None
        # Accept either a mapping or the positional tuple shape returned by
        # ``returning *`` from app.claim_next_job. The positional path mirrors
        # the app.jobs column order.
        if isinstance(row, dict):
            data = row
        else:
            data = _row_to_job_dict(row)
        if not data.get("id"):
            return None
        return cls(
            job_id=str(data["id"]),
            job_type=str(data["job_type"]),
            case_id=str(data["case_id"]) if data.get("case_id") else None,
            evidence_id=str(data["evidence_id"]) if data.get("evidence_id") else None,
            spec_public=dict(data.get("spec_public") or {}),
            spec_internal=dict(data.get("spec_internal") or {}),
            attempts=int(data.get("attempts") or 0),
            max_attempts=int(data.get("max_attempts") or 1),
            worker_id=worker_id,
        )


# Positional column order of app.jobs for ``returning *`` rows.
_JOB_COLUMNS = (
    "id",
    "job_type",
    "status",
    "case_id",
    "evidence_id",
    "priority",
    "spec_public",
    "result_public",
    "spec_internal",
    "worker_id",
    "lease_expires_at",
    "attempts",
    "max_attempts",
    "error_summary",
    "provenance_id",
    "enqueue_audit_event_id",
    "requested_by_type",
    "requested_by_user_id",
    "requested_by_agent_id",
    "requested_by_service_identity_id",
    "created_at",
    "updated_at",
    "started_at",
    "finished_at",
)


def _row_to_job_dict(row: Any) -> dict[str, Any]:
    seq = list(row)
    return {col: seq[i] if i < len(seq) else None for i, col in enumerate(_JOB_COLUMNS)}


@dataclass
class JobResult:
    """Handler outcome written back to Postgres on success."""

    result_public: dict[str, Any] = field(default_factory=dict)
    provenance_id: str | None = None


# A handler resolves IDs to local work internally and returns a JobResult.
JobHandler = Callable[[ClaimedJob, "JobContext"], JobResult]


class JobContext:
    """Handler-facing API for steps, logs, and heartbeats during execution."""

    def __init__(self, worker: "JobWorker", job: ClaimedJob) -> None:
        self._worker = worker
        self.job = job

    def heartbeat(self) -> bool:
        return self._worker._heartbeat(self.job)

    def log(self, message: str, *, level: str = "info", step_id: str | None = None) -> str | None:
        return self._worker._append_log(self.job.job_id, message, level=level, step_id=step_id)

    def record_step(
        self,
        step_index: int,
        name: str,
        *,
        status: str = "pending",
        detail: dict[str, Any] | None = None,
    ) -> str | None:
        return self._worker._record_step(
            self.job.job_id, step_index, name, status=status, detail=detail or {}
        )


class JobWorker:
    """Postgres-backed durable job claim loop.

    Parameters
    ----------
    connection_factory:
        Returns a fresh DB connection per operation. Use
        :func:`psycopg_connection_factory` in production.
    handlers:
        Maps ``job_type`` -> :data:`JobHandler`.
    worker_id:
        Stable id for this worker process. Defaults to a random uuid.
    lease_seconds:
        Lease duration requested on claim/heartbeat.
    """

    def __init__(
        self,
        connection_factory: ConnectionFactory,
        handlers: dict[str, JobHandler],
        *,
        worker_id: str | None = None,
        lease_seconds: int = 300,
        poll_interval: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        unknown = set(handlers) - JOB_TYPES
        if unknown:
            raise ValueError(f"unknown job types in handlers: {sorted(unknown)}")
        self._factory = connection_factory
        self._handlers = dict(handlers)
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:12]}"
        self.lease_seconds = int(lease_seconds)
        self.poll_interval = float(poll_interval)
        self._clock = clock
        self._sleep = sleep
        self._stop = False

    # -- public loop --------------------------------------------------------

    def stop(self) -> None:
        self._stop = True

    def run_forever(
        self,
        *,
        max_iterations: int | None = None,
        job_types: list[str] | None = None,
    ) -> int:
        """Claim and run jobs until stopped. Returns the count of jobs handled."""
        handled = 0
        iterations = 0
        while not self._stop:
            if max_iterations is not None and iterations >= max_iterations:
                break
            iterations += 1
            job = self.claim_one(job_types=job_types)
            if job is None:
                self._heartbeat_idle()
                self._sleep(self.poll_interval)
                continue
            self.run_job(job)
            handled += 1
        return handled

    def run_once(self, *, job_types: list[str] | None = None) -> ClaimedJob | None:
        """Claim and run a single job if one is available."""
        job = self.claim_one(job_types=job_types)
        if job is None:
            return None
        self.run_job(job)
        return job

    # -- claim / execute ----------------------------------------------------

    def claim_one(self, job_types: list[str] | None = None) -> ClaimedJob | None:
        with self._factory() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select * from app.claim_next_job(%s, %s, %s)",
                    (self.worker_id, self.lease_seconds, job_types),
                )
                row = cur.fetchone()
            conn.commit()
        job = ClaimedJob.from_row(_unwrap_single(row), self.worker_id)
        if job is not None:
            self._mark_busy(job.job_id)
        return job

    def run_job(self, job: ClaimedJob) -> None:
        handler = self._handlers.get(job.job_type)
        if handler is None:
            self._fail(job, f"no handler for job_type={job.job_type}", force_terminal=True)
            return
        if not self._start(job):
            # Lost the lease before we could start; let expiry/retry handle it.
            return
        ctx = JobContext(self, job)
        try:
            result = handler(job, ctx)
        except FatalJobError as exc:
            self._fail(job, _sanitize(str(exc)), force_terminal=True)
            return
        except JobError as exc:
            self._fail(job, _sanitize(str(exc)))
            return
        except Exception as exc:  # defensive: unexpected handler crash
            self._fail(job, _sanitize(f"unhandled worker error: {type(exc).__name__}"))
            return
        if not isinstance(result, JobResult):
            result = JobResult()
        self._complete(job, result)

    # -- DB transition helpers ---------------------------------------------

    def _start(self, job: ClaimedJob) -> bool:
        return self._call_bool(
            "select app.start_job(%s, %s, %s)",
            (job.job_id, self.worker_id, self.lease_seconds),
        )

    def _heartbeat(self, job: ClaimedJob) -> bool:
        return self._call_bool(
            "select app.heartbeat_job(%s, %s, %s)",
            (job.job_id, self.worker_id, self.lease_seconds),
        )

    def _complete(self, job: ClaimedJob, result: JobResult) -> bool:
        ok = self._call_bool(
            "select app.complete_job(%s, %s, %s, %s)",
            (job.job_id, self.worker_id, _jsonb(result.result_public), result.provenance_id),
        )
        self._mark_idle()
        return ok

    def _fail(self, job: ClaimedJob, summary: str, *, force_terminal: bool = False) -> str | None:
        next_status = self._call_scalar(
            "select app.fail_job(%s, %s, %s, %s)",
            (job.job_id, self.worker_id, summary, force_terminal),
        )
        self._mark_idle()
        return str(next_status) if next_status is not None else None

    def _append_log(
        self, job_id: str, message: str, *, level: str = "info", step_id: str | None = None
    ) -> str | None:
        return self._call_scalar(
            "select app.append_job_log(%s, %s, %s, %s)",
            (job_id, _sanitize(message), level, step_id),
        )

    def _record_step(
        self,
        job_id: str,
        step_index: int,
        name: str,
        *,
        status: str = "pending",
        detail: dict[str, Any] | None = None,
    ) -> str | None:
        return self._call_scalar(
            "select app.record_job_step(%s, %s, %s, %s, %s)",
            (job_id, step_index, name, status, _jsonb(detail or {})),
        )

    def expire_stale_jobs(self) -> int:
        value = self._call_scalar("select app.expire_stale_jobs()", ())
        return int(value or 0)

    # -- heartbeat registry -------------------------------------------------

    def _heartbeat_idle(self) -> None:
        self._mark_idle()

    def _mark_busy(self, job_id: str) -> None:
        self._worker_heartbeat("busy", job_id)

    def _mark_idle(self) -> None:
        self._worker_heartbeat("idle", None)

    def _worker_heartbeat(self, status: str, current_job_id: str | None) -> None:
        try:
            with self._factory() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "select app.worker_heartbeat(%s, %s, %s, %s)",
                        (self.worker_id, status, current_job_id, _jsonb({})),
                    )
                conn.commit()
        except Exception as exc:
            # Heartbeat is best-effort liveness; never let it fail the loop.
            logger.debug("Worker heartbeat failed (best-effort): %s", exc)

    # -- low-level call helpers --------------------------------------------

    def _call_bool(self, sql: str, params: tuple) -> bool:
        return bool(self._call_scalar(sql, params))

    def _call_scalar(self, sql: str, params: tuple) -> Any:
        with self._factory() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                row = cur.fetchone()
            conn.commit()
        return _unwrap_single(row)


def _unwrap_single(row: Any) -> Any:
    """Return the single column of a one-column row, else the row itself."""
    if isinstance(row, (list, tuple)) and len(row) == 1:
        return row[0]
    return row


def _sanitize(message: str | None) -> str:
    """Best-effort scrub of obvious absolute-path leakage from a log/error line.

    The handler is the primary redaction boundary; this is defense in depth so a
    stray absolute path never reaches an agent-visible column. It collapses
    POSIX absolute paths (``/cases/...``, ``/mnt/...``) to ``<path>``.
    """
    if not message:
        return ""
    import re

    return re.sub(r"(?<![\w])/[^\s\"']*", "<path>", str(message))
