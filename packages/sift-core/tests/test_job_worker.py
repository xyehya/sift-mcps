"""Tests for the durable Postgres job worker (BATCH-D1).

These tests run against an in-memory ``FakeJobDB`` that faithfully models the
semantics of the SQL RPCs in ``202606081200_durable_jobs.sql``:

- ``claim_next_job`` uses ``FOR UPDATE SKIP LOCKED``: a row currently locked by
  another (uncommitted) transaction is skipped, so two concurrent workers can
  never claim the same job.
- ``fail_job`` re-queues while ``attempts < max_attempts``, else marks terminal
  ``failed``.
- ``expire_stale_jobs`` reclaims leases past their deadline (re-queue or
  ``expired``).

The fake is the same connection/cursor duck-typed shape the worker expects, so
the worker code path under test is identical to production; only the SQL engine
is simulated.
"""

from __future__ import annotations

import threading
import time

import pytest

from sift_core.execute.job_worker import (
    ClaimedJob,
    FatalJobError,
    JobContext,
    JobError,
    JobResult,
    JobWorker,
    _sanitize,
)


# --------------------------------------------------------------------------
# Fake Postgres modeling the durable-jobs RPC semantics.
# --------------------------------------------------------------------------


def _unwrap_jsonb(value):
    """Mirror Postgres jsonb decoding: a psycopg Jsonb wrapper becomes its dict."""
    obj = getattr(value, "obj", None)
    if obj is not None and type(value).__name__ == "Jsonb":
        return obj
    return value


class _Job:
    _seq = 0

    def __init__(self, job_type, case_id=None, evidence_id=None, max_attempts=3,
                 spec_public=None, spec_internal=None):
        _Job._seq += 1
        self.id = f"job-{_Job._seq:04d}"
        self.job_type = job_type
        self.status = "queued"
        self.case_id = case_id
        self.evidence_id = evidence_id
        self.priority = 100
        self.spec_public = dict(spec_public or {})
        self.result_public = None
        self.spec_internal = dict(spec_internal or {})
        self.worker_id = None
        self.lease_expires_at = None
        self.attempts = 0
        self.max_attempts = max_attempts
        self.error_summary = None
        self.provenance_id = None
        self.created_at = _Job._seq  # monotonic ordering proxy

    def as_row(self):
        # Positional order matching _JOB_COLUMNS in job_worker.
        return (
            self.id, self.job_type, self.status, self.case_id, self.evidence_id,
            self.priority, self.spec_public, self.result_public, self.spec_internal,
            self.worker_id, self.lease_expires_at, self.attempts, self.max_attempts,
            self.error_summary, self.provenance_id, None, None, None, None, None,
            self.created_at, None, None, None,
        )


class FakeJobDB:
    """Shared store + lock table that the connection/cursor objects mutate."""

    def __init__(self, now_fn=None):
        self.jobs: list[_Job] = []
        self.steps: list[dict] = []
        self.logs: list[dict] = []
        self.heartbeats: dict[str, dict] = {}
        # job_id -> True while a transaction holds a FOR UPDATE lock on it.
        self._row_locks: set[str] = set()
        self._lock = threading.Lock()
        self._now = now_fn or (lambda: time.time())

    def now(self):
        return self._now()

    def enqueue(self, job: _Job) -> _Job:
        self.jobs.append(job)
        return job

    def get(self, job_id):
        for j in self.jobs:
            if j.id == job_id:
                return j
        return None

    def connect(self):
        return _Conn(self)


class _Conn:
    def __init__(self, db: FakeJobDB):
        self.db = db
        self._locked: set[str] = set()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._release()
        return False

    def cursor(self):
        return _Cursor(self)

    def commit(self):
        self._release()

    def close(self):
        self._release()

    def _release(self):
        with self.db._lock:
            for jid in self._locked:
                self.db._row_locks.discard(jid)
        self._locked.clear()


class _Cursor:
    def __init__(self, conn: _Conn):
        self.conn = conn
        self.db = conn.db
        self._result = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        s = " ".join(sql.lower().split())
        p = tuple(_unwrap_jsonb(v) for v in (params or ()))
        if "app.claim_next_job" in s:
            self._claim(*p)
        elif "app.start_job" in s:
            self._start(*p)
        elif "app.heartbeat_job" in s:
            self._heartbeat(*p)
        elif "app.complete_job" in s:
            self._complete(*p)
        elif "app.fail_job" in s:
            self._fail(*p)
        elif "app.cancel_job" in s:
            self._cancel(*p)
        elif "app.expire_stale_jobs" in s:
            self._expire()
        elif "app.record_job_step" in s:
            self._record_step(*p)
        elif "app.append_job_log" in s:
            self._append_log(*p)
        elif "app.worker_heartbeat" in s:
            self._worker_heartbeat(*p)
        else:
            raise AssertionError(f"unexpected SQL: {s}")

    def fetchone(self):
        return self._result

    # -- RPC implementations (mirror the SQL) ------------------------------

    def _claim(self, worker_id, lease_seconds, job_types):
        with self.db._lock:
            candidates = [
                j for j in self.db.jobs
                if j.status == "queued"
                and (not job_types or j.job_type in job_types)
                and j.id not in self.db._row_locks  # SKIP LOCKED
            ]
            candidates.sort(key=lambda j: (j.priority, j.created_at))
            if not candidates:
                self._result = (None,)
                return
            job = candidates[0]
            # FOR UPDATE: take the row lock for this transaction.
            self.db._row_locks.add(job.id)
            self.conn._locked.add(job.id)
            job.status = "claimed"
            job.worker_id = worker_id
            job.lease_expires_at = self.db.now() + max(1, lease_seconds or 300)
            job.attempts += 1
        self._result = (job.as_row(),)

    def _start(self, job_id, worker_id, lease_seconds):
        job = self.db.get(job_id)
        ok = (job and job.worker_id == worker_id
              and job.status in ("claimed", "running"))
        if ok:
            job.status = "running"
            job.lease_expires_at = self.db.now() + max(1, lease_seconds or 300)
        self._result = (bool(ok),)

    def _heartbeat(self, job_id, worker_id, lease_seconds):
        job = self.db.get(job_id)
        ok = (job and job.worker_id == worker_id
              and job.status in ("claimed", "running"))
        if ok:
            job.lease_expires_at = self.db.now() + max(1, lease_seconds or 300)
        self._result = (bool(ok),)

    def _complete(self, job_id, worker_id, result_public, provenance_id):
        job = self.db.get(job_id)
        ok = (job and job.worker_id == worker_id
              and job.status in ("claimed", "running"))
        if ok:
            job.status = "succeeded"
            job.result_public = result_public if isinstance(result_public, dict) else {}
            job.provenance_id = provenance_id or job.provenance_id
            job.worker_id = None
            job.lease_expires_at = None
            job.error_summary = None
        self._result = (bool(ok),)

    def _fail(self, job_id, worker_id, summary, force_terminal):
        job = self.db.get(job_id)
        if not (job and job.worker_id == worker_id
                and job.status in ("claimed", "running")):
            self._result = (None,)
            return
        if force_terminal or job.attempts >= job.max_attempts:
            job.status = "failed"
        else:
            job.status = "queued"
        job.worker_id = None
        job.lease_expires_at = None
        job.error_summary = summary
        self._result = (job.status,)

    def _cancel(self, job_id, reason):
        job = self.db.get(job_id)
        ok = job and job.status in ("queued", "claimed", "running")
        if ok:
            job.status = "cancelled"
            job.worker_id = None
            job.lease_expires_at = None
            job.error_summary = reason or job.error_summary
        self._result = (bool(ok),)

    def _expire(self):
        count = 0
        now = self.db.now()
        for job in self.db.jobs:
            if (job.status in ("claimed", "running")
                    and job.lease_expires_at is not None
                    and job.lease_expires_at < now):
                if job.attempts >= job.max_attempts:
                    job.status = "expired"
                    job.error_summary = job.error_summary or "lease expired: max attempts reached"
                else:
                    job.status = "queued"
                job.worker_id = None
                job.lease_expires_at = None
                count += 1
        self._result = (count,)

    def _record_step(self, job_id, step_index, name, status, detail):
        existing = next(
            (st for st in self.db.steps
             if st["job_id"] == job_id and st["step_index"] == step_index),
            None,
        )
        if existing:
            existing.update(name=name, status=status, detail=detail)
            self._result = (existing["id"],)
            return
        sid = f"step-{len(self.db.steps) + 1}"
        self.db.steps.append({
            "id": sid, "job_id": job_id, "step_index": step_index,
            "name": name, "status": status, "detail": detail,
        })
        self._result = (sid,)

    def _append_log(self, job_id, message, level, step_id):
        lid = f"log-{len(self.db.logs) + 1}"
        self.db.logs.append({
            "id": lid, "job_id": job_id, "message": message,
            "level": level, "step_id": step_id,
        })
        self._result = (lid,)

    def _worker_heartbeat(self, worker_id, status, current_job_id, detail):
        self.db.heartbeats[worker_id] = {
            "status": status, "current_job_id": current_job_id, "detail": detail,
        }
        self._result = (None,)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def db():
    _Job._seq = 0
    return FakeJobDB()


def _worker(db, handlers, **kw):
    return JobWorker(
        db.connect,
        handlers,
        sleep=lambda _s: None,
        poll_interval=0,
        **kw,
    )


# --------------------------------------------------------------------------
# Basic lifecycle
# --------------------------------------------------------------------------


def test_claim_and_complete_happy_path(db):
    job = db.enqueue(_Job("ingest", case_id="case-1", evidence_id="ev-1",
                          spec_internal={"resolved_hint": "x"}))
    seen = {}

    def handler(claimed: ClaimedJob, ctx: JobContext) -> JobResult:
        seen["case_id"] = claimed.case_id
        seen["evidence_id"] = claimed.evidence_id
        seen["spec_internal"] = claimed.spec_internal
        ctx.record_step(0, "parse", status="running")
        ctx.log("parsing evidence")
        ctx.record_step(0, "parse", status="succeeded")
        return JobResult(result_public={"docs": 42}, provenance_id="prov-1")

    w = _worker(db, {"ingest": handler})
    ran = w.run_once()

    assert ran is not None and ran.job_id == job.id
    assert job.status == "succeeded"
    assert job.result_public == {"docs": 42}
    assert job.provenance_id == "prov-1"
    assert job.worker_id is None and job.lease_expires_at is None
    # Worker received opaque IDs only.
    assert seen["case_id"] == "case-1"
    assert seen["evidence_id"] == "ev-1"
    assert seen["spec_internal"] == {"resolved_hint": "x"}
    # Steps + logs persisted.
    assert any(s["name"] == "parse" and s["status"] == "succeeded" for s in db.steps)
    assert any(l["message"] == "parsing evidence" for l in db.logs)


def test_run_once_returns_none_when_empty(db):
    w = _worker(db, {"ingest": lambda j, c: JobResult()})
    assert w.run_once() is None


def test_unknown_job_type_in_handlers_rejected(db):
    with pytest.raises(ValueError):
        _worker(db, {"bogus": lambda j, c: JobResult()})


# --------------------------------------------------------------------------
# Concurrency: SKIP LOCKED prevents double-claim
# --------------------------------------------------------------------------


def test_two_workers_cannot_claim_same_job(db):
    db.enqueue(_Job("ingest"))  # exactly one job

    w1 = _worker(db, {"ingest": lambda j, c: JobResult()}, worker_id="w1")
    w2 = _worker(db, {"ingest": lambda j, c: JobResult()}, worker_id="w2")

    c1 = w1.claim_one()
    c2 = w2.claim_one()  # w1's claim already committed -> job no longer queued

    claimed = [c for c in (c1, c2) if c is not None]
    assert len(claimed) == 1, "exactly one worker may claim the single job"


def test_concurrent_claims_under_active_lock_are_disjoint(db):
    # Two queued jobs, two workers claiming simultaneously while each holds its
    # FOR UPDATE lock (uncommitted). SKIP LOCKED must hand them different rows.
    db.enqueue(_Job("ingest"))
    db.enqueue(_Job("ingest"))

    results: dict[str, str] = {}
    barrier = threading.Barrier(2)

    def claim(worker_id):
        conn = db.connect()
        cur = conn.cursor()
        barrier.wait()  # ensure both hold no lock yet, then race the claim
        cur.execute(
            "select * from app.claim_next_job(%s, %s, %s)",
            (worker_id, 300, None),
        )
        row = cur.fetchone()[0]
        # Do NOT commit yet: hold the FOR UPDATE lock so the peer must SKIP it.
        time.sleep(0.05)
        results[worker_id] = row[0] if row else None
        conn.commit()

    t1 = threading.Thread(target=claim, args=("w1",))
    t2 = threading.Thread(target=claim, args=("w2",))
    t1.start(); t2.start()
    t1.join(); t2.join()

    ids = [v for v in results.values() if v]
    assert len(ids) == 2, "both workers should claim a job (two queued)"
    assert ids[0] != ids[1], "workers must not share the same job id"


def test_claim_respects_job_type_filter(db):
    db.enqueue(_Job("report"))
    w = _worker(db, {"ingest": lambda j, c: JobResult()})
    assert w.claim_one(job_types=["ingest"]) is None
    assert w.claim_one(job_types=["report"]) is not None


# --------------------------------------------------------------------------
# Failure, retry, and lease expiry
# --------------------------------------------------------------------------


def test_recoverable_failure_requeues_until_max_attempts(db):
    job = db.enqueue(_Job("enrich", max_attempts=2))

    def handler(j, c):
        raise JobError("transient boom")

    w = _worker(db, {"enrich": handler})

    w.run_once()  # attempt 1 -> requeued
    assert job.status == "queued"
    assert job.attempts == 1

    w.run_once()  # attempt 2 -> terminal failed (attempts == max_attempts)
    assert job.status == "failed"
    assert job.attempts == 2
    assert "boom" in (job.error_summary or "")


def test_fatal_failure_is_terminal_immediately(db):
    job = db.enqueue(_Job("enrich", max_attempts=5))

    def handler(j, c):
        raise FatalJobError("cannot recover")

    w = _worker(db, {"enrich": handler})
    w.run_once()
    assert job.status == "failed"
    assert job.attempts == 1  # no retries despite max_attempts=5


def test_unexpected_exception_is_caught_and_failed(db):
    job = db.enqueue(_Job("enrich", max_attempts=1))

    def handler(j, c):
        raise RuntimeError("/cases/secret/path blew up")

    w = _worker(db, {"enrich": handler})
    w.run_once()
    assert job.status == "failed"
    # Sanitized: no absolute path leaks into the agent-visible error summary.
    assert "/cases/secret" not in (job.error_summary or "")


def test_lease_expiry_requeues_then_expires(db):
    clock = {"t": 1000.0}
    db._now = lambda: clock["t"]
    job = db.enqueue(_Job("ingest", max_attempts=2))

    w = JobWorker(db.connect, {"ingest": lambda j, c: JobResult()},
                  worker_id="w1", lease_seconds=10, sleep=lambda _s: None)

    # Claim but simulate the worker dying before completion.
    claimed = w.claim_one()
    assert claimed is not None and job.status == "claimed"
    assert job.attempts == 1

    # Lease not yet expired -> nothing reclaimed.
    clock["t"] = 1005.0
    assert w.expire_stale_jobs() == 0
    assert job.status == "claimed"

    # Past the lease -> re-queued (attempts < max_attempts).
    clock["t"] = 1020.0
    assert w.expire_stale_jobs() == 1
    assert job.status == "queued"

    # Re-claim (attempt 2) and die again; now expiry is terminal.
    w.claim_one()
    assert job.attempts == 2
    clock["t"] = 2000.0
    assert w.expire_stale_jobs() == 1
    assert job.status == "expired"
    assert "max attempts" in (job.error_summary or "")


def test_heartbeat_extends_lease(db):
    clock = {"t": 500.0}
    db._now = lambda: clock["t"]
    job = db.enqueue(_Job("ingest"))

    w = JobWorker(db.connect, {"ingest": lambda j, c: JobResult()},
                  worker_id="w1", lease_seconds=10, sleep=lambda _s: None)
    claimed = w.claim_one()
    first_deadline = job.lease_expires_at

    clock["t"] = 505.0
    assert w._heartbeat(claimed) is True
    assert job.lease_expires_at > first_deadline


# --------------------------------------------------------------------------
# Worker heartbeat registry
# --------------------------------------------------------------------------


def test_worker_heartbeat_tracks_busy_then_idle(db):
    db.enqueue(_Job("ingest"))
    w = _worker(db, {"ingest": lambda j, c: JobResult()}, worker_id="hb1")
    w.run_once()
    hb = db.heartbeats.get("hb1")
    assert hb is not None
    # After completion the worker reports idle.
    assert hb["status"] == "idle"


def test_run_forever_stops_after_max_iterations(db):
    db.enqueue(_Job("ingest"))
    db.enqueue(_Job("ingest"))
    w = _worker(db, {"ingest": lambda j, c: JobResult()})
    handled = w.run_forever(max_iterations=5)
    assert handled == 2  # two jobs, then idle polls until iteration cap


# --------------------------------------------------------------------------
# Sanitizer
# --------------------------------------------------------------------------


@pytest.mark.parametrize("raw,expected_absent", [
    ("failed reading /cases/case-x/evidence/disk.E01", "/cases/case-x"),
    ("/mnt/evidence/secret leaked", "/mnt/evidence"),
])
def test_sanitize_scrubs_absolute_paths(raw, expected_absent):
    assert expected_absent not in _sanitize(raw)


def test_sanitize_keeps_plain_text():
    assert _sanitize("parsed 42 events") == "parsed 42 events"
