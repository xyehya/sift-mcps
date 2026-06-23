"""feat/opensearch-workers: tests for the decoupled ingest/enrich job handlers.

These drive the REAL ``JobWorker`` claim loop (reusing the faithful in-memory
``FakeJobDB`` from sift-core's worker tests, which models ``claim_next_job`` /
``record_job_step`` / ``complete_job`` / ``fail_job`` exactly) through
``opensearch_ingest_job_handler``. The opensearch entry point and ``ingest_status``
read are monkeypatched so no real OpenSearch / FUSE mount is needed — the unit
under test is the handler's case-dir resolution, progress mirroring, terminal
handling, and path-free output, plus N-worker lane-scoped claim safety.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from sift_core.execute.job_worker import JobWorker

# Reuse the faithful fake DB from sift-core's worker test module.
_CORE_TEST = (
    Path(__file__).resolve().parents[2]
    / "sift-core"
    / "tests"
    / "test_job_worker.py"
)
_spec = importlib.util.spec_from_file_location("_sift_core_worker_test", _CORE_TEST)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["_sift_core_worker_test"] = _mod
_spec.loader.exec_module(_mod)
FakeJobDB = _mod.FakeJobDB
_Job = _mod._Job

from opensearch_mcp import ingest_job  # noqa: E402


@pytest.fixture
def db():
    _Job._seq = 0
    return FakeJobDB()


def _worker(db, handlers, **kw):
    return JobWorker(db.connect, handlers, sleep=lambda _s: None, poll_interval=0, **kw)


def _enqueue_ingest(db, *, case_dir="/cases/case-1", case_key="case-1", path="evidence/x.e01"):
    return db.enqueue(
        _Job(
            "ingest",
            case_id="uuid-1",
            spec_public={"path": path, "format": "auto", "force": True},
            spec_internal={"case_dir": case_dir, "case_key": case_key, "examiner": "agent"},
        )
    )


# ---------------------------------------------------------------------------
# case-dir resolution + spawn invocation
# ---------------------------------------------------------------------------


def test_handler_passes_db_case_dir_to_entrypoint_and_blocks_until_complete(db, monkeypatch):
    job = _enqueue_ingest(db, case_dir="/cases/case-rocba", path="evidence/disk.e01")
    seen = {}

    def fake_ingest(**kwargs):
        seen.update(kwargs)
        return {"status": "started", "run_id": "run-1", "pid": 4242}

    # ingest_status: first poll running, second poll terminal complete.
    polls = iter(
        [
            [{"run_id": "run-1", "status": "running",
              "totals": {"indexed": 100, "artifacts_complete": 1, "artifacts_total": 5,
                         "hosts_complete": 0, "hosts_total": 1}, "hosts": []}],
            [{"run_id": "run-1", "status": "complete",
              "totals": {"indexed": 1800, "artifacts_complete": 5, "artifacts_total": 5,
                         "hosts_complete": 1, "hosts_total": 1},
              "hosts": [{"hostname": "hayabusa",
                         "artifacts": [{"name": "hayabusa-detection", "indexed": 37}]}]}],
        ]
    )

    monkeypatch.setattr("opensearch_mcp.server.opensearch_ingest", fake_ingest, raising=False)
    monkeypatch.setattr(
        "opensearch_mcp.ingest_status.read_active_ingests",
        lambda: next(polls, []),
        raising=False,
    )
    monkeypatch.setattr(ingest_job, "_POLL_SECONDS", 0)

    w = _worker(db, {"ingest": ingest_job.opensearch_ingest_job_handler}, worker_id="osw-ingest-1")
    ran = w.run_once(job_types=["ingest"])

    assert ran is not None and ran.job_id == job.id
    assert job.status == "succeeded"
    # The DB-authoritative case_dir from spec_internal reached the entry point.
    assert seen["case_dir"] == "/cases/case-rocba"
    assert seen["dry_run"] is False
    assert seen["path"] == "evidence/disk.e01"
    # Terminal result is path-free and carries the indexed + hayabusa counts.
    rp = job.result_public
    assert rp["status"] == "complete"
    assert rp["indexed_docs"] == 1800
    assert rp["hayabusa_alerts"] == 37
    assert rp["hosts_complete"] == 1


def test_dsn_and_case_uuid_bound_into_subprocess_env_then_restored(db, monkeypatch):
    """B-D1 worker side: the gateway-injected control_plane_dsn (in spec_internal)
    and the case UUID (job.case_id) are exported into the env for the duration of
    the launch — so the spawned ingest_cli child inherits them and can
    forward-write provenance — and the worker's own env is restored afterward
    (mirrors the SIFT_CASE_DIR save/finally-restore discipline)."""
    import os

    job = db.enqueue(
        _Job(
            "ingest",
            case_id="uuid-rocba-2",
            spec_public={"path": "evidence/x.e01", "format": "auto", "force": True},
            spec_internal={
                "case_dir": "/cases/case-rocba",
                "case_key": "case-rocba",
                "examiner": "agent",
                "control_plane_dsn": "postgresql://svc:pw@db:5432/sift",
            },
        )
    )

    captured = {}

    def fake_ingest(**kwargs):
        # Snapshot the env exactly as the spawned child would inherit it.
        captured["dsn"] = os.environ.get("SIFT_CONTROL_PLANE_DSN")
        captured["case_uuid"] = os.environ.get("SIFT_CASE_UUID")
        captured["case_dir"] = os.environ.get("SIFT_CASE_DIR")
        return {"status": "started", "run_id": "run-1", "pid": 1}

    monkeypatch.setattr("opensearch_mcp.server.opensearch_ingest", fake_ingest, raising=False)
    monkeypatch.setattr(
        "opensearch_mcp.ingest_status.read_active_ingests",
        lambda: [{"run_id": "run-1", "status": "complete",
                  "totals": {"indexed": 1}, "hosts": []}],
        raising=False,
    )
    monkeypatch.setattr(ingest_job, "_POLL_SECONDS", 0)

    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    monkeypatch.delenv("SIFT_CASE_UUID", raising=False)

    w = _worker(db, {"ingest": ingest_job.opensearch_ingest_job_handler}, worker_id="osw-1")
    w.run_once(job_types=["ingest"])

    # During the launch the child saw both the DSN and the case UUID.
    assert captured["dsn"] == "postgresql://svc:pw@db:5432/sift"
    assert captured["case_uuid"] == "uuid-rocba-2"
    assert captured["case_dir"] == "/cases/case-rocba"
    # After the launch the worker's own env is clean again (no leak between jobs).
    assert os.environ.get("SIFT_CONTROL_PLANE_DSN") is None
    assert os.environ.get("SIFT_CASE_UUID") is None
    assert job.status == "succeeded"


def test_progress_mirrored_into_job_steps_with_worker_label(db, monkeypatch):
    _enqueue_ingest(db)
    polls = iter(
        [
            [{"run_id": "run-1", "status": "running",
              "totals": {"indexed": 50, "artifacts_complete": 1, "artifacts_total": 4,
                         "hosts_complete": 0, "hosts_total": 1}, "hosts": []}],
            [{"run_id": "run-1", "status": "complete",
              "totals": {"indexed": 900, "artifacts_complete": 4, "artifacts_total": 4,
                         "hosts_complete": 1, "hosts_total": 1}, "hosts": []}],
        ]
    )
    monkeypatch.setattr(
        "opensearch_mcp.server.opensearch_ingest",
        lambda **kw: {"status": "started", "run_id": "run-1"},
        raising=False,
    )
    monkeypatch.setattr(
        "opensearch_mcp.ingest_status.read_active_ingests",
        lambda: next(polls, []),
        raising=False,
    )
    monkeypatch.setattr(ingest_job, "_POLL_SECONDS", 0)

    w = _worker(db, {"ingest": ingest_job.opensearch_ingest_job_handler}, worker_id="osw-ingest-7")
    w.run_once(job_types=["ingest"])

    progress = [s for s in db.steps if s["name"] == "ingest:progress"]
    assert progress, "a progress step must be recorded"
    # The worker_label rides every progress step (realtime N-way visibility).
    assert all(s["detail"].get("worker") == "osw-ingest-7" for s in progress)
    # Step 1 is upserted in place (one row), terminal status succeeded.
    assert {s["step_index"] for s in progress} == {1}
    assert progress[-1]["status"] == "succeeded"
    # Detail is path-free counts only.
    serialized = repr(db.steps)
    assert "/cases/" not in serialized


def test_immediate_already_indexed_fails_job_path_free(db, monkeypatch):
    _enqueue_ingest(db)
    monkeypatch.setattr(
        "opensearch_mcp.server.opensearch_ingest",
        lambda **kw: {
            "status": "already_indexed",
            "message": "case already has 1,234 docs at /cases/case-1/index",
            "doc_count": 1234,
        },
        raising=False,
    )
    monkeypatch.setattr("opensearch_mcp.ingest_status.read_active_ingests", lambda: [], raising=False)

    w = _worker(db, {"ingest": ingest_job.opensearch_ingest_job_handler})
    job = db.jobs[0]
    w.run_once(job_types=["ingest"])

    assert job.status == "failed"
    # No retry on a deterministic refusal; absolute path scrubbed from the step.
    assert "/cases/" not in repr(db.steps)


def test_terminal_failure_fails_the_job(db, monkeypatch):
    _enqueue_ingest(db)
    polls = iter(
        [
            [{"run_id": "run-1", "status": "failed", "totals": {},
              "error": "fusermount: Operation not permitted at /cases/x", "hosts": []}],
        ]
    )
    monkeypatch.setattr(
        "opensearch_mcp.server.opensearch_ingest",
        lambda **kw: {"status": "started", "run_id": "run-1"},
        raising=False,
    )
    monkeypatch.setattr(
        "opensearch_mcp.ingest_status.read_active_ingests",
        lambda: next(polls, []),
        raising=False,
    )
    monkeypatch.setattr(ingest_job, "_POLL_SECONDS", 0)

    w = _worker(db, {"ingest": ingest_job.opensearch_ingest_job_handler})
    job = db.jobs[0]
    w.run_once(job_types=["ingest"])

    assert job.status == "failed"
    assert "/cases/" not in (job.error_summary or "")


def test_multi_container_terminal_only_when_all_runs_done(db, monkeypatch):
    _enqueue_ingest(db, path="evidence/")
    monkeypatch.setattr(
        "opensearch_mcp.server.opensearch_ingest",
        lambda **kw: {
            "status": "multi_started",
            "containers": [{"run_id": "run-a"}, {"run_id": "run-b"}],
        },
        raising=False,
    )
    # run-a completes first; run-b still running, then both complete.
    polls = iter(
        [
            [{"run_id": "run-a", "status": "complete",
              "totals": {"indexed": 10, "hosts_complete": 1, "hosts_total": 1,
                         "artifacts_complete": 1, "artifacts_total": 1}, "hosts": []},
             {"run_id": "run-b", "status": "running",
              "totals": {"indexed": 3, "hosts_complete": 0, "hosts_total": 1,
                         "artifacts_complete": 0, "artifacts_total": 2}, "hosts": []}],
            [{"run_id": "run-a", "status": "complete",
              "totals": {"indexed": 10, "hosts_complete": 1, "hosts_total": 1,
                         "artifacts_complete": 1, "artifacts_total": 1}, "hosts": []},
             {"run_id": "run-b", "status": "complete",
              "totals": {"indexed": 20, "hosts_complete": 1, "hosts_total": 1,
                         "artifacts_complete": 2, "artifacts_total": 2}, "hosts": []}],
        ]
    )
    monkeypatch.setattr(
        "opensearch_mcp.ingest_status.read_active_ingests",
        lambda: next(polls, []),
        raising=False,
    )
    monkeypatch.setattr(ingest_job, "_POLL_SECONDS", 0)

    w = _worker(db, {"ingest": ingest_job.opensearch_ingest_job_handler})
    job = db.jobs[0]
    w.run_once(job_types=["ingest"])

    assert job.status == "succeeded"
    # Summed across both containers (10 + 20).
    assert job.result_public["indexed_docs"] == 30
    assert job.result_public["hosts_complete"] == 2


# ---------------------------------------------------------------------------
# N-worker, lane-scoped claim safety (FOR UPDATE SKIP LOCKED + job_types)
# ---------------------------------------------------------------------------


def test_n_opensearch_workers_claim_distinct_ingest_jobs(db, monkeypatch):
    # Three ingest jobs, three opensearch workers — each claims a distinct one.
    for _ in range(3):
        _enqueue_ingest(db)
    monkeypatch.setattr(
        "opensearch_mcp.server.opensearch_ingest",
        lambda **kw: {"status": "started", "run_id": "r"},
        raising=False,
    )
    monkeypatch.setattr(
        "opensearch_mcp.ingest_status.read_active_ingests",
        lambda: [{"run_id": "r", "status": "complete", "totals": {"indexed": 1}, "hosts": []}],
        raising=False,
    )
    monkeypatch.setattr(ingest_job, "_POLL_SECONDS", 0)

    claimed_ids = []
    for wid in ("osw-1", "osw-2", "osw-3"):
        w = _worker(db, {"ingest": ingest_job.opensearch_ingest_job_handler}, worker_id=wid)
        ran = w.run_once(job_types=["ingest"])
        assert ran is not None
        claimed_ids.append(ran.job_id)

    assert len(set(claimed_ids)) == 3, "each worker must claim a distinct job (SKIP LOCKED)"
    assert all(j.status == "succeeded" for j in db.jobs)


def test_opensearch_worker_does_not_claim_run_command(db):
    # A run_command job must be invisible to an ingest,enrich-lane worker.
    rc = db.enqueue(_Job("run_command"))
    w = _worker(db, {"ingest": ingest_job.opensearch_ingest_job_handler})
    assert w.claim_one(job_types=["ingest", "enrich"]) is None
    assert rc.status == "queued"
