"""OSW RUN-1 targeted tests for B3 (ingest_status K4-preserving redirect) and B4 (memory lane).

B3 (K4-preserving): opensearch_ingest_status in DB-active mode must NOT read
    local ingest-status mirror files (BATCH-K4 locked contract — tamper vector).
    It must return ingests=[] + authority="postgres-durable-jobs" + a redirect
    pointer to job_status(job_id) for the authoritative app.job_status_public
    record. The get-mirror-and-label-it-supplemental approach is rejected: serving
    any local mirror content in DB-active mode reopens the K4 spoof vector.

B4: idx_ingest_memory must expose run_id in its response so the durable
    ingest_job handler can track the memory-ingest subprocess via
    _run_ids() -> _mirror_until_terminal, giving memory ingest full parity
    with the disk lane (realtime worker_label, current_step, parallel claim).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import opensearch_mcp.server as srv
from opensearch_mcp.server import opensearch_ingest_status

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_CASE_ID = "case-rocba-test"
_RUNNING_MIRROR = [
    {
        "run_id": "run-mem-1",
        "case_id": _CASE_ID,
        "status": "running",
        "pid": 9999,
        "elapsed_seconds": 45.0,
        "totals": {
            "indexed": 12000,
            "artifacts_complete": 3,
            "artifacts_total": 11,
            "hosts_complete": 0,
            "hosts_total": 1,
        },
        "hosts": [
            {
                "hostname": "srl-forge",
                "artifacts": [
                    {"name": "vol-pslist", "status": "complete", "indexed": 120},
                    {"name": "vol-netscan", "status": "running", "indexed": 0},
                ],
            }
        ],
        "bulk_failed": 0,
        "bulk_failed_reason": "",
        "log_file": "/tmp/fake.log",
    }
]

_COMPLETE_MIRROR = [
    {
        "run_id": "run-disk-1",
        "case_id": _CASE_ID,
        "status": "complete",
        "pid": 8888,
        "elapsed_seconds": 180.0,
        "totals": {
            "indexed": 18500,
            "artifacts_complete": 14,
            "artifacts_total": 14,
            "hosts_complete": 1,
            "hosts_total": 1,
        },
        "hosts": [
            {
                "hostname": "srl-forge",
                "artifacts": [
                    {"name": "evtx", "status": "complete", "indexed": 12440},
                    {"name": "registry", "status": "complete", "indexed": 7278},
                ],
            }
        ],
        "bulk_failed": 0,
        "bulk_failed_reason": "",
        "log_file": "/tmp/fake2.log",
    }
]


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.cluster.health.return_value = {"status": "green"}
    with patch("opensearch_mcp.server.get_client", return_value=client):
        yield client


@pytest.fixture(autouse=True)
def _reset_server_state():
    old_client = srv._client
    old_verified = srv._client_verified
    srv._client = None
    srv._client_verified = False
    yield
    srv._client = old_client
    srv._client_verified = old_verified


# ---------------------------------------------------------------------------
# B3 — opensearch_ingest_status in DB-active mode
# ---------------------------------------------------------------------------


class TestB3IngestStatusDBActive:
    """B3 (K4-preserving): ingest_status in DB-active mode must NOT read local
    mirror files and must always return ingests=[] + authority redirect."""

    def _active_case(self, monkeypatch):
        monkeypatch.setattr(srv, "_get_active_case", lambda: _CASE_ID)

    def test_db_active_always_returns_empty_ingests_no_mirror_read(self, monkeypatch):
        """Even when mirror files exist, DB-active mode must NOT read them.
        K4 locked contract: local files are tamperable; ingests=[] always."""
        self._active_case(monkeypatch)
        read_called = []
        with (
            patch("opensearch_mcp.ingest_status.db_status_active", return_value=True),
            patch(
                "opensearch_mcp.ingest_status.read_active_ingests",
                side_effect=lambda: read_called.append(1) or _RUNNING_MIRROR,
            ),
        ):
            resp = opensearch_ingest_status()

        # Must not surface mirror content.
        assert resp["ingests"] == []
        # Local files must not have been consulted.
        assert read_called == [], "read_active_ingests must NOT be called in DB-active mode"
        # Authority pointer must be present.
        assert resp.get("authority") == "postgres-durable-jobs"
        # M-JOBSTATUS-NAME fix: message must reference running_commands_status, not job_status.
        msg = resp.get("message", "")
        assert "running_commands_status" in msg, f"Message must reference running_commands_status: {msg!r}"
        assert "job_status" not in msg or "running_commands_status" in msg, (
            "Message must not reference the nonexistent job_status tool"
        )
        # Tamper values from _RUNNING_MIRROR must not appear.
        assert "srl-forge" not in repr(resp)
        assert "12000" not in repr(resp)

    def test_no_mirror_data_returns_redirect_with_job_id(self, monkeypatch):
        """When job_id is supplied, include it in the redirect for direct linkage."""
        self._active_case(monkeypatch)
        with patch("opensearch_mcp.ingest_status.db_status_active", return_value=True):
            resp = opensearch_ingest_status(job_id="abc-job-1")

        assert resp["ingests"] == []
        assert resp.get("authority") == "postgres-durable-jobs"
        assert resp.get("job_id") == "abc-job-1"
        assert "next_step" in resp
        assert "abc-job-1" in resp["next_step"]
        # M-JOBSTATUS-NAME: next_step must use running_commands_status not job_status.
        assert "running_commands_status" in resp["next_step"], (
            f"next_step must reference running_commands_status: {resp['next_step']!r}"
        )

    def test_no_job_id_returns_redirect_without_job_id_key(self, monkeypatch):
        """Without a job_id argument, redirect has no job_id key."""
        self._active_case(monkeypatch)
        with patch("opensearch_mcp.ingest_status.db_status_active", return_value=True):
            resp = opensearch_ingest_status()

        assert resp["ingests"] == []
        assert resp.get("authority") == "postgres-durable-jobs"
        assert "job_id" not in resp

    def test_complete_mirror_not_surfaced_in_db_active_mode(self, monkeypatch):
        """Completed mirror file content must not appear in DB-active response."""
        self._active_case(monkeypatch)
        with (
            patch("opensearch_mcp.ingest_status.db_status_active", return_value=True),
            patch(
                "opensearch_mcp.ingest_status.read_active_ingests",
                return_value=_COMPLETE_MIRROR,
            ),
        ):
            resp = opensearch_ingest_status()

        # Still empty — complete mirror must not be served.
        assert resp["ingests"] == []
        assert resp.get("authority") == "postgres-durable-jobs"
        assert "18500" not in repr(resp)

    def test_job_id_in_redirect_when_supplied_with_mirror_present(self, monkeypatch):
        """job_id in redirect even when (ignored) mirror files exist."""
        self._active_case(monkeypatch)
        with (
            patch("opensearch_mcp.ingest_status.db_status_active", return_value=True),
            patch(
                "opensearch_mcp.ingest_status.read_active_ingests",
                return_value=_RUNNING_MIRROR,
            ),
        ):
            resp = opensearch_ingest_status(job_id="xyz-job-99")

        assert resp.get("job_id") == "xyz-job-99"
        assert "xyz-job-99" in resp.get("next_step", "")
        # Mirror content must still be absent.
        assert resp["ingests"] == []

    def test_db_active_ignores_mirror_regardless_of_active_case(self, monkeypatch):
        """K4 applies globally: mirror is ignored even on active case."""
        monkeypatch.setattr(srv, "_get_active_case", lambda: "other-case")
        with (
            patch("opensearch_mcp.ingest_status.db_status_active", return_value=True),
            patch(
                "opensearch_mcp.ingest_status.read_active_ingests",
                return_value=_RUNNING_MIRROR,
            ),
        ):
            resp = opensearch_ingest_status()

        assert resp["ingests"] == []
        assert resp.get("authority") == "postgres-durable-jobs"

    def test_m_ingstatus_backend_always_returns_empty_ingests_in_db_active(self, monkeypatch):
        """M-INGSTATUS: in DB-active mode the BACKEND always returns ingests=[].

        The gateway's OpenSearchIngestStatusAugmentMiddleware (policy_middleware.py)
        populates ingests[] using its own DSN. The backend has no DB credentials by
        design. This test pins that the backend envelope is stable and never changes
        from the expected ingests=[]+authority+message shape — the gateway augments on
        top of this exact envelope.
        """
        self._active_case(monkeypatch)

        with (
            patch("opensearch_mcp.ingest_status.db_status_active", return_value=True),
            patch(
                "opensearch_mcp.ingest_status.read_active_ingests",
                return_value=[],  # K4: mirror must not be consulted
            ),
        ):
            resp = opensearch_ingest_status()

        # Backend always returns ingests=[] — gateway augments on top.
        assert resp["ingests"] == [], (
            "Backend must always return ingests=[] in DB-active mode — "
            "the gateway's augment middleware populates it"
        )
        assert resp.get("authority") == "postgres-durable-jobs"
        # Message must reference running_commands_status (not job_status).
        msg = resp.get("message", "")
        assert "running_commands_status" in msg, (
            f"Backend message must name running_commands_status: {msg!r}"
        )

    def test_m_ingstatus_backend_has_no_job_status_lister(self, monkeypatch):
        """M-INGSTATUS: the backend server module must NOT have a _JOB_STATUS_LISTER
        attribute. Population is the gateway's responsibility, not the backend's.

        Regression guard: the old injected-lister approach was inert (the subprocess
        never received the injection) and has been removed. Ensure it doesn't return.
        """
        assert not hasattr(srv, "_JOB_STATUS_LISTER"), (
            "_JOB_STATUS_LISTER must be removed from the backend — "
            "population is now the gateway's OpenSearchIngestStatusAugmentMiddleware"
        )
        assert not hasattr(srv, "set_job_status_lister"), (
            "set_job_status_lister must be removed from the backend — "
            "population is now the gateway's OpenSearchIngestStatusAugmentMiddleware"
        )


class TestB3IngestStatusNonDBActive:
    """Regression: in non-DB-active mode opensearch_ingest_status works as before."""

    def test_returns_ingests_without_authority_note(self, monkeypatch):
        monkeypatch.setattr(srv, "_get_active_case", lambda: _CASE_ID)
        with (
            patch("opensearch_mcp.ingest_status.db_status_active", return_value=False),
            patch(
                "opensearch_mcp.ingest_status.read_active_ingests",
                return_value=_RUNNING_MIRROR,
            ),
        ):
            resp = opensearch_ingest_status()

        assert len(resp["ingests"]) == 1
        # No authority note in non-DB-active mode.
        assert "authority" not in resp

    def test_empty_returns_no_active_ingests_message(self, monkeypatch):
        monkeypatch.setattr(srv, "_get_active_case", lambda: _CASE_ID)
        with (
            patch("opensearch_mcp.ingest_status.db_status_active", return_value=False),
            patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]),
        ):
            resp = opensearch_ingest_status()

        assert resp["ingests"] == []
        assert "No active" in resp["message"]

    def test_existing_test_compatibility(self, mock_client):
        """Existing test: case_id='*' with no status files → empty ingests."""
        with patch(
            "opensearch_mcp.ingest_status.read_active_ingests",
            return_value=[],
        ):
            resp = opensearch_ingest_status(case_id="*")
        assert resp["ingests"] == []
        assert "No active" in resp["message"]


# ---------------------------------------------------------------------------
# B4 — memory ingest run_id parity
# ---------------------------------------------------------------------------


class TestB4MemoryIngestRunId:
    """B4: idx_ingest_memory must expose run_id so the durable ingest_job
    handler can track the memory-lane subprocess via _run_ids()."""

    def _make_evidence(self, tmp_path: Path) -> Path:
        """Create a fake case dir with evidence/ subdir and a .raw file."""
        case_dir = tmp_path / _CASE_ID
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        raw_file = evidence_dir / "test.raw"
        raw_file.write_bytes(b"\x00" * 8)
        return case_dir

    def test_memory_ingest_response_includes_run_id(self, mock_client, monkeypatch, tmp_path):
        case_dir = self._make_evidence(tmp_path)
        # Inject the case dir so _resolve_tool_path resolves under it.
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        monkeypatch.setattr(srv, "_get_active_case", lambda: _CASE_ID)

        fake_proc = MagicMock()
        fake_proc.pid = 55555
        captured_run_id = []

        def _capture_spawn(cmd, env, stdout, run_id):
            captured_run_id.append(run_id)
            return fake_proc

        with (
            patch("opensearch_mcp.server._spawn_ingest", side_effect=_capture_spawn),
            patch("opensearch_mcp.ingest_status.write_status"),
            patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]),
            patch("opensearch_mcp.paths.sift_dir", return_value=tmp_path / ".sift"),
            patch(
                "opensearch_mcp.shard_capacity.check_shard_headroom",
                return_value=(True, "ok"),
            ),
        ):
            from opensearch_mcp.server import idx_ingest_memory

            resp = idx_ingest_memory(
                path="evidence/test.raw",
                hostname="srl-forge",
                tier=1,
                dry_run=False,
            )

        assert "run_id" in resp, "B4: idx_ingest_memory must return run_id"
        assert resp["run_id"] == captured_run_id[0]
        assert resp["status"] == "started"
        assert resp["pid"] == 55555

    def test_memory_ingest_run_id_is_non_empty_string(self, mock_client, monkeypatch, tmp_path):
        case_dir = self._make_evidence(tmp_path)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        monkeypatch.setattr(srv, "_get_active_case", lambda: _CASE_ID)

        fake_proc = MagicMock()
        fake_proc.pid = 66666

        with (
            patch("opensearch_mcp.server._spawn_ingest", return_value=fake_proc),
            patch("opensearch_mcp.ingest_status.write_status"),
            patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]),
            patch("opensearch_mcp.paths.sift_dir", return_value=tmp_path / ".sift"),
            patch(
                "opensearch_mcp.shard_capacity.check_shard_headroom",
                return_value=(True, "ok"),
            ),
        ):
            from opensearch_mcp.server import idx_ingest_memory

            resp = idx_ingest_memory(
                path="evidence/test.raw",
                hostname="srl-forge",
                tier=1,
                dry_run=False,
            )

        assert isinstance(resp.get("run_id"), str) and resp["run_id"], (
            "B4: run_id must be a non-empty string UUID"
        )

    def test_memory_ingest_dry_run_does_not_include_run_id(self, monkeypatch, tmp_path):
        """dry_run=True preview must not carry run_id (no subprocess launched)."""
        case_dir = self._make_evidence(tmp_path)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        monkeypatch.setattr(srv, "_get_active_case", lambda: _CASE_ID)

        from opensearch_mcp.server import idx_ingest_memory

        resp = idx_ingest_memory(
            path="evidence/test.raw",
            hostname="srl-forge",
            tier=1,
            dry_run=True,
        )

        assert resp["status"] == "preview"
        assert "run_id" not in resp


# ---------------------------------------------------------------------------
# B4 — ingest_job handler memory lane parity
# ---------------------------------------------------------------------------

# Reuse the faithful FakeJobDB from sift-core's worker test module.
_CORE_TEST = (
    Path(__file__).resolve().parents[2]
    / "sift-core"
    / "tests"
    / "test_job_worker.py"
)
_spec = importlib.util.spec_from_file_location("_sift_core_worker_test_b4", _CORE_TEST)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["_sift_core_worker_test_b4"] = _mod
_spec.loader.exec_module(_mod)
FakeJobDB = _mod.FakeJobDB
_Job = _mod._Job

from opensearch_mcp import ingest_job  # noqa: E402


@pytest.fixture
def db():
    _Job._seq = 0
    return FakeJobDB()


def _worker(db, handlers, **kw):
    from sift_core.execute.job_worker import JobWorker

    return JobWorker(db.connect, handlers, sleep=lambda _s: None, poll_interval=0, **kw)


def _enqueue_memory_ingest(db, *, case_dir="/cases/case-1", case_key="case-1"):
    return db.enqueue(
        _Job(
            "ingest",
            case_id="uuid-mem-1",
            spec_public={
                "path": "evidence/Rocba-Memory.raw",
                "format": "memory",
                "hostname": "srl-forge",
                "tier": 1,
                "force": False,
            },
            spec_internal={"case_dir": case_dir, "case_key": case_key, "examiner": "agent"},
        )
    )


class TestB4MemoryIngestJobParity:
    """B4: the durable ingest_job handler must block-poll a memory ingest
    run the same way it does a disk ingest — via _run_ids() extracting
    run_id from the idx_ingest_memory response."""

    def test_memory_ingest_job_tracks_run_id_and_reaches_terminal(self, db, monkeypatch):
        """Handler spawns memory ingest, extracts its run_id, mirrors progress,
        and reaches a terminal 'complete' result — same as the disk lane."""
        _enqueue_memory_ingest(db, case_dir="/cases/case-rocba")

        def fake_memory_ingest(**kwargs):
            # B4: must include run_id in the response (the fix).
            return {"status": "started", "run_id": "run-mem-42", "pid": 7777, "tier": 1}

        polls = iter(
            [
                [
                    {
                        "run_id": "run-mem-42",
                        "status": "running",
                        "totals": {
                            "indexed": 3000,
                            "artifacts_complete": 3,
                            "artifacts_total": 11,
                            "hosts_complete": 0,
                            "hosts_total": 1,
                        },
                        "hosts": [],
                    }
                ],
                [
                    {
                        "run_id": "run-mem-42",
                        "status": "complete",
                        "totals": {
                            "indexed": 180892,
                            "artifacts_complete": 11,
                            "artifacts_total": 11,
                            "hosts_complete": 1,
                            "hosts_total": 1,
                        },
                        "hosts": [],
                    }
                ],
            ]
        )

        monkeypatch.setattr(
            "opensearch_mcp.server.opensearch_ingest",
            fake_memory_ingest,
            raising=False,
        )
        monkeypatch.setattr(
            "opensearch_mcp.ingest_status.read_active_ingests",
            lambda: next(polls, []),
            raising=False,
        )
        monkeypatch.setattr(ingest_job, "_POLL_SECONDS", 0)

        w = _worker(db, {"ingest": ingest_job.opensearch_ingest_job_handler}, worker_id="osw-mem-1")
        job = db.jobs[0]
        ran = w.run_once(job_types=["ingest"])

        assert ran is not None, "Worker must claim and run the memory ingest job"
        assert job.status == "succeeded"
        rp = job.result_public
        assert rp["status"] == "complete"
        assert rp["indexed_docs"] == 180892
        assert rp["artifacts_complete"] == 11
        assert rp["hosts_complete"] == 1
