"""BATCH-F1: DB-job-driven ingest adapter + provenance stamping tests.

Covers:
- bulk.set_ingest_provenance stamps opaque IDs onto every doc and drops
  non-allow-listed/path-like keys;
- the ingest job handler resolves the evidence path from the worker-only
  spec_internal (never spec_public), stamps case/evidence/provenance/job IDs,
  records sanitized index/provenance metadata, and never leaks paths/credentials
  into the agent-visible JobResult;
- a missing/unavailable evidence source fails terminally without a path in the
  error summary.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import bulk
from opensearch_mcp import job_ingest
from opensearch_mcp.results import ArtifactResult, HostResult, IngestResult

from sift_core.execute.job_worker import (
    ClaimedJob,
    FatalJobError,
    JobContext,
    JobResult,
    JobWorker,
)


# ---------------------------------------------------------------------------
# Provenance context stamping (bulk.py)
# ---------------------------------------------------------------------------


def test_set_ingest_provenance_stamps_allowed_ids_only():
    actions = [
        {"_index": "case-c1-evtx-h1", "_id": "a", "_source": {"event.code": 4624}},
        {"_index": "case-c1-evtx-h1", "_id": "b", "_source": {"event.code": 4625}},
    ]
    token = bulk.set_ingest_provenance(
        {
            "vhir.case_id": "case-c1",
            "vhir.evidence_id": "ev-1",
            "vhir.provenance_id": "prov-1",
            "vhir.job_id": "job-1",
            # not allow-listed — must be dropped
            "vhir.source_path": "/cases/case-c1/evidence/x.evtx",
            "evil": "/mnt/evidence",
        }
    )
    try:
        bulk._stamp_provenance(actions)
    finally:
        bulk.reset_ingest_provenance(token)

    for action in actions:
        src = action["_source"]
        assert src["vhir.case_id"] == "case-c1"
        assert src["vhir.evidence_id"] == "ev-1"
        assert src["vhir.provenance_id"] == "prov-1"
        assert src["vhir.job_id"] == "job-1"
        assert "vhir.source_path" not in src
        assert "evil" not in src


def test_stamp_provenance_noop_without_scope():
    actions = [{"_index": "i", "_id": "a", "_source": {"x": 1}}]
    bulk._stamp_provenance(actions)  # no active scope
    assert actions[0]["_source"] == {"x": 1}


def test_stamp_provenance_does_not_overwrite_parser_fields():
    actions = [{"_index": "i", "_id": "a", "_source": {"vhir.case_id": "parser-set"}}]
    token = bulk.set_ingest_provenance({"vhir.case_id": "job-set"})
    try:
        bulk._stamp_provenance(actions)
    finally:
        bulk.reset_ingest_provenance(token)
    assert actions[0]["_source"]["vhir.case_id"] == "parser-set"


# ---------------------------------------------------------------------------
# Job ingest handler
# ---------------------------------------------------------------------------


def _claimed_job(tmp_path: Path, *, case_id="11111111-1111-1111-1111-111111111111",
                 evidence_id="22222222-2222-2222-2222-222222222222") -> ClaimedJob:
    return ClaimedJob(
        job_id="job-abc",
        job_type="ingest",
        case_id=case_id,
        evidence_id=evidence_id,
        # spec_public is agent-visible: NO path here.
        spec_public={"hostname": "HOST01"},
        # spec_internal is worker-only: the resolved evidence path lives here.
        spec_internal={"evidence_path": str(tmp_path)},
        attempts=1,
        max_attempts=3,
        worker_id="worker-1",
    )


def _fake_ctx(job: ClaimedJob) -> JobContext:
    worker = MagicMock()
    worker._record_step = MagicMock(return_value="step-id")
    worker._append_log = MagicMock(return_value="log-id")
    worker._heartbeat = MagicMock(return_value=True)
    return JobContext(worker, job)


def _ingest_result() -> IngestResult:
    res = IngestResult(pipeline_version="opensearch-mcp-9.9.9")
    host = HostResult(hostname="HOST01", volume_root="/should/not/leak")
    host.artifacts.append(
        ArtifactResult(artifact="evtx", index="case-c1-evtx-host01", indexed=42, bulk_failed=1)
    )
    res.hosts.append(host)
    return res


def test_ingest_handler_runs_stack_and_returns_sanitized_result(tmp_path):
    job = _claimed_job(tmp_path)
    ctx = _fake_ctx(job)
    recorded = {}

    def _recorder(**kwargs):
        recorded.update(kwargs)

    handler = job_ingest.make_ingest_job_handler(provenance_recorder=_recorder)

    with patch.object(job_ingest, "_resolve_evidence_path", return_value=tmp_path), \
         patch("opensearch_mcp.ingest.discover", return_value=[object()]) as mock_disc, \
         patch("opensearch_mcp.ingest.ingest", return_value=_ingest_result()) as mock_ing, \
         patch("opensearch_mcp.client.get_client", return_value=MagicMock()):
        result = handler(job, ctx)

    assert isinstance(result, JobResult)
    rp = result.result_public
    assert rp["indexed"] == 42
    assert rp["bulk_failed"] == 1
    assert rp["provenance_id"] == result.provenance_id
    # index names are case-scoped derived identifiers (agent-safe)
    assert rp["hosts"][0]["artifacts"][0]["index"] == "case-c1-evtx-host01"

    # No path/credential leakage anywhere in the agent-visible result.
    blob = repr(rp)
    assert "/should/not/leak" not in blob
    assert str(tmp_path) not in blob
    assert "volume_root" not in blob
    assert "source_file" not in blob

    # Provenance recorded into Postgres-shaped recorder call.
    assert recorded["case_id"] == job.case_id
    assert recorded["evidence_id"] == job.evidence_id
    assert recorded["job_id"] == job.job_id
    assert recorded["indexed"] == 42
    assert recorded["pipeline_version"] == "opensearch-mcp-9.9.9"

    # The ingest stack was driven with the resolved case id.
    assert mock_disc.called
    assert mock_ing.call_args.kwargs["case_id"] == job.case_id


def test_ingest_handler_stamps_provenance_during_ingest(tmp_path):
    """The provenance context must be active for the duration of the ingest call."""
    job = _claimed_job(tmp_path)
    ctx = _fake_ctx(job)
    captured = {}

    def _fake_ingest(**kwargs):
        # bulk's context var should be set while ingest runs.
        prov = bulk._provenance_ctx.get()
        captured["prov"] = dict(prov) if prov else None
        return _ingest_result()

    with patch.object(job_ingest, "_resolve_evidence_path", return_value=tmp_path), \
         patch("opensearch_mcp.ingest.discover", return_value=[object()]), \
         patch("opensearch_mcp.ingest.ingest", side_effect=_fake_ingest), \
         patch("opensearch_mcp.client.get_client", return_value=MagicMock()):
        job_ingest.ingest_job_handler(job, ctx)

    assert captured["prov"]["vhir.case_id"] == job.case_id
    assert captured["prov"]["vhir.evidence_id"] == job.evidence_id
    assert "vhir.provenance_id" in captured["prov"]
    assert captured["prov"]["vhir.job_id"] == job.job_id
    # Scope is cleared after the handler returns.
    assert bulk._provenance_ctx.get() is None


def test_ingest_handler_missing_evidence_path_fails_terminally_without_path(tmp_path):
    job = ClaimedJob(
        job_id="job-x",
        job_type="ingest",
        case_id="11111111-1111-1111-1111-111111111111",
        evidence_id=None,
        spec_public={"hostname": "HOST01"},
        spec_internal={},  # no evidence path
        attempts=1,
        max_attempts=3,
        worker_id="worker-1",
    )
    ctx = _fake_ctx(job)
    with pytest.raises(FatalJobError) as exc:
        job_ingest.ingest_job_handler(job, ctx)
    # Sanitized message: no path text.
    assert "/" not in str(exc.value)


def test_ingest_handler_unavailable_source_path_message_has_no_path(tmp_path):
    missing = tmp_path / "does-not-exist"
    job = _claimed_job(tmp_path)
    job.spec_internal["evidence_path"] = str(missing)
    ctx = _fake_ctx(job)
    with pytest.raises(FatalJobError) as exc:
        job_ingest.ingest_job_handler(job, ctx)
    assert str(missing) not in str(exc.value)


def test_handler_registers_with_jobworker_as_ingest_type():
    """The handler is accepted by JobWorker under job_type='ingest'."""
    worker = JobWorker(
        connection_factory=lambda: MagicMock(),
        handlers={"ingest": job_ingest.ingest_job_handler},
        worker_id="w1",
    )
    assert "ingest" in worker._handlers
