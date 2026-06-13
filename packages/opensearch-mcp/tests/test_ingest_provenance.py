"""wave8/ingest-tools: add-on direct-ingest provenance.

The opensearch-mcp add-on owns the real ingest surface (opensearch_ingest ->
ingest_cli scan) and writes its OWN Postgres provenance receipt — there is no
core ingest gatekeeper. These tests prove the thin provenance writer:

  - builds a sanitized host/index/count summary from an IngestResult (no paths);
  - records the receipt with job_id=None (a direct, non-job ingest);
  - resolves the service DSN from SIFT_CONTROL_PLANE_DSN, and skips silently
    (returning False, never raising) when no DSN is present;
  - never raises when the receipt write fails — the docs are already indexed.
"""

from __future__ import annotations

from opensearch_mcp.ingest_provenance import (
    _summary_hosts_from_result,
    record_direct_ingest_provenance,
)
from opensearch_mcp.results import ArtifactResult, HostResult, IngestResult


def _result_with_two_artifacts() -> IngestResult:
    res = IngestResult(pipeline_version="opensearch-mcp-9.9.9")
    host = HostResult(hostname="HOST01", volume_root="/should/not/leak")
    host.artifacts.append(
        ArtifactResult(
            artifact="evtx",
            index="case-c1-evtx-host01",
            indexed=30,
            bulk_failed=2,
            source_files=["/abs/leak/path.evtx"],
        )
    )
    host.artifacts.append(
        ArtifactResult(artifact="mft", index="case-c1-mft-host01", indexed=10, bulk_failed=0)
    )
    res.hosts.append(host)
    return res


def test_summary_is_path_free_and_aggregates_counts():
    hosts, indexed, bulk_failed = _summary_hosts_from_result(_result_with_two_artifacts())
    assert indexed == 40
    assert bulk_failed == 2
    assert hosts == [
        {
            "hostname": "HOST01",
            "artifacts": [
                {"artifact": "evtx", "index": "case-c1-evtx-host01", "indexed": 30, "bulk_failed": 2},
                {"artifact": "mft", "index": "case-c1-mft-host01", "indexed": 10, "bulk_failed": 0},
            ],
        }
    ]
    # Sanitized: no source-file paths leak into the recorded summary.
    assert "/should/not/leak" not in repr(hosts)
    assert "/abs/leak" not in repr(hosts)


def test_record_calls_recorder_with_job_id_none_and_aggregates():
    captured: dict = {}

    def _recorder(**kwargs):
        captured.update(kwargs)

    ok = record_direct_ingest_provenance(
        case_id="11111111-1111-1111-1111-111111111111",
        provenance_id="22222222-2222-2222-2222-222222222222",
        result=_result_with_two_artifacts(),
        recorder=_recorder,
    )
    assert ok is True
    assert captured["job_id"] is None  # direct ingest — not a durable job
    assert captured["case_id"] == "11111111-1111-1111-1111-111111111111"
    assert captured["provenance_id"] == "22222222-2222-2222-2222-222222222222"
    assert captured["indexed"] == 40
    assert captured["bulk_failed"] == 2
    assert captured["pipeline_version"] == "opensearch-mcp-9.9.9"
    assert captured["hosts"][0]["hostname"] == "HOST01"


def test_record_skips_without_dsn(monkeypatch):
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    ok = record_direct_ingest_provenance(
        case_id="c1",
        provenance_id="p1",
        result=_result_with_two_artifacts(),
    )
    assert ok is False  # no DSN -> skipped, never raised


def test_record_never_raises_on_recorder_failure():
    def _boom(**_kwargs):
        raise RuntimeError("db down: postgresql://secret")

    ok = record_direct_ingest_provenance(
        case_id="c1",
        provenance_id="p1",
        result=_result_with_two_artifacts(),
        recorder=_boom,
    )
    assert ok is False  # failure swallowed: docs already indexed
