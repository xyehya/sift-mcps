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


def test_ingest_handler_accepts_single_jsonl_file_without_path_leak(tmp_path):
    evidence_file = tmp_path / "events.jsonl"
    evidence_file.write_text(
        '{"timestamp":"2026-06-08T18:20:00Z","event":"suspicious","host":"HOST01"}\n',
        encoding="utf-8",
    )
    job = _claimed_job(evidence_file)
    ctx = _fake_ctx(job)
    captured_actions = []

    def _bulk(_client, actions, **_kwargs):
        captured_actions.extend(actions)
        return len(actions), []

    with patch("opensearch_mcp.ingest.discover", side_effect=AssertionError("no dir walk")), \
         patch("opensearch_mcp.client.get_client", return_value=MagicMock()), \
         patch("opensearch_mcp.bulk.helpers.bulk", side_effect=_bulk):
        result = job_ingest.ingest_job_handler(job, ctx)

    rp = result.result_public
    assert rp["indexed"] == 1
    assert rp["bulk_failed"] == 0
    assert rp["hosts"][0]["hostname"] == "HOST01"
    assert rp["hosts"][0]["artifacts"][0]["artifact"] == "json"
    assert rp["hosts"][0]["artifacts"][0]["index"].startswith(
        "case-11111111-1111-1111-1111-111111111111-json-events-host01"
    )

    blob = repr(rp)
    assert str(evidence_file) not in blob
    assert "source_file" not in blob

    assert len(captured_actions) == 1
    source = captured_actions[0]["_source"]
    assert source["vhir.case_id"] == job.case_id
    assert source["vhir.evidence_id"] == job.evidence_id
    assert source["vhir.job_id"] == job.job_id
    assert source["vhir.provenance_id"] == result.provenance_id
    assert "vhir.source_file" not in source


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


# ---------------------------------------------------------------------------
# Forensic image ingest (AUT2-B1)
# ---------------------------------------------------------------------------

_IMG_NOISE = bytes(range(0, 32)) * 8  # 256 bytes, no printable runs


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("disk.e01", "forensic_image"),
        ("disk.Ex01", "forensic_image"),
        ("disk.RAW", "forensic_image"),
        ("disk.dd", "forensic_image"),
        ("disk.img", "forensic_image"),
        ("disk.vmdk", "forensic_image"),
        ("disk.vhdx", "forensic_image"),
        ("events.jsonl", "json"),
        ("plain.log", None),
    ],
)
def test_single_file_kind_detects_forensic_images(name, expected):
    assert job_ingest._single_file_kind(Path(name)) == expected


def _write_raw_image(path: Path) -> tuple[bytes, bytes]:
    ascii_payload = b"malicious-c2.example.net"
    utf16_payload = "powershell -enc SQBFAFgA".encode("utf-16-le")
    path.write_bytes(_IMG_NOISE + ascii_payload + _IMG_NOISE + utf16_payload + _IMG_NOISE)
    return ascii_payload, utf16_payload


def _run_image_job(job, ctx):
    captured_actions = []

    def _bulk(_client, actions, **_kwargs):
        captured_actions.extend(actions)
        return len(actions), []

    with patch("opensearch_mcp.ingest.discover", side_effect=AssertionError("no dir walk")), \
         patch("opensearch_mcp.client.get_client", return_value=MagicMock()), \
         patch("opensearch_mcp.bulk.helpers.bulk", side_effect=_bulk):
        result = job_ingest.ingest_job_handler(job, ctx)
    return result, captured_actions


def test_ingest_handler_indexes_strings_from_raw_image(tmp_path):
    evidence_file = tmp_path / "Workstation01.raw"
    _write_raw_image(evidence_file)
    job = _claimed_job(evidence_file)
    job.spec_internal["sha256"] = "ab" * 32
    ctx = _fake_ctx(job)

    result, captured_actions = _run_image_job(job, ctx)

    rp = result.result_public
    image = rp["image"]
    assert image["kind"] == "forensic_image"
    assert image["evidence_file"] == "Workstation01.raw"
    assert image["strings_indexed"] == 2
    assert image["bytes_scanned"] == evidence_file.stat().st_size
    assert image["truncated"] is False
    assert image["size_bytes"] == evidence_file.stat().st_size
    assert image["sha256"] == "ab" * 32
    assert image["index"].startswith(
        "case-11111111-1111-1111-1111-111111111111-imgstrings-workstation01"
    )
    assert rp["indexed"] == 2
    assert rp["hosts"][0]["artifacts"][0]["artifact"] == "image_strings"

    # Agent-visible result carries the display name only — never a path.
    blob = repr(rp)
    assert str(tmp_path) not in blob

    texts = {a["_source"]["text"] for a in captured_actions}
    assert texts == {"malicious-c2.example.net", "powershell -enc SQBFAFgA"}
    encodings = {a["_source"]["encoding"] for a in captured_actions}
    assert encodings == {"ascii", "utf-16le"}
    for action in captured_actions:
        src = action["_source"]
        assert src["source"] == "image_strings"
        assert src["evidence_file"] == "Workstation01.raw"
        assert isinstance(src["offset"], int)
        assert src["job_id"] == job.job_id
        # Job provenance is stamped through the shared bulk path.
        assert src["vhir.case_id"] == job.case_id
        assert src["vhir.provenance_id"] == result.provenance_id
        assert str(tmp_path) not in repr(src)


def test_ingest_handler_image_max_strings_cap_truncates(tmp_path):
    evidence_file = tmp_path / "disk.dd"
    parts = [b"string-number-%03d" % i for i in range(20)]
    evidence_file.write_bytes(b"\xff\xfe".join(parts))
    job = _claimed_job(evidence_file)
    job.spec_public["max_strings"] = 5
    ctx = _fake_ctx(job)

    result, captured_actions = _run_image_job(job, ctx)

    image = result.result_public["image"]
    assert image["strings_indexed"] == 5
    assert image["truncated"] is True
    assert len(captured_actions) == 5


def test_ingest_handler_e01_without_pyewf_falls_back_with_warning(tmp_path):
    import sys

    evidence_file = tmp_path / "laptop.E01"
    _write_raw_image(evidence_file)
    job = _claimed_job(evidence_file)
    ctx = _fake_ctx(job)

    # Force `import pyewf` to fail regardless of the local environment.
    with patch.dict(sys.modules, {"pyewf": None}):
        result, captured_actions = _run_image_job(job, ctx)

    image = result.result_public["image"]
    assert image["warnings"] == ["ewf_compressed_read"]
    # Raw-byte fallback still indexes the strings instead of failing the job.
    assert image["strings_indexed"] == 2
    assert len(captured_actions) == 2
    assert str(tmp_path) not in repr(result.result_public)


def test_ingest_handler_unsupported_single_file_message_has_no_path(tmp_path):
    evidence_file = tmp_path / "plain.log"
    evidence_file.write_text("not json\n", encoding="utf-8")
    job = _claimed_job(evidence_file)
    ctx = _fake_ctx(job)
    with pytest.raises(FatalJobError) as exc:
        job_ingest.ingest_job_handler(job, ctx)
    assert "unsupported single-file evidence format" in str(exc.value)
    assert str(evidence_file) not in str(exc.value)


def test_handler_registers_with_jobworker_as_ingest_type():
    """The handler is accepted by JobWorker under job_type='ingest'."""
    worker = JobWorker(
        connection_factory=lambda: MagicMock(),
        handlers={"ingest": job_ingest.ingest_job_handler},
        worker_id="w1",
    )
    assert "ingest" in worker._handlers


# ---------------------------------------------------------------------------
# BATCH-OS4: sealed-evidence ingest + DB provenance + no-leak assertions
# ---------------------------------------------------------------------------


def test_ingest_job_indexes_and_writes_db_provenance(tmp_path):
    """(OS4-a) The job handler BOTH indexes documents AND calls the Postgres
    provenance recorder.  Both actions are required: only-index without DB
    registration is a security gap (no audit trail for the derived plane)."""
    evidence_file = tmp_path / "events.jsonl"
    evidence_file.write_text(
        '{"timestamp":"2026-06-10T10:00:00Z","event":"login","host":"DC01"}\n',
        encoding="utf-8",
    )
    job = _claimed_job(evidence_file)
    ctx = _fake_ctx(job)
    provenance_calls: list[dict] = []

    def _recorder(**kwargs):
        provenance_calls.append(kwargs)

    handler = job_ingest.make_ingest_job_handler(provenance_recorder=_recorder)
    captured_actions: list[dict] = []

    def _bulk(_client, actions, **_kwargs):
        captured_actions.extend(actions)
        return len(actions), []

    with patch("opensearch_mcp.ingest.discover", side_effect=AssertionError("no dir")), \
         patch("opensearch_mcp.client.get_client", return_value=MagicMock()), \
         patch("opensearch_mcp.bulk.helpers.bulk", side_effect=_bulk):
        result = handler(job, ctx)

    # (a-i) documents were indexed
    assert len(captured_actions) == 1
    source = captured_actions[0]["_source"]
    assert source["event"] == "login"
    # (a-ii) provenance fields stamped on the indexed doc
    assert source["vhir.case_id"] == job.case_id
    assert source["vhir.evidence_id"] == job.evidence_id
    assert "vhir.provenance_id" in source
    assert source["vhir.job_id"] == job.job_id
    # (a-iii) DB provenance recorder was called exactly once
    assert len(provenance_calls) == 1
    rec = provenance_calls[0]
    assert rec["case_id"] == job.case_id
    assert rec["evidence_id"] == job.evidence_id
    assert rec["job_id"] == job.job_id
    assert rec["indexed"] == 1
    assert rec["bulk_failed"] == 0


def test_ingest_job_result_public_carries_no_absolute_paths_or_credentials(tmp_path):
    """(OS4-b) The agent-visible JobResult.result_public must contain no absolute
    paths, no OpenSearch credentials, no DB DSNs, no worker file paths, and no
    volume roots.  Only counts, sanitized index names, and opaque IDs may appear."""
    evidence_file = tmp_path / "ingest-data.jsonl"
    evidence_file.write_text(
        '{"timestamp":"2026-06-10T10:05:00Z","event":"logon","host":"WS01"}\n',
        encoding="utf-8",
    )
    job = _claimed_job(evidence_file)
    ctx = _fake_ctx(job)

    def _bulk(_client, actions, **_kwargs):
        return len(actions), []

    with patch("opensearch_mcp.ingest.discover", side_effect=AssertionError("no dir")), \
         patch("opensearch_mcp.client.get_client", return_value=MagicMock()), \
         patch("opensearch_mcp.bulk.helpers.bulk", side_effect=_bulk):
        result = job_ingest.ingest_job_handler(job, ctx)

    blob = repr(result.result_public)
    # No absolute paths of any kind
    assert str(tmp_path) not in blob
    assert str(evidence_file) not in blob
    assert "/home/" not in blob
    assert "/cases/" not in blob
    assert "/mnt/" not in blob
    # No credential-like patterns
    assert "password" not in blob.lower()
    assert "postgresql://" not in blob
    assert "opensearch" not in blob.lower() or "index" in blob.lower()  # index names ok
    # Sanitized index name (case-scoped, derived) is present
    assert "case-11111111" in blob
    # No source_file, volume_root paths in public result
    assert "source_file" not in blob
    assert "volume_root" not in blob


def test_ingest_job_directory_result_carries_no_absolute_paths(tmp_path):
    """(OS4-b extended) For directory-based ingest (the common case), the
    volume_root from IngestResult is not leaked into result_public."""
    job = _claimed_job(tmp_path)
    ctx = _fake_ctx(job)

    result_with_path = _ingest_result()  # contains volume_root="/should/not/leak"

    with patch.object(job_ingest, "_resolve_evidence_path", return_value=tmp_path), \
         patch("opensearch_mcp.ingest.discover", return_value=[object()]), \
         patch("opensearch_mcp.ingest.ingest", return_value=result_with_path), \
         patch("opensearch_mcp.client.get_client", return_value=MagicMock()):
        result = job_ingest.ingest_job_handler(job, ctx)

    blob = repr(result.result_public)
    assert "/should/not/leak" not in blob
    assert str(tmp_path) not in blob


def test_make_ingest_job_handler_without_provenance_recorder_still_indexes(tmp_path):
    """(OS4-a variant) When no provenance recorder is injected (e.g. legacy /
    unit-test mode), the handler still indexes documents — the DB registration
    step is skipped but ingest succeeds.  This keeps the package free of a
    hard psycopg dependency."""
    evidence_file = tmp_path / "nosql.jsonl"
    evidence_file.write_text(
        '{"timestamp":"2026-06-10T10:10:00Z","event":"reboot","host":"SRV01"}\n',
        encoding="utf-8",
    )
    job = _claimed_job(evidence_file)
    ctx = _fake_ctx(job)

    # No provenance_recorder injected
    handler = job_ingest.make_ingest_job_handler(provenance_recorder=None)
    captured_actions: list[dict] = []

    def _bulk(_client, actions, **_kwargs):
        captured_actions.extend(actions)
        return len(actions), []

    with patch("opensearch_mcp.ingest.discover", side_effect=AssertionError("no dir")), \
         patch("opensearch_mcp.client.get_client", return_value=MagicMock()), \
         patch("opensearch_mcp.bulk.helpers.bulk", side_effect=_bulk):
        result = handler(job, ctx)

    # Documents still indexed
    assert result.result_public["indexed"] == 1
    assert len(captured_actions) == 1


def test_psycopg_provenance_recorder_writes_index_and_provenance_rpcs():
    """(OS4-a, Postgres path) psycopg_provenance_recorder executes the correct
    RPCs: app.register_opensearch_index (one per artifact) and
    app.record_opensearch_ingest_provenance (one per run).  Uses a mock
    connection factory to avoid a live DB requirement."""
    from opensearch_mcp.job_ingest import psycopg_provenance_recorder

    executed: list[tuple] = []

    class _MockCursor:
        def execute(self, sql, params):
            executed.append((sql.strip(), params))
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass

    class _MockConn:
        def cursor(self):
            return _MockCursor()
        def commit(self):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass

    recorder = None

    # Patch psycopg.connect to return our mock.
    with patch("psycopg.connect", return_value=_MockConn()):
        recorder = psycopg_provenance_recorder("postgresql://mock/db")
        recorder(
            case_id="case-aaa",
            evidence_id="ev-bbb",
            job_id="job-ccc",
            provenance_id="prov-ddd",
            pipeline_version="opensearch-mcp-9.9.9",
            indexed=5,
            bulk_failed=0,
            hosts=[
                {
                    "hostname": "HOST01",
                    "artifacts": [
                        {"artifact": "evtx", "index": "case-aaa-evtx-host01", "indexed": 5},
                    ],
                }
            ],
        )

    # register_opensearch_index called for each artifact
    register_calls = [sql for sql, _ in executed if "register_opensearch_index" in sql]
    assert len(register_calls) == 1
    # record_opensearch_ingest_provenance called once
    prov_calls = [sql for sql, _ in executed if "record_opensearch_ingest_provenance" in sql]
    assert len(prov_calls) == 1

    # No DSN, path, or secret exposed in the executed SQL params
    for sql, params in executed:
        params_str = str(params)
        assert "postgresql://" not in params_str
        assert "/home/" not in params_str
        assert "/cases/" not in params_str
