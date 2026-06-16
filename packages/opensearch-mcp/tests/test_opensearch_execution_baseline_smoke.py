"""JOB-0 baseline execution smoke tests for current OpenSearch MCP behavior."""

from __future__ import annotations

import json
import importlib.metadata
from unittest.mock import MagicMock, patch

_metadata_version = importlib.metadata.version


def _version_with_source_tree_fallback(distribution_name: str) -> str:
    if distribution_name == "opensearch-mcp":
        return "0.6.1"
    return _metadata_version(distribution_name)


importlib.metadata.version = _version_with_source_tree_fallback

from opensearch_mcp.ingest_status import write_status
from opensearch_mcp.parse_json import ingest_json
from opensearch_mcp.paths import build_index_name


def test_opensearch_index_name_and_provenance_contract(tmp_path):
    """Capture current index naming and JSON parser action provenance without OpenSearch."""
    json_path = tmp_path / "mini_records.jsonl"
    json_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-06-07T09:30:00Z",
                "Hostname": "Admin 01.Example",
                "event.action": "baseline",
            }
        )
        + "\n"
    )
    index_name = build_index_name("INC 2026/Alpha", "JSON Logs", "HOST 01.EXAMPLE!")

    captured_first: list[dict] = []
    captured_second: list[dict] = []

    def capture_first(_client, actions):
        captured_first.extend(actions)
        return len(actions), 0

    def capture_second(_client, actions):
        captured_second.extend(actions)
        return len(actions), 0

    with patch("opensearch_mcp.parse_json.flush_bulk", side_effect=capture_first):
        result = ingest_json(
            path=json_path,
            client=MagicMock(),
            index_name=index_name,
            hostname="fallback-host",
            source_file=str(json_path),
            ingest_audit_id="audit-001",
            pipeline_version="job0-baseline",
        )
    with patch("opensearch_mcp.parse_json.flush_bulk", side_effect=capture_second):
        ingest_json(
            path=json_path,
            client=MagicMock(),
            index_name=index_name,
            hostname="fallback-host",
            source_file=str(json_path),
            ingest_audit_id="audit-001",
            pipeline_version="job0-baseline",
        )

    assert index_name == "case-inc-2026-alpha-json-logs-host-01.example-"
    assert result == (1, 0, 0, 0)
    assert len(captured_first) == 1
    assert captured_first[0]["_index"] == index_name
    assert captured_first[0]["_id"] == captured_second[0]["_id"]

    source = captured_first[0]["_source"]
    assert source["@timestamp"] == "2026-06-07T09:30:00Z"
    assert source["host.name"] == "Admin 01.Example"
    assert source["host.id"] == "Admin 01.Example"
    assert source["sift.parse_method"] == "json-ingest"
    assert source["sift.source_file"] == str(json_path)
    assert source["sift.ingest_audit_id"] == "audit-001"
    assert source["pipeline_version"] == "job0-baseline"


def test_ingest_status_metadata_shape_uses_temp_status_dir(tmp_path, monkeypatch):
    """Write current file-backed ingest status into a temp status directory."""
    status_dir = tmp_path / ".sift" / "ingest-status"
    monkeypatch.setattr("opensearch_mcp.ingest_status._STATUS_DIR", status_dir)

    write_status(
        case_id="INC/2026/JOB0",
        pid=4242,
        run_id="run-job0",
        status="running",
        hosts=[
            {
                "hostname": "HOST1",
                "artifacts": [{"name": "json", "status": "running", "indexed": 1}],
            }
        ],
        totals={"indexed": 1, "skipped": 0, "bulk_failed": 0},
        started="2026-06-07T09:00:00Z",
        log_file=str(tmp_path / "ingest.log"),
        source_path=str(tmp_path / "mini_records.jsonl"),
    )

    status_files = list(status_dir.glob("*.json"))
    assert [p.name for p in status_files] == ["INC_2026_JOB0-4242.json"]
    data = json.loads(status_files[0].read_text())
    assert data["run_id"] == "run-job0"
    assert data["pid"] == 4242
    assert data["status"] == "running"
    assert data["case_id"] == "INC/2026/JOB0"
    assert data["started"] == "2026-06-07T09:00:00Z"
    assert data["hosts"][0]["hostname"] == "HOST1"
    assert data["totals"] == {"indexed": 1, "skipped": 0, "bulk_failed": 0}
    assert data["log_file"].endswith("ingest.log")
    assert data["source_path"].endswith("mini_records.jsonl")
    assert list(status_dir.glob("*.tmp")) == []
