"""Tests for server.py MCP tool functions with mocked OpenSearch."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import opensearch_mcp.server as srv
from opensearch_mcp.server import (
    _get_os,
    _os_call,
    _strip_hits,
    idx_aggregate,
    idx_count,
    idx_field_values,
    idx_get_event,
    idx_ingest,
    idx_ingest_status,
    idx_search,
    idx_status,
    idx_timeline,
)


@pytest.fixture(autouse=True)
def _reset_server_state():
    """Reset the module-level client cache before each test."""
    old_client = srv._client
    old_verified = srv._client_verified
    srv._client = None
    srv._client_verified = False
    yield
    srv._client = old_client
    srv._client_verified = old_verified


@pytest.fixture
def mock_client():
    """Provide a mock OpenSearch client and inject it into server module."""
    client = MagicMock()
    client.cluster.health.return_value = {"status": "green"}
    with patch("opensearch_mcp.server.get_client", return_value=client):
        yield client


class TestToolRegistry:
    def test_ingest_format_variants_are_consolidated_under_idx_ingest(self):
        tools = srv.server._tool_manager._tools

        assert "idx_ingest" in tools
        for old_name in (
            "idx_ingest_json",
            "idx_ingest_delimited",
            "idx_ingest_accesslog",
            "idx_ingest_memory",
        ):
            assert old_name not in tools

        schema = tools["idx_ingest"].fn_metadata.arg_model.model_json_schema()
        assert "format" in schema["properties"]

    def test_query_and_status_tools_are_marked_read_only(self):
        read_only_tools = [
            "idx_search",
            "idx_count",
            "idx_aggregate",
            "idx_get_event",
            "idx_timeline",
            "idx_field_values",
            "idx_status",
            "idx_shard_status",
            "idx_case_summary",
            "idx_list_detections",
        ]
        tools = srv.server._tool_manager._tools

        for name in read_only_tools:
            assert getattr(tools[name].annotations, "readOnlyHint", None) is True

    def test_admin_pipeline_install_not_in_public_registry(self):
        """idx_install_pipelines is an internal admin function, not a public MCP tool.

        It was removed from the agent-facing surface during Group 3 consolidation.
        Confirm it is absent from the tool manager so the agent cannot call it.
        """
        tools = srv.server._tool_manager._tools
        assert "idx_install_pipelines" not in tools


# ---------------------------------------------------------------------------
# _get_os
# ---------------------------------------------------------------------------


class TestGetOs:
    def test_raises_runtime_error_when_config_missing(self):
        """_get_os raises RuntimeError when config file not found."""
        with patch(
            "opensearch_mcp.server.get_client",
            side_effect=FileNotFoundError("OpenSearch config not found"),
        ):
            with pytest.raises(RuntimeError, match="config not found"):
                _get_os()

    def test_raises_runtime_error_on_connection_failure(self):
        """_get_os raises RuntimeError when health check fails."""
        mock_client = MagicMock()
        mock_client.cluster.health.side_effect = Exception("Connection refused")
        with patch("opensearch_mcp.server.get_client", return_value=mock_client):
            with pytest.raises(RuntimeError, match="not running"):
                _get_os()

    def test_caches_client_on_second_call(self):
        """_get_os returns cached client on second call (no second get_client)."""
        mock_client = MagicMock()
        mock_client.cluster.health.return_value = {"status": "green"}
        with patch("opensearch_mcp.server.get_client", return_value=mock_client) as mock_gc:
            c1 = _get_os()
            c2 = _get_os()
        assert c1 is c2
        # get_client called only once
        mock_gc.assert_called_once()


# ---------------------------------------------------------------------------
# _os_call
# ---------------------------------------------------------------------------


class TestOsCall:
    def test_resets_cache_on_connection_error(self, mock_client):
        """_os_call resets client cache on ConnectionError."""
        from opensearchpy.exceptions import ConnectionError as OSConnectionError

        # First call succeeds to populate the cache
        _get_os()
        assert srv._client is not None
        assert srv._client_verified is True

        # Now simulate a connection error
        def failing_fn():
            raise OSConnectionError("connection lost")

        with pytest.raises(RuntimeError, match="temporarily lost"):
            _os_call(failing_fn)
        assert srv._client is None
        assert srv._client_verified is False

    def test_passes_through_successful_call(self, mock_client):
        """_os_call passes through the return value on success."""
        _get_os()
        result = _os_call(lambda x: x * 2, 21)
        assert result == 42


# ---------------------------------------------------------------------------
# _strip_hits
# ---------------------------------------------------------------------------


class TestStripHits:
    def test_extracts_source_adds_id_and_index(self):
        hits = [
            {
                "_id": "doc1",
                "_index": "case-test-evtx-host1",
                "_source": {"event.code": 4624, "user.name": "admin"},
            }
        ]
        result = _strip_hits(hits)
        assert len(result) == 1
        assert result[0]["_id"] == "doc1"
        assert result[0]["_index"] == "case-test-evtx-host1"
        assert result[0]["event.code"] == 4624

    def test_empty_hits_returns_empty(self):
        assert _strip_hits([]) == []

    def test_missing_source_returns_id_and_index(self):
        hits = [{"_id": "x", "_index": "idx"}]
        result = _strip_hits(hits)
        assert result[0]["_id"] == "x"
        assert result[0]["_index"] == "idx"


# ---------------------------------------------------------------------------
# idx_search
# ---------------------------------------------------------------------------


class TestIdxSearch:
    def test_returns_total_returned_results(self, mock_client):
        mock_client.search.return_value = {
            "hits": {
                "total": {"value": 2},
                "hits": [
                    {"_id": "1", "_index": "idx", "_source": {"event.code": 4624}},
                    {"_id": "2", "_index": "idx", "_source": {"event.code": 4625}},
                ],
            }
        }
        resp = idx_search(query="event.code:4624")
        assert resp["total"] == 2
        assert resp["returned"] == 2
        assert len(resp["results"]) == 2

    def test_caps_limit_at_200(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
        }
        idx_search(query="*", limit=999)
        call_body = mock_client.search.call_args[1]["body"]
        assert call_body["size"] == 200

    def test_validates_sort_order_invalid_becomes_desc(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
        }
        idx_search(query="*", sort="@timestamp:INVALID")
        call_body = mock_client.search.call_args[1]["body"]
        assert call_body["sort"][0]["@timestamp"]["order"] == "desc"

    def test_audit_id_in_response(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
        }
        with patch.object(srv.audit, "log", return_value="audit-123"):
            resp = idx_search(query="*")
        assert resp["audit_id"] == "audit-123"


# ---------------------------------------------------------------------------
# idx_count
# ---------------------------------------------------------------------------


class TestIdxCount:
    def test_returns_count(self, mock_client):
        mock_client.count.return_value = {"count": 42}
        resp = idx_count(query="*")
        assert resp["count"] == 42

    def test_audit_id_in_response(self, mock_client):
        mock_client.count.return_value = {"count": 0}
        with patch.object(srv.audit, "log", return_value="audit-456"):
            resp = idx_count()
        assert resp["audit_id"] == "audit-456"


# ---------------------------------------------------------------------------
# idx_aggregate
# ---------------------------------------------------------------------------


class TestIdxAggregate:
    def test_returns_field_total_docs_buckets(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 100}},
            "aggregations": {
                "agg": {
                    "buckets": [
                        {"key": "host-a", "doc_count": 60},
                        {"key": "host-b", "doc_count": 40},
                    ]
                }
            },
        }
        resp = idx_aggregate(field="host.name")
        assert resp["field"] == "host.name"
        assert resp["total_docs"] == 100
        assert len(resp["buckets"]) == 2
        assert resp["buckets"][0] == {"key": "host-a", "count": 60}

    def test_caps_limit_at_500(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}},
            "aggregations": {"agg": {"buckets": []}},
        }
        idx_aggregate(field="host.name", limit=9999)
        call_body = mock_client.search.call_args[1]["body"]
        assert call_body["aggs"]["agg"]["terms"]["size"] == 500


# ---------------------------------------------------------------------------
# idx_get_event
# ---------------------------------------------------------------------------


class TestIdxGetEvent:
    def test_returns_document_with_id_and_index(self, mock_client):
        mock_client.get.return_value = {
            "_id": "doc123",
            "_index": "case-test-evtx-host1",
            "_source": {"event.code": 4624, "user.name": "admin"},
        }
        resp = idx_get_event(event_id="doc123", index="case-test-evtx-host1")
        assert resp["_id"] == "doc123"
        assert resp["_index"] == "case-test-evtx-host1"
        assert resp["event.code"] == 4624


# ---------------------------------------------------------------------------
# idx_timeline
# ---------------------------------------------------------------------------


class TestIdxTimeline:
    def test_returns_total_docs_interval_buckets(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 500}},
            "aggregations": {
                "timeline": {
                    "buckets": [
                        {"key_as_string": "2024-01-15T10:00:00Z", "doc_count": 100},
                        {"key_as_string": "2024-01-15T11:00:00Z", "doc_count": 200},
                    ]
                }
            },
        }
        resp = idx_timeline(query="*", interval="1h")
        assert resp["total_docs"] == 500
        assert resp["interval"] == "1h"
        assert len(resp["buckets"]) == 2
        assert resp["buckets"][0] == {"time": "2024-01-15T10:00:00Z", "count": 100}


# ---------------------------------------------------------------------------
# idx_field_values
# ---------------------------------------------------------------------------


class TestIdxFieldValues:
    def test_returns_field_and_values(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 100}},
            "aggregations": {
                "values": {
                    "buckets": [
                        {"key": "Sysmon", "doc_count": 50},
                        {"key": "Security", "doc_count": 30},
                    ]
                }
            },
        }
        resp = idx_field_values(field="winlog.provider_name")
        assert resp["field"] == "winlog.provider_name"
        assert len(resp["values"]) == 2
        assert resp["values"][0] == {"value": "Sysmon", "count": 50, "doc_count": 50}


# ---------------------------------------------------------------------------
# idx_status
# ---------------------------------------------------------------------------


class TestIdxStatus:
    def test_filters_to_case_indices_only(self, mock_client):
        mock_client.cat.indices.return_value = [
            {
                "index": "case-test-evtx-host1",
                "docs.count": "1000",
                "store.size": "5mb",
                "status": "open",
            },
            {"index": ".kibana_1", "docs.count": "10", "store.size": "1mb", "status": "open"},
            {
                "index": "case-inc2-amcache-host2",
                "docs.count": "50",
                "store.size": "100kb",
                "status": "open",
            },
        ]
        mock_client.cluster.health.return_value = {"status": "green"}
        resp = idx_status()
        assert resp["total_indices"] == 2
        index_names = [i["index"] for i in resp["indices"]]
        assert ".kibana_1" not in index_names
        assert "case-test-evtx-host1" in index_names

    def test_includes_cluster_status(self, mock_client):
        mock_client.cat.indices.return_value = []
        mock_client.cluster.health.return_value = {
            "status": "yellow",
            "number_of_nodes": 1,
        }
        resp = idx_status()
        assert "yellow" in resp["cluster_status"]
        assert "single-node" in resp["cluster_status"]

    def test_cluster_status_green_not_annotated(self, mock_client):
        mock_client.cat.indices.return_value = []
        mock_client.cluster.health.return_value = {
            "status": "green",
            "number_of_nodes": 3,
        }
        resp = idx_status()
        assert resp["cluster_status"] == "green"


# ---------------------------------------------------------------------------
# idx_ingest
# ---------------------------------------------------------------------------


class TestIdxIngest:
    def test_rejects_unknown_format(self, mock_client, monkeypatch):
        monkeypatch.setattr(srv, "_get_active_case", lambda: "test-case")
        resp = idx_ingest(path="evidence", format="unknown", dry_run=True)
        assert "error" in resp
        assert "supported_formats" in resp

    def test_routes_json_format_through_idx_ingest(self, mock_client, monkeypatch):
        monkeypatch.setattr(srv, "_get_active_case", lambda: "test-case")
        with patch("opensearch_mcp.server.idx_ingest_json") as handler:
            handler.return_value = {"status": "preview", "format": "jsonl"}
            resp = idx_ingest(
                path="evidence/events.jsonl",
                format="json",
                hostname="HOST1",
                index_suffix="events",
                time_field="@timestamp",
                dry_run=True,
            )
        handler.assert_called_once_with(
            "evidence/events.jsonl",
            "HOST1",
            "events",
            "@timestamp",
            True,
        )
        assert resp["status"] == "preview"

    def test_routes_delimited_format_through_idx_ingest(self, mock_client, monkeypatch):
        monkeypatch.setattr(srv, "_get_active_case", lambda: "test-case")
        with patch("opensearch_mcp.server.idx_ingest_delimited") as handler:
            handler.return_value = {"status": "preview", "format": "csv"}
            resp = idx_ingest(
                path="evidence/csv",
                format="delimited",
                hostname="auto",
                delimiter=",",
                recursive=True,
                dry_run=True,
            )
        handler.assert_called_once_with(
            "evidence/csv",
            hostname="auto",
            index_suffix="",
            time_field="",
            delimiter=",",
            recursive=True,
            dry_run=True,
        )
        assert resp["status"] == "preview"

    def test_routes_memory_format_through_idx_ingest(self, mock_client, monkeypatch):
        monkeypatch.setattr(srv, "_get_active_case", lambda: "test-case")
        with patch("opensearch_mcp.server.idx_ingest_memory") as handler:
            handler.return_value = {"status": "preview", "plugin_count": 2}
            resp = idx_ingest(
                path="evidence/memdump.raw",
                format="memory",
                hostname="HOST1",
                tier=2,
                plugins=["windows.pslist", "windows.netscan"],
                dry_run=True,
            )
        handler.assert_called_once_with(
            "evidence/memdump.raw",
            "HOST1",
            tier=2,
            plugins=["windows.pslist", "windows.netscan"],
            dry_run=True,
        )
        assert resp["status"] == "preview"

    def test_rejects_paths_outside_allowed_locations(self, mock_client):
        """Paths outside the active case are rejected."""
        resp = idx_ingest(path="/etc")
        assert "error" in resp
        assert "No active case" in resp["error"]

    def test_dry_run_returns_preview(self, mock_client, tmp_path, monkeypatch):
        """dry_run=True returns preview with host/artifact discovery."""
        from _helpers import make_windows_tree

        make_windows_tree(tmp_path)

        case_dir = tmp_path / "test-case-20260525-1200"
        case_dir.mkdir()
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir()
        make_windows_tree(evidence_dir)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

        mock_client.count.side_effect = Exception("no index")

        resp = idx_ingest(path="evidence", dry_run=True)
        assert resp.get("status") == "preview"
        assert len(resp.get("hosts", [])) >= 1

    def test_not_a_directory_returns_error(self, mock_client, tmp_path, monkeypatch):
        """Non-directory, non-container path returns error."""
        case_dir = tmp_path / "test-case-20260525-1200"
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        f = evidence_dir / "not_a_dir.txt"
        f.write_text("test")
        resp = idx_ingest(path="not_a_dir.txt")
        assert "error" in resp
        assert "Not a directory or supported container" in resp["error"]

    def test_ingest_status_returns_empty_when_no_status(self, mock_client):
        """idx_ingest_status returns empty when no status files exist."""
        with patch(
            "opensearch_mcp.ingest_status.read_active_ingests",
            return_value=[],
        ):
            resp = idx_ingest_status(case_id="*")
        assert resp["ingests"] == []
        assert "No active" in resp["message"]


# ---------------------------------------------------------------------------
# idx_enrich_intel — async launch (UAT 2026-04-23 B79)
# ---------------------------------------------------------------------------


class TestEnrichIntelAsync:
    """B79: idx_enrich_intel with dry_run=False must return immediately
    with {status: started, pid, run_id, ...} so the gateway's 300s
    synchronous tool timeout cannot kill a real enrichment run. The
    worker runs under systemd-run scope and writes progress to the
    shared ingest-status dir with artifact_name='intel'."""

    def test_dry_run_stays_synchronous(self, mock_client, monkeypatch):
        """dry_run=True must keep the synchronous preview path — operators
        rely on the IOC count for decide-before-run flow."""
        from opensearch_mcp.server import idx_enrich_intel

        monkeypatch.setattr(srv, "_get_active_case", lambda: "TEST-CASE")
        fake_iocs = {
            "ip": {"1.2.3.4", "5.6.7.8"},
            "hash": {"abc", "def", "ghi"},
            "domain": {"evil.example"},
        }
        with patch("opensearch_mcp.threat_intel.extract_unique_iocs", return_value=fake_iocs):
            resp = idx_enrich_intel(dry_run=True)
        assert resp["status"] == "preview"
        assert resp["ips"] == 2
        assert resp["hashes"] == 3
        assert resp["domains"] == 1
        assert resp["total_iocs"] == 6

    def test_execute_launches_background(self, mock_client, monkeypatch, tmp_path):
        """dry_run=False must return {status: started, pid, run_id}
        immediately — does NOT block on enrich_case."""
        from opensearch_mcp.server import idx_enrich_intel

        monkeypatch.setattr(srv, "_get_active_case", lambda: "TEST-CASE")

        fake_proc = MagicMock()
        fake_proc.pid = 54321
        # Run the background helper against mocked _spawn_ingest and
        # write_status so nothing real forks.
        with (
            patch("opensearch_mcp.server._spawn_ingest", return_value=fake_proc),
            patch("opensearch_mcp.ingest_status.write_status"),
            patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]),
            patch("opensearch_mcp.paths.sift_dir", return_value=tmp_path),
        ):
            resp = idx_enrich_intel(dry_run=False)

        assert resp["status"] == "started"
        assert resp["pid"] == 54321
        assert "run_id" in resp
        assert resp["case_id"] == "TEST-CASE"
        # Message points operators at the right status tool.
        assert "idx_ingest_status" in resp["message"]
        assert "intel" in resp["message"]

    def test_execute_respects_explicit_case_arg(self, mock_client, monkeypatch, tmp_path):
        """Explicit case_id must be passed to the worker, not silently
        overridden by the active-case."""
        from opensearch_mcp.server import idx_enrich_intel

        monkeypatch.setattr(srv, "_get_active_case", lambda: "ACTIVE-CASE")

        fake_proc = MagicMock()
        fake_proc.pid = 11111
        captured_cmd = []

        def _capture_spawn(cmd, env, stdout, run_id):
            captured_cmd.extend(cmd)
            return fake_proc

        with (
            patch("opensearch_mcp.server._spawn_ingest", side_effect=_capture_spawn),
            patch("opensearch_mcp.ingest_status.write_status"),
            patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]),
            patch("opensearch_mcp.paths.sift_dir", return_value=tmp_path),
        ):
            resp = idx_enrich_intel(case_id="OVERRIDE-CASE", dry_run=False)

        assert resp["case_id"] == "OVERRIDE-CASE"
        # Worker cmd includes --case OVERRIDE-CASE, not ACTIVE-CASE.
        assert "OVERRIDE-CASE" in captured_cmd
        assert "ACTIVE-CASE" not in captured_cmd

    def test_execute_force_flag_propagated(self, mock_client, monkeypatch, tmp_path):
        """--force flag must reach the worker command line."""
        from opensearch_mcp.server import idx_enrich_intel

        monkeypatch.setattr(srv, "_get_active_case", lambda: "TEST-CASE")

        fake_proc = MagicMock()
        fake_proc.pid = 22222
        captured_cmd = []

        def _capture_spawn(cmd, env, stdout, run_id):
            captured_cmd.extend(cmd)
            return fake_proc

        with (
            patch("opensearch_mcp.server._spawn_ingest", side_effect=_capture_spawn),
            patch("opensearch_mcp.ingest_status.write_status"),
            patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]),
            patch("opensearch_mcp.paths.sift_dir", return_value=tmp_path),
        ):
            idx_enrich_intel(dry_run=False, force=True)

        assert "--force" in captured_cmd

    def test_execute_concurrency_gate_blocks_at_cap(self, mock_client, monkeypatch):
        """Enrichment must respect the same concurrency cap as ingest —
        running 5+ long enrichments simultaneously would starve the
        OpenCTI rate limiter and is a stability hazard."""
        from opensearch_mcp.server import _MAX_CONCURRENT_INGESTS, idx_enrich_intel

        monkeypatch.setattr(srv, "_get_active_case", lambda: "TEST-CASE")
        full_roster = [
            {"status": "running", "case_id": f"C{i}", "pid": 1000 + i}
            for i in range(_MAX_CONCURRENT_INGESTS)
        ]
        with patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=full_roster):
            resp = idx_enrich_intel(dry_run=False)
        assert "error" in resp
        assert "Too many concurrent" in resp["error"]


# ---------------------------------------------------------------------------
# R0-1: _get_active_case — env var first, file fallback
# ---------------------------------------------------------------------------


class TestGetActiveCase:
    def test_env_var_wins(self, tmp_path, monkeypatch):
        """SIFT_CASE_DIR set → returns its basename, lowercased."""
        case_dir = tmp_path / "test-case-20260525-1200"
        case_dir.mkdir()
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        result = srv._get_active_case()
        assert result == "test-case-20260525-1200"

    def test_env_var_lowercases(self, tmp_path, monkeypatch):
        """SIFT_CASE_DIR with uppercase → lowercased for OpenSearch indices."""
        case_dir = tmp_path / "MYCASE-20260525"
        case_dir.mkdir()
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        result = srv._get_active_case()
        assert result == "mycase-20260525"

    def test_fallback_to_file(self, tmp_path, monkeypatch):
        """Env var absent, active_case file present → returns file basename."""
        monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
        fake_home = tmp_path / "home"
        sift_d = fake_home / ".sift"
        sift_d.mkdir(parents=True)
        case_dir = tmp_path / "cases" / "file-case-001"
        case_dir.mkdir(parents=True)
        (sift_d / "active_case").write_text(str(case_dir))
        monkeypatch.setattr("opensearch_mcp.paths.sift_home", lambda: fake_home)
        result = srv._get_active_case()
        assert result == "file-case-001"

    def test_env_var_beats_stale_file(self, tmp_path, monkeypatch):
        """Env var set + stale active_case file → env var wins."""
        env_case = tmp_path / "env-case-20260525-1200"
        env_case.mkdir()
        monkeypatch.setenv("SIFT_CASE_DIR", str(env_case))
        fake_home = tmp_path / "home"
        sift_d = fake_home / ".sift"
        sift_d.mkdir(parents=True)
        stale_dir = tmp_path / "stale-case"
        stale_dir.mkdir()
        (sift_d / "active_case").write_text(str(stale_dir))
        monkeypatch.setattr("opensearch_mcp.paths.sift_home", lambda: fake_home)
        result = srv._get_active_case()
        assert result == "env-case-20260525-1200"

    def test_returns_none_when_neither_set(self, tmp_path, monkeypatch):
        """Both env var absent and no file → None."""
        monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
        fake_home = tmp_path / "home"
        (fake_home / ".sift").mkdir(parents=True)
        monkeypatch.setattr("opensearch_mcp.paths.sift_home", lambda: fake_home)
        result = srv._get_active_case()
        assert result is None


# ---------------------------------------------------------------------------
# R0-2: idx_ingest — uses _get_active_case, not inline active_case read
# ---------------------------------------------------------------------------


class TestIdxIngestActiveCase:
    def test_no_active_case_returns_portal_hint(self, mock_client, monkeypatch):
        """When no active case is set, returns portal_hint (not legacy CLI error)."""
        monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
        fake_home = monkeypatch.monkeypatch if False else None
        # Point sift_dir to empty tmp so file fallback also fails
        monkeypatch.setattr(srv, "_get_active_case", lambda: None)
        # A valid path to satisfy path validation
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            resp = idx_ingest(path=d)
        assert "error" in resp
        assert "portal_hint" in resp
        assert "portal" in resp["portal_hint"].lower()

    def test_active_case_from_env_var(self, mock_client, tmp_path, monkeypatch):
        """SIFT_CASE_DIR env var provides case_id without active_case file."""
        from _helpers import make_windows_tree

        case_dir = tmp_path / "rocba-20260525-1200"
        case_dir.mkdir()
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        # Do NOT create ~/.sift/active_case
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir()
        make_windows_tree(evidence_dir)
        mock_client.count.side_effect = Exception("no index")
        resp = idx_ingest(path="evidence", dry_run=True)
        assert resp.get("status") == "preview"
        assert resp.get("case_id") == "rocba-20260525-1200"


# ---------------------------------------------------------------------------
# R0-3: idx_ingest — directory with containers returns containers_detected
# ---------------------------------------------------------------------------


class TestIdxIngestContainerDetection:
    def test_directory_with_e01_returns_containers_detected(self, mock_client, tmp_path, monkeypatch):
        """Directory containing .e01 file → containers_detected with next_step."""
        case_dir = tmp_path / "test-case-001"
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        e01 = evidence_dir / "rocba-cdrive.e01"
        e01.write_bytes(b"EVF" + b"\x00" * 100)  # minimal EWF magic
        resp = idx_ingest(path="evidence", dry_run=True)
        assert resp.get("status") == "containers_detected"
        assert resp.get("case_id") == "test-case-001"
        assert len(resp.get("containers", [])) >= 1
        assert "next_step" in resp
        assert "idx_ingest" in resp["next_step"]

    def test_directory_empty_returns_error(self, mock_client, tmp_path, monkeypatch):
        """Empty directory → no containers, falls through to original error."""
        case_dir = tmp_path / "test-case-001"
        (case_dir / "evidence").mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        resp = idx_ingest(path="evidence", dry_run=True)
        assert "error" in resp
        assert "containers_detected" != resp.get("status")

    def test_directory_no_containers_preserves_original_error(self, mock_client, tmp_path, monkeypatch):
        """Dir with only non-container files → 'No Windows artifacts found'."""
        case_dir = tmp_path / "test-case-001"
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        (evidence_dir / "notes.txt").write_text("not a container")
        resp = idx_ingest(path="evidence", dry_run=True)
        assert "error" in resp
        assert "No Windows artifacts found" in resp["error"]

    def test_idx_ingest_directory_auto_launches_containers(
        self, mock_client, tmp_path, monkeypatch
    ):
        """dry_run=False on a directory launches each detected container."""
        case_dir = tmp_path / "test-case-001"
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        (evidence_dir / "rocba-cdrive.e01").write_bytes(b"EVF" + b"\x00" * 100)
        (evidence_dir / "memdump.raw").write_bytes(b"\x00" * 100)

        proc1 = MagicMock(pid=101)
        proc2 = MagicMock(pid=102)
        with (
            patch("opensearch_mcp.ingest.discover", return_value=[]),
            patch("opensearch_mcp.shard_capacity.check_shard_headroom", return_value=(True, "ok")),
            patch("opensearch_mcp.server._spawn_ingest", side_effect=[proc1, proc2]) as mock_spawn,
        ):
            resp = idx_ingest(path="evidence", hostname="srl-forge", dry_run=False, force=True)

        assert resp["status"] == "multi_started"
        assert len(resp["containers"]) == 2
        assert mock_spawn.call_count == 2
        spawned_cmds = [call.args[0] for call in mock_spawn.call_args_list]
        assert any("scan" in cmd and "--clean" in cmd for cmd in spawned_cmds)
        assert any("memory" in cmd for cmd in spawned_cmds)
