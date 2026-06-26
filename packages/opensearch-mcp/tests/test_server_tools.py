"""Tests for server.py MCP tool functions with mocked OpenSearch."""

from __future__ import annotations

import asyncio as _asyncio
import json as _json
from pathlib import Path as _Path
from unittest.mock import MagicMock, patch

import pytest
from opensearchpy.exceptions import RequestError as _OSRequestError

import opensearch_mcp.server as _srv_mod
import opensearch_mcp.server as srv
from opensearch_mcp.registry import (
    IngestIn,
    IngestStatusIn,
    SearchIn,
    run_opensearch_ingest_status,
    run_opensearch_search,
)
from opensearch_mcp.server import (
    _get_os,
    _os_call,
    _strip_hits,
    opensearch_aggregate,
    opensearch_count,
    opensearch_field_values,
    opensearch_get_event,
    opensearch_ingest,
    opensearch_ingest_status,
    opensearch_search,
    opensearch_status,
    opensearch_timeline,
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


class TestResolveIndexB1:
    """B1 + XYE-10: default index-pattern resolution must agree with index naming.

    Indices are named ``case-<case_key>-<type>-<host>`` where ``case_key`` is
    the case directory basename — which itself already starts with ``case-``
    (e.g. ``case-rocba-case-06132304``). The indexer normalizes that key so the
    ``case-`` prefix is applied exactly ONCE (XYE-10): the canonical name is
    ``case-rocba-case-06132304-<type>-<host>``, NOT a doubled ``case-case-``
    form. The default query pattern MUST reproduce that single-prefix name, and
    must NOT be built from the opaque DB UUID the Gateway injects.
    """

    def test_case_key_starting_with_case_prefix_is_not_doubled(self, monkeypatch):
        # Active case dir basename already starts with 'case-' (real-world key).
        monkeypatch.setattr(srv, "_get_active_case", lambda: "case-rocba-case-06132304")
        # No explicit index, no explicit case_id -> derive from active case.
        pattern = srv._resolve_index("", "")
        # Single-prefix: the redundant leading 'case-' is stripped from the key
        # before the canonical prefix is applied (XYE-10).
        assert pattern == "case-rocba-case-06132304-*"
        assert "case-case-" not in pattern

    def test_explicit_case_id_with_case_prefix_resolves_correctly(self):
        pattern = srv._resolve_index("", "case-rocba-case-06132304")
        assert pattern == "case-rocba-case-06132304-*"

    def test_uuid_case_id_is_ignored_in_favour_of_active_case(self, monkeypatch):
        # The Gateway injects the opaque DB UUID into case_id; building
        # case-<uuid>-* would match nothing. The active-case dir must win.
        monkeypatch.setattr(srv, "_get_active_case", lambda: "case-rocba-case-06132304")
        uuid = "674425ae-78ea-4c9c-9a14-3c9d0b6f900c"
        pattern = srv._resolve_index("", uuid)
        assert pattern == "case-rocba-case-06132304-*"
        assert uuid not in pattern

    def test_explicit_index_always_wins(self):
        # Explicit caller-supplied index is returned verbatim, untouched.
        assert (
            srv._resolve_index("case-x-evtx-*", "case-y")
            == "case-x-evtx-*"
        )

    def test_no_case_falls_back_to_wildcard(self, monkeypatch):
        monkeypatch.setattr(srv, "_get_active_case", lambda: None)
        assert srv._resolve_index("", "") == "case-*"

    def test_count_uses_injected_case_dir_basename_as_key(self, mock_client, tmp_path):
        # Simulate the Gateway injecting the authoritative case_dir (whose
        # basename is the case_key) while also injecting the opaque UUID into
        # case_id. The query must target the single-prefix indices.
        case_dir = tmp_path / "case-rocba-case-06132304"
        case_dir.mkdir()
        mock_client.count.return_value = {"count": 7}
        opensearch_count(
            query="*",
            case_id="674425ae-78ea-4c9c-9a14-3c9d0b6f900c",
            case_dir=str(case_dir),
        )
        # Inspect the index the client was actually asked to count.
        _, kwargs = mock_client.count.call_args
        assert kwargs["index"] == "case-rocba-case-06132304-*"
        assert "case-case-" not in kwargs["index"]


class TestIndexPrefixNormalizationXYE10:
    """XYE-10: the ``case-`` index prefix is applied exactly once.

    Write path (``build_index_name``) and read path (``build_index_pattern``)
    must produce matching single-prefix names so a fresh ingest is queryable by
    the default resolver.
    """

    def test_normalize_case_key_strips_one_leading_case_prefix(self):
        from opensearch_mcp.paths import normalize_case_key

        # Real-world key (dir basename) -> redundant leading 'case-' removed.
        assert normalize_case_key("case-rocba-3-06171852") == "rocba-3-06171852"
        # Only ONE leading prefix is stripped; inner 'case' tokens are kept.
        assert normalize_case_key("case-rocba-case-06132304") == "rocba-case-06132304"
        # Idempotent: a key without the prefix is unchanged.
        assert normalize_case_key("rocba-3-06171852") == "rocba-3-06171852"

    def test_build_index_name_single_prefix_for_case_prefixed_key(self):
        from opensearch_mcp.paths import build_index_name

        name = build_index_name("case-rocba-3-06171852", "amcache", "SRL-FORGE")
        assert name == "case-rocba-3-06171852-amcache-srl-forge"
        assert "case-case-" not in name

    def test_build_index_name_and_pattern_agree(self):
        from opensearch_mcp.paths import build_index_name, build_index_pattern

        # The pattern the reader derives must match the name the writer creates.
        name = build_index_name("case-rocba-3-06171852", "evtx", "host1")
        pattern = build_index_pattern("case-rocba-3-06171852")
        prefix = pattern[: -len("*")]  # strip trailing wildcard
        assert name.startswith(prefix)
        assert "case-case-" not in pattern


def _served_tools() -> dict:
    """The tools actually SERVED over stdio: ``registry.create_server()`` (what
    ``server.py:main`` runs and the Gateway aggregates).

    B-MVP-041: ``opensearch_mcp.server`` no longer carries its own FastMCP tool
    surface — the unserved ``server = FastMCP(...)`` shadow and its ``@server.tool``
    decorators were removed (they masked the B-MVP-036 audit). The registry's
    ``create_server`` is the single, layer-correct surface to assert on; the
    ``server`` module now holds only the plain implementation-engine functions the
    registry wrappers call.
    """
    import asyncio as _asyncio

    from opensearch_mcp.registry import create_server

    tools = _asyncio.run(create_server().list_tools())
    return {t.name: t for t in tools}


class TestToolRegistry:
    def test_ingest_format_variants_are_consolidated_under_idx_ingest(self):
        tools = _served_tools()

        assert "opensearch_ingest" in tools
        for old_name in (
            "idx_ingest_json",
            "idx_ingest_delimited",
            "idx_ingest_accesslog",
            "idx_ingest_memory",
        ):
            assert old_name not in tools

        schema = tools["opensearch_ingest"].parameters
        assert "format" in schema["properties"]

    def test_query_and_status_tools_are_marked_read_only(self):
        read_only_tools = [
            "opensearch_search",
            "opensearch_count",
            "opensearch_aggregate",
            "opensearch_get_event",
            "opensearch_timeline",
            "opensearch_field_values",
            "opensearch_status",
            "opensearch_shard_status",
            "opensearch_case_summary",
        ]
        tools = _served_tools()

        for name in read_only_tools:
            assert getattr(tools[name].annotations, "readOnlyHint", None) is True

    def test_admin_pipeline_install_not_in_public_registry(self):
        """The pipeline-install admin function is not an MCP tool.

        idx_install_pipelines was removed entirely in Phase 6 — pipeline/template
        setup now runs via ensure_winlog_pipeline at server first-connection. Guard
        that it does not reappear under either the old or namespaced name.
        """
        tools = _served_tools()
        assert "idx_install_pipelines" not in tools
        assert "opensearch_install_pipelines" not in tools
        assert not hasattr(srv, "idx_install_pipelines")


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
# F-MVP-2 absolute-path leak neutralization (B-MVP-029 STEP 1)
# ---------------------------------------------------------------------------


class TestCaseRelativeRef:
    def test_in_case_path_collapses_to_relative(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case-x"
        (case_dir / "evidence").mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        # The Gateway-injected contextvar takes precedence over the env in
        # active_case_dir(); bind it to this test's case so prior tests can't leak
        # a stale injected dir.
        srv._INJECTED_CASE_DIR.set(str(case_dir))
        ref = srv._case_relative_ref(str(case_dir / "evidence" / "disk.E01"))
        assert ref == "evidence/disk.E01"
        assert not ref.startswith("/")

    def test_empty_returns_none(self):
        assert srv._case_relative_ref("") is None
        assert srv._case_relative_ref(None) is None

    def test_idx_ingest_json_error_omits_resolved_path(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case-x"
        (case_dir / "evidence").mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        srv._INJECTED_CASE_DIR.set(str(case_dir))
        resp = srv.idx_ingest_json(path="missing.json", hostname="h", dry_run=True)
        assert "error" in resp
        # The absolute resolved path must NOT be echoed back to the agent.
        assert "resolved_path" not in resp
        import json as _json

        assert str(case_dir) not in _json.dumps(resp)

    def test_host_fix_missing_case_dir_error_omits_absolute_path(self, tmp_path, monkeypatch):
        """F-MVP-2 (F5): the host-fix 'case directory not found' error must not
        leak the absolute case directory."""
        missing = tmp_path / "no-such-case-dir-abc"
        srv._INJECTED_CASE_DIR.set(str(missing))
        try:
            resp = srv.opensearch_host_fix(raw="a", new_canonical="b")
        finally:
            srv._INJECTED_CASE_DIR.set("")
        assert "error" in resp
        import json as _json

        assert str(missing) not in _json.dumps(resp)
        assert not any(
            isinstance(v, str) and v.startswith("/") for v in resp.values()
        )


# ---------------------------------------------------------------------------
# opensearch_search
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
        resp = opensearch_search(query="event.code:4624")
        assert resp["total"] == 2
        assert resp["returned"] == 2
        assert len(resp["results"]) == 2

    def test_caps_limit_at_200(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
        }
        opensearch_search(query="*", limit=999)
        call_body = mock_client.search.call_args[1]["body"]
        assert call_body["size"] == 200

    def test_validates_sort_order_invalid_becomes_desc(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
        }
        opensearch_search(query="*", sort="@timestamp:INVALID")
        call_body = mock_client.search.call_args[1]["body"]
        assert call_body["sort"][0]["@timestamp"]["order"] == "desc"

    def test_audit_id_in_response(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
        }
        with patch.object(srv.audit, "log", return_value="audit-123"):
            resp = opensearch_search(query="*")
        assert resp["audit_id"] == "audit-123"

    def test_small_result_set_has_no_autosave(self, mock_client):
        hits = [
            {"_id": str(i), "_index": "idx", "_source": {"event.code": 4624}}
            for i in range(5)
        ]
        mock_client.search.return_value = {"hits": {"total": {"value": 5}, "hits": hits}}
        resp = opensearch_search(query="*")
        assert "full_path" not in resp
        assert len(resp["results"]) == 5

    def test_large_result_set_autosaves_and_returns_relative_ref(
        self, mock_client, tmp_path, monkeypatch
    ):
        case_dir = tmp_path / "case-x"
        (case_dir / "agent").mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        hits = [
            {"_id": str(i), "_index": "idx", "_source": {"event.code": 4624}}
            for i in range(50)
        ]
        mock_client.search.return_value = {"hits": {"total": {"value": 50}, "hits": hits}}
        resp = opensearch_search(query="*")
        # Inline view is capped at the top-N; full set saved to disk.
        assert resp["returned"] == 50
        assert len(resp["results"]) == srv._SEARCH_INLINE_TOP_N
        ref = resp["full_path"]
        assert ref.startswith("agent/searches/search_")
        assert "/" in ref and not ref.startswith("/")  # case-relative, not absolute
        saved = case_dir / ref
        assert saved.is_file()
        import json as _json

        with open(saved) as fh:
            full = _json.load(fh)
        assert len(full) == 50  # FULL set persisted, not just the inline top-N

    def test_no_active_case_caps_inline_and_notes_save_failure(self, mock_client, monkeypatch):
        # A3/D2: when autosave TRIGGERS (here 40 hits > the count threshold) but
        # there is no case dir to spill to, the oversized set must STILL be
        # capped inline (not returned in full) and a note must flag that the
        # full set could not be persisted — otherwise a save failure floods
        # context with the entire oversized set uncapped.
        monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
        monkeypatch.setattr(srv, "active_case_dir", lambda: "")
        hits = [
            {"_id": str(i), "_index": "idx", "_source": {"event.code": 4624}}
            for i in range(40)
        ]
        mock_client.search.return_value = {"hits": {"total": {"value": 40}, "hits": hits}}
        resp = opensearch_search(query="*")
        assert "full_path" not in resp
        # Inline preview is capped to the top-N even though the save failed.
        assert len(resp["results"]) == srv._SEARCH_INLINE_TOP_N
        assert resp["returned"] == 40  # full count still reported
        # A degraded-save note is present and references the full count.
        assert "full_results_note" in resp
        assert "40" in resp["full_results_note"]


class TestHoistConstantFields:
    def test_hoists_field_constant_across_all_hits(self):
        docs = [
            {"_id": "1", "_index": "i", "sift.case_id": "C1", "event.code": 4624},
            {"_id": "2", "_index": "i", "sift.case_id": "C1", "event.code": 4625},
        ]
        common, slim = srv._hoist_constant_fields(docs)
        assert common == {"sift.case_id": "C1"}
        assert all("sift.case_id" not in d for d in slim)
        assert slim[0]["event.code"] == 4624

    def test_mixed_values_are_not_hoisted(self):
        docs = [
            {"_id": "1", "sift.case_id": "C1"},
            {"_id": "2", "sift.case_id": "C2"},
        ]
        common, slim = srv._hoist_constant_fields(docs)
        assert common == {}
        assert slim[0]["sift.case_id"] == "C1"

    def test_field_absent_from_some_hits_is_not_hoisted(self):
        docs = [
            {"_id": "1", "sift.provenance_id": "P"},
            {"_id": "2"},  # missing the candidate field
        ]
        common, _ = srv._hoist_constant_fields(docs)
        assert "sift.provenance_id" not in common

    def test_search_response_hoists_common_fields(self, mock_client):
        hits = [
            {"_id": "1", "_index": "i", "_source": {"sift.case_id": "C1", "x": 1}},
            {"_id": "2", "_index": "i", "_source": {"sift.case_id": "C1", "x": 2}},
        ]
        mock_client.search.return_value = {"hits": {"total": {"value": 2}, "hits": hits}}
        resp = opensearch_search(query="*")
        assert resp["common_fields"] == {"sift.case_id": "C1"}
        assert all("sift.case_id" not in r for r in resp["results"])


# ---------------------------------------------------------------------------
# opensearch_count
# ---------------------------------------------------------------------------


class TestIdxCount:
    def test_returns_count(self, mock_client):
        mock_client.count.return_value = {"count": 42}
        resp = opensearch_count(query="*")
        assert resp["count"] == 42

    def test_audit_id_in_response(self, mock_client):
        mock_client.count.return_value = {"count": 0}
        with patch.object(srv.audit, "log", return_value="audit-456"):
            resp = opensearch_count()
        assert resp["audit_id"] == "audit-456"


# ---------------------------------------------------------------------------
# opensearch_aggregate
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
        resp = opensearch_aggregate(field="host.name")
        assert resp["field"] == "host.name"
        assert resp["total_docs"] == 100
        assert len(resp["buckets"]) == 2
        assert resp["buckets"][0] == {"key": "host-a", "count": 60}

    def test_caps_limit_at_500(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}},
            "aggregations": {"agg": {"buckets": []}},
        }
        opensearch_aggregate(field="host.name", limit=9999)
        call_body = mock_client.search.call_args[1]["body"]
        assert call_body["aggs"]["agg"]["terms"]["size"] == 500

    def test_save_failure_caps_inline_and_notes(self, mock_client, monkeypatch):
        # A3/D2: a large bucket set that TRIGGERS autosave (150 > the count
        # threshold) but FAILS to persist (no case dir / disk full) must still
        # be capped inline + carry a degraded-save note, never returned in full.
        # Simulate the save failure directly via _save_full_results -> None.
        buckets = [{"key": f"h{i}", "doc_count": 1} for i in range(150)]
        mock_client.search.return_value = {
            "hits": {"total": {"value": 150}},
            "aggregations": {"agg": {"buckets": buckets}},
        }
        monkeypatch.setattr(srv, "_save_full_results", lambda *a, **k: None)
        resp = opensearch_aggregate(field="host.name", limit=500)
        assert "full_path" not in resp
        # Inline preview capped to the top-N even though the save failed.
        assert len(resp["buckets"]) == srv._AGG_INLINE_TOP_N
        assert "full_results_note" in resp
        assert "150" in resp["full_results_note"]


# ---------------------------------------------------------------------------
# _last_completed_from_opensearch (B3)
# ---------------------------------------------------------------------------


class TestLastCompletedFromOpensearch:
    def test_missing_creation_time_falls_back_by_name_not_arbitrary(self, mock_client):
        # B3: when cat indices omit creation.date.string for ALL rows, max()
        # over empty keys would pick an arbitrary row and falsely assert it as
        # newest. The guard falls back to a deterministic name-ordered choice
        # and leaves the creation time null while flagging it in the note.
        mock_client.cat.indices.return_value = [
            {"index": "case-c-evtx-a", "docs.count": "10"},
            {"index": "case-c-evtx-z", "docs.count": "5"},
            {"index": "case-c-evtx-m", "docs.count": "7"},
        ]
        out = srv._last_completed_from_opensearch("c")
        assert out is not None
        assert out["total_docs"] == 22
        # Deterministic: last by index NAME, creation time left null.
        assert out["most_recent_index"] == "case-c-evtx-z"
        assert out["most_recent_index_created"] is None
        assert "name" in out["note"].lower()

    def test_creation_time_present_picks_latest_by_time(self, mock_client):
        mock_client.cat.indices.return_value = [
            {
                "index": "case-c-evtx-a",
                "docs.count": "1",
                "creation.date.string": "2026-06-10T00:00:00.000Z",
            },
            {
                "index": "case-c-evtx-b",
                "docs.count": "1",
                "creation.date.string": "2026-06-15T00:00:00.000Z",
            },
        ]
        out = srv._last_completed_from_opensearch("c")
        assert out["most_recent_index"] == "case-c-evtx-b"
        assert out["most_recent_index_created"] == "2026-06-15T00:00:00.000Z"


# ---------------------------------------------------------------------------
# opensearch_get_event
# ---------------------------------------------------------------------------


class TestIdxGetEvent:
    def test_returns_document_with_id_and_index(self, mock_client):
        mock_client.get.return_value = {
            "_id": "doc123",
            "_index": "case-test-evtx-host1",
            "_source": {"event.code": 4624, "user.name": "admin"},
        }
        resp = opensearch_get_event(event_id="doc123", index="case-test-evtx-host1")
        assert resp["_id"] == "doc123"
        assert resp["_index"] == "case-test-evtx-host1"
        assert resp["event.code"] == 4624


# ---------------------------------------------------------------------------
# opensearch_timeline
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
        resp = opensearch_timeline(query="*", interval="1h")
        assert resp["total_docs"] == 500
        assert resp["interval"] == "1h"
        assert len(resp["buckets"]) == 2
        assert resp["buckets"][0] == {"time": "2024-01-15T10:00:00Z", "count": 100}


# ---------------------------------------------------------------------------
# opensearch_field_values
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
        resp = opensearch_field_values(field="winlog.provider_name")
        assert resp["field"] == "winlog.provider_name"
        assert len(resp["values"]) == 2
        assert resp["values"][0] == {"value": "Sysmon", "count": 50, "doc_count": 50}


# ---------------------------------------------------------------------------
# opensearch_status
# ---------------------------------------------------------------------------


class TestIdxStatus:
    # SEC-7: the multi-case fixture below is the recon corpus a malicious agent
    # would try to enumerate. The active case is ``case-aaa`` (key ``aaa`` →
    # prefix ``case-aaa-``); ``case-bbb-*`` is another case, ``case-aaab-evtx`` is
    # a sibling whose name shares the ``case-aaa`` text but NOT the ``case-aaa-``
    # boundary, and ``.kibana_1`` is a system index.
    _MULTI_CASE_INDICES = [
        {
            "index": "case-aaa-evtx-host1",
            "docs.count": "1000",
            "store.size": "5mb",
            "status": "open",
        },
        {
            "index": "case-aaa-prefetch",
            "docs.count": "20",
            "store.size": "1mb",
            "status": "open",
        },
        {
            "index": "case-bbb-evtx-host1",
            "docs.count": "50",
            "store.size": "100kb",
            "status": "open",
        },
        # Prefix-boundary decoy: ``case-aaab-evtx``.startswith("case-aaa")
        # is True, but startswith("case-aaa-") is False (the trailing dash
        # stops ``case-aaa`` from matching the longer ``case-aaab`` key).
        {
            "index": "case-aaab-evtx",
            "docs.count": "7",
            "store.size": "50kb",
            "status": "open",
        },
        {"index": ".kibana_1", "docs.count": "10", "store.size": "1mb", "status": "open"},
    ]

    def test_scopes_index_catalog_to_active_case(self, mock_client):
        # SEC-7 fail-on-revert: with case A active, opensearch_status must
        # return ONLY case A's indices — never the cluster-wide ``case-*`` set,
        # which is a cross-case targeting map. Reverting the filter to
        # ``.startswith("case-")`` re-admits ``case-bbb-*`` and breaks this.
        mock_client.cat.indices.return_value = list(self._MULTI_CASE_INDICES)
        mock_client.cluster.health.return_value = {"status": "green"}
        # The Gateway injects the opaque DB UUID into case_id and the
        # authoritative case directory into case_dir; the dir basename
        # (``case-aaa``) is the case key the indices are named from.
        resp = opensearch_status(
            case_id="674425ae-78ea-4c9c-9a14-3c9d0b6f900c",
            case_dir="/cases/case-aaa",
        )
        index_names = [i["index"] for i in resp["indices"]]
        assert index_names == ["case-aaa-evtx-host1", "case-aaa-prefetch"]
        assert resp["total_indices"] == 2
        # Other case + boundary decoy + system index are all excluded.
        assert "case-bbb-evtx-host1" not in index_names
        assert "case-aaab-evtx" not in index_names
        assert ".kibana_1" not in index_names

    def test_prefix_boundary_excludes_sibling_case(self, mock_client):
        # SEC-7: the trailing-dash boundary is load-bearing — a missing dash
        # would let active case ``aaa`` leak the sibling ``case-aaab-*``.
        mock_client.cat.indices.return_value = list(self._MULTI_CASE_INDICES)
        mock_client.cluster.health.return_value = {"status": "green"}
        resp = opensearch_status(case_dir="/cases/case-aaa")
        index_names = [i["index"] for i in resp["indices"]]
        assert "case-aaab-evtx" not in index_names

    def test_no_active_case_returns_empty_catalog(self, mock_client, monkeypatch):
        # SEC-7: with no resolvable active case the index catalog is EMPTY
        # (never the cluster-wide ``case-*`` enumeration), but cluster health
        # still reports — the standalone health-probe path must not error and
        # must not leak the cross-case index list.
        monkeypatch.setattr(srv, "_get_active_case", lambda: None)
        mock_client.cat.indices.return_value = list(self._MULTI_CASE_INDICES)
        mock_client.cluster.health.return_value = {"status": "green"}
        resp = opensearch_status()
        assert resp["cluster_status"] == "green"
        assert resp["indices"] == []
        assert resp["total_indices"] == 0

    def test_includes_cluster_status(self, mock_client):
        mock_client.cat.indices.return_value = []
        mock_client.cluster.health.return_value = {
            "status": "yellow",
            "number_of_nodes": 1,
        }
        resp = opensearch_status()
        assert "yellow" in resp["cluster_status"]
        assert "single-node" in resp["cluster_status"]

    def test_cluster_status_green_not_annotated(self, mock_client):
        mock_client.cat.indices.return_value = []
        mock_client.cluster.health.return_value = {
            "status": "green",
            "number_of_nodes": 3,
        }
        resp = opensearch_status()
        assert resp["cluster_status"] == "green"


# ---------------------------------------------------------------------------
# opensearch_ingest
# ---------------------------------------------------------------------------


class TestIdxIngest:
    def test_rejects_unknown_format(self, mock_client, monkeypatch):
        monkeypatch.setattr(srv, "_get_active_case", lambda: "test-case")
        resp = opensearch_ingest(path="evidence", format="unknown", dry_run=True)
        assert "error" in resp
        assert "supported_formats" in resp

    def test_routes_json_format_through_idx_ingest(self, mock_client, monkeypatch):
        monkeypatch.setattr(srv, "_get_active_case", lambda: "test-case")
        with patch("opensearch_mcp.server.idx_ingest_json") as handler:
            handler.return_value = {"status": "preview", "format": "jsonl"}
            resp = opensearch_ingest(
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
            resp = opensearch_ingest(
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
            resp = opensearch_ingest(
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
        resp = opensearch_ingest(path="/etc")
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

        resp = opensearch_ingest(path="evidence", dry_run=True)
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
        resp = opensearch_ingest(path="not_a_dir.txt")
        assert "error" in resp
        assert "Not a directory or supported container" in resp["error"]

    def test_ingest_status_returns_empty_when_no_status(self, mock_client):
        """opensearch_ingest_status returns empty when no status files exist."""
        with patch(
            "opensearch_mcp.ingest_status.read_active_ingests",
            return_value=[],
        ):
            resp = opensearch_ingest_status(case_id="*")
        assert resp["ingests"] == []
        assert "No active" in resp["message"]

    def test_ingest_status_does_not_leak_absolute_log_path(self, mock_client, monkeypatch):
        """F-MVP-2: the on-disk status file stores an absolute ~/.sift log path;
        opensearch_ingest_status must surface a non-absolute pointer to the agent."""
        monkeypatch.setattr("opensearch_mcp.ingest_status.db_status_active", lambda: False)
        roster = [
            {
                "case_id": "TEST-CASE",
                "status": "running",
                "pid": 7,
                "run_id": "run-xyz",
                "elapsed_seconds": 90,
                "totals": {"indexed": 5},
                "log_file": "/home/operator/.sift/ingest-logs/run-xyz.log",
                "hosts": [],
            }
        ]
        with patch(
            "opensearch_mcp.ingest_status.read_active_ingests", return_value=roster
        ):
            resp = opensearch_ingest_status(case_id="TEST-CASE")
        log_file = resp["ingests"][0]["log_file"]
        assert not log_file.startswith("/")
        assert log_file == "ingest-logs/run-xyz.log"
        import json as _json

        assert "/home/operator/.sift" not in _json.dumps(resp)


# ---------------------------------------------------------------------------
# opensearch_enrich_intel — async launch (UAT 2026-04-23 B79)
# ---------------------------------------------------------------------------


class TestEnrichIntelAsync:
    """B79: opensearch_enrich_intel with dry_run=False must return immediately
    with {status: started, pid, run_id, ...} so the gateway's 300s
    synchronous tool timeout cannot kill a real enrichment run. The
    worker runs under systemd-run scope and writes progress to the
    shared ingest-status dir with artifact_name='intel'."""

    def test_dry_run_stays_synchronous(self, mock_client, monkeypatch):
        """dry_run=True must keep the synchronous preview path — operators
        rely on the IOC count for decide-before-run flow."""
        from opensearch_mcp.server import opensearch_enrich_intel

        monkeypatch.setattr(srv, "_get_active_case", lambda: "TEST-CASE")
        fake_iocs = {
            "ip": {"1.2.3.4", "5.6.7.8"},
            "hash": {"abc", "def", "ghi"},
            "domain": {"evil.example"},
        }
        with patch("opensearch_mcp.threat_intel.extract_unique_iocs", return_value=fake_iocs):
            resp = opensearch_enrich_intel(dry_run=True)
        assert resp["status"] == "preview"
        assert resp["ips"] == 2
        assert resp["hashes"] == 3
        assert resp["domains"] == 1
        assert resp["total_iocs"] == 6

    def test_execute_launches_background(self, mock_client, monkeypatch, tmp_path):
        """dry_run=False must return {status: started, pid, run_id}
        immediately — does NOT block on enrich_case."""
        from opensearch_mcp.server import opensearch_enrich_intel

        monkeypatch.setattr(srv, "_get_active_case", lambda: "TEST-CASE")

        fake_proc = MagicMock()
        fake_proc.pid = 54321
        # Run the background helper against mocked _spawn_ingest and
        # write_status so nothing real forks.
        with (
            patch("opensearch_mcp.gateway.gateway_available", return_value=True),
            patch("opensearch_mcp.server._spawn_ingest", return_value=fake_proc),
            patch("opensearch_mcp.ingest_status.write_status"),
            patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]),
            patch("opensearch_mcp.paths.sift_dir", return_value=tmp_path),
        ):
            resp = opensearch_enrich_intel(dry_run=False)

        assert resp["status"] == "started"
        assert resp["pid"] == 54321
        assert "run_id" in resp
        assert resp["case_id"] == "TEST-CASE"
        # Message points operators at the right status tool.
        assert "opensearch_ingest_status" in resp["message"]
        assert "intel" in resp["message"]
        # F-MVP-2: no absolute log path leaks to the agent — neither in the
        # structured log_file field nor embedded in the message string.
        assert not resp["log_file"].startswith("/")
        assert resp["log_file"] == f"ingest-logs/{resp['run_id']}.log"
        assert "Log file:" not in resp["message"]
        assert str(tmp_path) not in resp["message"]
        assert str(tmp_path) not in resp["log_file"]

    def test_execute_respects_explicit_case_arg(self, mock_client, monkeypatch, tmp_path):
        """Explicit case_id must be passed to the worker, not silently
        overridden by the active-case."""
        from opensearch_mcp.server import opensearch_enrich_intel

        monkeypatch.setattr(srv, "_get_active_case", lambda: "ACTIVE-CASE")

        fake_proc = MagicMock()
        fake_proc.pid = 11111
        captured_cmd = []

        def _capture_spawn(cmd, env, stdout, run_id):
            captured_cmd.extend(cmd)
            return fake_proc

        with (
            patch("opensearch_mcp.gateway.gateway_available", return_value=True),
            patch("opensearch_mcp.server._spawn_ingest", side_effect=_capture_spawn),
            patch("opensearch_mcp.ingest_status.write_status"),
            patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]),
            patch("opensearch_mcp.paths.sift_dir", return_value=tmp_path),
        ):
            resp = opensearch_enrich_intel(case_id="OVERRIDE-CASE", dry_run=False)

        assert resp["case_id"] == "OVERRIDE-CASE"
        # Worker cmd includes --case OVERRIDE-CASE, not ACTIVE-CASE.
        assert "OVERRIDE-CASE" in captured_cmd
        assert "ACTIVE-CASE" not in captured_cmd

    def test_execute_force_flag_propagated(self, mock_client, monkeypatch, tmp_path):
        """--force flag must reach the worker command line."""
        from opensearch_mcp.server import opensearch_enrich_intel

        monkeypatch.setattr(srv, "_get_active_case", lambda: "TEST-CASE")

        fake_proc = MagicMock()
        fake_proc.pid = 22222
        captured_cmd = []

        def _capture_spawn(cmd, env, stdout, run_id):
            captured_cmd.extend(cmd)
            return fake_proc

        with (
            patch("opensearch_mcp.gateway.gateway_available", return_value=True),
            patch("opensearch_mcp.server._spawn_ingest", side_effect=_capture_spawn),
            patch("opensearch_mcp.ingest_status.write_status"),
            patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]),
            patch("opensearch_mcp.paths.sift_dir", return_value=tmp_path),
        ):
            opensearch_enrich_intel(dry_run=False, force=True)

        assert "--force" in captured_cmd

    def test_execute_concurrency_gate_blocks_at_cap(self, mock_client, monkeypatch):
        """Enrichment must respect the same concurrency cap as ingest —
        running 5+ long enrichments simultaneously would starve the
        OpenCTI rate limiter and is a stability hazard."""
        from opensearch_mcp.server import _MAX_CONCURRENT_INGESTS, opensearch_enrich_intel

        monkeypatch.setattr(srv, "_get_active_case", lambda: "TEST-CASE")
        full_roster = [
            {"status": "running", "case_id": f"C{i}", "pid": 1000 + i}
            for i in range(_MAX_CONCURRENT_INGESTS)
        ]
        with (
            patch("opensearch_mcp.gateway.gateway_available", return_value=True),
            patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=full_roster),
        ):
            resp = opensearch_enrich_intel(dry_run=False)
        assert "error" in resp
        assert "Too many concurrent" in resp["error"]


class TestEnrichIntelBackendUnavailable:
    """F8: when no OpenCTI/intel backend is registered, the tool must surface a
    clear unavailable signal instead of a misleading success/started."""

    def test_dry_run_flags_unavailable_backend(self, mock_client, monkeypatch):
        """dry_run still previews IOCs but annotates that enrichment can't run."""
        from opensearch_mcp.server import opensearch_enrich_intel

        monkeypatch.setattr(srv, "_get_active_case", lambda: "TEST-CASE")
        fake_iocs = {"ip": {"1.2.3.4"}, "hash": {"abc"}, "domain": set()}
        with (
            patch("opensearch_mcp.gateway.gateway_available", return_value=False),
            patch("opensearch_mcp.threat_intel.extract_unique_iocs", return_value=fake_iocs),
        ):
            resp = opensearch_enrich_intel(dry_run=True)
        # Preview still works (IOC extraction is independent of the backend).
        assert resp["status"] == "preview"
        assert resp["total_iocs"] == 2
        # But the unavailability is now explicit, not silent.
        assert resp["intel_backend"] == "unavailable"
        assert "unavailable" in resp["intel_backend_message"].lower()
        assert "setup-addon" in resp["intel_backend_message"]

    def test_dry_run_flags_available_backend(self, mock_client, monkeypatch):
        """When a backend is present, dry_run marks intel_backend available."""
        from opensearch_mcp.server import opensearch_enrich_intel

        monkeypatch.setattr(srv, "_get_active_case", lambda: "TEST-CASE")
        fake_iocs = {"ip": {"1.2.3.4"}, "hash": set(), "domain": set()}
        with (
            patch("opensearch_mcp.gateway.gateway_available", return_value=True),
            patch("opensearch_mcp.threat_intel.extract_unique_iocs", return_value=fake_iocs),
        ):
            resp = opensearch_enrich_intel(dry_run=True)
        assert resp["status"] == "preview"
        assert resp["intel_backend"] == "available"
        assert "intel_backend_message" not in resp

    def test_execute_returns_unavailable_not_started(self, mock_client, monkeypatch):
        """dry_run=False with no backend must NOT launch — returns unavailable."""
        from opensearch_mcp.server import opensearch_enrich_intel

        monkeypatch.setattr(srv, "_get_active_case", lambda: "TEST-CASE")
        spawn_called = []

        def _spy_spawn(*a, **k):
            spawn_called.append(True)
            return MagicMock(pid=1)

        with (
            patch("opensearch_mcp.gateway.gateway_available", return_value=False),
            patch("opensearch_mcp.server._spawn_ingest", side_effect=_spy_spawn),
            patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]),
        ):
            resp = opensearch_enrich_intel(dry_run=False)
        assert resp["status"] == "unavailable"
        assert resp["intel_backend"] == "unavailable"
        assert "setup-addon" in resp["error"]
        # Critically: no background enrichment was launched.
        assert spawn_called == []


# ---------------------------------------------------------------------------
# EnrichIntelOut — output model validation (P35-5 queued status)
# ---------------------------------------------------------------------------


class TestEnrichIntelOutModel:
    """EnrichIntelOut.status must accept all three legitimate values so the
    gateway's worker-dispatch path (which returns status='queued' + job_id)
    passes MCP output validation instead of raising 'queued not in enum'."""

    def test_accepts_preview(self):
        """dry_run=True preview path: status='preview' must be valid."""
        from opensearch_mcp.registry import EnrichIntelOut

        out = EnrichIntelOut(status="preview", case_id="test-case", ips=2, total_iocs=2)
        assert out.status == "preview"

    def test_accepts_started(self):
        """Background launch path: status='started' must be valid."""
        from opensearch_mcp.registry import EnrichIntelOut

        out = EnrichIntelOut(status="started", case_id="test-case", pid=54321, run_id="r1")
        assert out.status == "started"

    def test_accepts_queued(self):
        """Worker-dispatch path: status='queued' must be valid (P35-5 fix).

        The gateway's OpenSearchJobDispatchMiddleware returns this status when
        opensearch_enrich_intel is redirected to a durable sift-opensearch-worker@
        job. Before this fix, 'queued' was not in the Literal enum so the MCP
        output validator rejected the response with 'queued is not one of
        [preview, started]'.
        """
        from opensearch_mcp.registry import EnrichIntelOut

        out = EnrichIntelOut(
            status="queued",
            case_id="test-case",
            job_id="job-enrich-001",
            job_type="enrich",
            dispatched_to="opensearch-worker",
            next_step="Poll running_commands_status(job_id) for progress.",
        )
        assert out.status == "queued"
        assert out.job_id == "job-enrich-001"
        assert out.job_type == "enrich"
        assert out.dispatched_to == "opensearch-worker"

    def test_accepts_exact_gateway_dispatch_payload(self):
        """Regression (live P35-5): the gateway's _enqueue payload OMITS case_id.

        OpenSearchJobDispatchMiddleware._enqueue returns exactly
        {job_id,status,job_type,dispatched_to,next_step} for both ingest and
        enrich — no case_id. EnrichIntelOut.case_id must therefore be optional
        (IngestOut already is). The earlier test_accepts_queued passed only
        because it supplied case_id; the real worker-dispatch response does not,
        and a required case_id rejected the legitimate queued response live.
        """
        from opensearch_mcp.registry import EnrichIntelOut

        # Byte-for-byte the shape policy_middleware._enqueue emits (no case_id).
        payload = {
            "job_id": "7b62ef54-3884-4baf-ade1-89954e22f4ea",
            "status": "queued",
            "job_type": "enrich",
            "dispatched_to": "opensearch-worker",
            "next_step": "Dispatched to a dedicated OpenSearch worker (non-blocking).",
        }
        out = EnrichIntelOut.model_validate(payload)
        assert out.status == "queued"
        assert out.case_id is None
        assert out.job_id == payload["job_id"]

    def test_rejects_invalid_status(self):
        """Invalid status values must still fail validation."""
        import pytest
        from pydantic import ValidationError

        from opensearch_mcp.registry import EnrichIntelOut

        with pytest.raises(ValidationError):
            EnrichIntelOut(status="running", case_id="test-case")

    def test_queued_schema_enum_contains_all_three(self):
        """JSON Schema for EnrichIntelOut.status must list all three values so
        schema-validating MCP clients accept queued worker-dispatch responses."""
        from opensearch_mcp.registry import EnrichIntelOut

        schema = EnrichIntelOut.model_json_schema()
        status_enum = schema["properties"]["status"]["enum"]
        assert "preview" in status_enum
        assert "started" in status_enum
        assert "queued" in status_enum


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
# R0-2: opensearch_ingest — uses _get_active_case, not inline active_case read
# ---------------------------------------------------------------------------


class TestIdxIngestActiveCase:
    def test_no_active_case_returns_portal_hint(self, mock_client, monkeypatch):
        """When no active case is set, returns portal_hint (not legacy CLI error)."""
        monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
        # Point sift_dir to empty tmp so file fallback also fails
        monkeypatch.setattr(srv, "_get_active_case", lambda: None)
        # A valid path to satisfy path validation
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            resp = opensearch_ingest(path=d)
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
        resp = opensearch_ingest(path="evidence", dry_run=True)
        assert resp.get("status") == "preview"
        assert resp.get("case_id") == "rocba-20260525-1200"


# ---------------------------------------------------------------------------
# R0-3: opensearch_ingest — directory with containers returns containers_detected
# ---------------------------------------------------------------------------


class TestIdxIngestContainerDetection:
    def test_directory_with_e01_returns_containers_detected(
        self, mock_client, tmp_path, monkeypatch
    ):
        """Directory containing .e01 file → containers_detected with next_step."""
        case_dir = tmp_path / "test-case-001"
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        e01 = evidence_dir / "rocba-cdrive.e01"
        e01.write_bytes(b"EVF" + b"\x00" * 100)  # minimal EWF magic
        resp = opensearch_ingest(path="evidence", dry_run=True)
        assert resp.get("status") == "containers_detected"
        assert resp.get("case_id") == "test-case-001"
        assert len(resp.get("containers", [])) >= 1
        assert "next_step" in resp
        assert "opensearch_ingest" in resp["next_step"]
        # F-MVP-2 (F1): the dry_run response must not leak the absolute container
        # path — only the case-relative display path survives.
        for c in resp["containers"]:
            assert "path" not in c
            assert "relative_path" in c
            assert not str(c["relative_path"]).startswith("/")
        assert str(case_dir) not in _json.dumps(resp)

    def test_directory_empty_returns_error(self, mock_client, tmp_path, monkeypatch):
        """Empty directory → no containers, falls through to original error."""
        case_dir = tmp_path / "test-case-001"
        (case_dir / "evidence").mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        resp = opensearch_ingest(path="evidence", dry_run=True)
        assert "error" in resp
        assert "containers_detected" != resp.get("status")

    def test_directory_no_containers_preserves_original_error(
        self, mock_client, tmp_path, monkeypatch
    ):
        """Dir with only non-container files → 'No Windows artifacts found'."""
        case_dir = tmp_path / "test-case-001"
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        (evidence_dir / "notes.txt").write_text("not a container")
        resp = opensearch_ingest(path="evidence", dry_run=True)
        assert "error" in resp
        assert "No Windows artifacts found" in resp["error"]

    def test_directory_container_detection_ignores_symlinks(
        self, mock_client, tmp_path, monkeypatch
    ):
        """Directory auto-detection must not follow symlinks to container files."""
        active_case_dir = tmp_path / "active-case"
        evidence_dir = active_case_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        other_case_dir = tmp_path / "other-case"
        other_evidence_dir = other_case_dir / "evidence"
        other_evidence_dir.mkdir(parents=True)
        target = other_evidence_dir / "disk.e01"
        target.write_bytes(b"EVF" + b"\x00" * 100)
        try:
            (evidence_dir / "other-case.e01").symlink_to(target)
        except OSError:
            pytest.skip(
                "Symbolic links are not supported or privileges are missing on this platform"
            )
        monkeypatch.setenv("SIFT_CASE_DIR", str(active_case_dir))

        with patch("opensearch_mcp.ingest.discover", return_value=[]):
            resp = opensearch_ingest(path="evidence", dry_run=True)

        assert "error" in resp
        assert resp.get("status") != "containers_detected"

    def test_directory_discovery_ignores_symlinked_host_dirs(
        self, mock_client, tmp_path, monkeypatch
    ):
        """Directory discovery must not follow symlinked host dirs to another case."""
        active_case_dir = tmp_path / "active-case"
        evidence_dir = active_case_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        other_host = tmp_path / "other-case" / "evidence" / "HOSTA"
        (other_host / "Windows" / "System32" / "config").mkdir(parents=True)
        (other_host / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"")
        try:
            (evidence_dir / "HOSTA").symlink_to(other_host, target_is_directory=True)
        except OSError:
            pytest.skip(
                "Symbolic links are not supported or privileges are missing on this platform"
            )
        monkeypatch.setenv("SIFT_CASE_DIR", str(active_case_dir))

        resp = opensearch_ingest(path="evidence", dry_run=True)

        assert "error" in resp
        assert resp.get("status") != "ok"

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
            resp = opensearch_ingest(
                path="evidence", hostname="srl-forge", dry_run=False, force=True
            )

        assert resp["status"] == "multi_started"
        assert len(resp["containers"]) == 2
        assert mock_spawn.call_count == 2
        spawned_cmds = [call.args[0] for call in mock_spawn.call_args_list]
        assert any("scan" in cmd and "--clean" in cmd for cmd in spawned_cmds)
        assert any("memory" in cmd for cmd in spawned_cmds)


class TestInjectedCaseDirPropagation:
    """P0 fix: Gateway-injected case_dir is the authoritative case directory.

    The opensearch backend subprocess gets no DB access and (by D32) no
    SIFT_CASE_DIR; the Gateway propagates the DB active-case artifact_path into
    each filesystem-touching tool call via the injected ``case_dir`` argument.
    These tests pin that the injected value resolves the case (without env or a
    pointer file) and wins over a stale env value.
    """

    def test_active_case_dir_prefers_injection(self, monkeypatch):
        monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
        with srv._use_injected_case_dir("/cases/injected-case"):
            assert srv.active_case_dir() == "/cases/injected-case"
            assert srv._get_active_case() == "injected-case"

    def test_active_case_dir_injection_wins_over_env(self, monkeypatch):
        monkeypatch.setenv("SIFT_CASE_DIR", "/cases/stale-env-case")
        with srv._use_injected_case_dir("/cases/injected-case"):
            assert srv.active_case_dir() == "/cases/injected-case"
        # Outside the injection scope, env is the standalone-CLI fallback.
        assert srv.active_case_dir() == "/cases/stale-env-case"

    def test_active_case_dir_empty_without_any_source(self, monkeypatch):
        monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
        # Point the legacy pointer lookup at an empty dir so no pointer resolves.
        import opensearch_mcp.paths as _paths

        monkeypatch.setattr(_paths, "sift_dir", lambda: _paths.Path("/nonexistent-sift"))
        assert srv.active_case_dir() == ""

    def test_ingest_uses_injected_case_dir(self, mock_client, tmp_path, monkeypatch):
        """opensearch_ingest resolves the case from the injected case_dir alone."""
        monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
        case_dir = tmp_path / "case-injected-001"
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        (evidence_dir / "rocba-cdrive.e01").write_bytes(b"EVF" + b"\x00" * 100)

        proc = MagicMock(pid=303)
        with (
            patch("opensearch_mcp.ingest.discover", return_value=[]),
            patch(
                "opensearch_mcp.shard_capacity.check_shard_headroom",
                return_value=(True, "ok"),
            ),
            patch("opensearch_mcp.server._spawn_ingest", return_value=proc) as mock_spawn,
        ):
            resp = opensearch_ingest(
                path="evidence/rocba-cdrive.e01",
                hostname="srl-forge",
                dry_run=False,
                force=True,
                case_dir=str(case_dir),
            )

        # No "no_active_case" — the injected dir resolved the case end-to-end.
        assert resp.get("status") in {"started", "multi_started", "containers_detected"}
        assert "error" not in resp or "active case" not in str(resp.get("error", "")).lower()
        # The ingest worker child gets the authoritative dir propagated via env.
        spawned_env = mock_spawn.call_args_list[0].args[1]
        assert spawned_env.get("SIFT_CASE_DIR") == str(case_dir)

    def test_ingest_no_active_case_when_nothing_injected(self, mock_client, monkeypatch):
        monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
        import opensearch_mcp.paths as _paths

        monkeypatch.setattr(_paths, "sift_dir", lambda: _paths.Path("/nonexistent-sift"))
        resp = opensearch_ingest(path="evidence/x.e01", case_dir="")
        assert resp.get("error") == "No active case."


class TestSpawnIngestUserBusFallback:
    """_spawn_ingest must skip systemd-run --user when no user bus exists.

    System service accounts (e.g. sift-service) have no login session and no
    /run/user/<uid>/bus, so systemd-run --user fails with 'Failed to connect to
    bus' and the ingest never runs. Without a reachable user bus the spawn must
    go straight to a bare Popen (which still isolates via start_new_session).
    """

    def test_no_user_bus_skips_systemd_run(self, tmp_path):
        from unittest.mock import MagicMock, patch

        import opensearch_mcp.server as s

        # XDG_RUNTIME_DIR points at a dir with NO 'bus' socket → no user bus.
        env = {"XDG_RUNTIME_DIR": str(tmp_path)}
        captured = {}

        def fake_popen(cmd, **kw):
            captured["cmd"] = list(cmd)
            m = MagicMock()
            m.poll.return_value = None
            return m

        with patch("subprocess.Popen", side_effect=fake_popen):
            s._spawn_ingest(
                ["python", "-m", "opensearch_mcp.ingest_cli", "scan"],
                env,
                None,
                "run-1234567890ab",
            )

        assert captured["cmd"][0] != "systemd-run", captured["cmd"]
        assert captured["cmd"][0] == "python"

    def test_user_bus_present_uses_systemd_run_scope(self, tmp_path):
        from unittest.mock import MagicMock, patch

        import opensearch_mcp.server as s

        # Create a fake bus socket so the user-bus probe passes.
        (tmp_path / "bus").write_text("")
        env = {"XDG_RUNTIME_DIR": str(tmp_path)}
        captured = {}

        def fake_popen(cmd, **kw):
            captured["cmd"] = list(cmd)
            m = MagicMock()
            m.poll.return_value = None  # still running → no fallback
            return m

        with (
            patch("shutil.which", return_value="/usr/bin/systemd-run"),
            patch("subprocess.Popen", side_effect=fake_popen),
        ):
            s._spawn_ingest(
                ["python", "-m", "opensearch_mcp.ingest_cli", "scan"],
                env,
                None,
                "run-1234567890ab",
            )

        assert captured["cmd"][0] == "systemd-run"
        assert "--scope" in captured["cmd"]


# ---------------------------------------------------------------------------
# B-MVP-036: gateway case_dir kwarg-injection must never raise
# ---------------------------------------------------------------------------

# The manifest is the source of truth for which tool calls the Gateway injects
# arguments into: every tool whose ``safe_case_argument_names`` lists
# ``case_dir`` receives an extra ``case_dir=<active-case>`` kwarg at call time.
# The check must target the SERVED server (``registry.create_server()`` -- what
# ``server.py:main`` runs over stdio) and the tool's ADVERTISED input schema: the
# Gateway proxies via FastMCP, whose ``tool_transform._forward`` validates the
# call against the advertised schema and rejects an injected kwarg the schema
# does not declare -- BEFORE it reaches the backend function. So a tool can
# *accept* case_dir in its impl yet still fail live if its served ``*In`` model
# does not declare it (the real B-MVP-036 cause: ``CountIn`` lacked the field
# while ``SearchIn`` had it). Checking the function signature is the WRONG layer
# (it inspected ``server.py``'s separate, unserved @server.tool surface).
_MANIFEST_PATH = _Path(__file__).resolve().parent.parent / "sift-backend.json"

# Canonical-manifest-name -> registered-registry-name. Identity today: the
# served surface == the manifest 'tools' block (the gateway enforces that). The
# deprecated `opensearch_host_fix` alias cutover is complete, so the host-fix
# tool is served under its canonical name only.
_MANIFEST_TO_REGISTRY: dict[str, str] = {}


def _case_dir_injected_tool_names() -> list[str]:
    manifest = _json.loads(_MANIFEST_PATH.read_text())
    return [
        t["name"]
        for t in manifest["tools"]
        if "case_dir" in t.get("safe_case_argument_names", [])
    ]


_CASE_DIR_TOOLS = _case_dir_injected_tool_names()


def _served_tool_schemas() -> dict:
    """Advertised input schemas of the tools the stdio entrypoint actually serves
    (``registry.create_server`` -- NOT ``server.py``'s separate @server.tool
    surface, which is not mounted over stdio and previously masked this bug)."""
    import asyncio as _asyncio

    from opensearch_mcp.registry import create_server

    tools = _asyncio.run(create_server().list_tools())
    return {t.name: (getattr(t, "parameters", None) or {}) for t in tools}


_SERVED_TOOL_SCHEMAS = _served_tool_schemas()


class TestCaseDirArgInjectionInvariant:
    """B-MVP-036: every Gateway-injected ``case_dir`` target must accept it.

    These are manifest-driven so a newly added case-scoped tool (or a manifest
    entry that starts listing ``case_dir``) is automatically covered against the
    arg-injection regression that previously broke ``opensearch_count``.
    """

    def test_manifest_has_case_dir_tools(self):
        # Guard against the manifest path/shape silently breaking the sweep.
        assert _CASE_DIR_TOOLS, "expected >=1 tool with case_dir in safe_case_argument_names"
        assert "opensearch_count" in _CASE_DIR_TOOLS
        assert "opensearch_search" in _CASE_DIR_TOOLS

    @pytest.mark.parametrize("manifest_name", _CASE_DIR_TOOLS)
    def test_served_tool_advertises_case_dir(self, manifest_name):
        # The Gateway's FastMCP proxy validates against the ADVERTISED input
        # schema, so the served *In model must declare case_dir or the injected
        # kwarg is rejected at tool_transform._forward before reaching the
        # backend (B-MVP-036). The function-signature check was the wrong layer.
        registry_name = _MANIFEST_TO_REGISTRY.get(manifest_name, manifest_name)
        assert registry_name in _SERVED_TOOL_SCHEMAS, (
            f"manifest tool {manifest_name!r} (registry {registry_name!r}) "
            "is not registered on the served (create_server) server"
        )
        props = _SERVED_TOOL_SCHEMAS[registry_name].get("properties", {})
        assert "case_dir" in props, (
            f"{registry_name} does not ADVERTISE 'case_dir' in its served input "
            "schema — the Gateway's FastMCP proxy (_forward) rejects the injected "
            "case_dir kwarg before it reaches the backend (B-MVP-036). The impl "
            "function accepting case_dir is NOT sufficient."
        )


class TestSEC7StatusCaseScopeSurface:
    """SEC-7 fail-on-revert surface: bind status/shard_status to the active case.

    The recon half of SEC-2: ``opensearch_status`` and ``opensearch_shard_status``
    scope their per-case index catalogs (``indices[]`` /
    ``top_indices_by_shard_count``) to the DB-active case so an agent cannot
    enumerate other cases' indices. For the Gateway's gate-⑥ injection to reach
    the backend, three surfaces must agree (the MCP-fix-surfacing lesson):
      1. the manifest declares ``case_id``/``case_dir`` in
         ``safe_case_argument_names`` (so the gateway injects them), and
      2. the served ``*In`` model advertises both fields (so the FastMCP proxy
         does not drop the injected kwargs), and
      3. the impl forwards them.
    Reverting the manifest's ``safe_case_argument_names`` back to ``[]`` (which
    would silently re-open the cross-case catalog) fails (1); reverting the
    registry ``*In`` model fails (2)/(3).
    """

    _SEC7_TOOLS = ("opensearch_status", "opensearch_shard_status")

    @pytest.mark.parametrize("tool_name", _SEC7_TOOLS)
    def test_manifest_declares_both_case_args(self, tool_name):
        manifest = _json.loads(_MANIFEST_PATH.read_text())
        entry = next((t for t in manifest["tools"] if t["name"] == tool_name), None)
        assert entry is not None, f"{tool_name} missing from manifest"
        names = entry.get("safe_case_argument_names", [])
        # Both must be present so the gateway injects the DB-active case; a revert
        # to [] re-opens the cluster-wide enumeration (SEC-7 regression).
        assert "case_id" in names and "case_dir" in names, (
            f"{tool_name} must declare case_id AND case_dir in "
            f"safe_case_argument_names (SEC-7); got {names!r}"
        )

    @pytest.mark.parametrize("tool_name", _SEC7_TOOLS)
    def test_in_model_and_served_schema_expose_both_case_args(self, tool_name):
        from opensearch_mcp.registry import REGISTRY

        tool_def = next((td for td in REGISTRY if td.name == tool_name), None)
        assert tool_def is not None, f"{tool_name} not in REGISTRY"
        fields = tool_def.in_model.model_fields
        assert "case_id" in fields and "case_dir" in fields, (
            f"{tool_name}'s served *In model must expose case_id AND case_dir "
            f"(SEC-7); got {sorted(fields)!r}"
        )
        props = _SERVED_TOOL_SCHEMAS[tool_name].get("properties", {})
        assert "case_id" in props and "case_dir" in props, (
            f"{tool_name} does not ADVERTISE both case args in its served input "
            "schema — the gateway's FastMCP proxy would drop the injected kwargs "
            "and the backend would resolve no active case (empty catalog)."
        )


class TestCaseDirKwargNoRaiseLive:
    """Read-path tools must behave identically with and without injected case_dir.

    Mirrors test_count_uses_injected_case_dir_basename_as_key but pins the
    no-raise / parity invariant across the easily-mockable query tools. The
    fixed tool (opensearch_count) is the lead case; the rest guard regressions.

    SEC-2 note: the supplied ``index`` must stay WITHIN the injected case (the
    gateway injects case_dir = the active case, and the index narrows within it).
    Each pair therefore uses an index matching its case_dir; a deliberately
    cross-case index is covered by the denial tests in test_security.py.
    """

    @pytest.fixture(autouse=True)
    def _no_env_case(self, monkeypatch):
        monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
        # The query tools set the _INJECTED_CASE_DIR ContextVar directly (not via
        # the _use_injected_case_dir context manager), so a leaked value would
        # bleed the injected case_dir into unrelated later tests. Snapshot and
        # restore it so these no-raise calls stay hermetic.
        token = srv._INJECTED_CASE_DIR.set(srv._INJECTED_CASE_DIR.get())
        try:
            yield
        finally:
            srv._INJECTED_CASE_DIR.reset(token)

    def test_count_with_case_dir_matches_without(self, mock_client, tmp_path):
        case_dir = tmp_path / "case-rocba-case-06132304"
        case_dir.mkdir()
        mock_client.count.return_value = {"count": 11}

        idx = "case-rocba-case-06132304-*"  # within case_dir's case
        plain = opensearch_count(query="event.code:4624", index=idx)
        injected = opensearch_count(
            query="event.code:4624", index=idx, case_dir=str(case_dir)
        )
        assert plain["count"] == injected["count"] == 11

    def test_search_with_case_dir_matches_without(self, mock_client):
        mock_client.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
        plain = opensearch_search(query="*", index="case-c1-*")
        injected = opensearch_search(query="*", index="case-c1-*", case_dir="/cases/c1")
        assert plain["total"] == injected["total"] == 0

    def test_aggregate_with_case_dir_matches_without(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}},
            "aggregations": {"agg": {"buckets": []}},
        }
        plain = opensearch_aggregate(field="host.name", index="case-c1-*")
        injected = opensearch_aggregate(
            field="host.name", index="case-c1-*", case_dir="/cases/c1"
        )
        assert plain["buckets"] == injected["buckets"] == []

    def test_timeline_with_case_dir_matches_without(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}},
            "aggregations": {"timeline": {"buckets": []}},
        }
        plain = opensearch_timeline(query="*", index="case-c1-*", interval="1h")
        injected = opensearch_timeline(
            query="*", index="case-c1-*", interval="1h", case_dir="/cases/c1"
        )
        assert plain.get("buckets") == injected.get("buckets")
        assert "error" not in plain and "error" not in injected

    def test_field_values_with_case_dir_matches_without(self, mock_client):
        mock_client.search.return_value = {
            "aggregations": {"values": {"buckets": []}},
        }
        plain = opensearch_field_values(field="user.name", index="case-c1-*")
        injected = opensearch_field_values(
            field="user.name", index="case-c1-*", case_dir="/cases/c1"
        )
        assert plain["values"] == injected["values"] == []


_FAKE_DURABLE_ROW = {
    "job_id": "aabb-1234-ccdd-5678",
    "job_type": "ingest",
    "status": "running",
    "case_id": "case-surface-test",
    "evidence_id": None,
    "priority": 100,
    "attempts": 1,
    "max_attempts": 3,
    "spec_public": {"path": "evidence/test.e01"},
    "result_public": {"indexed_docs": 8000},
    "error_summary": None,
    "provenance_id": None,
    "created_at": "2026-06-25T10:00:00Z",
    "started_at": "2026-06-25T10:01:00Z",
    "finished_at": None,
    "updated_at": "2026-06-25T10:05:00Z",
    "step_count": 3,
    "steps_succeeded": 2,
    "worker_label": "osw-ingest-5678",
    "current_step": {"name": "evtx", "detail": "8000 indexed"},
}


class TestMIngestStatusRegistrySurface:
    """M-INGSTATUS: registry surface (run_opensearch_ingest_status) envelope in DB-active mode.

    Architecture: the backend always returns ingests=[] + authority='postgres-durable-jobs'
    in DB-active mode. The gateway's OpenSearchIngestStatusAugmentMiddleware
    (policy_middleware.py) intercepts the result and populates ingests[] using its own DSN.
    These tests pin the backend's stable envelope shape at the registry surface layer.
    """

    def _run(self, coro):
        loop = _asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_backend_returns_empty_ingests_and_authority_in_db_active_mode(self, monkeypatch):
        """Backend registry surface must return ingests=[] + authority in DB-active mode.

        The gateway augments ingests[] — the backend provides only the authority envelope.
        K4-compliant: no local mirror files consulted.
        """
        monkeypatch.setattr(_srv_mod, "_get_active_case", lambda: "case-surface-test")

        with (
            patch("opensearch_mcp.ingest_status.db_status_active", return_value=True),
            patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]),
        ):
            params = IngestStatusIn(case_id="case-surface-test")
            result = self._run(run_opensearch_ingest_status(params))

        assert not result.is_error, f"Expected success, got error: {result}"
        payload = _json.loads(result.content[0].text)

        # Backend envelope: ingests=[] always (gateway fills it via augment middleware).
        assert payload.get("ingests") == [], (
            "Backend must return ingests=[] in DB-active mode; "
            "gateway OpenSearchIngestStatusAugmentMiddleware populates it"
        )
        assert payload.get("authority") == "postgres-durable-jobs", (
            f"Expected postgres-durable-jobs authority, got: {payload.get('authority')!r}"
        )
        # Message must reference running_commands_status (not the removed job_status).
        msg = payload.get("message", "")
        assert "running_commands_status" in msg, (
            f"Backend message must reference running_commands_status: {msg!r}"
        )

    def test_backend_has_no_job_status_lister(self):
        """Backend server module must NOT expose _JOB_STATUS_LISTER.

        The injectable-lister approach was inert (subprocess never received the injection)
        and has been superseded by the gateway-side augment middleware.
        """
        assert not hasattr(_srv_mod, "_JOB_STATUS_LISTER"), (
            "_JOB_STATUS_LISTER must be removed from the backend server module — "
            "use the gateway's OpenSearchIngestStatusAugmentMiddleware instead"
        )
        assert not hasattr(_srv_mod, "set_job_status_lister"), (
            "set_job_status_lister must be removed from the backend server module"
        )


class TestMHostnameIngestInSurface:
    """M-HOSTNAME: registry surface (IngestIn model) must advertise optional hostname.

    Operator decision: derive-first — auto/memory/e01-disk derivation wins even
    when caller passes hostname.  json/accesslog/non-recursive-delimited must still
    accept a caller-supplied hostname since those formats have no derivable host.
    """

    def test_hostname_is_optional_in_ingest_in_schema(self):
        """hostname field must exist in IngestIn but be optional (default='')."""
        schema = IngestIn.model_json_schema()
        props = schema.get("properties", {})
        assert "hostname" in props, (
            "hostname must be present in IngestIn schema so json/accesslog/delimited "
            "callers can supply it"
        )
        # Optional means it's not in the 'required' list
        required = schema.get("required", [])
        assert "hostname" not in required, (
            "hostname must NOT be required in IngestIn — only used for hostless formats"
        )

    def test_hostname_default_is_empty_string(self):
        """IngestIn.hostname defaults to '' so callers don't need to supply it."""
        m = IngestIn(path="evidence/test.e01")
        assert m.hostname == "", f"Default hostname must be '', got {m.hostname!r}"

    def test_memory_format_description_says_ignored(self):
        """hostname field description must say it is IGNORED for memory/e01-disk formats."""
        schema = IngestIn.model_json_schema()
        desc = schema["properties"]["hostname"].get("description", "")
        assert "IGNORED" in desc, (
            f"hostname description must say IGNORED for memory/e01-disk, got: {desc!r}"
        )
        assert "json" in desc.lower() or "accesslog" in desc.lower(), (
            f"hostname description must mention the hostless formats, got: {desc!r}"
        )

    def test_hostname_in_served_tool_schema(self):
        """The served tool schema (what the Gateway sees) must include hostname."""
        schemas = _served_tool_schemas()
        assert "opensearch_ingest" in schemas, "opensearch_ingest must be in served schemas"
        props = schemas["opensearch_ingest"].get("properties", {})
        assert "hostname" in props, (
            "hostname must be in the served opensearch_ingest schema — missing means "
            "json/accesslog callers can't pass it through the Gateway"
        )

    def test_memory_ingest_derivation_wins_over_passed_hostname(self, monkeypatch, tmp_path):
        """memory format: _derive_hostname_from_image is called even when hostname passed.

        Tests the idx_ingest_memory path in server.py via opensearch_ingest.
        The image must live inside the case evidence dir (path-containment gate).
        """
        case_dir = tmp_path / "case-derive-test"
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        image = evidence_dir / "memdump.raw"
        image.write_bytes(b"\x00" * 16)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

        derive_called = {"n": 0}

        def _spy_derive(path, timeout=120):
            derive_called["n"] += 1
            return ("REGISTRY-DERIVED", "registry")

        # Patch the module attribute — server.py does a local `from … import`
        # inside idx_ingest_memory at call time, which reads from the module
        # object, so patching opensearch_mcp.parse_memory._derive_hostname_from_image
        # is the correct intercept point.
        with patch(
            "opensearch_mcp.parse_memory._derive_hostname_from_image",
            side_effect=_spy_derive,
        ):
            opensearch_ingest(
                path="evidence/memdump.raw",
                format="memory",
                hostname="EXPLICIT-WRONG-HOST",  # should be ignored — derive wins
                dry_run=True,
            )

        assert derive_called["n"] >= 1, (
            "Derivation must be called even when explicit hostname is passed "
            "(M-HOSTNAME: derive-first is authoritative for memory format)"
        )

    def test_json_ingest_passes_hostname_to_server(self, mock_client, monkeypatch, tmp_path):
        """json format: caller-supplied hostname is passed through to idx_ingest_json.

        For formats with no derivable host (json/accesslog/delimited), the
        agent-supplied hostname must reach the server function.
        """
        case_dir = tmp_path / "case-json-test"
        (case_dir / "evidence").mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        monkeypatch.setattr(srv, "_get_active_case", lambda: "case-json-test")

        captured_hostname = []

        def _capture_json(path, hostname, *args, **kwargs):
            captured_hostname.append(hostname)
            return {"status": "preview", "format": "json"}

        with patch("opensearch_mcp.server.idx_ingest_json", side_effect=_capture_json):
            opensearch_ingest(
                path="evidence/events.jsonl",
                format="json",
                hostname="WEB-SRV01",
                dry_run=True,
            )

        assert captured_hostname, "idx_ingest_json was not called"
        assert captured_hostname[0] == "WEB-SRV01", (
            f"hostname must be passed to idx_ingest_json for json format, "
            f"got: {captured_hostname[0]!r}"
        )

def _make_request_error(reason: str) -> _OSRequestError:
    """Construct a RequestError mimicking a 400 query_shard_exception."""
    info = {"error": {"type": "query_shard_exception", "reason": reason}}
    return _OSRequestError(400, "query_shard_exception", info)


class TestMQueryErrSurface:
    """M-QUERYERR: run_opensearch_search must surface query-parse errors as typed
    user-input errors (not internal/opaque messages) at the registry surface."""

    def _run(self, coro):
        loop = _asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_bad_query_string_returns_invalid_input_not_internal(self, mock_client):
        """A query_shard_exception / parsing_exception from OpenSearch must produce
        error='invalid_input' (not 'internal') with a query-parse message."""
        mock_client.search.side_effect = _make_request_error(
            "Failed to parse query [... AND (broken]"
        )
        params = SearchIn(query="... AND (broken", index="case-test-*")
        result = self._run(run_opensearch_search(params))

        assert result.is_error, "Bad query must return a ToolResult with is_error=True"
        import json as _json
        payload = _json.loads(result.content[0].text)
        assert payload.get("error") == "invalid_input", (
            f"Expected invalid_input, got {payload.get('error')!r}. "
            "Must NOT be 'internal'."
        )
        msg = payload.get("message", "")
        assert "parse error" in msg.lower() or "query" in msg.lower(), (
            f"Message must mention parse error, got: {msg!r}"
        )
        # Must NOT say 'check backend logs' (that's the opaque internal message)
        assert "check backend logs" not in payload.get("remediation", ""), (
            "Remediation must not say 'check backend logs' for a user-caused parse error"
        )
        # Must give a quoting/syntax hint
        remediation = payload.get("remediation", "")
        assert remediation, "Remediation must not be empty for a parse error"

    def test_valid_query_still_works(self, mock_client):
        """A syntactically valid query must succeed normally (no regression)."""
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
        }
        params = SearchIn(query="event.code:4624", index="case-test-*")
        result = self._run(run_opensearch_search(params))

        assert not result.is_error, "Valid query must not return an error"

    def test_genuine_backend_error_propagates_for_dispatch_wrapper(self, mock_client):
        """A non-parse RuntimeError (backend/connection failure) must NOT be caught
        by the query-parse ValueError handler — it must propagate so the generic
        dispatch wrapper (registry.py:2518) can label it 'internal'.

        run_opensearch_search only catches ValueError with "Query error:" prefix.
        A connection RuntimeError must re-raise so it reaches the generic except-
        Exception at registry.py:2518 → 'internal' ErrorCode (verified by the live
        agent surface, not this unit test which calls run_opensearch_search directly).
        """
        from opensearchpy.exceptions import ConnectionError as _OSConnErr
        # Simulate a genuine backend connection failure (not a query-parse error)
        mock_client.search.side_effect = _OSConnErr("N/A", "Connection refused")
        params = SearchIn(query="event.code:4624", index="case-test-*")
        # run_opensearch_search must raise RuntimeError (not catch it as invalid_input).
        # The generic dispatch wrapper catches it and returns 'internal'.
        with pytest.raises(RuntimeError, match="connection") as exc_info:
            self._run(run_opensearch_search(params))
        # Confirm it's a connection/backend error, not a query-parse ValueError
        assert not isinstance(exc_info.value, ValueError), (
            "Backend RuntimeError must not be converted to a user-input ValueError"
        )
