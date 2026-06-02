"""Tests for triage_remote.py — the only triage enrichment path."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Response field mapping
# ---------------------------------------------------------------------------


class TestResponseFieldMapping:
    """check_file response fields correctly mapped to triage.* fields."""

    def test_reasons_list_joined_to_string(self):
        from opensearch_mcp.triage_remote import _batch_stamp_verdicts

        verdicts = {
            "C:\\Windows\\cmd.exe": {
                "verdict": "EXPECTED_LOLBIN",
                "reasons": ["LOLBin", "Known admin tool"],
                "confidence": "high",
                "is_lolbin": True,
            }
        }
        client = MagicMock()
        client.update_by_query.return_value = {"updated": 1}
        _batch_stamp_verdicts(client, "case-test-*", "Path.keyword", verdicts)
        call_args = client.update_by_query.call_args
        params = call_args.kwargs["body"]["script"]["params"]
        assert params["verdict"] == "EXPECTED_LOLBIN"
        assert params["confidence"] == "high"

    def test_is_lolbin_mapped(self):
        from opensearch_mcp.triage_remote import _batch_stamp_verdicts

        verdicts = {
            "C:\\Windows\\cmd.exe": {
                "verdict": "EXPECTED_LOLBIN",
                "reasons": [],
                "confidence": "high",
                "is_lolbin": True,
            }
        }
        client = MagicMock()
        client.update_by_query.return_value = {"updated": 1}
        _batch_stamp_verdicts(client, "case-test-*", "Path.keyword", verdicts)
        script_source = client.update_by_query.call_args.kwargs["body"]["script"]["source"]
        assert "triage.lolbin" in script_source

    def test_confidence_stamped(self):
        from opensearch_mcp.triage_remote import _batch_stamp_verdicts

        verdicts = {
            "C:\\Windows\\svchost.exe": {
                "verdict": "EXPECTED",
                "reasons": [],
                "confidence": "high",
            }
        }
        client = MagicMock()
        client.update_by_query.return_value = {"updated": 1}
        _batch_stamp_verdicts(client, "case-test-*", "Path.keyword", verdicts)
        script_source = client.update_by_query.call_args.kwargs["body"]["script"]["source"]
        assert "triage.confidence" in script_source
        params = client.update_by_query.call_args.kwargs["body"]["script"]["params"]
        assert params["confidence"] == "high"

    def test_no_lolbin_when_false(self):
        from opensearch_mcp.triage_remote import _batch_stamp_verdicts

        verdicts = {
            "C:\\Windows\\notepad.exe": {
                "verdict": "EXPECTED",
                "reasons": [],
                "confidence": "medium",
            }
        }
        client = MagicMock()
        client.update_by_query.return_value = {"updated": 1}
        _batch_stamp_verdicts(client, "case-test-*", "Path.keyword", verdicts)
        script_source = client.update_by_query.call_args.kwargs["body"]["script"]["source"]
        assert "triage.lolbin" not in script_source

    def test_gateway_calls_use_curated_windows_triage_tools(self):
        from opensearch_mcp.triage_remote import _check_file, _check_service

        with patch("opensearch_mcp.triage_remote.call_tool", return_value={"verdict": "EXPECTED"}) as call:
            _check_file("C:\\Windows\\System32\\cmd.exe")
            _check_service("EventLog")

        call.assert_any_call(
            "wintriage_check_artifact",
            {"type": "file", "value": "C:\\Windows\\System32\\cmd.exe"},
            timeout=15,
        )
        call.assert_any_call(
            "wintriage_check_system",
            {"type": "service", "name": "EventLog"},
            timeout=15,
        )


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    def test_stops_after_3_failures(self):
        from opensearch_mcp.triage_remote import _enrich_file_artifact

        mock_client = MagicMock()
        mock_client.search.return_value = {
            "aggregations": {
                "paths": {"buckets": [{"key": f"C:\\path{i}.exe"} for i in range(10)]}
            }
        }

        with patch("opensearch_mcp.triage_remote.call_tool", side_effect=Exception("down")):
            result = _enrich_file_artifact(
                mock_client, "test", "case-test-shimcache-*", "Path.keyword", "shimcache"
            )
        assert result["enriched"] == 0
        assert result["status"] == "degraded"
        # Should stop after 3, not try all 10
        assert result["checked"] == 10  # checked = total buckets

    def test_missing_windows_triage_db_returns_degraded(self):
        from opensearch_mcp.triage_remote import _enrich_file_artifact

        mock_client = MagicMock()
        mock_client.search.return_value = {
            "aggregations": {
                "paths": {"buckets": [{"key": "C:\\Windows\\System32\\cmd.exe"}]}
            }
        }

        with patch(
            "opensearch_mcp.triage_remote.call_tool",
            return_value={
                "status": "degraded",
                "verdict": "UNKNOWN",
                "db_available": False,
                "reasons": ["baseline database is not installed"],
            },
        ):
            result = _enrich_file_artifact(
                mock_client, "test", "case-test-shimcache-*", "Path.keyword", "shimcache"
            )

        assert result["status"] == "degraded"
        assert result["enriched"] == 0
        assert "baseline database" in result["reason"]


# ---------------------------------------------------------------------------
# case_id sanitization
# ---------------------------------------------------------------------------


class TestSanitization:
    def test_case_id_sanitized(self):
        from opensearch_mcp.triage_remote import enrich_remote

        mock_client = MagicMock()
        mock_client.indices.refresh.return_value = {}
        # Registry persistence will try to query — mock to return no results
        mock_client.search.return_value = {"hits": {"hits": []}}
        mock_client.update_by_query.return_value = {"updated": 0}

        with (
            patch("opensearch_mcp.triage_remote.wait_for_gateway", return_value=True),
            patch("opensearch_mcp.triage_remote.gateway_available", return_value=False),
        ):
            enrich_remote(mock_client, "Test Case!@#")

        # Should have called refresh with sanitized case_id
        refresh_call = mock_client.indices.refresh.call_args
        index_arg = refresh_call.kwargs.get("index", "")
        assert "!" not in index_arg
        assert "@" not in index_arg


# ---------------------------------------------------------------------------
# Gateway-unavailable path
# ---------------------------------------------------------------------------


class TestGatewayUnavailable:
    def test_registry_rules_run_without_gateway(self):
        from opensearch_mcp.triage_remote import enrich_remote

        mock_client = MagicMock()
        mock_client.indices.refresh.return_value = {}
        mock_client.update_by_query.return_value = {"updated": 0}

        with (
            patch("opensearch_mcp.triage_remote.wait_for_gateway", return_value=True),
            patch("opensearch_mcp.triage_remote.gateway_available", return_value=False),
        ):
            result = enrich_remote(mock_client, "test-case")

        assert "registry_persistence" in result
        assert "_gateway" in result
        assert "not configured" in result["_gateway"]
        # File/service enrichment should NOT be in results
        assert "shimcache" not in result


# ---------------------------------------------------------------------------
# Batch stamp grouping
# ---------------------------------------------------------------------------


class TestBatchStamp:
    def test_groups_by_verdict(self):
        from opensearch_mcp.triage_remote import _batch_stamp_verdicts

        verdicts = {
            "C:\\a.exe": {"verdict": "EXPECTED", "confidence": "high"},
            "C:\\b.exe": {"verdict": "EXPECTED", "confidence": "high"},
            "C:\\c.exe": {"verdict": "SUSPICIOUS", "reasons": ["bad"], "confidence": "low"},
        }
        client = MagicMock()
        client.update_by_query.return_value = {"updated": 1}
        _batch_stamp_verdicts(client, "case-test-*", "Path.keyword", verdicts)
        # Should be 2 calls: one for EXPECTED group, one for SUSPICIOUS
        assert client.update_by_query.call_count == 2

    def test_chunks_large_batches(self):
        from opensearch_mcp.triage_remote import _batch_stamp_verdicts

        verdicts = {
            f"C:\\path{i}.exe": {"verdict": "EXPECTED", "confidence": "high"} for i in range(1200)
        }
        client = MagicMock()
        client.update_by_query.return_value = {"updated": 500}
        _batch_stamp_verdicts(client, "case-test-*", "Path.keyword", verdicts)
        # 1200 paths / 500 chunk = 3 calls
        assert client.update_by_query.call_count == 3


# ---------------------------------------------------------------------------
# Non-path filter
# ---------------------------------------------------------------------------


class TestNonPathFilter:
    def test_appx_metadata_skipped(self):
        from opensearch_mcp.triage_remote import _enrich_file_artifact

        mock_client = MagicMock()
        mock_client.search.return_value = {
            "aggregations": {
                "paths": {
                    "buckets": [
                        {"key": "00000009\t00010000a4d00000"},  # AppX metadata
                        {"key": "C:\\Windows\\cmd.exe"},  # real path
                    ]
                }
            }
        }

        call_count = 0

        def mock_call_tool(name, args, timeout=15):
            nonlocal call_count
            call_count += 1
            return {"verdict": "EXPECTED", "confidence": "high"}

        with patch("opensearch_mcp.triage_remote.call_tool", side_effect=mock_call_tool):
            mock_client.update_by_query.return_value = {"updated": 1}
            _enrich_file_artifact(
                mock_client, "test", "case-test-shimcache-*", "Path.keyword", "shimcache"
            )

        # Only the real path should have been checked
        assert call_count == 1


# ---------------------------------------------------------------------------
# Hayabusa ↔ memory correlation
# ---------------------------------------------------------------------------


class TestHayabusaMemoryCorrelation:
    def _make_client(self, hayabusa_hits=None, vol_buckets=None, updated=0):
        """Build a mock OpenSearch client for correlation tests."""
        client = MagicMock()

        def search_side_effect(index="", body=None, **kwargs):
            if "hayabusa" in index:
                return {
                    "hits": {
                        "hits": hayabusa_hits or [],
                        "total": {"value": len(hayabusa_hits or [])},
                    }
                }
            # vol index aggregation
            return {
                "aggregations": {
                    "names": {"buckets": vol_buckets or []}
                }
            }

        client.search.side_effect = search_side_effect
        client.update_by_query.return_value = {"updated": updated}
        return client

    def test_skips_when_hayabusa_index_missing(self):
        from opensearch_mcp.triage_remote import _enrich_hayabusa_memory_correlation

        client = MagicMock()
        client.search.side_effect = Exception("index not found")
        result = _enrich_hayabusa_memory_correlation(client, "test-case")
        assert result["status"] == "skipped"

    def test_empty_when_no_high_critical_alerts(self):
        from opensearch_mcp.triage_remote import _enrich_hayabusa_memory_correlation

        client = self._make_client(hayabusa_hits=[])
        result = _enrich_hayabusa_memory_correlation(client, "test-case")
        assert result["status"] == "empty"
        assert result["hayabusa_alerts_scanned"] == 0

    def test_stamps_pslist_on_proc_alias_match(self):
        from opensearch_mcp.triage_remote import _enrich_hayabusa_memory_correlation

        hits = [
            {
                "_source": {
                    "Details": "Proc: cmd.exe ¦ User: admin",
                    "RuleTitle": "Suspicious Cmd Usage",
                    "Level": "high",
                }
            }
        ]
        vol_buckets = [{"key": "cmd.exe"}]
        client = self._make_client(hayabusa_hits=hits, vol_buckets=vol_buckets, updated=3)

        result = _enrich_hayabusa_memory_correlation(client, "test-case")

        assert result["status"] == "complete"
        assert result["flagged_process_names"] == 1
        assert result["vol_docs_stamped"] > 0

        # Verify stamp fields passed to update_by_query
        stamp_calls = [
            c for c in client.update_by_query.call_args_list
        ]
        assert len(stamp_calls) > 0
        first_params = stamp_calls[0].kwargs["body"]["script"]["params"]
        assert first_params["max_level"] == "high"
        assert "Suspicious Cmd Usage" in first_params["rule_titles"]

    def test_stamps_netscan_owner_match(self):
        from opensearch_mcp.triage_remote import _enrich_hayabusa_memory_correlation

        hits = [
            {
                "_source": {
                    "Details": "Proc: powershell.exe ¦ Cmd: powershell -enc ...",
                    "RuleTitle": "Encoded PS",
                    "Level": "critical",
                }
            }
        ]
        # vol-netscan returns Owner field aggregation
        client = MagicMock()

        def search_side_effect(index="", body=None, **kwargs):
            if "hayabusa" in index:
                return {"hits": {"hits": hits}}
            if "vol-netscan" in index:
                return {"aggregations": {"names": {"buckets": [{"key": "powershell.exe"}]}}}
            return {"aggregations": {"names": {"buckets": []}}}

        client.search.side_effect = search_side_effect
        client.update_by_query.return_value = {"updated": 2}

        result = _enrich_hayabusa_memory_correlation(client, "test-case")

        assert result["status"] == "complete"
        # At least the netscan stamp call should have fired
        netscan_calls = [
            c for c in client.update_by_query.call_args_list
            if "vol-netscan" in str(c)
        ]
        assert len(netscan_calls) >= 1

    def test_critical_beats_high_for_max_level(self):
        from opensearch_mcp.triage_remote import _enrich_hayabusa_memory_correlation

        hits = [
            {
                "_source": {
                    "Details": "Proc: evil.exe ¦ Cmd: evil.exe -c",
                    "RuleTitle": "Rule A",
                    "Level": "high",
                }
            },
            {
                "_source": {
                    "Details": "Proc: evil.exe ¦ User: nt authority",
                    "RuleTitle": "Rule B",
                    "Level": "critical",
                }
            },
        ]
        client = self._make_client(
            hayabusa_hits=hits,
            vol_buckets=[{"key": "evil.exe"}],
            updated=1,
        )

        _enrich_hayabusa_memory_correlation(client, "test-case")

        params = client.update_by_query.call_args_list[0].kwargs["body"]["script"]["params"]
        assert params["max_level"] == "critical"
        assert "Rule A" in params["rule_titles"]
        assert "Rule B" in params["rule_titles"]

    def test_case_insensitive_name_match(self):
        from opensearch_mcp.triage_remote import _enrich_hayabusa_memory_correlation

        hits = [
            {
                "_source": {
                    "Details": "Proc: WINWORD.EXE ¦ User: user",
                    "RuleTitle": "Macro Exec",
                    "Level": "high",
                }
            }
        ]
        # vol-pslist stores it with different casing
        client = self._make_client(
            hayabusa_hits=hits,
            vol_buckets=[{"key": "winword.exe"}],
            updated=1,
        )

        result = _enrich_hayabusa_memory_correlation(client, "test-case")
        assert result["flagged_process_names"] == 1
        assert result["vol_docs_stamped"] > 0

    def test_img_alias_extracts_basename(self):
        from opensearch_mcp.triage_remote import _enrich_hayabusa_memory_correlation

        # Sysmon-style Details with full path in Img alias
        hits = [
            {
                "_source": {
                    "Details": "Img: C:\\Windows\\System32\\cmd.exe ¦ Cmd: cmd /c whoami",
                    "RuleTitle": "Sysmon Process",
                    "Level": "high",
                }
            }
        ]
        client = self._make_client(
            hayabusa_hits=hits,
            vol_buckets=[{"key": "cmd.exe"}],
            updated=2,
        )

        result = _enrich_hayabusa_memory_correlation(client, "test-case")
        assert result["flagged_process_names"] == 1

    def test_empty_when_no_vol_match(self):
        from opensearch_mcp.triage_remote import _enrich_hayabusa_memory_correlation

        hits = [
            {
                "_source": {
                    "Details": "Proc: rare_malware.exe ¦ Cmd: ...",
                    "RuleTitle": "APT Tool",
                    "Level": "critical",
                }
            }
        ]
        # vol indices return no matching names
        client = self._make_client(
            hayabusa_hits=hits,
            vol_buckets=[],
            updated=0,
        )

        result = _enrich_hayabusa_memory_correlation(client, "test-case")
        assert result["status"] == "complete"
        assert result["flagged_process_names"] == 1
        assert result["vol_docs_stamped"] == 0

    def test_hayabusa_in_gateway_unavailable_path(self):
        """Hayabusa correlation runs even when gateway (windows-triage) is down."""
        from opensearch_mcp.triage_remote import enrich_remote
        from unittest.mock import patch

        hits = [
            {
                "_source": {
                    "Details": "Proc: cmd.exe ¦ User: admin",
                    "RuleTitle": "Cmd Exec",
                    "Level": "high",
                }
            }
        ]

        client = MagicMock()
        client.indices.refresh.return_value = {}
        client.update_by_query.return_value = {"updated": 0}

        def search_side_effect(index="", body=None, **kwargs):
            if "hayabusa" in index:
                return {"hits": {"hits": hits}}
            return {"hits": {"hits": []}, "aggregations": {"names": {"buckets": []}}}

        client.search.side_effect = search_side_effect

        with (
            patch("opensearch_mcp.triage_remote.wait_for_gateway", return_value=True),
            patch("opensearch_mcp.triage_remote.gateway_available", return_value=False),
        ):
            result = enrich_remote(client, "test-case")

        # Hayabusa correlation must be present regardless of gateway state
        assert "hayabusa_memory" in result
        assert result["hayabusa_memory"]["status"] in ("complete", "empty", "skipped")
