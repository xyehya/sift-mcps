"""Tests for Plaso parsing (parse_plaso.py)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from opensearch_mcp.parse_plaso import (
    _PLASO_VOLATILE_KEYS,
    _ingest_jsonl,
)


class TestPlasoVolatileKeys:
    def test_contains_expected_keys(self):
        assert "__container_type__" in _PLASO_VOLATILE_KEYS
        assert "__type__" in _PLASO_VOLATILE_KEYS
        assert "pathspec" in _PLASO_VOLATILE_KEYS
        assert "sha256_hash" in _PLASO_VOLATILE_KEYS
        assert "sift.vss_id" in _PLASO_VOLATILE_KEYS


class TestIngestJsonl:
    @patch("opensearch_mcp.parse_plaso.flush_bulk")
    def test_basic_ingest(self, mock_flush, tmp_path):
        """JSONL records are parsed and indexed."""
        mock_flush.return_value = (2, 0)
        jsonl = tmp_path / "output.jsonl"
        records = [
            {
                "timestamp": 1705312800000000,
                "datetime": "2024-01-15T10:00:00+00:00",
                "executable": "CMD.EXE",
                "run_count": 5,
                "parser": "prefetch",
                "data_type": "windows:prefetch:execution",
                "message": "CMD.EXE was executed 5 times",
            },
            {
                "timestamp": 1705316400000000,
                "datetime": "2024-01-15T11:00:00+00:00",
                "executable": "POWERSHELL.EXE",
                "run_count": 3,
                "parser": "prefetch",
                "data_type": "windows:prefetch:execution",
                "message": "POWERSHELL.EXE was executed 3 times",
            },
        ]
        jsonl.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        client = MagicMock()
        count, bf = _ingest_jsonl(jsonl, client, "case-test-prefetch-host1", "HOST1")
        assert count == 2
        assert bf == 0

    @patch("opensearch_mcp.parse_plaso.flush_bulk")
    def test_provenance_injected(self, mock_flush, tmp_path):
        """Provenance fields are set on each record."""
        mock_flush.return_value = (1, 0)
        jsonl = tmp_path / "output.jsonl"
        record = {"timestamp": 123, "parser": "prefetch", "message": "test"}
        jsonl.write_text(json.dumps(record) + "\n")

        client = MagicMock()
        _ingest_jsonl(
            jsonl,
            client,
            "case-test-prefetch-host1",
            "HOST1",
            ingest_audit_id="audit-001",
            pipeline_version="v0.1.0",
            vss_id="vss1",
        )
        actions = mock_flush.call_args[0][1]
        doc = actions[0]["_source"]
        assert doc["host.name"] == "HOST1"
        assert doc["sift.ingest_audit_id"] == "audit-001"
        assert doc["pipeline_version"] == "v0.1.0"
        assert doc["sift.vss_id"] == "vss1"

    @patch("opensearch_mcp.parse_plaso.flush_bulk")
    def test_empty_jsonl(self, mock_flush, tmp_path):
        """Empty JSONL file produces no actions."""
        jsonl = tmp_path / "output.jsonl"
        jsonl.write_text("")

        client = MagicMock()
        count, bf = _ingest_jsonl(jsonl, client, "idx", "HOST1")
        assert count == 0
        assert bf == 0
        mock_flush.assert_not_called()

    @patch("opensearch_mcp.parse_plaso.flush_bulk")
    def test_invalid_json_line_skipped(self, mock_flush, tmp_path):
        """Invalid JSON lines are skipped."""
        mock_flush.return_value = (1, 0)
        jsonl = tmp_path / "output.jsonl"
        jsonl.write_text("not json\n" + json.dumps({"parser": "prefetch"}) + "\n")

        client = MagicMock()
        count, bf = _ingest_jsonl(jsonl, client, "idx", "HOST1")
        assert count == 1

    @patch("opensearch_mcp.parse_plaso.flush_bulk")
    def test_volatile_keys_excluded_from_hash(self, mock_flush, tmp_path):
        """Plaso internal fields do not affect dedup ID."""
        mock_flush.return_value = (1, 0)

        # Two records differing only in __type__ and pathspec
        rec1 = {"parser": "prefetch", "executable": "CMD.EXE", "__type__": "v1", "pathspec": "a"}
        rec2 = {"parser": "prefetch", "executable": "CMD.EXE", "__type__": "v2", "pathspec": "b"}

        jsonl1 = tmp_path / "out1.jsonl"
        jsonl1.write_text(json.dumps(rec1) + "\n")
        jsonl2 = tmp_path / "out2.jsonl"
        jsonl2.write_text(json.dumps(rec2) + "\n")

        client = MagicMock()
        _ingest_jsonl(jsonl1, client, "idx", "HOST1")
        id1 = mock_flush.call_args[0][1][0]["_id"]

        _ingest_jsonl(jsonl2, client, "idx", "HOST1")
        id2 = mock_flush.call_args[0][1][0]["_id"]

        assert id1 == id2  # Same content after volatile keys stripped

    @patch("opensearch_mcp.parse_plaso.flush_bulk")
    def test_reingest_different_audit_id_same_doc_id(self, mock_flush, tmp_path):
        """Re-ingesting same evidence with different audit ID produces same doc ID."""
        mock_flush.return_value = (1, 0)
        record = {"parser": "prefetch", "executable": "CMD.EXE", "run_count": 5}
        jsonl = tmp_path / "output.jsonl"
        jsonl.write_text(json.dumps(record) + "\n")

        client = MagicMock()

        _ingest_jsonl(
            jsonl,
            client,
            "idx",
            "HOST1",
            ingest_audit_id="audit-run-1",
            pipeline_version="v1",
        )
        id1 = mock_flush.call_args[0][1][0]["_id"]

        _ingest_jsonl(
            jsonl,
            client,
            "idx",
            "HOST1",
            ingest_audit_id="audit-run-2",
            pipeline_version="v2",
        )
        id2 = mock_flush.call_args[0][1][0]["_id"]

        assert id1 == id2  # Provenance must not affect dedup


class TestParsePrefetch:
    @patch("opensearch_mcp.parse_plaso._run_plaso")
    @patch("opensearch_mcp.parse_plaso._ingest_jsonl")
    def test_calls_plaso_with_prefetch_parser(self, mock_ingest, mock_run):
        from opensearch_mcp.parse_plaso import parse_prefetch

        mock_run.return_value = Path("/tmp/output.jsonl")
        mock_ingest.return_value = (100, 0)

        client = MagicMock()
        cnt, bf = parse_prefetch(Path("/evidence/Prefetch"), client, "idx", "HOST1")
        assert cnt == 100
        # Verify Plaso called with "prefetch" parser
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] == "prefetch"


class TestParseSrum:
    @patch("opensearch_mcp.parse_plaso._run_plaso")
    @patch("opensearch_mcp.parse_plaso._ingest_jsonl")
    def test_calls_plaso_with_esedb_srum_parser(self, mock_ingest, mock_run):
        from opensearch_mcp.parse_plaso import parse_srum

        mock_run.return_value = Path("/tmp/output.jsonl")
        mock_ingest.return_value = (50, 0)

        client = MagicMock()
        cnt, bf = parse_srum(Path("/evidence/SRUDB.dat"), client, "idx", "HOST1")
        assert cnt == 50
        # Verify Plaso called with "esedb/srum" parser
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] == "esedb/srum"


class TestSrumApplicationFlagWiring:
    """F9 (LIVE-CONFIRMED): _ingest_jsonl flags unresolved numeric SRUM
    network-usage application ids, gated on data_type so non-SRUM plaso
    records (the shared-path consumers) are untouched."""

    @patch("opensearch_mcp.parse_plaso.flush_bulk")
    def test_srum_numeric_application_flagged(self, mock_flush, tmp_path):
        mock_flush.return_value = (1, 0)
        jsonl = tmp_path / "srum.jsonl"
        rec = {
            "timestamp": 1,
            "parser": "esedb",
            "data_type": "windows:srum:network_usage",
            "application": 1,
            "user_identifier": 2,
            "message": "Application: 1",
        }
        jsonl.write_text(json.dumps(rec) + "\n")
        _ingest_jsonl(jsonl, MagicMock(), "case-test-srum-host1", "HOST1")
        doc = mock_flush.call_args[0][1][0]["_source"]
        assert doc["application_unresolved"] is True
        assert doc["application_id"] == "1"
        assert doc["application"] == 1  # raw value preserved

    @patch("opensearch_mcp.parse_plaso.flush_bulk")
    def test_srum_resolved_name_untouched(self, mock_flush, tmp_path):
        mock_flush.return_value = (1, 0)
        jsonl = tmp_path / "srum.jsonl"
        rec = {
            "timestamp": 1,
            "parser": "esedb",
            "data_type": "windows:srum:network_usage",
            "application": "TermService",
            "user_identifier": "S-1-5-20",
            "message": "Application: TermService",
        }
        jsonl.write_text(json.dumps(rec) + "\n")
        _ingest_jsonl(jsonl, MagicMock(), "case-test-srum-host1", "HOST1")
        doc = mock_flush.call_args[0][1][0]["_source"]
        assert "application_unresolved" not in doc
        assert "application_id" not in doc
        assert doc["application"] == "TermService"

    @patch("opensearch_mcp.parse_plaso.flush_bulk")
    def test_non_srum_plaso_record_untouched(self, mock_flush, tmp_path):
        """A non-SRUM record that happens to carry a numeric `application`
        must NOT be flagged — the data_type guard scopes the flag to SRUM."""
        mock_flush.return_value = (1, 0)
        jsonl = tmp_path / "other.jsonl"
        rec = {
            "timestamp": 1,
            "parser": "prefetch",
            "data_type": "windows:prefetch:execution",
            "application": 1,  # numeric, but NOT a SRUM record
            "message": "unrelated",
        }
        jsonl.write_text(json.dumps(rec) + "\n")
        _ingest_jsonl(jsonl, MagicMock(), "case-test-prefetch-host1", "HOST1")
        doc = mock_flush.call_args[0][1][0]["_source"]
        assert "application_unresolved" not in doc
        assert "application_id" not in doc

    @patch("opensearch_mcp.parse_plaso.flush_bulk")
    def test_record_without_data_type_untouched(self, mock_flush, tmp_path):
        """No data_type at all → guard skips the flag entirely."""
        mock_flush.return_value = (1, 0)
        jsonl = tmp_path / "nodt.jsonl"
        rec = {"timestamp": 1, "parser": "esedb", "application": 1, "message": "x"}
        jsonl.write_text(json.dumps(rec) + "\n")
        _ingest_jsonl(jsonl, MagicMock(), "idx", "HOST1")
        doc = mock_flush.call_args[0][1][0]["_source"]
        assert "application_unresolved" not in doc

    @patch("opensearch_mcp.parse_plaso.flush_bulk")
    def test_mixed_batch_only_srum_numeric_flagged(self, mock_flush, tmp_path):
        """A realistic mixed batch: numeric-SRUM flagged, named-SRUM and
        non-SRUM untouched — all in one ingest pass."""
        mock_flush.return_value = (3, 0)
        jsonl = tmp_path / "mixed.jsonl"
        recs = [
            {"timestamp": 1, "data_type": "windows:srum:network_usage",
             "application": 1, "message": "Application: 1"},
            {"timestamp": 2, "data_type": "windows:srum:network_usage",
             "application": "TermService", "message": "Application: TermService"},
            {"timestamp": 3, "data_type": "windows:prefetch:execution",
             "application": 1, "message": "prefetch"},
        ]
        jsonl.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
        _ingest_jsonl(jsonl, MagicMock(), "idx", "HOST1")
        actions = mock_flush.call_args[0][1]
        by_ts = {a["_source"]["timestamp"]: a["_source"] for a in actions}
        assert by_ts[1]["application_unresolved"] is True
        assert by_ts[1]["application_id"] == "1"
        assert "application_unresolved" not in by_ts[2]
        assert "application_unresolved" not in by_ts[3]
