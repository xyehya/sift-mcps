"""Characterization tests for opensearch_mcp.search_format (D5/XYE-73).

These tests pin the exact behavior of the extracted search-result formatting
helpers BEFORE the move and continue to verify it after. They exercise the
module directly (not via server.py) so regressions in the formatting layer are
caught even if server-level wiring changes.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

import opensearch_mcp.search_format as sf


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
        result = sf._strip_hits(hits)
        assert len(result) == 1
        doc = result[0]
        assert doc["_id"] == "doc1"
        assert doc["_index"] == "case-test-evtx-host1"
        assert doc["event.code"] == 4624
        assert doc["user.name"] == "admin"

    def test_empty_hits_returns_empty(self):
        assert sf._strip_hits([]) == []

    def test_missing_source_returns_id_and_index_only(self):
        hits = [{"_id": "x", "_index": "idx"}]
        result = sf._strip_hits(hits)
        assert result[0]["_id"] == "x"
        assert result[0]["_index"] == "idx"

    def test_excluded_fields_are_stripped(self):
        # Fields in _SEARCH_EXCLUDE_FIELDS must not appear in compact output.
        hits = [
            {
                "_id": "1",
                "_index": "case-test-evtx-h",
                "_source": {
                    "event.code": 4624,
                    "Payload": "<xml>raw</xml>",      # excluded
                    "ExtraFieldInfo": "dup",           # excluded
                    "Keywords": "AuditSuccess",        # excluded
                },
            }
        ]
        result = sf._strip_hits(hits)
        assert "Payload" not in result[0]
        assert "ExtraFieldInfo" not in result[0]
        assert "Keywords" not in result[0]
        assert result[0]["event.code"] == 4624

    def test_long_values_are_truncated(self):
        long_val = "A" * 600
        hits = [{"_id": "1", "_index": "idx", "_source": {"Description": long_val}}]
        result = sf._strip_hits(hits)
        assert result[0]["Description"].endswith("...")
        assert len(result[0]["Description"]) == sf._MAX_FIELD_CHARS + 3
        assert "_truncated" in result[0]
        assert "Description" in result[0]["_truncated"]

    def test_short_values_are_not_truncated(self):
        hits = [{"_id": "1", "_index": "idx", "_source": {"Name": "short"}}]
        result = sf._strip_hits(hits)
        assert result[0]["Name"] == "short"
        assert "_truncated" not in result[0]

    def test_full_mode_includes_excluded_fields(self):
        # Passing an empty frozenset bypasses the exclusion list entirely.
        hits = [
            {
                "_id": "1",
                "_index": "idx",
                "_source": {"Payload": "raw", "event.code": 4624},
            }
        ]
        result = sf._strip_hits(hits, exclude_fields=frozenset(), max_chars=999999)
        assert result[0]["Payload"] == "raw"

    def test_non_string_values_coerced_for_length_check(self):
        # Integer values must be length-checked after str() coercion, not crash.
        hits = [{"_id": "1", "_index": "idx", "_source": {"count": 42}}]
        result = sf._strip_hits(hits)
        assert result[0]["count"] == 42  # short — passed through as-is


# ---------------------------------------------------------------------------
# _hoist_constant_fields
# ---------------------------------------------------------------------------


class TestHoistConstantFields:
    def test_hoists_field_constant_across_all_hits(self):
        docs = [
            {"_id": "1", "_index": "i", "sift.case_id": "C1", "event.code": 4624},
            {"_id": "2", "_index": "i", "sift.case_id": "C1", "event.code": 4625},
        ]
        common, slim = sf._hoist_constant_fields(docs)
        assert common == {"sift.case_id": "C1"}
        assert all("sift.case_id" not in d for d in slim)
        assert slim[0]["event.code"] == 4624

    def test_mixed_values_are_not_hoisted(self):
        docs = [
            {"_id": "1", "sift.case_id": "C1"},
            {"_id": "2", "sift.case_id": "C2"},
        ]
        common, slim = sf._hoist_constant_fields(docs)
        assert common == {}
        assert slim[0]["sift.case_id"] == "C1"

    def test_field_absent_from_some_hits_is_not_hoisted(self):
        docs = [
            {"_id": "1", "sift.provenance_id": "P"},
            {"_id": "2"},  # missing the candidate field
        ]
        common, _ = sf._hoist_constant_fields(docs)
        assert "sift.provenance_id" not in common

    def test_empty_docs_returns_empty_common_and_same_list(self):
        common, slim = sf._hoist_constant_fields([])
        assert common == {}
        assert slim == []

    def test_id_and_index_are_never_hoisted(self):
        # Even if _id/_index appear in the candidate list they must not be hoisted.
        docs = [{"_id": "x", "_index": "i"}, {"_id": "x", "_index": "i"}]
        common, _ = sf._hoist_constant_fields(
            docs, candidate_fields=("_id", "_index", "sift.case_id")
        )
        assert "_id" not in common
        assert "_index" not in common

    def test_both_provenance_id_and_case_id_hoisted(self):
        docs = [
            {"_id": "1", "sift.case_id": "C", "sift.provenance_id": "P", "x": 1},
            {"_id": "2", "sift.case_id": "C", "sift.provenance_id": "P", "x": 2},
        ]
        common, slim = sf._hoist_constant_fields(docs)
        assert common == {"sift.case_id": "C", "sift.provenance_id": "P"}
        assert "sift.case_id" not in slim[0]
        assert "sift.provenance_id" not in slim[0]
        assert slim[0]["x"] == 1

    def test_single_hit_is_hoisted(self):
        docs = [{"_id": "1", "sift.case_id": "C", "event.code": 4624}]
        common, slim = sf._hoist_constant_fields(docs)
        assert common == {"sift.case_id": "C"}
        assert "sift.case_id" not in slim[0]


# ---------------------------------------------------------------------------
# _payload_bytes
# ---------------------------------------------------------------------------


class TestPayloadBytes:
    def test_small_payload(self):
        assert sf._payload_bytes([{"a": 1}]) > 0

    def test_empty_list_is_small(self):
        assert sf._payload_bytes([]) == 2  # "[]" in UTF-8

    def test_large_payload_larger_than_small(self):
        small = [{"x": 1}]
        large = [{"x": "A" * 10000}]
        assert sf._payload_bytes(large) > sf._payload_bytes(small)


# ---------------------------------------------------------------------------
# _save_full_results
# ---------------------------------------------------------------------------


class TestSaveFullResults:
    def test_writes_json_and_returns_relative_ref(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case-test"
        (case_dir / "agent").mkdir(parents=True)
        # Patch active_case_dir inside search_format's lazy import target
        with patch("opensearch_mcp.server.active_case_dir", return_value=str(case_dir)):
            ref = sf._save_full_results("searches", [{"_id": "1", "x": 2}])
        assert ref is not None
        assert ref.startswith("agent/searches/search_")
        assert not ref.startswith("/")
        saved = case_dir / ref
        assert saved.is_file()
        data = json.loads(saved.read_text())
        assert data[0]["x"] == 2

    def test_no_case_dir_returns_none(self):
        with patch("opensearch_mcp.server.active_case_dir", return_value=""):
            result = sf._save_full_results("searches", [{"x": 1}])
        assert result is None

    def test_aggregations_prefix(self, tmp_path):
        case_dir = tmp_path / "case-test"
        (case_dir / "agent").mkdir(parents=True)
        with patch("opensearch_mcp.server.active_case_dir", return_value=str(case_dir)):
            ref = sf._save_full_results("aggregations", [{"key": "host-a", "count": 5}])
        assert ref is not None
        assert ref.startswith("agent/aggregations/aggregation_")


# ---------------------------------------------------------------------------
# _autosave_or_inline
# ---------------------------------------------------------------------------


class TestAutosaveOrInline:
    def _note_builder(self, fp, n, total):
        return f"Saved {total} to {fp}; showing {n} inline."

    def test_small_set_stays_inline(self):
        items = [{"x": i} for i in range(5)]
        result, path, note = sf._autosave_or_inline(
            "searches",
            items,
            count_threshold=20,
            byte_cap=sf._SEARCH_AUTOSAVE_MAX_BYTES,
            inline_n=20,
            note_builder=self._note_builder,
        )
        assert result == items
        assert path is None
        assert note is None

    def test_large_set_triggers_save(self, tmp_path):
        case_dir = tmp_path / "case-test"
        (case_dir / "agent").mkdir(parents=True)
        items = [{"x": i} for i in range(50)]
        with patch("opensearch_mcp.server.active_case_dir", return_value=str(case_dir)):
            result, path, note = sf._autosave_or_inline(
                "searches",
                items,
                count_threshold=20,
                byte_cap=sf._SEARCH_AUTOSAVE_MAX_BYTES,
                inline_n=20,
                note_builder=self._note_builder,
            )
        assert path is not None
        assert not path.startswith("/")
        assert len(result) <= 20
        assert "50" in note

    def test_save_failure_caps_inline_and_adds_note(self):
        items = [{"x": i} for i in range(50)]
        with patch("opensearch_mcp.server.active_case_dir", return_value=""):
            result, path, note = sf._autosave_or_inline(
                "searches",
                items,
                count_threshold=20,
                byte_cap=sf._SEARCH_AUTOSAVE_MAX_BYTES,
                inline_n=20,
                note_builder=self._note_builder,
            )
        # Save failed (no case dir) — but preview MUST still be capped, not full set.
        assert path is None
        assert len(result) <= 20
        assert note is not None
        assert "50" in note

    def test_byte_cap_triggers_even_for_small_item_count(self, tmp_path):
        case_dir = tmp_path / "case-test"
        (case_dir / "agent").mkdir(parents=True)
        # 3 items but each very large (exceeds 64 KiB byte cap)
        items = [{"blob": "X" * 30_000} for _ in range(3)]
        with patch("opensearch_mcp.server.active_case_dir", return_value=str(case_dir)):
            result, path, note = sf._autosave_or_inline(
                "searches",
                items,
                count_threshold=20,  # count=3 is below threshold
                byte_cap=64 * 1024,   # but ~90 KiB > 64 KiB byte cap
                inline_n=20,
                note_builder=self._note_builder,
            )
        # The byte cap must have triggered even though count < threshold.
        assert path is not None or note is not None


# ---------------------------------------------------------------------------
# Constants sanity-checks
# ---------------------------------------------------------------------------


class TestConstants:
    def test_search_exclude_fields_is_frozenset(self):
        assert isinstance(sf._SEARCH_EXCLUDE_FIELDS, frozenset)
        assert "Payload" in sf._SEARCH_EXCLUDE_FIELDS
        assert "ExtraFieldInfo" in sf._SEARCH_EXCLUDE_FIELDS

    def test_autosave_thresholds_are_positive(self):
        assert sf._SEARCH_AUTOSAVE_THRESHOLD > 0
        assert sf._AGG_AUTOSAVE_THRESHOLD > 0
        assert sf._SEARCH_AUTOSAVE_MAX_BYTES > 0
        assert sf._AGG_AUTOSAVE_MAX_BYTES > 0

    def test_inline_top_n_leq_autosave_threshold(self):
        # inline cap must not exceed the threshold that triggers autosave
        assert sf._SEARCH_INLINE_TOP_N <= sf._SEARCH_AUTOSAVE_THRESHOLD
        assert sf._AGG_INLINE_TOP_N <= sf._AGG_AUTOSAVE_THRESHOLD

    def test_hoistable_fields_contains_expected_candidates(self):
        assert "sift.case_id" in sf._HOISTABLE_CONSTANT_FIELDS
        assert "sift.provenance_id" in sf._HOISTABLE_CONSTANT_FIELDS
