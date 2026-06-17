"""Tests for sift_common.audit — AuditWriter and helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

from sift_common.audit import (
    AuditWriter,
    _case_id,
    _sanitize_slug,
    _state_root_for_case,
    _summarize,
    resolve_examiner,
)

# ---------------------------------------------------------------------------
# _sanitize_slug
# ---------------------------------------------------------------------------


class TestSanitizeSlug:
    def test_valid_slug_unchanged(self):
        assert _sanitize_slug("alice") == "alice"

    def test_uppercase_lowered(self):
        assert _sanitize_slug("ALICE") == "alice"

    def test_special_chars_replaced(self):
        assert _sanitize_slug("a.b@c") == "a-b-c"

    def test_truncates_long_slugs(self):
        assert len(_sanitize_slug("a" * 30)) == 20

    def test_empty_becomes_unknown(self):
        assert _sanitize_slug("") == "unknown"

    def test_only_special_chars_becomes_unknown(self):
        assert _sanitize_slug("!!!") == "unknown"

    def test_leading_hyphens_stripped(self):
        assert _sanitize_slug("-test") == "test"


# ---------------------------------------------------------------------------
# resolve_examiner
# ---------------------------------------------------------------------------


class TestResolveExaminer:
    def test_env_sift_examiner(self):
        with mock.patch.dict(os.environ, {"SIFT_EXAMINER": "bob"}, clear=False):
            assert resolve_examiner() == "bob"

    def test_env_sift_analyst_fallback(self):
        with mock.patch.dict(
            os.environ, {"SIFT_ANALYST": "carol"}, clear=False
        ):
            env = os.environ.copy()
            env.pop("SIFT_EXAMINER", None)
            with mock.patch.dict(os.environ, env, clear=True):
                assert resolve_examiner() == "carol"

    def test_os_username_fallback(self):
        env = os.environ.copy()
        env.pop("SIFT_EXAMINER", None)
        env.pop("SIFT_ANALYST", None)
        with mock.patch.dict(os.environ, env, clear=True):
            result = resolve_examiner()
            assert result  # some valid slug


# ---------------------------------------------------------------------------
# _state_root_for_case
# ---------------------------------------------------------------------------


class TestStateRootForCase:
    def test_env_override(self, tmp_path):
        with mock.patch.dict(
            os.environ, {"SIFT_STATE_DIR": str(tmp_path)}, clear=False
        ):
            assert _state_root_for_case(Path("/some/case")) == tmp_path

    def test_tmp_prefix_uses_sift_state_subdir(self):
        env = os.environ.copy()
        env.pop("SIFT_STATE_DIR", None)
        with mock.patch.dict(os.environ, env, clear=True):
            result = _state_root_for_case(Path("/tmp/case1"))
            assert ".sift-state" in str(result)

    def test_non_tmp_uses_default(self):
        env = os.environ.copy()
        env.pop("SIFT_STATE_DIR", None)
        with mock.patch.dict(os.environ, env, clear=True):
            result = _state_root_for_case(Path("/home/user/case1"))
            assert str(result) == "/var/lib/sift"


# ---------------------------------------------------------------------------
# _case_id
# ---------------------------------------------------------------------------


class TestCaseId:
    def test_no_case_yaml_returns_dirname(self, tmp_path):
        assert _case_id(tmp_path) == tmp_path.name

    def test_case_yaml_provides_id(self, tmp_path):
        (tmp_path / "CASE.yaml").write_text("case_id: ABC-123\n")
        assert _case_id(tmp_path) == "ABC-123"

    def test_empty_case_yaml_returns_dirname(self, tmp_path):
        (tmp_path / "CASE.yaml").write_text("")
        assert _case_id(tmp_path) == tmp_path.name


# ---------------------------------------------------------------------------
# _summarize
# ---------------------------------------------------------------------------


class TestSummarize:
    def test_dict_passthrough(self):
        d = {"key": "val"}
        assert _summarize(d) is d

    def test_list_summarized(self):
        result = _summarize([1, 2, 3])
        assert result == {"count": 3, "type": "list"}

    def test_string_truncated(self):
        result = _summarize("x" * 1000)
        assert result["value"] == "x" * 500


# ---------------------------------------------------------------------------
# AuditWriter
# ---------------------------------------------------------------------------


class TestAuditWriter:
    def test_init(self):
        w = AuditWriter("test-mcp")
        assert w.mcp_name == "test-mcp"
        assert w._sequence == 0

    def test_log_returns_none_without_case_dir(self):
        env = os.environ.copy()
        env.pop("SIFT_AUDIT_DIR", None)
        env.pop("SIFT_CASE_DIR", None)
        env.pop("SIFT_DB_ACTIVE", None)
        with mock.patch.dict(os.environ, env, clear=True):
            w = AuditWriter("test-mcp")
            result = w.log("some_tool", {"key": "val"}, "ok")
            assert result is None

    def test_log_returns_audit_id_in_db_authority_mode(self):
        env = os.environ.copy()
        env.pop("SIFT_AUDIT_DIR", None)
        env.pop("SIFT_CASE_DIR", None)
        env["SIFT_DB_ACTIVE"] = "1"
        with mock.patch.dict(os.environ, env, clear=True):
            w = AuditWriter("test-mcp")
            result = w.log("some_tool", {}, "ok")
            assert result is not None

    def test_log_writes_entry_to_audit_dir(self, tmp_path):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        with mock.patch.dict(
            os.environ, {"SIFT_AUDIT_DIR": str(audit_dir)}, clear=False
        ):
            w = AuditWriter("test-mcp")
            aid = w.log("search", {"q": "test"}, {"count": 5})
            assert aid is not None
            log_file = audit_dir / "test-mcp.jsonl"
            assert log_file.exists()
            entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
            assert len(entries) == 1
            assert entries[0]["tool"] == "search"
            assert entries[0]["audit_id"] == aid

    def test_log_with_extra_fields(self, tmp_path):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        with mock.patch.dict(
            os.environ, {"SIFT_AUDIT_DIR": str(audit_dir)}, clear=False
        ):
            w = AuditWriter("test-mcp")
            w.log(
                "cmd",
                {"cmd": "vol3"},
                "ok",
                elapsed_ms=42.5,
                input_files=["/evidence/mem.raw"],
                input_sha256s=["abc123"],
                input_detection_method="heuristic",
                source_evidence="case-001",
                extra={"custom": True},
            )
            entry = json.loads(
                (audit_dir / "test-mcp.jsonl").read_text().strip()
            )
            assert entry["elapsed_ms"] == 42.5
            assert entry["input_files"] == ["/evidence/mem.raw"]
            assert entry["custom"] is True

    def test_get_entries_empty(self):
        env = os.environ.copy()
        env.pop("SIFT_AUDIT_DIR", None)
        env.pop("SIFT_CASE_DIR", None)
        with mock.patch.dict(os.environ, env, clear=True):
            w = AuditWriter("test-mcp")
            assert w.get_entries() == []

    def test_get_entries_filters(self, tmp_path):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        with mock.patch.dict(
            os.environ, {"SIFT_AUDIT_DIR": str(audit_dir)}, clear=False
        ):
            w = AuditWriter("test-mcp")
            w.log("t1", {}, "ok", case_id="case-a")
            w.log("t2", {}, "ok", case_id="case-b")
            all_entries = w.get_entries()
            assert len(all_entries) == 2
            filtered = w.get_entries(case_id="case-a")
            assert len(filtered) == 1
            assert filtered[0]["case_id"] == "case-a"

    def test_reset_counter(self, tmp_path):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        with mock.patch.dict(
            os.environ, {"SIFT_AUDIT_DIR": str(audit_dir)}, clear=False
        ):
            w = AuditWriter("test-mcp")
            w.log("t1", {}, "ok")
            w.reset_counter()
            assert w._sequence == 0

    def test_audit_id_sequence_increments(self, tmp_path):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        with mock.patch.dict(
            os.environ, {"SIFT_AUDIT_DIR": str(audit_dir)}, clear=False
        ):
            w = AuditWriter("test-mcp")
            aid1 = w.log("t1", {}, "ok")
            aid2 = w.log("t2", {}, "ok")
            assert aid1 != aid2

    def test_examiner_override(self, tmp_path):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        with mock.patch.dict(
            os.environ, {"SIFT_AUDIT_DIR": str(audit_dir)}, clear=False
        ):
            w = AuditWriter("test-mcp")
            w.log("t1", {}, "ok", examiner_override="agent-007")
            entry = json.loads(
                (audit_dir / "test-mcp.jsonl").read_text().strip()
            )
            assert entry["examiner"] == "agent-007"

    def test_explicit_audit_dir_used(self, tmp_path):
        audit_dir = tmp_path / "explicit-audit"
        audit_dir.mkdir()
        w = AuditWriter("test-mcp", audit_dir=str(audit_dir))
        aid = w.log("tool", {}, "result")
        assert aid is not None
        assert (audit_dir / "test-mcp.jsonl").exists()
