"""Tests for sift_common.audit — AuditWriter and helpers."""

from __future__ import annotations

import json
import os
import threading
from datetime import timezone
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


# ---------------------------------------------------------------------------
# AuditWriter — adversarial / forensic-durability tests (XYE-65 / C1)
#
# CodeGuard (privacy, logging, data-storage) requirements applied:
#   - No secrets, credentials, or sensitive paths in fixtures.
#   - Fail-closed assertions: a write failure must return None, never silently
#     succeed; duplicate IDs must never appear.
#   - All synthetic examiner names and audit payloads are obviously synthetic.
# ---------------------------------------------------------------------------


def _today_utc() -> str:
    """Return today's UTC date string in YYYYMMDD format (same as AuditWriter)."""
    from datetime import datetime

    return datetime.now(timezone.utc).strftime("%Y%m%d")


def _mcp_prefix(mcp_name: str) -> str:
    """Derive the audit-ID prefix from an MCP name (mirrors AuditWriter logic)."""
    return mcp_name.replace("-mcp", "").replace("-", "")


class TestAuditWriterAdversarial:
    """Forensic-durability tests for AuditWriter's JSONL mirror.

    These tests probe failure modes that could silently corrupt the audit
    chain: sidecar corruption, JSONL resume, malformed lines, fsync failure,
    date rollover, and concurrent writers.  All tests must pass without
    weakening DB-authority behavior.
    """

    # ------------------------------------------------------------------
    # Corrupted .seq sidecar
    # ------------------------------------------------------------------

    def test_corrupted_seq_sidecar_non_utf8_falls_back_to_jsonl_scan(self, tmp_path):
        """A sidecar with non-UTF-8 bytes (UnicodeDecodeError) must not abort
        sequencing.

        PRODUCTION BUG EXPOSED AND FIXED: the original code caught only
        (json.JSONDecodeError, OSError).  A non-UTF-8 sidecar raised
        UnicodeDecodeError, which propagated uncaught and silently reset the
        sequence to 0, producing duplicate IDs after restart.  The fix adds
        UnicodeDecodeError and ValueError to the except tuple.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"
        today = _today_utc()
        prefix = _mcp_prefix(mcp)

        # Write an initial entry to establish a known sequence baseline.
        w = AuditWriter(mcp, audit_dir=str(audit_dir))
        aid1 = w.log("t1", {}, "ok", examiner_override="analyst")
        assert aid1 is not None
        assert aid1 == f"{prefix}-analyst-{today}-001"

        # Corrupt the sidecar with non-UTF-8 bytes (e.g. BOM + garbage).
        seq_file = audit_dir / f"{mcp}.seq"
        seq_file.write_bytes(b"\xff\xfeNOT JSON")

        # Create a fresh writer (simulates server restart after crash/corruption).
        w2 = AuditWriter(mcp, audit_dir=str(audit_dir))
        aid2 = w2.log("t2", {}, "ok", examiner_override="analyst")
        assert aid2 is not None

        # JSONL scan must have found seq=1, so next ID must be seq=2.
        assert aid2 != aid1
        seq_num_2 = int(aid2.rsplit("-", 1)[-1])
        assert seq_num_2 >= 2, (
            f"Expected seq >= 2 from JSONL fallback after corrupt sidecar, got {seq_num_2}"
        )

    def test_corrupted_seq_sidecar_empty_falls_back_to_jsonl_scan(self, tmp_path):
        """An empty .seq sidecar (e.g. truncated mid-write) falls back gracefully."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"

        w = AuditWriter(mcp, audit_dir=str(audit_dir))
        aid1 = w.log("t1", {}, "ok", examiner_override="analyst")
        assert aid1 is not None

        # Truncate sidecar to zero bytes.
        (audit_dir / f"{mcp}.seq").write_bytes(b"")

        w2 = AuditWriter(mcp, audit_dir=str(audit_dir))
        aid2 = w2.log("t2", {}, "ok", examiner_override="analyst")
        assert aid2 is not None
        assert aid1 != aid2

    def test_seq_sidecar_stale_date_triggers_jsonl_resume(self, tmp_path):
        """A .seq sidecar from a previous date must not be reused as-is.

        When the stored date differs from today, _resume_sequence must fall
        back to scanning the JSONL file for the *current* date.  Since the
        JSONL has no entries for today, seq resets to 1 on the new day — not
        jump to the old day's last value.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"

        # Write a sidecar that claims a long-past date with seq=99.
        seq_file = audit_dir / f"{mcp}.seq"
        seq_file.write_text(json.dumps({"date": "20000101", "seq": 99}))

        w = AuditWriter(mcp, audit_dir=str(audit_dir))
        aid = w.log("t1", {}, "ok")
        assert aid is not None

        # Sequence should start at 1 for today, NOT 100 (old sidecar not reused).
        seq_num = int(aid.rsplit("-", 1)[-1])
        assert seq_num == 1

    # ------------------------------------------------------------------
    # Missing sidecar / JSONL resume fallback
    # ------------------------------------------------------------------

    def test_resume_from_jsonl_when_sidecar_absent(self, tmp_path):
        """With no .seq sidecar, sequence is inferred from JSONL scan on restart.

        This simulates a crash in the window between writing the JSONL entry
        and writing the sidecar — a durability gap that exists in the current
        implementation.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"
        today = _today_utc()
        prefix = _mcp_prefix(mcp)

        # Manually write a JSONL entry with a known sequence number.
        # The audit_id format is "{prefix}-{examiner}-{date}-{seq:03d}".
        synthetic_entry = {
            "ts": "2030-01-01T00:00:00+00:00",
            "mcp": mcp,
            "tool": "synthetic",
            "audit_id": f"{prefix}-analyst-{today}-007",
            "examiner": "analyst",
            "case_id": "",
            "source": "mcp_server",
            "params": {},
            "result_summary": {"value": "synthetic"},
        }
        log_file = audit_dir / f"{mcp}.jsonl"
        log_file.write_text(json.dumps(synthetic_entry) + "\n")
        # Ensure NO sidecar file exists (crash before sidecar was written).
        (audit_dir / f"{mcp}.seq").unlink(missing_ok=True)

        w = AuditWriter(mcp, audit_dir=str(audit_dir))
        aid = w.log("t1", {}, "ok", examiner_override="analyst")
        assert aid is not None

        # JSONL scan must have found seq=7, so next must be 8.
        seq_num = int(aid.rsplit("-", 1)[-1])
        assert seq_num >= 8, (
            f"Expected seq >= 8 from JSONL resume (found seq=7 in log), got {seq_num}"
        )

    def test_jsonl_resume_skips_entries_from_different_mcp(self, tmp_path):
        """JSONL resume must skip lines whose audit_id prefix does not match.

        A JSONL file may contain entries written by multiple tools/runs; only
        the entries belonging to this MCP's prefix should count toward the
        sequence.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"
        today = _today_utc()
        prefix = _mcp_prefix(mcp)  # "probe"

        # Mix of valid entries from a different MCP and one with no audit_id.
        # "forensic-mcp" has prefix "forensic" — no overlap with "probe".
        lines = [
            # Entry for a different MCP — must NOT affect our counter.
            json.dumps({"audit_id": f"forensic-analyst-{today}-099", "mcp": "forensic-mcp"}),
            # Entry with no audit_id field.
            json.dumps({"tool": "something", "mcp": mcp}),
            # Valid entry for our MCP with seq=5.
            json.dumps({"audit_id": f"{prefix}-analyst-{today}-005", "mcp": mcp}),
        ]
        (audit_dir / f"{mcp}.jsonl").write_text("\n".join(lines) + "\n")
        (audit_dir / f"{mcp}.seq").unlink(missing_ok=True)

        w = AuditWriter(mcp, audit_dir=str(audit_dir))
        aid = w.log("t1", {}, "ok", examiner_override="analyst")
        assert aid is not None
        seq_num = int(aid.rsplit("-", 1)[-1])
        # Must resume from seq=5 (not 99 from the other MCP), next = 6.
        assert seq_num == 6, (
            f"Expected seq=6 after JSONL resume (max for our MCP was 5), got {seq_num}"
        )

    # ------------------------------------------------------------------
    # Malformed JSONL lines in get_entries
    # ------------------------------------------------------------------

    def test_get_entries_skips_malformed_lines(self, tmp_path):
        """get_entries must skip corrupted JSONL lines and return valid ones.

        A forensic reader must never crash on a partially-written or
        bit-flipped log line; it should log a warning and continue.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"

        log_file = audit_dir / f"{mcp}.jsonl"
        good_entry = {
            "audit_id": "e1",
            "ts": "2030-01-01T00:00:00+00:00",
            "tool": "scan",
            "case_id": "",
        }
        log_file.write_text(
            json.dumps(good_entry) + "\n"
            + "NOT VALID JSON {{{\n"
            + "\x00\x01truncated\n"
            + json.dumps(
                {"audit_id": "e2", "ts": "2030-01-01T00:01:00+00:00", "tool": "read", "case_id": ""}
            ) + "\n"
        )

        w = AuditWriter(mcp, audit_dir=str(audit_dir))
        entries = w.get_entries()

        # Must return only the 2 valid entries; corrupt lines silently skipped.
        assert len(entries) == 2
        assert entries[0]["audit_id"] == "e1"
        assert entries[1]["audit_id"] == "e2"

    def test_get_entries_skips_blank_lines(self, tmp_path):
        """Blank lines in the JSONL file must be silently skipped."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"

        log_file = audit_dir / f"{mcp}.jsonl"
        log_file.write_text(
            "\n"
            + json.dumps(
                {"audit_id": "e1", "ts": "2030-01-01T00:00:00+00:00", "tool": "t", "case_id": ""}
            ) + "\n"
            + "\n\n"
        )

        w = AuditWriter(mcp, audit_dir=str(audit_dir))
        entries = w.get_entries()
        assert len(entries) == 1

    def test_get_entries_all_malformed_returns_empty(self, tmp_path):
        """A JSONL file that is entirely corrupt returns an empty list (fail-closed)."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"

        (audit_dir / f"{mcp}.jsonl").write_text("GARBAGE\nMORE GARBAGE\n")

        w = AuditWriter(mcp, audit_dir=str(audit_dir))
        # Must not raise; returns empty list rather than crashing.
        entries = w.get_entries()
        assert entries == []

    # ------------------------------------------------------------------
    # fsync / write failure handling (fail-closed)
    # ------------------------------------------------------------------

    def test_write_failure_returns_none(self, tmp_path):
        """A write failure (OSError on fsync) must cause log() to return None.

        This is the fail-closed contract: an audit entry that could not be
        durably fsynced must never be silently counted as recorded.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"

        w = AuditWriter(mcp, audit_dir=str(audit_dir))

        with mock.patch("sift_common.audit.os.fsync", side_effect=OSError("disk full")):
            result = w.log("risky-tool", {}, "result")

        # Fail-closed: the audit_id must NOT be returned.
        assert result is None

    def test_write_failure_does_not_block_subsequent_writes(self, tmp_path):
        """After a failed write, subsequent successful writes must proceed.

        A failed write consumes a sequence slot but must not prevent future
        writes.  The next successful call must return a unique non-None ID.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"

        w = AuditWriter(mcp, audit_dir=str(audit_dir))

        # First write succeeds.
        aid1 = w.log("t1", {}, "ok")
        assert aid1 is not None

        # Second write fails due to fsync error — must return None (fail-closed).
        with mock.patch("sift_common.audit.os.fsync", side_effect=OSError("io error")):
            failed = w.log("t2", {}, "ok")
        assert failed is None

        # Third write must succeed and have a unique ID.
        aid3 = w.log("t3", {}, "ok")
        assert aid3 is not None
        assert aid3 != aid1

    def test_open_failure_returns_none(self, tmp_path):
        """If the audit file cannot be opened for append, log() returns None."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"

        w = AuditWriter(mcp, audit_dir=str(audit_dir))

        with mock.patch("builtins.open", side_effect=OSError("permission denied")):
            result = w.log("t1", {}, "ok")

        assert result is None

    def test_audit_dir_creation_failure_returns_none(self, tmp_path):
        """If the audit directory cannot be created, log() returns None (fail-closed).

        Simulates a filesystem permission error or read-only mount.
        """
        w = AuditWriter("probe-mcp", audit_dir=str(tmp_path / "nonexistent" / "audit"))

        with mock.patch("pathlib.Path.mkdir", side_effect=OSError("read-only filesystem")):
            result = w.log("t1", {}, "ok")

        assert result is None

    # ------------------------------------------------------------------
    # Day/date rollover
    # ------------------------------------------------------------------

    def test_date_rollover_resets_sequence_to_one(self, tmp_path):
        """When the date changes, the sequence counter must reset to 1 for
        the new day and not carry over the previous day's max sequence.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"

        w = AuditWriter(mcp, audit_dir=str(audit_dir))

        import datetime as _dt

        # Simulate "yesterday".
        with mock.patch("sift_common.audit.datetime") as dt_mock:
            dt_mock.now.return_value.strftime.return_value = "20300101"
            dt_mock.now.return_value.isoformat.return_value = "2030-01-01T00:00:00+00:00"
            dt_mock.timezone = _dt.timezone
            aid_day1_a = w.log("t1", {}, "ok")
            aid_day1_b = w.log("t2", {}, "ok")

        assert aid_day1_a is not None
        assert aid_day1_b is not None
        seq_d1 = int(aid_day1_b.rsplit("-", 1)[-1])
        assert seq_d1 == 2  # day 1 reached seq=2

        # Now simulate "today" — writer must detect date change and reset.
        with mock.patch("sift_common.audit.datetime") as dt_mock2:
            dt_mock2.now.return_value.strftime.return_value = "20300102"
            dt_mock2.now.return_value.isoformat.return_value = "2030-01-02T00:00:00+00:00"
            dt_mock2.timezone = _dt.timezone
            aid_day2 = w.log("t3", {}, "ok")

        assert aid_day2 is not None
        # Day 2's first entry should have seq=1, not seq=3.
        seq_d2 = int(aid_day2.rsplit("-", 1)[-1])
        assert seq_d2 == 1, (
            f"Expected seq=1 after date rollover, got {seq_d2} in {aid_day2}"
        )
        assert "20300102" in aid_day2

    def test_date_rollover_ids_embed_correct_date(self, tmp_path):
        """Audit IDs must embed the UTC date at generation time, not startup time."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"

        w = AuditWriter(mcp, audit_dir=str(audit_dir))

        import datetime as _dt

        with mock.patch("sift_common.audit.datetime") as dt_mock:
            dt_mock.now.return_value.strftime.return_value = "20300615"
            dt_mock.now.return_value.isoformat.return_value = "2030-06-15T12:00:00+00:00"
            dt_mock.timezone = _dt.timezone
            aid = w.log("t1", {}, "ok")

        assert aid is not None
        assert "20300615" in aid

    # ------------------------------------------------------------------
    # Concurrent logging (thread safety — single instance)
    # ------------------------------------------------------------------

    def test_concurrent_writes_produce_unique_audit_ids(self, tmp_path):
        """A single AuditWriter used from multiple threads must produce unique IDs.

        AuditWriter is documented as thread-safe (sequence counter protected by
        a threading.Lock).  This test validates the lock under real concurrent
        load.  Duplicate IDs would be a forensic chain-of-custody failure: two
        distinct events sharing an ID cannot be unambiguously distinguished.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"

        # Single shared writer — the documented thread-safe usage pattern.
        w = AuditWriter(mcp, audit_dir=str(audit_dir))

        n_threads = 8
        n_per_thread = 10
        ids: list[str] = []
        errors: list[Exception] = []
        id_lock = threading.Lock()

        def worker(idx: int) -> None:
            for i in range(n_per_thread):
                try:
                    aid = w.log(f"tool-{idx}-{i}", {}, "ok", examiner_override="analyst")
                    if aid is None:
                        errors.append(
                            AssertionError(f"worker {idx} iter {i}: log returned None")
                        )
                        return
                    with id_lock:
                        ids.append(aid)
                except Exception as exc:
                    with id_lock:
                        errors.append(exc)
                    return

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Worker errors: {errors}"
        expected = n_threads * n_per_thread
        assert len(ids) == expected, f"Expected {expected} IDs, got {len(ids)}"
        assert len(ids) == len(set(ids)), (
            f"Duplicate audit IDs detected among {len(ids)} concurrent writes"
        )

    def test_concurrent_writes_all_persisted_to_jsonl(self, tmp_path):
        """Every audit ID returned by log() must appear in the JSONL file.

        Validates the durability contract: if log() returns a non-None ID,
        the entry must be recoverable from disk.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"

        # Single shared writer — the documented thread-safe usage pattern.
        w = AuditWriter(mcp, audit_dir=str(audit_dir))

        n_threads = 4
        n_per_thread = 5
        returned_ids: list[str] = []
        id_lock = threading.Lock()

        def worker(idx: int) -> None:
            for _i in range(n_per_thread):
                aid = w.log(f"tool-{idx}", {}, "ok", examiner_override="analyst")
                if aid is not None:
                    with id_lock:
                        returned_ids.append(aid)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        # Read back from JSONL and verify every returned ID is present.
        log_file = audit_dir / f"{mcp}.jsonl"
        persisted_ids: set[str] = set()
        for line in log_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                persisted_ids.add(json.loads(line)["audit_id"])
            except (json.JSONDecodeError, KeyError):
                pass

        missing = set(returned_ids) - persisted_ids
        assert not missing, (
            f"{len(missing)} audit IDs were returned by log() but not found in JSONL: {missing}"
        )

    def test_single_writer_multiple_examiners_unique_ids(self, tmp_path):
        """A single writer with different examiner_override values per call must
        still produce unique IDs because the global sequence counter is shared.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"
        w = AuditWriter(mcp, audit_dir=str(audit_dir))

        ids = []
        for examiner in ["analyst-a", "analyst-b", "analyst-a"]:
            aid = w.log("tool", {}, "ok", examiner_override=examiner)
            assert aid is not None
            ids.append(aid)

        # All three IDs must be distinct despite the repeated "analyst-a".
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"

    # ------------------------------------------------------------------
    # DB-authority mode edge cases
    # ------------------------------------------------------------------

    def test_db_authority_mode_returns_caller_supplied_audit_id(self):
        """In DB-authority mode with no local dir, a caller-supplied audit_id
        is echoed back unchanged (Gateway envelope reuse pattern).
        """
        env = os.environ.copy()
        env.pop("SIFT_AUDIT_DIR", None)
        env.pop("SIFT_CASE_DIR", None)
        env["SIFT_DB_ACTIVE"] = "true"
        with mock.patch.dict(os.environ, env, clear=True):
            w = AuditWriter("probe-mcp")
            result = w.log("tool", {}, "ok", audit_id="gateway-supplied-id-001")
        assert result == "gateway-supplied-id-001"

    def test_db_authority_mode_true_variants(self):
        """All accepted truthy values for SIFT_DB_ACTIVE must enable DB-authority mode."""
        for val in ("1", "true", "yes", "on", "True", "YES", "ON"):
            env = os.environ.copy()
            env.pop("SIFT_AUDIT_DIR", None)
            env.pop("SIFT_CASE_DIR", None)
            env["SIFT_DB_ACTIVE"] = val
            with mock.patch.dict(os.environ, env, clear=True):
                w = AuditWriter("probe-mcp")
                result = w.log("tool", {}, "ok")
            assert result is not None, (
                f"SIFT_DB_ACTIVE={val!r} should enable DB-authority mode"
            )

    def test_db_authority_mode_false_variants_return_none_without_dir(self):
        """Unrecognised / falsy SIFT_DB_ACTIVE values must NOT enable DB-authority mode."""
        for val in ("0", "false", "no", "off", "", "2", "maybe"):
            env = os.environ.copy()
            env.pop("SIFT_AUDIT_DIR", None)
            env.pop("SIFT_CASE_DIR", None)
            env["SIFT_DB_ACTIVE"] = val
            with mock.patch.dict(os.environ, env, clear=True):
                w = AuditWriter("probe-mcp")
                result = w.log("tool", {}, "ok")
            assert result is None, (
                f"SIFT_DB_ACTIVE={val!r} should NOT enable DB-authority mode"
            )

    # ------------------------------------------------------------------
    # Audit entry shape / field presence
    # ------------------------------------------------------------------

    def test_entry_always_has_required_fields(self, tmp_path):
        """Every written entry must contain the mandatory forensic fields.

        This pins the public entry shape so regressions are caught immediately.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        required_fields = {
            "ts", "mcp", "tool", "audit_id", "examiner",
            "case_id", "source", "params", "result_summary",
        }

        w = AuditWriter("probe-mcp", audit_dir=str(audit_dir))
        w.log("scan", {"path": "/evidence/sample"}, {"count": 1})

        entry = json.loads((audit_dir / "probe-mcp.jsonl").read_text().strip())
        missing = required_fields - entry.keys()
        assert not missing, f"Audit entry missing required fields: {missing}"

    def test_result_summary_large_string_truncated_in_entry(self, tmp_path):
        """_summarize must cap string values at 500 chars to bound log entry size."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        w = AuditWriter("probe-mcp", audit_dir=str(audit_dir))
        w.log("t1", {}, "x" * 2000)

        entry = json.loads((audit_dir / "probe-mcp.jsonl").read_text().strip())
        # result_summary must be the _summarize output, not the raw 2000-char string.
        assert entry["result_summary"] == {"value": "x" * 500}

    def test_params_not_leaked_into_audit_id(self, tmp_path):
        """Audit IDs must be derived only from MCP name, examiner, date, and sequence.

        Parameter values (which may contain PII or sensitive content) must never
        appear in the audit ID itself.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        w = AuditWriter("probe-mcp", audit_dir=str(audit_dir))
        synthetic_sensitive = "synthetic-sensitive-value"
        aid = w.log("t1", {"field": synthetic_sensitive}, "ok")
        assert aid is not None
        assert synthetic_sensitive not in aid


# ---------------------------------------------------------------------------
# AuditWriter — durability/concurrency hardening (#27)
#
#   1. Atomic .seq sidecar write (temp + fsync + os.replace) — no torn sidecar.
#   2. Cross-process flock — two processes sharing one audit_dir must never
#      resume the same seq and mint DUPLICATE audit IDs.
# ---------------------------------------------------------------------------

import multiprocessing as _mp

import pytest


def _xproc_mint_worker(audit_dir: str, mcp: str, n: int, out_q) -> None:
    """Top-level (picklable) worker: mint N audit IDs and push them to a queue.

    Runs in a separate PROCESS (multiprocessing) sharing one audit_dir with a
    sibling worker. Each returned non-None ID is the audit_id of a JSONL entry
    that was durably written, so the union across both processes must be
    duplicate-free if the cross-process flock holds.
    """
    w = AuditWriter(mcp, audit_dir=audit_dir)
    ids = []
    for _i in range(n):
        aid = w.log("t", {}, "ok", examiner_override="analyst")
        if aid is not None:
            ids.append(aid)
    w.close()
    out_q.put(ids)


# fork is required so the child inherits this module's definitions cleanly and
# flock semantics are exercised on a shared FS. Guard for platforms without it.
_HAS_FORK = hasattr(os, "fork") and "fork" in _mp.get_all_start_methods()

from sift_common import audit as _audit_mod

_HAS_FLOCK = _audit_mod.fcntl is not None


class TestAuditWriterCrossProcessLock:
    """#27: cross-process duplicate-ID prevention via fcntl.flock."""

    @pytest.mark.skipif(
        not (_HAS_FORK and _HAS_FLOCK),
        reason="requires POSIX fork + fcntl.flock (cross-process advisory lock)",
    )
    def test_two_processes_concurrent_mint_no_duplicate_ids(self, tmp_path):
        """Two processes minting concurrently on ONE audit_dir must yield 2N
        unique IDs (zero duplicates).

        This is the substantive #27 bug: without the flock, both processes
        independently resume the same on-disk sequence and mint colliding audit
        IDs — a forensic chain-of-custody failure. Removing the flock from
        _next_audit_id makes this test FAIL (observed duplicates); with the
        flock it PASSES.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"
        n = 50

        ctx = _mp.get_context("fork")
        q = ctx.Queue()
        procs = [
            ctx.Process(target=_xproc_mint_worker, args=(str(audit_dir), mcp, n, q))
            for _ in range(2)
        ]
        for p in procs:
            p.start()
        collected: list[str] = []
        for _ in procs:
            collected.extend(q.get(timeout=60))
        for p in procs:
            p.join(timeout=60)
            assert p.exitcode == 0, f"child exited {p.exitcode}"

        # Every returned ID corresponds to a durably-written JSONL entry.
        assert len(collected) == 2 * n, (
            f"Expected {2 * n} minted IDs, got {len(collected)}"
        )
        dupes = sorted({x for x in collected if collected.count(x) > 1})
        assert not dupes, f"Duplicate audit IDs across processes: {dupes}"

        # Cross-check against what actually landed in the JSONL ledger.
        log_file = audit_dir / f"{mcp}.jsonl"
        persisted = [
            json.loads(line)["audit_id"]
            for line in log_file.read_text().splitlines()
            if line.strip()
        ]
        assert len(persisted) == 2 * n
        assert len(set(persisted)) == 2 * n, (
            "Duplicate audit IDs found in persisted JSONL ledger"
        )

    def test_flock_unavailable_degrades_to_threading_only(self, tmp_path, monkeypatch):
        """When fcntl is unavailable (non-POSIX), the cross-process lock is a
        graceful no-op — minting still works and never blocks/raises.
        """
        monkeypatch.setattr(_audit_mod, "fcntl", None)
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        w = AuditWriter("probe-mcp", audit_dir=str(audit_dir))
        # _get_lock_fd returns None, _acquire/_release are no-ops; minting works.
        assert w._acquire_xproc_lock() is None
        w._release_xproc_lock(None)  # must not raise
        aid1 = w.log("t1", {}, "ok")
        aid2 = w.log("t2", {}, "ok")
        assert aid1 and aid2 and aid1 != aid2


class TestAuditWriterAtomicSidecar:
    """#27: atomic .seq sidecar write (temp + fsync + os.replace)."""

    def test_sidecar_written_via_os_replace(self, tmp_path):
        """The sidecar must be persisted via os.replace (atomic rename), not a
        plain in-place write — observed by spying on os.replace.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"
        seq_target = audit_dir / f"{mcp}.seq"

        real_replace = os.replace
        calls: list[tuple[str, str]] = []

        def spy_replace(src, dst):
            calls.append((str(src), str(dst)))
            return real_replace(src, dst)

        w = AuditWriter(mcp, audit_dir=str(audit_dir))
        with mock.patch("sift_common.audit.os.replace", side_effect=spy_replace):
            aid = w.log("t1", {}, "ok")
        assert aid is not None
        # os.replace was called targeting the sidecar.
        assert any(dst == str(seq_target) for _src, dst in calls), (
            f"os.replace never targeted the sidecar; calls={calls}"
        )
        # The source was a temp path in the SAME directory.
        for src, dst in calls:
            if dst == str(seq_target):
                assert Path(src).parent == seq_target.parent
                assert ".tmp." in Path(src).name

    def test_no_tmp_residue_after_successful_write(self, tmp_path):
        """After successful sidecar writes, no .seq.tmp.* residue may remain."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"
        w = AuditWriter(mcp, audit_dir=str(audit_dir))
        for i in range(5):
            assert w.log(f"t{i}", {}, "ok") is not None
        residue = list(audit_dir.glob(f"{mcp}.seq.tmp.*"))
        assert not residue, f"Temp sidecar residue left behind: {residue}"
        # The real sidecar exists and is valid JSON with the latest seq.
        data = json.loads((audit_dir / f"{mcp}.seq").read_text())
        assert data["seq"] == 5

    def test_replace_failure_cleans_up_temp_and_does_not_crash(self, tmp_path):
        """If os.replace fails (e.g. simulated rename error), the temp file is
        cleaned up and the call is a graceful no-op (no crash, no residue).
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"
        w = AuditWriter(mcp, audit_dir=str(audit_dir))

        with mock.patch(
            "sift_common.audit.os.replace", side_effect=OSError("rename failed")
        ):
            # log() still returns the id (JSONL append succeeded); only the
            # sidecar persist degrades. The sidecar write is best-effort.
            aid = w.log("t1", {}, "ok")
        assert aid is not None
        residue = list(audit_dir.glob(f"{mcp}.seq.tmp.*"))
        assert not residue, f"Temp residue after failed replace: {residue}"

    def test_crash_between_jsonl_and_sidecar_recovers_without_duplicate(self, tmp_path):
        """Simulate a crash AFTER the JSONL append but BEFORE the sidecar is
        durably renamed: a fresh AuditWriter must resume from the JSONL scan and
        NOT re-mint the same seq (no duplicate).

        This extends the existing crash-window coverage with the atomic-write
        path: even when os.replace never lands, the recoverable order
        (JSONL-append-then-sidecar) guarantees no duplicate on restart.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "probe-mcp"

        # First writer: JSONL append succeeds, but the sidecar rename is forced
        # to fail (crash window). The JSONL entry with seq=1 is durable.
        w1 = AuditWriter(mcp, audit_dir=str(audit_dir))
        with mock.patch(
            "sift_common.audit.os.replace", side_effect=OSError("crash before rename")
        ):
            aid1 = w1.log("t1", {}, "ok", examiner_override="analyst")
        assert aid1 is not None
        seq1 = int(aid1.rsplit("-", 1)[-1])
        assert seq1 == 1
        # Sidecar must be absent/stale (rename failed) — prove no residue.
        assert not list(audit_dir.glob(f"{mcp}.seq.tmp.*"))

        # Fresh writer (simulated restart): must resume from JSONL (seq=1) and
        # mint seq=2 — never duplicate seq=1.
        w2 = AuditWriter(mcp, audit_dir=str(audit_dir))
        aid2 = w2.log("t2", {}, "ok", examiner_override="analyst")
        assert aid2 is not None
        assert aid2 != aid1
        seq2 = int(aid2.rsplit("-", 1)[-1])
        assert seq2 == 2, f"Expected seq=2 after crash-window resume, got {seq2}"


# ---------------------------------------------------------------------------
# In-process thread-safety (review #27): lock-fd init + per-thread sidecar temp
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_log_unique_ids_single_lock_fd(self, tmp_path):
        """Many threads in one process minting IDs concurrently on one writer.

        Asserts: no exception, every minted audit_id is unique, and the
        lazy lock-fd is opened EXACTLY ONCE (no fd leak from a check-then-open
        race in ``_get_lock_fd``). The os.open count is measured only on the
        ``.lock`` path so unrelated opens (JSONL/sidecar) are not counted.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "race-mcp"
        lock_path = str(audit_dir / f"{mcp}.lock")

        real_open = os.open
        lock_open_count = 0
        count_lock = threading.Lock()

        def counting_open(path, *args, **kwargs):
            nonlocal lock_open_count
            if path == lock_path:
                with count_lock:
                    lock_open_count += 1
            return real_open(path, *args, **kwargs)

        n_threads = 16
        per_thread = 25
        ids: list[str] = []
        ids_lock = threading.Lock()
        errors: list[BaseException] = []
        start = threading.Barrier(n_threads)

        w = AuditWriter(mcp, audit_dir=str(audit_dir))

        def worker():
            try:
                start.wait()
                local: list[str] = []
                for i in range(per_thread):
                    aid = w.log("t", {"i": i}, "ok", examiner_override="analyst")
                    assert aid is not None
                    local.append(aid)
                with ids_lock:
                    ids.extend(local)
            except BaseException as e:  # noqa: BLE001 - surface in assertion
                errors.append(e)

        with mock.patch("sift_common.audit.os.open", side_effect=counting_open):
            threads = [threading.Thread(target=worker) for _ in range(n_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        assert not errors, f"worker threads raised: {errors!r}"
        assert len(ids) == n_threads * per_thread
        assert len(set(ids)) == len(ids), "duplicate audit IDs minted under contention"
        # The whole point: the lock fd is opened once and reused, never racing
        # two os.open calls on the lockfile (which would leak an fd and create
        # mutually-blocking flock fds in one process).
        assert lock_open_count == 1, (
            f"lock fd opened {lock_open_count} times; expected exactly 1 "
            "(check-then-open race in _get_lock_fd)"
        )
        assert isinstance(w._lock_fd, int)
        w.close()

    def test_concurrent_sidecar_writes_no_residue_no_fnf(self, tmp_path):
        """Two+ threads writing the sidecar concurrently must not collide.

        Before the fix the temp path used only ``os.getpid()`` so two threads in
        one process computed the SAME ``.tmp.<pid>`` path → truncation /
        interleaved writes / FileNotFoundError on ``os.replace``. With the
        thread-id in the temp name each thread uses a distinct temp file. We
        assert no exception, the sidecar ends valid, and no ``.tmp.*`` residue
        remains.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "sidecar-mcp"
        w = AuditWriter(mcp, audit_dir=str(audit_dir))

        n_threads = 16
        iters = 50
        errors: list[BaseException] = []
        start = threading.Barrier(n_threads)

        def worker(tid: int):
            try:
                start.wait()
                for k in range(iters):
                    # Vary date/seq per call; the writer is the locked atomic path.
                    w._write_seq_sidecar_locked("20260626", tid * 1000 + k)
            except BaseException as e:  # noqa: BLE001 - surface in assertion
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=(i,)) for i in range(n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"sidecar writers raised: {errors!r}"
        seq_file = audit_dir / f"{mcp}.seq"
        assert seq_file.exists(), "sidecar missing after concurrent writes"
        # Final sidecar must be a complete, valid JSON document (no torn write).
        data = json.loads(seq_file.read_text())
        assert data["date"] == "20260626"
        # No leftover temp files from any thread.
        assert not list(audit_dir.glob(f"{mcp}.seq.tmp.*")), "temp sidecar residue left"

    def test_sidecar_temp_name_includes_thread_id(self, tmp_path):
        """The temp sidecar path embeds both pid and thread id (regression guard).

        Intercepts the open() used by ``_write_seq_sidecar_locked`` to capture
        the temp path and assert it carries ``.tmp.<pid>.<ident>`` — a fail-on
        -revert guard for the per-thread temp-name fix.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        mcp = "name-mcp"
        w = AuditWriter(mcp, audit_dir=str(audit_dir))

        captured: list[str] = []
        real_builtin_open = open

        def spy_open(file, *args, **kwargs):
            captured.append(str(file))
            return real_builtin_open(file, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=spy_open):
            w._write_seq_sidecar_locked("20260626", 7)

        ident = threading.get_ident()
        expected_suffix = f".tmp.{os.getpid()}.{ident}"
        assert any(p.endswith(expected_suffix) for p in captured), (
            f"temp sidecar path missing per-thread suffix {expected_suffix!r}; "
            f"captured opens: {captured!r}"
        )
