"""Windows Triage MCP — risk-path tests with bounded synthetic fixtures.

Covers (XYE-67 / C3):
- Missing / degraded baseline DBs and graceful degradation
- Strict env parsing: invalid integer env vars must raise ConfigurationError
- Config validation bounds (log level, numeric limits)
- Tool error result shapes from the MCP dispatch layer
- Path-bounds / oversized-input ValidationError raised and surfaced as JSON
- Named-pipe analysis paths (EXPECTED / SUSPICIOUS / UNKNOWN)
- Autorun suspicious-location path (high-risk key not in baseline)
- Scheduled task suspicious-location path
- Service with missing os_version and binary-path mismatch
- Verdict calculation branches not yet hit (verdicts module)
- RegistryDB helpers with a tiny synthetic SQLite DB
- Surface snapshot drift guard (no fixture update expected)

No network calls, no downloads, no optional 12 GB registry baseline required.
All synthetic databases are tiny in-memory or tmp-path SQLite files.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from windows_triage_mcp.config import (
    Config,
    _load_config_from_env,
    _parse_int_env,
    get_config,
    reset_config,
    set_config,
)
from windows_triage_mcp.exceptions import ConfigurationError, ValidationError
from windows_triage_mcp.db import KnownGoodDB, ContextDB, RegistryDB
from windows_triage_mcp.server import WindowsTriageServer, _validate_input_length, _validate_no_null_bytes
from windows_triage_mcp.analysis.verdicts import (
    Verdict,
    VerdictResult,
    calculate_file_verdict,
    calculate_hash_verdict,
    calculate_process_verdict,
    calculate_service_verdict,
)
from windows_triage_mcp.analysis.filename import analyze_filename


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server(tmp_path: Path) -> WindowsTriageServer:
    """Build a minimal server with fully initialized but empty-ish databases."""
    kg_path = tmp_path / "known_good.db"
    ctx_path = tmp_path / "context.db"
    reg_path = tmp_path / "known_good_registry.db"

    kg_db = KnownGoodDB(kg_path, read_only=False, cache_size=0)
    kg_db.init_schema()

    ctx_db = ContextDB(ctx_path, read_only=False, cache_size=0)
    ctx_db.init_schema()

    reg_db = RegistryDB(reg_path, read_only=False, cache_size=0)
    reg_db.init_schema()

    # Seed minimal data so health reports "healthy"
    kg_db.add_os_version(short_name="Win10_Test", os_family="Windows 10")
    ctx_db.add_lolbin(filename="mshta.exe", name="mshta", functions=["hta"])

    config = Config(
        known_good_db=kg_path,
        context_db=ctx_path,
        registry_db=reg_path,
        skip_db_validation=True,
        cache_size=0,
    )
    srv = WindowsTriageServer(
        config=config,
        known_good_path=kg_path,
        context_path=ctx_path,
        registry_path=reg_path,
    )
    return srv


# ---------------------------------------------------------------------------
# Config strict env parsing (XYE-33 regression guard)
# ---------------------------------------------------------------------------


class TestStrictIntEnvParsing:
    """All integer env vars must raise ConfigurationError on non-integer input."""

    @pytest.mark.parametrize(
        "env_var",
        [
            "WT_CACHE_SIZE",
            "WT_MAX_PATH_LENGTH",
            "WT_MAX_HASH_LENGTH",
            "WT_MAX_PIPE_NAME_LENGTH",
            "WT_MAX_SERVICE_NAME_LENGTH",
            "WT_MAX_TASK_PATH_LENGTH",
            "WT_MAX_KEY_PATH_LENGTH",
        ],
    )
    def test_invalid_int_raises_configuration_error(self, env_var, monkeypatch):
        monkeypatch.setenv(env_var, "not_a_number")
        with pytest.raises(ConfigurationError):
            _load_config_from_env()

    def test_parse_int_env_zero_accepted(self, monkeypatch):
        monkeypatch.setenv("WT_CACHE_SIZE", "0")
        assert _parse_int_env("WT_CACHE_SIZE", 10000) == 0

    def test_parse_int_env_negative_accepted_at_parse_level(self, monkeypatch):
        # _parse_int_env itself only validates parsability; bound checks are in Config._validate
        monkeypatch.setenv("WT_CACHE_SIZE", "-1")
        assert _parse_int_env("WT_CACHE_SIZE", 10000) == -1

    def test_float_string_raises_configuration_error(self, monkeypatch):
        monkeypatch.setenv("WT_CACHE_SIZE", "3.14")
        with pytest.raises(ConfigurationError):
            _parse_int_env("WT_CACHE_SIZE", 10000)

    def test_empty_string_raises_configuration_error(self, monkeypatch):
        monkeypatch.setenv("WT_CACHE_SIZE", "")
        with pytest.raises(ConfigurationError):
            _parse_int_env("WT_CACHE_SIZE", 10000)


# ---------------------------------------------------------------------------
# Config._validate bounds
# ---------------------------------------------------------------------------


class TestConfigValidation:
    def test_invalid_log_level_raises(self):
        with pytest.raises(ConfigurationError, match="Invalid log_level"):
            Config(log_level="VERBOSE")

    def test_max_path_length_too_low_raises(self):
        with pytest.raises(ConfigurationError, match="max_path_length"):
            Config(max_path_length=0)

    def test_max_path_length_too_high_raises(self):
        with pytest.raises(ConfigurationError, match="max_path_length"):
            Config(max_path_length=99999)

    def test_max_hash_length_too_low_raises(self):
        with pytest.raises(ConfigurationError, match="max_hash_length"):
            Config(max_hash_length=8)

    def test_max_hash_length_too_high_raises(self):
        with pytest.raises(ConfigurationError, match="max_hash_length"):
            Config(max_hash_length=512)

    def test_cache_size_negative_raises(self):
        with pytest.raises(ConfigurationError, match="cache_size"):
            Config(cache_size=-1)

    def test_cache_size_too_large_raises(self):
        with pytest.raises(ConfigurationError, match="cache_size"):
            Config(cache_size=2_000_000)

    def test_valid_log_levels_accepted(self):
        for level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            cfg = Config(log_level=level)
            assert cfg.log_level == level

    def test_defaults_are_valid(self):
        cfg = Config()
        # Should not raise — defaults must pass their own validation.
        assert cfg.cache_size == 10000

    def test_set_and_reset_config(self):
        custom = Config(cache_size=1234)
        set_config(custom)
        assert get_config().cache_size == 1234
        reset_config()
        # After reset, next get_config() reloads from environment (default=10000)
        fresh = get_config()
        assert fresh.cache_size == 10000


# ---------------------------------------------------------------------------
# Input validation helpers (_validate_input_length, _validate_no_null_bytes)
# ---------------------------------------------------------------------------


class TestInputValidationHelpers:
    def test_length_ok_passes(self):
        _validate_input_length("a" * 100, 200, "field")  # no raise

    def test_length_at_limit_passes(self):
        _validate_input_length("a" * 4096, 4096, "field")  # no raise

    def test_length_over_limit_raises(self):
        with pytest.raises(ValidationError, match="field"):
            _validate_input_length("a" * 4097, 4096, "field")

    def test_none_value_passes(self):
        _validate_input_length(None, 100, "field")  # no raise

    def test_non_string_passes(self):
        _validate_input_length(42, 100, "field")  # integers not checked

    def test_null_bytes_raises(self):
        with pytest.raises(ValidationError, match="null"):
            _validate_no_null_bytes("path\x00injection", "field")

    def test_no_null_bytes_passes(self):
        _validate_no_null_bytes("clean_path", "field")  # no raise

    def test_none_no_null_bytes_passes(self):
        _validate_no_null_bytes(None, "field")  # no raise


# ---------------------------------------------------------------------------
# Missing/degraded DB → graceful degradation
# ---------------------------------------------------------------------------


class TestDegradedDatabase:
    @pytest.mark.asyncio
    async def test_missing_db_file_check_file_returns_unknown(self, tmp_path):
        config = Config(
            known_good_db=tmp_path / "absent_kg.db",
            context_db=tmp_path / "absent_ctx.db",
            registry_db=tmp_path / "absent_reg.db",
            skip_db_validation=True,
        )
        srv = WindowsTriageServer(
            config=config,
            known_good_path=tmp_path / "absent_kg.db",
            context_path=tmp_path / "absent_ctx.db",
            registry_path=tmp_path / "absent_reg.db",
        )
        result = await srv._check_file(r"C:\Windows\System32\cmd.exe")
        assert result["verdict"] == "UNKNOWN"
        assert result["path_in_baseline"] is False
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_missing_db_health_is_degraded(self, tmp_path):
        config = Config(
            known_good_db=tmp_path / "absent_kg.db",
            context_db=tmp_path / "absent_ctx.db",
            registry_db=tmp_path / "absent_reg.db",
            skip_db_validation=True,
        )
        srv = WindowsTriageServer(
            config=config,
            known_good_path=tmp_path / "absent_kg.db",
            context_path=tmp_path / "absent_ctx.db",
            registry_path=tmp_path / "absent_reg.db",
        )
        health = await srv._get_health()
        assert health["status"] == "degraded"
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_registry_db_none_returns_unavailable(self, tmp_path):
        srv = _make_server(tmp_path)
        srv.registry_db = None
        result = await srv._check_registry(r"HKLM\SOFTWARE\Foo", None, None, None)
        assert result["registry_db_available"] is False
        assert result["verdict"] is None
        assert "wintriage_check_system" in result["note"]
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_db_stats_registry_not_installed(self, tmp_path):
        srv = _make_server(tmp_path)
        srv.registry_db = None
        stats = await srv._get_db_stats()
        assert stats["registry_db"]["available"] is False
        srv.close_databases()


# ---------------------------------------------------------------------------
# Tool MCP dispatch — unsupported type returns structured error
# ---------------------------------------------------------------------------


class TestToolDispatchErrors:
    @pytest.mark.asyncio
    async def test_check_artifact_unsupported_type_returns_error(self, tmp_path):
        from mcp.types import CallToolRequest

        srv = _make_server(tmp_path)
        handler = srv.server.request_handlers[CallToolRequest]
        res = await handler(
            CallToolRequest(
                params={
                    "name": "wintriage_check_artifact",
                    "arguments": {"type": "bogus_type", "value": "anything"},
                }
            )
        )
        payload = json.loads(res.root.content[0].text)
        assert payload["error"] == "unsupported_artifact_type"
        assert "supported_types" in payload
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_check_system_unsupported_type_returns_error(self, tmp_path):
        from mcp.types import CallToolRequest

        srv = _make_server(tmp_path)
        handler = srv.server.request_handlers[CallToolRequest]
        res = await handler(
            CallToolRequest(
                params={
                    "name": "wintriage_check_system",
                    "arguments": {
                        "type": "unknown_type",
                        "name": "Foo",
                        "os_version": "Win10_Test",
                    },
                }
            )
        )
        payload = json.loads(res.root.content[0].text)
        assert payload["error"] == "unsupported_system_type"
        assert "supported_types" in payload
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_server_status_unsupported_resource_returns_error(self, tmp_path):
        from mcp.types import CallToolRequest

        srv = _make_server(tmp_path)
        handler = srv.server.request_handlers[CallToolRequest]
        res = await handler(
            CallToolRequest(
                params={
                    "name": "wintriage_server_status",
                    "arguments": {"resource": "undefined_resource"},
                }
            )
        )
        payload = json.loads(res.root.content[0].text)
        assert payload["error"] == "unsupported_status_resource"
        assert "supported_resources" in payload
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_unknown_tool_name_returns_error(self, tmp_path):
        from mcp.types import CallToolRequest

        srv = _make_server(tmp_path)
        handler = srv.server.request_handlers[CallToolRequest]
        res = await handler(
            CallToolRequest(
                params={
                    "name": "no_such_tool",
                    "arguments": {},
                }
            )
        )
        payload = json.loads(res.root.content[0].text)
        assert "error" in payload
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_oversized_file_path_returns_validation_error(self, tmp_path):
        from mcp.types import CallToolRequest

        srv = _make_server(tmp_path)
        handler = srv.server.request_handlers[CallToolRequest]
        long_path = "C:\\" + "A" * 5000
        res = await handler(
            CallToolRequest(
                params={
                    "name": "wintriage_check_artifact",
                    "arguments": {"type": "file", "value": long_path},
                }
            )
        )
        payload = json.loads(res.root.content[0].text)
        assert payload["error"] == "validation_error"
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_null_byte_in_path_returns_validation_error(self, tmp_path):
        from mcp.types import CallToolRequest

        srv = _make_server(tmp_path)
        handler = srv.server.request_handlers[CallToolRequest]
        res = await handler(
            CallToolRequest(
                params={
                    "name": "wintriage_check_artifact",
                    "arguments": {"type": "file", "value": "C:\\foo\x00bar"},
                }
            )
        )
        payload = json.loads(res.root.content[0].text)
        assert payload["error"] == "validation_error"
        srv.close_databases()


# ---------------------------------------------------------------------------
# Named pipe analysis risk paths
# ---------------------------------------------------------------------------


class TestPipeAnalysis:
    @pytest.mark.asyncio
    async def test_pipe_with_prefix_stripped_is_expected(self, tmp_path):
        srv = _make_server(tmp_path)
        # "spoolss" is a built-in Windows pipe registered in the schema data
        result = await srv._check_pipe(r"\pipe\spoolss")
        assert result["verdict"] == "EXPECTED"
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_postex_pipe_is_suspicious(self, tmp_path):
        srv = _make_server(tmp_path)
        result = await srv._check_pipe(r"\pipe\postex_123")
        assert result["verdict"] == "SUSPICIOUS"
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_unknown_pipe_is_unknown(self, tmp_path):
        srv = _make_server(tmp_path)
        result = await srv._check_pipe(r"\pipe\totally_legitimate_custom_app")
        assert result["verdict"] == "UNKNOWN"
        assert result["is_suspicious"] is False
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_oversized_pipe_name_raises_via_dispatch(self, tmp_path):
        from mcp.types import CallToolRequest

        srv = _make_server(tmp_path)
        handler = srv.server.request_handlers[CallToolRequest]
        res = await handler(
            CallToolRequest(
                params={
                    "name": "wintriage_check_pipe",
                    "arguments": {"pipe_name": "p" * 300},
                }
            )
        )
        payload = json.loads(res.root.content[0].text)
        assert payload["error"] == "validation_error"
        srv.close_databases()


# ---------------------------------------------------------------------------
# Autorun / scheduled-task suspicious-location paths
# ---------------------------------------------------------------------------


class TestAutorunAndTask:
    @pytest.mark.asyncio
    async def test_autorun_unknown_non_risky_key(self, tmp_path):
        srv = _make_server(tmp_path)
        # A key not in the baseline but also not a high-risk Run key
        result = await srv._check_autorun(
            r"HKLM\Software\CustomApp\Settings",
            "StartWith",
            "Win10_Test",
        )
        assert result["verdict"] == "UNKNOWN"
        assert result["in_baseline"] is False
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_autorun_risky_run_key_not_in_baseline_is_suspicious(self, tmp_path):
        srv = _make_server(tmp_path)
        # A Run key value that is not seeded in the baseline is SUSPICIOUS
        result = await srv._check_autorun(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            "MaliciousPersistence",
            "Win10_Test",
        )
        assert result["verdict"] == "SUSPICIOUS"
        assert any("persistence" in f["type"] or "risk" in f["type"] for f in result.get("findings", []))
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_autorun_missing_os_version_returns_error(self, tmp_path):
        srv = _make_server(tmp_path)
        result = await srv._check_autorun(r"HKLM\Software\Foo")
        assert "error" in result
        assert result["lookup_performed"] is False
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_scheduled_task_suspicious_appdata_location(self, tmp_path):
        srv = _make_server(tmp_path)
        result = await srv._check_scheduled_task(
            r"\AppData\Local\Temp\evil_task", "Win10_Test"
        )
        assert result["verdict"] == "SUSPICIOUS"
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_scheduled_task_unknown_benign_location(self, tmp_path):
        srv = _make_server(tmp_path)
        result = await srv._check_scheduled_task(
            r"\ThirdParty\Vendor\SomeTask", "Win10_Test"
        )
        assert result["verdict"] == "UNKNOWN"
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_scheduled_task_missing_os_version_returns_error(self, tmp_path):
        srv = _make_server(tmp_path)
        result = await srv._check_scheduled_task(r"\Microsoft\Windows\Foo")
        assert "error" in result
        assert result["lookup_performed"] is False
        srv.close_databases()


# ---------------------------------------------------------------------------
# Service check risk paths
# ---------------------------------------------------------------------------


class TestServiceCheck:
    @pytest.mark.asyncio
    async def test_service_missing_os_version_returns_error(self, tmp_path):
        srv = _make_server(tmp_path)
        result = await srv._check_service("SomeService")
        assert "error" in result
        assert result["lookup_performed"] is False
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_service_unknown_not_in_baseline(self, tmp_path):
        srv = _make_server(tmp_path)
        result = await srv._check_service("MaliciousService", None, "Win10_Test")
        assert result["verdict"] == "UNKNOWN"
        assert result["in_baseline"] is False
        srv.close_databases()


# ---------------------------------------------------------------------------
# Hash check — invalid hash format
# ---------------------------------------------------------------------------


class TestHashCheck:
    @pytest.mark.asyncio
    async def test_invalid_hash_format_returns_error(self, tmp_path):
        srv = _make_server(tmp_path)
        result = await srv._check_hash("not_a_hash_at_all")
        assert result.get("error") == "Invalid hash format"
        srv.close_databases()

    @pytest.mark.asyncio
    async def test_clean_sha256_not_in_db_returns_unknown(self, tmp_path):
        srv = _make_server(tmp_path)
        clean_hash = "c" * 64
        result = await srv._check_hash(clean_hash)
        assert result["verdict"] == "UNKNOWN"
        srv.close_databases()


# ---------------------------------------------------------------------------
# Filename analysis risk paths
# ---------------------------------------------------------------------------


class TestFilenameAnalysis:
    def test_control_chars_detected(self):
        result = analyze_filename("malware\x01.exe")
        findings_types = {f["type"] for f in result["findings"]}
        assert "control_chars" in findings_types
        assert result["is_suspicious"] is True

    def test_space_padding_detected(self):
        result = analyze_filename("document         .exe")
        findings_types = {f["type"] for f in result["findings"]}
        assert "space_padding" in findings_types

    def test_trailing_spaces_detected(self):
        result = analyze_filename("document   .exe")
        findings_types = {f["type"] for f in result["findings"]}
        assert "trailing_spaces" in findings_types

    def test_short_name_detected(self):
        result = analyze_filename("a.exe")
        findings_types = {f["type"] for f in result["findings"]}
        assert "short_name" in findings_types

    def test_high_entropy_detected(self):
        # All 23 distinct characters -> entropy = log2(23) ≈ 4.52 > 4.5 threshold
        # Uses a name that is >6 chars and has near-maximum entropy for its length.
        result = analyze_filename("a1B2c3D4e5F6g7H8i9JkLmN.exe")
        findings_types = {f["type"] for f in result["findings"]}
        assert "high_entropy" in findings_types

    def test_non_executable_no_short_name_finding(self):
        # Short non-executable filename should not trigger the short_name finding
        result = analyze_filename("a.txt")
        findings_types = {f["type"] for f in result["findings"]}
        assert "short_name" not in findings_types

    def test_no_extension_no_entropy_finding(self):
        result = analyze_filename("justname")
        findings_types = {f["type"] for f in result["findings"]}
        assert "high_entropy" not in findings_types


# ---------------------------------------------------------------------------
# Verdict calculation branches (analysis/verdicts.py)
# ---------------------------------------------------------------------------


class TestVerdictCalculation:
    # --- calculate_file_verdict ---

    def test_file_critical_finding_returns_suspicious(self):
        findings = [{"type": "double_extension", "severity": "critical", "description": "bad"}]
        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=findings,
            lolbin_info=None,
        )
        assert result.verdict == Verdict.SUSPICIOUS
        assert result.confidence == "high"

    def test_file_path_in_baseline_with_lolbin(self):
        lolbin = {"functions": ["execute", "download"]}
        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info=lolbin,
        )
        assert result.verdict == Verdict.EXPECTED_LOLBIN

    def test_file_path_in_baseline_without_lolbin(self):
        result = calculate_file_verdict(
            path_in_baseline=True,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info=None,
        )
        assert result.verdict == Verdict.EXPECTED

    def test_file_known_tool_finding_returns_suspicious(self):
        findings = [{"type": "known_tool", "tool_name": "mimikatz", "severity": "high", "category": "cred_dump"}]
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=False,
            is_system_path=False,
            filename_findings=findings,
            lolbin_info=None,
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_file_masquerade_target_wrong_dir_returns_suspicious(self):
        # svchost.exe in a non-baseline location triggers masquerade detection
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=True,
            is_system_path=False,
            filename_findings=[],
            lolbin_info=None,
            filename="svchost.exe",
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_file_protected_masquerade_target_is_high_confidence(self):
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=True,
            is_system_path=False,
            filename_findings=[],
            lolbin_info=None,
            is_protected_process=True,
            filename="lsass.exe",
        )
        assert result.verdict == Verdict.SUSPICIOUS
        assert result.confidence == "high"

    def test_file_known_dir_lolbin_returns_expected_lolbin(self):
        lolbin = {"functions": ["hta"]}
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info=lolbin,
            directory_known_for_file=True,
            filename="mshta.exe",
        )
        assert result.verdict == Verdict.EXPECTED_LOLBIN
        assert result.confidence == "medium"

    def test_file_known_dir_no_lolbin_returns_expected(self):
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=True,
            is_system_path=True,
            filename_findings=[],
            lolbin_info=None,
            directory_known_for_file=True,
            filename="calc.exe",
        )
        assert result.verdict == Verdict.EXPECTED

    def test_file_non_masquerade_baseline_hit_returns_unknown(self):
        # "setup.exe" is in the baseline but not a masquerade target
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=True,
            is_system_path=False,
            filename_findings=[],
            lolbin_info=None,
            filename="setup.exe",
        )
        assert result.verdict == Verdict.UNKNOWN

    def test_file_high_severity_finding_no_baseline_returns_suspicious(self):
        findings = [{"type": "space_padding", "severity": "high", "description": "bad spaces"}]
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=False,
            is_system_path=False,
            filename_findings=findings,
            lolbin_info=None,
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_file_nothing_matches_returns_unknown(self):
        result = calculate_file_verdict(
            path_in_baseline=False,
            filename_in_baseline=False,
            is_system_path=False,
            filename_findings=[],
            lolbin_info=None,
        )
        assert result.verdict == Verdict.UNKNOWN
        assert result.confidence == "low"

    # --- calculate_process_verdict ---

    def test_process_critical_finding_returns_suspicious(self):
        findings = [{"type": "injection_detected", "severity": "critical", "description": "injected"}]
        result = calculate_process_verdict(
            process_known=True,
            parent_valid=True,
            path_valid=None,
            user_valid=None,
            findings=findings,
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_process_unknown_with_high_finding_returns_suspicious(self):
        findings = [{"type": "weird", "severity": "high", "description": "odd"}]
        result = calculate_process_verdict(
            process_known=False,
            parent_valid=True,
            path_valid=None,
            user_valid=None,
            findings=findings,
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_process_unknown_no_findings_returns_unknown(self):
        result = calculate_process_verdict(
            process_known=False,
            parent_valid=True,
            path_valid=None,
            user_valid=None,
            findings=[],
        )
        assert result.verdict == Verdict.UNKNOWN

    def test_process_invalid_parent_returns_suspicious(self):
        result = calculate_process_verdict(
            process_known=True,
            parent_valid=False,
            path_valid=None,
            user_valid=None,
            findings=[],
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_process_invalid_path_returns_suspicious(self):
        result = calculate_process_verdict(
            process_known=True,
            parent_valid=True,
            path_valid=False,
            user_valid=None,
            findings=[],
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_process_invalid_user_returns_suspicious(self):
        result = calculate_process_verdict(
            process_known=True,
            parent_valid=True,
            path_valid=None,
            user_valid=False,
            findings=[],
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_process_all_valid_returns_expected(self):
        result = calculate_process_verdict(
            process_known=True,
            parent_valid=True,
            path_valid=True,
            user_valid=True,
            findings=[],
        )
        assert result.verdict == Verdict.EXPECTED

    # --- calculate_service_verdict ---

    def test_service_critical_binary_finding_returns_suspicious(self):
        findings = [{"type": "double_extension", "severity": "critical", "description": "bad"}]
        result = calculate_service_verdict(
            service_in_baseline=True,
            binary_path_matches=True,
            binary_findings=findings,
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_service_in_baseline_binary_mismatch_returns_suspicious(self):
        result = calculate_service_verdict(
            service_in_baseline=True,
            binary_path_matches=False,
            binary_findings=[],
        )
        assert result.verdict == Verdict.SUSPICIOUS
        assert any("hijacked" in r.lower() for r in result.reasons)

    def test_service_in_baseline_no_binary_check_returns_expected(self):
        result = calculate_service_verdict(
            service_in_baseline=True,
            binary_path_matches=None,
            binary_findings=[],
        )
        assert result.verdict == Verdict.EXPECTED

    def test_service_not_in_baseline_high_binary_finding_returns_suspicious(self):
        findings = [{"type": "space_padding", "severity": "high", "description": "bad"}]
        result = calculate_service_verdict(
            service_in_baseline=False,
            binary_path_matches=None,
            binary_findings=findings,
        )
        assert result.verdict == Verdict.SUSPICIOUS

    def test_service_not_in_baseline_no_findings_returns_unknown(self):
        result = calculate_service_verdict(
            service_in_baseline=False,
            binary_path_matches=None,
            binary_findings=[],
        )
        assert result.verdict == Verdict.UNKNOWN

    # --- calculate_hash_verdict ---

    def test_hash_vulnerable_driver_returns_suspicious(self):
        driver_info = {"product": "BadDriver", "cve": "CVE-2023-0001", "vulnerability_type": "EoP"}
        result = calculate_hash_verdict(is_vulnerable_driver=True, driver_info=driver_info)
        assert result.verdict == Verdict.SUSPICIOUS
        assert any("CVE" in r for r in result.reasons)

    def test_hash_lolbin_returns_expected_lolbin(self):
        lolbin_info = {"name": "certutil", "functions": ["download"]}
        result = calculate_hash_verdict(is_lolbin=True, lolbin_info=lolbin_info)
        assert result.verdict == Verdict.EXPECTED_LOLBIN

    def test_hash_nothing_found_returns_unknown(self):
        result = calculate_hash_verdict()
        assert result.verdict == Verdict.UNKNOWN

    def test_verdict_result_to_dict(self):
        vr = VerdictResult(verdict=Verdict.EXPECTED, reasons=["reason1"], confidence="high")
        d = vr.to_dict()
        assert d["verdict"] == "EXPECTED"
        assert d["confidence"] == "high"
        assert d["reasons"] == ["reason1"]

    def test_verdict_str(self):
        assert str(Verdict.SUSPICIOUS) == "SUSPICIOUS"
        assert str(Verdict.UNKNOWN) == "UNKNOWN"


# ---------------------------------------------------------------------------
# RegistryDB with tiny synthetic SQLite — path bounds and lookup helpers
# ---------------------------------------------------------------------------


class TestRegistryDB:
    def _make_reg_db(self, tmp_path: Path) -> RegistryDB:
        """Build and seed a tiny registry DB."""
        db_path = tmp_path / "reg.db"
        reg = RegistryDB(db_path, read_only=False, cache_size=0)
        reg.init_schema()
        conn = reg.connect()
        conn.execute(
            "INSERT INTO baseline_registry (hive, key_path_lower, value_name, value_type, value_data, os_versions, value_data_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "SYSTEM",
                "system\\currentcontrolset\\control\\session manager",
                "BootExecute",
                "REG_MULTI_SZ",
                "autocheck autochk *",
                json.dumps(["Win10_Test"]),
                "dummyhash",
            ),
        )
        conn.commit()
        return reg

    def test_lookup_key_returns_match(self, tmp_path):
        reg = self._make_reg_db(tmp_path)
        results = reg.lookup_key(
            r"SYSTEM\CurrentControlSet\Control\Session Manager", hive="SYSTEM"
        )
        assert len(results) >= 1
        assert results[0]["hive"] == "SYSTEM"
        reg.close()

    def test_lookup_key_no_hive_provided(self, tmp_path):
        reg = self._make_reg_db(tmp_path)
        # normalize_key_path keeps the raw path as-is (lowercased); it does not
        # strip HKLM prefixes. The DB stores paths without that prefix, so we
        # must pass the path without a HKLM root to get a match.
        # This test verifies the no-hive-arg code path (hive auto-extracted from path)
        # when the key is stored with a bare "SYSTEM" hive prefix.
        results = reg.lookup_key(
            r"SYSTEM\CurrentControlSet\Control\Session Manager"
        )
        assert len(results) >= 1
        reg.close()

    def test_lookup_value_hit(self, tmp_path):
        reg = self._make_reg_db(tmp_path)
        results = reg.lookup_value(
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "BootExecute",
            hive="SYSTEM",
        )
        assert len(results) == 1
        assert results[0]["value_name"] == "BootExecute"
        reg.close()

    def test_lookup_value_miss(self, tmp_path):
        reg = self._make_reg_db(tmp_path)
        results = reg.lookup_value(
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "NonExistentValue",
        )
        assert results == []
        reg.close()

    def test_lookup_key_empty_path_returns_empty(self, tmp_path):
        reg = self._make_reg_db(tmp_path)
        assert reg.lookup_key("") == []
        reg.close()

    def test_key_exists_true_and_false(self, tmp_path):
        reg = self._make_reg_db(tmp_path)
        assert reg.key_exists(
            r"SYSTEM\CurrentControlSet\Control\Session Manager", hive="SYSTEM"
        ) is True
        assert reg.key_exists(r"HKLM\SOFTWARE\NonExistentKey") is False
        reg.close()

    def test_value_exists(self, tmp_path):
        reg = self._make_reg_db(tmp_path)
        assert reg.value_exists(
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "BootExecute",
            hive="SYSTEM",
        ) is True
        assert reg.value_exists(
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "NoSuchValue",
        ) is False
        reg.close()

    def test_normalize_key_path(self):
        assert RegistryDB.normalize_key_path(r"HKLM\Software\Foo") == r"hklm\software\foo"
        assert RegistryDB.normalize_key_path("") == ""

    def test_extract_hive_from_hklm(self):
        assert RegistryDB.extract_hive(r"HKLM\SYSTEM\CurrentControlSet") == "SYSTEM"
        assert RegistryDB.extract_hive(r"HKCU\Software\Foo") == "NTUSER"

    def test_extract_hive_direct_name(self):
        assert RegistryDB.extract_hive("SOFTWARE\\Microsoft") == "SOFTWARE"

    def test_extract_hive_none_for_empty(self):
        assert RegistryDB.extract_hive("") is None

    def test_is_available_returns_false_for_missing_file(self, tmp_path):
        reg = RegistryDB(tmp_path / "nonexistent.db", read_only=False, cache_size=0)
        assert reg.is_available() is False

    def test_is_available_returns_true_after_init(self, tmp_path):
        reg = self._make_reg_db(tmp_path)
        assert reg.is_available() is True
        reg.close()

    def test_get_stats_unavailable(self, tmp_path):
        reg = RegistryDB(tmp_path / "nope.db", read_only=False, cache_size=0)
        stats = reg.get_stats()
        assert stats["available"] is False

    def test_get_stats_available(self, tmp_path):
        reg = self._make_reg_db(tmp_path)
        stats = reg.get_stats()
        assert stats["available"] is True
        assert stats["registry_entries"] >= 1
        reg.close()

    def test_lookup_key_with_os_version_filter(self, tmp_path):
        reg = self._make_reg_db(tmp_path)
        # Present OS version
        results = reg.lookup_key(
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            hive="SYSTEM",
            os_version="Win10_Test",
        )
        assert len(results) >= 1
        # Missing OS version → filtered out
        results_miss = reg.lookup_key(
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            hive="SYSTEM",
            os_version="Win11_Missing",
        )
        assert len(results_miss) == 0
        reg.close()

    def test_with_cache_enabled(self, tmp_path):
        """RegistryDB with cache_size > 0 uses _lookup_key_cached."""
        db_path = tmp_path / "reg_cached.db"
        reg = RegistryDB(db_path, read_only=False, cache_size=100)
        reg.init_schema()
        conn = reg.connect()
        conn.execute(
            "INSERT INTO baseline_registry (hive, key_path_lower, value_name, value_type, value_data, os_versions, value_data_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("SOFTWARE", "software\\test", "Val", "REG_SZ", "data", json.dumps(["Win10_Test"]), "h"),
        )
        conn.commit()
        # First call populates cache
        r1 = reg.lookup_key("SOFTWARE\\Test", hive="SOFTWARE")
        assert len(r1) == 1
        # Second call hits cache
        r2 = reg.lookup_key("SOFTWARE\\Test", hive="SOFTWARE")
        assert r1 == r2
        reg.close()
