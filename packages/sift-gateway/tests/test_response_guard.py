"""Tests for sift_gateway.response_guard (Approach C).

Covers: scan_tool_result, redact_tool_result, override state lifecycle.
"""

from __future__ import annotations

import json
import time

import pytest
from fastmcp.tools import ToolResult
from mcp.types import TextContent

import sift_gateway.response_guard as rg
from sift_gateway.response_guard import (
    UNTRUSTED_OUTPUT_LABEL,
    cancel_override,
    enable_override,
    get_override_status,
    guard_tool_result,
    is_override_active,
    redact_tool_result,
    sanitize_untrusted_output_text,
    scan_tool_result,
)

_CASE = "/tmp/case-test-rg"


@pytest.fixture(autouse=True)
def _clear_override_state():
    rg._override_state.clear()
    yield
    rg._override_state.clear()


# ---------------------------------------------------------------------------
# scan_tool_result
# ---------------------------------------------------------------------------


class TestScanToolResult:
    def test_aws_access_key_detected(self):
        findings = scan_tool_result("AKIAIOSFODNN7EXAMPLE rest of text")
        assert len(findings) == 1
        assert findings[0]["pattern_name"] == "AWS Access Key"
        assert findings[0]["severity"] == "critical"
        assert findings[0]["char_offset"] == 0

    def test_clean_text_returns_empty(self):
        assert scan_tool_result("clean forensic output with no secrets") == []

    def test_github_token_detected(self):
        findings = scan_tool_result("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        names = [f["pattern_name"] for f in findings]
        assert "GitHub Token" in names

    def test_private_key_header_detected(self):
        findings = scan_tool_result("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        names = [f["pattern_name"] for f in findings]
        assert "RSA Private Key" in names

    def test_connection_string_detected(self):
        findings = scan_tool_result("postgres://user:password@host:5432/db")
        names = [f["pattern_name"] for f in findings]
        assert "Connection String" in names

    def test_bearer_token_detected(self):
        findings = scan_tool_result("Authorization: Bearer eyABC123tokenvalue")
        names = [f["pattern_name"] for f in findings]
        assert "Bearer Token" in names

    def test_medium_env_var_detected_not_critical(self):
        findings = scan_tool_result("SOME_SECRET=verylongvalue123\nother line")
        sev = {f["severity"] for f in findings}
        assert "medium" in sev
        assert "critical" not in sev or all(f["severity"] != "critical" for f in findings if f["pattern_name"] == "Env File Content")

    def test_multiple_findings_sorted_by_offset(self):
        text = "AKIAIOSFODNN7EXAMPLE ... Bearer sometoken123"
        findings = scan_tool_result(text)
        offsets = [f["char_offset"] for f in findings]
        assert offsets == sorted(offsets)

    def test_generic_password_high_severity(self):
        findings = scan_tool_result("password=SuperSecret123!")
        pw = [f for f in findings if f["pattern_name"] == "Generic Password"]
        assert pw
        assert pw[0]["severity"] == "high"

    # F2 regression: ewfinfo "Password" field false-positive investigation.
    # The {8,} bound in the Generic Password pattern already prevents short
    # benign forensic metadata values from matching.  These tests document the
    # confirmed-safe boundaries so future pattern changes cannot silently
    # re-introduce the false positive.
    def test_ewfinfo_password_na_not_flagged(self):
        """'Password: N/A' (3 chars) must NOT match — below the {8,} bound."""
        assert scan_tool_result("Password:\t\t\tN/A") == []
        assert scan_tool_result("Password: N/A") == []
        assert scan_tool_result("Password:                       N/A") == []

    def test_ewfinfo_password_not_set_not_flagged(self):
        """'Password: (not set)' — 9 chars but contains parentheses and spaces
        which break the [^\\s\"']{8,} character class (spaces are excluded)."""
        assert scan_tool_result("Password:                       (not set)") == []
        assert scan_tool_result("Set password:                   (not set)") == []

    def test_ewfinfo_password_empty_not_flagged(self):
        """Empty / whitespace-only value after 'Password:' → no match."""
        assert scan_tool_result("Password:") == []
        assert scan_tool_result("Password:          ") == []

    def test_ewfinfo_typical_block_not_redacted(self):
        """A typical ewfinfo metadata block with N/A password clears unmodified."""
        block = (
            "Acquisition date:\t2026-06-24\n"
            "System date:\t\t2026-06-24\n"
            "Password:\t\t\tN/A\n"
            "Set password:\t\t(not set)\n"
            "Compression method:\tdeflate\n"
        )
        redacted, findings = redact_tool_result(block)
        assert redacted == block, "ewfinfo block must not be redacted"
        assert findings == []


# ---------------------------------------------------------------------------
# redact_tool_result
# ---------------------------------------------------------------------------


class TestRedactToolResult:
    def test_aws_key_redacted_by_default(self):
        text = "Found key AKIAIOSFODNN7EXAMPLE in registry"
        redacted, findings = redact_tool_result(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        assert "[REDACTED:AWS Access Key]" in redacted
        assert len(findings) == 1

    def test_clean_text_unchanged(self):
        text = "no secrets here, just a normal log line"
        redacted, findings = redact_tool_result(text)
        assert redacted == text
        assert findings == []

    def test_medium_severity_not_redacted(self):
        text = "SOME_API_VAR=longvalue123456\nrest of output"
        redacted, findings = redact_tool_result(text)
        # Env File Content is medium — text not touched
        assert "SOME_API_VAR=longvalue123456" in redacted
        # But it appears in findings
        med = [f for f in findings if f["severity"] == "medium"]
        assert med

    def test_override_active_skips_redaction(self):
        text = "AKIAIOSFODNN7EXAMPLE in output"
        redacted, findings = redact_tool_result(text, override_active=True)
        assert redacted == text  # unchanged
        assert len(findings) == 1  # still scanned for audit

    def test_private_key_header_redacted(self):
        text = "key material:\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA..."
        redacted, findings = redact_tool_result(text)
        assert "-----BEGIN OPENSSH PRIVATE KEY-----" not in redacted
        assert "[REDACTED:OpenSSH Private Key]" in redacted

    def test_bearer_token_redacted(self):
        text = "HTTP header: Bearer abc123tokenXYZ"
        redacted, findings = redact_tool_result(text)
        # Bearer Token is high — should be redacted
        assert "[REDACTED:Bearer Token]" in redacted

    def test_findings_from_original_text(self):
        """Findings offsets reference the original text."""
        text = "AKIAIOSFODNN7EXAMPLE"
        redacted, findings = redact_tool_result(text)
        assert findings[0]["char_offset"] == 0


# ---------------------------------------------------------------------------
# untrusted output sanitation
# ---------------------------------------------------------------------------


class TestUntrustedOutputSanitation:
    def test_sanitize_untrusted_output_strips_ansi_osc_and_controls(self):
        text = "\x1b[31mred\x1b[0m \x1b]8;;http://x\x07click\x1b]8;;\x07\x00\x1f\nok\t"
        sanitized = sanitize_untrusted_output_text(text)
        assert "\x1b" not in sanitized
        assert "\x00" not in sanitized
        assert "\x1f" not in sanitized
        assert sanitized == "red click\nok\t"

    def test_guard_labels_run_command_json_output_fields(self):
        payload = {
            "success": True,
            "stdout": "\x1b]8;;http://x\x07click\x1b]8;;\x07\n",
            "stderr": "\x1b[31merr\x1b[0m",
        }
        result = ToolResult(content=[TextContent(type="text", text=json.dumps(payload))])

        guarded, findings, cap_events = guard_tool_result(
            result,
            override_active=False,
            case_dir=None,
            tool_name="run_command",
            cap_bytes=100_000,
        )

        body = json.loads(guarded.content[0].text)
        assert body["stdout"].startswith(UNTRUSTED_OUTPUT_LABEL)
        assert "\x1b" not in body["stdout"]
        assert body["stderr"].startswith(UNTRUSTED_OUTPUT_LABEL)
        assert guarded.meta["_sift_untrusted_output"]["label"] == UNTRUSTED_OUTPUT_LABEL
        assert findings == []
        assert cap_events == []

    def test_guard_sanitizes_and_labels_structured_run_command_output(self):
        result = ToolResult(
            structured_content={
                "stdout": "\x1b[32mok\x1b[0m",
                "nested": {"stderr_tail": "\x1b]0;bad\x07tail"},
            }
        )

        guarded, _, _ = guard_tool_result(
            result,
            override_active=False,
            case_dir=None,
            tool_name="run_command_job",
            cap_bytes=100_000,
        )

        assert guarded.structured_content["stdout"] == f"{UNTRUSTED_OUTPUT_LABEL}\nok"
        assert guarded.structured_content["nested"]["stderr_tail"] == (
            f"{UNTRUSTED_OUTPUT_LABEL}\ntail"
        )


# ---------------------------------------------------------------------------
# Override state
# ---------------------------------------------------------------------------


class TestOverrideState:
    def test_default_inactive(self):
        assert not is_override_active(_CASE)

    def test_enable_activates_override(self):
        enable_override(_CASE, "alice", ttl=300)
        assert is_override_active(_CASE)

    def test_enable_returns_status(self):
        status = enable_override(_CASE, "alice", ttl=300)
        assert status["active"] is True
        assert status["enabled_by"] == "alice"
        assert status["seconds_remaining"] > 0

    def test_cancel_clears_override(self):
        enable_override(_CASE, "alice", ttl=300)
        cancel_override(_CASE)
        assert not is_override_active(_CASE)

    def test_get_status_when_inactive(self):
        status = get_override_status(_CASE)
        assert status["active"] is False
        assert status["seconds_remaining"] == 0
        assert status["enabled_by"] is None

    def test_get_status_when_active(self):
        enable_override(_CASE, "bob", ttl=120)
        status = get_override_status(_CASE)
        assert status["active"] is True
        assert status["enabled_by"] == "bob"
        assert 0 < status["seconds_remaining"] <= 120

    def test_expired_override_auto_clears(self):
        rg._override_state[_CASE] = {
            "expires_at": time.monotonic() - 1,
            "enabled_by": "alice",
            "ttl": 1,
        }
        assert not is_override_active(_CASE)
        assert _CASE not in rg._override_state

    def test_cancel_nonexistent_is_safe(self):
        cancel_override("no-such-case")  # must not raise
