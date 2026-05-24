"""Tests for sift_gateway.response_guard (Approach C).

Covers: scan_tool_result, redact_tool_result, override state lifecycle.
"""

from __future__ import annotations

import time

import pytest

import sift_gateway.response_guard as rg
from sift_gateway.response_guard import (
    cancel_override,
    enable_override,
    get_override_status,
    is_override_active,
    redact_tool_result,
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
