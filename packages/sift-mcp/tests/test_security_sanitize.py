import logging

import pytest
from sift_mcp.security import sanitize_extra_args, validate_output_path


def test_sanitize_extra_args_rejects_null_byte():
    with pytest.raises(ValueError, match="Null byte"):
        sanitize_extra_args(["evidence\x00.bin"], tool_name="fls")


def test_sanitize_extra_args_rejects_long_argument():
    with pytest.raises(ValueError, match="Argument too long"):
        sanitize_extra_args(["a" * 4097], tool_name="fls")


def test_sanitize_extra_args_normalizes_non_nfc_argument(caplog):
    caplog.set_level(logging.INFO, logger="sift_mcp.security")
    decomposed = "case-e\u0301vidence"

    sanitized = sanitize_extra_args([decomposed], tool_name="fls")

    assert sanitized == ["case-\u00e9vidence"]
    assert "Normalized non-NFC argument" in caplog.text


def test_validate_output_path_allows_agent_dir(tmp_path, monkeypatch):
    case_dir = tmp_path / "case-001"
    agent_dir = case_dir / "agent" / "commands"
    agent_dir.mkdir(parents=True)
    monkeypatch.setenv("AGENTIR_CASE_DIR", str(case_dir))

    assert validate_output_path(str(agent_dir / "tool-output.txt")) == str(
        agent_dir / "tool-output.txt"
    )
