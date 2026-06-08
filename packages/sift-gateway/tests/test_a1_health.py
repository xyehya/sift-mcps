"""A1-BOOTSTRAP health.py targeted tests.

Covers _check_evidence_root: existence, permissions, write-protected detection.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from sift_gateway.health import _check_evidence_root


# ---------------------------------------------------------------------------
# _check_evidence_root
# ---------------------------------------------------------------------------

def test_evidence_root_ok(tmp_path):
    """Returns status=ok for a readable/writable directory."""
    result = _check_evidence_root(str(tmp_path))
    assert result["status"] == "ok"
    assert result["readable"] is True
    assert result["writable"] is True
    assert result["path"] == str(tmp_path)
    assert "case_count" in result
    assert isinstance(result["case_count"], int)


def test_evidence_root_counts_case_dirs(tmp_path):
    """case_count reflects subdirectory count."""
    (tmp_path / "case-one-05251400").mkdir()
    (tmp_path / "case-two-05251400").mkdir()
    result = _check_evidence_root(str(tmp_path))
    assert result["status"] == "ok"
    assert result["case_count"] == 2


def test_evidence_root_missing_returns_error():
    """Returns status=error when root does not exist."""
    result = _check_evidence_root("/nonexistent/path/to/cases")
    assert result["status"] == "error"
    assert result["readable"] is False
    assert "does not exist" in result.get("detail", "").lower()


def test_evidence_root_not_readable(tmp_path):
    """Returns status=error when root is not readable."""
    no_read = tmp_path / "noaccess"
    no_read.mkdir()
    original_mode = no_read.stat().st_mode
    try:
        no_read.chmod(0o000)
        result = _check_evidence_root(str(no_read))
        # Only meaningful when not running as root
        if os.getuid() != 0:
            assert result["status"] == "error"
            assert result["readable"] is False
    finally:
        no_read.chmod(original_mode)


def test_evidence_root_write_protected_flag_present(tmp_path):
    """write_protected key is always present in ok result."""
    result = _check_evidence_root(str(tmp_path))
    assert "write_protected" in result


def test_evidence_root_uses_env_fallback(tmp_path, monkeypatch):
    """Falls back to SIFT_CASES_ROOT env when cases_root arg is None."""
    monkeypatch.setenv("SIFT_CASES_ROOT", str(tmp_path))
    monkeypatch.delenv("SIFT_CASE_ROOT", raising=False)
    result = _check_evidence_root(None)
    assert result["status"] == "ok"
    assert result["path"] == str(tmp_path)


def test_evidence_root_uses_sift_case_root_env(tmp_path, monkeypatch):
    """Falls back to SIFT_CASE_ROOT env when SIFT_CASES_ROOT is unset."""
    monkeypatch.delenv("SIFT_CASES_ROOT", raising=False)
    monkeypatch.setenv("SIFT_CASE_ROOT", str(tmp_path))
    result = _check_evidence_root(None)
    assert result["status"] == "ok"
    assert result["path"] == str(tmp_path)
