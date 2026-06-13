"""Regression: run_command must not emit the misleading file-ledger warning in
DB-authority mode.

In DB-authority mode there is no local audit directory, so the file
``AuditWriter.log()`` returns ``None``. The gateway MCP envelope is the
authoritative audit trail (it now captures command + provenance), so a missing
local JSONL ledger is expected, NOT a failure. run_command must therefore NOT
set ``response['warning'] == "Audit write failed — action not recorded"`` when
``db_authority_active()`` is True. File-authority mode (no DB) keeps the warning.
"""

from __future__ import annotations

from unittest.mock import patch

import sift_core.agent_tools as agent_tools
from sift_common.audit import AuditWriter
from sift_core.execute.exceptions import SiftError

_WARN = "Audit write failed — action not recorded"


class _NullAudit:
    """AuditWriter stand-in whose log() always returns None (no audit dir)."""

    def _next_audit_id(self, examiner=None):
        return "AUD-TEST-1"

    def log(self, *args, **kwargs):
        return None


def _drive_run_command():
    """Drive _run_command through its SiftError branch (which hits the warning
    decision) with a fake audit that returns None."""
    args = {"command": "ls", "purpose": "list"}
    with patch.object(
        agent_tools, "_execute_command", side_effect=SiftError("blocked by policy")
    ):
        return agent_tools._run_command(args, "analyst", _NullAudit())


def test_no_warning_in_db_authority_mode():
    with patch.object(agent_tools, "_db_authority_active", return_value=True):
        resp = _drive_run_command()
    assert resp.get("warning") != _WARN


def test_warning_still_set_in_file_authority_mode():
    with patch.object(agent_tools, "_db_authority_active", return_value=False):
        resp = _drive_run_command()
    # File-authority mode + None audit return => genuine failure => warning kept.
    assert resp.get("warning") == _WARN


# --------------------------------------------------------------------------
# audit.py: AuditWriter.log() no-op-success contract under DB-authority env.
# --------------------------------------------------------------------------


def _writer_without_dir(tmp_path):
    """An AuditWriter with no resolvable audit directory (DB-authority shape)."""
    w = AuditWriter(mcp_name="sift-core")
    # Force the no-audit-dir condition deterministically.
    w._get_audit_dir = lambda: None  # type: ignore[method-assign]
    return w


def test_audit_log_returns_none_without_db_env(tmp_path, monkeypatch):
    monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
    w = _writer_without_dir(tmp_path)
    assert w.log("run_command", {}, {"exit_code": 0}, audit_id="AUD-X") is None


def test_audit_log_no_op_success_under_db_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFT_DB_ACTIVE", "1")
    w = _writer_without_dir(tmp_path)
    # No audit dir but DB-authority env active => clean no-op-success receipt,
    # echoing the caller-supplied audit_id rather than None.
    assert w.log("run_command", {}, {"exit_code": 0}, audit_id="AUD-X") == "AUD-X"
