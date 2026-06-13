"""Gateway-centric audit DETAIL capture at the MCP policy boundary.

The AuditEnvelopeMiddleware records, for every tool call:
- PRE-dispatch (mcp.tool.call): the tool's REDACTED, bounded arguments under
  ``details['arguments']`` — uniform for core and proxied add-on tools.
- POST-dispatch (mcp.tool.result): a bounded result summary under
  ``details['result_summary']`` and, for run_command, the rich provenance/
  stages/privilege detail under ``details['detail']``.

Redaction is MANDATORY: secrets (JWTs/DSNs/keys/passwords) and sensitive
absolute paths (case/evidence/mount/state) must never land raw in the audit
row, and large values are truncated/bounded. Fail-closed semantics for mutating
tools on a failed required pre-dispatch audit are preserved (covered by
test_mvp_k1_db_audit.py and re-asserted here).
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastmcp.tools import ToolResult
from mcp.types import TextContent

from sift_core.active_case_context import AuthorityContext, use_active_case_context
from sift_gateway.active_case import ActiveCase
from sift_gateway.audit_helpers import (
    AuditPersistError,
    _extract_run_command_detail,
    redact_for_audit,
)
from sift_gateway.identity import Identity
from sift_gateway.policy_middleware import (
    AuditEnvelopeMiddleware,
    _use_gateway_active_case,
)


# --------------------------------------------------------------------------
# helpers / fakes
# --------------------------------------------------------------------------


def _identity() -> Identity:
    return Identity(
        principal="hermes",
        principal_type="agent",
        token_id="tok-1",
        agent_id="agent-1",
        created_by=None,
        role="agent",
        source_ip="127.0.0.1",
        auth_surface="mcp",
        tool_scopes=frozenset({"mcp:*"}),
        principal_id="agent-1",
    )


def _case() -> ActiveCase:
    return ActiveCase(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="db-case",
        title="DB Case",
        description=None,
        status="active",
        artifact_path="/cases/case-x",
        metadata={},
        membership_role="agent",
    )


class _FakeDbAudit:
    def __init__(self, fail_on=None):
        self.calls = []
        self._fail_on = fail_on
        self._n = 0

    def record(self, **kwargs):
        self.calls.append(kwargs)
        if self._fail_on is not None and kwargs.get("status") == self._fail_on:
            raise AuditPersistError("boom")
        self._n += 1
        return f"evt-{self._n}"


class _Gateway:
    def __init__(self, db_audit, manifest_meta=None):
        self.db_audit = db_audit
        self._audit = MagicMock()
        self._audit.log = MagicMock(return_value="aid")
        self._tool_map = {"run_command": "sift-core", "opensearch_search": "opensearch"}
        self.control_plane_dsn = "postgres://service@example/db"
        self._tool_manifest_meta = manifest_meta or {
            "opensearch_search": {"read_only": True},
        }


def _ctx(tool_name, arguments=None):
    return SimpleNamespace(
        message=SimpleNamespace(name=tool_name, arguments=arguments or {})
    )


def _result(payload: dict) -> ToolResult:
    return ToolResult(content=[TextContent(type="text", text=json.dumps(payload))])


def _run_with_envelope(mw, ctx, next_fn):
    auth = AuthorityContext(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="db-case",
        request_id="req-detail",
        db_active=True,
    )
    with patch(
        "sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()
    ):
        with use_active_case_context(auth), _use_gateway_active_case(_case()):
            return mw.on_call_tool(ctx, next_fn)


# --------------------------------------------------------------------------
# redact_for_audit unit coverage
# --------------------------------------------------------------------------


def test_redact_for_audit_strips_secret_and_sensitive_path():
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ_secretsig"
    args = {
        "command": "cat /cases/case-x/evidence/secret",
        "token": fake_jwt,
        "dsn": "postgres://user:supersecretpw@db.internal:5432/case",
    }
    out = redact_for_audit(args, case_dir="/cases/case-x")
    blob = json.dumps(out)
    # No raw secret material survives.
    assert "supersecretpw" not in blob
    assert fake_jwt not in blob
    # The sensitive absolute path under a sibling case root is redacted, not raw.
    assert "/cases/case-x/evidence/secret" not in blob


def test_redact_for_audit_bounds_large_values():
    big = "A" * 50_000
    out = redact_for_audit({"blob": big})
    assert len(json.dumps(out)) < 30_000  # bounded well below the raw size
    assert "[truncated]" in json.dumps(out)


def test_extract_run_command_detail_pulls_provenance_block():
    payload = {
        "tool": "run_command",
        "success": True,
        "provenance": {
            "input_sha256s": ["a" * 64],
            "output_sha256": "b" * 64,
            "audit_id": "AUD-1",
        },
        "stages": [{"binary": "grep", "exit_code": 0}],
        "data": {"exit_code": 0},
    }
    detail = _extract_run_command_detail([TextContent(type="text", text=json.dumps(payload))])
    assert detail is not None
    assert detail["provenance"]["output_sha256"] == "b" * 64
    assert detail["stages"][0]["binary"] == "grep"
    assert detail["exit_code"] == 0


def test_extract_run_command_detail_none_for_other_tools():
    payload = {"tool": "case_info", "success": True, "data": {"x": 1}}
    detail = _extract_run_command_detail([TextContent(type="text", text=json.dumps(payload))])
    assert detail is None


# --------------------------------------------------------------------------
# Envelope: arguments captured (all tools) + run_command detail
# --------------------------------------------------------------------------


async def test_envelope_records_redacted_arguments_for_addon_tool():
    db = _FakeDbAudit()
    mw = AuditEnvelopeMiddleware(_Gateway(db))

    async def _next(context):
        return _result({"tool": "opensearch_search", "success": True, "data": {"hits": 0}})

    await _run_with_envelope(
        mw, _ctx("opensearch_search", {"query_string": "EventID:4625"}), _next
    )

    pre = db.calls[0]
    assert pre["status"] == "requested"
    assert pre["details"]["arguments"]["query_string"] == "EventID:4625"


async def test_envelope_records_run_command_detail_and_args():
    db = _FakeDbAudit()
    mw = AuditEnvelopeMiddleware(_Gateway(db))

    async def _next(context):
        return _result(
            {
                "tool": "run_command",
                "success": True,
                "provenance": {
                    "input_sha256s": ["c" * 64],
                    "output_sha256": "d" * 64,
                    "audit_id": "AUD-9",
                },
                "stages": [{"binary": "fls", "exit_code": 0}],
                "privilege_escalation": {"used": False},
                "data": {"exit_code": 0},
            }
        )

    await _run_with_envelope(
        mw,
        _ctx("run_command", {"command": "fls -r image.E01", "purpose": "list files"}),
        _next,
    )

    # (a) redacted arguments captured pre-dispatch
    pre = db.calls[0]
    assert pre["details"]["arguments"]["command"] == "fls -r image.E01"
    # (b) rich provenance detail captured post-dispatch
    result_row = db.calls[1]
    assert result_row["status"] == "success"
    detail = result_row["details"]["detail"]
    assert detail["provenance"]["output_sha256"] == "d" * 64
    assert detail["stages"][0]["binary"] == "fls"
    assert detail["exit_code"] == 0


async def test_envelope_redaction_regression_no_secret_or_path_leak():
    """A fake absolute path and a token-like arg must appear REDACTED in details."""
    db = _FakeDbAudit()
    mw = AuditEnvelopeMiddleware(_Gateway(db))
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoZXJtZXMifQ.aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"

    async def _next(context):
        return _result({"tool": "run_command", "success": True, "data": {"exit_code": 0}})

    await _run_with_envelope(
        mw,
        _ctx(
            "run_command",
            {
                "command": "grep root /cases/case-x/evidence/secret",
                "auth_token": fake_jwt,
            },
        ),
        _next,
    )

    pre_blob = json.dumps(db.calls[0]["details"])
    assert fake_jwt not in pre_blob
    assert "/cases/case-x/evidence/secret" not in pre_blob


async def test_mutating_tool_still_fails_closed_when_required_audit_fails():
    """Fail-closed regression: detail capture must not weaken the gate."""
    db = _FakeDbAudit(fail_on="requested")
    mw = AuditEnvelopeMiddleware(_Gateway(db))
    dispatched = {"ran": False}

    async def _next(context):
        dispatched["ran"] = True
        return _result({"ok": True})

    with patch(
        "sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()
    ):
        # run_command is mutating (not read-only) -> must fail closed.
        result = await mw.on_call_tool(
            _ctx("run_command", {"command": "rm x"}), _next
        )

    assert result.is_error
    assert "audit_unavailable" in result.content[0].text
    assert dispatched["ran"] is False
