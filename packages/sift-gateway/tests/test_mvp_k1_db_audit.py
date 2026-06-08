"""BATCH-K1: DB-first transport audit envelope + fail-closed on audit failure.

Proves:
- AuditEnvelopeMiddleware reserves a pre-dispatch ``requested`` row and a
  ``result`` receipt in app.audit_events, carrying request/tool/principal/case
  fields and attaching the envelope id to the AuthorityContext.
- A mutating tool fails closed (backend never invoked) when the required
  pre-dispatch DB audit write fails.
- A read-only tool proceeds best-effort when the DB audit write fails.
- DbAuditWriter builds the insert and maps actor columns.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastmcp.tools import ToolResult
from mcp.types import TextContent

from sift_core.active_case_context import AuthorityContext, use_active_case_context
from sift_core.evidence_chain import ChainStatus
from sift_gateway.active_case import ActiveCase
from sift_gateway.audit_helpers import AuditPersistError, DbAuditWriter, _actor_columns
from sift_gateway.identity import Identity
from sift_gateway.policy_middleware import (
    AuditEnvelopeMiddleware,
    EvidenceGateMiddleware,
    gateway_policy_middlewares,
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
        artifact_path="/cases/db-case",
        metadata={},
        membership_role="agent",
    )


class _FakeDbAudit:
    def __init__(self, fail_on=None):
        self.calls = []
        self._fail_on = fail_on  # status value to fail on, e.g. "requested"
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
        self._tool_map = {"addon_write": "addon", "addon_read": "addon"}
        self.control_plane_dsn = "postgres://service@example/db"
        self._tool_manifest_meta = manifest_meta or {
            "addon_write": {"read_only": False},
            "addon_read": {"read_only": True},
        }


def _ctx(tool_name, arguments=None):
    return SimpleNamespace(
        message=SimpleNamespace(name=tool_name, arguments=arguments or {})
    )


async def _ok_next(context):
    return ToolResult(content=[TextContent(type="text", text="{}")])


# --------------------------------------------------------------------------
# DbAuditWriter
# --------------------------------------------------------------------------


class _FakeCursor:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params):
        self.store["sql"] = sql
        self.store["params"] = params

    def fetchone(self):
        return ("audit-id-1",)


class _FakeConn:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return _FakeCursor(self.store)

    def commit(self):
        self.store["committed"] = True


def test_db_audit_writer_inserts_and_returns_id():
    store: dict = {}
    writer = DbAuditWriter(connect=lambda: _FakeConn(store))
    eid = writer.record(
        event_type="mcp.tool.call",
        actor=_identity(),
        case_id="11111111-1111-1111-1111-111111111111",
        source="gateway_mcp_envelope",
        status="requested",
        summary="requested addon_write",
        request_id="req-1",
        details={"tool": "addon_write"},
    )
    assert eid == "audit-id-1"
    assert store["committed"] is True
    assert "insert into app.audit_events" in store["sql"]
    assert "req-1" in store["params"]
    assert "11111111-1111-1111-1111-111111111111" in store["params"]


def test_db_audit_writer_wraps_failure():
    def _boom():
        raise RuntimeError("db down")

    writer = DbAuditWriter(connect=_boom)
    with pytest.raises(AuditPersistError):
        writer.record(
            event_type="x", actor=None, case_id=None,
            source="s", status="requested",
        )


def test_actor_columns_agent_maps_agent_id():
    actor_type, user, agent, service, token = _actor_columns(_identity())
    assert actor_type == "agent"
    assert agent == "agent-1"
    assert user is None and service is None
    assert token == "tok-1"


# --------------------------------------------------------------------------
# AuditEnvelopeMiddleware — DB-first envelope
# --------------------------------------------------------------------------


async def test_envelope_records_requested_and_result_with_context_attach():
    db = _FakeDbAudit()
    gw = _Gateway(db)
    mw = AuditEnvelopeMiddleware(gw)
    ctx = AuthorityContext(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="db-case",
        request_id="req-xyz",
        db_active=True,
    )
    with patch(
        "sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()
    ):
        with use_active_case_context(ctx), _use_gateway_active_case(_case()):
            result = await mw.on_call_tool(_ctx("addon_write"), _ok_next)

    assert not result.is_error
    statuses = [c["status"] for c in db.calls]
    assert statuses == ["requested", "success"]
    pre = db.calls[0]
    assert pre["request_id"] == "req-xyz"
    assert pre["details"]["tool"] == "addon_write"
    assert pre["details"]["principal"] == "hermes"
    assert pre["case_id"] == "11111111-1111-1111-1111-111111111111"
    # envelope id attached to the authority context for mutating handlers (K2)
    assert ctx.audit_event_ids == ["evt-1"]


async def test_mutating_tool_fails_closed_when_required_audit_fails():
    db = _FakeDbAudit(fail_on="requested")
    gw = _Gateway(db)
    mw = AuditEnvelopeMiddleware(gw)
    dispatched = {"ran": False}

    async def _next(context):
        dispatched["ran"] = True
        return ToolResult(content=[TextContent(type="text", text="{}")])

    with patch(
        "sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()
    ):
        result = await mw.on_call_tool(_ctx("addon_write"), _next)

    assert result.is_error
    assert "audit_unavailable" in result.content[0].text
    assert dispatched["ran"] is False  # backend never invoked


async def test_read_only_tool_proceeds_when_audit_fails():
    db = _FakeDbAudit(fail_on="requested")
    gw = _Gateway(db)
    mw = AuditEnvelopeMiddleware(gw)
    dispatched = {"ran": False}

    async def _next(context):
        dispatched["ran"] = True
        return ToolResult(content=[TextContent(type="text", text="{}")])

    with patch(
        "sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()
    ):
        result = await mw.on_call_tool(_ctx("addon_read"), _next)

    assert not result.is_error
    assert dispatched["ran"] is True


async def test_no_db_audit_sink_is_legacy_jsonl_only():
    gw = _Gateway(db_audit=None)
    mw = AuditEnvelopeMiddleware(gw)
    with patch(
        "sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()
    ):
        result = await mw.on_call_tool(_ctx("addon_write"), _ok_next)
    assert not result.is_error
    # JSONL mirror still written
    assert gw._audit.log.called


def test_policy_order_wraps_proxy_and_evidence_denials_with_db_audit():
    names = [mw.__class__.__name__ for mw in gateway_policy_middlewares(_Gateway(None))]
    assert names.index("CaseContextMiddleware") < names.index("AuditEnvelopeMiddleware")
    assert names.index("AuditEnvelopeMiddleware") < names.index("ProxyActiveCaseMiddleware")
    assert names.index("AuditEnvelopeMiddleware") < names.index("EvidenceGateMiddleware")


async def test_evidence_gate_block_gets_db_requested_and_failure_receipts():
    db = _FakeDbAudit()
    gw = _Gateway(db)
    audit = AuditEnvelopeMiddleware(gw)
    gate = EvidenceGateMiddleware(gw)
    dispatched = {"ran": False}
    ctx = AuthorityContext(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="db-case",
        request_id="req-gate",
        db_active=True,
    )

    async def _next(context):
        dispatched["ran"] = True
        return ToolResult(content=[TextContent(type="text", text="{}")])

    async def _gate_next(context):
        return await gate.on_call_tool(context, _next)

    with patch(
        "sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()
    ), patch(
        "sift_gateway.policy_middleware.check_evidence_gate_db",
        return_value={
            "blocked": True,
            "status": ChainStatus.UNSEALED,
            "issues": ["No sealed evidence for this case"],
            "manifest_version": 0,
        },
    ):
        with use_active_case_context(ctx), _use_gateway_active_case(_case()):
            result = await audit.on_call_tool(_ctx("addon_write"), _gate_next)

    assert result.is_error
    assert dispatched["ran"] is False
    assert [c["status"] for c in db.calls] == ["requested", "failure"]
    assert db.calls[1]["details"]["envelope_event_id"] == "evt-1"
