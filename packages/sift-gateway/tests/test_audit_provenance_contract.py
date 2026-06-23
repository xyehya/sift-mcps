"""Tests for the §9 systemic audit-provenance contract (Unit 1 / Gap A).

Covers:
- Unified extractor: _extract_audit_id_from_result / _extract_all_audit_ids_from_result
  across content / structured_content / meta shapes (§9.4).
- AuditEnvelopeMiddleware: response stamping injects top-level audit_id (§9.5),
  backend_audit_id is set to the canonical id (§9.3 D1), audit_aliases include
  native ids + envelope uuid.
- _backend_name fix: run_command_job / running_commands_status → sift-core (§9.7).
- Conformance: per-backend-category tool call results carry audit_id; result row
  has backend_audit_id; resolver returns the row for the cited id (§9.9).
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastmcp.tools import ToolResult
from mcp.types import TextContent

from sift_core.active_case_context import AuthorityContext, use_active_case_context
from sift_gateway.active_case import ActiveCase
from sift_gateway.audit_helpers import (
    AuditPersistError,
    _extract_all_audit_ids_from_result,
    _extract_audit_id_from_result,
)
from sift_gateway.identity import Identity
from sift_gateway.policy_middleware import (
    AuditEnvelopeMiddleware,
    _CORE_DURABLE_LANE_TOOLS,
    _use_gateway_active_case,
)
from sift_gateway.response_guard import guard_tool_result


# ---------------------------------------------------------------------------
# helpers / fakes
# ---------------------------------------------------------------------------


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
        case_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        case_key="test-case",
        title="Test Case",
        description=None,
        status="active",
        artifact_path="/cases/test-case",
        metadata={},
        membership_role="agent",
    )


class _FakeDbAudit:
    def __init__(self):
        self.calls: list[dict] = []
        self._n = 0

    def record(self, **kwargs):
        self.calls.append(kwargs)
        self._n += 1
        return f"evt-{self._n}"


class _Gateway:
    def __init__(self, db_audit, tool_map=None):
        self.db_audit = db_audit
        self._audit = MagicMock()
        self._audit.log = MagicMock(return_value="aid")
        self._tool_map = tool_map or {
            "opensearch_status": "opensearch-mcp",
            "wintriage_check_system": "windows-triage-mcp",
            "kb_search_knowledge": "forensic-rag-mcp",
        }
        self.control_plane_dsn = "postgres://service@example/db"
        self._tool_manifest_meta = {
            "opensearch_status": {"read_only": True},
            "wintriage_check_system": {"read_only": True},
            "kb_search_knowledge": {"read_only": True},
            "run_command": {"read_only": False},
            "run_command_job": {"read_only": False},
            "running_commands_status": {"read_only": True},
        }


def _ctx(tool_name, arguments=None):
    return SimpleNamespace(
        message=SimpleNamespace(name=tool_name, arguments=arguments or {})
    )


def _run_envelope(mw, ctx, next_fn):
    """Run AuditEnvelopeMiddleware.on_call_tool in an active-case context."""
    auth = AuthorityContext(
        case_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        case_key="test-case",
        request_id="req-provenance",
        db_active=True,
    )

    async def _wrapped():
        coro = mw.on_call_tool(ctx, next_fn)
        with patch(
            "sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()
        ):
            with use_active_case_context(auth), _use_gateway_active_case(_case()):
                return await coro

    return asyncio.run(_wrapped())


# ---------------------------------------------------------------------------
# §9.4 unified extractor — unit tests across shapes
# ---------------------------------------------------------------------------


class TestUnifiedExtractorSingle:
    """_extract_audit_id_from_result: returns first audit_id across all surfaces."""

    def test_content_text_json(self):
        """Core-style: audit_id embedded in content[0].text JSON."""
        tr = ToolResult(
            content=[TextContent(
                type="text",
                text=json.dumps({"audit_id": "siftgateway-hermes-20260623-001", "result": "ok"})
            )]
        )
        assert _extract_audit_id_from_result(tr) == "siftgateway-hermes-20260623-001"

    def test_structured_content_after_real_cap(self):
        """After ResponseGuard caps a large result, _cap_guarded_result preserves
        the native audit_id in structured_content so the extractor can recover it.
        Uses the real guard_tool_result path (not a fabricated shape)."""
        native_id = "opensearch-hermes-20260623-001"
        large_payload = {"audit_id": native_id, "hits": list(range(5000))}
        tr = ToolResult(
            content=[TextContent(type="text", text=json.dumps(large_payload))]
        )
        # Cap at 500 bytes — well below the full payload.
        guarded, _findings, _meta = guard_tool_result(
            tr, override_active=False, case_dir=None,
            tool_name="opensearch_search", cap_bytes=500,
        )
        # After cap: content is truncated (preview+marker), structured_content is
        # the _sift_output_capped envelope WITH the native audit_id preserved.
        assert guarded.structured_content is not None
        assert guarded.structured_content.get("audit_id") == native_id
        # Extractor should still recover the id from structured_content.
        assert _extract_audit_id_from_result(guarded) == native_id

    def test_meta_only(self):
        """Wintriage-style: audit_id in ToolResult.meta (ResultMeta field)."""
        tr = ToolResult(
            content=[TextContent(type="text", text='{"findings": []}')],
            meta={"audit_id": "wintriage-hermes-20260623-001", "examiner": "hermes"},
        )
        assert _extract_audit_id_from_result(tr) == "wintriage-hermes-20260623-001"

    def test_no_id_anywhere(self):
        """Rag-style: no audit_id anywhere → returns None."""
        tr = ToolResult(
            content=[TextContent(type="text", text='{"answer": "yes"}')]
        )
        assert _extract_audit_id_from_result(tr) is None

    def test_content_takes_priority_over_meta(self):
        """Content id wins over meta id (ordering: content → structured_content → meta)."""
        tr = ToolResult(
            content=[TextContent(
                type="text",
                text=json.dumps({"audit_id": "content-id", "x": 1})
            )],
            meta={"audit_id": "meta-id"},
        )
        assert _extract_audit_id_from_result(tr) == "content-id"

    def test_structured_content_takes_priority_over_meta(self):
        """structured_content id wins over meta id."""
        tr = ToolResult(
            content=[TextContent(type="text", text="[capped]")],
            structured_content={"audit_id": "sc-id"},
            meta={"audit_id": "meta-id"},
        )
        assert _extract_audit_id_from_result(tr) == "sc-id"

    def test_empty_content_list(self):
        """Empty content list with id in meta."""
        tr = ToolResult(
            content=[TextContent(type="text", text="[]")],
            meta={"audit_id": "meta-id"},
        )
        assert _extract_audit_id_from_result(tr) == "meta-id"

    def test_non_object_content_falls_through(self):
        """Content that parses as a list (not object) is skipped; meta is checked."""
        tr = ToolResult(
            content=[TextContent(type="text", text='["item1", "item2"]')],
            meta={"audit_id": "meta-id"},
        )
        assert _extract_audit_id_from_result(tr) == "meta-id"

    def test_fail_soft_on_bad_result(self):
        """Extractor returns None instead of raising on a broken object."""
        assert _extract_audit_id_from_result(None) is None
        assert _extract_audit_id_from_result("not a tool result") is None

    def test_whitespace_stripped(self):
        """Leading/trailing whitespace in audit_id values is stripped."""
        tr = ToolResult(
            content=[TextContent(type="text", text=json.dumps({"audit_id": "  siftgateway-001  "}))]
        )
        assert _extract_audit_id_from_result(tr) == "siftgateway-001"


class TestUnifiedExtractorAll:
    """_extract_all_audit_ids_from_result: returns ordered unique list across all surfaces."""

    def test_content_only(self):
        tr = ToolResult(
            content=[TextContent(type="text", text=json.dumps({"audit_id": "aid-1"}))]
        )
        assert _extract_all_audit_ids_from_result(tr) == ["aid-1"]

    def test_structured_content_adds_additional(self):
        """When content is capped, structured_content supplies the id."""
        tr = ToolResult(
            content=[TextContent(type="text", text="[capped]")],
            structured_content={"audit_id": "sc-aid"},
        )
        assert "sc-aid" in _extract_all_audit_ids_from_result(tr)

    def test_meta_adds_additional(self):
        tr = ToolResult(
            content=[TextContent(type="text", text='{}')],
            meta={"audit_id": "meta-aid"},
        )
        assert "meta-aid" in _extract_all_audit_ids_from_result(tr)

    def test_dedup_across_surfaces(self):
        """The same id appearing in content and structured_content is returned once."""
        tr = ToolResult(
            content=[TextContent(type="text", text=json.dumps({"audit_id": "same-id"}))],
            structured_content={"audit_id": "same-id"},
        )
        result = _extract_all_audit_ids_from_result(tr)
        assert result.count("same-id") == 1

    def test_audit_ids_list_key(self):
        """Values under audit_ids (list) key are expanded."""
        tr = ToolResult(
            content=[TextContent(
                type="text",
                text=json.dumps({"audit_ids": ["aid-a", "aid-b"]})
            )]
        )
        result = _extract_all_audit_ids_from_result(tr)
        assert "aid-a" in result
        assert "aid-b" in result

    def test_no_id_anywhere(self):
        tr = ToolResult(content=[TextContent(type="text", text='{"x": 1}')])
        assert _extract_all_audit_ids_from_result(tr) == []

    def test_fail_soft(self):
        """Returns empty list, never raises."""
        assert _extract_all_audit_ids_from_result(None) == []
        assert _extract_all_audit_ids_from_result(object()) == []


# ---------------------------------------------------------------------------
# §9.7 backend tagging — run_command_job / running_commands_status
# ---------------------------------------------------------------------------


class TestBackendTagging:
    def _mw(self):
        db = _FakeDbAudit()
        gw = _Gateway(db)
        return AuditEnvelopeMiddleware(gw)

    def test_durable_lane_tools_in_constant(self):
        assert "run_command_job" in _CORE_DURABLE_LANE_TOOLS
        assert "running_commands_status" in _CORE_DURABLE_LANE_TOOLS

    def test_run_command_job_tagged_sift_core(self):
        mw = self._mw()
        assert mw._backend_name("run_command_job") == "sift-core"

    def test_running_commands_status_tagged_sift_core(self):
        mw = self._mw()
        assert mw._backend_name("running_commands_status") == "sift-core"

    def test_core_tool_still_sift_core(self):
        mw = self._mw()
        assert mw._backend_name("run_command") == "sift-core"

    def test_capability_guide_still_sift_core(self):
        mw = self._mw()
        assert mw._backend_name("capability_guide") == "sift-core"

    def test_addon_tool_correct(self):
        mw = self._mw()
        assert mw._backend_name("opensearch_status") == "opensearch-mcp"

    def test_unknown_tool_falls_to_unknown(self):
        mw = self._mw()
        assert mw._backend_name("totally_unknown_tool") == "unknown"


# ---------------------------------------------------------------------------
# §9.5 response stamping + §9.3 canonical id recording
# ---------------------------------------------------------------------------


def _make_mw():
    db = _FakeDbAudit()
    gw = _Gateway(db)
    return AuditEnvelopeMiddleware(gw), db


class TestResponseStamping:
    """AuditEnvelopeMiddleware stamps audit_id into the returned ToolResult."""

    def test_core_tool_result_already_has_audit_id_preserved(self):
        """If content already has audit_id, it is not overwritten."""
        mw, db = _make_mw()
        payload = {"audit_id": "siftgateway-hermes-20260623-001", "result": "ok"}

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(type="text", text=json.dumps(payload))]
            )

        result = _run_envelope(mw, _ctx("run_command"), _next)
        data = json.loads(result.content[0].text)
        # Original id must be preserved exactly.
        assert data["audit_id"] == "siftgateway-hermes-20260623-001"

    def test_addon_result_gets_audit_id_stamped(self):
        """Add-on result without top-level audit_id gets one injected."""
        mw, db = _make_mw()
        payload = {"status": "green", "total_docs": 100}  # no audit_id

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(type="text", text=json.dumps(payload))]
            )

        result = _run_envelope(mw, _ctx("opensearch_status"), _next)
        data = json.loads(result.content[0].text)
        assert "audit_id" in data
        assert data["audit_id"]  # non-empty

    def test_opensearch_native_id_promoted_and_used_as_canonical(self):
        """When the backend emits audit_id, that id becomes the canonical."""
        mw, db = _make_mw()
        native_id = "opensearch-hermes-20260623-001"
        payload = {"audit_id": native_id, "total": 5}

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(type="text", text=json.dumps(payload))]
            )

        result = _run_envelope(mw, _ctx("opensearch_status"), _next)
        data = json.loads(result.content[0].text)
        # Native id is preserved in content.
        assert data["audit_id"] == native_id
        # Result row records native as canonical backend_audit_id.
        result_row = next(c for c in db.calls if c.get("event_type") == "mcp.tool.result")
        assert result_row["details"]["backend_audit_id"] == native_id

    def test_rag_no_native_id_gets_envelope_uuid_as_canonical(self):
        """When no backend id exists, envelope_event_id becomes backend_audit_id."""
        mw, db = _make_mw()

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(type="text", text='{"answer": "42"}')]
            )

        result = _run_envelope(mw, _ctx("kb_search_knowledge"), _next)
        result_row = next(c for c in db.calls if c.get("event_type") == "mcp.tool.result")
        # backend_audit_id must be set (envelope uuid, not None).
        assert result_row["details"]["backend_audit_id"] is not None
        assert result_row["details"]["backend_audit_id"]  # non-empty
        # Content should have been stamped with the same id.
        data = json.loads(result.content[0].text)
        assert data["audit_id"] == result_row["details"]["backend_audit_id"]

    def test_wintriage_meta_id_recovered_and_used_as_canonical(self):
        """Wintriage stores audit_id in ToolResult.meta; unified extractor recovers it."""
        mw, db = _make_mw()
        meta_id = "wintriage-hermes-20260623-001"

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(type="text", text='{"checks": []}')],
                meta={"audit_id": meta_id, "examiner": "hermes"},
            )

        result = _run_envelope(mw, _ctx("wintriage_check_system"), _next)
        result_row = next(c for c in db.calls if c.get("event_type") == "mcp.tool.result")
        # Meta id recovered as canonical.
        assert result_row["details"]["backend_audit_id"] == meta_id
        # Content should also be stamped (meta id promoted into content JSON).
        data = json.loads(result.content[0].text)
        assert data["audit_id"] == meta_id

    def test_audit_aliases_include_native_and_envelope(self):
        """audit_aliases in the result row includes both native id and envelope uuid."""
        mw, db = _make_mw()
        native_id = "opensearch-hermes-20260623-002"

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(
                    type="text",
                    text=json.dumps({"audit_id": native_id, "hits": 3})
                )]
            )

        _run_envelope(mw, _ctx("opensearch_status"), _next)
        result_row = next(c for c in db.calls if c.get("event_type") == "mcp.tool.result")
        aliases = result_row["details"]["audit_aliases"]
        assert native_id in aliases
        # Envelope uuid is always present as a backstop.
        envelope_id = result_row["details"]["envelope_event_id"]
        assert envelope_id in aliases

    def test_stamping_fail_soft_non_object_root(self):
        """Non-JSON-object content root doesn't break tool call; audit_id in meta."""
        mw, db = _make_mw()

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(type="text", text='["item1", "item2"]')]
            )

        # Must not raise.
        result = _run_envelope(mw, _ctx("opensearch_status"), _next)
        assert result is not None
        result_row = next(c for c in db.calls if c.get("event_type") == "mcp.tool.result")
        # backend_audit_id still populated (envelope uuid).
        assert result_row["details"]["backend_audit_id"] is not None

    def test_backend_audit_id_always_set(self):
        """backend_audit_id is never None in the result row (invariant §9.2)."""
        mw, db = _make_mw()

        async def _next(_ctx):
            return ToolResult(content=[TextContent(type="text", text="{}")])

        _run_envelope(mw, _ctx("kb_search_knowledge"), _next)
        result_row = next(c for c in db.calls if c.get("event_type") == "mcp.tool.result")
        assert result_row["details"]["backend_audit_id"] is not None

    def test_capped_structured_content_gets_audit_id_stamped(self):
        """After ResponseGuard caps a large response, AuditEnvelope stamps the
        canonical audit_id into structured_content so MCP clients that render
        structured_content over content still see the id.

        Uses real guard_tool_result to produce the actual capped shape, then
        runs the full AuditEnvelopeMiddleware stamp pass."""
        mw, db = _make_mw()
        native_id = "opensearch-hermes-20260623-999"
        large_payload = {"audit_id": native_id, "hits": list(range(5000))}
        large_text = json.dumps(large_payload)

        async def _next(_ctx):
            # Simulate ResponseGuard (inner middleware) capping the result.
            raw = ToolResult(content=[TextContent(type="text", text=large_text)])
            guarded, _findings, _cap_meta = guard_tool_result(
                raw, override_active=False, case_dir=None,
                tool_name="opensearch_search", cap_bytes=500,
            )
            return guarded

        result = _run_envelope(mw, _ctx("opensearch_search"), _next)

        # structured_content must carry audit_id after the envelope stamp.
        assert isinstance(result.structured_content, dict), \
            "structured_content should be a dict (capped envelope)"
        assert "audit_id" in result.structured_content, \
            "structured_content missing audit_id after envelope stamp"
        # The native id is preserved (not the envelope backstop).
        assert result.structured_content["audit_id"] == native_id, \
            f"expected native id {native_id!r}, got {result.structured_content['audit_id']!r}"
        # The canonical in the DB row matches too.
        result_row = next(
            (c for c in db.calls if c.get("event_type") == "mcp.tool.result"), None
        )
        assert result_row is not None
        assert result_row["details"]["backend_audit_id"] == native_id


# ---------------------------------------------------------------------------
# §9.9 conformance — per-backend-category
# ---------------------------------------------------------------------------


class TestConformancePerCategory:
    """For each backend category, the result carries audit_id and the DB row has
    backend_audit_id set.  Lightweight: these use in-memory fakes, not the DB.
    """

    @pytest.mark.parametrize(
        "tool_name,payload,meta",
        [
            # sift-core/run_command: native id in content
            (
                "run_command",
                {"audit_id": "siftgateway-hermes-20260623-001", "exit_code": 0},
                None,
            ),
            # opensearch-mcp: native id in content
            (
                "opensearch_status",
                {"audit_id": "opensearch-hermes-20260623-001", "status": "green"},
                None,
            ),
            # windows-triage-mcp: native id in meta only
            (
                "wintriage_check_system",
                {"checks": []},
                {"audit_id": "wintriage-hermes-20260623-001", "examiner": "hermes"},
            ),
            # forensic-rag-mcp: no native id (backstop envelope)
            (
                "kb_search_knowledge",
                {"answer": "no match"},
                None,
            ),
            # durable-lane: run_command_job (no native id here)
            (
                "run_command_job",
                {"job_id": "j-1234"},
                None,
            ),
        ],
    )
    def test_response_has_audit_id_and_row_has_backend_audit_id(
        self, tool_name, payload, meta
    ):
        mw, db = _make_mw()

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(type="text", text=json.dumps(payload))],
                meta=meta,
            )

        result = _run_envelope(mw, _ctx(tool_name), _next)

        # §9.2 invariant (a): agent-visible response has top-level audit_id.
        content_text = result.content[0].text if result.content else ""
        try:
            data = json.loads(content_text)
            assert "audit_id" in data, f"{tool_name}: content missing audit_id"
            assert data["audit_id"], f"{tool_name}: audit_id is empty"
        except json.JSONDecodeError:
            # Non-JSON content — check meta instead.
            assert getattr(result, "meta", {}).get("audit_id"), \
                f"{tool_name}: neither content nor meta has audit_id"

        # §9.2 invariant (b): result row has backend_audit_id set.
        result_row = next(
            (c for c in db.calls if c.get("event_type") == "mcp.tool.result"), None
        )
        assert result_row is not None, f"{tool_name}: no mcp.tool.result row"
        assert result_row["details"]["backend_audit_id"] is not None, \
            f"{tool_name}: backend_audit_id is None"
        assert result_row["details"]["backend_audit_id"], \
            f"{tool_name}: backend_audit_id is empty"
