"""Tests for the §9 systemic audit-provenance contract (Unit 1 / Gap A).

Covers:
- Unified extractor: _extract_audit_id_from_result / _extract_all_audit_ids_from_result
  across content / structured_content / meta shapes (§9.4).
- AuditEnvelopeMiddleware: response stamping injects top-level audit_id (§9.5),
  backend_audit_id is set to the canonical id (§9.3 D1), audit_aliases include
  native ids + envelope uuid.
- _backend_name fix: run_command_job / running_commands_status → sift-core (§9.7).
- Conformance (§9.9): for EVERY registered tool (core plane enumerated
  exhaustively via agent_tools.core_tool_names(); durable-lane + the add-on
  fake-backend plane), all three §9.2 invariants hold — (a) the agent-visible
  response carries a top-level audit_id; (b) a mcp.tool.result row exists with
  non-empty details.backend_audit_id; (c) the resolver returns that row for the
  cited canonical id (+ aliases), driven from the ids the envelope ACTUALLY
  produced (round-trip closed via _faithful_resolver, a verbatim reimplementation
  of InvestigationService.audit_events's superset predicates).  A new-tool GUARD
  fails the day a registered tool is added without conformance coverage.
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

    def test_opensearch_native_id_in_aliases_canonical_is_envelope(self):
        """Option B: proxied add-on (opensearch) emits native id; canonical is the
        gateway's envelope uuid (not the native id); native id goes to audit_aliases."""
        mw, db = _make_mw()
        native_id = "opensearch-hermes-20260623-001"
        payload = {"audit_id": native_id, "total": 5}

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(type="text", text=json.dumps(payload))]
            )

        result = _run_envelope(mw, _ctx("opensearch_status"), _next)
        result_row = next(c for c in db.calls if c.get("event_type") == "mcp.tool.result")
        # Option B: canonical = envelope uuid, NOT the native opensearch id.
        canonical = result_row["details"]["backend_audit_id"]
        assert canonical != native_id, \
            "proxied backend: canonical must be envelope uuid, not native id"
        # Native id is preserved in audit_aliases for resolution.
        assert native_id in result_row["details"]["audit_aliases"]
        # Content carries the envelope uuid (stamped canonical, not native id).
        data = json.loads(result.content[0].text)
        assert data["audit_id"] == canonical

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

    def test_wintriage_meta_id_recovered_into_aliases_canonical_is_envelope(self):
        """Option B: wintriage (proxied) stores audit_id in ToolResult.meta; unified
        extractor recovers it into aliases, but canonical remains the envelope uuid."""
        mw, db = _make_mw()
        meta_id = "wintriage-hermes-20260623-001"

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(type="text", text='{"checks": []}')],
                meta={"audit_id": meta_id, "examiner": "hermes"},
            )

        result = _run_envelope(mw, _ctx("wintriage_check_system"), _next)
        result_row = next(c for c in db.calls if c.get("event_type") == "mcp.tool.result")
        # Option B: canonical = envelope uuid (not the native wintriage meta id).
        canonical = result_row["details"]["backend_audit_id"]
        assert canonical != meta_id, \
            "proxied backend: canonical must be envelope uuid, not meta id"
        # Native meta id preserved in audit_aliases.
        assert meta_id in result_row["details"]["audit_aliases"]
        # Content stamped with the envelope canonical (injected since content lacked audit_id).
        data = json.loads(result.content[0].text)
        assert data["audit_id"] == canonical

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
        canonical audit_id (Option B: envelope uuid for proxied tools) into
        structured_content so MCP clients rendering structured_content see the id.

        The native opensearch id is preserved in audit_aliases by the cap path
        and survives into aliases; the envelope uuid is canonical + stamped.
        Uses real guard_tool_result to produce the actual capped shape."""
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
        result_row = next(
            (c for c in db.calls if c.get("event_type") == "mcp.tool.result"), None
        )
        assert result_row is not None

        # Option B: canonical = envelope uuid (proxied add-on).
        canonical = result_row["details"]["backend_audit_id"]
        assert canonical != native_id, \
            "proxied backend: canonical must be envelope uuid, not native id"

        # structured_content must carry the canonical audit_id after stamp.
        assert isinstance(result.structured_content, dict), \
            "structured_content should be a dict (capped envelope)"
        assert "audit_id" in result.structured_content, \
            "structured_content missing audit_id after envelope stamp"
        assert result.structured_content["audit_id"] == canonical, \
            f"structured_content audit_id should be canonical {canonical!r}"

        # Native id is preserved in aliases (accessible via alias resolver predicate).
        aliases = result_row["details"].get("audit_aliases", [])
        assert native_id in aliases, \
            f"native id {native_id!r} should be in aliases {aliases!r}"


# ---------------------------------------------------------------------------
# §9.9 conformance — per-backend-category
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# §9.9 conformance — faithful in-test resolver + per-REGISTERED-tool coverage
# ---------------------------------------------------------------------------
#
# This block upgrades the previous hand-picked 5-tool sample to a per-registered
# tool conformance suite that asserts ALL THREE §9.2 invariants for EVERY
# registered tool (core plane exhaustively; add-on plane as completely as the
# existing fake-backend harness allows), AND fails the day a registered tool is
# added without conformance coverage (the §9.9 "never silently breaks" guard).


def _faithful_resolver(rows: list[dict], case_id: str, cited_ids: list[str]) -> list[dict]:
    """A faithful in-test reimplementation of the SUPERSET predicates in
    ``InvestigationService.audit_events`` (``sift_gateway/portal_services.py``,
    the six OR-clauses at ~:1686-1691), evaluated against the rows the envelope
    actually wrote via ``_FakeDbAudit.record``.

    Drives invariant (c) WITHOUT a live DB: given the canonical id + aliases the
    envelope produced for a tool call, this returns the matching audit row(s).

    Predicates (each ANDed with ``case_id``, mirroring the SECURITY INVARIANT
    that a requested id belonging to another case is never surfaced):
      1. ``id::text = any(ids)``                       — uuid PK / direct ref
      2. ``details->>'backend_audit_id' = any(ids)``   — gateway-stamped canonical
      3. ``details->'audit_aliases' ?| ids``           — any alias in the set
      4. ``details->>'envelope_event_id' = any(ids)``  — call-row uuid backstop
      5. ``request_id = any(ids)``                      — call↔result link
      6. ``details->>'audit_id' = any(ids)``           — parity (no producer today)

    ``_FakeDbAudit.record`` returns synthetic PKs like ``evt-N``; we treat the
    returned id as the row PK (it is appended onto each captured call below).
    """
    ids = {str(c) for c in cited_ids if str(c).strip()}
    if not ids:
        return []
    matched: list[dict] = []
    for row in rows:
        # SECURITY INVARIANT parity: case-scope every match.
        if str(row.get("case_id") or "") != str(case_id):
            continue
        det = row.get("details") or {}
        aliases = det.get("audit_aliases") or []
        if (
            str(row.get("_pk") or "") in ids  # (1) id::text
            or str(det.get("backend_audit_id") or "") in ids  # (2)
            or any(str(a) in ids for a in aliases)  # (3) audit_aliases ?|
            or str(det.get("envelope_event_id") or "") in ids  # (4)
            or str(row.get("request_id") or "") in ids  # (5)
            or str(det.get("audit_id") or "") in ids  # (6) parity
        ):
            matched.append(row)
    return matched


# ---------------------------------------------------------------------------
# Per-registered-tool COVERAGE registry.
#
# Maps every registered tool name → a representative (payload, meta) response
# shape exercising the relevant native-id surface.  Three planes are covered:
#   - CORE plane: enumerated EXHAUSTIVELY from agent_tools.core_tool_names().
#   - DURABLE-LANE: the gateway-embedded core tools (run_command_job /
#     running_commands_status) that _backend_name tags sift-core.
#   - PROXIED/add-on plane: as completely as the fake-backend harness's
#     _Gateway._tool_map registers (opensearch / wintriage / forensic-rag),
#     spanning content-native, meta-only, and no-native-id shapes.
#
# THE NEW-TOOL GUARD (test_every_registered_tool_has_conformance_coverage)
# asserts the union of all registered tool names == the COVERAGE keys, so the
# day a new core tool or add-on backend tool is registered without a coverage
# entry, that test FAILS — surfacing the missing conformance contract before a
# broken backend can ship.  To OBSERVE the failure: register a new tool (add to
# core_tool_names() or _Gateway._tool_map) WITHOUT adding it to _COVERAGE →
# test_every_registered_tool_has_conformance_coverage raises
# "registered tools without §9.9 conformance coverage: {...}".
# ---------------------------------------------------------------------------
_COVERAGE: dict[str, tuple[dict, dict | None]] = {
    # --- CORE plane (siftcore-* native id in content; canonical = native id) ---
    "run_command": ({"audit_id": "siftcore-hermes-20260623-001", "exit_code": 0}, None),
    "record_finding": ({"audit_id": "siftcore-hermes-20260623-002", "status": "DRAFT"}, None),
    "record_timeline_event": (
        {"audit_id": "siftcore-hermes-20260623-003", "event": "ok"},
        None,
    ),
    "list_existing_findings": ({"findings": []}, None),  # read-only, no native id
    "manage_todo": ({"audit_id": "siftcore-hermes-20260623-004", "todos": []}, None),
    "case_info": ({"case_id": "c-1"}, None),  # read-only, no native id
    "evidence_info": ({"evidence": []}, None),  # read-only, no native id
    "get_tool_help": ({"help": "..."}, None),  # read-only, no native id
    # --- DURABLE-LANE (sift-core; no native id here → envelope backstop) ---
    "run_command_job": ({"job_id": "j-1234"}, None),
    "running_commands_status": ({"jobs": []}, None),
    # --- PROXIED add-on plane (canonical ALWAYS = envelope uuid) ---
    # opensearch-mcp: scheme-formatted native id in content (kept in aliases).
    "opensearch_status": (
        {"audit_id": "opensearch-hermes-20260623-001", "status": "green"},
        None,
    ),
    # windows-triage-mcp: native id in META only (recovered into aliases).
    "wintriage_check_system": (
        {"checks": []},
        {"audit_id": "wintriage-hermes-20260623-001", "examiner": "hermes"},
    ),
    # forensic-rag-mcp: NO native id anywhere (pure envelope backstop).
    "kb_search_knowledge": ({"answer": "no match"}, None),
}


def _registered_tool_names() -> set[str]:
    """Union of every tool name the envelope tags + the fake-backend harness
    registers: core plane (exhaustive) + durable-lane + the add-on _tool_map.

    This is the authoritative "what is registered" set the new-tool guard
    compares against the _COVERAGE keys.
    """
    from sift_core.agent_tools import core_tool_names

    _mw, _db = _make_mw()
    addon_tools = set(getattr(_mw.gateway, "_tool_map", {}))
    return core_tool_names() | set(_CORE_DURABLE_LANE_TOOLS) | addon_tools


class TestConformancePerRegisteredTool:
    """§9.9: for EVERY registered tool, all three §9.2 invariants hold —
       (a) the agent-visible response carries a top-level ``audit_id``;
       (b) a ``mcp.tool.result`` row exists with non-empty
           ``details.backend_audit_id``;
       (c) the resolver returns that row for the cited canonical id (+ aliases),
           driven from the ids the envelope ACTUALLY produced.

    Lightweight: in-memory fakes (``_make_mw`` / ``_FakeDbAudit`` / ``_run_envelope``),
    no live DB.  Invariant (c) uses ``_faithful_resolver`` — a verbatim
    reimplementation of ``InvestigationService.audit_events``'s superset
    predicates evaluated against the rows the envelope wrote.
    """

    def test_every_registered_tool_has_conformance_coverage(self):
        """NEW-TOOL GUARD: the day a registered tool (core or add-on) lacks a
        coverage entry, this FAILS — so a new backend cannot ship without proving
        the §9.2 invariants.

        Observe the failure: add a tool to ``core_tool_names()`` or to
        ``_Gateway._tool_map`` WITHOUT adding it to ``_COVERAGE`` → this raises
        with the uncovered tool name(s).
        """
        registered = _registered_tool_names()
        covered = set(_COVERAGE)
        uncovered = registered - covered
        assert not uncovered, (
            "registered tools without §9.9 conformance coverage: "
            f"{sorted(uncovered)} — add a representative (payload, meta) entry to "
            "_COVERAGE so the (a)+(b)+(c) invariants are proven for this tool."
        )
        # Also guard the inverse: a coverage entry for a tool no longer
        # registered is stale and should be pruned (keeps the suite honest).
        stale = covered - registered
        assert not stale, (
            f"_COVERAGE has entries for tools that are no longer registered: "
            f"{sorted(stale)} — prune them."
        )

    @pytest.mark.parametrize("tool_name", sorted(_COVERAGE))
    def test_invariants_a_b_c_for_registered_tool(self, tool_name):
        payload, meta = _COVERAGE[tool_name]
        mw, db = _make_mw()

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(type="text", text=json.dumps(payload))],
                meta=meta,
            )

        result = _run_envelope(mw, _ctx(tool_name), _next)

        # --- §9.2 invariant (a): agent-visible response carries top-level audit_id.
        content_text = result.content[0].text if result.content else ""
        agent_visible_id: str | None = None
        try:
            data = json.loads(content_text)
            if isinstance(data, dict) and data.get("audit_id"):
                agent_visible_id = str(data["audit_id"])
        except json.JSONDecodeError:
            pass
        if agent_visible_id is None:
            # Non-JSON-object content — the id must then be visible in meta.
            meta_id = getattr(result, "meta", None)
            if isinstance(meta_id, dict):
                agent_visible_id = meta_id.get("audit_id")
        assert agent_visible_id, (
            f"{tool_name}: invariant (a) — no top-level audit_id on the "
            "agent-visible response (content or meta)"
        )

        # --- §9.2 invariant (b): result row has non-empty backend_audit_id.
        # Tag each captured row with its synthetic PK so the faithful resolver can
        # evaluate the id::text predicate exactly as the SQL would.
        for idx, c in enumerate(db.calls, start=1):
            c.setdefault("_pk", f"evt-{idx}")
        result_row = next(
            (c for c in db.calls if c.get("event_type") == "mcp.tool.result"), None
        )
        assert result_row is not None, f"{tool_name}: invariant (b) — no mcp.tool.result row"
        canonical = result_row["details"]["backend_audit_id"]
        assert canonical, f"{tool_name}: invariant (b) — backend_audit_id is empty/None"

        # The stamped agent-visible id must equal the canonical when content was a
        # JSON object (core preserves native; proxied stamps envelope uuid). For
        # meta-only / no-id shapes the canonical is the envelope uuid.
        aliases = result_row["details"].get("audit_aliases") or []

        # --- §9.2 invariant (c): resolver round-trip — citing [canonical]+aliases
        # returns the very row the envelope wrote, case-scoped.
        cited = [canonical, *aliases]
        case_id = result_row.get("case_id")
        resolved = _faithful_resolver(db.calls, case_id, cited)
        resolved_pks = {r.get("_pk") for r in resolved}
        assert result_row["_pk"] in resolved_pks, (
            f"{tool_name}: invariant (c) — resolver did not return the result row "
            f"for cited ids {cited!r} (resolved PKs: {sorted(resolved_pks)})"
        )

        # Defense-in-depth: citing the canonical ALONE must also resolve the row
        # (the canonical is the id an agent records in a finding).
        resolved_canonical = _faithful_resolver(db.calls, case_id, [canonical])
        assert result_row["_pk"] in {r.get("_pk") for r in resolved_canonical}, (
            f"{tool_name}: invariant (c) — canonical id {canonical!r} alone does "
            "not resolve the result row"
        )

    def test_cross_case_citation_is_not_surfaced(self):
        """SECURITY INVARIANT parity: a canonical id resolved under a DIFFERENT
        case_id must NOT return the row (mirrors the resolver's mandatory
        ``case_id = %s`` AND-scope)."""
        mw, db = _make_mw()

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(type="text", text='{"status": "green"}')]
            )

        _run_envelope(mw, _ctx("opensearch_status"), _next)
        for idx, c in enumerate(db.calls, start=1):
            c.setdefault("_pk", f"evt-{idx}")
        result_row = next(c for c in db.calls if c.get("event_type") == "mcp.tool.result")
        canonical = result_row["details"]["backend_audit_id"]
        # Resolving under a foreign case must yield nothing.
        foreign = _faithful_resolver(db.calls, "ffffffff-0000-0000-0000-000000000000", [canonical])
        assert foreign == [], "cross-case citation leaked a row (case-scope broken)"


# ---------------------------------------------------------------------------
# §9.3 Option B canonical selection — core vs proxied add-on
# ---------------------------------------------------------------------------


class TestOptionBCanonical:
    """Option B: core tools may use native id as canonical; proxied add-ons
    always use envelope_event_id as canonical regardless of backend-supplied ids."""

    def test_proxied_addon_with_meta_id_uses_envelope_as_canonical(self):
        """Proxied add-on emits audit_id in meta → canonical == envelope_event_id,
        native id still appears in audit_aliases, agent sees envelope id.

        Note: _FakeDbAudit.record() returns synthetic ids like 'evt-1' so the
        test checks envelope identity via details.envelope_event_id, not uuid format."""
        mw, db = _make_mw()
        native_id = "wintriage-hermes-20260623-001"

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(type="text", text='{"checks": []}')],
                meta={"audit_id": native_id, "examiner": "hermes"},
            )

        result = _run_envelope(mw, _ctx("wintriage_check_system"), _next)
        result_row = next(c for c in db.calls if c.get("event_type") == "mcp.tool.result")

        # canonical must equal the envelope_event_id (NOT the native wintriage id)
        canonical = result_row["details"]["backend_audit_id"]
        envelope_eid = result_row["details"]["envelope_event_id"]
        assert canonical == envelope_eid, \
            f"proxied: canonical {canonical!r} must equal envelope_event_id {envelope_eid!r}"
        assert canonical != native_id, \
            f"proxied: canonical must not be the native backend id {native_id!r}"

        # native id preserved in audit_aliases
        aliases = result_row["details"]["audit_aliases"]
        assert native_id in aliases, \
            f"native id {native_id!r} missing from audit_aliases {aliases!r}"

        # agent-visible content carries the envelope id, not the native id
        data = json.loads(result.content[0].text)
        assert data["audit_id"] == canonical, \
            f"content audit_id should be canonical {canonical!r}, got {data['audit_id']!r}"

    def test_core_tool_uses_native_id_as_canonical(self):
        """Core tool emits native siftgateway-* id → canonical == that native id."""
        mw, db = _make_mw()
        native_id = "siftgateway-hermes-20260623-001"

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(
                    type="text",
                    text=json.dumps({"audit_id": native_id, "exit_code": 0})
                )]
            )

        result = _run_envelope(mw, _ctx("run_command"), _next)
        result_row = next(c for c in db.calls if c.get("event_type") == "mcp.tool.result")

        canonical = result_row["details"]["backend_audit_id"]
        assert canonical == native_id, \
            f"core: canonical should be native id, got {canonical!r}"
        # content preserves the native id (already present, not overwritten)
        data = json.loads(result.content[0].text)
        assert data["audit_id"] == native_id

    def test_uuid_shaped_native_id_from_proxied_backend_dropped_from_aliases(self):
        """A uuid-shaped 'native id' from a proxied backend is excluded from aliases
        to prevent collision with real row PKs via the id::text resolver predicate."""
        mw, db = _make_mw()
        # Simulate a proxied backend that returns a bare uuid in its content.
        foreign_uuid = "12345678-abcd-ef01-2345-678901234567"

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(
                    type="text",
                    text=json.dumps({"audit_id": foreign_uuid, "hits": 3})
                )]
            )

        _run_envelope(mw, _ctx("opensearch_status"), _next)
        result_row = next(c for c in db.calls if c.get("event_type") == "mcp.tool.result")

        aliases = result_row["details"]["audit_aliases"]
        # The uuid-shaped foreign id must NOT be in aliases.
        assert foreign_uuid not in aliases, \
            f"uuid-shaped proxied id {foreign_uuid!r} should not be in aliases {aliases!r}"
        # But the envelope uuid (our own) IS in aliases as the backstop.
        envelope_eid = result_row["details"]["envelope_event_id"]
        assert envelope_eid in aliases, \
            f"envelope_event_id {envelope_eid!r} missing from aliases"

    def test_scheme_formatted_proxied_id_kept_in_aliases(self):
        """A scheme-formatted native id (e.g. opensearch-*) is kept in aliases
        even for proxied backends — it won't collide with uuid PKs."""
        mw, db = _make_mw()
        scheme_id = "opensearch-hermes-20260623-007"

        async def _next(_ctx):
            return ToolResult(
                content=[TextContent(
                    type="text",
                    text=json.dumps({"audit_id": scheme_id, "hits": 7})
                )]
            )

        _run_envelope(mw, _ctx("opensearch_status"), _next)
        result_row = next(c for c in db.calls if c.get("event_type") == "mcp.tool.result")

        aliases = result_row["details"]["audit_aliases"]
        assert scheme_id in aliases, \
            f"scheme-formatted id {scheme_id!r} missing from aliases {aliases!r}"
        # canonical is still the envelope uuid (Option B for proxied tools)
        canonical = result_row["details"]["backend_audit_id"]
        assert canonical != scheme_id, "proxied: canonical must be envelope uuid, not native scheme id"
