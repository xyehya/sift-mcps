"""M-INGSTATUS: gateway OpenSearchIngestStatusAugmentMiddleware tests.

Root cause: the opensearch backend is a stdio subprocess with no DB credentials
(by design). In DB-active mode its opensearch_ingest_status always returns
ingests=[] + authority='postgres-durable-jobs'.  The gateway must intercept that
response and populate ingests[] from app.job_status_public via JobService.

These tests drive the REAL middleware through a FastMCP server stub, following the
same harness style as test_opensearch_dispatch_middleware.py.
"""

from __future__ import annotations

import json

import pytest
from fastmcp import FastMCP
from fastmcp.tools import ToolResult
from mcp.types import TextContent

from sift_gateway.active_case import ActiveCase
from sift_gateway.identity import Identity
from sift_gateway.policy_middleware import (
    OpenSearchIngestStatusAugmentMiddleware,
    _use_gateway_active_case,
)
from sift_gateway.server import Gateway


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_ACTIVE = ActiveCase(
    case_id="a4b8a875-cd32-4d75-a3c5-d3e8eb9e277a",
    case_key="case-test-case-06251017",
    title="Test Case",
    description=None,
    status="active",
    artifact_path="/cases/case-test-case-06251017",
    metadata={},
    membership_role="owner",
)

# Fake durable job row as JobService.list_ingest_jobs_for_case returns.
_FAKE_JOB_ROW = {
    "job_id": "aabb-1234-ccdd-5678",
    "job_type": "ingest",
    "status": "running",
    "case_id": "a4b8a875-cd32-4d75-a3c5-d3e8eb9e277a",
    "evidence_id": None,
    "priority": 100,
    "attempts": 1,
    "max_attempts": 3,
    "spec_public": {"path": "evidence/rocba-cdrive.e01"},
    "result_public": {"indexed_docs": 5000},
    "error_summary": None,
    "provenance_id": None,
    "created_at": "2026-06-25T10:00:00Z",
    "started_at": "2026-06-25T10:01:00Z",
    "finished_at": None,
    "updated_at": "2026-06-25T10:05:00Z",
    "step_count": 3,
    "steps_succeeded": 2,
    "worker_label": "osw-ingest-1234",
    "current_step": {"name": "evtx", "detail": "12000 indexed"},
}


def _agent_identity():
    return Identity(
        principal="hermes",
        principal_type="agent",
        token_id="t1",
        agent_id="hermes",
        created_by="alice",
        role="agent",
        source_ip=None,
        auth_surface="mcp",
        case_id="a4b8a875-cd32-4d75-a3c5-d3e8eb9e277a",
        principal_id="hermes",
        case_memberships=(),
    )


class _FakeJobService:
    """Configurable fake JobService for list_ingest_jobs_for_case."""

    def __init__(self, rows=None, raise_exc=None):
        self.rows = rows if rows is not None else []
        self.raise_exc = raise_exc
        self.calls: list[str] = []

    def list_ingest_jobs_for_case(self, case_id: str, **kwargs) -> list[dict]:
        self.calls.append(case_id)
        if self.raise_exc:
            raise self.raise_exc
        return self.rows


def _gateway_with_job_service(rows=None, raise_exc=None):
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": []}}})
    gateway.job_service = _FakeJobService(rows=rows, raise_exc=raise_exc)
    return gateway


def _server(gateway, backend_payload: dict):
    """Mount the augment middleware over a stub that returns a fixed backend payload.

    The stub returns a ToolResult with BOTH content (text) and structured_content,
    mirroring the real opensearch_ingest_status backend which declares an outputSchema
    (IngestStatusOut) and therefore always sets structured_content.  This is critical:
    the augment middleware must preserve structured_content on its returned ToolResult —
    FastMCP's live output validator rejects a result whose structured_content is None
    when outputSchema is defined.
    """
    mcp = FastMCP("parent", middleware=[OpenSearchIngestStatusAugmentMiddleware(gateway)])

    @mcp.tool(name="opensearch_ingest_status")
    async def _status(case_id: str = "", job_id: str = "", case_dir: str = ""):
        # Return a ToolResult with structured_content set, like the real backend does.
        text = json.dumps(backend_payload)
        return ToolResult(
            content=[TextContent(type="text", text=text)],
            structured_content=backend_payload,
            is_error=False,
        )

    return mcp


async def _call(gateway, args: dict, backend_payload: dict, *, identity=None):
    from unittest.mock import patch

    mcp = _server(gateway, backend_payload)
    identity = identity or _agent_identity()
    with (
        patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=identity),
        _use_gateway_active_case(_ACTIVE),
    ):
        return await mcp.call_tool("opensearch_ingest_status", args)


# Backend envelope that opensearch_ingest_status returns in DB-active mode.
_BACKEND_DB_ACTIVE_ENVELOPE = {
    "ingests": [],
    "authority": "postgres-durable-jobs",
    "message": (
        "No active or recent ingest/enrich jobs found for this case. "
        "If your opensearch_ingest returned a job_id (status='queued'), "
        "poll running_commands_status(job_id=<that job_id>) directly. "
        "Confirm a completed ingest with opensearch_count / "
        "opensearch_case_summary on the target indices."
    ),
}


# ---------------------------------------------------------------------------
# M-INGSTATUS: gateway augments ingests[] from DB
# ---------------------------------------------------------------------------


async def test_augment_populates_ingests_from_job_service():
    """M-INGSTATUS: gateway augments ingests[] with durable job rows from DB.

    The backend returns ingests=[] + authority envelope; the middleware replaces
    ingests[] with the rows returned by JobService.list_ingest_jobs_for_case.
    """
    gateway = _gateway_with_job_service(rows=[_FAKE_JOB_ROW])
    result = await _call(gateway, {}, _BACKEND_DB_ACTIVE_ENVELOPE)

    assert not result.is_error
    payload = json.loads(result.content[0].text)

    ingests = payload.get("ingests", [])
    assert len(ingests) == 1, f"Expected 1 ingest row after augmentation, got {len(ingests)}"

    run = ingests[0]
    assert run["status"] == "running"
    assert run["case_id"] == "a4b8a875-cd32-4d75-a3c5-d3e8eb9e277a"

    # details must be FLAT — job_id at ingests[0].details.job_id, not double-nested.
    details = run.get("details", {})
    assert details.get("job_id") == "aabb-1234-ccdd-5678", (
        f"job_id must be flat in details: {details!r}"
    )
    assert details.get("worker_label") == "osw-ingest-1234"
    assert "details" not in details, (
        f"Double-nesting detected: details.details exists: {details.get('details')!r}"
    )

    # message in the ingest run must reference running_commands_status.
    msg = run.get("message", "")
    assert "running_commands_status" in msg, (
        f"Run message must name running_commands_status: {msg!r}"
    )

    # authority preserved from backend envelope.
    assert payload.get("authority") == "postgres-durable-jobs"

    # job_service was queried with the case UUID (not the case_key).
    assert gateway.job_service.calls == ["a4b8a875-cd32-4d75-a3c5-d3e8eb9e277a"], (
        "JobService must be called with the case UUID from ActiveCase.case_id"
    )


async def test_augment_result_has_structured_content():
    """Augmented ToolResult MUST carry structured_content (not text-only).

    opensearch_ingest_status declares outputSchema (IngestStatusOut).  FastMCP's
    live output validator rejects ToolResult.structured_content=None with:
      "outputSchema defined but no structured output returned"

    This test is the regression guard that would have caught the original bug:
    a text-only ToolResult (structured_content=None or missing) must FAIL here.
    """
    gateway = _gateway_with_job_service(rows=[_FAKE_JOB_ROW])
    result = await _call(gateway, {}, _BACKEND_DB_ACTIVE_ENVELOPE)

    assert not result.is_error
    # structured_content must be a dict — never None.
    assert isinstance(result.structured_content, dict), (
        f"structured_content must be a dict for outputSchema compliance, "
        f"got: {type(result.structured_content).__name__!r} = {result.structured_content!r}. "
        "A text-only ToolResult causes 'outputSchema defined but no structured output returned' live."
    )
    # The dict must carry the augmented ingests[].
    sc = result.structured_content
    assert "ingests" in sc, f"structured_content missing 'ingests': {sc!r}"
    assert len(sc["ingests"]) == 1, (
        f"structured_content.ingests must contain 1 row: {sc['ingests']!r}"
    )
    # Authority field must be present.
    assert sc.get("authority") == "postgres-durable-jobs", (
        f"structured_content missing authority: {sc!r}"
    )
    # ingests[] in structured_content must match content (text) — no split-brain.
    payload_from_text = json.loads(result.content[0].text)
    assert sc["ingests"] == payload_from_text["ingests"], (
        "structured_content.ingests must match the text representation"
    )


async def test_augment_updates_summary_message_when_jobs_found():
    """Summary message must reflect the count of found jobs when ingests[] is non-empty."""
    gateway = _gateway_with_job_service(rows=[_FAKE_JOB_ROW])
    result = await _call(gateway, {}, _BACKEND_DB_ACTIVE_ENVELOPE)

    payload = json.loads(result.content[0].text)
    msg = payload.get("message", "")
    assert "1 ingest/enrich job(s) found" in msg, (
        f"Summary message must report job count: {msg!r}"
    )
    assert "running_commands_status" in msg


async def test_augment_preserves_empty_ingests_when_no_jobs():
    """When job_service returns [] (no active jobs), ingests stays [] with redirect message."""
    gateway = _gateway_with_job_service(rows=[])
    result = await _call(gateway, {}, _BACKEND_DB_ACTIVE_ENVELOPE)

    payload = json.loads(result.content[0].text)
    assert payload.get("ingests") == [], "No jobs → ingests must remain []"
    assert payload.get("authority") == "postgres-durable-jobs"
    msg = payload.get("message", "")
    assert "running_commands_status" in msg, (
        f"Redirect message must reference running_commands_status: {msg!r}"
    )


async def test_augment_fail_closed_on_db_error():
    """If JobService.list_ingest_jobs_for_case raises, middleware returns backend result unchanged.

    Fail-closed: DB errors must never crash the call; the original authority envelope
    (ingests=[], authority, message, and structured_content) is returned as-is.
    """
    gateway = _gateway_with_job_service(raise_exc=RuntimeError("DB unavailable"))
    result = await _call(gateway, {}, _BACKEND_DB_ACTIVE_ENVELOPE)

    # Must not raise; result must be the original backend envelope.
    assert not result.is_error
    payload = json.loads(result.content[0].text)
    assert payload.get("authority") == "postgres-durable-jobs"
    assert payload.get("ingests") == [], "On DB error ingests must degrade to []"
    # structured_content must still be present (the backend's original SC is preserved).
    assert isinstance(result.structured_content, dict), (
        "On DB error, backend's structured_content must be preserved (not dropped)"
    )


async def test_augment_skips_when_no_job_service():
    """When gateway has no job_service, middleware passes through to backend unchanged."""
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": []}}})
    # No job_service attribute set.
    result = await _call(gateway, {}, _BACKEND_DB_ACTIVE_ENVELOPE)

    assert not result.is_error
    payload = json.loads(result.content[0].text)
    # Unchanged: the backend envelope is returned as-is.
    assert payload.get("ingests") == []
    assert payload.get("authority") == "postgres-durable-jobs"


async def test_augment_skips_when_no_active_case():
    """When no active case is set, middleware passes through to backend unchanged."""
    from unittest.mock import patch

    gateway = _gateway_with_job_service(rows=[_FAKE_JOB_ROW])
    mcp = _server(gateway, _BACKEND_DB_ACTIVE_ENVELOPE)
    identity = _agent_identity()
    # No active case injected via _use_gateway_active_case.
    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=identity):
        result = await mcp.call_tool("opensearch_ingest_status", {})

    assert not result.is_error
    payload = json.loads(result.content[0].text)
    # No case → no augmentation → backend result unchanged.
    assert payload.get("ingests") == []

    # job_service was never called.
    assert gateway.job_service.calls == [], (
        "JobService must not be called when there is no active case"
    )


async def test_augment_preserves_backend_fields_not_in_ingests():
    """Augmentation must preserve all backend envelope fields (authority, last_completed, etc.)."""
    backend_with_extras = {
        **_BACKEND_DB_ACTIVE_ENVELOPE,
        "last_completed": {"most_recent_index": "case-x-evtx-host1", "total_docs": 5000},
        "job_id": "some-job-id",
        "next_step": "Call running_commands_status(job_id='some-job-id')",
    }
    gateway = _gateway_with_job_service(rows=[])
    result = await _call(gateway, {}, backend_with_extras)

    payload = json.loads(result.content[0].text)
    # Extra envelope fields must survive augmentation.
    assert payload.get("last_completed") is not None, (
        "last_completed must be preserved from the backend envelope"
    )
    assert payload.get("job_id") == "some-job-id"
    assert payload.get("next_step") is not None


# ---------------------------------------------------------------------------
# M-INGSTATUS Seam B: SDK outputSchema enforcement — the exact gap that shipped
# ---------------------------------------------------------------------------
# The existing tests above call ``mcp.call_tool()`` (FastMCP level) which does
# NOT run the SDK ``outputSchema`` check.  The real failure fires at the MCP SDK
# lowlevel handler (mcp/server/lowlevel/server.py:560-567) when:
#   - the tool has an ``outputSchema`` (IngestStatusOut is registered with one), AND
#   - the ToolResult has ``structured_content=None`` (the pre-fix augment path returned
#     a text-only ToolResult when the backend payload was not a dict).
#
# This test registers the REAL IngestStatusOut outputSchema, makes the augment
# return a text-only ToolResult (structured_content=None), drives the SDK
# CallToolRequest handler, and asserts the SDK fires:
#   "outputSchema defined but no structured output returned"


def _server_with_real_schema(gateway, backend_payload: dict, *, text_only: bool = False):
    """Mount augment middleware over a stub with the REAL IngestStatusOut outputSchema.

    When ``text_only=True`` the stub returns a ToolResult with
    ``structured_content=None`` — the pre-fix behaviour that triggered the live
    SDK rejection.  When ``text_only=False`` (default) it returns structured_content
    populated (the post-fix, correct behaviour).
    """
    from opensearch_mcp.registry import IngestStatusOut
    from sift_common.registry_helpers import tool_output_schema

    schema = tool_output_schema(IngestStatusOut)
    mcp = FastMCP("parent", middleware=[OpenSearchIngestStatusAugmentMiddleware(gateway)])

    @mcp.tool(name="opensearch_ingest_status", output_schema=schema)
    async def _status(case_id: str = "", job_id: str = "", case_dir: str = ""):
        text = json.dumps(backend_payload)
        if text_only:
            # Pre-fix: text-only result; SDK will reject when outputSchema is defined.
            return ToolResult(
                content=[TextContent(type="text", text=text)],
                structured_content=None,
                is_error=False,
            )
        # Post-fix: structured_content populated.
        return ToolResult(
            content=[TextContent(type="text", text=text)],
            structured_content=backend_payload,
            is_error=False,
        )

    return mcp


async def test_ingstatus_sdk_rejects_text_only_result_with_real_schema():
    """M-INGSTATUS Seam B: SDK fires outputSchema error when structured_content=None.

    This test drives the REAL SDK ``CallToolRequest`` handler (not just
    ``mcp.call_tool()``) with the REAL ``IngestStatusOut`` outputSchema registered.
    When the result has ``structured_content=None`` the SDK fires:
      "outputSchema defined but no structured output returned"

    This is the exact gap that shipped: the existing augment tests called
    ``mcp.call_tool()`` which does NOT run the SDK outputSchema check; only the
    lowlevel handler at mcp/server/lowlevel/server.py:560-567 does.

    Fail-on-revert proof (2026-06-26):
      text_only=True → SDK fires outputSchema error → inner.isError=True, PASS.
      Change to text_only=False → inner.isError=False → assertion fails, confirming
      the test is load-bearing (proven by test_ingstatus_sdk_accepts_structured_content_result).
    """
    import mcp.types as mcp_types
    from mcp.types import CallToolRequest, CallToolRequestParams

    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": []}}})
    mcp_server = _server_with_real_schema(gateway, _BACKEND_DB_ACTIVE_ENVELOPE, text_only=True)

    # Prime handler registration: get_tools() triggers FastMCP's _setup_handlers.
    await mcp_server.list_tools()
    lowlevel = mcp_server._mcp_server

    request = CallToolRequest(
        method="tools/call",
        params=CallToolRequestParams(name="opensearch_ingest_status", arguments={}),
    )
    handler = lowlevel.request_handlers.get(type(request))
    if handler is None:
        pytest.skip(
            "SDK CallToolRequest handler not populated without a running transport; "
            "Seam B regression is still covered by test_ingstatus_assert_passes_schema_catches_text_only."
        )

    # The handler calls _call_tool_mcp which wraps request_context access in
    # try/except (AttributeError, LookupError): pass — safe to call without a session.
    server_result = await handler(request)

    inner = server_result.root if hasattr(server_result, "root") else server_result
    assert isinstance(inner, mcp_types.CallToolResult), (
        f"Expected CallToolResult, got {type(inner).__name__!r}: {inner!r}"
    )
    assert inner.isError, (
        "SDK must return isError=True when structured_content=None and outputSchema is defined. "
        "M-INGSTATUS Seam B: text-only augmented result must be rejected at the SDK layer."
    )
    error_text = " ".join(
        block.text for block in (inner.content or []) if hasattr(block, "text")
    )
    assert "outputSchema defined but no structured output returned" in error_text, (
        f"SDK error must contain the outputSchema rejection string; got: {error_text!r}"
    )


async def test_ingstatus_sdk_accepts_structured_content_result():
    """M-INGSTATUS Seam B: SDK accepts augmented result when structured_content is set.

    Counterpart: when structured_content is populated the SDK must NOT return an
    error.  Making the stub return text_only=True (structured_content=None) here
    would cause isError=True, proving SDK enforcement is active and this test is
    load-bearing.
    """
    import mcp.types as mcp_types
    from mcp.types import CallToolRequest, CallToolRequestParams

    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": []}}})
    mcp_server = _server_with_real_schema(gateway, _BACKEND_DB_ACTIVE_ENVELOPE, text_only=False)

    await mcp_server.list_tools()
    lowlevel = mcp_server._mcp_server

    request = CallToolRequest(
        method="tools/call",
        params=CallToolRequestParams(name="opensearch_ingest_status", arguments={}),
    )
    handler = lowlevel.request_handlers.get(type(request))
    if handler is None:
        pytest.skip("SDK CallToolRequest handler not populated without a running transport.")

    server_result = await handler(request)

    inner = server_result.root if hasattr(server_result, "root") else server_result
    assert isinstance(inner, mcp_types.CallToolResult)
    assert not inner.isError, (
        "SDK must accept a result with structured_content populated when outputSchema is defined. "
        f"Got error: {[getattr(b,'text','?') for b in (inner.content or [])]!r}"
    )


async def test_ingstatus_real_schema_validates_structured_content_shape():
    """M-INGSTATUS Seam B (assert_passes_output_schema): structured_content must pass IngestStatusOut schema.

    Uses the lightweight ``assert_passes_output_schema`` helper (replicates the
    SDK jsonschema.validate call without needing the full SDK dispatch context).
    This complements the SDK-dispatch test above and provides a stable fallback
    even when request_handlers is not populated.

    Fail-on-revert: setting structured_content=None in the result causes
    assert_passes_output_schema to raise AssertionError with the SDK error string.
    """
    from opensearch_mcp.registry import IngestStatusOut
    from sift_common.registry_helpers import tool_output_schema
    from sift_common.testing.surface import assert_passes_output_schema

    schema = tool_output_schema(IngestStatusOut)
    gateway = _gateway_with_job_service(rows=[_FAKE_JOB_ROW])
    result = await _call(gateway, {}, _BACKEND_DB_ACTIVE_ENVELOPE)

    # Post-fix: structured_content is populated; assert_passes_output_schema must not raise.
    assert_passes_output_schema(schema, result, tool_name="opensearch_ingest_status")

    # Also assert the shape matches what IngestStatusOut expects at the top level.
    sc = result.structured_content
    assert isinstance(sc, dict)
    assert "ingests" in sc
    assert "authority" in sc


async def test_ingstatus_assert_passes_schema_catches_text_only():
    """Revert proof: assert_passes_output_schema raises for structured_content=None.

    If the augment middleware regresses to returning text-only (structured_content=None),
    assert_passes_output_schema must raise AssertionError with the SDK error string.
    This is the lightweight Seam B regression guard for the M-INGSTATUS bug class.
    """
    from opensearch_mcp.registry import IngestStatusOut
    from sift_common.registry_helpers import tool_output_schema
    from sift_common.testing.surface import assert_passes_output_schema

    import pytest

    schema = tool_output_schema(IngestStatusOut)
    # Simulate a pre-fix text-only result (structured_content=None).
    text_only_result = ToolResult(
        content=[TextContent(type="text", text=json.dumps(_BACKEND_DB_ACTIVE_ENVELOPE))],
        structured_content=None,
        is_error=False,
    )
    with pytest.raises(AssertionError) as exc_info:
        assert_passes_output_schema(schema, text_only_result, tool_name="opensearch_ingest_status")
    assert "outputSchema defined but no structured output returned" in str(exc_info.value), (
        f"assert_passes_output_schema must raise with the SDK error string; "
        f"got: {exc_info.value!r}"
    )
