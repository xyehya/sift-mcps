"""Shared surfacing-conformance test helpers for SIFT-platform backends.

The "surfacing-law" bug class (caught 6× live in 2026-06-25 wave, shipped past
unit tests each time) is when a fix applied to the implementation layer fails to
reach the MCP surface because an intermediate layer silently drops the key:

  Seam A — run_* wrapper does explicit field-by-field construction; a missing
            ``=raw.get("key")`` line drops the key before Pydantic.

  Seam B — MCP SDK ``outputSchema`` enforcement; the SDK validates
            ``structuredContent`` against ``outputSchema`` only in the lowlevel
            handler, NOT in ``FastMCP.call_tool``.  A ``ToolResult`` with
            ``structured_content=None`` causes "outputSchema defined but no
            structured output returned" only at the SDK dispatch layer.

  Seam C — worker ``_aggregate`` plain-dict; conditional guards
            (``if intel_backend: detail["intel_backend"]=…``) can disappear if
            the guard condition or key name changes.

Usage
-----
Seam A — drive the real ``run_*`` with a controlled raw dict::

    from sift_common.testing.surface import assert_surfaces

    def test_advisory_surfaces(monkeypatch):
        assert_surfaces(
            run_opensearch_field_values,
            FieldValuesIn(field="x"),
            raw={"field": "x", "values": [], "truncated": False,
                 "advisory": "field not mapped; available: a,b"},
            expected={"advisory": "field not mapped; available: a,b"},
            monkeypatch_impl=monkeypatch,
        )

Seam B — replicate SDK outputSchema check on a ToolResult::

    from sift_common.testing.surface import assert_passes_output_schema

    result = await mcp.call_tool("opensearch_ingest_status", {})
    assert_passes_output_schema(server, "opensearch_ingest_status", result)

Seam C — call ``_aggregate`` directly and assert the key survives::

    from opensearch_mcp.ingest_job import _aggregate
    out = _aggregate({rid: {"status": "complete", "totals": {"intel_backend": "unavailable"}}}, {rid})
    assert out["detail"]["intel_backend"] == "unavailable"

M-INGSTATUS (full SDK dispatch) — use the SDK CallToolRequest path::

    from sift_common.testing.surface import assert_sdk_output_schema_enforced

    await assert_sdk_output_schema_enforced(mcp_server, "opensearch_ingest_status")
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import jsonschema
from fastmcp import FastMCP
from fastmcp.tools import ToolResult
from pydantic import BaseModel

from sift_common.registry_helpers import tool_output_schema


# ---------------------------------------------------------------------------
# Seam A: drive real run_* via monkeypatched _impl_server
# ---------------------------------------------------------------------------


def _run_with_raw(
    run_fn: Callable,
    in_model: BaseModel,
    raw_dict: dict[str, Any],
    *,
    monkeypatch_impl: Any,
) -> ToolResult:
    """Drive ``run_fn`` with a controlled ``raw_dict`` via a monkeypatched impl.

    ``run_fn`` calls ``_impl_server()`` which returns a module whose methods
    (e.g. ``opensearch_field_values``) are the raw-dict producers.  We replace
    ``_impl_server`` in ``run_fn``'s module with a fake that returns
    ``raw_dict`` for any attribute access, exercising the full run_* body
    (Seam A: field-by-field explicit construction → Pydantic whitelist) without
    real OpenSearch I/O.

    Returns the ``ToolResult`` the run_* wrapper produces.
    """
    # Identify the module ``run_fn`` lives in to patch _impl_server there.
    import inspect

    module = inspect.getmodule(run_fn)
    if module is None:
        raise RuntimeError(f"Cannot determine module for {run_fn!r}")

    class _FakeImpl:
        """Return raw_dict for any method call, ignoring kwargs."""

        def __getattr__(self, name: str) -> Callable[..., dict[str, Any]]:
            def _method(**_kwargs: Any) -> dict[str, Any]:
                return raw_dict

            return _method

    monkeypatch_impl.setattr(module, "_impl_server", lambda: _FakeImpl())
    coro = run_fn(in_model)
    return asyncio.run(coro)


def call_through_registry(
    run_fn: Callable,
    in_model: BaseModel,
    raw_dict: dict[str, Any],
    *,
    monkeypatch_impl: Any,
) -> ToolResult:
    """Drive ``run_fn`` and return the ``ToolResult``.  Public alias of ``_run_with_raw``."""
    return _run_with_raw(run_fn, in_model, raw_dict, monkeypatch_impl=monkeypatch_impl)


def assert_surfaces(
    run_fn: Callable,
    in_model: BaseModel,
    raw: dict[str, Any],
    expected: dict[str, Any],
    *,
    monkeypatch_impl: Any,
) -> ToolResult:
    """Assert that every key-value pair in ``expected`` reaches ``structured_content``.

    Drives the real ``run_fn`` (Seam A) with a controlled raw dict and asserts
    each key in ``expected`` appears in ``result.structured_content`` with the
    correct value.  Returns the ``ToolResult`` for further assertions.

    The raw dict must contain all required fields for the in_model's tool plus
    the optional key under test.  For a key to be covered, the run_* wrapper must
    (a) read it from raw and (b) pass it to the *Out constructor.  Reverting
    either (a) or (b) makes this test fail.
    """
    result = _run_with_raw(run_fn, in_model, raw, monkeypatch_impl=monkeypatch_impl)
    sc = result.structured_content
    assert isinstance(sc, dict), (
        f"run_fn={run_fn.__name__!r}: structured_content must be a dict, "
        f"got {type(sc).__name__!r}.  "
        "Check that run_* calls _success_tool_result (not a text-only path)."
    )
    for key, value in expected.items():
        assert key in sc, (
            f"run_fn={run_fn.__name__!r}: expected key {key!r} missing from "
            f"structured_content.  "
            "Did the run_* wrapper forget to read raw.get({key!r}) and pass it "
            "to the *Out constructor?"
        )
        assert sc[key] == value, (
            f"run_fn={run_fn.__name__!r}: structured_content[{key!r}] = "
            f"{sc[key]!r} but expected {value!r}."
        )
    return result


# ---------------------------------------------------------------------------
# Seam B: replicate SDK outputSchema check (jsonschema.validate path)
# ---------------------------------------------------------------------------


def assert_passes_output_schema(
    out_schema: dict[str, Any],
    result: ToolResult,
    *,
    tool_name: str = "<tool>",
) -> None:
    """Assert that ``result`` passes the SDK ``outputSchema`` validation.

    Replicates the check in ``mcp/server/lowlevel/server.py:560-567``:
      1. ``structured_content`` must not be ``None``.
      2. ``jsonschema.validate(structured_content, outputSchema)`` must pass.

    This catches Seam B regressions (``structured_content=None`` after middleware
    augmentation) without needing a faked SDK request context.

    Pass the schema explicitly (e.g. ``tool_output_schema(IngestStatusOut)``)
    rather than pulling it from a FastMCP server to avoid async overhead.

    Raises ``AssertionError`` with a descriptive message mirroring the SDK error
    string on failure.
    """
    sc = result.structured_content
    if sc is None:
        raise AssertionError(
            "Output validation error: outputSchema defined but no structured output returned.  "
            f"Tool {tool_name!r} declares outputSchema but the ToolResult has "
            "structured_content=None — this is the exact M-INGSTATUS bug class."
        )

    try:
        jsonschema.validate(instance=sc, schema=out_schema)
    except jsonschema.ValidationError as exc:
        raise AssertionError(
            f"Output validation error: {exc.message}  "
            f"(tool={tool_name!r}, structured_content={json.dumps(sc)[:200]!r})"
        ) from exc


# ---------------------------------------------------------------------------
# Seam B: full SDK dispatch path (M-INGSTATUS: the only test that needs this)
# ---------------------------------------------------------------------------


async def assert_sdk_output_schema_enforced(
    mcp_server: FastMCP,
    tool_name: str,
    *,
    args: dict[str, Any] | None = None,
    expect_error_substring: str = "outputSchema defined but no structured output returned",
) -> None:
    """Assert the SDK fires the outputSchema error when structured_content is None.

    This invokes the REAL SDK ``CallToolRequest`` handler (not just
    ``FastMCP.call_tool``), which is the ONLY path that runs the
    ``if tool.outputSchema is not None: if maybe_structured_content is None:
    return error(...)`` branch.

    Constructs a ``CallToolRequest``, feeds it to ``mcp_server._mcp_server``'s
    handler, and asserts the response error contains ``expect_error_substring``.
    """
    import mcp.types as mcp_types
    from mcp.types import CallToolRequest, CallToolRequestParams

    request = CallToolRequest(
        method="tools/call",
        params=CallToolRequestParams(name=tool_name, arguments=args or {}),
    )

    # The lowlevel server exposes request_handlers keyed by the request type.
    handler = mcp_server._mcp_server.request_handlers.get(type(request))
    if handler is None:
        raise RuntimeError(
            f"No handler registered for CallToolRequest on {mcp_server.name!r}; "
            "call mcp_server.run() or use _setup_handlers() before this assertion."
        )

    from contextlib import asynccontextmanager

    # Provide a minimal request_context so the handler doesn't crash on ctx access.
    from unittest.mock import MagicMock, patch

    fake_ctx = MagicMock()
    fake_ctx.meta = None
    fake_ctx.experimental.is_task = False

    with patch.object(mcp_server._mcp_server, "request_context", fake_ctx):
        server_result = await handler(request)

    # ServerResult wraps a CallToolResult.
    inner = server_result.root if hasattr(server_result, "root") else server_result
    if not isinstance(inner, mcp_types.CallToolResult):
        raise AssertionError(
            f"Expected a CallToolResult, got {type(inner).__name__!r}: {inner!r}"
        )

    assert inner.isError, (
        f"Expected the SDK to return an error result for {tool_name!r} when "
        "structured_content=None, but isError=False.  "
        "The M-INGSTATUS bug class is NOT being caught at the SDK level — "
        "check that the tool's outputSchema is registered and structured_content is None."
    )
    error_text = " ".join(
        block.text for block in (inner.content or []) if hasattr(block, "text")
    )
    assert expect_error_substring in error_text, (
        f"Expected SDK error {expect_error_substring!r} in result content, "
        f"but got: {error_text!r}"
    )


# ---------------------------------------------------------------------------
# Seam B meta: validate a model instance against its own tool_output_schema
# ---------------------------------------------------------------------------


def assert_model_matches_output_schema(
    out_model: type[BaseModel],
    instance: BaseModel | None = None,
) -> None:
    """Assert that ``instance.model_dump(mode='json')`` satisfies ``tool_output_schema(out_model)``.

    If ``instance`` is None, uses the model's default constructor (all fields
    with defaults).  Use this in the parametrized meta-test over all REGISTRY
    entries to catch *Out / outputSchema divergence early (before a tool is
    registered).

    Seam B (generic): ``tool_output_schema`` produces the schema; any *Out field
    that violates the schema it declares would fail live validation.
    """
    schema = tool_output_schema(out_model)
    if instance is None:
        try:
            instance = out_model.model_construct()
        except Exception:
            raise RuntimeError(
                f"Cannot construct {out_model.__name__!r} with no arguments; "
                "pass an explicit instance= to assert_model_matches_output_schema."
            )
    payload = instance.model_dump(mode="json")
    try:
        jsonschema.validate(instance=payload, schema=schema)
    except jsonschema.ValidationError as exc:
        raise AssertionError(
            f"{out_model.__name__}.model_dump() fails its own outputSchema: {exc.message}.  "
            "This means the *Out model and the registered outputSchema are out of sync."
        ) from exc
