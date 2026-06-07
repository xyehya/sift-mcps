"""Exposure-agnostic FastMCP 3 registry for the OpenSearch backend."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Any, Literal

from fastmcp import FastMCP
from fastmcp.tools import FunctionTool, ToolResult
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field, ValidationError, field_validator
from sift_common.instructions import OPENSEARCH as _INSTRUCTIONS

from .contracts import ErrorCode, ResultMeta, ToolDef, ToolError


class PromptDef(BaseModel, arbitrary_types_allowed=True):
    name: str
    fn: Callable
    title: str
    description: str


class ResourceDef(BaseModel, arbitrary_types_allowed=True):
    uri: str
    fn: Callable
    name: str
    title: str
    description: str
    mime_type: str = Field("application/json", description="MCP resource MIME type.")


REGISTRY: list[ToolDef] = []
PROMPT_REGISTRY: list[PromptDef] = []
RESOURCE_REGISTRY: list[ResourceDef] = []


class Advisory(BaseModel):
    kind: Literal["field_mapping", "execution_evidence", "pagination", "empty_result"] = Field(
        ..., description="Machine-readable advisory category."
    )
    text: str = Field(..., description="Human-readable advisory text.")


class CaseScopedQueryBase(BaseModel):
    index: str = Field(
        "",
        description=(
            "Index pattern; every segment MUST start with 'case-'. Overrides case_id "
            "when set. Leave empty to derive from case_id/active case."
        ),
    )
    case_id: str = Field(
        "",
        description=(
            "Case id. If empty, resolves to the active portal case (SIFT_CASE_DIR). "
            "Yields 'case-{id}-*'."
        ),
    )

    @field_validator("index")
    @classmethod
    def _validate_case_index(cls, value: str) -> str:
        if not value:
            return value
        for segment in value.split(","):
            segment = segment.strip()
            if segment and not segment.startswith("case-"):
                raise ValueError(
                    f"Index segment '{segment}' must start with 'case-' "
                    "(security: blocks access to system indices)"
                )
        return value


class SearchHit(BaseModel):
    id: str = Field(..., description="Document _id.")
    index: str = Field(..., description="Concrete index the hit came from.")
    fields: dict[str, Any] = Field(
        ...,
        description="Projected _source fields after compact-mode shaping.",
    )
    truncated: list[str] = Field(
        default_factory=list,
        description="Field names whose values were truncated to the size ceiling.",
    )


class SearchIn(CaseScopedQueryBase):
    query: str = Field(
        ...,
        min_length=1,
        description=(
            "OpenSearch query_string. Include file extensions ('svchost.exe' not "
            "'svchost'); quote special chars (source.ip:\"::1\")."
        ),
    )
    limit: int = Field(50, ge=1, le=200, description="Max hits to return. Hard cap 200.")
    offset: int = Field(
        0,
        ge=0,
        le=10000,
        description="Pagination offset; capped at OpenSearch max_result_window (10000).",
    )
    sort: str = Field(
        "@timestamp:desc", description="Sort as 'field:asc|desc'. Defaults to newest-first."
    )
    time_from: str = Field("", description="ISO-8601 lower bound on @timestamp (inclusive).")
    time_to: str = Field("", description="ISO-8601 upper bound on @timestamp (inclusive).")
    compact: bool = Field(
        True,
        description=(
            "True excludes bloat fields and truncates values to 500 chars. Set False "
            "for full docs (prefer opensearch_get_event for one doc)."
        ),
    )

    @field_validator("sort")
    @classmethod
    def _validate_sort(cls, value: str) -> str:
        field, separator, order = value.partition(":")
        if not field.strip():
            raise ValueError("sort field must not be empty")
        if separator and order not in {"asc", "desc"}:
            raise ValueError("sort must be 'field:asc' or 'field:desc'")
        return value


class SearchOut(BaseModel):
    total: int = Field(..., description="Total matching docs (see total_capped).")
    total_capped: bool = Field(
        False,
        description="True when total is a lower bound (relation gte); call count for exact.",
    )
    returned: int = Field(..., description="Number of hits in results.")
    offset: int = Field(0, description="Echoed pagination offset.")
    compact: bool = Field(..., description="Whether compact projection was applied.")
    results: list[SearchHit] = Field(..., description="Matching documents, projected.")
    advisories: list[Advisory] = Field(
        default_factory=list, description="Optional field-mapping/empty-result/pagination hints."
    )


class CountIn(CaseScopedQueryBase):
    query: str = Field(
        "*",
        description="query_string filter; default '*' counts all docs in scope.",
    )


class CountOut(BaseModel):
    count: int = Field(..., description="Exact document count for the query in scope.")


def _read_annotations(title: str) -> ToolAnnotations:
    return ToolAnnotations(
        title=title,
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    )


def _write_annotations(
    title: str,
    *,
    destructive: bool = False,
    idempotent: bool = False,
) -> ToolAnnotations:
    return ToolAnnotations(
        title=title,
        readOnlyHint=False,
        destructiveHint=destructive,
        idempotentHint=idempotent,
        openWorldHint=True,
    )


def _legacy_server():
    from opensearch_mcp import server as legacy

    return legacy


def _meta_from_raw(raw: dict[str, Any]) -> ResultMeta:
    audit_id = raw.pop("audit_id", None)
    return ResultMeta(audit_id=audit_id)


def _json_text(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, default=str)


def _success_tool_result(out: BaseModel, meta: ResultMeta | None = None) -> ToolResult:
    payload = out.model_dump(mode="json")
    return ToolResult(
        content=_json_text(payload),
        structured_content=payload,
        meta=(meta or ResultMeta()).model_dump(mode="json"),
    )


def _tool_error_result(
    code: ErrorCode,
    message: str,
    remediation: str,
    *,
    retryable: bool = False,
    details: dict[str, Any] | None = None,
    meta: ResultMeta | None = None,
) -> ToolResult:
    error = ToolError(
        error=code,
        message=message,
        remediation=remediation,
        retryable=retryable,
        details=details or {},
    )
    payload = error.model_dump(mode="json")
    return ToolResult(
        content=_json_text(payload),
        structured_content=payload,
        meta=(meta or ResultMeta()).model_dump(mode="json"),
        is_error=True,
    )


def _legacy_error(
    raw: dict[str, Any], *, default_code: ErrorCode = ErrorCode.invalid_input
) -> ToolResult:
    meta = _meta_from_raw(raw)
    message = str(raw.get("error") or raw.get("message") or "Tool call failed.")
    if "OpenSearch" in message or "connection" in message.lower():
        code = ErrorCode.upstream_unavailable
        retryable = True
    else:
        code = default_code
        retryable = False
    remediation = str(
        raw.get("next_step")
        or raw.get("action")
        or raw.get("portal_hint")
        or "Correct the request or check backend readiness, then retry."
    )
    details = {
        key: value
        for key, value in raw.items()
        if key not in {"error", "message", "next_step", "action", "portal_hint"}
    }
    return _tool_error_result(
        code, message, remediation, retryable=retryable, details=details, meta=meta
    )


def _advisories_from_raw(raw: dict[str, Any]) -> list[Advisory]:
    advisories: list[Advisory] = []
    mapping = {
        "field_hint": "field_mapping",
        "discipline_reminder": "execution_evidence",
        "total_note": "pagination",
        "note": "pagination",
        "hint": "empty_result",
    }
    for key, kind in mapping.items():
        text = raw.pop(key, None)
        if text:
            advisories.append(Advisory(kind=kind, text=str(text)))
    return advisories


def _search_hit_from_legacy(hit: dict[str, Any]) -> SearchHit:
    fields = {
        key: value for key, value in hit.items() if key not in {"_id", "_index", "_truncated"}
    }
    return SearchHit(
        id=str(hit.get("_id", "")),
        index=str(hit.get("_index", "")),
        fields=fields,
        truncated=list(hit.get("_truncated") or []),
    )


async def run_opensearch_search(params: SearchIn) -> ToolResult:
    raw = _legacy_server().opensearch_search(**params.model_dump())
    if "error" in raw:
        return _legacy_error(raw)
    meta = _meta_from_raw(raw)
    advisories = _advisories_from_raw(raw)
    out = SearchOut(
        total=int(raw.get("total", 0)),
        total_capped=bool(raw.get("total_capped", False)),
        returned=int(raw.get("returned", 0)),
        offset=params.offset,
        compact=bool(raw.get("compact", params.compact)),
        results=[_search_hit_from_legacy(hit) for hit in raw.get("results", [])],
        advisories=advisories,
    )
    return _success_tool_result(out, meta)


async def run_opensearch_count(params: CountIn) -> ToolResult:
    raw = _legacy_server().opensearch_count(**params.model_dump())
    if "error" in raw:
        return _legacy_error(raw)
    meta = _meta_from_raw(raw)
    return _success_tool_result(CountOut(count=int(raw.get("count", 0))), meta)


REGISTRY.append(
    ToolDef(
        name="opensearch_search",
        fn=run_opensearch_search,
        in_model=SearchIn,
        out_model=SearchOut,
        annotations=_read_annotations("Search Evidence"),
        title="Search Evidence",
        description=(
            "Search indexed evidence with query_string syntax. Use for targeted lookups "
            "by indicator, user, IP, hash, or field value. Do not use for frequency "
            "counts (use opensearch_aggregate) or activity spikes (use "
            "opensearch_timeline); for one full document use opensearch_get_event. "
            "Example: opensearch_search(query='event.code:4688 AND "
            "process.name:*powershell*', case_id='rocba-drive-20260526-1417')."
        ),
    )
)

REGISTRY.append(
    ToolDef(
        name="opensearch_count",
        fn=run_opensearch_count,
        in_model=CountIn,
        out_model=CountOut,
        annotations=_read_annotations("Count Documents"),
        title="Count Documents",
        description=(
            "Return an exact match count without documents. Use to verify index "
            "population or gauge magnitude before opensearch_search. Do not use "
            "when you need per-value counts; use opensearch_aggregate. Example: "
            "opensearch_count(query='event.code:4624')."
        ),
    )
)


def create_server() -> FastMCP:
    """Create the standalone FastMCP server from registry definitions."""
    mcp = FastMCP("opensearch-mcp", instructions=_INSTRUCTIONS)
    register_all(mcp)
    return mcp


def register_all(mcp: FastMCP) -> None:
    """Register tools, deprecated aliases, prompts, and resources."""
    for tool_def in REGISTRY:
        mcp.add_tool(_function_tool(tool_def, tool_def.name))
        for alias in tool_def.deprecated_aliases:
            mcp.add_tool(_function_tool(tool_def, alias, deprecated_alias_of=tool_def.name))
    for prompt_def in PROMPT_REGISTRY:
        mcp.prompt(
            name=prompt_def.name,
            title=prompt_def.title,
            description=prompt_def.description,
        )(prompt_def.fn)
    for resource_def in RESOURCE_REGISTRY:
        mcp.resource(
            resource_def.uri,
            name=resource_def.name,
            title=resource_def.title,
            description=resource_def.description,
            mime_type=resource_def.mime_type,
        )(resource_def.fn)


def _function_tool(
    tool_def: ToolDef,
    name: str,
    deprecated_alias_of: str | None = None,
) -> FunctionTool:
    description = tool_def.description
    meta: dict[str, Any] | None = None
    if deprecated_alias_of is not None:
        description = (
            f"DEPRECATED alias for `{deprecated_alias_of}`. "
            "Use the canonical name; this alias will be removed after one cutover cycle.\n\n"
            f"{tool_def.description}"
        )
        meta = {"deprecated": True, "canonical_name": deprecated_alias_of}

    async def invoke(**kwargs: Any) -> ToolResult:
        try:
            params = tool_def.in_model.model_validate(kwargs)
        except ValidationError as exc:
            return _error_result(
                ErrorCode.invalid_input,
                "Input did not match the tool schema.",
                "Correct the invalid argument values and retry.",
                details={"errors": exc.errors(include_url=False)},
            )

        try:
            result = _call_with_optional_context(tool_def.fn, params)
            if inspect.isawaitable(result):
                result = await result
            return _success_result(result, tool_def.out_model)
        except Exception as exc:
            return _error_result(
                ErrorCode.internal,
                f"{type(exc).__name__}: tool execution failed.",
                "Check backend logs for details, then retry or narrow the request.",
            )

    return FunctionTool(
        name=name,
        title=tool_def.title,
        description=description,
        fn=invoke,
        return_type=ToolResult,
        parameters=tool_def.in_model.model_json_schema(),
        output_schema=tool_def.out_model.model_json_schema(),
        annotations=tool_def.annotations,
        meta=meta,
        run_in_thread=False,
    )


def _call_with_optional_context(fn: Callable, params: BaseModel) -> Any:
    signature = inspect.signature(fn)
    positional = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(positional) >= 2:
        return fn(params, None)
    return fn(params)


def _success_result(result: Any, out_model: type[BaseModel]) -> ToolResult:
    if isinstance(result, ToolResult):
        return result
    if isinstance(result, BaseModel):
        out = result
    else:
        out = out_model.model_validate(result)
    structured = out.model_dump(mode="json")
    return ToolResult(
        content=out.model_dump_json(),
        structured_content=structured,
        meta=ResultMeta().model_dump(mode="json"),
    )


def _error_result(
    code: ErrorCode,
    message: str,
    remediation: str,
    *,
    retryable: bool = False,
    details: dict[str, Any] | None = None,
) -> ToolResult:
    error = ToolError(
        error=code,
        message=message,
        remediation=remediation,
        retryable=retryable,
        details=details or {},
    )
    return ToolResult(
        content=error.model_dump_json(),
        structured_content=error.model_dump(mode="json"),
        meta=ResultMeta().model_dump(mode="json"),
        is_error=True,
    )
