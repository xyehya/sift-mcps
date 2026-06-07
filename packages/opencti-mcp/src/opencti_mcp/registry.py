"""Exposure-agnostic FastMCP 3 registry for the OpenCTI backend."""

from __future__ import annotations

import asyncio
import inspect
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from fastmcp import FastMCP
from fastmcp.tools import FunctionTool, ToolResult
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field, ValidationError as PydanticValidationError
from sift_common.instructions import OPENCTI as _INSTRUCTIONS

from .audit import AuditWriter, resolve_examiner
from .client import OpenCTIClient
from .config import Config
from .contracts import ErrorCode, ResultMeta, ToolDef, ToolError
from .errors import (
    ConfigurationError,
    ConnectionError,
    DegradedError,
    OpenCTIMCPError,
    QueryError,
    RateLimitError,
    ValidationError as OpenCTIValidationError,
    VersionMismatchError,
)
from .tool_metadata import DEFAULT_METADATA, TOOL_METADATA
from .validation import sanitize_for_log


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


@dataclass
class RuntimeContext:
    config: Config | None = None
    client: OpenCTIClient | None = None
    audit: AuditWriter | None = None

    def require_client(self) -> OpenCTIClient:
        """Return a configured OpenCTI client or raise a typed tool error."""
        if self.client is None:
            if self.config is None:
                raise ToolFault(
                    ErrorCode.not_configured,
                    "OpenCTI is not configured for this server instance.",
                    "Set OPENCTI_URL and OPENCTI_TOKEN, then restart opencti-mcp.",
                )
            self.client = OpenCTIClient(self.config)
        return self.client

    def audit_writer(self) -> AuditWriter:
        if self.audit is None:
            self.audit = AuditWriter("opencti-mcp")
        return self.audit


class ToolFault(Exception):
    """Typed tool error raised by tool logic and converted to ToolResult."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        remediation: str,
        *,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.remediation = remediation
        self.retryable = retryable
        self.details = details or {}


def _opencti_annotations(title: str) -> ToolAnnotations:
    return ToolAnnotations(
        title=title,
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    )


def _tool_meta(
    *,
    category: str = "threat-intel",
    recommended_phase: str = "CORRELATE",
    case_scoped: bool = False,
    resource_uri: str | None = None,
    deprecated: bool = False,
    health: bool = False,
) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "category": category,
        "recommended_phase": recommended_phase,
        "case_scoped": case_scoped,
        "evidence_class": "read_only",
    }
    if resource_uri:
        meta["resource_uri"] = resource_uri
    if deprecated:
        meta["deprecated"] = True
        meta["deprecation_reason"] = "Resource-compatible tool alias kept for one cutover cycle."
    if health:
        meta["health"] = True
    return meta


TOOL_CATALOG_META: dict[str, dict[str, Any]] = {
    "cti_get_health": _tool_meta(
        recommended_phase="SURVEY",
        resource_uri="cti://health",
        deprecated=True,
        health=True,
    )
}


class CtiHealthIn(BaseModel):
    """No-argument health check input."""


class CtiHealthOut(BaseModel):
    status: Literal["healthy", "unavailable"] = Field(..., description="OpenCTI API health state.")
    opencti_available: bool = Field(..., description="True when the OpenCTI API answered the health probe.")


async def cti_get_health(params: CtiHealthIn, ctx: RuntimeContext) -> CtiHealthOut:
    del params
    client = ctx.require_client()
    available = await asyncio.to_thread(client.is_available)
    return CtiHealthOut(
        status="healthy" if available else "unavailable",
        opencti_available=available,
    )


async def cti_health_resource(ctx: RuntimeContext) -> str:
    result = await cti_get_health(CtiHealthIn(), ctx)
    return result.model_dump_json()


REGISTRY: list[ToolDef] = [
    ToolDef(
        name="cti_get_health",
        fn=cti_get_health,
        in_model=CtiHealthIn,
        out_model=CtiHealthOut,
        annotations=_opencti_annotations("OpenCTI Health"),
        title="OpenCTI Health",
        description=(
            "Check OpenCTI connectivity and API health before relying on CTI lookups. "
            "Use at the start of an intel-dependent step to verify the threat-intel "
            "source is reachable. This is a deprecated tool-form alias for the "
            "`cti://health` resource for one cutover cycle. Example: `cti_get_health()`."
        ),
    )
]
PROMPT_REGISTRY: list[PromptDef] = []
RESOURCE_REGISTRY: list[ResourceDef] = [
    ResourceDef(
        uri="cti://health",
        fn=cti_health_resource,
        name="cti_health",
        title="OpenCTI Health",
        description=(
            "Read-only OpenCTI connectivity and API health resource. Use before relying "
            "on CTI lookups; the `cti_get_health` tool remains as a deprecated "
            "resource-compatible alias for one cutover cycle."
        ),
    )
]


def create_server(
    *,
    config: Config | None = None,
    client: OpenCTIClient | None = None,
    audit: AuditWriter | None = None,
) -> FastMCP:
    """Create the standalone FastMCP server from registry definitions."""
    mcp = FastMCP("opencti-mcp", instructions=_INSTRUCTIONS)
    register_all(mcp, RuntimeContext(config=config, client=client, audit=audit))
    return mcp


def register_all(mcp: FastMCP, context: RuntimeContext | None = None) -> None:
    """Register tools, deprecated aliases, prompts, and resources."""
    runtime = context or RuntimeContext()
    for tool_def in REGISTRY:
        mcp.add_tool(_function_tool(tool_def, tool_def.name, runtime))
        for alias in tool_def.deprecated_aliases:
            mcp.add_tool(
                _function_tool(tool_def, alias, runtime, deprecated_alias_of=tool_def.name)
            )
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
        )(_resource_reader(resource_def, runtime))


def _function_tool(
    tool_def: ToolDef,
    name: str,
    context: RuntimeContext,
    deprecated_alias_of: str | None = None,
) -> FunctionTool:
    description = tool_def.description
    meta: dict[str, Any] = dict(TOOL_CATALOG_META.get(tool_def.name, {}))
    if deprecated_alias_of is not None:
        description = (
            f"DEPRECATED alias for `{deprecated_alias_of}`. "
            "Use the canonical name; this alias will be removed after one cutover cycle.\n\n"
            f"{tool_def.description}"
        )
        meta.update({"deprecated": True, "canonical_name": deprecated_alias_of})

    async def invoke(**kwargs: Any) -> ToolResult:
        audit_id = context.audit_writer()._next_audit_id()
        start = time.monotonic()
        try:
            params = tool_def.in_model.model_validate(kwargs)
        except PydanticValidationError as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            fault = ToolFault(
                ErrorCode.invalid_input,
                "Input did not match the tool schema.",
                "Correct the invalid argument values and retry.",
                details={"errors": exc.errors(include_url=False)},
            )
            result_meta = _audit_meta(
                context,
                name,
                sanitize_for_log(kwargs),
                {"error": fault.code.value},
                audit_id,
                elapsed_ms,
                is_error=True,
            )
            return _error_result(fault, result_meta)

        args_for_audit = params.model_dump(mode="json")
        try:
            result = _call_with_context(tool_def.fn, params, context)
            if inspect.isawaitable(result):
                result = await result
            elapsed_ms = (time.monotonic() - start) * 1000
            return _success_result(
                result,
                tool_def.out_model,
                _audit_meta(
                    context,
                    name,
                    args_for_audit,
                    result,
                    audit_id,
                    elapsed_ms,
                    is_error=False,
                    params=params,
                ),
            )
        except ToolFault as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            result_meta = _audit_meta(
                context,
                name,
                args_for_audit,
                {"error": exc.code.value},
                audit_id,
                elapsed_ms,
                is_error=True,
                params=params,
            )
            return _error_result(exc, result_meta)
        except Exception as exc:
            fault = _fault_from_exception(exc)
            elapsed_ms = (time.monotonic() - start) * 1000
            result_meta = _audit_meta(
                context,
                name,
                args_for_audit,
                {"error": fault.code.value},
                audit_id,
                elapsed_ms,
                is_error=True,
                params=params,
            )
            return _error_result(fault, result_meta)

    return FunctionTool(
        name=name,
        title=tool_def.title,
        description=description,
        fn=invoke,
        return_type=ToolResult,
        parameters=tool_def.in_model.model_json_schema(),
        output_schema=_output_schema(tool_def.out_model),
        annotations=tool_def.annotations,
        meta=meta or None,
        run_in_thread=False,
    )


def _call_with_context(fn: Callable, params: BaseModel, context: RuntimeContext) -> Any:
    signature = inspect.signature(fn)
    positional = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(positional) >= 2:
        return fn(params, context)
    return fn(params)


def _resource_reader(resource_def: ResourceDef, context: RuntimeContext) -> Callable[[], Any]:
    async def read() -> str:
        result = _call_resource_with_context(resource_def.fn, context)
        if inspect.isawaitable(result):
            result = await result
        if isinstance(result, BaseModel):
            return result.model_dump_json()
        if isinstance(result, (dict, list)):
            return json.dumps(result, default=str)
        return str(result)

    return read


def _call_resource_with_context(fn: Callable, context: RuntimeContext) -> Any:
    signature = inspect.signature(fn)
    positional = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if positional:
        return fn(context)
    return fn()


def _success_result(
    result: Any,
    out_model: type[BaseModel],
    meta: ResultMeta,
) -> ToolResult:
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
        meta=meta.model_dump(mode="json"),
    )


def _error_result(fault: ToolFault, meta: ResultMeta) -> ToolResult:
    error = ToolError(
        error=fault.code,
        message=fault.message,
        remediation=fault.remediation,
        retryable=fault.retryable,
        details=fault.details,
    )
    return ToolResult(
        content=error.model_dump_json(),
        structured_content=error.model_dump(mode="json"),
        meta=meta.model_dump(mode="json"),
        is_error=True,
    )


def _audit_meta(
    context: RuntimeContext,
    tool_name: str,
    arguments: dict[str, Any],
    result_summary: Any,
    audit_id: str,
    elapsed_ms: float,
    *,
    is_error: bool,
    params: BaseModel | None = None,
) -> ResultMeta:
    writer = context.audit_writer()
    recorded_audit_id = writer.log(
        tool=tool_name,
        params=arguments,
        result_summary=_audit_summary(result_summary),
        audit_id=audit_id,
        elapsed_ms=elapsed_ms,
    )
    meta_source = _metadata_for(tool_name, params)
    audit_warning = None
    if recorded_audit_id is None:
        audit_warning = "Audit write failed - action not recorded"
    return ResultMeta(
        audit_id=recorded_audit_id,
        examiner=resolve_examiner(),
        caveats=[] if is_error else list(meta_source.get("caveats", [])),
        interpretation_constraint=None
        if is_error
        else str(meta_source.get("interpretation_constraint", "")),
        audit_warning=audit_warning,
    )


def _metadata_for(tool_name: str, params: BaseModel | None) -> dict[str, Any]:
    return TOOL_METADATA.get(tool_name, DEFAULT_METADATA)


def _audit_summary(result: Any) -> Any:
    if isinstance(result, BaseModel):
        return result.model_dump(mode="json")
    if isinstance(result, dict):
        return result
    return {"value": str(result)[:500]}


def _fault_from_exception(exc: Exception) -> ToolFault:
    if isinstance(exc, ToolFault):
        return exc
    if isinstance(exc, OpenCTIValidationError):
        return ToolFault(
            ErrorCode.invalid_input,
            exc.safe_message if isinstance(exc, OpenCTIMCPError) else str(exc),
            "Correct the invalid argument values and retry.",
        )
    if isinstance(exc, RateLimitError):
        return ToolFault(
            ErrorCode.rate_limited,
            exc.safe_message,
            "Wait for the rate-limit window to reset, then retry.",
            retryable=True,
            details={"wait_seconds": exc.wait_seconds, "limit_type": exc.limit_type},
        )
    if isinstance(exc, (ConfigurationError, VersionMismatchError)):
        return ToolFault(
            ErrorCode.not_configured,
            exc.safe_message,
            "Fix the OpenCTI backend configuration and restart opencti-mcp.",
        )
    if isinstance(exc, DegradedError):
        return ToolFault(
            ErrorCode.upstream_degraded,
            exc.safe_message,
            "Restore OpenCTI connectivity, then restart opencti-mcp to clear degraded mode.",
            retryable=False,
        )
    if isinstance(exc, ConnectionError):
        return ToolFault(
            ErrorCode.upstream_unavailable,
            exc.safe_message,
            "Check OpenCTI availability and retry.",
            retryable=True,
        )
    if isinstance(exc, QueryError):
        return ToolFault(
            ErrorCode.upstream_unavailable,
            exc.safe_message,
            "Check OpenCTI server logs and retry with a narrower query.",
            retryable=True,
        )
    if isinstance(exc, OpenCTIMCPError):
        return ToolFault(
            ErrorCode.internal,
            exc.safe_message,
            "Check backend logs for details, then retry.",
        )
    return ToolFault(
        ErrorCode.internal,
        f"{type(exc).__name__}: tool execution failed.",
        "Check backend logs for details, then retry or narrow the request.",
    )


def _output_schema(out_model: type[BaseModel]) -> dict[str, Any]:
    return {
        "anyOf": [
            out_model.model_json_schema(),
            ToolError.model_json_schema(),
        ]
    }
