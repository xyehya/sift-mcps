"""Shared MCP registry helpers for SIFT-platform backends.

Provides the common data models and utility functions used by all SIFT backend
registry modules (opensearch-mcp, opencti-mcp, windows-triage-mcp) to register
tools, prompts, and resources on a FastMCP server instance.

Canonical implementation shared by all SIFT-platform MCPs via sift-common.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP
from fastmcp.tools import FunctionTool, ToolResult
from pydantic import BaseModel, Field

from .contracts import ErrorCode, ResultMeta, ToolDef, ToolError
from .mcp_schema import output_schema


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


def register_all(
    mcp: FastMCP,
    tools: list[ToolDef],
    prompts: list[PromptDef],
    resources: list[ResourceDef],
    *,
    make_function_tool: Callable[[ToolDef, str], FunctionTool] | None = None,
) -> None:
    """Register tools, prompts, and resources on a FastMCP server.

    Args:
        mcp: The FastMCP server instance.
        tools: Tool definitions to register.
        prompts: Prompt definitions to register.
        resources: Resource definitions to register.
        make_function_tool: Optional custom factory for building FunctionTool
            instances. When None, uses the default ``build_function_tool``.
    """
    factory = make_function_tool or build_function_tool
    for tool_def in tools:
        mcp.add_tool(factory(tool_def, tool_def.name))
    for prompt_def in prompts:
        mcp.prompt(
            name=prompt_def.name,
            title=prompt_def.title,
            description=prompt_def.description,
        )(prompt_def.fn)
    for resource_def in resources:
        mcp.resource(
            resource_def.uri,
            name=resource_def.name,
            title=resource_def.title,
            description=resource_def.description,
            mime_type=resource_def.mime_type,
        )(resource_def.fn)


def tool_output_schema(out_model: type[BaseModel]) -> dict[str, Any]:
    """Advertised output schema: the success model OR a structured ``ToolError``.

    Thin wrapper over :func:`sift_common.mcp_schema.output_schema`; see that
    module for the full rationale (root ``type``, ``$defs`` hoisting,
    ``PointerToNowhere`` avoidance, and the strict-client / B-MVP-038 gateway
    concerns).
    """
    return output_schema(out_model, ToolError)


def success_result(
    result: Any,
    out_model: type[BaseModel],
    meta: ResultMeta | None = None,
) -> ToolResult:
    """Convert a tool's raw result into a structured ``ToolResult``."""
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
        meta=(meta or ResultMeta()).model_dump(mode="json"),
    )


def error_result(
    code: ErrorCode,
    message: str,
    remediation: str,
    *,
    retryable: bool = False,
    details: dict[str, Any] | None = None,
    meta: ResultMeta | None = None,
) -> ToolResult:
    """Build a structured error ``ToolResult``."""
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
        meta=(meta or ResultMeta()).model_dump(mode="json"),
        is_error=True,
    )


def call_with_optional_context(
    fn: Callable, params: BaseModel, context: Any = None
) -> Any:
    """Call a tool function, passing an optional context if it accepts two args."""
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


def build_function_tool(
    tool_def: ToolDef,
    name: str,
    *,
    meta: dict[str, Any] | None = None,
) -> FunctionTool:
    """Build a FunctionTool with standard validation and error handling.

    This is the default tool builder used by ``register_all`` when no custom
    ``make_function_tool`` factory is provided.
    """
    from pydantic import ValidationError

    in_model = tool_def.in_model

    async def invoke(**kwargs: Any) -> ToolResult:
        try:
            params = in_model.model_validate(kwargs)
        except ValidationError as exc:
            return error_result(
                ErrorCode.invalid_input,
                "Input did not match the tool schema.",
                "Correct the invalid argument values and retry.",
                details={"errors": exc.errors(include_url=False)},
            )

        try:
            result = call_with_optional_context(tool_def.fn, params)
            if inspect.isawaitable(result):
                result = await result
            return success_result(result, tool_def.out_model)
        except Exception as exc:
            return error_result(
                ErrorCode.internal,
                f"{type(exc).__name__}: tool execution failed.",
                "Check backend logs for details, then retry or narrow the request.",
            )

    return FunctionTool(
        name=name,
        title=tool_def.title,
        description=tool_def.description,
        fn=invoke,
        return_type=ToolResult,
        parameters=in_model.model_json_schema(),
        output_schema=tool_output_schema(tool_def.out_model),
        annotations=tool_def.annotations,
        meta=meta,
        run_in_thread=False,
    )
