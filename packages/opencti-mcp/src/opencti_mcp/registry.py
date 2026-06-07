"""Exposure-agnostic FastMCP 3 registry for the OpenCTI backend."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP
from fastmcp.tools import FunctionTool, ToolResult
from pydantic import BaseModel, Field, ValidationError
from sift_common.instructions import OPENCTI as _INSTRUCTIONS

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


def create_server() -> FastMCP:
    """Create the standalone FastMCP server from registry definitions."""
    mcp = FastMCP("opencti-mcp", instructions=_INSTRUCTIONS)
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
