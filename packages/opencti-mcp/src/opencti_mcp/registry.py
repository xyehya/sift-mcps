"""Exposure-agnostic FastMCP 3 registry for the OpenCTI backend."""

from __future__ import annotations

import asyncio
import inspect
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal

from fastmcp import FastMCP
from fastmcp.tools import FunctionTool, ToolResult
from mcp.types import ToolAnnotations
from pydantic import (
    BaseModel,
    Field,
    ValidationError as PydanticValidationError,
    ValidationInfo,
    field_validator,
)
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
from .validation import (
    MAX_QUERY_LENGTH,
    sanitize_for_log,
    validate_date_filter,
    validate_labels,
    validate_observable_types,
)


_ENTITY_TYPE_METHODS = {
    "threat_actor": "search_threat_actors",
    "malware": "search_malware",
    "attack_pattern": "search_attack_patterns",
    "vulnerability": "search_vulnerabilities",
    "campaign": "search_campaigns",
    "tool": "search_tools",
    "infrastructure": "search_infrastructure",
    "incident": "search_incidents",
    "observable": "search_observables",
    "sighting": "search_sightings",
    "organization": "search_organizations",
    "sector": "search_sectors",
    "location": "search_locations",
    "course_of_action": "search_courses_of_action",
    "grouping": "search_groupings",
    "note": "search_notes",
}

_ENTITY_TYPES_WITH_CONFIDENCE = frozenset(
    {"threat_actor", "malware", "campaign", "incident"}
)

_ENTITY_TYPES_FULL_FILTERS = frozenset(
    {
        "threat_actor",
        "malware",
        "attack_pattern",
        "vulnerability",
        "campaign",
        "tool",
        "infrastructure",
        "incident",
        "observable",
    }
)

_SEARCH_ENTITY_META_KEYS = {
    "threat_actor": "search_threat_actor",
    "malware": "search_malware",
    "attack_pattern": "search_attack_pattern",
    "vulnerability": "search_vulnerability",
    "campaign": "search_campaign",
    "tool": "search_tool",
    "infrastructure": "search_infrastructure",
    "incident": "search_incident",
    "observable": "search_observable",
    "sighting": "search_sighting",
    "organization": "search_organization",
    "sector": "search_sector",
    "location": "search_location",
    "course_of_action": "search_course_of_action",
    "grouping": "search_grouping",
    "note": "search_note",
}


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
    ),
    "cti_search_threat_intel": _tool_meta(),
    "cti_search_entity": _tool_meta(),
}


class CtiHealthIn(BaseModel):
    """No-argument health check input."""


class CtiHealthOut(BaseModel):
    status: Literal["healthy", "unavailable"] = Field(..., description="OpenCTI API health state.")
    opencti_available: bool = Field(..., description="True when the OpenCTI API answered the health probe.")


class CtiSearchFilters(BaseModel):
    limit: int = Field(..., description="Per-tool result limit; concrete default and cap are set by each tool.")
    offset: int = Field(0, ge=0, le=500, description="Pagination offset; cap 500.")
    labels: list[str] | None = Field(None, description="Filter by labels such as ['tlp:amber', 'malicious']; safe characters only.")
    confidence_min: int | None = Field(None, ge=0, le=100, description="Minimum confidence threshold from 0 to 100.")
    created_after: str | None = Field(None, description="ISO-8601 lower bound for entity creation date, e.g. 2024-01-01.")
    created_before: str | None = Field(None, description="ISO-8601 upper bound for entity creation date.")

    @field_validator("labels")
    @classmethod
    def _validate_labels(cls, value: list[str] | None) -> list[str] | None:
        labels = validate_labels(value) if value else None
        return labels or None

    @field_validator("created_after", "created_before")
    @classmethod
    def _validate_date(cls, value: str | None, info: ValidationInfo) -> str | None:
        return validate_date_filter(value, info.field_name)


class CtiSearchThreatIntelIn(CtiSearchFilters):
    query: str = Field(..., min_length=1, max_length=MAX_QUERY_LENGTH, description="Search term: IOC, actor, malware, CVE, campaign, or other CTI keyword.")
    limit: int = Field(5, ge=1, le=20, description="Max results per entity type. Cap 20.")


class CtiEntityType(str, Enum):
    threat_actor = "threat_actor"
    malware = "malware"
    attack_pattern = "attack_pattern"
    vulnerability = "vulnerability"
    campaign = "campaign"
    tool = "tool"
    infrastructure = "infrastructure"
    incident = "incident"
    observable = "observable"
    sighting = "sighting"
    organization = "organization"
    sector = "sector"
    location = "location"
    course_of_action = "course_of_action"
    grouping = "grouping"
    note = "note"


class CtiSearchEntityIn(CtiSearchFilters):
    type: CtiEntityType = Field(..., description="Single OpenCTI entity type to search.")
    query: str = Field(..., min_length=1, max_length=MAX_QUERY_LENGTH, description="Search term for the selected entity type.")
    limit: int = Field(10, ge=1, le=50, description="Max results for this entity type. Cap 50.")
    observable_types: list[str] | None = Field(None, description="Only for type='observable': restrict to these OpenCTI observable subtypes.")


class CtiEntity(BaseModel):
    id: str | None = Field(None, description="OpenCTI entity id when returned by the platform.")
    entity_type: str | None = Field(None, description="OpenCTI/STIX entity type.")
    name: str | None = Field(None, description="Primary display name or observable value.")
    description: str | None = Field(None, description="Short description, truncated by the client.")
    confidence: int | None = Field(None, description="OpenCTI confidence score when available.")
    labels: list[str] = Field(default_factory=list, description="OpenCTI labels attached to the entity.")
    created: str | None = Field(None, description="Created timestamp when available.")
    modified: str | None = Field(None, description="Modified timestamp when available.")
    extra: dict[str, Any] = Field(default_factory=dict, description="Type-specific fields preserved from the OpenCTI client.")


class CtiUnifiedSearchOut(BaseModel):
    query: str = Field(..., description="Echoed search term.")
    results_by_type: dict[str, list[CtiEntity]] = Field(..., description="Projected OpenCTI entities grouped by entity type.")
    total: int = Field(..., description="Total returned entities across all groups.")
    offset: int = Field(0, description="Echoed pagination offset.")


class CtiEntitySearchOut(BaseModel):
    type: CtiEntityType = Field(..., description="Entity type searched.")
    results: list[CtiEntity] = Field(..., description="Projected matching OpenCTI entities.")
    total: int = Field(..., description="Number of returned entities.")
    offset: int = Field(0, description="Echoed pagination offset.")


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


async def cti_search_threat_intel(
    params: CtiSearchThreatIntelIn,
    ctx: RuntimeContext,
) -> CtiUnifiedSearchOut:
    client = ctx.require_client()
    raw = await asyncio.to_thread(
        client.unified_search,
        params.query,
        params.limit,
        params.offset,
        params.labels,
        params.confidence_min,
        params.created_after,
        params.created_before,
    )
    groups: dict[str, list[CtiEntity]] = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            if key == "query" or not isinstance(value, list):
                continue
            groups[key] = [_shape_entity(item) for item in value[: params.limit]]
    total = sum(len(items) for items in groups.values())
    return CtiUnifiedSearchOut(
        query=params.query,
        results_by_type=groups,
        total=total,
        offset=params.offset,
    )


async def cti_search_entity(
    params: CtiSearchEntityIn,
    ctx: RuntimeContext,
) -> CtiEntitySearchOut:
    client = ctx.require_client()
    entity_type = params.type.value
    method = getattr(client, _ENTITY_TYPE_METHODS[entity_type])

    if entity_type == "observable":
        extra_types = ctx.config.extra_observable_types if ctx.config else None
        observable_types = validate_observable_types(
            params.observable_types,
            extra_types=extra_types,
        )
        results = await asyncio.to_thread(
            method,
            params.query,
            params.limit,
            params.offset,
            observable_types,
            params.labels,
            params.created_after,
            params.created_before,
        )
    elif entity_type in _ENTITY_TYPES_FULL_FILTERS:
        if entity_type in _ENTITY_TYPES_WITH_CONFIDENCE:
            results = await asyncio.to_thread(
                method,
                params.query,
                params.limit,
                params.offset,
                params.labels,
                params.confidence_min,
                params.created_after,
                params.created_before,
            )
        else:
            results = await asyncio.to_thread(
                method,
                params.query,
                params.limit,
                params.offset,
                params.labels,
                params.created_after,
                params.created_before,
            )
    else:
        results = await asyncio.to_thread(method, params.query, params.limit)

    shaped = [_shape_entity(item) for item in _safe_list(results)[: params.limit]]
    return CtiEntitySearchOut(
        type=params.type,
        results=shaped,
        total=len(shaped),
        offset=params.offset,
    )


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
    ),
    ToolDef(
        name="cti_search_threat_intel",
        fn=cti_search_threat_intel,
        in_model=CtiSearchThreatIntelIn,
        out_model=CtiUnifiedSearchOut,
        annotations=_opencti_annotations("Search All Threat Intel"),
        title="Search All Threat Intel",
        description=(
            "Broad search across all OpenCTI entity types: indicators, actors, malware, "
            "techniques, CVEs, reports, and related CTI records. Use for discovery from a "
            "keyword, malware family, actor, CVE, campaign, or IOC-like term. Don't use for "
            "focused single-type queries; use `cti_search_entity` for that, or "
            "`cti_lookup_ioc` for a known IOC. Example: "
            "`cti_search_threat_intel(query='APT28', confidence_min=60)`."
        ),
    ),
    ToolDef(
        name="cti_search_entity",
        fn=cti_search_entity,
        in_model=CtiSearchEntityIn,
        out_model=CtiEntitySearchOut,
        annotations=_opencti_annotations("Search Entities by Type"),
        title="Search Entities by Type",
        description=(
            "Search one OpenCTI entity type with a higher per-type cap than broad search. "
            "Use for focused questions such as malware linked to an actor, vulnerabilities "
            "matching a CVE prefix, or observables of a specific subtype. Valid types: "
            "threat_actor, malware, attack_pattern, vulnerability, campaign, tool, "
            "infrastructure, incident, observable, sighting, organization, sector, location, "
            "course_of_action, grouping, note. Example: "
            "`cti_search_entity(type='vulnerability', query='CVE-2024')`."
        ),
    ),
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
    if tool_name == "cti_search_entity" and params is not None:
        raw_type = getattr(params, "type", "")
        entity_type = raw_type.value if isinstance(raw_type, Enum) else str(raw_type)
        meta_key = _SEARCH_ENTITY_META_KEYS.get(entity_type)
        if meta_key:
            return TOOL_METADATA.get(meta_key, TOOL_METADATA.get(tool_name, DEFAULT_METADATA))
    return TOOL_METADATA.get(tool_name, DEFAULT_METADATA)


def _safe_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _shape_entity(raw: Any) -> CtiEntity:
    if not isinstance(raw, dict):
        return CtiEntity(name=str(raw), extra={"raw": raw})
    labels = raw.get("labels") or raw.get("objectLabel") or []
    if isinstance(labels, list):
        shaped_labels = [
            str(item.get("value") if isinstance(item, dict) else item)
            for item in labels
            if item is not None
        ]
    else:
        shaped_labels = [str(labels)]
    core_keys = {
        "id",
        "entity_type",
        "type",
        "name",
        "value",
        "observable_value",
        "description",
        "confidence",
        "labels",
        "objectLabel",
        "created",
        "modified",
    }
    extra = {key: value for key, value in raw.items() if key not in core_keys}
    return CtiEntity(
        id=_optional_str(raw.get("id")),
        entity_type=_optional_str(raw.get("entity_type") or raw.get("type")),
        name=_optional_str(
            raw.get("name") or raw.get("observable_value") or raw.get("value")
        ),
        description=_optional_str(raw.get("description")),
        confidence=_optional_int(raw.get("confidence")),
        labels=shaped_labels,
        created=_optional_str(raw.get("created")),
        modified=_optional_str(raw.get("modified")),
        extra=extra,
    )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


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
