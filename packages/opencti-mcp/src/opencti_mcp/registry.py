"""Exposure-agnostic FastMCP 3 registry for the OpenCTI backend."""

from __future__ import annotations

import asyncio
import inspect
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Annotated, Any, Literal

from fastmcp import FastMCP
from fastmcp.tools import FunctionTool, ToolResult
from mcp.types import ToolAnnotations
from pydantic import (
    BaseModel,
    Field,
    ValidationInfo,
    field_validator,
)
from pydantic import (
    ValidationError as PydanticValidationError,
)
from sift_common.instructions import OPENCTI as _INSTRUCTIONS
from sift_common.registry_helpers import (
    PromptDef,
    ResourceDef,
    tool_output_schema,
)

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
    VersionMismatchError,
)
from .errors import (
    ValidationError as OpenCTIValidationError,
)
from .tool_metadata import DEFAULT_METADATA, TOOL_METADATA
from .validation import (
    MAX_IOC_LENGTH,
    MAX_QUERY_LENGTH,
    sanitize_for_log,
    validate_date_filter,
    validate_ioc,
    validate_labels,
    validate_observable_types,
    validate_relationship_types,
    validate_uuid,
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
    "cti_lookup_ioc": _tool_meta(),
    "cti_get_recent_indicators": _tool_meta(),
    "cti_get_entity": _tool_meta(),
    "cti_get_relationships": _tool_meta(),
    "cti_search_reports": _tool_meta(),
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


class CtiDirection(str, Enum):
    from_ = "from"
    to = "to"
    both = "both"


class CtiSearchEntityIn(CtiSearchFilters):
    type: CtiEntityType = Field(..., description="Single OpenCTI entity type to search.")
    query: str = Field(..., min_length=1, max_length=MAX_QUERY_LENGTH, description="Search term for the selected entity type.")
    limit: int = Field(10, ge=1, le=50, description="Max results for this entity type. Cap 50.")
    observable_types: list[str] | None = Field(None, description="Only for type='observable': restrict to these OpenCTI observable subtypes.")


class CtiSearchReportsIn(CtiSearchFilters):
    query: str = Field(..., min_length=1, max_length=MAX_QUERY_LENGTH, description="Report search term: campaign, actor, malware, CVE, or technique.")
    limit: int = Field(10, ge=1, le=50, description="Maximum reports to return. Cap 50.")


class CtiLookupIocIn(BaseModel):
    ioc: str = Field(..., min_length=1, max_length=MAX_IOC_LENGTH, description="IOC value: IP, MD5/SHA1/SHA256 hash, domain, URL, CVE, or MITRE ATT&CK id.")

    @field_validator("ioc")
    @classmethod
    def _validate_ioc(cls, value: str) -> str:
        validate_ioc(value)
        return value.strip()


class CtiRecentIndicatorsIn(BaseModel):
    days: int = Field(7, ge=1, le=90, description="Look-back window in days. Cap 90.")
    limit: int = Field(20, ge=1, le=100, description="Maximum recent indicators to return. Cap 100.")


class CtiGetEntityIn(BaseModel):
    entity_id: str = Field(..., description="OpenCTI entity UUID from a search result; validated before dispatch.")

    @field_validator("entity_id")
    @classmethod
    def _validate_entity_id(cls, value: str) -> str:
        return validate_uuid(value, "entity_id")


class CtiGetRelationshipsIn(BaseModel):
    entity_id: str = Field(..., description="OpenCTI entity UUID to expand.")
    direction: CtiDirection = Field(CtiDirection.both, description="Relationship direction: from=outgoing, to=incoming, both=default.")
    relationship_types: list[str] | None = Field(None, description="Optional relationship type filter, e.g. ['indicates', 'uses', 'targets'].")
    limit: int = Field(50, ge=1, le=50, description="Maximum relationships to return. Cap 50.")

    @field_validator("entity_id")
    @classmethod
    def _validate_entity_id(cls, value: str) -> str:
        return validate_uuid(value, "entity_id")

    @field_validator("relationship_types")
    @classmethod
    def _validate_relationship_types(cls, value: list[str] | None) -> list[str] | None:
        relationship_types = validate_relationship_types(value)
        return relationship_types or None


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


class CtiIocContextOut(BaseModel):
    ioc: str = Field(..., description="Echoed IOC value.")
    ioc_type: str | None = Field(None, description="Detected IOC type: ipv4, ipv6, hash type, domain, url, cve, mitre, or unknown.")
    found: bool = Field(..., description="True when OpenCTI returned indicator or observable context.")
    indicator: CtiEntity | None = Field(None, description="Matched indicator or observable, projected to common entity fields.")
    related_threat_actors: list[CtiEntity] = Field(default_factory=list, description="Related actors from OpenCTI relationships.")
    related_malware: list[CtiEntity] = Field(default_factory=list, description="Related malware from OpenCTI relationships.")
    related_techniques: list[CtiEntity] = Field(default_factory=list, description="Related MITRE techniques or attack patterns.")
    related_campaigns: list[CtiEntity] = Field(default_factory=list, description="Related campaigns when returned by the platform.")


class CtiRecentIndicatorsOut(BaseModel):
    days: int = Field(..., description="Echoed look-back window in days.")
    results: list[CtiEntity] = Field(..., description="Recently created OpenCTI indicators.")
    total: int = Field(..., description="Number of indicators returned.")


class CtiGetEntityOut(BaseModel):
    found: bool = Field(..., description="True when the entity id exists in OpenCTI.")
    entity_id: str = Field(..., description="Echoed entity UUID.")
    entity: CtiEntity | None = Field(None, description="Projected entity details, or null when not found.")


class CtiRelationship(BaseModel):
    id: str | None = Field(None, description="OpenCTI relationship id.")
    relationship_type: str | None = Field(None, description="OpenCTI relationship type such as indicates, uses, or targets.")
    source: CtiEntity | None = Field(None, description="Source entity for the relationship.")
    target: CtiEntity | None = Field(None, description="Target entity for the relationship.")
    direction: str | None = Field(None, description="Direction relative to the requested entity when inferable.")


class CtiRelationshipsOut(BaseModel):
    entity_id: str = Field(..., description="Echoed entity UUID.")
    relationships: list[CtiRelationship] = Field(..., description="Projected relationships for the entity.")
    total: int = Field(..., description="Number of relationships returned.")


class CtiReport(BaseModel):
    id: str | None = Field(None, description="OpenCTI report id when available.")
    name: str | None = Field(None, description="Report title.")
    published: str | None = Field(None, description="Publication timestamp when available.")
    description: str | None = Field(None, description="Short report description, truncated by the client.")
    labels: list[str] = Field(default_factory=list, description="OpenCTI labels attached to the report.")
    confidence: int | None = Field(None, description="OpenCTI confidence score when available.")
    object_refs: list[str] = Field(default_factory=list, description="Referenced entity ids when returned by the platform.")


class CtiReportsOut(BaseModel):
    results: list[CtiReport] = Field(..., description="Projected report results.")
    total: int = Field(..., description="Number of reports returned.")
    offset: int = Field(0, description="Echoed pagination offset.")


class CtiConnector(BaseModel):
    id: str | None = Field(None, description="OpenCTI connector id.")
    name: str | None = Field(None, description="Connector/feed name.")
    scope: list[str] = Field(default_factory=list, description="Connector scopes advertised by OpenCTI.")
    auto: bool = Field(False, description="True when the connector runs automatically.")
    active: bool = Field(False, description="True when the connector is active.")


class CtiConnectorCatalogOut(BaseModel):
    configured: bool = Field(..., description="True when this backend had OpenCTI configuration for a live read.")
    connectors: list[CtiConnector] = Field(default_factory=list, description="Enabled enrichment connectors/feeds returned by OpenCTI.")
    note: str | None = Field(None, description="Operational note or remediation when the live catalog is unavailable.")


class CtiEntityTypeRef(BaseModel):
    type: CtiEntityType = Field(..., description="Searchable cti_search_entity type value.")
    client_method: str = Field(..., description="OpenCTI client method used by this backend.")
    supports_confidence_min: bool = Field(..., description="True when confidence_min is passed to the client method.")
    supports_full_filters: bool = Field(..., description="True when offset, labels, and created date filters are supported.")


class CtiEntityTypeReferenceOut(BaseModel):
    entity_types: list[CtiEntityTypeRef] = Field(..., description="Searchable OpenCTI entity types and supported filters.")


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
    applied_offset = params.offset

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
        # These entity client methods take only (query, limit) — offset is not
        # supported, so report the offset actually applied (0) rather than
        # echoing the requested value, which would falsely imply page N and
        # cause silent duplicate/missing results during pagination.
        applied_offset = 0
        results = await asyncio.to_thread(method, params.query, params.limit)

    shaped = [_shape_entity(item) for item in _safe_list(results)[: params.limit]]
    return CtiEntitySearchOut(
        type=params.type,
        results=shaped,
        total=len(shaped),
        offset=applied_offset,
    )


async def cti_lookup_ioc(
    params: CtiLookupIocIn,
    ctx: RuntimeContext,
) -> CtiIocContextOut:
    _, ioc_type = validate_ioc(params.ioc)
    client = ctx.require_client()
    raw = await asyncio.to_thread(client.get_indicator_context, params.ioc)
    raw = raw if isinstance(raw, dict) else {"found": False, "ioc": params.ioc}
    found = bool(raw.get("found"))
    indicator = None
    if found:
        indicator = _shape_entity(
            {
                "id": raw.get("id"),
                "entity_type": raw.get("entity_type") or raw.get("type"),
                "name": raw.get("name") or raw.get("ioc") or params.ioc,
                "description": raw.get("description"),
                "confidence": raw.get("confidence"),
                "labels": raw.get("labels") or [],
                "created": raw.get("created"),
                "source": raw.get("source"),
                "pattern_type": raw.get("type"),
            }
        )
    return CtiIocContextOut(
        ioc=params.ioc,
        ioc_type=ioc_type,
        found=found,
        indicator=indicator,
        related_threat_actors=_shape_related_entities(
            raw.get("related_threat_actors"),
            "threat_actor",
        ),
        related_malware=_shape_related_entities(raw.get("related_malware"), "malware"),
        related_techniques=_shape_related_entities(
            raw.get("mitre_techniques") or raw.get("related_techniques"),
            "attack_pattern",
        ),
        related_campaigns=_shape_related_entities(
            raw.get("related_campaigns"),
            "campaign",
        ),
    )


async def cti_get_recent_indicators(
    params: CtiRecentIndicatorsIn,
    ctx: RuntimeContext,
) -> CtiRecentIndicatorsOut:
    client = ctx.require_client()
    results = await asyncio.to_thread(
        client.get_recent_indicators,
        params.days,
        params.limit,
    )
    shaped = [_shape_entity(item) for item in _safe_list(results)[: params.limit]]
    return CtiRecentIndicatorsOut(days=params.days, results=shaped, total=len(shaped))


async def cti_get_entity(
    params: CtiGetEntityIn,
    ctx: RuntimeContext,
) -> CtiGetEntityOut:
    client = ctx.require_client()
    result = await asyncio.to_thread(client.get_entity, params.entity_id)
    if result is None:
        return CtiGetEntityOut(found=False, entity_id=params.entity_id, entity=None)
    return CtiGetEntityOut(
        found=True,
        entity_id=params.entity_id,
        entity=_shape_entity(result),
    )


async def cti_get_relationships(
    params: CtiGetRelationshipsIn,
    ctx: RuntimeContext,
) -> CtiRelationshipsOut:
    client = ctx.require_client()
    results = await asyncio.to_thread(
        client.get_relationships,
        params.entity_id,
        params.direction.value,
        params.relationship_types,
        params.limit,
    )
    relationships = [
        _shape_relationship(item, params.entity_id)
        for item in _safe_list(results)[: params.limit]
    ]
    return CtiRelationshipsOut(
        entity_id=params.entity_id,
        relationships=relationships,
        total=len(relationships),
    )


async def cti_search_reports(
    params: CtiSearchReportsIn,
    ctx: RuntimeContext,
) -> CtiReportsOut:
    client = ctx.require_client()
    results = await asyncio.to_thread(
        client.search_reports,
        params.query,
        params.limit,
        params.offset,
        params.labels,
        params.confidence_min,
        params.created_after,
        params.created_before,
    )
    reports = [_shape_report(item) for item in _safe_list(results)[: params.limit]]
    return CtiReportsOut(results=reports, total=len(reports), offset=params.offset)


def enrich_ioc_prompt(
    ioc: Annotated[str, Field(description="IOC to contextualize: IP, hash, domain, URL, CVE, or MITRE id.")],
) -> str:
    return (
        "Enrich and contextualize this IOC using OpenCTI.\n\n"
        f"IOC: {ioc}\n\n"
        "1. Call `cti_get_health()` or read `cti://health` to confirm OpenCTI is available.\n"
        "2. Call `cti_lookup_ioc(ioc=<IOC>)` and inspect `found`, `indicator`, and related entities.\n"
        "3. For the strongest related actor, malware, technique, or campaign entity with an id, call "
        "`cti_get_relationships(entity_id=<id>)` to map adjacent context.\n"
        "4. Search reports with the top actor, malware, campaign, CVE, or technique name using "
        "`cti_search_reports(query=<name>)`.\n"
        "5. Summarize CTI as supporting context only, and tie every conclusion back to observed case evidence."
    )


async def cti_connector_catalog_resource(ctx: RuntimeContext) -> str:
    if ctx.client is None and ctx.config is None:
        return CtiConnectorCatalogOut(
            configured=False,
            note="OpenCTI is not configured. Set OPENCTI_URL and OPENCTI_TOKEN, then restart opencti-mcp.",
        ).model_dump_json()
    try:
        client = ctx.require_client()
        raw_connectors = await asyncio.to_thread(client.list_enrichment_connectors)
    except Exception as exc:
        fault = _fault_from_exception(exc)
        return CtiConnectorCatalogOut(
            configured=True,
            note=f"{fault.message} Remediation: {fault.remediation}",
        ).model_dump_json()
    connectors = [
        CtiConnector(
            id=_optional_str(item.get("id")),
            name=_optional_str(item.get("name")),
            scope=[str(scope) for scope in _safe_list(item.get("scope"))],
            auto=bool(item.get("auto", False)),
            active=bool(item.get("active", False)),
        )
        for item in _safe_list(raw_connectors)
        if isinstance(item, dict)
    ]
    return CtiConnectorCatalogOut(configured=True, connectors=connectors).model_dump_json()


def cti_entity_type_reference_resource() -> str:
    refs = [
        CtiEntityTypeRef(
            type=CtiEntityType(entity_type),
            client_method=method,
            supports_confidence_min=entity_type in _ENTITY_TYPES_WITH_CONFIDENCE,
            supports_full_filters=entity_type in _ENTITY_TYPES_FULL_FILTERS,
        )
        for entity_type, method in sorted(_ENTITY_TYPE_METHODS.items())
    ]
    return CtiEntityTypeReferenceOut(entity_types=refs).model_dump_json()


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
    ToolDef(
        name="cti_lookup_ioc",
        fn=cti_lookup_ioc,
        in_model=CtiLookupIocIn,
        out_model=CtiIocContextOut,
        annotations=_opencti_annotations("Look Up IOC Context"),
        title="Look Up IOC Context",
        description=(
            "Look up one observed IOC and return OpenCTI context: matched indicator or "
            "observable plus related actors, malware, techniques, and campaigns. Use for a "
            "known IOC extracted from case evidence; don't use for broad keyword discovery "
            "or speculative indicators not observed in evidence. Handles IPs, hashes, "
            "domains, URLs, CVEs, and MITRE ids. Example: `cti_lookup_ioc(ioc='8.8.8.8')`."
        ),
    ),
    ToolDef(
        name="cti_get_recent_indicators",
        fn=cti_get_recent_indicators,
        in_model=CtiRecentIndicatorsIn,
        out_model=CtiRecentIndicatorsOut,
        annotations=_opencti_annotations("Recent Indicators"),
        title="Recent Indicators",
        description=(
            "Return recently added OpenCTI indicators from a bounded look-back window. "
            "Use for situational awareness during active response or to check whether "
            "fresh intel relevant to an ongoing case has landed. Don't bulk-pivot on "
            "recent indicators without a case-specific hypothesis or observed overlap. "
            "Example: `cti_get_recent_indicators(days=14)`."
        ),
    ),
    ToolDef(
        name="cti_get_entity",
        fn=cti_get_entity,
        in_model=CtiGetEntityIn,
        out_model=CtiGetEntityOut,
        annotations=_opencti_annotations("Get Entity by ID"),
        title="Get Entity by ID",
        description=(
            "Return full details for one OpenCTI entity UUID, including projected common "
            "fields and type-specific extras. Use after a search returns an entity id "
            "that needs expansion; the UUID comes from search-result `id`. Example: "
            "`cti_get_entity(entity_id='00000000-0000-4000-8000-000000000000')`."
        ),
    ),
    ToolDef(
        name="cti_get_relationships",
        fn=cti_get_relationships,
        in_model=CtiGetRelationshipsIn,
        out_model=CtiRelationshipsOut,
        annotations=_opencti_annotations("Entity Relationships"),
        title="Entity Relationships",
        description=(
            "Return relationships for an OpenCTI entity: who uses it, what it indicates, "
            "what it targets, and adjacent context. Use to map actor toolkits, malware "
            "capabilities, or indicator context after selecting a relevant entity. Filter "
            "with `direction` and `relationship_types` for narrower pivots. Example: "
            "`cti_get_relationships(entity_id='00000000-0000-4000-8000-000000000000', "
            "relationship_types=['uses'])`."
        ),
    ),
    ToolDef(
        name="cti_search_reports",
        fn=cti_search_reports,
        in_model=CtiSearchReportsIn,
        out_model=CtiReportsOut,
        annotations=_opencti_annotations("Search Reports"),
        title="Search Reports",
        description=(
            "Search threat-intel reports by keyword. Reports carry analytical narrative "
            "that individual IOCs often lack, so use this when attribution, campaign, "
            "malware, CVE, or technique context matters. Treat report content as context "
            "and tie conclusions back to case artifacts. Example: "
            "`cti_search_reports(query='SolarWinds', created_after='2023-01-01')`."
        ),
    ),
]
PROMPT_REGISTRY: list[PromptDef] = [
    PromptDef(
        name="enrich_ioc",
        fn=enrich_ioc_prompt,
        title="Enrich IOC",
        description="Investigation prompt for enriching one observed IOC with OpenCTI lookup, relationships, and report context.",
    )
]
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
    ),
    ResourceDef(
        uri="cti://catalog/connectors",
        fn=cti_connector_catalog_resource,
        name="cti_connector_catalog",
        title="OpenCTI Connector Catalog",
        description="Enabled OpenCTI enrichment connectors/feeds and active state, refreshed on read.",
    ),
    ResourceDef(
        uri="cti://reference/entity-types",
        fn=cti_entity_type_reference_resource,
        name="cti_entity_type_reference",
        title="OpenCTI Entity Type Reference",
        description="Static reference for the 16 searchable OpenCTI entity types and supported filters.",
    ),
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
    """Register tools, prompts, and resources."""
    runtime = context or RuntimeContext()
    for tool_def in REGISTRY:
        mcp.add_tool(_function_tool(tool_def, tool_def.name, runtime))
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
) -> FunctionTool:
    description = tool_def.description
    meta: dict[str, Any] = dict(TOOL_CATALOG_META.get(tool_def.name, {}))

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


def _shape_related_entities(raw: Any, entity_type: str) -> list[CtiEntity]:
    entities = []
    for item in _safe_list(raw):
        if isinstance(item, dict):
            entities.append(_shape_entity(item))
        else:
            entities.append(CtiEntity(entity_type=entity_type, name=str(item)))
    return entities


def _shape_relationship(raw: Any, requested_entity_id: str) -> CtiRelationship:
    if not isinstance(raw, dict):
        return CtiRelationship(relationship_type=str(raw))
    source_raw = raw.get("from") or raw.get("source")
    target_raw = raw.get("to") or raw.get("target")
    source = _shape_endpoint(source_raw)
    target = _shape_endpoint(target_raw)
    direction = raw.get("direction")
    if not direction:
        if source and source.id == requested_entity_id:
            direction = "from"
        elif target and target.id == requested_entity_id:
            direction = "to"
    return CtiRelationship(
        id=_optional_str(raw.get("id")),
        relationship_type=_optional_str(raw.get("relationship_type")),
        source=source,
        target=target,
        direction=_optional_str(direction),
    )


def _shape_report(raw: Any) -> CtiReport:
    if not isinstance(raw, dict):
        return CtiReport(name=str(raw))
    labels = raw.get("labels") or raw.get("objectLabel") or []
    if isinstance(labels, list):
        shaped_labels = [
            str(item.get("value") if isinstance(item, dict) else item)
            for item in labels
            if item is not None
        ]
    else:
        shaped_labels = [str(labels)]
    object_refs_raw = raw.get("object_refs") or raw.get("objects") or []
    object_refs = []
    for item in _safe_list(object_refs_raw):
        if isinstance(item, dict):
            ref_id = item.get("id")
            if ref_id:
                object_refs.append(str(ref_id))
        elif item is not None:
            object_refs.append(str(item))
    return CtiReport(
        id=_optional_str(raw.get("id")),
        name=_optional_str(raw.get("name")),
        published=_optional_str(raw.get("published")),
        description=_optional_str(raw.get("description")),
        labels=shaped_labels,
        confidence=_optional_int(raw.get("confidence")),
        object_refs=object_refs,
    )


def _shape_endpoint(raw: Any) -> CtiEntity | None:
    if not isinstance(raw, dict):
        return None
    return _shape_entity(
        {
            "id": raw.get("id"),
            "entity_type": raw.get("entity_type") or raw.get("type"),
            "name": raw.get("name") or raw.get("value"),
        }
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
    """Advertised output schema — delegates to ``sift_common.registry_helpers``."""
    return tool_output_schema(out_model)
