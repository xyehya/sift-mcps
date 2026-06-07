"""Exposure-agnostic FastMCP 3 registry for the OpenSearch backend."""

from __future__ import annotations

import inspect
import json
import os
from collections.abc import Callable
from enum import Enum
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
_TOOL_META: dict[str, dict[str, Any]] = {}


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


class AggregateIn(CaseScopedQueryBase):
    field: str = Field(
        ...,
        min_length=1,
        description=(
            "Field to group by. CSV/registry text fields need '.keyword' "
            "(e.g. 'Path.keyword'); evtx fields like event.code are already keyword."
        ),
    )
    query: str = Field("*", description="query_string filter applied before aggregation.")
    limit: int = Field(50, ge=1, le=500, description="Max buckets. Hard cap 500.")


class Bucket(BaseModel):
    key: Any = Field(..., description="Bucket value.")
    count: int = Field(..., description="Doc count for the value.")


class AggregateOut(BaseModel):
    field: str = Field(..., description="Field grouped by this aggregation.")
    total_docs: int = Field(..., description="Docs matching query before bucketing.")
    buckets: list[Bucket] = Field(..., description="Top-N buckets for the requested field.")
    truncated: bool = Field(..., description="True when bucket count hit the limit.")


class GetEventIn(BaseModel):
    event_id: str = Field(..., min_length=1, description="Document _id from a search hit.")
    index: str = Field(
        ...,
        description="Exact case-* index name from the search hit; patterns are rejected.",
    )

    @field_validator("index")
    @classmethod
    def _validate_exact_case_index(cls, value: str) -> str:
        if not value.startswith("case-"):
            raise ValueError("index must start with 'case-'")
        if "*" in value or "," in value:
            raise ValueError("index must be an exact index name, not a pattern")
        return value


class GetEventOut(SearchHit):
    note: str = Field("Full document - no truncation", description="Full document fetch note.")


class TimelineIn(CaseScopedQueryBase):
    query: str = Field("*", description="query_string filter.")
    interval: str = Field(
        "1h",
        pattern=r"^\d+[smhd]$",
        description="Bucket size: Ns/Nm/Nh/Nd (e.g. 30m, 1h, 1d).",
    )
    time_field: str = Field("@timestamp", description="Date field to bucket on.")
    time_from: str = Field("", description="ISO-8601 lower bound.")
    time_to: str = Field("", description="ISO-8601 upper bound.")


class TimeBucket(BaseModel):
    time: str = Field(..., description="Bucket start (ISO-8601).")
    count: int = Field(..., description="Document count in this time bucket.")


class TimelineOut(BaseModel):
    total_docs: int = Field(..., description="Docs matching query before bucketing.")
    interval: str = Field(..., description="Histogram interval used.")
    buckets: list[TimeBucket] = Field(..., description="Sparse date histogram buckets.")
    advisories: list[Advisory] = Field(
        default_factory=list,
        description="Optional narrowing advisory for very large histograms.",
    )


class FieldValuesIn(CaseScopedQueryBase):
    field: str = Field(
        ...,
        min_length=1,
        description="Field to enumerate. CSV/text fields need '.keyword'.",
    )
    query: str = Field("*", description="query_string filter to narrow the value set.")
    limit: int = Field(50, ge=1, le=500, description="Max distinct values. Hard cap 500.")


class FieldValue(BaseModel):
    value: Any = Field(..., description="Distinct field value.")
    count: int = Field(..., description="Document count for this value.")


class FieldValuesOut(BaseModel):
    field: str = Field(..., description="Field enumerated.")
    values: list[FieldValue] = Field(..., description="Distinct values with counts.")
    truncated: bool = Field(..., description="True when more distinct values exist than returned.")


class StatusIn(BaseModel):
    pass


class IndexInfo(BaseModel):
    index: str = Field(..., description="Case index name.")
    docs: int = Field(..., description="Document count for the index.")
    size: str = Field(..., description="Human store size, e.g. '1.2gb'.")
    status: str = Field(..., description="Index status reported by cat indices.")


class StatusOut(BaseModel):
    cluster_status: str = Field(
        ..., description="Cluster health status; single-node yellow may be annotated normal."
    )
    indices: list[IndexInfo] = Field(..., description="All case-* indices, sorted by name.")
    total_indices: int = Field(..., description="Number of case-* indices returned.")


class ShardStatusIn(BaseModel):
    pass


class TopIndexShards(BaseModel):
    index: str = Field(..., description="Index name.")
    primary_shards: int = Field(..., description="Primary shard count.")
    replica_shards: int = Field(..., description="Replica shard count.")
    doc_count: int = Field(..., description="Document count.")
    size: str | None = Field(None, description="Human store size if reported.")


class ShardStatusOut(BaseModel):
    current_shards: int = Field(..., description="Current shard count.")
    max_shards_per_node: int = Field(..., description="Configured max shards per data node.")
    data_nodes: int = Field(..., description="Number of data nodes.")
    max_total: int = Field(..., description="Maximum total shards across data nodes.")
    headroom_pct: float = Field(..., description="Remaining shard capacity percentage.")
    status: Literal["ok", "warning", "critical"] = Field(
        ..., description="ok>=10%, warning>=2%, critical<2% headroom."
    )
    top_indices_by_shard_count: list[TopIndexShards] = Field(
        ..., description="Top visible indices by shard count."
    )


class CaseSummaryIn(BaseModel):
    case_id: str = Field("", description="Case id; empty resolves to active case.")
    include_fields: bool = Field(
        False,
        description=(
            "Include per-artifact field-type mappings; large output needed to decide "
            "'.keyword' suffixes."
        ),
    )


class ArtifactCoverage(BaseModel):
    docs: int = Field(..., description="Document count for the artifact family.")
    hosts: list[str] = Field(default_factory=list, description="Hosts with this artifact.")
    indices: list[str] = Field(default_factory=list, description="Concrete indices merged.")


class CoverageGap(BaseModel):
    coverage_gap: str = Field(..., description="Missing coverage or enrichment.")
    when_to_run: str = Field(..., description="When this gap should be filled.")
    command: str = Field(..., description="Exact ingest/enrich call to fill the gap.")
    next_mcp_step: str = Field(..., description="Next MCP step after filling the gap.")
    warning: str | None = Field(None, description="Non-fatal warning about the gap.")
    output_path: str | None = Field(None, description="Expected output path if applicable.")


class CoverageState(BaseModel):
    disk_artifacts: dict[str, Literal["indexed", "not_run", "not_available"]] = Field(
        default_factory=dict,
        description="Expected disk artifact coverage state.",
    )
    memory: dict[str, Any] = Field(
        default_factory=dict,
        description="{tier_run, plugins_run, plugins_not_run}.",
    )
    enrichment: dict[str, Literal["done", "not_run"]] = Field(
        default_factory=dict,
        description="Triage and threat-intel enrichment state.",
    )
    gaps: list[CoverageGap] = Field(default_factory=list, description="Actionable gaps.")
    filesystem_meta_path: str | None = Field(
        None,
        description="Most recent filesystem metadata sidecar path, relative to case dir.",
    )


class CaseSummaryOut(BaseModel):
    case_id: str = Field(..., description="Resolved case id.")
    hosts: list[str] = Field(default_factory=list, description="Indexed hosts.")
    artifacts: dict[str, ArtifactCoverage] = Field(
        default_factory=dict,
        description="Artifact coverage keyed by artifact family.",
    )
    total_docs: int = Field(..., description="Total case document count.")
    time_range: dict[str, str] = Field(
        default_factory=dict,
        description="{earliest, latest} ISO-8601.",
    )
    enrichment: dict[str, Any] = Field(
        default_factory=dict,
        description="{triage:{checked,suspicious}, threat_intel:{checked,malicious}}.",
    )
    coverage_state: CoverageState = Field(..., description="Coverage and gap state.")
    fields_per_type: dict[str, list[dict[str, Any]]] | None = Field(
        None,
        description="Optional capped field mappings per artifact type.",
    )
    investigation_hints: list[str] = Field(
        default_factory=list,
        description="Compact investigation hints for indexed artifacts.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal sub-query failures.",
    )


class InspectContainerIn(BaseModel):
    path: str = Field(
        ...,
        description="Container path under the active case; bare names resolve to evidence/.",
    )


class InspectContainerOut(BaseModel):
    path: str = Field(..., description="Original path argument.")
    resolved_path: str = Field(..., description="Resolved filesystem path.")
    container_type: Literal["e01", "raw", "file", "unknown"] = Field(
        ..., description="Detected container type."
    )
    tool_available: bool = Field(
        ..., description="False when no inspection tool is available on the SIFT VM."
    )
    size_bytes: int | None = Field(None, description="Container size in bytes if known.")
    size_human: str | None = Field(None, description="Human-readable container size.")
    hashes: dict[str, str] = Field(default_factory=dict, description="Reported hashes.")
    partitions: list[dict[str, Any]] = Field(
        default_factory=list, description="Detected partitions when available."
    )
    acquiry_info: dict[str, Any] | None = Field(
        None, description="E01 acquisition metadata from ewfinfo."
    )
    raw_info: str | None = Field(None, description="Truncated fdisk/img_stat output.")


class IngestFormat(str, Enum):
    auto = "auto"
    json = "json"
    delimited = "delimited"
    accesslog = "accesslog"
    memory = "memory"


class IngestIn(BaseModel):
    path: str = Field(
        ...,
        description="Evidence path under active case; bare names resolve to evidence/.",
    )
    format: IngestFormat = Field(
        IngestFormat.auto,
        description="auto=containers/artifact dirs; otherwise choose a specific evidence format.",
    )
    hostname: str = Field(
        "",
        description=(
            "Source hostname. Required for json/accesslog/memory and most delimited. "
            "'auto' detects from filenames for flat delimited dirs."
        ),
    )
    index_suffix: str = Field("", description="Optional index suffix.")
    time_field: str = Field("", description="Optional timestamp field.")
    delimiter: str = Field("", description="Optional delimiter for delimited input.")
    recursive: bool = Field(
        False, description="Delimited dirs: treat immediate subdirs as hostnames."
    )
    include: list[str] | None = Field(None, description="Only these artifact types.")
    exclude: list[str] | None = Field(None, description="Skip these artifact types.")
    source_timezone: str = Field(
        "", description="Evidence system local timezone, e.g. Eastern Standard Time."
    )
    all_logs: bool = Field(False, description="Parse all evtx, not only forensic logs.")
    reduced_ids: bool = Field(False, description="Filter to high-value Event IDs.")
    full: bool = Field(False, description="Include all ingest tiers.")
    tier: int = Field(1, ge=1, le=3, description="Memory analysis depth: 1 fast, 3 deep.")
    plugins: list[str] | None = Field(None, description="Memory: run only these plugins.")
    dry_run: bool = Field(True, description="Preview without indexing by default.")
    force: bool = Field(
        False,
        description="Allow intentional re-ingest when the case already has docs.",
    )
    vss: bool = Field(False, description="Process Volume Shadow Copies.")
    password: str = Field(
        "",
        description="Archive/container password. SECRET - redacted from audit/logs/results.",
    )
    no_hayabusa: bool = Field(False, description="Skip Hayabusa Sigma scan.")


class IngestOut(BaseModel):
    status: Literal[
        "preview",
        "started",
        "containers_detected",
        "multi_started",
        "already_indexed",
        "failed",
    ] = Field(..., description="Ingest response status.")
    case_id: str | None = Field(None, description="Resolved active case id.")
    plan: dict[str, Any] = Field(default_factory=dict, description="Preview plan/details.")
    container: dict[str, Any] | None = Field(None, description="Detected container details.")
    already_indexed: dict[str, Any] | None = Field(
        None, description="Existing index warning, when present."
    )
    suggested_hostname: str | None = Field(None, description="Suggested source hostname.")
    warning: str | None = Field(None, description="Non-fatal warning.")
    pid: int | None = Field(None, description="Background process id for started runs.")
    run_id: str | None = Field(None, description="Background ingest run id.")
    log_file: str | None = Field(None, description="Background run log file.")
    note: str | None = Field(None, description="Polling or operator note.")
    details: dict[str, Any] = Field(
        default_factory=dict, description="Additional behavior-compatible legacy fields."
    )


class IngestStatusIn(BaseModel):
    case_id: str = Field("", description="Filter to this case; default active. '*' for all.")


class ChecklistItem(BaseModel):
    host: str = Field(..., description="Host name.")
    artifact: str = Field(..., description="Artifact name.")
    status: Literal["done", "running", "failed", "pending"] = Field(
        ..., description="Per-artifact status."
    )
    detail: str = Field(..., description="Human-readable artifact progress detail.")


class IngestRun(BaseModel):
    case_id: str | None = Field(None, description="Case id.")
    status: Literal["starting", "running", "complete", "failed", "killed", "unknown"] = Field(
        ..., description="Run status."
    )
    pid: int | None = Field(None, description="Worker process id.")
    elapsed: str = Field(..., description="Elapsed time display.")
    total_indexed: int = Field(..., description="Total submitted documents.")
    bulk_failed: int = Field(..., description="Bulk write failures.")
    hosts_complete: int = Field(..., description="Completed host count.")
    hosts_total: int = Field(..., description="Total host count.")
    artifacts_complete: int = Field(..., description="Completed artifact count.")
    artifacts_total: int = Field(..., description="Total artifact count.")
    log_file: str = Field("", description="Run log file.")
    checklist: list[ChecklistItem] = Field(default_factory=list, description="Progress checklist.")
    message: str = Field("", description="Operator-facing status message.")
    halt_reason: str | None = Field(None, description="Structured halt reason when failed.")
    errors: list[str] = Field(default_factory=list, description="Per-artifact errors.")
    next_steps: list[str] = Field(default_factory=list, description="Suggested next steps.")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings.")
    details: dict[str, Any] = Field(
        default_factory=dict, description="Additional behavior-compatible fields."
    )


class IngestStatusOut(BaseModel):
    ingests: list[IngestRun] = Field(..., description="Running or recent ingest/enrich runs.")
    message: str | None = Field(None, description="Summary message when no runs are present.")


class EnrichIntelIn(BaseModel):
    case_id: str = Field("", description="Case to enrich; default active.")
    dry_run: bool = Field(True, description="Extract and count IOCs without lookup.")
    force: bool = Field(False, description="Re-enrich already-enriched docs.")


class EnrichIntelOut(BaseModel):
    status: Literal["preview", "started"] = Field(..., description="Enrichment response status.")
    case_id: str = Field(..., description="Resolved case id.")
    ips: int | None = Field(None, description="Unique IP indicators in preview.")
    hashes: int | None = Field(None, description="Unique hash indicators in preview.")
    domains: int | None = Field(None, description="Unique domain indicators in preview.")
    total_iocs: int | None = Field(None, description="Total unique IOCs in preview.")
    pid: int | None = Field(None, description="Background process id.")
    run_id: str | None = Field(None, description="Background run id.")
    log_file: str | None = Field(None, description="Background run log file.")
    note: str | None = Field(None, description="Polling note.")


class EnrichTriageIn(BaseModel):
    case_id: str = Field("", description="Case to enrich; default active.")


class EnrichTriageOut(BaseModel):
    status: Literal["complete"] = Field(..., description="Triage enrichment status.")
    documents_enriched: int = Field(..., description="Total documents enriched.")
    details: dict[str, Any] = Field(..., description="Per-artifact enriched counts.")


class ListDetectionsIn(BaseModel):
    severity: Literal["", "critical", "high", "medium", "low"] = Field(
        "", description="Severity filter; empty returns all severities."
    )
    detector_type: str = Field("", description="Detector type filter; empty returns all.")
    limit: int = Field(50, ge=1, le=500, description="Max findings. Hard cap 500.")
    offset: int = Field(0, ge=0, description="Pagination start.")


class DetectionRuleRef(BaseModel):
    name: str | None = Field(None, description="Detection rule name.")
    tags: list[str] = Field(default_factory=list, description="Rule tags.")


class Detection(BaseModel):
    id: str | None = Field(None, description="Finding id.")
    timestamp: str | int | None = Field(None, description="Finding timestamp.")
    index: str | None = Field(None, description="Source index.")
    rules: list[DetectionRuleRef] = Field(default_factory=list, description="Matched rules.")
    matched_docs: int = Field(..., description="Related document count.")


class ListDetectionsOut(BaseModel):
    findings: list[Detection] = Field(..., description="Detection findings.")
    total: int = Field(..., description="Total findings reported by upstream.")
    returned: int = Field(..., description="Findings returned after filtering.")
    offset: int = Field(..., description="Pagination offset.")
    suggestion: str | None = Field(
        None, description="Hayabusa fallback query when Sigma is unavailable or empty."
    )


class FixHostMappingIn(BaseModel):
    raw: str = Field(
        ..., min_length=1, description="The raw host.name value with the wrong mapping."
    )
    new_canonical: str = Field(
        ..., min_length=1, description="The correct canonical host.id to assign."
    )


class FixHostMappingOut(BaseModel):
    status: Literal["complete"] = Field(..., description="Correction status.")
    raw: str = Field(..., description="Raw host.name value corrected.")
    new_canonical: str = Field(..., description="Canonical host.id assigned.")
    docs_updated: int | None = Field(None, description="Documents updated by reindex.")
    dict_path: str | None = Field(None, description="Host dictionary path.")
    dict_saved: bool = Field(True, description="Whether the host dictionary was saved.")
    details: dict[str, Any] = Field(
        default_factory=dict, description="Additional behavior-compatible fields."
    )


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


def _timeline_bucket_warning_limit() -> int:
    raw = os.environ.get("OPENSEARCH_TIMELINE_BUCKET_WARNING_LIMIT", "2000")
    try:
        value = int(raw)
    except ValueError:
        return 2000
    return max(value, 1)


def _json_from_tool_result(result: ToolResult) -> str:
    return _json_text(result.structured_content or {})


def _redact_secret_fields(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if key.lower() in {"password", "secret", "token"}:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_secret_fields(item)
        return redacted
    if isinstance(value, list):
        return [_redact_secret_fields(item) for item in value]
    return value


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


async def run_opensearch_aggregate(params: AggregateIn) -> ToolResult:
    raw = _legacy_server().opensearch_aggregate(**params.model_dump())
    if "error" in raw:
        return _legacy_error(raw)
    meta = _meta_from_raw(raw)
    out = AggregateOut(
        field=str(raw.get("field", params.field)),
        total_docs=int(raw.get("total_docs", 0)),
        buckets=[Bucket.model_validate(bucket) for bucket in raw.get("buckets", [])],
        truncated=bool(raw.get("truncated", False)),
    )
    return _success_tool_result(out, meta)


async def run_opensearch_get_event(params: GetEventIn) -> ToolResult:
    try:
        raw = _legacy_server().opensearch_get_event(**params.model_dump())
    except Exception as exc:  # noqa: BLE001 - sanitized typed error for MCP clients
        message = f"{type(exc).__name__}: document lookup failed."
        code = ErrorCode.not_found if "not" in type(exc).__name__.lower() else ErrorCode.internal
        return _tool_error_result(
            code,
            message,
            "Confirm event_id and exact case-* index from opensearch_search, then retry.",
        )
    if "error" in raw:
        return _legacy_error(raw)
    meta = _meta_from_raw(raw)
    fields = {key: value for key, value in raw.items() if key not in {"_id", "_index", "_note"}}
    out = GetEventOut(
        id=str(raw.get("_id", params.event_id)),
        index=str(raw.get("_index", params.index)),
        fields=fields,
        truncated=[],
        note=str(raw.get("_note", "Full document - no truncation")),
    )
    return _success_tool_result(out, meta)


async def run_opensearch_timeline(params: TimelineIn) -> ToolResult:
    raw = _legacy_server().opensearch_timeline(**params.model_dump())
    if "error" in raw:
        return _legacy_error(raw)
    meta = _meta_from_raw(raw)
    buckets = [TimeBucket.model_validate(bucket) for bucket in raw.get("buckets", [])]
    advisories = _advisories_from_raw(raw)
    warning_limit = _timeline_bucket_warning_limit()
    if len(buckets) >= warning_limit:
        advisories.append(
            Advisory(
                kind="pagination",
                text=(
                    f"Timeline returned {len(buckets)} buckets, meeting the "
                    f"configured warning ceiling ({warning_limit}). Narrow with "
                    "time_from/time_to or increase interval; buckets were not truncated."
                ),
            )
        )
    out = TimelineOut(
        total_docs=int(raw.get("total_docs", 0)),
        interval=str(raw.get("interval", params.interval)),
        buckets=buckets,
        advisories=advisories,
    )
    return _success_tool_result(out, meta)


async def run_opensearch_field_values(params: FieldValuesIn) -> ToolResult:
    raw = _legacy_server().opensearch_field_values(**params.model_dump())
    if "error" in raw:
        return _legacy_error(raw)
    meta = _meta_from_raw(raw)
    values = [
        FieldValue(value=value.get("value"), count=int(value.get("count", 0)))
        for value in raw.get("values", [])
    ]
    out = FieldValuesOut(
        field=str(raw.get("field", params.field)),
        values=values,
        truncated=bool(raw.get("truncated", False)),
    )
    return _success_tool_result(out, meta)


async def run_opensearch_status(_params: StatusIn) -> ToolResult:
    try:
        raw = _legacy_server().opensearch_status()
    except Exception as exc:  # noqa: BLE001 - expose typed upstream failure
        return _tool_error_result(
            ErrorCode.upstream_unavailable,
            f"{type(exc).__name__}: OpenSearch status check failed.",
            "Check OpenSearch connectivity and credentials, then retry.",
            retryable=True,
        )
    if "error" in raw:
        return _legacy_error(raw, default_code=ErrorCode.upstream_unavailable)
    meta = _meta_from_raw(raw)
    out = StatusOut(
        cluster_status=str(raw.get("cluster_status", "unknown")),
        indices=[IndexInfo.model_validate(item) for item in raw.get("indices", [])],
        total_indices=int(raw.get("total_indices", 0)),
    )
    return _success_tool_result(out, meta)


async def opensearch_cluster_status_resource() -> str:
    return _json_from_tool_result(await run_opensearch_status(StatusIn()))


async def run_opensearch_shard_status(_params: ShardStatusIn) -> ToolResult:
    try:
        raw = _legacy_server().opensearch_shard_status()
    except Exception as exc:  # noqa: BLE001 - expose typed upstream failure
        return _tool_error_result(
            ErrorCode.upstream_unavailable,
            f"{type(exc).__name__}: OpenSearch shard status check failed.",
            "Check OpenSearch connectivity and credentials, then retry.",
            retryable=True,
        )
    if raw.get("status") == "error" or "error" in raw:
        return _legacy_error(raw, default_code=ErrorCode.upstream_unavailable)
    meta = _meta_from_raw(raw)
    out = ShardStatusOut(
        current_shards=int(raw.get("current_shards", 0)),
        max_shards_per_node=int(raw.get("max_shards_per_node", 0)),
        data_nodes=int(raw.get("data_nodes", 0)),
        max_total=int(raw.get("max_total", 0)),
        headroom_pct=float(raw.get("headroom_pct", 0.0)),
        status=raw.get("status", "critical"),
        top_indices_by_shard_count=[
            TopIndexShards.model_validate(item)
            for item in raw.get("top_indices_by_shard_count", [])
        ],
    )
    return _success_tool_result(out, meta)


async def opensearch_cluster_shards_resource() -> str:
    return _json_from_tool_result(await run_opensearch_shard_status(ShardStatusIn()))


def _coverage_state_from_raw(raw: dict[str, Any]) -> CoverageState:
    state = raw.get("coverage_state") or {}
    return CoverageState(
        disk_artifacts=state.get("disk_artifacts") or {},
        memory=state.get("memory") or {},
        enrichment=state.get("enrichment") or {},
        gaps=[CoverageGap.model_validate(gap) for gap in state.get("gaps", [])],
        filesystem_meta_path=state.get("filesystem_meta_path"),
    )


async def run_opensearch_case_summary(params: CaseSummaryIn) -> ToolResult:
    raw = _legacy_server().opensearch_case_summary(**params.model_dump())
    if "error" in raw:
        default = (
            ErrorCode.no_active_case
            if "active case" in str(raw.get("error"))
            else ErrorCode.not_found
        )
        return _legacy_error(raw, default_code=default)
    meta = _meta_from_raw(raw)
    fields_per_type = raw.get("fields_per_type")
    out = CaseSummaryOut(
        case_id=str(raw.get("case_id", params.case_id)),
        hosts=list(raw.get("hosts", [])),
        artifacts={
            key: ArtifactCoverage.model_validate(value)
            for key, value in (raw.get("artifacts") or {}).items()
        },
        total_docs=int(raw.get("total_docs", 0)),
        time_range=dict(raw.get("time_range") or {}),
        enrichment=dict(raw.get("enrichment") or {}),
        coverage_state=_coverage_state_from_raw(raw),
        fields_per_type=fields_per_type,
        investigation_hints=list(raw.get("investigation_hints", [])),
        warnings=list(raw.get("warnings", [])),
    )
    return _success_tool_result(out, meta)


async def opensearch_case_summary_resource(case_id: str) -> str:
    result = await run_opensearch_case_summary(
        CaseSummaryIn(case_id=case_id, include_fields=False)
    )
    return _json_from_tool_result(result)


async def run_opensearch_inspect_container(params: InspectContainerIn) -> ToolResult:
    raw = _legacy_server().opensearch_inspect_container(**params.model_dump())
    if "error" in raw:
        return _legacy_error(raw, default_code=ErrorCode.not_found)
    meta = _meta_from_raw(raw)
    out = InspectContainerOut(
        path=str(raw.get("path", params.path)),
        resolved_path=str(raw.get("resolved_path", "")),
        container_type=raw.get("container_type", "unknown"),
        tool_available=bool(raw.get("tool_available", False)),
        size_bytes=raw.get("size_bytes"),
        size_human=raw.get("size_human"),
        hashes=dict(raw.get("hashes") or {}),
        partitions=list(raw.get("partitions") or []),
        acquiry_info=raw.get("acquiry_info") or raw.get("acquiry"),
        raw_info=raw.get("raw_info"),
    )
    return _success_tool_result(out, meta)


async def run_opensearch_ingest(params: IngestIn) -> ToolResult:
    raw = _legacy_server().opensearch_ingest(**params.model_dump(mode="json"))
    raw = _redact_secret_fields(raw)
    if "error" in raw and raw.get("status") not in {"failed", "already_indexed"}:
        message = str(raw.get("error"))
        if "No active case" in message:
            code = ErrorCode.no_active_case
        elif "Path not found" in message or "not found" in message.lower():
            code = ErrorCode.not_found
        elif raw.get("error") == "shard_capacity":
            code = ErrorCode.capacity_refused
        else:
            code = ErrorCode.invalid_input
        return _legacy_error(raw, default_code=code)
    meta = _meta_from_raw(raw)
    status = str(raw.get("status", "preview"))
    if status == "running":
        status = "started"
    if status not in {
        "preview",
        "started",
        "containers_detected",
        "multi_started",
        "already_indexed",
        "failed",
    }:
        status = "preview"
    details = {
        key: value
        for key, value in raw.items()
        if key
        not in {
            "status",
            "case_id",
            "plan",
            "container",
            "already_indexed",
            "suggested_hostname",
            "warning",
            "pid",
            "run_id",
            "log_file",
            "message",
            "note",
        }
    }
    out = IngestOut(
        status=status,
        case_id=raw.get("case_id"),
        plan=dict(raw.get("plan") or {}),
        container=raw.get("container"),
        already_indexed=raw.get("already_indexed"),
        suggested_hostname=raw.get("suggested_hostname"),
        warning=raw.get("warning"),
        pid=raw.get("pid"),
        run_id=raw.get("run_id"),
        log_file=raw.get("log_file"),
        note=raw.get("note") or raw.get("message"),
        details=details,
    )
    return _success_tool_result(out, meta)


async def run_opensearch_ingest_status(params: IngestStatusIn) -> ToolResult:
    raw = _legacy_server().opensearch_ingest_status(**params.model_dump())
    if "error" in raw:
        return _legacy_error(raw, default_code=ErrorCode.no_active_case)
    meta = _meta_from_raw(raw)
    runs: list[IngestRun] = []
    for item in raw.get("ingests", []):
        details = {
            key: value
            for key, value in item.items()
            if key
            not in {
                "case_id",
                "status",
                "pid",
                "elapsed",
                "total_indexed",
                "bulk_failed",
                "hosts_complete",
                "hosts_total",
                "artifacts_complete",
                "artifacts_total",
                "log_file",
                "checklist",
                "message",
                "halt_reason",
                "errors",
                "next_steps",
                "warnings",
            }
        }
        runs.append(
            IngestRun(
                case_id=item.get("case_id"),
                status=item.get("status", "unknown"),
                pid=item.get("pid"),
                elapsed=str(item.get("elapsed", "")),
                total_indexed=int(item.get("total_indexed", 0)),
                bulk_failed=int(item.get("bulk_failed", 0)),
                hosts_complete=int(item.get("hosts_complete", 0)),
                hosts_total=int(item.get("hosts_total", 0)),
                artifacts_complete=int(item.get("artifacts_complete", 0)),
                artifacts_total=int(item.get("artifacts_total", 0)),
                log_file=str(item.get("log_file", "")),
                checklist=[
                    ChecklistItem.model_validate(check) for check in item.get("checklist", [])
                ],
                message=str(item.get("message", "")),
                halt_reason=item.get("halt_reason"),
                errors=list(item.get("errors", [])),
                next_steps=list(item.get("next_steps", [])),
                warnings=list(item.get("warnings", [])),
                details=details,
            )
        )
    return _success_tool_result(
        IngestStatusOut(ingests=runs, message=raw.get("message")),
        meta,
    )


async def run_opensearch_enrich_intel(params: EnrichIntelIn) -> ToolResult:
    raw = _legacy_server().opensearch_enrich_intel(**params.model_dump())
    if "error" in raw:
        message = str(raw.get("error"))
        if "No active case" in message:
            code = ErrorCode.no_active_case
        elif "Too many concurrent" in message:
            code = ErrorCode.capacity_refused
        else:
            code = ErrorCode.upstream_unavailable
        return _legacy_error(raw, default_code=code)
    meta = _meta_from_raw(raw)
    out = EnrichIntelOut(
        status=raw.get("status", "preview"),
        case_id=str(raw.get("case_id", params.case_id)),
        ips=raw.get("ips"),
        hashes=raw.get("hashes"),
        domains=raw.get("domains"),
        total_iocs=raw.get("total_iocs"),
        pid=raw.get("pid"),
        run_id=raw.get("run_id"),
        log_file=raw.get("log_file"),
        note=raw.get("note") or raw.get("message"),
    )
    return _success_tool_result(out, meta)


async def run_opensearch_enrich_triage(params: EnrichTriageIn) -> ToolResult:
    raw = _legacy_server().opensearch_enrich_triage(**params.model_dump())
    if "error" in raw:
        default = (
            ErrorCode.no_active_case
            if "No active case" in str(raw.get("error"))
            else ErrorCode.upstream_unavailable
        )
        return _legacy_error(raw, default_code=default)
    meta = _meta_from_raw(raw)
    out = EnrichTriageOut(
        status=raw.get("status", "complete"),
        documents_enriched=int(raw.get("documents_enriched", 0)),
        details=dict(raw.get("details") or {}),
    )
    return _success_tool_result(out, meta)


async def run_opensearch_list_detections(params: ListDetectionsIn) -> ToolResult:
    try:
        raw = _legacy_server().opensearch_list_detections(**params.model_dump())
    except Exception as exc:  # noqa: BLE001 - expose typed upstream failure
        return _tool_error_result(
            ErrorCode.upstream_unavailable,
            f"{type(exc).__name__}: detection lookup failed.",
            "Check OpenSearch Security Analytics availability, then retry.",
            retryable=True,
        )
    if "error" in raw and "Security Analytics plugin not available" not in str(raw.get("error")):
        return _legacy_error(raw, default_code=ErrorCode.upstream_unavailable)
    raw.pop("error", None)
    meta = _meta_from_raw(raw)
    out = ListDetectionsOut(
        findings=[Detection.model_validate(item) for item in raw.get("findings", [])],
        total=int(raw.get("total", 0)),
        returned=int(raw.get("returned", 0)),
        offset=int(raw.get("offset", params.offset)),
        suggestion=raw.get("suggestion"),
    )
    return _success_tool_result(out, meta)


async def opensearch_case_detections_resource(case_id: str) -> str:
    _ = case_id
    result = await run_opensearch_list_detections(ListDetectionsIn())
    return _json_from_tool_result(result)


async def run_opensearch_fix_host_mapping(params: FixHostMappingIn) -> ToolResult:
    raw = _legacy_server().opensearch_host_fix(**params.model_dump())
    raw = _redact_secret_fields(raw)
    meta = _meta_from_raw(raw)
    legacy_status = raw.get("status")
    if raw.get("isError") or "error" in raw:
        code = (
            ErrorCode.invalid_input
            if legacy_status == "rejected" or "InvalidHostnameValue" in str(raw.get("error"))
            else ErrorCode.upstream_unavailable
            if legacy_status == "reindex_failed"
            else ErrorCode.internal
        )
        return _tool_error_result(
            code,
            str(raw.get("error") or "Host mapping correction failed."),
            str(
                raw.get("retry_hint")
                or raw.get("portal_hint")
                or "Review the host dictionary and retry with a valid canonical host id."
            ),
            retryable=legacy_status == "reindex_failed",
            details={k: v for k, v in raw.items() if k not in {"error", "isError"}},
            meta=meta,
        )
    details = {
        key: value
        for key, value in raw.items()
        if key
        not in {
            "status",
            "raw",
            "new_canonical",
            "docs_updated",
            "dict_path",
            "dict_saved",
        }
    }
    out = FixHostMappingOut(
        status="complete",
        raw=str(raw.get("raw", params.raw)),
        new_canonical=str(raw.get("new_canonical", params.new_canonical)),
        docs_updated=raw.get("docs_updated"),
        dict_path=raw.get("dict_path"),
        dict_saved=bool(raw.get("dict_saved", True)),
        details=details,
    )
    return _success_tool_result(out, meta)


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

REGISTRY.append(
    ToolDef(
        name="opensearch_list_detections",
        fn=run_opensearch_list_detections,
        in_model=ListDetectionsIn,
        out_model=ListDetectionsOut,
        annotations=_read_annotations("Security Analytics Detections"),
        title="Security Analytics Detections",
        description=(
            "List Security Analytics detection findings, or suggest a Hayabusa "
            "query when Sigma is unavailable or empty. Use to triage rule-based "
            "detections; severity filtering is applied behavior-compatibly. "
            "Example: opensearch_list_detections(severity='high')."
        ),
    )
)

RESOURCE_REGISTRY.append(
    ResourceDef(
        uri="opensearch://case/{case_id}/detections",
        fn=opensearch_case_detections_resource,
        name="opensearch_case_detections",
        title="Case Detection Findings",
        description="Unfiltered resource view of detection findings for case-oriented clients.",
    )
)

REGISTRY.append(
    ToolDef(
        name="opensearch_fix_host_mapping",
        fn=run_opensearch_fix_host_mapping,
        in_model=FixHostMappingIn,
        out_model=FixHostMappingOut,
        annotations=_write_annotations("Fix Host ID Mapping", idempotent=True),
        title="Fix Host ID Mapping",
        description=(
            "Correct a wrong host.id mapping in the active case by updating the "
            "case host dictionary and reindexing docs where host.name equals raw. "
            "host.name is never changed. Use when ingest applied a wrong canonical "
            "host id. Example: opensearch_fix_host_mapping(raw='wksn01', "
            "new_canonical='wksn01')."
        ),
        deprecated_aliases=["opensearch_host_fix"],
    )
)

REGISTRY.append(
    ToolDef(
        name="opensearch_enrich_triage",
        fn=run_opensearch_enrich_triage,
        in_model=EnrichTriageIn,
        out_model=EnrichTriageOut,
        annotations=_write_annotations("Enrich: Windows Baseline Triage"),
        title="Enrich: Windows Baseline Triage",
        description=(
            "Check indexed filenames and services against the Windows baseline DB "
            "and stamp triage verdict fields. Use after ingest or after a baseline "
            "update. This remains behavior-compatible with the current synchronous "
            "path. Example: opensearch_enrich_triage()."
        ),
    )
)

REGISTRY.append(
    ToolDef(
        name="opensearch_enrich_intel",
        fn=run_opensearch_enrich_intel,
        in_model=EnrichIntelIn,
        out_model=EnrichIntelOut,
        annotations=_write_annotations("Enrich: Threat Intel (OpenCTI)"),
        title="Enrich: Threat Intel (OpenCTI)",
        description=(
            "Extract unique IOCs from indexed docs, optionally look them up in "
            "OpenCTI, and stamp matching docs with threat_intel fields. Use "
            "dry_run=True to size the work, then dry_run=False to launch the "
            "existing async enrichment path. Example: "
            "opensearch_enrich_intel(dry_run=True)."
        ),
    )
)

REGISTRY.append(
    ToolDef(
        name="opensearch_ingest_status",
        fn=run_opensearch_ingest_status,
        in_model=IngestStatusIn,
        out_model=IngestStatusOut,
        annotations=_read_annotations("Ingest/Enrichment Progress"),
        title="Ingest/Enrichment Progress",
        description=(
            "Return status for running or recent ingest and enrichment runs. Use to "
            "poll every roughly 30 seconds while a run is active and present the "
            "per-host artifact checklist. Default is active case; case_id='*' "
            "shows all cases. Example: opensearch_ingest_status()."
        ),
    )
)

REGISTRY.append(
    ToolDef(
        name="opensearch_ingest",
        fn=run_opensearch_ingest,
        in_model=IngestIn,
        out_model=IngestOut,
        annotations=_write_annotations("Ingest Evidence into OpenSearch"),
        title="Ingest Evidence into OpenSearch",
        description=(
            "Preview (dry_run=True, default) or run evidence ingest into OpenSearch. "
            "Use dry_run=True first, review the plan, then dry_run=False with "
            "force=True only for intentional re-ingest. Execution remains "
            "behavior-compatible with the current async subprocess path. Example: "
            "opensearch_ingest(path='evidence/rocba-cdrive.e01', format='auto', "
            "dry_run=True)."
        ),
    )
)

REGISTRY.append(
    ToolDef(
        name="opensearch_field_values",
        fn=run_opensearch_field_values,
        in_model=FieldValuesIn,
        out_model=FieldValuesOut,
        annotations=_read_annotations("Field Value Discovery"),
        title="Field Value Discovery",
        description=(
            "Enumerate distinct values of a field with counts before writing "
            "targeted queries. Use for value discovery such as usernames or "
            "process names; prefer opensearch_aggregate when ranking matters. "
            "Example: opensearch_field_values(field='winlog.provider_name')."
        ),
    )
)

REGISTRY.append(
    ToolDef(
        name="opensearch_timeline",
        fn=run_opensearch_timeline,
        in_model=TimelineIn,
        out_model=TimelineOut,
        annotations=_read_annotations("Event Timeline (Histogram)"),
        title="Event Timeline (Histogram)",
        description=(
            "Build a date histogram of event counts to find activity bursts before "
            "drilling in. Use to locate spikes, then scope opensearch_search with "
            "time_from/time_to. Buckets are warned at the configured ceiling and "
            "never silently truncated. Example: "
            "opensearch_timeline(query='event.code:4688', interval='1h')."
        ),
    )
)

REGISTRY.append(
    ToolDef(
        name="opensearch_get_event",
        fn=run_opensearch_get_event,
        in_model=GetEventIn,
        out_model=GetEventOut,
        annotations=_read_annotations("Get Full Document"),
        title="Get Full Document",
        description=(
            "Fetch one complete document by _id with every field and no truncation. "
            "Use after opensearch_search when a compact hit needs inspection. "
            "The index must be exact, not a wildcard. Example: "
            "opensearch_get_event(event_id='abc123', "
            "index='case-rocba-drive-20260526-1417-evtx-srl-forge')."
        ),
    )
)

REGISTRY.append(
    ToolDef(
        name="opensearch_aggregate",
        fn=run_opensearch_aggregate,
        in_model=AggregateIn,
        out_model=AggregateOut,
        annotations=_read_annotations("Aggregate Field (Top-N)"),
        title="Aggregate Field (Top-N)",
        description=(
            "Group by a field for top-N frequency analysis such as event codes, "
            "users, hosts, or process names. Use for distributions. Do not use "
            "when you want individual documents; use opensearch_search. Example: "
            "opensearch_aggregate(field='event.code')."
        ),
    )
)

_TOOL_META["opensearch_status"] = {
    "deprecated": True,
    "resource_uri": "opensearch://cluster/status",
    "removal_horizon": "at/after D27b",
}
REGISTRY.append(
    ToolDef(
        name="opensearch_status",
        fn=run_opensearch_status,
        in_model=StatusIn,
        out_model=StatusOut,
        annotations=_read_annotations("Cluster & Index Status"),
        title="Cluster & Index Status",
        description=(
            "DEPRECATED tool form; prefer resource opensearch://cluster/status when "
            "available. Shows cluster health and per-case-index document counts. "
            "Use to confirm the cluster is reachable and see which cases have data; "
            "use opensearch_case_summary for one case's artifact and coverage breakdown."
        ),
    )
)

RESOURCE_REGISTRY.append(
    ResourceDef(
        uri="opensearch://cluster/status",
        fn=opensearch_cluster_status_resource,
        name="opensearch_cluster_status",
        title="Cluster & Index Status",
        description="Read-only resource view of OpenSearch cluster health and case index counts.",
    )
)

REGISTRY.append(
    ToolDef(
        name="opensearch_inspect_container",
        fn=run_opensearch_inspect_container,
        in_model=InspectContainerIn,
        out_model=InspectContainerOut,
        annotations=_read_annotations("Inspect Forensic Container"),
        title="Inspect Forensic Container",
        description=(
            "Survey a forensic container without mounting it: integrity, size, "
            "partitions, and available inspection details. Use before "
            "opensearch_ingest; follow with opensearch_ingest(dry_run=True) for "
            "the full plan. Example: "
            "opensearch_inspect_container(path='evidence/rocba-cdrive.e01')."
        ),
    )
)

REGISTRY.append(
    ToolDef(
        name="opensearch_case_summary",
        fn=run_opensearch_case_summary,
        in_model=CaseSummaryIn,
        out_model=CaseSummaryOut,
        annotations=_read_annotations("Case Coverage Summary"),
        title="Case Coverage Summary",
        description=(
            "Complete coverage overview for a case. Call this first in every "
            "indexed session to see hosts, artifact families, doc counts, "
            "enrichment state, and coverage_state.gaps with exact commands to "
            "fill missing coverage. Example: "
            "opensearch_case_summary(case_id='rocba-drive-20260526-1417')."
        ),
    )
)

RESOURCE_REGISTRY.append(
    ResourceDef(
        uri="opensearch://case/{case_id}/summary",
        fn=opensearch_case_summary_resource,
        name="opensearch_case_summary",
        title="Case Coverage Summary",
        description="Parameterized resource view of a case coverage summary.",
    )
)

_TOOL_META["opensearch_shard_status"] = {
    "deprecated": True,
    "resource_uri": "opensearch://cluster/shards",
    "removal_horizon": "at/after D27b",
}
REGISTRY.append(
    ToolDef(
        name="opensearch_shard_status",
        fn=run_opensearch_shard_status,
        in_model=ShardStatusIn,
        out_model=ShardStatusOut,
        annotations=_read_annotations("Shard Capacity"),
        title="Shard Capacity",
        description=(
            "DEPRECATED tool form; prefer resource opensearch://cluster/shards when "
            "available. Reports shard usage and capacity headroom. Use before large "
            "ingests because a full disk image can add many shards."
        ),
    )
)

RESOURCE_REGISTRY.append(
    ResourceDef(
        uri="opensearch://cluster/shards",
        fn=opensearch_cluster_shards_resource,
        name="opensearch_cluster_shards",
        title="Shard Capacity",
        description="Read-only resource view of OpenSearch shard usage and capacity headroom.",
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
    meta: dict[str, Any] | None = _TOOL_META.get(name)
    if deprecated_alias_of is not None:
        description = (
            f"DEPRECATED alias for `{deprecated_alias_of}`. "
            "Use the canonical name; this alias will be removed after one cutover cycle.\n\n"
            f"{tool_def.description}"
        )
        meta = {**(meta or {}), "deprecated": True, "canonical_name": deprecated_alias_of}

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
