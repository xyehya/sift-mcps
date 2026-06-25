"""Exposure-agnostic FastMCP 3 registry for the OpenSearch backend.

Layering (B-MVP-029):
  * ``opensearch_mcp.registry`` (this module) is the **typed contract layer** —
    it defines the pydantic In/Out models, validates inputs, maps raw dicts onto
    the typed result/error contracts, and advertises tool metadata.
  * ``opensearch_mcp.server`` is the **implementation engine** — it does the raw
    OpenSearch I/O and returns plain dicts.

The ``run_*`` wrappers here call into the implementation engine via
``_impl_server()`` and reshape its raw dict into a typed ``*Out`` model (or a
typed error via ``_impl_error``). The helper names use the ``_impl_*`` prefix to
reflect this engine relationship (formerly ``_legacy_*`` — renamed, the engine is
not legacy, it is the live implementation).
"""

from __future__ import annotations

import inspect
import json
import os
import re
from enum import Enum
from typing import Any, Literal

from fastmcp import FastMCP
from fastmcp.tools import FunctionTool, ToolResult
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field, ValidationError, field_validator
from sift_common.instructions import OPENSEARCH as _INSTRUCTIONS
from sift_common.registry_helpers import (
    PromptDef,
    ResourceDef,
    call_with_optional_context,
    error_result,
    success_result,
    tool_output_schema,
)
from sift_common.registry_helpers import (
    register_all as _register_all,
)

from .contracts import ErrorCode, ResultMeta, ToolDef, ToolError

REGISTRY: list[ToolDef] = []
PROMPT_REGISTRY: list[PromptDef] = []
RESOURCE_REGISTRY: list[ResourceDef] = []
_TOOL_META: dict[str, dict[str, Any]] = {}


# Gateway-injected authoritative case directory. The Gateway reads the
# deployment active case from Postgres (app.active_case_state) and propagates
# the case's artifact_path into each filesystem-touching tool call via this
# argument. Agents do not set it; the Gateway overwrites any client-supplied
# value with the DB-authoritative path (and denies a mismatching client value).
_CASE_DIR_DESCRIPTION = (
    "Gateway-injected authoritative case directory (from Postgres "
    "active_case_state). Do not set this; the Gateway populates it from the DB "
    "active case and rejects a mismatching client value."
)


def _case_dir_field() -> Any:
    return Field("", description=_CASE_DIR_DESCRIPTION)


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
    # B-MVP-036/029: every case-scoped query tool must ADVERTISE case_dir so the
    # Gateway's schema-gated injection (sift_gateway.server) can pass the
    # DB-authoritative active case directory through FastMCP's proxy transform.
    # Without the field on the served *In model, the proxy _forward rejects the
    # injected kwarg — count/aggregate/timeline/field_values previously failed
    # live; only search worked because it redeclared the field. Declared on the
    # base so every CaseScopedQueryBase tool inherits it (all are manifest-listed
    # with case_dir in safe_case_argument_names).
    case_dir: str = _case_dir_field()

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
    common_fields: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Fields identical across every hit, hoisted out of the per-hit docs "
            "(e.g. sift.case_id, sift.provenance_id). Apply to every hit in results."
        ),
    )
    full_path: str | None = Field(
        None,
        description=(
            "Case-relative path (e.g. agent/searches/search_<uuid>.json) holding the "
            "FULL hit set when results exceeded the inline cap; only the top-N are in "
            "results. Read/grep this file instead of re-querying."
        ),
    )
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
            "Field to group by (terms aggregation). CSV/registry text fields need "
            "'.keyword' (e.g. 'Path.keyword'); evtx fields like event.code are already "
            "keyword. There is no agg_type parameter — aggregation is always group-by."
        ),
    )
    query: str = Field(
        "*",
        description="query_string filter applied before aggregation (not an agg_type).",
    )
    limit: int = Field(
        50,
        ge=1,
        le=500,
        description="Max buckets. Hard cap 500. This is the bucket cap; there is no 'size' arg.",
    )


class Bucket(BaseModel):
    key: Any = Field(..., description="Bucket value.")
    count: int = Field(..., description="Doc count for the value.")


class AggregateOut(BaseModel):
    field: str = Field(..., description="Field grouped by this aggregation.")
    total_docs: int = Field(..., description="Docs matching query before bucketing.")
    buckets: list[Bucket] = Field(..., description="Top-N buckets for the requested field.")
    truncated: bool = Field(..., description="True when bucket count hit the limit.")
    full_path: str | None = Field(
        None,
        description=(
            "Case-relative path (e.g. agent/aggregations/aggregation_<uuid>.json) holding "
            "the FULL bucket set when it exceeded the inline count/byte cap; only the "
            "top-N are in buckets. Read/grep this file instead of re-aggregating."
        ),
    )


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


class HayabusaHealth(BaseModel):
    binary: str | None = Field(
        None,
        description="Resolved hayabusa binary path, or null when NOT installed (Sigma detection will be skipped).",
    )
    rules_dir: str | None = Field(
        None, description="Resolved hayabusa rules directory, or null when not found."
    )
    rules_count: int = Field(0, description="Count of *.yml rule files under rules_dir.")


class StatusOut(BaseModel):
    cluster_status: str = Field(
        ..., description="Cluster health status; single-node yellow may be annotated normal."
    )
    indices: list[IndexInfo] = Field(..., description="All case-* indices, sorted by name.")
    total_indices: int = Field(..., description="Number of case-* indices returned.")
    hayabusa: HayabusaHealth | None = Field(
        None,
        description=(
            "Hayabusa detection-engine health (binary/rules_dir/rules_count). "
            "binary=null ⇒ engine not installed; evtx ingest will skip Sigma detection."
        ),
    )


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
    case_dir: str = _case_dir_field()


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
    case_dir: str = _case_dir_field()


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
    partition_note: str | None = Field(
        None,
        description=(
            "Guidance when no partition table (single-volume image) — use "
            "fls -i ewf -f ntfs directly."
        ),
    )


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
            "Only used for formats with no derivable host (json, accesslog, "
            "non-recursive delimited). IGNORED for auto/memory/e01-disk/recursive-"
            "delimited, where the true host is derived from the registry ComputerName "
            "/ parser. Correct a wrong derived host with opensearch_fix_host_mapping."
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
    case_dir: str = _case_dir_field()


class IngestOut(BaseModel):
    status: Literal[
        "preview",
        "started",
        "containers_detected",
        "multi_started",
        "already_indexed",
        "failed",
        # feat/opensearch-workers: privileged ingest is dispatched (non-blocking)
        # to a dedicated sift-opensearch-worker@ via the durable job queue; the
        # gateway returns this immediately instead of running the pipeline inline.
        "queued",
    ] = Field(..., description="Ingest response status.")
    case_id: str | None = Field(None, description="Resolved active case id.")
    job_id: str | None = Field(
        None, description="Durable job id for a queued (worker-dispatched) ingest; poll running_commands_status(job_id)."
    )
    job_type: str | None = Field(None, description="Dispatched job type (ingest/enrich) when queued.")
    dispatched_to: str | None = Field(
        None, description="Worker lane a queued ingest was dispatched to."
    )
    next_step: str | None = Field(None, description="Operator guidance for a queued dispatch.")
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
    case_dir: str = _case_dir_field()


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
    authority: str | None = Field(
        None,
        description="Status authority plane ('postgres-durable-jobs' in DB-active mode).",
    )
    last_completed: dict[str, Any] | None = Field(
        None,
        description=(
            "OpenSearch-derived summary of the last finished ingest for the case "
            "(most-recent index, its creation time, index/doc totals). Lets you "
            "confirm a run landed without polling opensearch_count. Not the Postgres "
            "durable-job record."
        ),
    )
    job_id: str | None = Field(
        None, description="Echoed durable job_id when one was supplied for polling."
    )
    next_step: str | None = Field(None, description="Suggested next polling step, when applicable.")


class EnrichIntelIn(BaseModel):
    case_id: str = Field("", description="Case to enrich; default active.")
    dry_run: bool = Field(True, description="Extract and count IOCs without lookup.")
    force: bool = Field(False, description="Re-enrich already-enriched docs.")
    case_dir: str = _case_dir_field()


class EnrichIntelOut(BaseModel):
    status: Literal[
        "preview",
        "started",
        # feat/opensearch-workers: privileged enrich is dispatched (non-blocking)
        # to a dedicated sift-opensearch-worker@ via the durable job queue; the
        # gateway returns this immediately instead of running the pipeline inline.
        "queued",
    ] = Field(..., description="Enrichment response status.")
    # Optional (mirrors IngestOut): the gateway's worker-dispatch payload for a
    # queued enrich is {job_id,status,job_type,dispatched_to,next_step} and omits
    # case_id, so a required case_id would reject the legitimate queued response.
    case_id: str | None = Field(None, description="Resolved case id.")
    ips: int | None = Field(None, description="Unique IP indicators in preview.")
    hashes: int | None = Field(None, description="Unique hash indicators in preview.")
    domains: int | None = Field(None, description="Unique domain indicators in preview.")
    total_iocs: int | None = Field(None, description="Total unique IOCs in preview.")
    job_id: str | None = Field(
        None, description="Durable job id for a queued (worker-dispatched) enrich; poll running_commands_status(job_id)."
    )
    job_type: str | None = Field(None, description="Dispatched job type (enrich) when queued.")
    dispatched_to: str | None = Field(
        None, description="Worker lane a queued enrich was dispatched to."
    )
    next_step: str | None = Field(None, description="Operator guidance for a queued dispatch.")
    pid: int | None = Field(None, description="Background process id.")
    run_id: str | None = Field(None, description="Background run id.")
    log_file: str | None = Field(None, description="Background run log file.")
    note: str | None = Field(None, description="Polling note.")


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
    case_dir: str = _case_dir_field()


class FixHostMappingOut(BaseModel):
    status: Literal["complete"] = Field(..., description="Correction status.")
    raw: str = Field(..., description="Raw host.name value corrected.")
    new_canonical: str = Field(..., description="Canonical host.id assigned.")
    docs_updated: int | None = Field(None, description="Documents updated by reindex.")
    dict_path: str | None = Field(
        None,
        description=(
            "Legacy host dictionary path (legacy/non-DB-active mode only; "
            "omitted in DB-active mode where the dictionary is parser-compat)."
        ),
    )
    dict_saved: bool = Field(True, description="Whether the host dictionary was saved.")
    host_identity_authority: str | None = Field(
        None, description="Authority plane for host identity (postgres in DB-active mode)."
    )
    host_identity_decision_id: str | None = Field(
        None, description="DB host-identity correction receipt id, when recorded."
    )
    audit_id: str | None = Field(None, description="Audit event id for the correction.")
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


def _impl_server():
    """The implementation engine module (``opensearch_mcp.server``).

    This registry is the typed contract layer; ``opensearch_mcp.server`` holds the
    raw OpenSearch I/O. The run_* wrappers below call into it and shape the result
    into the typed *Out models.
    """
    from opensearch_mcp import server as impl

    return impl


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


def _impl_error(
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
        "full_results_note": "pagination",
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


def _impl_search_hit(hit: dict[str, Any]) -> SearchHit:
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
    # M-QUERYERR fix: intercept query-parse errors (OpenSearch 400 /
    # query_shard_exception / parsing_exception) BEFORE they reach the generic
    # except-Exception wrapper at registry.py:2518, which collapses them to an
    # opaque "internal / check backend logs" message.
    #
    # _os_call (server.py) already catches RequestError (400-class) and
    # re-raises it as ValueError("Query error: <reason>") — that specific
    # prefix is the signal we detect here. Genuine 5xx errors (RuntimeError
    # from ConnectionTimeout/ConnectionError/AuthorizationException) propagate
    # unchanged to the generic wrapper, which remains correct for backend errors.
    try:
        raw = _impl_server().opensearch_search(**params.model_dump())
    except ValueError as exc:  # noqa: BLE001 — narrow: only query-parse ValueErrors
        msg = str(exc)
        if msg.startswith("Query error:"):
            # Strip the "Query error: " prefix — the reason is already user-readable.
            reason = msg[len("Query error:"):].strip()
            return _tool_error_result(
                ErrorCode.invalid_input,
                f"query_string parse error: {reason}",
                (
                    "Fix the query syntax and retry. Tips: quote values with special "
                    "characters (source.ip:\"::1\"), use wildcards for partial matches "
                    "(*ServiceUpdater*), avoid unmatched parentheses or unescaped "
                    "reserved chars (+ - = && || > < ! ( ) { } [ ] ^ \" ~ * ? : \\ /)."
                ),
                retryable=True,
            )
        raise  # not a query-parse error; let the generic wrapper handle it
    if "error" in raw:
        return _impl_error(raw)
    meta = _meta_from_raw(raw)
    advisories = _advisories_from_raw(raw)
    out = SearchOut(
        total=int(raw.get("total", 0)),
        total_capped=bool(raw.get("total_capped", False)),
        returned=int(raw.get("returned", 0)),
        offset=params.offset,
        compact=bool(raw.get("compact", params.compact)),
        results=[_impl_search_hit(hit) for hit in raw.get("results", [])],
        common_fields=dict(raw.get("common_fields") or {}),
        full_path=raw.get("full_path"),
        advisories=advisories,
    )
    return _success_tool_result(out, meta)


async def run_opensearch_count(params: CountIn) -> ToolResult:
    raw = _impl_server().opensearch_count(**params.model_dump())
    if "error" in raw:
        return _impl_error(raw)
    meta = _meta_from_raw(raw)
    return _success_tool_result(CountOut(count=int(raw.get("count", 0))), meta)


async def run_opensearch_aggregate(params: AggregateIn) -> ToolResult:
    raw = _impl_server().opensearch_aggregate(**params.model_dump())
    if "error" in raw:
        return _impl_error(raw)
    meta = _meta_from_raw(raw)
    out = AggregateOut(
        field=str(raw.get("field", params.field)),
        total_docs=int(raw.get("total_docs", 0)),
        buckets=[Bucket.model_validate(bucket) for bucket in raw.get("buckets", [])],
        truncated=bool(raw.get("truncated", False)),
        full_path=raw.get("full_path"),
    )
    return _success_tool_result(out, meta)


async def run_opensearch_get_event(params: GetEventIn) -> ToolResult:
    try:
        raw = _impl_server().opensearch_get_event(**params.model_dump())
    except Exception as exc:  # noqa: BLE001 - sanitized typed error for MCP clients
        message = f"{type(exc).__name__}: document lookup failed."
        code = ErrorCode.not_found if "not" in type(exc).__name__.lower() else ErrorCode.internal
        return _tool_error_result(
            code,
            message,
            "Confirm event_id and exact case-* index from opensearch_search, then retry.",
        )
    if "error" in raw:
        return _impl_error(raw)
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
    raw = _impl_server().opensearch_timeline(**params.model_dump())
    if "error" in raw:
        return _impl_error(raw)
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
    raw = _impl_server().opensearch_field_values(**params.model_dump())
    if "error" in raw:
        return _impl_error(raw)
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
        raw = _impl_server().opensearch_status()
    except Exception as exc:  # noqa: BLE001 - expose typed upstream failure
        return _tool_error_result(
            ErrorCode.upstream_unavailable,
            f"{type(exc).__name__}: OpenSearch status check failed.",
            "Check OpenSearch connectivity and credentials, then retry.",
            retryable=True,
        )
    if "error" in raw:
        return _impl_error(raw, default_code=ErrorCode.upstream_unavailable)
    meta = _meta_from_raw(raw)
    _hb = raw.get("hayabusa")
    out = StatusOut(
        cluster_status=str(raw.get("cluster_status", "unknown")),
        indices=[IndexInfo.model_validate(item) for item in raw.get("indices", [])],
        total_indices=int(raw.get("total_indices", 0)),
        hayabusa=HayabusaHealth.model_validate(_hb) if isinstance(_hb, dict) else None,
    )
    return _success_tool_result(out, meta)


async def opensearch_cluster_status_resource() -> str:
    return _json_from_tool_result(await run_opensearch_status(StatusIn()))


async def run_opensearch_shard_status(_params: ShardStatusIn) -> ToolResult:
    try:
        raw = _impl_server().opensearch_shard_status()
    except Exception as exc:  # noqa: BLE001 - expose typed upstream failure
        return _tool_error_result(
            ErrorCode.upstream_unavailable,
            f"{type(exc).__name__}: OpenSearch shard status check failed.",
            "Check OpenSearch connectivity and credentials, then retry.",
            retryable=True,
        )
    if raw.get("status") == "error" or "error" in raw:
        return _impl_error(raw, default_code=ErrorCode.upstream_unavailable)
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
    raw = _impl_server().opensearch_case_summary(**params.model_dump())
    if "error" in raw:
        default = (
            ErrorCode.no_active_case
            if "active case" in str(raw.get("error"))
            else ErrorCode.not_found
        )
        return _impl_error(raw, default_code=default)
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
    raw = _impl_server().opensearch_inspect_container(**params.model_dump())
    if "error" in raw:
        return _impl_error(raw, default_code=ErrorCode.not_found)
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
        partition_note=raw.get("partition_note"),
    )
    return _success_tool_result(out, meta)


async def run_opensearch_ingest(params: IngestIn) -> ToolResult:
    raw = _impl_server().opensearch_ingest(**params.model_dump(mode="json"))
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
        return _impl_error(raw, default_code=code)
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
    raw = _impl_server().opensearch_ingest_status(**params.model_dump())
    if "error" in raw:
        return _impl_error(raw, default_code=ErrorCode.no_active_case)
    meta = _meta_from_raw(raw)
    runs: list[IngestRun] = []
    for item in raw.get("ingests", []):
        # Collect any extra fields NOT explicitly mapped below into the overflow bag.
        # "details" is excluded here because it is already an explicit named field
        # on the item dict (server.py puts durable-job fields there directly) — we
        # wire it through to IngestRun.details below.  Excluding it prevents the
        # double-nesting bug where the agent would see ingests[].details.details.*
        _named_fields = {
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
            "details",  # explicit — wired directly below, not via overflow
        }
        overflow = {key: value for key, value in item.items() if key not in _named_fields}
        # Merge named details dict (from server.py) with any overflow keys so the
        # agent surface is a flat IngestRun.details dict with all extra fields.
        details: dict = {**(item.get("details") or {}), **overflow}
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
        IngestStatusOut(
            ingests=runs,
            message=raw.get("message"),
            authority=raw.get("authority"),
            last_completed=raw.get("last_completed"),
            job_id=raw.get("job_id"),
            next_step=raw.get("next_step"),
        ),
        meta,
    )


async def run_opensearch_enrich_intel(params: EnrichIntelIn) -> ToolResult:
    raw = _impl_server().opensearch_enrich_intel(**params.model_dump())
    if "error" in raw:
        message = str(raw.get("error"))
        if "No active case" in message:
            code = ErrorCode.no_active_case
        elif "Too many concurrent" in message:
            code = ErrorCode.capacity_refused
        else:
            code = ErrorCode.upstream_unavailable
        return _impl_error(raw, default_code=code)
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


async def run_opensearch_list_detections(params: ListDetectionsIn) -> ToolResult:
    try:
        raw = _impl_server().opensearch_list_detections(**params.model_dump())
    except Exception as exc:  # noqa: BLE001 - expose typed upstream failure
        return _tool_error_result(
            ErrorCode.upstream_unavailable,
            f"{type(exc).__name__}: detection lookup failed.",
            "Check OpenSearch Security Analytics availability, then retry.",
            retryable=True,
        )
    if "error" in raw and "Security Analytics plugin not available" not in str(raw.get("error")):
        return _impl_error(raw, default_code=ErrorCode.upstream_unavailable)
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


def triage_host_prompt(host: str, case_id: str = "") -> str:
    case_arg = f", case_id={case_id!r}" if case_id else ""
    return (
        f"Triage host {host!r}. Start with "
        f"opensearch_case_summary(case_id={case_id!r}) if case_id is known, then "
        f"opensearch_aggregate(field='event.code', query='host.name:{host}'{case_arg}), "
        f"opensearch_timeline(query='host.name:{host}'{case_arg}), and targeted "
        "opensearch_search calls for event.code:4624, event.code:4688, and "
        "event.code:7045 in the spike windows. Treat Shimcache/Amcache as file "
        "presence only, not execution."
    )


def build_timeline_prompt(query: str, case_id: str = "", interval: str = "1h") -> str:
    case_arg = f", case_id={case_id!r}" if case_id else ""
    return (
        f"Build an investigative timeline for query {query!r}. First call "
        f"opensearch_timeline(query={query!r}, interval={interval!r}{case_arg}). "
        "Identify spike windows, then call opensearch_search with time_from/time_to "
        "for each spike and summarize the event families, hosts, and users involved."
    )


def ioc_sweep_prompt(case_id: str = "") -> str:
    case_arg = f"case_id={case_id!r}, " if case_id else ""
    return (
        "Sweep this case for known-bad IOCs. Start with "
        f"opensearch_enrich_intel({case_arg}dry_run=True) to size the IOC corpus. "
        "If appropriate, run the enrichment asynchronously, poll "
        "opensearch_ingest_status, then search for "
        "threat_intel.verdict:MALICIOUS and review opensearch_list_detections."
    )


async def opensearch_index_catalog_resource() -> str:
    return _json_from_tool_result(await run_opensearch_status(StatusIn()))


def _flatten_mapping_props(props: dict[str, Any], prefix: str = "") -> list[dict[str, str]]:
    fields: list[dict[str, str]] = []
    for key, value in props.items():
        full = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict) and "properties" in value:
            fields.extend(_flatten_mapping_props(value["properties"], full))
        elif isinstance(value, dict):
            fields.append({"field": full, "type": str(value.get("type", "object"))})
        else:
            fields.append({"field": full, "type": "unknown"})
    return fields


async def opensearch_field_catalog_resource(artifact_type: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", artifact_type):
        return _json_text(
            {
                "artifact_type": artifact_type,
                "fields": [],
                "error": "artifact_type contains unsupported characters.",
            }
        )
    try:
        client = _impl_server()._get_os()
        indices = client.cat.indices(
            index=f"case-*-{artifact_type}-*",
            format="json",
            h="index",
        )
        first = next((item.get("index") for item in indices or [] if item.get("index")), None)
        if not first:
            return _json_text({"artifact_type": artifact_type, "fields": [], "total_fields": 0})
        mapping = client.indices.get_mapping(index=first)
        props = mapping.get(first, {}).get("mappings", {}).get("properties", {})
        fields = sorted(_flatten_mapping_props(props), key=lambda item: item["field"])[:500]
        return _json_text(
            {
                "artifact_type": artifact_type,
                "sample_index": first,
                "fields": fields,
                "total_fields": len(fields),
            }
        )
    except Exception as exc:  # noqa: BLE001 - resource returns JSON diagnostics
        return _json_text(
            {
                "artifact_type": artifact_type,
                "fields": [],
                "error": f"{type(exc).__name__}: field catalog unavailable.",
            }
        )


async def opensearch_detection_catalog_resource() -> str:
    try:
        client = _impl_server()._get_os()
        response = client.transport.perform_request(
            "GET",
            "/_plugins/_security_analytics/detectors/_search",
            params={"size": 1000},
        )
        detectors = response.get("detectors") or response.get("hits", {}).get("hits", [])
        by_type: dict[str, int] = {}
        for detector in detectors:
            source = detector.get("_source", detector) if isinstance(detector, dict) else {}
            dtype = str(source.get("detector_type") or source.get("detectorType") or "unknown")
            by_type[dtype] = by_type.get(dtype, 0) + 1
        return _json_text(
            {
                "total_detectors": len(detectors),
                "detectors_by_type": by_type,
                "hayabusa_note": "Hayabusa alerts use case-*-hayabusa-* when available.",
            }
        )
    except Exception as exc:  # noqa: BLE001 - Sigma is often unavailable on OpenSearch 3.5
        return _json_text(
            {
                "total_detectors": 0,
                "detectors_by_type": {},
                "hayabusa_note": (
                    "Security Analytics detector catalog unavailable; query "
                    "case-*-hayabusa-* for Hayabusa alerts when evtx ingest ran."
                ),
                "error": f"{type(exc).__name__}: detection catalog unavailable.",
            }
        )


async def run_opensearch_fix_host_mapping(params: FixHostMappingIn) -> ToolResult:
    raw = _impl_server().opensearch_host_fix(**params.model_dump())
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
            "host_identity_authority",
            "host_identity_decision_id",
            "audit_id",
        }
    }
    out = FixHostMappingOut(
        status="complete",
        raw=str(raw.get("raw", params.raw)),
        new_canonical=str(raw.get("new_canonical", params.new_canonical)),
        docs_updated=raw.get("docs_updated"),
        dict_path=raw.get("dict_path"),
        dict_saved=bool(raw.get("dict_saved", True)),
        host_identity_authority=raw.get("host_identity_authority"),
        host_identity_decision_id=raw.get("host_identity_decision_id"),
        audit_id=raw.get("audit_id"),
        details=details,
    )
    return _success_tool_result(out, meta)


# ---------------------------------------------------------------------------
# Advanced tool-use metadata (BATCH-OSX2)
#
# Anthropic "advanced tool use" guidance: enumerate capabilities, document the
# OUTPUT shape, give explicit when_to_use / avoid_when guidance, attach 1-5
# realistic usage examples (minimal/partial/full), and flag low-frequency tools
# as Tool-Search `defer_loading` candidates so the large OpenSearch tool set does
# not crowd the always-loaded context. This metadata is advertised via the MCP
# tool `meta` field; it is descriptive ONLY and changes no tool behavior. The
# values mirror the per-tool guidance in ``sift-backend.json`` so the standalone
# FastMCP surface and the gateway manifest stay in lockstep.
# ---------------------------------------------------------------------------


def _example(description: str, **arguments: Any) -> dict[str, Any]:
    """One realistic usage example for a tool's ``meta.usage_examples``."""
    return {"description": description, "arguments": arguments}


# Per-tool advanced metadata, keyed by canonical tool name. Merged into
# ``_TOOL_META`` below so pre-existing deprecation/resource markers are kept.
_ADVANCED_META: dict[str, dict[str, Any]] = {
    "opensearch_case_summary": {
        "category": "search-analysis",
        "recommended_for_phase": "ANALYZE",
        "when_to_use": (
            "Call FIRST in every indexed session. Returns hosts, artifact families, "
            "per-family doc counts, time range, enrichment state, and "
            "coverage_state.gaps with the exact ingest/enrich command to fill each "
            "gap — the map you plan the whole investigation from."
        ),
        "avoid_when": (
            "Skip only when you already hold a current summary this session; for a "
            "single artifact's frequency use opensearch_aggregate instead."
        ),
        "output_shape": (
            "CaseSummaryOut: case_id, hosts[], artifacts{family: {docs, hosts[], "
            "indices[]}}, total_docs, time_range{earliest, latest}, enrichment{...}, "
            "coverage_state{disk_artifacts, memory, enrichment, gaps[]}, "
            "investigation_hints[], warnings[]. Set include_fields=True only when you "
            "need per-artifact field/type maps to decide '.keyword' suffixes (large)."
        ),
        "response_shaping": (
            "include_fields defaults False to keep the summary compact; the field map "
            "is the bulk of the payload — request it only when picking aggregation "
            "fields."
        ),
        "usage_examples": [
            _example("Coverage map for the active case", ),
            _example("Coverage map for a named case", case_id="rocba-drive-20260526-1417"),
            _example(
                "Include field/type maps to plan aggregations",
                case_id="rocba-drive-20260526-1417",
                include_fields=True,
            ),
        ],
        "defer_loading": False,
        "defer_loading_rationale": (
            "High-frequency entry point; keep always-loaded so the agent can orient at "
            "session start without a Tool-Search round trip."
        ),
    },
    "opensearch_search": {
        "category": "search-analysis",
        "recommended_for_phase": "ANALYZE",
        "when_to_use": (
            "Targeted lookups by indicator, user, IP, hash, process, or field value "
            "across already-indexed case evidence. Supports query_string syntax, "
            "time_from/time_to bounds, sort, and offset pagination."
        ),
        "avoid_when": (
            "Avoid for frequency counts (use opensearch_aggregate), activity spikes "
            "(use opensearch_timeline), exact totals (use opensearch_count), or one "
            "full document (use opensearch_get_event). Avoid before evidence is "
            "ingested."
        ),
        "output_shape": (
            "SearchOut: total, total_capped (true ⇒ total is a gte lower bound — call "
            "opensearch_count for exact), returned, offset, compact, results[] of "
            "SearchHit{id, index, fields, truncated[]}, advisories[]."
        ),
        "response_shaping": (
            "compact=True (default) drops bloat fields and truncates values to 500 "
            "chars for context efficiency; raise limit/offset to page rather than "
            "widening the query. Use opensearch_get_event to expand a single hit."
        ),
        "usage_examples": [
            _example(
                "Minimal: find a process by name",
                query="process.name:*powershell*"
            ),
            _example(
                "Scoped + time-bounded",
                query="event.code:4688 AND process.name:*powershell*",
                case_id="rocba-drive-20260526-1417",
                time_from="2026-05-26T00:00:00Z",
                time_to="2026-05-26T23:59:59Z"
            ),
            _example(
                "Full document view, second page, oldest-first",
                query="source.ip:\"::1\"",
                compact=False,
                sort="@timestamp:asc",
                limit=100,
                offset=100,
            ),
        ],
        "defer_loading": False,
        "defer_loading_rationale": (
            "Core analysis verb used in nearly every session; keep always-loaded."
        ),
    },
    "opensearch_aggregate": {
        "category": "search-analysis",
        "recommended_for_phase": "ANALYZE",
        "when_to_use": (
            "Top-N frequency analysis: group by a field (event codes, users, hosts, "
            "process names, IPs) with an optional query_string pre-filter."
        ),
        "avoid_when": (
            "Avoid when you want the individual documents (use opensearch_search) or a "
            "simple distinct value list without ranking (use opensearch_field_values)."
        ),
        "output_shape": (
            "AggregateOut: field, total_docs (matched before bucketing), buckets[] of "
            "{key, count}, truncated (true ⇒ more buckets than limit exist), full_path "
            "(set when a large/byte-heavy bucket set was autosaved to "
            "agent/aggregations/ and only the top-N are inline)."
        ),
        "response_shaping": (
            "Returns only the requested buckets, never raw docs — the canonical "
            "summary-over-bytes shape. Accepted args are field/query/index/case_id/limit "
            "only; there is no agg_type or size. CSV/registry text fields need "
            "'.keyword'; evtx fields like event.code are already keyword."
        ),
        "usage_examples": [
            _example("Top event codes in the active case", field="event.code"),
            _example(
                "Top file paths (text field needs .keyword), filtered",
                field="Path.keyword",
                query="host.name:wksn01",
                limit=20,
            ),
        ],
        "defer_loading": False,
        "defer_loading_rationale": (
            "Frequent pivot tool; keep always-loaded alongside search/timeline."
        ),
    },
    "opensearch_timeline": {
        "category": "search-analysis",
        "recommended_for_phase": "ANALYZE",
        "when_to_use": (
            "Find activity bursts: a date histogram of event counts over time. Locate "
            "spike windows, then scope opensearch_search with time_from/time_to."
        ),
        "avoid_when": (
            "Avoid for value distributions (use opensearch_aggregate) or for the events "
            "themselves (use opensearch_search)."
        ),
        "output_shape": (
            "TimelineOut: total_docs, interval, buckets[] of {time (ISO-8601), count} "
            "(sparse — empty buckets omitted), advisories[]. Buckets are warned at the "
            "configured ceiling and never silently truncated."
        ),
        "response_shaping": (
            "Returns bucket counts only. Narrow with time_from/time_to or widen the "
            "interval (Ns/Nm/Nh/Nd) when an advisory flags a very large histogram."
        ),
        "usage_examples": [
            _example("Hourly histogram of process creations", query="event.code:4688"),
            _example(
                "15-minute resolution over a known window",
                query="host.name:wksn01",
                interval="15m",
                time_from="2026-05-26T08:00:00Z",
                time_to="2026-05-26T18:00:00Z"
            ),
        ],
        "defer_loading": False,
        "defer_loading_rationale": (
            "Frequent triage tool; keep always-loaded."
        ),
    },
    "opensearch_count": {
        "category": "search-analysis",
        "recommended_for_phase": "ANALYZE",
        "when_to_use": (
            "Get an EXACT match count with no documents — verify index population or "
            "gauge magnitude before a larger opensearch_search."
        ),
        "avoid_when": (
            "Avoid when you need per-value counts (use opensearch_aggregate) or the "
            "documents themselves (use opensearch_search)."
        ),
        "output_shape": "CountOut: count (exact document count for the query in scope).",
        "response_shaping": (
            "Cheapest possible probe — one integer, no docs. Use to decide whether a "
            "full search is worth paging."
        ),
        "usage_examples": [
            _example("Count all docs in scope", ),
            _example("Count successful logons", query="event.code:4624"),
        ],
        "defer_loading": True,
        "defer_loading_rationale": (
            "Low-frequency helper; opensearch_search already reports total. Tool-Search "
            "`defer_loading` candidate to trim the always-loaded set."
        ),
    },
    "opensearch_field_values": {
        "category": "search-analysis",
        "recommended_for_phase": "ANALYZE",
        "when_to_use": (
            "Enumerate the distinct values of a field (with counts) before writing a "
            "narrower query — e.g. discover the usernames or process names present."
        ),
        "avoid_when": (
            "Use opensearch_aggregate instead when ranking/top-N matters; that path is "
            "the same terms aggregation framed for frequency."
        ),
        "output_shape": (
            "FieldValuesOut: field, values[] of {value, count}, truncated (true ⇒ more "
            "distinct values exist than returned)."
        ),
        "response_shaping": (
            "Returns the value inventory only. CSV/text fields need '.keyword'; raise "
            "limit (hard cap 500) to widen the inventory."
        ),
        "usage_examples": [
            _example(
                "Distinct event-log providers present",
                field="winlog.provider_name"
            ),
            _example(
                "Distinct users, filtered to a host",
                field="user.name.keyword",
                query="host.name:wksn01",
                limit=100,
            ),
        ],
        "defer_loading": True,
        "defer_loading_rationale": (
            "Overlaps opensearch_aggregate; lower-frequency discovery helper and a "
            "Tool-Search `defer_loading` candidate."
        ),
    },
    "opensearch_get_event": {
        "category": "search-analysis",
        "recommended_for_phase": "ANALYZE",
        "when_to_use": (
            "Fetch ONE complete document by _id with every field and no truncation — "
            "use after opensearch_search when a compact hit needs full inspection."
        ),
        "avoid_when": (
            "Avoid for many documents (page opensearch_search instead) — this is a "
            "single-doc lookup."
        ),
        "output_shape": (
            "GetEventOut: id, index, fields (full, untruncated), truncated[] (empty), "
            "note. The index MUST be the exact case-* name from the hit, not a pattern."
        ),
        "response_shaping": (
            "The deliberate counterpart to compact search: pay the full-document cost "
            "for exactly one record, identified from a prior search hit."
        ),
        "usage_examples": [
            _example(
                "Expand a specific hit",
                event_id="abc123",
                index="case-rocba-drive-20260526-1417-evtx-srl-forge"
            ),
        ],
        "defer_loading": True,
        "defer_loading_rationale": (
            "Used only to expand a known search hit; Tool-Search `defer_loading` "
            "candidate."
        ),
    },
    "opensearch_inspect_container": {
        "category": "evidence-survey",
        "recommended_for_phase": "SURVEY",
        "when_to_use": (
            "Survey a forensic container (E01/raw/zip) WITHOUT mounting it: integrity, "
            "size, partitions, acquisition metadata. Run during evidence survey before "
            "deciding what to ingest."
        ),
        "avoid_when": (
            "Avoid after ingest planning is done; follow this with "
            "opensearch_ingest(dry_run=True) for the full plan."
        ),
        "output_shape": (
            "InspectContainerOut: path, resolved_path, container_type "
            "(e01|raw|file|unknown), tool_available, size_bytes, size_human, hashes{}, "
            "partitions[], acquiry_info{}, raw_info (truncated), partition_note "
            "(guidance when no partition table — use fls -i ewf -f ntfs directly)."
        ),
        "response_shaping": (
            "raw_info is truncated fdisk/img_stat text — a preview, not the full tool "
            "dump. Read-only; never modifies evidence."
        ),
        "usage_examples": [
            _example(
                "Preview an E01 before ingest",
                path="evidence/rocba-cdrive.e01"
            ),
        ],
        "defer_loading": True,
        "defer_loading_rationale": (
            "SURVEY-phase tool used once per evidence item; Tool-Search "
            "`defer_loading` candidate."
        ),
    },
    "opensearch_ingest": {
        "category": "ingest",
        "recommended_for_phase": "INGEST",
        "when_to_use": (
            "Discover and ingest forensic artifacts into OpenSearch after examiner "
            "approval. dry_run=True (default) previews the plan; set dry_run=False to "
            "write. Supports container/artifact-dir auto-detect, format override, "
            "include/exclude artifact filters, memory tiers/plugins, and VSS. "
            "Host is auto-derived from the evidence (registry ComputerName for disk/"
            "archive images, vol3 for memory); correct a wrong mapping with "
            "opensearch_fix_host_mapping after ingest."
        ),
        "avoid_when": (
            "Do NOT set dry_run=False until the target evidence and plan are clear. "
            "Use force=True only for an intentional re-ingest when the case already "
            "has docs. Do NOT pass hostname — host is auto-derived; use "
            "opensearch_fix_host_mapping to correct a wrong mapping after ingest."
        ),
        "output_shape": (
            "IngestOut: status (preview|started|containers_detected|multi_started|"
            "already_indexed|failed|queued), case_id, job_id, job_type, dispatched_to, "
            "next_step, plan{}, container{}, already_indexed{}, suggested_hostname, "
            "warning, pid, run_id, log_file, note, details{}. Disk/E01 ingest returns "
            "status=queued + job_id (non-blocking, dispatched to a sift-opensearch-worker@); "
            "poll running_commands_status(job_id) for realtime worker_label/current_step."
        ),
        "response_shaping": (
            "Returns a plan/run reference (run_id, log_file) rather than streaming "
            "ingest output — poll opensearch_ingest_status for progress. The "
            "'password' arg is a SECRET, redacted from audit/logs/results."
        ),
        "usage_examples": [
            _example(
                "Preview an auto-detected container (default dry run)",
                path="evidence/rocba-cdrive.e01",
                format="auto"
            ),
            _example(
                "Ingest a specific delimited artifact set (host derived from evidence)",
                path="evidence/triage/wksn01",
                format="delimited",
                include=["amcache", "shimcache"],
                dry_run=False,
            ),
            _example(
                "Deep memory analysis, write (host auto-derived via vol3)",
                path="evidence/memdump.raw",
                format="memory",
                tier=3,
                dry_run=False,
            ),
        ],
        "defer_loading": False,
        "defer_loading_rationale": (
            "Central INGEST-phase verb; keep always-loaded."
        ),
    },
    "opensearch_ingest_status": {
        "category": "ingest",
        "recommended_for_phase": "INGEST",
        "when_to_use": (
            "Poll running or recent ingest AND enrichment runs (~every 30s while "
            "active) and present the per-host artifact checklist. Also the status "
            "channel for async enrichment (poll with artifact_name 'intel'/'triage')."
        ),
        "avoid_when": (
            "Operational status only — inspect indexed records (opensearch_search) for "
            "evidence, not this."
        ),
        "output_shape": (
            "IngestStatusOut: ingests[] of IngestRun{case_id, status, pid, elapsed, "
            "total_indexed, bulk_failed, hosts_complete/total, "
            "artifacts_complete/total, log_file, checklist[], message, halt_reason, "
            "errors[], next_steps[], warnings[], details{}}, message, authority, "
            "last_completed (OpenSearch-derived last-finished-run summary in DB-active "
            "mode). case_id='*' shows all cases; default is the active case."
        ),
        "response_shaping": (
            "Returns a structured progress summary plus a log_file reference, not the "
            "raw run log. In DB-active mode ingests[] is empty (authority is "
            "postgres-durable-jobs); use last_completed to confirm a run landed."
        ),
        "usage_examples": [
            _example("Poll the active case's runs", ),
            _example("Show runs across all cases", case_id="*"),
        ],
        "defer_loading": True,
        "defer_loading_rationale": (
            "Used only while an ingest/enrich run is in flight; Tool-Search "
            "`defer_loading` candidate."
        ),
    },
    "opensearch_enrich_intel": {
        "category": "enrichment",
        "recommended_for_phase": "CORRELATE",
        "when_to_use": (
            "Extract unique IOCs from indexed docs and, with dry_run=False, look them "
            "up in OpenCTI and stamp matching docs with threat_intel fields. Use after "
            "indexed indicators exist and CTI context would help prioritize pivots. "
            "Requires enrichment:intel scope."
        ),
        "avoid_when": (
            "Avoid when OpenCTI is unavailable or indicators are speculative. Use "
            "dry_run=True first to size the IOC corpus."
        ),
        "output_shape": (
            "EnrichIntelOut: status (preview|started|queued), case_id, ips, hashes, domains, "
            "total_iocs (preview counts), job_id, job_type, dispatched_to, next_step, "
            "pid, run_id, log_file, note. "
            "Disk/E01 enrich returns status=queued + job_id (non-blocking, dispatched to "
            "sift-opensearch-worker@); poll running_commands_status(job_id) for realtime "
            "worker_label/current_step. ASYNC on write — returns a run reference; "
            "poll opensearch_ingest_status (artifact_name=='intel')."
        ),
        "response_shaping": (
            "Returns counts + a run reference, never IOC dumps or OpenCTI/OpenSearch "
            "credentials. Cannot approve findings, alter evidence, or decide reports."
        ),
        "usage_examples": [
            _example("Size the IOC corpus without lookup", dry_run=True),
            _example(
                "Launch async enrichment for a case",
                case_id="rocba-drive-20260526-1417",
                dry_run=False,
            ),
        ],
        "defer_loading": True,
        "defer_loading_rationale": (
            "CORRELATE-phase, scope-gated, add-on-dependent (OpenCTI); Tool-Search "
            "`defer_loading` candidate."
        ),
    },
    "opensearch_list_detections": {
        "category": "search-analysis",
        "recommended_for_phase": "ANALYZE",
        "when_to_use": (
            "List Security Analytics (Sigma) detection findings for triage pivots, "
            "filtered by severity/detector_type; falls back to a Hayabusa query "
            "suggestion when the Sigma plugin is unavailable or empty."
        ),
        "avoid_when": (
            "Detection hits are leads, not conclusions — validate against source events "
            "and surrounding context before recording a finding."
        ),
        "output_shape": (
            "ListDetectionsOut: findings[] of Detection{id, timestamp, index, rules[] "
            "of {name, tags[]}, matched_docs}, total, returned, offset, suggestion "
            "(Hayabusa fallback when present)."
        ),
        "response_shaping": (
            "Paginate with limit/offset; the per-finding payload references matched "
            "docs by count, not by embedding them."
        ),
        "usage_examples": [
            _example("All detections, first page", ),
            _example("High-severity detections only", severity="high"),
        ],
        "defer_loading": True,
        "defer_loading_rationale": (
            "Depends on the optional Security Analytics plugin; lower-frequency. "
            "Tool-Search `defer_loading` candidate."
        ),
    },
    "opensearch_fix_host_mapping": {
        "category": "admin",
        "recommended_for_phase": "INGEST",
        "when_to_use": (
            "Correct a wrong host.id mapping in the active case: updates the host "
            "dictionary and reindexes docs where host.name equals raw. host.name is "
            "never changed. Use only when indexed host identity is known to be wrong."
        ),
        "avoid_when": (
            "Avoid before confirming the canonical host mapping with the examiner or "
            "evidence. In DB-active mode WITHOUT a receipt recorder the correction is "
            "DENIED (fail closed)."
        ),
        "output_shape": (
            "FixHostMappingOut: status ('complete'), raw, new_canonical, docs_updated, "
            "host_identity_authority, host_identity_decision_id (DB receipt), audit_id, "
            "dict_path/dict_saved (legacy non-DB mode only), details{}. Mutating; "
            "returns no local filesystem paths in DB-active mode."
        ),
        "response_shaping": (
            "Returns the correction receipt (decision/audit ids, docs_updated), not the "
            "reindexed documents."
        ),
        "usage_examples": [
            _example(
                "Re-map a mis-attributed host across the case",
                raw="wksn01",
                new_canonical="WKSN01.corp.local"
            ),
        ],
        "defer_loading": True,
        "defer_loading_rationale": (
            "Rare, sensitive admin correction; Tool-Search `defer_loading` candidate."
        ),
    },
    "opensearch_status": {
        "category": "ingest",
        "recommended_for_phase": "INGEST",
        "when_to_use": (
            "Backend health/readiness check: cluster reachability, per-case-index "
            "document counts, and Hayabusa detection-engine health (preflight before "
            "evtx ingest — confirms Sigma detection will run). Confirms which cases "
            "have data."
        ),
        "avoid_when": (
            "DEPRECATED tool form — prefer the resource opensearch://cluster/status. "
            "For one case's artifact/coverage breakdown use opensearch_case_summary."
        ),
        "output_shape": (
            "StatusOut: cluster_status (single-node yellow may be annotated normal), "
            "indices[] of {index, docs, size, status}, total_indices, "
            "hayabusa{binary, rules_dir, rules_count} (binary=null ⇒ engine not "
            "installed; evtx ingest skips Sigma detection). Health/status only — not "
            "case evidence."
        ),
        "response_shaping": (
            "Compact cluster + index roll-up; also exposed as a read-only resource to "
            "keep it out of the tool budget."
        ),
        "usage_examples": [
            _example("Cluster + per-case index health", ),
        ],
        "defer_loading": True,
        "defer_loading_rationale": (
            "Deprecated tool form mirrored by a resource; Tool-Search `defer_loading` "
            "candidate pending removal at/after D27b."
        ),
    },
    "opensearch_shard_status": {
        "category": "admin",
        "recommended_for_phase": "INGEST",
        "when_to_use": (
            "Operational readiness before a large ingest (a full disk image can add "
            "many shards) or when indexing fails: shard usage and capacity headroom."
        ),
        "avoid_when": (
            "DEPRECATED tool form — prefer the resource opensearch://cluster/shards. "
            "Administrative signal, not investigation evidence."
        ),
        "output_shape": (
            "ShardStatusOut: current_shards, max_shards_per_node, data_nodes, "
            "max_total, headroom_pct, status (ok>=10% | warning>=2% | critical<2%), "
            "top_indices_by_shard_count[]."
        ),
        "response_shaping": (
            "Capacity roll-up with only the top shard-heavy indices; also exposed as a "
            "read-only resource."
        ),
        "usage_examples": [
            _example("Check shard headroom before a large image ingest", ),
        ],
        "defer_loading": True,
        "defer_loading_rationale": (
            "Deprecated, operations-only; mirrored by a resource. Tool-Search "
            "`defer_loading` candidate pending removal at/after D27b."
        ),
    },
}


for _name, _adv in _ADVANCED_META.items():
    _TOOL_META[_name] = {**_adv, **_TOOL_META.get(_name, {})}


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
            "Rule-based detection on this deployment is Hayabusa-on-ingest "
            "(Sigma/Security-Analytics is disabled on OpenSearch 3.5); when no "
            "Hayabusa alerts exist yet, the fallback is manual EVTX hunting "
            "(e.g. EventID:4625/4624/7045) via opensearch_search — the response "
            "message spells this out rather than dead-ending. "
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

PROMPT_REGISTRY.extend(
    [
        PromptDef(
            name="triage_host",
            fn=triage_host_prompt,
            title="Triage Host",
            description="Compose a host-triage workflow from OpenSearch tools.",
        ),
        PromptDef(
            name="build_timeline",
            fn=build_timeline_prompt,
            title="Build Timeline",
            description="Compose a timeline-first workflow and guided searches for spike windows.",
        ),
        PromptDef(
            name="ioc_sweep",
            fn=ioc_sweep_prompt,
            title="IOC Sweep",
            description="Compose an IOC enrichment and malicious-indicator review workflow.",
        ),
    ]
)

RESOURCE_REGISTRY.extend(
    [
        ResourceDef(
            uri="opensearch://catalog/indices",
            fn=opensearch_index_catalog_resource,
            name="opensearch_index_catalog",
            title="Index Catalog",
            description="Read-only catalog of case-* indices and document counts.",
        ),
        ResourceDef(
            uri="opensearch://catalog/fields/{artifact_type}",
            fn=opensearch_field_catalog_resource,
            name="opensearch_field_catalog",
            title="Field Mapping Dictionary",
            description="Flattened field-to-type mapping for an artifact type.",
        ),
        ResourceDef(
            uri="opensearch://catalog/detections",
            fn=opensearch_detection_catalog_resource,
            name="opensearch_detection_catalog",
            title="Detection Rule Catalog",
            description="Installed Sigma detector counts, with Hayabusa fallback guidance.",
        ),
    ]
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
    **_TOOL_META.get("opensearch_status", {}),
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
    **_TOOL_META.get("opensearch_shard_status", {}),
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
    """Register tools, prompts, and resources."""
    _register_all(
        mcp, REGISTRY, PROMPT_REGISTRY, RESOURCE_REGISTRY,
        make_function_tool=_function_tool,
    )


def _output_schema(out_model: type[BaseModel]) -> dict[str, Any]:
    """Advertised output schema — delegates to ``sift_common.registry_helpers``."""
    return tool_output_schema(out_model)


def _function_tool(
    tool_def: ToolDef,
    name: str,
) -> FunctionTool:
    description = tool_def.description
    meta: dict[str, Any] | None = _TOOL_META.get(name)

    async def invoke(**kwargs: Any) -> ToolResult:
        try:
            params = tool_def.in_model.model_validate(kwargs)
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
        description=description,
        fn=invoke,
        return_type=ToolResult,
        parameters=tool_def.in_model.model_json_schema(),
        output_schema=_output_schema(tool_def.out_model),
        annotations=tool_def.annotations,
        meta=meta,
        run_in_thread=False,
    )


# _call_with_optional_context, _success_result, and _error_result are
# now provided by sift_common.registry_helpers as call_with_optional_context,
# success_result, and error_result respectively.
