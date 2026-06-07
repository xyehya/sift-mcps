# 16 — Backend Tool Contracts (per-tool D28 contracts for all 30 backend tools)

Status: **implemented & landed** in D27a (Run 20 `c0a040a` build; Run 21 `5ab3df5`
review/remediation/land — see `MIGRATION_STATE.md`). Originally **design detail** for
stage **D27a** (`15_backend_tooling_revamp.md`). This
document instantiates the **D28 tool-quality contract** (charter `00_migration_charter.md`)
for every one of the 30 backend tools individually, so the backend-revamp worktree can
implement without guessing. It is grounded in the current `server.py` of each backend
(I/O extracted from source, not memory). The charter wins on any conflict; doc 15 governs
the revamp method; this doc is the per-tool specification doc 15 §10 pointed to.

**Scope discipline:** this is a *planning* document. No runtime code, schemas, versions,
or manifests change in this run. Where a tool is renamed or reclassified, the change is
recorded as a *proposal* with an alias/flag — see §6 and the Forks list (§7). Nothing here
silently drops a tool or redesigns the D5 write/job semantics of the OpenSearch write tools.

---

## 0. How to read a contract block

Every block has the same seven parts (the D28 contract, made concrete):

1. **Name** — `current → proposed` (or *keep*); rename reason + alias if renamed.
2. **Nature + annotations** — read/write + full `ToolAnnotations` (`readOnlyHint`,
   `destructiveHint`, `idempotentHint`, `openWorldHint`, `title`).
3. **INPUT model** — a Pydantic `BaseModel`; every field has type, constraint/enum,
   default, and `Field(description=…)`. Replaces hand-written `inputSchema` dicts and
   type-hint-only inference.
4. **OUTPUT model** — a Pydantic `BaseModel` returned via
   `ToolResult(structured_content=…)`. No untyped blobs.
5. **RESULT SHAPING** — default projection, pagination/caps, size ceiling.
6. **DESCRIPTION** — task-oriented: what it does, when to use / not use, one example.
7. **ERROR MODEL** — the typed error cases (`code` + message + remediation).

FastMCP 3.0 primitives cited inline: **`ToolResult`** (`content` + `structured_content`
+ `meta`), **`ToolAnnotations`**, **`@mcp.prompt`**, **`@mcp.resource`** — all per
`14_fastmcp3_supabase_integration.md` §2.

---

## 1. Shared conventions (apply to all 30 tools)

These remove repetition from the per-tool blocks. A tool block only restates a convention
when it deviates.

### 1.1 The response envelope → `ToolResult.meta`

All three backends today hand-wrap every result with `audit_id` + `examiner`
(opencti/wintriage also add `caveats` + `interpretation_constraint`; opensearch adds
`audit_id` only). In the revamp these **leave the structured payload** and move to
`ToolResult.meta`, so `structured_content` is clean, typed domain data:

```python
class ResultMeta(BaseModel):
    audit_id: str | None = Field(None, description="Audit-log id for this call; None if the audit write failed.")
    examiner: str | None = Field(None, description="Resolved examiner identity recorded in audit.")
    caveats: list[str] = Field(default_factory=list, description="Interpretation caveats for this tool's output.")
    interpretation_constraint: str | None = Field(None, description="What this result may NOT be used to conclude.")
    audit_warning: str | None = Field(None, description="Set when the audit write failed — action not recorded.")
```

Returned as `ToolResult(structured_content=<OutModel>, meta=ResultMeta(...), content=<human text>)`.
Rationale: the gateway response-guard must still scan `structured_content` (doc 14 §6,
doc 15 §11) — keeping envelope noise out of it makes the guard's size-cap/redaction
cleaner. **Flag F-3** (§7) tracks the guard-vs-structured-content confirmation owed to D27b.

### 1.2 The typed error model

Every tool returns errors as a typed model, never a raw stack trace or ad-hoc dict.
A tool that hits an error returns `ToolResult(structured_content=ToolError(...), isError=True)`:

```python
class ErrorCode(str, Enum):
    invalid_input        = "invalid_input"        # schema/enum/range violation caught pre-dispatch
    not_found            = "not_found"            # entity/index/document/path absent
    upstream_unavailable = "upstream_unavailable" # OpenSearch / OpenCTI / DB down or unreachable
    upstream_degraded    = "upstream_degraded"    # reachable but partial (yellow cluster, missing optional DB/plugin)
    rate_limited         = "rate_limited"         # OpenCTI rate limiter tripped
    not_configured       = "not_configured"       # backend misconfigured (creds/paths)
    no_active_case       = "no_active_case"       # case-scoped tool with no resolvable active case
    capacity_refused     = "capacity_refused"     # write refused pre-flight (shard/circuit capacity)
    internal             = "internal"             # unexpected; message is sanitized

class ToolError(BaseModel):
    error: ErrorCode = Field(..., description="Machine-readable error category.")
    message: str = Field(..., description="Human-readable, secret-free explanation.")
    remediation: str = Field(..., description="Concrete next step the caller can take.")
    retryable: bool = Field(False, description="True if retrying the same call may succeed (e.g. transient upstream loss).")
    details: dict[str, Any] = Field(default_factory=dict, description="Optional structured context (e.g. supported_types, halt_reason).")
```

Maps the existing ad-hoc error dicts: opencti `{"error": "validation_error", ...}`,
wintriage `{"error": "unsupported_artifact_type", "supported_types": [...], "next_step": ...}`,
opensearch `{"error": ..., "next_step": ...}` / `_os_call`'s `RuntimeError`/`ValueError`.
Existing per-tool `next_step` text becomes `remediation`; `supported_*` lists become `details`.

### 1.3 Annotation defaults

| Backend | readOnlyHint | destructiveHint | idempotentHint | openWorldHint | rationale |
| --- | --- | --- | --- | --- | --- |
| opencti (all 8) | true | false | true | **true** | live OpenCTI platform; results vary over time (D20) |
| wintriage (all 6) | true | false | true | **false** | static local baseline DBs; same input → same output (D23) |
| opensearch read tools | true | false | true | **true** | live cluster; index contents change |
| opensearch write tools (`_ingest`, `_enrich_intel`, `_enrich_triage`, `_host_fix`) | **false** | see block | see block | true | D5 job/write surface — per-block |

`title` is set per tool (human-friendly). All blocks below assume these defaults and only
note deviations.

### 1.4 Exposure-agnostic authoring (§7 of doc 15)

Each tool is authored as: a **pure async function** `fn(params: InModel, ctx) -> OutModel`,
its **InModel/OutModel/annotations/description**, and a **registration-table entry**:

```python
class ToolDef(BaseModel, arbitrary_types_allowed=True):
    name: str
    fn: Callable
    in_model: type[BaseModel]
    out_model: type[BaseModel]
    annotations: ToolAnnotations
    title: str
    description: str
    deprecated_aliases: list[str] = []   # §6 change-map
REGISTRY: list[ToolDef] = [ ... ]
```

- opensearch's `REGISTRY` is the durable artifact reused verbatim by the in-process
  `LocalProvider` at the D19 core cutover (the standalone server shell is throwaway).
- opencti/wintriage keep a standalone FastMCP 3.0 server (fronted by `ProxyProvider`,
  D22) but use the same table for consistency.
- Existing rich manifest metadata (`when_to_use`, `avoid_when`, `output_notes`,
  `recommended_phase`, `category`) found in `sift-backend.json` folds into the
  `description` and into resource catalogs (§ per backend). The `mcp_backends` registry
  (D22) supersedes `sift-backend.json` for registration in a later D22/F-11 phase;
  D27b intentionally kept `gateway.yaml`/manifest-backed add-on registration.

### 1.5 Case scoping

`case_id` resolution stays behavior-compatible for this stage: opensearch read/write
tools resolve `case_id` arg → active case (`SIFT_CASE_DIR`). The migration to
Gateway-propagated active case (D32) and `case_scoped` flags (D22) is a *later* phase;
this revamp does **not** change where case context comes from. opencti/wintriage are
case-agnostic (`case_scoped=false`) but audited under the active case.

---

## 2. The tool-vs-resource reclassification — APPROVED (Run 19, Fork F-1)

**Status: APPROVED additively.** Apply the table below: the four strong candidates
become resources (tool kept as a deprecated alias with a removal horizon — backlog
**B-1**); the two query-shaped ones stay tools with an optional resource view. Tracked
in `REGISTER.md` (F-1).

Six current "tools" are read-only reference/status data with little or no query
parameterization — i.e. they are **MCP resources** in the FastMCP 3.0 model
(`@mcp.resource`, doc 14 §2.1), exposable to tool-only clients via `ResourcesAsTools`.
Modeling them as resources lets future context-bloat controls drop them from
the always-in-context tool catalog while keeping them reachable. D27b did not
adopt FastMCP `ToolSearch`; reintroducing it would require a new scoped
decision.

**Per the operator constraint, this is proposed ADDITIVELY and FLAGGED, not applied:**
each stays a callable tool (so existing skills/RAG don't break) **and** also gets a
resource view; the tool is marked a deprecated alias of the resource for one cutover
cycle. Removal of the tool form is a separate operator decision (Fork **F-1**, §7).

| Current tool | Resource candidate URI | Strength | Recommendation |
| --- | --- | --- | --- |
| `opensearch_status` | `opensearch://cluster/status` | strong (no args) | reclassify + keep tool alias |
| `opensearch_shard_status` | `opensearch://cluster/shards` | strong (no args) | reclassify + keep tool alias |
| `opensearch_list_detections` | `opensearch://case/{case_id}/detections` | medium (filter args) | **keep as tool**; ALSO expose unfiltered resource view |
| `opensearch_case_summary` | `opensearch://case/{case_id}/summary` | weak (heavy live aggregation + args) | **keep as tool**; optional resource template |
| `cti_get_health` | `cti://health` | strong (`health:true` in manifest) | reclassify + keep tool alias |
| `wintriage_server_status` | `wintriage://status` | strong (low args) | reclassify + keep tool alias |

The four strong/medium-strong candidates are also the **mandatory ≥1 resource per
backend** seeds (§ per backend). Each of the six keeps a full tool contract below
regardless, so the worktree can ship the tool form and add the resource form behind the
flag.

---

## 3. OpenSearch backend (16 tools) — `opensearch_` namespace

Framework today: in-SDK FastMCP 1.x decorators. Target: standalone FastMCP 3.0, authored
**exposure-agnostic** (§1.4) for the D19 in-process move. Shared input field (used by the
query tools):

```python
class CaseScopedQueryBase(BaseModel):
    index: str = Field("", description="Index pattern; every segment MUST start with 'case-'. Overrides case_id when set. Leave empty to derive from case_id/active case.")
    case_id: str = Field("", description="Case id. If empty, resolves to the active portal case (SIFT_CASE_DIR). Yields 'case-{id}-*'.")
    # validator: each comma-segment of `index` startswith 'case-' (mirrors _validate_index)
```

Shared output hit shape (search/get_event):

```python
class SearchHit(BaseModel):
    id: str = Field(..., description="Document _id.")
    index: str = Field(..., description="Concrete index the hit came from.")
    fields: dict[str, Any] = Field(..., description="Projected _source fields (bloat fields excluded, long values truncated unless full=True).")
    truncated: list[str] = Field(default_factory=list, description="Field names whose values were truncated to the size ceiling.")
```

Non-fatal advisory strings the current code injects into results (`hint`, `note`,
`field_hint`, `discipline_reminder`, `total_note`, investigation hints) become a typed,
optional `advisories: list[Advisory]` on the relevant OutModels (not free-floating keys),
where `Advisory = {kind: Literal["field_mapping","execution_evidence","pagination","empty_result"], text: str}`.

### 3.1 `opensearch_search` — *keep*

- **Nature/annotations:** read. `readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=true, title="Search Evidence"`.
- **INPUT:**
```python
class SearchIn(CaseScopedQueryBase):
    query: str = Field(..., min_length=1, description="OpenSearch query_string. Include file extensions ('svchost.exe' not 'svchost'); quote special chars (source.ip:\"::1\").")
    limit: int = Field(50, ge=1, le=200, description="Max hits to return. Hard cap 200.")
    offset: int = Field(0, ge=0, le=10000, description="Pagination offset; capped at OpenSearch max_result_window (10000).")
    sort: str = Field("@timestamp:desc", description="Sort as 'field:asc|desc'. Defaults to newest-first.")
    time_from: str = Field("", description="ISO-8601 lower bound on @timestamp (inclusive).")
    time_to: str = Field("", description="ISO-8601 upper bound on @timestamp (inclusive).")
    compact: bool = Field(True, description="True excludes bloat fields and truncates values to 500 chars. Set False for full docs (prefer opensearch_get_event for one doc).")
```
- **OUTPUT:**
```python
class SearchOut(BaseModel):
    total: int = Field(..., description="Total matching docs (see total_capped).")
    total_capped: bool = Field(False, description="True when total is a lower bound (relation gte); call opensearch_count for exact.")
    returned: int = Field(..., description="Number of hits in results.")
    offset: int = Field(0, description="Echoed pagination offset.")
    compact: bool = Field(..., description="Whether compact projection was applied.")
    results: list[SearchHit] = Field(..., description="Matching documents, projected.")
    advisories: list[Advisory] = Field(default_factory=list, description="Optional field-mapping/empty-result/pagination hints.")
```
- **RESULT SHAPING (mandatory):** default projection excludes `_SEARCH_EXCLUDE_FIELDS`
  (~25 bloat/duplicate/metadata fields, source of truth in current module) and truncates
  any value > **500 chars** (recorded in `truncated`). `limit` cap **200**; `offset` cap
  **10000**. `compact=False` lifts exclusion+truncation. Size ceiling = 200 hits ×
  500-char fields.
- **DESCRIPTION:** "Search indexed evidence with query_string syntax. **Use** for
  targeted lookups by indicator/user/IP/hash/field value. **Don't use** for frequency
  counts (use `opensearch_aggregate`) or activity spikes (use `opensearch_timeline`); for
  one full document use `opensearch_get_event`. Example:
  `opensearch_search(query='event.code:4688 AND process.name:*powershell*', case_id='rocba-drive-20260526-1417')`."
- **ERROR MODEL:** `invalid_input` (empty/blank index, non-`case-` segment, bad sort);
  `upstream_unavailable`/`upstream_degraded` (`_os_call` connection/auth loss → retryable);
  `invalid_input` (RequestError → malformed query, with reason in `details`).

### 3.2 `opensearch_count` — *keep*

- **Nature/annotations:** read; defaults.  `title="Count Documents"`.
- **INPUT:**
```python
class CountIn(CaseScopedQueryBase):
    query: str = Field("*", description="query_string filter; default '*' counts all docs in scope.")
```
- **OUTPUT:** `class CountOut(BaseModel): count: int = Field(..., description="Exact document count for the query in scope.")`
- **RESULT SHAPING:** scalar; no pagination. Size ceiling trivial.
- **DESCRIPTION:** "Return an exact match count, no documents. **Use** to verify index
  population or gauge magnitude before `opensearch_search`. **Don't use** when you need
  per-value counts (use `opensearch_aggregate`). Example:
  `opensearch_count(query='event.code:4624')`."
- **ERROR MODEL:** `invalid_input` (index), `upstream_unavailable`, `invalid_input`(RequestError).

### 3.3 `opensearch_aggregate` — *keep*

- **Nature/annotations:** read; defaults. `title="Aggregate Field (Top-N)"`.
- **INPUT:**
```python
class AggregateIn(CaseScopedQueryBase):
    field: str = Field(..., min_length=1, description="Field to group by. CSV/registry text fields need '.keyword' (e.g. 'Path.keyword'); evtx fields like event.code are already keyword.")
    query: str = Field("*", description="query_string filter applied before aggregation.")
    limit: int = Field(50, ge=1, le=500, description="Max buckets. Hard cap 500.")
```
- **OUTPUT:**
```python
class Bucket(BaseModel):
    key: Any = Field(..., description="Bucket value.")
    count: int = Field(..., description="Doc count for the value.")
class AggregateOut(BaseModel):
    field: str
    total_docs: int = Field(..., description="Docs matching query before bucketing.")
    buckets: list[Bucket]
    truncated: bool = Field(..., description="True when bucket count hit the limit (more values exist).")
```
- **RESULT SHAPING (mandatory):** `limit` cap **500** buckets; `truncated` flags capping.
  Ceiling = 500 buckets.
- **DESCRIPTION:** "Group-by/frequency analysis (top event codes, users, processes).
  **Use** for distributions. **Don't use** when you want the value set without ranking
  (use `opensearch_field_values`) or individual docs (use `opensearch_search`). Example:
  `opensearch_aggregate(field='event.code')`."
- **ERROR MODEL:** `invalid_input` (index/field/missing `.keyword`→ reason in `details`),
  `upstream_unavailable`.

### 3.4 `opensearch_get_event` — *keep* (rename considered, rejected)

- Considered `opensearch_get_document` (returns any doc, not only events) but the DFIR
  audience reads "event" as "indexed record"; rename churn not worth it. **Keep.**
- **Nature/annotations:** read; defaults. `title="Get Full Document"`.
- **INPUT:**
```python
class GetEventIn(BaseModel):
    event_id: str = Field(..., min_length=1, description="Document _id from a search hit.")
    index: str = Field(..., description="EXACT index name (not a pattern); must start with 'case-'. From the hit's _index.")
```
- **OUTPUT:** `class GetEventOut(SearchHit): note: str = Field("Full document — no truncation", ...)` (full, no exclusion/truncation).
- **RESULT SHAPING:** single doc, no projection/truncation. Ceiling = one document.
- **DESCRIPTION:** "Fetch one complete document by _id — every field, no truncation.
  **Use** after `opensearch_search` (compact) when a hit is worth full inspection.
  `index` must be exact, not a wildcard. Example:
  `opensearch_get_event(event_id='abc123', index='case-rocba-...-evtx-srl-forge')`."
- **ERROR MODEL:** `invalid_input` (pattern instead of exact index / bad prefix),
  `not_found` (no such _id/index), `upstream_unavailable`.

### 3.5 `opensearch_timeline` — *keep*

- **Nature/annotations:** read; defaults. `title="Event Timeline (Histogram)"`.
- **INPUT:**
```python
class TimelineIn(CaseScopedQueryBase):
    query: str = Field("*", description="query_string filter.")
    interval: str = Field("1h", pattern=r"^\d+[smhd]$", description="Bucket size: Ns/Nm/Nh/Nd (e.g. 30m, 1h, 1d).")
    time_field: str = Field("@timestamp", description="Date field to bucket on.")
    time_from: str = Field("", description="ISO-8601 lower bound.")
    time_to: str = Field("", description="ISO-8601 upper bound.")
```
- **OUTPUT:**
```python
class TimeBucket(BaseModel):
    time: str = Field(..., description="Bucket start (ISO-8601).")
    count: int
class TimelineOut(BaseModel):
    total_docs: int
    interval: str
    buckets: list[TimeBucket]
    advisories: list[Advisory] = Field(default_factory=list, description="e.g. 'narrow with time_from/time_to' on huge ranges.")
```
- **RESULT SHAPING (mandatory):** `interval` regex-validated (rejects free-form);
  `min_doc_count=1` (sparse). **Add a bucket ceiling** (e.g. 2000) with an advisory
  prompting `time_from/time_to` narrowing — current code is unbounded (Fork-adjacent;
  noted, behavior-compatible default = warn not truncate).
- **DESCRIPTION:** "Date-histogram of event counts — find activity bursts before drilling
  in. **Use** to locate spikes, then scope `opensearch_search` with `time_from/time_to`.
  Example: `opensearch_timeline(query='event.code:4688', interval='1h')`."
- **ERROR MODEL:** `invalid_input` (interval format → remediation 'use 1h/30m'; index),
  `upstream_unavailable`.

### 3.6 `opensearch_field_values` — *keep*

- **Nature/annotations:** read; defaults. `title="Field Value Discovery"`.
- **INPUT:**
```python
class FieldValuesIn(CaseScopedQueryBase):
    field: str = Field(..., min_length=1, description="Field to enumerate. CSV/text fields need '.keyword'.")
    query: str = Field("*", description="query_string filter to narrow the value set.")
    limit: int = Field(50, ge=1, le=500, description="Max distinct values. Hard cap 500.")
```
- **OUTPUT:**
```python
class FieldValue(BaseModel):
    value: Any
    count: int
class FieldValuesOut(BaseModel):
    field: str
    values: list[FieldValue]
    truncated: bool = Field(..., description="True when more distinct values exist than returned.")
```
  (Drop the current redundant `doc_count` duplicate of `count`.)
- **RESULT SHAPING (mandatory):** `limit` cap **500**; `truncated` flags capping.
- **DESCRIPTION:** "Enumerate distinct values of a field with counts — discover what
  exists before targeted queries (all usernames, all process names). **Use** for value
  discovery; prefer `opensearch_aggregate` when ranking matters. Example:
  `opensearch_field_values(field='winlog.provider_name')`."
- **ERROR MODEL:** as `opensearch_aggregate`.

### 3.7 `opensearch_status` — *keep* + **resource candidate** (`opensearch://cluster/status`, Fork F-1)

- **Nature/annotations:** read; defaults. `title="Cluster & Index Status"`.
- **INPUT:** `class StatusIn(BaseModel): pass` (no args).
- **OUTPUT:**
```python
class IndexInfo(BaseModel):
    index: str
    docs: int
    size: str = Field(..., description="Human store size (e.g. '1.2gb').")
    status: str
class StatusOut(BaseModel):
    cluster_status: str = Field(..., description="green/yellow/red; yellow on single-node is annotated normal.")
    indices: list[IndexInfo] = Field(..., description="All case-* indices, sorted by name.")
    total_indices: int
```
- **RESULT SHAPING:** lists only `case-*` indices (already filtered). For large clusters,
  add `total_indices` (present) + optional cap with advisory (additive).
- **DESCRIPTION:** "Cluster health + per-case-index doc counts. **Use** to confirm the
  cluster is reachable and see which cases have data; use `opensearch_case_summary` for a
  single case's artifact/coverage breakdown."
- **ERROR MODEL:** `upstream_unavailable` (retryable).
- **RECLASSIFICATION:** strong resource candidate; expose `opensearch://cluster/status`
  with the same `StatusOut`, refresh on read; keep the tool as a deprecated alias. **F-1.**

### 3.8 `opensearch_shard_status` — *keep* + **resource candidate** (`opensearch://cluster/shards`, Fork F-1)

- **Nature/annotations:** read; defaults. `title="Shard Capacity"`.
- **INPUT:** `class ShardStatusIn(BaseModel): pass`.
- **OUTPUT:**
```python
class TopIndexShards(BaseModel):
    index: str
    primary_shards: int
    replica_shards: int
    doc_count: int
    size: str | None
class ShardStatusOut(BaseModel):
    current_shards: int
    max_shards_per_node: int
    data_nodes: int
    max_total: int
    headroom_pct: float
    status: Literal["ok", "warning", "critical"] = Field(..., description="ok>=10%, warning>=2%, critical<2% headroom.")
    top_indices_by_shard_count: list[TopIndexShards]
```
- **RESULT SHAPING:** top-10 indices (already capped); excludes system `.`-indices.
- **DESCRIPTION:** "Shard usage + capacity headroom. **Use** before a large ingest (a
  full disk image can add 40+ shards) to confirm the cluster can accept new indices."
- **ERROR MODEL:** `upstream_unavailable`/`internal` (current returns
  `{"status":"error","error":...}` → map to `ToolError`).
- **RECLASSIFICATION:** strong resource candidate (`opensearch://cluster/shards`). **F-1.**

### 3.9 `opensearch_case_summary` — *keep* (resource template optional, Fork F-1)

- **Nature/annotations:** read; defaults. `title="Case Coverage Summary"`.
- **INPUT:**
```python
class CaseSummaryIn(BaseModel):
    case_id: str = Field("", description="Case id; empty resolves to active case.")
    include_fields: bool = Field(False, description="Include per-artifact field-type mappings (large output; needed to decide '.keyword' suffixes).")
```
- **OUTPUT:** typed version of the current dict:
```python
class ArtifactCoverage(BaseModel):
    docs: int
    hosts: list[str]
    indices: list[str]
class CoverageGap(BaseModel):
    coverage_gap: str
    when_to_run: str
    command: str = Field(..., description="Exact opensearch_ingest/enrich call to fill the gap; usable verbatim.")
    next_mcp_step: str
    warning: str | None = None
    output_path: str | None = None
class CoverageState(BaseModel):
    disk_artifacts: dict[str, Literal["indexed","not_run","not_available"]]
    memory: dict[str, Any]              # {tier_run, plugins_run[], plugins_not_run[]}
    enrichment: dict[str, Literal["done","not_run"]]
    gaps: list[CoverageGap]
    filesystem_meta_path: str | None
class CaseSummaryOut(BaseModel):
    case_id: str
    hosts: list[str]
    artifacts: dict[str, ArtifactCoverage]
    total_docs: int
    time_range: dict[str, str] = Field(default_factory=dict, description="{earliest, latest} ISO-8601.")
    enrichment: dict[str, Any] = Field(default_factory=dict, description="{triage:{checked,suspicious}, threat_intel:{checked,malicious}}.")
    coverage_state: CoverageState
    fields_per_type: dict[str, list[dict]] | None = None
    investigation_hints: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list, description="Non-fatal sub-query failures.")
```
- **RESULT SHAPING:** sub-indices already merged (`delim-amcache-*`→`delim-amcache`);
  hosts capped at 500 in agg; `fields_per_type` capped at 150 fields/type; only behind
  `include_fields`. Keep these caps.
- **DESCRIPTION:** "Complete coverage overview for a case — call this **first** every
  indexed session. Returns hosts, artifact types + doc counts, enrichment state, and
  `coverage_state.gaps` with exact ingest commands to fill them. Example:
  `opensearch_case_summary(case_id='rocba-drive-20260526-1417')`."
- **ERROR MODEL:** `no_active_case` (with portal remediation), `not_found` ('No indices
  for this case'), `upstream_unavailable`.
- **RECLASSIFICATION:** weak candidate (parameterized + heavy live aggregation).
  **Recommend keep as tool**; optionally also a resource *template*
  `opensearch://case/{case_id}/summary`. **F-1.**

### 3.10 `opensearch_inspect_container` — *keep*

- **Nature/annotations:** read (spawns read-only `ewfinfo`/`fdisk`/`img_stat`; no mount,
  no write). `readOnlyHint=true, destructiveHint=false, idempotentHint=true,
  openWorldHint=true` (touches the filesystem/subprocess). `title="Inspect Forensic Container"`.
- **INPUT:**
```python
class InspectContainerIn(BaseModel):
    path: str = Field(..., description="Container path under the active case; bare filenames resolve to SIFT_CASE_DIR/evidence/.")
```
- **OUTPUT:**
```python
class InspectContainerOut(BaseModel):
    path: str
    resolved_path: str
    container_type: Literal["e01","raw","file","unknown"]
    tool_available: bool = Field(..., description="False when no inspection tool found on the SIFT VM.")
    size_bytes: int | None = None
    size_human: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)
    partitions: list[dict] = Field(default_factory=list)
    acquiry_info: dict | None = Field(None, description="E01 acquisition metadata (ewfinfo).")
    raw_info: str | None = Field(None, description="Truncated fdisk/img_stat output for raw images.")
```
- **RESULT SHAPING:** `raw_info` already truncated to 2000 chars; keep.
- **DESCRIPTION:** "Survey a forensic container (E01/raw) **without mounting** —
  integrity, size, partitions. **Use** before `opensearch_ingest`; follow with
  `opensearch_ingest(dry_run=True)` for the full plan. If `tool_available=false`, fall
  back to `run_command(['ewfinfo', path])`. Example:
  `opensearch_inspect_container(path='evidence/rocba-cdrive.e01')`."
- **ERROR MODEL:** `not_found` (container path), `internal`.

### 3.11 `opensearch_ingest` — *keep* (WRITE / D5 job-enqueuing — behavior-compatible, NOT redesigned)

- **Nature/annotations:** **write**. `readOnlyHint=false, destructiveHint=false`
  (additive indexing; dedup prevents silent loss per D16), `idempotentHint=false`
  (re-ingest without `force` is guarded but a real execute changes state),
  `openWorldHint=true`. `title="Ingest Evidence into OpenSearch"`.
- **D5 note:** today the execute path spawns a background subprocess and returns
  `{status:"started", pid, run_id, log_file}`; the durable-job phase reshapes execution
  later (charter D5, doc 15 §11). **This contract types the existing I/O only — it does
  not move ingest onto jobs now.**
- **INPUT:** (all current args preserved, typed)
```python
class IngestFormat(str, Enum): auto="auto"; json="json"; delimited="delimited"; accesslog="accesslog"; memory="memory"
class IngestIn(BaseModel):
    path: str = Field(..., description="Evidence path under active case; bare names resolve to SIFT_CASE_DIR/evidence/.")
    format: IngestFormat = Field(IngestFormat.auto, description="auto=containers/artifact dirs; json/delimited/accesslog/memory for specific evidence.")
    hostname: str = Field("", description="Source hostname. Required for json/accesslog/memory and most delimited. 'auto' detects from filenames (delimited flat dir).")
    index_suffix: str = Field("", description="Optional index suffix (json/delimited/accesslog).")
    time_field: str = Field("", description="Optional timestamp field (json/delimited).")
    delimiter: str = Field("", description="Optional delimiter (delimited).")
    recursive: bool = Field(False, description="Delimited dirs: treat immediate subdirs as hostnames.")
    include: list[str] | None = Field(None, description="Only these artifact types (e.g. ['mft','usn']).")
    exclude: list[str] | None = Field(None, description="Skip these artifact types.")
    source_timezone: str = Field("", description="Evidence system local tz (e.g. 'Eastern Standard Time').")
    all_logs: bool = Field(False, description="Parse all evtx (default: forensic logs only).")
    reduced_ids: bool = Field(False, description="Filter to ~78 high-value Event IDs.")
    full: bool = Field(False, description="Include all tiers (MFT, USN, timeline).")
    tier: int = Field(1, ge=1, le=3, description="Memory analysis depth: 1 fast, 2 moderate, 3 deep.")
    plugins: list[str] | None = Field(None, description="Memory: run only these Volatility plugins.")
    dry_run: bool = Field(True, description="Preview without indexing (default). Set False to execute.")
    force: bool = Field(False, description="Allow re-ingest when the case already has docs. Required with dry_run=False on a populated case.")
    vss: bool = Field(False, description="Process Volume Shadow Copies.")
    password: str = Field("", description="Archive/container password. SECRET — must be redacted in audit/logs.")
    no_hayabusa: bool = Field(False, description="Skip Hayabusa Sigma scan during evtx ingest.")
```
- **OUTPUT:** a discriminated union by `status`:
```python
class IngestPreviewOut(BaseModel):
    status: Literal["preview"]
    case_id: str
    plan: dict = Field(..., description="Discovered hosts/artifacts/estimated docs (format-specific).")
    container: dict | None = None
    already_indexed: dict | None = Field(None, description="Set when the case already has docs; review before force.")
    suggested_hostname: str | None = None
    warning: str | None = None
class IngestStartedOut(BaseModel):
    status: Literal["started"]
    case_id: str
    pid: int
    run_id: str
    log_file: str
    note: str = Field("Async ingest; poll opensearch_ingest_status.", ...)
IngestOut = IngestPreviewOut | IngestStartedOut
```
- **RESULT SHAPING:** preview plans can be large — keep current per-format summarization;
  cap discovered-file enumerations with a count + advisory.
- **DESCRIPTION:** "Preview (`dry_run=True`, default) or run evidence ingest into
  OpenSearch. Case id comes from the active portal case — no `case_id` arg. **Use**
  `dry_run=True` first, review the plan, then `dry_run=False` (with `force=True` if the
  case already has docs). Long executes run async — poll `opensearch_ingest_status`.
  Example: `opensearch_ingest(path='evidence/rocba-cdrive.e01', format='auto', dry_run=True)`."
- **ERROR MODEL:** `no_active_case`; `invalid_input` (unsupported format → `details.supported_formats`;
  missing hostname for json/accesslog/memory → remediation); `not_found` (path);
  `capacity_refused` (shard/circuit pre-flight, `details.halt_reason`); `upstream_unavailable`.

### 3.12 `opensearch_ingest_status` — *keep*

- **Nature/annotations:** read; defaults. `title="Ingest/Enrichment Progress"`.
- **INPUT:**
```python
class IngestStatusIn(BaseModel):
    case_id: str = Field("", description="Filter to this case (default active). '*' for all cases.")
```
- **OUTPUT:**
```python
class ChecklistItem(BaseModel):
    host: str; artifact: str
    status: Literal["done","running","failed","pending"]
    detail: str
class IngestRun(BaseModel):
    case_id: str
    status: Literal["running","complete","failed","killed","unknown"]
    pid: int | None
    elapsed: str
    total_indexed: int
    bulk_failed: int
    hosts_complete: int; hosts_total: int
    artifacts_complete: int; artifacts_total: int
    log_file: str
    checklist: list[ChecklistItem]
    message: str
    halt_reason: str | None = None
    errors: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
class IngestStatusOut(BaseModel):
    ingests: list[IngestRun]
    message: str | None = None
```
- **RESULT SHAPING:** per-host/artifact checklist already structured; keep. Enrichment
  runs appear here with `artifact_name="intel"` (disambiguator).
- **DESCRIPTION:** "Status of running/recent ingest and enrichment runs. **Use** to poll
  progress (every ~30s while running) and present the per-host checklist. Default = active
  case; `case_id='*'` for all. Example: `opensearch_ingest_status()`."
- **ERROR MODEL:** `no_active_case`; (no upstream call — file-backed status).

### 3.13 `opensearch_enrich_intel` — *keep* (WRITE / D5 — behavior-compatible)

- **Nature/annotations:** **write** (stamps `threat_intel.*` via update_by_query).
  `readOnlyHint=false, destructiveHint=false, idempotentHint=false` (re-enrich changes
  docs; `force` re-runs), `openWorldHint=true` (queries OpenCTI). `title="Enrich: Threat Intel (OpenCTI)"`.
- **D5 note:** execute path is async (`status:"started"`, ~15–60 min); jobs phase
  reshapes later. Not redesigned here.
- **INPUT:**
```python
class EnrichIntelIn(BaseModel):
    case_id: str = Field("", description="Case to enrich (default active).")
    dry_run: bool = Field(True, description="Extract+count IOCs without lookup (default). False launches async enrichment.")
    force: bool = Field(False, description="Re-enrich already-enriched docs.")
```
- **OUTPUT:**
```python
class EnrichIntelPreviewOut(BaseModel):
    status: Literal["preview"]; case_id: str
    ips: int; hashes: int; domains: int; total_iocs: int
class EnrichStartedOut(BaseModel):
    status: Literal["started"]; case_id: str; pid: int; run_id: str; log_file: str
    note: str = Field("Async; poll opensearch_ingest_status (artifact 'intel').", ...)
EnrichIntelOut = EnrichIntelPreviewOut | EnrichStartedOut
```
- **RESULT SHAPING:** scalar counts (preview) or job handle (started).
- **DESCRIPTION:** "Extract unique IOCs from indexed docs, look them up in OpenCTI, and
  stamp matches with `threat_intel.verdict`/confidence. No LLM tokens used. **Use**
  `dry_run=True` to size the work, then `dry_run=False` (async). Requires OpenCTI
  reachable via the gateway. Example: `opensearch_enrich_intel(dry_run=True)`."
- **ERROR MODEL:** `no_active_case`; `upstream_unavailable` (OpenCTI/OpenSearch); `internal`.

### 3.14 `opensearch_enrich_triage` — *keep* (WRITE / D5 — behavior-compatible)

- **Nature/annotations:** **write** (stamps `triage.*`). `readOnlyHint=false,
  destructiveHint=false, idempotentHint=false, openWorldHint=true`. `title="Enrich: Windows Baseline Triage"`.
- **D5 note:** current path is **synchronous** (returns `status:"complete"` with counts);
  the jobs phase may make it async later. Keep sync behavior now.
- **INPUT:** `class EnrichTriageIn(BaseModel): case_id: str = Field("", description="Case to enrich (default active).")`
- **OUTPUT:**
```python
class EnrichTriageOut(BaseModel):
    status: Literal["complete"]
    documents_enriched: int
    details: dict = Field(..., description="Per-artifact enriched counts.")
```
- **RESULT SHAPING:** counts + per-artifact detail map.
- **DESCRIPTION:** "Check indexed filenames/services against the Windows baseline DB
  (known_good.db) via the gateway windows-triage backend and stamp `triage.verdict`
  (EXPECTED/SUSPICIOUS/UNKNOWN/EXPECTED_LOLBIN). **Use** after ingest, or to re-enrich
  after a baseline update. Requires the windows-triage backend running. Example:
  `opensearch_enrich_triage()`."
- **ERROR MODEL:** `no_active_case`; `upstream_unavailable` (triage backend/OpenSearch,
  passed through from `enrich_remote`); `internal`.

### 3.15 `opensearch_list_detections` — *keep* + **resource candidate** (Fork F-1)

- **Nature/annotations:** read; defaults. `title="Security Analytics Detections"`.
- **INPUT:**
```python
class ListDetectionsIn(BaseModel):
    severity: Literal["","critical","high","medium","low"] = Field("", description="Severity filter (tag-based); empty=all.")
    detector_type: str = Field("", description="Detector type filter (windows, linux, dns, ...); empty=all.")
    limit: int = Field(50, ge=1, le=500, description="Max findings. Hard cap 500.")
    offset: int = Field(0, ge=0, description="Pagination start.")
```
- **OUTPUT:**
```python
class DetectionRuleRef(BaseModel):
    name: str | None; tags: list[str]
class Detection(BaseModel):
    id: str | None; timestamp: str | None; index: str | None
    rules: list[DetectionRuleRef]; matched_docs: int
class ListDetectionsOut(BaseModel):
    findings: list[Detection]
    total: int
    returned: int
    offset: int
    suggestion: str | None = Field(None, description="Hayabusa fallback query when Sigma is unavailable/empty.")
```
- **RESULT SHAPING:** `limit` cap **500**; severity filter applied Python-side (API gap)
  by over-fetching ×3 then truncating to `limit`. Keep.
- **DESCRIPTION:** "List Security Analytics (Sigma) detection findings, or suggest a
  Hayabusa query when Sigma is unavailable/empty (common on OpenSearch 3.5). **Use** to
  triage rule-based detections. Example:
  `opensearch_list_detections(severity='high')`."
- **ERROR MODEL:** graceful — Sigma absence returns `findings:[]` + `suggestion`, NOT an
  error (keep). `upstream_unavailable` only on cluster loss.
- **RECLASSIFICATION:** medium candidate — keep as tool (has filters); also expose an
  unfiltered resource `opensearch://case/{case_id}/detections`. **F-1.**

### 3.16 `opensearch_host_fix` → **rename `opensearch_fix_host_mapping`** (alias `opensearch_host_fix`) (WRITE)

- **Rename reason:** `host_fix` is vague ("fix what?"); the tool corrects a wrong
  `host.id` alias mapping and reindexes. Proposed `opensearch_fix_host_mapping`; register
  `opensearch_host_fix` as a **deprecated alias** for one cutover cycle (§6).
- **Nature/annotations:** **write** (edits case host-dictionary on disk + `update_by_query`
  on `host.id`). `readOnlyHint=false, destructiveHint=false` (corrective metadata reindex,
  not data loss; `host.name` never touched), `idempotentHint=true` (re-call is a dict
  no-op + finishes remaining reindex), `openWorldHint=true`. `title="Fix Host ID Mapping"`.
- **INPUT:**
```python
class FixHostMappingIn(BaseModel):
    raw: str = Field(..., min_length=1, description="The raw host.name value whose host.id mapping is wrong.")
    new_canonical: str = Field(..., min_length=1, description="The correct canonical host.id to assign to docs with host.name == raw.")
```
- **OUTPUT:**
```python
class FixHostMappingOut(BaseModel):
    status: Literal["complete","rejected","error"]
    raw: str
    new_canonical: str
    docs_updated: int | None = None
    dict_path: str | None = None
    dict_saved: bool = True
```
- **RESULT SHAPING:** scalar counts; idempotent re-call safe (dict saved before reindex).
- **DESCRIPTION:** "Correct a wrong `host.id` mapping in the active case: edit the case
  host-dictionary (atomic save) then reindex `host.id` for docs with `host.name == raw`
  (`host.name` is never changed). **Use** when a prior ingest auto-applied a wrong
  canonical (e.g. merged `wksn01` into `wkstn01`). On 5M+ doc hosts the reindex may exceed
  the 300s gateway timeout — re-call is idempotent and finishes server-side. Example:
  `opensearch_fix_host_mapping(raw='wksn01', new_canonical='wksn01')`."
- **ERROR MODEL:** `invalid_input` (`InvalidHostnameValue` → status 'rejected',
  `dict_saved=false`); `internal` (status 'error'); `upstream_unavailable`.

### 3.17 OpenSearch prompts (≥1 required — seeds from doc 15 §10)

`@mcp.prompt` (doc 14 §2.1). Specify **three**:

- **`triage_host`** — args: `host` (str), `case_id` (str=""). Composes:
  `opensearch_case_summary` → `opensearch_aggregate(field='event.code', query='host.name:{host}')`
  → `opensearch_timeline(query='host.name:{host}')` → targeted `opensearch_search` for
  4624/4688/7045. Produces a "triage this host" investigation message.
- **`build_timeline`** — args: `query` (str), `case_id` (str=""), `interval` (str="1h").
  Composes `opensearch_timeline` then guided `opensearch_search` per spike window.
- **`ioc_sweep`** — args: `case_id` (str=""). Composes `opensearch_enrich_intel(dry_run=True)`
  preview → `opensearch_search` for stamped `threat_intel.verdict:MALICIOUS` →
  `opensearch_list_detections`. A "sweep this case for known-bad IOCs" template.

### 3.18 OpenSearch resources (≥1 required — seeds from doc 15 §10)

`@mcp.resource` (doc 14 §2.1). Specify **three** (+ the F-1 reclassified status resources):

- **Index catalog** — `opensearch://catalog/indices` → `StatusOut`-shaped list of `case-*`
  indices + doc counts. Refresh: on read; invalidated after ingest (reuse
  `invalidate_index_cache`).
- **Field/mapping dictionary** — `opensearch://catalog/fields/{artifact_type}` (template)
  → flattened field→type mapping for an artifact type (the `_flatten_props` output already
  in `case_summary`). Refresh: on read. Tells the agent which fields need `.keyword`.
- **Detection-rule catalog** — `opensearch://catalog/detections` → installed Sigma
  detector types/counts (or Hayabusa-available note). Refresh: on read.
- (F-1) `opensearch://cluster/status`, `opensearch://cluster/shards` — see §3.7–3.8.

---

## 4. OpenCTI backend (8 tools) — `cti_` namespace

Framework today: low-level `mcp.server.Server` with hand-written `inputSchema` dicts.
Target: standalone FastMCP 3.0 (decorator), fronted by `ProxyProvider` (D22). **Query-only
→ all `readOnlyHint=true` (D20).** `openWorldHint=true` (live platform). Existing
`validation.py` (`validate_ioc`, `validate_uuid`, `validate_limit`, `validate_offset`,
`validate_labels`, `validate_date_filter`, `MAX_QUERY_LENGTH`, `MAX_IOC_LENGTH`) becomes
the Pydantic field constraints/validators. Shared filter base:

```python
class CtiSearchFilters(BaseModel):
    limit: int = Field(..., description="Per-block default/cap (see each tool).")
    offset: int = Field(0, ge=0, le=500, description="Pagination offset; cap 500.")
    labels: list[str] | None = Field(None, description="Filter by labels (e.g. ['tlp:amber','malicious']); validated for safe chars.")
    confidence_min: int | None = Field(None, ge=0, le=100, description="Minimum confidence (0-100).")
    created_after: str | None = Field(None, description="ISO date lower bound (e.g. 2024-01-01).")
    created_before: str | None = Field(None, description="ISO date upper bound.")
```

### 4.1 `cti_get_health` — *keep* + **resource candidate** (`cti://health`, Fork F-1)

- **Nature/annotations:** read; opencti defaults. `title="OpenCTI Health"`.
- **INPUT:** `class CtiHealthIn(BaseModel): pass`.
- **OUTPUT:**
```python
class CtiHealthOut(BaseModel):
    status: Literal["healthy","unavailable"]
    opencti_available: bool
```
- **RESULT SHAPING:** scalar. Does not count against rate limits.
- **DESCRIPTION:** "Check OpenCTI connectivity/API health before relying on CTI lookups.
  **Use** at the start of an intel-dependent step. Example: `cti_get_health()`."
- **ERROR MODEL:** never raises for 'down' — returns `status:"unavailable"`; `not_configured`
  if creds missing.
- **RECLASSIFICATION:** strong candidate (manifest already flags `health:true`); expose
  `cti://health`, keep tool alias. **F-1.**

### 4.2 `cti_search_threat_intel` — *keep*

- **Nature/annotations:** read; opencti defaults. `title="Search All Threat Intel"`.
- **INPUT:**
```python
class CtiSearchThreatIntelIn(CtiSearchFilters):
    query: str = Field(..., min_length=1, max_length=MAX_QUERY_LENGTH, description="Search term (IOC, actor, malware, CVE, campaign).")
    limit: int = Field(5, ge=1, le=20, description="Max results PER entity type. Cap 20.")
```
- **OUTPUT:**
```python
class CtiEntity(BaseModel):
    id: str | None; entity_type: str | None; name: str | None
    description: str | None = None
    confidence: int | None = None
    labels: list[str] = Field(default_factory=list)
    created: str | None = None; modified: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict, description="Type-specific fields preserved.")
class CtiUnifiedSearchOut(BaseModel):
    query: str
    results_by_type: dict[str, list[CtiEntity]] = Field(..., description="Entities grouped by entity type.")
    total: int
    offset: int
```
- **RESULT SHAPING (advisable):** per-type cap 20; offset cap 500. Project to `CtiEntity`
  core fields + `extra` to avoid raw platform blobs.
- **DESCRIPTION:** "Broad search across ALL OpenCTI entity types (indicators, actors,
  malware, techniques, CVEs, reports). **Use** for discovery from a keyword. **Don't use**
  for focused single-type queries (use `cti_search_entity`, which returns more per type) or
  to contextualize a known IOC (use `cti_lookup_ioc`). Example:
  `cti_search_threat_intel(query='APT28', confidence_min=60)`."
- **ERROR MODEL:** `invalid_input` (query length); `rate_limited` (`details.wait_seconds`);
  `upstream_unavailable`; `not_configured`.

### 4.3 `cti_search_entity` — *keep*

- **Nature/annotations:** read; opencti defaults. `title="Search Entities by Type"`.
- **INPUT:**
```python
class CtiEntityType(str, Enum):  # the 16 valid types from _ENTITY_TYPE_METHODS
    threat_actor="threat_actor"; malware="malware"; attack_pattern="attack_pattern"
    vulnerability="vulnerability"; campaign="campaign"; tool="tool"
    infrastructure="infrastructure"; incident="incident"; observable="observable"
    sighting="sighting"; organization="organization"; sector="sector"
    location="location"; course_of_action="course_of_action"; grouping="grouping"; note="note"
class CtiSearchEntityIn(CtiSearchFilters):
    type: CtiEntityType = Field(..., description="Single entity type to search.")
    query: str = Field(..., min_length=1, max_length=MAX_QUERY_LENGTH, description="Search term.")
    limit: int = Field(10, ge=1, le=50, description="Max results. Cap 50.")
    observable_types: list[str] | None = Field(None, description="Only when type='observable': restrict observable subtypes.")
```
- **OUTPUT:**
```python
class CtiEntitySearchOut(BaseModel):
    type: CtiEntityType
    results: list[CtiEntity]
    total: int
    offset: int = 0
```
- **RESULT SHAPING:** `limit` cap **50** (vs 20-per-type for unified); offset cap 500.
- **DESCRIPTION:** "Search ONE entity type (up to 50 results) — more precise than
  `cti_search_threat_intel`. **Use** for focused queries ('all malware linked to APT28').
  Valid types: threat_actor, malware, attack_pattern, vulnerability, campaign, tool,
  infrastructure, incident, observable, sighting, organization, sector, location,
  course_of_action, grouping, note. Example:
  `cti_search_entity(type='vulnerability', query='CVE-2024')`."
- **ERROR MODEL:** `invalid_input` (bad type → `details.valid_types`; query length);
  `rate_limited`; `upstream_unavailable`.

### 4.4 `cti_lookup_ioc` — *keep*

- **Nature/annotations:** read; opencti defaults. `title="Look Up IOC Context"`.
- **INPUT:**
```python
class CtiLookupIocIn(BaseModel):
    ioc: str = Field(..., min_length=1, max_length=MAX_IOC_LENGTH, description="IOC value: IP, file hash (MD5/SHA1/SHA256), domain, or URL.")
    # validator runs validate_ioc → also yields detected ioc_type in output
```
- **OUTPUT:**
```python
class CtiIocContextOut(BaseModel):
    ioc: str
    ioc_type: str | None = Field(None, description="Detected type: ip, hash(md5/sha1/sha256), domain, url.")
    found: bool
    indicator: CtiEntity | None = None
    related_threat_actors: list[CtiEntity] = Field(default_factory=list)
    related_malware: list[CtiEntity] = Field(default_factory=list)
    related_techniques: list[CtiEntity] = Field(default_factory=list)
    related_campaigns: list[CtiEntity] = Field(default_factory=list)
```
- **RESULT SHAPING:** related-entity lists; cap each (e.g. 50) with the platform default.
- **DESCRIPTION:** "Look up one IOC and return full context: related actors, malware,
  MITRE techniques, campaigns. **Use** for a known IOC you want to contextualize; **don't
  use** for broad searching (use `cti_search_threat_intel`). Handles IP/hash/domain/URL.
  Example: `cti_lookup_ioc(ioc='8.8.8.8')`."
- **ERROR MODEL:** `invalid_input` (length/format); `rate_limited`; `upstream_unavailable`.

### 4.5 `cti_get_recent_indicators` — *keep*

- **Nature/annotations:** read; opencti defaults. `title="Recent Indicators"`.
- **INPUT:**
```python
class CtiRecentIndicatorsIn(BaseModel):
    days: int = Field(7, ge=1, le=90, description="Look-back window in days. Cap 90.")
    limit: int = Field(20, ge=1, le=100, description="Max indicators. Cap 100.")
```
- **OUTPUT:**
```python
class CtiRecentIndicatorsOut(BaseModel):
    days: int
    results: list[CtiEntity]
    total: int
```
- **RESULT SHAPING:** `limit` cap **100**, sorted by creation date.
- **DESCRIPTION:** "Recently added indicators from the last N days (≤100). **Use** for
  situational awareness or to check whether new intel relevant to an ongoing case has
  landed. Example: `cti_get_recent_indicators(days=14)`."
- **ERROR MODEL:** `invalid_input` (days/limit range); `rate_limited`; `upstream_unavailable`.

### 4.6 `cti_get_entity` — *keep*

- **Nature/annotations:** read; opencti defaults. `title="Get Entity by ID"`.
- **INPUT:**
```python
class CtiGetEntityIn(BaseModel):
    entity_id: str = Field(..., description="OpenCTI entity UUID (validated as UUID to block injection).")
```
- **OUTPUT:**
```python
class CtiGetEntityOut(BaseModel):
    found: bool
    entity_id: str
    entity: CtiEntity | None = None
```
- **RESULT SHAPING:** single entity, full fields.
- **DESCRIPTION:** "Full details for one entity by UUID (description, labels, confidence,
  external refs, dates). **Use** after a search to expand an entity. The UUID comes from
  search-result `id`. Example: `cti_get_entity(entity_id='<uuid>')`."
- **ERROR MODEL:** `invalid_input` (non-UUID); `not_found` (`found:false`); `rate_limited`;
  `upstream_unavailable`.

### 4.7 `cti_get_relationships` — *keep*

- **Nature/annotations:** read; opencti defaults. `title="Entity Relationships"`.
- **INPUT:**
```python
class CtiDirection(str, Enum): from_="from"; to="to"; both="both"
class CtiGetRelationshipsIn(BaseModel):
    entity_id: str = Field(..., description="Entity UUID to expand (validated).")
    direction: CtiDirection = Field(CtiDirection.both, description="from=outgoing, to=incoming, both=default.")
    relationship_types: list[str] | None = Field(None, description="Filter (e.g. ['indicates','uses','targets']); validated.")
    limit: int = Field(50, ge=1, le=50, description="Max related entities. Cap 50.")
```
- **OUTPUT:**
```python
class CtiRelationship(BaseModel):
    id: str | None; relationship_type: str | None
    source: CtiEntity | None; target: CtiEntity | None
    direction: str | None = None
class CtiRelationshipsOut(BaseModel):
    entity_id: str
    relationships: list[CtiRelationship]
    total: int
```
- **RESULT SHAPING:** `limit` cap **50**.
- **DESCRIPTION:** "Relationships for an entity (who uses it, what it indicates/targets).
  **Use** to map actor toolkits, malware capabilities, or indicator context. Filter by
  `direction` and `relationship_types`. Example:
  `cti_get_relationships(entity_id='<uuid>', relationship_types=['uses'])`."
- **ERROR MODEL:** `invalid_input` (UUID/rel types); `rate_limited`; `upstream_unavailable`.

### 4.8 `cti_search_reports` — *keep*

- **Nature/annotations:** read; opencti defaults. `title="Search Reports"`.
- **INPUT:**
```python
class CtiSearchReportsIn(CtiSearchFilters):
    query: str = Field(..., min_length=1, max_length=MAX_QUERY_LENGTH, description="Search term (campaign, actor, malware, CVE).")
    limit: int = Field(10, ge=1, le=50, description="Max reports. Cap 50.")
```
- **OUTPUT:**
```python
class CtiReport(BaseModel):
    id: str | None; name: str | None; published: str | None
    description: str | None = None; labels: list[str] = Field(default_factory=list)
    confidence: int | None = None
    object_refs: list[str] = Field(default_factory=list, description="Referenced entity ids.")
class CtiReportsOut(BaseModel):
    results: list[CtiReport]
    total: int
    offset: int
```
- **RESULT SHAPING:** `limit` cap **50**; offset cap 500.
- **DESCRIPTION:** "Search threat-intel reports by keyword — reports carry the analytical
  narrative individual IOCs lack. **Use** when you want context/attribution prose. Example:
  `cti_search_reports(query='SolarWinds', created_after='2023-01-01')`."
- **ERROR MODEL:** `invalid_input` (query length); `rate_limited`; `upstream_unavailable`.

### 4.9 OpenCTI prompt (≥1 required)

- **`enrich_ioc`** — args: `ioc` (str). Composes `cti_get_health` →
  `cti_lookup_ioc(ioc)` → for the top related entity, `cti_get_relationships` →
  `cti_search_reports(query=<actor/malware name>)`. Produces a "enrich and contextualize
  this IOC" message (lookup + relationships + reports).

### 4.10 OpenCTI resources (≥1 required)

- **Connector/feed catalog** — `cti://catalog/connectors` → enabled connectors/feeds
  (MITRE ATT&CK, CVE/NVD, etc.) and last-sync state. Refresh: on read (cheap platform call).
- **Entity-type reference** — `cti://reference/entity-types` → the 16 searchable entity
  types + which support `confidence_min`/full filters (`_ENTITY_TYPES_WITH_CONFIDENCE`,
  `_ENTITY_TYPES_FULL_FILTERS`, `_ENTITY_TYPES_SIMPLE`). Static; refresh rarely.
- (F-1) `cti://health` — see §4.1.

---

## 5. Windows-Triage backend (6 tools) — `wintriage_` namespace

Framework today: low-level `mcp.server.Server`, hand-written `inputSchema`. Target:
standalone FastMCP 3.0 (decorator), `ProxyProvider` (D22). **Query-only against static
local SQLite baselines → all `readOnlyHint=true, openWorldHint=false, idempotentHint=true`
(D23).** Shared verdict enum + base:

```python
class Verdict(str, Enum):
    EXPECTED="EXPECTED"; EXPECTED_LOLBIN="EXPECTED_LOLBIN"
    SUSPICIOUS="SUSPICIOUS"; UNKNOWN="UNKNOWN"; ERROR="ERROR"
class Finding(BaseModel):
    type: str; severity: Literal["critical","high","medium","low"]
    description: str
    extra: dict[str, Any] = Field(default_factory=dict)
class VerdictOut(BaseModel):
    verdict: Verdict
    reasons: list[str]
    confidence: Literal["high","medium","low"]
    findings: list[Finding] = Field(default_factory=list)
```

**Note on legacy aliases:** `call_tool` currently also dispatches un-listed legacy names
(`check_file`, `check_service`, `check_scheduled_task`, `check_autorun`, `check_hash`,
`analyze_filename`, `check_lolbin`, `check_hijackable_dll`, `get_db_stats`, `get_health`).
They are NOT in `list_tools` (already invisible). In the revamp they are recorded in the
change-map (§6) as **deprecated aliases** of the consolidated tools (or dropped — Fork
**F-2**), not silently lost.

### 5.1 `wintriage_check_artifact` — *keep* (consolidated multi-type tool)

- **Nature/annotations:** read; wintriage defaults. `title="Check Windows Artifact"`.
- **INPUT:**
```python
class ArtifactType(str, Enum): file="file"; hash="hash"; filename="filename"; lolbin="lolbin"; dll="dll"
class CheckArtifactIn(BaseModel):
    type: ArtifactType = Field(..., description="file=path baseline (+optional hash); hash=LOLDrivers vuln-driver lookup; filename=deception heuristics; lolbin=LOLBin context; dll=hijackability.")
    value: str = Field(..., min_length=1, description="file=Windows path; hash=MD5/SHA1/SHA256; filename/lolbin=filename; dll=DLL name. No null bytes; length-capped per type.")
    hash: str | None = Field(None, description="Optional file hash when type='file' (baseline mismatch check).")
    os_version: str | None = Field(None, description="Optional OS filter for type='file' (e.g. Win10_21H2_Pro).")
```
- **OUTPUT:** `VerdictOut` extended:
```python
class CheckArtifactOut(VerdictOut):
    artifact_type: ArtifactType
    path_in_baseline: bool | None = None
    filename_in_baseline: bool | None = None
    is_system_path: bool | None = None
    is_lolbin: bool = False
    lolbin_functions: list[str] = Field(default_factory=list)
    # hash subtype: vulnerable_driver: dict|None; algorithm; hash
    # dll subtype: is_hijackable, hijack_types, scenarios_by_type, mitre_technique
    subtype_data: dict[str, Any] = Field(default_factory=dict, description="Type-specific fields (vulnerable_driver, scenarios_by_type, etc.).")
```
- **RESULT SHAPING:** verdict + findings; per-type bounded. UNKNOWN is neutral (state in
  description so the agent does not over-escalate).
- **DESCRIPTION:** "Validate ONE Windows artifact against local offline baselines.
  `type='file'` (path + optional hash), `'hash'` (LOLDrivers vuln-driver), `'filename'`
  (deception heuristics), `'lolbin'` (LOLBin context), `'dll'` (hijackability). **UNKNOWN
  is neutral** — not in the local DB, not evidence of malice. For hash/IOC *reputation*
  use `cti_lookup_ioc`. Example:
  `wintriage_check_artifact(type='file', value='C:\\Windows\\System32\\svchost.exe', os_version='Win10_21H2_Pro')`."
- **ERROR MODEL:** `invalid_input` (unsupported `type` → `details.supported_types`; length;
  null bytes; bad hash format → verdict ERROR); `upstream_degraded` (baseline DB
  unavailable → verdict UNKNOWN + reason).

### 5.2 `wintriage_check_process_tree` — *keep*

- **Nature/annotations:** read; wintriage defaults. `title="Check Process Tree"`.
- **INPUT:**
```python
class CheckProcessTreeIn(BaseModel):
    process_name: str = Field(..., min_length=1, description="Child process name (e.g. 'cmd.exe').")
    parent_name: str = Field(..., min_length=1, description="Parent process name (e.g. 'winword.exe').")
    path: str | None = Field(None, description="Optional executable path for tighter matching.")
    user: str | None = Field(None, description="Optional user context (SYSTEM vs user).")
```
- **OUTPUT:**
```python
class CheckProcessTreeOut(VerdictOut):
    in_expectations_db: bool
    expected_parents: list[str] = Field(default_factory=list)
    suspicious_parents: list[str] = Field(default_factory=list)
    user_context: dict | None = None
```
- **RESULT SHAPING:** verdict + findings (`injection_detected`/`suspicious_parent`/
  `unexpected_parent`/`unexpected_path`/`unexpected_user`).
- **DESCRIPTION:** "Validate a parent→child process relationship against the Windows
  process-tree baseline. Three checks: never-spawns (injection targets like lsass.exe),
  suspicious-parent blacklist (Office/browsers spawning shells), and valid-parent
  whitelist (svchost.exe must descend from services.exe). **Use** on process-creation
  evidence. Example:
  `wintriage_check_process_tree(process_name='cmd.exe', parent_name='winword.exe')`."
- **ERROR MODEL:** `invalid_input` (length/null bytes); `upstream_degraded`.

### 5.3 `wintriage_check_system` — *keep* (consolidated service/task/autorun)

- **Nature/annotations:** read; wintriage defaults. `title="Check System Persistence"`.
- **INPUT:**
```python
class SystemType(str, Enum): service="service"; scheduled_task="scheduled_task"; autorun="autorun"
class CheckSystemIn(BaseModel):
    type: SystemType = Field(..., description="service | scheduled_task | autorun.")
    name: str = Field(..., min_length=1, description="Service name, scheduled-task path, or autorun registry key path.")
    binary_path: str | None = Field(None, description="Optional service binary path (type='service').")
    value_name: str | None = Field(None, description="Optional registry value name (type='autorun').")
    os_version: str = Field(..., min_length=1, description="Target OS (e.g. Win10_21H2_Pro, W11_22H2, Server2022). REQUIRED — baselines vary by release.")
```
- **OUTPUT:** `VerdictOut` + `system_type: SystemType` + optional `baseline_info`/`os_versions`/`hive`/`task_name`.
- **RESULT SHAPING:** verdict + findings; `os_version` mandatory (missing → typed error,
  not a silent UNKNOWN — matches current `os_version is required` guard).
- **DESCRIPTION:** "Validate Windows persistence/config against OS-version baselines:
  `type='service'|'scheduled_task'|'autorun'`. `os_version` is **required** (services/tasks
  /autoruns vary by release). UNKNOWN is neutral unless concrete suspicious findings
  appear. Example:
  `wintriage_check_system(type='service', name='EventLog', os_version='Win10_21H2_Pro', binary_path='C:\\Windows\\System32\\svchost.exe')`."
- **ERROR MODEL:** `invalid_input` (unsupported `type` → `details.supported_types`;
  missing `os_version` → remediation lists examples; length/null bytes); `upstream_degraded`.

### 5.4 `wintriage_check_registry` — *keep*

- **Nature/annotations:** read; wintriage defaults. `title="Check Registry Baseline"`.
- **INPUT:**
```python
class CheckRegistryIn(BaseModel):
    key_path: str = Field(..., min_length=1, description="Registry key path (e.g. 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion').")
    value_name: str | None = Field(None, description="Optional specific value name.")
    hive: Literal["SYSTEM","SOFTWARE","NTUSER","DEFAULT"] | None = Field(None, description="Optional registry hive.")
    os_version: str | None = Field(None, description="Optional OS-version filter.")
```
- **OUTPUT:**
```python
class CheckRegistryOut(VerdictOut):
    in_baseline: bool
    os_versions: list[str] = Field(default_factory=list)
    os_version_count: int | None = None
    match_count: int | None = None
    values: list[dict] = Field(default_factory=list, description="Up to 10 {name,type,hive}.")
    value_count: int | None = None
```
- **RESULT SHAPING:** `os_versions`/`values` already capped at 10 — keep, expose true counts.
- **DESCRIPTION:** "Check a registry key/value against the FULL registry baseline (requires
  the optional 12GB known_good_registry.db). **Use** for general registry validation; for
  autorun/persistence specifically prefer `wintriage_check_system(type='autorun')` (faster,
  no large DB). Example: `wintriage_check_registry(key_path='SOFTWARE\\...\\Run')`."
- **ERROR MODEL:** `upstream_degraded` (registry DB not installed → remediation points to
  SETUP.md; verdict null/lookup_performed=false); `invalid_input` (length/null bytes).

### 5.5 `wintriage_check_pipe` — *keep*

- **Nature/annotations:** read; wintriage defaults. `title="Check Named Pipe"`.
- **INPUT:**
```python
class CheckPipeIn(BaseModel):
    pipe_name: str = Field(..., min_length=1, description="Named pipe (with or without \\\\.\\pipe\\ prefix; normalized).")
```
- **OUTPUT:**
```python
class CheckPipeOut(BaseModel):
    verdict: Verdict
    is_suspicious: bool = False
    is_windows_pipe: bool = False
    tool_name: str | None = None
    malware_family: str | None = None
    description: str | None = None
    protocol: str | None = None
    service_name: str | None = None
```
- **RESULT SHAPING:** single verdict.
- **DESCRIPTION:** "Check a named pipe against known Windows pipes and known C2 pipes
  (Cobalt Strike, Metasploit, etc.). SUSPICIOUS = matches a C2 pattern; EXPECTED =
  standard Windows pipe; UNKNOWN = neither. **Use** when pipe artifacts appear (named
  pipes are a common C2 channel). Example:
  `wintriage_check_pipe(pipe_name='\\\\.\\pipe\\msagent_12')`."
- **ERROR MODEL:** `invalid_input` (length/null bytes); `upstream_degraded`.

### 5.6 `wintriage_server_status` — *keep* + **resource candidate** (`wintriage://status`, Fork F-1)

- **Nature/annotations:** read; wintriage defaults. `title="Triage Backend Status"`.
- **INPUT:**
```python
class ServerStatusIn(BaseModel):
    resource: Literal["health","db_stats","all"] = Field("health", description="health=connectivity/cache; db_stats=baseline coverage counts; all=both.")
```
- **OUTPUT:**
```python
class WintriageHealth(BaseModel):
    status: Literal["healthy","degraded"]
    uptime_seconds: float
    databases: dict[str, str]
    cache: dict[str, Any]
    config: dict[str, Any]
class WintriageDbStats(BaseModel):
    known_good_db: dict[str, Any]
    context_db: dict[str, Any]
    registry_db: dict[str, Any]
class ServerStatusOut(BaseModel):
    resource: Literal["health","db_stats","all"]
    health: WintriageHealth | None = None
    db_stats: WintriageDbStats | None = None
```
- **RESULT SHAPING:** scalar/stat dicts.
- **DESCRIPTION:** "Report triage backend readiness: `resource='health'` (connectivity/
  cache), `'db_stats'` (baseline coverage counts), or `'all'` (before a triage-heavy
  investigation). Example: `wintriage_server_status(resource='all')`."
- **ERROR MODEL:** `invalid_input` (bad `resource` → `details.supported_resources`);
  `upstream_degraded` (DB error surfaces as status 'degraded', not an exception).
- **RECLASSIFICATION:** strong candidate; expose `wintriage://status` (health) +
  `wintriage://catalog/baselines` (db_stats), keep tool alias. **F-1.**

### 5.7 Windows-Triage prompt (≥1 required)

- **`triage_process_tree`** — args: `process_name`, `parent_name`, `path` (opt),
  `user` (opt). Composes `wintriage_check_process_tree` →, if the process/parent name is
  notable, `wintriage_check_artifact(type='file'/'lolbin')` on each → summary verdict.
- **`baseline_compare`** (second prompt) — args: `os_version`, plus a small set of
  observed services/tasks/autoruns. Composes repeated `wintriage_check_system` calls +
  `wintriage_check_artifact` on referenced binaries, producing a persistence-baseline diff.

### 5.8 Windows-Triage resources (≥1 required)

- **Baseline-DB catalog + summaries** — `wintriage://catalog/baselines` → counts/coverage
  from `get_stats()` for known_good.db (files/hashes/os_versions), context.db (lolbins/
  vulnerable_drivers/protected processes), and registry.db availability. Refresh: on read
  (static DBs; cache-friendly).
- **Known-good reference** — `wintriage://reference/known-good/{kind}` (template; kind ∈
  services|pipes|lolbins) → enumerations of common baseline entries for orientation.
- (F-1) `wintriage://status` — see §5.6.

---

## 6. Consolidated rename change-map

Namespaces (`opensearch_`, `cti_`, `wintriage_`) are fixed (D24 Namespace transform);
renames happen within a namespace. Each rename registers the old name as a **deprecated
alias** for one cutover cycle (doc 15 §6); the change-map is an input to D27b and to
RAG/skills that reference tool names.

| Backend | Old name | New name | Reason | Alias action |
| --- | --- | --- | --- | --- |
| opensearch | `opensearch_host_fix` | `opensearch_fix_host_mapping` | "host_fix" is vague; clarifies it corrects a host.id alias mapping + reindex | register `opensearch_host_fix` as deprecated alias (1 cycle) |
| opensearch | *(advisory keys)* `hint`,`note`,`field_hint`,`discipline_reminder` | folded into typed `advisories[]` | untyped free-floating keys → typed model | n/a (output reshape, not a rename) |
| opensearch | envelope `audit_id` (in body) | `ToolResult.meta.audit_id` | clean structured_content | n/a |
| opencti | envelope `audit_id`,`examiner`,`caveats`,`interpretation_constraint` (in body) | `ToolResult.meta.*` | clean structured_content | n/a |
| wintriage | envelope `audit_id`,`examiner`,`caveats`,`interpretation_constraint` (in body) | `ToolResult.meta.*` | clean structured_content | n/a |
| wintriage | legacy `check_file` | `wintriage_check_artifact(type='file')` | already unlisted; consolidate | deprecated alias, 1 cycle (F-2 resolved) |
| wintriage | legacy `check_hash` | `wintriage_check_artifact(type='hash')` | already unlisted | deprecated alias, 1 cycle (F-2 resolved) |
| wintriage | legacy `analyze_filename` | `wintriage_check_artifact(type='filename')` | already unlisted | deprecated alias, 1 cycle (F-2 resolved) |
| wintriage | legacy `check_lolbin` | `wintriage_check_artifact(type='lolbin')` | already unlisted | deprecated alias, 1 cycle (F-2 resolved) |
| wintriage | legacy `check_hijackable_dll` | `wintriage_check_artifact(type='dll')` | already unlisted | deprecated alias, 1 cycle (F-2 resolved) |
| wintriage | legacy `check_service` | `wintriage_check_system(type='service')` | already unlisted | deprecated alias, 1 cycle (F-2 resolved) |
| wintriage | legacy `check_scheduled_task` | `wintriage_check_system(type='scheduled_task')` | already unlisted | deprecated alias, 1 cycle (F-2 resolved) |
| wintriage | legacy `check_autorun` | `wintriage_check_system(type='autorun')` | already unlisted | deprecated alias, 1 cycle (F-2 resolved) |
| wintriage | legacy `get_db_stats` | `wintriage_server_status(resource='db_stats')` | already unlisted | deprecated alias, 1 cycle (F-2 resolved) |
| wintriage | legacy `get_health` | `wintriage_server_status(resource='health')` | already unlisted | deprecated alias, 1 cycle (F-2 resolved) |

All **other** tool names (15 opensearch besides host_fix, all 8 cti, the 6 wintriage
public tools) are **kept**. The resource reclassifications (§2) add resource URIs while
keeping the tool names as deprecated aliases — they appear in the F-1 fork, not as renames.

---

## 7. Forks — RESOLVED (Run 19)

All five forks were decided by the operator in Run 19 and are tracked in `REGISTER.md`.

- **F-1 — tool→resource reclassification (§2): APPROVED, additive.** Reclassify the four
  strong candidates (`opensearch_status`, `opensearch_shard_status`, `cti_get_health`,
  `wintriage_server_status`) as MCP resources, keeping the tool form as a **deprecated
  alias**; keep the two query-shaped ones (`opensearch_list_detections`,
  `opensearch_case_summary`) as tools with an optional resource view. The kept aliases get
  a removal horizon (at/after D27b, once skills/RAG updated) → **B-1**. Affects D27b
  (`ResourcesAsTools`) + the golden snapshot.
- **F-2 — legacy wintriage aliases (§6): KEEP AS DEPRECATED ALIASES (one cycle), not drop.**
  Repo grep found no internal references to the 10 legacy names **except** `analyze_filename`,
  which is referenced as a tool in a `forensic-knowledge` playbook
  (`packages/forensic-knowledge/data/discipline/playbooks/suspicious_execution.yaml`) and in
  `tool_metadata.py`. Dropping would break that reference; an alias is near-free and covers
  un-greppable external scripts. Removal + playbook/skill update tracked → **B-2**. (Count
  confirmed: 10 = 9 `check_/get_` dispatch names + `analyze_filename`.)
- **F-3 — response-guard scans `structured_content` (§1.1): REQUIRED (security).** Not
  optional — moving typed data into `structured_content` while the gateway guard scans only
  text is a **redaction bypass**. Output models here assume the guard covers
  `structured_content`. D27b implemented this via the gateway `guard_tool_result`;
  **B-3** is DONE as of Run 24.
- **F-4 — `opensearch_timeline` ceiling (§3.5): ADD, warn-not-truncate.** Cap default ~2000
  (configurable), emit a narrowing advisory; never silently drop buckets (forensic
  no-silent-loss principle).
- **F-5 — `opensearch_ingest.password` (§3.11): REDACT (mandatory).** Redact in
  audit/logs/`ToolResult` (intersects F-3). Forward: credentials-as-tool-arg is an
  anti-pattern — move to a named control-plane credential so the secret never transits the
  call/audit path → **B-4** (auth/jobs phase; does not block D27a).

The **D5 write-tool guardrail holds**: `opensearch_ingest`, `opensearch_enrich_intel`,
`opensearch_enrich_triage`, `opensearch_fix_host_mapping` keep `readOnlyHint=false` and
their current execution behavior; the durable-job phase reshapes execution later. None of
the resolved forks change that.

---

## Sources

- Current I/O ground truth: `packages/opensearch-mcp/src/opensearch_mcp/server.py`
  (16 tools), `packages/opencti-mcp/src/opencti_mcp/server.py` (8 tools),
  `packages/windows-triage-mcp/src/windows_triage_mcp/server.py` (6 tools, + 10 unlisted
  legacy aliases); backend manifests `packages/{opencti,windows-triage}-mcp/sift-backend.json`.
- Contract/decisions: `00_migration_charter.md` (D19, D20, D22, D23, D24, D27a/b, D28;
  D2/D3 boundary, D5 jobs); `15_backend_tooling_revamp.md` (§5 contract, §6 change-map,
  §7 exposure-agnostic, §9 gates, §10 per-backend seeds); `14_fastmcp3_supabase_integration.md`
  (§2 FastMCP 3.0 primitives: ToolResult, annotations, prompts, resources, transforms).
