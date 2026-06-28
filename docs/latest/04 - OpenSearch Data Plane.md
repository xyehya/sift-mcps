---
title: OpenSearch Data Plane — Log Indexing and Search
source_commit: eadb92b
generated: 2026-06-27
verified_against: code+tests+config
invariants_checked: 8
status: draft
---

## Overview
`opensearch-mcp` (`packages/opensearch-mcp/src/opensearch_mcp/`) is the primary add-on MCP backend providing the derived data plane. It indexes forensic artifacts into OpenSearch, provides full-text/aggregate/timeline/field-value search across indexed evidence, and orchestrates durable ingest/enrich jobs. Namespace: `opensearch`, tier: addon, transport: stdio. 14 registered tools, all case-scoped (`default_case_scoped: true`). Indexes are built as `case-{key}-{artifact_type}-{host}`.

## How it works
The add-on runs as a stdio subprocess launched by the Gateway. It opens a TCP connection to OpenSearch (default `localhost:9200`). The Gateway injects the DB-authoritative active case context (`case_dir`) into every tool call via the `ProxyActiveCase` middleware, which this backend stores in `_INJECTED_CASE_DIR` contextvar.

Ingest pipeline: artifact discovery → EZ tool processing (ZimmermanTools binaries) → parser → bulk indexing with provenance stamping → optional Hayabusa sigma detection. Heavy ingest/enrich operations are redirected to durable Postgres worker jobs (`sift-opensearch-worker@`).

Search flow: validate index segments → resolve active-case prefix → execute query → format results (exclusion, truncation, hoisting, autosave) → return.

## Reference sections

### REGISTRY (14 tools + 5 resources + 3 prompts)

All from `registry.py:REGISTRY` and `sift-backend.json`:

**Tools (all `readOnlyHint`, namespaced `opensearch_`):**
1. `opensearch_search` — search using `query_string`, supports time range, sort, offset, compact projection
2. `opensearch_count` — exact document count matching query
3. `opensearch_aggregate` — terms aggregation (group-by), top-N frequency, optional pre-filter
4. `opensearch_get_event` — fetch one complete document by `_id`
5. `opensearch_timeline` — date histogram, interval Ns/Nm/Nh/Nd, sparse buckets omitted
6. `opensearch_field_values` — distinct field values with counts
7. `opensearch_status` — DEPRECATED, cluster health + active-case index catalog
8. `opensearch_shard_status` — DEPRECATED, shard capacity
9. `opensearch_case_summary` — complete coverage overview: hosts, artifact families, time range, enrichment state
10. `opensearch_inspect_container` — survey forensic container without mounting
11. `opensearch_ingest` — discover and ingest artifacts (`dry_run=True` default, destructive)
12. `opensearch_ingest_status` — poll running/recent ingest/enrich runs
13. `opensearch_enrich_intel` — IOC extraction + OpenCTI enrichment (requires `enrichment:intel` scope)
14. `opensearch_fix_host_mapping` — correct host.id mapping across indexed docs

**Resources:**
- `opensearch://cluster/status` — cluster health + case index counts
- `opensearch://cluster/shards` — shard usage + capacity headroom
- `opensearch://catalog/indices` — case-* index catalog
- `opensearch://catalog/fields/{artifact_type}` — field-to-type mapping
- `opensearch://case/{case_id}/summary` — parameterized case coverage

**Prompts:** `triage_host`, `build_timeline`, `ioc_sweep`

### client.py — OpenSearch Client
`get_client()`: Resolution: explicit path → `OPENSEARCH_CONFIG` env → `~/.sift/opensearch.yaml`. Config: `{host, user, password, verify_certs}`. Creates `opensearchpy.OpenSearch` instance with `use_ssl` true for https, `verify_certs` defaults False. Cached globally in `server.py` via `_get_os()`. Health-checks on first use, auto-installs winlog pipeline + index templates on first verified connection.

### ingest.py — Ingest Orchestrator
`ingest(hosts, case_id, ...)`: Discovery → EZ tool processing → custom parser → bulk index → Hayabusa post-ingest. `_persist_ingest_audit_event()`: Writes one `app.audit_events` row per artifact via Postgres (when `SIFT_CONTROL_PLANE_DSN` set).

### ingest_job.py — Durable Job Handlers
Heavy ingest/enrich redirected to `sift-opensearch-worker@` systemd units. Flow: Gateway enqueues durable job → worker claims → handler runs existing entry point → progress mirrored every 5s → `result_public` returned (path-free).

### case_scoped.py — Case Scoping
Index prefix convention: `case-{normalized_key}-{artifact_type}-{host}`. Key helpers: `resolve_active_case_prefix()`, `active_case_index_pattern()`, `in_active_case()`, `filter_rows_by_index_prefix()`. Authority chain: Gateway injects DB case_dir → stored in `_INJECTED_CASE_DIR` contextvar → resolution: injected > SIFT_CASE_DIR env > legacy `~/.sift/active_case`.

### search_format.py — Result Formatting
Field exclusion: `_SEARCH_EXCLUDE_FIELDS` (Payload, task.xml, FilesLoaded, MFT structural, EvtxECmd low-value, sift.*). Field truncation: default 500 chars per field, truncated listed in `_truncated` per hit. Constant-field hoisting: identical fields across all hits moved to `common_fields`. Autosave: large sets spilled to `<case>/agent/<kind>/<prefix>_<uuid>.json`. Thresholds: 20 search hits, 100 aggregate buckets.

### paths.py — Index Path Conventions
- `build_index_name(case_id, artifact_type, hostname)`: `case-{key}-{artifact_type}-{host}`
- `sanitize_index_component(value)`: lowercases, non-`[a-z0-9._-]` → `-`
- `normalize_case_key(case_id)`: strips leading `case-`
- `auto_detect_time_field(sample)`: candidate: @timestamp, timestamp, ts, datetime
- `resolve_timezone(tz_name)`: Windows→IANA mapping (134 entries)

### bulk.py — Bulk Indexing
`flush_bulk(client, actions)`: Provenance stamping (`sift.case_id`, `sift.evidence_id`, `sift.provenance_id`, `sift.job_id`) via ContextVar. Exponential backoff retry (10s→120s, 10 retries). Circuit breaker on systemic failure.

### tools.py — EZ Tool Registry (11 tools)
amcache, shimcache, registry, shellbags, jumplists, lnk, recyclebin, mft, usn, timeline, evtxecmd. Each with binary name, tier, index suffix, time field, multi-CSV flag.

### discover.py — Artifact Discovery
Scans triage directory structure, identifies hosts from `$VolumeRoot/registry` ComputerName, enumerates artifacts (evtx, registry hives, MFT, USN, prefetch, SRUM).

### gateway.py — Gateway REST Client
`call_tool(tool_name, arguments, timeout)`: Calls via POST `/api/v1/tools/{tool_name}`. Retry on 502/503/504. Used by `threat_intel.py` for OpenCTI enrichment callback.

### threat_intel.py — OpenCTI Enrichment
Calls back through gateway: `call_tool("cti_lookup_ioc", {"ioc": value})`. Updates opensearch doc `threat_intel.*` fields.

### registry.py — Tool Registration
REGISTRY list of ToolDef objects. Each: name, fn, in_model, out_model, annotations. `server.py` returns plain dicts; `registry.py` rebuilds into typed Out models.

## Invariants
- **No active case → empty result**: Never cluster-wide fallback. Enforced by `case_scoped.py` and `server.py:_validate_index()`. (`case_scoped.py`)
- **Index segments must start with active-case prefix**: Rejects `case-*`, other case keys, system `.`-indices. (`server.py:_validate_index()`)
- **OpenSearch is derived, never authoritative**: Postgres is source of truth. Indexed docs carry sift.* provenance. (`data_plane` manifest field, `sift-backend.json`)
- **Ingest/enrich job result_public is path-free**: Never returns absolute paths or secrets. (`ingest_job.py`)
- **Provenance stamping**: Every indexed doc receives `sift.case_id`, `sift.evidence_id`, `sift.provenance_id`, `sift.job_id`. (`bulk.py`)
- **Case summary coverage gaps**: `opensearch_case_summary` reports exact fill commands for missing coverage. (`server.py`)
- **Search results never return raw container paths**: Collapsed to case-relative or `[REDACTED]`. (F-MVP-2, manifest annotations)

## Gotchas & Edge Cases
> [!warning] `opensearch_status` and `opensearch_shard_status` are DEPRECATED. Use resources `opensearch://cluster/status` and `opensearch://cluster/shards` instead.

> [!important] `opensearch_ingest` defaults to `dry_run=True`. Explicitly set `dry_run=false` to actually index. (`sift-backend.json`)

> [!note] The circuit breaker in `bulk.py` trips after N consecutive systemic failures. `reset_circuit_breaker()` must be called at ingest start for in-process paths. (`bulk.py`)

> [!warning] `opensearch_enrich_intel` requires `enrichment:intel` scope. `opensearch_fix_host_mapping` in DB-active mode requires a receipt recorder (denied without it). (`sift-backend.json`)

> [!note] `opensearch_inspect_container` is read-only (`readOnlyHint: true`) despite having a mutating-looking name. (`sift-backend.json`)

## Related
- Gateway doc (how ProxyActiveCase middleware injects case context)
- Control Plane doc (app.audit_events for ingest provenance, app.job_status_public for durable jobs)
- Add-on Ecosystem doc (shared add-on pattern)

## Key files
- `server.py` — All opensearch_* tool implementations, `_get_os()` cached client
- `registry.py` — ToolDef REGISTRY, Pydantic In/Out models
- `client.py` — OpenSearch client factory
- `paths.py` — Index naming, path resolution, timezone mapping
- `case_scoped.py` — Index-prefix isolation
- `search_format.py` — Hit/bucket shaping, autosave
- `bulk.py` — Bulk indexing with provenance stamping + circuit breaker
- `ingest.py` — Ingest orchestrator
- `ingest_job.py` — Durable job handlers
- `tools.py` — EZ tool registry
- `discover.py` — Artifact discovery
- `gateway.py` — Gateway REST client for enrichment callback
- `threat_intel.py` — OpenCTI enrichment pipeline
- `sift-backend.json` — Manifest with tool metadata, capabilities, security annotations
- `contracts.py` — Shared type contracts
- `manifest.py` — SHA-256 hashing
- `mappings/` — Index templates + winlog pipeline

## Reconciliation log
None — independently confirmed against code.
