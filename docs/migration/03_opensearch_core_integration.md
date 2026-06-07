# OpenSearch Core Integration

Last updated: 2026-06-06

Scope: documentation and design only. This document does not introduce code
changes, database migrations, OpenSearch refactors, or MCP tool rewrites.

Line references were taken from repository inspection during this planning run.

> Locked decisions (see `00_migration_charter.md`): OpenSearch profile is **3.5.0
> with security enabled** (D6). The root repo `docker-compose.yml` (OpenSearch
> 2.18.0, security disabled, bound to localhost) is **pre-migration only** and is
> not the target; security-disabled localhost exposure is incompatible with the
> Gateway-mediated case-scope boundary this document depends on, because anything
> on localhost could reach `:9200` directly. The per-case approach (Option A) is
> approved, but **v1 reuses the existing working index naming**
> `case-{case_id}-{artifact_type}-{hostname}` and the existing templates/
> `flush_bulk`/host-discovery/provenance machinery; the control plane *registers*
> these indices rather than renaming them. The logical-family rename
> (`dfir-case-*-vN`) is a deferred, optional evolution (D18). Query/tool access is
> Gateway-only and per-backend `/mcp/{name}` routes are disabled (D2/D3); internal
> execution-plane bulk writes (workers/enrichments) write directly under an
> authorized job. All long-running ingestion/indexing runs as control-plane
> durable jobs claimed by workers - there is never a direct invoke to the Evidence
> Vault (D5). The shared **write contract** in §7A governs every writer (core +
> addon + enrichment) without refactoring working backends.

## 1. Executive summary

OpenSearch should become a core SIFT search/data plane for indexed forensic
data. It should no longer be treated as an optional standalone MCP backend that
the Gateway exposes opportunistically when a separate add-on backend happens to
be available.

In the target architecture:

- Supabase/Postgres remains the authority for case lifecycle, active case state,
  case membership and operator authorization, evidence metadata, evidence
  integrity status, audit events, approvals, findings review state, jobs, job
  steps, job logs, parser runs, parser output metadata, reports, and OpenSearch
  index registration.
- OpenSearch stores searchable forensic documents derived from authoritative
  control-plane and evidence-vault state: artifacts, normalized timeline events,
  IOCs, parsed records, full-text records, and optional vector embeddings.
- The Gateway/Broker and the core SIFT MCP tool layer enforce case scope before
  any OpenSearch query is constructed or executed.
- OpenSearch query access is mediated by Gateway policy and control-plane
  lookups. Agents must not reach OpenSearch directly, pass arbitrary index names
  for normal searches, or perform cross-case searches unless explicitly allowed
  by a high-privilege policy.
- OpenSearch is a derived, reindexable data plane. It is not the source of truth
  for cases, evidence, parser state, job state, reports, approvals, audit, or
  authorization.

The current repository already has useful OpenSearch ingestion, parsing,
template, and search code. The migration should adapt that code rather than
discard it. The key architectural change is that OpenSearch access must move
behind durable case/job/evidence state and Gateway-enforced policy.

## 2. Current OpenSearch implementation from code

### Package entry points and backend registration

- The root workspace treats `opensearch-mcp` as an optional package in the
  `standard` extra rather than as unavoidable core infrastructure
  (`pyproject.toml:7-14`, `pyproject.toml:41-46`).
- The OpenSearch package declares console scripts for `opensearch-mcp` and
  `opensearch-ingest`, plus a `sift.plugins` entry named `opensearch`
  (`packages/opensearch-mcp/pyproject.toml:23-28`).
- The package manifest registers OpenSearch as an add-on backend with namespace
  `opensearch`, declared capabilities `search`, `ingest`, and `enrichment`, and
  a runtime requirement on `https://localhost:9200`
  (`packages/opensearch-mcp/sift-backend.json:1-13`).
- The manifest declares standalone OpenSearch MCP tools such as
  `opensearch_search`, `opensearch_count`, `opensearch_aggregate`,
  `opensearch_get_event`, `opensearch_timeline`, `opensearch_field_values`,
  `opensearch_status`, `opensearch_shard_status`,
  `opensearch_case_summary`, `opensearch_inspect_container`,
  `opensearch_ingest`, `opensearch_ingest_status`,
  `opensearch_enrich_intel`, `opensearch_enrich_triage`,
  `opensearch_list_detections`, and `opensearch_host_fix`
  (`packages/opensearch-mcp/sift-backend.json:14-198`).
- The MCP server is a standalone FastMCP server. `server = FastMCP(...)` and
  the package-level `AuditWriter` are initialized in
  `packages/opensearch-mcp/src/opensearch_mcp/server.py:48-49`.
- The module entry point runs the server over stdio by default, with an
  optional HTTP mode controlled by CLI flags
  (`packages/opensearch-mcp/src/opensearch_mcp/__main__.py:6-27`).
- The HTTP wrapper exposes the same FastMCP app with DNS rebinding protection
  and localhost-style allowed hosts
  (`packages/opensearch-mcp/src/opensearch_mcp/http_server.py`,
  `create_http_app`).
- The OpenSearch package README explicitly documents that it can run as stdio,
  HTTP, CLI, or a SIFT plugin
  (`packages/opensearch-mcp/README.md:96-100`).

Current conclusion: OpenSearch is packaged and mounted as an optional add-on MCP
backend, not as a core SIFT MCP service.

### Current server and tool registration

- Gateway core tools come from `sift_core.agent_tools`; the Gateway imports
  `call_core_tool`, `core_tool_names`, and `core_tool_specs` from that module
  (`packages/sift-gateway/src/sift_gateway/server.py:11-15`).
- The current core tool specs begin with file/case-oriented tools such as
  `case_info`, `evidence_info`, `record_finding`, and
  `record_timeline_event`, with no OpenSearch search tools in the inspected core
  spec table (`packages/sift-core/src/sift_core/agent_tools.py:91-115`,
  `packages/sift-core/src/sift_core/agent_tools.py:183-212`).
- `core_tool_names()` returns the in-process core tool names from
  `_SPECS_BY_NAME` (`packages/sift-core/src/sift_core/agent_tools.py:276-281`).
- `SiftGateway.call_tool()` routes core tools to `call_core_tool()` and all
  other tools through the backend map (`packages/sift-gateway/src/sift_gateway/server.py:728-787`).
- Add-on tools are built from backend manifests and live tool lists in
  `_build_tool_map()` (`packages/sift-gateway/src/sift_gateway/server.py:376-504`).
- Gateway rejects add-on tools that collide with core tool names
  (`packages/sift-gateway/src/sift_gateway/server.py:466-476`).

Current conclusion: OpenSearch tools are outside the core SIFT MCP namespace and
are registered through the add-on backend path.

### Current query and search code

- `_validate_index(index)` rejects comma-separated index segments that do not
  start with `case-`, which blocks obvious system index access but still allows
  broad case wildcards such as `case-*`
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:32-45`).
- `_resolve_index(index, case_id)` uses the caller-supplied `index` if present;
  otherwise it resolves to `case-{active_case}-*` if a case is known, and
  finally falls back to `case-*`
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:564-573`).
- `opensearch_search()` accepts `query`, optional `index`, optional `case_id`,
  pagination, sort, and time filters
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:711-722`).
- The `opensearch_search()` docstring states that an explicit `index`
  overrides `case_id`, and that `case_id` defaults to the active portal case
  from `SIFT_CASE_DIR`
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:744-749`).
- `opensearch_search()` builds an OpenSearch `query_string` query, adds an
  optional time range, and runs the search against the resolved index
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:763-791`).
- `opensearch_count()` resolves and validates the index, then calls
  `client.count()` with a query-string query
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:832-873`).
- `opensearch_aggregate()` performs a terms aggregation over a caller-selected
  field and index, with a maximum of 500 buckets
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:876-947`).
- `opensearch_get_event()` accepts an `event_id` and explicit `index`, validates
  the index prefix, and returns the stored document
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:950-990`).
- `opensearch_timeline()` resolves and validates an index and runs a
  date-histogram style query
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:993-1089`).
- `opensearch_field_values()` runs a terms aggregation for distinct values
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1092-1157`).
- `_strip_hits()` compacts search hits, preserves `_id` and `_index`, and
  truncates or strips large fields
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:526-561`).
- `opensearch_list_detections()` can query Security Analytics APIs and has a
  fallback path that suggests querying Hayabusa detections under
  `case-*-hayabusa-*`
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:3530-3661`).

Current conclusion: current search tools have useful query behavior, but case
scope is mostly inferred from environment or caller-provided parameters rather
than enforced from authenticated Gateway identity and Postgres authorization.

### Current ingest and indexing code

- `opensearch_ingest()` has no `case_id` input parameter. Its docstring says
  the case ID is resolved from the active portal case and that `case_id` is not
  accepted (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1826-1854`).
- `opensearch_ingest()` resolves the active case with `_get_active_case()`
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1913-1919`).
- `_get_active_case()` prefers `SIFT_CASE_DIR`, falling back to
  `~/.sift/active_case`
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:3504-3527`).
- Ingest path resolution uses `_resolve_tool_path()` and case-path jail logic
  before operating on evidence paths
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:690-708`,
  `packages/opensearch-mcp/src/opensearch_mcp/server.py:1965-1971`).
- The container ingest launcher creates a `run_id`, sets
  `SIFT_INGEST_RUN_ID`, spawns `python -m opensearch_mcp.ingest_cli scan
  <path> --case <case_id> --yes`, and writes logs under
  `sift_dir()/ingest-logs`
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1702-1823`).
- Generic background ingest for JSON, delimited, access log, and memory modes
  uses subprocesses and filesystem status files, not database jobs
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:3006-3168`,
  `packages/opensearch-mcp/src/opensearch_mcp/server.py:3292-3501`).
- `_spawn_ingest()` uses `systemd-run --user --scope` when available and falls
  back to a bare `Popen`
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:2941-3003`).
- `opensearch_ingest_status()` reads filesystem status, defaults to the active
  case, and accepts `case_id="*"` to see all cases
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:2373-2397`).
- `opensearch_ingest_status()` returns status records with fields such as
  `status`, `pid`, `elapsed`, `total_indexed`, `bulk_failed`, `log_file`, and
  host-discovery reports
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:2401-2567`).
- `write_status()` persists ingest status under `~/.sift/ingest-status` with
  fields such as `run_id`, `pid`, `status`, `case_id`, timestamps, host totals,
  errors, `log_file`, and `source_path`
  (`packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:13-89`).
- `read_active_ingests()` reads `*.json` status files, detects dead/zombie
  processes, and marks status as failed when needed
  (`packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:101-148`).
- `_write_ingest_manifest()` writes per-artifact JSON manifests under
  `<case>/audit/ingest-manifests` with `source_path`, `hostname`,
  `artifact_type`, `written_at`, `doc_count`, and `sha256`
  (`packages/opensearch-mcp/src/opensearch_mcp/ingest.py:29-95`).
- `ingest()` and `_ingest_hosts()` run parser/indexing pipelines and update
  filesystem status rather than durable database job state
  (`packages/opensearch-mcp/src/opensearch_mcp/ingest.py:179-305`,
  `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:514-830`).

Current conclusion: current ingest is operationally useful, but job state,
parser-run state, indexing state, and retry semantics live in subprocesses,
status files, logs, and audit entries rather than durable Postgres tables.

### Current availability, health, and config

- `get_client()` loads OpenSearch config from an explicit path,
  `OPENSEARCH_CONFIG`, or `~/.sift/opensearch.yaml`, requires `user` and
  `password`, and defaults the host to `https://localhost:9200`
  (`packages/opensearch-mcp/src/opensearch_mcp/client.py:12-44`).
- The OpenSearch README documents the default connection config file at
  `~/.sift/opensearch.yaml` with `host`, `user`, `password`, and
  `verify_certs` fields (`packages/opensearch-mcp/README.md:176-187`).
- The Gateway config loader applies `SIFT_CASES_ROOT` and `SIFT_CASE_DIR` from
  configured case state, which is one reason current OpenSearch case context is
  process-environment driven
  (`packages/sift-gateway/src/sift_gateway/config.py:49-75`).
- The OpenSearch README documents ingest/enrichment resilience environment
  variables such as `HAYABUSA_RULES_DIR`, `SIFT_SHARD_BREAKER_THRESHOLD`,
  `SIFT_INTEL_BREAKER_THRESHOLD`, `SIFT_INTEL_RATE_LIMIT_RETRIES`, and
  `SIFT_INTEL_MIN_INTERVAL_MS`
  (`packages/opensearch-mcp/README.md:202-212`).
- `_get_os()` creates and caches the OpenSearch client, calls
  `cluster.health()`, auto-installs templates on first verified connection, and
  raises a setup-style error if OpenSearch is unreachable
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:411-452`).
- `opensearch_status()` calls `_get_os()`, reports cluster health, lists
  indices starting with `case-`, and treats single-node yellow status as normal
  in the returned message
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1160-1203`).
- `opensearch_shard_status()` computes shard capacity and returns statuses such
  as ok, warning, or critical
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1206-1287`).
- The Gateway config template includes an `opensearch:` block with URL and TLS
  fields, but the add-on backend block is still external and optional
  (`configs/gateway.yaml.template:146-169`).
- Root Docker Compose runs OpenSearch 2.18.0 with security disabled and binds it
  to `127.0.0.1:9200` (`docker-compose.yml:1-35`).
- The OpenSearch package Docker Compose runs OpenSearch 3.5.0 with
  `SIFT_OS_PASSWORD` and a persistent volume
  (`packages/opensearch-mcp/docker/docker-compose.yml:1-17`).

Current conclusion: OpenSearch health exists at the add-on/tool level, but the
target system needs Gateway-level degraded-state semantics tied to policy and
control-plane state.

### Current index naming

- `sanitize_index_component()` lowercases and normalizes index components
  (`packages/opensearch-mcp/src/opensearch_mcp/paths.py:194-198`).
- `build_index_name(case_id, artifact_type, hostname)` returns
  `case-{case_id}-{artifact_type}-{hostname}`
  (`packages/opensearch-mcp/src/opensearch_mcp/paths.py:201-207`).
- `validate_index_name()` rejects invalid or uppercase index names
  (`packages/opensearch-mcp/src/opensearch_mcp/paths.py:210-220`).
- The OpenSearch README documents current index naming as
  `case-{case_id}-{artifact_type}-{hostname}`
  (`packages/opensearch-mcp/README.md:164-174`).
- The ingest code builds indices with `_build_idx(case_id, artifact, hostname)`
  for EVTX, EZ/custom artifacts, plaso-derived artifacts, custom artifacts, and
  memory plugin results
  (`packages/opensearch-mcp/src/opensearch_mcp/ingest.py:559-563`,
  `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:732-736`,
  `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:844-965`,
  `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:968-1071`,
  `packages/opensearch-mcp/src/opensearch_mcp/parse_memory.py:403-407`).

Current conclusion: the existing index model is already case-prefixed and can be
evolved into a control-plane-registered per-case strategy.

### Current document schema and provenance

There is no single explicit domain-level OpenSearch document contract today.
Instead, parsers stamp a partially consistent implicit schema.

- EVTX indexing stamps host identity and `vhir` provenance fields such as
  `vhir.source_file`, `vhir.ingest_audit_id`, optional `vhir.vss_id`, and
  `vhir.parse_method`, plus `pipeline_version`
  (`packages/opensearch-mcp/src/opensearch_mcp/parse_evtx.py:36-137`).
- CSV ingest stamps host fields, optional `vhir.table` and `vhir.vss_id`,
  `vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`, and
  `pipeline_version`
  (`packages/opensearch-mcp/src/opensearch_mcp/parse_csv.py:87-206`).
- JSON ingest stamps timestamp, hostname, host ID, `vhir.parse_method`,
  `vhir.source_file`, `vhir.ingest_audit_id`, and `pipeline_version`
  (`packages/opensearch-mcp/src/opensearch_mcp/parse_json.py:135-244`).
- Delimited ingest stamps timestamp, deterministic document ID, host fields,
  `vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`, and
  `pipeline_version`
  (`packages/opensearch-mcp/src/opensearch_mcp/parse_delimited.py:169-280`).
- Memory ingest stamps `@timestamp`, host fields, `vhir.source_file`,
  `vhir.parse_method`, `vhir.ingest_audit_id`, and `pipeline_version`
  (`packages/opensearch-mcp/src/opensearch_mcp/parse_memory.py:270-325`).
- Plaso and W3C ingest paths stamp similar `vhir` provenance and
  `pipeline_version` fields
  (`packages/opensearch-mcp/src/opensearch_mcp/parse_plaso.py:72-139`,
  `packages/opensearch-mcp/src/opensearch_mcp/parse_w3c.py:24-176`).
- Mapping templates use `case-*` index patterns and define common fields such
  as `@timestamp`, `host.name`, `host.id`, `vhir.source_file`,
  `vhir.ingest_audit_id`, `vhir.parse_method`, optional `vhir.vss_id`, and
  `pipeline_version`
  (`packages/opensearch-mcp/src/opensearch_mcp/mappings/evtx_ecs_template.json:2-45`,
  `packages/opensearch-mcp/src/opensearch_mcp/mappings/csv_template.json:2-42`,
  `packages/opensearch-mcp/src/opensearch_mcp/mappings/json_template.json:2-22`,
  `packages/opensearch-mcp/src/opensearch_mcp/mappings/vol3_template.json:2-82`).
- Template installation is centralized in
  `packages/opensearch-mcp/src/opensearch_mcp/mappings/__init__.py`, where the
  package declares non-EVTX templates and installs component and index templates
  (`packages/opensearch-mcp/src/opensearch_mcp/mappings/__init__.py:52-176`).

Current conclusion: provenance exists, but it is parser/audit oriented. It does
not yet provide a full control-plane link to `case_id`, `evidence_id`, `job_id`,
`job_step_id`, `parser_run_id`, `parser_name`, `parser_version`,
`schema_version`, and indexing batch state on every document.

### Current gateway exposure

- Gateway builds a backend map from configured backends and skips disabled
  backends (`packages/sift-gateway/src/sift_gateway/server.py:133-175`).
- Gateway evaluates backend manifest requirements such as host/port or URL
  availability and gates manifest tools if requirements are unmet
  (`packages/sift-gateway/src/sift_gateway/server.py:260-330`,
  `packages/sift-gateway/src/sift_gateway/server.py:376-391`).
- `list_tools()` returns core tools plus currently mapped add-on tools
  (`packages/sift-gateway/src/sift_gateway/server.py:649-653`).
- The aggregate MCP endpoint wraps Gateway calls with authentication, evidence
  gating, response guards, and a transport audit envelope
  (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:624-872`).
- Gateway also mounts per-backend MCP routes for each configured backend
  (`packages/sift-gateway/src/sift_gateway/server.py:840-864`,
  `packages/sift-gateway/src/sift_gateway/server.py:971-973`).
- The per-backend MCP route calls one backend directly through
  `create_backend_mcp_server()`, with a simpler policy surface than the
  aggregate endpoint
  (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:876-977`).
- Gateway health reports `degraded` when any configured backend health check is
  not ok, and includes backend health details
  (`packages/sift-gateway/src/sift_gateway/health.py:16-67`).
- REST backend listing exposes backend status, requirement status, and tool
  counts (`packages/sift-gateway/src/sift_gateway/rest.py:296-363`).

Current conclusion: the Gateway can expose OpenSearch as an add-on when
available, and can hide or degrade it when requirements are unmet. The target
architecture needs an explicit OpenSearch policy boundary instead of
availability-driven optional exposure.

### Current direct callers and non-callers

Components that currently call OpenSearch directly or launch OpenSearch work:

- `opensearch_mcp.server` obtains clients through `_get_os()` and implements the
  search, status, ingest, enrichment, and maintenance MCP tools
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:411-452`).
- `opensearch_mcp.ingest_cli` resolves cases and runs scan, CSV, JSON,
  delimited, access log, enrichment, and memory ingest commands from the CLI
  (`packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`,
  symbols `cmd_scan`, `cmd_csv`, `cmd_ingest`, `cmd_ingest_json`,
  `cmd_ingest_delimited`, `cmd_ingest_accesslog`, `cmd_enrich_intel`,
  `cmd_ingest_memory`).
- Parser modules receive OpenSearch clients and write bulk actions directly to
  OpenSearch (`parse_evtx.py`, `parse_csv.py`, `parse_json.py`,
  `parse_delimited.py`, `parse_memory.py`, `parse_plaso.py`, `parse_w3c.py`).
- Some OpenSearch package code calls back to the Gateway through
  `opensearch_mcp.gateway.call_tool()`, which loads a raw token from
  `~/.sift/gateway.yaml` and posts to `/api/v1/tools/{tool_name}`
  (`packages/opensearch-mcp/src/opensearch_mcp/gateway.py:17-105`).

Components that do not yet treat OpenSearch as core authority or core search:

- Core SIFT tools use `CaseManager`, local JSON files, evidence chain helpers,
  and reporting helpers rather than core OpenSearch search tools
  (`packages/sift-core/src/sift_core/agent_tools.py:91-281`,
  `packages/sift-core/src/sift_core/case_manager.py:1508-1552`).
- Case timeline and IOC state still load from `timeline.json` and `iocs.json`
  (`packages/sift-core/src/sift_core/case_io.py:270-320`,
  `packages/sift-core/src/sift_core/case_manager.py:1904-2017`).
- Dashboard REST routes for findings, timeline, and IOCs read case JSON files
  rather than OpenSearch
  (`packages/case-dashboard/src/case_dashboard/routes.py:1624-1673`,
  `packages/case-dashboard/src/case_dashboard/routes.py:2147-2200`).
- Frontend endpoints poll Gateway/dashboard API routes such as `/api/timeline`
  and `/api/iocs`, not OpenSearch directly
  (`packages/case-dashboard/frontend/src/api/endpoints.js:20-30`,
  `packages/case-dashboard/frontend/src/api/endpoints.js:70-77`,
  `packages/case-dashboard/frontend/src/hooks/useDataPolling.js:16-43`).

Current conclusion: OpenSearch is isolated in the add-on package and parser
pipeline. The core Gateway/SIFT/frontend control plane does not yet use
OpenSearch as a first-class, case-scoped search/data service.

## 3. Current weaknesses and risks

| Risk | Current cause from code | Impact | Target control | Priority |
| --- | --- | --- | --- | --- |
| OpenSearch is optional/standalone rather than core. | OpenSearch is an optional `standard` extra and add-on backend (`pyproject.toml:41-46`, `packages/opensearch-mcp/sift-backend.json:1-13`). | Search availability and tool visibility depend on backend availability rather than explicit platform state. | Promote OpenSearch access into core Gateway/SIFT search services while preserving additive compatibility. | P0 |
| OpenSearch tools may not be consistently case-scoped. | `_resolve_index()` uses explicit `index` first, then active case, then `case-*` (`packages/opensearch-mcp/src/opensearch_mcp/server.py:564-573`). `opensearch_ingest_status(case_id="*")` can list all cases (`packages/opensearch-mcp/src/opensearch_mcp/server.py:2373-2397`). | Cross-case discovery or accidental broad queries are possible for capable tokens. | Resolve case from authenticated token/session context and enforce authorized case before query or status lookup. | P0 |
| OpenSearch may not be tied to Postgres/Supabase authorization. | Current case context comes from `SIFT_CASE_DIR` or `~/.sift/active_case` (`packages/opensearch-mcp/src/opensearch_mcp/server.py:3504-3527`), while Gateway identity has no case-scope fields today (`packages/sift-gateway/src/sift_gateway/identity.py:5-66`). | A process-local active case can diverge from the authenticated user's permitted cases. | Store case membership and token scopes in Postgres; Gateway validates them before OpenSearch use. | P0 |
| OpenSearch ingest/status can drift from case authority. | Status is stored in `~/.sift/ingest-status` JSON files and process state (`packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:13-148`). | Jobs can be lost, stale, duplicated, or invisible to authoritative state. | Use DB-backed jobs, job steps, parser runs, parser outputs, and indexing status. | P0 |
| Parser/indexing provenance may be incomplete. | Current parser provenance uses `vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`, and `pipeline_version`, but not a complete DB identity set (`parse_evtx.py:114-123`, `parse_json.py:224-230`). | Documents may be hard to trace to evidence, jobs, parser runs, and reports. | Require document metadata linking every document to case, evidence, job, parser run, source hash, schema version, and indexing batch. | P0 |
| OpenSearch document metadata may not link back to evidence/job/parser state. | Ingest manifests are filesystem JSON files (`packages/opensearch-mcp/src/opensearch_mcp/ingest.py:29-95`), and job/parser concepts are not represented as durable DB IDs. | Reindex, audit, report evidence lookup, and deletion are fragile. | Add control-plane IDs to indexed docs and register index/doc batches in Postgres. | P0 |
| Cross-case search risk. | `_validate_index()` only checks the `case-` prefix, not the authenticated caller's authorized case (`packages/opensearch-mcp/src/opensearch_mcp/server.py:32-45`). | A wildcard like `case-*` can search across cases if allowed through a tool path. | Prohibit raw index input for normal tools; use aliases resolved from authorized case context. | P0 |
| Degraded mode may be unclear when OpenSearch is down. | Gateway can hide/gate add-on tools based on manifest requirements (`packages/sift-gateway/src/sift_gateway/server.py:376-391`) and health becomes `degraded` generically (`packages/sift-gateway/src/sift_gateway/health.py:16-67`). | Operators may see missing tools rather than an explicit search/indexing degradation reason. | Add explicit OpenSearch status in Gateway health, frontend status views, and MCP structured errors. | P1 |
| MCP Gateway may expose OpenSearch based on availability instead of target policy. | Backend requirements are evaluated from manifest `requires`, and tools are registered from backend availability (`packages/sift-gateway/src/sift_gateway/server.py:260-330`, `packages/sift-gateway/src/sift_gateway/server.py:376-504`). | A policy-critical core service behaves like a plugin. | Treat OpenSearch as a core dependency with degraded-mode policy, not an opportunistic add-on. Per-backend `/mcp/{name}` routes are **disabled** (D3); all OpenSearch tool calls use the single aggregate Gateway policy path. | P1 |
| Frontend search/timeline behavior may depend on backend assumptions rather than explicit control-plane state. | Timeline and IOC endpoints currently read JSON files, while OpenSearch search is separate (`packages/case-dashboard/src/case_dashboard/routes.py:1660-1673`, `packages/case-dashboard/src/case_dashboard/routes.py:2147-2161`). | UI may present stale or incomplete search/indexing state. | Frontend should combine authorized control-plane reads with Gateway-mediated search results and explicit index status. | P1 |
| Per-backend MCP routes may bypass aggregate endpoint controls. | Aggregate MCP applies evidence gates and transport audit (`mcp_endpoint.py:624-872`); per-backend route directly calls one backend (`mcp_endpoint.py:876-977`). | Add-on OpenSearch tools can have a different policy/audit surface than aggregate tools. | Restrict or deprecate per-backend OpenSearch exposure; enforce identical policy for all OpenSearch paths. | P1 |
| OpenSearch versions/config may diverge. | Root compose uses 2.18.0 with security disabled (`docker-compose.yml:1-35`); package compose uses 3.5.0 and `SIFT_OS_PASSWORD` (`packages/opensearch-mcp/docker/docker-compose.yml:1-17`). | Mappings, APIs, security, and demo setup can behave differently. | **Locked (D6): canonical profile is OpenSearch 3.5.0 with security enabled.** The root 2.18.0/security-disabled compose is pre-migration only and must be aligned to the target as a scoped implementation task. | P1 |

## 4. Target responsibility boundary

### Postgres/Supabase owns

- Cases.
- Active case state, with explicit precedence for user session, token context,
  and Gateway process defaults.
- Case members and operator authorization.
- Agents.
- MCP/service token registry, including hashes, expiry, revocation, allowed
  cases, and allowed scopes.
- Evidence metadata.
- Evidence integrity status.
- Audit events.
- Approvals.
- Findings review state.
- Reports metadata.
- Jobs.
- Job steps.
- Job logs.
- Parser runs.
- Parser outputs metadata.
- OpenSearch index registry.
- OpenSearch indexing status.

Postgres/Supabase is the source of truth for what exists, who may access it,
what has run, what has been approved, what has been indexed, and what must be
reindexed.

### OpenSearch owns

- Parsed artifact documents.
- Normalized timeline records.
- IOCs derived from approved or indexed forensic content.
- Searchable forensic records.
- Full-text search.
- Optional semantic/vector search.
- Query-time aggregations over indexed forensic data.

OpenSearch owns query acceleration and derived search representations. It does
not own case state, authorization, evidence truth, job truth, approval truth, or
audit truth.

### Evidence Vault owns

- Immutable raw evidence files.
- Immutable evidence paths or blobs.
- Hash-addressed or hash-verified raw evidence storage.

The Evidence Vault remains the place from which parser input can be verified and
replayed. OpenSearch documents point back to evidence-vault identities; they do
not replace raw evidence.

### Gateway owns

- Authentication enforcement.
- MCP/service token validation.
- Case-scope enforcement.
- Tool-scope enforcement.
- OpenSearch query mediation.
- Audit event creation for API/MCP activity.
- API and MCP routing.

The Gateway is the mandatory policy boundary for OpenSearch search, aggregate,
document lookup, and indexing-control APIs.

### Workers own

- Running parsers.
- Normalizing artifacts.
- Indexing into OpenSearch.
- Updating Postgres job, job-step, parser-run, parser-output, and indexing
  state.
- Writing audit events for execution milestones.

Workers can write to OpenSearch, but only as part of claimed DB-backed jobs and
with DB-backed parser/indexing state.

## 5. Required OpenSearch document metadata

Every indexed document should eventually include the fields below. Fields may be
null only when explicitly not applicable and when the control-plane record
documents why they are not applicable.

| Field | Required purpose |
| --- | --- |
| `case_id` | Enforces case isolation, enables case deletion/reindex, and lets every document be tied back to the authoritative case. Current index names contain case identity, but current document bodies do not consistently include `case_id`. |
| `evidence_id` | Links the document to authoritative evidence metadata and integrity state. Required for finding evidence lookup, report evidence lookup, and re-parsing from the original evidence. |
| `job_id` | Links the document to the durable job that caused indexing. Required for retry, cancellation, operator status, and audit reconstruction. |
| `job_step_id` | Links the document to the parser/indexing step where applicable. Required when one job has multiple parser/indexing phases. |
| `parser_run_id` | Links documents to one parser execution attempt. Required for parser version comparison, partial failure handling, and replay. |
| `parser_name` | Identifies the parser family, such as EVTX, Volatility, CSV, JSON, W3C, plaso, or Hayabusa. Required for filtering, dashboards, and parser-specific reindexing. |
| `parser_version` | Identifies parser code or tool version. Required for reproducibility and deciding which documents need reindex after parser changes. |
| `source_path` or source logical reference | Links the document to the evidence-vault path, object key, or logical source. Required for examiner traceability and report generation. |
| `source_hash` | Records the hash of the raw input or source chunk when available. Required to prove the indexed document came from verified evidence and to detect drift. |
| `artifact_type` | Normalizes index/query behavior across current artifact-specific indices. Required for filtering and mapping selection. |
| `timestamp` | For temporal artifacts, provides the event time used in timeline search. Must distinguish event time from ingest/index time. |
| `indexed_at` | Records when the document was written to OpenSearch. Required for stale-index detection and operational dashboards. |
| `schema_version` | Identifies the document contract and mapping version. Required for safe migration and reindexing. |
| `ingest_batch_id` | Groups bulk-index operations. Required for partial failure recovery, duplicate avoidance, and batch-level audit. |
| tenant/case routing field if needed | Supports routing, shard strategy, and future multi-tenant deployment. For this repo it can initially be the same as `case_id`. |
| visibility/sensitivity marker if needed | Allows restricted documents, privileged artifacts, or legal-hold flags without inventing a separate authorization model later. |

The current parser code already stamps useful fields such as `host.name`,
`host.id`, `vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`,
optional `vhir.vss_id`, and `pipeline_version` across multiple parsers
(`parse_evtx.py:114-123`, `parse_csv.py:183-191`,
`parse_json.py:224-230`, `parse_memory.py:291-312`). The target metadata
contract should preserve those fields where useful, but add explicit
control-plane IDs and versioned schema fields.

## 6. Index strategy

### Option A - per-case indexes

Example target indexes:

- `dfir-case-{case_id}-artifacts-v{schema_version}`
- `dfir-case-{case_id}-timeline-v{schema_version}`
- `dfir-case-{case_id}-iocs-v{schema_version}`

| Dimension | Evaluation |
| --- | --- |
| Case isolation | Strong. Index names and aliases are case-specific, matching the current case-prefixed model. Accidental cross-case query is easier to prevent. |
| Query simplicity | Simple for single-case workflows because the Gateway resolves one case alias and still adds a `case_id` filter. Multi-case search requires explicit privileged fan-out. |
| Operational overhead | More indexes and aliases, especially for many small cases. Shard sizing must be conservative. |
| Mapping/schema management | Manageable if templates are versioned and shared across case indexes. |
| Cleanup/deletion | Straightforward. Retire aliases and delete one case's indexes after authorization and retention checks. |
| Reindexing | Straightforward per case and per schema version. New `vN` index can be built beside old `vN-1`, then aliases can switch. |
| Dashboard performance | Good for normal case dashboards because searches hit only case-specific indexes. |
| Hackathon/prototype suitability | Best fit. The current implementation already uses `case-{case_id}-{artifact_type}-{hostname}` (`packages/opensearch-mcp/src/opensearch_mcp/paths.py:201-207`, `packages/opensearch-mcp/README.md:164-174`) and current query resolution already uses `case-{case_id}-*` (`packages/opensearch-mcp/src/opensearch_mcp/server.py:564-573`). |
| Serious DFIR platform suitability | Suitable for workstation/local and moderate case counts. At higher scale it may need shard controls, rollover, or a shared-index strategy for dense multi-tenant deployments. |

### Option B - shared indexes with mandatory `case_id` filters

Example target indexes:

- `dfir-artifacts-v{schema_version}`
- `dfir-timeline-v{schema_version}`
- `dfir-iocs-v{schema_version}`

| Dimension | Evaluation |
| --- | --- |
| Case isolation | Depends on mandatory filters, query builders, and possibly OpenSearch document-level security. A missing filter becomes a cross-case incident. |
| Query simplicity | Simple for multi-case analytics, but every normal query must add and test `case_id` filters. |
| Operational overhead | Fewer indexes and easier shard management. |
| Mapping/schema management | Centralized mappings per logical document family. |
| Cleanup/deletion | Requires delete-by-query or tombstone/reindex workflows per case, which must be carefully audited. |
| Reindexing | Efficient for global schema migrations but more complex for one-case rollback. |
| Dashboard performance | Good when data volume is moderate and routing is configured. Can degrade if case filters fan across large shared shards. |
| Hackathon/prototype suitability | Riskier because it requires strong case-filter discipline that the current code does not yet have. |
| Serious DFIR platform suitability | Attractive for large managed deployments once token scopes, query builders, routing, tests, and operational controls are mature. |

### Recommendation

Use Option A, per-case logical indexes, as the initial project strategy.

This is the lowest-risk migration path because the current implementation is
already organized around case-prefixed index names. `build_index_name()` returns
`case-{case_id}-{artifact_type}-{hostname}`
(`packages/opensearch-mcp/src/opensearch_mcp/paths.py:201-207`), the README
documents the same shape (`packages/opensearch-mcp/README.md:164-174`), and the
current query resolver defaults to `case-{case_id}-*`
(`packages/opensearch-mcp/src/opensearch_mcp/server.py:564-573`). Starting with
per-case indexes lets the migration add Gateway-enforced case aliases and
Postgres index registration without immediately redesigning every parser.

**v1 decision (locked, D18): reuse the existing naming.** Keep
`case-{case_id}-{artifact_type}-{hostname}` as the concrete index name in v1. It
is already case-prefixed, already backed by installed index templates that
auto-create the index on first bulk write, and already produced by the single
`build_index_name()` helper. The control plane **registers** each such index in
`opensearch_indexes` (with `logical_kind` classifying it, e.g. `evtx`,
`hayabusa`, `csv`, `timeline`, `iocs`) rather than renaming it. This adds
Postgres registration, Gateway-enforced case scope, and per-document
control-plane provenance **without redesigning any parser**.

**Deferred, optional evolution (not required for v1):** collapsing
`artifact_type`/`hostname` into document fields under logical document-family
indexes:

- Artifacts: `dfir-case-{case_id}-artifacts-v{schema_version}`
- Timeline: `dfir-case-{case_id}-timeline-v{schema_version}`
- IOCs: `dfir-case-{case_id}-iocs-v{schema_version}`

This rename can be introduced later behind read/write aliases and the
`opensearch_indexes` registry, building `vN` beside `vN-1` and switching aliases,
without breaking the v1 indexes. It is an optimization, not a prerequisite.

### Aliases

> The `### Aliases`, `### Schema versioning`, `### Mapping templates`, and
> `### Migration and reindexing` subsections below describe the **deferred,
> optional** logical-family evolution (D18). They are NOT v1 work. In v1, the
> Gateway resolves the concrete registered `case-{case}-{type}-{host}` index from
> `opensearch_indexes` for the authorized case; aliases are nullable and unused.

Each case should have control-plane-registered aliases:

- `dfir-case-{case_id}-artifacts-read`
- `dfir-case-{case_id}-artifacts-write`
- `dfir-case-{case_id}-timeline-read`
- `dfir-case-{case_id}-timeline-write`
- `dfir-case-{case_id}-iocs-read`
- `dfir-case-{case_id}-iocs-write`
- Optional: `dfir-case-{case_id}-all-read`

Gateway search tools should use aliases resolved from Postgres
`opensearch_indexes` state, not caller-provided index strings.

### Schema versioning

- Include `schema_version` in every document.
- Include `v{schema_version}` in concrete index names.
- Use read/write aliases to switch between versions.
- Store the active schema version per logical index family in Postgres.
- Preserve current `pipeline_version` as parser/pipeline provenance, but do not
  use it as a substitute for the OpenSearch document schema version.

### Mapping templates

- Keep shared component templates for common metadata fields.
- Add versioned logical templates such as:
  - `sift-dfir-artifacts-v1`
  - `sift-dfir-timeline-v1`
  - `sift-dfir-iocs-v1`
- Preserve parser-specific templates or dynamic templates only where needed for
  high-cardinality forensic fields.
- Add explicit mapping tests for required metadata fields and query fields.

### Migration and reindexing

1. Register current `case-*` indexes in Postgres as legacy indexes.
2. Add new write aliases for a selected case and schema version.
3. Update one parser/indexing path to write target metadata to new indexes.
4. Build a reindex worker that reads legacy `case-*` indexes or parser outputs,
   writes `dfir-case-*` indexes, and records batch status in Postgres.
5. Validate document counts, source hashes, parser-run links, and audit links.
6. Switch read aliases for the case.
7. Keep legacy indexes read-only until rollback window expires.
8. Retire legacy indexes through an audited Postgres state change.

### `opensearch_indexes` domain

Postgres should record OpenSearch indexes through an `opensearch_indexes`
domain/table. Initial fields should include:

- `id`
- `case_id`
- `logical_kind` such as `artifacts`, `timeline`, or `iocs`
- `index_name`
- `read_alias`
- `write_alias`
- `schema_version`
- `mapping_template`
- `status` such as `planned`, `creating`, `ready`, `degraded`, `reindexing`,
  `retired`, or `failed`
- `created_at`
- `updated_at`
- `retired_at`
- `last_indexed_at`
- `doc_count`
- `last_health_status`
- optional `created_by_job_id`
- optional `active_parser_run_id`

The table is a control-plane registry. OpenSearch still stores documents, but
Postgres decides which indexes are valid for a case and what health/status they
have.

## 7. OpenSearch integration with core SIFT MCP

OpenSearch tools should become core SIFT MCP tools, not optional add-on tools.
They should be exposed from the core namespace and mediated by Gateway policy.

Normal MCP clients should not pass arbitrary `case_id`. The default case context
must come from token/session context and Postgres authorization, not from
`SIFT_CASE_DIR`, process environment, or `~/.sift/active_case`. A privileged
operator token may request a different case only if the Gateway verifies that
scope.

Raw OpenSearch Query DSL should not be exposed to normal agent tokens. Normal
tokens get constrained inputs: query text, time ranges, artifact types, fields,
limits, sort choices, and aggregations from an allowlist.

| Tool | Purpose | Required scope | Required case context | Allowed inputs | Forbidden inputs | Control-plane lookup before query | Audit event | Degraded-mode behavior |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `timeline.search` | Search normalized timeline records for the authorized case. | `search:timeline:read` | Authorized case from token/session. | query text, time range, host, artifact type, event category, pagination, sort allowlist. | arbitrary index, raw DSL, unaudited `case_id`, wildcard case. | Verify token case access; load case timeline read alias and index status. | `opensearch.timeline.search` with query summary, filters, result count, case, token identity. | Return structured `degraded` error if no ready timeline index or OpenSearch is down. |
| `artifact.search` | Search forensic artifacts and parsed records. | `search:artifact:read` | Authorized case from token/session. | query text, artifact type allowlist, host, source evidence ID, time range, fields allowlist, pagination. | arbitrary index, raw DSL, cross-case index pattern, unrestricted field selection. | Verify case access; load artifact index alias; optionally verify evidence filter belongs to case. | `opensearch.artifact.search`. | Return degraded error with control-plane index status. |
| `ioc.search` | Search IOCs indexed for the case. | `search:ioc:read` | Authorized case from token/session. | IOC value, type, confidence/severity filters, related finding/evidence filters, pagination. | raw DSL, arbitrary case, arbitrary index. | Verify case access; load IOC index alias; check IOC index status. | `opensearch.ioc.search`. | Return degraded error or empty indexed-state response if IOC index not built. |
| `opensearch.health` | Report OpenSearch and index health. | `opensearch:health:read` | Optional case context; global health requires operator/admin scope. | case-local health, include index registry flag, include shard summary flag. | raw cluster admin API passthrough for normal tokens. | Verify caller role; for case health, load only authorized case indexes. | `opensearch.health.read`. | Always returns structured status: `ok`, `degraded`, `unavailable`, or `not_configured`. |
| `opensearch.case_indexes` | List registered OpenSearch indexes for an authorized case. | `opensearch:indexes:read` | Authorized case from token/session. | logical kind, status filter. | arbitrary case unless privileged; raw index wildcard. | Verify case access; read `opensearch_indexes` rows. | `opensearch.case_indexes.read`. | Return DB registry state even if OpenSearch is down, with health marked stale/degraded. |
| `opensearch.explain_document` | Explain provenance for one indexed document. | `search:document:read` | Authorized case from token/session. | document ID, logical kind, optional evidence/job/parser detail flags. | arbitrary index, cross-case document lookup. | Verify case access; resolve index alias; join document metadata to evidence/job/parser/audit records. | `opensearch.document.explain`. | If OpenSearch is down, return DB-known provenance if available and mark document lookup degraded. |
| `opensearch.get_artifact` | Fetch one artifact document by ID for an authorized case. | `search:artifact:read` | Authorized case from token/session. | document ID, logical kind/artifact type, include source metadata flag. | arbitrary index, raw `_source` include/exclude for restricted fields. | Verify case access; resolve alias; verify visibility/sensitivity policy. | `opensearch.artifact.get`. | Structured degraded error if document lookup cannot reach OpenSearch. |
| `opensearch.aggregate` | Run constrained aggregations for dashboards and analysis. | `search:aggregate:read` | Authorized case from token/session. | aggregation type allowlist, field allowlist, time range, artifact kind. | raw aggregation DSL, arbitrary fields, arbitrary index, cross-case wildcard. | Verify case access; load alias; validate requested fields against mapping policy. | `opensearch.aggregate`. | Structured degraded error; frontend may fall back to DB counts where available. |

Gateway enforcement requirements:

- Gateway must resolve the allowed case from Postgres token/session state before
  calling any OpenSearch service.
- Gateway must reject caller-provided `case_id` unless the identity has a
  specific multi-case or case-switch scope.
- Gateway must never pass normal caller-provided OpenSearch index names through
  to OpenSearch.
- Gateway must add a case filter to every query even when using per-case aliases.
- Gateway must emit audit events for every query and document fetch, including
  identity, case, tool, filters, alias/index ID, result count, status, and
  degraded-mode reason when applicable.
- Agents must not bypass Gateway policy by using the standalone OpenSearch MCP
  backend or direct OpenSearch HTTP access.

## 7A. OpenSearch write contract for all writers (core + addon + enrichment)

This section locks the spec the migration needs so that the **existing working
ingestion model is reused** and **future addon backends** (e.g. an OpenCTI
enrichment that writes back, a Hayabusa autodetection addon, or any future addon)
can write to OpenSearch **without a full refactor**, while still respecting the
control-plane requirements (D18).

### Confirmed current mechanics (reused as-is)

These are confirmed from code and are the foundation v1 builds on:

- **Index naming**: one helper, `build_index_name(case_id, artifact_type,
  hostname) -> case-{case}-{type}-{host}`, fully sanitized/lowercased
  (`packages/opensearch-mcp/src/opensearch_mcp/paths.py:194-220`). Every ingest
  path uses it (`ingest.py`, `ingest_cli.py`, `parse_memory.py`, `server.py`).
- **Index creation is implicit**: indices are auto-created on first bulk write,
  governed by **index templates** matching `case-*-{type}-*` that are installed
  idempotently at server first-connection and ingest pre-flight
  (`mappings/__init__.py:install_all_templates` + `ensure_winlog_pipeline`; 14
  registered templates + a winlog normalize pipeline). No explicit create call.
- **Single shared writer**: `flush_bulk()` with persistent retry, batch
  splitting, a systemic-failure circuit breaker, and deterministic `_id`s for
  safe re-ingest dedup (`bulk.py`).
- **Host auto-discovery preflight**: `host_discovery.discover_hosts()` runs once
  per ingest, sourcing hostnames from the SYSTEM hive
  (`hostname.detect_hostname_from_volume`), Velociraptor, path patterns, content
  peek (`hostname.peek_hostname_from_evidence`), and EVTX `Computer` sampling,
  building a per-case host dictionary; parsers resolve `host.id` from it at parse
  time. Archive basenames are never used as `host.name`.
- **Provenance stamping**: parsers stamp `host.name`, `host.id`, and `vhir.*`
  (`vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`, optional
  `vhir.vss_id`, `vhir.table`) plus `pipeline_version`, with dedup `_id` computed
  before provenance is added so it stays stable across re-ingests (e.g.
  `parse_csv.py:160-193`).
- **In-place enrichment**: enrichers mutate existing `case-*` docs via
  `client.update_by_query(...)` (`threat_intel.py:570`, `triage_remote.py`,
  `server.py:3904`) rather than creating indices.
- **Today only `opensearch-mcp` writes to OpenSearch.** OpenCTI, windows-triage,
  forensic-mcp, and forensic-rag do not write to OpenSearch in the current code;
  the contract below is what *future* writers must follow.

### Two write modes

1. **Document ingestion** - a parser/worker produces normalized documents and
   bulk-writes them to a `case-{case}-{type}-{host}` index. New artifact types
   create a new index implicitly via template match.
2. **In-place enrichment** - an enricher adds fields to existing case documents
   via `update_by_query`, keyed on a case-scoped query. It must not create
   uncontrolled new indices and must not rewrite the original parsed fields'
   meaning.

### Mandatory write contract (all writers, both modes)

Every writer - the core worker, an addon MCP backend, or an enrichment - must:

1. **Take `case_id` from job / active-case context, never invent it.** Workers
   inherit `case_id` from the claimed job; addon enrichments inherit it from the
   Gateway-issued, case-scoped invocation. No writer derives case scope from a
   raw argument, `SIFT_CASE_DIR`, or `~/.sift/active_case` as authority.
2. **Name indices only via `build_index_name()`** (or the registered alias for a
   logical-family index, when that optional evolution lands). No ad-hoc or
   cross-case index names; no `case-*` wildcard writes.
3. **Stamp the provenance/metadata contract on every document** it creates:
   the existing `host.*`, `vhir.*`, `pipeline_version` fields **plus** the
   control-plane IDs (`case_id`, `job_id`, `job_step_id`, `parser_run_id`,
   `parser_name`, `parser_version`, `source_hash`, `indexed_at`,
   `schema_version`, `ingest_batch_id`). Reuse `flush_bulk()` so retry/dedup/
   circuit-breaker behavior is consistent.
4. **Register the index and the indexing batch in the control plane** before/
   after writing: an `opensearch_indexes` row (discovery/registration of the
   concrete `case-{case}-{type}-{host}` name with a `logical_kind`) and an
   `opensearch_indexing_status`/`ingest_batches` row with counts and status
   (`08_control_plane_schema.md` §9). This is how Postgres stays authoritative
   for "what was indexed" while documents live in OpenSearch.
5. **Enrichment writers additionally** scope every `update_by_query` to the
   authorized case (no `case-*` fan-out), stamp enrichment provenance
   (`enrichment.<name>`, enricher version, intel/source reference, `job_id`,
   `enriched_at`) on the fields they add, and never mutate the original parsed
   fields' values or the dedup `_id`.
6. **Audit** the indexing/enrichment batch (alias/index, counts, failures,
   schema version, parser/enricher run) per the job model.

### How addons conform without a refactor

Addon backends keep their own client, tools, and parsing logic. Conformance is
**additive**, delivered as a thin shared adapter/SDK (a small importable module,
not a rewrite):

- The adapter exposes `build_index_name()`, the provenance-stamping helper, the
  `flush_bulk()` writer, and `register_index()` / `record_indexing_batch()` /
  `record_enrichment()` calls against the control plane.
- An addon ingests by: receiving `case_id` + job context from the Gateway-issued
  invocation, building the index name via the helper, stamping provenance, writing
  via `flush_bulk`, and registering the batch. Its internal parsing is untouched.
- An addon enriches by: scoping `update_by_query` to the case, stamping
  `enrichment.<name>` provenance, and recording the enrichment batch.
- If an addon cannot yet register batches, it still must use the index-naming
  helper and provenance contract; registration can be backfilled by a discovery
  sweep (`opensearch.case_indexes` discovery) until the addon adopts the adapter.

### Gateway-only reconciliation (important)

The Gateway-only rule (D2/D3) governs the **control/tool-call boundary**: no
operator or agent reaches OpenSearch except through Gateway-mediated, case-scoped
tools; per-backend `/mcp/{name}` routes are disabled; raw DSL/index names are
admin-only. It does **not** require funneling every bulk write through the
Gateway HTTP path. **Execution-plane writes** (a worker or an addon enrichment
running under an authorized, case-scoped job) write to OpenSearch directly with a
service credential, bound by this contract. This preserves the existing working
ingestion performance and the addon backends while keeping case scope,
provenance, and registration authoritative in the control plane.

## 7B. OpenSearch as a core service + cluster cohabitation with OpenCTI

### OpenSearch is core, not an add-on (D19)

OpenSearch is promoted from an optional add-on backend to a **core service**:

- Read tools (`search`, `status`, `aggregate`, `timeline`, `field_values`,
  `case_summary`, document/explain) are exposed as in-process **core SIFT MCP
  tools**, served synchronously through the single aggregate Gateway policy path
  (case-scoped, audited, evidence-gated). They are no longer registered through
  the add-on manifest path.
- Long-running tools (`ingest`, enrichment batches, reindex) are core tools that
  **enqueue durable jobs**; the worker (which imports the `opensearch-mcp` ingest/
  enrichment code) runs them. Nothing long-running runs inside the Gateway
  request path.
- The standalone stdio/http server and the OpenSearch add-on **manifest
  registration** are retired. The `opensearch-mcp` **package remains** as the
  in-process implementation imported by the Gateway (read tools) and the worker
  (ingest/enrichment). This is a packaging/exposure change, not a rewrite.
- Call-path note: the control plane is **consulted and written** for authz, case
  scope, evidence gate, audit, and job state - it is not a data-path proxy that
  MCP payloads flow through. Synchronous reads return through the Gateway;
  long-running work returns a `job_id`.

### Cluster cohabitation with OpenCTI (D20/D21)

OpenCTI runs as the **full platform** (platform, worker, redis, rabbitmq, minio)
but uses the **existing SIFT OpenSearch cluster** as its index store instead of a
second cluster. `opencti-mcp` stays a **query-only** API client to the OpenCTI
platform (`OpenCTIClient`, circuit breaker, TTL cache) - the agent never queries
OpenCTI's OpenSearch indices directly; the path is `Gateway -> opencti-mcp ->
OpenCTI API -> OpenCTI's own indices`.

The shared cluster therefore hosts **two index classes**:

| Index class | Pattern | Owner / writer | Scope | Lifecycle | Agent access |
| --- | --- | --- | --- | --- | --- |
| SIFT case indices | `case-{case}-{type}-{host}` | SIFT worker/enrichment (§7A contract) | Case-scoped, evidence-derived | Tied to case lifecycle | Only via Gateway case-scoped tools |
| OpenCTI platform indices | `opencti_*` (OpenCTI-managed) | OpenCTI platform + connectors (MITRE/CVE/...) | Global reference data | Persistent, not tied to any case | Never directly; only via `opencti-mcp` query tools |

Governance rules (locked):

- **Per-consumer OpenSearch security roles** (OpenSearch 3.5.0 security is on):
  - SIFT worker/service user -> read/write `case-*` only.
  - OpenCTI user -> read/write `opencti_*` only.
  - The **AI agent gets no cluster credentials at all**; it reaches OpenSearch
    only through Gateway-mediated, case-scoped tools.
  This role split is the real isolation boundary: OpenCTI cannot read case
  evidence and case-search cannot read CTI. The existing `_validate_index`
  (`case-*` only) already keeps agent case-search off `opencti_*`.
- **Capacity**: OpenCTI's reference indices add real shard/volume load to the
  shared single-VM cluster. `shard_capacity`/`opensearch_shard_status`
  monitoring must account for both classes; the portal surfaces combined cluster
  health.
- **OpenCTI internals are exempt from "No Redis/RQ"**: that rule governs SIFT
  durable-job authority (Postgres) only. OpenCTI's internal redis/rabbitmq/minio
  are third-party platform internals.
- **Reference-data population** (connectors) is OpenCTI-managed and runs outside
  the SIFT job/worker model. It is not a SIFT parser run and does not register in
  `opensearch_indexes` (which is case-scoped). Cohabitation is by isolation
  (roles + naming), not by SIFT-side registration of OpenCTI indices.

### Portal OpenSearch monitoring/management

The operator portal monitors and operates OpenSearch through Gateway REST:
cluster health (`GET /api/system/opensearch/health`), per-case index status, and
ingest via the job APIs. Diagnostics are surfaced read-only; actual remediation
(restart docker, raise `cluster.max_shards_per_node`, fix host) is an operator
action on the SIFT VM, optionally guided by the existing `opensearch_host_fix`
diagnostic. The portal does not perform privileged VM-level fixes itself.

## 8. OpenSearch integration with Gateway APIs and frontend

The target REST/WebSocket/SSE layer should expose case-scoped search behavior
through the Gateway, while the frontend reads authoritative state either through
Gateway APIs or authorized Supabase reads. The frontend must not become the
authority for forensic state and must not talk to OpenSearch directly.

### Target APIs

- Timeline search API:
  - Example target shape: `GET /api/cases/{case_ref}/search/timeline`.
  - Gateway resolves `case_ref` against token/session authorization, then uses
    the case timeline read alias.
  - Response includes hits, pagination, applied filters, index freshness, and
    degraded-mode fields.
- Artifact search API:
  - Example target shape: `GET /api/cases/{case_ref}/search/artifacts`.
  - Supports query text, artifact type, host, evidence ID, parser, source hash,
    and time-range filters from allowlists.
- IOC search API:
  - Example target shape: `GET /api/cases/{case_ref}/search/iocs`.
  - Searches indexed IOC documents and may join to Postgres finding/review state.
- Finding evidence lookup:
  - Given a finding ID, Postgres supplies finding, approval, evidence, and audit
    links. Gateway may use OpenSearch to retrieve supporting indexed documents by
    document ID or metadata filters.
- Report evidence lookup:
  - Reports should use Postgres report metadata and approved finding/timeline
    state, then fetch indexed snippets/documents from OpenSearch through Gateway
    for authorized evidence references.
- OpenSearch health/degraded status API:
  - Example target shape: `GET /api/opensearch/health` and case-local
    `GET /api/cases/{case_ref}/opensearch/status`.
  - Response includes cluster reachability, registry health, per-logical-index
    status, freshness, and last indexing error.
- Job/indexing progress views:
  - Example target shape: `GET /api/cases/{case_ref}/jobs` and
    `GET /api/jobs/{job_id}`.
  - Frontend renders Postgres job, job-step, parser-run, and indexing status,
    not transient process status files.
- Optional WebSocket/SSE:
  - Job progress, parser-run progress, and index health changes can stream from
    Postgres-backed events or Gateway job status, not direct OpenSearch polling.

### Frontend composition model

The frontend should combine:

- Supabase/Postgres control-plane records for cases, evidence, authorization,
  jobs, parser runs, approvals, findings review, report metadata, and index
  registry.
- Gateway-mediated OpenSearch results for full-text, timeline, IOC, artifact,
  and aggregate searches.
- Gateway health/degraded status for OpenSearch reachability and index
  freshness.

The frontend should never:

- Send requests directly to OpenSearch.
- Construct OpenSearch index names.
- Send raw Query DSL for normal operator or agent workflows.
- Decide whether a user or token is authorized for a case.
- Treat search hits as authoritative evidence metadata, approval state, audit
  state, or job state.
- Hide OpenSearch failure by silently showing empty search results.

Current repository grounding: the frontend currently calls dashboard API
endpoints such as `/api/timeline` and `/api/iocs`
(`packages/case-dashboard/frontend/src/api/endpoints.js:20-30`), and polling
loads those views through the application store
(`packages/case-dashboard/frontend/src/hooks/useDataPolling.js:16-43`). That
makes Gateway-mediated search APIs a natural migration point.

## 9. OpenSearch integration with DB-backed jobs and workers

Indexing should happen through the future DB-backed job model, not through
process-local active case state and filesystem status as the authoritative
record.

### Target indexing flow

1. Portal or MCP creates a job in Postgres.
   - The request identifies an authorized case and evidence input.
   - Postgres records `jobs`, initial `job_steps`, and requested parser/indexing
     parameters.
   - Gateway writes an audit event for job creation.
2. Worker claims a job from Postgres.
   - Claiming uses a lease, worker identity, status transition, and retry
     policy.
   - The worker only receives jobs for cases and operations it is authorized to
     handle.
3. Worker creates a `parser_run` record.
   - Records parser name, parser version, input evidence IDs, source hashes,
     start time, worker identity, and expected output kind.
4. Worker runs parser.
   - Parser reads immutable evidence-vault files or verified paths.
   - Parser writes normalized output batches or streams normalized records.
5. Worker records parser output metadata.
   - `parser_outputs` records batch identity, output type, output location or
     object key, output hash if applicable, record counts, and parser-run link.
6. Worker indexes into OpenSearch.
   - Worker resolves the case write alias from `opensearch_indexes`.
   - Worker stamps required document metadata on every document.
   - Worker uses deterministic IDs where possible to avoid duplicates.
7. Worker records indexing status in Postgres.
   - Records batch counts, success/failure counts, write alias, concrete index,
     schema version, indexed_at, retryable errors, and last OpenSearch response
     summary.
8. Worker updates `job_steps` and `job_logs`.
   - Status transitions are durable: `queued`, `running`, `retry_wait`,
     `partially_failed`, `failed`, `completed`, or `cancelled`.
9. Worker writes audit events.
   - Parser start/end, index batch start/end, partial failure, retry, and final
     completion are audited.
10. Worker handles partial failures.
    - Failed documents are recorded by batch and reason.
    - Retryable failures do not mark the whole job successful.
    - Non-retryable failures preserve enough metadata for examiner review.
11. Worker handles retry/reindex.
    - Retry uses the same `job_id` or a linked retry job according to policy.
    - Reindex creates a new parser/indexing batch or reuses parser outputs if
      raw parsing need not be repeated.
12. Worker avoids duplicate indexing.
    - Document IDs should be deterministic from case, evidence, parser run or
      stable parser output key, and source record identity.
    - `ingest_batch_id` and `parser_run_id` allow idempotent cleanup and replay.

### Relationship between domains

- `jobs`: requested unit of work, created by portal/MCP/API and scoped to one
  case.
- `job_steps`: durable phases within a job, such as verify input, parse,
  normalize, index artifacts, index timeline, extract IOCs, and finalize.
- `job_logs`: append-only operator-visible logs and structured milestones.
- `parser_runs`: one parser execution attempt with parser version, source
  evidence, worker identity, start/end status, and error state.
- `parser_outputs`: metadata for normalized parser output batches, including
  output hash/path/object reference and record counts.
- `opensearch_indexes`: authoritative registry of case index aliases, concrete
  indexes, schema versions, and health/status.
- OpenSearch documents: derived searchable records that include foreign keys or
  stable IDs back to case, evidence, job, job step, parser run, parser output,
  and ingest batch.

This model directly addresses the current implementation gap where ingest
status is held in `~/.sift/ingest-status` files and subprocess state
(`packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:13-148`) while
parser outputs and OpenSearch indexes are not registered in a durable
control-plane domain.

## 10. Health and degraded mode

OpenSearch unavailability must be explicit and understandable.

When OpenSearch is unavailable:

- Case management still works.
- Evidence metadata still works.
- Evidence integrity checks still work where they do not require OpenSearch.
- Audit still works.
- Token management still works.
- Findings review and approvals still work for Postgres-backed state.
- Jobs that require indexing should move to explicit `retry_wait`, `paused`,
  `failed`, or `indexing_degraded` state according to retry policy.
- Search and timeline views show degraded mode instead of empty results.
- MCP search tools return structured degraded-mode errors.
- Gateway health reports OpenSearch status explicitly.
- Operator dashboard shows OpenSearch as degraded instead of silently hiding
  search tools.

Structured degraded-mode errors should include:

- `status`: `degraded` or `unavailable`
- `component`: `opensearch`
- `case_id`
- `operation`
- `retryable`
- `reason_code`
- `message`
- `last_known_index_status`
- optional `job_id` or `index_id`

### Hackathon/prototype mode

Acceptable prototype behavior:

- Case, evidence, audit, and token workflows continue.
- Search tools return clear degraded errors.
- Indexing jobs may pause or fail fast with retry instructions.
- Frontend shows a prominent search/indexing degraded state.
- Legacy OpenSearch add-on tools can remain available behind warnings while the
  core path is added.

Not acceptable even in prototype mode:

- Silent cross-case queries.
- Empty search results that actually mean OpenSearch is down.
- Treating OpenSearch as authority for case/evidence/job/audit state.
- Allowing normal agent tokens to pass raw index patterns or raw DSL.

### Target hardened mode

Hardened behavior:

- Gateway has a first-class OpenSearch health dependency.
- `opensearch_indexes` rows record stale/degraded/failed health.
- Workers use backoff and durable retry policy.
- Alerts or dashboard warnings trigger on sustained degraded state.
- Search APIs fail closed for unauthorized or ambiguous case context.
- Standalone OpenSearch MCP exposure is disabled, restricted to admins, or
  removed.
- OpenSearch security settings, TLS, credentials, and network exposure are
  consistent across deployment profiles.

## 11. Migration plan for OpenSearch refactor

### Phase OS-0 - Inventory and tests around current standalone OpenSearch MCP backend

- Goal: freeze the current behavior with tests before moving policy boundaries.
- Likely files to change:
  - `packages/opensearch-mcp/src/opensearch_mcp/server.py`
  - `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`
  - `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`
  - `packages/opensearch-mcp/src/opensearch_mcp/paths.py`
  - `packages/opensearch-mcp/tests/*`
- New files likely to add:
  - Tests for `_resolve_index()`, `_validate_index()`, status file behavior,
    and current index naming.
- Tests to add:
  - Explicit index overrides case ID today.
  - Missing case falls back to `case-*` today.
  - Invalid non-`case-` indexes are rejected.
  - Ingest status `case_id="*"` current behavior is documented by tests.
- Acceptance criteria:
  - Current standalone behavior is captured without changing behavior.
  - Risks are documented in test names or comments.
- Rollback strategy:
  - Remove tests only if the later refactor replaces them with target behavior
    tests in the same PR.
- Risks:
  - Tests may initially expose ambiguous or stale README/tool-name behavior.

### Phase OS-1 - Add Postgres/Supabase index registry design/documentation

- Goal: define the `opensearch_indexes` domain and status lifecycle before
  schema implementation.
- Likely files to change:
  - `docs/migration/*`
  - future schema design docs.
- New files likely to add:
  - A control-plane schema design document or section for
    `opensearch_indexes`, `indexing_batches`, and parser/indexing status.
- Tests to add:
  - None in documentation-only phase.
- Acceptance criteria:
  - Ownership, fields, statuses, and relationships are approved.
- Rollback strategy:
  - Update docs before any migration is generated.
- Risks:
  - Designing this without job/parser tables may leave gaps; coordinate with
    the DB-backed jobs design.

### Phase OS-2 - Add control-plane-aware OpenSearch service abstraction

- Goal: introduce a single internal service that builds case-scoped queries and
  resolves aliases from control-plane state.
- Likely files to change:
  - `packages/sift-gateway/src/sift_gateway/*`
  - possibly `packages/sift-core/src/sift_core/*` if core tool definitions own
    the abstraction.
  - existing OpenSearch client/config code may be wrapped but not removed.
- New files likely to add:
  - `packages/sift-gateway/src/sift_gateway/opensearch_service.py`
  - `packages/sift-gateway/tests/test_opensearch_service.py`
- Tests to add:
  - Query builder always includes `case_id`.
  - Normal calls cannot pass raw indexes.
  - Alias resolution requires authorized case and ready index state.
  - Degraded health is structured.
- Acceptance criteria:
  - Service can construct target queries from mocked registry state.
  - No standalone backend behavior is removed.
- Rollback strategy:
  - Disable the new service path while leaving existing add-on backend intact.
- Risks:
  - The service may need placeholder DB interfaces until Supabase/Postgres
    schema exists.

### Phase OS-3 - Add case-scoped Gateway APIs for search/timeline/IOC queries

- Goal: expose first-class REST APIs for timeline, artifact, IOC, document, and
  aggregate search through Gateway policy.
- Likely files to change:
  - `packages/sift-gateway/src/sift_gateway/rest.py`
  - `packages/sift-gateway/src/sift_gateway/auth.py`
  - `packages/sift-gateway/src/sift_gateway/identity.py`
  - dashboard API/frontend files after backend API shape is stable.
- New files likely to add:
  - Request/response schemas for search APIs.
  - Gateway search API tests.
- Tests to add:
  - Unauthorized case is rejected.
  - Cross-case query is rejected.
  - OpenSearch unavailable returns degraded response.
  - Frontend receives explicit health/index freshness fields.
- Acceptance criteria:
  - Search APIs work against mocked OpenSearch service and mocked registry.
- Rollback strategy:
  - Keep old dashboard JSON endpoints while new endpoints are additive.
- Risks:
  - API shape may need revision after DB schema decisions.

### Phase OS-4 - Promote OpenSearch tools into core SIFT MCP namespace

- Goal: add core MCP tools such as `timeline.search`, `artifact.search`,
  `ioc.search`, `opensearch.health`, `opensearch.case_indexes`,
  `opensearch.explain_document`, `opensearch.get_artifact`, and
  `opensearch.aggregate`.
- Likely files to change:
  - `packages/sift-core/src/sift_core/agent_tools.py`
  - `packages/sift-gateway/src/sift_gateway/server.py`
  - `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
- New files likely to add:
  - Core search tool tests.
  - MCP policy tests.
- Tests to add:
  - Core tool specs include constrained schemas.
  - Tools resolve case from identity/session, not input.
  - Raw DSL and raw index inputs are rejected.
  - Audit events include case, identity, scope, result count, and degraded
    status.
- Acceptance criteria:
  - New core tools are visible through aggregate MCP and enforce policy.
  - Existing standalone OpenSearch backend still works for compatibility.
- Rollback strategy:
  - Disable core OpenSearch tools behind a feature flag while retaining add-on
    backend.
- Risks:
  - Tool names with dots should be validated against the MCP/FastMCP clients in
    use.

### Phase OS-5 - Update parser/indexing paths to attach required metadata

- Goal: stamp required control-plane metadata on every new indexed document.
- Likely files to change:
  - `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`
  - `packages/opensearch-mcp/src/opensearch_mcp/parse_evtx.py`
  - `packages/opensearch-mcp/src/opensearch_mcp/parse_csv.py`
  - `packages/opensearch-mcp/src/opensearch_mcp/parse_json.py`
  - `packages/opensearch-mcp/src/opensearch_mcp/parse_delimited.py`
  - `packages/opensearch-mcp/src/opensearch_mcp/parse_memory.py`
  - `packages/opensearch-mcp/src/opensearch_mcp/parse_plaso.py`
  - `packages/opensearch-mcp/src/opensearch_mcp/parse_w3c.py`
  - mapping templates.
- New files likely to add:
  - Metadata contract tests.
  - Versioned mapping templates.
- Tests to add:
  - Each parser stamps required metadata.
  - Missing evidence/job/parser IDs fail before indexing in target mode.
  - Legacy mode remains compatible during transition.
- Acceptance criteria:
  - New documents are traceable to case, evidence, job, parser run, source hash,
    schema version, and batch.
- Rollback strategy:
  - Keep legacy parser fields and write compatibility metadata in parallel.
- Risks:
  - Some parser inputs may not have a clean evidence ID until evidence-vault
    migration is designed.

### Phase OS-6 - Connect indexing to future DB-backed jobs

- Goal: replace filesystem/process status as authority with durable jobs,
  parser runs, parser outputs, and indexing status.
- Likely files to change:
  - Future job/worker modules.
  - OpenSearch ingest launchers.
  - Gateway job APIs.
  - Dashboard job progress views.
- New files likely to add:
  - Worker dispatcher.
  - Job repository/control-plane interfaces.
  - Parser-run and indexing-status adapters.
- Tests to add:
  - Worker claims one job once.
  - Parser run is recorded before indexing.
  - Partial bulk failure produces durable failed batch state.
  - Retry does not duplicate documents.
- Acceptance criteria:
  - A parser/indexing job can be created, claimed, run, indexed, audited, and
    inspected through DB state.
- Rollback strategy:
  - Keep legacy `opensearch_ingest` subprocess flow available until the DB job
    path is accepted.
- Risks:
  - This phase depends on the job schema and worker process model.

### Phase OS-7 - Add health/degraded-mode behavior

- Goal: make OpenSearch degradation visible across Gateway, MCP, API, jobs, and
  frontend.
- Likely files to change:
  - `packages/sift-gateway/src/sift_gateway/health.py`
  - `packages/sift-gateway/src/sift_gateway/rest.py`
  - `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
  - dashboard frontend status components.
- New files likely to add:
  - Degraded-mode response schemas.
  - Health tests.
- Tests to add:
  - OpenSearch down does not break case/evidence/token APIs.
  - Search returns structured degraded error.
  - Jobs pause/retry/fail with explicit indexing status.
  - Dashboard status reflects OpenSearch degradation.
- Acceptance criteria:
  - Operators can distinguish "no hits" from "search unavailable".
- Rollback strategy:
  - Degraded API can be disabled while keeping core case workflows live.
- Risks:
  - Existing generic backend health may conflict with new first-class health
    semantics.

### Phase OS-8 - Deprecate standalone optional OpenSearch MCP backend exposure path

- Goal: prevent policy bypass once core OpenSearch tools are stable.
- Likely files to change:
  - `packages/opensearch-mcp/sift-backend.json`
  - `packages/sift-gateway/src/sift_gateway/server.py`
  - `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
  - docs and configs.
- New files likely to add:
  - Deprecation notes.
  - Compatibility tests.
- Tests to add:
  - Normal agent tokens cannot access standalone OpenSearch tools.
  - Per-backend OpenSearch MCP route is disabled or admin-only.
  - Core tools remain available.
- Acceptance criteria:
  - No normal path bypasses Gateway case/tool policy.
- Rollback strategy:
  - Admin-only compatibility route can remain behind an explicit config flag.
- Risks:
  - Existing demos or operator workflows may still call `opensearch_*` tools.

### Phase OS-9 - Add tests, docs, and demo flow

- Goal: provide an end-to-end migration acceptance path.
- Likely files to change:
  - `docs/*`
  - package READMEs.
  - test suites across Gateway, core, OpenSearch package, and dashboard.
- New files likely to add:
  - Demo guide for case-scoped indexing and search.
  - Acceptance checklist.
- Tests to add:
  - End-to-end case-scoped search.
  - Cross-case denial.
  - Reindex flow.
  - OpenSearch down/degraded flow.
  - Report/finding evidence lookup through indexed documents.
- Acceptance criteria:
  - A new operator can run the demo and see DB-backed job status, indexed
    search, explicit health, and audit/provenance links.
- Rollback strategy:
  - Keep demo behind migration feature flags until stable.
- Risks:
  - Demo data must not rely on stale `idx_*` documentation or legacy active-case
    assumptions.

## 12. First OpenSearch implementation slice recommendation

The safest first OpenSearch-focused PR should be additive and policy-oriented.
It should not remove the standalone OpenSearch MCP backend yet.

Recommended first PR scope:

- Add an OpenSearch service abstraction in the Gateway or core/Gateway boundary.
- Add interfaces for authorized case resolution and OpenSearch index-registry
  lookup, even if backed by an in-memory or compatibility adapter at first.
- Add a health/degraded-mode response model for OpenSearch.
- Add constrained query-construction helpers for timeline/artifact/IOC searches.
- Add tests around case-scoped query construction.
- Document the target metadata contract in code-adjacent docs.
- Leave existing `opensearch-mcp` tools, ingest CLI, parser code, and
  standalone backend registration unchanged.

Likely files to add/change in that first PR:

- Add `packages/sift-gateway/src/sift_gateway/opensearch_service.py`.
- Add `packages/sift-gateway/tests/test_opensearch_service.py`.
- Add small config plumbing only if needed for health checks.
- Optionally add `packages/sift-gateway/src/sift_gateway/search_schemas.py` for
  request/response shapes.
- Do not change parser behavior yet.
- Do not change `packages/opensearch-mcp/sift-backend.json` yet.
- Do not remove any `opensearch_*` tools yet.

Tests to add:

- Normal query builder requires an authorized case context.
- Query builder always adds a `case_id` filter.
- Caller-provided raw index is rejected in normal tool/API mode.
- Cross-case case ID is rejected by the policy interface.
- OpenSearch unavailable returns structured degraded status.
- Registry says no ready index returns structured degraded status.

Acceptance criteria:

- The new abstraction can be used by future Gateway APIs and MCP tools without
  passing raw OpenSearch index names from clients.
- All tests pass without requiring a live OpenSearch instance.
- Existing standalone OpenSearch MCP backend behavior is unchanged.
- No database migration is included.
- No parser/indexing rewrite is included.

What intentionally remains unchanged:

- Current `opensearch_*` standalone MCP tools remain present.
- Current `opensearch_ingest` subprocess/status-file flow remains present.
- Current `case-{case_id}-{artifact_type}-{hostname}` indexes remain supported.
- Current mapping templates remain supported.
- Current frontend timeline/IOC JSON endpoints remain supported until new
  Gateway search APIs and control-plane state are ready.

## 13. Decisions and open questions

### Confirmed decisions

- No Redis/RQ.
- OpenSearch is a core search/data plane.
- OpenSearch is not the authority for case, job, evidence, audit, or approval
  state.
- All OpenSearch access must be case-scoped.
- OpenSearch MCP tools become core SIFT MCP tools.
- Agents must not bypass Gateway policy.
- Degraded mode must be explicit.
- Supabase/Postgres owns OpenSearch index registration and indexing status.
- The first migration slices should be additive and preserve current
  OpenSearch add-on behavior until target policy paths are tested.

### Decisions previously open here, now locked (charter)

- Per-case approach approved; **v1 reuses the existing
  `case-{case_id}-{artifact_type}-{hostname}` naming + templates + `flush_bulk` +
  host discovery + provenance** and registers those indices in
  `opensearch_indexes` (D18). The `dfir-case-*-vN` logical-family rename is a
  deferred, optional evolution, not a v1 requirement.
- A single write contract (§7A) governs every writer (core worker, addon MCP
  backend, enrichment) additively, without refactoring working backends.
- Per-backend OpenSearch MCP routes are **disabled** (D3), not merely admin-only.
- Raw OpenSearch DSL is **admin-only**; normal agent tokens get constrained,
  allowlisted query inputs only (never raw DSL or raw index names).
- Canonical OpenSearch profile: **3.5.0 with security enabled** (D6). The root
  2.18.0/security-disabled compose is pre-migration only.

### Decisions still genuinely open (non-blocking, decide at implementation)

- How long legacy `case-{case_id}-{artifact_type}-{hostname}` indexes remain
  queryable after reindex (default: read-only until the per-case rollback window
  closes, then audited retirement).
- Whether semantic/vector search ships in the first OpenSearch slice or follows
  RAG centralization (default: defer vector to the RAG/skills phase, keep
  full-text/timeline/IOC first).

### Code facts still needing confirmation

- Exact parser coverage for required target metadata, including edge cases where
  the source is generated output rather than a raw evidence file.
- Which external scripts or operator workflows still read
  `~/.sift/active_case`, `~/.sift/ingest-status`, ingest logs, or legacy
  `case-*` index names directly.
- Whether the README references to older `idx_*` tool names are stale or still
  required compatibility documentation; the manifest and current server use
  `opensearch_*` names.
- Whether OpenSearch Security Analytics APIs are required for target demos or
  should remain optional behind capability detection.
- The exact Supabase/Postgres schema split among `jobs`, `job_steps`,
  `job_logs`, `parser_runs`, `parser_outputs`, `opensearch_indexes`, and
  indexing batches.

## 14. Status

The DB-backed jobs/worker design this section anticipated now exists as
`05_execution_job_model.md`, `06_execution_integration_contracts.md`,
`07_execution_roadmap.md`, and `08_control_plane_schema.md`. OpenSearch
indexing is connected to durable jobs there (OpenSearch indexing/parser lineage
in Postgres; documents in OpenSearch). Per the cutover order (charter D17),
identity/cases/tokens (`09_identity_auth_cutover.md`) land before the OpenSearch
integration phases here, because OpenSearch case-scope enforcement depends on
control-plane case authorization.

Recommended next scope:

- Inventory current execution, parser, ingest, and status paths.
- Define `jobs`, `job_steps`, `job_logs`, `parser_runs`, `parser_outputs`, and
  indexing-batch relationships.
- Define worker claiming, leases, retries, cancellation, partial failure, and
  audit events.
- Keep it documentation/design only unless a future run explicitly authorizes
  implementation.
