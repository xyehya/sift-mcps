# Migration State

## Current Objective

Run 4 migration planning completed. The migration workspace now has a focused
current-state execution inventory covering portal-triggered operations, Gateway
REST/MCP dispatch, native `run_command`, forensic MCP workflow/status tools,
OpenSearch parser and ingest execution, evidence/audit behavior, and scattered
workflow/status state.

This run stayed documentation-only. It did not design the future job schema,
REST APIs, MCP tools, execution roadmap, database migrations, or new worker
technology.

## Decisions Already Made

- Supabase/Postgres is the authoritative control plane.
- Human operators use Supabase Auth and RLS.
- Agents, MCP clients, workers, and backend services use Gateway-issued, case-scoped MCP/service tokens.
- MCP/service tokens are stored in the Postgres token registry as hashes only.
- Gateway validates MCP/service tokens and enforces tool scope, case scope, expiry, revocation, and policy before MCP or workflow actions.
- Postgres is authoritative for token registry state, case permissions, audit events, durable job state, evidence metadata, approval state, and workflow state.
- Immutable raw evidence and cryptographic ledger artifacts are preserved as proof/export while control-plane state moves to Postgres.
- OpenSearch is integrated through Gateway policy as a core derived search/data plane, initially by adapting existing OpenSearch code.
- OpenSearch must not become the authority for cases, tokens, jobs, evidence integrity, or approvals.
- No Redis/RQ.
- Frontend UI state is not forensic state authority.
- Agent-generated findings remain draft/proposed until human approval and are not auto-approved.
- OpenSearch query and ingest paths must be Gateway-mediated and case-scoped by token/session context.
- OpenSearch MCP tools should move into the core SIFT MCP namespace rather than remain only optional add-on tools.
- Normal agent tokens must not pass arbitrary OpenSearch index names, wildcard case patterns, or raw OpenSearch DSL.
- OpenSearch degraded mode must be explicit in Gateway health, MCP responses, frontend views, and job/indexing state.
- Compatibility with current files should be additive first; file-backed behavior is not removed before DB authority and compatibility exports are verified.

## Files Created

- `docs/migration/README.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/01_repo_inventory.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/04_execution_current_state.md`

## Files Inspected

- Attached target architecture image from the user prompt.
- `/home/yk/.codex/attachments/037bdcf4-8981-45cc-ab65-77883484d9b1/sift_vm_dfir_exact_replica.mmd`
- `docs/README.md`
- `docs/revamp/target-architecture.mmd`
- `docs/migration/README.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/01_repo_inventory.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/04_execution_current_state.md`
- `pyproject.toml`
- `configs/gateway.yaml.template`
- `configs/apparmor/sift-gateway.template`
- `docker-compose.yml`
- `docker-compose.opencti.yml`
- `packages/case-dashboard/frontend/package.json`
- `packages/case-dashboard/frontend/src/App.jsx`
- `packages/case-dashboard/frontend/src/api/client.js`
- `packages/case-dashboard/frontend/src/api/endpoints.js`
- `packages/case-dashboard/frontend/src/hooks/useDataPolling.js`
- `packages/case-dashboard/frontend/src/store/useStore.js`
- `packages/case-dashboard/frontend/src/components/layout/NavRail.jsx`
- `packages/case-dashboard/frontend/src/components/evidence/EvidenceTab.jsx`
- `packages/case-dashboard/frontend/src/components/reports/ReportsTab.jsx`
- `packages/case-dashboard/frontend/src/components/settings/SettingsTab.jsx`
- `packages/case-dashboard/src/case_dashboard/auth.py`
- `packages/case-dashboard/src/case_dashboard/session_jwt.py`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/sift-core/src/sift_core/case_io.py`
- `packages/sift-core/src/sift_core/case_manager.py`
- `packages/sift-core/src/sift_core/evidence_chain.py`
- `packages/sift-core/src/sift_core/case_ops.py`
- `packages/sift-core/src/sift_core/evidence_ops.py`
- `packages/sift-core/src/sift_core/verification.py`
- `packages/sift-core/src/sift_core/reporting.py`
- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-core/src/sift_core/execute/executor.py`
- `packages/sift-core/src/sift_core/execute/tools/generic.py`
- `packages/sift-common/src/sift_common/audit.py`
- `packages/sift-common/src/sift_common/__init__.py`
- `packages/sift-gateway/src/sift_gateway/auth.py`
- `packages/sift-gateway/src/sift_gateway/identity.py`
- `packages/sift-gateway/src/sift_gateway/token_gen.py`
- `packages/sift-gateway/src/sift_gateway/config.py`
- `packages/sift-gateway/src/sift_gateway/__main__.py`
- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
- `packages/sift-gateway/src/sift_gateway/rest.py`
- `packages/sift-gateway/src/sift_gateway/backends/__init__.py`
- `packages/sift-gateway/src/sift_gateway/backends/base.py`
- `packages/sift-gateway/src/sift_gateway/backends/stdio_backend.py`
- `packages/sift-gateway/src/sift_gateway/backends/http_backend.py`
- `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`
- `packages/forensic-mcp/src/forensic_mcp/server.py`
- `packages/forensic-rag-mcp/src/rag_mcp/server.py`
- `packages/forensic-rag-mcp/sift-backend.json`
- `packages/opencti-mcp/src/opencti_mcp/server.py`
- `packages/opencti-mcp/sift-backend.json`
- `packages/windows-triage-mcp/src/windows_triage_mcp/server.py`
- `packages/windows-triage-mcp/sift-backend.json`
- `packages/opensearch-mcp/pyproject.toml`
- `packages/opensearch-mcp/README.md`
- `packages/opensearch-mcp/sift-backend.json`
- `packages/opensearch-mcp/docker/docker-compose.yml`
- `packages/opensearch-mcp/src/opensearch_mcp/server.py`
- `packages/opensearch-mcp/src/opensearch_mcp/__main__.py`
- `packages/opensearch-mcp/src/opensearch_mcp/http_server.py`
- `packages/opensearch-mcp/src/opensearch_mcp/client.py`
- `packages/opensearch-mcp/src/opensearch_mcp/paths.py`
- `packages/opensearch-mcp/src/opensearch_mcp/gateway.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_evtx.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_accesslog.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_csv.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_defender.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_json.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_delimited.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_memory.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_plaso.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_prefetch.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_srum.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_ssh.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_tasks.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_transcripts.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_w3c.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_wer.py`
- `packages/opensearch-mcp/src/opensearch_mcp/tools.py`
- `packages/opensearch-mcp/src/opensearch_mcp/mappings/__init__.py`
- `packages/opensearch-mcp/src/opensearch_mcp/mappings/*.json`
- Targeted `find`, `tree`, and `rg` scans for repo/package structure, frontend API usage, Starlette routes, MCP registration, JSON state, evidence, audit, tokens, OpenSearch, jobs/workflows, tests, docs, setup files, Redis/RQ/Celery, and Supabase/Postgres presence.

## Key OpenSearch Findings From Run 3

- Current OpenSearch is implemented as `opensearch-mcp`, an optional add-on MCP backend with standalone stdio/HTTP/CLI entry points and a `sift-backend.json` manifest.
- Current query tools validate that index names start with `case-`, but normal search can still accept explicit index names and can fall back to broad `case-*` behavior when no active case is resolved.
- Current case context comes from `SIFT_CASE_DIR` or `~/.sift/active_case`, not from Postgres/Supabase case membership or Gateway-issued case-scoped token state.
- Current ingest and indexing are subprocess-driven and tracked through `~/.sift/ingest-status`, ingest logs, and filesystem manifests, not durable database jobs, parser runs, parser outputs, or indexing batches.
- Current parser documents already include useful partial provenance such as `vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`, host fields, and `pipeline_version`, but do not yet consistently include the target control-plane IDs.
- The recommended initial index strategy is per-case logical indexes with Postgres-registered aliases, because the current code already uses case-prefixed indexes. This recommendation still needs user approval before implementation.
- The safest first OpenSearch implementation slice is additive: add a control-plane-aware OpenSearch service abstraction, case-scope query construction tests, and explicit health/degraded behavior without removing the standalone backend.

## Execution Facts Confirmed From Run 4

- Portal/operator execution is mostly synchronous request/response against
  file-backed state. Evidence operations, approval commit, report generation,
  backend/service management, and polling all resolve active case from
  `SIFT_CASE_DIR`/legacy case resolution rather than durable DB session state.
- Gateway aggregate MCP calls run an evidence-chain gate before dispatch and
  write a transport-envelope audit entry. Per-backend MCP endpoints call a
  single backend directly and have a different policy/audit surface.
- Native `run_command` is synchronous. It validates command plans, executes
  shell-free subprocess stages, can save stdout/stderr under case-controlled
  directories, and writes detailed JSONL audit including input hashes where
  detectable.
- OpenSearch ingest is the main long-running execution path. It starts
  subprocesses with `python -m opensearch_mcp.ingest_cli`, records pid/run_id
  status under `~/.sift/ingest-status`, writes logs under
  `~/.sift/ingest-logs`, and indexes derived documents into case-prefixed
  OpenSearch indices.
- Parser modules generally write directly to OpenSearch bulk actions and stamp
  partial provenance fields such as `vhir.source_file`,
  `vhir.ingest_audit_id`, `vhir.parse_method`, optional `vhir.vss_id`, and
  `pipeline_version`. Durable DB IDs are not present.
- Evidence chain authority is currently the manifest/ledger files, with
  `evidence.json` as compatibility view. Audit and approval records are JSONL
  under the state-root case record directory by default.
- Current workflow/status state is scattered across case JSON files,
  `pending-reviews.json`, in-memory report drafts, `~/.sift/ingest-status`,
  ingest logs, active-case env/pointers, OpenSearch indices, and frontend cache.

## Execution Risks Discovered From Run 4

- Long-running parsers are not durable DB jobs.
- Case scope depends on env or active-case pointers.
- Status is file-based or scattered.
- Worker crash recovery is local pid-file and `/proc` based; durable ownership,
  heartbeat, and stale-claim handling are absent.
- Duplicate ingestion/indexing risk remains because status and idempotency are
  not control-plane-backed.
- OpenSearch indexing status can drift from existing indices and cleaned status
  files.
- Evidence provenance can disconnect from parser outputs because parser docs and
  ingest manifests do not carry durable evidence/job/parser IDs.
- MCP tools may block synchronously, especially native commands and add-on calls.
- Frontend cannot reliably observe parser/native progress through one
  authoritative progress model.
- Audit gaps can occur when parser subprocesses, sidecar writes, or active-case
  resolution fail outside a durable audit/job transaction.
- Per-backend MCP routes may bypass the aggregate evidence-gate behavior.
- Report generation uses in-memory in-flight/draft state only.

## Open Questions

- What exact Supabase Local deployment shape should this repo target?
- Should active-case state be per human session, per workstation, per Gateway instance, or a combination with explicit precedence?
- What token hashing strategy should be canonical, including algorithm, optional pepper/KMS use, displayed fingerprints, and default expiry?
- What is the safest first cutover order: cases/tokens first, evidence/audit first, or OpenSearch/jobs first?
- How long should generated compatibility files remain supported after Postgres becomes authority?
- Which external scripts or operator workflows still read `~/.sift/active_case`, `~/.sift/ingest-status`, saved report JSON, or flat case JSON directly?
- Must evidence manifest/ledger files remain canonical legal artifacts even after Postgres becomes operational authority?
- What exact worker process model should parser execution target: single Gateway-host worker, multiple local workers, or future distributed workers?
- Should the project approve per-case logical indexes as the initial OpenSearch strategy, or target shared indexes with mandatory `case_id` filters from the start?
- What target index names and aliases should be canonical for artifacts, timeline records, and IOCs?
- How long should the legacy `case-{case_id}-{artifact_type}-{hostname}` indexes remain queryable?
- Should per-backend OpenSearch MCP routes become admin-only, disabled by default, or removed after core tools are available?
- Should any normal agent token ever receive constrained raw OpenSearch DSL access, or should raw DSL be admin-only?
- Which OpenSearch version/profile is canonical: root compose OpenSearch 2.18.0, package compose OpenSearch 3.5.0, or a newly declared target?
- Is semantic/vector search in the first OpenSearch migration scope, or explicitly deferred?
- For the execution job model, should the first durable jobs cover only
  OpenSearch ingest, or also native `run_command`, report generation, and
  evidence operations?
- Should short native commands remain synchronous while only long-running parser
  workflows become jobs?
- Should legacy `~/.sift/ingest-status` continue as a compatibility export once
  Postgres job state exists, and for how long?
- What cancellation semantics are acceptable for partially indexed OpenSearch
  batches and subprocess trees?

## Next Recommended Run

Create `docs/migration/05_execution_job_model.md`. Recommended scope: design
only the target job lifecycle, job claiming strategy, status transitions, worker
heartbeat/stale job handling, retry/cancel behavior, and no Redis/RQ. Do not
design the full parser output schema, all REST APIs, all MCP tools, database
migrations, or the final execution roadmap in that run.
