# Migration State

## Current Objective

Run 6 migration planning completed. The migration workspace now has integration
contracts for connecting the DB-backed execution/job model to Gateway REST APIs,
core SIFT MCP tools, the React + Vite operator portal, OpenSearch indexing and
search status, evidence vault/integrity workflows, audit events, approval gates,
worker status, and degraded-mode behavior.

This run stayed documentation-only. It did not implement code, create database
migrations, refactor REST APIs, MCP tools, frontend views, OpenSearch, evidence,
audit, or worker code, and did not write the final execution roadmap. It did not
introduce Redis/RQ/Celery/Temporal or any external queue.

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
- Gateway/API/MCP creates durable job records in Postgres for long-running work.
- SIFT workers poll Postgres and atomically claim jobs using DB row-locking semantics.
- Long-running MCP tools enqueue jobs and return job IDs rather than executing inside request paths.
- OpenSearch indexing status is recorded in Postgres and OpenSearch remains a derived searchable data plane.
- Jobs are explicitly case-scoped from Gateway-validated human session or MCP/service-token context, not from `SIFT_CASE_DIR` or legacy active-case pointers.
- Retry preserves previous attempts, job steps, logs, parser runs, and indexing records.
- Cancellation is explicit and audited.
- Approval-gated work enters `waiting_human`; destructive or final actions require human approval.

## Files Created

- `docs/migration/README.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/01_repo_inventory.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/04_execution_current_state.md`
- `docs/migration/05_execution_job_model.md`
- `docs/migration/06_execution_integration_contracts.md`

## Files Inspected In Run 6

- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/04_execution_current_state.md`
- `docs/migration/05_execution_job_model.md`
- `docs/migration/README.md`

No implementation code was inspected during run 6. Current repository facts in
`06_execution_integration_contracts.md` were carried forward from the required
migration documents.

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
- `docs/migration/05_execution_job_model.md`
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

## Key Job-Model Decisions From Run 5

- Target job statuses are `pending`, `queued`, `running`, `waiting_human`,
  `succeeded`, `failed`, `retrying`, `cancelled`, `stale`, and `paused`.
- Job scope includes `case_id`, requester identity fields, creator type,
  job type, status, priority, idempotency key, JSON spec, timestamps, worker
  claim/lease fields, heartbeat, attempt counters, cancellation fields, and
  failure summary.
- `case_id` must come from Gateway-validated human session or
  MCP/service-token context, not from process environment or legacy active-case
  pointers.
- Workers claim queued jobs from Postgres using an atomic row-locking /
  `SKIP LOCKED`-style pattern with worker capabilities, priority ordering,
  case fairness, leases, and heartbeats.
- Stale jobs are detected through expired leases and recovered through audited
  retry/requeue/fail/cancel decisions.
- `job_steps` and `job_logs` are the target observability model; stdout/stderr
  should be captured with redaction and linked to steps/jobs.
- Parser runs, parser outputs, ingest batches, and OpenSearch indexing status
  link back to `case_id`, `job_id`, `job_step_id`, `parser_run_id`, evidence
  IDs where applicable, parser versions, source hashes, and schema versions.
- Initial target job types are `evidence_register`, `evidence_hash`,
  `evidence_verify_integrity`, `evidence_ingest`, `parser_run`,
  `opensearch_index`, `timeline_build`, `ioc_extract`, `finding_generate`,
  `report_generate`, `report_export`, `case_archive`,
  `maintenance_reindex`, and `health_check`.
- Worker runtime assumes registration, capabilities, parser/command allowlists,
  no arbitrary shell execution, environment isolation, subprocess timeouts,
  stdout/stderr capture, heartbeat, graceful shutdown, cancellation handling,
  and crash recovery through leases.

## Key Integration Decisions From Run 6

- Gateway REST APIs are the human/operator job surface. They create, list,
  inspect, cancel, retry, and observe jobs, steps, logs, workers, execution
  health, and OpenSearch health through Gateway policy.
- Case authorization for REST job APIs must come from Supabase Auth/RLS plus
  Gateway policy. The Gateway remains the REST policy enforcement point.
- The frontend must not directly mutate authoritative job state. It submits
  actions through Gateway endpoints and reads job/status/health/audit views.
- Core SIFT MCP tools are the AI-agent/service job surface. Long-running tools
  enqueue DB-backed jobs and return `job_id`.
- Target MCP tools include `jobs.enqueue`, `jobs.get`, `jobs.list`,
  `jobs.tail_logs`, `jobs.cancel`, `jobs.retry`, `evidence.ingest`,
  `evidence.verify_integrity`, `parsers.list`, `parsers.run`,
  `opensearch.index_status`, `opensearch.health`, `report.generate`, and
  `finding.generate`.
- MCP case context comes from Gateway-validated token/session context, not
  process environment or legacy active-case pointers. Normal agent tokens cannot
  pass arbitrary `case_id`, raw OpenSearch DSL, raw index names, or wildcard case
  patterns.
- Initial frontend update strategy is polling first, with later SSE/WebSocket or
  Supabase Realtime as an upgrade path after DB/RLS/Gateway event policy is
  stable.
- Evidence vault behavior is preserved. Raw evidence remains immutable while
  operational metadata, integrity status, job state, and audit linkage move into
  Postgres over time.
- OpenSearch indexing jobs link parser runs, parser outputs, ingest batches,
  index registrations, and OpenSearch documents through Postgres IDs and source
  hashes. OpenSearch remains derived and non-authoritative.
- Audit remains mandatory for job lifecycle transitions, parser runs, evidence
  access/checks, OpenSearch indexing, report/finding generation, human
  approvals, destructive/final actions, and policy denials.
- Approval-gated work enters `waiting_human`. Agent-generated findings remain
  proposed/pending and cannot be auto-approved.
- Worker health is observed through registration, capabilities, heartbeat,
  active job, `last_seen_at`, degraded/offline state, health endpoints, and
  stale-job audit/log behavior.

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
- Should the first implementation slice cover only OpenSearch ingest, or also
  native `run_command`, report generation, and evidence operations?
- Should short native commands remain synchronous while only long-running parser
  workflows become jobs?
- Should legacy `~/.sift/ingest-status` continue as a compatibility export once
  Postgres job state exists, and for how long?
- What cancellation semantics are acceptable for partially indexed OpenSearch
  batches and subprocess trees?
- Should retry happen at whole-job, host, artifact, parser-run, or indexing
  batch granularity first?
- Which report/export workflows should become job-backed first?
- Which evidence operations are too expensive to remain synchronous?
- Which external scripts still consume `~/.sift/ingest-status`,
  `~/.sift/ingest-logs`, active-case pointers, or ingest manifests?
- What exact human role names and permissions should apply to job creation,
  retry, cancel, log reads, worker detail, approvals, final export, archive, and
  destructive cleanup?
- What exact initial REST response schemas and MCP result schemas should be
  frozen before implementation?
- What initial frontend polling intervals should be accepted, and when should
  SSE/WebSocket or Supabase Realtime become part of the roadmap?
- Should raw OpenSearch DSL be admin-only forever, or should a constrained
  normal-agent mode ever exist?
- Which job/action audit events must be fail-closed if the DB audit writer is
  unavailable during the transition?

## Next Recommended Run

Create `docs/migration/07_execution_roadmap.md`.

Recommended scope:

- migration phases for execution/jobs
- first execution-focused PR plan
- rollback strategy
- tests and acceptance criteria

Keep the next run focused on planning. Do not create database migrations or
implement code unless a future prompt explicitly authorizes that work.
