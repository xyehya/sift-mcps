# Task Batches

Status: MVP sprint execution tracker.
Last updated: 2026-06-08.

Rules:

- Use one worktree per batch when running parallel sessions.
- Checkboxes are grep targets. Mark only the leading batch checkbox when the
  batch acceptance checks pass.
- Do not start dependent work until dependencies are checked complete or the
  blocking decision is resolved in `Session-Notes.md`.
- Resolve blockers on spot for dependent work. Independent batches may proceed.
- Keep new planning in this file. Do not create more migration docs.
- Parallel worker branches must not all edit `docs/migration`. A worker returns
  a landing log block; the integration/conductor session updates this tracker
  and `Session-Notes.md` after merge.

## Batch Index

- [x] BATCH-A0 - Freeze simplified migration operating model
- [x] BATCH-A1 - Final installer, Supabase bootstrap, forced reset, and health contract
- [x] BATCH-B1 - Gateway policy parity and agent response redaction
- [x] BATCH-C1 - DB evidence authority, custody ledger, and seal broker
- [x] BATCH-D1 - Durable Postgres jobs and local worker claim loop
- [x] BATCH-D2 - Gateway job adapter and add-on authority enforcement
- [x] BATCH-E1 - Portal authority migration for evidence, findings, timeline, TODOs, and reports
- [x] BATCH-F1 - OpenSearch secure core integration and ingest job adapter
- [x] BATCH-G1 - RAG pgvector target with provenance filters
- [x] BATCH-H1 - Add-on contract hardening for OpenCTI, Windows triage, and forensic knowledge
- [x] BATCH-I1 - Sandboxed run_command uplift
- [x] BATCH-J1 - Approved-only report generation and export
- [x] BATCH-L1 - Live service binding, worker bootstrap, and Gateway tool bridge
- [x] BATCH-K0 - Authority cutover impact model and batch freeze
- [x] BATCH-K1 - Authority context and DB audit cutover
- [x] BATCH-K2 - Core investigation DB authority cutover
- [x] BATCH-K3 - Evidence gate, proof export, and Solana anchor cutover
- [x] BATCH-K4 - OpenSearch derived-state and host identity cutover
- [x] BATCH-K5 - run_command authority-isolation hardening
- [x] BATCH-K6 - Portal/report tamper regression and file-authority removal
- [ ] BATCH-V1 - End-to-end validation and cutover

## BATCH-A0 - Freeze simplified migration operating model

Dependencies: none.

Scope:

- `docs/migration/**`
- `AGENTS.md`
- `CLAUDE.md`
- `scripts/validate_docs.py`
- `scripts/validate_migration_docs.py`

Exact work:

- Purge the previous migration document forest.
- Replace it with `Migration-Spec.md`, `task-batches.md`, and
  `Session-Notes.md`.
- Simplify root agent instructions to point at the three active docs only.
- Make `scripts/validate_docs.py` enforce the new three-file model.

Acceptance:

- `rg --files docs/migration` lists only the three active docs.
- `python3 scripts/validate_docs.py` passes.
- `python3 scripts/validate_migration_docs.py` passes.

## BATCH-A1 - Final installer, Supabase bootstrap, forced reset, and health contract

Dependencies: BATCH-A0.

Scope:

- `install.sh`
- `configs/gateway.yaml.template`
- `configs/systemd/sift-gateway.service`
- `configs/audit/99-sift-evidence.rules`
- `configs/apparmor/sift-gateway.template`
- `scripts/setup-agent-runtime.sh`
- `packages/sift-gateway/src/sift_gateway/config.py`
- `packages/sift-gateway/src/sift_gateway/health.py`
- `packages/sift-gateway/src/sift_gateway/supabase_auth.py`
- `packages/case-dashboard/src/case_dashboard/auth.py`
- `packages/case-dashboard/src/case_dashboard/routes.py`

Exact work:

- Update the final installer so it performs installation, configuration,
  hardening, health check, and operator handoff in one idempotent flow.
- Make the operator bootstrap Supabase-first. The installer must produce a
  one-time credential or reset challenge that forces reset on first login.
- Preserve the SIFT VM constraints: `/usr/bin/python3.12`,
  `UV_NO_MANAGED_PYTHON=1`, and `UV_PYTHON_DOWNLOADS=never`.
- Add explicit evidence mount validation and case root validation.
- Freeze the case path implementation to `/cases/case-<slug>-<MMDDHHSS>`, with
  a filesystem-safe lowercase slug and `-NN` collision suffix if needed.
- Health output must prove Gateway, portal, Supabase connectivity, OpenSearch
  reachability if configured, evidence root permissions, and worker readiness
  if enabled.

Acceptance:

- Fresh SIFT VM install completes without manual patching.
- Operator can log in with one-time credential and is forced to reset.
- Operator can create and activate a case with re-auth.
- Active case is sourced from Postgres, not local env/pointer files.
- Installer health check shows the evidence root/mount status.

## BATCH-B1 - Gateway policy parity and agent response redaction

Dependencies: BATCH-A0.

Scope:

- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/rest.py`
- `packages/sift-gateway/src/sift_gateway/mcp_server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
- `packages/sift-gateway/src/sift_gateway/policy_middleware.py`
- `packages/sift-gateway/src/sift_gateway/evidence_gate.py`
- `packages/sift-gateway/src/sift_gateway/response_guard.py`
- `packages/sift-gateway/src/sift_gateway/rate_limit.py`
- `packages/sift-core/src/sift_core/agent_tools.py`
- Gateway and core tests touching auth, active case, evidence gate, response guard, and REST tools

Exact work:

- Make protected portal REST and MCP tool paths policy-equivalent for equivalent
  actions.
- For the MVP, make REST tool execution operator-only. Agents use Gateway MCP
  only.
- Ensure every agent-facing tool response uses opaque IDs and redacted/capped
  previews.
- Remove absolute case paths, evidence paths, mount paths, local config paths,
  and secret-bearing values from agent-visible responses.
- Allow agent-visible evidence IDs, display names, relative display paths, size,
  hash, seal status, and provenance IDs. Deny absolute paths.
- Verify pre-seal evidence denial and post-seal allow behavior.

Acceptance:

- Tests prove agent tokens cannot use REST to bypass MCP policy.
- Tests prove `case_info`, `evidence_info`, existing-finding views, and
  run-command results expose no absolute paths.
- Evidence gate failures are fail-closed and audited.
- Rate limit and response guard still apply on agent paths.

## BATCH-C1 - DB evidence authority, custody ledger, and seal broker

Dependencies: BATCH-A0; BATCH-A1 for final case path details.

Scope:

- `supabase/migrations/*.sql`
- `packages/sift-gateway/src/sift_gateway/evidence_gate.py`
- `packages/sift-gateway/src/sift_gateway/audit_helpers.py`
- `packages/sift-core/src/sift_core/evidence_chain.py`
- `packages/sift-core/src/sift_core/verification.py`
- `packages/sift-core/src/sift_core/case_io.py`
- Evidence API/route tests only if they do not overlap a concurrently running
  portal batch; otherwise return the route patch as follow-up for BATCH-E1

Exact work:

- Add Postgres evidence tables for detected files, registered evidence,
  evidence versions, custody events, hash chain heads, seal status, and proof
  export metadata.
- Add service-only transition RPCs for detect, register, seal, verify, ignore,
  retire, and violation marking.
- Keep file manifests and proof files as exported artifacts, not as the
  authoritative state machine.
- Broker must resolve evidence IDs to mounted paths internally. The agent never
  receives the path.
- Hash-chain/custody arrow is mounted evidence focused: proof links to the
  evidence mount and custody ledger, not RAG.

Acceptance:

- Portal detects unregistered evidence and shows it from DB state.
- Operator registers evidence with name and description.
- Seal requires re-auth and writes a custody event/hash-chain entry.
- Agent analysis is blocked until sealed OK.
- Proof export can verify sealed mounted evidence.

## BATCH-D1 - Durable Postgres jobs and local worker claim loop

Dependencies: BATCH-A0; can run in parallel with BATCH-C1 after table contracts are agreed.

Scope:

- `supabase/migrations/*.sql`
- `packages/sift-gateway/src/sift_gateway/**`
- `packages/sift-core/src/sift_core/execute/worker.py`
- New worker module if needed under `packages/sift-core/src/sift_core/**`
- Tests for job enqueue, claim, lease, status, logs, cancellation, and retry

Exact work:

- Add minimal job tables: jobs, job_steps, job_logs, worker_heartbeats, and
  typed status enums.
- Add enqueue RPC/API for ingest, enrich, report, and run-command jobs.
- Add worker claim loop using Postgres row locking or equivalent lease
  semantics.
- Jobs return `job_id` to portal/agent and write status/logs to Postgres.
- Worker receives case/evidence/job IDs, resolves paths internally, and writes
  provenance IDs on outputs.

Acceptance:

- Concurrent workers do not claim the same job.
- Lease expiry and retry behavior are tested.
- Portal and agent can poll job status without reading worker files.
- Failed jobs preserve audit/provenance and sanitized logs.

## BATCH-D2 - Gateway job adapter and add-on authority enforcement

Dependencies: BATCH-B1; BATCH-D1; BATCH-H1. BATCH-C1 context is available for
case/evidence IDs, but D2 must not implement evidence UI.

Scope:

- `packages/sift-gateway/src/sift_gateway/rest.py`
- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
- `packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py`
- `packages/sift-gateway/src/sift_gateway/backends/**`
- `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`
- Gateway tests for jobs, backend registry, scope enforcement, and add-on
  authority contracts
- Optional narrow SQL migration only if required for grants/wrappers around
  existing D1 job RPCs

Exact work:

- Add the Gateway adapter over D1's `app.enqueue_job`,
  `app.job_status_public`, and `app.expire_stale_jobs` surfaces.
- Job enqueue returns only `job_id` to portal/agent callers and attaches the
  Gateway audit event ID as `enqueue_audit_event_id`.
- Job status reads are sanitized and expose no worker files or local paths.
- Add a safe Gateway-owned reaper trigger or service hook for
  `expire_stale_jobs`.
- Enforce add-on `authority_contract` at runtime: `non_authoritative`,
  `prohibited_operations`, and tool-level `required_scopes`.
- Keep `transport: library` manifests non-routable.

Acceptance:

- Tests prove enqueue/status uses D1 RPC/view shape and returns sanitized
  `job_id`/status only.
- Tests prove a missing required add-on scope is denied before backend dispatch.
- Tests prove prohibited add-on authority operations are denied before backend
  dispatch.
- Tests prove library manifests remain accepted but non-routable.
- Existing Gateway manifest and backend registry tests remain green.

## BATCH-E1 - Portal authority migration for evidence, findings, timeline, TODOs, and reports

Dependencies: BATCH-B1; BATCH-C1 for evidence; BATCH-D1 for job-backed actions; BATCH-D2 for Gateway job/status adapter.

Scope:

- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/case-dashboard/frontend/src/App.jsx`
- `packages/case-dashboard/frontend/src/components/evidence/EvidenceTab.jsx`
- `packages/case-dashboard/frontend/src/components/findings/FindingsTab.jsx`
- `packages/case-dashboard/frontend/src/components/timeline/TimelineTab.jsx`
- `packages/case-dashboard/frontend/src/components/todos/TodosTab.jsx`
- `packages/case-dashboard/frontend/src/components/reports/ReportsTab.jsx`
- `packages/case-dashboard/frontend/src/components/settings/SettingsTab.jsx`
- Portal tests

Exact work:

- Wire evidence screens to DB evidence state and custody transitions.
- Wire findings, timeline, TODOs, and report metadata to Postgres.
- Preserve human review power: approve, reject, edit, manage TODOs, and approve
  report inclusion from portal only.
- Sensitive actions require password/HMAC re-auth.
- Portal must show job status, evidence seal status, custody status, add-on
  status, and report eligibility clearly.

Acceptance:

- Operator can complete the full portal journey without relying on old file
  authority.
- Agent proposals appear as proposed/draft records until human action.
- Approved-only report eligibility is visible and testable.
- Portal tests cover auth, re-auth, and rejected unauthorized mutations.

## BATCH-F1 - OpenSearch secure core integration and ingest job adapter

Dependencies: BATCH-D1; BATCH-C1 for evidence IDs; BATCH-D2 for Gateway job/status adapter and add-on contract enforcement.

Scope:

- `packages/opensearch-mcp/src/opensearch_mcp/**`
- `packages/opensearch-mcp/docker/**`
- `packages/opensearch-mcp/scripts/setup-opensearch.sh`
- `packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py`
- Gateway backend registry integration tests

Exact work:

- Keep the working parser/ingestor stack. Add the minimal adapter needed for
  DB job execution and evidence/provenance IDs.
- Ensure OpenSearch security remains enabled and credentials are never exposed
  to the AI agent.
- Write case/provenance IDs into indexed documents.
- Register index/job/provenance metadata in Postgres.
- Keep OpenSearch derived and rebuildable.

Acceptance:

- Ingest job indexes parser documents with case/evidence/provenance metadata.
- Search tools are case-scoped through Gateway.
- OpenSearch direct credentials are not present in agent-visible output.
- Existing parser tests remain green.

## BATCH-G1 - RAG pgvector target with provenance filters

Dependencies: BATCH-D1; BATCH-C1 for evidence provenance; BATCH-B1 for Gateway policy; BATCH-D2 for job/status adapter.

Scope:

- `supabase/migrations/*.sql`
- `packages/forensic-rag-mcp/src/rag_mcp/**`
- `packages/forensic-rag-mcp/knowledge/**`
- Gateway RAG tool bridge tests

Exact work:

- Add Supabase pgvector schema for RAG collections, documents, chunks,
  embeddings, and provenance IDs.
- Store derived text and forensic knowledge chunks with case/provenance filters.
- Query RAG only through Gateway.
- Return grounded context with provenance IDs, not evidence paths.
- Keep knowledge data as reference data, not evidence.

Acceptance:

- RAG queries return case-scoped, provenance-linked context.
- Agent cannot query another case's RAG data.
- RAG has no authority over evidence seal, approvals, or reports.

## BATCH-H1 - Add-on contract hardening for OpenCTI, Windows triage, and forensic knowledge

Dependencies: BATCH-B1; can run in parallel with DB-heavy batches.

Scope:

- `packages/opencti-mcp/src/opencti_mcp/**`
- `packages/windows-triage-mcp/src/windows_triage_mcp/**`
- `packages/forensic-knowledge/src/**`
- `packages/*/sift-backend.json`
- Gateway backend registry tests

Exact work:

- Align add-ons with the final contract: query-only, audited, scoped, and
  non-authoritative.
- Ensure add-ons cannot create cases, seal evidence, approve findings, approve
  reports, or bypass Gateway.
- Preserve Windows triage suspicious file/service/process/hash baseline value.
- Preserve forensic knowledge snippets as discipline guidance only.

Acceptance:

- Add-on metadata clearly marks capabilities and required scopes.
- Gateway registry can enable/disable/gate add-ons.
- Tool surface snapshots remain deterministic.

## BATCH-I1 - Sandboxed run_command uplift

Dependencies: BATCH-B1; BATCH-C1 for evidence refs; BATCH-D1 for job backing; BATCH-D2 for Gateway job/status adapter.

Scope:

- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-core/src/sift_core/execute/tools/generic.py`
- `packages/sift-core/src/sift_core/execute/executor.py`
- `packages/sift-core/src/sift_core/execute/security.py`
- `packages/sift-core/src/sift_core/execute/security_policy.py`
- `scripts/setup-agent-runtime.sh`
- Execution tests

Exact work:

- Make `run_command` accept evidence refs and output refs, not arbitrary paths.
- Keep `shell=False`, deny-by-default parsing, and runtime user isolation.
- Add a tight MVP allowlist for necessary forensic tools.
- Run as a job where practical and return `job_id`, stdout preview, output refs,
  output hashes, and provenance receipts.
- Sanitize all returned path-like values for the agent.

Acceptance:

- Allowed forensic commands work against sealed evidence refs.
- Denied commands fail closed and are audited.
- Outputs are hash-linked and reportable without exposing local paths.

## BATCH-J1 - Approved-only report generation and export

Dependencies: BATCH-E1; BATCH-D1; BATCH-C1; BATCH-D2.

Scope:

- `packages/sift-core/src/sift_core/reporting.py`
- `packages/sift-core/src/sift_core/report_profiles.py`
- Portal report routes and `ReportsTab.jsx`
- Report tests

Exact work:

- Store report metadata and report state in Postgres.
- Generate reports from approved findings and approved supporting data only.
- Require operator re-auth for report inclusion/export.
- Include custody/evidence seal status, provenance IDs, and hash-chain proof
  references.
- Keep report files as exported artifacts, not authority.

Acceptance:

- Unapproved findings cannot appear in generated reports.
- Approved findings include provenance and supporting custody references.
- Exported report bundle includes verification material.

## BATCH-L1 - Live service binding, worker bootstrap, and Gateway tool bridge

Dependencies: BATCH-C1; BATCH-D1; BATCH-D2; BATCH-E1; BATCH-F1; BATCH-G1; BATCH-I1; BATCH-J1.

Scope:

- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_server.py`
- `packages/sift-gateway/src/sift_gateway/policy_middleware.py`
- `packages/sift-gateway/src/sift_gateway/jobs.py`
- `packages/sift-gateway/src/sift_gateway/portal_services.py`
- `packages/sift-gateway/src/sift_gateway/job_tools.py`
- `packages/sift-gateway/src/sift_gateway/rag_bridge.py`
- `packages/sift-core/src/sift_core/execute/job_worker.py`
- `packages/sift-core/src/sift_core/execute/job_worker_cli.py`
- `packages/sift-core/src/sift_core/execute/run_command_job.py`
- `supabase/migrations/202606081500_report_metadata.sql`
- `configs/systemd/sift-job-worker.service`
- Binding tests and DB structural tests

Exact work:

- Bind `create_dashboard_v2_app` service slots to live Gateway-owned DB
  adapters for evidence/custody, findings/timeline/IOCs/TODOs, report metadata,
  and D2 job status.
- Add the report/investigation metadata migration required by J1's
  `report_service.record_report` seam.
- Prefer the C1 DB evidence gate for DB active cases; keep the legacy file gate
  only as bridge fallback.
- Add a worker CLI/service that registers D1 `JobWorker` handlers for `ingest`
  and `run_command`, and filters claims to job types this worker can handle.
- Add Gateway-owned MCP tools for durable `ingest_job`, durable
  `run_command_job`, and sanitized `job_status`; public job specs stay
  path-free and worker-only `spec_internal` carries resolved local paths.
- Add the case-scoped pgvector `rag_search_case` Gateway tool over G1's
  `PgVectorRagStore`, routed through normal Gateway policy and response guard.

Acceptance:

- Portal DB service slots are wired by Gateway startup when a control-plane DSN
  exists.
- Agent-facing durable job tools return `job_id` and status only; absolute
  paths appear only in worker-only `spec_internal`.
- Worker claim loop does not claim unsupported job types.
- DB active cases use DB evidence-gate status before tool dispatch.
- RAG query tool validates case scope and embedding shape and returns
  provenance-linked, path-free results.
- Gateway, core, portal, RAG/DB, and OpenSearch job-ingest tests pass.

## BATCH-K0 - Authority cutover impact model and batch freeze

Dependencies: BATCH-L1 live binding context; BATCH-V1 partial validation
findings.

Scope:

- `docs/migration/Migration-Spec.md`
- `docs/migration/task-batches.md`
- `docs/migration/Session-Notes.md`
- `scripts/validate_docs.py` only if the three-file governance model itself
  needs an intentional rule change

Exact work:

- Document the authority cutover impact model: Postgres is authority for
  critical mutable state; Supabase Storage/case files are immutable exports,
  workspace/debug artifacts, parser compatibility artifacts, or legacy fallback
  only.
- Map critical file touchpoints with code references so implementation sessions
  do not rediscover the same split-brain paths:
  - active case: `packages/sift-common/src/sift_common/__init__.py`,
    `packages/sift-core/src/sift_core/case_manager.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`;
  - audit: `packages/sift-common/src/sift_common/audit.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`;
  - evidence/custody: `packages/sift-core/src/sift_core/evidence_chain.py`,
    `packages/sift-core/src/sift_core/verification.py`,
    `packages/case-dashboard/src/case_dashboard/routes.py`;
  - investigation records: `packages/sift-core/src/sift_core/case_manager.py`,
    `packages/sift-core/src/sift_core/case_io.py`,
    `packages/sift-gateway/src/sift_gateway/portal_services.py`,
    `packages/case-dashboard/src/case_dashboard/routes.py`;
  - OpenSearch status/provenance/host identity:
    `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/host_discovery.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/host_dictionary.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/server.py`;
  - run-command: `packages/sift-core/src/sift_core/execute/**`,
    `packages/sift-core/src/sift_core/agent_tools.py`,
    `scripts/setup-agent-runtime.sh`.
- Preserve the hostname carve-out: host detection/index naming is derived
  parser metadata, not case/evidence authority. `opensearch_fix_host_mapping`
  is the canonical correction tool; `opensearch_host_fix` is a deprecated alias.
- Preserve the Solana carve-out: optional SPL Memo anchoring strengthens
  external proof but never decides evidence gate state. DB custody chain heads
  remain authority.
- Split the blocking authority cutover into K1-K6 implementation batches and
  make BATCH-V1 depend on them.

Acceptance:

- `Migration-Spec.md` includes the authority cutover model, host identity
  carve-out, Solana anchor carve-out, and DB-active constraints.
- `task-batches.md` contains grep-friendly K-series checkboxes and executable
  batch sections.
- `Session-Notes.md` records the authority decision and next execution order.
- `python3 scripts/validate_docs.py` passes.
- `python3 scripts/validate_migration_docs.py` passes.

## BATCH-K1 - Authority context and DB audit cutover

Dependencies: BATCH-K0. This is the dependency root for K2-K6.

Status (2026-06-08): DONE - landed as `0e9577a`. K1 introduced
`AuthorityContext`, DB-active active-case fail-closed behavior, worker
`SIFT_DB_ACTIVE=1`, DB-first `app.audit_events` envelope writes, and mutating
fail-closed audit behavior. Conductor security review found and fixed one
pre-merge gap: the DB audit envelope now wraps proxy/evidence-gate denials after
case-context setup, and evidence-gate block results are MCP errors so DB result
receipts record `failure`.

Scope:

- `packages/sift-common/src/sift_common/__init__.py`
- `packages/sift-common/src/sift_common/audit.py`
- `packages/sift-core/src/sift_core/active_case_context.py`
- `packages/sift-core/src/sift_core/case_manager.py`
- `packages/sift-core/src/sift_core/case_ops.py`
- `packages/sift-gateway/src/sift_gateway/active_case.py`
- `packages/sift-gateway/src/sift_gateway/audit_helpers.py`
- `packages/sift-gateway/src/sift_gateway/policy_middleware.py`
- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/job_tools.py`
- `packages/sift-core/src/sift_core/execute/job_worker.py`
- `packages/sift-core/src/sift_core/execute/job_worker_cli.py`
- Existing DB migrations only if a narrow audit/helper RPC is missing; otherwise
  add a new timestamped migration.
- Gateway/common/core tests for active case, audit, and response redaction.

Exact work:

- Introduce or harden a single `AuthorityContext`/request context contract that
  carries case UUID, case key, artifact path for worker-only use, principal,
  membership role, tool scopes, evidence gate version/status, request ID, and
  audit event IDs.
- In DB-active mode, Gateway/core/worker must use this context for
  authoritative work. `SIFT_CASE_DIR`, `~/.sift/active_case`, and `CASE.yaml`
  remain legacy fallback only when DB authority is disabled.
- Replace JSONL-first audit on Gateway/core DB-active paths with DB-first
  audit writes to `app.audit_events`. The file writer may remain as an export
  or legacy fallback, but a required DB audit failure must fail a mutating
  call.
- For MCP/API calls, write a pre-dispatch audit envelope and a result/failure
  audit receipt. Mutating handlers must be able to attach those IDs to DB
  transitions.
- Ensure audit output and errors are path/secret redacted for agent callers.

Acceptance:

- Tests prove DB-active Gateway/tool calls do not read active case from
  `~/.sift/active_case`.
- Tests prove file pointer tampering cannot change the active case used by
  MCP/API calls.
- Tests prove mutating DB-active calls fail closed when required DB audit write
  fails.
- Tests prove audit rows carry request/tool/principal/case/provenance fields
  needed by K2-K6.
- Existing legacy CLI/file-mode tests still pass or are explicitly scoped as
  legacy fallback.

## BATCH-K2 - Core investigation DB authority cutover

Dependencies: BATCH-K1.

Scope:

- `packages/sift-core/src/sift_core/case_manager.py`
- `packages/sift-core/src/sift_core/case_io.py`
- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-core/src/sift_core/reporting.py`
- `packages/sift-gateway/src/sift_gateway/portal_services.py`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- `supabase/migrations/202606081500_report_metadata.sql` for contract
  reference; add a new timestamped migration only if schema/RPC gaps remain.
- Core, Gateway, portal, and DB tests for findings, timeline, TODOs, IOCs, and
  approvals.

Exact work:

- Add a typed investigation authority port/store used by core mutating tools:
  findings, timeline events, TODOs, IOCs, approvals/rejections, and content
  hashes.
- In DB-active mode, `record_finding`, `record_timeline_event`, and
  `manage_todo` write to `app.investigation_*` first and return DB-backed IDs.
  File writes are disabled or mirror-only.
- Approval/rejection/edit transitions must update the DB row, status, actor,
  re-auth audit ID, content hash, and approval metadata atomically.
- Portal reads and report generation must use DB rows only for DB-active cases.
- Prevent agent downgrades or overwrites of human-approved/rejected records:
  agents may create/update draft/proposed rows only.

Acceptance:

- Agent-created findings, timeline events, TODOs, and IOCs appear in portal
  from Postgres without reading case JSON.
- Portal approval/rejection updates Postgres and is visible to report
  generation.
- Tampering with `findings.json`, `timeline.json`, `todos.json`, `iocs.json`,
  or `approvals.jsonl` cannot alter portal state or report eligibility in
  DB-active mode.
- Race tests cover stale content hash/version on approval/edit.
- Approved-only report tests still pass using DB authority.

## BATCH-K3 - Evidence gate, proof export, and Solana anchor cutover

Dependencies: BATCH-K1. Can run in parallel with K2 and K4 after K1 lands.

Scope:

- `packages/sift-core/src/sift_core/evidence_chain.py`
- `packages/sift-core/src/sift_core/verification.py`
- `packages/sift-core/src/sift_core/case_io.py`
- `packages/sift-gateway/src/sift_gateway/evidence_gate.py`
- `packages/sift-gateway/src/sift_gateway/portal_services.py`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/case-dashboard/frontend/src/components/evidence/EvidenceTab.jsx`
- `supabase/migrations/202606081000_evidence_custody.sql` for contract
  reference; add a new timestamped migration only if proof export/anchor
  metadata is missing.
- Evidence/custody/proof-export tests.

Exact work:

- Ensure DB-active evidence gate reads only `app.evidence_gate_status` /
  `app.evidence_chain_heads` and never treats `evidence-manifest.json` or
  `evidence-ledger.jsonl` as gate authority.
- Make evidence detect/register/seal/ignore/retire/violation transitions write
  DB custody rows and chain heads first. File manifest/ledger writes become
  immutable proof exports or legacy fallback.
- Add or complete proof export generation from DB-derived evidence state:
  manifest snapshot, ledger/custody event snapshot, chain head, verification
  result, and optional storage/file object metadata.
- Preserve optional Solana anchoring as export proof only. Anchor payload must
  derive from DB custody proof material and record result in
  `app.evidence_proof_exports`; lack of Solana must not block sealing.
- New/changed file detection after seal must mark the case evidence gate non-OK
  until the operator resolves and seals again.

Acceptance:

- Tampering with `evidence-manifest.json`, `evidence-ledger.jsonl`, or
  `evidence-anchor-v*.json` cannot change evidence gate state in DB-active mode.
- Evidence gate fails closed when DB chain head is missing, violated, unsealed,
  or stale.
- Proof export verifies mounted evidence and records export metadata/hash in
  Postgres.
- Optional Solana anchor writes proof metadata when configured and degrades
  cleanly when not configured.

## BATCH-K4 - OpenSearch derived-state and host identity cutover

Dependencies: BATCH-K1; BATCH-F1/L1 OpenSearch job adapter. Can run in
parallel with K2, K3, and K5 after K1 lands.

Scope:

- `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`
- `packages/opensearch-mcp/src/opensearch_mcp/host_discovery.py`
- `packages/opensearch-mcp/src/opensearch_mcp/host_dictionary.py`
- `packages/opensearch-mcp/src/opensearch_mcp/server.py`
- `packages/opensearch-mcp/src/opensearch_mcp/registry.py`
- `packages/opensearch-mcp/sift-backend.json`
- `packages/sift-core/src/sift_core/execute/job_worker.py`
- `supabase/migrations/202606081300_opensearch_provenance.sql` for contract
  reference; add a new timestamped migration only if host identity/job-status
  tables/RPCs are missing.
- OpenSearch ingest/job/host identity tests and Gateway tool-surface snapshots.

Exact work:

- Keep hostname extraction/detection because parsers and index naming need it.
  Host identity is derived indexing metadata, not case/evidence authority.
- Move DB-active ingest status, per-artifact provenance manifests, host
  discovery decisions, host dictionary mutations, and host-fix receipts into
  Postgres-backed provenance/host-identity records.
- Treat local `host-dictionary.yaml`, ingest manifests, discovery reports, and
  ingest status JSON as legacy/parser-compatibility/debug artifacts only.
- Preserve `opensearch_fix_host_mapping` as the canonical correction tool and
  `opensearch_host_fix` as the deprecated alias. Both may mutate OpenSearch
  derived docs and host metadata only, with DB audit/provenance receipts.
- Ensure OpenSearch credentials and local paths never appear in agent-visible
  responses.

Acceptance:

- Ingest/job status visible to portal/agent comes from Postgres durable job and
  provenance state, not case status JSON.
- Host identity decisions/corrections are recorded in DB with source,
  canonical value, actor/tool, affected index/provenance IDs, and audit ID.
- Tampering with `host-dictionary.yaml` cannot change portal/Gateway authority
  in DB-active mode; at most it can affect a legacy parser compatibility file
  that is regenerated from DB.
- Existing parser/index-name behavior remains compatible.

## BATCH-K5 - run_command authority-isolation hardening

Dependencies: BATCH-K1; BATCH-I1/L1 run-command job path. Can run in parallel
with K2-K4 after K1 lands.

Scope:

- `packages/sift-core/src/sift_core/execute/tools/generic.py`
- `packages/sift-core/src/sift_core/execute/executor.py`
- `packages/sift-core/src/sift_core/execute/security.py`
- `packages/sift-core/src/sift_core/execute/security_policy.py`
- `packages/sift-core/src/sift_core/execute/run_command_job.py`
- `packages/sift-core/src/sift_core/execute/runtime_acl.py`
- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-gateway/src/sift_gateway/job_tools.py`
- `scripts/setup-agent-runtime.sh`
- `configs/systemd/sift-job-worker.service`
- Execution, ACL, redaction, and job tests.

Exact work:

- Ensure `run_command` receives opaque evidence refs/input refs and controlled
  output refs only. Worker-only path resolution must happen after DB job claim,
  evidence gate check, and audit pre-event.
- Strip DB DSNs, Supabase keys, service-role secrets, OpenSearch credentials,
  local VM secrets, and unrelated environment variables from the run-command
  subprocess environment.
- Ensure runtime user ACLs cannot read/write authority files. In the final
  model, critical authority files should not exist in the case dir; remaining
  proof/export files are read-only unless an operator/export process writes
  them.
- Persist output receipt metadata in Postgres: command plan hash, evidence refs,
  stdout/stderr preview hash, output refs, output file hash, audit IDs, job ID,
  and provenance ID.
- Keep `shell=False`, deny floor, allowlist profiles, path redaction, and
  bounded output previews.

Acceptance:

- Allowed commands work against sealed evidence refs and return job/status plus
  redacted previews only.
- Denied commands fail closed and are audited.
- A command cannot read DB secrets from env, cannot write authority state, and
  cannot cause portal/report/evidence gate state changes except through
  approved DB authority APIs.
- Output receipts are DB-backed and reportable without local paths.

## BATCH-K6 - Portal/report tamper regression and file-authority removal

Dependencies: BATCH-K2; BATCH-K3; BATCH-K4 for OpenSearch status views if
included; BATCH-K5 for run-command receipts.

Scope:

- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/case-dashboard/frontend/src/**` only for surfaced authority labels
  or removed file fallback flows
- `packages/sift-gateway/src/sift_gateway/portal_services.py`
- `packages/sift-core/src/sift_core/reporting.py`
- `packages/sift-core/src/sift_core/audit_ops.py`
- `packages/sift-core/src/sift_core/backup_ops.py`
- End-to-end portal/Gateway/core/security regression tests.

Exact work:

- Remove or gate DB-active file fallbacks from portal views, approvals, report
  generation, audit views, backup/export views, and status endpoints.
- Add tamper regression tests that modify or delete legacy files and prove DB
  portal state, MCP state, evidence gate, approvals, report eligibility, and
  report output do not change.
- Keep legacy file mode explicitly available for old tests/CLI only when DB
  authority is not configured.
- Update visible portal labels only where needed so the operator can see DB
  authority versus export/debug artifacts.
- Confirm no duplicate state write path remains where file success can mask DB
  failure for critical mutable state.

Acceptance:

- Portal and report generation remain functional after legacy JSON/JSONL files
  are absent, stale, corrupt, or tampered in DB-active mode.
- Tests prove file tampering cannot approve findings, alter todos/timeline,
  change evidence seal state, change report inclusion, or spoof audit/custody.
- Any remaining file fallback is protected by an explicit legacy-mode guard.
- BATCH-V1 can resume with the authority cutover no longer blocking approval,
  report, ingest status, RAG verification, or run-command proof.

## BATCH-V1 - End-to-end validation and cutover

Dependencies: BATCH-A1; BATCH-B1; BATCH-C1; BATCH-D1; BATCH-D2; BATCH-E1; BATCH-F1; BATCH-G1; BATCH-H1; BATCH-I1; BATCH-J1; BATCH-L1; BATCH-K1; BATCH-K2; BATCH-K3; BATCH-K4; BATCH-K5; BATCH-K6.

Status (2026-06-08): IN_PROGRESS - first live VM run done, and the remaining V1
enablers are now integrated on `revamp/spg-v1`: B-MVP-8 installer
operator-profile/control-plane env, B-MVP-9 default-case agent issuance,
B-MVP-11 `rag_search_case` proxy-denial fix, B-MVP-12 per-case
`agent_runtime` ACLs, B-MVP-13 local-HMAC MVP re-auth decision, B-MVP-14
atomic register+seal journey decision, and B-MVP-15 pgvector seed path. Earlier
live validation covered auth, forced reset, case DB authority, evidence
detect/seal, custody hash chain, agent credential/MCP, path redaction,
pre-seal deny/post-seal allow, and the run_command deny floor. NOT complete:
live VM cutover must still apply/restart from the integrated root and drive
`ingest_job`/OpenSearch, seeded pgvector `rag_search_case`, allowed
`run_command`, report export, and custody proof export. Box stays unchecked
until the full live journey completes.

Scope:

- End-to-end tests and smoke scripts.
- VM deployment/test instructions if needed.
- `docs/migration/Session-Notes.md`
- `docs/migration/task-batches.md`

Exact work:

- Run the Phase 3 smoke journey from `Migration-Spec.md`.
- Run package tests for changed areas.
- Run document validators.
- Confirm no agent-visible absolute paths or secrets.
- Confirm old file-backed authority paths are not needed for the demo journey.
- Mark all completed batches and record final validation evidence at the top of
  `Session-Notes.md`.

Acceptance:

- SIFT VM demo flow works end to end.
- Security checks cover auth, authorization, access control, evidence gate,
  response guard, audit, custody, jobs, and report approval.
- The MVP is ready to freeze for the hackathon demo.

## Parallel Prompt Pack

Use these prompts after the governance/doc-freeze commit is available on
`revamp/spg-v1`. Suggested worktree names are examples; adjust only the branch
suffix if needed.

### PROMPT-A1 - Installer and bootstrap

Suggested worktree:

```bash
git worktree add ../sift-mcps-a1 -b revamp/mvp-a1-installer-bootstrap revamp/spg-v1
```

Prompt:

```text
ROLE & MODE
You are the BATCH-A1 coding agent for the SIFT MVP sprint. Build the installer/bootstrap slice. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md sections 1, 2, 3 Phase 1, 4, and 5; docs/migration/task-batches.md BATCH-A1; docs/migration/Session-Notes.md latest entry and resolved F-MVP decisions.

GROUND IN SOURCE
Inspect only the BATCH-A1 scope paths before editing: install.sh; configs/gateway.yaml.template; configs/systemd/sift-gateway.service; configs/audit/99-sift-evidence.rules; configs/apparmor/sift-gateway.template; scripts/setup-agent-runtime.sh; packages/sift-gateway/src/sift_gateway/config.py; packages/sift-gateway/src/sift_gateway/health.py; packages/sift-gateway/src/sift_gateway/supabase_auth.py; packages/case-dashboard/src/case_dashboard/auth.py; packages/case-dashboard/src/case_dashboard/routes.py; directly related tests.

DELIVERABLE
Implement the final installer/bootstrap path: installation, config rendering, hardening, health check, Supabase-first operator bootstrap/forced reset, evidence root validation, and case path creation using /cases/case-<slug>-<MMDDHHSS> with -NN collision suffix.

HARD CONSTRAINTS
Do not add evidence DB schema, durable jobs, OpenSearch adapters, RAG changes, add-on changes, or report changes. Do not store secrets in repo files. Preserve /usr/bin/python3.12, UV_NO_MANAGED_PYTHON=1, and UV_PYTHON_DOWNLOADS=never for the SIFT VM.

OUTPUT DISCIPLINE
Keep the scope fence. Do not edit docs/migration in this worker branch. End with a LANDING LOG block containing changed files, tests run, acceptance status, and any follow-up needed.

ACCEPTANCE
Operator can receive a one-time forced-reset handoff, login/reset through portal, create and activate a case with re-auth, and health output covers Gateway, portal, Supabase, evidence root, and configured services.
```

### PROMPT-B1 - Gateway policy and redaction

Suggested worktree:

```bash
git worktree add ../sift-mcps-b1 -b revamp/mvp-b1-gateway-policy-redaction revamp/spg-v1
```

Prompt:

```text
ROLE & MODE
You are the BATCH-B1 coding agent for the SIFT MVP sprint. Build the Gateway policy/redaction slice. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md architecture invariants, trust boundaries, Phase 2 journey, and technical constraints; docs/migration/task-batches.md BATCH-B1; docs/migration/Session-Notes.md resolved F-MVP-2 and F-MVP-3.

GROUND IN SOURCE
Inspect only the BATCH-B1 scope paths before editing: packages/sift-gateway/src/sift_gateway/server.py; rest.py; mcp_server.py; mcp_endpoint.py; policy_middleware.py; evidence_gate.py; response_guard.py; rate_limit.py; packages/sift-core/src/sift_core/agent_tools.py; directly related Gateway/core tests.

DELIVERABLE
Make agent access MCP-only for the MVP, make REST tool execution operator-only, and sanitize agent-visible results. Agent-visible evidence data may include evidence_id, display name, relative display path, size, hash, seal status, and provenance ID. It must not include absolute case/evidence/mount paths or secrets.

HARD CONSTRAINTS
Do not implement installer changes, DB evidence authority, durable jobs, portal feature rewrites, OpenSearch adapters, RAG, add-ons, or reports. Keep evidence gate fail-closed.

OUTPUT DISCIPLINE
Keep the scope fence. Do not edit docs/migration in this worker branch. End with a LANDING LOG block containing changed files, tests run, acceptance status, path-redaction evidence, and any follow-up needed.

ACCEPTANCE
Tests prove agent tokens cannot use REST to bypass MCP policy; case_info/evidence_info/finding views/run-command previews expose no absolute paths; evidence-gate denial is fail-closed and audited; response guard and rate limits still apply.
```

### PROMPT-C1 - Evidence authority and custody ledger

Suggested worktree:

```bash
git worktree add ../sift-mcps-c1 -b revamp/mvp-c1-evidence-custody revamp/spg-v1
```

Prompt:

```text
ROLE & MODE
You are the BATCH-C1 coding agent for the SIFT MVP sprint. Build the DB evidence authority and custody ledger slice. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md component mapping, trust boundaries, Phase 2 journey, and DoD; docs/migration/task-batches.md BATCH-C1; docs/migration/Session-Notes.md resolved F-MVP-1 and F-MVP-2.

GROUND IN SOURCE
Inspect only the BATCH-C1 scope paths before editing: supabase/migrations/*.sql; packages/sift-gateway/src/sift_gateway/evidence_gate.py; packages/sift-gateway/src/sift_gateway/audit_helpers.py; packages/sift-core/src/sift_core/evidence_chain.py; verification.py; case_io.py; directly related evidence/custody tests.

DELIVERABLE
Add Postgres evidence metadata, evidence versions, custody events, hash-chain heads, seal status, and proof-export metadata. Add service-only transition RPCs for detect/register/seal/verify/ignore/retire/violation. Keep file manifests/proofs as exports, not authority.

HARD CONSTRAINTS
The AI agent never receives local paths. Evidence IDs resolve to mounted paths only inside broker/worker code. Do not wire portal UI broadly in this branch if it overlaps another worker; return route/UI follow-up for BATCH-E1. Do not add durable job worker logic.

OUTPUT DISCIPLINE
Use a new timestamped SQL migration file; do not edit prior migrations unless unavoidable and explained. Do not edit docs/migration in this worker branch. End with a LANDING LOG block containing changed files, tests run, acceptance status, and any route/UI follow-up.

ACCEPTANCE
DB state can represent detected, registered, sealed, ignored, retired, and violated evidence. Seal requires re-auth transition support. Custody events are append-only/hash-linked. Proof export can verify mounted evidence without making file manifests authoritative.
```

### PROMPT-D1 - Durable jobs and worker loop

Suggested worktree:

```bash
git worktree add ../sift-mcps-d1 -b revamp/mvp-d1-durable-jobs revamp/spg-v1
```

Prompt:

```text
ROLE & MODE
You are the BATCH-D1 coding agent for the SIFT MVP sprint. Build the durable Postgres job and local worker slice. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md durable job state machine, worker, run-command, and Phase 2 journey; docs/migration/task-batches.md BATCH-D1; docs/migration/Session-Notes.md latest entry.

GROUND IN SOURCE
Inspect only the BATCH-D1 scope paths before editing: supabase/migrations/*.sql; packages/sift-core/src/sift_core/execute/worker.py; existing execute modules and tests; only Gateway files needed for a minimal enqueue/status adapter if BATCH-B1 has already landed in your branch.

DELIVERABLE
Add minimal Postgres job tables/RPCs and a local worker claim loop: jobs, job_steps, job_logs, worker heartbeats, typed statuses, claim lease, status update, failure logging, and retry/expiry behavior.

HARD CONSTRAINTS
Do not introduce Redis/RQ/Celery/Temporal. Do not take arbitrary client paths. Worker receives case_id/evidence_id/job_id and resolves local paths internally after policy. Avoid Gateway edits if they overlap BATCH-B1; return the enqueue/status adapter as follow-up if needed.

OUTPUT DISCIPLINE
Use a new timestamped SQL migration file separate from BATCH-C1. Do not edit docs/migration in this worker branch. End with a LANDING LOG block containing changed files, tests run, lease/race behavior evidence, and any follow-up.

ACCEPTANCE
Concurrent workers cannot claim the same job; lease expiry/retry is tested; portal/agent callers can poll sanitized status when the adapter is present; failed jobs preserve audit/provenance and sanitized logs.
```

### PROMPT-D2 - Gateway job adapter and authority enforcement

Suggested worktree:

```bash
git worktree add ../sift-mcps-d2 -b revamp/mvp-d2-gateway-job-contract-seam revamp/spg-v1
```

Prompt:

```text
ROLE & MODE
You are the BATCH-D2 coding agent for the SIFT MVP sprint. Build the Gateway integration seam for jobs and add-on authority contracts. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md Gateway, Durable Job State Machine, Postgres Control Plane, derived/reference planes, and technical constraints; docs/migration/task-batches.md BATCH-D2; docs/migration/Session-Notes.md latest entry and B-MVP-3/B-MVP-4 rows.

GROUND IN SOURCE
Inspect only the BATCH-D2 scope paths before editing: packages/sift-gateway/src/sift_gateway/rest.py; server.py; mcp_server.py; mcp_endpoint.py; mcp_backends_registry.py; backends/**; sift-backend.schema.json; packages/sift-gateway/tests relevant to jobs/backend registry/scopes/manifests; supabase/migrations/202606081200_durable_jobs.sql only to confirm RPC/view names.

DELIVERABLE
Add the Gateway adapter over D1 job surfaces: enqueue_job, job_status_public, and expire_stale_jobs. Enqueue returns only job_id and stores the Gateway audit event id as enqueue_audit_event_id. Status responses are sanitized. Also enforce H1 authority_contract at runtime: non_authoritative, prohibited_operations, and tool required_scopes before backend dispatch. Keep transport: library manifests accepted but non-routable.

HARD CONSTRAINTS
Do not implement portal UI, OpenSearch ingest handlers, RAG, run_command handlers, report generation, or evidence UI. Do not expose DB errors, local paths, worker files, or credentials. Add SQL only if a minimal grant/wrapper is unavoidable and explain it.

OUTPUT DISCIPLINE
Keep the scope fence. Do not edit docs/migration in this worker branch. End with a LANDING LOG block containing changed files, tests run, acceptance status, and whether E1/F1/G1/I1 can launch without more Gateway glue.

ACCEPTANCE
Tests prove job enqueue/status returns sanitized job_id/status only; missing required add-on scopes deny before backend dispatch; prohibited authority operations deny before backend dispatch; library manifests remain non-routable; existing Gateway backend registry tests stay green.
```

### PROMPT-H1 - Add-on contract hardening

Suggested worktree:

```bash
git worktree add ../sift-mcps-h1 -b revamp/mvp-h1-addon-contracts revamp/spg-v1
```

Prompt:

```text
ROLE & MODE
You are the BATCH-H1 coding agent for the SIFT MVP sprint. Build the add-on contract hardening slice. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md architecture invariants and derived/reference planes; docs/migration/task-batches.md BATCH-H1; docs/migration/Session-Notes.md latest entry.

GROUND IN SOURCE
Inspect only the BATCH-H1 scope paths before editing: packages/opencti-mcp/src/opencti_mcp/**; packages/windows-triage-mcp/src/windows_triage_mcp/**; packages/forensic-knowledge/src/**; packages/*/sift-backend.json; directly related add-on tests and surface snapshots.

DELIVERABLE
Align OpenCTI, Windows triage, and forensic knowledge add-ons with the final contract: query-only, audited, scoped, deterministic tool metadata, and non-authoritative. Preserve Windows triage baseline value and forensic knowledge discipline snippets.

HARD CONSTRAINTS
Add-ons must not create cases, seal evidence, approve findings, approve reports, expose secrets, bypass Gateway, or become case authority. Avoid Gateway registry edits if they overlap another worker; return integration follow-up if needed.

OUTPUT DISCIPLINE
Keep the scope fence. Do not edit docs/migration in this worker branch. End with a LANDING LOG block containing changed files, tests/snapshots run, acceptance status, and any registry follow-up.

ACCEPTANCE
Add-on metadata clearly marks capabilities and required scopes; query-only behavior is tested or snapshotted; tool surface snapshots remain deterministic; no add-on gains authority over cases, evidence, approvals, or reports.
```

## Next Prompt

Launch BATCH-K2, BATCH-K3, BATCH-K4, and BATCH-K5 in parallel worktrees.
BATCH-K6 waits until K2-K5 land. BATCH-V1 remains blocked until K1-K6 close the
DB-active authority cutover.

Suggested worktrees:

```bash
git worktree add ../sift-mcps-k2 -b revamp/mvp-k2-investigation-db-authority revamp/spg-v1
git worktree add ../sift-mcps-k3 -b revamp/mvp-k3-evidence-proof-cutover revamp/spg-v1
git worktree add ../sift-mcps-k4 -b revamp/mvp-k4-opensearch-host-authority revamp/spg-v1
git worktree add ../sift-mcps-k5 -b revamp/mvp-k5-run-command-authority-isolation revamp/spg-v1
```

### PROMPT-K2 - Core investigation DB authority

```text
ROLE & MODE
You are the BATCH-K2 coding agent for the SIFT MVP sprint. Cut over core
investigation state to Postgres authority in DB-active mode. Do not redesign the
architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md sections 2, 3, 4,
and 5, especially "Authority cutover impact model"; docs/migration/task-batches.md
BATCH-K2; the latest entry in docs/migration/Session-Notes.md.

SCOPE
Own BATCH-K2 only. Inspect and edit only the K2 scope paths unless a test proves
a minimal adjacent change is required: sift_core case_manager/case_io/agent_tools/
reporting; sift_gateway portal_services; case-dashboard routes; the existing
202606081500 report/investigation migration for contract reference; direct core,
Gateway, portal, and DB tests.

SECURITY INVARIANTS
In DB-active mode, findings, timeline, TODOs, IOCs, approvals, report
eligibility, and content hashes are Postgres authority. JSON/JSONL files are
legacy fallback or mirror/export only. Agents cannot overwrite human-approved or
rejected records. Mutations must carry AuthorityContext audit event IDs.

DELIVERABLE
Implement the typed investigation authority store/port and wire agent tools,
portal approval/rejection/edit flows, and report reads to DB authority for
DB-active cases.

OUTPUT DISCIPLINE
Do not edit docs/migration in this worker branch. End with a LANDING LOG block:
changed files, tests run, acceptance evidence, schema/RPC gaps, and any K6
tamper-regression follow-up.

ACCEPTANCE
Agent-created findings/timeline/TODO/IOC records appear in portal from Postgres
without case JSON; portal approval/rejection updates DB and report eligibility;
tampering with findings/timeline/todos/iocs JSON or approvals.jsonl cannot alter
DB-active portal/report state; stale content-hash/version races are tested.
```

### PROMPT-K3 - Evidence proof and gate cutover

```text
ROLE & MODE
You are the BATCH-K3 coding agent for the SIFT MVP sprint. Cut over evidence
gate/proof export/Solana anchor behavior to DB authority. Do not redesign the
architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md sections 2, 3, 4,
and 5, especially the evidence, proof-export, and Solana carve-out parts;
docs/migration/task-batches.md BATCH-K3; the latest entry in
docs/migration/Session-Notes.md.

SCOPE
Own BATCH-K3 only. Inspect and edit only the K3 scope paths unless a test proves
a minimal adjacent change is required: sift_core evidence_chain/verification/
case_io; sift_gateway evidence_gate/portal_services; case-dashboard evidence
routes/UI; the existing 202606081000 evidence custody migration for contract
reference; direct evidence/custody/proof-export tests.

SECURITY INVARIANTS
In DB-active mode, evidence gate state comes only from Postgres chain heads and
custody events. File manifests, ledgers, and anchor JSON are proof exports or
legacy fallback only. Optional Solana anchoring is external proof, not authority.

DELIVERABLE
Ensure evidence detect/register/seal/ignore/retire/violation transitions are
DB-first, proof exports derive from DB custody material, and new/changed files
after seal make the DB evidence gate non-OK until resolved and resealed.

OUTPUT DISCIPLINE
Do not edit docs/migration in this worker branch. End with a LANDING LOG block:
changed files, tests run, acceptance evidence, Solana/export behavior, and any
K6 tamper-regression follow-up.

ACCEPTANCE
Tampering with evidence-manifest.json, evidence-ledger.jsonl, or anchor JSON
cannot change DB-active gate state; missing/violated/unsealed/stale DB chain head
fails closed; proof export verifies mounted evidence and records metadata/hash in
Postgres; Solana configured/unconfigured paths degrade correctly.
```

### PROMPT-K4 - OpenSearch and host identity authority

```text
ROLE & MODE
You are the BATCH-K4 coding agent for the SIFT MVP sprint. Cut over OpenSearch
ingest status/provenance and host identity decisions to Postgres-backed derived
state. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md sections 2, 3, 4,
and 5, especially the OpenSearch/host identity carve-out; docs/migration/task-batches.md
BATCH-K4; the latest entry in docs/migration/Session-Notes.md.

SCOPE
Own BATCH-K4 only. Inspect and edit only the K4 scope paths unless a test proves
a minimal adjacent change is required: opensearch_mcp ingest/ingest_cli/
ingest_status/host_discovery/host_dictionary/server/registry/sift-backend.json;
sift_core job_worker; the existing 202606081300 OpenSearch provenance migration
for contract reference; direct OpenSearch/job/host tests and Gateway snapshots.

SECURITY INVARIANTS
Hostname detection/index naming remains required derived parser metadata.
Host identity and ingest status do not authorize cases, evidence, approvals, or
reports. Local host-dictionary/status/manifest files are parser compatibility,
debug, or legacy only in DB-active mode.

DELIVERABLE
Move DB-active ingest status, provenance manifests, host discovery decisions,
host dictionary mutations, and host-fix receipts into Postgres-backed records.
Preserve `opensearch_fix_host_mapping` canonical behavior and deprecated
`opensearch_host_fix` alias without leaking paths/credentials.

OUTPUT DISCIPLINE
Do not edit docs/migration in this worker branch. End with a LANDING LOG block:
changed files, tests run, acceptance evidence, schema/RPC gaps, and any K6
tamper-regression follow-up.

ACCEPTANCE
Portal/agent ingest status comes from Postgres job/provenance state; host
identity decisions/corrections are DB-recorded with source/canonical/actor/tool/
affected IDs/audit ID; tampering with host-dictionary.yaml cannot change
DB-active authority; parser/index behavior remains compatible.
```

### PROMPT-K5 - run_command authority isolation

```text
ROLE & MODE
You are the BATCH-K5 coding agent for the SIFT MVP sprint. Harden run_command so
it cannot read/write authority state and persists command receipts in Postgres.
Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md sections 2, 3, 4,
and 5, especially the run_command and authority cutover constraints;
docs/migration/task-batches.md BATCH-K5; the latest entry in
docs/migration/Session-Notes.md.

SCOPE
Own BATCH-K5 only. Inspect and edit only the K5 scope paths unless a test proves
a minimal adjacent change is required: sift_core execute generic/executor/
security/security_policy/run_command_job/runtime_acl/agent_tools; Gateway
job_tools; setup-agent-runtime.sh; sift-job-worker systemd unit; direct execution,
ACL, redaction, and job tests.

SECURITY INVARIANTS
run_command receives opaque evidence/input refs and controlled output refs only.
It must not inherit DB DSNs, Supabase keys, service-role secrets, OpenSearch
credentials, VM secrets, or unrelated env. It must not read/write authority files
or change portal/report/evidence state except through approved DB authority APIs.

DELIVERABLE
Harden job-backed run_command path resolution/env/ACLs, persist command receipt
metadata in Postgres, keep shell=False/deny floor/allowlist profiles/path
redaction/bounded previews, and prove allowed and denied paths.

OUTPUT DISCIPLINE
Do not edit docs/migration in this worker branch. End with a LANDING LOG block:
changed files, tests run, acceptance evidence, ACL/env proof, and any K6
tamper-regression follow-up.

ACCEPTANCE
Allowed commands work against sealed evidence refs and return job/status plus
redacted previews; denied commands fail closed and are audited; commands cannot
read DB/service secrets or write authority state; output receipts are DB-backed
and reportable without local paths.
```
