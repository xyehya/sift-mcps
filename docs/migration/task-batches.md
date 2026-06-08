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

## BATCH-V1 - End-to-end validation and cutover

Dependencies: BATCH-A1; BATCH-B1; BATCH-C1; BATCH-D1; BATCH-D2; BATCH-E1; BATCH-F1; BATCH-G1; BATCH-H1; BATCH-I1; BATCH-J1; BATCH-L1.

Status (2026-06-08): IN_PROGRESS - first live VM run done. Security core
validated end to end (auth, forced reset, case DB authority, evidence
detect/seal, custody hash chain, agent credential/MCP, path redaction, pre-seal
deny/post-seal allow, run_command deny floor); migrations apply clean to live
Supabase; unit suites and both doc validators passed. Three live defects fixed:
health `apikey`, invited-login deadlock, and custody `digest()` on Supabase. NOT
complete: agent findings/timeline reach only the case file, so portal approval
and approved-only report are blocked on the agent-to-DB investigation bridge;
`ingest_job`/OpenSearch, `rag_search_case`, allowed `run_command`, report
export, and custody proof export still need to be driven. The live pgvector RAG
tables are empty (`app.rag_collections=0`, `app.rag_documents=0`,
`app.rag_chunks=0`), so any successful knowledge-style VM answers were legacy
`kb_*`/forensic-knowledge responses, not the new Supabase pgvector path. See
`Session-Notes.md` `BATCH-V1` entry plus F-MVP-5..7 and B-MVP-8..15. Box stays
unchecked until the full journey completes.

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

Launch BATCH-V1 next. No additional implementation batch is currently open.

Suggested worktree:

```bash
git worktree add ../sift-mcps-v1 -b revamp/mvp-v1-validation-cutover revamp/spg-v1
```

Prompt:

```text
ROLE & MODE
You are the BATCH-V1 validation/cutover agent for the SIFT MVP sprint. Do not
start new architecture work. Validate the integrated MVP on the live SIFT VM,
fix only defects that block the Phase 3 smoke journey, and keep the repo in a
clean, committable state.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md sections 2, 3, 4,
and 5; docs/migration/task-batches.md BATCH-V1 and BATCH-L1; the latest two
entries in docs/migration/Session-Notes.md.

SCOPE
Own BATCH-V1 only. Apply Supabase migrations in timestamp order, start/verify
Gateway and sift-job-worker, run the Phase 3 smoke journey, run package tests
for any changed code, and update only task-batches.md and Session-Notes.md for
final validation evidence. If a live defect appears, fix it in the smallest
relevant code surface and rerun the failing smoke/test step.

SECURITY INVARIANTS
No agent-visible absolute case/evidence/mount paths, DB credentials,
OpenSearch credentials, service-role keys, or local secrets. Gateway remains
the policy boundary. Supabase/Postgres remains authority. Evidence must be
registered and sealed before analysis. Reports include approved findings only.

ACCEPTANCE
The SIFT VM flow works end to end: install/health, operator forced reset, case
create/activate, evidence detect/register/seal, one-time agent credential,
MCP connection, pre-seal denial and post-seal allow, ingest_job/job_status,
search/RAG query, record finding/timeline/TODO, portal approval, approved-only
report generation/export, allowed/denied run_command examples, and audit/custody
proof export. Both doc validators pass. Record all live validation evidence in
Session-Notes.md and mark BATCH-V1 only after acceptance passes.
```
