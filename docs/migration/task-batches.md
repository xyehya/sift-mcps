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
- [ ] BATCH-E1 - Portal authority migration for evidence, findings, timeline, TODOs, and reports
- [ ] BATCH-F1 - OpenSearch secure core integration and ingest job adapter
- [ ] BATCH-G1 - RAG pgvector target with provenance filters
- [x] BATCH-H1 - Add-on contract hardening for OpenCTI, Windows triage, and forensic knowledge
- [ ] BATCH-I1 - Sandboxed run_command uplift
- [ ] BATCH-J1 - Approved-only report generation and export
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

## BATCH-E1 - Portal authority migration for evidence, findings, timeline, TODOs, and reports

Dependencies: BATCH-B1; BATCH-C1 for evidence; BATCH-D1 for job-backed actions.

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

Dependencies: BATCH-D1; BATCH-C1 for evidence IDs.

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

Dependencies: BATCH-D1; BATCH-C1 for evidence provenance; BATCH-B1 for Gateway policy.

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

Dependencies: BATCH-B1; BATCH-C1 for evidence refs; BATCH-D1 for job backing.

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

Dependencies: BATCH-E1; BATCH-D1; BATCH-C1.

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

## BATCH-V1 - End-to-end validation and cutover

Dependencies: BATCH-A1; BATCH-B1; BATCH-C1; BATCH-D1; BATCH-E1; BATCH-F1; BATCH-G1; BATCH-H1; BATCH-I1; BATCH-J1.

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

## Dependent Prompt Order

After BATCH-B1, BATCH-C1, and BATCH-D1 land, launch:

- BATCH-E1 for portal DB authority migration.
- BATCH-F1 for OpenSearch secure ingest job adapter.
- BATCH-G1 for RAG pgvector and provenance filters.
- BATCH-I1 for job-backed sandboxed `run_command`.
- BATCH-J1 for approved-only report generation and export.
- BATCH-V1 after all implementation batches land.
