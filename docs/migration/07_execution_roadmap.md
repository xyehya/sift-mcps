# Execution Roadmap

Last updated: 2026-06-07.

Scope: planning only. This document converts the execution current-state
inventory, target job model, and integration contracts into an incremental
migration roadmap. It does not implement code, create database migrations,
refactor REST APIs, MCP tools, frontend views, OpenSearch, evidence, audit, or
worker code. It does not introduce Redis, RQ, Celery, Temporal, or any external
queue.

> Cutover order (locked, charter D17): this JOB-* roadmap is the **execution
> track**. The **identity/cases/tokens foundation track**
> (`09_identity_auth_cutover.md`, phases ID-0..ID-6) lands first, because the
> case-scoped job APIs (JOB-5/JOB-6) require control-plane case authorization,
> active-case authority, and the hash-only token registry to exist. JOB-0
> baseline tests are additive and order-independent and may run in parallel.
>
> Other locks reflected below: v1 job schema is the **lean core** (`jobs`,
> `job_steps`, `job_logs`, `workers`; defer `job_attempts`/`job_cancellations`/
> `worker_heartbeats`; row-level attempt/cancel/heartbeat fields), single local
> worker, no cross-case fairness until a second worker exists (D13/D9).
> Disabling per-backend `/mcp/{name}` routes is an **early hardening step**
> (folded into the identity track ID-5 and reinforced in JOB-6), not a late one
> (D3). OpenSearch is 3.5.0 security-on (D6).

## 1. Executive Summary

The execution migration moves SIFT from scattered file-based workflow and
status handling toward Postgres/Supabase-authoritative durable jobs.

Target direction:

- Move long-running workflow state from case JSON, pending review files,
  `~/.sift/ingest-status`, ingest logs, in-memory report drafts, active-case
  pointers, and process-local status into durable Postgres/Supabase job state.
- Preserve existing evidence vault behavior, including immutable raw evidence,
  manifest/ledger proof artifacts, and current audit behavior during the
  transition.
- Keep OpenSearch as a core search/data plane for derived forensic data, but
  never as the authority for workflows, jobs, evidence integrity, approvals, or
  audit.
- Make long-running REST and MCP actions enqueue jobs and return job IDs in the
  target design.
- Make SIFT workers claim jobs from Postgres using ordinary database ownership,
  leases, heartbeats, and stale-job recovery.
- Avoid Redis/RQ and avoid replacing Postgres with any external queue.
- Migrate additively first: establish tests, interfaces, schemas, repositories,
  and no-op workers before converting real parser, evidence, OpenSearch, report,
  or finding workflows.
- Deprecate file-based workflow authority only after DB-backed equivalents,
  compatibility exports, tests, and operator workflows are validated.

## 2. Migration Principles

- Additive before destructive.
- Preserve working evidence vault behavior.
- Preserve existing operator workflows during transition.
- Do not remove current parser paths until DB-backed equivalents are tested.
- Do not let frontend mutate authoritative job state directly.
- Do not let MCP tools run long parsers synchronously in the final design.
- Do not make OpenSearch optional or standalone in the target architecture.
- Keep all job state, step state, parser run state, and indexing status in
  Postgres/Supabase in the target design.
- Keep audit mandatory.
- Keep agent-generated findings proposed or pending, not approved.
- Keep each future implementation PR small enough for one Codex coding session.
- Avoid broad refactors until baseline tests and fixtures exist.
- Preserve current shell-free native execution discipline when native workflows
  are later wrapped by jobs.
- Prefer compatibility bridges and adapters over rewrites until the target
  service boundary is tested.
- Treat OpenSearch degradation, worker unavailability, and DB unavailability as
  explicit states, not empty results or silent fallbacks.

## 3. Execution Migration Phases

Each phase is designed to be small enough to split into one or more focused
implementation PRs. A later coding session should take one phase slice, inspect
only the relevant files, add tests first where practical, and avoid unrelated
refactors.

### Phase JOB-0 - Baseline tests and execution fixtures

Goal: document and test current execution-critical paths before modifying
behavior.

Scope:

- Capture current parser, ingest, evidence, audit, report, OpenSearch status,
  and MCP-triggered workflow behavior with minimal smoke tests and fixtures.
- Favor tests that use temporary directories, mocks, and request-construction
  checks rather than live services.
- Document how to run the baseline checks locally.

Likely files to change:

- Existing test directories under `packages/sift-core`, `packages/sift-common`,
  `packages/opensearch-mcp`, `packages/sift-gateway`, and
  `packages/case-dashboard` where matching test structure exists.
- `docs/migration/*` or package test docs for baseline check instructions.

Likely new files:

- Baseline evidence/audit smoke tests.
- Baseline ingest status or OpenSearch request-shaping tests.
- Small fixture files for parser/ingest smoke tests when safe.
- A short baseline execution checks note.

Tests to add:

- Evidence vault regression for manifest/ledger or chain status behavior using
  temporary case/state directories.
- Audit regression proving JSONL audit write shape and case-scoped location.
- Parser/ingest smoke fixture for one already-testable path, if it does not
  require a live OpenSearch instance.
- OpenSearch degraded/request-construction/status-shaping test that avoids a
  live OpenSearch dependency.
- MCP-triggered workflow smoke test only where it can be isolated without
  running long parsers.

Acceptance criteria:

- Tests pass without changing runtime behavior.
- Tests do not require a live OpenSearch cluster unless explicitly marked and
  skipped by default.
- Current file-backed behavior remains authoritative.
- No database migration, worker dispatcher, job service, frontend change, MCP
  rewrite, parser conversion, or OpenSearch refactor is included.

Rollback strategy:

- Remove the added tests, fixtures, and docs note. No runtime rollback is
  needed because behavior is unchanged.

Risks:

- Fixtures may accidentally depend on local workstation paths.
- Tests may be too broad and pull in unrelated services.
- Current behavior may be hard to isolate without small helper fixtures.

Dependencies on earlier phases:

- None.

What remains intentionally unchanged:

- All runtime evidence, audit, parser, OpenSearch, REST, MCP, frontend, report,
  and worker behavior.

### Phase JOB-1 - Add job domain interfaces, no database yet

Goal: add backend/core interfaces or abstractions for job creation, status,
steps, and logs without changing runtime behavior.

Scope:

- Define small domain types or protocols for jobs, job steps, job logs,
  parser-run metadata, indexing status, worker records, and job repository
  operations.
- Keep these interfaces unused or behind tests until DB-backed implementation
  exists.
- Avoid importing Supabase/Postgres clients in this phase.

Likely files to change:

- `packages/sift-core/src/sift_core/*`
- Potentially `packages/sift-gateway/src/sift_gateway/*` for type boundaries
  only if the repo pattern places service contracts there.
- Matching package tests.

Likely new files:

- `packages/sift-core/src/sift_core/jobs/` interface modules.
- Job domain unit tests.

Tests to add:

- Status transition validation tests.
- Job type/spec summary tests.
- Log redaction helper tests if a small pure helper is introduced.
- Interface fake tests that prove callers can be written against the contract
  without a database.

Acceptance criteria:

- Pure unit tests pass.
- Existing runtime paths are not wired to the new interfaces.
- No DB dependency, migration, worker process, API route, MCP tool, frontend
  view, OpenSearch code, parser code, or evidence behavior changes are included.

Rollback strategy:

- Remove the new interface modules and tests.

Risks:

- Interfaces may overfit before the schema is approved.
- Too many abstractions could create context overhead without implementation
  value.

Dependencies on earlier phases:

- JOB-0 baseline tests should exist or be in progress.

What remains intentionally unchanged:

- Current file-backed workflow/status authority and all existing execution
  entry points.

### Phase JOB-2 - Add Postgres/Supabase job schema migrations

Goal: introduce tables for jobs, job steps, job logs, workers, parser runs,
parser outputs, ingest batches, and OpenSearch indexing status.

Scope:

- Add migrations for the execution control-plane tables after schema design is
  approved. v1 lean core only (D13): `jobs`, `job_steps`, `job_logs`, `workers`
  with attempt/cancel/heartbeat fields on the rows. Do not add `job_attempts`,
  `job_cancellations`, or `worker_heartbeats` tables yet.
- This phase assumes the identity foundation tables (`09_identity_auth_cutover.md`
  Phase ID-1: `cases`, `case_members`, `active_case_state`, `mcp_tokens`, etc.)
  already exist, since jobs carry `case_id` and requester identity FKs.
- Include constraints for case scope, job status, idempotency keys, worker
  leases (single fields), parser lineage, indexing batches, and audit linkage.
- Keep runtime code unconverted.

Likely files to change:

- Future Supabase/Postgres migration directory.
- Schema documentation under `docs/migration`.
- Migration tests or schema validation tests.

Likely new files:

- Job/control-plane migration files.
- Schema test fixtures.

Tests to add:

- Migration applies cleanly to an empty local database.
- Status enum/check constraints reject invalid states.
- Idempotency uniqueness works for compatible scopes.
- Foreign-key relationships exist for jobs, steps, parser runs, parser outputs,
  ingest batches, workers, and indexing status.
- RLS/policy tests where the repo has a pattern for them.

Acceptance criteria:

- Schema is additive and reversible through the repo's accepted migration
  workflow.
- No runtime path depends on the new tables yet.
- Tables can represent the job model from `05_execution_job_model.md` and the
  integration contracts from `06_execution_integration_contracts.md`.

Rollback strategy:

- Revert the migration before data is written in production-like environments.
- If already applied in a disposable local Supabase instance, reset the local DB.

Risks:

- Premature schema details may conflict with later Supabase Auth/RLS decisions.
- Indexing, parser, and evidence relationships may be incomplete if code facts
  remain unconfirmed.

Dependencies on earlier phases:

- JOB-0.
- Preferably JOB-1, or at least an approved schema design document.

What remains intentionally unchanged:

- Existing file-backed execution and status flows.

### Phase JOB-3 - Add job repository/service layer

Goal: implement DB-backed service methods for create, list, get, update, claim,
add steps, append logs, heartbeat workers, and record parser/indexing metadata.

Scope:

- Implement repository/service methods against the approved schema.
- Keep the service covered by database or repository tests.
- Do not yet convert real evidence, parser, OpenSearch, report, frontend, or MCP
  workflows.

Likely files to change:

- `packages/sift-core/src/sift_core/jobs/`
- `packages/sift-gateway/src/sift_gateway/*` if Gateway owns service wiring.
- Tests for repository/service behavior.

Likely new files:

- Job repository/service modules.
- DB test helpers or fakes.

Tests to add:

- Create/list/get/update jobs.
- Append steps and logs.
- Worker registration and heartbeat.
- Atomic claim behavior with simulated concurrent workers.
- Idempotency conflict/replay behavior.
- Parser/indexing metadata recording.

Acceptance criteria:

- Repository methods are tested and fail closed on invalid case/job ownership.
- Claiming preserves single-owner semantics.
- No existing runtime behavior changes.

Rollback strategy:

- Disable or remove the new service layer while leaving migrations intact if no
  production data depends on it.

Risks:

- Database tests may become slow or brittle.
- Service layer may accidentally become a second policy authority if Gateway
  authorization boundaries are unclear.

Dependencies on earlier phases:

- JOB-2.

What remains intentionally unchanged:

- Current REST/MCP execution paths and legacy status files.

### Phase JOB-4 - Add worker dispatcher skeleton in dry-run/no-op mode

Goal: introduce a worker process that can register, heartbeat, claim synthetic
or no-op jobs, update status, and exit safely.

Scope:

- Add worker registration, heartbeat, claim loop, graceful shutdown, and no-op
  job execution.
- Limit execution to synthetic `health_check` or test-only jobs.
- Do not run evidence operations, parsers, OpenSearch indexing, report
  generation, or native commands.

Likely files to change:

- `packages/sift-core/src/sift_core/workers/`
- CLI/entry-point metadata only if needed.
- Worker tests.

Likely new files:

- Worker dispatcher skeleton.
- Worker lifecycle tests.

Tests to add:

- Worker registers and heartbeats.
- Worker claims exactly one eligible no-op job.
- Worker skips unsupported job types.
- Worker exits without claiming new jobs on shutdown.
- Expired heartbeat can be marked stale by service tests.

Acceptance criteria:

- No-op worker can run locally against the job repository.
- Worker does not require Redis/RQ or any external queue.
- Worker cannot execute arbitrary commands or real parsers.

Rollback strategy:

- Stop the worker process and remove the no-op worker modules.
- Existing runtime paths continue to work.

Risks:

- Entry-point or packaging changes could affect installs.
- Worker loop could be overbuilt before real job adapters exist.

Dependencies on earlier phases:

- JOB-3.

What remains intentionally unchanged:

- Real parser, evidence, OpenSearch, report, finding, REST, MCP, and frontend
  workflows.

### Phase JOB-5 - Add Gateway REST job APIs

Goal: expose job creation, status, log, cancel, and retry APIs to the portal
without converting all real workflows yet.

Scope:

- Add REST endpoints from `06_execution_integration_contracts.md`.
- Back them with the job service.
- Initially allow only no-op, health-check, or tightly scoped synthetic jobs
  until real workflow conversions are ready.

Likely files to change:

- `packages/sift-gateway/src/sift_gateway/rest.py`
- `packages/sift-gateway/src/sift_gateway/auth.py`
- `packages/sift-gateway/src/sift_gateway/identity.py`
- Gateway tests.

Likely new files:

- Job API request/response schemas if the repo pattern supports them.
- REST job API tests.

Tests to add:

- Create job with authorized case context.
- Reject unauthorized case/job access.
- List/get jobs by case.
- Tail redacted logs.
- Cancel/retry allowed states and reject terminal/nonretryable states.
- Postgres unavailable returns `503` without claiming success.

Acceptance criteria:

- APIs are additive and can observe/create only allowed early job types.
- Frontend file-backed workflows remain unchanged.
- No real parser or evidence conversion is included.

Rollback strategy:

- Disable or remove the new routes. Existing portal routes remain available.

Risks:

- REST APIs could freeze response shapes before frontend needs are fully known.
- Authorization gaps could expose cross-case job metadata.

Dependencies on earlier phases:

- JOB-3.
- JOB-4 for useful no-op worker validation.

What remains intentionally unchanged:

- Current portal evidence, report, review, parser, OpenSearch, and MCP
  workflows.

### Phase JOB-6 - Add core SIFT MCP job tools

Goal: expose `jobs.enqueue`, `jobs.get`, `jobs.list`, `jobs.tail_logs`,
`jobs.cancel`, and `jobs.retry` with strict case and tool scope.

Scope:

- Add core MCP job tools through the Gateway/FastMCP policy path.
- Resolve case context from Gateway-validated token/session context.
- Permit only synthetic or explicitly safe job types until real conversions are
  implemented.

Likely files to change:

- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
- Gateway/core MCP tests.

Likely new files:

- MCP job tool contract tests.

Tests to add:

- Job tools require token tool scope.
- Normal tokens cannot pass arbitrary `case_id`.
- Cross-case job IDs are rejected.
- Long-running job tools return `job_id` rather than running work.
- Log reads are redacted and scoped.
- Cancel/retry produce audited state changes.

Acceptance criteria:

- Job tools are additive and policy-scoped.
- Existing MCP tools continue to operate during transition.
- No real parser conversion is included.

Rollback strategy:

- Hide or remove the new job tools from the core tool registry.

Risks:

- Tool names and result envelopes must be compatible with existing MCP clients.
- Per-backend MCP policy differences must not be widened.

Dependencies on earlier phases:

- JOB-3.
- Preferably JOB-5 for matching REST semantics.

What remains intentionally unchanged:

- Existing parser, OpenSearch, evidence, report, and finding MCP behavior.

### Phase JOB-7 - Convert evidence hash/verify/register flows to jobs

Goal: move the safest evidence operations into DB-backed jobs while preserving
evidence vault behavior.

Scope:

- Wrap evidence registration, hashing, and integrity verification in jobs.
- Preserve current evidence manifest, ledger, immutable file behavior, and
  compatibility views.
- Keep high-risk evidence operations such as ignore, retire, anchor, and
  exception handling gated and incremental.

Likely files to change:

- `packages/sift-core/src/sift_core/evidence_chain.py`
- `packages/sift-core/src/sift_core/evidence_ops.py`
- `packages/sift-core/src/sift_core/verification.py`
- Evidence routes in `packages/case-dashboard/src/case_dashboard/routes.py`
- Gateway REST/MCP job integration files.

Likely new files:

- Evidence job adapters.
- Evidence job regression tests.

Tests to add:

- Evidence hash job preserves current manifest/ledger outcome.
- Integrity verification job records steps/logs/audit and does not mutate raw
  evidence.
- Failed integrity check does not auto-fix or auto-approve.
- DB unavailable does not corrupt evidence vault files.
- Compatibility files remain readable.

Acceptance criteria:

- Selected evidence operations can be run as jobs and inspected through job
  state.
- Evidence vault behavior is unchanged except for additive DB/job records.
- Audit is mandatory for job lifecycle and evidence access/check events.

Rollback strategy:

- Route evidence operations back to current synchronous paths.
- Preserve DB records as historical attempted job records or mark them
  deprecated after rollback.

Risks:

- Evidence state corruption is high impact.
- Dual-write ordering between manifest/ledger and DB audit/status can drift.

Dependencies on earlier phases:

- JOB-3.
- JOB-5 and/or JOB-6 for operator/agent job surfaces.

What remains intentionally unchanged:

- Parser/ingest conversion, OpenSearch indexing conversion, frontend job
  monitoring, report/finding generation conversion, and file proof artifacts.

### Phase JOB-8 - Convert parser/ingest workflows to jobs

Goal: wrap existing parser and ingest modules with job steps, logs,
parser runs, parser outputs, and idempotency keys.

Scope:

- Start with one narrow parser/ingest path that has baseline tests.
- Create parser-run and parser-output records before indexing.
- Add worker callbacks for step/log/status updates.
- Keep existing parser modules and CLI paths available during transition.

Likely files to change:

- `packages/opensearch-mcp/src/opensearch_mcp/server.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`
- Selected parser modules.
- Job/worker adapter modules.

Likely new files:

- Parser job adapters.
- Parser-run and parser-output tests.

Tests to add:

- Parser job creates parser_run before execution.
- Parser job records parser output metadata and source hashes.
- Idempotency prevents duplicate parser runs for the same source/parser/version.
- Legacy ingest status remains compatible where required.
- Parser failure records failed parser_run and job step without losing logs.

Acceptance criteria:

- One parser/ingest path can run through DB-backed job state.
- Existing parser path remains available until the job-backed path is accepted.
- No broad parser rewrite is included.

Rollback strategy:

- Disable the job-backed parser adapter and use the legacy ingest path.
- Preserve parser job rows for audit/history.

Risks:

- Duplicate parser/indexing runs.
- Incomplete cancellation behavior.
- Parser outputs may lack registered evidence IDs for some source types.

Dependencies on earlier phases:

- JOB-0.
- JOB-3.
- JOB-4.
- JOB-7 is preferred for evidence-linked parser inputs.

What remains intentionally unchanged:

- Most parser modules, frontend job views, report/finding generation, and final
  deprecation of legacy status files.

### Phase JOB-9 - Connect OpenSearch indexing to job/parser state

Goal: ensure indexing is performed by workers and recorded in Postgres/Supabase
with case, evidence, job, parser, and indexing provenance.

Scope:

- Move indexing status authority to DB rows.
- Record indexing batches, target aliases/indexes, schema version, document
  counts, failures, and degraded OpenSearch state.
- Stamp required control-plane metadata on newly indexed documents for converted
  paths.

Likely files to change:

- OpenSearch ingest/indexing modules.
- OpenSearch path/mapping helpers.
- Worker/job adapters.
- Gateway OpenSearch health/status surfaces.

Likely new files:

- Indexing batch adapters.
- OpenSearch degraded-mode tests.
- Metadata stamping tests.

Tests to add:

- Indexing batch success/failure counts are durable.
- OpenSearch unavailable creates explicit retry/degraded state.
- Query/index status can be read from Postgres even when OpenSearch is down.
- New documents carry case, evidence, job, parser, source hash, and schema
  metadata for converted paths.
- Retrying indexing does not duplicate documents where deterministic IDs exist.

Acceptance criteria:

- Converted parser/indexing work has DB-visible indexing status.
- OpenSearch remains derived and reindexable.
- Legacy standalone OpenSearch behavior is not removed in this phase.

Rollback strategy:

- Disable worker-driven indexing for converted paths and fall back to legacy
  indexing while preserving DB records as attempted batches.

Risks:

- OpenSearch and DB status can drift if bulk indexing succeeds but DB update
  fails, or vice versa.
- Cross-case index mistakes are high impact.

Dependencies on earlier phases:

- JOB-3.
- JOB-4.
- JOB-8.
- Approved OpenSearch index registry/schema design.

What remains intentionally unchanged:

- Frontend monitoring and final removal of standalone OpenSearch paths.

### Phase JOB-10 - Add frontend job monitoring

Goal: add operator views for job list, job details, step progress, logs, worker
health, degraded status, retry, and cancel.

Scope:

- Add read-only job monitoring first.
- Add retry/cancel controls only through Gateway APIs.
- Use polling first and avoid frontend authority over job state.

Likely files to change:

- `packages/case-dashboard/frontend/src/api/client.js`
- `packages/case-dashboard/frontend/src/api/endpoints.js`
- `packages/case-dashboard/frontend/src/hooks/useDataPolling.js`
- `packages/case-dashboard/frontend/src/store/useStore.js`
- Frontend components for navigation, status, evidence, reports, and settings
  where job status is displayed.

Likely new files:

- Job list/detail/log/worker health components.
- Frontend smoke tests.

Tests to add:

- Job list renders queued/running/succeeded/failed/stale states.
- Job detail renders steps/logs and degraded dependencies.
- Retry/cancel buttons call Gateway endpoints and do not mutate state locally.
- OpenSearch unavailable is shown differently from no results.
- Worker unavailable is visible without hiding queued jobs.

Acceptance criteria:

- Operators can inspect jobs without reading legacy status files directly from
  the browser.
- Frontend actions go through Gateway APIs.
- Existing operator workflows remain available during transition.

Rollback strategy:

- Hide the job monitoring routes/components and keep existing portal views.

Risks:

- UI may accidentally encode transitional response shapes as permanent product
  contracts.
- Polling intervals can overload APIs if not bounded.

Dependencies on earlier phases:

- JOB-5.
- JOB-9 for meaningful parser/indexing status, though read-only monitoring can
  start earlier with no-op/evidence jobs.

What remains intentionally unchanged:

- Frontend does not directly mutate job rows, parser state, evidence integrity,
  OpenSearch indexing state, or audit rows.

### Phase JOB-11 - Convert report/finding generation to jobs

Goal: move report and finding generation into DB-backed jobs with
approval-aware outputs.

Scope:

- Convert long-running report generation and finding generation to jobs.
- Preserve approval behavior: generated findings are proposed/pending, not
  approved.
- Preserve current saved report/export behavior until DB metadata and artifact
  registration are validated.

Likely files to change:

- Report routes and helpers in `packages/case-dashboard/src/case_dashboard/*`
  and `packages/sift-core/src/sift_core/reporting.py`.
- Finding generation or core tool modules.
- Job adapters and tests.

Likely new files:

- Report job adapter tests.
- Finding generation job tests.

Tests to add:

- Report generation job snapshots approved data and records output refs.
- Generated findings remain proposed/pending.
- Final report/export requires approval where policy requires it.
- OpenSearch degraded behavior is explicit for reports that depend on indexed
  sources.
- In-memory draft loss is no longer the durable progress authority for
  converted paths.

Acceptance criteria:

- Converted report/finding workflows return job IDs for long work.
- Outputs are tied to case, job, audit, approval, and source references.
- No agent-generated finding is auto-approved.

Rollback strategy:

- Route report/finding generation back to current synchronous paths while
  keeping DB job records as historical attempts.

Risks:

- Report outputs may change if the data snapshot boundary is not explicit.
- Approval and proposed/final state can drift during dual-write.

Dependencies on earlier phases:

- JOB-3.
- JOB-5 or JOB-6.
- Approval schema/contracts from the control-plane schema work.

What remains intentionally unchanged:

- Evidence vault proof artifacts and legacy saved report artifacts until
  compatibility is validated.

### Phase JOB-12 - Deprecate file-based workflow/status authority

Goal: remove or freeze file-backed workflow/status authority after
compatibility and migration are validated.

Scope:

- Freeze legacy status files as generated compatibility exports or read-only
  artifacts.
- Move remaining readers to DB-backed services.
- Deprecate `~/.sift/ingest-status`, in-memory report draft authority,
  file-backed workflow locks, and active-case pointer authority after validated
  compatibility.

Likely files to change:

- Compatibility exporters.
- Legacy status readers.
- Gateway, portal, MCP, OpenSearch, and core modules that still read/write
  workflow state from files.
- Documentation.

Likely new files:

- Deprecation checks.
- Compatibility export tests.

Tests to add:

- DB authority exports compatibility files with expected shapes.
- Legacy readers no longer own authoritative state.
- External compatibility paths are documented or explicitly unsupported.
- Removing legacy authority does not break evidence manifest/ledger proof
  artifacts.

Acceptance criteria:

- No primary workflow/status decision depends on legacy files.
- Compatibility exports are generated from DB authority where still needed.
- Operators have a tested rollback window before destructive cleanup.

Rollback strategy:

- Re-enable compatibility file writes and legacy readers if DB-backed paths
  fail validation.
- Do not delete proof artifacts.

Risks:

- External scripts may still read legacy files.
- Removing file authority too early can break operator muscle memory and
  automation.

Dependencies on earlier phases:

- JOB-7 through JOB-11 for converted workflows.
- Compatibility-reader inventory.

What remains intentionally unchanged:

- Immutable evidence vault artifacts remain preserved as proof/export even when
  operational authority moves to Postgres.

### Phase JOB-13 - Hardening, tests, and docs

Goal: add robust tests, security review, degraded-mode validation, and
documentation.

Scope:

- Expand unit, integration, smoke, MCP, REST, worker, idempotency, OpenSearch,
  evidence, audit, and frontend tests.
- Review authorization, case scope, token leakage, raw path leakage, audit
  fail-closed behavior, and degraded-mode behavior.
- Update operator and developer documentation.

Likely files to change:

- Test suites across core, common, gateway, OpenSearch, worker, and frontend
  packages.
- Migration and operator documentation.
- Config templates only where needed to document final behavior.

Likely new files:

- End-to-end migration acceptance checks.
- Security and degraded-mode test fixtures.

Tests to add:

- Cross-case denial across REST, MCP, OpenSearch, worker, and frontend paths.
- Token/log redaction.
- Worker crash/stale recovery.
- Idempotency under retry and duplicate requests.
- OpenSearch down, worker down, and DB down behavior.
- Evidence vault and audit regression suites.

Acceptance criteria:

- Converted execution workflows have meaningful automated coverage.
- Security-sensitive behavior is tested before legacy authority is deprecated.
- Documentation describes the supported operational model and compatibility
  limits.

Rollback strategy:

- Keep compatibility exports and legacy fallback until hardening passes.

Risks:

- Hardening can become a broad catch-all. Split this phase into focused PRs by
  subsystem.

Dependencies on earlier phases:

- All prior phases as applicable.

What remains intentionally unchanged:

- No new architecture dependency is introduced. Postgres/Supabase remains the
  durable job authority and OpenSearch remains derived search/data.

## 4. First Execution-Focused PR Plan

Recommended first PR:

Add baseline execution smoke-test fixtures and lightweight tests for the current
execution-critical paths, without changing runtime behavior.

No repository evidence in the migration documents suggests a safer first slice.
This PR creates confidence before DB-backed job migration and avoids committing
to schema, worker, REST, MCP, frontend, parser, or OpenSearch implementation
details.

Exact scope:

- Add one or two minimal smoke tests for current evidence vault and audit
  behavior.
- Add one minimal smoke test or fixture around a current parser/ingest path only
  if it can run locally without live OpenSearch.
- Add one minimal OpenSearch ingest/status/degraded/request-shaping test that
  avoids a live OpenSearch dependency.
- Add a short docs note explaining how to run these baseline execution checks.
- Keep tests small and focused on currently documented behavior.

Files likely to add/change:

- A small test file under the existing `packages/sift-core` test structure for
  evidence chain behavior.
- A small test file under the existing `packages/sift-common` or
  `packages/sift-core` test structure for audit behavior.
- A small test file under the existing `packages/opensearch-mcp` test structure
  for ingest status/request construction/degraded behavior.
- A short docs note under `docs/migration` or a package test README.

Files explicitly not to touch:

- Supabase/Postgres migration files.
- Worker dispatcher/runtime files.
- Gateway REST route behavior.
- Gateway MCP endpoint behavior.
- Core MCP tool definitions.
- Frontend API/client/store/components.
- OpenSearch parser/indexing runtime modules except for test-only imports.
- Evidence vault implementation modules.
- Audit implementation modules.
- Report/finding generation runtime.
- Config templates and deployment files unless a test command note already
  exists and needs a link.

Tests to add:

- Evidence chain smoke test using temporary case/state directories, proving the
  current manifest/ledger or chain status behavior remains intact.
- Audit smoke test proving the current audit writer creates the expected JSONL
  shape/location for a case-scoped action.
- OpenSearch status/request-construction/degraded test that mocks the client or
  tests pure status-file/request-shaping behavior without starting OpenSearch.
- Optional parser/ingest fixture test for one parser path that can parse a tiny
  local fixture into generated actions or metadata without indexing to a live
  cluster.

Commands to run:

```bash
python -m pytest <new evidence/audit baseline tests>
python -m pytest <new opensearch/parser baseline tests>
git diff --check
```

Use the repo's actual package-specific test commands if inspection in that PR
shows a different convention.

Manual validation steps:

- Confirm no live OpenSearch service is required for the new default tests.
- Confirm no runtime source files changed except optional test helper docs.
- Confirm temporary test directories are isolated and cleaned up.
- Confirm test names document current behavior rather than target behavior.

Expected before behavior:

- Current execution-critical behavior exists but is weakly protected by focused
  baseline tests.
- Operators still use file-backed evidence, audit, parser/status, report, and
  OpenSearch behavior.

Expected after behavior:

- Same runtime behavior.
- A small set of baseline tests and fixtures documents current behavior before
  job migration begins.
- Future PRs have regression checks for evidence/audit and at least one
  OpenSearch/parser/status edge.

Rollback strategy:

- Remove the added test files, fixtures, and docs note.
- No runtime rollback is required.

Acceptance criteria:

- The PR is additive and test/documentation focused.
- No runtime behavior changes.
- No schema migrations.
- No worker dispatcher.
- No job service implementation.
- No frontend changes.
- No MCP tool rewrites.
- No OpenSearch refactor.
- No parser conversion.
- Tests pass locally with the documented commands.
- `git diff --check` passes.

Context limit guardrails for the coding agent:

- Start by reading this roadmap, `04_execution_current_state.md`, and only the
  test/runtime files needed for the selected smoke tests.
- Use `rg --files` to find existing test layout, then inspect only nearby test
  patterns and the minimum runtime functions under test.
- Do not inspect or edit broad frontend, REST, MCP, worker, schema, or parser
  trees unless the chosen smoke test requires one file.
- Keep the PR to a few test files, tiny fixtures, and one short docs note.
- Stop if a test requires live OpenSearch or a broad runtime refactor; replace
  it with a mocked/degraded/status-file test.

## 5. Second PR Recommendation

Recommended second PR:

Add job domain interface skeletons, no database yet.

Justification:

- It follows the safest dependency chain after baseline tests.
- It creates shared vocabulary for jobs, steps, logs, parser runs, indexing
  status, worker records, idempotency, and status transitions before committing
  to schema details.
- It avoids a Supabase/Postgres dependency while the concrete control-plane
  schema is still being designed.
- It is small enough for one Codex coding session if limited to pure types,
  protocols, and unit tests.

Scope:

- Add pure job domain types/interfaces and transition validation helpers.
- Add tests for status transitions, job type definitions, idempotency key
  shaping, and log redaction where pure helpers exist.
- Do not wire existing REST, MCP, parser, evidence, OpenSearch, frontend, or
  worker code to the interfaces yet.

Files likely to add/change:

- `packages/sift-core/src/sift_core/jobs/`
- Matching `packages/sift-core` tests.
- Minimal docs note only if needed to point future PRs at the interface.

Tests:

- Status transition table validation.
- Allowed terminal/nonterminal state checks.
- Job type constants match the migration model.
- Fake repository/service protocol can create in-memory job summaries for unit
  tests without a database.

Acceptance criteria:

- No runtime behavior changes.
- No database client imports.
- No migrations.
- Existing tests plus new pure unit tests pass.
- Interfaces are small and directly traceable to `05_execution_job_model.md`.

Risks:

- Interface design can sprawl. Limit the PR to fields and operations needed by
  the next schema design and repository phases.
- Interface names may change after schema approval. Keep them easy to rename.

Why it is safe for one Codex coding session:

- It is additive.
- It has no external service dependency.
- It does not require understanding all parser, frontend, or Gateway behavior.
- It gives future schema and repository PRs a narrow contract to implement.

## 6. Testing Strategy

Testing must protect current behavior before real parsers are converted. The
minimum pre-conversion bar is evidence vault regression, audit regression,
OpenSearch degraded/status behavior, idempotency design tests, repository
claiming tests, and no-op worker lifecycle tests.

Unit tests:

- Job status transitions, terminal state rules, retry/cancel validation, and
  idempotency key construction.
- Log redaction helpers for tokens, credentials, raw bearer values, and unsafe
  stderr/env output.
- Parser metadata shaping for converted parser adapters.
- OpenSearch query/indexing request builders with mocked registry state.

Integration tests:

- Job repository create/list/get/update/claim behavior against local
  Postgres/Supabase test DB once migrations exist.
- Worker heartbeat, lease expiry, stale detection, and recovery.
- Evidence job wrappers against temporary case/state directories.
- OpenSearch indexing adapters with mocked or test-double OpenSearch client.

Smoke tests:

- Current evidence/audit baseline before migration.
- No-op worker claim and completion.
- One converted evidence job.
- One converted parser/indexing path after JOB-8/JOB-9.

CLI/manual tests:

- Run baseline execution tests locally.
- Start a no-op worker, enqueue a synthetic job, observe completion, stop the
  worker cleanly.
- Simulate OpenSearch down and confirm job/indexing degraded state is explicit.
- Simulate worker shutdown and confirm queued jobs remain durable.

MCP tool contract tests:

- `jobs.enqueue`, `jobs.get`, `jobs.list`, `jobs.tail_logs`, `jobs.cancel`, and
  `jobs.retry` enforce tool and case scope.
- Long-running tools return `job_id`.
- Normal tokens cannot pass arbitrary `case_id`, raw OpenSearch indexes, raw
  DSL, or cross-case patterns.
- Agent-generated findings remain proposed/pending.

REST API tests:

- Create/list/get/steps/logs/cancel/retry endpoints enforce case membership.
- Unauthorized case/job reads return `403` or policy-shaped `404`.
- Postgres unavailable returns `503` without claiming job success.
- No worker available returns queued/degraded state where policy allows.

Worker claiming tests:

- Two workers cannot claim the same queued job.
- Capabilities filter job types and parser names.
- Lease heartbeat extends ownership.
- Lost lease stops work or prevents finalization.
- Stale detector requeues, retries, fails, or cancels according to policy.

Idempotency tests:

- Browser/MCP retry returns the same compatible job.
- Incompatible duplicate idempotency key returns conflict.
- Parser run duplicate prevention includes case, evidence/source, parser,
  parser version, source hash, schema version, and relevant spec options.
- Indexing duplicate prevention includes ingest batch, target alias, schema
  version, parser run, and source hash.

OpenSearch degraded-mode tests:

- Search unavailable is distinct from no hits.
- Indexing jobs enter retrying/failed/degraded state with durable status.
- DB job/indexing status remains readable when OpenSearch is down.
- Normal agents cannot use wildcard `case-*` or raw index names.

Evidence vault regression tests:

- Manifest/ledger behavior remains compatible.
- Integrity verification does not mutate raw evidence.
- DB unavailable during job-backed evidence flow does not corrupt vault files.
- Compatibility exports remain readable during transition.

Audit regression tests:

- Job lifecycle transitions audit.
- Evidence access/checks audit.
- Parser run and indexing batch start/end/failure audit.
- Policy denial audit where actor/token is known.
- Destructive/final actions fail closed when required audit cannot be written.

Frontend smoke tests:

- Job list/detail render core states.
- Step progress and logs render from Gateway responses.
- Retry/cancel controls call APIs and do not mutate authoritative state locally.
- OpenSearch/worker degraded banners are visible.
- Polling backs off for hidden tabs or terminal jobs.

Priority before converting real parsers:

1. Evidence vault and audit baseline tests.
2. Current OpenSearch ingest/status or degraded/request-shaping baseline.
3. Job interface and schema validation tests.
4. Job repository idempotency and claim tests.
5. No-op worker lifecycle tests.
6. REST/MCP job contract tests.
7. OpenSearch degraded-mode tests.

## 7. Rollback And Compatibility Strategy

File-backed workflow compatibility:

- Keep current file-backed authority during early additive phases.
- Mirror or export DB-backed state only after the DB path is tested.
- Preserve legacy readers until replacements are validated.
- Treat `~/.sift/ingest-status`, ingest logs, active-case pointers, saved report
  JSON, pending review files, and case JSON as compatibility surfaces until a
  specific deprecation phase.

Dual-write risks:

- Dual-write only where unavoidable and test the ordering explicitly.
- Prefer one authoritative write plus generated compatibility export.
- Include audit/event IDs and content hashes so drift can be detected.
- Never consider a file and DB write equivalent unless reconciliation tests
  prove it.

Read-through and mirror strategies:

- Early phases may read legacy files and mirror status into DB for observation.
- Later phases should write DB first and export compatibility files.
- Once DB authority is accepted, legacy files become generated views or frozen
  artifacts.

DB unavailable fallback:

- Before cutover, existing file-backed workflows can continue where they already
  do not require DB authority.
- After a workflow becomes DB-backed, job creation/update must fail closed when
  Postgres is unavailable; do not claim a job was created without a durable row.
- Workers should stop claiming and should pause/stop running work if they cannot
  heartbeat safely.

OpenSearch unavailable behavior:

- Case, evidence, audit, approval, token, and job state remain observable from
  Postgres where available.
- Parser outputs may be preserved for later indexing if parsing does not require
  OpenSearch.
- Indexing jobs become retrying, failed, paused, or dependency-degraded by
  policy.
- Frontend and MCP responses must distinguish search unavailable from no hits.

Worker unavailable behavior:

- Job creation can return queued/degraded state when policy allows.
- No capable worker is an execution-health issue, not data loss.
- Queued jobs remain durable until workers return or an operator cancels.

Avoiding evidence corruption:

- Do not mutate raw evidence in job migration code.
- Preserve existing evidence manifest/ledger behavior until DB parity is proven.
- Evidence jobs must treat failed DB/audit writes as non-successful outcomes for
  privileged operations.
- Partial parser/indexing failure must not change evidence integrity state.

Freezing/deprecating file authority later:

- Freeze file-backed workflow authority only after all known readers are moved
  or compatibility exports are validated.
- Keep manifest/ledger proof artifacts indefinitely unless a separate legal
  retention decision changes that.
- Deprecate local PID/status files after job state, worker state, and operator
  views are authoritative.

## 8. Risks And Mitigations

| Risk | Affected phase | Impact | Mitigation | Priority |
| --- | --- | --- | --- | --- |
| Breaking existing evidence vault behavior | JOB-0, JOB-7, JOB-12 | Loss of trust in evidence integrity and proof artifacts | Add baseline evidence tests first; preserve manifest/ledger behavior; convert only safe evidence operations first | P0 |
| Inconsistent DB/file state | JOB-2 through JOB-12 | Operators and agents see conflicting workflow status | Prefer DB-first plus generated exports; test reconciliation; avoid broad dual-write | P0 |
| Duplicate parser/indexing runs | JOB-8, JOB-9 | Duplicate documents, skewed counts, confusing reports | Use idempotency keys, parser_run records, indexing batches, deterministic IDs, and retry tests | P0 |
| Worker crash during execution | JOB-4, JOB-8, JOB-9 | Partial work, stale jobs, orphan subprocesses | Use leases, heartbeats, stale detection, step logs, and safe recovery policies | P0 |
| Case-scope leakage | JOB-5, JOB-6, JOB-9, JOB-10 | Cross-case disclosure or mutation | Resolve case from Gateway auth/token/session/job rows; reject arbitrary case IDs; test cross-case denial | P0 |
| Raw token leakage | JOB-5, JOB-6, JOB-10, JOB-13 | Credential exposure through logs, APIs, or UI | Hash-only token registry in target; redaction tests; never log raw bearer/service tokens | P0 |
| OpenSearch cross-case search | JOB-6, JOB-9, JOB-10 | Cross-case search disclosure | Use Gateway-mediated aliases and case filters; block raw indexes, wildcards, and raw DSL for normal tokens | P0 |
| Audit gaps | JOB-3 through JOB-13 | Privileged actions cannot be reconstructed | Mandatory audit for lifecycle, evidence, parser, indexing, approval, denial; fail closed for required audit | P0 |
| Frontend relying on stale state | JOB-10 | UI displays wrong progress or mutates state optimistically | Frontend reads Gateway/DB state, uses bounded polling, and never mutates job state directly | P1 |
| Too much migration scope in one PR | All phases | Hard-to-review changes and regressions | One phase slice per PR; tests/docs first; no broad refactors until fixtures exist | P0 |
| Context explosion in future Codex coding sessions | All phases | Coding sessions lose focus and make unrelated changes | Keep PR guardrails; inspect only relevant files; split adapters by workflow/parser | P0 |
| OpenSearch and DB indexing status drift | JOB-9 | Jobs show success while index is incomplete, or vice versa | Record batches before/after indexing; reconcile counts; expose degraded/partial state | P1 |
| Parser output missing evidence lineage | JOB-8, JOB-9 | Search hits cannot be traced to evidence | Require evidence/source hash and parser_run linkage for converted paths; fail or mark unknown explicitly | P1 |
| Cancellation corrupts partial outputs | JOB-4, JOB-8, JOB-9 | Partial files/indexes look complete | Cooperative cancellation, partial output markers, batch status, and explicit audit/log events | P1 |
| Schema overdesign before code facts are confirmed | JOB-2 | Migration churn and blocked implementation | Create `08_control_plane_schema.md` first; keep first coding PR test-only | P1 |

## 9. Decisions And Open Questions

### Confirmed decisions

- No Redis/RQ.
- No Celery, Temporal, or external queue.
- Postgres/Supabase is the authority for durable jobs in the target design.
- Workers will claim jobs from Postgres in the target design.
- Long-running REST/MCP actions will enqueue jobs and return job IDs in the
  target design.
- OpenSearch indexing status will be recorded in Postgres.
- OpenSearch is a core search/data plane and not workflow authority.
- Evidence vault behavior is preserved.
- Existing evidence manifest/ledger artifacts remain preserved as proof/export
  artifacts while operational authority moves over time.
- Audit remains mandatory.
- Agent-generated findings are not auto-approved.
- Migration is additive first.
- Frontend does not mutate authoritative job state directly.
- MCP tools must not run long parsers synchronously in the final design.
- First execution PR should be baseline tests/fixtures only and small enough for
  one Codex coding session.

### Decisions previously open here, now locked (charter)

- Worker topology: single local worker in v1 (D9).
- Human roles: `readonly`, `operator`, `lead`, `owner`, `admin`
  (`09_identity_auth_cutover.md` §5).
- OpenSearch indexing: reuse the existing `case-{case}-{type}-{host}` model and
  register it; logical-family rename deferred (D18, see `03` §7A). OpenSearch
  3.5.0 security-on (D6).
- Raw OpenSearch DSL admin-only; normal agents get allowlisted inputs.
- Cutover order: identity/cases/tokens first (D17).
- Lean job core (D13).

### Decisions still genuinely open (non-blocking, decide at implementation)

- Exact Supabase Local deployment/migration directory shape (resolved in the
  first schema-infrastructure PR by inspecting the repo).
- Whether short native commands stay synchronous (default: yes; long/parser work
  becomes jobs).
- Compatibility-export lifetime (default: one release cycle past parity).
- Retry granularity (default: whole job in v1; finer parser-run/indexing-batch
  retry in JOB-8/JOB-9).
- Cancellation semantics for subprocess trees / partial batches (default:
  cooperative stop, mark `partial`, never report partial as complete).

### Code facts still needing confirmation

- Existing test layout and commands for each package.
- Complete list of direct writers/readers for legacy case JSON, pending review,
  report, ingest status, ingest log, and active-case files.
- Exact parser coverage for required target metadata fields.
- Which parser modules generate output files that should become registered
  parser outputs before indexing.
- Current subprocess cancellation behavior for parser/tool families.
- Which external scripts consume `~/.sift/ingest-status`,
  `~/.sift/ingest-logs`, active-case pointers, ingest manifests, or legacy
  `case-*` index names.
- Which evidence operations are too expensive to remain synchronous.
- Which report/export workflows should become job-backed first.
- Canonical OpenSearch deployment/version profile for the local SIFT VM target.

## 10. Next Recommended Run

JOB-0, PR01/ID-1, PR02/ID-2, D27a, and D27b are complete. Execution JOB-* work
remains behind the foundation track. The current recommended run is PR03 /
Phase ID-3 planning for Supabase Auth and case-membership resolution, unless the
operator explicitly reprioritizes execution work.
