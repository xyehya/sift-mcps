# Execution Integration Contracts

Last updated: 2026-06-07.

Scope: planning only. This document defines integration contracts for the
target DB-backed execution/job model. It does not implement REST APIs, MCP
tools, frontend views, OpenSearch changes, evidence changes, workers, database
migrations, or the final execution roadmap.

> Locked decisions (see `00_migration_charter.md`): ALL REST APIs, MCP tools,
> and actions go through the Gateway; per-backend `/mcp/{name}` routes are
> disabled (D2/D3). Case context is the control-plane active case (portal-set,
> Gateway-propagated, charter D4). v1 is a single local worker with a lean job
> schema (D9/D13). OpenSearch is 3.5.0 security-on (D6). Identity/cases/tokens
> cut over first (D17, `09_identity_auth_cutover.md`). These contracts target
> the post-foundation state; the foundation track must land before the job APIs
> here are wired to real authorization.

This design is grounded in:

- `docs/migration/04_execution_current_state.md`
- `docs/migration/05_execution_job_model.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- repository facts already cited in those documents

No new implementation-code inspection was performed for this run. Code
references below are carried forward from the required migration documents.

## 1. Executive Summary

The target integration model connects every long-running execution path to
Postgres/Supabase durable job authority while preserving Gateway policy,
evidence-vault behavior, audit requirements, and OpenSearch as a derived search
plane.

- Gateway REST APIs create and observe DB-backed jobs for human operators.
- Core SIFT MCP tools create and observe DB-backed jobs for AI agents and
  backend services.
- Long-running MCP tools enqueue jobs and return `job_id` instead of running
  parsers, evidence verification, indexing, finding generation, or report
  generation inside the request path.
- SIFT workers execute jobs asynchronously by claiming durable Postgres rows,
  writing job steps, logs, parser runs, parser outputs, OpenSearch indexing
  status, evidence status, and audit events back to the control plane.
- The React + Vite operator portal observes job state, steps, logs, worker
  health, OpenSearch degraded mode, evidence integrity progress, parser
  progress, finding generation, and report progress through Gateway-mediated
  APIs.
- OpenSearch indexing is tied to parser runs, parser outputs, ingest batches,
  index registrations, and indexing metadata stored in Postgres. OpenSearch is
  searchable derived data, not authority for job or forensic lifecycle state.
- Evidence and audit integrations preserve current strong evidence vault and
  JSONL/HMAC proof behavior while moving operational metadata/state into the
  control plane over time.

Current facts carried forward:

- The portal currently polls file-backed case APIs every 15 seconds through
  `packages/case-dashboard/frontend/src/hooks/useDataPolling.js:16-43` and
  endpoint wrappers in
  `packages/case-dashboard/frontend/src/api/endpoints.js:12-77`.
- Current Gateway REST v1 exposes tool calls, backend registration/reload,
  service controls, and join-code flows, but no durable execution jobs
  (`packages/sift-gateway/src/sift_gateway/rest.py:1082-1098`).
- Aggregate MCP calls run an evidence gate and write transport-envelope audit
  (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:637-674`,
  `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:841-871`), while the
  per-backend MCP path has a different policy/audit surface
  (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:898-973`).
- OpenSearch ingest is the main current long-running path. It launches
  `python -m opensearch_mcp.ingest_cli`, records pid/run status under
  `~/.sift/ingest-status`, writes logs under `~/.sift/ingest-logs`, and indexes
  derived docs into case-prefixed indexes
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1702-1823`,
  `packages/opensearch-mcp/src/opensearch_mcp/server.py:3006-3168`,
  `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:13-148`).
- Current parser documents carry partial provenance such as
  `vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`, optional
  `vhir.vss_id`, host fields, and `pipeline_version`, but not the target
  control-plane IDs.
- Current evidence-chain authority is `evidence-manifest.json` plus
  `evidence-ledger.jsonl`, with `evidence.json` as compatibility view
  (`packages/sift-core/src/sift_core/evidence_chain.py:1-8`).
- `AuditWriter` currently writes filesystem JSONL with fsync but can return
  `None` when no active case resolves
  (`packages/sift-common/src/sift_common/audit.py:246-332`).

## 2. Gateway REST Job APIs

The Gateway remains the policy enforcement point for human/operator REST
operations. Supabase Auth and RLS establish human identity and baseline case
membership. Gateway policy then enforces role, case authorization, job type,
approval, degraded-mode, and audit behavior before creating or mutating any job
state.

The frontend must not directly mutate authoritative job state. It can submit
requests through Gateway action endpoints, render read models, and cache UI
state only.

### Common REST Shapes

Job summary:

```json
{
  "job_id": "uuid",
  "case_id": "case-id",
  "job_type": "parser_run",
  "status": "queued",
  "priority": "normal",
  "requested_by": {
    "type": "user",
    "id": "user-id",
    "display": "Operator Name"
  },
  "created_at": "timestamp",
  "queued_at": "timestamp",
  "started_at": null,
  "finished_at": null,
  "attempt_count": 0,
  "max_attempts": 3,
  "progress": {
    "percent": null,
    "current_step": null,
    "counts": {}
  },
  "degraded_dependencies": [],
  "links": {
    "self": "/api/cases/case-id/jobs/job-id",
    "steps": "/api/cases/case-id/jobs/job-id/steps",
    "logs": "/api/cases/case-id/jobs/job-id/logs"
  }
}
```

Job detail extends the summary with `spec_summary`, `failure_summary`,
`cancellation`, `worker`, `approval_gate`, `parser_runs`, `indexing_status`,
`evidence_refs`, `output_refs`, and `audit_event_ids`.

Error response:

```json
{
  "error": {
    "code": "opensearch_unavailable",
    "message": "OpenSearch is unavailable for indexing.",
    "request_id": "uuid",
    "case_id": "case-id",
    "job_id": "uuid-or-null",
    "retryable": true,
    "degraded": true,
    "details": {}
  }
}
```

### `POST /api/cases/{case_id}/jobs`

- Purpose: create a DB-backed job for operator-triggered work such as evidence
  ingestion, parser runs, OpenSearch indexing, evidence integrity verification,
  report generation, finding generation, export, archive, or maintenance
  reindex.
- Required human auth/role: Supabase-authenticated human with a case role that
  permits the requested `job_type`. Examples: case operator for parser/report
  draft work, case lead for retry/cancel of high-impact jobs, admin for
  cross-case maintenance.
- Required case authorization: Supabase Auth/RLS membership plus Gateway case
  policy. The path `case_id` must match an authorized case and must not be
  inferred from browser state alone.
- Request body:

```json
{
  "job_type": "parser_run",
  "spec": {
    "evidence_id": "uuid",
    "parser_name": "evtx",
    "options": {}
  },
  "priority": "normal",
  "idempotency_key": "optional-client-or-gateway-key",
  "force_rerun": false
}
```

- Response shape: `201 Created` with `JobDetail` for a new job. `200 OK` with
  `idempotent_replay: true` when the same idempotency key maps to an existing
  compatible job. `409 Conflict` when the idempotency key exists with a
  different spec.
- Audit behavior: emit `job.create_requested`, then `job.created` and
  `job.queued` or `job.waiting_human`. Denials emit `job.create_denied` with
  actor, case, role, job type, and policy reason.
- Error/degraded-mode behavior: if no capable worker is online, accept the job
  as `queued` and include `degraded_dependencies: ["worker_unavailable"]` unless
  policy requires immediate capacity. If OpenSearch is down for an indexing
  job, accept as `queued`, `pending`, or `retrying` according to dependency
  policy and include explicit degraded dependency state. If Postgres is
  unavailable, return `503` and do not claim job creation succeeded.
- Frontend usage: job creation dialogs and action buttons for ingest, parser,
  reindex, report, finding, integrity, archive, and export flows.

### `GET /api/cases/{case_id}/jobs`

- Purpose: list jobs visible to the operator for a case.
- Required human auth/role: authenticated case member. Case leads/admins may see
  more requester and worker details than read-only members.
- Required case authorization: Supabase Auth/RLS plus Gateway case policy.
- Request body: none. Query parameters should include `status`, `job_type`,
  `created_after`, `created_before`, `requester`, `limit`, `cursor`, and
  `include_terminal`.
- Response shape:

```json
{
  "items": ["JobSummary"],
  "next_cursor": "opaque-or-null",
  "health": {
    "workers": "ok|degraded|offline",
    "opensearch": "ok|degraded|offline",
    "postgres": "ok"
  }
}
```

- Audit behavior: normal list reads may emit low-cardinality `job.list` audit
  only when required by policy. High-sensitivity cases can audit every read.
- Error/degraded-mode behavior: return `200` with degraded health if workers or
  OpenSearch are down but Postgres is available. Return `503` when job state
  cannot be read from Postgres.
- Frontend usage: case job list, sidebar badges, case overview progress panels.

### `GET /api/cases/{case_id}/jobs/{job_id}`

- Purpose: fetch authoritative job detail.
- Required human auth/role: authenticated case member with permission to view
  the requested job. Sensitive jobs may require case lead/admin.
- Required case authorization: `job.case_id` must equal the path `case_id` and
  the user must be authorized for that case.
- Request body: none.
- Response shape: `JobDetail`.
- Audit behavior: audit sensitive job reads such as evidence verification,
  destructive cleanup, export, archive, and jobs containing restricted evidence
  references. Ordinary status reads can be sampled or omitted according to case
  audit policy.
- Error/degraded-mode behavior: `404` if the job does not exist within the
  authorized case; `403` or policy-shaped `404` if the user is not authorized.
  Degraded OpenSearch/worker health is shown inside the response and must not
  hide the authoritative Postgres job state.
- Frontend usage: job detail page, progress drawer, report/finding/evidence
  progress pages.

### `GET /api/cases/{case_id}/jobs/{job_id}/steps`

- Purpose: list ordered `job_steps` with status, timings, progress, retries, and
  output references.
- Required human auth/role: same as job detail.
- Required case authorization: job must belong to the path case.
- Request body: none. Query parameters can include `include_logs_summary` and
  `cursor` for large step sets.
- Response shape:

```json
{
  "items": [
    {
      "job_step_id": "uuid",
      "name": "parse_evtx",
      "status": "running",
      "started_at": "timestamp",
      "finished_at": null,
      "progress": {"indexed": 1000, "failed": 0},
      "attempt": 1,
      "worker_id": "worker-id",
      "output_refs": []
    }
  ]
}
```

- Audit behavior: step reads are normally not audited separately; step state
  changes are audited/logged by workers.
- Error/degraded-mode behavior: Postgres unavailable returns `503`; stale jobs
  include the last known step and stale recovery status.
- Frontend usage: step progress component, parser progress, indexing progress,
  evidence verification progress.

### `GET /api/cases/{case_id}/jobs/{job_id}/logs`

- Purpose: read redacted, case-scoped job logs and optional log tail metadata.
- Required human auth/role: authenticated case member. Logs containing sensitive
  evidence paths, command output, or parser stderr may require elevated case
  role.
- Required case authorization: job must belong to the path case.
- Request body: none. Query parameters should include `cursor`, `limit`,
  `level`, `since`, `step_id`, and `tail=true`.
- Response shape:

```json
{
  "items": [
    {
      "log_id": "uuid",
      "timestamp": "timestamp",
      "level": "info",
      "job_step_id": "uuid",
      "message": "Indexed batch",
      "structured_data": {"indexed": 1000, "failed": 0}
    }
  ],
  "next_cursor": "opaque-or-null",
  "redaction": {"applied": true}
}
```

- Audit behavior: log reads for restricted jobs can emit `job.logs_read`.
  Worker log writes are job logs, not necessarily audit events unless they
  represent privileged lifecycle or evidence actions.
- Error/degraded-mode behavior: if large retained logs live in files/object
  storage, unavailable log storage returns partial logs with
  `degraded_dependencies: ["job_log_storage"]` while preserving DB state.
- Frontend usage: log viewer, parser stderr summaries, report generation
  diagnostics.

### `POST /api/cases/{case_id}/jobs/{job_id}/cancel`

- Purpose: request cooperative cancellation of a nonterminal job.
- Required human auth/role: case operator for ordinary jobs, case lead/admin for
  destructive, export, archive, or high-risk evidence jobs.
- Required case authorization: job must belong to the path case.
- Request body:

```json
{
  "reason": "operator requested cancellation",
  "force_after_seconds": 60
}
```

- Response shape: `202 Accepted` with `JobDetail` showing
  `cancellation_requested_at`; `409 Conflict` if terminal or not cancellable.
- Audit behavior: emit `job.cancel_requested`; worker later emits
  `job.cancelled` or `job.cancel_failed`.
- Error/degraded-mode behavior: if the worker is offline, mark cancellation
  requested and rely on stale recovery. If Postgres is unavailable, return
  `503` and do not claim cancellation was recorded.
- Frontend usage: cancel buttons on job list/detail for eligible jobs.

### `POST /api/cases/{case_id}/jobs/{job_id}/retry`

- Purpose: retry a failed, stale, retryable, or explicitly paused job according
  to policy while preserving previous attempts, steps, logs, parser runs, and
  indexing records.
- Required human auth/role: case operator for ordinary retry, case lead/admin
  for force rerun or high-risk jobs.
- Required case authorization: job must belong to the path case.
- Request body:

```json
{
  "reason": "transient OpenSearch outage resolved",
  "mode": "retry_existing|force_rerun",
  "override_max_attempts": false
}
```

- Response shape: `202 Accepted` with updated `JobDetail`. `force_rerun` may
  return a new `job_id` with `supersedes_job_id` when policy requires new job
  lineage.
- Audit behavior: emit `job.retry_requested`, `job.requeued`, or
  `job.force_rerun_created`.
- Error/degraded-mode behavior: `409` for nonretryable terminal jobs unless
  `force_rerun` is allowed. Duplicate idempotency conflict returns `409` with
  the existing job reference.
- Frontend usage: retry controls on failed/stale job detail and indexing health
  pages.

### `GET /api/cases/{case_id}/workers`

- Purpose: show worker capacity relevant to a case and job types.
- Required human auth/role: authenticated case member for summarized worker
  availability; case lead/admin for host, pid, and active-job detail.
- Required case authorization: case membership plus Gateway policy. Workers are
  not authorized by frontend selection.
- Request body: none. Query parameters can include `capability`, `job_type`,
  and `include_offline`.
- Response shape:

```json
{
  "items": [
    {
      "worker_id": "worker-id",
      "status": "online|degraded|offline|stale",
      "capabilities": ["parser_run", "opensearch_index"],
      "active_job_id": "uuid-or-null",
      "last_seen_at": "timestamp",
      "version": "version",
      "degraded_reason": null
    }
  ]
}
```

- Audit behavior: ordinary worker health reads do not require per-read audit.
  Worker registration, heartbeat stale transitions, and worker capability
  changes are audited at the service layer.
- Error/degraded-mode behavior: no worker available returns `200` with
  `status=offline|degraded`, not a hard API failure.
- Frontend usage: worker status view, job list degraded badges, parser capacity
  warnings.

### `GET /api/system/execution/health`

- Purpose: system-level execution health for operators and admins.
- Required human auth/role: authenticated operator for summarized health; admin
  for full worker and queue details.
- Required case authorization: none for system summary, but case-level counts
  must be filtered by the user's memberships unless admin.
- Request body: none.
- Response shape:

```json
{
  "status": "ok|degraded|offline",
  "postgres": "ok|degraded|offline",
  "workers": {"online": 1, "degraded": 0, "offline": 0},
  "queues": {"queued": 3, "running": 1, "stale": 0},
  "oldest_queued_at": "timestamp-or-null"
}
```

- Audit behavior: admin-only detailed reads can emit `execution.health_read`.
  Health calculation itself should not mutate job state except through explicit
  stale-detector service paths.
- Error/degraded-mode behavior: if Postgres is unavailable, return `503` with a
  best-effort Gateway-local degraded response.
- Frontend usage: global health banner, settings/status page, worker dashboard.

### `GET /api/system/opensearch/health`

- Purpose: Gateway-mediated OpenSearch dependency health.
- Required human auth/role: authenticated operator for summarized health; admin
  for cluster/index details.
- Required case authorization: no case needed for system summary; case-specific
  index health should be filtered by authorized cases.
- Request body: none.
- Response shape:

```json
{
  "status": "ok|yellow|degraded|offline",
  "cluster": {"reachable": true, "version": "unknown-or-version"},
  "indexes": {"ready": 10, "degraded": 1, "stale": 0},
  "last_checked_at": "timestamp",
  "message": "Search available"
}
```

- Audit behavior: admin detail reads can emit `opensearch.health_read`.
  Health failures that affect jobs emit audit/log events from the job/indexing
  workflow.
- Error/degraded-mode behavior: OpenSearch down returns `200` with
  `status=offline` when Gateway and Postgres are available, because the system
  is degraded but observable. Gateway/Postgres failure returns `503`.
- Frontend usage: OpenSearch degraded banners, search/timeline/indexing status
  panels.

## 3. Core SIFT MCP Job Tools

Core SIFT MCP tools are the target AI-agent and service workflow surface. They
must be exposed through the Gateway/FastMCP policy path so token scope, case
scope, evidence gates, approval policy, and audit are consistent.

Common MCP constraints:

- Long-running tools must enqueue DB-backed jobs and return `job_id`.
- MCP tools must not run long parsers directly in the request path.
- MCP clients must not pass arbitrary `case_id` unless the token is explicitly
  authorized for case selection or cross-case admin/service work.
- Normal case context comes from the Gateway-validated token/session context,
  not from `SIFT_CASE_DIR`, `~/.sift/active_case`, or process environment.
- Gateway must enforce tool scope and case scope before dispatch.
- Normal agent tokens must not pass raw OpenSearch query DSL, raw index names,
  wildcard case patterns, or OpenSearch credentials.
- Agents must not approve their own findings.
- Agent-generated findings remain proposed/pending until a human approves them.

MCP response envelope for job-producing tools:

```json
{
  "ok": true,
  "job_id": "uuid",
  "status": "queued",
  "case_id": "case-id",
  "idempotent_replay": false,
  "degraded_dependencies": [],
  "audit_event_id": "uuid"
}
```

MCP error envelope:

```json
{
  "ok": false,
  "error": {
    "code": "invalid_token_scope",
    "message": "Token is not allowed to enqueue parser jobs.",
    "retryable": false,
    "degraded": false
  },
  "audit_event_id": "uuid-or-null"
}
```

| Tool | Purpose | Required scope | Case context | Allowed inputs | Forbidden inputs | Job behavior | Audit event | Degraded behavior |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `jobs.enqueue` | Generic job creation for service and agent workflows. | `jobs.enqueue` plus job-type scope such as `parser.run` or `report.generate`. | Token/session case scope; explicit `case_id` only for approved multi-case service tokens. | `job_type`, constrained `spec`, `priority`, `idempotency_key`, `force_rerun` when scoped. | Arbitrary `case_id`, `worker_id`, status fields, raw SQL, raw OpenSearch DSL, approval overrides. | Returns `job_id`; long work always enqueued. | `job.create_requested`, `job.created`, `job.queued` or denial. | No worker returns queued job with degraded dependency; Postgres down returns error. |
| `jobs.get` | Fetch one job's status. | `jobs.read`. | Token must be scoped to the job case. | `job_id`, optional `include_steps`, `include_summary_logs`. | Cross-case job IDs, raw log file paths. | Synchronous read. | Sensitive reads may emit `job.read`. | Returns degraded dependency flags from job state. |
| `jobs.list` | List jobs for the scoped case. | `jobs.read`. | Token/session case scope. | Filters for status, type, time range, pagination. | Unscoped all-case listing for normal agents. | Synchronous read. | Optional `job.list`. | Returns health/degraded summary with list. |
| `jobs.tail_logs` | Read redacted job logs. | `jobs.logs.read`. | Token must be scoped to the job case and allowed to read logs. | `job_id`, `cursor`, `limit`, `level`, `step_id`. | Raw filesystem log paths, unrestricted stderr dumps, unrelated job IDs. | Synchronous read. | `job.logs_read` for sensitive logs. | Returns partial logs if log storage degraded. |
| `jobs.cancel` | Request cancellation. | `jobs.cancel` plus job-type permission. | Token must be scoped to job case. | `job_id`, `reason`. | Force-kill flags for normal agents, cancelling approval gates they do not own. | Synchronous request that mutates job state; worker completes asynchronously. | `job.cancel_requested`. | Offline worker leaves cancellation requested and stale recovery handles it. |
| `jobs.retry` | Retry failed/stale/retryable work. | `jobs.retry` plus job-type permission. | Token must be scoped to job case. | `job_id`, `reason`, constrained `mode`. | Retry override/max attempts unless admin/service scoped. | Requeues existing job or creates approved rerun lineage. | `job.retry_requested`. | Returns error if dependency still hard down and policy disallows queueing. |
| `evidence.ingest` | Prepare registered evidence for parser/index workflows. | `evidence.ingest`. | Token-scoped case; evidence must belong to case. | `evidence_id`, allowed parser hints, ingest options, idempotency key. | Raw paths outside vault/case, mutable evidence writes, arbitrary case, bypass integrity gates. | Returns `job_id`; must enqueue. | `evidence.ingest_requested`, `job.created`. | Evidence unavailable fails or queues retry based on IO classification. |
| `evidence.verify_integrity` | Verify evidence manifest, ledger, hashes, and provenance. | `evidence.verify`. | Token-scoped case. | `evidence_id` or `scope=case`, `mode=fast|full`, idempotency key. | Mutating raw evidence, ignoring ledger failures, approving integrity exceptions. | Full/hash verification enqueues; read-only last-known status can be synchronous. | `evidence.integrity_verify_requested`. | Evidence mount unavailable returns degraded/failure without raw path leakage. |
| `parsers.list` | List parsers and worker capabilities. | `parsers.read`. | Optional scoped case for availability; system tokens may see global registry. | `artifact_type`, `evidence_id`, `include_unavailable`. | Local filesystem probing outside policy. | Synchronous read. | Optional `parsers.list`. | Returns unavailable/degraded parser capability details. |
| `parsers.run` | Run a parser against evidence/source. | `parsers.run` plus parser allowlist scope. | Token-scoped case; evidence/source must be authorized. | `evidence_id`, `parser_name`, constrained `options`, idempotency key. | Arbitrary host paths, unregistered parsers, raw OpenSearch index names, shell commands. | Returns `job_id`; must enqueue. | `parser.run_requested`, `job.created`. | OpenSearch down can still run parser if outputs can be preserved for later indexing. |
| `opensearch.index_status` | Read DB-backed indexing status. | `opensearch.status.read`. | Token-scoped case. | `evidence_id`, `parser_run_id`, `job_id`, `index_alias`, pagination. | Raw cluster admin APIs, wildcard `case-*` for normal agents. | Synchronous read from Postgres, with optional health check. | Optional `opensearch.index_status_read`. | OpenSearch down is reported as degraded; DB status remains authoritative. |
| `opensearch.health` | Report Gateway-mediated OpenSearch health. | `opensearch.health.read`. | Case-scoped summary for normal agents; admin token for system detail. | `include_case_indexes`, `include_cluster_summary`. | Credentials, raw node stats, unrestricted index lists for normal agents. | Synchronous. | Optional `opensearch.health_read`. | Returns `ok=false` or `degraded=true` without causing job state loss. |
| `report.generate` | Generate draft or final report artifacts. | `report.generate`. | Token-scoped case. | `profile`, approved finding refs, date range, idempotency key. | Final approval flags, unapproved agent findings as final, arbitrary file output path. | Returns `job_id`; must enqueue for full generation. | `report.generate_requested`. | If OpenSearch unavailable, report can use approved DB state or enter degraded/failed based on profile. |
| `finding.generate` | Generate proposed findings from scoped sources. | `finding.generate`. | Token-scoped case. | source refs, prompt/profile ID, model/profile metadata, idempotency key. | Auto-approval, final finding mutation, cross-case sources, raw OpenSearch DSL. | Returns `job_id`; generated findings remain proposed. | `finding.generate_requested`, later `finding.proposed`. | Search/index degradation reduces source set or fails safely with proposed-only output. |

## 4. Frontend/Operator Portal Integration

The operator portal is a read/write client of Gateway policy endpoints, not
forensic state authority. It may cache UI state, show optimistic button loading,
and poll for updates, but it must not directly write job status, parser status,
OpenSearch status, evidence integrity state, approvals, or audit rows.

Initial update mechanism: polling first.

Rationale:

- The current frontend already uses polling every 15 seconds for case data
  (`packages/case-dashboard/frontend/src/hooks/useDataPolling.js:16-43`).
- Polling is simplest to add safely behind Gateway auth and case policy.
- Polling keeps degraded-mode handling explicit and avoids adding a realtime
  dependency before the DB job model is implemented.
- Suggested initial cadence: active job detail every 2 to 5 seconds, job list
  and worker health every 10 to 15 seconds, system health every 15 to 30
  seconds, with backoff when the tab is hidden or jobs are terminal.

Later upgrade path: add SSE/WebSocket or Supabase Realtime for job updates once
the DB schema, RLS, and Gateway event policy are stable. Realtime should remain
read-only from the browser and should not bypass Gateway policy for actions.

| View/component | Data source | Endpoint or realtime source | Operator actions | Authorization | Degraded behavior | Read-only state |
| --- | --- | --- | --- | --- | --- | --- |
| Case job list | Postgres job summaries through Gateway. | `GET /api/cases/{case_id}/jobs`, initial polling. | Open job detail, retry/cancel eligible jobs, start allowed jobs. | Case membership plus job visibility policy. | Show worker/OpenSearch/evidence badges; list remains available if Postgres works. | Job status, attempts, progress, requester, worker. |
| Job detail page | Job detail, steps, logs, output refs. | `GET /jobs/{job_id}`, `/steps`, `/logs`. | Cancel, retry, open outputs, open approval gate. | Same as job visibility, elevated for sensitive logs/actions. | Show stale/offline dependency state and last known step. | Step state, logs, parser/indexing status, audit refs. |
| Step progress | `job_steps` read model. | `GET /jobs/{job_id}/steps`. | None except navigate/filter. | Case job read. | Last known progress remains visible; stale steps labeled. | Step status/timing/counts. |
| Log viewer | Redacted job logs. | `GET /jobs/{job_id}/logs?tail=true`. | Filter, copy visible log snippets, download approved log export later. | Log-read permission; restricted logs require elevated role. | Partial log storage degradation is explicit. | Raw log state and redaction decisions. |
| Worker status | Worker registrations/heartbeats. | `GET /api/cases/{case_id}/workers`, `GET /api/system/execution/health`. | None initially; admin later may drain/pause workers through separate APIs. | Case summary for members, detail for admin/lead. | Offline/degraded workers shown without hiding queued jobs. | Worker heartbeat/status/capabilities. |
| Ingestion progress | Jobs, parser runs, evidence ingest state. | Job detail/steps plus future evidence read endpoints. | Start ingest, cancel/retry. | Evidence ingest permission. | Evidence unavailable or no worker banners. | Evidence metadata, source hashes, integrity status. |
| Parser progress | Parser runs and job steps. | `GET /jobs/{job_id}/steps`; future parser-run endpoint if needed. | Retry failed parser run through job retry policy. | Parser job read/action policy. | Parser failures show retryability and stderr summary. | Parser run state and output counts. |
| OpenSearch indexing progress | Postgres indexing batches and OpenSearch health. | Job detail/index status plus `GET /api/system/opensearch/health`. | Retry/reindex through jobs. | Case search/index visibility. | Search unavailable is distinct from no results. | Indexing status, aliases, document counts. |
| Evidence integrity progress | Evidence jobs and integrity metadata. | Job detail/steps; future evidence integrity status endpoint. | Verify, seal/register/ignore/retire if authorized and gated. | Evidence policy and case role. | Integrity check unavailable or failed is prominent. | Hashes, ledger state, verification result. |
| Report generation progress | Report jobs and report metadata. | Job detail plus report read endpoints. | Generate, retry, approve final/export when allowed. | Report permission, approval role for final. | OpenSearch degraded may reduce source data or block profile. | Draft/final approval state. |
| Finding generation progress | Finding generation jobs and proposed findings. | Job detail plus findings review queue. | Review/approve/reject proposed findings. | Agent can propose; human approves. | Source/search degraded prevents finalization. | Proposed finding state and model/source metadata. |
| Retry/cancel controls | Job action policy from job detail. | `POST /cancel`, `POST /retry`. | Cancel/retry eligible jobs. | Gateway action policy; frontend only submits requests. | Disabled with explanation when dependency/policy blocks. | Actual state transition. |
| Degraded-mode banners | Gateway health endpoints and job dependency flags. | System health plus job/list health fields. | Navigate to health/details; retry after resolution. | Operator/admin split for detail. | Persistent banners for OpenSearch down, no worker, stale jobs, Postgres errors. | Health state. |
| Audit trail display | Audit read model. | Future `GET /api/cases/{case_id}/audit` or job detail audit refs. | Filter/export when authorized. | Case audit-read permission. | Audit unavailable is high severity; privileged actions fail closed where required. | Audit events. |

## 5. Evidence Vault And Evidence Integrity Integration

The migration must not replace the evidence vault or make raw evidence mutable.
The target moves operational metadata, status, and workflow state into
Postgres/Supabase while preserving the existing manifest/ledger behavior as
proof/export artifacts.

Target evidence job contracts:

- `evidence_register`: validates case scope, source policy, vault reference,
  duplicate source/hash behavior, and writes evidence metadata. It preserves
  current vault behavior and emits audit for registration.
- `evidence_hash`: computes or verifies cryptographic hashes for registered
  evidence. It writes hash status and provenance linkage in Postgres and, where
  compatible, appends/preserves evidence-chain ledger proof.
- `evidence_verify_integrity`: verifies manifest hash, ledger chain, file stat
  differences, and optional full hashes. Full verification is job-backed.
- `evidence_ingest`: prepares evidence for parser discovery and parser/indexing
  jobs. It does not mutate raw evidence; it creates derived output/job lineage.

Evidence metadata stored in Postgres should include:

- `evidence_id`
- `case_id`
- vault URI or controlled filesystem reference
- original source reference where policy allows
- size, mtime, and source description
- cryptographic hashes and hash algorithm
- immutable/vault status
- manifest entry reference
- ledger event reference or exported proof reference
- provenance chain to import/register actor, job, and audit event
- integrity status, last verification time, and verification job ID

Immutable evidence files remain in the evidence vault. Postgres stores metadata
and status, not mutable raw evidence blobs. Compatibility files such as
`evidence.json`, `evidence-manifest.json`, and `evidence-ledger.jsonl` can be
mirrored/exported during migration, but Postgres becomes operational authority
only after parity is verified.

Hash and provenance linkage:

- Every parser run that reads evidence must link to `evidence_id` and
  `source_hash` where available.
- Parser outputs and OpenSearch documents must carry or link to evidence ID,
  job ID, parser run ID, parser version, source hash, and schema version.
- A parser run must fail or enter `waiting_human` when required evidence
  integrity checks fail or are stale according to case policy.
- Derived files under current locations such as `agent/`, `extractions/`, or
  `tmp/` should eventually be registered as parser outputs with hashes.

Audit requirements:

- Evidence registration, access, hash reads, integrity verification, seal,
  ignore, retire, anchor, and high-risk evidence operations emit audit events.
- Job logs may include operational progress, but audit events remain the
  durable privileged-action record.
- High-risk evidence exceptions should enter `waiting_human` and require human
  approval before continuing.

Frontend behavior:

- Evidence views show last known integrity state, active integrity job, failed
  checks, hash/provenance links, and parser jobs derived from each evidence
  item.
- Evidence integrity progress is read from job/step state and evidence metadata,
  not inferred from local browser state.
- Raw evidence remains read-only from the portal unless a separate, audited,
  policy-approved access/export flow exists.

MCP behavior:

- `evidence.ingest` and full `evidence.verify_integrity` return `job_id`.
- MCP tools expose evidence IDs, approved metadata, hashes, and integrity status
  according to token scope.
- Normal agent tokens do not receive arbitrary raw paths or authority to mutate
  raw evidence.

## 6. OpenSearch Integration Contract

OpenSearch is a core search/data plane for derived forensic data. It is not a
standalone authority for job state, audit, approvals, evidence metadata, case
lifecycle, or token validity.

Parser output normalization:

- Parser workers normalize outputs into versioned records before indexing.
- Parser outputs are registered in Postgres with case, evidence/source, parser,
  schema, hash, job, and step lineage.
- OpenSearch documents can denormalize selected metadata for query performance,
  but authoritative lineage remains in Postgres.

Ingest batches and indexing jobs:

- `parser_run` jobs create parser run records and parser output or ingest batch
  registrations.
- `opensearch_index` jobs index a registered parser output or ingest batch into
  a Gateway-approved target alias/index.
- `maintenance_reindex` jobs rebuild derived indexes from registered parser
  outputs or source batches.
- Indexing status is stored in Postgres even when OpenSearch documents exist.

Minimum OpenSearch document metadata:

- `case_id`
- `evidence_id` where applicable
- `job_id`
- `job_step_id`
- `parser_run_id`
- `parser_output_id` or `ingest_batch_id`
- `indexing_batch_id`
- `parser_name`
- `parser_version`
- `source_path` or source logical reference where policy allows
- `source_hash`
- `indexed_at`
- `schema_version`
- current compatibility fields such as `vhir.source_file`,
  `vhir.ingest_audit_id`, `vhir.parse_method`, host fields, and
  `pipeline_version` where still useful

Search/timeline/IOC access:

- Search, timeline, IOC, aggregate, and artifact views use case-scoped Gateway
  APIs and/or core SIFT MCP tools.
- The Gateway resolves authorized case scope from Supabase session or MCP token
  context and constructs OpenSearch queries internally.
- Normal operators and agents do not pass raw OpenSearch index names or raw DSL.
- Admin-only diagnostic APIs may expose constrained cluster/index detail, but
  not as the normal investigative workflow.

Degraded mode:

- If OpenSearch is down, Postgres job, evidence, audit, approval, and case state
  remain readable.
- Parser outputs can be preserved for later indexing if parser execution does
  not require OpenSearch at parse time.
- Indexing jobs become `retrying`, `failed`, or dependency-degraded according to
  retry policy.
- Frontend search views must distinguish "no hits" from "search unavailable".
- MCP tools return structured degraded responses and do not fall back to
  cross-case wildcard searches.

Duplicate indexing prevention:

- Job idempotency keys include case, evidence/source, parser name/version,
  source hash, schema version, target alias/index, and ingest batch.
- Indexing batch registrations prevent repeated bulk indexing from creating
  duplicate documents.
- Reindex jobs create explicit new batch/index lineage and should use aliases or
  cutover records rather than overwriting untracked state.
- Parser version and schema version are part of the deduplication key because a
  changed parser or schema can intentionally produce new documents.

Target mapping between control-plane rows and OpenSearch docs:

| Control-plane record | Role | Link to next layer |
| --- | --- | --- |
| `jobs` | Durable requested work and lifecycle. | One job has many `job_steps`; parser/index jobs create parser and indexing records. |
| `job_steps` | Ordered progress and operational status. | Parser steps link to `parser_runs`; indexing steps link to indexing batches. |
| `parser_runs` | One parser execution against a source/evidence item. | One parser run creates one or more `parser_outputs` or ingest batches. |
| `parser_outputs` / ingest batches | Registered derived output with hashes and schema. | One output can be indexed into one or more OpenSearch aliases/indices. |
| `opensearch_indexes` | Registered case-scoped aliases/indices and health. | Used by Gateway/OpenSearch service to construct allowed queries. |
| `opensearch_indexing_batches` | Bulk indexing attempt/status/counts. | Each OpenSearch document stores `indexing_batch_id` and lineage metadata. |
| OpenSearch docs | Searchable derived records. | Docs link back to Postgres IDs and evidence/source hashes. |

## 7. Audit And Approval Integration

Audit remains mandatory for privileged and forensic state-changing actions.
Job logs provide operational detail. Some events are both audit events and job
logs.

Event classification:

| Event | Audit event | Job log | Notes |
| --- | --- | --- | --- |
| Job creation request | Yes | Yes | Includes actor, case, job type, idempotency key, policy result. |
| Job claim/start | Yes | Yes | Includes worker ID, attempt, lease. |
| Step progress | Usually no | Yes | High-level privileged step boundaries can also audit. |
| Job success/failure | Yes | Yes | Includes output refs, metrics, failure class. |
| Cancellation request/finalization | Yes | Yes | Actor and reason are audited. |
| Retry/requeue/force rerun | Yes | Yes | Preserves previous attempts and lineage. |
| Worker heartbeat | No | Optional | Stale detection is audited, normal heartbeat is not. |
| Worker stale/offline transition | Yes | Yes | Includes prior worker, heartbeat age, recovery decision. |
| Parser run start/end/failure | Yes | Yes | Includes parser, version, source hash, evidence ID if known. |
| Evidence access/hash/integrity | Yes | Sometimes | Operational progress in logs; access/check is audited. |
| OpenSearch indexing batch | Yes | Yes | Includes alias/index, schema version, counts, failures. |
| Search read | Policy-dependent | No | Sensitive/cross-cutting search may audit. |
| Finding generation | Yes | Yes | Generated findings remain proposed. |
| Report generation/export | Yes | Yes | Final/exported reports require approval. |
| Human approval/rejection | Yes | Optional | Includes human actor, content hash, approval target. |
| Policy denial | Yes | No | Includes actor, token/user, case, tool/action, reason. |

Approval-gated actions enter `waiting_human` when execution cannot continue
without a human decision. Target approval gates include:

- final report approval
- official report export
- case archive or close
- destructive cleanup
- finding approval or promotion from proposed to accepted
- high-risk evidence operations such as ignore, retire, seal exception, failed
  integrity override, or export of restricted evidence
- maintenance reindex cutover when it would replace active aliases or operator
  views

Approval rules:

- Human approvals use Supabase-authenticated human identity and Gateway policy.
- Agent-generated findings remain proposed/pending and cannot become final
  without human approval.
- Agents must not approve their own findings.
- Approval audit events include actor, case, target entity, target content hash
  or version, decision, reason, timestamp, and linked job/audit IDs.
- Destructive/final actions fail closed if approval audit cannot be written.

## 8. Worker Status And Health Integration

This contract defines observation and policy integration only. It does not
design the full worker implementation.

Worker registration fields:

- `worker_id`
- host and process identity
- worker version
- capabilities
- parser allowlist and versions
- supported job types
- OpenSearch access mode
- evidence operation support
- report/finding generation support
- `registered_at`
- `last_seen_at`
- active job ID
- heartbeat/degraded reason

Worker behavior visible to Gateway/portal/MCP:

- Workers register in Postgres before claiming jobs.
- Workers heartbeat while online and while running claimed jobs.
- Workers claim only jobs matching their capabilities.
- Workers report active job and current step.
- Workers become `degraded` when a dependency is unavailable but the worker can
  still heartbeat.
- Workers become `offline` or `stale` when `last_seen_at` exceeds policy.
- Stale running jobs are marked `stale` by a system/stale-detector path and then
  requeued, retried, failed, or cancelled according to job policy.

Health surfaces:

- Gateway REST exposes `GET /api/cases/{case_id}/workers` and
  `GET /api/system/execution/health`.
- MCP exposes health through `jobs.list`, `parsers.list`, `opensearch.health`,
  and later an explicit worker/execution health tool if needed.
- Frontend renders worker capability, active job, last seen, degraded reason,
  and queue impact.

Audit/log behavior:

- Worker registration and capability changes are audited.
- Job claim/start/succeed/fail/cancel transitions are both audit and job logs.
- Normal heartbeat is not audited at high volume.
- Worker stale detection and recovery decision are audited and logged on the
  affected job.

## 9. Error And Degraded-Mode Contract

REST error envelope:

```json
{
  "error": {
    "code": "code",
    "message": "human safe message",
    "request_id": "uuid",
    "case_id": "case-id-or-null",
    "job_id": "job-id-or-null",
    "retryable": false,
    "degraded": false,
    "details": {}
  }
}
```

MCP error envelope:

```json
{
  "ok": false,
  "error": {
    "code": "code",
    "message": "agent safe message",
    "retryable": false,
    "degraded": false,
    "details": {}
  },
  "audit_event_id": "uuid-or-null"
}
```

| Scenario | REST behavior | MCP behavior | Frontend display | Audit/log behavior |
| --- | --- | --- | --- | --- |
| OpenSearch down | Search/status returns `200` degraded if Gateway/Postgres work; indexing create may queue/pending/retry; hard search can return `503` with `opensearch_unavailable`. | `opensearch.health` returns degraded; indexing tools return job ID or retryable error by policy. | Banner: search/indexing degraded; distinguish from no hits. | Audit indexing failure/degraded; job logs include health error. |
| No worker available | Job creation returns accepted queued job with degraded dependency unless policy requires worker. Health returns degraded/offline. | Job tools return queued job and worker-unavailable flag. | Job list shows queued/no capable worker. | Optional health log; no claim audit until a worker claims. |
| Job stale | Job reads return `stale` or recovery status. Retry/cancel allowed by policy. | `jobs.get` returns stale/recovering; clients should not resubmit. | Stale badge, last worker, last heartbeat, recovery decision. | Audit `job.stale_detected`; job log includes last known step. |
| Evidence unavailable | Job create may fail validation or queue retry; running job becomes retrying/failed. | Evidence tools return safe failure without leaking unauthorized raw path. | Evidence unavailable warning and affected jobs. | Audit attempted evidence access and failure; job log summarizes. |
| Parser failure | Job becomes `retrying` or `failed`; parser_run failed. | `jobs.get` exposes failure summary and retryability. | Parser step failed with retry action when allowed. | Audit parser failure; job log has redacted stderr/error. |
| Cancellation requested | `POST /cancel` returns `202`; job shows cancellation requested until worker finalizes. | `jobs.cancel` returns accepted request. | Spinner/state "cancellation requested"; final cancelled/failed state later. | Audit request and final result; job logs signal/termination steps. |
| Authorization failure | `401` unauthenticated or `403`/policy-shaped `404` unauthorized. | `ok=false`, `invalid_token_scope` or `case_scope_denied`. | Access denied; do not reveal hidden case/job details. | Audit policy denial where actor/token is known. |
| Invalid case scope | `404` or `403` depending on disclosure policy; no job mutation. | `case_scope_denied` or `invalid_case_scope`. | Not found/access denied. | Audit denied case/tool scope. |
| Invalid token scope | `403` for REST service paths or MCP `ok=false`. | `invalid_token_scope`; no backend dispatch. | Usually not shown to human portal except token management/debug views. | Audit token-scope denial. |
| Duplicate job/idempotency conflict | Compatible duplicate returns existing job; incompatible duplicate returns `409`. | Returns existing `job_id` or `idempotency_conflict`. | Show existing job with explanation. | Audit duplicate request or conflict. |
| Postgres unavailable | `503`; no job creation/status guarantee. Gateway may return local health only. | `ok=false`, `postgres_unavailable`; no claim of job creation. | High-severity control-plane unavailable banner. | DB audit unavailable; Gateway emergency/local logs only until DB returns. |

## 10. Migration Notes From Current Implementation

These modules will likely need later changes. This run does not implement them.

Gateway REST routes:

- `packages/sift-gateway/src/sift_gateway/rest.py` will need job, worker,
  execution health, OpenSearch health, and policy-shaped response routes.
- `packages/sift-gateway/src/sift_gateway/auth.py` and
  `packages/sift-gateway/src/sift_gateway/identity.py` will need Supabase
  session, service-token, case-scope, and tool-scope integration.
- `packages/sift-gateway/src/sift_gateway/server.py` will need service wiring
  for job creation/observation and OpenSearch core integration.
- `packages/case-dashboard/src/case_dashboard/routes.py` currently owns many
  portal file-backed routes and will need bridge or replacement paths for job
  creation/status, report generation, evidence integrity, and approvals.

FastMCP endpoint/tool registration:

- `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py` will need one
  consistent policy/evidence/audit path for aggregate and any per-backend
  execution tools.
- `packages/sift-gateway/src/sift_gateway/server.py` currently routes core
  tools to `sift_core.agent_tools` and add-on tools through backend maps; core
  job/OpenSearch tools will need to fit this policy model.
- `packages/sift-core/src/sift_core/agent_tools.py` will likely gain constrained
  job, parser, evidence, report, finding, and OpenSearch tool specs.

OpenSearch MCP backend:

- `packages/opensearch-mcp/src/opensearch_mcp/server.py` currently contains
  standalone MCP search/status/ingest tools and background subprocess launchers.
- `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`,
  `ingest_cli.py`, and `ingest_status.py` will need adapters from filesystem
  status to DB-backed jobs, parser runs, outputs, and indexing batches.
- Parser modules such as `parse_evtx.py`, `parse_csv.py`, `parse_json.py`,
  `parse_delimited.py`, `parse_memory.py`, `parse_plaso.py`, and others will
  need metadata stamping for job/parser/evidence/indexing IDs.
- `packages/opensearch-mcp/src/opensearch_mcp/paths.py` and mapping templates
  will need alignment with the approved index strategy and metadata contract.

Evidence vault modules:

- `packages/sift-core/src/sift_core/evidence_chain.py` must be preserved and
  bridged, not replaced abruptly.
- `packages/sift-core/src/sift_core/evidence_ops.py`,
  `packages/sift-core/src/sift_core/verification.py`, and evidence routes in
  `packages/case-dashboard/src/case_dashboard/routes.py` will need job-backed
  operation paths where work is expensive or approval-gated.
- `packages/sift-core/src/sift_core/case_io.py` currently provides records and
  approval-log helpers that will need DB authority plus compatibility export.

Audit modules:

- `packages/sift-common/src/sift_common/audit.py` will need a Postgres-backed
  audit writer or adapter with JSONL export during migration.
- Gateway MCP audit in `mcp_endpoint.py`, core tool audit in
  `agent_tools.py`, OpenSearch ingest audit, and evidence ledger events need
  consistent IDs and linkage to jobs and case-scoped actors.

Parser/ingest modules:

- OpenSearch parser and ingest code needs DB job/step/parser-run callbacks,
  idempotency keys, retry/cancel support, and output registration.
- Native execution in
  `packages/sift-core/src/sift_core/execute/executor.py` and
  `packages/sift-core/src/sift_core/execute/tools/generic.py` may later be
  wrapped by job-backed execution for long commands while preserving shell-free
  subprocess discipline.

Frontend API clients/state:

- `packages/case-dashboard/frontend/src/api/client.js`,
  `packages/case-dashboard/frontend/src/api/endpoints.js`,
  `packages/case-dashboard/frontend/src/hooks/useDataPolling.js`, and
  `packages/case-dashboard/frontend/src/store/useStore.js` will need job,
  worker, health, OpenSearch status, and audit read models.
- Components under evidence, reports, findings/review, settings/status, and
  navigation will need progress/status views once REST contracts are
  implemented.

Config/env handling:

- `configs/gateway.yaml.template`,
  `packages/sift-gateway/src/sift_gateway/config.py`,
  `packages/sift-gateway/src/sift_gateway/server.py`, and
  `packages/sift-common/src/sift_common/__init__.py` currently participate in
  env/pointer-based active-case behavior.
- Target jobs must use case context from Gateway-validated session/token/job
  rows. Compatibility exports for `SIFT_CASE_DIR`, `~/.sift/active_case`,
  `~/.sift/ingest-status`, and `~/.sift/ingest-logs` should be generated from
  DB authority only during transition.

## 11. Decisions And Open Questions

### Confirmed Decisions

- No Redis/RQ.
- No Celery, Temporal, or external queue for this migration path.
- REST and MCP long-running actions enqueue DB-backed jobs.
- Gateway enforces case scope and tool scope.
- Case authorization comes from Supabase Auth/RLS plus Gateway policy.
- OpenSearch is core but not authoritative for jobs, audit, approvals, evidence
  metadata, case lifecycle, or tokens.
- Frontend is not forensic state authority.
- Evidence vault behavior is preserved.
- Raw evidence remains immutable.
- Audit remains mandatory.
- Agent findings are not auto-approved.
- Long-running MCP parser/evidence/indexing/report/finding tools return
  `job_id`.
- Workers claim and heartbeat jobs through Postgres/Supabase authority.
- OpenSearch degraded mode is explicit in REST, MCP, frontend, and job/indexing
  state.

### Decisions previously open here, now locked (charter)

- Human role names/permissions: `readonly`, `operator`, `lead`, `owner`, `admin`
  with the permission matrix in `09_identity_auth_cutover.md` §5.
- Worker topology: single local worker in v1 (D9).
- OpenSearch indexing: reuse the existing `case-{case}-{type}-{host}` model and
  register it; logical-family rename deferred (D18, see `03` §7A). OpenSearch
  3.5.0 security-on (D6).
- Raw OpenSearch DSL is admin-only; normal agents get allowlisted query inputs
  only.
- Gateway-only access; per-backend MCP routes disabled (D2/D3).
- Frontend polling first; SSE/WebSocket/Supabase Realtime is a later upgrade once
  the DB/RLS/Gateway event policy is stable (suggested cadences are in §4).

### Decisions still genuinely open (non-blocking, decide at conversion time)

- Whether short native commands stay synchronous while long native work becomes
  jobs (default: short stays synchronous).
- Retry granularity (default: whole job in v1; finer later).
- Cancellation semantics for subprocess trees and partially indexed batches
  (default: cooperative stop, mark `partial`, never report partial as complete).
- Compatibility-export lifetime for `~/.sift/ingest-status`, `~/.sift/ingest-logs`,
  `~/.sift/active_case`, and legacy case JSON (default: one release cycle past
  parity).

### Code Facts Still Needing Confirmation

- Exact current role/session model that will map to Supabase Auth/RLS and
  Gateway job policies.
- Complete list of REST endpoints and frontend components that will submit
  long-running work after the portal cutover.
- Exact parser coverage for required metadata fields and parser outputs that are
  files rather than direct OpenSearch documents.
- Current subprocess cancellation behavior for every parser/tool family.
- Which external scripts still consume `~/.sift/ingest-status`,
  `~/.sift/ingest-logs`, active-case pointers, ingest manifests, or legacy
  `case-*` index names.
- Which evidence operations are too expensive to remain synchronous.
- Which report/export workflows should become job-backed first.
- Canonical OpenSearch deployment/version profile for the local SIFT VM target.

## 12. Next Recommended Run

Create `docs/migration/07_execution_roadmap.md`.

Recommended scope:

- migration phases for execution/jobs
- first execution-focused PR plan
- rollback strategy
- tests and acceptance criteria

The next run should remain planning-focused unless explicitly authorized to
implement code or database migrations.
