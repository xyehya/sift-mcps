# Execution Job Model

Last updated: 2026-06-07.

Scope: planning only. This document defines the target DB-backed execution job
model for SIFT workers claiming and running durable jobs from
Supabase/Postgres. It does not create schemas, migrations, REST APIs, MCP tools,
frontend views, code changes, or a full execution roadmap.

## 1. Executive Summary

The target execution model makes Supabase/Postgres the source of truth for
durable work.

- Gateway/API/MCP request paths create durable job records in Postgres.
- SIFT workers poll Postgres and atomically claim jobs.
- Workers run SIFT workflows, parsers, evidence operations, OpenSearch
  indexing, reports, and finding-generation tasks outside MCP request paths.
- Workers write status, steps, logs, parser run records, indexing status,
  evidence integrity events, and audit events back to Postgres.
- OpenSearch stores searchable parsed artifacts and derived investigative
  documents, but Postgres remains authoritative for job, workflow, parser,
  indexing, evidence, approval, and audit state.
- No Redis, RQ, Celery, Temporal, or external queue is introduced.

This design is grounded in the current execution inventory:

- Portal/operator execution is mostly synchronous and file-backed. Evidence
  operations, review commits, report generation, and polling resolve active case
  through `_resolve_case_dir()` and legacy active-case state
  (`04_execution_current_state.md`, section 1).
- Gateway MCP calls are synchronous; aggregate calls run an evidence gate and
  write transport audit, while per-backend MCP routes have a different
  policy/audit surface (`04_execution_current_state.md`, section 1).
- Native `run_command` executes synchronously through shell-free subprocess
  stages and may save stdout/stderr under case-controlled directories
  (`04_execution_current_state.md`, section 1).
- OpenSearch ingest is the main long-running execution path. It launches
  `python -m opensearch_mcp.ingest_cli`, records pid/run_id under
  `~/.sift/ingest-status`, writes logs under `~/.sift/ingest-logs`, and indexes
  into case-prefixed OpenSearch indices (`04_execution_current_state.md`,
  sections 1, 2, and 4).
- Parser modules write directly to OpenSearch and stamp partial provenance such
  as `vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`, optional
  `vhir.vss_id`, and `pipeline_version`, but do not yet carry durable
  `job_id`, `job_step_id`, or `parser_run_id` (`04_execution_current_state.md`,
  section 2; `03_opensearch_core_integration.md`, section 2).
- Evidence chain authority is currently manifest/ledger files, with
  `evidence.json` as compatibility view. The target preserves evidence vault
  behavior while moving operational metadata, integrity status, and audit
  events to Postgres (`02_authoritative_domains_and_boundaries.md`, sections 2
  and 3).

## 2. Target Job Lifecycle

Long-running work must not execute directly inside MCP request paths. MCP tools
that start parser workflows, evidence workflows, report generation,
OpenSearch indexing, or other long work enqueue a job and return a job ID.
Destructive or final actions require explicit human approval. Agent-generated
findings are proposed/pending until a human approves them. Cancellation is an
explicit audited lifecycle transition. Retry preserves previous attempts, steps,
logs, parser runs, and indexing records.

### Status Definitions

| Status | Meaning | Who can set it | Allowed next statuses | Required audit/log behavior | Operator-facing meaning | MCP-facing meaning |
| --- | --- | --- | --- | --- | --- | --- |
| `pending` | Job record exists but is not yet eligible to run, usually because validation, dependency checks, or approval gating has not completed. | Gateway, system policy, worker for dependency discovery. | `queued`, `waiting_human`, `cancelled`, `failed`, `paused` | Audit creation with requester, case, job type, idempotency key, and reason for pending. Log validation/dependency notes. | Work request received but not yet runnable. | Tool call returns job ID and pending reason; agents should poll rather than repeat. |
| `queued` | Job is eligible for a worker to claim. | Gateway, scheduler/system, worker after dependency resolution or retry delay. | `running`, `cancelled`, `paused`, `waiting_human`, `failed` | Audit enqueue transition. Log queue reason, priority, and dependencies. | Waiting for worker capacity. | Job is accepted and waiting; no execution result yet. |
| `running` | A worker has claimed the job lease and is executing steps. | Worker through atomic claim only. | `succeeded`, `failed`, `retrying`, `waiting_human`, `cancelled`, `stale`, `paused` | Audit claim/start with worker ID and lease. Logs and step updates must be written during execution. | Work is actively running on a named worker. | Tool status should expose progress, step names, and whether cancellation is available. |
| `waiting_human` | Execution is blocked until a human approves, rejects, modifies, or resumes. | Gateway policy, worker when it reaches an approval gate, human approval service. | `queued`, `running`, `cancelled`, `failed`, `paused` | Audit why human input is required and what actor requested it. Log any proposed outputs. | Requires operator decision before continuing. | Agents see blocked state and may not auto-approve. |
| `succeeded` | Job completed successfully and all required durable status/audit writes succeeded. | Worker. | Terminal, except administrative re-run creates a new job or explicit `maintenance_reindex` job. | Audit success with outputs, metrics, parser/indexing summaries, and content hashes where applicable. | Completed. | Tool status returns final result references, not raw long logs by default. |
| `failed` | Job reached a terminal failure or exhausted retry policy. | Worker, stale detector/system for unrecoverable stale work, Gateway for validation failure. | Terminal, except explicit retry/rerun creates a new attempt or new job according to policy. | Audit failure with summary, attempt, failure class, and retry exhaustion state. Logs preserve error details with redaction. | Failed and needs operator review or explicit rerun. | Tool status returns failure summary, retryability, and safe next action. |
| `retrying` | Job failed an attempt but remains eligible for another attempt after backoff. | Worker or system retry policy. | `queued`, `failed`, `cancelled`, `paused` | Audit retry decision and preserve previous attempt steps/logs. Log backoff, attempt count, and failure summary. | Transient failure; will run again later. | Agents should not submit duplicate jobs; status exposes next retry time. |
| `cancelled` | Job was explicitly cancelled before or during execution. | Human operator, Gateway policy, authorized service token; worker finalizes after observing cancellation. | Terminal. | Audit cancellation request and final cancellation completion. Logs must distinguish requested, signaled, and stopped. | Stopped by explicit request. Outputs may be partial and marked as such. | Agents see cancellation as final and audited; they cannot silently abandon work. |
| `stale` | Job lease expired or heartbeat stopped while in a nonterminal running state. | Stale detector/system. | `queued`, `retrying`, `failed`, `cancelled` | Audit stale detection with prior worker ID, lease, heartbeat age, and recovery decision. | Worker likely crashed or lost connectivity. | Agents see degraded/recovering state; duplicate submission is discouraged. |
| `paused` | Job is intentionally held by operator/system and should not be claimed. | Human operator, Gateway policy, scheduler/system. | `queued`, `waiting_human`, `cancelled`, `failed` | Audit pause/resume reason and actor. Logs record pause boundaries. | Intentionally stopped but resumable. | Agents see not-running state; no automatic continuation until resumed. |

### State Transition Table

| From | To | Condition |
| --- | --- | --- |
| `pending` | `queued` | Validation complete, dependencies met, no approval gate blocking. |
| `pending` | `waiting_human` | Human approval is required before execution. |
| `pending` | `paused` | Operator/system holds work before queueing. |
| `pending` | `failed` | Request cannot be validated or authorized. |
| `pending` | `cancelled` | Explicit cancellation before queueing. |
| `queued` | `running` | Worker atomically claims lease. |
| `queued` | `waiting_human` | Late policy check requires approval. |
| `queued` | `paused` | Operator/system pauses before claim. |
| `queued` | `failed` | Queue-time validation or dependency check fails. |
| `queued` | `cancelled` | Explicit cancellation before claim. |
| `running` | `succeeded` | Worker completes all required steps and durable writes. |
| `running` | `failed` | Nonretryable failure or retry exhaustion. |
| `running` | `retrying` | Retryable failure after attempt records are finalized. |
| `running` | `waiting_human` | Worker reaches an approval gate. |
| `running` | `paused` | Cooperative pause requested and safe pause point reached. |
| `running` | `cancelled` | Cancellation requested and worker/subprocess stops or is marked stopped. |
| `running` | `stale` | Lease/heartbeat expires and stale detector takes ownership. |
| `waiting_human` | `queued` | Human approves continuation or submits required decision. |
| `waiting_human` | `running` | Same worker can continue immediately after approval and valid lease. |
| `waiting_human` | `paused` | Operator holds the job instead of deciding. |
| `waiting_human` | `failed` | Human rejects required prerequisite or policy marks unrecoverable. |
| `waiting_human` | `cancelled` | Human/operator cancels. |
| `retrying` | `queued` | Retry backoff elapses. |
| `retrying` | `failed` | Retry budget exhausted or retry disabled by policy. |
| `retrying` | `paused` | Operator/system pauses before retry. |
| `retrying` | `cancelled` | Explicit cancellation before retry. |
| `stale` | `queued` | Recovery policy allows requeue and idempotency checks pass. |
| `stale` | `retrying` | Recovery policy records stale attempt as retryable failure. |
| `stale` | `failed` | Recovery is unsafe or attempts exhausted. |
| `stale` | `cancelled` | Operator cancels stale job. |
| `paused` | `queued` | Operator/system resumes runnable work. |
| `paused` | `waiting_human` | Resume requires human decision. |
| `paused` | `failed` | Operator/system marks unrecoverable. |
| `paused` | `cancelled` | Explicit cancellation while paused. |

## 3. Job Ownership And Scope

Every job is explicitly scoped. Minimum target job fields:

- `job_id`
- `case_id`
- `requested_by_user_id`, nullable
- `requested_by_agent_id`, nullable
- `requested_by_token_id`, nullable
- `created_by_type`: `user | agent | system | worker`
- `job_type`
- `status`
- `priority`
- `idempotency_key`
- `spec` JSON
- `created_at`
- `queued_at`
- `started_at`
- `finished_at`
- `claimed_by_worker_id`
- `lease_expires_at`
- `heartbeat_at`
- `attempt_count`
- `max_attempts`
- `cancellation_requested_at`
- `cancellation_requested_by`
- `failure_summary`

`case_id` must not come from process environment, Gateway config active-case
pointers, `SIFT_CASE_DIR`, or `~/.sift/active_case` in the target model. The
current system uses these mechanisms for portal, Gateway, MCP backends, audit,
and OpenSearch active-case resolution (`04_execution_current_state.md`,
sections 1 and 4). That is acceptable as legacy compatibility but unsafe as
job authority because jobs can outlive request processes, workers can run
multiple cases, and subprocesses inherit environment accidentally.

Target case scope comes from:

- Gateway-validated human session context for operator-created jobs.
- Gateway-validated MCP/service-token context for agent/service-created jobs.
- System policy only for maintenance jobs, with explicit case scope unless the
  maintenance type is intentionally cross-case and admin-only.

Workers do not choose arbitrary case scope. They receive case scope from the
claimed job row and use it to constrain evidence paths, parser execution,
OpenSearch index aliases, audit events, and output registrations.

## 4. DB-Backed Job Claiming Model

Workers poll Postgres for runnable jobs and atomically claim one job at a time
or in a small bounded batch. The design should be compatible with local
Supabase/Postgres and use ordinary Postgres transactions, row locks, and
`SKIP LOCKED`-style claiming.

### Claiming Rules

- Poll `queued` jobs whose dependencies and retry delay are satisfied.
- Claim in a transaction using row locks so two workers cannot claim the same
  job.
- Filter by worker capabilities, parser allowlist, command allowlist, and job
  type.
- Prefer higher priority, then older `queued_at`.
- Preserve fairness across cases so one noisy case cannot starve others.
- Set `claimed_by_worker_id`, `started_at`, `heartbeat_at`,
  `lease_expires_at`, and increment attempt metadata inside the claim
  transaction.
- Workers heartbeat running jobs before lease expiry.
- A stale detector marks expired leases as `stale` and then requeues, retries,
  or fails according to retry/idempotency policy.
- Cancellation is cooperative first: mark cancellation requested, signal the
  worker/subprocess, then finalize `cancelled` with audit.
- Paused jobs are never claimed.
- Idempotency keys and parser/indexing registrations reduce harm if a stale job
  is retried after partial work.

Fairness can be implemented by selecting the best candidate per case and then
ordering across those candidates by priority and age. The exact SQL is deferred,
but the principle is fixed: job priority matters, but case starvation must be
avoided.

### Design Pseudocode

Worker dispatcher loop:

```text
worker_startup():
  worker_id = register_worker(hostname, pid, version, capabilities)
  while not shutdown_requested:
    refresh_worker_registration(worker_id)
    job = claim_next_job(worker_id, capabilities)
    if job is null:
      sleep(poll_interval_with_jitter)
      continue

    try:
      execute_job(job, worker_id)
    except UnexpectedWorkerError as error:
      mark_job_failed(job.job_id, worker_id, error, retryable=true)
```

Claim next job:

```text
claim_next_job(worker_id, capabilities):
  begin transaction
    candidate = select queued job
      where status = 'queued'
        and job_type is supported by capabilities
        and retry_after <= now if present
        and not paused
      order by fairness_bucket(case_id), priority desc, queued_at asc
      for update skip locked
      limit 1

    if no candidate:
      commit
      return null

    update jobs
      set status = 'running',
          claimed_by_worker_id = worker_id,
          started_at = coalesce(started_at, now),
          heartbeat_at = now,
          lease_expires_at = now + lease_duration,
          attempt_count = attempt_count + 1
      where job_id = candidate.job_id
        and status = 'queued'

    insert audit event 'job.claimed'
    insert job log 'claimed by worker'
  commit
  return candidate
```

Heartbeat running job:

```text
heartbeat_job(job_id, worker_id):
  update jobs
    set heartbeat_at = now,
        lease_expires_at = now + lease_duration
    where job_id = job_id
      and claimed_by_worker_id = worker_id
      and status in ('running', 'waiting_human')

  if zero rows updated:
    stop work; ownership was lost or job is no longer runnable
```

Mark job succeeded:

```text
mark_job_succeeded(job_id, worker_id, result_summary, output_refs):
  begin transaction
    assert current row is running and claimed_by_worker_id = worker_id
    finalize open job_steps as succeeded or failed according to step state
    record parser/indexing/output summaries
    update jobs
      set status = 'succeeded',
          finished_at = now,
          heartbeat_at = now,
          lease_expires_at = null,
          failure_summary = null
    insert audit event 'job.succeeded'
    insert job log with metrics and output_refs
  commit
```

Mark job failed:

```text
mark_job_failed(job_id, worker_id, error, retryable):
  begin transaction
    assert worker owns current running job, or system owns stale recovery
    close running step with failed status and error_summary
    insert job log level='error' with redacted structured_data

    if retryable and attempt_count < max_attempts and not cancellation requested:
      update jobs set status = 'retrying', failure_summary = summary(error)
      insert audit event 'job.retry_scheduled'
    else:
      update jobs set status = 'failed', finished_at = now,
        lease_expires_at = null, failure_summary = summary(error)
      insert audit event 'job.failed'
  commit
```

Retry job:

```text
retry_job(job_id, policy):
  begin transaction
    assert status = 'retrying'
    preserve previous attempts, steps, logs, parser_runs, and indexing batches
    if retry_after <= now and attempt_count < max_attempts:
      update jobs
        set status = 'queued',
            queued_at = now,
            claimed_by_worker_id = null,
            lease_expires_at = null,
            heartbeat_at = null
      insert audit event 'job.requeued'
    else if attempt_count >= max_attempts:
      update jobs set status = 'failed', finished_at = now
      insert audit event 'job.retry_exhausted'
  commit
```

Detect stale jobs:

```text
detect_stale_jobs():
  begin transaction
    stale_rows = select running jobs
      where lease_expires_at < now
      for update skip locked

    for each job in stale_rows:
      update jobs set status = 'stale'
      insert audit event 'job.stale_detected'
      insert job log level='warning' with prior worker and heartbeat age

      if recovery_is_safe(job) and attempt_count < max_attempts:
        update jobs set status = 'retrying', claimed_by_worker_id = null
      else:
        update jobs set status = 'failed', finished_at = now
  commit
```

Cancel job:

```text
request_cancel_job(job_id, actor):
  begin transaction
    assert actor is authorized for case and job action
    assert status in ('pending', 'queued', 'running', 'retrying',
                      'waiting_human', 'paused', 'stale')
    update jobs
      set cancellation_requested_at = now,
          cancellation_requested_by = actor
    insert audit event 'job.cancel_requested'

    if status in ('pending', 'queued', 'retrying', 'waiting_human',
                  'paused', 'stale'):
      update jobs set status = 'cancelled', finished_at = now
      insert audit event 'job.cancelled'
  commit

worker_observes_cancel(job_id):
  signal subprocess group if one exists
  close steps and partial outputs as cancelled/partial
  update jobs set status = 'cancelled', finished_at = now
  insert audit event 'job.cancelled'
```

## 5. Job Steps And Logs

`job_steps` describe structured execution progress. Likely fields:

- `step_id`
- `job_id`
- `case_id`
- `step_name`
- `step_type`
- `status`
- `attempt`
- `started_at`
- `finished_at`
- `duration_ms`
- `error_summary`
- `metrics` JSON
- `output_refs` JSON

Step examples include `validate_request`, `resolve_evidence`,
`hash_evidence`, `run_parser`, `bulk_index_opensearch`,
`write_report_artifact`, `generate_findings`, `verify_integrity`, and
`cleanup_partial_outputs`.

`job_logs` provide append-only operational logs. Likely fields:

- `log_id`
- `job_id`
- `step_id`, nullable
- `case_id`
- `timestamp`
- `level`
- `message`
- `structured_data` JSON
- `source`: `gateway | worker | parser | opensearch | evidence | report`

Stdout/stderr from subprocesses should be captured by the worker and either:

- stored as bounded structured log lines in `job_logs`;
- stored in retained log files/object storage with a DB log reference; or
- both, with tail summaries in Postgres and full logs retained outside hot DB
  rows.

Sensitive data must be redacted before writing logs to Postgres or exported log
files. Redaction should cover secrets, bearer tokens, service-token material,
credential-like strings, overly broad environment dumps, and evidence content
that is not necessary for operational diagnosis. Logs should prefer paths,
hashes, counts, and durable IDs over raw evidence snippets.

Future streaming can read `job_logs` by `case_id` and `job_id` ordered by
timestamp/log ID. The streaming transport is deferred; the data model should
not depend on frontend polling files or OpenSearch ingest status files.

Logs and audit events are related but separate:

- Job logs are operational detail for progress and troubleshooting.
- Audit events are durable accountability records for privileged actions,
  lifecycle transitions, evidence access, indexing, approvals, cancellation,
  and policy decisions.
- Every lifecycle transition creates audit. Not every log line creates audit.

## 6. Parser Run And Parser Output Model

The target model links jobs, steps, parser runs, parser outputs, ingest batches,
and OpenSearch indexing status.

Every parser run should link to:

- `case_id`
- `job_id`
- `job_step_id`
- `evidence_id` where applicable
- `parser_name`
- `parser_version`
- `source_path` or logical source reference
- `source_hash`
- `started_at`
- `finished_at`
- `status`
- `output_count`
- `error_summary`

Every parser output or ingest batch should link to:

- `case_id`
- `evidence_id` where applicable
- `job_id`
- `job_step_id`
- `parser_run_id`
- `output_uri` or `batch_ref`
- `output_hash`
- `schema_version`
- `target_opensearch_index` or alias
- `indexed_document_count`
- `indexing_status`

Relationships:

- A job can have many steps.
- A parser step can have one or more parser runs.
- A parser run can produce one or more parser outputs or ingest batches.
- An ingest batch can target one or more OpenSearch aliases/indices depending
  on artifact type and host.
- OpenSearch indexing status is recorded in Postgres even though the documents
  live in OpenSearch.

OpenSearch documents should link back to:

- `case_id`
- `evidence_id` where applicable
- `job_id`
- `job_step_id`
- `parser_run_id`
- `parser_name`
- `parser_version`
- `source_hash`
- `indexed_at`
- `schema_version`

This extends the current partial provenance fields described in the OpenSearch
integration plan. Current parser documents already contain useful fields such
as `vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`, host
metadata, and `pipeline_version`, but they do not yet consistently carry the
target control-plane IDs (`03_opensearch_core_integration.md`, section 2).

## 7. Idempotency And Deduplication

Idempotency prevents duplicate work from repeated MCP calls, browser retries,
worker crashes, and stale lease recovery. The target model should use unique or
conflict-aware idempotency keys for operations where duplicate execution would
distort evidence, parser, indexing, or report state.

Strategies:

- Job creation uses a caller-provided or Gateway-derived `idempotency_key`.
- Duplicate job prevention checks active or successful jobs with the same
  `case_id`, `job_type`, and `idempotency_key`.
- Duplicate parser run prevention keys on case, evidence/source, parser,
  parser version, source hash, and relevant spec options.
- Duplicate OpenSearch indexing prevention keys on ingest batch, target alias,
  schema version, source hash, parser run, and reindex policy.
- Evidence hash-based deduplication uses registered evidence hashes and source
  hashes, not paths alone.
- Parser version and schema version are part of idempotency because parser or
  schema changes can intentionally produce new output.
- `force_rerun` creates a new attempt or new job lineage while preserving the
  old records.
- `reindex` can reuse parser outputs when the source/parser output hash is
  unchanged but target index alias or schema version changes.

Example idempotency keys:

- `case_id + evidence_id + parser_name + parser_version + source_hash`
- `case_id + evidence_id + operation_type + source_hash`
- `case_id + report_type + finding_set_version`
- `case_id + index_alias + schema_version + ingest_batch_id`

Operations that should be idempotent:

- Evidence registration for the same immutable source/hash.
- Evidence hashing and integrity verification.
- Parser runs for the same evidence/source/parser/version/spec.
- OpenSearch indexing of the same ingest batch to the same alias/schema.
- Timeline builds from the same indexed source set and schema.
- IOC extraction from the same source set and extractor version.
- Report generation from the same approved finding set and report profile.

Operations that may intentionally create new records:

- Human approval/rejection events.
- Cancellation requests.
- Manual notes and operator annotations.
- Force reruns.
- Maintenance reindex jobs.
- New proposed findings from a changed model/prompt/source set.

## 8. Job Types

Initial target job types:

| Job type | Purpose | Case context | Evidence context | Expected steps | OpenSearch dependency | Approval requirement | Idempotency strategy | Failure behavior |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `evidence_register` | Register evidence metadata and vault reference. | Required. | Source path/hash expected. | Validate scope, register metadata, audit access. | None. | Required for unsafe path/import policies. | Case + evidence/source hash + operation. | Fail without mutating evidence authority; log validation reason. |
| `evidence_hash` | Compute or confirm cryptographic hashes. | Required. | Required. | Resolve evidence, hash, store hash event. | None. | None unless destructive side effects are requested. | Case + evidence + hash algorithm + source hash. | Retry if transient IO; fail on missing source. |
| `evidence_verify_integrity` | Verify manifest/ledger and file integrity. | Required. | Optional single evidence or full case. | Load metadata, stat/hash as needed, write integrity event. | None. | None. | Case + evidence/all + verification policy + manifest hash. | Mark failed/degraded with integrity findings; do not auto-fix. |
| `evidence_ingest` | Prepare evidence for parser workflows. | Required. | Required. | Validate, discover sources, create parser/index jobs or steps. | Optional. | Required when ingest changes final/immutable state. | Case + evidence + operation + source hash. | Retry discovery; preserve partial registered outputs. |
| `parser_run` | Run a parser against evidence/source. | Required. | Usually required. | Resolve source, run parser, register parser_run/output. | Often yes. | None for derived output; approval needed for final findings. | Case + evidence + parser + version + source hash + spec. | Retry by parser/source; preserve failed run records. |
| `opensearch_index` | Index parser output or ingest batch. | Required. | Optional through parser output. | Validate alias, bulk index, register counts/status. | Required. | None. | Case + alias + schema + ingest batch. | Retry transient OpenSearch; mark degraded if OpenSearch down. |
| `timeline_build` | Build derived timeline records. | Required. | Optional source set. | Select sources, normalize, register timeline refs/output. | Usually yes. | Human approval before final timeline promotion. | Case + source set hash + builder version + schema. | Preserve partial output; retry transient query/index errors. |
| `ioc_extract` | Extract IOCs from approved or derived sources. | Required. | Optional. | Select sources, extract, stage proposed IOCs. | Optional. | Human approval before final IOC/finding state. | Case + source set hash + extractor version. | Failed extraction stays proposed/partial only. |
| `finding_generate` | Generate proposed findings. | Required. | Optional source refs. | Read sources, generate draft findings, link evidence. | Optional/likely. | Required; agent findings are never auto-approved. | Case + source set + model/prompt/finding set version. | Fail without final finding mutation; logs summarize. |
| `report_generate` | Generate report metadata/content from case state. | Required. | Optional refs. | Snapshot approved data, render draft/report artifact. | Optional. | Approval if final/exported report is official. | Case + report type + finding set version + profile. | Retry render; preserve draft/error state. |
| `report_export` | Export report to final artifact format. | Required. | Optional refs. | Validate approved report, render/export, hash artifact. | None. | Required for official/final export. | Case + report ID + format + template version. | Fail export only; keep source report record. |
| `case_archive` | Package case metadata, evidence refs, audit, reports. | Required. | Full case. | Approval, snapshot, package, hash, record archive. | Optional. | Required. | Case + archive policy + snapshot version. | Fail safely; never delete case on failure. |
| `maintenance_reindex` | Rebuild OpenSearch derived data. | Required or admin cross-case. | Optional batch/source set. | Select batches, reindex, reconcile status. | Required. | Admin/operator approval. | Case + alias + schema + batch/source set. | Mark degraded/partial; old index remains until cutover approval. |
| `health_check` | Validate worker/parser/OpenSearch/evidence readiness. | Optional case or system. | Optional. | Check capabilities, paths, OpenSearch, DB connectivity. | Optional. | None. | Case/system + check type + worker/profile. | Nonterminal diagnostic failure; no retries unless scheduled. |

## 9. Worker Runtime Assumptions

Target workers are local SIFT VM execution processes first, with room for
multiple local workers and future distributed workers. They are not an external
queue system.

Worker assumptions:

- Workers register in Postgres with `worker_id`, host, process identity,
  version, heartbeat, and capabilities.
- Capabilities describe supported job types, parser names, parser versions,
  OpenSearch access mode, evidence operation support, report support, and local
  tool availability.
- Parser allowlists define which parser modules/tools a worker may run.
- Command allowlists define permitted native commands; workers do not run
  arbitrary shell strings.
- No arbitrary shell execution. Existing shell-free subprocess discipline from
  `run_command` should be preserved (`04_execution_current_state.md`,
  section 1).
- Workers run in a constrained environment with explicit case/evidence paths,
  limited inherited environment, and no authority to invent case scope.
- Subprocesses have timeouts, output caps, process-group management, and
  stdout/stderr capture.
- Workers heartbeat running jobs and stop work if lease ownership is lost.
- Graceful shutdown stops claiming new jobs, requests cooperative cancellation
  or safe pause for running subprocesses, writes final heartbeat/logs, and exits.
- Cancellation signal handling should attempt cooperative termination first,
  then bounded force termination when policy allows.
- Worker crash behavior is handled by lease expiry and stale detection.
- Local SIFT VM constraints matter: evidence may live on local filesystems,
  parsers may be CPU/IO heavy, OpenSearch may be local, and a single host may
  run Gateway, Postgres/Supabase Local, OpenSearch, and workers.

Likely future module locations based on current structure, without creating
files now:

- `packages/sift-core/src/sift_core/jobs/` for shared job domain helpers.
- `packages/sift-core/src/sift_core/workers/` for worker runtime logic.
- `packages/sift-core/src/sift_core/parsers/` or adapters around existing
  `opensearch_mcp` parser modules.
- `packages/sift-gateway/src/sift_gateway/` additions for job creation policy
  and service-path authorization.
- `packages/opensearch-mcp/src/opensearch_mcp/` adapters during migration,
  because current parser and ingest code already lives there.

## 10. Security And Audit Requirements

- Jobs must be case-scoped.
- Workers must not choose arbitrary case scope.
- MCP tokens must have required job/tool scope for creation, status reads, and
  cancellation requests.
- Frontend must not directly mutate job state. It calls Gateway-controlled
  service paths or RLS-safe read paths according to future contracts.
- Service-role writes must be limited to Gateway and worker service paths.
- Every job lifecycle transition creates audit and at least one structured log.
- Evidence access must be auditable, including source resolution, hash reads,
  integrity verification, and parser input access.
- OpenSearch indexing must be auditable, including target alias/index,
  document counts, schema version, parser run, source hash, and failure counts.
- Approval-gated jobs enter `waiting_human`.
- Agent-generated findings remain proposed/pending and are not auto-approved.
- Destructive, final, export, archive, and approval-promoting actions require
  human approval.
- Per-backend execution paths must not bypass aggregate Gateway policy or
  evidence gates in the target model.

## 11. Failure And Degraded-Mode Behavior

| Scenario | Job status | Log/audit behavior | Operator-facing behavior | MCP-facing behavior | Retry/recovery behavior |
| --- | --- | --- | --- | --- | --- |
| Worker offline before claim | Remains `queued`. | Optional health log; no job claim audit. | Queue grows; health shows no capable worker. | Job ID remains queued with no progress. | Starts when worker returns; no duplicate needed. |
| Worker crash mid-job | `running` becomes `stale`, then `retrying`, `queued`, or `failed`. | Audit stale detection with worker/heartbeat. Logs note last known step. | Shows interrupted worker and recovery decision. | Status reports stale/retrying; agents should not resubmit. | Lease expiry drives recovery; idempotency checks protect partial work. |
| OpenSearch down | `opensearch_index` or dependent job becomes `retrying`, `failed`, or degraded step state. | Log OpenSearch health error; audit indexing failure/degraded state. | Search/indexing degraded, Postgres job state still visible. | MCP status reports degraded OpenSearch and retryability. | Retry transient errors; preserve parser outputs for later indexing. |
| Evidence path unavailable | Usually `failed` or `retrying` if transient mount issue. | Audit attempted evidence access and failure summary. | Operator sees missing/unavailable evidence. | Status returns safe failure without raw path leakage beyond policy. | Retry only if source may return; do not substitute paths. |
| Parser failure | `retrying` or `failed`; parser_run failed. | Log stderr summary and parser error; audit parser failure. | Parser step failed with source/parser/version. | Status exposes failure summary and retryability. | Retry per parser/source when safe; preserve failed run. |
| Postgres connection lost | Worker cannot claim/update; running job may later become `stale`. | Local emergency logs only until DB returns; audit resumes after reconnect if ownership valid. | Control plane may show stale after lease expiry. | Status reads may fail or show stale. | Worker stops or pauses subprocess if it cannot heartbeat; stale recovery handles ambiguity. |
| Gateway restart | Existing jobs remain in Postgres. | No job loss; audit only for interrupted request if applicable. | UI/API returns after Gateway restarts. | Agents can poll same job IDs. | No worker impact unless Gateway hosts worker process. |
| Frontend disconnected | Job continues. | No special audit. | On reconnect, UI reads Postgres status/logs. | No MCP impact. | None. |
| Stale job | `stale` then recovery status. | Audit stale detection and decision. | Clear stale/recovered/final state. | Polling returns stale/retrying/failed. | Requeue only when idempotency and side-effect policy allow. |
| Cancelled job with running subprocess | `running` with cancellation requested, then `cancelled` or `failed` if termination fails. | Audit request, signal, termination result, partial outputs. | Shows cancellation in progress and final stopped state. | Agents see cancellation requested/final; no silent abandon. | Cooperative stop first; bounded force kill if allowed. |
| Duplicate job request | Existing `pending`/`queued`/`running`/`succeeded` job returned or new force-rerun created. | Audit duplicate request or force rerun. | Operator sees existing job rather than duplicate work. | Tool returns existing job ID and status unless force allowed. | Idempotency key prevents duplicate execution. |

## 12. Decisions And Open Questions

### Confirmed Decisions

- No Redis/RQ.
- Postgres/Supabase is the authority for durable jobs.
- Workers claim jobs from Postgres.
- Long-running MCP tools enqueue jobs and return job IDs.
- OpenSearch indexing status is recorded in Postgres.
- OpenSearch remains a derived searchable data plane, not job/workflow
  authority.
- Evidence vault behavior is preserved.
- Current manifest/ledger artifacts remain important proof/export artifacts
  while operational authority moves to Postgres.
- Agent-generated findings are not auto-approved.
- Retry preserves previous attempts, steps, logs, parser runs, and indexing
  records.
- Cancellation is explicit and audited.

### Decisions Needing User Approval

- Whether the first implementation slice covers only OpenSearch ingest or also
  native `run_command`, report generation, and evidence operations.
- Whether short native commands remain synchronous or all native execution
  becomes job-backed.
- The exact local worker topology: one local worker, multiple local workers, or
  Gateway-hosted worker plus independent workers.
- How long to export legacy `~/.sift/ingest-status` and
  `~/.sift/ingest-logs` compatibility files after DB job state exists.
- Cancellation semantics for partially indexed OpenSearch batches.
- Retry granularity: whole job, host, artifact, parser run, or indexing batch.
- Whether per-case logical OpenSearch indexes are approved as the initial
  strategy, as recommended in the OpenSearch integration plan.

### Code Facts Still Needing Confirmation

- Exact current behavior for all parser subprocess trees under cancellation.
- Which external scripts still consume `~/.sift/ingest-status`,
  `~/.sift/ingest-logs`, active-case pointers, or ingest manifests.
- Whether any parser modules generate output files that should be registered
  before indexing.
- Which report/export workflows should become job-backed first.
- Which evidence operations are too expensive to remain synchronous.
- The canonical OpenSearch version/profile for local SIFT VM deployments.

## 13. Next Recommended Run

Create `docs/migration/06_execution_integration_contracts.md`.

Recommended scope for that focused run:

- Gateway REST job APIs.
- Core SIFT MCP job tools.
- Frontend job/status views.
- OpenSearch, evidence, and audit integration contracts.

That run should still avoid database migrations and implementation. It should
define contracts between existing planes only after this job model is accepted.
