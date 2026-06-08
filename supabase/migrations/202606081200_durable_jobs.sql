-- BATCH-D1: durable Postgres job state machine + local worker claim loop.
--
-- Long-running ingest/enrich/report/run-command work becomes a durable job in
-- Postgres instead of an in-process task. Workers claim jobs with a lease
-- (FOR UPDATE SKIP LOCKED), heartbeat the lease, and write typed status, steps,
-- and sanitized logs back to Postgres. Portal/agent callers poll job status by
-- job_id only; they never read worker files or local paths.
--
-- This migration is additive, idempotent, and rollback-safe inside a
-- transaction. It introduces no queue dependency (no Redis/RQ/Celery/Temporal);
-- claim/lease semantics are pure Postgres row locking. It stores no raw evidence
-- bytes and no secret material. job specs/results carry opaque IDs only
-- (case_id, evidence_id, provenance IDs); absolute OS paths must never be
-- persisted in agent-visible columns (spec_public/result_public/job_logs).

create schema if not exists app;
create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- 1. Tables
-- ---------------------------------------------------------------------------

-- 1.1 jobs: one row per unit of durable work.
--
-- Typed status enum (text + CHECK, matching the established migration style):
--   queued     -> waiting for a worker to claim
--   claimed    -> leased by a worker, not yet running
--   running    -> worker actively executing
--   succeeded  -> terminal success
--   failed     -> terminal failure (may be re-queued by retry)
--   cancelled  -> terminal, operator/system cancellation
--   expired    -> lease expired without heartbeat (re-queued or terminal)
--
-- spec_public/result_public are the agent-visible (sanitized) JSON payloads.
-- spec_internal is worker-only and may hold resolution hints; it is never
-- returned to the agent. The worker resolves case_id/evidence_id to local
-- paths internally; paths are not stored here.
create table if not exists app.jobs (
  id uuid primary key default gen_random_uuid(),
  job_type text not null,
  status text not null default 'queued',
  case_id uuid null references app.cases(id) on delete set null,
  evidence_id uuid null,
  priority int not null default 100,
  -- Sanitized, agent/portal-pollable spec and result. Opaque IDs only.
  spec_public jsonb not null default '{}'::jsonb,
  result_public jsonb null,
  -- Worker-only payload. Never returned to agents. Still must not hold secrets.
  spec_internal jsonb not null default '{}'::jsonb,
  -- Lease + worker tracking.
  worker_id text null,
  lease_expires_at timestamptz null,
  -- Retry accounting.
  attempts int not null default 0,
  max_attempts int not null default 3,
  -- Sanitized failure summary surfaced to portal/agent.
  error_summary text null,
  -- Provenance + audit linkage (opaque IDs).
  provenance_id uuid null,
  enqueue_audit_event_id uuid null references app.audit_events(id) on delete set null,
  -- Actor that enqueued the job (mirror of audit actor model).
  requested_by_type text null,
  requested_by_user_id uuid null references app.operator_profiles(id) on delete set null,
  requested_by_agent_id uuid null references app.agents(id) on delete set null,
  requested_by_service_identity_id uuid null references app.service_identities(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  started_at timestamptz null,
  finished_at timestamptz null,
  constraint jobs_job_type_check
    check (job_type in ('ingest', 'enrich', 'report', 'run_command')),
  constraint jobs_status_check
    check (status in ('queued', 'claimed', 'running', 'succeeded', 'failed', 'cancelled', 'expired')),
  constraint jobs_priority_check
    check (priority >= 0),
  constraint jobs_max_attempts_check
    check (max_attempts >= 1),
  constraint jobs_attempts_check
    check (attempts >= 0),
  constraint jobs_spec_public_object_check
    check (jsonb_typeof(spec_public) = 'object'),
  constraint jobs_spec_internal_object_check
    check (jsonb_typeof(spec_internal) = 'object'),
  constraint jobs_requested_by_type_check
    check (requested_by_type is null or requested_by_type in ('user', 'agent', 'service', 'system')),
  -- A claimed/running job must carry a worker + lease; a queued job must not.
  constraint jobs_lease_consistency_check
    check (
      (status in ('claimed', 'running') and worker_id is not null and lease_expires_at is not null)
      or (status not in ('claimed', 'running'))
    )
);

-- Claim ordering / poll indexes.
create index if not exists jobs_status_priority_idx
  on app.jobs (status, priority, created_at)
  where status = 'queued';
create index if not exists jobs_lease_expires_at_idx
  on app.jobs (lease_expires_at)
  where status in ('claimed', 'running');
create index if not exists jobs_case_id_idx on app.jobs (case_id);
create index if not exists jobs_worker_id_idx on app.jobs (worker_id);
create index if not exists jobs_job_type_idx on app.jobs (job_type);
create index if not exists jobs_updated_at_idx on app.jobs (updated_at);

-- 1.2 job_steps: ordered sub-steps within a job (parser stage, enrich pass...).
create table if not exists app.job_steps (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references app.jobs(id) on delete cascade,
  step_index int not null,
  name text not null,
  status text not null default 'pending',
  detail jsonb not null default '{}'::jsonb,
  started_at timestamptz null,
  finished_at timestamptz null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint job_steps_status_check
    check (status in ('pending', 'running', 'succeeded', 'failed', 'skipped')),
  constraint job_steps_detail_object_check
    check (jsonb_typeof(detail) = 'object')
);

create unique index if not exists job_steps_job_step_idx
  on app.job_steps (job_id, step_index);
create index if not exists job_steps_job_id_idx on app.job_steps (job_id);

-- 1.3 job_logs: append-only sanitized log lines for portal/agent polling.
-- Logs are agent-visible; callers must write only sanitized text here. Absolute
-- paths/secrets must be redacted before insert (Gateway/worker responsibility).
create table if not exists app.job_logs (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references app.jobs(id) on delete cascade,
  step_id uuid null references app.job_steps(id) on delete set null,
  level text not null default 'info',
  message text not null,
  created_at timestamptz not null default now(),
  constraint job_logs_level_check
    check (level in ('debug', 'info', 'warning', 'error'))
);

create index if not exists job_logs_job_created_idx
  on app.job_logs (job_id, created_at);

-- 1.4 worker_heartbeats: liveness registry for local workers.
create table if not exists app.worker_heartbeats (
  worker_id text primary key,
  status text not null default 'idle',
  current_job_id uuid null references app.jobs(id) on delete set null,
  detail jsonb not null default '{}'::jsonb,
  first_seen_at timestamptz not null default now(),
  last_heartbeat_at timestamptz not null default now(),
  constraint worker_heartbeats_status_check
    check (status in ('idle', 'busy', 'draining', 'stopped')),
  constraint worker_heartbeats_detail_object_check
    check (jsonb_typeof(detail) = 'object')
);

create index if not exists worker_heartbeats_last_heartbeat_idx
  on app.worker_heartbeats (last_heartbeat_at);

-- ---------------------------------------------------------------------------
-- 2. RPCs (service-only transition functions)
-- ---------------------------------------------------------------------------
-- These run with the caller's privileges (no SECURITY DEFINER); the Gateway
-- worker connects with a service DSN. Browser/agent never call these directly;
-- they go through the Gateway enqueue/status adapter.

-- 2.1 enqueue_job: create a queued job and return its id.
create or replace function app.enqueue_job(
  p_job_type text,
  p_case_id uuid,
  p_evidence_id uuid default null,
  p_spec_public jsonb default '{}'::jsonb,
  p_spec_internal jsonb default '{}'::jsonb,
  p_priority int default 100,
  p_max_attempts int default 3,
  p_requested_by_type text default null,
  p_requested_by_user_id uuid default null,
  p_requested_by_agent_id uuid default null,
  p_requested_by_service_identity_id uuid default null,
  p_enqueue_audit_event_id uuid default null
)
returns uuid
language plpgsql
as $$
declare
  v_job_id uuid;
begin
  insert into app.jobs (
    job_type, status, case_id, evidence_id,
    spec_public, spec_internal, priority, max_attempts,
    requested_by_type, requested_by_user_id, requested_by_agent_id,
    requested_by_service_identity_id, enqueue_audit_event_id
  )
  values (
    p_job_type, 'queued', p_case_id, p_evidence_id,
    coalesce(p_spec_public, '{}'::jsonb), coalesce(p_spec_internal, '{}'::jsonb),
    coalesce(p_priority, 100), coalesce(p_max_attempts, 3),
    p_requested_by_type, p_requested_by_user_id, p_requested_by_agent_id,
    p_requested_by_service_identity_id, p_enqueue_audit_event_id
  )
  returning id into v_job_id;
  return v_job_id;
end;
$$;

-- 2.2 claim_next_job: atomically lease the next eligible queued job.
--
-- Concurrency contract: FOR UPDATE SKIP LOCKED guarantees two concurrent
-- workers cannot select and claim the same row. The losing worker skips the
-- locked row and either claims the next queued job or returns no row. The claim
-- and the status/worker/lease write happen in one statement, so there is no
-- read-then-write race window.
create or replace function app.claim_next_job(
  p_worker_id text,
  p_lease_seconds int default 300,
  p_job_types text[] default null
)
returns app.jobs
language plpgsql
as $$
declare
  v_job app.jobs;
begin
  select j.* into v_job
  from app.jobs j
  where j.status = 'queued'
    and (p_job_types is null or j.job_type = any(p_job_types))
  order by j.priority asc, j.created_at asc
  for update skip locked
  limit 1;

  if not found then
    return null;
  end if;

  update app.jobs
  set status = 'claimed',
      worker_id = p_worker_id,
      lease_expires_at = now() + make_interval(secs => greatest(1, coalesce(p_lease_seconds, 300))),
      attempts = attempts + 1,
      updated_at = now()
  where id = v_job.id
  returning * into v_job;

  return v_job;
end;
$$;

-- 2.3 start_job: claimed -> running.
create or replace function app.start_job(
  p_job_id uuid,
  p_worker_id text,
  p_lease_seconds int default 300
)
returns boolean
language plpgsql
as $$
declare
  v_updated int;
begin
  update app.jobs
  set status = 'running',
      started_at = coalesce(started_at, now()),
      lease_expires_at = now() + make_interval(secs => greatest(1, coalesce(p_lease_seconds, 300))),
      updated_at = now()
  where id = p_job_id
    and worker_id = p_worker_id
    and status in ('claimed', 'running');
  get diagnostics v_updated = row_count;
  return v_updated > 0;
end;
$$;

-- 2.4 heartbeat_job: extend the lease while a worker is still processing.
-- Only the owning worker may extend, and only for non-terminal jobs.
create or replace function app.heartbeat_job(
  p_job_id uuid,
  p_worker_id text,
  p_lease_seconds int default 300
)
returns boolean
language plpgsql
as $$
declare
  v_updated int;
begin
  update app.jobs
  set lease_expires_at = now() + make_interval(secs => greatest(1, coalesce(p_lease_seconds, 300))),
      updated_at = now()
  where id = p_job_id
    and worker_id = p_worker_id
    and status in ('claimed', 'running');
  get diagnostics v_updated = row_count;
  return v_updated > 0;
end;
$$;

-- 2.5 complete_job: running/claimed -> succeeded. Clears the lease.
create or replace function app.complete_job(
  p_job_id uuid,
  p_worker_id text,
  p_result_public jsonb default '{}'::jsonb,
  p_provenance_id uuid default null
)
returns boolean
language plpgsql
as $$
declare
  v_updated int;
begin
  update app.jobs
  set status = 'succeeded',
      result_public = coalesce(p_result_public, '{}'::jsonb),
      provenance_id = coalesce(p_provenance_id, provenance_id),
      worker_id = null,
      lease_expires_at = null,
      error_summary = null,
      finished_at = now(),
      updated_at = now()
  where id = p_job_id
    and worker_id = p_worker_id
    and status in ('claimed', 'running');
  get diagnostics v_updated = row_count;
  return v_updated > 0;
end;
$$;

-- 2.6 fail_job: failure with retry/backoff.
--
-- If attempts < max_attempts the job is re-queued (status 'queued', lease
-- cleared) so another worker can retry. Otherwise it becomes terminal 'failed'.
-- error_summary is the sanitized failure message surfaced to portal/agent;
-- callers must not pass raw paths/secrets.
create or replace function app.fail_job(
  p_job_id uuid,
  p_worker_id text,
  p_error_summary text default null,
  p_force_terminal boolean default false
)
returns text
language plpgsql
as $$
declare
  v_job app.jobs;
  v_next_status text;
begin
  select * into v_job
  from app.jobs
  where id = p_job_id
    and worker_id = p_worker_id
    and status in ('claimed', 'running')
  for update;

  if not found then
    return null;
  end if;

  if p_force_terminal or v_job.attempts >= v_job.max_attempts then
    v_next_status := 'failed';
    update app.jobs
    set status = 'failed',
        worker_id = null,
        lease_expires_at = null,
        error_summary = p_error_summary,
        finished_at = now(),
        updated_at = now()
    where id = p_job_id;
  else
    v_next_status := 'queued';
    update app.jobs
    set status = 'queued',
        worker_id = null,
        lease_expires_at = null,
        error_summary = p_error_summary,
        updated_at = now()
    where id = p_job_id;
  end if;

  return v_next_status;
end;
$$;

-- 2.7 cancel_job: operator/system cancellation of a non-terminal job.
create or replace function app.cancel_job(
  p_job_id uuid,
  p_reason text default null
)
returns boolean
language plpgsql
as $$
declare
  v_updated int;
begin
  update app.jobs
  set status = 'cancelled',
      worker_id = null,
      lease_expires_at = null,
      error_summary = coalesce(p_reason, error_summary),
      finished_at = now(),
      updated_at = now()
  where id = p_job_id
    and status in ('queued', 'claimed', 'running');
  get diagnostics v_updated = row_count;
  return v_updated > 0;
end;
$$;

-- 2.8 expire_stale_jobs: reclaim leases whose worker stopped heartbeating.
--
-- A claimed/running job past its lease is re-queued for retry if attempts
-- remain, else marked 'expired' (terminal). Returns the number of jobs touched.
-- A reaper/worker calls this periodically; it needs no per-row worker identity.
create or replace function app.expire_stale_jobs()
returns int
language plpgsql
as $$
declare
  v_count int;
begin
  with stale as (
    select id
    from app.jobs
    where status in ('claimed', 'running')
      and lease_expires_at is not null
      and lease_expires_at < now()
    for update skip locked
  ), updated as (
    update app.jobs j
    set status = case when j.attempts >= j.max_attempts then 'expired' else 'queued' end,
        worker_id = null,
        lease_expires_at = null,
        error_summary = case
          when j.attempts >= j.max_attempts then coalesce(j.error_summary, 'lease expired: max attempts reached')
          else j.error_summary
        end,
        finished_at = case when j.attempts >= j.max_attempts then now() else j.finished_at end,
        updated_at = now()
    from stale
    where j.id = stale.id
    returning j.id
  )
  select count(*)::int into v_count from updated;
  return v_count;
end;
$$;

-- 2.9 record_job_step: upsert a step row by (job_id, step_index).
create or replace function app.record_job_step(
  p_job_id uuid,
  p_step_index int,
  p_name text,
  p_status text default 'pending',
  p_detail jsonb default '{}'::jsonb
)
returns uuid
language plpgsql
as $$
declare
  v_step_id uuid;
begin
  insert into app.job_steps (job_id, step_index, name, status, detail,
                             started_at, finished_at)
  values (
    p_job_id, p_step_index, p_name, p_status, coalesce(p_detail, '{}'::jsonb),
    case when p_status = 'running' then now() else null end,
    case when p_status in ('succeeded', 'failed', 'skipped') then now() else null end
  )
  on conflict (job_id, step_index) do update
    set name = excluded.name,
        status = excluded.status,
        detail = excluded.detail,
        started_at = coalesce(app.job_steps.started_at,
                              case when excluded.status = 'running' then now() else null end),
        finished_at = case
          when excluded.status in ('succeeded', 'failed', 'skipped') then now()
          else app.job_steps.finished_at
        end,
        updated_at = now()
  returning id into v_step_id;
  return v_step_id;
end;
$$;

-- 2.10 append_job_log: append a sanitized log line.
create or replace function app.append_job_log(
  p_job_id uuid,
  p_message text,
  p_level text default 'info',
  p_step_id uuid default null
)
returns uuid
language plpgsql
as $$
declare
  v_log_id uuid;
begin
  insert into app.job_logs (job_id, step_id, level, message)
  values (p_job_id, p_step_id, coalesce(p_level, 'info'), p_message)
  returning id into v_log_id;
  return v_log_id;
end;
$$;

-- 2.11 worker_heartbeat: upsert worker liveness.
create or replace function app.worker_heartbeat(
  p_worker_id text,
  p_status text default 'idle',
  p_current_job_id uuid default null,
  p_detail jsonb default '{}'::jsonb
)
returns void
language plpgsql
as $$
begin
  insert into app.worker_heartbeats (worker_id, status, current_job_id, detail,
                                     last_heartbeat_at)
  values (p_worker_id, coalesce(p_status, 'idle'), p_current_job_id,
          coalesce(p_detail, '{}'::jsonb), now())
  on conflict (worker_id) do update
    set status = excluded.status,
        current_job_id = excluded.current_job_id,
        detail = excluded.detail,
        last_heartbeat_at = now();
end;
$$;

-- ---------------------------------------------------------------------------
-- 3. Sanitized status read model
-- ---------------------------------------------------------------------------
-- Portal/agent poll this view (or the equivalent Gateway adapter) by job_id.
-- It exposes typed status, sanitized spec/result, and progress counts. It does
-- NOT expose spec_internal, worker_id, lease internals, or any local path.
create or replace view app.job_status_public as
select
  j.id as job_id,
  j.job_type,
  j.status,
  j.case_id,
  j.evidence_id,
  j.priority,
  j.attempts,
  j.max_attempts,
  j.spec_public,
  j.result_public,
  j.error_summary,
  j.provenance_id,
  j.created_at,
  j.started_at,
  j.finished_at,
  j.updated_at,
  (select count(*) from app.job_steps s where s.job_id = j.id) as step_count,
  (select count(*) from app.job_steps s where s.job_id = j.id and s.status = 'succeeded') as steps_succeeded
from app.jobs j;

-- ---------------------------------------------------------------------------
-- 4. RLS
-- ---------------------------------------------------------------------------
-- Forward-looking only, mirroring the PR03/D22A pattern: enable RLS, add a
-- case-member read policy. No broad direct GRANT is added; the Gateway worker
-- reads/writes via a service DSN and the portal reads through the Gateway.
alter table app.jobs enable row level security;
alter table app.job_steps enable row level security;
alter table app.job_logs enable row level security;
alter table app.worker_heartbeats enable row level security;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'jobs'
      and policyname = 'jobs_case_member_select'
  ) then
    create policy jobs_case_member_select
      on app.jobs
      for select
      using (
        case_id is null
        or exists (
          select 1
          from app.case_members cm
          join app.operator_profiles op on op.id = cm.operator_profile_id
          where cm.case_id = app.jobs.case_id
            and cm.status = 'active'
            and op.auth_user_id = auth.uid()
        )
      );
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'job_logs'
      and policyname = 'job_logs_case_member_select'
  ) then
    create policy job_logs_case_member_select
      on app.job_logs
      for select
      using (
        exists (
          select 1
          from app.jobs j
          left join app.case_members cm on cm.case_id = j.case_id and cm.status = 'active'
          left join app.operator_profiles op on op.id = cm.operator_profile_id
          where j.id = app.job_logs.job_id
            and (j.case_id is null or op.auth_user_id = auth.uid())
        )
      );
  end if;
end
$$;

-- ---------------------------------------------------------------------------
-- 5. Comments (single source of fact for the schema contract)
-- ---------------------------------------------------------------------------
comment on table app.jobs is
  'BATCH-D1 durable job state machine. One row per ingest/enrich/report/'
  'run_command unit. Claimed via FOR UPDATE SKIP LOCKED with a lease; no '
  'external queue. spec_public/result_public are agent-visible (opaque IDs '
  'only, no OS paths/secrets); spec_internal is worker-only.';
comment on column app.jobs.spec_internal is
  'Worker-only job payload. Never returned to agents. Must not hold secrets.';
comment on column app.jobs.lease_expires_at is
  'Lease deadline. A claimed/running job past this without a heartbeat is '
  'reclaimed by app.expire_stale_jobs (re-queued or marked expired).';
comment on function app.claim_next_job(text, int, text[]) is
  'Atomically lease the next queued job using FOR UPDATE SKIP LOCKED so two '
  'concurrent workers cannot claim the same job. Returns null when none.';
comment on function app.fail_job(uuid, text, text, boolean) is
  'Record failure: re-queue for retry while attempts < max_attempts, else mark '
  'terminal failed. error_summary must be sanitized (no paths/secrets).';
comment on function app.expire_stale_jobs() is
  'Reclaim leases whose worker stopped heartbeating: re-queue if attempts '
  'remain, else mark expired. Returns count of jobs touched.';
comment on view app.job_status_public is
  'Sanitized job status read model for portal/agent polling by job_id. Excludes '
  'spec_internal, worker_id, and lease internals.';
