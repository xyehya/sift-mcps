-- BATCH-K4: Postgres-backed host-identity decisions + ingest-status read model.
--
-- Hostname detection/index naming stays a REQUIRED derived parser metadata
-- concern (Migration-Spec OpenSearch/host carve-out): the parser/indexer still
-- detects hostnames for `case-<case_id>-<artifact_type>-<host>` index names and
-- the `host.name`/`host.id` document fields. This migration does NOT change that.
--
-- What it DOES add: in DB-active mode the *decisions* about host identity
-- (preflight discovery auto-mappings + operator/agent host-mapping corrections)
-- are recorded in authoritative Postgres with their source, canonical value,
-- actor/tool, affected index/provenance IDs, and audit-event id. Host identity
-- and ingest status do NOT authorize cases, evidence, approvals, or reports;
-- these rows are a derived/append-only ledger that makes the derived OpenSearch
-- plane traceable and makes the local `host-dictionary.yaml` a parser
-- compatibility / debug artifact only (tampering it cannot change DB authority).
--
-- It stores opaque IDs and sanitized host/index names only. No raw evidence
-- bytes, no OS/mount/case filesystem paths, no OpenSearch credentials. The local
-- SIFT worker calls these RPCs via a service DSN after it has claimed a job /
-- after an operator-authorized correction; the agent/browser never call them
-- directly (they go through the Gateway).
--
-- Additive, idempotent, and rollback-safe within a transaction. Introduces no
-- queue/broker dependency.

create schema if not exists app;
create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- 1. host_identity_decisions: append-only ledger of host-identity decisions.
-- ---------------------------------------------------------------------------
-- One row per applied decision or correction. `raw` is the observed host.name
-- value; `canonical` is the host.id it was mapped to. `decision` records why:
--   discovery auto-mappings (preflight) vs operator/agent corrections.
-- `source` records where the raw value was observed (registry/evtx/csv_peek/...
-- for discovery; 'host_fix' for corrections). Affected derived state is linked
-- by opaque IDs (`provenance_id`, `index_names`) and the correction's audit id.
create table if not exists app.host_identity_decisions (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  -- Observed raw host.name value and the canonical host.id it maps to.
  raw text not null,
  canonical text not null,
  -- Decision class. discovery_* are auto-applied by ingest preflight;
  -- correction is an operator/agent host-mapping fix (opensearch_fix_host_mapping).
  decision text not null,
  -- Where the raw value was observed / which tool drove the decision.
  source text null,
  tool text null,
  confidence double precision null,
  -- Actor that drove the decision (mirror of the audit/job actor model).
  actor_type text null,
  actor_user_id uuid null references app.operator_profiles(id) on delete set null,
  actor_agent_id uuid null references app.agents(id) on delete set null,
  actor_service_identity_id uuid null references app.service_identities(id) on delete set null,
  -- Opaque linkage to the derived plane this decision affected. index_names is
  -- a sanitized, case-scoped derived-name list (never absolute paths).
  job_id uuid null references app.jobs(id) on delete set null,
  provenance_id uuid null,
  index_names text[] not null default '{}'::text[],
  docs_updated bigint null,
  -- Audit-event id for the correction/decision (opaque; from app.audit_events).
  audit_event_id uuid null references app.audit_events(id) on delete set null,
  -- Sanitized extra context (host/index/count shape); no paths, no secrets.
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint host_identity_decisions_raw_check
    check (length(btrim(raw)) > 0 and left(raw, 1) <> '/'),
  constraint host_identity_decisions_canonical_check
    check (length(btrim(canonical)) > 0 and left(canonical, 1) <> '/'),
  constraint host_identity_decisions_decision_check
    check (decision in (
      'discovery_already_mapped',
      'discovery_auto_alias',
      'discovery_auto_new_canonical',
      'correction'
    )),
  constraint host_identity_decisions_actor_type_check
    check (actor_type is null or actor_type in ('user', 'agent', 'service', 'system')),
  constraint host_identity_decisions_docs_updated_check
    check (docs_updated is null or docs_updated >= 0),
  constraint host_identity_decisions_metadata_object_check
    check (jsonb_typeof(metadata) = 'object')
);

create index if not exists host_identity_decisions_case_idx
  on app.host_identity_decisions (case_id, created_at desc);
create index if not exists host_identity_decisions_canonical_idx
  on app.host_identity_decisions (case_id, canonical);
create index if not exists host_identity_decisions_provenance_idx
  on app.host_identity_decisions (provenance_id);
create index if not exists host_identity_decisions_job_idx
  on app.host_identity_decisions (job_id);

-- ---------------------------------------------------------------------------
-- 2. RPCs (service-only; the worker connects with a service DSN)
-- ---------------------------------------------------------------------------
-- No SECURITY DEFINER; run with the caller's privileges (mirrors the D1 job /
-- F1 provenance RPC style). Browser/agent never call these — they go through
-- the Gateway.

-- 2.1 record_host_identity_decision: append a host-identity decision/correction.
create or replace function app.record_host_identity_decision(
  p_case_id uuid,
  p_raw text,
  p_canonical text,
  p_decision text,
  p_source text default null,
  p_tool text default null,
  p_confidence double precision default null,
  p_actor_type text default null,
  p_actor_user_id uuid default null,
  p_actor_agent_id uuid default null,
  p_actor_service_identity_id uuid default null,
  p_job_id uuid default null,
  p_provenance_id uuid default null,
  p_index_names text[] default '{}'::text[],
  p_docs_updated bigint default null,
  p_audit_event_id uuid default null,
  p_metadata jsonb default '{}'::jsonb
)
returns uuid
language plpgsql
as $$
declare
  v_id uuid;
begin
  if p_raw is null or length(btrim(p_raw)) = 0 then
    raise exception 'raw host value is required';
  end if;
  if p_canonical is null or length(btrim(p_canonical)) = 0 then
    raise exception 'canonical host value is required';
  end if;
  insert into app.host_identity_decisions (
    case_id, raw, canonical, decision, source, tool, confidence,
    actor_type, actor_user_id, actor_agent_id, actor_service_identity_id,
    job_id, provenance_id, index_names, docs_updated, audit_event_id, metadata
  )
  values (
    p_case_id, p_raw, p_canonical, p_decision, p_source, p_tool, p_confidence,
    p_actor_type, p_actor_user_id, p_actor_agent_id, p_actor_service_identity_id,
    p_job_id, p_provenance_id, coalesce(p_index_names, '{}'::text[]),
    p_docs_updated, p_audit_event_id, coalesce(p_metadata, '{}'::jsonb)
  )
  returning id into v_id;
  return v_id;
end;
$$;

-- 2.2 opensearch_ingest_status: DB-active ingest/enrich status for a case.
-- The DB-active replacement for the local `~/.sift/ingest-status/*.json` files.
-- Returns the sanitized job state (status, counts, provenance) for the case's
-- ingest + enrich jobs, joined to the F1 provenance receipt. spec_internal,
-- worker_id, and lease internals are NEVER selected. Index names returned are
-- the sanitized case-scoped derived identifiers from app.opensearch_indices.
create or replace function app.opensearch_ingest_status(
  p_case_id uuid,
  p_limit int default 25
)
returns table (
  job_id uuid,
  job_type text,
  status text,
  case_id uuid,
  evidence_id uuid,
  provenance_id uuid,
  attempts int,
  max_attempts int,
  error_summary text,
  result_public jsonb,
  step_count bigint,
  steps_succeeded bigint,
  indexed_count bigint,
  bulk_failed_count bigint,
  created_at timestamptz,
  started_at timestamptz,
  finished_at timestamptz,
  updated_at timestamptz
)
language sql
stable
as $$
  select
    s.job_id,
    s.job_type,
    s.status,
    s.case_id,
    s.evidence_id,
    s.provenance_id,
    s.attempts,
    s.max_attempts,
    s.error_summary,
    s.result_public,
    s.step_count,
    s.steps_succeeded,
    p.indexed_count,
    p.bulk_failed_count,
    s.created_at,
    s.started_at,
    s.finished_at,
    s.updated_at
  from app.job_status_public s
  left join app.opensearch_ingest_provenance p
    on p.provenance_id = s.provenance_id
  where s.case_id = p_case_id
    and s.job_type in ('ingest', 'enrich')
  order by s.created_at desc
  limit greatest(coalesce(p_limit, 25), 1);
$$;

-- ---------------------------------------------------------------------------
-- 3. RLS
-- ---------------------------------------------------------------------------
-- Mirror the F1/D1 pattern: enable RLS, add a case-member read policy. The
-- Gateway worker reads/writes via a service DSN; the portal reads through the
-- Gateway. Host-identity rows are derived, not authority — read access is the
-- same case-membership gate used for the OpenSearch coverage view.
alter table app.host_identity_decisions enable row level security;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'host_identity_decisions'
      and policyname = 'host_identity_decisions_case_member_select'
  ) then
    create policy host_identity_decisions_case_member_select
      on app.host_identity_decisions
      for select
      using (
        exists (
          select 1
          from app.case_members cm
          join app.operator_profiles op on op.id = cm.operator_profile_id
          where cm.case_id = app.host_identity_decisions.case_id
            and cm.status = 'active'
            and op.auth_user_id = auth.uid()
        )
      );
  end if;
end
$$;

-- ---------------------------------------------------------------------------
-- 4. Comments (single source of fact for the schema contract)
-- ---------------------------------------------------------------------------
comment on table app.host_identity_decisions is
  'BATCH-K4 append-only ledger of host-identity decisions: ingest preflight '
  'auto-mappings and operator/agent host-mapping corrections '
  '(opensearch_fix_host_mapping). Host identity is DERIVED indexing metadata, '
  'not case/evidence/report authority. Records source, canonical value, '
  'actor/tool, affected index/provenance IDs, and audit id. Sanitized '
  'host/index names + opaque IDs only; no OS paths or credentials. The local '
  'host-dictionary.yaml is a parser-compatibility/debug artifact in DB-active '
  'mode; tampering it cannot change these authoritative records.';
comment on function app.record_host_identity_decision(
  uuid, text, text, text, text, text, double precision, text, uuid, uuid, uuid,
  uuid, uuid, text[], bigint, uuid, jsonb) is
  'Append a host-identity decision/correction receipt. Service-only; called by '
  'the local worker (preflight) and the host-mapping correction tool after an '
  'operator-authorized fix. Never agent-callable directly.';
comment on function app.opensearch_ingest_status(uuid, int) is
  'DB-active ingest/enrich status read model for a case. Replaces the local '
  'ingest-status JSON files: derives status/counts/provenance from durable '
  'job state (app.job_status_public) joined to the F1 provenance receipt. '
  'Sanitized fields only; spec_internal/worker/lease internals are never '
  'exposed.';
