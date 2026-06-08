-- BATCH-F1: OpenSearch index + ingest provenance registry.
--
-- OpenSearch is a DERIVED, REBUILDABLE plane (Migration-Spec architecture
-- invariants): it never authorizes cases or evidence. This migration records,
-- in authoritative Postgres, which OpenSearch indices a case/evidence/ingest-job
-- produced and the provenance ID stamped onto those documents, so the derived
-- plane stays traceable back to authoritative state and can be rebuilt/audited.
--
-- It stores opaque IDs and sanitized index names only. No raw evidence bytes,
-- no OS/mount/case filesystem paths, no OpenSearch credentials. The local SIFT
-- worker calls these RPCs via a service DSN after it has claimed an ingest job;
-- the agent/browser never call them directly (they go through the Gateway).
--
-- Additive, idempotent, and rollback-safe within a transaction. Introduces no
-- queue/broker dependency. Index names follow the case-scoped convention
-- `case-<case_id>-<artifact_type>-<host>` produced by the parser/ingestor stack.

create schema if not exists app;
create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- 1. opensearch_indices: one row per case-scoped index the ingest stack writes.
-- ---------------------------------------------------------------------------
-- The index name is the sanitized, case-scoped derived identifier. doc_count is
-- a derived snapshot at registration time (OpenSearch remains the live source);
-- it exists for portal/agent coverage views and rebuild planning, not authority.
create table if not exists app.opensearch_indices (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  -- Sanitized, case-scoped OpenSearch index name (no OS paths).
  index_name text not null,
  artifact_type text null,
  hostname text null,
  -- Opaque provenance + evidence linkage (no paths, no secrets).
  evidence_id uuid null,
  provenance_id uuid null,
  -- Last ingest job that wrote to this index.
  last_job_id uuid null references app.jobs(id) on delete set null,
  doc_count bigint not null default 0,
  pipeline_version text null,
  status text not null default 'active',
  first_indexed_at timestamptz not null default now(),
  last_indexed_at timestamptz not null default now(),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint opensearch_indices_status_check
    check (status in ('active', 'stale', 'rebuilding', 'deleted')),
  constraint opensearch_indices_index_name_check
    check (
      length(btrim(index_name)) > 0
      -- case-scoped derived name; never an absolute path.
      and left(index_name, 1) <> '/'
      and index_name = lower(index_name)
    ),
  constraint opensearch_indices_doc_count_check
    check (doc_count >= 0),
  constraint opensearch_indices_metadata_object_check
    check (jsonb_typeof(metadata) = 'object')
);

-- One row per (case, index) — re-ingest upserts the same row.
create unique index if not exists opensearch_indices_case_index_idx
  on app.opensearch_indices (case_id, index_name);
create index if not exists opensearch_indices_case_id_idx
  on app.opensearch_indices (case_id);
create index if not exists opensearch_indices_provenance_idx
  on app.opensearch_indices (provenance_id);
create index if not exists opensearch_indices_evidence_idx
  on app.opensearch_indices (evidence_id);
create index if not exists opensearch_indices_last_job_idx
  on app.opensearch_indices (last_job_id);

-- ---------------------------------------------------------------------------
-- 2. opensearch_ingest_provenance: append-only provenance receipts per run.
-- ---------------------------------------------------------------------------
-- One row per ingest job execution. provenance_id matches the `vhir.provenance_id`
-- stamped onto the indexed documents, so a finding/report can resolve any
-- indexed doc back to the job, case, evidence, and ingest receipt.
create table if not exists app.opensearch_ingest_provenance (
  id uuid primary key default gen_random_uuid(),
  provenance_id uuid not null,
  case_id uuid not null references app.cases(id) on delete cascade,
  evidence_id uuid null,
  job_id uuid null references app.jobs(id) on delete set null,
  pipeline_version text null,
  indexed_count bigint not null default 0,
  bulk_failed_count bigint not null default 0,
  -- Sanitized summary (host/index/count shape); no paths, no secrets.
  summary jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint opensearch_ingest_provenance_indexed_check
    check (indexed_count >= 0),
  constraint opensearch_ingest_provenance_bulk_failed_check
    check (bulk_failed_count >= 0),
  constraint opensearch_ingest_provenance_summary_object_check
    check (jsonb_typeof(summary) = 'object')
);

create unique index if not exists opensearch_ingest_provenance_pid_idx
  on app.opensearch_ingest_provenance (provenance_id);
create index if not exists opensearch_ingest_provenance_case_idx
  on app.opensearch_ingest_provenance (case_id);
create index if not exists opensearch_ingest_provenance_job_idx
  on app.opensearch_ingest_provenance (job_id);

-- ---------------------------------------------------------------------------
-- 3. RPCs (service-only; the worker connects with a service DSN)
-- ---------------------------------------------------------------------------
-- No SECURITY DEFINER; run with the caller's privileges (mirrors the D1 job
-- RPC style). Browser/agent never call these — they go through the Gateway.

-- 3.1 register_opensearch_index: upsert a case-scoped index registration.
create or replace function app.register_opensearch_index(
  p_case_id uuid,
  p_index_name text,
  p_artifact_type text default null,
  p_hostname text default null,
  p_evidence_id uuid default null,
  p_provenance_id uuid default null,
  p_job_id uuid default null,
  p_doc_count bigint default 0,
  p_pipeline_version text default null
)
returns uuid
language plpgsql
as $$
declare
  v_id uuid;
begin
  if p_index_name is null or length(btrim(p_index_name)) = 0 then
    raise exception 'index_name is required';
  end if;
  insert into app.opensearch_indices (
    case_id, index_name, artifact_type, hostname, evidence_id,
    provenance_id, last_job_id, doc_count, pipeline_version,
    last_indexed_at, updated_at
  )
  values (
    p_case_id, p_index_name, p_artifact_type, p_hostname, p_evidence_id,
    p_provenance_id, p_job_id, greatest(coalesce(p_doc_count, 0), 0),
    p_pipeline_version, now(), now()
  )
  on conflict (case_id, index_name) do update
    set artifact_type = coalesce(excluded.artifact_type, app.opensearch_indices.artifact_type),
        hostname = coalesce(excluded.hostname, app.opensearch_indices.hostname),
        evidence_id = coalesce(excluded.evidence_id, app.opensearch_indices.evidence_id),
        provenance_id = coalesce(excluded.provenance_id, app.opensearch_indices.provenance_id),
        last_job_id = coalesce(excluded.last_job_id, app.opensearch_indices.last_job_id),
        doc_count = greatest(excluded.doc_count, 0),
        pipeline_version = coalesce(excluded.pipeline_version, app.opensearch_indices.pipeline_version),
        status = 'active',
        last_indexed_at = now(),
        updated_at = now()
  returning id into v_id;
  return v_id;
end;
$$;

-- 3.2 record_opensearch_ingest_provenance: append a provenance receipt for a run.
create or replace function app.record_opensearch_ingest_provenance(
  p_provenance_id uuid,
  p_case_id uuid,
  p_evidence_id uuid default null,
  p_job_id uuid default null,
  p_pipeline_version text default null,
  p_indexed_count bigint default 0,
  p_bulk_failed_count bigint default 0,
  p_summary jsonb default '{}'::jsonb
)
returns uuid
language plpgsql
as $$
declare
  v_id uuid;
begin
  if p_provenance_id is null then
    raise exception 'provenance_id is required';
  end if;
  insert into app.opensearch_ingest_provenance (
    provenance_id, case_id, evidence_id, job_id, pipeline_version,
    indexed_count, bulk_failed_count, summary
  )
  values (
    p_provenance_id, p_case_id, p_evidence_id, p_job_id, p_pipeline_version,
    greatest(coalesce(p_indexed_count, 0), 0),
    greatest(coalesce(p_bulk_failed_count, 0), 0),
    coalesce(p_summary, '{}'::jsonb)
  )
  on conflict (provenance_id) do update
    set indexed_count = greatest(excluded.indexed_count, 0),
        bulk_failed_count = greatest(excluded.bulk_failed_count, 0),
        summary = coalesce(excluded.summary, app.opensearch_ingest_provenance.summary),
        pipeline_version = coalesce(excluded.pipeline_version, app.opensearch_ingest_provenance.pipeline_version)
  returning id into v_id;
  return v_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- 4. Sanitized read model + RLS
-- ---------------------------------------------------------------------------
-- Portal/agent read this case-scoped coverage view (or the Gateway adapter).
-- It exposes derived index coverage only; no paths, no credentials.
create or replace view app.opensearch_index_coverage as
select
  i.case_id,
  i.index_name,
  i.artifact_type,
  i.hostname,
  i.evidence_id,
  i.provenance_id,
  i.doc_count,
  i.status,
  i.first_indexed_at,
  i.last_indexed_at
from app.opensearch_indices i;

alter table app.opensearch_indices enable row level security;
alter table app.opensearch_ingest_provenance enable row level security;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'opensearch_indices'
      and policyname = 'opensearch_indices_case_member_select'
  ) then
    create policy opensearch_indices_case_member_select
      on app.opensearch_indices
      for select
      using (
        exists (
          select 1
          from app.case_members cm
          join app.operator_profiles op on op.id = cm.operator_profile_id
          where cm.case_id = app.opensearch_indices.case_id
            and cm.status = 'active'
            and op.auth_user_id = auth.uid()
        )
      );
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'opensearch_ingest_provenance'
      and policyname = 'opensearch_ingest_provenance_case_member_select'
  ) then
    create policy opensearch_ingest_provenance_case_member_select
      on app.opensearch_ingest_provenance
      for select
      using (
        exists (
          select 1
          from app.case_members cm
          join app.operator_profiles op on op.id = cm.operator_profile_id
          where cm.case_id = app.opensearch_ingest_provenance.case_id
            and cm.status = 'active'
            and op.auth_user_id = auth.uid()
        )
      );
  end if;
end
$$;

-- ---------------------------------------------------------------------------
-- 5. Comments (single source of fact for the schema contract)
-- ---------------------------------------------------------------------------
comment on table app.opensearch_indices is
  'BATCH-F1 registry of case-scoped OpenSearch indices written by the ingest '
  'stack. OpenSearch is a derived/rebuildable plane; these rows make the derived '
  'plane traceable to authoritative Postgres state. Opaque IDs + sanitized '
  'index names only; no OS paths or credentials.';
comment on table app.opensearch_ingest_provenance is
  'BATCH-F1 append-only ingest provenance receipts. provenance_id matches the '
  'vhir.provenance_id stamped onto indexed documents, linking any indexed doc '
  'back to its case/evidence/job.';
comment on function app.register_opensearch_index(uuid, text, text, text, uuid, uuid, uuid, bigint, text) is
  'Upsert a case-scoped OpenSearch index registration (one row per case+index). '
  'Service-only; called by the local worker after an ingest job indexes docs.';
comment on view app.opensearch_index_coverage is
  'Sanitized case-scoped index coverage read model for portal/agent polling.';
