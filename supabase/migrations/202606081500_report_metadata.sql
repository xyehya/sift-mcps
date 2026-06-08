-- B-MVP-5 binding: DB investigation/report metadata authority.
--
-- The portal and Gateway need a live Postgres authority for findings, timeline
-- events, IOCs, TODOs, and report metadata before BATCH-V1 can honestly run the
-- end-to-end journey. Existing JSON case files remain compatibility/export
-- artifacts during the MVP bridge; these tables are the service-mediated read
-- model and transition target.

create schema if not exists app;
create extension if not exists pgcrypto;

create table if not exists app.investigation_findings (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  item_id text not null,
  status text not null default 'DRAFT',
  content_hash text null,
  payload jsonb not null default '{}'::jsonb,
  created_by text null,
  approved_by text null,
  approved_at timestamptz null,
  rejected_by text null,
  rejected_at timestamptz null,
  source text not null default 'artifact_sync',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint investigation_findings_item_id_check check (length(btrim(item_id)) > 0),
  constraint investigation_findings_payload_object_check check (jsonb_typeof(payload) = 'object')
);

create table if not exists app.investigation_timeline_events (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  item_id text not null,
  status text not null default 'DRAFT',
  content_hash text null,
  payload jsonb not null default '{}'::jsonb,
  created_by text null,
  approved_by text null,
  approved_at timestamptz null,
  rejected_by text null,
  rejected_at timestamptz null,
  source text not null default 'artifact_sync',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint investigation_timeline_item_id_check check (length(btrim(item_id)) > 0),
  constraint investigation_timeline_payload_object_check check (jsonb_typeof(payload) = 'object')
);

create table if not exists app.investigation_iocs (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  item_id text not null,
  status text not null default 'DRAFT',
  value text null,
  ioc_type text null,
  payload jsonb not null default '{}'::jsonb,
  created_by text null,
  approved_by text null,
  approved_at timestamptz null,
  rejected_by text null,
  rejected_at timestamptz null,
  source text not null default 'artifact_sync',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint investigation_iocs_item_id_check check (length(btrim(item_id)) > 0),
  constraint investigation_iocs_payload_object_check check (jsonb_typeof(payload) = 'object')
);

create table if not exists app.investigation_todos (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  todo_id text not null,
  status text not null default 'open',
  priority text not null default 'medium',
  assignee text null,
  payload jsonb not null default '{}'::jsonb,
  created_by text null,
  completed_at timestamptz null,
  source text not null default 'portal',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint investigation_todos_todo_id_check check (length(btrim(todo_id)) > 0),
  constraint investigation_todos_priority_check check (priority in ('low', 'medium', 'high')),
  constraint investigation_todos_status_check check (status in ('open', 'completed')),
  constraint investigation_todos_payload_object_check check (jsonb_typeof(payload) = 'object')
);

create table if not exists app.report_metadata (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  report_id text not null,
  profile text not null,
  examiner text null,
  status text not null default 'generated',
  reauth_audit_event_id uuid null references app.audit_events(id) on delete set null,
  seal_status text null,
  manifest_version integer null,
  manifest_hash text null,
  chain_head_hash text null,
  exported boolean not null default false,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint report_metadata_report_id_check check (length(btrim(report_id)) > 0),
  constraint report_metadata_profile_check check (length(btrim(profile)) > 0),
  constraint report_metadata_status_check check (status in ('generated', 'saved', 'exported')),
  constraint report_metadata_metadata_object_check check (jsonb_typeof(metadata) = 'object')
);

create unique index if not exists investigation_findings_case_item_key
  on app.investigation_findings (case_id, item_id);
create index if not exists investigation_findings_case_status_idx
  on app.investigation_findings (case_id, status);
create index if not exists investigation_findings_updated_at_idx
  on app.investigation_findings (updated_at);

create unique index if not exists investigation_timeline_case_item_key
  on app.investigation_timeline_events (case_id, item_id);
create index if not exists investigation_timeline_case_status_idx
  on app.investigation_timeline_events (case_id, status);
create index if not exists investigation_timeline_updated_at_idx
  on app.investigation_timeline_events (updated_at);

create unique index if not exists investigation_iocs_case_item_key
  on app.investigation_iocs (case_id, item_id);
create index if not exists investigation_iocs_case_status_idx
  on app.investigation_iocs (case_id, status);
create index if not exists investigation_iocs_value_idx
  on app.investigation_iocs (case_id, value);

create unique index if not exists investigation_todos_case_todo_key
  on app.investigation_todos (case_id, todo_id);
create index if not exists investigation_todos_case_status_idx
  on app.investigation_todos (case_id, status);
create index if not exists investigation_todos_updated_at_idx
  on app.investigation_todos (updated_at);

create unique index if not exists report_metadata_case_report_key
  on app.report_metadata (case_id, report_id);
create index if not exists report_metadata_case_created_at_idx
  on app.report_metadata (case_id, created_at desc);
create index if not exists report_metadata_case_exported_idx
  on app.report_metadata (case_id, exported);

alter table app.investigation_findings enable row level security;
alter table app.investigation_timeline_events enable row level security;
alter table app.investigation_iocs enable row level security;
alter table app.investigation_todos enable row level security;
alter table app.report_metadata enable row level security;

do $$
declare
  v_table text;
begin
  foreach v_table in array array[
    'investigation_findings',
    'investigation_timeline_events',
    'investigation_iocs',
    'investigation_todos',
    'report_metadata'
  ]
  loop
    if not exists (
      select 1
      from pg_policies
      where schemaname = 'app' and tablename = v_table
        and policyname = v_table || '_case_member_select'
    ) then
      execute format($f$
        create policy %1$s_case_member_select
          on app.%1$s
          for select
          using (
            exists (
              select 1
              from app.case_members cm
              join app.operator_profiles op on op.id = cm.operator_profile_id
              where cm.case_id = app.%1$s.case_id
                and cm.status = 'active'
                and op.auth_user_id = auth.uid()
            )
          )
      $f$, v_table);
    end if;
  end loop;
end
$$;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant select, insert, update, delete on app.investigation_findings to service_role;
    grant select, insert, update, delete on app.investigation_timeline_events to service_role;
    grant select, insert, update, delete on app.investigation_iocs to service_role;
    grant select, insert, update, delete on app.investigation_todos to service_role;
    grant select, insert, update, delete on app.report_metadata to service_role;
  end if;
end
$$;

comment on table app.investigation_findings is
  'DB authority/read model for proposed, approved, rejected, and superseded findings. JSON case files are bridge/export artifacts only.';
comment on table app.investigation_timeline_events is
  'DB authority/read model for proposed and approved timeline events. JSON case files are bridge/export artifacts only.';
comment on table app.investigation_iocs is
  'DB authority/read model for IOCs derived from approved/proposed findings.';
comment on table app.investigation_todos is
  'DB authority for operator-visible investigation TODOs.';
comment on table app.report_metadata is
  'DB authority for report metadata, approval/export provenance, and custody hash references. Report files are exported artifacts.';
