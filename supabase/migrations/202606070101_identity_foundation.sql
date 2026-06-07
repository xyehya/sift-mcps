-- PR01: additive control-plane identity foundation schema.
-- Runtime auth, Gateway token validation, portal wiring, active-case propagation,
-- jobs, evidence behavior, OpenSearch, and frontend changes are intentionally
-- deferred to later migration phases.

create schema if not exists app;
create extension if not exists pgcrypto;

create table if not exists app.operator_profiles (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid null references auth.users(id) on delete set null,
  display_name text not null,
  email text null,
  status text not null default 'active',
  default_case_id uuid null,
  legacy_examiner_id text null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint operator_profiles_status_check
    check (status in ('active', 'disabled', 'invited', 'archived'))
);

create table if not exists app.cases (
  id uuid primary key default gen_random_uuid(),
  case_key text not null,
  legacy_case_id text null,
  title text not null,
  description text null,
  status text not null default 'draft',
  created_by_user_id uuid null references app.operator_profiles(id) on delete set null,
  opened_at timestamptz null,
  closed_at timestamptz null,
  legacy_case_dir text null,
  legacy_case_yaml_path text null,
  compat_export_status text not null default 'pending',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint cases_status_check
    check (status in ('draft', 'active', 'paused', 'closed', 'archived')),
  constraint cases_compat_export_status_check
    check (compat_export_status in ('pending', 'exported', 'stale'))
);

alter table app.operator_profiles
  add constraint operator_profiles_default_case_id_fkey
  foreign key (default_case_id) references app.cases(id) on delete set null;

create table if not exists app.case_members (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  operator_profile_id uuid not null references app.operator_profiles(id) on delete cascade,
  role text not null,
  status text not null default 'active',
  added_by_user_id uuid null references app.operator_profiles(id) on delete set null,
  expires_at timestamptz null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint case_members_role_check
    check (role in ('readonly', 'operator', 'lead', 'owner', 'admin')),
  constraint case_members_status_check
    check (status in ('active', 'suspended', 'removed', 'expired'))
);

create table if not exists app.active_case_state (
  id uuid primary key default gen_random_uuid(),
  scope text not null default 'deployment',
  active_case_id uuid null references app.cases(id) on delete set null,
  set_by_user_id uuid null references app.operator_profiles(id) on delete set null,
  set_at timestamptz null,
  compat_export_status text not null default 'pending',
  metadata jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  constraint active_case_state_scope_check
    check (scope in ('deployment')),
  constraint active_case_state_compat_export_status_check
    check (compat_export_status in ('pending', 'exported', 'stale'))
);

create table if not exists app.agents (
  id uuid primary key default gen_random_uuid(),
  display_name text not null,
  agent_type text not null,
  status text not null default 'active',
  owner_user_id uuid null references app.operator_profiles(id) on delete set null,
  default_case_id uuid null references app.cases(id) on delete set null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint agents_status_check
    check (status in ('active', 'disabled', 'revoked', 'archived'))
);

create table if not exists app.service_identities (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  service_type text not null,
  status text not null default 'active',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint service_identities_status_check
    check (status in ('active', 'disabled', 'revoked', 'archived'))
);

create table if not exists app.mcp_tokens (
  id uuid primary key default gen_random_uuid(),
  token_hash text not null,
  token_fingerprint text not null,
  status text not null default 'active',
  agent_id uuid null references app.agents(id) on delete set null,
  service_identity_id uuid null references app.service_identities(id) on delete set null,
  created_by_user_id uuid null references app.operator_profiles(id) on delete set null,
  case_id uuid null references app.cases(id) on delete cascade,
  label text null,
  expires_at timestamptz not null,
  revoked_at timestamptz null,
  revoked_by_user_id uuid null references app.operator_profiles(id) on delete set null,
  last_used_at timestamptz null,
  last_used_audit_event_id uuid null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint mcp_tokens_status_check
    check (status in ('active', 'expired', 'revoked', 'disabled')),
  constraint mcp_tokens_principal_check
    check (
      (case when agent_id is null then 0 else 1 end) +
      (case when service_identity_id is null then 0 else 1 end) <= 1
    )
);

create table if not exists app.audit_events (
  id uuid primary key default gen_random_uuid(),
  case_id uuid null references app.cases(id) on delete set null,
  event_type text not null,
  actor_type text not null,
  actor_user_id uuid null references app.operator_profiles(id) on delete set null,
  actor_agent_id uuid null references app.agents(id) on delete set null,
  actor_token_id uuid null references app.mcp_tokens(id) on delete set null,
  actor_service_identity_id uuid null references app.service_identities(id) on delete set null,
  job_id uuid null,
  request_id text null,
  source text not null,
  status text not null,
  summary text null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint audit_events_actor_type_check
    check (actor_type in ('user', 'agent', 'token', 'service', 'system')),
  constraint audit_events_status_check
    check (status in ('success', 'failure', 'denied', 'warning', 'degraded', 'requested'))
);

alter table app.mcp_tokens
  add constraint mcp_tokens_last_used_audit_event_id_fkey
  foreign key (last_used_audit_event_id) references app.audit_events(id) on delete set null;

create table if not exists app.mcp_token_scopes (
  id uuid primary key default gen_random_uuid(),
  token_id uuid not null references app.mcp_tokens(id) on delete cascade,
  scope text not null,
  case_id uuid null references app.cases(id) on delete cascade,
  constraints jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create unique index if not exists operator_profiles_auth_user_id_key
  on app.operator_profiles (auth_user_id)
  where auth_user_id is not null;
create unique index if not exists operator_profiles_email_lower_key
  on app.operator_profiles (lower(email))
  where email is not null;
create index if not exists operator_profiles_status_idx
  on app.operator_profiles (status);
create index if not exists operator_profiles_default_case_id_idx
  on app.operator_profiles (default_case_id);

create unique index if not exists cases_case_key_key
  on app.cases (case_key);
create index if not exists cases_status_idx
  on app.cases (status);
create index if not exists cases_created_at_idx
  on app.cases (created_at);
create index if not exists cases_created_by_user_id_idx
  on app.cases (created_by_user_id);

create unique index if not exists case_members_active_member_key
  on app.case_members (case_id, operator_profile_id)
  where status = 'active';
create index if not exists case_members_case_status_idx
  on app.case_members (case_id, status);
create index if not exists case_members_operator_status_idx
  on app.case_members (operator_profile_id, status);
create index if not exists case_members_case_role_idx
  on app.case_members (case_id, role);

create unique index if not exists active_case_state_scope_key
  on app.active_case_state (scope);
create index if not exists active_case_state_active_case_id_idx
  on app.active_case_state (active_case_id);

create index if not exists agents_status_idx
  on app.agents (status);
create index if not exists agents_agent_type_idx
  on app.agents (agent_type);
create index if not exists agents_owner_user_id_idx
  on app.agents (owner_user_id);
create index if not exists agents_default_case_id_idx
  on app.agents (default_case_id);

create unique index if not exists service_identities_name_key
  on app.service_identities (name);
create index if not exists service_identities_service_type_idx
  on app.service_identities (service_type);
create index if not exists service_identities_status_idx
  on app.service_identities (status);

create unique index if not exists mcp_tokens_token_hash_key
  on app.mcp_tokens (token_hash);
create unique index if not exists mcp_tokens_token_fingerprint_key
  on app.mcp_tokens (token_fingerprint);
create index if not exists mcp_tokens_case_status_idx
  on app.mcp_tokens (case_id, status);
create index if not exists mcp_tokens_agent_status_idx
  on app.mcp_tokens (agent_id, status);
create index if not exists mcp_tokens_service_identity_status_idx
  on app.mcp_tokens (service_identity_id, status);
create index if not exists mcp_tokens_expires_at_idx
  on app.mcp_tokens (expires_at);
create index if not exists mcp_tokens_last_used_at_idx
  on app.mcp_tokens (last_used_at);

create index if not exists audit_events_case_created_at_idx
  on app.audit_events (case_id, created_at);
create index if not exists audit_events_event_type_created_at_idx
  on app.audit_events (event_type, created_at);
create index if not exists audit_events_actor_user_id_idx
  on app.audit_events (actor_user_id);
create index if not exists audit_events_actor_agent_id_idx
  on app.audit_events (actor_agent_id);
create index if not exists audit_events_actor_token_id_idx
  on app.audit_events (actor_token_id);
create index if not exists audit_events_actor_service_identity_id_idx
  on app.audit_events (actor_service_identity_id);
create index if not exists audit_events_job_id_idx
  on app.audit_events (job_id);
create index if not exists audit_events_request_id_idx
  on app.audit_events (request_id);

create index if not exists mcp_token_scopes_token_scope_idx
  on app.mcp_token_scopes (token_id, scope);
create index if not exists mcp_token_scopes_case_scope_idx
  on app.mcp_token_scopes (case_id, scope);
create unique index if not exists mcp_token_scopes_case_key
  on app.mcp_token_scopes (token_id, scope, case_id)
  where case_id is not null;
create unique index if not exists mcp_token_scopes_global_key
  on app.mcp_token_scopes (token_id, scope)
  where case_id is null;

alter table app.operator_profiles enable row level security;
alter table app.cases enable row level security;
alter table app.case_members enable row level security;
alter table app.active_case_state enable row level security;
alter table app.agents enable row level security;
alter table app.service_identities enable row level security;
alter table app.mcp_tokens enable row level security;
alter table app.audit_events enable row level security;
alter table app.mcp_token_scopes enable row level security;

comment on schema app is
  'SIFT control-plane authority schema. PR01 adds identity foundation tables only.';
comment on table app.operator_profiles is
  'Human operator profiles linked to Supabase Auth; credentials are not stored here.';
comment on table app.cases is
  'Authoritative case lifecycle and legacy compatibility anchor.';
comment on table app.case_members is
  'Human case membership and role authority.';
comment on table app.active_case_state is
  'Authoritative active case state. PR01 creates schema only; runtime propagation is deferred.';
comment on table app.agents is
  'AI agent or automation identities independent from Supabase Auth users.';
comment on table app.service_identities is
  'Non-human service principals for Gateway, workers, and maintenance actors.';
comment on table app.mcp_tokens is
  'Hash-only MCP/service token registry. Raw token material is never stored.';
comment on table app.mcp_token_scopes is
  'Normalized case/tool/action scopes for MCP and service tokens.';
comment on table app.audit_events is
  'Append-oriented audit event foundation for identity, policy, token, and later job/evidence activity.';
