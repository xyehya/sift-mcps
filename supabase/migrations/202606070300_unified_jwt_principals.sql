-- PR03A / Batch A: additive unified Supabase JWT principal schema.
-- Links agent/service principals to Supabase Auth, adds an operator system role,
-- introduces DB-backed principal tool scopes (B-10), a stable principal resolver
-- view, and the first useful Supabase-JWT read policies. PR02 mcp_tokens remain a
-- compatibility bridge, not the target credential authority. Gateway/portal
-- runtime wiring, agent/service JWT issuance, active-case DB authority, evidence
-- DB authority, jobs/workers, OpenSearch, RAG, and legacy-auth removal are out of
-- scope and intentionally deferred. This migration is additive and rollback-safe
-- inside a transaction.

-- 5.1 Principal auth links: link agent/service principals to Supabase Auth users.
alter table app.agents
  add column if not exists auth_user_id uuid null references auth.users(id) on delete set null;

alter table app.service_identities
  add column if not exists auth_user_id uuid null references auth.users(id) on delete set null;

create unique index if not exists agents_auth_user_id_key
  on app.agents (auth_user_id)
  where auth_user_id is not null;

create unique index if not exists service_identities_auth_user_id_key
  on app.service_identities (auth_user_id)
  where auth_user_id is not null;

-- 5.2 Operator system role: cross-case/bootstrap/admin policy only. Case
-- membership roles still live in app.case_members.role.
alter table app.operator_profiles
  add column if not exists system_role text not null default 'operator';

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'operator_profiles_system_role_check'
  ) then
    alter table app.operator_profiles
      add constraint operator_profiles_system_role_check
      check (system_role in ('readonly', 'operator', 'lead', 'owner', 'admin'));
  end if;
end
$$;

-- 5.3 Principal tool scopes: DB-backed list/call authorization grammar (B-10).
-- Scope grammar enforced by the Gateway: 'mcp:*', 'tool:<exact_tool_name>',
-- 'namespace:<prefix>'.
create table if not exists app.principal_tool_scopes (
  id uuid primary key default gen_random_uuid(),
  operator_profile_id uuid null references app.operator_profiles(id) on delete cascade,
  agent_id uuid null references app.agents(id) on delete cascade,
  service_identity_id uuid null references app.service_identities(id) on delete cascade,
  case_id uuid null references app.cases(id) on delete cascade,
  scope text not null,
  status text not null default 'active',
  constraints jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint principal_tool_scopes_principal_check
    check (
      (case when operator_profile_id is null then 0 else 1 end) +
      (case when agent_id is null then 0 else 1 end) +
      (case when service_identity_id is null then 0 else 1 end) = 1
    ),
  constraint principal_tool_scopes_status_check
    check (status in ('active', 'disabled', 'revoked'))
);

create index if not exists principal_tool_scopes_operator_profile_id_idx
  on app.principal_tool_scopes (operator_profile_id);
create index if not exists principal_tool_scopes_agent_id_idx
  on app.principal_tool_scopes (agent_id);
create index if not exists principal_tool_scopes_service_identity_id_idx
  on app.principal_tool_scopes (service_identity_id);
create index if not exists principal_tool_scopes_case_id_idx
  on app.principal_tool_scopes (case_id);

-- One active scope per (principal, scope, case_id). Two partial unique indexes
-- mirror the PR01 mcp_token_scopes null/non-null case_id pattern; uniqueness is
-- scoped to active rows so disabled/revoked history does not block re-grant.
create unique index if not exists principal_tool_scopes_active_case_key
  on app.principal_tool_scopes (
    coalesce(operator_profile_id, agent_id, service_identity_id), scope, case_id
  )
  where status = 'active' and case_id is not null;
create unique index if not exists principal_tool_scopes_active_global_key
  on app.principal_tool_scopes (
    coalesce(operator_profile_id, agent_id, service_identity_id), scope
  )
  where status = 'active' and case_id is null;

-- 5.4 Principal resolver view: stable union for the shared identity resolver.
-- Columns absent on a given source table are NULL-filled (see migration notes:
-- agents/service_identities have no email; service_identities have no
-- display_name or default_case_id).
-- security_invoker = true so the view honors the querying role's RLS instead of
-- defaulting to the (RLS-bypassing) view-owner's rights, once direct browser
-- grants ever land (D12).
create or replace view app.principal_identities with (security_invoker = true) as
  select
    'operator'::text as principal_type,
    op.id as principal_id,
    op.auth_user_id as auth_user_id,
    op.display_name as display_name,
    op.email as email,
    op.status as status,
    op.system_role as principal_role,
    op.default_case_id as default_case_id
  from app.operator_profiles op
  union all
  select
    'agent'::text as principal_type,
    ag.id as principal_id,
    ag.auth_user_id as auth_user_id,
    ag.display_name as display_name,
    null::text as email,
    ag.status as status,
    ag.agent_type as principal_role,
    ag.default_case_id as default_case_id
  from app.agents ag
  union all
  select
    'service'::text as principal_type,
    si.id as principal_id,
    si.auth_user_id as auth_user_id,
    null::text as display_name,
    null::text as email,
    si.status as status,
    si.service_type as principal_role,
    null::uuid as default_case_id
  from app.service_identities si;

-- mcp_tokens compatibility-bridge marker (PR02 hash-token bridge, not target).
comment on table app.mcp_tokens is
  'PR02 hash-only MCP/service token registry. Compatibility bridge only, not the '
  'target credential authority; Supabase-issued JWTs are the unified target '
  'credential. Raw token material is never stored.';

comment on table app.principal_tool_scopes is
  'DB-backed per-principal MCP tool authorization (B-10). Scope grammar: mcp:*, '
  'tool:<exact_tool_name>, namespace:<prefix>. Gateway enforces list filtering '
  'and call rejection; this table is the authority.';
comment on view app.principal_identities is
  'Stable resolver view unioning operator/agent/service principals for the shared '
  'Supabase identity resolver. Not a substitute for table-specific policy checks.';

-- 5.5 RLS: enable on the new table; add minimal Supabase-JWT read policies.
-- Privileged writes remain Gateway/service-role mediated (D12); no broad direct
-- write access is granted to any principal here.
--
-- Forward-looking: PR03 issues NO `grant select ... to authenticated` on the app
-- schema, so all of these read policies (and PR01's) are currently inert. The
-- Gateway resolver reads via a superuser DSN and bypasses RLS by design, and the
-- portal browser reads go through the Gateway, not the DB directly. These policies
-- become active when a later phase grants narrow direct browser SELECT under D12.
-- Do not add grants in PR03.
alter table app.principal_tool_scopes enable row level security;

-- Operator may read its own operator_profiles row.
do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'operator_profiles'
      and policyname = 'operator_profiles_self_select'
  ) then
    create policy operator_profiles_self_select
      on app.operator_profiles
      for select
      using (auth.uid() = auth_user_id);
  end if;
end
$$;

-- Operator may read cases where it has an active case_members row.
do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'cases'
      and policyname = 'cases_member_select'
  ) then
    create policy cases_member_select
      on app.cases
      for select
      using (
        exists (
          select 1
          from app.case_members cm
          join app.operator_profiles op on op.id = cm.operator_profile_id
          where cm.case_id = app.cases.id
            and cm.status = 'active'
            and op.auth_user_id = auth.uid()
        )
      );
  end if;
end
$$;

-- Operator may read its own active case_members rows.
do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'case_members'
      and policyname = 'case_members_self_select'
  ) then
    create policy case_members_self_select
      on app.case_members
      for select
      using (
        status = 'active'
        and exists (
          select 1
          from app.operator_profiles op
          where op.id = app.case_members.operator_profile_id
            and op.auth_user_id = auth.uid()
        )
      );
  end if;
end
$$;

-- Owner may read its own agents. Without this, the owner branch of
-- principal_tool_scopes_owner_or_lead_select below is a dead subquery: PR01
-- enabled RLS on app.agents with no SELECT policy, so under a non-superuser role
-- the agents lookup returns zero rows and silently denies an operator read of
-- scopes for agents it owns.
do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'agents'
      and policyname = 'agents_owner_select'
  ) then
    create policy agents_owner_select
      on app.agents
      for select
      using (
        exists (
          select 1
          from app.operator_profiles op
          where op.id = app.agents.owner_user_id
            and op.auth_user_id = auth.uid()
        )
      );
  end if;
end
$$;

-- Note: no app.service_identities SELECT policy is added here. PR01's
-- service_identities table has no owner column, so the owner branch below does
-- not reference it; service-identity tool scopes are reachable instead through
-- the case lead/owner membership branch (principal_tool_scopes.case_id). A direct
-- service-identity read policy is deferred to a later scoped phase if needed.

-- Operator may read active principal_tool_scopes rows for principals it owns or
-- for cases where it has lead/owner membership.
do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'principal_tool_scopes'
      and policyname = 'principal_tool_scopes_owner_or_lead_select'
  ) then
    create policy principal_tool_scopes_owner_or_lead_select
      on app.principal_tool_scopes
      for select
      using (
        status = 'active'
        and (
          exists (
            select 1
            from app.operator_profiles op
            where op.id = app.principal_tool_scopes.operator_profile_id
              and op.auth_user_id = auth.uid()
          )
          or exists (
            select 1
            from app.agents ag
            join app.operator_profiles op on op.id = ag.owner_user_id
            where ag.id = app.principal_tool_scopes.agent_id
              and op.auth_user_id = auth.uid()
          )
          or exists (
            select 1
            from app.case_members cm
            join app.operator_profiles op on op.id = cm.operator_profile_id
            where cm.case_id = app.principal_tool_scopes.case_id
              and cm.status = 'active'
              and cm.role in ('lead', 'owner')
              and op.auth_user_id = auth.uid()
          )
        )
      );
  end if;
end
$$;
