-- D22A / Batch H: additive MCP add-on backend control-plane registry.
-- Backend registration authority moves from gateway.yaml into Postgres. This
-- migration stores no usable backend secret material; connection JSON may carry
-- only non-secret metadata plus credential references resolved by the Gateway.

create schema if not exists app;
create extension if not exists pgcrypto;

create table if not exists app.mcp_backends (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  namespace text not null,
  transport text not null,
  tier text null,
  enabled boolean not null default true,
  connection jsonb not null default '{}'::jsonb,
  data_plane jsonb null,
  default_case_scoped boolean null,
  manifest jsonb not null,
  manifest_source text null,
  manifest_sha256 text not null,
  health_status text not null default 'unknown',
  health_detail text null,
  health_checked_at timestamptz null,
  registered_by uuid null references app.operator_profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint mcp_backends_name_check
    check (
      name ~ '^[a-z0-9][a-z0-9-]*$'
      and name not in ('forensic-mcp', 'case-mcp', 'sift-mcp', 'report-mcp', 'sift-core')
    ),
  constraint mcp_backends_namespace_check
    check (length(btrim(namespace)) > 0),
  constraint mcp_backends_transport_check
    check (transport in ('stdio', 'http')),
  constraint mcp_backends_health_status_check
    check (health_status in ('ok', 'error', 'gated', 'disabled', 'invalid_manifest', 'stopped', 'unknown')),
  constraint mcp_backends_connection_object_check
    check (jsonb_typeof(connection) = 'object'),
  constraint mcp_backends_no_raw_secret_keys_check
    check (
      not (
        connection ?| array[
          'bearer_token',
          'tls_cert',
          'env',
          'headers',
          'password',
          'secret',
          'api_key',
          'token',
          'raw_token',
          'plaintext_token'
        ]
      )
    )
);

create unique index if not exists mcp_backends_name_key
  on app.mcp_backends (name);
create index if not exists mcp_backends_enabled_idx
  on app.mcp_backends (enabled);
create index if not exists mcp_backends_transport_idx
  on app.mcp_backends (transport);
create index if not exists mcp_backends_namespace_idx
  on app.mcp_backends (namespace);
create index if not exists mcp_backends_health_status_idx
  on app.mcp_backends (health_status);
create index if not exists mcp_backends_registered_by_idx
  on app.mcp_backends (registered_by);
create index if not exists mcp_backends_updated_at_idx
  on app.mcp_backends (updated_at);

alter table app.mcp_backends enable row level security;

-- Forward-looking read policy only. The browser still reads through the Gateway
-- in D22A, and no broad direct GRANT is added here.
do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'mcp_backends'
      and policyname = 'mcp_backends_operator_select'
  ) then
    create policy mcp_backends_operator_select
      on app.mcp_backends
      for select
      using (
        exists (
          select 1
          from app.operator_profiles op
          where op.auth_user_id = auth.uid()
            and op.status = 'active'
        )
      );
  end if;
end
$$;

comment on table app.mcp_backends is
  'Authoritative add-on MCP backend registry. Holds cached manifests and '
  'non-secret connection metadata only; usable backend secrets resolve from '
  'Gateway-side credential references per D33.';
comment on column app.mcp_backends.connection is
  'Non-secret connection metadata. D22A permits env-backed credential references '
  'such as bearer_token_env, tls_cert_env, and env_refs; raw secret fields are '
  'rejected by schema and Gateway validation.';
comment on column app.mcp_backends.health_status is
  'Last known health summary for the portal. No separate health event table in D22A v1.';
