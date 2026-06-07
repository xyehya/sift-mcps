-- D22A follow-up: defense-in-depth constraints for app.mcp_backends.connection.
-- The Gateway is still the write path, but DB rows now also reject nested raw
-- secret keys, malformed env references, secret-bearing headers, and transport
-- shape drift for future inserts/updates.

create schema if not exists app;

create or replace function app.mcp_backend_env_name_is_valid(value text)
returns boolean
language sql
immutable
as $$
  select coalesce(value ~ '^[A-Za-z_][A-Za-z0-9_]*$', false);
$$;

create or replace function app.jsonb_has_forbidden_key(doc jsonb, forbidden_keys text[])
returns boolean
language sql
immutable
as $$
  with recursive walk(value) as (
    select doc
    union all
    select child.value
    from walk w
    cross join lateral (
      select value
      from jsonb_each(
        case when jsonb_typeof(w.value) = 'object' then w.value else '{}'::jsonb end
      )
      union all
      select value
      from jsonb_array_elements(
        case when jsonb_typeof(w.value) = 'array' then w.value else '[]'::jsonb end
      )
    ) child
  )
  select exists (
    select 1
    from walk w
    cross join lateral jsonb_each(
      case when jsonb_typeof(w.value) = 'object' then w.value else '{}'::jsonb end
    ) entry(key, value)
    where lower(entry.key) = any(forbidden_keys)
  );
$$;

create or replace function app.mcp_backend_env_refs_are_valid(doc jsonb)
returns boolean
language sql
immutable
as $$
  select not (doc ? 'env_refs')
    or (
      jsonb_typeof(doc->'env_refs') = 'object'
      and not exists (
        select 1
        from jsonb_each_text(
          case when jsonb_typeof(doc->'env_refs') = 'object' then doc->'env_refs' else '{}'::jsonb end
        ) entry(key, value)
        where not app.mcp_backend_env_name_is_valid(entry.key)
           or not app.mcp_backend_env_name_is_valid(entry.value)
      )
    );
$$;

create or replace function app.mcp_backend_headers_are_valid(doc jsonb)
returns boolean
language sql
immutable
as $$
  select not (doc ? 'headers')
    or (
      jsonb_typeof(doc->'headers') = 'object'
      and not exists (
        select 1
        from jsonb_each_text(
          case when jsonb_typeof(doc->'headers') = 'object' then doc->'headers' else '{}'::jsonb end
        ) entry(key, value)
        where entry.key ~* '(authorization|cookie|token|secret|password|api[-_]?key)'
      )
    );
$$;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'mcp_backends_connection_no_nested_raw_secret_keys_check'
      and conrelid = 'app.mcp_backends'::regclass
  ) then
    alter table app.mcp_backends
      add constraint mcp_backends_connection_no_nested_raw_secret_keys_check
      check (
        not app.jsonb_has_forbidden_key(
          connection,
          array[
            'bearer_token',
            'authorization',
            'cookie',
            'token',
            'password',
            'secret',
            'api_key',
            'apikey',
            'tls_cert',
            'env'
          ]
        )
      ) not valid;
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'mcp_backends_connection_credential_refs_valid_check'
      and conrelid = 'app.mcp_backends'::regclass
  ) then
    alter table app.mcp_backends
      add constraint mcp_backends_connection_credential_refs_valid_check
      check (
        (not (connection ? 'bearer_token_env') or app.mcp_backend_env_name_is_valid(connection->>'bearer_token_env'))
        and (not (connection ? 'tls_cert_env') or app.mcp_backend_env_name_is_valid(connection->>'tls_cert_env'))
        and app.mcp_backend_env_refs_are_valid(connection)
        and app.mcp_backend_headers_are_valid(connection)
      ) not valid;
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'mcp_backends_connection_transport_shape_check'
      and conrelid = 'app.mcp_backends'::regclass
  ) then
    alter table app.mcp_backends
      add constraint mcp_backends_connection_transport_shape_check
      check (
        (
          transport = 'stdio'
          and connection ? 'command'
          and not (connection ? 'url')
        )
        or
        (
          transport = 'http'
          and connection ? 'url'
          and not (connection ? 'command')
        )
      ) not valid;
  end if;
end
$$;

comment on function app.mcp_backend_env_name_is_valid(text) is
  'D22A mcp_backends guard: validates env-var reference names, not secret values.';
comment on function app.jsonb_has_forbidden_key(jsonb, text[]) is
  'D22A mcp_backends guard: recursively finds forbidden raw-secret keys in JSONB.';
comment on function app.mcp_backend_env_refs_are_valid(jsonb) is
  'D22A mcp_backends guard: validates env_refs target/source env-var names.';
comment on function app.mcp_backend_headers_are_valid(jsonb) is
  'D22A mcp_backends guard: rejects secret-bearing HTTP header names in connection JSON.';
