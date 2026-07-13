-- P4.23.1: correlate read-only MCP/durable inventory observations with the
-- general audit request without changing re-auth audit semantics.

create or replace function app.evidence_observe_admission(
  p_case_id uuid,
  p_display_path text,
  p_display_name text default null,
  p_bytes bigint default null,
  p_correlation_id text default null,
  p_actor_user_id uuid default null,
  p_actor_service_identity_id uuid default null
)
returns uuid
language plpgsql
security definer
set search_path = app, public
set row_security = off
as $$
declare
  v_id uuid;
  v_name text;
  v_correlation_id text;
begin
  v_name := coalesce(nullif(btrim(coalesce(p_display_name, '')), ''),
                     regexp_replace(p_display_path, '^.*/', ''));
  v_correlation_id := nullif(btrim(coalesce(p_correlation_id, '')), '');
  if length(coalesce(v_correlation_id, '')) > 128 then
    raise exception 'correlation_id_too_long' using errcode = 'invalid_parameter_value';
  end if;

  insert into app.evidence_objects (
    case_id, display_name, display_path, status, seal_status,
    current_bytes, detected_by_user_id, detected_at
  ) values (
    p_case_id, v_name, p_display_path, 'detected', 'unsealed',
    p_bytes, p_actor_user_id, now()
  )
  on conflict (case_id, display_path) do nothing
  returning id into v_id;

  if v_id is null then
    select id into v_id from app.evidence_objects
      where case_id = p_case_id and display_path = p_display_path;
    return v_id;
  end if;

  perform app.evidence_append_custody_event(
    p_case_id, v_id, 'EVIDENCE_DETECTED', null, null, null,
    p_actor_user_id, p_actor_service_identity_id,
    jsonb_strip_nulls(jsonb_build_object(
      'display_path', p_display_path,
      'correlation_id', v_correlation_id
    ))
  );
  perform app.evidence_recompute_seal_status(p_case_id);
  return v_id;
end;
$$;

revoke all on function app.evidence_observe_admission(
  uuid, text, text, bigint, text, uuid, uuid
) from public;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant execute on function app.evidence_observe_admission(
      uuid, text, text, bigint, text, uuid, uuid
    ) to service_role;
  end if;
end;
$$;

comment on function app.evidence_observe_admission(
  uuid, text, text, bigint, text, uuid, uuid
) is 'Idempotently records a read-only admission observation and links a new custody event to an opaque audit/job correlation id.';

-- Admission-specific forward path. Keep app.evidence_mark_violation(...) intact
-- for existing operator and verification callers; Gateway/worker admission uses
-- this service-only RPC so the immutable CHAIN_VIOLATION event can be joined to
-- its MCP request or durable job without overloading re-auth audit semantics.
create or replace function app.evidence_mark_admission_violation(
  p_case_id uuid,
  p_evidence_object_id uuid,
  p_reason text,
  p_issues jsonb default '[]'::jsonb,
  p_correlation_id text default null,
  p_actor_user_id uuid default null,
  p_actor_service_identity_id uuid default null
)
returns app.evidence_chain_heads
language plpgsql
security definer
set search_path = app, public
set row_security = off
as $$
declare
  v_head app.evidence_chain_heads;
  v_correlation_id text;
begin
  v_correlation_id := nullif(btrim(coalesce(p_correlation_id, '')), '');
  if length(coalesce(v_correlation_id, '')) > 128 then
    raise exception 'correlation_id_too_long' using errcode = 'invalid_parameter_value';
  end if;

  if p_evidence_object_id is not null then
    update app.evidence_objects
      set status = 'violated', seal_status = 'violated', updated_at = now()
      where id = p_evidence_object_id and case_id = p_case_id;
  end if;

  perform app.evidence_append_custody_event(
    p_case_id, p_evidence_object_id, 'CHAIN_VIOLATION', null, null, null,
    p_actor_user_id, p_actor_service_identity_id,
    jsonb_strip_nulls(jsonb_build_object(
      'reason', p_reason,
      'issues', coalesce(p_issues, '[]'::jsonb),
      'correlation_id', v_correlation_id
    ))
  );

  insert into app.evidence_chain_heads (case_id, seal_status, issues)
    values (p_case_id, 'violated', coalesce(p_issues, '[]'::jsonb))
    on conflict (case_id) do update
      set seal_status = 'violated',
          issues = coalesce(p_issues, '[]'::jsonb),
          updated_at = now();

  select * into v_head from app.evidence_chain_heads where case_id = p_case_id;
  return v_head;
end;
$$;

revoke all on function app.evidence_mark_admission_violation(
  uuid, uuid, text, jsonb, text, uuid, uuid
) from public;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant execute on function app.evidence_mark_admission_violation(
      uuid, uuid, text, jsonb, text, uuid, uuid
    ) to service_role;
  end if;
end;
$$;

comment on function app.evidence_mark_admission_violation(
  uuid, uuid, text, jsonb, text, uuid, uuid
) is 'Service-only admission violation transition with a bounded opaque MCP request or durable job correlation id.';
