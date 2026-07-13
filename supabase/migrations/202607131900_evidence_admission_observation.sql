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
