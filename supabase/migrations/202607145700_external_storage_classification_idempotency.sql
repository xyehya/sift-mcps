-- P4.23 Gate C: repeated current-generation storage-only classifications are
-- append-only observations, not new custody violations. Object/content causes
-- still require the synthetic persisted marker and their owning recovery lane.

do $$ begin
  if to_regprocedure(
      'app.evidence_record_inventory_classification_v2_pre_storage_repeat_idempotency(uuid,text,text,jsonb)'
    ) is null then
    alter function app.evidence_record_inventory_classification_v2(uuid,text,text,jsonb)
      rename to evidence_record_inventory_classification_v2_pre_storage_repeat_idempotency;
  end if;
end $$;

create function app.evidence_record_inventory_classification_v2(
  p_case_id uuid,p_correlation_id text,p_gate_state text,p_findings jsonb
) returns app.evidence_inventory_observations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare
  v_row app.evidence_inventory_observations;
  v_head app.evidence_chain_heads;
  v_storage app.evidence_storage_authorities;
  v_repeat boolean := false;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  select * into v_head from app.evidence_chain_heads
    where case_id=p_case_id for update;
  select * into v_storage from app.evidence_storage_authorities
    where case_id=p_case_id for update;

  if v_head.case_id is not null
     and v_storage.case_id is not null
     and v_head.seal_status='violated'
     and coalesce(v_head.manifest_version,0)>0
     and coalesce(v_head.active_count,0)>0
     and v_storage.profile='EXTERNALLY_READ_ONLY'
     and v_storage.state='UNAVAILABLE'
     and v_storage.remediation='RECONNECT_AND_VERIFY'
     and v_storage.generation=v_storage.verified_generation
     and p_gate_state='BLOCKED_UNAVAILABLE'
     and p_findings=jsonb_build_array(jsonb_build_object(
       'code','STORAGE_UNAVAILABLE',
       'gate_state','BLOCKED_UNAVAILABLE',
       'recovery','RECONNECT_AND_VERIFY',
       'evidence_object_id',null,
       'observation_id',null,
       'full_verification_required',false))
     and jsonb_typeof(coalesce(v_head.issues,'[]'::jsonb))='array'
     and jsonb_array_length(coalesce(v_head.issues,'[]'::jsonb))=1
     and not exists(select 1 from app.evidence_objects o
       where o.case_id=p_case_id
         and (o.status='violated' or o.seal_status='violated'))
     and not exists(select 1
       from jsonb_array_elements(coalesce(v_head.issues,'[]'::jsonb)) issue
       where issue->>'code'<>'STORAGE_UNAVAILABLE'
         or case
           when coalesce(issue->>'storage_generation','') ~ '^[0-9]+$'
             then (issue->>'storage_generation')::numeric<>v_storage.generation
           else true
         end)
     and (
       select coalesce(jsonb_agg(issue - 'storage_generation' order by
         (issue - 'storage_generation')::text),'[]'::jsonb)
       from jsonb_array_elements(coalesce(v_head.issues,'[]'::jsonb)) issue
     ) is not distinct from (
       select coalesce(jsonb_agg(finding order by finding::text),'[]'::jsonb)
       from jsonb_array_elements(p_findings) finding
     ) then
    v_repeat := true;
  end if;

  if v_repeat then
    if length(coalesce(p_correlation_id,'')) not between 1 and 128 then
      raise exception 'invalid_inventory_classification'
        using errcode='invalid_parameter_value';
    end if;
    insert into app.evidence_inventory_observations(
      case_id,correlation_id,gate_state,findings
    ) values(p_case_id,p_correlation_id,p_gate_state,p_findings)
    on conflict(case_id,correlation_id) do nothing returning * into v_row;
    if not found then
      select * into v_row from app.evidence_inventory_observations
        where case_id=p_case_id and correlation_id=p_correlation_id;
      if v_row.gate_state is distinct from p_gate_state
         or v_row.findings is distinct from p_findings then
        raise exception 'inventory_correlation_reused' using errcode='unique_violation';
      end if;
    end if;
    return v_row;
  end if;

  select * into v_row
  from app.evidence_record_inventory_classification_v2_pre_storage_repeat_idempotency(
    p_case_id,p_correlation_id,p_gate_state,p_findings
  );
  return v_row;
end $$;

revoke execute on function
  app.evidence_record_inventory_classification_v2_pre_storage_repeat_idempotency(
    uuid,text,text,jsonb
  ) from public,anon,authenticated;
revoke execute on function app.evidence_record_inventory_classification_v2(
  uuid,text,text,jsonb
) from public,anon,authenticated;
do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  revoke execute on function
    app.evidence_record_inventory_classification_v2_pre_storage_repeat_idempotency(
      uuid,text,text,jsonb
    ) from service_role;
  grant execute on function app.evidence_record_inventory_classification_v2(
    uuid,text,text,jsonb
  ) to service_role;
end if; end $$;

comment on function app.evidence_record_inventory_classification_v2(
  uuid,text,text,jsonb
) is 'Service-only append-only inventory classification; exact current-generation external storage-only repeats are idempotent while object/content violations retain recovery enforcement.';
