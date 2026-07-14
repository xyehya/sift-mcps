-- P4.23 Gate C: a verified external source that returns read-only after an
-- availability outage advances to Full Verify instead of being rejected as an
-- unrelated persisted custody violation.  This is deliberately a narrow
-- read-model transition; every other violation delegates to the existing
-- causal-preservation classifier.

do $$ begin
  if to_regprocedure(
      'app.evidence_record_inventory_classification_v2_pre_reconnect_transition(uuid,text,text,jsonb)'
    ) is null then
    alter function app.evidence_record_inventory_classification_v2(uuid,text,text,jsonb)
      rename to evidence_record_inventory_classification_v2_pre_reconnect_transition;
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
  v_transition boolean := false;
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
     and v_storage.state='FULL_VERIFY_REQUIRED'
     and v_storage.remediation='FULL_VERIFY'
     and v_storage.generation=v_storage.verified_generation
     and coalesce(v_storage.source_identity,'') ~ '^[0-9a-f]{64}$'
     and coalesce(v_storage.verified_mount_instance,'') ~ '^[0-9a-f]{64}$'
     and coalesce(v_storage.observed_mount_instance,'') ~ '^[0-9a-f]{64}$'
     and v_storage.read_only is true
     and p_gate_state='BLOCKED_UNAVAILABLE'
     and p_findings=jsonb_build_array(jsonb_build_object(
       'code','STORAGE_FULL_VERIFY_REQUIRED',
       'gate_state','BLOCKED_UNAVAILABLE',
       'recovery','FULL_VERIFY_AND_REPAIR',
       'evidence_object_id',null,
       'observation_id',null,
       'full_verification_required',true))
     and jsonb_typeof(coalesce(v_head.issues,'[]'::jsonb))='array'
     and jsonb_array_length(coalesce(v_head.issues,'[]'::jsonb))=1
     and (select count(*) from app.evidence_objects o
       where o.case_id=p_case_id and o.status='sealed')=v_head.active_count
     and not exists(select 1 from app.evidence_objects o
       where o.case_id=p_case_id
         and (o.status='violated' or o.seal_status='violated'))
     and not exists(select 1 from app.evidence_objects o
       where o.case_id=p_case_id and o.status='sealed'
         and o.seal_status is distinct from 'sealed')
     and not exists(select 1 from app.evidence_objects o
       where o.case_id=p_case_id and o.status in ('detected','registered'))
     and not exists(select 1
       from app.evidence_objects o
       left join app.evidence_versions ev on ev.id=o.current_version_id
       where o.case_id=p_case_id and o.status='sealed'
         and (ev.id is null
           or ev.storage_profile is distinct from 'EXTERNALLY_READ_ONLY'
           or ev.storage_source_identity is distinct from v_storage.source_identity))
     and not exists(select 1 from app.custody_operations op
       where op.case_id=p_case_id and op.phase<>'COMPLETED')
     then
    if not exists(select 1
      from jsonb_array_elements(coalesce(v_head.issues,'[]'::jsonb)) issue
      where issue->>'code'<>'STORAGE_UNAVAILABLE'
        or issue->>'gate_state'<>'BLOCKED_UNAVAILABLE'
        or issue->>'recovery'<>'RECONNECT_AND_VERIFY'
        or issue->'evidence_object_id'<>'null'::jsonb
        or issue->'observation_id'<>'null'::jsonb
        or issue->'full_verification_required'<>'false'::jsonb
        or case
          when coalesce(issue->>'storage_generation','') ~ '^[0-9]+$'
            then (issue->>'storage_generation')::numeric<>v_storage.generation
          else true
        end)
       and (
         select coalesce(jsonb_agg(issue - 'storage_generation' order by
           (issue - 'storage_generation')::text),'[]'::jsonb)
         from jsonb_array_elements(coalesce(v_head.issues,'[]'::jsonb)) issue
       ) is not distinct from jsonb_build_array(jsonb_build_object(
         'code','STORAGE_UNAVAILABLE',
         'gate_state','BLOCKED_UNAVAILABLE',
         'recovery','RECONNECT_AND_VERIFY',
         'evidence_object_id',null,
         'observation_id',null,
         'full_verification_required',false)) then
      v_transition := true;
    elsif not exists(select 1
      from jsonb_array_elements(coalesce(v_head.issues,'[]'::jsonb)) issue
      where issue->>'code'<>'STORAGE_FULL_VERIFY_REQUIRED'
        or issue->>'gate_state'<>'BLOCKED_UNAVAILABLE'
        or issue->>'recovery'<>'FULL_VERIFY_AND_REPAIR'
        or issue->'evidence_object_id'<>'null'::jsonb
        or issue->'observation_id'<>'null'::jsonb
        or issue->'full_verification_required'<>'true'::jsonb
        or case
          when coalesce(issue->>'storage_generation','') ~ '^[0-9]+$'
            then (issue->>'storage_generation')::numeric<>v_storage.generation
          else true
        end)
       and (
         select coalesce(jsonb_agg(issue - 'storage_generation' order by
           (issue - 'storage_generation')::text),'[]'::jsonb)
         from jsonb_array_elements(coalesce(v_head.issues,'[]'::jsonb)) issue
       ) is not distinct from p_findings then
      v_repeat := true;
    end if;
  end if;

  if v_transition or v_repeat then
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
    if v_transition then
      update app.evidence_chain_heads
      set issues=jsonb_build_array(
            p_findings->0 || jsonb_build_object('storage_generation',v_storage.generation)
          ),
          seal_status='violated',
          updated_at=now()
      where case_id=p_case_id;
    end if;
    return v_row;
  end if;

  select * into v_row
  from app.evidence_record_inventory_classification_v2_pre_reconnect_transition(
    p_case_id,p_correlation_id,p_gate_state,p_findings
  );
  return v_row;
end $$;

revoke execute on function
  app.evidence_record_inventory_classification_v2_pre_reconnect_transition(
    uuid,text,text,jsonb
  ) from public,anon,authenticated;
revoke execute on function app.evidence_record_inventory_classification_v2(
  uuid,text,text,jsonb
) from public,anon,authenticated;
do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  revoke execute on function
    app.evidence_record_inventory_classification_v2_pre_reconnect_transition(
      uuid,text,text,jsonb
    ) from service_role;
  grant execute on function app.evidence_record_inventory_classification_v2(
    uuid,text,text,jsonb
  ) to service_role;
end if; end $$;

comment on function app.evidence_record_inventory_classification_v2(
  uuid,text,text,jsonb
) is 'Service-only append-only inventory classification; exact same-generation read-only external reconnect advances to Full Verify while every other persisted violation retains its recovery lane.';
