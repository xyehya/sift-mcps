-- P4.23 Gate C: an already-latched external read-write posture drift must be
-- repeatable across Portal/admission reconciliation, and restoring that exact
-- source/mount read-only advances only to Full Verify.  This wrapper changes
-- the chain-head read model; every non-storage or non-causal issue delegates
-- to the existing causal-preservation classifier.

do $$ begin
  if to_regprocedure(
      'app.evidence_record_inventory_classification_v2_pre_rw_transition(uuid,text,text,jsonb)'
    ) is null then
    alter function app.evidence_record_inventory_classification_v2(uuid,text,text,jsonb)
      rename to evidence_record_inventory_classification_v2_pre_rw_transition;
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
  v_finding jsonb;
  v_prior_issues jsonb;
  v_safe_active_set boolean := false;
  v_rw_repeat boolean := false;
  v_ro_transition boolean := false;
  v_ro_repeat boolean := false;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  select * into v_head from app.evidence_chain_heads
    where case_id=p_case_id for update;
  select * into v_storage from app.evidence_storage_authorities
    where case_id=p_case_id for update;

  v_finding := case
    when jsonb_typeof(p_findings)='array' and jsonb_array_length(p_findings)=1
      then p_findings->0
    else null
  end;
  v_prior_issues := case
    when jsonb_typeof(coalesce(v_head.issues,'[]'::jsonb))='array'
      then coalesce(v_head.issues,'[]'::jsonb)
    else '[]'::jsonb
  end;

  v_safe_active_set :=
    v_head.case_id is not null
    and v_storage.case_id is not null
    and v_head.seal_status='violated'
    and coalesce(v_head.manifest_version,0)>0
    and coalesce(v_head.active_count,0)>0
    and v_storage.profile='EXTERNALLY_READ_ONLY'
    and v_storage.generation=v_storage.verified_generation
    and coalesce(v_storage.source_identity,'') ~ '^[0-9a-f]{64}$'
    and coalesce(v_storage.verified_mount_instance,'') ~ '^[0-9a-f]{64}$'
    and coalesce(v_storage.observed_mount_instance,'') ~ '^[0-9a-f]{64}$'
    and v_storage.observed_mount_instance=v_storage.verified_mount_instance
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
          or ev.storage_source_identity is distinct from v_storage.source_identity
          or ev.storage_mount_instance is distinct from v_storage.verified_mount_instance))
    and not exists(select 1 from app.custody_operations op
      where op.case_id=p_case_id and op.phase<>'COMPLETED');

  if v_safe_active_set
     and v_storage.state='READ_WRITE_DRIFT'
     and v_storage.remediation='RESTORE_READ_ONLY'
     and v_storage.read_only is false
     and p_gate_state='BLOCKED_VIOLATION'
     and jsonb_typeof(p_findings)='array'
     and jsonb_array_length(p_findings)=v_head.active_count
     and not exists(select 1 from jsonb_array_elements(p_findings) f
       where jsonb_typeof(f)<>'object'
         or f<>jsonb_build_object(
           'code','POSTURE_DRIFT',
           'gate_state','BLOCKED_VIOLATION',
           'recovery','RESTORE_READ_ONLY',
           'evidence_object_id',f->'evidence_object_id',
           'observation_id',f->'observation_id',
           'full_verification_required',true)
         or jsonb_typeof(f->'evidence_object_id')<>'string'
         or coalesce(f->>'evidence_object_id','') !~
           '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
         or jsonb_typeof(f->'observation_id')<>'string'
         or coalesce(f->>'observation_id','') !~
           '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
         or not exists(select 1 from app.evidence_objects o
           where o.case_id=p_case_id and o.id::text=lower(f->>'evidence_object_id')
             and o.status='sealed' and o.seal_status='sealed'))
     and (select count(distinct f->>'evidence_object_id')
       from jsonb_array_elements(p_findings) f)=v_head.active_count
     and not exists(select 1 from app.evidence_objects o
       where o.case_id=p_case_id and o.status='sealed'
         and not exists(select 1 from jsonb_array_elements(p_findings) f
           where lower(f->>'evidence_object_id')=o.id::text))
     and jsonb_array_length(v_prior_issues)=v_head.active_count
     and not exists(select 1 from jsonb_array_elements(v_prior_issues) issue
       where issue->'storage_generation' is distinct from
         to_jsonb(v_storage.generation))
     and (select jsonb_agg(issue-'storage_generation'
            order by (issue-'storage_generation')::text)
          from jsonb_array_elements(v_prior_issues) issue)
       is not distinct from
         (select jsonb_agg(f order by f::text)
          from jsonb_array_elements(p_findings) f)
     then
    v_rw_repeat := true;
  end if;

  if v_safe_active_set
     and v_storage.state='FULL_VERIFY_REQUIRED'
     and v_storage.remediation='FULL_VERIFY'
     and v_storage.read_only is true
     and p_gate_state='BLOCKED_UNAVAILABLE'
     and v_finding=jsonb_build_object(
       'code','STORAGE_FULL_VERIFY_REQUIRED',
       'gate_state','BLOCKED_UNAVAILABLE',
       'recovery','FULL_VERIFY_AND_REPAIR',
       'evidence_object_id',null,
       'observation_id',null,
       'full_verification_required',true) then
    if jsonb_array_length(v_prior_issues)=v_head.active_count
       and not exists(select 1 from jsonb_array_elements(v_prior_issues) issue
         where jsonb_typeof(issue)<>'object'
           or issue<>jsonb_build_object(
             'code','POSTURE_DRIFT',
             'gate_state','BLOCKED_VIOLATION',
             'recovery','RESTORE_READ_ONLY',
             'evidence_object_id',issue->'evidence_object_id',
             'observation_id',issue->'observation_id',
             'full_verification_required',true,
             'storage_generation',v_storage.generation)
           or jsonb_typeof(issue->'evidence_object_id')<>'string'
           or coalesce(issue->>'evidence_object_id','') !~
             '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
           or jsonb_typeof(issue->'observation_id')<>'string'
           or coalesce(issue->>'observation_id','') !~
             '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
           or not exists(select 1 from app.evidence_objects o
             where o.case_id=p_case_id
               and o.id::text=lower(issue->>'evidence_object_id')
               and o.status='sealed' and o.seal_status='sealed'))
       and (select count(distinct issue->>'evidence_object_id')
         from jsonb_array_elements(v_prior_issues) issue)=v_head.active_count
       and not exists(select 1 from app.evidence_objects o
         where o.case_id=p_case_id and o.status='sealed'
           and not exists(select 1 from jsonb_array_elements(v_prior_issues) issue
             where lower(issue->>'evidence_object_id')=o.id::text)) then
      v_ro_transition := true;
    elsif v_prior_issues=jsonb_build_array(
      v_finding||jsonb_build_object(
        'storage_generation',v_storage.generation)) then
      v_ro_repeat := true;
    end if;
  end if;

  if v_rw_repeat or v_ro_transition or v_ro_repeat then
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
    if v_ro_transition then
      update app.evidence_chain_heads
      set issues=jsonb_build_array(
            v_finding||jsonb_build_object(
              'storage_generation',v_storage.generation)
          ),
          seal_status='violated',
          updated_at=now()
      where case_id=p_case_id;
    end if;
    return v_row;
  end if;

  select * into v_row
  from app.evidence_record_inventory_classification_v2_pre_rw_transition(
    p_case_id,p_correlation_id,p_gate_state,p_findings
  );
  return v_row;
end $$;

revoke execute on function
  app.evidence_record_inventory_classification_v2_pre_rw_transition(
    uuid,text,text,jsonb
  ) from public,anon,authenticated;
revoke execute on function app.evidence_record_inventory_classification_v2(
  uuid,text,text,jsonb
) from public,anon,authenticated;
do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  revoke execute on function
    app.evidence_record_inventory_classification_v2_pre_rw_transition(
      uuid,text,text,jsonb
    ) from service_role;
  grant execute on function app.evidence_record_inventory_classification_v2(
    uuid,text,text,jsonb
  ) to service_role;
end if; end $$;

comment on function app.evidence_record_inventory_classification_v2(
  uuid,text,text,jsonb
) is 'Service-only append-only inventory classification; exact same-generation external RW posture repeats and restored same-source/same-mount RO advances only to Full Verify; every other cause retains its recovery lane.';
