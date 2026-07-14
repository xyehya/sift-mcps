-- P4.23 Gate C: an external case may retain immutable Evidence Versions from
-- its original mount while a later successful Full Verify bound a different
-- mount instance.  If read-write posture drift is then restored under the new
-- stable host observer, all three mount identities can legitimately differ.
-- Admit only that exact receipt-backed causal transition into the existing
-- operator Full Verify lane.  Never bless the observed mount or open the gate.

do $$ begin
  if to_regprocedure(
      'app.evidence_record_inventory_classification_v2_pre_legacy_mount_transition(uuid,text,text,jsonb)'
    ) is null then
    alter function app.evidence_record_inventory_classification_v2(uuid,text,text,jsonb)
      rename to evidence_record_inventory_classification_v2_pre_legacy_mount_transition;
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
  v_existing boolean := false;
  v_exact_receipt boolean := false;
  v_transition boolean := false;
  v_repeat boolean := false;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  if length(coalesce(p_correlation_id,'')) not between 1 and 128 then
    raise exception 'invalid_inventory_classification'
      using errcode='invalid_parameter_value';
  end if;
  select * into v_head from app.evidence_chain_heads
    where case_id=p_case_id for update;
  select * into v_storage from app.evidence_storage_authorities
    where case_id=p_case_id for update;
  select * into v_row from app.evidence_inventory_observations
    where case_id=p_case_id and correlation_id=p_correlation_id;
  v_existing := found;
  if v_existing
     and (v_row.gate_state is distinct from p_gate_state
       or v_row.findings is distinct from p_findings) then
    raise exception 'inventory_correlation_reused' using errcode='unique_violation';
  end if;

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

  if v_head.case_id is not null
     and v_storage.case_id is not null
     and v_head.seal_status='violated'
     and coalesce(v_head.manifest_version,0)>0
     and coalesce(v_head.manifest_hash,'') ~ '^sha256:[0-9a-f]{64}$'
     and coalesce(v_head.active_count,0)>0
     and v_storage.profile='EXTERNALLY_READ_ONLY'
     and v_storage.state='FULL_VERIFY_REQUIRED'
     and v_storage.remediation='FULL_VERIFY'
     and v_storage.generation=v_storage.verified_generation
     and coalesce(v_storage.source_identity,'') ~ '^[0-9a-f]{64}$'
     and coalesce(v_storage.verified_mount_instance,'') ~ '^[0-9a-f]{64}$'
     and coalesce(v_storage.observed_mount_instance,'') ~ '^[0-9a-f]{64}$'
     and v_storage.observed_mount_instance<>v_storage.verified_mount_instance
     and v_storage.read_only is true
     and p_gate_state='BLOCKED_UNAVAILABLE'
     and v_finding=jsonb_build_object(
       'code','STORAGE_FULL_VERIFY_REQUIRED',
       'gate_state','BLOCKED_UNAVAILABLE',
       'recovery','FULL_VERIFY_AND_REPAIR',
       'evidence_object_id',null,
       'observation_id',null,
       'full_verification_required',true)
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
           or ev.entry_status is distinct from 'ACTIVE'
           or ev.storage_profile is distinct from 'EXTERNALLY_READ_ONLY'
           or ev.storage_source_identity is distinct from v_storage.source_identity
           or coalesce(ev.storage_mount_instance,'') !~ '^[0-9a-f]{64}$'))
     and not exists(select 1 from app.custody_operations op
       where op.case_id=p_case_id and op.phase<>'COMPLETED')
     and ((
       jsonb_array_length(v_prior_issues)=v_head.active_count
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
             where lower(issue->>'evidence_object_id')=o.id::text))
     ) or v_prior_issues=jsonb_build_array(
       v_finding||jsonb_build_object(
         'storage_generation',v_storage.generation))) then
    select exists(select 1
      from app.evidence_storage_verifications v
      where v.case_id=p_case_id
        and v.outcome='SUCCESS'
        and v.generation=v_storage.generation
        and v.profile=v_storage.profile
        and v.source_identity is not distinct from v_storage.source_identity
        and v.mount_instance is not distinct from v_storage.verified_mount_instance
        and v.manifest_version=v_head.manifest_version
        and v.manifest_hash=v_head.manifest_hash
        and jsonb_array_length(v.item_facts)=v_head.active_count
        and (select count(distinct x->>'evidence_object_id')
          from jsonb_array_elements(v.item_facts) x)=v_head.active_count
        and not exists(select 1
          from app.evidence_objects o
          join app.evidence_versions ev on ev.id=o.current_version_id
          where o.case_id=p_case_id and o.status='sealed'
            and not exists(select 1 from jsonb_array_elements(v.item_facts) x
              where x->>'evidence_object_id'=o.id::text
                and x->>'evidence_version_id'=ev.id::text
                and x->>'sha256'=ev.sha256
                and x->>'bytes'=ev.bytes::text
                and x->>'storage_profile'='EXTERNALLY_READ_ONLY'
                and x->>'storage_source_identity'=v_storage.source_identity
                and x->>'mount_instance_identity'=v_storage.verified_mount_instance
                and x->'read_only'='true'::jsonb
                and x->>'st_nlink'='1'))
        and not exists(select 1 from jsonb_array_elements(v.item_facts) x
          where not exists(select 1
            from app.evidence_objects o
            join app.evidence_versions ev on ev.id=o.current_version_id
            where o.case_id=p_case_id and o.status='sealed'
              and x->>'evidence_object_id'=o.id::text
              and x->>'evidence_version_id'=ev.id::text
              and x->>'sha256'=ev.sha256
              and x->>'bytes'=ev.bytes::text)))
      into v_exact_receipt;
    if v_exact_receipt then
      v_repeat := v_prior_issues=jsonb_build_array(
        v_finding||jsonb_build_object(
          'storage_generation',v_storage.generation));
      v_transition := not v_repeat;
    end if;
  end if;

  if v_existing then
    if v_repeat then
      return v_row;
    end if;
    raise exception 'inventory_correlation_reused' using errcode='unique_violation';
  end if;

  if v_transition then
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
    update app.evidence_chain_heads
    set issues=jsonb_build_array(
          v_finding||jsonb_build_object(
            'storage_generation',v_storage.generation)
        ),
        seal_status='violated',
        updated_at=now()
    where case_id=p_case_id;
    return v_row;
  end if;

  select * into v_row
  from app.evidence_record_inventory_classification_v2_pre_legacy_mount_transition(
    p_case_id,p_correlation_id,p_gate_state,p_findings
  );
  return v_row;
end $$;

revoke execute on function
  app.evidence_record_inventory_classification_v2_pre_legacy_mount_transition(
    uuid,text,text,jsonb
  ) from public,anon,authenticated;
revoke execute on function app.evidence_record_inventory_classification_v2(
  uuid,text,text,jsonb
) from public,anon,authenticated;
do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  revoke execute on function
    app.evidence_record_inventory_classification_v2_pre_legacy_mount_transition(
      uuid,text,text,jsonb
    ) from service_role;
  grant execute on function app.evidence_record_inventory_classification_v2(
    uuid,text,text,jsonb
  ) to service_role;
end if; end $$;

comment on function app.evidence_record_inventory_classification_v2(
  uuid,text,text,jsonb
) is 'Service-only append-only inventory classification; exact receipt-backed legacy/version/verified/observed mount transition advances only to operator Full Verify while every other cause delegates fail closed.';
