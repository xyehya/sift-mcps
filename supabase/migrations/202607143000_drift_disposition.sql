-- P4.23.4: path-free drift observations and durable operator disposition.

create table app.evidence_inventory_observations (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  correlation_id text not null check (length(correlation_id) between 1 and 128),
  gate_state text not null check (gate_state in (
    'OPEN','BLOCKED_PENDING','BLOCKED_VIOLATION','BLOCKED_UNAVAILABLE')),
  findings jsonb not null check (jsonb_typeof(findings)='array'),
  created_at timestamptz not null default now(),
  unique(case_id,correlation_id)
);

alter table app.evidence_inventory_observations enable row level security;
alter table app.evidence_inventory_observations force row level security;
create trigger evidence_inventory_observations_no_update_delete
  before update or delete on app.evidence_inventory_observations
  for each row execute function app.evidence_block_mutation();
create trigger evidence_inventory_observations_no_truncate before truncate
  on app.evidence_inventory_observations execute function app.evidence_block_truncate();

create function app.evidence_record_inventory_classification(
  p_case_id uuid,p_correlation_id text,p_gate_state text,p_findings jsonb
) returns app.evidence_inventory_observations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_row app.evidence_inventory_observations;
  v_expected_gate text;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  if length(coalesce(p_correlation_id,'')) not between 1 and 128
     or p_gate_state not in ('OPEN','BLOCKED_PENDING','BLOCKED_VIOLATION','BLOCKED_UNAVAILABLE')
     or p_findings is null or jsonb_typeof(p_findings)<>'array'
     or exists(select 1 from jsonb_array_elements(p_findings) f where
       jsonb_typeof(f)<>'object'
       or not (f ?& array['code','gate_state','recovery','evidence_object_id',
         'observation_id','full_verification_required'])
       or jsonb_typeof(f->'code')<>'string'
       or jsonb_typeof(f->'gate_state')<>'string'
       or jsonb_typeof(f->'recovery')<>'string'
       or f->>'code' not in ('STORAGE_UNAVAILABLE','INVENTORY_SCAN_FAILED','MOUNT_IDENTITY_CHANGED',
         'LEDGER_INVALID','CONFLICTING_AUTHORITY','CONFLICTING_OBSERVATION','UNKNOWN_OBJECT_BINDING',
         'DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM','SEALED_EVIDENCE_MISSING','UNSAFE_SEALED_ENTRY',
         'CONTENT_CHANGED','IDENTITY_CHANGED','FULL_VERIFY_REQUIRED','POSTURE_DRIFT')
       or f->>'gate_state' not in ('BLOCKED_PENDING','BLOCKED_VIOLATION','BLOCKED_UNAVAILABLE')
       or f->>'recovery' not in ('INVESTIGATE_AVAILABILITY','RECONNECT_AND_VERIFY',
         'REPAIR_LEDGER','OPERATOR_DISPOSITION','RESTORE_REACQUIRE_RETIRE','FULL_VERIFY_AND_REPAIR')
       or (f ? 'evidence_object_id' and f->'evidence_object_id'<>'null'::jsonb
         and coalesce(f->>'evidence_object_id','') !~
           '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')
       or (f ? 'observation_id' and f->'observation_id'<>'null'::jsonb
         and coalesce(f->>'observation_id','') !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$')
       or not (f ? 'full_verification_required')
       or jsonb_typeof(f->'full_verification_required')<>'boolean'
       or f->>'gate_state' is distinct from case
         when f->>'code' in ('DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM') then 'BLOCKED_PENDING'
         when f->>'code' in ('STORAGE_UNAVAILABLE','INVENTORY_SCAN_FAILED','MOUNT_IDENTITY_CHANGED')
           then 'BLOCKED_UNAVAILABLE'
         else 'BLOCKED_VIOLATION' end
       or exists(select 1 from jsonb_object_keys(f) k where k not in
         ('code','gate_state','recovery','evidence_object_id','observation_id','full_verification_required'))
     ) then
    raise exception 'invalid_inventory_classification' using errcode='invalid_parameter_value';
  end if;
  select case
    when exists(select 1 from jsonb_array_elements(p_findings) f
      where f->>'gate_state'='BLOCKED_UNAVAILABLE') then 'BLOCKED_UNAVAILABLE'
    when exists(select 1 from jsonb_array_elements(p_findings) f
      where f->>'gate_state'='BLOCKED_VIOLATION') then 'BLOCKED_VIOLATION'
    when exists(select 1 from jsonb_array_elements(p_findings) f
      where f->>'gate_state'='BLOCKED_PENDING') then 'BLOCKED_PENDING'
    else 'OPEN' end into v_expected_gate;
  if p_gate_state is distinct from v_expected_gate then
    raise exception 'inventory_gate_findings_mismatch' using errcode='invalid_parameter_value';
  end if;
  insert into app.evidence_inventory_observations(case_id,correlation_id,gate_state,findings)
    values(p_case_id,p_correlation_id,p_gate_state,p_findings)
    on conflict(case_id,correlation_id) do nothing returning * into v_row;
  if not found then select * into v_row from app.evidence_inventory_observations
    where case_id=p_case_id and correlation_id=p_correlation_id;
    if v_row.gate_state is distinct from p_gate_state or v_row.findings is distinct from p_findings then
      raise exception 'inventory_correlation_reused' using errcode='unique_violation';
    end if;
  end if;
  update app.evidence_chain_heads set
    seal_status=case when p_gate_state='OPEN' then seal_status
      when p_gate_state='BLOCKED_PENDING' then 'unsealed' else 'violated' end,
    issues=p_findings,updated_at=now() where case_id=p_case_id;
  return v_row;
end $$;

create function app.custody_operation_resume_disposition(
  p_operation_id uuid,p_actor_user_id uuid,p_resume_reauth_audit_event_id uuid,
  p_runner_instance_id text
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_case_id uuid; v_op app.custody_operations; v_reauth app.audit_events;
  v_target_phase text; v_expected_event text; v_previous_runner text;
begin
  select case_id into v_case_id from app.custody_operations where id=p_operation_id;
  if not found then raise exception 'custody_operation_missing' using errcode='no_data_found'; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_case_id::text,0));
  select * into v_op from app.custody_operations where id=p_operation_id for update;
  if v_op.action not in ('IGNORE','DELETE_STRAY','RETIRE')
     or v_op.phase not in ('GATE_BLOCKED','FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED','FAILED_RECOVERABLE')
     or v_op.actor_user_id is distinct from p_actor_user_id
     or v_op.actor_service_identity_id is not null
     or length(btrim(coalesce(p_runner_instance_id,'')))=0 then
    raise exception 'disposition_not_resumable' using errcode='invalid_authorization_specification';
  end if;
  v_expected_event:=app.custody_operation_reauth_event(v_op.action,'RESUME');
  select * into v_reauth from app.audit_events where id=p_resume_reauth_audit_event_id for share;
  if not found or v_reauth.case_id is distinct from v_op.case_id
     or v_reauth.event_type is distinct from v_expected_event
     or v_reauth.source<>'portal_reauth' or v_reauth.status<>'success'
     or v_reauth.actor_type<>'user'
     or v_reauth.actor_user_id is distinct from v_op.actor_user_id
     or v_reauth.actor_service_identity_id is not null
     or v_reauth.details->'binding' is distinct from
       jsonb_build_object('operation_id',v_op.id::text) then
    raise exception 'resume_reauth_scope_mismatch' using errcode='invalid_authorization_specification';
  end if;
  begin
    insert into app.custody_operation_history(
      operation_id,phase,facts,resume_reauth_audit_event_id
    ) values(v_op.id,v_op.phase,jsonb_build_object('resume_authorized',true),
      p_resume_reauth_audit_event_id);
  exception when unique_violation then
    raise exception 'resume_reauth_reused' using errcode='invalid_authorization_specification';
  end;
  v_previous_runner:=v_op.runner_instance_id;
  v_target_phase:=case when v_op.phase='FAILED_RECOVERABLE'
    then coalesce(v_op.failed_from_phase,'GATE_BLOCKED') else v_op.phase end;
  if v_target_phase not in ('GATE_BLOCKED','FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED') then
    raise exception 'disposition_resume_phase_invalid' using errcode='invalid_authorization_specification';
  end if;
  update app.custody_operations set phase=v_target_phase,failed_from_phase=null,
    failure_code=null,runner_instance_id=p_runner_instance_id,
    retired_runner_instance_ids=case
      when v_previous_runner is null or v_previous_runner=p_runner_instance_id
        then retired_runner_instance_ids
      else retired_runner_instance_ids||jsonb_build_array(v_previous_runner) end,
    updated_at=now() where id=v_op.id returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase,facts)
    values(v_op.id,v_op.phase,jsonb_build_object(
      'resumed',true,'preserved_prepared_facts',v_op.prepared_facts<>'{}'::jsonb,
      'preserved_verified_facts',v_op.verified_facts<>'{}'::jsonb));
  return v_op;
end $$;

create function app.custody_operation_commit_verified_disposition(
  p_operation_id uuid,p_item jsonb,p_examiner text,p_runner_instance_id text
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_case_id uuid; v_op app.custody_operations; v_obj app.evidence_objects;
  v_head app.evidence_chain_heads; v_event_type text; v_result jsonb;
  v_manifest_version integer; v_manifest_hash text; v_facts jsonb;
begin
  select case_id into v_case_id from app.custody_operations where id=p_operation_id;
  if not found then raise exception 'custody_operation_missing' using errcode='no_data_found'; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_case_id::text,0));
  select * into v_op from app.custody_operations where id=p_operation_id for update;
  if v_op.action not in ('IGNORE','DELETE_STRAY','RETIRE') then
    raise exception 'custody_operation_finalizer_action_mismatch' using errcode='invalid_parameter_value';
  end if;
  if v_op.phase='COMPLETED' then return v_op; end if;
  if v_op.phase<>'FILESYSTEM_VERIFIED' or v_op.runner_instance_id<>p_runner_instance_id
     or p_item is distinct from v_op.verified_facts->'item'
     or p_item->>'evidence_object_id' is distinct from v_op.command->>'evidence_object_id'
     or coalesce(p_examiner,'')='' then
    raise exception 'verified_disposition_required' using errcode='invalid_parameter_value';
  end if;
  select * into v_obj from app.evidence_objects where id=(v_op.command->>'evidence_object_id')::uuid
    and case_id=v_op.case_id for update;
  if not found or v_obj.display_path is distinct from p_item->>'display_path'
     or v_obj.status is distinct from p_item->>'prior_status'
     or v_obj.seal_status is distinct from p_item->>'prior_seal_status' then
    raise exception 'disposition_object_binding_changed' using errcode='serialization_failure';
  end if;
  select * into v_head from app.evidence_chain_heads where case_id=v_op.case_id for update;
  if v_op.action in ('IGNORE','DELETE_STRAY') then
    if (v_op.action='IGNORE' and v_obj.status<>'detected')
       or (v_op.action='DELETE_STRAY' and v_obj.status not in ('detected','registered','ignored'))
       or v_obj.seal_status<>'unsealed'
       or coalesce(p_item->>'sha256','') !~ '^sha256:[0-9a-f]{64}$'
       or (case when coalesce(p_item->>'bytes','') ~ '^[0-9]+$'
         then (p_item->>'bytes')::numeric between 0 and 9223372036854775807
         else false end) is not true
       or (v_op.action='IGNORE' and coalesce((p_item->>'present')::boolean,false) is false)
       or (v_op.action='DELETE_STRAY' and coalesce((p_item->>'present')::boolean,false)
           and coalesce((p_item->>'file_removed')::boolean,false) is false) then
      raise exception 'pending_disposition_ineligible' using errcode='object_not_in_prerequisite_state';
    end if;
    v_event_type:='FILE_IGNORED';
    update app.evidence_objects set status='ignored',seal_status='unsealed',
      current_sha256=p_item->>'sha256',current_bytes=(p_item->>'bytes')::bigint,updated_at=now()
      where id=v_obj.id;
  else
    if v_obj.status not in ('sealed','violated') or v_obj.current_version_id is null
       or v_obj.current_version_id::text is distinct from p_item->>'original_version_id'
       or v_obj.current_sha256 is distinct from p_item->>'original_sha256'
       or coalesce((p_item->>'file_removed')::boolean,false) then
      raise exception 'retire_disposition_ineligible' using errcode='object_not_in_prerequisite_state';
    end if;
    v_event_type:='FILE_RETIRED'; v_manifest_version:=coalesce(v_head.manifest_version,0)+1;
    select coalesce(jsonb_agg(jsonb_build_object('evidence_object_id',o.id,
      'evidence_version_id',o.current_version_id,'sha256',o.current_sha256,'bytes',o.current_bytes,
      'display_path',o.display_path,'preserved_sibling',true) order by o.id),'[]'::jsonb)
      into v_facts from app.evidence_objects o where o.case_id=v_op.case_id
      and o.status='sealed' and o.id<>v_obj.id;
    v_manifest_hash:='sha256:'||encode(sha256(convert_to(jsonb_build_object(
      'case_id',v_op.case_id,'manifest_version',v_manifest_version,'items',v_facts)::text,'UTF8')),'hex');
    insert into app.evidence_manifests(case_id,manifest_version,manifest_hash,operation_id,item_facts)
      values(v_op.case_id,v_manifest_version,v_manifest_hash,v_op.id,v_facts);
    update app.evidence_objects set status='retired',seal_status='unsealed',retired_at=now(),updated_at=now()
      where id=v_obj.id;
    update app.evidence_chain_heads set manifest_version=v_manifest_version,
      manifest_hash=v_manifest_hash,active_count=jsonb_array_length(v_facts) where case_id=v_op.case_id;
  end if;
  perform app.evidence_append_canonical_event_v1(v_op.id,v_obj.id,v_event_type,
    coalesce(v_manifest_version,v_head.manifest_version),coalesce(v_manifest_hash,v_head.manifest_hash),
    jsonb_build_object('status',v_obj.status,'sha256',v_obj.current_sha256),
    jsonb_build_object('status',case when v_op.action='RETIRE' then 'retired' else 'ignored' end),
    jsonb_build_object('disposition',v_op.action,'sha256',p_item->>'sha256','bytes',p_item->'bytes',
      'file_removed',coalesce(p_item->'file_removed','false'::jsonb)));
  perform app.evidence_recompute_seal_status(v_op.case_id);
  v_result:=jsonb_build_object('case_id',v_op.case_id,'operation_id',v_op.id,
    'operation_phase','COMPLETED','evidence_object_id',v_obj.id,
    'status',case when v_op.action='RETIRE' then 'retired' else 'ignored' end,
    'file_removed',coalesce((p_item->>'file_removed')::boolean,false),
    'sha256',p_item->>'sha256','bytes',p_item->'bytes');
  update app.custody_operations set phase='LEDGER_COMMITTED',updated_at=now() where id=v_op.id;
  insert into app.custody_operation_history(operation_id,phase) values(v_op.id,'LEDGER_COMMITTED');
  update app.custody_operations set phase='COMPLETED',result=v_result,completed_at=now(),updated_at=now()
    where id=v_op.id returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase) values(v_op.id,'COMPLETED');
  return v_op;
end $$;

revoke all on app.evidence_inventory_observations from public,anon,authenticated;
revoke execute on function app.evidence_record_inventory_classification(uuid,text,text,jsonb)
  from public,anon,authenticated;
revoke execute on function app.custody_operation_commit_verified_disposition(uuid,jsonb,text,text)
  from public,anon,authenticated;
revoke execute on function app.custody_operation_resume_disposition(uuid,uuid,uuid,text)
  from public,anon,authenticated;
revoke execute on function app.evidence_ignore(uuid,text,uuid,uuid,uuid)
  from public,anon,authenticated;
revoke execute on function app.evidence_retire(uuid,text,uuid,uuid,uuid)
  from public,anon,authenticated;
do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  revoke execute on function app.evidence_ignore(uuid,text,uuid,uuid,uuid) from service_role;
  revoke execute on function app.evidence_retire(uuid,text,uuid,uuid,uuid) from service_role;
  grant select on app.evidence_inventory_observations to service_role;
  grant execute on function app.evidence_record_inventory_classification(uuid,text,text,jsonb) to service_role;
  grant execute on function app.custody_operation_commit_verified_disposition(uuid,jsonb,text,text)
    to service_role;
  grant execute on function app.custody_operation_resume_disposition(uuid,uuid,uuid,text)
    to service_role;
end if; end $$;
