-- P4.23.3: durable gate-first Replace/Reacquire and exact Restore.
-- Operator Portal only. No MCP, anon, or authenticated execution grant exists.

alter table app.custody_operations
  add column if not exists completion_reauth_audit_event_id uuid null
    unique references app.audit_events(id);

-- Owner-only implementation helpers are invoked by SECURITY DEFINER wrappers;
-- they are not independently privileged boundaries.
alter function app.custody_operation_commit_verified_add_seal_v1(uuid,jsonb,text,text)
  security invoker;

-- Validate object lifecycle/current-version eligibility under the case lock
-- before the shared begin implementation can create a nonterminal operation.
alter function app.custody_operation_begin_or_resume(
  uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid
) rename to custody_operation_begin_or_resume_v2;
alter function app.custody_operation_begin_or_resume_v2(
  uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid
) security invoker;

create function app.custody_operation_begin_or_resume(
  p_case_id uuid, p_action text, p_command jsonb, p_request_digest text,
  p_reason text, p_reauth_audit_event_id uuid, p_idempotency_key text,
  p_actor_user_id uuid, p_actor_service_identity_id uuid, p_runner_instance_id text,
  p_resume_reauth_audit_event_id uuid
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_obj app.evidence_objects; v_op app.custody_operations;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  if p_action in ('REPLACE_REACQUIRE','RESTORE_EXACT') then
    if jsonb_typeof(p_command)<>'object'
       or coalesce(p_command->>'evidence_object_id','') !~
         '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$' then
      raise exception 'invalid_recovery_object' using errcode='invalid_parameter_value';
    end if;
    select * into v_obj from app.evidence_objects
      where id=(p_command->>'evidence_object_id')::uuid and case_id=p_case_id
      for share;
    if not found or v_obj.status not in ('sealed','violated')
       or v_obj.current_version_id is null
       or coalesce(v_obj.current_sha256,'') !~ '^sha256:[0-9a-f]{64}$' then
      raise exception 'recovery_object_not_admitted'
        using errcode='object_not_in_prerequisite_state';
    end if;
  end if;
  select * into v_op from app.custody_operation_begin_or_resume_v2(
    p_case_id,p_action,p_command,p_request_digest,p_reason,p_reauth_audit_event_id,
    p_idempotency_key,p_actor_user_id,p_actor_service_identity_id,
    p_runner_instance_id,p_resume_reauth_audit_event_id
  );
  return v_op;
end $$;

create or replace function app.custody_operation_reauth_event(
  p_action text,p_stage text
) returns text language sql immutable set search_path=pg_catalog,app as $$
  select case
    when p_action='ADD_SEAL' and p_stage='BEGIN' then 'reauth.evidence_seal'
    when p_action='ADD_SEAL' and p_stage='RESUME' then 'reauth.evidence_seal_resume'
    when p_action='REPLACE_REACQUIRE' and p_stage='BEGIN' then 'reauth.evidence_replace_begin'
    when p_action='REPLACE_REACQUIRE' and p_stage='COMPLETE' then 'reauth.evidence_replace_complete'
    when p_action='REPLACE_REACQUIRE' and p_stage='RESUME' then 'reauth.evidence_replace_resume'
    when p_action='RESTORE_EXACT' and p_stage='BEGIN' then 'reauth.evidence_restore'
    when p_action='RESTORE_EXACT' and p_stage='COMPLETE' then 'reauth.evidence_restore_complete'
    when p_action='RESTORE_EXACT' and p_stage='RESUME' then 'reauth.evidence_restore_resume'
    when p_action='IGNORE' and p_stage='BEGIN' then 'reauth.evidence_ignore'
    when p_action='IGNORE' and p_stage='RESUME' then 'reauth.evidence_ignore_resume'
    when p_action='DELETE_STRAY' and p_stage='BEGIN' then 'reauth.evidence_delete'
    when p_action='DELETE_STRAY' and p_stage='RESUME' then 'reauth.evidence_delete_resume'
    when p_action='RETIRE' and p_stage='BEGIN' then 'reauth.evidence_retire'
    when p_action='RETIRE' and p_stage='RESUME' then 'reauth.evidence_retire_resume'
    else null end
$$;

create function app.custody_operation_authorize_recovery_completion(
  p_operation_id uuid,p_actor_user_id uuid,p_completion_reauth_audit_event_id uuid,
  p_runner_instance_id text
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_case_id uuid; v_op app.custody_operations; v_reauth app.audit_events;
begin
  select case_id into v_case_id from app.custody_operations where id=p_operation_id;
  if not found then raise exception 'custody_operation_missing' using errcode='no_data_found'; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_case_id::text,0));
  select * into v_op from app.custody_operations where id=p_operation_id for update;
  if v_op.action not in ('REPLACE_REACQUIRE','RESTORE_EXACT') then
    raise exception 'custody_operation_finalizer_action_mismatch'
      using errcode='invalid_parameter_value';
  end if;
  if v_op.phase='COMPLETED' then return v_op; end if;
  if v_op.phase not in ('FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED','FAILED_RECOVERABLE')
     or v_op.actor_user_id is distinct from p_actor_user_id
     or v_op.actor_service_identity_id is not null
     or p_completion_reauth_audit_event_id is null
     or length(btrim(coalesce(p_runner_instance_id,'')))=0
     or jsonb_typeof(v_op.prepared_facts->'item')<>'object' then
    raise exception 'recovery_completion_not_authorized'
      using errcode='invalid_authorization_specification';
  end if;
  select * into v_reauth from app.audit_events
    where id=p_completion_reauth_audit_event_id for share;
  if not found or v_reauth.case_id is distinct from v_op.case_id
     or v_reauth.event_type is distinct from
       app.custody_operation_reauth_event(v_op.action,'COMPLETE')
     or v_reauth.source<>'portal_reauth' or v_reauth.status<>'success'
     or v_reauth.actor_type<>'user'
     or v_reauth.actor_user_id is distinct from v_op.actor_user_id
     or v_reauth.actor_service_identity_id is not null
     or v_reauth.details->'binding' is distinct from
       jsonb_build_object('operation_id',v_op.id::text) then
    raise exception 'recovery_completion_reauth_scope_mismatch'
      using errcode='invalid_authorization_specification';
  end if;
  if v_op.completion_reauth_audit_event_id is not null
     and v_op.completion_reauth_audit_event_id is distinct from
       p_completion_reauth_audit_event_id then
    raise exception 'recovery_completion_already_authorized'
      using errcode='invalid_authorization_specification';
  end if;
  if v_op.retired_runner_instance_ids ? p_runner_instance_id then
    raise exception 'custody_operation_retired_runner' using errcode='P4232';
  end if;
  update app.custody_operations set
    phase='FILESYSTEM_APPLYING',
    failed_from_phase=failed_from_phase,
    failure_code=null,
    completion_reauth_audit_event_id=p_completion_reauth_audit_event_id,
    retired_runner_instance_ids=case when runner_instance_id=p_runner_instance_id
      then retired_runner_instance_ids
      else retired_runner_instance_ids||jsonb_build_array(runner_instance_id) end,
    runner_instance_id=p_runner_instance_id,updated_at=now()
  where id=v_op.id returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase,facts)
    values(v_op.id,'FILESYSTEM_APPLYING',jsonb_build_object(
      'completion_authorized',true,
      'completion_reauth_audit_event_id',p_completion_reauth_audit_event_id));
  return v_op;
end $$;

-- Canonical recovery events use the fresh completion receipt while retaining
-- the immutable original begin receipt on the operation itself.
create or replace function app.evidence_append_canonical_event_v1(
  p_operation_id uuid,p_evidence_object_id uuid,p_event_type text,p_manifest_version integer,
  p_manifest_hash text,p_before jsonb,p_after jsonb,p_details jsonb
) returns uuid
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_op app.custody_operations; v_seq bigint; v_prev text; v_at timestamptz;
  v_material jsonb; v_hash text; v_id uuid; v_event_reauth uuid;
begin
  select * into v_op from app.custody_operations where id=p_operation_id for update;
  v_event_reauth:=coalesce(v_op.completion_reauth_audit_event_id,v_op.reauth_audit_event_id);
  select head_seq,head_hash into v_seq,v_prev from app.evidence_chain_heads
    where case_id=v_op.case_id for update;
  v_seq:=coalesce(v_seq,0)+1; v_prev:=coalesce(v_prev,''); v_at:=clock_timestamp();
  v_material:=jsonb_build_object(
    'schema','canonical_event_v1','event_type',p_event_type,'operation_id',v_op.id,
    'case_id',v_op.case_id,'action',v_op.action,'evidence_object_id',p_evidence_object_id,
    'manifest_version',p_manifest_version,'manifest_hash',p_manifest_hash,
    'actor_user_id',v_op.actor_user_id,'actor_service_identity_id',v_op.actor_service_identity_id,
    'reason',v_op.reason,'reauth_audit_event_id',v_event_reauth,
    'before',coalesce(p_before,'{}'),'after',coalesce(p_after,'{}'),
    'details',coalesce(p_details,'{}'),'db_timestamp',to_char(v_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'seq',v_seq,'prev_hash',v_prev);
  v_hash:='sha256:'||encode(sha256(convert_to(v_material::text,'UTF8')),'hex');
  insert into app.evidence_custody_events(case_id,evidence_object_id,seq,event_type,
    manifest_version,prev_hash,event_hash,reauth_audit_event_id,actor_user_id,
    actor_service_identity_id,details,created_at,custody_operation_id,canonical_schema,canonical_material)
  values(v_op.case_id,p_evidence_object_id,v_seq,p_event_type,p_manifest_version,v_prev,v_hash,
    v_event_reauth,v_op.actor_user_id,v_op.actor_service_identity_id,
    coalesce(p_details,'{}'),v_at,v_op.id,'canonical_event_v1',v_material) returning id into v_id;
  update app.evidence_chain_heads set head_seq=v_seq,head_hash=v_hash,last_event_type=p_event_type,
    updated_at=now() where case_id=v_op.case_id;
  return v_id;
end $$;

create function app.custody_operation_commit_verified_recovery(
  p_operation_id uuid,p_item jsonb,p_examiner text,p_runner_instance_id text
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_case_id uuid; v_op app.custody_operations; v_obj app.evidence_objects;
  v_head app.evidence_chain_heads; v_manifest_version integer; v_manifest_hash text;
  v_manifest_id uuid; v_version_id uuid; v_facts jsonb; v_result jsonb;
begin
  select case_id into v_case_id from app.custody_operations where id=p_operation_id;
  if not found then raise exception 'custody_operation_missing' using errcode='no_data_found'; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_case_id::text,0));
  select * into v_op from app.custody_operations where id=p_operation_id for update;
  if v_op.action not in ('REPLACE_REACQUIRE','RESTORE_EXACT') then
    raise exception 'custody_operation_finalizer_action_mismatch' using errcode='invalid_parameter_value';
  end if;
  if v_op.phase='COMPLETED' then return v_op; end if;
  if v_op.phase<>'FILESYSTEM_VERIFIED' or v_op.runner_instance_id<>p_runner_instance_id
     or v_op.completion_reauth_audit_event_id is null
     or p_item is distinct from v_op.verified_facts->'item'
     or p_item->>'sha256' !~ '^sha256:[0-9a-f]{64}$'
     or (p_item->>'bytes')::bigint<0 or p_item->>'mode'<>'0644'
     or coalesce((p_item->>'immutable')::boolean,false) is false
     or (p_item->>'st_nlink')::integer<>1 then
    raise exception 'verified_recovery_required' using errcode='invalid_parameter_value';
  end if;
  select * into v_obj from app.evidence_objects
    where id=(v_op.command->>'evidence_object_id')::uuid and case_id=v_op.case_id for update;
  if not found or v_obj.status not in ('sealed','violated')
     or v_obj.current_version_id::text is distinct from p_item->>'original_version_id'
     or v_obj.current_sha256 is distinct from p_item->>'original_sha256'
     or v_obj.id::text is distinct from p_item->>'evidence_object_id'
     or v_obj.display_path is distinct from p_item->>'display_path' then
    raise exception 'recovery_object_binding_changed' using errcode='serialization_failure';
  end if;
  select * into v_head from app.evidence_chain_heads where case_id=v_op.case_id for update;
  if exists(select 1 from app.evidence_objects where case_id=v_op.case_id
       and id<>v_obj.id and status in ('detected','registered','violated')) then
    raise exception 'other_custody_issue_remains'
      using errcode='object_not_in_prerequisite_state';
  end if;

  if v_op.action='RESTORE_EXACT' then
    if p_item->>'sha256' is distinct from v_obj.current_sha256
       or (p_item->>'bytes')::bigint is distinct from v_obj.current_bytes then
      raise exception 'restore_hash_mismatch' using errcode='data_exception';
    end if;
    perform app.evidence_append_canonical_event_v1(v_op.id,v_obj.id,'CHAIN_VERIFIED',
      v_head.manifest_version,v_head.manifest_hash,
      jsonb_build_object('status',v_obj.status,'sha256',v_obj.current_sha256),
      jsonb_build_object('status','sealed','sha256',v_obj.current_sha256),
      jsonb_build_object('restored_exact',true,'evidence_version_id',v_obj.current_version_id,
        'posture',jsonb_build_object('owner',p_item->>'owner','mode',p_item->>'mode',
          'immutable',p_item->'immutable','st_dev',p_item->'st_dev,'st_ino',p_item->'st_ino)));
    update app.evidence_objects set status='sealed',seal_status='sealed',updated_at=now()
      where id=v_obj.id;
    update app.evidence_chain_heads set seal_status='sealed',issues='[]'::jsonb,
      last_verified_at=now(),updated_at=now() where case_id=v_op.case_id;
    v_result:=jsonb_build_object('restored_exact',true,'case_id',v_op.case_id,
      'operation_id',v_op.id,'evidence_object_id',v_obj.id,
      'evidence_version_id',v_obj.current_version_id,
      'manifest_version',v_head.manifest_version,'manifest_hash',v_head.manifest_hash,
      'seal_status','sealed','operation_phase','COMPLETED');
  else
    if p_item->>'sha256' is not distinct from v_obj.current_sha256 then
      raise exception 'replace_requires_changed_bytes' using errcode='data_exception';
    end if;
    v_manifest_version:=coalesce(v_head.manifest_version,0)+1;
    v_version_id:=gen_random_uuid();
    select jsonb_agg(f order by f->>'evidence_object_id') into v_facts from (
      select jsonb_build_object('evidence_object_id',o.id,'evidence_version_id',v.id,
        'sha256',v.sha256,'bytes',v.bytes,'display_path',o.display_path,
        'preserved_sibling',true) f
      from app.evidence_objects o join app.evidence_versions v on v.id=o.current_version_id
      where o.case_id=v_op.case_id and o.status='sealed' and o.id<>v_obj.id
      union all select jsonb_build_object('evidence_object_id',v_obj.id,
        'evidence_version_id',v_version_id,'sha256',p_item->>'sha256',
        'bytes',(p_item->>'bytes')::bigint,'display_path',v_obj.display_path,
        'supersedes_version_id',v_obj.current_version_id)
    ) q;
    v_manifest_hash:='sha256:'||encode(sha256(convert_to(jsonb_build_object(
      'case_id',v_op.case_id,'manifest_version',v_manifest_version,'items',v_facts)::text,'UTF8')),'hex');
    insert into app.evidence_manifests(case_id,manifest_version,manifest_hash,operation_id,item_facts)
      values(v_op.case_id,v_manifest_version,v_manifest_hash,v_op.id,v_facts)
      returning id into v_manifest_id;
    insert into app.evidence_versions(id,evidence_object_id,case_id,manifest_version,sha256,bytes,
      entry_status,manifest_hash,registered_by,metadata,custody_operation_id)
    values(v_version_id,v_obj.id,v_op.case_id,v_manifest_version,p_item->>'sha256',
      (p_item->>'bytes')::bigint,'ACTIVE',v_manifest_hash,p_examiner,
      jsonb_build_object('reacquired',true,'supersedes_version_id',v_obj.current_version_id,
        'superseded_sha256',v_obj.current_sha256,'posture',jsonb_build_object(
          'owner',p_item->>'owner','mode',p_item->>'mode','immutable',p_item->'immutable',
          'st_dev',p_item->'st_dev,'st_ino',p_item->'st_ino,'st_nlink',p_item->'st_nlink)),v_op.id);
    perform app.evidence_append_canonical_event_v1(v_op.id,v_obj.id,'MANIFEST_SEALED',
      v_manifest_version,v_manifest_hash,
      jsonb_build_object('evidence_version_id',v_obj.current_version_id,
        'sha256',v_obj.current_sha256,'gate','BLOCKED_VIOLATION'),
      jsonb_build_object('evidence_version_id',v_version_id,
        'sha256',p_item->>'sha256','gate','OPEN'),
      jsonb_build_object('reacquired',true,'manifest_id',v_manifest_id,'items',v_facts));
    update app.evidence_objects set status='sealed',seal_status='sealed',
      current_version_id=v_version_id,current_sha256=p_item->>'sha256',
      current_bytes=(p_item->>'bytes')::bigint,
      sealed_by_user_id=v_op.actor_user_id,sealed_at=now(),updated_at=now()
      where id=v_obj.id;
    update app.evidence_chain_heads set manifest_version=v_manifest_version,
      manifest_hash=v_manifest_hash,seal_status='sealed',issues='[]'::jsonb,
      active_count=(select count(*) from app.evidence_objects
        where case_id=v_op.case_id and status='sealed'),updated_at=now()
      where case_id=v_op.case_id;
    v_result:=jsonb_build_object('reacquired',true,'case_id',v_op.case_id,
      'operation_id',v_op.id,'evidence_object_id',v_obj.id,
      'evidence_version_id',v_version_id,'manifest_version',v_manifest_version,
      'manifest_hash',v_manifest_hash,'seal_status','sealed','operation_phase','COMPLETED');
  end if;
  update app.custody_operations set phase='LEDGER_COMMITTED',updated_at=now()
    where id=v_op.id;
  insert into app.custody_operation_history(operation_id,phase)
    values(v_op.id,'LEDGER_COMMITTED');
  update app.custody_operations set phase='COMPLETED',result=v_result,
    completed_at=now(),updated_at=now() where id=v_op.id returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase)
    values(v_op.id,'COMPLETED');
  return v_op;
end $$;

-- The legacy unsafe paths are retained only as inert historical definitions so
-- accumulated migrations remain reproducible. No runtime role can invoke them.
revoke execute on function app.evidence_unseal(uuid,text,uuid,uuid,uuid)
  from public,anon,authenticated;
revoke execute on function app.evidence_reacquire(
  uuid,uuid,text,bigint,integer,text,text,uuid,uuid,uuid
) from public,anon,authenticated;

revoke execute on function app.custody_operation_begin_or_resume_v2(
  uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid
) from public,anon,authenticated;
revoke execute on function app.custody_operation_begin_or_resume(
  uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid
) from public,anon,authenticated;
revoke execute on function app.custody_operation_authorize_recovery_completion(
  uuid,uuid,uuid,text
) from public,anon,authenticated;
revoke execute on function app.custody_operation_commit_verified_recovery(
  uuid,jsonb,text,text
) from public,anon,authenticated;

do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  revoke execute on function app.evidence_unseal(uuid,text,uuid,uuid,uuid)
    from service_role;
  revoke execute on function app.evidence_reacquire(
    uuid,uuid,text,bigint,integer,text,text,uuid,uuid,uuid
  ) from service_role;
  revoke execute on function app.custody_operation_begin_or_resume_v2(
    uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid
  ) from service_role;
  grant execute on function app.custody_operation_begin_or_resume(
    uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid
  ) to service_role;
  grant execute on function app.custody_operation_authorize_recovery_completion(
    uuid,uuid,uuid,text
  ) to service_role;
  grant execute on function app.custody_operation_commit_verified_recovery(
    uuid,jsonb,text,text
  ) to service_role;
end if; end $$;
