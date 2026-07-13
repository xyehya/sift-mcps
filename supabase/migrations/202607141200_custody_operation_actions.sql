-- P4.23.3 shared seam: cumulative, server-authorized custody action vocabulary.
--
-- The P4.23.2 Add/Seal RPC keeps its original name, signature, binding, and
-- violation behavior while gaining a closed action vocabulary. Later packets
-- add action-specific finalizers. No MCP, anon, or authenticated grant is added.

alter table app.custody_operations
  drop constraint custody_operations_action_check;
alter table app.custody_operations
  add constraint custody_operations_action_check check (action in (
    'ADD_SEAL',
    'REPLACE_REACQUIRE',
    'RESTORE_EXACT',
    'IGNORE',
    'DELETE_STRAY',
    'RETIRE'
  ));

create or replace function app.custody_operation_reauth_event(
  p_action text,p_stage text
) returns text
language sql immutable set search_path=pg_catalog,app as $$
  select case
    when p_action='ADD_SEAL' and p_stage='BEGIN' then 'reauth.evidence_seal'
    when p_action='ADD_SEAL' and p_stage='RESUME' then 'reauth.evidence_seal_resume'
    when p_action='REPLACE_REACQUIRE' and p_stage='BEGIN' then 'reauth.evidence_replace_begin'
    when p_action='REPLACE_REACQUIRE' and p_stage='COMPLETE' then 'reauth.evidence_replace_complete'
    when p_action='REPLACE_REACQUIRE' and p_stage='RESUME' then 'reauth.evidence_replace_resume'
    when p_action='RESTORE_EXACT' and p_stage='BEGIN' then 'reauth.evidence_restore'
    when p_action='RESTORE_EXACT' and p_stage='RESUME' then 'reauth.evidence_restore_resume'
    when p_action='IGNORE' and p_stage='BEGIN' then 'reauth.evidence_ignore'
    when p_action='IGNORE' and p_stage='RESUME' then 'reauth.evidence_ignore_resume'
    when p_action='DELETE_STRAY' and p_stage='BEGIN' then 'reauth.evidence_delete'
    when p_action='DELETE_STRAY' and p_stage='RESUME' then 'reauth.evidence_delete_resume'
    when p_action='RETIRE' and p_stage='BEGIN' then 'reauth.evidence_retire'
    when p_action='RETIRE' and p_stage='RESUME' then 'reauth.evidence_retire_resume'
    else null
  end
$$;

create or replace function app.custody_operation_begin_or_resume(
  p_case_id uuid, p_action text, p_command jsonb, p_request_digest text,
  p_reason text, p_reauth_audit_event_id uuid, p_idempotency_key text,
  p_actor_user_id uuid, p_actor_service_identity_id uuid, p_runner_instance_id text,
  p_resume_reauth_audit_event_id uuid
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare
  v_op app.custody_operations;
  v_reauth app.audit_events;
  v_resume app.audit_events;
  v_object app.evidence_objects;
  v_expected_reauth text;
  v_expected_resume_reauth text;
  v_binding jsonb;
begin
  -- The action determines its authorization ceremony. Neither the browser nor
  -- an action payload can select an arbitrary audit event type or binding shape.
  select app.custody_operation_reauth_event(p_action,'BEGIN'),
         app.custody_operation_reauth_event(p_action,'RESUME')
    into v_expected_reauth,v_expected_resume_reauth;

  if v_expected_reauth is null
     or length(btrim(coalesce(p_reason,''))) not between 1 and 1000
     or length(coalesce(p_idempotency_key,'')) not between 1 and 128
     or coalesce(p_request_digest,'') !~ '^sha256:[0-9a-f]{64}$'
     or p_reauth_audit_event_id is null
     or p_actor_user_id is null
     or p_actor_service_identity_id is not null
     or length(btrim(coalesce(p_runner_instance_id,'')))=0
     or jsonb_typeof(p_command)<>'object' then
    raise exception 'invalid_custody_operation_action'
      using errcode='invalid_parameter_value';
  end if;

  -- Global invariant: acquire the per-case advisory transaction lock before
  -- any custody row lock. Each action owns and documents its internal row order.
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));

  if p_action='ADD_SEAL' then
    v_binding:=jsonb_build_object(
      'idempotency_key',p_idempotency_key,
      'reason',btrim(p_reason),
      'targets',(
        select jsonb_agg(x->>'path' order by x->>'path')
        from jsonb_array_elements(p_command->'files') x
      )
    );
  else
    if p_command->>'schema_version' is distinct from '2'
       or p_command->>'action' is distinct from p_action
       or coalesce(p_command->>'evidence_object_id','') !~
         '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
       or exists (
         select 1 from jsonb_object_keys(p_command) as key
         where key not in ('schema_version','action','evidence_object_id')
       ) then
      raise exception 'invalid_custody_operation_action'
        using errcode='invalid_parameter_value';
    end if;
    select * into v_object from app.evidence_objects
      where id=(p_command->>'evidence_object_id')::uuid and case_id=p_case_id
      for share;
    if not found then
      raise exception 'evidence_object_not_in_case' using errcode='no_data_found';
    end if;
    v_binding:=jsonb_build_object(
      'action',p_action,
      'evidence_object_id',v_object.id::text,
      'idempotency_key',p_idempotency_key,
      'reason',btrim(p_reason)
    );
  end if;
  select * into v_reauth from app.audit_events
    where id=p_reauth_audit_event_id for share;
  if not found
     or v_reauth.case_id is distinct from p_case_id
     or v_reauth.event_type is distinct from v_expected_reauth
     or v_reauth.source<>'portal_reauth'
     or v_reauth.status<>'success'
     or v_reauth.actor_type<>'user'
     or v_reauth.actor_user_id is distinct from p_actor_user_id
     or v_reauth.actor_service_identity_id is not null
     or v_reauth.details->'binding' is distinct from v_binding then
    raise exception 'reauth_scope_mismatch'
      using errcode='invalid_authorization_specification';
  end if;

  if p_action='ADD_SEAL' and (
    exists(select 1 from app.evidence_chain_heads h where h.case_id=p_case_id
      and (h.seal_status='violated' or coalesce(h.issues,'[]'::jsonb)<>'[]'::jsonb))
    or exists(select 1 from app.evidence_objects o where o.case_id=p_case_id
      and (o.status='violated' or o.seal_status='violated'))
  ) then
    raise exception 'custody_violation_requires_recovery'
      using errcode='object_not_in_prerequisite_state';
  end if;
  select * into v_op from app.custody_operations
    where case_id=p_case_id and idempotency_key=p_idempotency_key for update;
  if found then
    if v_op.action<>p_action or v_op.request_digest<>p_request_digest
       or v_op.command is distinct from p_command then
      raise exception 'idempotency_key_reused' using errcode='P4231';
    end if;
    if v_op.retired_runner_instance_ids ? p_runner_instance_id then
      raise exception 'custody_operation_retired_runner' using errcode='P4232';
    end if;
    if p_resume_reauth_audit_event_id is not null
       and v_op.phase not in (
         'GATE_BLOCKED','FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED','FAILED_RECOVERABLE'
       ) then
      raise exception 'custody_operation_not_resumable'
        using errcode='invalid_authorization_specification';
    end if;
    if v_op.runner_instance_id<>p_runner_instance_id
       and v_op.phase in (
         'GATE_BLOCKED','FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED','FAILED_RECOVERABLE'
       ) and p_resume_reauth_audit_event_id is null then
      raise exception 'resume_reauth_required'
        using errcode='invalid_authorization_specification';
    end if;
    if p_resume_reauth_audit_event_id is not null then
      select * into v_resume from app.audit_events
        where id=p_resume_reauth_audit_event_id for share;
      if not found
         or v_resume.case_id is distinct from v_op.case_id
         or v_resume.event_type is distinct from v_expected_resume_reauth
         or v_resume.source<>'portal_reauth'
         or v_resume.status<>'success'
         or v_resume.actor_type<>'user'
         or v_resume.actor_user_id is distinct from v_op.actor_user_id
         or v_resume.actor_service_identity_id is not null
         or v_resume.details->'binding' is distinct from
           jsonb_build_object('operation_id',v_op.id::text) then
        raise exception 'resume_reauth_scope_mismatch'
          using errcode='invalid_authorization_specification';
      end if;
      begin
        insert into app.custody_operation_history(
          operation_id,phase,facts,resume_reauth_audit_event_id
        ) values(
          v_op.id,v_op.phase,jsonb_build_object('resume_authorized',true),
          p_resume_reauth_audit_event_id
        );
      exception
        when unique_violation then
          raise exception 'resume_reauth_reused'
            using errcode='invalid_authorization_specification';
      end;
    end if;
    if v_op.phase='GATE_BLOCKED'
       and v_op.runner_instance_id<>p_runner_instance_id then
      update app.custody_operations set
        runner_instance_id=p_runner_instance_id,
        retired_runner_instance_ids=
          retired_runner_instance_ids||jsonb_build_array(v_op.runner_instance_id),
        updated_at=now()
      where id=v_op.id and phase='GATE_BLOCKED' returning * into v_op;
      insert into app.custody_operation_history(operation_id,phase,facts)
        values(v_op.id,'GATE_BLOCKED',jsonb_build_object('runner_claimed',true));
    elsif v_op.phase in ('FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED') then
      if v_op.runner_instance_id=p_runner_instance_id then
        raise exception 'custody_operation_same_runner_active' using errcode='P4232';
      end if;
      update app.custody_operations set
        phase='FAILED_RECOVERABLE',failed_from_phase=v_op.phase,
        failure_code='runner_interrupted',updated_at=now()
      where id=v_op.id and phase=v_op.phase returning * into v_op;
      insert into app.custody_operation_history(operation_id,phase,facts)
        values(v_op.id,'FAILED_RECOVERABLE',jsonb_build_object(
          'failed_from',v_op.failed_from_phase,'code','runner_interrupted'));
    end if;
    if v_op.phase='FAILED_RECOVERABLE' then
      update app.custody_operations set
        phase='GATE_BLOCKED',failure_code=null,runner_instance_id=p_runner_instance_id,
        retired_runner_instance_ids=case when runner_instance_id=p_runner_instance_id
          then retired_runner_instance_ids
          else retired_runner_instance_ids||jsonb_build_array(runner_instance_id) end,
        verified_facts=case when failed_from_phase='FILESYSTEM_VERIFIED'
          then '{}'::jsonb else verified_facts end,
        updated_at=now()
      where id=v_op.id and phase='FAILED_RECOVERABLE' returning * into v_op;
      insert into app.custody_operation_history(operation_id,phase,facts)
        values(v_op.id,'GATE_BLOCKED',jsonb_build_object(
          'resumed',true,'resumed_from',v_op.failed_from_phase));
    end if;
    return v_op;
  end if;

  if p_resume_reauth_audit_event_id is not null then
    raise exception 'resume_operation_not_found'
      using errcode='invalid_authorization_specification';
  end if;
  insert into app.custody_operations(
    case_id,action,phase,idempotency_key,request_digest,command,reason,
    reauth_audit_event_id,actor_user_id,actor_service_identity_id,runner_instance_id
  ) values(
    p_case_id,p_action,'REQUESTED',p_idempotency_key,p_request_digest,p_command,
    btrim(p_reason),p_reauth_audit_event_id,p_actor_user_id,
    p_actor_service_identity_id,p_runner_instance_id
  ) returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase)
    values(v_op.id,'REQUESTED');
  insert into app.evidence_chain_heads(case_id,seal_status)
    values(p_case_id,'unsealed')
    on conflict(case_id) do update set
      seal_status=case when app.evidence_chain_heads.seal_status='violated'
        then 'violated' else 'unsealed' end,
      updated_at=now();
  update app.custody_operations set phase='GATE_BLOCKED',updated_at=now()
    where id=v_op.id returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase)
    values(v_op.id,'GATE_BLOCKED');
  return v_op;
end $$;

-- Preserve the proven Add/Seal implementation behind an owner-only function,
-- then restore the public service-role RPC name with an action gate. The gate
-- runs before the legacy function's COMPLETED replay branch and before any
-- evidence, manifest, event, object, or head mutation.
alter function app.custody_operation_commit_verified_seal(uuid,jsonb,text,text)
  rename to custody_operation_commit_verified_add_seal_v1;

create or replace function app.custody_operation_commit_verified_seal(
  p_operation_id uuid,p_items jsonb,p_examiner text,p_runner_instance_id text
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare
  v_case_id uuid;
  v_op app.custody_operations;
begin
  select case_id into v_case_id from app.custody_operations
    where id=p_operation_id;
  if not found then
    raise exception 'custody_operation_missing' using errcode='no_data_found';
  end if;
  -- Finalizers share only the case-first invariant. The Add/Seal inner
  -- finalizer owns and documents its action-specific row order.
  perform pg_advisory_xact_lock(hashtextextended(v_case_id::text,0));
  select * into v_op from app.custody_operations
    where id=p_operation_id for update;
  if v_op.action<>'ADD_SEAL' then
    raise exception 'custody_operation_finalizer_action_mismatch'
      using errcode='invalid_parameter_value';
  end if;
  select * into v_op from app.custody_operation_commit_verified_add_seal_v1(
    p_operation_id,p_items,p_examiner,p_runner_instance_id
  );
  return v_op;
end $$;

revoke execute on function app.custody_operation_reauth_event(text,text)
  from public,anon,authenticated;
revoke execute on function app.custody_operation_begin_or_resume(
  uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid
) from public,anon,authenticated;
revoke execute on function app.custody_operation_commit_verified_add_seal_v1(
  uuid,jsonb,text,text
) from public,anon,authenticated;
revoke execute on function app.custody_operation_commit_verified_seal(
  uuid,jsonb,text,text
) from public,anon,authenticated;

do $$ begin
  if exists(select 1 from pg_roles where rolname='service_role') then
    revoke execute on function app.custody_operation_commit_verified_add_seal_v1(
      uuid,jsonb,text,text
    ) from service_role;
    grant execute on function app.custody_operation_begin_or_resume(
      uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid
    ) to service_role;
    grant execute on function app.custody_operation_commit_verified_seal(
      uuid,jsonb,text,text
    ) to service_role;
  end if;
end $$;
