-- P4.23.5: case-scoped storage authority and externally read-only custody.
-- Raw mount paths/sources/options are never persisted. All identities are opaque SHA-256.

do $$ begin
  alter table app.evidence_custody_events
    drop constraint if exists evidence_custody_events_event_type_check;
  alter table app.evidence_custody_events
    add constraint evidence_custody_events_event_type_check check (event_type in (
      'EVIDENCE_DETECTED','EVIDENCE_REGISTERED','MANIFEST_SEALED','CHAIN_VERIFIED',
      'FILE_IGNORED','FILE_RETIRED','FILE_UNSEALED','CHAIN_VIOLATION',
      'STORAGE_PROFILE_CHANGED'));
end $$;

create table app.evidence_storage_authorities (
  case_id uuid primary key references app.cases(id) on delete cascade,
  profile text not null check (profile in ('LOCAL_IMMUTABLE','EXTERNALLY_READ_ONLY')),
  source_identity text null check (source_identity is null or source_identity ~ '^[0-9a-f]{64}$'),
  verified_mount_instance text null check (verified_mount_instance is null or verified_mount_instance ~ '^[0-9a-f]{64}$'),
  observed_mount_instance text null check (observed_mount_instance is null or observed_mount_instance ~ '^[0-9a-f]{64}$'),
  state text not null check (state in (
    'AVAILABLE','UNAVAILABLE','FULL_VERIFY_REQUIRED','IDENTITY_DRIFT','READ_WRITE_DRIFT',
    'CUSTODY_VIOLATION')),
  generation bigint not null default 1 check (generation > 0),
  verified_generation bigint null check (verified_generation is null or verified_generation > 0),
  read_only boolean null,
  last_observed_at timestamptz null,
  last_full_verified_at timestamptz null,
  remediation text not null default 'NONE' check (remediation in (
    'NONE','RECONNECT_AND_VERIFY','AUTHORIZE_SOURCE_CHANGE','RESTORE_READ_ONLY','FULL_VERIFY',
    'RESTORE_REACQUIRE_RETIRE')),
  updated_at timestamptz not null default now(),
  check ((profile='LOCAL_IMMUTABLE' and source_identity is null
          and verified_mount_instance is null and observed_mount_instance is null)
      or profile='EXTERNALLY_READ_ONLY')
);

insert into app.evidence_storage_authorities(case_id,profile,state,verified_generation)
select id,'LOCAL_IMMUTABLE','AVAILABLE',1 from app.cases on conflict(case_id) do nothing;

create function app.evidence_storage_authority_for_new_case() returns trigger
language plpgsql security definer set search_path=pg_catalog,app as $$
begin
  insert into app.evidence_storage_authorities(case_id,profile,state,verified_generation)
    values(new.id,'LOCAL_IMMUTABLE','AVAILABLE',1) on conflict(case_id) do nothing;
  return new;
end $$;
create trigger cases_evidence_storage_authority
  after insert on app.cases for each row execute function app.evidence_storage_authority_for_new_case();

alter table app.evidence_storage_authorities enable row level security;
alter table app.evidence_storage_authorities force row level security;
revoke all on app.evidence_storage_authorities from public,anon,authenticated;

create table app.evidence_storage_verifications (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  generation bigint not null check (generation > 0),
  profile text not null check (profile in ('LOCAL_IMMUTABLE','EXTERNALLY_READ_ONLY')),
  source_identity text null check (source_identity is null or source_identity ~ '^[0-9a-f]{64}$'),
  mount_instance text null check (mount_instance is null or mount_instance ~ '^[0-9a-f]{64}$'),
  manifest_version integer not null check (manifest_version >= 0),
  manifest_hash text not null,
  item_facts jsonb not null check (jsonb_typeof(item_facts)='array'),
  outcome text not null default 'SUCCESS' check (outcome in ('SUCCESS','FAILED')),
  issues jsonb not null default '[]'::jsonb check (jsonb_typeof(issues)='array'),
  correlation_id text not null check (length(correlation_id) between 1 and 128),
  actor_user_id uuid null references app.operator_profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  unique(case_id,correlation_id)
);
alter table app.evidence_storage_verifications enable row level security;
alter table app.evidence_storage_verifications force row level security;
create trigger evidence_storage_verifications_no_update_delete before update or delete
  on app.evidence_storage_verifications for each row execute function app.evidence_block_mutation();
create trigger evidence_storage_verifications_no_truncate before truncate
  on app.evidence_storage_verifications execute function app.evidence_block_truncate();
revoke all on app.evidence_storage_verifications from public,anon,authenticated;

alter table app.evidence_versions
  add column storage_profile text not null default 'LOCAL_IMMUTABLE'
    check (storage_profile in ('LOCAL_IMMUTABLE','EXTERNALLY_READ_ONLY')),
  add column storage_source_identity text null
    check (storage_source_identity is null or storage_source_identity ~ '^[0-9a-f]{64}$'),
  add column storage_mount_instance text null
    check (storage_mount_instance is null or storage_mount_instance ~ '^[0-9a-f]{64}$'),
  add constraint evidence_version_storage_facts_check check (
    (storage_profile='LOCAL_IMMUTABLE' and storage_source_identity is null
      and storage_mount_instance is null)
    or (storage_profile='EXTERNALLY_READ_ONLY' and storage_source_identity is not null
      and storage_mount_instance is not null));

create function app.custody_operation_begin_or_resume_storage_v3(
  p_case_id uuid,p_command jsonb,p_request_digest text,p_reason text,
  p_reauth_audit_event_id uuid,p_idempotency_key text,p_actor_user_id uuid,
  p_runner_instance_id text,p_resume_reauth_audit_event_id uuid
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_op app.custody_operations; v_reauth app.audit_events; v_resume app.audit_events;
  v_storage app.evidence_storage_authorities; v_binding jsonb; v_previous_runner text;
begin
  if p_command->>'action'<>'ADD_SEAL' or (p_command->>'schema_version')::integer<>3
     or p_command->>'storage_profile' not in ('LOCAL_IMMUTABLE','EXTERNALLY_READ_ONLY')
     or jsonb_typeof(p_command->'files')<>'array' or jsonb_array_length(p_command->'files')=0
     or length(btrim(coalesce(p_reason,''))) not between 1 and 1000
     or length(p_idempotency_key) not between 1 and 128 or p_actor_user_id is null
     or p_reauth_audit_event_id is null or length(btrim(coalesce(p_runner_instance_id,'')))=0
     or p_request_digest !~ '^sha256:[0-9a-f]{64}$' then
    raise exception 'invalid_custody_operation' using errcode='invalid_parameter_value';
  end if;
  v_binding:=jsonb_build_object('idempotency_key',p_idempotency_key,'reason',btrim(p_reason),
    'storage_profile',p_command->>'storage_profile','targets',(
      select jsonb_agg(x->>'path' order by x->>'path') from jsonb_array_elements(p_command->'files') x));
  select * into v_reauth from app.audit_events where id=p_reauth_audit_event_id for share;
  if not found or v_reauth.case_id is distinct from p_case_id
     or v_reauth.event_type<>'reauth.evidence_seal' or v_reauth.source<>'portal_reauth'
     or v_reauth.status<>'success' or v_reauth.actor_type<>'user'
     or v_reauth.actor_user_id is distinct from p_actor_user_id
     or v_reauth.actor_service_identity_id is not null
     or v_reauth.details->'binding' is distinct from v_binding then
    raise exception 'reauth_scope_mismatch' using errcode='invalid_authorization_specification';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  select * into v_storage from app.evidence_storage_authorities where case_id=p_case_id for update;
  if not found or v_storage.profile is distinct from p_command->>'storage_profile' then
    raise exception 'storage_profile_transition_required' using errcode='object_not_in_prerequisite_state';
  end if;
  if p_command->>'storage_profile'='EXTERNALLY_READ_ONLY'
     and exists(select 1 from app.evidence_objects where case_id=p_case_id and status='sealed')
     and (v_storage.state<>'AVAILABLE' or v_storage.verified_generation is distinct from v_storage.generation) then
    raise exception 'external_storage_full_verify_required' using errcode='object_not_in_prerequisite_state';
  end if;
  if exists(select 1 from app.evidence_chain_heads where case_id=p_case_id
      and (seal_status='violated' or exists(select 1 from jsonb_array_elements(
        coalesce(issues,'[]'::jsonb)) issue where issue->>'gate_state'='BLOCKED_VIOLATION')))
     or exists(select 1 from app.evidence_objects where case_id=p_case_id
       and (status='violated' or seal_status='violated')) then
    raise exception 'custody_violation_requires_recovery' using errcode='object_not_in_prerequisite_state';
  end if;
  select * into v_op from app.custody_operations
    where case_id=p_case_id and idempotency_key=p_idempotency_key for update;
  if found then
    if v_op.action<>'ADD_SEAL' or v_op.request_digest<>p_request_digest
       or v_op.command is distinct from p_command then
      raise exception 'idempotency_key_reused' using errcode='P4231';
    end if;
    if v_op.phase='COMPLETED' then return v_op; end if;
    if v_op.retired_runner_instance_ids ? p_runner_instance_id then
      raise exception 'custody_operation_retired_runner'
        using errcode='invalid_authorization_specification';
    end if;
    if v_op.phase not in ('GATE_BLOCKED','FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED','FAILED_RECOVERABLE')
       or p_resume_reauth_audit_event_id is null then
      raise exception 'custody_operation_not_resumable' using errcode='invalid_authorization_specification';
    end if;
    select * into v_resume from app.audit_events where id=p_resume_reauth_audit_event_id for share;
    if not found or v_resume.case_id is distinct from p_case_id
       or v_resume.event_type<>'reauth.evidence_seal_resume' or v_resume.source<>'portal_reauth'
       or v_resume.status<>'success' or v_resume.actor_type<>'user'
       or v_resume.actor_user_id is distinct from p_actor_user_id
       or v_resume.actor_service_identity_id is not null
       or v_resume.details->'binding' is distinct from jsonb_build_object('operation_id',v_op.id::text)
       or exists(select 1 from app.custody_operation_history
         where resume_reauth_audit_event_id=p_resume_reauth_audit_event_id) then
      raise exception 'resume_reauth_scope_mismatch' using errcode='invalid_authorization_specification';
    end if;
    insert into app.custody_operation_history(operation_id,phase,facts,resume_reauth_audit_event_id)
      values(v_op.id,v_op.phase,jsonb_build_object('resume_authorized',true),p_resume_reauth_audit_event_id);
    v_previous_runner:=v_op.runner_instance_id;
    update app.custody_operations set phase='GATE_BLOCKED',failed_from_phase=case
        when phase='FAILED_RECOVERABLE' then failed_from_phase else phase end,
      failure_code=null,runner_instance_id=p_runner_instance_id,
      retired_runner_instance_ids=case when v_previous_runner=p_runner_instance_id
        then retired_runner_instance_ids else retired_runner_instance_ids||jsonb_build_array(v_previous_runner) end,
      verified_facts='{}'::jsonb,updated_at=now() where id=v_op.id returning * into v_op;
    insert into app.custody_operation_history(operation_id,phase,facts)
      values(v_op.id,'GATE_BLOCKED',jsonb_build_object('resumed',true));
    return v_op;
  end if;
  if p_resume_reauth_audit_event_id is not null then
    raise exception 'resume_operation_not_found' using errcode='invalid_authorization_specification';
  end if;
  if exists(select 1 from app.custody_operations where case_id=p_case_id and phase<>'COMPLETED') then
    raise exception 'custody_operation_active' using errcode='object_in_use';
  end if;
  insert into app.custody_operations(case_id,action,phase,idempotency_key,request_digest,
    command,reason,reauth_audit_event_id,actor_user_id,runner_instance_id)
  values(p_case_id,'ADD_SEAL','REQUESTED',p_idempotency_key,p_request_digest,p_command,
    btrim(p_reason),p_reauth_audit_event_id,p_actor_user_id,p_runner_instance_id) returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase) values(v_op.id,'REQUESTED');
  insert into app.evidence_chain_heads(case_id,seal_status) values(p_case_id,'unsealed')
    on conflict(case_id) do update set seal_status=case when app.evidence_chain_heads.seal_status='violated'
      then 'violated' else 'unsealed' end,updated_at=now();
  update app.custody_operations set phase='GATE_BLOCKED',updated_at=now()
    where id=v_op.id returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase) values(v_op.id,'GATE_BLOCKED');
  return v_op;
end $$;

create function app.evidence_storage_record_verify_failure(
  p_case_id uuid,p_generation bigint,p_profile text,p_manifest_version integer,
  p_manifest_hash text,p_failure_code text,p_correlation_id text,p_actor_user_id uuid
) returns app.evidence_storage_authorities
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_row app.evidence_storage_authorities; v_head app.evidence_chain_heads;
  v_issue jsonb;
begin
  if p_failure_code not in ('STORAGE_UNAVAILABLE','READ_WRITE_DRIFT',
      'FULL_VERIFY_FAILED','MOUNTED_EVIDENCE_MISMATCH')
     or length(coalesce(p_correlation_id,'')) not between 1 and 128
     or p_actor_user_id is null then
    raise exception 'storage_verify_failure_invalid' using errcode='invalid_parameter_value';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  select * into v_row from app.evidence_storage_authorities where case_id=p_case_id for update;
  select * into v_head from app.evidence_chain_heads where case_id=p_case_id for update;
  if v_row.case_id is null or v_head.case_id is null
     or v_row.generation<>p_generation or v_row.profile<>p_profile
     or v_head.manifest_version is distinct from p_manifest_version
     or v_head.manifest_hash is distinct from p_manifest_hash then
    raise exception 'storage_verify_failure_stale' using errcode='serialization_failure';
  end if;
  v_issue:=jsonb_build_object('code',p_failure_code,'full_verification_required',true,
    'storage_generation',p_generation,
    'gate_state',case when p_failure_code='STORAGE_UNAVAILABLE' then 'BLOCKED_UNAVAILABLE'
      else 'BLOCKED_VIOLATION' end);
  insert into app.evidence_storage_verifications(case_id,generation,profile,source_identity,
    mount_instance,manifest_version,manifest_hash,item_facts,outcome,issues,correlation_id,actor_user_id)
  values(p_case_id,p_generation,p_profile,v_row.source_identity,v_row.observed_mount_instance,
    p_manifest_version,p_manifest_hash,'[]'::jsonb,'FAILED',jsonb_build_array(v_issue),
    p_correlation_id,p_actor_user_id);
  update app.evidence_storage_authorities set state=case
      when p_failure_code='STORAGE_UNAVAILABLE' then 'UNAVAILABLE'
      when p_failure_code='READ_WRITE_DRIFT' then 'READ_WRITE_DRIFT'
      else 'CUSTODY_VIOLATION' end,
    remediation=case when p_failure_code='STORAGE_UNAVAILABLE' then 'RECONNECT_AND_VERIFY'
      when p_failure_code='READ_WRITE_DRIFT' then 'RESTORE_READ_ONLY'
      else 'RESTORE_REACQUIRE_RETIRE' end,
    read_only=case when p_failure_code='READ_WRITE_DRIFT' then false else read_only end,
    last_observed_at=now(),updated_at=now() where case_id=p_case_id returning * into v_row;
  update app.evidence_chain_heads set seal_status=case
      when seal_status='violated' then 'violated'
      when p_failure_code='STORAGE_UNAVAILABLE' then seal_status else 'violated' end,
    issues=coalesce(issues,'[]'::jsonb)||jsonb_build_array(v_issue),updated_at=now()
    where case_id=p_case_id;
  return v_row;
end $$;

-- The source identity has different semantics from a mount instance: reconnecting the
-- same source may be verified, while a changed source requires an explicit profile
-- transition.  Extend the path-free observation vocabulary without weakening the
-- P4.23.4 shape, case, replay, or persisted-violation checks.
create function app.evidence_record_inventory_classification_v2(
  p_case_id uuid,p_correlation_id text,p_gate_state text,p_findings jsonb
) returns app.evidence_inventory_observations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_row app.evidence_inventory_observations; v_expected_gate text; v_generation bigint;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  if length(coalesce(p_correlation_id,'')) not between 1 and 128
     or p_gate_state not in ('OPEN','BLOCKED_PENDING','BLOCKED_VIOLATION','BLOCKED_UNAVAILABLE')
     or p_findings is null or jsonb_typeof(p_findings)<>'array'
     or exists(select 1 from jsonb_array_elements(p_findings) f where
       jsonb_typeof(f)<>'object'
       or not (f ?& array['code','gate_state','recovery','evidence_object_id',
         'observation_id','full_verification_required'])
       or jsonb_typeof(f->'code')<>'string' or jsonb_typeof(f->'gate_state')<>'string'
       or jsonb_typeof(f->'recovery')<>'string'
       or f->>'code' not in ('STORAGE_UNAVAILABLE','INVENTORY_SCAN_FAILED','MOUNT_IDENTITY_CHANGED',
         'STORAGE_SOURCE_CHANGED','STORAGE_FULL_VERIFY_REQUIRED','LEDGER_INVALID','CONFLICTING_AUTHORITY','CONFLICTING_OBSERVATION',
         'UNKNOWN_OBJECT_BINDING','DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM','SEALED_EVIDENCE_MISSING',
         'UNSAFE_SEALED_ENTRY','CONTENT_CHANGED','IDENTITY_CHANGED','FULL_VERIFY_REQUIRED',
         'POSTURE_DRIFT','PERSISTED_VIOLATION')
       or f->>'gate_state' not in ('BLOCKED_PENDING','BLOCKED_VIOLATION','BLOCKED_UNAVAILABLE')
       or f->>'recovery' not in ('INVESTIGATE_AVAILABILITY','RECONNECT_AND_VERIFY',
         'AUTHORIZE_STORAGE_SOURCE_CHANGE','RESTORE_READ_ONLY','REPAIR_LEDGER','OPERATOR_DISPOSITION',
         'RESTORE_REACQUIRE_RETIRE','FULL_VERIFY_AND_REPAIR')
       or jsonb_typeof(f->'evidence_object_id') not in ('string','null')
       or (f->'evidence_object_id'<>'null'::jsonb and coalesce(f->>'evidence_object_id','') !~
         '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')
       or jsonb_typeof(f->'observation_id') not in ('string','null')
       or (f->'observation_id'<>'null'::jsonb and coalesce(f->>'observation_id','') !~
         '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$')
       or jsonb_typeof(f->'full_verification_required')<>'boolean'
       or f->>'gate_state' is distinct from case
         when f->>'code' in ('DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM') then 'BLOCKED_PENDING'
         when f->>'code' in ('STORAGE_UNAVAILABLE','INVENTORY_SCAN_FAILED','MOUNT_IDENTITY_CHANGED',
           'STORAGE_FULL_VERIFY_REQUIRED')
           then 'BLOCKED_UNAVAILABLE' else 'BLOCKED_VIOLATION' end
       or exists(select 1 from jsonb_object_keys(f) k where k not in
         ('code','gate_state','recovery','evidence_object_id','observation_id','full_verification_required'))
     ) then raise exception 'invalid_inventory_classification' using errcode='invalid_parameter_value';
  end if;
  if (exists(select 1 from app.evidence_chain_heads h where h.case_id=p_case_id
      and h.seal_status='violated') or exists(select 1 from app.evidence_objects o
      where o.case_id=p_case_id and (o.status='violated' or o.seal_status='violated')))
     and (p_gate_state not in ('BLOCKED_VIOLATION','BLOCKED_UNAVAILABLE') or not exists(
       select 1 from jsonb_array_elements(p_findings) f where f->>'code'='PERSISTED_VIOLATION')) then
    raise exception 'persisted_custody_violation_requires_recovery'
      using errcode='object_not_in_prerequisite_state';
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
  select generation into v_generation from app.evidence_storage_authorities
    where case_id=p_case_id;
  insert into app.evidence_inventory_observations(case_id,correlation_id,gate_state,findings)
    values(p_case_id,p_correlation_id,p_gate_state,p_findings)
    on conflict(case_id,correlation_id) do nothing returning * into v_row;
  if not found then
    select * into v_row from app.evidence_inventory_observations
      where case_id=p_case_id and correlation_id=p_correlation_id;
    if v_row.gate_state is distinct from p_gate_state or v_row.findings is distinct from p_findings then
      raise exception 'inventory_correlation_reused' using errcode='unique_violation';
    end if;
  end if;
  update app.evidence_chain_heads set seal_status=case when p_gate_state='OPEN' then seal_status
      when p_gate_state='BLOCKED_PENDING' then 'unsealed' else 'violated' end,
    issues=(select coalesce(jsonb_agg(case when f->>'code' in ('STORAGE_UNAVAILABLE',
      'MOUNT_IDENTITY_CHANGED','STORAGE_SOURCE_CHANGED','STORAGE_FULL_VERIFY_REQUIRED','POSTURE_DRIFT')
      then f||jsonb_build_object('storage_generation',v_generation) else f end),'[]'::jsonb)
      from jsonb_array_elements(p_findings) f),updated_at=now() where case_id=p_case_id;
  return v_row;
end $$;

create function app.custody_operation_commit_verified_seal_storage_v3(
  p_operation_id uuid,p_items jsonb,p_examiner text,p_runner_instance_id text
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_case_id uuid; v_op app.custody_operations; v_head app.evidence_chain_heads;
  v_storage app.evidence_storage_authorities; v_item jsonb; v_obj app.evidence_objects;
  v_version uuid; v_manifest_version integer; v_manifest_hash text; v_new_facts jsonb;
  v_facts jsonb; v_verification_facts jsonb; v_result jsonb; v_manifest_id uuid; v_profile text;
  v_source text; v_mount text;
begin
  select case_id into v_case_id from app.custody_operations where id=p_operation_id;
  if not found then raise exception 'custody_operation_missing' using errcode='no_data_found'; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_case_id::text,0));
  select * into v_op from app.custody_operations where id=p_operation_id for update;
  if (v_op.command->>'schema_version')::integer=1
     and v_op.command->>'action'='ADD_SEAL' then
    return app.custody_operation_commit_verified_seal(
      p_operation_id,p_items,p_examiner,p_runner_instance_id);
  end if;
  v_profile:=v_op.command->>'storage_profile';
  if v_op.action<>'ADD_SEAL' or (v_op.command->>'schema_version')::integer<>3
     or v_profile not in ('LOCAL_IMMUTABLE','EXTERNALLY_READ_ONLY') then
    raise exception 'custody_operation_finalizer_action_mismatch' using errcode='invalid_parameter_value';
  end if;
  if v_op.runner_instance_id<>p_runner_instance_id then
    raise exception 'custody_operation_runner_conflict' using errcode='serialization_failure'; end if;
  if v_op.phase='COMPLETED' then return v_op; end if;
  if v_op.phase<>'FILESYSTEM_VERIFIED' or jsonb_typeof(p_items)<>'array'
     or jsonb_array_length(p_items)=0 or p_items is distinct from v_op.verified_facts->'items' then
    raise exception 'verified_seal_required' using errcode='invalid_parameter_value'; end if;
  select * into v_storage from app.evidence_storage_authorities where case_id=v_case_id for update;
  select * into v_head from app.evidence_chain_heads where case_id=v_case_id for update;
  if v_storage.case_id is null or v_head.case_id is null or v_storage.profile<>v_profile
     or v_head.seal_status='violated'
     or exists(select 1 from app.evidence_objects where case_id=v_case_id
       and (status='violated' or seal_status='violated')) then
    raise exception 'custody_violation_requires_recovery' using errcode='object_not_in_prerequisite_state';
  end if;
  if v_profile='LOCAL_IMMUTABLE' and exists(select 1 from jsonb_array_elements(p_items) x where
      x->>'storage_profile' is not null or x->>'sha256' !~ '^sha256:[0-9a-f]{64}$'
      or (x->>'bytes')::bigint<0 or x->>'owner'='' or x->>'mode'<>'0644'
      or coalesce((x->>'immutable')::boolean,false) is false or (x->>'st_nlink')::integer<>1) then
    raise exception 'verified_local_item_facts_invalid' using errcode='invalid_parameter_value';
  elsif v_profile='EXTERNALLY_READ_ONLY' then
    select min(x->>'storage_source_identity'),min(x->>'mount_instance_identity')
      into v_source,v_mount from jsonb_array_elements(p_items) x;
    if coalesce(v_source,'') !~ '^[0-9a-f]{64}$' or coalesce(v_mount,'') !~ '^[0-9a-f]{64}$'
       or exists(select 1 from jsonb_array_elements(p_items) x where
         x->>'storage_profile'<>'EXTERNALLY_READ_ONLY' or x->>'storage_source_identity'<>v_source
         or x->>'mount_instance_identity'<>v_mount or coalesce((x->>'read_only')::boolean,false) is false
         or x->>'sha256' !~ '^sha256:[0-9a-f]{64}$' or (x->>'bytes')::bigint<0
         or (x->>'st_nlink')::integer<>1 or x ? 'owner' or x ? 'mode' or x ? 'immutable')
       or (v_storage.source_identity is not null and v_storage.source_identity<>v_source) then
      raise exception 'verified_external_item_facts_invalid' using errcode='invalid_parameter_value';
    end if;
  end if;
  v_manifest_version:=coalesce(v_head.manifest_version,0)+1;
  select jsonb_agg(x||jsonb_build_object('evidence_version_id',gen_random_uuid())
    order by x->>'evidence_object_id') into v_new_facts from jsonb_array_elements(p_items) x;
  select jsonb_agg(f order by f->>'evidence_object_id') into v_facts from (
    select jsonb_build_object('evidence_object_id',o.id,'evidence_version_id',v.id,
      'sha256',v.sha256,'bytes',v.bytes,'display_path',o.display_path,'preserved_sibling',true) f
    from app.evidence_objects o join app.evidence_versions v on v.id=o.current_version_id
    where o.case_id=v_case_id and o.status='sealed' and not exists(
      select 1 from jsonb_array_elements(v_new_facts) x where (x->>'evidence_object_id')::uuid=o.id)
    union all select x from jsonb_array_elements(v_new_facts) x) all_facts;
  v_manifest_hash:='sha256:'||encode(sha256(convert_to(jsonb_build_object(
    'case_id',v_case_id,'manifest_version',v_manifest_version,'items',v_facts)::text,'UTF8')),'hex');
  insert into app.evidence_manifests(case_id,manifest_version,manifest_hash,operation_id,item_facts)
    values(v_case_id,v_manifest_version,v_manifest_hash,v_op.id,v_facts) returning id into v_manifest_id;
  for v_item in select * from jsonb_array_elements(v_new_facts) loop
    select * into v_obj from app.evidence_objects where id=(v_item->>'evidence_object_id')::uuid
      and case_id=v_case_id for update;
    if not found or v_obj.status not in ('detected','registered')
       or v_obj.display_path is distinct from v_item->>'path'
       or v_item->>'display_path' is distinct from v_item->>'path' then
      raise exception 'verified_item_binding_invalid' using errcode='data_exception'; end if;
    if v_obj.status='detected' then perform app.evidence_append_canonical_event_v1(
      v_op.id,v_obj.id,'EVIDENCE_REGISTERED',null,null,jsonb_build_object('status','detected'),
      jsonb_build_object('status','registered'),jsonb_build_object(
        'display_name',v_item->>'display_name','evidence_version_id',v_item->>'evidence_version_id',
        'manifest_id',v_manifest_id,'manifest_facts',v_facts)); end if;
    insert into app.evidence_versions(id,evidence_object_id,case_id,manifest_version,sha256,bytes,
      entry_status,manifest_hash,registered_by,metadata,custody_operation_id,storage_profile,
      storage_source_identity,storage_mount_instance)
    values((v_item->>'evidence_version_id')::uuid,v_obj.id,v_case_id,v_manifest_version,
      v_item->>'sha256',(v_item->>'bytes')::bigint,'ACTIVE',v_manifest_hash,p_examiner,
      jsonb_build_object('posture',case when v_profile='LOCAL_IMMUTABLE' then jsonb_build_object(
        'owner',v_item->>'owner','mode',v_item->>'mode','immutable',v_item->'immutable',
        'st_dev',v_item->'st_dev','st_ino',v_item->'st_ino','st_nlink',v_item->'st_nlink')
      else jsonb_build_object('read_only',true,'st_dev',v_item->'st_dev','st_ino',v_item->'st_ino',
        'st_nlink',v_item->'st_nlink') end),v_op.id,v_profile,
      case when v_profile='EXTERNALLY_READ_ONLY' then v_source else null end,
      case when v_profile='EXTERNALLY_READ_ONLY' then v_mount else null end) returning id into v_version;
    update app.evidence_objects set display_name=v_item->>'display_name',
      description=nullif(btrim(v_item->>'description'),''),source=nullif(btrim(v_item->>'source'),''),
      status='sealed',seal_status='sealed',current_version_id=v_version,current_sha256=v_item->>'sha256',
      current_bytes=(v_item->>'bytes')::bigint,sealed_by_user_id=coalesce(v_op.actor_user_id,sealed_by_user_id),
      sealed_at=now(),updated_at=now() where id=v_obj.id;
  end loop;
  if exists(select 1 from app.evidence_objects where case_id=v_case_id and status in ('detected','registered')) then
    raise exception 'pending_evidence_remains' using errcode='invalid_parameter_value'; end if;
  select jsonb_agg(f order by f->>'evidence_object_id') into v_verification_facts from (
    select x f from jsonb_array_elements(v_new_facts) x
    union all
    select x from app.evidence_storage_verifications sv
      cross join lateral jsonb_array_elements(sv.item_facts) x
      join app.evidence_objects o on o.id=(x->>'evidence_object_id')::uuid
        and o.case_id=v_case_id and o.current_version_id=(x->>'evidence_version_id')::uuid
      where sv.id=(select id from app.evidence_storage_verifications
        where case_id=v_case_id and generation=v_storage.generation and profile=v_profile
        order by created_at desc,id desc limit 1)
        and not exists(select 1 from jsonb_array_elements(v_new_facts) n
          where n->>'evidence_object_id'=x->>'evidence_object_id')
  ) verified;
  if v_profile='EXTERNALLY_READ_ONLY' and jsonb_array_length(v_verification_facts)<>
      (select count(*) from app.evidence_objects where case_id=v_case_id and status='sealed') then
    raise exception 'external_storage_full_verify_required'
      using errcode='object_not_in_prerequisite_state';
  end if;
  perform app.evidence_append_canonical_event_v1(v_op.id,null,'MANIFEST_SEALED',v_manifest_version,
    v_manifest_hash,jsonb_build_object('gate','BLOCKED_PENDING'),jsonb_build_object('gate','OPEN'),
    jsonb_build_object('manifest_id',v_manifest_id,'items',v_facts,'storage_profile',v_profile));
  if v_profile='EXTERNALLY_READ_ONLY' then
    update app.evidence_storage_authorities set source_identity=v_source,
      verified_mount_instance=v_mount,observed_mount_instance=v_mount,state='AVAILABLE',
      verified_generation=generation,read_only=true,last_observed_at=now(),last_full_verified_at=now(),
      remediation='NONE',updated_at=now() where case_id=v_case_id;
  end if;
  insert into app.evidence_storage_verifications(case_id,generation,profile,source_identity,
    mount_instance,manifest_version,manifest_hash,item_facts,correlation_id,actor_user_id)
  values(v_case_id,v_storage.generation,v_profile,case when v_profile='EXTERNALLY_READ_ONLY'
    then v_source else null end,case when v_profile='EXTERNALLY_READ_ONLY' then v_mount else null end,
    v_manifest_version,v_manifest_hash,v_verification_facts,'seal:'||v_op.id::text,v_op.actor_user_id);
  update app.evidence_chain_heads set manifest_version=v_manifest_version,manifest_hash=v_manifest_hash,
    seal_status='sealed',issues='[]'::jsonb,active_count=(select count(*) from app.evidence_objects
      where case_id=v_case_id and status='sealed'),last_verified_at=case when v_profile='EXTERNALLY_READ_ONLY'
      then now() else last_verified_at end,updated_at=now() where case_id=v_case_id;
  update app.custody_operations set phase='LEDGER_COMMITTED',updated_at=now() where id=v_op.id;
  insert into app.custody_operation_history(operation_id,phase) values(v_op.id,'LEDGER_COMMITTED');
  v_result:=jsonb_build_object('case_id',v_case_id,'manifest_version',v_manifest_version,
    'manifest_hash',v_manifest_hash,'seal_status','sealed','operation_id',v_op.id,
    'operation_phase','COMPLETED','storage_profile',v_profile);
  update app.custody_operations set phase='COMPLETED',result=v_result,completed_at=now(),updated_at=now()
    where id=v_op.id returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase) values(v_op.id,'COMPLETED');
  return v_op;
end $$;

create function app.evidence_storage_change_profile(
  p_case_id uuid,p_profile text,p_reason text,p_idempotency_key text,
  p_reauth_audit_event_id uuid,p_actor_user_id uuid
) returns app.evidence_storage_authorities
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_row app.evidence_storage_authorities; v_reauth app.audit_events;
begin
  if p_profile not in ('LOCAL_IMMUTABLE','EXTERNALLY_READ_ONLY')
     or length(btrim(coalesce(p_reason,''))) not between 1 and 1000
     or length(btrim(coalesce(p_idempotency_key,''))) not between 1 and 128
     or p_actor_user_id is null or p_reauth_audit_event_id is null then
    raise exception 'invalid_storage_profile_change' using errcode='invalid_parameter_value';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  if exists(select 1 from app.custody_operations where case_id=p_case_id and phase<>'COMPLETED') then
    raise exception 'custody_operation_active' using errcode='object_in_use';
  end if;
  select * into v_reauth from app.audit_events where id=p_reauth_audit_event_id for share;
  if not found or v_reauth.case_id is distinct from p_case_id
     or v_reauth.event_type<>'reauth.evidence_storage_profile_change'
     or v_reauth.source<>'portal_reauth' or v_reauth.status<>'success'
     or v_reauth.actor_type<>'user' or v_reauth.actor_user_id is distinct from p_actor_user_id
     or v_reauth.actor_service_identity_id is not null
     or v_reauth.details->'binding' is distinct from jsonb_build_object(
       'profile',p_profile,'reason',btrim(p_reason),'idempotency_key',btrim(p_idempotency_key)) then
    raise exception 'storage_profile_reauth_scope_mismatch'
      using errcode='invalid_authorization_specification';
  end if;
  if exists(select 1 from app.evidence_custody_events
            where reauth_audit_event_id=p_reauth_audit_event_id) then
    raise exception 'storage_profile_reauth_reused'
      using errcode='invalid_authorization_specification';
  end if;
  insert into app.evidence_storage_authorities(case_id,profile,state,generation,remediation)
  values(p_case_id,p_profile,'FULL_VERIFY_REQUIRED',1,'FULL_VERIFY')
  on conflict(case_id) do update set profile=excluded.profile,source_identity=null,
    verified_mount_instance=null,observed_mount_instance=null,state='FULL_VERIFY_REQUIRED',
    generation=app.evidence_storage_authorities.generation+1,verified_generation=null,
    read_only=null,last_full_verified_at=null,remediation='FULL_VERIFY',updated_at=now()
  returning * into v_row;
  insert into app.evidence_chain_heads(case_id,seal_status,issues) values(
    p_case_id,'unsealed',jsonb_build_array(jsonb_build_object(
      'code','STORAGE_PROFILE_CHANGED','recovery','FULL_VERIFY','storage_generation',v_row.generation)))
  on conflict(case_id) do update set seal_status=case
    when exists(select 1 from app.evidence_objects where case_id=p_case_id
      and (status='violated' or seal_status='violated'))
      or exists(select 1 from jsonb_array_elements(coalesce(
        app.evidence_chain_heads.issues,'[]'::jsonb)) issue where issue->>'code' not in (
        'STORAGE_UNAVAILABLE','MOUNT_IDENTITY_CHANGED','STORAGE_SOURCE_CHANGED',
        'STORAGE_FULL_VERIFY_REQUIRED','POSTURE_DRIFT','READ_WRITE_DRIFT','STORAGE_PROFILE_CHANGED'))
      then 'violated' else 'unsealed' end,
    issues=(select coalesce(jsonb_agg(issue),'[]'::jsonb) from jsonb_array_elements(
      coalesce(app.evidence_chain_heads.issues,'[]'::jsonb)) issue where issue->>'code' not in (
      'STORAGE_UNAVAILABLE','MOUNT_IDENTITY_CHANGED','STORAGE_SOURCE_CHANGED',
      'STORAGE_FULL_VERIFY_REQUIRED','POSTURE_DRIFT','READ_WRITE_DRIFT','STORAGE_PROFILE_CHANGED'))
      ||excluded.issues,updated_at=now();
  perform app.evidence_append_custody_event(p_case_id,null,'STORAGE_PROFILE_CHANGED',null,null,
    p_reauth_audit_event_id,p_actor_user_id,null,jsonb_build_object(
      'profile',p_profile,'reason',btrim(p_reason),'idempotency_key',btrim(p_idempotency_key),
      'generation',v_row.generation));
  return v_row;
end $$;

create function app.evidence_storage_record_observation(
  p_case_id uuid,p_profile text,p_available boolean,p_source_identity text,
  p_mount_instance text,p_read_only boolean
) returns app.evidence_storage_authorities
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_row app.evidence_storage_authorities;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  select * into v_row from app.evidence_storage_authorities where case_id=p_case_id for update;
  if not found or v_row.profile is distinct from p_profile then
    raise exception 'storage_profile_authority_mismatch' using errcode='invalid_parameter_value';
  end if;
  if p_profile='LOCAL_IMMUTABLE' then
    if p_source_identity is not null or p_mount_instance is not null or p_read_only is not null then
      raise exception 'local_storage_external_facts_forbidden' using errcode='invalid_parameter_value';
    end if;
    update app.evidence_storage_authorities set state=case when p_available then 'AVAILABLE' else 'UNAVAILABLE' end,
      remediation=case when p_available then 'NONE' else 'FULL_VERIFY' end,
      last_observed_at=now(),updated_at=now() where case_id=p_case_id returning * into v_row;
  else
    if not p_available then
      update app.evidence_storage_authorities set state='UNAVAILABLE',read_only=null,
        remediation='RECONNECT_AND_VERIFY',last_observed_at=now(),updated_at=now()
        where case_id=p_case_id returning * into v_row;
    elsif coalesce(p_source_identity,'') !~ '^[0-9a-f]{64}$'
       or coalesce(p_mount_instance,'') !~ '^[0-9a-f]{64}$' then
      raise exception 'external_storage_identity_invalid' using errcode='invalid_parameter_value';
    elsif p_read_only is not true then
      update app.evidence_storage_authorities set state='READ_WRITE_DRIFT',read_only=false,
        observed_mount_instance=p_mount_instance,remediation='RESTORE_READ_ONLY',
        last_observed_at=now(),updated_at=now() where case_id=p_case_id returning * into v_row;
    elsif v_row.source_identity is not null and v_row.source_identity<>p_source_identity then
      update app.evidence_storage_authorities set state='IDENTITY_DRIFT',read_only=true,
        observed_mount_instance=p_mount_instance,remediation='AUTHORIZE_SOURCE_CHANGE',
        last_observed_at=now(),updated_at=now() where case_id=p_case_id returning * into v_row;
    elsif v_row.verified_mount_instance is distinct from p_mount_instance
       or v_row.verified_generation is distinct from v_row.generation then
      update app.evidence_storage_authorities set state='FULL_VERIFY_REQUIRED',read_only=true,
        observed_mount_instance=p_mount_instance,remediation='RECONNECT_AND_VERIFY',
        last_observed_at=now(),updated_at=now() where case_id=p_case_id returning * into v_row;
    else
      update app.evidence_storage_authorities set state='AVAILABLE',read_only=true,
        observed_mount_instance=p_mount_instance,remediation='NONE',last_observed_at=now(),updated_at=now()
        where case_id=p_case_id returning * into v_row;
    end if;
  end if;
  return v_row;
end $$;

create function app.evidence_storage_commit_full_verify(
  p_case_id uuid,p_generation bigint,p_profile text,p_source_identity text,
  p_mount_instance text,p_read_only boolean,p_manifest_version integer,
  p_items jsonb,p_correlation_id text,p_actor_user_id uuid
) returns app.evidence_storage_authorities
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_row app.evidence_storage_authorities; v_head app.evidence_chain_heads;
begin
  if p_actor_user_id is null then
    raise exception 'storage_full_verify_operator_required'
      using errcode='invalid_authorization_specification';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  select * into v_row from app.evidence_storage_authorities where case_id=p_case_id for update;
  select * into v_head from app.evidence_chain_heads where case_id=p_case_id for update;
  if v_row.case_id is null or v_head.case_id is null
     or v_row.generation<>p_generation or v_row.profile<>p_profile
     or v_head.manifest_version is distinct from p_manifest_version then
    raise exception 'storage_full_verify_stale' using errcode='serialization_failure';
  end if;
  if jsonb_typeof(p_items)<>'array' or length(coalesce(p_correlation_id,'')) not between 1 and 128
     or exists(select 1 from jsonb_array_elements(p_items) x where
       coalesce(x->>'evidence_object_id','') !~ '^[0-9a-fA-F-]{36}$'
       or coalesce(x->>'evidence_version_id','') !~ '^[0-9a-fA-F-]{36}$'
       or x->>'sha256' !~ '^sha256:[0-9a-f]{64}$' or (x->>'bytes')::bigint<0
       or (x->>'st_nlink')::integer<>1)
     or exists(select 1 from app.evidence_objects o join app.evidence_versions v
       on v.id=o.current_version_id where o.case_id=p_case_id and o.status='sealed'
       and not exists(select 1 from jsonb_array_elements(p_items) x
         where (x->>'evidence_object_id')::uuid=o.id
           and (x->>'evidence_version_id')::uuid=v.id and x->>'sha256'=v.sha256
           and (x->>'bytes')::bigint=v.bytes))
     or jsonb_array_length(p_items)<>(select count(*) from app.evidence_objects
       where case_id=p_case_id and status='sealed') then
    raise exception 'storage_full_verify_items_invalid' using errcode='invalid_parameter_value';
  end if;
  if p_profile='EXTERNALLY_READ_ONLY' then
    if p_read_only is not true or coalesce(p_source_identity,'') !~ '^[0-9a-f]{64}$'
       or coalesce(p_mount_instance,'') !~ '^[0-9a-f]{64}$'
       or (v_row.source_identity is not null and v_row.source_identity<>p_source_identity)
       or exists(select 1 from jsonb_array_elements(p_items) x where
         x->>'storage_profile'<>'EXTERNALLY_READ_ONLY'
         or x->>'storage_source_identity'<>p_source_identity
         or x->>'mount_instance_identity'<>p_mount_instance
         or coalesce((x->>'read_only')::boolean,false) is false
         or x ? 'owner' or x ? 'mode' or x ? 'immutable') then
      raise exception 'external_full_verify_facts_invalid' using errcode='invalid_parameter_value';
    end if;
  elsif p_source_identity is not null or p_mount_instance is not null or p_read_only is not null
     or exists(select 1 from jsonb_array_elements(p_items) x where
       x ? 'storage_profile' or x ? 'storage_source_identity' or x ? 'mount_instance_identity'
       or x ? 'read_only' or x->>'mode'<>'0644'
       or coalesce((x->>'immutable')::boolean,false) is false) then
    raise exception 'local_full_verify_external_facts_forbidden' using errcode='invalid_parameter_value';
  end if;
  update app.evidence_storage_authorities set source_identity=case when p_profile='EXTERNALLY_READ_ONLY'
      then p_source_identity else null end,
    verified_mount_instance=case when p_profile='EXTERNALLY_READ_ONLY' then p_mount_instance else null end,
    observed_mount_instance=case when p_profile='EXTERNALLY_READ_ONLY' then p_mount_instance else null end,
    state='AVAILABLE',verified_generation=generation,read_only=case when p_profile='EXTERNALLY_READ_ONLY'
      then true else null end,last_observed_at=now(),last_full_verified_at=now(),
    remediation='NONE',updated_at=now() where case_id=p_case_id returning * into v_row;
  insert into app.evidence_storage_verifications(case_id,generation,profile,source_identity,
    mount_instance,manifest_version,manifest_hash,item_facts,correlation_id,actor_user_id)
  values(p_case_id,p_generation,p_profile,p_source_identity,p_mount_instance,p_manifest_version,
    v_head.manifest_hash,p_items,p_correlation_id,p_actor_user_id);
  update app.evidence_chain_heads set seal_status=case
      when exists(select 1 from app.evidence_objects where case_id=p_case_id
        and (status='violated' or seal_status='violated')) then 'violated'
      when seal_status='violated' and exists(select 1 from jsonb_array_elements(
        coalesce(app.evidence_chain_heads.issues,'[]'::jsonb)) issue
        where issue->>'code' not in ('STORAGE_UNAVAILABLE','MOUNT_IDENTITY_CHANGED',
          'STORAGE_SOURCE_CHANGED','STORAGE_FULL_VERIFY_REQUIRED','POSTURE_DRIFT',
          'READ_WRITE_DRIFT','STORAGE_PROFILE_CHANGED')
          or (issue->>'storage_generation')::bigint is distinct from p_generation) then 'violated'
      when exists(select 1 from app.evidence_objects where case_id=p_case_id
        and status in ('detected','registered')) then 'unsealed' else 'sealed' end,
    issues=(select coalesce(jsonb_agg(issue),'[]'::jsonb) from jsonb_array_elements(
      coalesce(app.evidence_chain_heads.issues,'[]'::jsonb)) issue
      where issue->>'code' not in ('STORAGE_UNAVAILABLE','MOUNT_IDENTITY_CHANGED',
        'STORAGE_FULL_VERIFY_REQUIRED','STORAGE_SOURCE_CHANGED','POSTURE_DRIFT',
        'READ_WRITE_DRIFT','STORAGE_PROFILE_CHANGED')
        or (issue->>'storage_generation')::bigint is distinct from p_generation),
    last_verified_at=now(),updated_at=now() where case_id=p_case_id;
  return v_row;
end $$;

revoke execute on function app.evidence_storage_change_profile(uuid,text,text,text,uuid,uuid)
  from public,anon,authenticated;
revoke execute on function app.evidence_storage_record_observation(uuid,text,boolean,text,text,boolean)
  from public,anon,authenticated;
revoke execute on function app.evidence_storage_commit_full_verify(uuid,bigint,text,text,text,boolean,integer,jsonb,text,uuid)
  from public,anon,authenticated;
revoke execute on function app.evidence_storage_record_verify_failure(uuid,bigint,text,integer,text,text,text,uuid)
  from public,anon,authenticated;
revoke execute on function app.evidence_record_inventory_classification_v2(uuid,text,text,jsonb)
  from public,anon,authenticated;
revoke execute on function app.evidence_storage_authority_for_new_case()
  from public,anon,authenticated;
do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  grant select on app.evidence_storage_authorities,app.evidence_storage_verifications to service_role;
  grant execute on function app.evidence_storage_change_profile(uuid,text,text,text,uuid,uuid) to service_role;
  grant execute on function app.evidence_storage_record_observation(uuid,text,boolean,text,text,boolean) to service_role;
  grant execute on function app.evidence_storage_commit_full_verify(uuid,bigint,text,text,text,boolean,integer,jsonb,text,uuid) to service_role;
  grant execute on function app.evidence_storage_record_verify_failure(uuid,bigint,text,integer,text,text,text,uuid)
    to service_role;
  grant execute on function app.evidence_record_inventory_classification_v2(uuid,text,text,jsonb)
    to service_role;
  grant execute on function app.custody_operation_begin_or_resume_storage_v3(
    uuid,jsonb,text,text,uuid,text,uuid,text,uuid) to service_role;
  grant execute on function app.custody_operation_commit_verified_seal_storage_v3(
    uuid,jsonb,text,text) to service_role;
end if; end $$;
revoke execute on function app.custody_operation_begin_or_resume_storage_v3(
  uuid,jsonb,text,text,uuid,text,uuid,text,uuid) from public,anon,authenticated;
revoke execute on function app.custody_operation_commit_verified_seal_storage_v3(
  uuid,jsonb,text,text) from public,anon,authenticated;
