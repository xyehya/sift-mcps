-- P4.23.2: durable, gate-first custody operations for operator Add/Seal.
-- MCP has no execute grant and no route to these functions.

create table app.custody_operations (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  action text not null,
  phase text not null,
  idempotency_key text not null,
  request_digest text not null,
  command jsonb not null,
  reason text not null,
  reauth_audit_event_id uuid not null references app.audit_events(id),
  actor_user_id uuid null references app.operator_profiles(id) on delete set null,
  actor_service_identity_id uuid null references app.service_identities(id) on delete set null,
  failed_from_phase text null,
  failure_code text null,
  runner_instance_id text not null,
  retired_runner_instance_ids jsonb not null default '[]'::jsonb,
  prepared_facts jsonb not null default '{}'::jsonb,
  verified_facts jsonb not null default '{}'::jsonb,
  result jsonb null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  completed_at timestamptz null,
  constraint custody_operations_action_check check (action = 'ADD_SEAL'),
  constraint custody_operations_phase_check check (phase in (
    'REQUESTED','GATE_BLOCKED','FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',
    'LEDGER_COMMITTED','COMPLETED','FAILED_RECOVERABLE'
  )),
  constraint custody_operations_reason_check check (length(btrim(reason)) between 1 and 1000),
  constraint custody_operations_key_check check (length(idempotency_key) between 1 and 128),
  constraint custody_operations_digest_check check (request_digest ~ '^sha256:[0-9a-f]{64}$'),
  unique (case_id, idempotency_key),
  unique (reauth_audit_event_id)
);

create unique index custody_operations_one_nonterminal_per_case
  on app.custody_operations(case_id) where phase <> 'COMPLETED';
create unique index audit_reauth_bound_intent_key
  on app.audit_events(case_id,event_type,actor_type,
    coalesce(actor_user_id,'00000000-0000-0000-0000-000000000000'::uuid),
    coalesce(actor_service_identity_id,'00000000-0000-0000-0000-000000000000'::uuid),
    ((details->'binding'->>'idempotency_key')))
  where source='portal_reauth' and details->'binding'->>'idempotency_key' is not null;

create table app.custody_operation_history (
  id bigint generated always as identity primary key,
  operation_id uuid not null references app.custody_operations(id) on delete cascade,
  phase text not null,
  facts jsonb not null default '{}'::jsonb,
  resume_reauth_audit_event_id uuid null unique references app.audit_events(id),
  created_at timestamptz not null default now(),
  constraint custody_operation_history_phase_check check (phase in (
    'REQUESTED','GATE_BLOCKED','FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',
    'LEDGER_COMMITTED','COMPLETED','FAILED_RECOVERABLE'
  ))
);

create table app.evidence_manifests (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  manifest_version integer not null check (manifest_version > 0),
  manifest_hash text not null check (manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  operation_id uuid not null unique references app.custody_operations(id),
  item_facts jsonb not null,
  created_at timestamptz not null default now(),
  unique(case_id, manifest_version)
);

alter table app.evidence_versions
  add column if not exists custody_operation_id uuid null references app.custody_operations(id);
create unique index if not exists evidence_versions_operation_object_key
  on app.evidence_versions(custody_operation_id, evidence_object_id)
  where custody_operation_id is not null;
create unique index if not exists evidence_versions_object_manifest_key
  on app.evidence_versions(evidence_object_id, manifest_version);

alter table app.evidence_custody_events
  add column if not exists custody_operation_id uuid null references app.custody_operations(id),
  add column if not exists canonical_schema text null,
  add column if not exists canonical_material jsonb null;
create unique index if not exists evidence_events_operation_type_object_key
  on app.evidence_custody_events(custody_operation_id, event_type, coalesce(evidence_object_id, '00000000-0000-0000-0000-000000000000'::uuid))
  where custody_operation_id is not null;

alter table app.custody_operations enable row level security;
alter table app.custody_operations force row level security;
alter table app.custody_operation_history enable row level security;
alter table app.custody_operation_history force row level security;
alter table app.evidence_manifests enable row level security;
alter table app.evidence_manifests force row level security;

create policy custody_operations_case_member_select on app.custody_operations
  for select using (exists (
    select 1 from app.case_members cm join app.operator_profiles op on op.id=cm.operator_profile_id
    where cm.case_id=custody_operations.case_id and cm.status='active' and op.auth_user_id=auth.uid()
  ));
create policy custody_operation_history_case_member_select on app.custody_operation_history
  for select using (exists (
    select 1 from app.custody_operations co join app.case_members cm on cm.case_id=co.case_id
      join app.operator_profiles op on op.id=cm.operator_profile_id
    where co.id=custody_operation_history.operation_id and cm.status='active' and op.auth_user_id=auth.uid()
  ));
create policy evidence_manifests_case_member_select on app.evidence_manifests
  for select using (exists (
    select 1 from app.case_members cm join app.operator_profiles op on op.id=cm.operator_profile_id
    where cm.case_id=evidence_manifests.case_id and cm.status='active' and op.auth_user_id=auth.uid()
  ));

create trigger custody_operations_no_update_delete
  before delete on app.custody_operations for each row execute function app.evidence_block_mutation();
create trigger custody_operation_history_no_update_delete
  before update or delete on app.custody_operation_history for each row execute function app.evidence_block_mutation();
create trigger evidence_manifests_no_update_delete
  before update or delete on app.evidence_manifests for each row execute function app.evidence_block_mutation();

create or replace function app.evidence_block_truncate()
returns trigger language plpgsql set search_path=pg_catalog,app as $$
begin raise exception 'append-only: TRUNCATE on % is not permitted',tg_table_name
  using errcode='restrict_violation'; end $$;
create trigger custody_operation_history_no_truncate before truncate on app.custody_operation_history
  for each statement execute function app.evidence_block_truncate();
create trigger evidence_manifests_no_truncate before truncate on app.evidence_manifests
  for each statement execute function app.evidence_block_truncate();
-- evidence_versions/evidence_custody_events already have the canonical
-- no-TRUNCATE guards from 202606141400_harden_append_only_chains.sql.  Reuse
-- those accumulated-migration triggers; do not create duplicate names here.

create or replace function app.custody_operation_begin_or_resume(
  p_case_id uuid, p_action text, p_command jsonb, p_request_digest text,
  p_reason text, p_reauth_audit_event_id uuid, p_idempotency_key text,
  p_actor_user_id uuid, p_actor_service_identity_id uuid, p_runner_instance_id text,
  p_resume_reauth_audit_event_id uuid
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_op app.custody_operations; v_reauth app.audit_events; v_resume app.audit_events; v_binding jsonb;
begin
  if p_action <> 'ADD_SEAL' or length(btrim(coalesce(p_reason,'')))=0
     or length(p_idempotency_key) not between 1 and 128
     or p_reauth_audit_event_id is null or p_actor_user_id is null
     or p_actor_service_identity_id is not null
     or length(btrim(coalesce(p_runner_instance_id,'')))=0 then
    raise exception 'invalid_custody_operation' using errcode='invalid_parameter_value';
  end if;
  v_binding:=jsonb_build_object('idempotency_key',p_idempotency_key,'reason',btrim(p_reason),
    'targets',(select jsonb_agg(x->>'path' order by x->>'path') from jsonb_array_elements(p_command->'files') x));
  select * into v_reauth from app.audit_events where id=p_reauth_audit_event_id for share;
  if not found or v_reauth.case_id is distinct from p_case_id
     or v_reauth.event_type<>'reauth.evidence_seal' or v_reauth.source<>'portal_reauth'
     or v_reauth.status<>'success' or v_reauth.actor_type<>'user'
     or v_reauth.actor_user_id is distinct from p_actor_user_id
     or v_reauth.actor_service_identity_id is distinct from p_actor_service_identity_id
     or v_reauth.details->'binding' is distinct from v_binding then
    raise exception 'reauth_scope_mismatch' using errcode='invalid_authorization_specification';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  if exists(select 1 from app.evidence_chain_heads h where h.case_id=p_case_id
      and (h.seal_status='violated' or coalesce(h.issues,'[]'::jsonb)<>'[]'::jsonb))
     or exists(select 1 from app.evidence_objects o where o.case_id=p_case_id
      and (o.status='violated' or o.seal_status='violated')) then
    raise exception 'custody_violation_requires_recovery' using errcode='object_not_in_prerequisite_state';
  end if;
  select * into v_op from app.custody_operations
    where case_id=p_case_id and idempotency_key=p_idempotency_key for update;
  if found then
    if v_op.request_digest <> p_request_digest then
      raise exception 'idempotency_key_reused' using errcode='P4231';
    end if;
    if v_op.retired_runner_instance_ids ? p_runner_instance_id then
      raise exception 'custody_operation_retired_runner' using errcode='P4232';
    end if;
    if v_op.runner_instance_id<>p_runner_instance_id
       and v_op.phase in ('GATE_BLOCKED','FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED','FAILED_RECOVERABLE')
       and p_resume_reauth_audit_event_id is null then
      raise exception 'resume_reauth_required' using errcode='invalid_authorization_specification';
    end if;
    if p_resume_reauth_audit_event_id is not null then
      select * into v_resume from app.audit_events where id=p_resume_reauth_audit_event_id for share;
      if not found or v_resume.case_id is distinct from v_op.case_id
         or v_resume.event_type<>'reauth.evidence_seal_resume'
         or v_resume.source<>'portal_reauth' or v_resume.status<>'success'
         or v_resume.actor_type<>'user'
         or v_resume.actor_user_id is distinct from v_op.actor_user_id
         or v_resume.actor_service_identity_id is not null
         or v_resume.details->'binding' is distinct from jsonb_build_object('operation_id',v_op.id::text) then
        raise exception 'resume_reauth_scope_mismatch' using errcode='invalid_authorization_specification';
      end if;
      if exists(select 1 from app.custody_operation_history h
                where h.resume_reauth_audit_event_id=p_resume_reauth_audit_event_id) then
        raise exception 'resume_reauth_reused' using errcode='invalid_authorization_specification';
      end if;
      begin
        insert into app.custody_operation_history(
          operation_id,phase,facts,resume_reauth_audit_event_id)
        values(v_op.id,v_op.phase,jsonb_build_object('resume_authorized',true),p_resume_reauth_audit_event_id);
      exception
        when unique_violation then
          raise exception 'resume_reauth_reused' using errcode='invalid_authorization_specification';
      end;
    end if;
    if v_op.phase='GATE_BLOCKED' and v_op.runner_instance_id<>p_runner_instance_id then
      update app.custody_operations set runner_instance_id=p_runner_instance_id,
        retired_runner_instance_ids=retired_runner_instance_ids||jsonb_build_array(v_op.runner_instance_id),updated_at=now()
        where id=v_op.id and phase='GATE_BLOCKED' returning * into v_op;
      insert into app.custody_operation_history(operation_id,phase,facts)
        values(v_op.id,'GATE_BLOCKED',jsonb_build_object('runner_claimed',true));
    elsif v_op.phase in ('FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED') then
      if v_op.runner_instance_id=p_runner_instance_id then
        raise exception 'custody_operation_same_runner_active' using errcode='P4232';
      end if;
      update app.custody_operations set phase='FAILED_RECOVERABLE',
        failed_from_phase=v_op.phase,failure_code='runner_interrupted',updated_at=now()
        where id=v_op.id and phase=v_op.phase returning * into v_op;
      insert into app.custody_operation_history(operation_id,phase,facts)
        values(v_op.id,'FAILED_RECOVERABLE',jsonb_build_object(
          'failed_from',v_op.failed_from_phase,'code','runner_interrupted'));
    end if;
    if v_op.phase='FAILED_RECOVERABLE' then
      update app.custody_operations set phase='GATE_BLOCKED', failure_code=null,
        runner_instance_id=p_runner_instance_id,
        retired_runner_instance_ids=case when runner_instance_id=p_runner_instance_id
          then retired_runner_instance_ids else retired_runner_instance_ids||jsonb_build_array(runner_instance_id) end,
        verified_facts=case when failed_from_phase='FILESYSTEM_VERIFIED'
          then '{}'::jsonb else verified_facts end,
        updated_at=now()
        where id=v_op.id and phase='FAILED_RECOVERABLE' returning * into v_op;
      insert into app.custody_operation_history(operation_id,phase,facts)
        values(v_op.id,'GATE_BLOCKED',jsonb_build_object('resumed',true,
          'resumed_from',v_op.failed_from_phase));
    end if;
    return v_op;
  end if;
  if p_resume_reauth_audit_event_id is not null then
    raise exception 'resume_operation_not_found' using errcode='invalid_authorization_specification';
  end if;
  insert into app.custody_operations(case_id,action,phase,idempotency_key,request_digest,
    command,reason,reauth_audit_event_id,actor_user_id,actor_service_identity_id,runner_instance_id)
  values(p_case_id,p_action,'REQUESTED',p_idempotency_key,p_request_digest,p_command,
    btrim(p_reason),p_reauth_audit_event_id,p_actor_user_id,p_actor_service_identity_id,p_runner_instance_id)
  returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase) values(v_op.id,'REQUESTED');
  insert into app.evidence_chain_heads(case_id,seal_status) values(p_case_id,'unsealed')
    on conflict(case_id) do update set
      seal_status=case when app.evidence_chain_heads.seal_status='violated'
        then 'violated' else 'unsealed' end,updated_at=now();
  update app.custody_operations set phase='GATE_BLOCKED',updated_at=now()
    where id=v_op.id returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase) values(v_op.id,'GATE_BLOCKED');
  return v_op;
end $$;

create or replace function app.custody_operation_advance(
  p_operation_id uuid,p_expected text,p_target text,p_facts jsonb,p_runner_instance_id text
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_op app.custody_operations;
begin
  select * into v_op from app.custody_operations where id=p_operation_id for update;
  if not found or v_op.phase<>p_expected or v_op.runner_instance_id<>p_runner_instance_id then
    raise exception 'custody_operation_phase_conflict' using errcode='serialization_failure';
  end if;
  if not ((p_expected='GATE_BLOCKED' and p_target='FILESYSTEM_APPLYING') or
          (p_expected='FILESYSTEM_APPLYING' and p_target='FILESYSTEM_VERIFIED')) then
    raise exception 'custody_operation_transition_forbidden' using errcode='invalid_parameter_value';
  end if;
  if p_target='FILESYSTEM_APPLYING' and v_op.prepared_facts<>'{}'::jsonb
     and v_op.prepared_facts is distinct from coalesce(p_facts,'{}') then
    raise exception 'prepared_facts_mismatch' using errcode='data_exception';
  end if;
  if p_target='FILESYSTEM_VERIFIED' and v_op.verified_facts<>'{}'::jsonb
     and v_op.verified_facts is distinct from coalesce(p_facts,'{}') then
    raise exception 'verified_facts_mismatch' using errcode='data_exception';
  end if;
  update app.custody_operations set phase=p_target,
    prepared_facts=case when p_target='FILESYSTEM_APPLYING' then coalesce(p_facts,'{}') else prepared_facts end,
    verified_facts=case when p_target='FILESYSTEM_VERIFIED' then coalesce(p_facts,'{}') else verified_facts end,
    updated_at=now() where id=p_operation_id returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase,facts)
    values(p_operation_id,p_target,coalesce(p_facts,'{}'));
  return v_op;
end $$;

create or replace function app.custody_operation_fail(
  p_operation_id uuid,p_expected text,p_failure_code text,p_runner_instance_id text
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_op app.custody_operations;
begin
  update app.custody_operations set phase='FAILED_RECOVERABLE',failed_from_phase=p_expected,
    failure_code=left(regexp_replace(coalesce(p_failure_code,'failure'),'[^a-zA-Z0-9_.-]','','g'),96),
    updated_at=now() where id=p_operation_id and phase=p_expected
      and runner_instance_id=p_runner_instance_id returning * into v_op;
  if not found then
    raise exception 'custody_operation_phase_conflict' using errcode='serialization_failure';
  end if;
  update app.evidence_chain_heads set
    seal_status=case when seal_status='violated' then 'violated' else 'unsealed' end,
    updated_at=now() where case_id=v_op.case_id;
  insert into app.custody_operation_history(operation_id,phase,facts)
    values(v_op.id,'FAILED_RECOVERABLE',jsonb_build_object('failed_from',p_expected,'code',v_op.failure_code));
  return v_op;
end $$;

create or replace function app.evidence_append_canonical_event_v1(
  p_operation_id uuid,p_evidence_object_id uuid,p_event_type text,p_manifest_version integer,
  p_manifest_hash text,p_before jsonb,p_after jsonb,p_details jsonb
) returns uuid
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_op app.custody_operations; v_seq bigint; v_prev text; v_at timestamptz;
  v_material jsonb; v_hash text; v_id uuid;
begin
  select * into v_op from app.custody_operations where id=p_operation_id for update;
  select head_seq,head_hash into v_seq,v_prev from app.evidence_chain_heads
    where case_id=v_op.case_id for update;
  v_seq:=coalesce(v_seq,0)+1; v_prev:=coalesce(v_prev,''); v_at:=clock_timestamp();
  v_material:=jsonb_build_object(
    'schema','canonical_event_v1','event_type',p_event_type,'operation_id',v_op.id,
    'case_id',v_op.case_id,'action',v_op.action,'evidence_object_id',p_evidence_object_id,
    'manifest_version',p_manifest_version,'manifest_hash',p_manifest_hash,
    'actor_user_id',v_op.actor_user_id,'actor_service_identity_id',v_op.actor_service_identity_id,
    'reason',v_op.reason,'reauth_audit_event_id',v_op.reauth_audit_event_id,
    'before',coalesce(p_before,'{}'),'after',coalesce(p_after,'{}'),
    'details',coalesce(p_details,'{}'),'db_timestamp',to_char(v_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'seq',v_seq,'prev_hash',v_prev);
  v_hash:='sha256:'||encode(sha256(convert_to(v_material::text,'UTF8')),'hex');
  insert into app.evidence_custody_events(case_id,evidence_object_id,seq,event_type,
    manifest_version,prev_hash,event_hash,reauth_audit_event_id,actor_user_id,
    actor_service_identity_id,details,created_at,custody_operation_id,canonical_schema,canonical_material)
  values(v_op.case_id,p_evidence_object_id,v_seq,p_event_type,p_manifest_version,v_prev,v_hash,
    v_op.reauth_audit_event_id,v_op.actor_user_id,v_op.actor_service_identity_id,
    coalesce(p_details,'{}'),v_at,v_op.id,'canonical_event_v1',v_material) returning id into v_id;
  update app.evidence_chain_heads set head_seq=v_seq,head_hash=v_hash,last_event_type=p_event_type,
    updated_at=now() where case_id=v_op.case_id;
  return v_id;
end $$;

create or replace function app.custody_operation_commit_verified_seal(
  p_operation_id uuid,p_items jsonb,p_examiner text,p_runner_instance_id text
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_op app.custody_operations; v_head app.evidence_chain_heads; v_item jsonb;
  v_obj app.evidence_objects; v_version uuid; v_manifest_version integer;
  v_manifest_hash text; v_new_facts jsonb; v_facts jsonb; v_result jsonb; v_manifest_id uuid;
begin
  select * into v_op from app.custody_operations where id=p_operation_id for update;
  if v_op.runner_instance_id<>p_runner_instance_id then
    raise exception 'custody_operation_runner_conflict' using errcode='serialization_failure'; end if;
  if v_op.phase='COMPLETED' then return v_op; end if;
  if v_op.phase<>'FILESYSTEM_VERIFIED' or jsonb_typeof(p_items)<>'array' or jsonb_array_length(p_items)=0 then
    raise exception 'verified_seal_required' using errcode='invalid_parameter_value'; end if;
  if p_items is distinct from v_op.verified_facts->'items' then
    raise exception 'verified_facts_mismatch' using errcode='data_exception'; end if;
  select * into v_head from app.evidence_chain_heads where case_id=v_op.case_id for update;
  if v_head.seal_status='violated' or coalesce(v_head.issues,'[]'::jsonb)<>'[]'::jsonb
     or exists(select 1 from app.evidence_objects o where o.case_id=v_op.case_id
       and (o.status='violated' or o.seal_status='violated')) then
    raise exception 'custody_violation_requires_recovery' using errcode='object_not_in_prerequisite_state';
  end if;
  v_manifest_version:=coalesce(v_head.manifest_version,0)+1;
  select jsonb_agg(x || jsonb_build_object('evidence_version_id',gen_random_uuid())
                   order by x->>'evidence_object_id') into v_new_facts
    from jsonb_array_elements(p_items) x;
  if exists(select 1 from jsonb_array_elements(p_items) x where
    x->>'sha256' !~ '^sha256:[0-9a-f]{64}$' or (x->>'bytes')::bigint<0 or
    x->>'owner'='' or x->>'mode'<>'0644' or coalesce((x->>'immutable')::boolean,false) is false or
    (x->>'st_nlink')::integer<>1) then
    raise exception 'verified_item_facts_invalid' using errcode='invalid_parameter_value'; end if;
  select jsonb_agg(f order by f->>'evidence_object_id') into v_facts from (
    select jsonb_build_object('evidence_object_id',o.id,'evidence_version_id',v.id,
      'sha256',v.sha256,'bytes',v.bytes,'display_path',o.display_path,'preserved_sibling',true) f
    from app.evidence_objects o join app.evidence_versions v on v.id=o.current_version_id
    where o.case_id=v_op.case_id and o.status='sealed'
      and not exists(select 1 from jsonb_array_elements(v_new_facts) x
                     where (x->>'evidence_object_id')::uuid=o.id)
    union all
    select x from jsonb_array_elements(v_new_facts) x
  ) all_facts;
  v_manifest_hash:='sha256:'||encode(sha256(convert_to(jsonb_build_object(
    'case_id',v_op.case_id,'manifest_version',v_manifest_version,'items',v_facts)::text,'UTF8')),'hex');
  insert into app.evidence_manifests(case_id,manifest_version,manifest_hash,operation_id,item_facts)
    values(v_op.case_id,v_manifest_version,v_manifest_hash,v_op.id,v_facts) returning id into v_manifest_id;
  for v_item in select * from jsonb_array_elements(v_new_facts) loop
    select * into v_obj from app.evidence_objects where id=(v_item->>'evidence_object_id')::uuid
      and case_id=v_op.case_id for update;
    if not found or v_obj.status not in ('detected','registered') then
      raise exception 'evidence_not_pending' using errcode='invalid_parameter_value'; end if;
    if v_obj.display_path is distinct from v_item->>'path'
       or v_item->>'display_path' is distinct from v_item->>'path' then
      raise exception 'verified_item_path_mismatch' using errcode='data_exception'; end if;
    if v_obj.status='detected' then
      perform app.evidence_append_canonical_event_v1(v_op.id,v_obj.id,'EVIDENCE_REGISTERED',null,null,
        jsonb_build_object('status','detected'),jsonb_build_object('status','registered'),
        jsonb_build_object('display_name',v_item->>'display_name',
          'evidence_version_id',v_item->>'evidence_version_id','manifest_id',v_manifest_id,
          'manifest_facts',v_facts));
    end if;
    insert into app.evidence_versions(id,evidence_object_id,case_id,manifest_version,sha256,bytes,
      entry_status,manifest_hash,registered_by,metadata,custody_operation_id)
    values((v_item->>'evidence_version_id')::uuid,v_obj.id,v_op.case_id,v_manifest_version,v_item->>'sha256',(v_item->>'bytes')::bigint,
      'ACTIVE',v_manifest_hash,p_examiner,jsonb_build_object('posture',jsonb_build_object(
      'owner',v_item->>'owner','mode',v_item->>'mode','immutable',v_item->'immutable',
      'st_dev',v_item->'st_dev','st_ino',v_item->'st_ino','st_nlink',v_item->'st_nlink')),v_op.id)
    returning id into v_version;
    update app.evidence_objects set display_name=v_item->>'display_name',
      description=nullif(btrim(v_item->>'description'),''),source=nullif(btrim(v_item->>'source'),''),
      status='sealed',seal_status='sealed',current_version_id=v_version,
      current_sha256=v_item->>'sha256',current_bytes=(v_item->>'bytes')::bigint,
      sealed_by_user_id=coalesce(v_op.actor_user_id,sealed_by_user_id),sealed_at=now(),updated_at=now()
      where id=v_obj.id;
  end loop;
  if exists(select 1 from app.evidence_objects where case_id=v_op.case_id and status in ('detected','registered')) then
    raise exception 'pending_evidence_remains' using errcode='invalid_parameter_value'; end if;
  perform app.evidence_append_canonical_event_v1(v_op.id,null,'MANIFEST_SEALED',v_manifest_version,
    v_manifest_hash,jsonb_build_object('gate','BLOCKED_PENDING'),jsonb_build_object('gate','OPEN'),
    jsonb_build_object('manifest_id',v_manifest_id,'items',v_facts));
  update app.evidence_chain_heads set manifest_version=v_manifest_version,manifest_hash=v_manifest_hash,
    seal_status='sealed',active_count=(select count(*) from app.evidence_objects where case_id=v_op.case_id and status='sealed'),
    updated_at=now() where case_id=v_op.case_id;
  update app.custody_operations set phase='LEDGER_COMMITTED',updated_at=now() where id=v_op.id;
  insert into app.custody_operation_history(operation_id,phase) values(v_op.id,'LEDGER_COMMITTED');
  v_result:=jsonb_build_object('case_id',v_op.case_id,'manifest_version',v_manifest_version,
    'manifest_hash',v_manifest_hash,'seal_status','sealed','operation_id',v_op.id,'operation_phase','COMPLETED');
  update app.custody_operations set phase='COMPLETED',result=v_result,completed_at=now(),updated_at=now()
    where id=v_op.id returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase) values(v_op.id,'COMPLETED');
  return v_op;
end $$;

revoke all on app.custody_operations,app.custody_operation_history,app.evidence_manifests from public,anon,authenticated;
revoke execute on function app.custody_operation_begin_or_resume(uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid) from public,anon,authenticated;
revoke execute on function app.custody_operation_advance(uuid,text,text,jsonb,text) from public,anon,authenticated;
revoke execute on function app.custody_operation_fail(uuid,text,text,text) from public,anon,authenticated;
revoke execute on function app.evidence_append_canonical_event_v1(uuid,uuid,text,integer,text,jsonb,jsonb,jsonb) from public,anon,authenticated;
revoke execute on function app.custody_operation_commit_verified_seal(uuid,jsonb,text,text) from public,anon,authenticated;
do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  grant select on app.custody_operations,app.custody_operation_history,app.evidence_manifests to service_role;
  grant execute on function app.custody_operation_begin_or_resume(uuid,text,jsonb,text,text,uuid,text,uuid,uuid,text,uuid) to service_role;
  grant execute on function app.custody_operation_advance(uuid,text,text,jsonb,text) to service_role;
  grant execute on function app.custody_operation_fail(uuid,text,text,text) to service_role;
  grant execute on function app.custody_operation_commit_verified_seal(uuid,jsonb,text,text) to service_role;
end if; end $$;
