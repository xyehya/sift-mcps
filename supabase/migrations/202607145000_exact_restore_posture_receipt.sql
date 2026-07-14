-- P4.23 Gate C repair: exact Restore preserves historical Evidence Version
-- identity while appending narrowly scoped current descriptor/posture authority.

create table app.evidence_exact_restore_posture_receipts (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  evidence_object_id uuid not null references app.evidence_objects(id) on delete restrict,
  evidence_version_id uuid not null references app.evidence_versions(id) on delete restrict,
  custody_operation_id uuid not null unique references app.custody_operations(id) on delete restrict,
  custody_event_id uuid not null unique references app.evidence_custody_events(id) on delete restrict,
  completion_reauth_audit_event_id uuid not null unique references app.audit_events(id) on delete restrict,
  runner_instance_id text not null check (length(runner_instance_id) between 1 and 255),
  storage_generation bigint not null check (storage_generation > 0),
  storage_profile text not null check (storage_profile = 'LOCAL_IMMUTABLE'),
  sha256 text not null check (sha256 ~ '^sha256:[0-9a-f]{64}$'),
  bytes bigint not null check (bytes >= 0),
  st_dev bigint not null check (st_dev >= 0),
  st_ino bigint not null check (st_ino > 0),
  st_mtime_ns bigint not null check (st_mtime_ns >= 0),
  st_ctime_ns bigint not null check (st_ctime_ns >= 0),
  st_nlink integer not null check (st_nlink = 1),
  owner_name text not null check (length(owner_name) between 1 and 255),
  mode text not null check (mode = '0644'),
  immutable boolean not null check (immutable is true),
  created_at timestamptz not null default now(),
  unique(case_id,evidence_object_id,evidence_version_id,custody_operation_id)
);
alter table app.evidence_exact_restore_posture_receipts enable row level security;
alter table app.evidence_exact_restore_posture_receipts force row level security;
create trigger evidence_exact_restore_posture_receipts_no_update_delete
  before update or delete on app.evidence_exact_restore_posture_receipts
  for each row execute function app.evidence_block_mutation();
create trigger evidence_exact_restore_posture_receipts_no_truncate
  before truncate on app.evidence_exact_restore_posture_receipts
  execute function app.evidence_block_truncate();
revoke all on app.evidence_exact_restore_posture_receipts from public,anon,authenticated;

alter function app.custody_operation_commit_verified_recovery(uuid,jsonb,text,text)
  rename to custody_operation_commit_verified_recovery_pre_posture_receipt;

create function app.custody_operation_commit_verified_recovery(
  p_operation_id uuid,p_item jsonb,p_examiner text,p_runner_instance_id text
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare
  v_op app.custody_operations;
  v_item jsonb;
  v_storage app.evidence_storage_authorities;
  v_event_id uuid;
  v_event_count bigint;
begin
  v_op := app.custody_operation_commit_verified_recovery_pre_posture_receipt(
    p_operation_id,p_item,p_examiner,p_runner_instance_id);
  if v_op.action <> 'RESTORE_EXACT' then return v_op; end if;

  -- Exact replay is idempotent; authoritative facts come from the durable
  -- FILESYSTEM_VERIFIED operation record, never from replay-supplied JSON.
  if exists(select 1 from app.evidence_exact_restore_posture_receipts
      where custody_operation_id=v_op.id) then
    return v_op;
  end if;
  v_item := v_op.verified_facts->'item';
  select * into v_storage from app.evidence_storage_authorities
    where case_id=v_op.case_id for update;
  select (array_agg(id order by id))[1],count(*) into v_event_id,v_event_count
    from app.evidence_custody_events
    where custody_operation_id=v_op.id
      and evidence_object_id=(v_item->>'evidence_object_id')::uuid
      and event_type='CHAIN_VERIFIED';
  if v_op.phase <> 'COMPLETED'
     or v_op.completion_reauth_audit_event_id is null
     or v_storage.case_id is null or v_storage.profile <> 'LOCAL_IMMUTABLE'
     or v_storage.state <> 'AVAILABLE'
     or v_storage.verified_generation is distinct from v_storage.generation
     or v_event_count <> 1 or v_event_id is null
     or v_item->>'evidence_object_id' is distinct from v_op.result->>'evidence_object_id'
     or v_item->>'original_version_id' is distinct from v_op.result->>'evidence_version_id'
     or v_item->>'sha256' is distinct from v_item->>'original_sha256'
     or v_item->>'sha256' !~ '^sha256:[0-9a-f]{64}$'
     or (v_item->>'bytes')::bigint is distinct from (v_item->>'original_bytes')::bigint
     or (v_item->>'bytes')::bigint < 0
     or v_item->>'mode' <> '0644'
     or coalesce((v_item->>'immutable')::boolean,false) is false
     or (v_item->>'st_nlink')::integer <> 1
     or v_item->>'owner' is null or v_item->>'st_dev' is null
     or v_item->>'st_ino' is null or v_item->>'st_mtime_ns' is null
     or v_item->>'st_ctime_ns' is null then
    raise exception 'exact_restore_posture_receipt_invalid'
      using errcode='invalid_parameter_value';
  end if;
  insert into app.evidence_exact_restore_posture_receipts(
    case_id,evidence_object_id,evidence_version_id,custody_operation_id,custody_event_id,
    completion_reauth_audit_event_id,runner_instance_id,storage_generation,storage_profile,sha256,bytes,
    st_dev,st_ino,st_mtime_ns,st_ctime_ns,st_nlink,owner_name,mode,immutable
  ) values(
    v_op.case_id,(v_item->>'evidence_object_id')::uuid,
    (v_item->>'original_version_id')::uuid,v_op.id,v_event_id,
    v_op.completion_reauth_audit_event_id,v_op.runner_instance_id,
    v_storage.generation,'LOCAL_IMMUTABLE',
    v_item->>'sha256',(v_item->>'bytes')::bigint,(v_item->>'st_dev')::bigint,
    (v_item->>'st_ino')::bigint,(v_item->>'st_mtime_ns')::bigint,
    (v_item->>'st_ctime_ns')::bigint,(v_item->>'st_nlink')::integer,
    v_item->>'owner',v_item->>'mode',(v_item->>'immutable')::boolean
  );
  return v_op;
end $$;

revoke execute on function app.custody_operation_commit_verified_recovery_pre_posture_receipt(
  uuid,jsonb,text,text) from public,anon,authenticated;
revoke execute on function app.custody_operation_commit_verified_recovery(
  uuid,jsonb,text,text) from public,anon,authenticated;
do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  revoke execute on function app.custody_operation_commit_verified_recovery_pre_posture_receipt(
    uuid,jsonb,text,text) from service_role;
  grant select on app.evidence_exact_restore_posture_receipts to service_role;
  grant execute on function app.custody_operation_commit_verified_recovery(
    uuid,jsonb,text,text) to service_role;
end if; end $$;
