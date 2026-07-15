-- P4.23.6: service-held asymmetric signatures for the canonical custody ledger.
-- The private key never enters PostgreSQL.  PostgreSQL records only public-key
-- identity and immutable checkpoint/signature metadata, and blocks completion
-- until the service has finalized the checkpoint.

alter table app.custody_operations drop constraint if exists custody_operations_phase_check;
alter table app.custody_operations add constraint custody_operations_phase_check check (phase in (
  'REQUESTED','GATE_BLOCKED','FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',
  'LEDGER_COMMITTED','PENDING_SIGNATURE','COMPLETED','FAILED_RECOVERABLE'
));
alter table app.custody_operation_history drop constraint if exists custody_operation_history_phase_check;
alter table app.custody_operation_history add constraint custody_operation_history_phase_check check (phase in (
  'REQUESTED','GATE_BLOCKED','FILESYSTEM_APPLYING','FILESYSTEM_VERIFIED',
  'LEDGER_COMMITTED','PENDING_SIGNATURE','COMPLETED','FAILED_RECOVERABLE'
));

create table if not exists app.custody_signing_keys (
  key_id text primary key check (key_id ~ '^ed25519:sha256:[0-9a-f]{64}$'),
  algorithm text not null check (algorithm = 'Ed25519'),
  public_key text not null check (length(public_key) between 40 and 128),
  activated_at timestamptz not null default now(),
  retired_at timestamptz null,
  metadata jsonb not null default '{}'::jsonb,
  check (not (metadata ?& array['private_key','secret','password','dsn','token']))
);

create table if not exists app.custody_signature_checkpoints (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  custody_operation_id uuid null references app.custody_operations(id) on delete restrict,
  manifest_version integer not null check (manifest_version >= 0),
  ledger_tip_hash text not null check (ledger_tip_hash ~ '^sha256:[0-9a-f]{64}$'),
  canonical_payload jsonb not null,
  payload_hash text not null check (payload_hash ~ '^sha256:[0-9a-f]{64}$'),
  key_id text null references app.custody_signing_keys(key_id) on delete restrict,
  signature text null,
  state text not null default 'PENDING_SIGNATURE'
    check (state in ('PENDING_SIGNATURE','SIGNED','FAILED')),
  failure_code text null check (failure_code is null or failure_code ~ '^[A-Z0-9_]{1,80}$'),
  created_at timestamptz not null default now(),
  signed_at timestamptz null,
  unique (custody_operation_id),
  check ((state='SIGNED') = (key_id is not null and signature is not null and signed_at is not null)),
  check (not (canonical_payload ?& array['private_key','secret','password','dsn','token']))
);
create index if not exists custody_signature_checkpoints_case_idx
  on app.custody_signature_checkpoints(case_id, created_at desc);

alter table app.custody_signing_keys enable row level security;
alter table app.custody_signature_checkpoints enable row level security;
alter table app.custody_signing_keys force row level security;
alter table app.custody_signature_checkpoints force row level security;

create or replace function app.custody_signature_checkpoint_append_only()
returns trigger language plpgsql as $$
begin
  if tg_op='DELETE' then
    raise exception 'append-only custody signature checkpoint' using errcode='restrict_violation';
  end if;
  if old.state='PENDING_SIGNATURE' and new.state='SIGNED'
     and new.case_id=old.case_id and new.custody_operation_id=old.custody_operation_id
     and new.manifest_version=old.manifest_version and new.ledger_tip_hash=old.ledger_tip_hash
     and new.canonical_payload=old.canonical_payload and new.payload_hash=old.payload_hash
     and old.key_id is null and old.signature is null and old.signed_at is null then
    return new;
  end if;
  raise exception 'append-only custody signature checkpoint' using errcode='restrict_violation';
end $$;
create trigger custody_signature_checkpoints_append_only
  before update or delete on app.custody_signature_checkpoints
  for each row execute function app.custody_signature_checkpoint_append_only();

create or replace function app.custody_signature_checkpoint_latch()
returns trigger language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_head app.evidence_chain_heads; v_payload jsonb; v_hash text;
begin
  if new.phase='LEDGER_COMMITTED' and old.phase is distinct from 'LEDGER_COMMITTED' then
    select * into v_head from app.evidence_chain_heads where case_id=new.case_id for share;
    if not found or coalesce(v_head.head_hash,'') !~ '^sha256:[0-9a-f]{64}$' then
      raise exception 'custody_signature_checkpoint_unavailable' using errcode='object_not_in_prerequisite_state';
    end if;
    v_payload := jsonb_build_object(
      'format','sift-custody-checkpoint/v1',
      'case_id',new.case_id::text,
      'operation_id',new.id::text,
      'manifest_version',v_head.manifest_version,
      'ledger_tip_hash',v_head.head_hash
    );
    v_hash := 'sha256:' || encode(sha256(convert_to(v_payload::text,'utf8')),'hex');
    insert into app.custody_signature_checkpoints(
      case_id,custody_operation_id,manifest_version,ledger_tip_hash,canonical_payload,payload_hash
    ) values(new.case_id,new.id,v_head.manifest_version,v_head.head_hash,v_payload,v_hash)
    on conflict(custody_operation_id) do nothing;
  end if;
  -- Existing finalizers still perform LEDGER_COMMITTED -> COMPLETED in one
  -- transaction. Rewrite that edge to the explicit latch; the service-only
  -- finalizer below is the sole route to COMPLETED.
  if new.phase='COMPLETED' and old.phase='LEDGER_COMMITTED'
     and current_setting('app.custody_signature_finalizer',true) is distinct from 'on' then
    new.phase := 'PENDING_SIGNATURE';
    new.completed_at := null;
    new.result := coalesce(new.result,'{}'::jsonb) || jsonb_build_object('operation_phase','PENDING_SIGNATURE');
  end if;
  return new;
end $$;

drop trigger if exists custody_signature_checkpoint_latch on app.custody_operations;
create trigger custody_signature_checkpoint_latch
  before update of phase on app.custody_operations
  for each row execute function app.custody_signature_checkpoint_latch();

-- Legacy action finalizers append their history row after their phase update.
-- Keep that immutable history truthful when the preceding COMPLETED transition
-- was rewritten to the signing latch above.
create or replace function app.custody_signature_history_latch()
returns trigger language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_phase text;
begin
  if new.phase='COMPLETED' then
    select phase into v_phase from app.custody_operations where id=new.operation_id;
    if v_phase='PENDING_SIGNATURE' then
      new.phase := 'PENDING_SIGNATURE';
      new.facts := coalesce(new.facts,'{}'::jsonb)
        || jsonb_build_object('signature_pending',true);
    end if;
  end if;
  return new;
end $$;
drop trigger if exists custody_signature_history_latch on app.custody_operation_history;
create trigger custody_signature_history_latch
  before insert on app.custody_operation_history
  for each row execute function app.custody_signature_history_latch();

create or replace function app.custody_signature_finalize(
  p_operation_id uuid, p_key_id text, p_signature text
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_op app.custody_operations; v_checkpoint app.custody_signature_checkpoints;
begin
  select * into v_op from app.custody_operations where id=p_operation_id for update;
  if not found or v_op.phase not in ('LEDGER_COMMITTED','PENDING_SIGNATURE') then
    raise exception 'custody_signature_operation_not_pending' using errcode='object_not_in_prerequisite_state';
  end if;
  select * into v_checkpoint from app.custody_signature_checkpoints
    where custody_operation_id=v_op.id for update;
  if not found or v_checkpoint.state <> 'PENDING_SIGNATURE'
     or p_signature !~ '^[A-Za-z0-9+/]{80,}={0,2}$' then
    raise exception 'custody_signature_invalid' using errcode='invalid_parameter_value';
  end if;
  if not exists(select 1 from app.custody_signing_keys where key_id=p_key_id and retired_at is null) then
    raise exception 'custody_signature_unknown_key' using errcode='invalid_authorization_specification';
  end if;
  update app.custody_signature_checkpoints set state='SIGNED',key_id=p_key_id,
    signature=p_signature,signed_at=now() where id=v_checkpoint.id;
  perform set_config('app.custody_signature_finalizer','on',true);
  update app.custody_operations set phase='COMPLETED',completed_at=now(),updated_at=now(),
    result=coalesce(result,'{}'::jsonb)||jsonb_build_object('operation_phase','COMPLETED')
    where id=v_op.id returning * into v_op;
  insert into app.custody_operation_history(operation_id,phase,facts)
    values(v_op.id,'COMPLETED',jsonb_build_object('signature_checkpoint_id',v_checkpoint.id::text));
  return v_op;
end $$;

grant execute on function app.custody_signature_finalize(uuid,text,text) to service_role;
comment on table app.custody_signature_checkpoints is
  'P4.23.6 append-only signing latch. Contains canonical public proof payload, never private signing material.';
