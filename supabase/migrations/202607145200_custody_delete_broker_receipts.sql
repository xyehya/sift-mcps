-- P4.23.4 Gate C repair: durable authorization/receipt for the fixed local
-- custody-delete broker. MCP/public roles receive no access.

create table app.custody_delete_broker_receipts (
  operation_id uuid primary key references app.custody_operations(id) on delete cascade,
  runner_instance_id text not null,
  prepared_facts_sha256 text not null
    check (prepared_facts_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  claimed_at timestamptz not null default clock_timestamp(),
  completed_at timestamptz null
);

alter table app.custody_delete_broker_receipts enable row level security;
alter table app.custody_delete_broker_receipts force row level security;
revoke all on table app.custody_delete_broker_receipts from public, anon, authenticated, service_role;

create function app.custody_delete_broker_receipt_guard() returns trigger
language plpgsql set search_path=pg_catalog,app as $$
begin
  if tg_op='DELETE'
     or old.completed_at is not null
     or new.operation_id is distinct from old.operation_id
     or new.runner_instance_id is distinct from old.runner_instance_id
     or new.prepared_facts_sha256 is distinct from old.prepared_facts_sha256
     or new.claimed_at is distinct from old.claimed_at
     or new.completed_at is null then
    raise exception 'custody_delete_broker_receipt_immutable'
      using errcode='integrity_constraint_violation';
  end if;
  return new;
end $$;
create trigger custody_delete_broker_receipt_no_rewrite
  before update or delete on app.custody_delete_broker_receipts
  for each row execute function app.custody_delete_broker_receipt_guard();
create trigger custody_delete_broker_receipt_no_truncate
  before truncate on app.custody_delete_broker_receipts
  execute function app.evidence_block_truncate();
revoke execute on function app.custody_delete_broker_receipt_guard() from public, anon, authenticated, service_role;

comment on table app.custody_delete_broker_receipts is
  'Internal exact-operation claim/one-way completion receipt for the fixed AppArmor custody-delete broker. No MCP or Portal role access.';
