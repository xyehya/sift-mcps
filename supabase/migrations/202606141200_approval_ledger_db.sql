-- FORK-2: DB-only approval-commit ledger (retire the file HMAC verification ledger).
--
-- Background
-- ----------
-- The approval-commit ledger recorded, per approved finding/timeline item, a
-- tamper-evident commit event at the moment an operator approved it in the
-- portal review path. Historically this lived in a FILE HMAC ledger at
-- /var/lib/sift/verification/{case_id}.jsonl (sift_core.verification.
-- write_ledger_entry + compute_hmac), keyed with a local PBKDF2 hash. CL3b
-- (718684e) retired the file-HMAC RE-AUTH plane; this migration retires the last
-- remaining file-ledger WRITER and moves the approval-commit ledger into
-- Postgres so the DB is the SOLE authority — matching how investigation
-- content_hash (app.investigation_*) and the evidence custody chain
-- (app.evidence_custody_events) are already DB-authoritative.
--
-- Design (mirrors app.evidence_custody_events; see 202606081000_evidence_custody.sql)
-- ----------------------------------------------------------------------------
--   * app.approval_commit_events: append-only, per-case hash-linked ledger.
--     prev_hash/event_hash form a per-case SHA-256 chain; rows are append-only
--     (UPDATE/DELETE blocked by a trigger). Tamper-evidence comes from the chain
--     + DB-level immutability, NOT a secret HMAC key — equivalent guarantees
--     without key management. (No secret key is introduced: see the FORK note in
--     the unit report; the locked evidence_custody pattern is a keyless hash
--     chain and is reused deliberately.)
--   * app.approval_commit_heads: per-case chain head (head_seq/head_hash) so an
--     append serializes against the head and reconciliation reads the tip in O(1).
--   * app.approval_append_commit_event(...): SECURITY DEFINER RPC that locks the
--     head, computes the next prev_hash/event_hash, inserts the event, and
--     advances the head — one atomic call, exactly like
--     app.evidence_append_custody_event. The hash uses the built-in
--     sha256(bytea) (NOT pgcrypto digest()) so a fresh Supabase deploy whose
--     pgcrypto lives in the extensions schema does not 500 under the pinned
--     SECURITY DEFINER search_path (same fix as evidence_custody).
--
-- Authority / exports
-- -------------------
-- The file ledger is no longer a write authority. sift_core.verification's file
-- writer is neutralized; backups may still copy a pre-existing legacy
-- {case_id}.jsonl as a read-only artifact. Any future file emission of this
-- ledger is an EXPORT, not authority — same posture as evidence proof exports.
--
-- RLS: enable + force (matches 202606131000_force_rls_app_tables.sql). No broad
-- grants; the Gateway/portal service workflow writes via the service-role DSN
-- (BYPASSRLS), and a forward-looking case-member SELECT policy mirrors the
-- evidence_custody tables so a later phase can grant narrow browser SELECT
-- without a schema change.

create schema if not exists app;

-- ---------------------------------------------------------------------------
-- 1. Append-only hash-linked approval-commit ledger
-- ---------------------------------------------------------------------------
-- One row per approved item committed in a review batch. prev_hash/event_hash
-- form a per-case hash chain. item_id is the logical finding/timeline id (e.g.
-- F-001 / T-003); content_hash mirrors the DB content_hash recorded at approval
-- so the ledger event binds to the exact approved content. Rows are append-only
-- (no UPDATE/DELETE) enforced by trigger; the chain head lives in
-- app.approval_commit_heads.
create table if not exists app.approval_commit_events (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  -- Monotonic per-case sequence number (1-based).
  seq bigint not null,
  -- Logical investigation item id (F-### / T-### / IOC-###).
  item_id text not null,
  -- 'finding' | 'timeline' | 'ioc'.
  item_type text not null,
  -- Operator decision recorded by this commit event.
  action text not null default 'APPROVED',
  -- DB content_hash recorded for the item at approval (sha256:<hex>) — binds the
  -- ledger event to the exact approved content. Nullable for non-approve actions
  -- that carry no content hash.
  content_hash text null,
  -- Hash chain: prev_hash is '' for the genesis event of a case.
  prev_hash text not null default '',
  event_hash text not null,
  -- Re-auth linkage: the audit event that authorized this review batch.
  reauth_audit_event_id uuid null references app.audit_events(id) on delete set null,
  audit_event_id uuid null references app.audit_events(id) on delete set null,
  approved_by text null,
  actor_user_id uuid null references app.operator_profiles(id) on delete set null,
  actor_service_identity_id uuid null references app.service_identities(id) on delete set null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint approval_commit_events_item_type_check
    check (item_type in ('finding', 'timeline', 'ioc')),
  constraint approval_commit_events_action_check
    check (action in ('APPROVED', 'REJECTED', 'EDITED')),
  constraint approval_commit_events_seq_check
    check (seq >= 1),
  constraint approval_commit_events_item_id_check
    check (length(btrim(item_id)) > 0),
  constraint approval_commit_events_event_hash_check
    check (length(btrim(event_hash)) > 0),
  constraint approval_commit_events_content_hash_shape_check
    check (content_hash is null or content_hash ~ '^sha256:[0-9a-f]{64}$')
);

-- ---------------------------------------------------------------------------
-- 2. Per-case chain head (reconciliation read model)
-- ---------------------------------------------------------------------------
-- One row per case. Reconciliation/report reads head_hash/head_seq here to
-- confirm the approval-commit ledger tip without re-walking events.
create table if not exists app.approval_commit_heads (
  case_id uuid primary key references app.cases(id) on delete cascade,
  head_seq bigint not null default 0,
  head_hash text not null default '',
  last_item_id text null,
  last_action text null,
  updated_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  constraint approval_commit_heads_head_seq_check
    check (head_seq >= 0)
);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------
create unique index if not exists approval_commit_events_case_seq_key
  on app.approval_commit_events (case_id, seq);
create index if not exists approval_commit_events_case_created_at_idx
  on app.approval_commit_events (case_id, created_at);
create index if not exists approval_commit_events_case_item_idx
  on app.approval_commit_events (case_id, item_id);

-- ---------------------------------------------------------------------------
-- Append-only enforcement for the ledger (reuse the evidence_custody pattern).
-- app.evidence_block_mutation already exists (202606081000); define an
-- approval-scoped twin idempotently so this migration is self-contained and does
-- not depend on load order beyond the evidence_custody migration that created
-- app.cases/app.audit_events references above.
-- ---------------------------------------------------------------------------
create or replace function app.approval_block_mutation()
returns trigger
language plpgsql
as $$
begin
  raise exception 'append-only: % on % is not permitted', tg_op, tg_table_name
    using errcode = 'restrict_violation';
end;
$$;

drop trigger if exists approval_commit_events_no_update on app.approval_commit_events;
create trigger approval_commit_events_no_update
  before update or delete on app.approval_commit_events
  for each row execute function app.approval_block_mutation();

-- ---------------------------------------------------------------------------
-- RPC: append one approval-commit event, advancing the per-case hash chain.
-- prev_hash links to the prior head; event_hash = sha256 over canonical fields.
-- Updates app.approval_commit_heads. Returns the new event row id.
-- Mirrors app.evidence_append_custody_event exactly.
-- ---------------------------------------------------------------------------
create or replace function app.approval_append_commit_event(
  p_case_id uuid,
  p_item_id text,
  p_item_type text,
  p_action text,
  p_content_hash text,
  p_reauth_audit_event_id uuid,
  p_approved_by text,
  p_actor_user_id uuid,
  p_actor_service_identity_id uuid,
  p_details jsonb
)
returns uuid
language plpgsql
security definer
set search_path = app, public
as $$
declare
  v_prev_seq bigint;
  v_prev_hash text;
  v_seq bigint;
  v_event_hash text;
  v_event_id uuid;
  v_payload text;
  v_action text;
  v_item_type text;
begin
  v_action := coalesce(nullif(btrim(coalesce(p_action, '')), ''), 'APPROVED');
  v_item_type := coalesce(nullif(btrim(coalesce(p_item_type, '')), ''), 'finding');

  -- Lock the head row to serialize chain appends per case.
  insert into app.approval_commit_heads (case_id)
    values (p_case_id)
    on conflict (case_id) do nothing;

  select head_seq, head_hash
    into v_prev_seq, v_prev_hash
    from app.approval_commit_heads
    where case_id = p_case_id
    for update;

  v_seq := coalesce(v_prev_seq, 0) + 1;
  v_prev_hash := coalesce(v_prev_hash, '');

  -- Canonical, order-stable payload for the chain hash.
  v_payload := coalesce(v_prev_hash, '')
    || '|' || p_case_id::text
    || '|' || v_seq::text
    || '|' || p_item_id
    || '|' || v_item_type
    || '|' || v_action
    || '|' || coalesce(p_content_hash, '')
    || '|' || coalesce(p_reauth_audit_event_id::text, '')
    || '|' || coalesce(p_details::text, '{}');
  -- Built-in sha256(bytea); see header note re: pgcrypto search_path on Supabase.
  v_event_hash := 'sha256:' || encode(sha256(v_payload::bytea), 'hex');

  insert into app.approval_commit_events (
    case_id, seq, item_id, item_type, action, content_hash,
    prev_hash, event_hash, reauth_audit_event_id, approved_by,
    actor_user_id, actor_service_identity_id, details
  ) values (
    p_case_id, v_seq, p_item_id, v_item_type, v_action, p_content_hash,
    v_prev_hash, v_event_hash, p_reauth_audit_event_id, p_approved_by,
    p_actor_user_id, p_actor_service_identity_id, coalesce(p_details, '{}'::jsonb)
  )
  returning id into v_event_id;

  update app.approval_commit_heads
    set head_seq = v_seq,
        head_hash = v_event_hash,
        last_item_id = p_item_id,
        last_action = v_action,
        updated_at = now()
    where case_id = p_case_id;

  return v_event_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- Read model RPC: approval-commit ledger tip for a case (reconciliation).
-- Returns the head seq/hash and total event count. Empty (seq 0, '' hash) when
-- no ledger exists for the case.
-- ---------------------------------------------------------------------------
create or replace function app.approval_commit_tip(p_case_id uuid)
returns table (
  case_id uuid,
  head_seq bigint,
  head_hash text,
  event_count bigint
)
language sql
stable
security definer
set search_path = app, public
as $$
  select
    p_case_id as case_id,
    coalesce(h.head_seq, 0) as head_seq,
    coalesce(h.head_hash, '') as head_hash,
    (select count(*) from app.approval_commit_events e where e.case_id = p_case_id)
      as event_count
  from (select p_case_id as case_id) base
  left join app.approval_commit_heads h on h.case_id = p_case_id;
$$;

-- ---------------------------------------------------------------------------
-- RLS: enable + force (defence-in-depth; service_role BYPASSRLS is unaffected).
-- Mirrors the evidence_custody tables: a forward-looking case-member SELECT
-- policy is created so a later phase can grant narrow browser SELECT without a
-- schema change.
-- ---------------------------------------------------------------------------
alter table app.approval_commit_events enable row level security;
alter table app.approval_commit_heads  enable row level security;
alter table app.approval_commit_events force row level security;
alter table app.approval_commit_heads  force row level security;

do $$
declare
  v_table text;
begin
  foreach v_table in array array[
    'approval_commit_events',
    'approval_commit_heads'
  ]
  loop
    if not exists (
      select 1 from pg_policies
      where schemaname = 'app' and tablename = v_table
        and policyname = v_table || '_case_member_select'
    ) then
      execute format($f$
        create policy %1$s_case_member_select
          on app.%1$s
          for select
          using (
            exists (
              select 1
              from app.case_members cm
              join app.operator_profiles op on op.id = cm.operator_profile_id
              where cm.case_id = app.%1$s.case_id
                and cm.status = 'active'
                and op.auth_user_id = auth.uid()
            )
          )
      $f$, v_table);
    end if;
  end loop;
end
$$;

-- ---------------------------------------------------------------------------
-- Service-only execute grants on the append + read RPCs.
-- ---------------------------------------------------------------------------
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant execute on function app.approval_append_commit_event(
      uuid, text, text, text, text, uuid, text, uuid, uuid, jsonb) to service_role;
    grant execute on function app.approval_commit_tip(uuid) to service_role;
  end if;
end
$$;

-- ---------------------------------------------------------------------------
-- Comments (authority documentation)
-- ---------------------------------------------------------------------------
comment on table app.approval_commit_events is
  'Append-only, per-case hash-linked approval-commit ledger (prev_hash/event_hash). '
  'Replaces the retired file HMAC verification ledger (FORK-2). Tamper-evidence '
  'comes from the SHA-256 chain + the append-only mutation trigger, not a secret '
  'HMAC key. UPDATE/DELETE blocked by trigger.';
comment on table app.approval_commit_heads is
  'Per-case approval-commit chain head (head_seq/head_hash). Reconciliation reads '
  'the ledger tip here.';
comment on function app.approval_append_commit_event(
  uuid, text, text, text, text, uuid, text, uuid, uuid, jsonb) is
  'Service-only append for the approval-commit ledger. Atomically locks the head, '
  'links prev_hash, computes event_hash = sha256(canonical payload), inserts the '
  'event, and advances the head. Mirrors app.evidence_append_custody_event.';
comment on function app.approval_commit_tip(uuid) is
  'Reconciliation read model: approval-commit ledger head seq/hash + event count '
  'for a case. Empty (seq 0, '''' hash) when no ledger exists.';
