-- P4.23 custody remediation — CP1 Foundation (REWRITTEN 2026-07-20).
--
-- Clean-chain rewrite of the never-released custody engine. This file defines the
-- TARGET custody-core schema and read model; the mutation RPCs live in the
-- companion migration 202607132200_custody_rpcs.sql. Authority:
-- docs/architecture/EVIDENCE-CUSTODY-SPEC.md and OPERATING-MODEL §2.
--
-- What changed vs the as-built engine (folded findings):
--   * EC-2 (permanent brick): the seal machine has exactly three phases
--     REQUESTED -> PROTECTED -> COMMITTED and NO FAILED_RECOVERABLE latched
--     state. Incomplete work stays resumable under the same idempotency key; it
--     never bricks the case. The one-active constraint applies to Seal ONLY;
--     DB-only Ignore/Retire/Reprotect are single atomic transactions recorded in
--     custody_action_receipts with no persistent failure state.
--   * EC-6 (cross-language sort): the reauth binding is built by ONE canonical
--     builder (app.custody_reauth_binding) whose target array is ordered by raw
--     byte order (COLLATE "C" == Python code-point sort). The seal verifier
--     compares the stored binding against that single canonical form, so a
--     mixed-case multi-file set can never drift between a Python writer and a SQL
--     verifier again.
--   * No latched head: the gate is a COMPUTED SQL function over current
--     inventory, sealed-set violations, storage availability, and open seal
--     operations. There is no evidence_chain_heads discharge/latch in the target.
--
-- Objects and versions are permanent, write-once identities created ONLY at
-- Seal COMMITTED. Pending entries live in app.evidence_inventory (202607131900),
-- never as objects (EC-1/EC-4).

-- ===========================================================================
-- 1. Reuse + extend the released permanent-identity tables (additive only).
-- ===========================================================================
-- Permanent custody identity: optional supersession pointer for a later
-- acquisition of the same real-world source (SPEC §Evidence Object).
alter table app.evidence_objects
  add column if not exists supersedes_object_id uuid null
    references app.evidence_objects(id) on delete set null;

-- Immutable per-version snapshot gains explicit digest/size/identity/posture
-- columns (OPERATING-MODEL §2) so the sealed posture is first-class, not buried
-- in metadata. seal_operation_id ties the version to the seal that created it.
alter table app.evidence_versions
  add column if not exists seal_operation_id uuid null,
  add column if not exists st_dev bigint null,
  add column if not exists st_ino bigint null,
  add column if not exists st_nlink integer null,
  add column if not exists owner text null,
  add column if not exists mode text null,
  add column if not exists immutable boolean null;

-- The append-only hash chain gains a seal linkage and the canonical event
-- material captured at append time (event_hash is computed over it).
alter table app.evidence_custody_events
  add column if not exists seal_operation_id uuid null,
  add column if not exists canonical_schema text null,
  add column if not exists canonical_material jsonb null;

-- Widen the event-type domain to the target verbs. This only ADDS types; every
-- previously valid type stays valid so the append-only chain is untouched.
do $$
begin
  alter table app.evidence_custody_events
    drop constraint if exists evidence_custody_events_event_type_check;
  alter table app.evidence_custody_events
    add constraint evidence_custody_events_event_type_check
      check (event_type in (
        'EVIDENCE_DETECTED',
        'EVIDENCE_REGISTERED',
        'EVIDENCE_SEALED',
        'MANIFEST_SEALED',
        'CHAIN_VERIFIED',
        'FILE_IGNORED',
        'FILE_RETIRED',
        'FILE_UNSEALED',
        'EVIDENCE_REPROTECTED',
        'SEAL_WINDOW_OPENED',
        'SEAL_WINDOW_CLOSED',
        'CUSTODY_EXPORTED',
        'SOLANA_ANCHORED',
        'CHAIN_VIOLATION'
      ));
end
$$;

-- ===========================================================================
-- 2. Manifest versions + membership (append-only).
-- ===========================================================================
-- A Manifest Version is the sealed set at a point in time. Add and Seal advances
-- it; Retire creates a new version excluding the retired object. Membership rows
-- record which object/version is ACTIVE or RETIRED in each manifest version.
create table if not exists app.manifest_versions (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  manifest_version integer not null check (manifest_version > 0),
  manifest_hash text not null check (manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  -- Seal that produced this version; null for a Retire-produced version, which
  -- is a DB-only action, not a seal.
  seal_operation_id uuid null,
  created_by_action text not null,
  created_at timestamptz not null default now(),
  constraint manifest_versions_action_check
    check (created_by_action in ('SEAL', 'RETIRE')),
  unique (case_id, manifest_version)
);

create table if not exists app.manifest_membership (
  id uuid primary key default gen_random_uuid(),
  manifest_version_id uuid not null references app.manifest_versions(id) on delete cascade,
  case_id uuid not null references app.cases(id) on delete cascade,
  evidence_object_id uuid not null references app.evidence_objects(id),
  evidence_version_id uuid not null references app.evidence_versions(id),
  entry_status text not null default 'ACTIVE',
  created_at timestamptz not null default now(),
  constraint manifest_membership_entry_status_check
    check (entry_status in ('ACTIVE', 'RETIRED')),
  unique (manifest_version_id, evidence_object_id)
);

create index if not exists manifest_versions_case_idx
  on app.manifest_versions (case_id, manifest_version desc);
create index if not exists manifest_membership_case_status_idx
  on app.manifest_membership (case_id, entry_status);
create index if not exists manifest_membership_object_idx
  on app.manifest_membership (evidence_object_id);

-- ===========================================================================
-- 3. custody_seal_operations — the ONE idempotency-keyed seal machine.
-- ===========================================================================
-- REQUESTED -> PROTECTED -> COMMITTED. No FAILED_RECOVERABLE (EC-2). Exactly one
-- non-committed seal operation may exist per case (enforced by a partial unique
-- index). Retry reuses the same idempotency key; a fresh reauth authorizes
-- continuation; a committed operation replays its recorded result.
create table if not exists app.custody_seal_operations (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  action text not null default 'ADD_SEAL',
  phase text not null default 'REQUESTED',
  idempotency_key text not null,
  request_digest text not null,
  reason text not null,
  reauth_audit_event_id uuid not null references app.audit_events(id),
  -- The canonical reauth binding (EC-6); byte-identical to the value the reauth
  -- audit event stored, verified via app.custody_reauth_binding.
  binding jsonb not null,
  -- Selected target set (relative evidence paths) from the most recent Refresh
  -- snapshot. PROTECTED re-verifies each from disk; a vanished/changed target
  -- fails with a shaped error (SPEC Add and Seal amendment).
  targets jsonb not null,
  -- D2: adding evidence to a sealed case opens a bounded staging window during
  -- the REQUESTED phase (directory immutability lifted; gate stays blocked).
  opens_staging_window boolean not null default false,
  prepared_facts jsonb not null default '{}'::jsonb,
  result jsonb null,
  actor_user_id uuid null references app.operator_profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  committed_at timestamptz null,
  constraint custody_seal_operations_action_check check (action = 'ADD_SEAL'),
  constraint custody_seal_operations_phase_check
    check (phase in ('REQUESTED', 'PROTECTED', 'COMMITTED')),
  constraint custody_seal_operations_reason_check
    check (length(btrim(reason)) between 1 and 1000),
  constraint custody_seal_operations_key_check
    check (length(idempotency_key) between 1 and 128),
  constraint custody_seal_operations_digest_check
    check (request_digest ~ '^sha256:[0-9a-f]{64}$'),
  unique (case_id, idempotency_key),
  unique (reauth_audit_event_id)
);

-- One active (non-committed) Seal per case. DB-only actions do not live here, so
-- a stuck seal never blocks Ignore/Retire (EC-2).
create unique index if not exists custody_seal_operations_one_active_per_case
  on app.custody_seal_operations (case_id) where phase <> 'COMMITTED';

-- Reauth idempotency at the audit layer: one portal_reauth event per
-- (case, event_type, actor, idempotency_key). Replaces the as-built
-- audit_reauth_bound_intent_key index (rewritten here since 202607132100 owned it).
create unique index if not exists audit_reauth_bound_intent_key
  on app.audit_events (
    case_id, event_type, actor_type,
    coalesce(actor_user_id, '00000000-0000-0000-0000-000000000000'::uuid),
    coalesce(actor_service_identity_id, '00000000-0000-0000-0000-000000000000'::uuid),
    ((details->'binding'->>'idempotency_key'))
  )
  where source = 'portal_reauth' and details->'binding'->>'idempotency_key' is not null;

-- ===========================================================================
-- 4. custody_action_receipts — idempotency + outcome ledger for DB-only actions.
-- ===========================================================================
-- Ignore / Retire / Verify-and-Reprotect are each a single atomic transaction
-- with NO persistent failure state (EC-2a): a failed attempt rolls back the whole
-- transaction, including this receipt, and never blocks the case. A retry under
-- the same key replays the recorded outcome (OPERATING-MODEL §2 idempotency).
create table if not exists app.custody_action_receipts (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  action text not null,
  idempotency_key text not null,
  reauth_audit_event_id uuid not null references app.audit_events(id),
  binding jsonb not null,
  target jsonb not null default '{}'::jsonb,
  result jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint custody_action_receipts_action_check
    check (action in ('IGNORE', 'RETIRE', 'REPROTECT')),
  constraint custody_action_receipts_key_check
    check (length(idempotency_key) between 1 and 128),
  unique (case_id, action, idempotency_key),
  unique (reauth_audit_event_id)
);

-- ===========================================================================
-- 5. Custody export + optional Solana receipt stubs (CP2B fills the bodies).
-- ===========================================================================
-- Derived, one-way custody export metadata. Non-authoritative (SPEC §Derived
-- export). The bytes are generated by CP2B's ledger module; this records digest,
-- source ledger head, and audit linkage.
create table if not exists app.custody_exports (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  export_schema_version text not null default 'custody_export_v1',
  export_digest text not null check (export_digest ~ '^sha256:[0-9a-f]{64}$'),
  source_ledger_head text null,
  manifest_version integer null,
  actor_user_id uuid null references app.operator_profiles(id) on delete set null,
  audit_event_id uuid null references app.audit_events(id) on delete set null,
  created_at timestamptz not null default now()
);

-- Optional, disabled-by-default, non-authoritative, nonblocking anchoring
-- receipt (SPEC §Solana). Status advances pending -> confirmed/failed; a failure
-- never rolls back custody or blocks the gate.
create table if not exists app.solana_receipts (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  status text not null default 'pending',
  tx_signature text null,
  anchored_head_digest text null,
  error_category text null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint solana_receipts_status_check
    check (status in ('pending', 'confirmed', 'failed'))
);

create index if not exists custody_exports_case_idx on app.custody_exports (case_id, created_at desc);
create index if not exists solana_receipts_case_idx on app.solana_receipts (case_id, created_at desc);

-- ===========================================================================
-- 6. Hash-only setup/recovery claims (stub; IP1 identity phase fills the flow).
-- ===========================================================================
-- Installation-level, single-use, short-lived claims. Only the hash, expiry,
-- attempt state, and consumption state persist — never plaintext (SPEC
-- §Installation Owner and Password Lifecycle).
create table if not exists app.custody_claims (
  id uuid primary key default gen_random_uuid(),
  claim_type text not null,
  claim_hash text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz null,
  attempt_count integer not null default 0,
  created_at timestamptz not null default now(),
  constraint custody_claims_type_check check (claim_type in ('setup', 'recovery')),
  constraint custody_claims_hash_check check (length(btrim(claim_hash)) > 0)
);

-- ===========================================================================
-- 7. Append-only enforcement.
-- ===========================================================================
-- Seal operations and solana receipts advance in place (UPDATE allowed via RPC),
-- but are never deleted. Manifests, membership, and action receipts are pure
-- history (no UPDATE/DELETE). All block TRUNCATE.
drop trigger if exists custody_seal_operations_no_delete on app.custody_seal_operations;
create trigger custody_seal_operations_no_delete
  before delete on app.custody_seal_operations
  for each row execute function app.evidence_block_mutation();

drop trigger if exists solana_receipts_no_delete on app.solana_receipts;
create trigger solana_receipts_no_delete
  before delete on app.solana_receipts
  for each row execute function app.evidence_block_mutation();

drop trigger if exists manifest_versions_no_update_delete on app.manifest_versions;
create trigger manifest_versions_no_update_delete
  before update or delete on app.manifest_versions
  for each row execute function app.evidence_block_mutation();

drop trigger if exists manifest_membership_no_update_delete on app.manifest_membership;
create trigger manifest_membership_no_update_delete
  before update or delete on app.manifest_membership
  for each row execute function app.evidence_block_mutation();

drop trigger if exists custody_action_receipts_no_update_delete on app.custody_action_receipts;
create trigger custody_action_receipts_no_update_delete
  before update or delete on app.custody_action_receipts
  for each row execute function app.evidence_block_mutation();

drop trigger if exists custody_exports_no_update_delete on app.custody_exports;
create trigger custody_exports_no_update_delete
  before update or delete on app.custody_exports
  for each row execute function app.evidence_block_mutation();

do $$
declare
  v_table text;
begin
  foreach v_table in array array[
    'manifest_versions', 'manifest_membership', 'custody_seal_operations',
    'custody_action_receipts', 'custody_exports', 'solana_receipts'
  ]
  loop
    execute format(
      'drop trigger if exists %1$s_no_truncate on app.%1$s', v_table);
    execute format(
      'create trigger %1$s_no_truncate before truncate on app.%1$s '
      'for each statement execute function app.custody_block_truncate()', v_table);
  end loop;
end
$$;

-- ===========================================================================
-- 8. Canonical reauth binding builder (EC-6, single source of truth).
-- ===========================================================================
-- The ONE canonical form of a reauth binding. Object keys are normalized by
-- jsonb; the target array is ordered by RAW BYTE ORDER (COLLATE "C"), which is
-- identical to a Python code-point sort of the same relative paths. Both the
-- Python reauth builder (custody/reauth.py) and this function MUST produce
-- byte-identical output; the seal/action verifiers compare against this single
-- form and never re-derive an ordering under a locale collation. The mixed-case
-- multi-file target set is the permanent regression fixture.
create or replace function app.custody_reauth_binding(
  p_idempotency_key text,
  p_reason text,
  p_targets jsonb
)
returns jsonb
language sql
immutable
set search_path = pg_catalog, app
as $$
  select jsonb_build_object(
    'idempotency_key', p_idempotency_key,
    'reason', btrim(p_reason),
    'targets', coalesce(
      (select jsonb_agg(t order by t collate "C")
         from jsonb_array_elements_text(coalesce(p_targets, '[]'::jsonb)) t),
      '[]'::jsonb)
  );
$$;

-- ===========================================================================
-- 9. Internal hash-chain appender (no latched head).
-- ===========================================================================
-- Appends one custody event, deriving seq and prev_hash directly from the
-- append-only chain (no evidence_chain_heads). Serialized per case by an
-- advisory transaction lock. event_hash = sha256 over the canonical material.
-- Not granted to any client role; called only by the mutation RPCs.
create or replace function app.custody_append_event(
  p_case_id uuid,
  p_evidence_object_id uuid,
  p_seal_operation_id uuid,
  p_event_type text,
  p_manifest_version integer,
  p_manifest_hash text,
  p_reauth_audit_event_id uuid,
  p_actor_user_id uuid,
  p_actor_service_identity_id uuid,
  p_details jsonb
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, app
as $$
declare
  v_seq bigint;
  v_prev text;
  v_at timestamptz;
  v_material jsonb;
  v_hash text;
  v_id uuid;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text, 0));

  select coalesce(max(seq), 0) into v_seq
    from app.evidence_custody_events where case_id = p_case_id;
  select event_hash into v_prev
    from app.evidence_custody_events
    where case_id = p_case_id order by seq desc limit 1;
  v_seq := v_seq + 1;
  v_prev := coalesce(v_prev, '');
  v_at := clock_timestamp();

  v_material := jsonb_build_object(
    'schema', 'custody_event_v2',
    'case_id', p_case_id,
    'seq', v_seq,
    'prev_hash', v_prev,
    'event_type', p_event_type,
    'evidence_object_id', p_evidence_object_id,
    'seal_operation_id', p_seal_operation_id,
    'manifest_version', p_manifest_version,
    'manifest_hash', p_manifest_hash,
    'reauth_audit_event_id', p_reauth_audit_event_id,
    'actor_user_id', p_actor_user_id,
    'actor_service_identity_id', p_actor_service_identity_id,
    'details', coalesce(p_details, '{}'::jsonb),
    'db_timestamp', to_char(v_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  v_hash := 'sha256:' || encode(sha256(convert_to(v_material::text, 'UTF8')), 'hex');

  insert into app.evidence_custody_events (
    case_id, evidence_object_id, seal_operation_id, seq, event_type,
    manifest_version, prev_hash, event_hash, reauth_audit_event_id,
    actor_user_id, actor_service_identity_id, details, created_at,
    canonical_schema, canonical_material
  ) values (
    p_case_id, p_evidence_object_id, p_seal_operation_id, v_seq, p_event_type,
    p_manifest_version, v_prev, v_hash, p_reauth_audit_event_id,
    p_actor_user_id, p_actor_service_identity_id, coalesce(p_details, '{}'::jsonb),
    v_at, 'custody_event_v2', v_material
  )
  returning id into v_id;
  return v_id;
end;
$$;

-- ===========================================================================
-- 10. Computed custody gate (the four public states; no latched state).
-- ===========================================================================
-- Projects the four public gate states from current facts:
--   BLOCKED_UNAVAILABLE  latest reconciliation saw storage unavailable
--   BLOCKED_VIOLATION    a sealed object drifted, or an unsafe entry/link exists
--   BLOCKED_PENDING      a pending inventory entry or an open seal operation
--   OPEN                 a committed sealed set with clean reconciliation
-- Fail-closed: a case with nothing sealed is never OPEN (SPEC scenario 14).
create or replace function app.custody_gate_state(p_case_id uuid)
returns text
language plpgsql
stable
security definer
set search_path = pg_catalog, app
as $$
declare
  v_storage_available boolean;
  v_has_observation boolean;
  v_violation boolean;
  v_open_seal boolean;
  v_pending boolean;
  v_sealed_count integer;
begin
  -- Storage availability from the most recent reconciliation observation.
  select o.storage_available
    into v_storage_available
    from app.admission_observations o
    where o.case_id = p_case_id
    order by o.observed_at desc, o.id desc
    limit 1;
  v_has_observation := found;
  if v_has_observation and v_storage_available is false then
    return 'BLOCKED_UNAVAILABLE';
  end if;

  -- Violation: an unsafe entry/link anywhere, or a sealed object that is missing
  -- from disk, has changed bytes/identity, or an invalid protection posture.
  select
    exists (
      select 1 from app.evidence_inventory i
      where i.case_id = p_case_id
        and i.entry_kind in ('symlink', 'multilink', 'nonregular')
    )
    or exists (
      select 1
      from app.evidence_objects o
      join app.evidence_versions v on v.id = o.current_version_id
      left join app.evidence_inventory i
        on i.case_id = o.case_id and i.display_path = o.display_path
      where o.case_id = p_case_id
        and o.status = 'sealed'
        and (
          i.id is null                                              -- missing
          or (i.bytes is not null and v.bytes is not null and i.bytes <> v.bytes)
          or (i.sha256 is not null and i.sha256 <> o.current_sha256)
          or (i.st_ino is not null and v.st_ino is not null and i.st_ino <> v.st_ino)
          or (i.st_dev is not null and v.st_dev is not null and i.st_dev <> v.st_dev)
          or (i.st_nlink is not null and i.st_nlink <> 1)
          or (v.mode is not null and i.st_mode is not null and i.st_mode <> v.mode)
        )
    )
    into v_violation;
  if v_violation then
    return 'BLOCKED_VIOLATION';
  end if;

  -- Open (non-committed) seal operation blocks throughout SEALING.
  select exists (
    select 1 from app.custody_seal_operations s
    where s.case_id = p_case_id and s.phase <> 'COMMITTED'
  ) into v_open_seal;

  -- Pending: a present, safe, undisposed inventory entry that is not itself an
  -- active sealed object's path.
  select exists (
    select 1 from app.evidence_inventory i
    where i.case_id = p_case_id
      and i.disposition = 'pending'
      and i.entry_kind = 'regular'
      and not exists (
        select 1 from app.evidence_objects o
        where o.case_id = p_case_id and o.status = 'sealed'
          and o.display_path = i.display_path
      )
  ) into v_pending;

  if v_open_seal or v_pending then
    return 'BLOCKED_PENDING';
  end if;

  select count(*) into v_sealed_count
    from app.evidence_objects o
    where o.case_id = p_case_id and o.status = 'sealed';

  if coalesce(v_sealed_count, 0) > 0 then
    return 'OPEN';
  end if;

  -- Nothing sealed: fail closed.
  return 'BLOCKED_PENDING';
end;
$$;

-- ===========================================================================
-- 11. RLS on the new tables (service-role mediated; FORCE RLS).
-- ===========================================================================
alter table app.manifest_versions enable row level security;
alter table app.manifest_versions force row level security;
alter table app.manifest_membership enable row level security;
alter table app.manifest_membership force row level security;
alter table app.custody_seal_operations enable row level security;
alter table app.custody_seal_operations force row level security;
alter table app.custody_action_receipts enable row level security;
alter table app.custody_action_receipts force row level security;
alter table app.custody_exports enable row level security;
alter table app.custody_exports force row level security;
alter table app.solana_receipts enable row level security;
alter table app.solana_receipts force row level security;
alter table app.custody_claims enable row level security;
alter table app.custody_claims force row level security;

do $$
declare
  v_table text;
begin
  foreach v_table in array array[
    'manifest_versions', 'manifest_membership', 'custody_seal_operations',
    'custody_action_receipts', 'custody_exports', 'solana_receipts'
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

revoke all on app.manifest_versions, app.manifest_membership,
  app.custody_seal_operations, app.custody_action_receipts,
  app.custody_exports, app.solana_receipts, app.custody_claims
  from public, anon, authenticated;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant select on app.manifest_versions, app.manifest_membership,
      app.custody_seal_operations, app.custody_action_receipts,
      app.custody_exports, app.solana_receipts to service_role;
  end if;
end
$$;

comment on table app.custody_seal_operations is
  'The one idempotency-keyed seal machine (REQUESTED->PROTECTED->COMMITTED). No '
  'FAILED_RECOVERABLE latched state (EC-2); one active operation per case; retry '
  'reuses the idempotency key; a committed operation replays its result.';
comment on function app.custody_reauth_binding(text, text, jsonb) is
  'Single canonical reauth-binding form (EC-6): targets ordered by COLLATE "C" '
  '(byte order == Python code-point sort). Both language builders must agree.';
comment on function app.custody_gate_state(uuid) is
  'Computed four-state custody gate. No latched state. Fail-closed: nothing '
  'sealed is never OPEN.';
