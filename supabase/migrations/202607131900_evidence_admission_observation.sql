-- P4.23 custody remediation — CP1 Foundation (REWRITTEN 2026-07-20).
--
-- Target reconciliation model: a read-only, present-on-disk inventory snapshot
-- plus an append-only observation history. This file is a clean-chain rewrite of
-- the as-built `evidence_observe_admission` engine, folding the live bring-up
-- findings from KNOWN-ISSUES-EVIDENCE-CUSTODY.md:
--
--   * EC-1 (phantom objects): the as-built admission INSERTed every detection as
--     a persistent `evidence_objects` row (status 'detected') that survived after
--     the file left disk. In the target model a detected *pending* entry is an
--     `evidence_inventory` row, never an evidence_object. Reconciliation reflects
--     present-on-disk truth: a path absent from the current inventory is deleted,
--     so it can never be surfaced as Pending or demand disposition.
--   * EC-4 (fake "sealed" list): because pending entries were objects, digestless
--     detections rendered as "Sealed Evidence". In the target model an
--     evidence_object exists ONLY for a COMMITTED sealed acquisition (created by
--     custody_seal_commit); the sealed rendering is structurally gated on a
--     committed version + manifest membership.
--   * EC-5 (staging race): reconciliation classifies partial-transfer artifacts as
--     entry_kind 'partial' so an in-flight copy never becomes a Pending entry.
--
-- Authority: docs/architecture/EVIDENCE-CUSTODY-SPEC.md (§Pre-seal staging window,
-- §Custody Gate and Admission). PostgreSQL is the sole custody authority; MCP has
-- zero custody-mutation authority; these tables are service-role only.

-- ---------------------------------------------------------------------------
-- Shared append-only TRUNCATE guard for the custody-core tables introduced by
-- the remediation. (evidence_block_mutation() from 202606081000 already blocks
-- UPDATE/DELETE for append-only tables; this adds the TRUNCATE guard the target
-- observation history needs, defined here so it is available to 202607132100.)
-- ---------------------------------------------------------------------------
create or replace function app.custody_block_truncate()
returns trigger
language plpgsql
set search_path = pg_catalog, app
as $$
begin
  raise exception 'append-only: TRUNCATE on % is not permitted', tg_table_name
    using errcode = 'restrict_violation';
end;
$$;

-- ---------------------------------------------------------------------------
-- evidence_inventory — the CURRENT read-only reconciliation snapshot.
-- One row per (case, display_path) that is present on disk right now. Upserted
-- by custody_reconcile; rows for vanished paths are deleted (present-on-disk
-- truth). This is NOT authority over sealed evidence — it is the observation the
-- computed gate classifies against the authoritative sealed set.
-- ---------------------------------------------------------------------------
create table if not exists app.evidence_inventory (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  display_path text not null,
  display_name text not null,
  -- Entry classification for the four gate states. 'partial' is a
  -- partial-transfer artifact (EC-5) and is never treated as Pending.
  entry_kind text not null default 'regular',
  bytes bigint null,
  -- Cheap fingerprint captured at reconciliation. The full SHA-256 that governs
  -- custody is (re)computed from disk under protection at Seal PROTECTED, never
  -- from this snapshot (kills the snapshot->seal TOCTOU; SPEC D1).
  sha256 text null,
  st_dev bigint null,
  st_ino bigint null,
  st_nlink integer null,
  st_mode text null,
  owner text null,
  -- Operator disposition of a pending entry. 'ignored' is preserved across
  -- reconciliations while the path stays present; a vanished path is removed
  -- entirely (a later reappearance is observed fresh as 'pending').
  disposition text not null default 'pending',
  first_observed_at timestamptz not null default now(),
  observed_at timestamptz not null default now(),
  constraint evidence_inventory_display_path_relative_check
    check (
      length(btrim(display_path)) > 0
      and left(display_path, 1) <> '/'
      and display_path !~ '(^|/)\.\.(/|$)'
      and display_path !~ '^[a-zA-Z]:[\\/]'
    ),
  constraint evidence_inventory_entry_kind_check
    check (entry_kind in ('regular', 'directory', 'symlink', 'multilink', 'nonregular', 'partial')),
  constraint evidence_inventory_disposition_check
    check (disposition in ('pending', 'ignored')),
  constraint evidence_inventory_sha256_shape_check
    check (sha256 is null or sha256 ~ '^sha256:[0-9a-f]{64}$'),
  unique (case_id, display_path)
);

create index if not exists evidence_inventory_case_idx
  on app.evidence_inventory (case_id);
create index if not exists evidence_inventory_case_disposition_idx
  on app.evidence_inventory (case_id, disposition);

-- ---------------------------------------------------------------------------
-- admission_observations — append-only history of every reconciliation.
-- Each reconcile (dispatch-driven, refresh-driven, or the Gateway-internal
-- periodic pass) appends exactly one row recording the classified gate state,
-- live storage availability, and a bounded finding summary. The computed gate
-- reads the LATEST row's storage_available as its unavailability input; the rest
-- is visibility/audit, never authority by assertion.
-- ---------------------------------------------------------------------------
create table if not exists app.admission_observations (
  id bigint generated always as identity primary key,
  case_id uuid not null references app.cases(id) on delete cascade,
  -- Opaque MCP request / durable job correlation id (never a path or secret).
  correlation_id text null,
  trigger text not null default 'dispatch',
  gate_state text not null,
  storage_available boolean not null default true,
  pending_count integer not null default 0,
  violation_count integer not null default 0,
  findings jsonb not null default '[]'::jsonb,
  observed_at timestamptz not null default now(),
  constraint admission_observations_trigger_check
    check (trigger in ('dispatch', 'refresh', 'periodic')),
  constraint admission_observations_gate_state_check
    check (gate_state in ('OPEN', 'BLOCKED_PENDING', 'BLOCKED_VIOLATION', 'BLOCKED_UNAVAILABLE')),
  constraint admission_observations_correlation_len_check
    check (correlation_id is null or length(correlation_id) <= 128)
);

create index if not exists admission_observations_case_observed_idx
  on app.admission_observations (case_id, observed_at desc);

-- ---------------------------------------------------------------------------
-- Append-only enforcement: admission_observations is history and never mutates.
-- evidence_inventory is a live snapshot (upsert/delete are normal), so it has no
-- block trigger.
-- ---------------------------------------------------------------------------
drop trigger if exists admission_observations_no_update_delete on app.admission_observations;
create trigger admission_observations_no_update_delete
  before update or delete on app.admission_observations
  for each row execute function app.evidence_block_mutation();

drop trigger if exists admission_observations_no_truncate on app.admission_observations;
create trigger admission_observations_no_truncate
  before truncate on app.admission_observations
  for each statement execute function app.custody_block_truncate();

-- ---------------------------------------------------------------------------
-- RLS: service-role mediated; browser reads via the Gateway. FORCE RLS so even a
-- table owner is subject to policy. A forward-looking case-member SELECT policy
-- mirrors the released custody tables for a later narrow direct browser read.
-- ---------------------------------------------------------------------------
alter table app.evidence_inventory enable row level security;
alter table app.evidence_inventory force row level security;
alter table app.admission_observations enable row level security;
alter table app.admission_observations force row level security;

do $$
declare
  v_table text;
begin
  foreach v_table in array array['evidence_inventory', 'admission_observations']
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

revoke all on app.evidence_inventory from public, anon, authenticated;
revoke all on app.admission_observations from public, anon, authenticated;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant select on app.evidence_inventory to service_role;
    grant select on app.admission_observations to service_role;
  end if;
end
$$;

comment on table app.evidence_inventory is
  'Current read-only reconciliation snapshot (one row per present-on-disk path). '
  'Pending entries live here, never as evidence_objects (EC-1/EC-4). Vanished '
  'paths are deleted (present-on-disk truth). Not authority over sealed evidence.';
comment on table app.admission_observations is
  'Append-only history of reconciliations. Records classified gate state and live '
  'storage availability per observation; the computed gate reads the latest '
  'storage_available. Visibility/audit, never authority by assertion.';
