-- BATCH-C1: DB evidence authority, custody ledger, and seal broker.
--
-- This migration moves evidence-chain authority from the file-backed
-- evidence-manifest.json + evidence-ledger.jsonl model into Postgres. The DB
-- becomes the authoritative state machine for detected/registered/sealed/
-- ignored/retired/violated evidence, append-only hash-linked custody events,
-- per-case hash-chain heads + seal status, and proof-export metadata.
--
-- File manifests, ledgers, and proof bundles remain EXPORTS only (artifacts the
-- broker/worker can emit and re-verify against mounted bytes); they are no
-- longer the authority. The migration stores NO absolute case/evidence/mount
-- paths and NO raw secret material. The AI agent never receives the resolved
-- local path; brokers/workers resolve evidence_id -> mount path internally.
--
-- Sensitive transitions (seal/ignore/retire/violation) are exposed only through
-- security-definer RPCs executable by the service role (the Gateway/portal
-- security workflow), and seal additionally requires a re-auth assertion
-- carried by the caller (password/HMAC re-auth happens in the portal workflow;
-- the RPC records the re-auth event id and rejects a seal without it).

create schema if not exists app;
create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- 1. Registered evidence authority
-- ---------------------------------------------------------------------------
-- One row per evidence item under a case. evidence_id (the row id) is the
-- opaque handle exposed to agents. display_path is a RELATIVE display path only
-- (e.g. evidence/disk.E01); absolute case/mount paths are never stored here.
create table if not exists app.evidence_objects (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  display_name text not null,
  display_path text not null,
  description text null,
  source text null,
  -- Lifecycle authority for this evidence item.
  status text not null default 'detected',
  -- Seal-level summary for the gate (independent of item-detail diffs).
  seal_status text not null default 'unsealed',
  -- Pointer to the current sealed/registered version snapshot.
  current_version_id uuid null,
  -- Latest known content hash for the item (sha256:<hex>); null until hashed.
  current_sha256 text null,
  current_bytes bigint null,
  detected_by_user_id uuid null references app.operator_profiles(id) on delete set null,
  registered_by_user_id uuid null references app.operator_profiles(id) on delete set null,
  sealed_by_user_id uuid null references app.operator_profiles(id) on delete set null,
  detected_at timestamptz null,
  registered_at timestamptz null,
  sealed_at timestamptz null,
  retired_at timestamptz null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint evidence_objects_status_check
    check (status in ('detected', 'registered', 'sealed', 'ignored', 'retired', 'violated')),
  constraint evidence_objects_seal_status_check
    check (seal_status in ('unsealed', 'sealed', 'violated')),
  -- display_path must be a relative path. Reject absolute paths and traversal so
  -- no absolute OS/mount path is ever persisted as evidence display metadata.
  constraint evidence_objects_display_path_relative_check
    check (
      length(btrim(display_path)) > 0
      and left(display_path, 1) <> '/'
      and display_path !~ '(^|/)\.\.(/|$)'
      and display_path !~ '^[a-zA-Z]:[\\/]'
    ),
  constraint evidence_objects_display_name_check
    check (length(btrim(display_name)) > 0),
  constraint evidence_objects_sha256_shape_check
    check (current_sha256 is null or current_sha256 ~ '^sha256:[0-9a-f]{64}$')
);

-- ---------------------------------------------------------------------------
-- 2. Immutable per-version snapshots (derived from sealed manifests)
-- ---------------------------------------------------------------------------
-- Each seal/register/ignore/retire transition that changes the manifest creates
-- a new manifest version for the case. evidence_versions records the per-item
-- snapshot at that version. These rows are append-only (enforced by trigger).
create table if not exists app.evidence_versions (
  id uuid primary key default gen_random_uuid(),
  evidence_object_id uuid not null references app.evidence_objects(id) on delete cascade,
  case_id uuid not null references app.cases(id) on delete cascade,
  manifest_version integer not null,
  sha256 text null,
  bytes bigint null,
  -- ACTIVE / IGNORED / RETIRED — mirrors the file manifest entry status.
  entry_status text not null default 'ACTIVE',
  manifest_hash text null,
  registered_by text null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint evidence_versions_entry_status_check
    check (entry_status in ('ACTIVE', 'IGNORED', 'RETIRED')),
  constraint evidence_versions_manifest_version_check
    check (manifest_version >= 0),
  constraint evidence_versions_sha256_shape_check
    check (sha256 is null or sha256 ~ '^sha256:[0-9a-f]{64}$')
);

alter table app.evidence_objects
  add constraint evidence_objects_current_version_fkey
  foreign key (current_version_id) references app.evidence_versions(id) on delete set null;

-- ---------------------------------------------------------------------------
-- 3. Append-only hash-linked custody ledger
-- ---------------------------------------------------------------------------
-- prev_hash/event_hash form a per-case hash chain. Each event optionally carries
-- a re-auth audit event id for human-gated transitions. Rows are append-only
-- (no UPDATE/DELETE) enforced by trigger; the chain head lives in
-- app.evidence_chain_heads.
create table if not exists app.evidence_custody_events (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  evidence_object_id uuid null references app.evidence_objects(id) on delete set null,
  -- Monotonic per-case sequence number (1-based).
  seq bigint not null,
  event_type text not null,
  manifest_version integer null,
  -- Hash chain: prev_hash is '' for the genesis event of a case.
  prev_hash text not null default '',
  event_hash text not null,
  -- Re-auth linkage for human-gated transitions (seal/ignore/retire/violation).
  reauth_audit_event_id uuid null references app.audit_events(id) on delete set null,
  audit_event_id uuid null references app.audit_events(id) on delete set null,
  actor_user_id uuid null references app.operator_profiles(id) on delete set null,
  actor_service_identity_id uuid null references app.service_identities(id) on delete set null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint evidence_custody_events_event_type_check
    check (event_type in (
      'EVIDENCE_DETECTED',
      'EVIDENCE_REGISTERED',
      'MANIFEST_SEALED',
      'CHAIN_VERIFIED',
      'FILE_IGNORED',
      'FILE_RETIRED',
      'CHAIN_VIOLATION'
    )),
  constraint evidence_custody_events_seq_check
    check (seq >= 1),
  constraint evidence_custody_events_event_hash_check
    check (length(btrim(event_hash)) > 0)
);

-- ---------------------------------------------------------------------------
-- 4. Per-case chain head + aggregate seal status (gate read model)
-- ---------------------------------------------------------------------------
-- The fail-closed evidence gate reads seal_status/manifest_version here to
-- decide allow/deny without re-walking files. One row per case.
create table if not exists app.evidence_chain_heads (
  case_id uuid primary key references app.cases(id) on delete cascade,
  manifest_version integer not null default 0,
  head_seq bigint not null default 0,
  head_hash text not null default '',
  manifest_hash text null,
  -- Aggregate gate status for the case.
  seal_status text not null default 'unsealed',
  active_count integer not null default 0,
  issues jsonb not null default '[]'::jsonb,
  last_event_type text null,
  last_verified_at timestamptz null,
  updated_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  constraint evidence_chain_heads_seal_status_check
    check (seal_status in ('unsealed', 'sealed', 'violated')),
  constraint evidence_chain_heads_manifest_version_check
    check (manifest_version >= 0)
);

-- ---------------------------------------------------------------------------
-- 5. Proof-export metadata (exports are artifacts, not authority)
-- ---------------------------------------------------------------------------
-- Records that a manifest/ledger/anchor proof bundle was exported for a case
-- version and verified against mounted bytes. The bundle itself stays on disk;
-- this table only carries non-authoritative export metadata + verify outcome.
create table if not exists app.evidence_proof_exports (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references app.cases(id) on delete cascade,
  manifest_version integer not null,
  -- Export kind: file manifest, ledger, anchor proof, or combined bundle.
  export_kind text not null default 'bundle',
  manifest_hash text null,
  ledger_tip_hash text null,
  -- Verification outcome against mounted evidence at export time.
  verified boolean not null default false,
  verified_at timestamptz null,
  exported_by_user_id uuid null references app.operator_profiles(id) on delete set null,
  audit_event_id uuid null references app.audit_events(id) on delete set null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint evidence_proof_exports_export_kind_check
    check (export_kind in ('manifest', 'ledger', 'anchor', 'bundle')),
  constraint evidence_proof_exports_manifest_version_check
    check (manifest_version >= 0)
);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------
create index if not exists evidence_objects_case_status_idx
  on app.evidence_objects (case_id, status);
create index if not exists evidence_objects_case_seal_status_idx
  on app.evidence_objects (case_id, seal_status);
create unique index if not exists evidence_objects_case_display_path_key
  on app.evidence_objects (case_id, display_path);
create index if not exists evidence_objects_current_version_idx
  on app.evidence_objects (current_version_id);
create index if not exists evidence_objects_updated_at_idx
  on app.evidence_objects (updated_at);

create index if not exists evidence_versions_object_idx
  on app.evidence_versions (evidence_object_id, manifest_version);
create index if not exists evidence_versions_case_version_idx
  on app.evidence_versions (case_id, manifest_version);

create unique index if not exists evidence_custody_events_case_seq_key
  on app.evidence_custody_events (case_id, seq);
create index if not exists evidence_custody_events_case_created_at_idx
  on app.evidence_custody_events (case_id, created_at);
create index if not exists evidence_custody_events_object_idx
  on app.evidence_custody_events (evidence_object_id);
create index if not exists evidence_custody_events_event_type_idx
  on app.evidence_custody_events (event_type);

create index if not exists evidence_proof_exports_case_version_idx
  on app.evidence_proof_exports (case_id, manifest_version);
create index if not exists evidence_proof_exports_verified_idx
  on app.evidence_proof_exports (case_id, verified);

-- ---------------------------------------------------------------------------
-- Append-only enforcement for the custody ledger and version snapshots
-- ---------------------------------------------------------------------------
create or replace function app.evidence_block_mutation()
returns trigger
language plpgsql
as $$
begin
  raise exception 'append-only: % on % is not permitted', tg_op, tg_table_name
    using errcode = 'restrict_violation';
end;
$$;

drop trigger if exists evidence_custody_events_no_update on app.evidence_custody_events;
create trigger evidence_custody_events_no_update
  before update or delete on app.evidence_custody_events
  for each row execute function app.evidence_block_mutation();

drop trigger if exists evidence_versions_no_update on app.evidence_versions;
create trigger evidence_versions_no_update
  before update or delete on app.evidence_versions
  for each row execute function app.evidence_block_mutation();

-- ---------------------------------------------------------------------------
-- Internal helper: append one custody event, advancing the per-case hash chain.
-- prev_hash links to the prior head; event_hash = sha256 over canonical fields.
-- Updates app.evidence_chain_heads head pointer. Returns the new event row id.
-- ---------------------------------------------------------------------------
create or replace function app.evidence_append_custody_event(
  p_case_id uuid,
  p_evidence_object_id uuid,
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
set search_path = app, public
as $$
declare
  v_prev_seq bigint;
  v_prev_hash text;
  v_seq bigint;
  v_event_hash text;
  v_event_id uuid;
  v_payload text;
begin
  -- Lock the head row to serialize chain appends per case.
  insert into app.evidence_chain_heads (case_id)
    values (p_case_id)
    on conflict (case_id) do nothing;

  select head_seq, head_hash
    into v_prev_seq, v_prev_hash
    from app.evidence_chain_heads
    where case_id = p_case_id
    for update;

  v_seq := coalesce(v_prev_seq, 0) + 1;
  v_prev_hash := coalesce(v_prev_hash, '');

  -- Canonical, order-stable payload for the chain hash.
  v_payload := coalesce(v_prev_hash, '')
    || '|' || p_case_id::text
    || '|' || v_seq::text
    || '|' || p_event_type
    || '|' || coalesce(p_evidence_object_id::text, '')
    || '|' || coalesce(p_manifest_version::text, '')
    || '|' || coalesce(p_manifest_hash, '')
    || '|' || coalesce(p_details::text, '{}');
  v_event_hash := 'sha256:' || encode(digest(v_payload, 'sha256'), 'hex');

  insert into app.evidence_custody_events (
    case_id, evidence_object_id, seq, event_type, manifest_version,
    prev_hash, event_hash, reauth_audit_event_id, actor_user_id,
    actor_service_identity_id, details
  ) values (
    p_case_id, p_evidence_object_id, v_seq, p_event_type, p_manifest_version,
    v_prev_hash, v_event_hash, p_reauth_audit_event_id, p_actor_user_id,
    p_actor_service_identity_id, coalesce(p_details, '{}'::jsonb)
  )
  returning id into v_event_id;

  update app.evidence_chain_heads
    set head_seq = v_seq,
        head_hash = v_event_hash,
        last_event_type = p_event_type,
        manifest_version = greatest(manifest_version, coalesce(p_manifest_version, manifest_version)),
        manifest_hash = coalesce(p_manifest_hash, manifest_hash),
        updated_at = now()
    where case_id = p_case_id;

  return v_event_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- Internal helper: recompute the aggregate gate seal_status for a case from
-- its evidence_objects and write it onto the chain head. A case is 'violated'
-- if any object is violated, 'sealed' only if at least one object is sealed and
-- none is unsealed-but-registered/detected blocking, else 'unsealed'.
-- ---------------------------------------------------------------------------
create or replace function app.evidence_recompute_seal_status(p_case_id uuid)
returns text
language plpgsql
security definer
set search_path = app, public
as $$
declare
  v_violated integer;
  v_sealed integer;
  v_pending integer;
  v_status text;
begin
  select
    count(*) filter (where status = 'violated' or seal_status = 'violated'),
    count(*) filter (where seal_status = 'sealed' and status = 'sealed'),
    count(*) filter (where status in ('detected', 'registered'))
    into v_violated, v_sealed, v_pending
    from app.evidence_objects
    where case_id = p_case_id;

  if coalesce(v_violated, 0) > 0 then
    v_status := 'violated';
  elsif coalesce(v_sealed, 0) > 0 and coalesce(v_pending, 0) = 0 then
    v_status := 'sealed';
  else
    v_status := 'unsealed';
  end if;

  insert into app.evidence_chain_heads (case_id, seal_status, active_count)
    values (p_case_id, v_status, coalesce(v_sealed, 0))
    on conflict (case_id) do update
      set seal_status = excluded.seal_status,
          active_count = excluded.active_count,
          updated_at = now();

  return v_status;
end;
$$;

-- ---------------------------------------------------------------------------
-- Transition RPC: DETECT
-- Records an unregistered file discovered under the case evidence tree. Idempotent
-- on (case_id, display_path): a re-detect of an existing item is a no-op insert.
-- ---------------------------------------------------------------------------
create or replace function app.evidence_detect(
  p_case_id uuid,
  p_display_path text,
  p_display_name text default null,
  p_bytes bigint default null,
  p_actor_user_id uuid default null,
  p_actor_service_identity_id uuid default null
)
returns uuid
language plpgsql
security definer
set search_path = app, public
as $$
declare
  v_id uuid;
  v_name text;
begin
  v_name := coalesce(nullif(btrim(coalesce(p_display_name, '')), ''),
                     regexp_replace(p_display_path, '^.*/', ''));

  insert into app.evidence_objects (
    case_id, display_name, display_path, status, seal_status,
    current_bytes, detected_by_user_id, detected_at
  ) values (
    p_case_id, v_name, p_display_path, 'detected', 'unsealed',
    p_bytes, p_actor_user_id, now()
  )
  on conflict (case_id, display_path) do nothing
  returning id into v_id;

  if v_id is null then
    select id into v_id from app.evidence_objects
      where case_id = p_case_id and display_path = p_display_path;
    return v_id;
  end if;

  perform app.evidence_append_custody_event(
    p_case_id, v_id, 'EVIDENCE_DETECTED', null, null, null,
    p_actor_user_id, p_actor_service_identity_id,
    jsonb_build_object('display_path', p_display_path)
  );
  perform app.evidence_recompute_seal_status(p_case_id);
  return v_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- Transition RPC: REGISTER
-- Operator names + describes a detected item. Moves status detected -> registered.
-- ---------------------------------------------------------------------------
create or replace function app.evidence_register(
  p_evidence_object_id uuid,
  p_display_name text,
  p_description text default null,
  p_source text default null,
  p_actor_user_id uuid default null,
  p_actor_service_identity_id uuid default null
)
returns app.evidence_objects
language plpgsql
security definer
set search_path = app, public
as $$
declare
  v_row app.evidence_objects;
begin
  select * into v_row from app.evidence_objects where id = p_evidence_object_id for update;
  if not found then
    raise exception 'evidence_object_not_found' using errcode = 'no_data_found';
  end if;
  if v_row.status not in ('detected', 'registered') then
    raise exception 'evidence_register_invalid_state: %', v_row.status
      using errcode = 'invalid_parameter_value';
  end if;
  if length(btrim(coalesce(p_display_name, ''))) = 0 then
    raise exception 'display_name_required' using errcode = 'invalid_parameter_value';
  end if;

  update app.evidence_objects
    set display_name = btrim(p_display_name),
        description = nullif(btrim(coalesce(p_description, '')), ''),
        source = nullif(btrim(coalesce(p_source, '')), ''),
        status = 'registered',
        registered_by_user_id = coalesce(p_actor_user_id, registered_by_user_id),
        registered_at = now(),
        updated_at = now()
    where id = p_evidence_object_id
    returning * into v_row;

  perform app.evidence_append_custody_event(
    v_row.case_id, v_row.id, 'EVIDENCE_REGISTERED', null, null, null,
    p_actor_user_id, p_actor_service_identity_id,
    jsonb_build_object('display_name', v_row.display_name)
  );
  perform app.evidence_recompute_seal_status(v_row.case_id);
  return v_row;
end;
$$;

-- ---------------------------------------------------------------------------
-- Transition RPC: SEAL (requires re-auth)
-- Seals one or more registered items at a new manifest version. The portal
-- security workflow performs password/HMAC re-auth and passes the resulting
-- audit event id; this RPC REJECTS a seal without a re-auth event id. The full
-- SHA-256 hashes are computed by the broker against mounted bytes and passed in
-- p_items as [{evidence_object_id, sha256, bytes}, ...].
-- ---------------------------------------------------------------------------
create or replace function app.evidence_seal(
  p_case_id uuid,
  p_items jsonb,
  p_manifest_version integer,
  p_manifest_hash text,
  p_reauth_audit_event_id uuid,
  p_actor_user_id uuid default null,
  p_actor_service_identity_id uuid default null
)
returns app.evidence_chain_heads
language plpgsql
security definer
set search_path = app, public
as $$
declare
  v_item jsonb;
  v_obj_id uuid;
  v_sha text;
  v_bytes bigint;
  v_version_id uuid;
  v_head app.evidence_chain_heads;
begin
  if p_reauth_audit_event_id is null then
    raise exception 'seal_requires_reauth' using errcode = 'insufficient_privilege';
  end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) = 0 then
    raise exception 'seal_requires_items' using errcode = 'invalid_parameter_value';
  end if;

  for v_item in select * from jsonb_array_elements(p_items)
  loop
    v_obj_id := (v_item->>'evidence_object_id')::uuid;
    v_sha := v_item->>'sha256';
    v_bytes := nullif(v_item->>'bytes', '')::bigint;

    perform 1 from app.evidence_objects
      where id = v_obj_id and case_id = p_case_id for update;
    if not found then
      raise exception 'evidence_object_not_in_case: %', v_obj_id
        using errcode = 'no_data_found';
    end if;

    insert into app.evidence_versions (
      evidence_object_id, case_id, manifest_version, sha256, bytes,
      entry_status, manifest_hash, registered_by
    ) values (
      v_obj_id, p_case_id, p_manifest_version, v_sha, v_bytes,
      'ACTIVE', p_manifest_hash, v_item->>'registered_by'
    )
    returning id into v_version_id;

    update app.evidence_objects
      set status = 'sealed',
          seal_status = 'sealed',
          current_version_id = v_version_id,
          current_sha256 = v_sha,
          current_bytes = v_bytes,
          sealed_by_user_id = coalesce(p_actor_user_id, sealed_by_user_id),
          sealed_at = now(),
          updated_at = now()
      where id = v_obj_id;
  end loop;

  perform app.evidence_append_custody_event(
    p_case_id, null, 'MANIFEST_SEALED', p_manifest_version, p_manifest_hash,
    p_reauth_audit_event_id, p_actor_user_id, p_actor_service_identity_id,
    jsonb_build_object('items', jsonb_array_length(p_items))
  );
  perform app.evidence_recompute_seal_status(p_case_id);

  select * into v_head from app.evidence_chain_heads where case_id = p_case_id;
  return v_head;
end;
$$;

-- ---------------------------------------------------------------------------
-- Transition RPC: VERIFY
-- Records a structural/HMAC verification outcome for the case chain. ok=false
-- escalates the case to 'violated'. Returns the chain head.
-- ---------------------------------------------------------------------------
create or replace function app.evidence_verify(
  p_case_id uuid,
  p_ok boolean,
  p_manifest_version integer default null,
  p_issues jsonb default '[]'::jsonb,
  p_actor_user_id uuid default null,
  p_actor_service_identity_id uuid default null
)
returns app.evidence_chain_heads
language plpgsql
security definer
set search_path = app, public
as $$
declare
  v_head app.evidence_chain_heads;
begin
  if p_ok then
    perform app.evidence_append_custody_event(
      p_case_id, null, 'CHAIN_VERIFIED', p_manifest_version, null, null,
      p_actor_user_id, p_actor_service_identity_id,
      jsonb_build_object('ok', true)
    );
    update app.evidence_chain_heads
      set last_verified_at = now(),
          issues = coalesce(p_issues, '[]'::jsonb),
          updated_at = now()
      where case_id = p_case_id;
    perform app.evidence_recompute_seal_status(p_case_id);
  else
    return app.evidence_mark_violation(
      p_case_id, null, 'verify_failed', p_issues,
      p_actor_user_id, p_actor_service_identity_id
    );
  end if;

  select * into v_head from app.evidence_chain_heads where case_id = p_case_id;
  return v_head;
end;
$$;

-- ---------------------------------------------------------------------------
-- Transition RPC: IGNORE
-- Operator decision to exclude an unregistered file. Records FILE_IGNORED.
-- ---------------------------------------------------------------------------
create or replace function app.evidence_ignore(
  p_evidence_object_id uuid,
  p_reason text,
  p_reauth_audit_event_id uuid,
  p_actor_user_id uuid default null,
  p_actor_service_identity_id uuid default null
)
returns app.evidence_objects
language plpgsql
security definer
set search_path = app, public
as $$
declare
  v_row app.evidence_objects;
begin
  if p_reauth_audit_event_id is null then
    raise exception 'ignore_requires_reauth' using errcode = 'insufficient_privilege';
  end if;
  select * into v_row from app.evidence_objects where id = p_evidence_object_id for update;
  if not found then
    raise exception 'evidence_object_not_found' using errcode = 'no_data_found';
  end if;

  update app.evidence_objects
    set status = 'ignored',
        seal_status = 'unsealed',
        description = coalesce(nullif(btrim(coalesce(p_reason, '')), ''), description),
        updated_at = now()
    where id = p_evidence_object_id
    returning * into v_row;

  perform app.evidence_append_custody_event(
    v_row.case_id, v_row.id, 'FILE_IGNORED', null, null,
    p_reauth_audit_event_id, p_actor_user_id, p_actor_service_identity_id,
    jsonb_build_object('reason', p_reason)
  );
  perform app.evidence_recompute_seal_status(v_row.case_id);
  return v_row;
end;
$$;

-- ---------------------------------------------------------------------------
-- Transition RPC: RETIRE (requires re-auth)
-- Operator decision to deliberately remove a previously registered/sealed item.
-- Records FILE_RETIRED. The actual on-disk unlink is performed by the broker.
-- ---------------------------------------------------------------------------
create or replace function app.evidence_retire(
  p_evidence_object_id uuid,
  p_reason text,
  p_reauth_audit_event_id uuid,
  p_actor_user_id uuid default null,
  p_actor_service_identity_id uuid default null
)
returns app.evidence_objects
language plpgsql
security definer
set search_path = app, public
as $$
declare
  v_row app.evidence_objects;
begin
  if p_reauth_audit_event_id is null then
    raise exception 'retire_requires_reauth' using errcode = 'insufficient_privilege';
  end if;
  select * into v_row from app.evidence_objects where id = p_evidence_object_id for update;
  if not found then
    raise exception 'evidence_object_not_found' using errcode = 'no_data_found';
  end if;
  if v_row.status = 'ignored' then
    raise exception 'cannot_retire_ignored' using errcode = 'invalid_parameter_value';
  end if;

  update app.evidence_objects
    set status = 'retired',
        seal_status = 'unsealed',
        retired_at = now(),
        updated_at = now()
    where id = p_evidence_object_id
    returning * into v_row;

  perform app.evidence_append_custody_event(
    v_row.case_id, v_row.id, 'FILE_RETIRED', null, null,
    p_reauth_audit_event_id, p_actor_user_id, p_actor_service_identity_id,
    jsonb_build_object('reason', p_reason)
  );
  perform app.evidence_recompute_seal_status(v_row.case_id);
  return v_row;
end;
$$;

-- ---------------------------------------------------------------------------
-- Transition RPC: MARK VIOLATION
-- Escalates the case chain to 'violated' (e.g. missing/modified/unregistered
-- file detected after seal, or broken hash chain). Records CHAIN_VIOLATION.
-- ---------------------------------------------------------------------------
create or replace function app.evidence_mark_violation(
  p_case_id uuid,
  p_evidence_object_id uuid,
  p_reason text,
  p_issues jsonb default '[]'::jsonb,
  p_actor_user_id uuid default null,
  p_actor_service_identity_id uuid default null
)
returns app.evidence_chain_heads
language plpgsql
security definer
set search_path = app, public
as $$
declare
  v_head app.evidence_chain_heads;
begin
  if p_evidence_object_id is not null then
    update app.evidence_objects
      set status = 'violated', seal_status = 'violated', updated_at = now()
      where id = p_evidence_object_id and case_id = p_case_id;
  end if;

  perform app.evidence_append_custody_event(
    p_case_id, p_evidence_object_id, 'CHAIN_VIOLATION', null, null, null,
    p_actor_user_id, p_actor_service_identity_id,
    jsonb_build_object('reason', p_reason, 'issues', coalesce(p_issues, '[]'::jsonb))
  );

  insert into app.evidence_chain_heads (case_id, seal_status, issues)
    values (p_case_id, 'violated', coalesce(p_issues, '[]'::jsonb))
    on conflict (case_id) do update
      set seal_status = 'violated',
          issues = coalesce(p_issues, '[]'::jsonb),
          updated_at = now();

  select * into v_head from app.evidence_chain_heads where case_id = p_case_id;
  return v_head;
end;
$$;

-- ---------------------------------------------------------------------------
-- Read model RPC: gate status for a case (fail-closed default).
-- The Gateway evidence gate calls this to resolve seal status without touching
-- files. Returns unsealed (blocked) when no head row exists for the case.
-- ---------------------------------------------------------------------------
create or replace function app.evidence_gate_status(p_case_id uuid)
returns table (
  case_id uuid,
  seal_status text,
  manifest_version integer,
  head_hash text,
  active_count integer,
  issues jsonb,
  last_verified_at timestamptz
)
language sql
stable
security definer
set search_path = app, public
as $$
  select
    coalesce(h.case_id, p_case_id) as case_id,
    coalesce(h.seal_status, 'unsealed') as seal_status,
    coalesce(h.manifest_version, 0) as manifest_version,
    coalesce(h.head_hash, '') as head_hash,
    coalesce(h.active_count, 0) as active_count,
    coalesce(h.issues, '[]'::jsonb) as issues,
    h.last_verified_at
  from (select p_case_id as case_id) base
  left join app.evidence_chain_heads h on h.case_id = p_case_id;
$$;

-- ---------------------------------------------------------------------------
-- Proof-export metadata RPC. The bundle is written to disk by the broker; this
-- only records non-authoritative export metadata and the verify outcome.
-- ---------------------------------------------------------------------------
create or replace function app.evidence_record_proof_export(
  p_case_id uuid,
  p_manifest_version integer,
  p_export_kind text,
  p_manifest_hash text,
  p_ledger_tip_hash text,
  p_verified boolean,
  p_exported_by_user_id uuid default null,
  p_metadata jsonb default '{}'::jsonb
)
returns uuid
language plpgsql
security definer
set search_path = app, public
as $$
declare
  v_id uuid;
begin
  insert into app.evidence_proof_exports (
    case_id, manifest_version, export_kind, manifest_hash, ledger_tip_hash,
    verified, verified_at, exported_by_user_id, metadata
  ) values (
    p_case_id, p_manifest_version, coalesce(p_export_kind, 'bundle'),
    p_manifest_hash, p_ledger_tip_hash, coalesce(p_verified, false),
    case when p_verified then now() else null end,
    p_exported_by_user_id, coalesce(p_metadata, '{}'::jsonb)
  )
  returning id into v_id;
  return v_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- RLS: enable on every new table. No broad direct grants are issued (D12). The
-- Gateway/portal service workflow reads/writes via the service-role DSN, which
-- bypasses RLS by design; the browser reaches these through the Gateway, not
-- the DB directly. A forward-looking operator SELECT policy mirrors PR03 so a
-- later phase can grant narrow direct browser SELECT without a schema change.
-- ---------------------------------------------------------------------------
alter table app.evidence_objects enable row level security;
alter table app.evidence_versions enable row level security;
alter table app.evidence_custody_events enable row level security;
alter table app.evidence_chain_heads enable row level security;
alter table app.evidence_proof_exports enable row level security;

do $$
declare
  v_table text;
begin
  foreach v_table in array array[
    'evidence_objects',
    'evidence_versions',
    'evidence_custody_events',
    'evidence_chain_heads',
    'evidence_proof_exports'
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
-- Service-only execute grants on the transition RPCs. Internal helpers are NOT
-- granted to any client role. No grant to anon/authenticated: these RPCs are
-- the service-mediated transition path only.
-- ---------------------------------------------------------------------------
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant execute on function app.evidence_detect(uuid, text, text, bigint, uuid, uuid) to service_role;
    grant execute on function app.evidence_register(uuid, text, text, text, uuid, uuid) to service_role;
    grant execute on function app.evidence_seal(uuid, jsonb, integer, text, uuid, uuid, uuid) to service_role;
    grant execute on function app.evidence_verify(uuid, boolean, integer, jsonb, uuid, uuid) to service_role;
    grant execute on function app.evidence_ignore(uuid, text, uuid, uuid, uuid) to service_role;
    grant execute on function app.evidence_retire(uuid, text, uuid, uuid, uuid) to service_role;
    grant execute on function app.evidence_mark_violation(uuid, uuid, text, jsonb, uuid, uuid) to service_role;
    grant execute on function app.evidence_gate_status(uuid) to service_role;
    grant execute on function app.evidence_record_proof_export(uuid, integer, text, text, text, boolean, uuid, jsonb) to service_role;
  end if;
end
$$;

-- ---------------------------------------------------------------------------
-- Comments (authority documentation)
-- ---------------------------------------------------------------------------
comment on table app.evidence_objects is
  'Authoritative registered-evidence items per case. The row id is the opaque '
  'evidence_id exposed to agents. display_path is relative only; absolute '
  'case/mount paths are never stored. Brokers/workers resolve evidence_id to a '
  'local mount path internally.';
comment on column app.evidence_objects.display_path is
  'Relative display path under the case evidence tree (e.g. evidence/disk.E01). '
  'Absolute paths and traversal are rejected by check constraint.';
comment on table app.evidence_versions is
  'Append-only per-item snapshots at each sealed manifest version. Derived from '
  'the file manifest; the DB row is the authority, the manifest file is an export.';
comment on table app.evidence_custody_events is
  'Append-only, per-case hash-linked custody ledger (prev_hash/event_hash). '
  'Human-gated transitions carry a reauth_audit_event_id. UPDATE/DELETE blocked '
  'by trigger.';
comment on table app.evidence_chain_heads is
  'Per-case hash-chain head and aggregate gate seal_status. The fail-closed '
  'evidence gate reads seal_status/manifest_version here. Missing row = unsealed '
  '= blocked.';
comment on table app.evidence_proof_exports is
  'Non-authoritative metadata for exported manifest/ledger/anchor proof bundles '
  'and their verification outcome against mounted evidence. Exports are artifacts, '
  'not authority.';
comment on function app.evidence_seal(uuid, jsonb, integer, text, uuid, uuid, uuid) is
  'Service-only seal transition. Rejects a seal without a re-auth audit event id '
  '(password/HMAC re-auth happens in the portal workflow).';
comment on function app.evidence_gate_status(uuid) is
  'Fail-closed gate read model. Returns unsealed for a case with no chain head.';
