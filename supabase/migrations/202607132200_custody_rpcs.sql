-- P4.23 custody remediation — CP1 Foundation (NEW 2026-07-20).
--
-- The target custody mutation surface: a small set of SECURITY DEFINER RPCs,
-- service-role only, that are the ONLY custody-mutation path (OPERATING-MODEL §2;
-- SPEC §Non-Negotiable Security Boundary 4/5). MCP holds zero grants here. CP2A
-- (custody/seal.py, custody/actions.py, custody/reauth.py) and CP2B
-- (custody/ledger.py) are the Python callers of these RPCs; this file freezes the
-- database contract they code against.
--
-- Transaction boundaries (§2): one transaction per seal transition; COMMITTED is
-- one atomic transaction (objects + versions + manifest + membership + canonical
-- events + completion). Ignore/Retire/Reprotect are each one transaction with no
-- persistent failure state (EC-2a).

-- ===========================================================================
-- custody_reconcile — persist one read-only reconciliation and return the gate.
-- ===========================================================================
-- Upserts the current on-disk inventory (present-on-disk truth: vanished paths
-- are deleted; 'ignored' disposition is preserved while a path stays present),
-- appends one admission_observations row, and returns the computed gate state.
-- This is the sole persistence path for reconcile-before-dispatch, operator
-- Refresh, and the Gateway-internal periodic pass (SPEC D1/D3). It never mutates
-- evidence bytes and never creates an evidence_object.
create or replace function app.custody_reconcile(
  p_case_id uuid,
  p_entries jsonb,
  p_storage_available boolean,
  p_trigger text default 'dispatch',
  p_correlation_id text default null,
  p_actor_user_id uuid default null,
  p_actor_service_identity_id uuid default null
)
returns text
language plpgsql
security definer
set search_path = pg_catalog, app
as $$
declare
  v_gate text;
  v_pending integer := 0;
  v_violation integer := 0;
  v_corr text;
begin
  v_corr := nullif(btrim(coalesce(p_correlation_id, '')), '');
  if v_corr is not null and length(v_corr) > 128 then
    raise exception 'correlation_id_too_long' using errcode = 'invalid_parameter_value';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text, 0));

  if coalesce(p_storage_available, false) then
    if jsonb_typeof(coalesce(p_entries, '[]'::jsonb)) <> 'array' then
      raise exception 'entries_must_be_array' using errcode = 'invalid_parameter_value';
    end if;

    -- Present-on-disk truth: drop rows whose path is no longer on disk.
    delete from app.evidence_inventory i
      where i.case_id = p_case_id
        and not exists (
          select 1 from jsonb_array_elements(p_entries) e
          where e->>'display_path' = i.display_path
        );

    -- Upsert present entries; preserve disposition + first_observed_at.
    insert into app.evidence_inventory (
      case_id, display_path, display_name, entry_kind, bytes, sha256,
      st_dev, st_ino, st_nlink, st_mode, owner, observed_at
    )
    select
      p_case_id,
      e->>'display_path',
      coalesce(nullif(btrim(e->>'display_name'), ''),
               regexp_replace(e->>'display_path', '^.*/', '')),
      coalesce(nullif(e->>'entry_kind', ''), 'regular'),
      nullif(e->>'bytes', '')::bigint,
      nullif(e->>'sha256', ''),
      nullif(e->>'st_dev', '')::bigint,
      nullif(e->>'st_ino', '')::bigint,
      nullif(e->>'st_nlink', '')::integer,
      nullif(e->>'st_mode', ''),
      nullif(e->>'owner', ''),
      now()
    from jsonb_array_elements(coalesce(p_entries, '[]'::jsonb)) e
    on conflict (case_id, display_path) do update
      set display_name = excluded.display_name,
          entry_kind = excluded.entry_kind,
          bytes = excluded.bytes,
          sha256 = excluded.sha256,
          st_dev = excluded.st_dev,
          st_ino = excluded.st_ino,
          st_nlink = excluded.st_nlink,
          st_mode = excluded.st_mode,
          owner = excluded.owner,
          observed_at = now();
  end if;

  v_gate := app.custody_gate_state(p_case_id);

  select count(*) filter (
      where i.disposition = 'pending' and i.entry_kind = 'regular'
        and not exists (
          select 1 from app.evidence_objects o
          where o.case_id = p_case_id and o.status = 'sealed'
            and o.display_path = i.display_path)),
    count(*) filter (
      where i.entry_kind in ('symlink', 'multilink', 'nonregular'))
    into v_pending, v_violation
    from app.evidence_inventory i
    where i.case_id = p_case_id;

  insert into app.admission_observations (
    case_id, correlation_id, trigger, gate_state, storage_available,
    pending_count, violation_count, findings
  ) values (
    p_case_id, v_corr, coalesce(p_trigger, 'dispatch'), v_gate,
    coalesce(p_storage_available, false), coalesce(v_pending, 0),
    coalesce(v_violation, 0), '[]'::jsonb
  );

  return v_gate;
end;
$$;

-- ===========================================================================
-- custody_seal_begin — REQUESTED (create or return an in-flight seal operation).
-- ===========================================================================
-- Verifies the initial reauthorization against the ONE canonical binding (EC-6),
-- enforces one active seal per case, and records the authorized intent. Adding
-- evidence to a case with a committed sealed set passes p_opens_staging_window,
-- which records the window open on the chain (directory immutability is lifted by
-- CP2A's seal.py; the gate stays blocked for the window's duration — SPEC D2).
create or replace function app.custody_seal_begin(
  p_case_id uuid,
  p_idempotency_key text,
  p_request_digest text,
  p_reason text,
  p_reauth_audit_event_id uuid,
  p_targets jsonb,
  p_actor_user_id uuid,
  p_opens_staging_window boolean default false,
  p_actor_service_identity_id uuid default null
)
returns app.custody_seal_operations
language plpgsql
security definer
set search_path = pg_catalog, app
as $$
declare
  v_op app.custody_seal_operations;
  v_reauth app.audit_events;
  v_binding jsonb;
begin
  if length(btrim(coalesce(p_reason, ''))) = 0
     or length(coalesce(p_idempotency_key, '')) not between 1 and 128
     or p_reauth_audit_event_id is null
     or p_actor_user_id is null
     or p_actor_service_identity_id is not null
     or jsonb_typeof(coalesce(p_targets, '[]'::jsonb)) <> 'array'
     or jsonb_array_length(coalesce(p_targets, '[]'::jsonb)) = 0 then
    raise exception 'invalid_seal_request' using errcode = 'invalid_parameter_value';
  end if;

  v_binding := app.custody_reauth_binding(p_idempotency_key, p_reason, p_targets);

  -- EC-6 single-source binding (proof). The reauth binding is bound in TWO
  -- enforced parts, and neither side re-derives the other under a different
  -- language/locale/collation default:
  --   1. {idempotency_key, reason, targets} : the canonical JSON binding, built
  --      ONLY by app.custody_reauth_binding (targets ordered COLLATE "C"). The
  --      writer (record_reauth) persists THIS function's output into
  --      details->'binding'; the verifier below re-derives THIS function and
  --      compares `IS DISTINCT FROM` verbatim — writer==verifier by construction.
  --   2. {actor, case, action} : bound here by SCALAR EQUALITY against the audit
  --      row columns (actor_user_id / case_id / event_type), so they cannot drift
  --      across a language/collation boundary either. They are deliberately NOT
  --      inside the JSON binding.
  select * into v_reauth from app.audit_events
    where id = p_reauth_audit_event_id for share;
  if not found
     or v_reauth.case_id is distinct from p_case_id
     or v_reauth.event_type <> 'reauth.evidence_seal'
     or v_reauth.source <> 'portal_reauth'
     or v_reauth.status <> 'success'
     or v_reauth.actor_type <> 'user'
     or v_reauth.actor_user_id is distinct from p_actor_user_id
     or v_reauth.actor_service_identity_id is distinct from p_actor_service_identity_id
     or v_reauth.details->'binding' is distinct from v_binding then
    raise exception 'seal_reauth_scope_mismatch'
      using errcode = 'invalid_authorization_specification';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text, 0));

  select * into v_op from app.custody_seal_operations
    where case_id = p_case_id and idempotency_key = p_idempotency_key for update;
  if found then
    if v_op.request_digest <> p_request_digest then
      raise exception 'idempotency_key_reused' using errcode = 'P4231';
    end if;
    return v_op;  -- REQUESTED/PROTECTED resume, or COMMITTED replay.
  end if;

  insert into app.custody_seal_operations (
    case_id, action, phase, idempotency_key, request_digest, reason,
    reauth_audit_event_id, binding, targets, opens_staging_window, actor_user_id
  ) values (
    p_case_id, 'ADD_SEAL', 'REQUESTED', p_idempotency_key, p_request_digest,
    btrim(p_reason), p_reauth_audit_event_id, v_binding, p_targets,
    coalesce(p_opens_staging_window, false), p_actor_user_id
  )
  returning * into v_op;

  if v_op.opens_staging_window then
    perform app.custody_append_event(
      p_case_id, null, v_op.id, 'SEAL_WINDOW_OPENED', null, null,
      p_reauth_audit_event_id, p_actor_user_id, p_actor_service_identity_id,
      jsonb_build_object('targets', p_targets));
  end if;

  return v_op;
end;
$$;

-- ===========================================================================
-- custody_seal_protect — PROTECTED (record the posture verified from disk).
-- ===========================================================================
-- CP2A applies immutable protection and recomputes every digest/identity/posture
-- from disk, then records the verified facts here. A target that vanished or
-- changed since the Refresh snapshot must fail in CP2A before this call; the RPC
-- only advances an intact REQUESTED operation.
create or replace function app.custody_seal_protect(
  p_operation_id uuid,
  p_prepared_facts jsonb,
  p_actor_user_id uuid,
  p_actor_service_identity_id uuid default null
)
returns app.custody_seal_operations
language plpgsql
security definer
set search_path = pg_catalog, app
as $$
declare
  v_op app.custody_seal_operations;
begin
  select * into v_op from app.custody_seal_operations
    where id = p_operation_id for update;
  if not found then
    raise exception 'seal_operation_not_found' using errcode = 'no_data_found';
  end if;
  if v_op.phase = 'PROTECTED' then
    return v_op;  -- idempotent re-record of the same phase.
  end if;
  if v_op.phase <> 'REQUESTED' then
    raise exception 'seal_operation_phase_conflict' using errcode = 'serialization_failure';
  end if;
  if v_op.actor_user_id is distinct from p_actor_user_id then
    raise exception 'seal_operation_actor_conflict'
      using errcode = 'invalid_authorization_specification';
  end if;

  update app.custody_seal_operations
    set phase = 'PROTECTED',
        prepared_facts = coalesce(p_prepared_facts, '{}'::jsonb),
        updated_at = now()
    where id = p_operation_id
    returning * into v_op;
  return v_op;
end;
$$;

-- ===========================================================================
-- custody_seal_commit — COMMITTED (one atomic manifest-advancing transaction).
-- ===========================================================================
-- Creates the Evidence Object/Version for each newly sealed target, advances the
-- Manifest Version (carrying prior ACTIVE members forward), appends the canonical
-- events, and records completion. Idempotent: a committed operation replays its
-- recorded result. Retry after an interruption may carry a resume reauthorization
-- (event_type 'reauth.evidence_seal_resume', binding {operation_id}).
create or replace function app.custody_seal_commit(
  p_operation_id uuid,
  p_items jsonb,
  p_examiner text default null,
  p_resume_reauth_audit_event_id uuid default null
)
returns app.custody_seal_operations
language plpgsql
security definer
set search_path = pg_catalog, app
as $$
declare
  v_op app.custody_seal_operations;
  v_item jsonb;
  v_manifest_version integer;
  v_manifest_hash text;
  v_manifest_id uuid;
  v_object_id uuid;
  v_version_id uuid;
  v_members jsonb;
  v_resume app.audit_events;
begin
  select * into v_op from app.custody_seal_operations
    where id = p_operation_id for update;
  if not found then
    raise exception 'seal_operation_not_found' using errcode = 'no_data_found';
  end if;
  if v_op.phase = 'COMMITTED' then
    return v_op;  -- idempotent replay of the recorded result.
  end if;
  if v_op.phase <> 'PROTECTED' then
    raise exception 'seal_operation_not_protected' using errcode = 'invalid_parameter_value';
  end if;
  if jsonb_typeof(coalesce(p_items, '[]'::jsonb)) <> 'array'
     or jsonb_array_length(coalesce(p_items, '[]'::jsonb)) = 0 then
    raise exception 'seal_items_required' using errcode = 'invalid_parameter_value';
  end if;

  if p_resume_reauth_audit_event_id is not null then
    select * into v_resume from app.audit_events
      where id = p_resume_reauth_audit_event_id for share;
    if not found
       or v_resume.case_id is distinct from v_op.case_id
       or v_resume.event_type <> 'reauth.evidence_seal_resume'
       or v_resume.source <> 'portal_reauth'
       or v_resume.status <> 'success'
       or v_resume.actor_type <> 'user'
       or v_resume.actor_user_id is distinct from v_op.actor_user_id
       or v_resume.details->'binding' is distinct
            from jsonb_build_object('operation_id', v_op.id::text) then
      raise exception 'seal_resume_reauth_scope_mismatch'
        using errcode = 'invalid_authorization_specification';
    end if;
  end if;

  perform pg_advisory_xact_lock(hashtextextended(v_op.case_id::text, 0));

  -- CP2A: defense-in-depth — cross-check that the committed p_items set matches
  -- the reauthorized v_op.targets (and their snapshot), so a committed item can
  -- never fall outside what the operator reauthenticated. Deferred to CP2A's
  -- seal.py commit path (no caller yet in CP1); the reauth binding over targets
  -- + the per-item posture invariants below are the CP1 authority.

  -- Enforce the sealed posture invariants on every item (SPEC PROTECTED facts).
  if exists (
    select 1 from jsonb_array_elements(p_items) x
    where x->>'sha256' !~ '^sha256:[0-9a-f]{64}$'
       or coalesce((x->>'bytes')::bigint, -1) < 0
       or nullif(btrim(x->>'display_path'), '') is null
       or x->>'mode' <> '0644'
       or coalesce((x->>'immutable')::boolean, false) is false
       or coalesce((x->>'st_nlink')::integer, 0) <> 1
  ) then
    raise exception 'seal_item_posture_invalid' using errcode = 'invalid_parameter_value';
  end if;

  select coalesce(max(manifest_version), 0) + 1 into v_manifest_version
    from app.manifest_versions where case_id = v_op.case_id;

  -- Create the object + version for each newly sealed target.
  for v_item in select * from jsonb_array_elements(p_items)
  loop
    insert into app.evidence_objects (
      case_id, display_name, display_path, source, status, seal_status,
      current_sha256, current_bytes, supersedes_object_id, sealed_by_user_id, sealed_at
    ) values (
      v_op.case_id,
      coalesce(nullif(btrim(v_item->>'display_name'), ''),
               regexp_replace(v_item->>'display_path', '^.*/', '')),
      v_item->>'display_path',
      nullif(btrim(v_item->>'source'), ''),
      'sealed', 'sealed',
      v_item->>'sha256', (v_item->>'bytes')::bigint,
      nullif(v_item->>'supersedes_object_id', '')::uuid,
      v_op.actor_user_id, now()
    )
    returning id into v_object_id;

    insert into app.evidence_versions (
      evidence_object_id, case_id, manifest_version, sha256, bytes, entry_status,
      seal_operation_id, st_dev, st_ino, st_nlink, owner, mode, immutable, registered_by
    ) values (
      v_object_id, v_op.case_id, v_manifest_version, v_item->>'sha256',
      (v_item->>'bytes')::bigint, 'ACTIVE', v_op.id,
      nullif(v_item->>'st_dev', '')::bigint, nullif(v_item->>'st_ino', '')::bigint,
      nullif(v_item->>'st_nlink', '')::integer, nullif(v_item->>'owner', ''),
      v_item->>'mode', (v_item->>'immutable')::boolean, p_examiner
    )
    returning id into v_version_id;

    update app.evidence_objects
      set current_version_id = v_version_id, updated_at = now()
      where id = v_object_id;

    perform app.custody_append_event(
      v_op.case_id, v_object_id, v_op.id, 'EVIDENCE_SEALED', v_manifest_version, null,
      v_op.reauth_audit_event_id, v_op.actor_user_id, null,
      jsonb_build_object('display_path', v_item->>'display_path',
                         'sha256', v_item->>'sha256'));
  end loop;

  -- Manifest hash over the full ACTIVE set at this version.
  select jsonb_agg(
           jsonb_build_object('evidence_object_id', o.id, 'sha256', o.current_sha256,
                              'display_path', o.display_path)
           order by o.display_path collate "C")
    into v_members
    from app.evidence_objects o
    where o.case_id = v_op.case_id and o.status = 'sealed';
  v_manifest_hash := 'sha256:' || encode(sha256(convert_to(jsonb_build_object(
    'case_id', v_op.case_id, 'manifest_version', v_manifest_version,
    'members', v_members)::text, 'UTF8')), 'hex');

  insert into app.manifest_versions (
    case_id, manifest_version, manifest_hash, seal_operation_id, created_by_action
  ) values (
    v_op.case_id, v_manifest_version, v_manifest_hash, v_op.id, 'SEAL'
  )
  returning id into v_manifest_id;

  insert into app.manifest_membership (
    manifest_version_id, case_id, evidence_object_id, evidence_version_id, entry_status
  )
  select v_manifest_id, v_op.case_id, o.id, o.current_version_id, 'ACTIVE'
    from app.evidence_objects o
    where o.case_id = v_op.case_id and o.status = 'sealed';

  perform app.custody_append_event(
    v_op.case_id, null, v_op.id, 'MANIFEST_SEALED', v_manifest_version, v_manifest_hash,
    v_op.reauth_audit_event_id, v_op.actor_user_id, null,
    jsonb_build_object('manifest_id', v_manifest_id));

  if v_op.opens_staging_window then
    perform app.custody_append_event(
      v_op.case_id, null, v_op.id, 'SEAL_WINDOW_CLOSED', v_manifest_version, null,
      v_op.reauth_audit_event_id, v_op.actor_user_id, null, '{}'::jsonb);
  end if;

  update app.custody_seal_operations
    set phase = 'COMMITTED',
        committed_at = now(),
        updated_at = now(),
        result = jsonb_build_object(
          'case_id', v_op.case_id, 'manifest_version', v_manifest_version,
          'manifest_hash', v_manifest_hash, 'gate', 'OPEN')
    where id = v_op.id
    returning * into v_op;

  return v_op;
end;
$$;

-- ===========================================================================
-- custody_ignore — DB-only exclusion of a pending inventory entry.
-- ===========================================================================
-- Single atomic transaction, no persistent failure state (EC-2a). Idempotent via
-- the receipt; a retry under the same key replays the outcome. The entry stays on
-- disk and inaccessible to MCP; a later explicit Add and Seal may admit it.
create or replace function app.custody_ignore(
  p_case_id uuid,
  p_display_path text,
  p_reason text,
  p_reauth_audit_event_id uuid,
  p_idempotency_key text,
  p_actor_user_id uuid,
  p_actor_service_identity_id uuid default null
)
returns app.custody_action_receipts
language plpgsql
security definer
set search_path = pg_catalog, app
as $$
declare
  v_receipt app.custody_action_receipts;
  v_binding jsonb;
  v_reauth app.audit_events;
begin
  if p_reauth_audit_event_id is null or p_actor_user_id is null
     or length(coalesce(p_idempotency_key, '')) not between 1 and 128
     or nullif(btrim(coalesce(p_display_path, '')), '') is null then
    raise exception 'invalid_ignore_request' using errcode = 'invalid_parameter_value';
  end if;

  select * into v_receipt from app.custody_action_receipts
    where case_id = p_case_id and action = 'IGNORE' and idempotency_key = p_idempotency_key;
  if found then
    return v_receipt;  -- replay recorded outcome.
  end if;

  v_binding := app.custody_reauth_binding(
    p_idempotency_key, coalesce(p_reason, ''), jsonb_build_array(p_display_path));
  select * into v_reauth from app.audit_events where id = p_reauth_audit_event_id for share;
  if not found or v_reauth.case_id is distinct from p_case_id
     or v_reauth.status <> 'success' or v_reauth.actor_type <> 'user'
     or v_reauth.actor_user_id is distinct from p_actor_user_id
     or v_reauth.details->'binding' is distinct from v_binding then
    raise exception 'ignore_reauth_scope_mismatch'
      using errcode = 'invalid_authorization_specification';
  end if;

  update app.evidence_inventory
    set disposition = 'ignored', observed_at = now()
    where case_id = p_case_id and display_path = p_display_path;
  if not found then
    raise exception 'ignore_target_not_pending' using errcode = 'no_data_found';
  end if;

  perform app.custody_append_event(
    p_case_id, null, null, 'FILE_IGNORED', null, null,
    p_reauth_audit_event_id, p_actor_user_id, p_actor_service_identity_id,
    jsonb_build_object('display_path', p_display_path, 'reason', p_reason));

  insert into app.custody_action_receipts (
    case_id, action, idempotency_key, reauth_audit_event_id, binding, target, result
  ) values (
    p_case_id, 'IGNORE', p_idempotency_key, p_reauth_audit_event_id, v_binding,
    jsonb_build_object('display_path', p_display_path),
    jsonb_build_object('disposition', 'ignored')
  )
  returning * into v_receipt;
  return v_receipt;
end;
$$;

-- ===========================================================================
-- custody_retire — DB-only exclusion of a sealed object from a new manifest.
-- ===========================================================================
-- Any object with a committed sealed record is retireable regardless of current
-- bytes (SPEC §Evidence lifecycle). Creates a new Manifest Version excluding the
-- object; never unlinks, modifies, unprotects, or repairs bytes. Single atomic
-- transaction; idempotent via the receipt.
create or replace function app.custody_retire(
  p_case_id uuid,
  p_evidence_object_id uuid,
  p_reason text,
  p_reauth_audit_event_id uuid,
  p_idempotency_key text,
  p_actor_user_id uuid,
  p_actor_service_identity_id uuid default null
)
returns app.custody_action_receipts
language plpgsql
security definer
set search_path = pg_catalog, app
as $$
declare
  v_receipt app.custody_action_receipts;
  v_binding jsonb;
  v_reauth app.audit_events;
  v_obj app.evidence_objects;
  v_manifest_version integer;
  v_manifest_hash text;
  v_manifest_id uuid;
  v_members jsonb;
begin
  if p_reauth_audit_event_id is null or p_actor_user_id is null
     or length(coalesce(p_idempotency_key, '')) not between 1 and 128 then
    raise exception 'invalid_retire_request' using errcode = 'invalid_parameter_value';
  end if;

  select * into v_receipt from app.custody_action_receipts
    where case_id = p_case_id and action = 'RETIRE' and idempotency_key = p_idempotency_key;
  if found then
    return v_receipt;
  end if;

  select * into v_obj from app.evidence_objects
    where id = p_evidence_object_id and case_id = p_case_id for update;
  if not found then
    raise exception 'retire_object_not_in_case' using errcode = 'no_data_found';
  end if;
  if v_obj.current_version_id is null then
    raise exception 'retire_requires_sealed_object' using errcode = 'invalid_parameter_value';
  end if;

  v_binding := app.custody_reauth_binding(
    p_idempotency_key, coalesce(p_reason, ''),
    jsonb_build_array(p_evidence_object_id::text));
  select * into v_reauth from app.audit_events where id = p_reauth_audit_event_id for share;
  if not found or v_reauth.case_id is distinct from p_case_id
     or v_reauth.status <> 'success' or v_reauth.actor_type <> 'user'
     or v_reauth.actor_user_id is distinct from p_actor_user_id
     or v_reauth.details->'binding' is distinct from v_binding then
    raise exception 'retire_reauth_scope_mismatch'
      using errcode = 'invalid_authorization_specification';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text, 0));

  update app.evidence_objects
    set status = 'retired', seal_status = 'unsealed', retired_at = now(), updated_at = now()
    where id = p_evidence_object_id;

  select coalesce(max(manifest_version), 0) + 1 into v_manifest_version
    from app.manifest_versions where case_id = p_case_id;

  select jsonb_agg(
           jsonb_build_object('evidence_object_id', o.id, 'sha256', o.current_sha256,
                              'display_path', o.display_path)
           order by o.display_path collate "C")
    into v_members
    from app.evidence_objects o
    where o.case_id = p_case_id and o.status = 'sealed';
  v_manifest_hash := 'sha256:' || encode(sha256(convert_to(jsonb_build_object(
    'case_id', p_case_id, 'manifest_version', v_manifest_version,
    'members', coalesce(v_members, '[]'::jsonb))::text, 'UTF8')), 'hex');

  insert into app.manifest_versions (
    case_id, manifest_version, manifest_hash, seal_operation_id, created_by_action
  ) values (
    p_case_id, v_manifest_version, v_manifest_hash, null, 'RETIRE'
  )
  returning id into v_manifest_id;

  insert into app.manifest_membership (
    manifest_version_id, case_id, evidence_object_id, evidence_version_id, entry_status
  )
  select v_manifest_id, p_case_id, o.id, o.current_version_id,
         case when o.id = p_evidence_object_id then 'RETIRED' else 'ACTIVE' end
    from app.evidence_objects o
    where o.case_id = p_case_id
      and (o.status = 'sealed' or o.id = p_evidence_object_id)
      and o.current_version_id is not null;

  perform app.custody_append_event(
    p_case_id, p_evidence_object_id, null, 'FILE_RETIRED', v_manifest_version, v_manifest_hash,
    p_reauth_audit_event_id, p_actor_user_id, p_actor_service_identity_id,
    jsonb_build_object('reason', p_reason));

  insert into app.custody_action_receipts (
    case_id, action, idempotency_key, reauth_audit_event_id, binding, target, result
  ) values (
    p_case_id, 'RETIRE', p_idempotency_key, p_reauth_audit_event_id, v_binding,
    jsonb_build_object('evidence_object_id', p_evidence_object_id),
    jsonb_build_object('manifest_version', v_manifest_version)
  )
  returning * into v_receipt;
  return v_receipt;
end;
$$;

-- ===========================================================================
-- custody_reprotect — Verify-and-Reprotect (posture-only, identical bytes).
-- ===========================================================================
-- Available only when bytes/digest match the committed version and the defect is
-- limited to ownership/mode/immutable posture (SPEC §Verify and Reprotect). CP2A
-- verifies the digest before and after applying posture; this records the
-- EVIDENCE_REPROTECTED event and refreshes the version posture. It never changes
-- bytes, renames, changes membership, or creates a new version.
create or replace function app.custody_reprotect(
  p_case_id uuid,
  p_evidence_object_id uuid,
  p_verified_posture jsonb,
  p_reauth_audit_event_id uuid,
  p_idempotency_key text,
  p_actor_user_id uuid,
  p_actor_service_identity_id uuid default null
)
returns app.custody_action_receipts
language plpgsql
security definer
set search_path = pg_catalog, app
as $$
declare
  v_receipt app.custody_action_receipts;
  v_binding jsonb;
  v_reauth app.audit_events;
  v_obj app.evidence_objects;
begin
  if p_reauth_audit_event_id is null or p_actor_user_id is null
     or length(coalesce(p_idempotency_key, '')) not between 1 and 128 then
    raise exception 'invalid_reprotect_request' using errcode = 'invalid_parameter_value';
  end if;

  select * into v_receipt from app.custody_action_receipts
    where case_id = p_case_id and action = 'REPROTECT' and idempotency_key = p_idempotency_key;
  if found then
    return v_receipt;
  end if;

  select * into v_obj from app.evidence_objects
    where id = p_evidence_object_id and case_id = p_case_id for update;
  if not found or v_obj.current_version_id is null then
    raise exception 'reprotect_requires_sealed_object' using errcode = 'no_data_found';
  end if;

  v_binding := app.custody_reauth_binding(
    p_idempotency_key, coalesce(p_verified_posture->>'reason', ''),
    jsonb_build_array(p_evidence_object_id::text));
  select * into v_reauth from app.audit_events where id = p_reauth_audit_event_id for share;
  if not found or v_reauth.case_id is distinct from p_case_id
     or v_reauth.status <> 'success' or v_reauth.actor_type <> 'user'
     or v_reauth.actor_user_id is distinct from p_actor_user_id
     or v_reauth.details->'binding' is distinct from v_binding then
    raise exception 'reprotect_reauth_scope_mismatch'
      using errcode = 'invalid_authorization_specification';
  end if;

  -- The committed Evidence Version posture is the immutable TARGET; Reprotect
  -- restores the on-disk posture to it (CP2A verifies the digest before and after
  -- on disk) and NEVER rewrites the version row. The verified posture is recorded
  -- only in the append-only EVIDENCE_REPROTECTED event.
  perform app.custody_append_event(
    p_case_id, p_evidence_object_id, null, 'EVIDENCE_REPROTECTED', null, null,
    p_reauth_audit_event_id, p_actor_user_id, p_actor_service_identity_id,
    jsonb_build_object('posture', p_verified_posture));

  insert into app.custody_action_receipts (
    case_id, action, idempotency_key, reauth_audit_event_id, binding, target, result
  ) values (
    p_case_id, 'REPROTECT', p_idempotency_key, p_reauth_audit_event_id, v_binding,
    jsonb_build_object('evidence_object_id', p_evidence_object_id),
    jsonb_build_object('reprotected', true)
  )
  returning * into v_receipt;
  return v_receipt;
end;
$$;

-- ===========================================================================
-- custody_record_export / custody_record_anchor — CP2B ledger stubs.
-- ===========================================================================
-- Record a derived custody export (no fresh password, read-only class), and an
-- optional non-authoritative Solana anchoring receipt. CP2B's ledger module
-- generates the bytes and calls these; anchoring failure never blocks custody.
create or replace function app.custody_record_export(
  p_case_id uuid,
  p_export_digest text,
  p_source_ledger_head text default null,
  p_manifest_version integer default null,
  p_actor_user_id uuid default null,
  p_audit_event_id uuid default null
)
returns app.custody_exports
language plpgsql
security definer
set search_path = pg_catalog, app
as $$
declare
  v_row app.custody_exports;
begin
  insert into app.custody_exports (
    case_id, export_digest, source_ledger_head, manifest_version,
    actor_user_id, audit_event_id
  ) values (
    p_case_id, p_export_digest, p_source_ledger_head, p_manifest_version,
    p_actor_user_id, p_audit_event_id
  )
  returning * into v_row;

  perform app.custody_append_event(
    p_case_id, null, null, 'CUSTODY_EXPORTED', p_manifest_version, null,
    null, p_actor_user_id, null,
    jsonb_build_object('export_digest', p_export_digest));
  return v_row;
end;
$$;

create or replace function app.custody_record_anchor(
  p_case_id uuid,
  p_status text,
  p_anchored_head_digest text default null,
  p_tx_signature text default null,
  p_error_category text default null,
  p_actor_user_id uuid default null
)
returns app.solana_receipts
language plpgsql
security definer
set search_path = pg_catalog, app
as $$
declare
  v_row app.solana_receipts;
begin
  insert into app.solana_receipts (
    case_id, status, tx_signature, anchored_head_digest, error_category
  ) values (
    p_case_id, coalesce(p_status, 'pending'), p_tx_signature,
    p_anchored_head_digest, p_error_category
  )
  returning * into v_row;

  if v_row.status = 'confirmed' then
    perform app.custody_append_event(
      p_case_id, null, null, 'SOLANA_ANCHORED', null, null,
      null, p_actor_user_id, null,
      jsonb_build_object('anchored_head_digest', p_anchored_head_digest));
  end if;
  return v_row;
end;
$$;

-- ===========================================================================
-- Grants: service-role only. MCP/browser/authenticated hold ZERO custody grants;
-- direct-role denial is test-enforced (SPEC §Automated contract level).
-- ===========================================================================
revoke execute on function app.custody_reconcile(uuid, jsonb, boolean, text, text, uuid, uuid) from public, anon, authenticated;
revoke execute on function app.custody_gate_state(uuid) from public, anon, authenticated;
revoke execute on function app.custody_reauth_binding(text, text, jsonb) from public, anon, authenticated;
revoke execute on function app.custody_seal_begin(uuid, text, text, text, uuid, jsonb, uuid, boolean, uuid) from public, anon, authenticated;
revoke execute on function app.custody_seal_protect(uuid, jsonb, uuid, uuid) from public, anon, authenticated;
revoke execute on function app.custody_seal_commit(uuid, jsonb, text, uuid) from public, anon, authenticated;
revoke execute on function app.custody_ignore(uuid, text, text, uuid, text, uuid, uuid) from public, anon, authenticated;
revoke execute on function app.custody_retire(uuid, uuid, text, uuid, text, uuid, uuid) from public, anon, authenticated;
revoke execute on function app.custody_reprotect(uuid, uuid, jsonb, uuid, text, uuid, uuid) from public, anon, authenticated;
revoke execute on function app.custody_record_export(uuid, text, text, integer, uuid, uuid) from public, anon, authenticated;
revoke execute on function app.custody_record_anchor(uuid, text, text, text, text, uuid) from public, anon, authenticated;
-- Internal helpers are never granted to any client role.
revoke execute on function app.custody_append_event(uuid, uuid, uuid, text, integer, text, uuid, uuid, uuid, jsonb) from public, anon, authenticated;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant execute on function app.custody_reconcile(uuid, jsonb, boolean, text, text, uuid, uuid) to service_role;
    grant execute on function app.custody_gate_state(uuid) to service_role;
    grant execute on function app.custody_seal_begin(uuid, text, text, text, uuid, jsonb, uuid, boolean, uuid) to service_role;
    grant execute on function app.custody_seal_protect(uuid, jsonb, uuid, uuid) to service_role;
    grant execute on function app.custody_seal_commit(uuid, jsonb, text, uuid) to service_role;
    grant execute on function app.custody_ignore(uuid, text, text, uuid, text, uuid, uuid) to service_role;
    grant execute on function app.custody_retire(uuid, uuid, text, uuid, text, uuid, uuid) to service_role;
    grant execute on function app.custody_reprotect(uuid, uuid, jsonb, uuid, text, uuid, uuid) to service_role;
    grant execute on function app.custody_record_export(uuid, text, text, integer, uuid, uuid) to service_role;
    grant execute on function app.custody_record_anchor(uuid, text, text, text, text, uuid) to service_role;
  end if;
end
$$;
