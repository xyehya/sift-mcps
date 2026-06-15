-- Operator UNSEAL transition (re-auth-gated unlock of a sealed evidence item so
-- its bytes can be replaced / re-imaged / supplemented, after which the operator
-- re-seals).
--
-- Problem this closes: once an item is sealed, B-MVP-048 sets the immutable
-- (+i) flag on its bytes and the DB marks it status='sealed', seal_status=
-- 'sealed'. There was no operator-authorized path to deliberately re-open a
-- sealed item: app.evidence_reacquire supersedes a CHANGED item with already-
-- re-imaged bytes (old sha -> new sha), and app.evidence_retire removes the item
-- entirely. Neither lets the operator take a still-good sealed item back to a
-- mutable, registered (non-sealed) state so they can intentionally swap or add
-- bytes and then seal again.
--
-- Unsealing is the explicit operator unlock. It is the deliberate inverse of the
-- seal control: clearing +i on disk happens in the Gateway (it owns the FS
-- posture via sift_core.evidence_chain.unharden_sealed_evidence); this RPC
-- records the logical transition. The item is moved status='sealed'/'violated'
-- -> status='registered', seal_status='unsealed'. Because
-- app.evidence_recompute_seal_status treats any object in (detected, registered)
-- as pending, the case aggregate seal_status drops to 'unsealed' and the
-- fail-closed agent evidence gate BLOCKS every agent MCP tool until the operator
-- re-seals. That gate block is the desired control: an item under active
-- replacement must not be analyzable.
--
-- Like seal/ignore/retire/reacquire it REJECTS a call without a re-auth audit
-- event id and additionally requires a non-empty operator reason. Only a
-- currently sealed or violated item can be unsealed (an item already in
-- detected/registered/ignored/retired is not a seal to open); the call is
-- guarded and raises otherwise, which makes it idempotent-safe (a second unseal
-- of an already-unsealed item raises rather than silently double-recording).
-- The append-only, hash-linked custody event records the transition for court
-- defensibility (nothing is deleted; the prior sealed version snapshot remains).
-- Exposed only to the service role.

-- Add the FILE_UNSEALED custody event type so the unlock is a first-class,
-- distinct ledger entry (not overloaded onto FILE_RETIRED/FILE_IGNORED, which
-- mean removal/exclusion). This widens the existing CHECK constraint only; it
-- never narrows it, so every previously-recorded event type stays valid and the
-- append-only chain is untouched. Idempotent: drop+recreate the named check.
do $$
begin
  alter table app.evidence_custody_events
    drop constraint if exists evidence_custody_events_event_type_check;
  alter table app.evidence_custody_events
    add constraint evidence_custody_events_event_type_check
      check (event_type in (
        'EVIDENCE_DETECTED',
        'EVIDENCE_REGISTERED',
        'MANIFEST_SEALED',
        'CHAIN_VERIFIED',
        'FILE_IGNORED',
        'FILE_RETIRED',
        'FILE_UNSEALED',
        'CHAIN_VIOLATION'
      ));
end
$$;

create or replace function app.evidence_unseal(
  p_evidence_id uuid,
  p_reason text,
  p_reauth_audit_event_id uuid,
  p_actor_user uuid default null,
  p_actor_service uuid default null
)
returns app.evidence_chain_heads
language plpgsql
security definer
set search_path = app, public
as $$
declare
  v_obj app.evidence_objects;
  v_head app.evidence_chain_heads;
  v_prior_status text;
  v_prior_seal text;
begin
  if p_reauth_audit_event_id is null then
    raise exception 'unseal_requires_reauth' using errcode = 'insufficient_privilege';
  end if;
  if length(btrim(coalesce(p_reason, ''))) = 0 then
    raise exception 'unseal_requires_reason' using errcode = 'invalid_parameter_value';
  end if;

  select * into v_obj from app.evidence_objects
    where id = p_evidence_id
    for update;
  if not found then
    raise exception 'evidence_object_not_found' using errcode = 'no_data_found';
  end if;
  -- Only a sealed (or escalated-to-violated) item is a seal that can be opened.
  -- detected/registered/ignored/retired are not unseal targets.
  if v_obj.status not in ('sealed', 'violated') then
    raise exception 'unseal_invalid_state: %', v_obj.status
      using errcode = 'invalid_parameter_value';
  end if;

  v_prior_status := v_obj.status;
  v_prior_seal := v_obj.seal_status;

  -- Take the item back to a mutable, non-sealed posture. registered (not
  -- detected) preserves the operator's name/description/source; seal_status
  -- 'unsealed' + status 'registered' makes the recompute treat it as pending so
  -- the case aggregate drops to 'unsealed' and the agent gate blocks until reseal.
  update app.evidence_objects
    set status = 'registered',
        seal_status = 'unsealed',
        updated_at = now()
    where id = p_evidence_id;

  -- Court-defensible record of the deliberate unlock: a custody event tied to
  -- THIS object carrying the prior sealed posture, the operator reason, and the
  -- re-auth audit event id so the human authorization is provable.
  perform app.evidence_append_custody_event(
    v_obj.case_id, p_evidence_id, 'FILE_UNSEALED', null, null,
    p_reauth_audit_event_id, p_actor_user, p_actor_service,
    jsonb_build_object(
      'unsealed', true,
      'display_path', v_obj.display_path,
      'prior_status', v_prior_status,
      'prior_seal_status', v_prior_seal,
      'reason', p_reason
    )
  );
  perform app.evidence_recompute_seal_status(v_obj.case_id);

  select * into v_head from app.evidence_chain_heads where case_id = v_obj.case_id;
  return v_head;
end;
$$;

comment on function app.evidence_unseal(uuid, text, uuid, uuid, uuid) is
  'Service-only operator unseal transition. Re-opens a sealed (or violated) '
  'evidence item so its bytes can be replaced/re-imaged: clears the logical seal '
  '(status -> registered, seal_status -> unsealed) and records an append-only '
  'custody event with the operator reason + re-auth id. Recompute drops the case '
  'aggregate to unsealed so the fail-closed agent gate blocks until reseal. The '
  'Gateway clears the on-disk immutable flag. Rejects a call without a re-auth '
  'audit event id or a non-empty reason, and only a sealed/violated item can be '
  'unsealed.';

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant execute on function app.evidence_unseal(uuid, text, uuid, uuid, uuid)
      to service_role;
  end if;
end
$$;
