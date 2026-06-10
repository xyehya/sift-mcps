-- Evidence re-acquisition transition (operator-authorized re-seal of a
-- legitimately changed/re-imaged evidence item).
--
-- Problem this closes: once a sealed evidence item's bytes change on disk
-- (e.g. a corrupted acquisition is re-imaged) the tamper detector escalates the
-- case to `violated` (app.evidence_mark_violation). Before this migration there
-- was NO transition that could move an item back out of `violated`:
--   * app.evidence_verify(ok=true) only re-confirms intact sealed bytes; it
--     never de-escalates a violated item, and app.evidence_recompute_seal_status
--     keeps the case `violated` while any object is violated.
--   * app.evidence_seal updates the hash, but the portal seal path first
--     re-registers each item, and app.evidence_register rejects a `violated`
--     status (evidence_register_invalid_state) — so re-sealing crashed.
-- The net effect was a permanent custody violation with the agent evidence gate
-- fail-closed forever, with no operator remedy short of retiring the item.
--
-- Re-acquisition is a normal DFIR event: the operator re-images the same logical
-- evidence and vouches (password/HMAC re-auth, exactly like seal) that the new
-- bytes are a legitimate replacement. This RPC records that decision as an
-- append-only, hash-linked custody event that explicitly supersedes the prior
-- sealed hash with the new one (old sha -> new sha + operator justification),
-- advances the manifest version, flips the item back to `sealed`, and recomputes
-- the gate. Nothing is deleted or silently rewritten: the prior sealed version
-- snapshot, the CHAIN_VIOLATION event, and this supersession all remain in the
-- ledger for court defensibility.
--
-- It is NOT a path to first-seal a brand-new file (use app.evidence_seal) and it
-- is NOT a way to clear a violation without changing bytes: the caller passes the
-- freshly computed hash of the mounted replacement. Like seal/ignore/retire it
-- REJECTS a call without a re-auth audit event id, and additionally requires a
-- non-empty operator reason. Exposed only to the service role.

create or replace function app.evidence_reacquire(
  p_evidence_object_id uuid,
  p_case_id uuid,
  p_sha256 text,
  p_bytes bigint,
  p_manifest_version integer,
  p_manifest_hash text,
  p_reason text,
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
  v_obj app.evidence_objects;
  v_version_id uuid;
  v_head app.evidence_chain_heads;
  v_prior_sha text;
  v_prior_bytes bigint;
  v_prior_seal text;
begin
  if p_reauth_audit_event_id is null then
    raise exception 'reacquire_requires_reauth' using errcode = 'insufficient_privilege';
  end if;
  if length(btrim(coalesce(p_reason, ''))) = 0 then
    raise exception 'reacquire_requires_reason' using errcode = 'invalid_parameter_value';
  end if;
  if p_sha256 is null or p_sha256 !~ '^sha256:[0-9a-f]{64}$' then
    raise exception 'reacquire_requires_sha256' using errcode = 'invalid_parameter_value';
  end if;

  select * into v_obj from app.evidence_objects
    where id = p_evidence_object_id and case_id = p_case_id
    for update;
  if not found then
    raise exception 'evidence_object_not_in_case: %', p_evidence_object_id
      using errcode = 'no_data_found';
  end if;
  -- Re-acquisition supersedes an item that was sealed at least once. A sealed
  -- item whose bytes changed lands here either still `sealed` (operator re-seals
  -- before a scan trips the tamper check) or already `violated` (scan escalated
  -- it first). Detected/registered/ignored/retired items are not re-acquisitions.
  if v_obj.status not in ('sealed', 'violated') then
    raise exception 'reacquire_invalid_state: %', v_obj.status
      using errcode = 'invalid_parameter_value';
  end if;

  v_prior_sha := v_obj.current_sha256;
  v_prior_bytes := v_obj.current_bytes;
  v_prior_seal := v_obj.seal_status;

  -- Append-only supersession snapshot at the new manifest version.
  insert into app.evidence_versions (
    evidence_object_id, case_id, manifest_version, sha256, bytes,
    entry_status, manifest_hash, registered_by, metadata
  ) values (
    p_evidence_object_id, p_case_id, p_manifest_version, p_sha256, p_bytes,
    'ACTIVE', p_manifest_hash, null,
    jsonb_build_object(
      'reacquired', true,
      'superseded_sha256', v_prior_sha,
      'superseded_bytes', v_prior_bytes,
      'reason', p_reason
    )
  )
  returning id into v_version_id;

  update app.evidence_objects
    set status = 'sealed',
        seal_status = 'sealed',
        current_version_id = v_version_id,
        current_sha256 = p_sha256,
        current_bytes = p_bytes,
        sealed_by_user_id = coalesce(p_actor_user_id, sealed_by_user_id),
        sealed_at = now(),
        updated_at = now()
    where id = p_evidence_object_id;

  -- Court-defensible record: a sealed-manifest event tied to THIS object that
  -- explicitly names the superseded hash, the new hash, and the operator reason.
  -- Carries the re-auth audit event id so the human authorization is provable.
  perform app.evidence_append_custody_event(
    p_case_id, p_evidence_object_id, 'MANIFEST_SEALED', p_manifest_version,
    p_manifest_hash, p_reauth_audit_event_id, p_actor_user_id,
    p_actor_service_identity_id,
    jsonb_build_object(
      'reacquired', true,
      'display_path', v_obj.display_path,
      'superseded_sha256', v_prior_sha,
      'superseded_bytes', v_prior_bytes,
      'superseded_seal_status', v_prior_seal,
      'new_sha256', p_sha256,
      'new_bytes', p_bytes,
      'reason', p_reason
    )
  );
  perform app.evidence_recompute_seal_status(p_case_id);

  select * into v_head from app.evidence_chain_heads where case_id = p_case_id;
  return v_head;
end;
$$;

comment on function app.evidence_reacquire(uuid, uuid, text, bigint, integer, text, text, uuid, uuid, uuid) is
  'Service-only re-acquisition transition. Supersedes a previously sealed '
  '(or violated) item with freshly re-imaged bytes: records an append-only '
  'supersession custody event (old sha -> new sha + operator reason), advances '
  'the manifest version, flips the item back to sealed, and recomputes the gate. '
  'Rejects a call without a re-auth audit event id and without a non-empty reason.';

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant execute on function app.evidence_reacquire(
      uuid, uuid, text, bigint, integer, text, text, uuid, uuid, uuid
    ) to service_role;
  end if;
end
$$;
