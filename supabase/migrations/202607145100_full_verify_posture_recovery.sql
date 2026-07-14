-- P4.23 Gate C repair: a successful Full Verify may recover current
-- storage/posture drift, but never content, missing-evidence, or ledger drift.

alter function app.evidence_storage_commit_full_verify(
  uuid,bigint,text,text,text,boolean,integer,jsonb,text,uuid,text
) rename to evidence_storage_commit_full_verify_pre_posture_recovery;

create function app.evidence_storage_commit_full_verify(
  p_case_id uuid,p_generation bigint,p_profile text,p_source_identity text,
  p_mount_instance text,p_read_only boolean,p_manifest_version integer,
  p_items jsonb,p_correlation_id text,p_actor_user_id uuid,p_note text
) returns app.evidence_storage_authorities
language plpgsql security definer set search_path=pg_catalog,app as $$
declare
  v_row app.evidence_storage_authorities;
  v_receipt_count bigint;
  v_original_issues jsonb;
  v_remaining_issues jsonb;
  v_has_object_violation boolean;
  v_has_pending_object boolean;
begin
  -- Join every custody writer on the same exclusive case transaction lease.
  -- The delegated verifier re-enters this lock before validating the complete
  -- active set and writing its append-only SUCCESS receipt.
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  select coalesce(issues,'[]'::jsonb) into v_original_issues
    from app.evidence_chain_heads where case_id=p_case_id for update;
  v_row := app.evidence_storage_commit_full_verify_pre_posture_recovery(
    p_case_id,p_generation,p_profile,p_source_identity,p_mount_instance,
    p_read_only,p_manifest_version,p_items,p_correlation_id,p_actor_user_id,p_note
  );

  -- Recovery authority is the exact receipt just committed by the proven
  -- verifier, not caller assertion or a historical success for the case.
  select count(*) into v_receipt_count
    from app.evidence_storage_verifications
    where case_id=p_case_id
      and generation=p_generation
      and profile=p_profile
      and manifest_version=p_manifest_version
      and manifest_hash=(select manifest_hash from app.evidence_chain_heads
        where case_id=p_case_id)
      and item_facts=p_items
      and correlation_id=p_correlation_id
      and actor_user_id=p_actor_user_id
      and outcome='SUCCESS';
  if v_receipt_count<>1 then
    raise exception 'full_verify_success_receipt_missing'
      using errcode='object_not_in_prerequisite_state';
  end if;

  select coalesce(jsonb_agg(issue),'[]'::jsonb) into v_remaining_issues
    from jsonb_array_elements(v_original_issues) issue
    where not (
      -- These classifier conclusions are discharged by a complete current
      -- version/hash/bytes/descriptor Full Verify. They are not content or
      -- ledger waivers.
      issue->>'code'='FULL_VERIFY_REQUIRED'
      or (
        issue->>'code' in ('STORAGE_UNAVAILABLE','MOUNT_IDENTITY_CHANGED',
          'STORAGE_FULL_VERIFY_REQUIRED','POSTURE_DRIFT',
          'READ_WRITE_DRIFT','STORAGE_PROFILE_CHANGED')
        and coalesce(issue->>'storage_generation','') ~ '^[0-9]+$'
        and (issue->>'storage_generation')::bigint=p_generation
      )
    );

  -- PERSISTED_VIOLATION is a synthetic latch marker. Remove it only when the
  -- successful verification discharged every substantive issue and no object
  -- row carries an independent violation. A marker can never hide a changed,
  -- missing, unsafe, conflicting-authority, or ledger finding.
  select exists(select 1 from app.evidence_objects
      where case_id=p_case_id and (status='violated' or seal_status='violated')),
    exists(select 1 from app.evidence_objects
      where case_id=p_case_id and status in ('detected','registered'))
    into v_has_object_violation,v_has_pending_object;
  if not v_has_object_violation and not exists(
      select 1 from jsonb_array_elements(v_remaining_issues) issue
      where issue->>'code'<>'PERSISTED_VIOLATION') then
    select coalesce(jsonb_agg(issue),'[]'::jsonb) into v_remaining_issues
      from jsonb_array_elements(v_remaining_issues) issue
      where issue->>'code'<>'PERSISTED_VIOLATION';
  end if;

  update app.evidence_chain_heads
    set issues=v_remaining_issues,
      seal_status=case
        when v_has_object_violation or v_remaining_issues<>'[]'::jsonb then 'violated'
        when v_has_pending_object then 'unsealed'
        else 'sealed'
      end,
      last_verified_at=now(),updated_at=now()
    where case_id=p_case_id;
  return v_row;
end $$;

revoke execute on function app.evidence_storage_commit_full_verify_pre_posture_recovery(
  uuid,bigint,text,text,text,boolean,integer,jsonb,text,uuid,text
) from public,anon,authenticated;
revoke execute on function app.evidence_storage_commit_full_verify(
  uuid,bigint,text,text,text,boolean,integer,jsonb,text,uuid,text
) from public,anon,authenticated;
do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  revoke execute on function app.evidence_storage_commit_full_verify_pre_posture_recovery(
    uuid,bigint,text,text,text,boolean,integer,jsonb,text,uuid,text
  ) from service_role;
  grant execute on function app.evidence_storage_commit_full_verify(
    uuid,bigint,text,text,text,boolean,integer,jsonb,text,uuid,text
  ) to service_role;
end if; end $$;

comment on function app.evidence_storage_commit_full_verify(
  uuid,bigint,text,text,text,boolean,integer,jsonb,text,uuid,text
) is 'Service-only complete evidence verification; clears only current storage/posture latch findings after an exact SUCCESS receipt.';
