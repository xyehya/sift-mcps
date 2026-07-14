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
  v_had_current_recoverable boolean;
  v_has_violation_issue boolean;
  v_has_pending_issue boolean;
begin
  -- Join every custody writer on the same exclusive case transaction lease.
  -- The delegated verifier re-enters this lock before validating the complete
  -- active set and writing its append-only SUCCESS receipt.
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  select coalesce(issues,'[]'::jsonb) into v_original_issues
    from app.evidence_chain_heads where case_id=p_case_id for update;
  if exists(select 1 from app.evidence_objects
      where case_id=p_case_id
        and (status='violated' or seal_status='violated')) then
    raise exception 'full_verify_violated_object_requires_recovery'
      using errcode='object_not_in_prerequisite_state';
  end if;
  select exists(select 1 from jsonb_array_elements(v_original_issues) issue
    where issue->>'code'='FULL_VERIFY_REQUIRED'
      or (issue->>'code' in ('STORAGE_UNAVAILABLE','MOUNT_IDENTITY_CHANGED',
          'STORAGE_FULL_VERIFY_REQUIRED','POSTURE_DRIFT','READ_WRITE_DRIFT',
          'STORAGE_PROFILE_CHANGED')
        and coalesce(issue->>'storage_generation','') ~ '^[0-9]+$'
        and (issue->>'storage_generation')::bigint=p_generation))
    into v_had_current_recoverable;
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
  if v_had_current_recoverable and not v_has_object_violation and not exists(
      select 1 from jsonb_array_elements(v_remaining_issues) issue
      where issue->>'code' not in (
        'PERSISTED_VIOLATION','DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM')) then
    select coalesce(jsonb_agg(issue),'[]'::jsonb) into v_remaining_issues
      from jsonb_array_elements(v_remaining_issues) issue
      where issue->>'code'<>'PERSISTED_VIOLATION';
  end if;

  select exists(select 1 from jsonb_array_elements(v_remaining_issues) issue
      where issue->>'code' not in ('DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM')),
    exists(select 1 from jsonb_array_elements(v_remaining_issues) issue
      where issue->>'code' in ('DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM'))
    into v_has_violation_issue,v_has_pending_issue;

  update app.evidence_chain_heads
    set issues=v_remaining_issues,
      seal_status=case
        when v_has_object_violation or v_has_violation_issue then 'violated'
        when v_has_pending_object or v_has_pending_issue then 'unsealed'
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

-- Reconciliation observations are append-only snapshots, but they must not
-- erase the durable cause of an already-latched violation merely because the
-- current cheap scan can express only PERSISTED_VIOLATION. Preserve every
-- closed/future causal code until its owning recovery transaction removes it.
alter function app.evidence_record_inventory_classification_v2(uuid,text,text,jsonb)
  rename to evidence_record_inventory_classification_v2_pre_causal_preservation;

create function app.evidence_record_inventory_classification_v2(
  p_case_id uuid,p_correlation_id text,p_gate_state text,p_findings jsonb
) returns app.evidence_inventory_observations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare
  v_row app.evidence_inventory_observations;
  v_original_issues jsonb;
  v_current_issues jsonb;
  v_merged_issues jsonb;
  v_scan_failure_only boolean;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  select coalesce(issues,'[]'::jsonb) into v_original_issues
    from app.evidence_chain_heads where case_id=p_case_id for update;
  select exists(select 1 from jsonb_array_elements(v_original_issues) issue
      where issue->>'code'='INVENTORY_SCAN_FAILED')
    and not exists(select 1 from jsonb_array_elements(v_original_issues) issue
      where issue->>'code' not in (
        'INVENTORY_SCAN_FAILED','PERSISTED_VIOLATION',
        'DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM'))
    into v_scan_failure_only;
  v_row := app.evidence_record_inventory_classification_v2_pre_causal_preservation(
    p_case_id,p_correlation_id,p_gate_state,p_findings);
  select coalesce(issues,'[]'::jsonb) into v_current_issues
    from app.evidence_chain_heads where case_id=p_case_id for update;
  select coalesce(jsonb_agg(issue order by issue::text),'[]'::jsonb)
    into v_merged_issues
    from (select distinct issue from jsonb_array_elements(
      v_current_issues || (select coalesce(jsonb_agg(original_issue),'[]'::jsonb)
        from jsonb_array_elements(v_original_issues) original_issue
        where original_issue->>'code' not in (
          'PERSISTED_VIOLATION','DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM',
          'INVENTORY_SCAN_FAILED'))
    ) issue) merged;
  if v_scan_failure_only
     and not exists(select 1 from jsonb_array_elements(v_current_issues) issue
       where issue->>'code' not in (
         'PERSISTED_VIOLATION','DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM'))
     and not exists(select 1 from app.evidence_objects
       where case_id=p_case_id and (status='violated' or seal_status='violated')) then
    select coalesce(jsonb_agg(issue),'[]'::jsonb) into v_merged_issues
      from jsonb_array_elements(v_merged_issues) issue
      where issue->>'code'<>'PERSISTED_VIOLATION';
  end if;
  update app.evidence_chain_heads
    set issues=v_merged_issues,
      seal_status=case
        when exists(select 1 from app.evidence_objects
          where case_id=p_case_id and (status='violated' or seal_status='violated'))
          then 'violated'
        when exists(select 1 from jsonb_array_elements(v_merged_issues) issue
          where issue->>'code' not in ('DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM'))
          then 'violated'
        when exists(select 1 from jsonb_array_elements(v_merged_issues) issue
          where issue->>'code' in ('DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM'))
          then 'unsealed'
        when v_scan_failure_only then 'sealed'
        else seal_status
      end,
      updated_at=now()
    where case_id=p_case_id;
  return v_row;
end $$;

revoke execute on function app.evidence_record_inventory_classification_v2_pre_causal_preservation(
  uuid,text,text,jsonb) from public,anon,authenticated;
revoke execute on function app.evidence_record_inventory_classification_v2(
  uuid,text,text,jsonb) from public,anon,authenticated;
do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  revoke execute on function app.evidence_record_inventory_classification_v2_pre_causal_preservation(
    uuid,text,text,jsonb) from service_role;
  grant execute on function app.evidence_record_inventory_classification_v2(
    uuid,text,text,jsonb) to service_role;
end if; end $$;
