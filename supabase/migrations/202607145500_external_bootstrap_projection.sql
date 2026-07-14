-- P4.23 Gate C: permit only the virgin Externally Read-Only Add & Seal
-- bootstrap. Storage/admission remain blocked until the existing v3 finalizer
-- atomically binds the first full-hash manifest, source, mount, and receipt.

create or replace function app.evidence_is_virgin_external_bootstrap(p_case_id uuid)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,app
as $$
  select exists(
    select 1
    from app.evidence_storage_authorities a
    join app.evidence_chain_heads h on h.case_id=a.case_id
    where a.case_id=p_case_id
      and a.profile='EXTERNALLY_READ_ONLY'
      and a.state='FULL_VERIFY_REQUIRED'
      and a.source_identity is null
      and a.verified_mount_instance is null
      and a.observed_mount_instance is not null
      and a.read_only is true
      and a.verified_generation is null
      and coalesce(h.manifest_version,0)=0
      and h.manifest_hash is null
      and coalesce(h.active_count,0)=0
      and h.seal_status in ('unsealed','violated')
      and jsonb_array_length(coalesce(h.issues,'[]'::jsonb))>0
      and exists(
        select 1 from jsonb_array_elements(coalesce(h.issues,'[]'::jsonb)) issue
        where issue->>'code'='STORAGE_FULL_VERIFY_REQUIRED'
          and case
            when coalesce(issue->>'storage_generation','') ~ '^[0-9]+$'
              then (issue->>'storage_generation')::numeric=a.generation
            else false
          end
      )
      and not exists(
        select 1 from jsonb_array_elements(coalesce(h.issues,'[]'::jsonb)) issue
        where issue->>'code' not in ('STORAGE_PROFILE_CHANGED','STORAGE_FULL_VERIFY_REQUIRED','PERSISTED_VIOLATION')
          or (
            issue->>'code' in ('STORAGE_PROFILE_CHANGED','STORAGE_FULL_VERIFY_REQUIRED')
            and case
              when coalesce(issue->>'storage_generation','') ~ '^[0-9]+$'
                then (issue->>'storage_generation')::numeric is distinct from a.generation
              else true
            end
          )
          or (
            issue->>'code'='PERSISTED_VIOLATION'
            and (issue->>'evidence_object_id') is not null
          )
      )
      and exists(
        select 1 from app.evidence_objects o
        where o.case_id=p_case_id and o.status='detected'
      )
      and not exists(
        select 1 from app.evidence_objects o
        where o.case_id=p_case_id
          and (
            o.status<>'detected'
            or o.seal_status='violated'
            or o.current_version_id is not null
            or o.current_sha256 is not null
            or o.current_bytes is not null
            or o.sealed_at is not null
          )
      )
      and not exists(select 1 from app.evidence_manifests m where m.case_id=p_case_id)
      and not exists(select 1 from app.evidence_versions v where v.case_id=p_case_id)
      and not exists(
        select 1 from app.evidence_storage_verifications v
        where v.case_id=p_case_id and v.outcome='SUCCESS'
      )
      and not exists(
        select 1 from app.evidence_custody_events e
        where e.case_id=p_case_id
          and e.event_type not in ('STORAGE_PROFILE_CHANGED','EVIDENCE_DETECTED')
      )
      and not exists(
        select 1 from app.custody_operations op
        where op.case_id=p_case_id and op.action<>'ADD_SEAL'
      )
  )
$$;

do $$ begin
  if to_regprocedure(
      'app.evidence_record_inventory_classification_v2_pre_external_bootstrap(uuid,text,text,jsonb)'
    ) is null then
    alter function app.evidence_record_inventory_classification_v2(uuid,text,text,jsonb)
      rename to evidence_record_inventory_classification_v2_pre_external_bootstrap;
  end if;
end $$;

create or replace function app.evidence_record_inventory_classification_v2(
  p_case_id uuid,p_correlation_id text,p_gate_state text,p_findings jsonb
) returns app.evidence_inventory_observations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_row app.evidence_inventory_observations;
begin
  -- The wrapped classifier owns the case lock, validates the closed finding
  -- vocabulary, and appends the immutable observation before this projection.
  select * into v_row
  from app.evidence_record_inventory_classification_v2_pre_external_bootstrap(
    p_case_id,p_correlation_id,p_gate_state,p_findings
  );
  if app.evidence_is_virgin_external_bootstrap(p_case_id) then
    update app.evidence_chain_heads
    set seal_status='unsealed',
        issues=(
          select coalesce(jsonb_agg(issue),'[]'::jsonb)
          from jsonb_array_elements(coalesce(issues,'[]'::jsonb)) issue
          where issue->>'code'<>'PERSISTED_VIOLATION'
        ),
        updated_at=now()
    where case_id=p_case_id;
  end if;
  return v_row;
end $$;

do $$ begin
  if to_regprocedure(
      'app.custody_operation_begin_or_resume_storage_v3_pre_external_bootstrap(uuid,jsonb,text,text,uuid,text,uuid,text,uuid)'
    ) is null then
    alter function app.custody_operation_begin_or_resume_storage_v3(
      uuid,jsonb,text,text,uuid,text,uuid,text,uuid
    ) rename to custody_operation_begin_or_resume_storage_v3_pre_external_bootstrap;
  end if;
end $$;

create or replace function app.custody_operation_begin_or_resume_storage_v3(
  p_case_id uuid,p_command jsonb,p_request_digest text,p_reason text,
  p_reauth_audit_event_id uuid,p_idempotency_key text,p_actor_user_id uuid,
  p_runner_instance_id text,p_resume_reauth_audit_event_id uuid
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_command_count integer; v_pending_count integer;
  v_command_paths text[]; v_pending_paths text[];
begin
  perform pg_advisory_xact_lock(hashtextextended(p_case_id::text,0));
  -- A source-less external authority is the bootstrap lane. It must satisfy
  -- the exact virgin predicate; otherwise the predecessor must not interpret
  -- a superficially unsealed head as permission to create new authority.
  if p_command->>'schema_version'='3'
     and p_command->>'storage_profile'='EXTERNALLY_READ_ONLY'
     and exists(
       select 1 from app.evidence_storage_authorities a
       where a.case_id=p_case_id
         and a.profile='EXTERNALLY_READ_ONLY'
         and a.source_identity is null
         and a.verified_generation is null
     ) then
    if not app.evidence_is_virgin_external_bootstrap(p_case_id) then
      raise exception 'external_bootstrap_state_mismatch'
        using errcode='object_not_in_prerequisite_state';
    end if;
    if jsonb_typeof(p_command->'files')<>'array'
       or jsonb_array_length(p_command->'files')=0 then
      raise exception 'external_bootstrap_target_set_mismatch'
        using errcode='invalid_parameter_value';
    end if;
    select count(*),array_agg(x->>'path' order by x->>'path')
      into v_command_count,v_command_paths
      from jsonb_array_elements(p_command->'files') x;
    select count(*),array_agg(o.display_path order by o.display_path)
      into v_pending_count,v_pending_paths
      from app.evidence_objects o
      where o.case_id=p_case_id and o.status='detected';
    if v_command_count is distinct from v_pending_count
       or coalesce(v_command_paths,array[]::text[]) is distinct from
          coalesce(v_pending_paths,array[]::text[]) then
      raise exception 'external_bootstrap_target_set_mismatch'
        using errcode='object_not_in_prerequisite_state';
    end if;
  end if;
  return app.custody_operation_begin_or_resume_storage_v3_pre_external_bootstrap(
    p_case_id,p_command,p_request_digest,p_reason,p_reauth_audit_event_id,
    p_idempotency_key,p_actor_user_id,p_runner_instance_id,p_resume_reauth_audit_event_id
  );
end $$;

do $$ begin
  if to_regprocedure(
      'app.custody_operation_commit_verified_seal_storage_v3_pre_external_bootstrap(uuid,jsonb,text,text)'
    ) is null then
    alter function app.custody_operation_commit_verified_seal_storage_v3(uuid,jsonb,text,text)
      rename to custody_operation_commit_verified_seal_storage_v3_pre_external_bootstrap;
  end if;
end $$;

create or replace function app.custody_operation_commit_verified_seal_storage_v3(
  p_operation_id uuid,p_items jsonb,p_examiner text,p_runner_instance_id text
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_case_id uuid; v_command jsonb; v_phase text; v_profile text;
  v_command_paths text[]; v_pending_paths text[]; v_verified_paths text[];
  v_command_count integer; v_pending_count integer; v_verified_count integer;
begin
  select case_id into v_case_id from app.custody_operations where id=p_operation_id;
  if not found then
    raise exception 'custody_operation_missing' using errcode='no_data_found';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_case_id::text,0));
  select command,phase into v_command,v_phase
  from app.custody_operations where id=p_operation_id for update;
  v_profile:=v_command->>'storage_profile';
  if v_phase<>'COMPLETED'
     and v_command->>'schema_version'='3'
     and v_profile='EXTERNALLY_READ_ONLY'
     and exists(
       select 1 from app.evidence_storage_authorities a
       where a.case_id=v_case_id
         and a.profile='EXTERNALLY_READ_ONLY'
         and a.source_identity is null
         and a.verified_generation is null
     ) then
    if not app.evidence_is_virgin_external_bootstrap(v_case_id) then
      raise exception 'external_bootstrap_finalizer_state_mismatch'
        using errcode='object_not_in_prerequisite_state';
    end if;
    select count(*),array_agg(x->>'path' order by x->>'path')
      into v_command_count,v_command_paths
      from jsonb_array_elements(v_command->'files') x;
    select count(*),array_agg(o.display_path order by o.display_path)
      into v_pending_count,v_pending_paths
      from app.evidence_objects o
      where o.case_id=v_case_id and o.status='detected';
    select count(*),array_agg(x->>'path' order by x->>'path')
      into v_verified_count,v_verified_paths
      from jsonb_array_elements(p_items) x;
    if v_command_count is distinct from v_pending_count
       or v_command_count is distinct from v_verified_count
       or coalesce(v_command_paths,array[]::text[]) is distinct from
          coalesce(v_pending_paths,array[]::text[])
       or coalesce(v_command_paths,array[]::text[]) is distinct from
          coalesce(v_verified_paths,array[]::text[]) then
      raise exception 'external_bootstrap_verified_set_mismatch'
        using errcode='object_not_in_prerequisite_state';
    end if;
  end if;
  return app.custody_operation_commit_verified_seal_storage_v3_pre_external_bootstrap(
    p_operation_id,p_items,p_examiner,p_runner_instance_id
  );
end $$;

-- Backfill only already-stuck virgin heads. The append-only custody events,
-- inventory observations, and verification attempts are intentionally untouched.
update app.evidence_chain_heads h
set seal_status='unsealed',
    issues=(
      select coalesce(jsonb_agg(issue),'[]'::jsonb)
      from jsonb_array_elements(coalesce(h.issues,'[]'::jsonb)) issue
      where issue->>'code'<>'PERSISTED_VIOLATION'
    ),
    updated_at=now()
where app.evidence_is_virgin_external_bootstrap(h.case_id);

-- Runtime grants remain service-role-only. Internal predecessors and the
-- predicate are not independently callable by a runtime database principal.
revoke execute on function app.evidence_is_virgin_external_bootstrap(uuid)
  from public,anon,authenticated;
revoke execute on function app.evidence_record_inventory_classification_v2_pre_external_bootstrap(
  uuid,text,text,jsonb) from public,anon,authenticated;
revoke execute on function app.custody_operation_begin_or_resume_storage_v3_pre_external_bootstrap(
  uuid,jsonb,text,text,uuid,text,uuid,text,uuid) from public,anon,authenticated;
revoke execute on function app.custody_operation_commit_verified_seal_storage_v3_pre_external_bootstrap(
  uuid,jsonb,text,text) from public,anon,authenticated;
revoke execute on function app.evidence_record_inventory_classification_v2(uuid,text,text,jsonb)
  from public,anon,authenticated;
revoke execute on function app.custody_operation_begin_or_resume_storage_v3(
  uuid,jsonb,text,text,uuid,text,uuid,text,uuid) from public,anon,authenticated;
revoke execute on function app.custody_operation_commit_verified_seal_storage_v3(
  uuid,jsonb,text,text) from public,anon,authenticated;

do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  revoke execute on function app.evidence_is_virgin_external_bootstrap(uuid)
    from service_role;
  revoke execute on function app.evidence_record_inventory_classification_v2_pre_external_bootstrap(
    uuid,text,text,jsonb) from service_role;
  revoke execute on function app.custody_operation_begin_or_resume_storage_v3_pre_external_bootstrap(
    uuid,jsonb,text,text,uuid,text,uuid,text,uuid) from service_role;
  revoke execute on function app.custody_operation_commit_verified_seal_storage_v3_pre_external_bootstrap(
    uuid,jsonb,text,text) from service_role;
  grant execute on function app.evidence_record_inventory_classification_v2(uuid,text,text,jsonb)
    to service_role;
  grant execute on function app.custody_operation_begin_or_resume_storage_v3(
    uuid,jsonb,text,text,uuid,text,uuid,text,uuid) to service_role;
  grant execute on function app.custody_operation_commit_verified_seal_storage_v3(
    uuid,jsonb,text,text) to service_role;
end if; end $$;

comment on function app.evidence_is_virgin_external_bootstrap(uuid) is
  'Exact path-free predicate for a v0 external source that has only DETECTED pending objects and current-generation storage bootstrap causes.';
