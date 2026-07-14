-- P4.23 Gate C repair: retiring one violated object resolves only that
-- object's approved missing/change causes. Append-only observations, events,
-- versions, manifests, and unrelated/security causes remain untouched.

alter function app.custody_operation_commit_verified_disposition(
  uuid,jsonb,text,text
) rename to custody_operation_commit_disposition_pre_retire_recovery;

create function app.custody_operation_commit_verified_disposition(
  p_operation_id uuid,p_item jsonb,p_examiner text,p_runner_instance_id text
) returns app.custody_operations
language plpgsql security definer set search_path=pg_catalog,app as $$
declare
  v_case_id uuid;
  v_object_id uuid;
  v_op app.custody_operations;
  v_remaining_issues jsonb;
  v_has_substantive_issue boolean;
  v_has_violated_object boolean;
begin
  select case_id,nullif(command->>'evidence_object_id','')::uuid
    into v_case_id,v_object_id
    from app.custody_operations where id=p_operation_id;
  if found then
    perform pg_advisory_xact_lock(hashtextextended(v_case_id::text,0));
  end if;

  v_op := app.custody_operation_commit_disposition_pre_retire_recovery(
    p_operation_id,p_item,p_examiner,p_runner_instance_id
  );

  if v_op.action='RETIRE' and v_op.phase='COMPLETED' then
    select coalesce(jsonb_agg(issue order by ordinal),'[]'::jsonb)
      into v_remaining_issues
      from app.evidence_chain_heads head
      cross join lateral jsonb_array_elements(coalesce(head.issues,'[]'::jsonb))
        with ordinality as current_issue(issue,ordinal)
      where head.case_id=v_op.case_id
        and not (
          issue->>'evidence_object_id'=v_object_id::text
          and issue->>'code' in (
            'SEALED_EVIDENCE_MISSING','CONTENT_CHANGED','IDENTITY_CHANGED'
          )
        );

    select exists(
      select 1 from jsonb_array_elements(v_remaining_issues) issue
      where issue->>'code'<>'PERSISTED_VIOLATION'
    ) into v_has_substantive_issue;
    select exists(
      select 1 from app.evidence_objects
      where case_id=v_op.case_id
        and (status='violated' or seal_status='violated')
    ) into v_has_violated_object;

    if not v_has_substantive_issue and not v_has_violated_object then
      select coalesce(jsonb_agg(issue order by ordinal),'[]'::jsonb)
        into v_remaining_issues
        from jsonb_array_elements(v_remaining_issues)
          with ordinality as current_issue(issue,ordinal)
        where issue->>'code'<>'PERSISTED_VIOLATION';
    end if;

    update app.evidence_chain_heads
      set issues=v_remaining_issues,
          seal_status=case
            when exists(
              select 1 from app.evidence_objects
              where case_id=v_op.case_id
                and (status='violated' or seal_status='violated')
            ) then 'violated'
            when exists(
              select 1 from jsonb_array_elements(v_remaining_issues) issue
              where issue->>'code' not in ('DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM')
            ) then 'violated'
            when exists(
              select 1 from app.evidence_objects
              where case_id=v_op.case_id and status in ('detected','registered')
            ) or exists(
              select 1 from jsonb_array_elements(v_remaining_issues) issue
              where issue->>'code' in ('DETECTED_NEW_ITEM','UNSAFE_PENDING_ITEM')
            ) then 'unsealed'
            when exists(
              select 1 from app.evidence_objects
              where case_id=v_op.case_id and status='sealed' and seal_status='sealed'
            ) then 'sealed'
            else 'unsealed'
          end,
          updated_at=now()
      where case_id=v_op.case_id;
  end if;
  return v_op;
end $$;

revoke execute on function app.custody_operation_commit_disposition_pre_retire_recovery(
  uuid,jsonb,text,text
) from public,anon,authenticated;
revoke execute on function app.custody_operation_commit_verified_disposition(
  uuid,jsonb,text,text
) from public,anon,authenticated;

do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  revoke execute on function app.custody_operation_commit_disposition_pre_retire_recovery(
    uuid,jsonb,text,text
  ) from service_role;
  grant execute on function app.custody_operation_commit_verified_disposition(
    uuid,jsonb,text,text
  ) to service_role;
end if; end $$;

comment on function app.custody_operation_commit_verified_disposition(
  uuid,jsonb,text,text
) is 'Service-only disposition finalizer; RETIRE discharges only the retired object missing/change causes.';
