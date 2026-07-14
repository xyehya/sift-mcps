-- P4.23 Gate C forward repair: DETECTED inventory observations may retain
-- their observed byte count. A byte count is not sealed content authority;
-- versions, hashes, sealed timestamps, unsafe causes, and all other virgin
-- bootstrap guards remain forbidden exactly as before.

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
        where issue->>'code'='UNSAFE_PENDING_ITEM'
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

-- Re-project only heads that became stuck after 145500. Append-only custody,
-- inventory, and verification rows remain untouched.
update app.evidence_chain_heads h
set seal_status='unsealed',
    issues=(
      select coalesce(jsonb_agg(issue),'[]'::jsonb)
      from jsonb_array_elements(coalesce(h.issues,'[]'::jsonb)) issue
      where issue->>'code'<>'PERSISTED_VIOLATION'
    ),
    updated_at=now()
where app.evidence_is_virgin_external_bootstrap(h.case_id);

revoke execute on function app.evidence_is_virgin_external_bootstrap(uuid)
  from public,anon,authenticated;
do $$ begin if exists(select 1 from pg_roles where rolname='service_role') then
  revoke execute on function app.evidence_is_virgin_external_bootstrap(uuid)
    from service_role;
end if; end $$;

comment on function app.evidence_is_virgin_external_bootstrap(uuid) is
  'Exact internal predicate for v0 external bootstrap; DETECTED observed bytes are non-authoritative while version/hash/sealed facts remain forbidden.';
