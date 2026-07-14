-- P4.23.4 Gate C forward repair: PostgreSQL does not provide
-- jsonb_object_length(jsonb). Enforce the same exact 13-key prepared-item
-- contract with native key-presence and no-extra-key operators.

create or replace function sift_custody_broker.authorize(
  p_operation_id uuid,p_runner_instance_id text
) returns jsonb
language plpgsql security definer set search_path=pg_catalog,app as $$
declare v_op app.custody_operations; v_obj app.evidence_objects;
  v_case app.cases; v_storage app.evidence_storage_authorities;
  v_receipt app.custody_delete_broker_receipts; v_item jsonb; v_digest text;
begin
  select * into v_op from app.custody_operations where id=p_operation_id for share;
  if not found or v_op.action<>'DELETE_STRAY' or v_op.phase<>'FILESYSTEM_APPLYING'
     or v_op.runner_instance_id is distinct from p_runner_instance_id
     or v_op.actor_user_id is null or v_op.actor_service_identity_id is not null
     or v_op.reauth_audit_event_id is null
     or v_op.command->>'action'<>'DELETE_STRAY'
     or v_op.command->>'schema_version'<>'2'
     or jsonb_typeof(v_op.prepared_facts->'item')<>'object' then
    raise exception 'custody_delete_broker_operation_unauthorized'
      using errcode='invalid_authorization_specification';
  end if;
  v_item:=v_op.prepared_facts->'item';
  select * into v_case from app.cases where id=v_op.case_id;
  select * into v_obj from app.evidence_objects
    where id=(v_op.command->>'evidence_object_id')::uuid and case_id=v_op.case_id;
  select * into v_storage from app.evidence_storage_authorities where case_id=v_op.case_id;
  if not found or v_case.legacy_case_dir is null or v_obj.id is null
     or v_storage.profile<>'LOCAL_IMMUTABLE' or v_storage.state<>'AVAILABLE'
     or not (v_item ?& array['evidence_object_id','display_path',
       'prior_status','prior_seal_status','original_version_id','original_sha256',
       'original_bytes','present','sha256','bytes','st_dev','st_ino','st_nlink'])
     or (v_item-array['evidence_object_id','display_path','prior_status',
       'prior_seal_status','original_version_id','original_sha256','original_bytes',
       'present','sha256','bytes','st_dev','st_ino','st_nlink'])<>'{}'::jsonb
     or jsonb_typeof(v_item->'original_version_id')<>'null'
     or jsonb_typeof(v_item->'original_sha256') not in ('null','string')
     or jsonb_typeof(v_item->'original_bytes') not in ('null','number')
     or jsonb_typeof(v_item->'present')<>'boolean'
     or jsonb_typeof(v_item->'bytes')<>'number'
     or jsonb_typeof(v_item->'st_dev')<>'number'
     or jsonb_typeof(v_item->'st_ino')<>'number'
     or jsonb_typeof(v_item->'st_nlink')<>'number'
     or v_obj.status not in ('detected','registered','ignored')
     or v_obj.seal_status<>'unsealed'
     or v_item->>'evidence_object_id' is distinct from v_obj.id::text
     or v_item->>'display_path' is distinct from v_obj.display_path
     or v_item->>'prior_status' is distinct from v_obj.status
     or v_item->>'prior_seal_status' is distinct from v_obj.seal_status
     or v_item->>'original_version_id' is distinct from v_obj.current_version_id::text
     or v_item->>'original_sha256' is distinct from v_obj.current_sha256
     or v_item->>'original_bytes' is distinct from v_obj.current_bytes::text
     or coalesce((v_item->>'present')::boolean,false) is false
     or coalesce(v_item->>'sha256','') !~ '^sha256:[0-9a-f]{64}$'
     or coalesce(v_item->>'bytes','') !~ '^[0-9]+$'
     or coalesce(v_item->>'st_dev','') !~ '^[0-9]+$'
     or coalesce(v_item->>'st_ino','') !~ '^[0-9]+$'
     or coalesce(v_item->>'st_nlink','')<>'1' then
    raise exception 'custody_delete_broker_object_unauthorized'
      using errcode='invalid_authorization_specification';
  end if;
  v_digest:='sha256:'||encode(sha256(convert_to(v_item::text,'UTF8')),'hex');
  select * into v_receipt from app.custody_delete_broker_receipts
    where operation_id=v_op.id;
  if found and (v_receipt.prepared_facts_sha256<>v_digest
     or (v_receipt.runner_instance_id<>v_op.runner_instance_id
       and not (coalesce(v_op.retired_runner_instance_ids,'[]'::jsonb)
         ? v_receipt.runner_instance_id))) then
    raise exception 'custody_delete_broker_receipt_mismatch'
      using errcode='integrity_constraint_violation';
  end if;
  return jsonb_build_object(
    'operation_id',v_op.id::text,'runner_instance_id',v_op.runner_instance_id,
    'prepared_facts_sha256',v_digest,'case_key',v_case.case_key,
    'legacy_case_dir',v_case.legacy_case_dir,'display_path',v_obj.display_path,
    'item',v_item,'receipt_claimed',v_receipt.operation_id is not null,
    'receipt_completed',v_receipt.completed_at is not null,
    'receipt_runner_instance_id',v_receipt.runner_instance_id);
end $$;

-- CREATE OR REPLACE retains the existing owner and ACL. Reassert the closed
-- runtime-role boundary in case an intermediate deployment drifted its grants.
revoke all on function sift_custody_broker.authorize(uuid,text)
  from public,anon,authenticated,service_role;
grant usage on schema sift_custody_broker to sift_custody_delete_broker;
grant execute on function sift_custody_broker.authorize(uuid,text)
  to sift_custody_delete_broker;
