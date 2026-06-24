-- C2: durable revoke of PUBLIC execute on all app SECURITY DEFINER functions.
--
-- W1-S1 (CWE-732/266) found that granting USAGE on schema app silently
-- re-exposes any SECURITY DEFINER function in that schema to PUBLIC EXECUTE:
-- Postgres grants EXECUTE to PUBLIC by default when a function is created, and
-- USAGE on the schema is sufficient to call it. A scoped role (or any authed
-- user) that gains schema USAGE can therefore call SECURITY DEFINER functions
-- regardless of whether it holds an explicit EXECUTE grant.
--
-- This migration closes that class of gap in a DATA-DRIVEN, idempotent way:
-- it loops over every SECURITY DEFINER function currently in schema app and:
--   1. REVOKES execute from PUBLIC (eliminates the default public grant).
--   2. GRANTs execute to service_role (preserves the legitimate privileged path).
--
-- The loop uses pg_get_function_identity_arguments to reconstruct each function's
-- full signature (including argument types) so the REVOKE/GRANT target is exact.
--
-- Idempotent: REVOKE from PUBLIC on an already-revoked function is a no-op.
-- GRANT to service_role on an already-granted function is a no-op.
-- Safe to re-run at any time; also covers new SECDEF functions added later if
-- this migration is re-applied (or if a follow-up migration re-runs this block).
--
-- DO NOT revoke from service_role — that role is the legitimate privileged caller.

do $$
declare
  r record;
  fn_sig text;
begin
  for r in
    select
      p.proname as fn_name,
      pg_get_function_identity_arguments(p.oid) as fn_args
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'app'
      and p.prosecdef = true
  loop
    fn_sig := 'app.' || quote_ident(r.fn_name) || '(' || r.fn_args || ')';

    -- Revoke the default PUBLIC execute grant (idempotent: no-op if already absent).
    execute 'revoke execute on function ' || fn_sig || ' from public';

    -- Preserve the legitimate privileged-caller path (idempotent: no-op if already granted).
    execute 'grant execute on function ' || fn_sig || ' to service_role';
  end loop;
end;
$$;
