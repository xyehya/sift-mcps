-- Harden ALL append-only hash chains + SECURITY DEFINER RPCs (F2/F3/F4 from the
-- DB-audit-unit security review, applied beyond the approval ledger).
--
-- The 2026-06-14 adversarial review of the approval-commit ledger
-- (202606141200) surfaced three gaps that, by construction, also apply to the
-- locked evidence custody chain (202606081000) and any app SECURITY DEFINER RPC:
--
--   F2 (canonicalization injection): the per-event chain hash joins fields with
--       '|'. A free-form field containing '|' could shift canonical boundaries.
--       -> For app.evidence_custody_events this is ALREADY closed: event_type is
--          enum-constrained (evidence_custody_events_event_type_check), and the
--          remaining hashed fields are uuid / integer / sha256-shaped /
--          service-written jsonb — NO request-supplied free-form field is
--          reachable (unlike the approval ledger's item_id, which got a CHECK).
--          So F2 needs NO new constraint here; documented, not changed. The hash
--          payload itself is NOT rewritten (the live chain has real events; a
--          canonicalization change would break verification across the boundary).
--
--   F3 (TRUNCATE bypass): the append-only guard is a BEFORE UPDATE/DELETE *row*
--       trigger; TRUNCATE is a statement-level op that bypasses row triggers, so
--       a TRUNCATE-privileged role could wipe a chain without tripping it. This
--       migration adds BEFORE TRUNCATE statement triggers to the custody chain
--       tables and the chain-head tip table (reusing app.evidence_block_mutation).
--
--   F4 (PUBLIC execute on SECURITY DEFINER RPCs): functions get EXECUTE to PUBLIC
--       by default and the evidence/reacquire migrations never revoked it. Today
--       this is not exploitable because USAGE on schema app is granted to
--       service_role only (verified: public/authenticated/anon = no USAGE), but a
--       future migration that widens app USAGE would expose every SECURITY DEFINER
--       app RPC to forged calls. This revokes EXECUTE from PUBLIC on ALL app
--       SECURITY DEFINER functions and (re)grants service_role — REQUIRED because
--       some (e.g. app.evidence_append_custody_event) currently have NO explicit
--       grantee and rely on the PUBLIC default, so a bare revoke would break the
--       gateway's service-role path.
--
-- Idempotent: triggers use drop-if-exists; the grant/revoke loop is repeatable.

-- ---------------------------------------------------------------------------
-- F3: BEFORE TRUNCATE guards on the custody chain + head tables.
-- app.evidence_block_mutation() already raises restrict_violation (202606081000).
-- ---------------------------------------------------------------------------
drop trigger if exists evidence_custody_events_no_truncate on app.evidence_custody_events;
create trigger evidence_custody_events_no_truncate
  before truncate on app.evidence_custody_events
  for each statement execute function app.evidence_block_mutation();

drop trigger if exists evidence_versions_no_truncate on app.evidence_versions;
create trigger evidence_versions_no_truncate
  before truncate on app.evidence_versions
  for each statement execute function app.evidence_block_mutation();

drop trigger if exists evidence_chain_heads_no_truncate on app.evidence_chain_heads;
create trigger evidence_chain_heads_no_truncate
  before truncate on app.evidence_chain_heads
  for each statement execute function app.evidence_block_mutation();

-- ---------------------------------------------------------------------------
-- F4: revoke EXECUTE from PUBLIC on every app SECURITY DEFINER function, then
-- (re)grant service_role. Covers evidence custody (11), evidence reacquire (1),
-- the approval ledger (2, already revoked in 202606141200 — idempotent here), and
-- any future app SECURITY DEFINER RPC. p.oid::regprocedure yields the exact
-- schema-qualified signature for the dynamic revoke/grant target.
-- ---------------------------------------------------------------------------
do $$
declare
  r record;
  has_service_role boolean := exists (select 1 from pg_roles where rolname = 'service_role');
begin
  for r in
    select p.oid::regprocedure::text as sig
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'app'
       and p.prosecdef
  loop
    execute format('revoke execute on function %s from public', r.sig);
    if has_service_role then
      execute format('grant execute on function %s to service_role', r.sig);
    end if;
  end loop;
end
$$;
