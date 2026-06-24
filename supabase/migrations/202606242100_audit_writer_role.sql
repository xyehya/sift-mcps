-- L-1b: least-privilege DB role for the B-D1 audit forward-write path.
--
-- Background
-- ----------
-- The gateway injects a Postgres write DSN into the opensearch-worker job and
-- thence the ingest subprocess (B-D1; policy_middleware.py:_enqueue ->
-- ingest_job.py) so the per-artifact provenance forward-writes can reach the
-- control plane. Today that DSN is the FULL control-plane DSN — the Supabase
-- `service_role`, which carries BYPASSRLS and has full DML on every app.* table.
-- A `/proc/<pid>/environ` read of the ingest subprocess (same-UID/root, single-
-- tenant appliance — see AUDIT_HARDENING_SPEC.md "L-1a") therefore exposes a
-- credential far broader than the forward-write path needs.
--
-- This migration creates a SCOPED role (`sift_audit_writer`) granted EXACTLY the
-- privileges the injected-DSN forward-write path uses (inventory below), so the
-- gateway can inject that role's DSN (SIFT_AUDIT_WRITER_DSN) instead of the full
-- control-plane DSN. The code falls back to the full DSN when the scoped DSN is
-- unset, so this is a non-breaking rollout: deploy the code first, set the
-- secret later, and least-privilege activates the moment the secret exists.
--
-- Exact privileges the INJECTED DSN performs (inventory — verified)
-- -----------------------------------------------------------------
-- The injected DSN runs ONLY in the ingest subprocess. It performs:
--   1. INSERT app.audit_events                 (B-D2; ingest.py:_persist_ingest_audit_event)
--   2. SELECT app.register_opensearch_index(...)        -> INSERT + UPDATE app.opensearch_indices
--   3. SELECT app.record_opensearch_ingest_provenance(...) -> INSERT + UPDATE app.opensearch_ingest_provenance
-- The two RPCs are `language plpgsql` with NO SECURITY DEFINER (see
-- 202606081300_opensearch_provenance.sql:110-111), so they run with the CALLER's
-- privileges — the role therefore needs INSERT+UPDATE on the two underlying
-- tables directly, plus EXECUTE on the functions.
-- The ingest subprocess does NOT SELECT app.audit_events (verified). The
-- shell-tier forward-write (B-D3, _persist_shell_audit_event) runs in the
-- gateway/core process and only INSERTs app.audit_events. The grounding SELECTs
-- on app.audit_events (case_manager.py:221,226,2078,2086) run in the
-- gateway/core process on the FULL control-plane DSN and are NOT part of the
-- injected/scoped path.
--
-- DIVERGENCE FROM "INSERT + SELECT on app.audit_events" (flagged for operator)
-- ---------------------------------------------------------------------------
-- The locked decision said "INSERT + SELECT on app.audit_events". The inventory
-- shows SELECT on app.audit_events is NOT used by EITHER scoped path (ingest
-- subprocess or shell forward-write). Granting it would be unnecessary surface,
-- so this migration grants INSERT-only on app.audit_events (minimal-correct).
-- If the operator later moves the grounding SELECTs onto the scoped DSN, add
-- `grant select on app.audit_events to sift_audit_writer;` then.
--
-- FORCE ROW LEVEL SECURITY interaction (IMPORTANT — read before narrowing)
-- -----------------------------------------------------------------------
-- All app.* tables carry FORCE ROW LEVEL SECURITY (202606131000). app.audit_events,
-- app.opensearch_indices and app.opensearch_ingest_provenance have only SELECT
-- RLS policies (or zero policies) — there is NO INSERT/UPDATE policy. A role
-- WITHOUT BYPASSRLS would have every INSERT/UPDATE DENIED by FORCE RLS even with
-- the table grants below. The current control-plane DSN works precisely because
-- service_role carries BYPASSRLS. So this role is created WITH BYPASSRLS to be
-- able to write where granted; the least-privilege win is the TABLE/FUNCTION
-- privilege scope (3 tables + 2 functions) vs service_role's full app.* DML —
-- a real blast-radius reduction for a /proc credential leak. (A no-BYPASSRLS
-- design would require adding service-write RLS policies to those three tables;
-- tracked as a possible follow-up, not done here to avoid widening RLS surface.)
--
-- Password / secret
-- -----------------
-- The role is created WITH LOGIN but NO password here — NEVER hardcode a
-- credential in a migration. The operator sets the password OUT-OF-BAND at
-- deploy, e.g.:
--     ALTER ROLE sift_audit_writer PASSWORD '<from-secret-store>';
-- and the deploy writes the scoped DSN to a 0600 secret (SIFT_AUDIT_WRITER_DSN
-- in control-plane.env). Until then the role cannot log in and the code falls
-- back to the full control-plane DSN (provenance keeps working).
--
-- Idempotency
-- -----------
-- create role is guarded (no-op if the role already exists); all grants are
-- idempotent (re-granting is a no-op). Safe to re-run on a DB where the role
-- already exists. ALTER ROLE ... LOGIN BYPASSRLS re-asserts the attributes
-- without touching any password the operator may already have set.

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'sift_audit_writer') then
    -- LOGIN so the role can authenticate via its own DSN; BYPASSRLS so its
    -- granted INSERT/UPDATEs are not blocked by FORCE RLS (no service-write
    -- policy exists on the target tables). NO password — set out-of-band.
    create role sift_audit_writer with login bypassrls;
  else
    -- Re-assert the attributes idempotently without disturbing an
    -- operator-set password.
    alter role sift_audit_writer with login bypassrls;
  end if;

  -- Schema access.
  grant usage on schema app to sift_audit_writer;

  -- (1) B-D2 + B-D3 audit forward-writes. INSERT-only (no SELECT — see
  -- inventory/divergence note above; the grounding SELECTs stay on the full DSN).
  grant insert on app.audit_events to sift_audit_writer;

  -- (2) BATCH-F1 ingest provenance. The RPCs are NOT SECURITY DEFINER, so the
  -- caller needs direct table privileges. The functions upsert (INSERT + ON
  -- CONFLICT DO UPDATE), so both INSERT and UPDATE are required.
  grant insert, update on app.opensearch_indices to sift_audit_writer;
  grant insert, update on app.opensearch_ingest_provenance to sift_audit_writer;

  -- EXECUTE on the two provenance RPCs the ingest subprocess calls.
  grant execute on function app.register_opensearch_index(
    uuid, text, text, text, uuid, uuid, uuid, bigint, text
  ) to sift_audit_writer;
  grant execute on function app.record_opensearch_ingest_provenance(
    uuid, uuid, uuid, uuid, text, bigint, bigint, jsonb
  ) to sift_audit_writer;
end
$$;

comment on role sift_audit_writer is
  'L-1b least-privilege audit-write role for the B-D1 forward-write path. '
  'Scoped to INSERT app.audit_events + INSERT/UPDATE the two opensearch '
  'provenance tables + EXECUTE the two provenance RPCs. Carries BYPASSRLS '
  '(the target tables have no service-write RLS policy under FORCE RLS). '
  'Password set out-of-band at deploy; injected as SIFT_AUDIT_WRITER_DSN.';
