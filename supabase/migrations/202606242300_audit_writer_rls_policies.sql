-- D2: drop BYPASSRLS from sift_audit_writer; add scoped per-table RLS write policies.
--
-- Background: the L-1b migration (202606242100) created sift_audit_writer WITH
-- BYPASSRLS because the target tables (app.opensearch_indices,
-- app.opensearch_ingest_provenance) had FORCE RLS with no service-write policy at
-- the time, so any INSERT/UPDATE from a non-BYPASSRLS role would be denied by the
-- RLS engine even with explicit table grants.
--
-- D2 hardens this by:
--   1. Adding narrow INSERT (and UPDATE where the forward-write upserts) policies
--      on all three tables for the sift_audit_writer role.
--   2. Removing the global BYPASSRLS from sift_audit_writer so the role can write
--      ONLY where an explicit RLS policy permits — no global bypass.
--
-- service_role is untouched (it retains its own BYPASSRLS; do not modify it here).
--
-- Tables + operations covered:
--   - app.audit_events               INSERT only (B-D2 + B-D3 forward-writes)
--   - app.opensearch_indices          INSERT + UPDATE (upsert via RPC)
--   - app.opensearch_ingest_provenance INSERT + UPDATE (upsert via RPC)
--
-- Idempotency: each policy is dropped-if-exists before re-creation. The final
-- ALTER ROLE is a no-op if BYPASSRLS is already absent.
--
-- ORCHESTRATOR NOTE: apply this migration AFTER 202606242100 and
-- 202606242200. After applying, re-prove the audit forward-write still succeeds
-- (ingest + shell paths) and that the role cannot write to out-of-scope tables.
-- A misconfigured policy would cause forward-writes to fail SILENTLY (fail-soft
-- swallows the error and logs at debug) — monitor the app.audit_events row count
-- during the live-prove step.

do $$
begin

  -- G4 (fresh-install defensive): if the role is absent (a partial/edited ledger
  -- state where 202606242100 did not run), this whole migration is a clean no-op
  -- rather than a mid-block abort on `create policy ... to sift_audit_writer`.
  -- Normal-path semantics are unchanged when the role exists.
  if not exists (select 1 from pg_roles where rolname = 'sift_audit_writer') then
    raise notice 'sift_audit_writer role absent — skipping RLS policy migration (no-op).';
    return;
  end if;

  -- -------------------------------------------------------------------------
  -- app.audit_events: INSERT policy for sift_audit_writer
  -- -------------------------------------------------------------------------
  if exists (
    select 1 from pg_policies
    where schemaname = 'app'
      and tablename  = 'audit_events'
      and policyname = 'audit_writer_insert'
  ) then
    drop policy audit_writer_insert on app.audit_events;
  end if;

  create policy audit_writer_insert
    on app.audit_events
    for insert
    to sift_audit_writer
    with check (true);

  -- -------------------------------------------------------------------------
  -- app.opensearch_indices: INSERT + UPDATE policies for sift_audit_writer
  -- -------------------------------------------------------------------------
  if exists (
    select 1 from pg_policies
    where schemaname = 'app'
      and tablename  = 'opensearch_indices'
      and policyname = 'audit_writer_insert'
  ) then
    drop policy audit_writer_insert on app.opensearch_indices;
  end if;

  create policy audit_writer_insert
    on app.opensearch_indices
    for insert
    to sift_audit_writer
    with check (true);

  if exists (
    select 1 from pg_policies
    where schemaname = 'app'
      and tablename  = 'opensearch_indices'
      and policyname = 'audit_writer_update'
  ) then
    drop policy audit_writer_update on app.opensearch_indices;
  end if;

  create policy audit_writer_update
    on app.opensearch_indices
    for update
    to sift_audit_writer
    using (true)
    with check (true);

  -- -------------------------------------------------------------------------
  -- app.opensearch_ingest_provenance: INSERT + UPDATE policies
  -- -------------------------------------------------------------------------
  if exists (
    select 1 from pg_policies
    where schemaname = 'app'
      and tablename  = 'opensearch_ingest_provenance'
      and policyname = 'audit_writer_insert'
  ) then
    drop policy audit_writer_insert on app.opensearch_ingest_provenance;
  end if;

  create policy audit_writer_insert
    on app.opensearch_ingest_provenance
    for insert
    to sift_audit_writer
    with check (true);

  if exists (
    select 1 from pg_policies
    where schemaname = 'app'
      and tablename  = 'opensearch_ingest_provenance'
      and policyname = 'audit_writer_update'
  ) then
    drop policy audit_writer_update on app.opensearch_ingest_provenance;
  end if;

  create policy audit_writer_update
    on app.opensearch_ingest_provenance
    for update
    to sift_audit_writer
    using (true)
    with check (true);

  -- -------------------------------------------------------------------------
  -- Drop the global BYPASSRLS — policies above now govern all write access.
  -- service_role's BYPASSRLS is untouched.
  -- -------------------------------------------------------------------------
  alter role sift_audit_writer nobypassrls;

end;
$$;
