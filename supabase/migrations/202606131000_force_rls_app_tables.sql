-- BATCH-DB1: FORCE ROW LEVEL SECURITY on all app.* tables (B-MVP-013).
--
-- Background
-- ----------
-- HR2 audit (2026-06-12) found: all 31 app.* base tables have RLS ENABLED
-- (relrowsecurity=t) and 0 of 31 have FORCE ROW LEVEL SECURITY
-- (relforcerowsecurity=t).
--
-- Without FORCE, the Postgres table OWNER role bypasses RLS unconditionally.
-- FORCE ROW LEVEL SECURITY makes RLS apply to the owner role as well.
--
-- Gateway impact
-- --------------
-- Supabase service_role carries the BYPASSRLS attribute (Postgres privilege,
-- not a policy).  BYPASSRLS is NOT affected by FORCE ROW LEVEL SECURITY —
-- only superusers and roles with explicit BYPASSRLS skip enforcement.
-- Therefore the gateway's own queries (which run as service_role) are
-- UNAFFECTED.  This migration is pure defence-in-depth:
--   * Tables that already carry policies: owner-role direct access is now
--     subject to those policies.
--   * Tables that have 0 policies (default-deny for ordinary roles, e.g.
--     active_case_state, audit_events, evidence_custody_events, job_steps,
--     job_logs, mcp_token_scopes, mcp_tokens, rag_chunks, rag_documents,
--     service_identities, worker_heartbeats): the owner is also denied by
--     default — this closes the owner-bypass gap on those tables.
--
-- Idempotency
-- -----------
-- ALTER TABLE ... FORCE ROW LEVEL SECURITY is a no-op if the flag is already
-- set (Postgres silently accepts re-FORCEing).  This migration is safe to
-- re-run.  It runs AFTER all table + policy definitions in the migration
-- sequence (all prior migrations are timestamped earlier).
--
-- Operator verification (redacted — emit boolean/count only)
-- ----------------------------------------------------------
--   SELECT relname
--   FROM   pg_class
--   WHERE  relkind = 'r'
--     AND  relnamespace = 'app'::regnamespace
--     AND  relrowsecurity = true
--     AND  relforcerowsecurity = false;
--   -- Expected: 0 rows after this migration is applied.
--
-- Source: B-MVP-013 / BATCH-DB1 (task-batches.md §BATCH-DB1).

-- identity_foundation (202606070101)
alter table app.operator_profiles    force row level security;
alter table app.cases                force row level security;
alter table app.case_members         force row level security;
alter table app.active_case_state    force row level security;
alter table app.agents               force row level security;
alter table app.service_identities   force row level security;
alter table app.mcp_tokens           force row level security;
alter table app.audit_events         force row level security;
alter table app.mcp_token_scopes     force row level security;

-- unified_jwt_principals (202606070300)
alter table app.principal_tool_scopes force row level security;

-- mcp_backends_registry (202606070500)
alter table app.mcp_backends         force row level security;

-- evidence_custody (202606081000)
alter table app.evidence_objects     force row level security;
alter table app.evidence_versions    force row level security;
alter table app.evidence_custody_events force row level security;
alter table app.evidence_chain_heads force row level security;
alter table app.evidence_proof_exports force row level security;

-- durable_jobs (202606081200)
alter table app.jobs                 force row level security;
alter table app.job_steps            force row level security;
alter table app.job_logs             force row level security;
alter table app.worker_heartbeats    force row level security;

-- opensearch_provenance (202606081300)
alter table app.opensearch_indices   force row level security;
alter table app.opensearch_ingest_provenance force row level security;

-- rag_pgvector (202606081400)
alter table app.rag_collections      force row level security;
alter table app.rag_documents        force row level security;
alter table app.rag_chunks           force row level security;

-- report_metadata / investigation_authority (202606081500 / 202606081600)
alter table app.investigation_findings       force row level security;
alter table app.investigation_timeline_events force row level security;
alter table app.investigation_iocs           force row level security;
alter table app.investigation_todos          force row level security;
alter table app.report_metadata              force row level security;

-- host_identity (202606081601)
alter table app.host_identity_decisions force row level security;
