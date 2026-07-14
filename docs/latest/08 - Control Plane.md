---
title: Control Plane — Postgres/Supabase Schema and RLS
class: live-reference
source_of_truth: supabase/migrations/*.sql
last_reconciled: 2026-07-14
verified_against: code+tests+config
invariants_checked: 9
status: maintained
---

## Overview

The Control Plane is the authoritative data layer running on Supabase (Postgres 15 with pgvector). Application tables live in the `app` schema. The baseline force-RLS migration covered the 31 tables that existed when it landed; later custody migrations explicitly enable and force RLS on each new authority table. The Gateway's DB-authoritative mode uses this schema for identity and JWT principals, active case authority, evidence custody chains, audit events, durable jobs, backends registry, investigation data, report metadata, approval ledger, OpenSearch provenance, and RAG vector storage. Schema evolution is the timestamp-ordered SQL set present in `supabase/migrations/` at the checked-out revision.

**Key files**: `supabase/config.toml`, `supabase/migrations/*.sql`. The directory listing is the migration inventory; this live reference does not duplicate its count.

## How it works

The Gateway connects to Postgres via two DSNs: `control-plane-dsn` (read-write) and optionally `audit-forward-write-dsn`. All evidence and identity operations call SECURITY DEFINER RPCs rather than direct table access. The `sift_audit_writer` role has narrow INSERT/UPDATE policies and no BYPASSRLS (dropped by `202606242300`). `FORCE ROW LEVEL SECURITY` on all 31 tables means even the table owner must satisfy RLS; only `service_role` (BYPASSRLS) is unaffected.

## Reference sections

### Config (`supabase/config.toml`)

Supabase CLI v2.105.0 local dev config. Enabled: db (Postgres 15, port 54322), auth (GoTrue), api (Kong). Disabled: studio, inbucket, storage, realtime, edge_runtime, analytics. Auth: `jwt_expiry = 172800` (48h for agent sessions), `enable_refresh_token_rotation = true`, `enable_confirmations = false` (autoconfirm — no SMTP), `enable_signup = true`.

### Migration files

**Foundation & Identity (`202606070101`):**
Creates `app` schema, `pgcrypto` extension. Nine tables:
- `app.operator_profiles` — linked to `auth.users(id)`, status (active/disabled/invited/archived)
- `app.cases` — case lifecycle, status (draft/active/paused/closed/archived)
- `app.case_members` — operator case membership with roles (readonly/operator/lead/owner/admin)
- `app.active_case_state` — singleton deployment-scoped active case pointer
- `app.agents` — AI agent identities
- `app.service_identities` — service principals
- `app.mcp_tokens` — hash-only MCP token registry (`token_hash` unique, `token_fingerprint` unique, `principal_check` ensures at most one of agent_id/service_identity_id)
- `app.audit_events` — append-oriented audit events
- `app.mcp_token_scopes` — normalized case/tool/action scopes

RLS enabled on all nine tables at creation (`alter table ... enable row level security`).

**Unified JWT Principals (`202606070300`):**
- `app.principal_tool_scopes` — normalized per-principal tool scopes

**Active Case Authority (`202606070400`):**
- View `app.deployment_active_case` — joins `active_case_state` + `cases`
- `app.active_case_state` is the SOLE authority for active case (comment: "It is not active-case authority; app.active_case_state is authoritative")

**MCP Backends Registry (`202606070500`) + hardening (`202606080100`):**
- `app.mcp_backends` — registered add-on backends with scopes, status, config

**Evidence Custody (`202606081000`):**
Five tables:
- `app.evidence_objects` — per-case evidence. `display_path` CHECK constraint rejects absolute paths (`left(display_path, 1) <> '/'`, no `..` traversal, no `[a-zA-Z]:[\\/]` Windows paths)
- `app.evidence_versions` — append-only per-item snapshots at each manifest version
- `app.evidence_custody_events` — **append-only** hash-linked custody ledger (`prev_hash`/`event_hash` per-case SHA-256 chain). UPDATE/DELETE blocked by `evidence_block_mutation()` trigger
- `app.evidence_chain_heads` — per-case chain head + aggregate seal status (gate read model)
- `app.evidence_proof_exports` — non-authoritative export metadata

Security-Definer RPCs include evidence detection, sealing, verification, closed drift classification, and durable operator dispositions. Portal routes do not invoke legacy one-shot ignore/retire mutations: Ignore, Delete Stray, and Retire begin a custody operation with an idempotency key and fresh re-authentication, block the gate, persist phase facts, and commit exactly once. Delete Stray is limited to readable pending Local Immutable files and records pinned pre-unlink identity/digest/size. The Gateway remains AppArmor write-denied; an exact no-argument sudo transition invokes a root-owned fixed broker. It reads a root-owned `0600` DSN for a dedicated role with no `app` schema/table access and only three isolated RPCs, rebinds operation/runner authority, drops to `sift-service`, revalidates the file, and records an exact claim/completion receipt around unlink. Postgres requires that completed receipt before verified or completed DELETE transitions. Missing-file recovery without the claim fails closed. Retire preserves protected bytes and every prior version. Service-only RPC grants and forced RLS keep browser roles out of this authority path. Internal chain helpers append custody events and recompute the aggregate gate.

**Durable Jobs (`202606081200`):**
- `app.jobs`, `app.job_steps`, `app.job_logs`, `app.worker_heartbeats`

**OpenSearch Provenance (`202606081300`):**
- `app.opensearch_indices`, `app.opensearch_ingest_provenance` — records every OpenSearch ingest for audit trail

**RAG pgvector (`202606081400`):**
- `app.rag_collections`, `app.rag_documents`, `app.rag_chunks` — pgvector(768) embedding store

**Report Metadata (`202606081500`):**
- `app.report_metadata`

**Investigation Authority (`202606081600`):**
- `app.investigation_findings`, `app.investigation_timeline_events`, `app.investigation_iocs`, `app.investigation_todos` — versioned with optimistic lock, `reauth_audit_event_id` for human decisions, `investigation_human_locked()` prevents agent overwrite of approved/rejected rows

**Host Identity (`202606081601`):**
- `app.host_identity_decisions`

**Investigation IOCs Content Hash (`202606081602`):**

**Evidence Reacquire (`202606101000`):**

**RAG Search Filters (`202606101100`):**

**RAG Knowledge Only (`202606111200`):**
- Replaces `app.rag_search` with knowledge-only variant — hard-codes `kind = 'knowledge'` in WHERE clause
- BEFORE INSERT triggers on all three RAG tables block `kind='derived'` inserts at DB level (`_block_derived_rag_insert()`)

**Force RLS (`202606131000`):**
- `FORCE ROW LEVEL SECURITY` on all 31 `app.*` tables
- Service_role (BYPASSRLS) is unaffected — this closes the owner-bypass gap for tables with 0 policies

**Approval Ledger (`202606141200`):**
- `app.approval_commit_events` — append-only, per-case hash-linked ledger (mirrors evidence_custody_events pattern)
- `app.approval_commit_heads` — per-case chain head
- `app.approval_append_commit_event(...)` — SECURITY DEFINER RPC

**Harden Append-Only Chains (`202606141400`):**
- F3: BEFORE TRUNCATE triggers on `evidence_custody_events`, `evidence_versions`, `evidence_chain_heads` (TRUNCATE bypasses row triggers)
- F4: Revoke EXECUTE FROM PUBLIC on ALL app SECURITY DEFINER functions; (re)grant service_role

**Evidence Unseal (`202606160100`):**
- B-MVP-048 unseal support

**OpenSearch Worker Status (`202606150900`):**

**Audit Details GIN Index (`202606232000`):**
- GIN index (default `jsonb_ops`) on `app.audit_events(details)` — supports `?|` operator for audit_aliases superset resolver
- Expression indexes on `details->>'backend_audit_id'` and `details->>'envelope_event_id'`

**Audit Writer Role (`202606242100`):**
- Creates `sift_audit_writer` role WITH LOGIN BYPASSRLS — scoped to INSERT on `app.audit_events`, INSERT/UPDATE on `app.opensearch_indices` and `app.opensearch_ingest_provenance`, EXECUTE on two provenance RPCs
- Revokes PUBLIC EXECUTE on `app.evidence_unseal` (SECURITY DEFINER function created after the F4 sweep)
- No password in migration — set out-of-band at deploy; code falls back to full DSN when scoped DSN unset

**Revoke Public Execute SecDef (`202606242200`):**

**Audit Writer RLS (`202606242300`):**
- Drops BYPASSRLS from `sift_audit_writer`; adds explicit INSERT policies on `app.audit_events`, INSERT+UPDATE policies on `app.opensearch_indices` and `app.opensearch_ingest_provenance`

### RLS Policies (declared across migrations)

Pattern: Every table has case-based SELECT policies via `app.case_members` join. Mutation policies typically require `service_role` (called via SECURITY DEFINER RPCs). Key design:
- `app.evidence_custody_events` — no UPDATE/DELETE allowed (trigger blocks row-level + TRUNCATE)
- `app.audit_events` — INSERT only for most roles; narrow INSERT policy for `sift_audit_writer` (no BYPASSRLS after `202606242300`)
- `app.evidence_objects` — service_role-only mutation RPCs; case_members SELECT
- `app.opensearch_indices`, `app.opensearch_ingest_provenance` — INSERT+UPDATE policies for `sift_audit_writer` only
- FORCE RLS ensures even table owner must satisfy RLS — only BYPASSRLS roles (service_role) are exempt

### 31 forced tables (from `202606131000_force_rls_app_tables.sql`)

identity_foundation: operator_profiles, cases, case_members, active_case_state, agents, service_identities, mcp_tokens, audit_events, mcp_token_scopes
unified_jwt: principal_tool_scopes
backends: mcp_backends
evidence: evidence_objects, evidence_versions, evidence_custody_events, evidence_chain_heads, evidence_proof_exports
jobs: jobs, job_steps, job_logs, worker_heartbeats
opensearch: opensearch_indices, opensearch_ingest_provenance
rag: rag_collections, rag_documents, rag_chunks
investigation: investigation_findings, investigation_timeline_events, investigation_iocs, investigation_todos
other: report_metadata, host_identity_decisions

## Invariants

- **Postgres is authoritative; OpenSearch is derived**: The control plane is the source of truth for identity, cases, evidence, audit, jobs, and configurations. OpenSearch is always a rebuildable projection.
- **`active_case_state` is the sole authority for active case**: View `deployment_active_case` joins it with `cases`. Comment explicitly states "It is not active-case authority; app.active_case_state is authoritative". (`202606070400` migration, lines 5-8)
- **Evidence custody chain is append-only**: `evidence_block_mutation()` trigger raises `restrict_violation` on UPDATE/DELETE (row-level) + TRUNCATE (statement-level added by `202606141400`). Hash-linked ledger. (`202606081000` migration, lines 235-253; `202606141400` lines 42-55)
- **FORCE RLS on all 31 app tables**: Even owner role must satisfy RLS. Service_role (BYPASSRLS) unaffected. (`202606131000` migration)
- **Audit writer role has no BYPASSRLS**: `sift_audit_writer` governed by explicit INSERT/UPDATE policies only after `202606242300` drops BYPASSRLS. (`202606242300` migration, line 134: `alter role sift_audit_writer nobypassrls`)
- **Absolute paths rejected in evidence_objects**: CHECK constraint on `display_path` — `left(display_path, 1) <> '/'`, no `..`, no Windows drive letters. (`202606081000` migration, lines 62-68)
- **Agent JWT TTL >= 48h**: Enforced by Supabase Auth config: `jwt_expiry = 172800`. (`config.toml`, line 99)
- **RLS on identity: one auth_user → one principal**: `lookup_by_auth_user_id` raises `AmbiguousPrincipalError` on one-to-many mapping. (`supabase_auth.py:553-577`)
- **RAG is shared-knowledge only**: Both Python layer and DB trigger (`_block_derived_rag_insert()`) reject `kind='derived'`. (`202606111200` migration)

## Gotchas & Edge Cases

> [!important] This is a live reference, not a generated snapshot. Validate migration inventory and behavior against `supabase/migrations/*.sql` in the checked-out revision; code and migrations win on conflict.

> [!important] RAG `kind='knowledge'` is enforced at both Python layer and DB trigger. `kind='derived'` inserts raise an exception. (`202606111200` migration, `_block_derived_rag_insert()`)

> [!warning] `sift_audit_writer` role has no BYPASSRLS — it is governed by explicit INSERT/UPDATE policies. If the audit writer's INSERT fails (RLS violation), the call is not silently degraded — the fail-soft path logs at debug. (`202606242300` migration; `202606242100` migration lines 47-48, 53-56 note fail-soft behavior)

> [!note] Migrations are timestamp-ordered. Apply them through the canonical installer/migration runner, which records applied versions; do not infer safety from a duplicated document count or manually reorder files.

> [!note] 31 `app.*` tables all carry `FORCE ROW LEVEL SECURITY` — repeated from the force_rls migration comment: "ALTER TABLE ... FORCE ROW LEVEL SECURITY is a no-op if the flag is already set."

> [!note] The SECURITY DEFINER F4 sweep (`202606141400`) revokes PUBLIC EXECUTE from ALL existing app secdef functions. Functions created after that migration (e.g., `evidence_unseal` at `202606160100`) were not covered — the audit writer migration (`202606242100`) manually revokes that one.

## Related

- Gateway doc — reads `app.active_case_state`, `app.mcp_backends`, `app.mcp_tokens`, `app.audit_events`
- Core Tools doc — uses Postgres investigation store for findings/timeline/iocs
- OpenSearch Data Plane doc — writes ingest provenance to `app.opensearch_ingest_provenance`
- Portal doc — reads all tables via REST API
- Add-on Ecosystem doc — forensic-rag-mcp uses `app.rag_*` tables

## Key files

- `supabase/config.toml` — Supabase CLI config, auth settings
- `supabase/migrations/202606070101_identity_foundation.sql` — Schema, identity, cases, tokens, audit base
- `supabase/migrations/202606070400_active_case_authority.sql` — active_case_state authority view
- `supabase/migrations/202606081000_evidence_custody.sql` — Append-only custody chain
- `supabase/migrations/202606131000_force_rls_app_tables.sql` — FORCE RLS on all 31 tables
- `supabase/migrations/202606242100_audit_writer_role.sql` — sift_audit_writer role creation
- `supabase/migrations/202606242300_audit_writer_rls_policies.sql` — sift_audit_writer RLS + drop BYPASSRLS
- `supabase/migrations/202606141200_approval_ledger_db.sql` — Approval hash chain
- `supabase/migrations/202606111200_rag_knowledge_only.sql` — RAG knowledge enforcement
- `supabase/migrations/202606141400_harden_append_only_chains.sql` — F3/F4 append-only guards + secdef sweep
- `supabase/migrations/202606232000_audit_details_gin_index.sql` — GIN index on audit_events(details)

## Reconciliation log

Reconciled 2026-07-14 with the current custody-operation migrations. Migration SQL remains the authority for inventory, grants, RLS, append-only guards, and operation-state enforcement; this document deliberately avoids a source-commit or total-count snapshot that would become false on the next additive migration.
