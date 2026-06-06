# Migration State

## Current Objective

Create the migration workspace and context-control process only.

## Decisions Already Made

- Supabase/Postgres is the authoritative control plane.
- Human operators use Supabase Auth and RLS.
- Agents, MCP clients, workers, and backend services use Gateway-issued, case-scoped MCP/service tokens.
- MCP/service tokens are stored in the Postgres token registry as hashes only.
- Gateway validates MCP/service tokens and enforces tool scope, case scope, expiry, revocation, and policy before MCP or workflow actions.
- Postgres is authoritative for token registry state, case permissions, audit events, durable job state, evidence metadata, approval state, and workflow state.
- Immutable raw evidence and cryptographic ledger artifacts are preserved as proof/export while control-plane state moves to Postgres.
- OpenSearch is integrated through Gateway policy as a core derived search/data plane, initially by adapting existing OpenSearch code.
- OpenSearch must not become the authority for cases, tokens, jobs, evidence integrity, or approvals.
- No Redis/RQ.

## Files Created

- `docs/migration/README.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/01_repo_inventory.md`

## Files Inspected

- Attached target architecture image from the user prompt.
- `/home/yk/.codex/attachments/037bdcf4-8981-45cc-ab65-77883484d9b1/sift_vm_dfir_exact_replica.mmd`
- `docs/README.md`
- `docs/revamp/target-architecture.mmd`
- `packages/sift-core/src/sift_core/case_io.py`
- `packages/sift-core/src/sift_core/evidence_chain.py`
- `packages/sift-core/src/sift_core/audit_ops.py`
- `packages/sift-core/src/sift_core/case_ops.py`
- `packages/sift-gateway/src/sift_gateway/auth.py`
- `packages/sift-gateway/src/sift_gateway/identity.py`
- `packages/sift-gateway/src/sift_gateway/token_gen.py`
- `packages/sift-gateway/src/sift_gateway/config.py`
- `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
- `packages/sift-gateway/src/sift_gateway/rest.py`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/opensearch-mcp/README.md`
- Targeted `rg` scans for JSON state, evidence, audit, tokens, OpenSearch, jobs, Redis/RQ, and case paths.

## Open Questions

- What exact Supabase Local deployment shape should this repo target?
- What are the eventual Postgres schema boundaries for cases, jobs, evidence metadata, audit events, approvals, and token registry state?
- What OpenSearch index naming, job linkage, and provenance conventions should become canonical?
- What is the safest migration cutover order from JSON/file authority to Postgres authority?

## Next Recommended Run

Fill `docs/migration/01_repo_inventory.md` from repo inspection only. Do not implement code, schema, Docker, or migration changes. Keep this state file short and update it at the end.
