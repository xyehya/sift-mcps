# Migration State

## Current Objective

Run 2 migration planning completed. The migration workspace now has a target
authority and trust-boundary document that maps current file-based authority
into the Supabase/Postgres control plane, OpenSearch core data plane, immutable
Evidence Vault, Gateway enforcement layer, and worker execution plane.

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
- Frontend UI state is not forensic state authority.
- Agent-generated findings remain draft/proposed until human approval and are not auto-approved.
- OpenSearch query and ingest paths must be Gateway-mediated and case-scoped by token/session context.
- Compatibility with current files should be additive first; file-backed behavior is not removed before DB authority and compatibility exports are verified.

## Files Created

- `docs/migration/README.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/01_repo_inventory.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`

## Files Inspected

- Attached target architecture image from the user prompt.
- `/home/yk/.codex/attachments/037bdcf4-8981-45cc-ab65-77883484d9b1/sift_vm_dfir_exact_replica.mmd`
- `docs/README.md`
- `docs/revamp/target-architecture.mmd`
- `docs/migration/README.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/01_repo_inventory.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `pyproject.toml`
- `configs/gateway.yaml.template`
- `configs/apparmor/sift-gateway.template`
- `docker-compose.yml`
- `docker-compose.opencti.yml`
- `packages/case-dashboard/frontend/package.json`
- `packages/case-dashboard/frontend/src/App.jsx`
- `packages/case-dashboard/frontend/src/api/client.js`
- `packages/case-dashboard/frontend/src/api/endpoints.js`
- `packages/case-dashboard/frontend/src/hooks/useDataPolling.js`
- `packages/case-dashboard/frontend/src/store/useStore.js`
- `packages/case-dashboard/frontend/src/components/layout/NavRail.jsx`
- `packages/case-dashboard/frontend/src/components/evidence/EvidenceTab.jsx`
- `packages/case-dashboard/frontend/src/components/reports/ReportsTab.jsx`
- `packages/case-dashboard/frontend/src/components/settings/SettingsTab.jsx`
- `packages/case-dashboard/src/case_dashboard/auth.py`
- `packages/case-dashboard/src/case_dashboard/session_jwt.py`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/sift-core/src/sift_core/case_io.py`
- `packages/sift-core/src/sift_core/case_manager.py`
- `packages/sift-core/src/sift_core/evidence_chain.py`
- `packages/sift-core/src/sift_core/case_ops.py`
- `packages/sift-core/src/sift_core/evidence_ops.py`
- `packages/sift-core/src/sift_core/verification.py`
- `packages/sift-core/src/sift_core/reporting.py`
- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-core/src/sift_core/execute/executor.py`
- `packages/sift-core/src/sift_core/execute/tools/generic.py`
- `packages/sift-common/src/sift_common/audit.py`
- `packages/sift-common/src/sift_common/__init__.py`
- `packages/sift-gateway/src/sift_gateway/auth.py`
- `packages/sift-gateway/src/sift_gateway/identity.py`
- `packages/sift-gateway/src/sift_gateway/token_gen.py`
- `packages/sift-gateway/src/sift_gateway/config.py`
- `packages/sift-gateway/src/sift_gateway/__main__.py`
- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
- `packages/sift-gateway/src/sift_gateway/rest.py`
- `packages/sift-gateway/src/sift_gateway/backends/__init__.py`
- `packages/sift-gateway/src/sift_gateway/backends/base.py`
- `packages/sift-gateway/src/sift_gateway/backends/stdio_backend.py`
- `packages/sift-gateway/src/sift_gateway/backends/http_backend.py`
- `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`
- `packages/forensic-mcp/src/forensic_mcp/server.py`
- `packages/forensic-rag-mcp/src/rag_mcp/server.py`
- `packages/forensic-rag-mcp/sift-backend.json`
- `packages/opencti-mcp/src/opencti_mcp/server.py`
- `packages/opencti-mcp/sift-backend.json`
- `packages/windows-triage-mcp/src/windows_triage_mcp/server.py`
- `packages/windows-triage-mcp/sift-backend.json`
- `packages/opensearch-mcp/pyproject.toml`
- `packages/opensearch-mcp/README.md`
- `packages/opensearch-mcp/sift-backend.json`
- `packages/opensearch-mcp/docker/docker-compose.yml`
- `packages/opensearch-mcp/src/opensearch_mcp/server.py`
- `packages/opensearch-mcp/src/opensearch_mcp/client.py`
- `packages/opensearch-mcp/src/opensearch_mcp/paths.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`
- `packages/opensearch-mcp/src/opensearch_mcp/tools.py`
- `packages/opensearch-mcp/src/opensearch_mcp/mappings/*.json`
- Targeted `find`, `tree`, and `rg` scans for repo/package structure, frontend API usage, Starlette routes, MCP registration, JSON state, evidence, audit, tokens, OpenSearch, jobs/workflows, tests, docs, setup files, Redis/RQ/Celery, and Supabase/Postgres presence.

## Open Questions

- What exact Supabase Local deployment shape should this repo target?
- Should active-case state be per human session, per workstation, per Gateway instance, or a combination with explicit precedence?
- What token hashing strategy should be canonical, including algorithm, optional pepper/KMS use, displayed fingerprints, and default expiry?
- What is the safest first cutover order: cases/tokens first, evidence/audit first, or OpenSearch/jobs first?
- How long should generated compatibility files remain supported after Postgres becomes authority?
- Which external scripts or operator workflows still read `~/.sift/active_case`, `~/.sift/ingest-status`, saved report JSON, or flat case JSON directly?
- Must evidence manifest/ledger files remain canonical legal artifacts even after Postgres becomes operational authority?
- What exact worker process model should parser execution target: single Gateway-host worker, multiple local workers, or future distributed workers?

## Next Recommended Run

Create `docs/migration/03_opensearch_core_integration.md`. Recommended scope:
map current OpenSearch standalone/add-on MCP backend behavior to the target
integrated core SIFT MCP and control-plane-aware design. Focus only on current
OpenSearch tools, index/query scoping, ingest status to jobs/parser-runs
mapping, document provenance metadata, OpenSearch index registration, and
Gateway-mediated authorization. Do not implement code, do not create migrations,
and do not design the full database schema.
