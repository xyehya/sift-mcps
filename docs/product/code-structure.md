# Code Structure

Status: skeleton. Validation owner: BATCH-PDOC1.
Last updated: 2026-06-09.

## High-Level Package Map

| Path | Role |
| --- | --- |
| `packages/sift-gateway/src/sift_gateway/**` | FastAPI/FastMCP Gateway, auth, policy, MCP bridge, portal service adapters, jobs, RAG bridge. |
| `packages/case-dashboard/src/case_dashboard/**` | Portal backend routes and auth helpers. |
| `packages/case-dashboard/frontend/src/**` | Operator portal frontend. |
| `packages/sift-core/src/sift_core/**` | Case operations, investigation records, evidence chain, reporting, execution tools, worker handlers. |
| `packages/opensearch-mcp/src/opensearch_mcp/**` | Parser ingest, OpenSearch indexing/search, host identity derived metadata. |
| `packages/forensic-rag-mcp/src/rag_mcp/**` | pgvector RAG store, seed/import CLIs, RAG query helpers. |
| `packages/forensic-knowledge/src/**` | Local forensic reference data and guidance package. |
| `packages/opencti-mcp/src/opencti_mcp/**` | Query-only OpenCTI enrichment add-on. |
| `packages/windows-triage-mcp/src/windows_triage_mcp/**` | Query-only Windows triage baseline add-on. |
| `supabase/migrations/**` | Postgres/Supabase schema, RPCs, views, and authority transitions. |
| `configs/**` | Gateway, systemd, auditd, AppArmor, and service templates. |
| `scripts/**` | Validation and setup helpers. |

## Development Routing

| Change type | Start here |
| --- | --- |
| Agent MCP behavior | Gateway MCP files, `sift_core.agent_tools`, `mcp-contracts.md`, BATCH-AUT1. |
| Portal operator flow | Case dashboard routes/frontend plus portal service adapters. |
| Evidence/custody | `sift_core.evidence_chain`, Gateway evidence gate, Supabase custody migrations. |
| Jobs/worker | Gateway jobs/job tools, `sift_core.execute.job_worker*`, durable job migrations. |
| `run_command` | `sift_core.execute.*`, Gateway `job_tools`, runtime ACL setup. |
| RAG | `rag_mcp` package, Gateway RAG bridge, pgvector migrations/importers. |
| OpenSearch | `opensearch_mcp` ingest/search/host modules and derived-state migrations. |
| Reports | `sift_core.reporting`, portal report routes/components, report metadata tables. |

## Required BATCH-PDOC1 Work

- Turn this into a future-developer onboarding map.
- Add call-flow diagrams for portal request, MCP request, job execution, and
  report generation.
- Link critical tests to the modules they protect.
- Note extension points and files that should not be treated as authority.

