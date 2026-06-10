# SIFT MVP Sprint Agent Instructions

This repo is in fast MVP sprint mode.

## Source of truth

Read these two files first and keep them current:

- `docs/migration/task-batches.md` - executable batch tracker for parallel work.
- `docs/migration/Session-Notes.md` - latest change log plus forks, blockers,
  and backlog.


## Component mapping to help speed up discovery (changes with migration steps, batches, reference for help not source of truth)

| Architecture node | Target responsibility | Current code/components | Current state | MVP gap |
| --- | --- | --- | --- | --- |
| Final Installer | Install, configure, harden, health-check, and hand off a forced-reset operator login | `install.sh`; `configs/gateway.yaml.template`; `configs/systemd/sift-gateway.service`; `configs/audit/99-sift-evidence.rules`; `configs/apparmor/sift-gateway.template`; `scripts/setup-agent-runtime.sh` | Substantial installer and hardening path exists | Align with Supabase-first operator bootstrap/reset, evidence mount validation, and final health contract |
| Operator Portal | Human case, evidence, agent key, review, TODO, report, and backend control surface | `packages/case-dashboard/frontend/src/**`; `packages/case-dashboard/src/case_dashboard/routes.py` | Live portal exists | Move authority for evidence, findings, timeline, TODOs, reports, and jobs into DB transitions |
| AI Agent / MCP Client | Autonomous investigator with tool-only access | Gateway `/mcp`; `mcp_server.py`; `mcp_endpoint.py` | Supabase JWT and compatibility token paths exist | Enforce opaque IDs and sanitize path-bearing tool responses |
| SIFT Gateway | Single policy and orchestration boundary | `server.py`; `rest.py`; `mcp_server.py`; `mcp_endpoint.py`; `auth.py`; `supabase_auth.py`; `identity.py`; `active_case.py`; `policy_middleware.py`; `evidence_gate.py`; `response_guard.py`; `rate_limit.py` | FastAPI and FastMCP foundation landed | REST tool endpoints need policy parity or operator-only restriction |
| Supabase Auth | Operator and agent JWT identity | `supabase_auth.py`; `supabase/migrations/202606070300_unified_jwt_principals.sql` | Target direction landed with compatibility fallback | Installer/bootstrap must fully use Supabase flow |
| Postgres Control Plane | Authoritative app state and transition store | `supabase/migrations/202606070101_identity_foundation.sql`; `202606070300_unified_jwt_principals.sql`; `202606070400_active_case_authority.sql`; `202606070500_mcp_backends_registry.sql`; `202606080100_mcp_backends_registry_hardening.sql` | Identity, cases, active case, audit table, token/principal scopes, and backend registry are present | Add evidence/custody, jobs, findings, timeline, TODOs, reports, and RAG tables/RPCs |
| Evidence Register + Seal Broker | Detect, register, name, describe, hash, seal, verify, ignore, and retire evidence | `packages/sift-core/src/sift_core/evidence_chain.py`; portal evidence routes in `routes.py`; `packages/sift-gateway/src/sift_gateway/evidence_gate.py` | Working file-backed manifest/ledger/HMAC flow | DB-backed evidence metadata and custody ledger become authority while file proofs remain exports |
| Local SIFT Worker | Claim jobs and execute parser, enrichment, report, and run-command work | `packages/sift-core/src/sift_core/execute/worker.py`; OpenSearch ingest package | Subprocess isolation exists; durable DB worker does not | Add Postgres job tables and worker claim loop |
| Sandboxed run_command | Controlled forensic CLI execution as final deeper-analysis tool | `agent_tools.py`; `execute/tools/generic.py`; `execute/executor.py`; `execute/security.py`; `execute/security_policy.py` | Useful security-aware implementation exists | Make it job-backed, evidence-ref based, allowlisted, and path-redacted |
| OpenSearch | Derived search, timeline, IOC, and enrichment plane | `packages/opensearch-mcp/src/opensearch_mcp/**`; `packages/opensearch-mcp/docker/**`; `packages/opensearch-mcp/scripts/setup-opensearch.sh` | Parser and ingestion stack is a winner | Register indices/provenance in DB and keep security enabled |
| RAG / Vector DB | Grounded forensic context with case/provenance filtering | `packages/forensic-rag-mcp/src/rag_mcp/**`; `packages/forensic-rag-mcp/knowledge/**` | Standalone/file-vector package exists | Move rag_mcp embeddings to Supabase pgvector |
| OpenCTI Add-on | Query-only CTI enrichment | `packages/opencti-mcp/src/opencti_mcp/**`; `docker-compose.opencti.yml` | Add-on exists | Keep query-only, audited, and non-authoritative |
| Windows Triage Add-on | Query suspicious file, hash, service, process, and registry baselines | `packages/windows-triage-mcp/src/windows_triage_mcp/**`; `packages/windows-triage-mcp/data/**` | Add-on exists | Align with add-on contract and keep query-only |
| Forensic Knowledge Pack | Local discipline guidance and tool/artifact catalog | `packages/forensic-knowledge/src/**`; `packages/forensic-knowledge/data/**` | Local reference data exists | Keep as grounding/reference, not evidence |
| Reports / Exports | Approved-only report generation and export | `packages/sift-core/src/sift_core/reporting.py`; `report_profiles.py`; portal report routes/components | Approved filtering exists but saved reports are file-backed | Add DB report metadata/state and operator-gated inclusion | 

## Sprint operating rules

- Update the batch checkbox only after its acceptance checks pass.
- In a single-session change, add the latest session note at the top of
  `Session-Notes.md`.
- Keep implementation docs minimal.

## Security invariants

- Gateway is the only policy boundary for portal and AI-agent operations.
- Supabase/Postgres is the authoritative control plane.
- Agents use MCP only for the MVP. Portal REST is for human operators.
- The AI agent never receives absolute evidence paths, case paths, mount paths,
  DB credentials, OpenSearch credentials, service-role keys, or shell access.
- Evidence bytes are mounted or copied only by the operator on the SIFT VM.
- Evidence must be registered and sealed before analysis.
- Sensitive human actions require password/HMAC re-auth: case activation,
  evidence seal/ignore/retire, finding approval, report inclusion/export, and
  agent credential issuance.
- OpenSearch, RAG joining the core and not add-on anymore. forensic knowledge data package stays for context injection after tool calls
- OpenCTI, Windows triage are add-on - not MVP
- Reports include approved findings and approved supporting data only.

## Host and VM constraints

- Host repo path: `/home/yk/AI/SIFTHACK/sift-mcps`.
- SIFT VM target Python: `/usr/bin/python3.12`.
- Do not install or download managed Python on the SIFT VM.
- Use `UV_NO_MANAGED_PYTHON=1` and `UV_PYTHON_DOWNLOADS=never` on the VM.
- Do not store raw MCP/service tokens, Supabase secrets, OpenSearch passwords,
  or local VM secrets in repo files.
- SSHpass to VM sansforensics/forensics 192.168.122.81
- Operator GUI PORTAL  https://192.168.122.81:4508/portal/ with examiner@operators.sift.local / forensis
## Work discipline

- Run targeted tests for touched code and return validation evidence in the
  final response, update the docs as per the operating model, following same structure and test validation of changes with the script.

## Live VM Smoke Tests
Code on this Host, rsycn changes to VM, restart gateway -> environment ready
Live VM coordinates, replay steps, and current batch validation state live in
`docs/migration/Session-Notes.md`.
