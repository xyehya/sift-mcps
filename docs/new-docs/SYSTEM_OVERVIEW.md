# System Overview (系统概述)

## sift-mcps: SIFT MCP Platform

**Version**: 0.1.0  
**Analysis date**: 2026-06-15  
**Code basis**: All claims verified against actual source files with [VERIFY:] citations.

---

## 1. System Purpose

`sift-mcps` is an AI-augmented Digital Forensics & Incident Response (DFIR) platform built on the Model Context Protocol (MCP). It gives a forensic AI agent (Hermes) a set of curated, security-hardened tools for:

- Executing forensic tools on the SIFT Workstation (autopsy, vol3, hayabusa, TSK, etc.)
- Searching indexed forensic event data in OpenSearch
- Looking up threat intelligence in OpenCTI
- Triaging Windows artifacts (processes, registry, known-bad files)
- Querying a vector-embedded forensic knowledge base (RAG)
- Managing case files, findings, evidence chain integrity, and audit trails

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         AI Agent (Hermes)                        │
│                    Claude Code / Anthropic API                   │
└────────────────────────────┬─────────────────────────────────────┘
                             │ MCP (Streamable HTTP)
                             │ POST /mcp/
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                    sift-gateway (port 4508)                      │
│  ┌──────────────┐  ┌─────────────────────────────────────────┐  │
│  │ REST API     │  │         MCP Surface (/mcp/)             │  │
│  │ /api/v1/...  │  │  FastMCP + Policy Middleware Stack      │  │
│  └──────────────┘  └─────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ Examiner Portal (/portal/)   case-dashboard package     │    │
│  │ FastAPI + React SPA                                      │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  In-Process Core Tools (sift-core: CORE_TOOL_SPECS = 8)  │    │
│  │  case_info · evidence_info · run_command · record_finding │    │
│  │  record_timeline_event · list_existing_findings          │    │
│  │  manage_todo · get_tool_help                             │    │
│  │  + gateway-local tools (registered by sift-gateway, not  │    │
│  │    in CORE_TOOL_SPECS): capability_guide; and, when a    │    │
│  │    job_service is wired, run_command_job &              │    │
│  │    running_commands_status                              │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                   │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐    │
│  │opensearch-  │  │ forensic-rag │  │  opencti-mcp         │    │
│  │mcp (stdio)  │  │ -mcp (stdio) │  │  (stdio/http)        │    │
│  │namespace:   │  │ namespace:   │  │  namespace: cti      │    │
│  │opensearch   │  │ kb           │  │  tools: cti_*        │    │
│  │tools:       │  │ tools: kb_*  │  └──────────────────────┘    │
│  │opensearch_* │  └──────────────┘  ┌──────────────────────┐    │
│  └─────────────┘                     │  windows-triage-mcp  │    │
│                                      │  (stdio)             │    │
│                                      │  namespace: wintriage│    │
│                                      │  tools: wintriage_*  │    │
│                                      └──────────────────────┘    │
└───────────────────────────────────────────┬──────────────────────┘
                                            │
                        ┌───────────────────┼───────────────────┐
                        │                   │                   │
               ┌────────▼──────┐   ┌────────▼──────┐  ┌───────▼────────┐
               │ Supabase      │   │ OpenSearch     │  │ OpenCTI        │
               │ (Postgres 15) │   │ (port 9200)    │  │ (external)     │
               │ port 54322    │   │ Forensic event │  │ Threat intel   │
               │ Auth: 54321   │   │ index          │  │ GraphQL API    │
               │               │   └───────────────┘  └────────────────┘
               │ app.* tables  │
               │ - active_cases│
               │ - audit_events│
               │ - mcp_backends│
               │ - jobs        │
               └───────────────┘
```

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:126-1408]  
[VERIFY: packages/sift-gateway/src/sift_gateway/mcp_server.py:385-423]

---

## 3. Packages and Modules

### 3.1 sift-gateway

**Role**: Central MCP aggregating gateway. The ONLY entry point for the AI agent.

**Key components**:

| Module | Responsibility |
|--------|----------------|
| `server.py` — `Gateway` class | Backend management, tool map, `create_app()` |
| `mcp_server.py` | FastMCP server assembly, proxy mounting |
| `policy_middleware.py` | Full policy middleware stack (7 layers) |
| `auth.py` — `AuthMiddleware` | REST API authentication (Supabase JWT + legacy API keys) |
| `mcp_endpoint.py` — `MCPAuthASGIApp` | MCP ASGI-level auth (SSE-compatible) |
| `active_case.py` — `ActiveCaseService` | DB active-case resolution |
| `evidence_gate.py` | Evidence chain integrity gate |
| `response_guard.py` | Secret/path redaction + output capping |
| `supabase_auth.py` | Supabase JWT verification + identity resolution |
| `token_registry.py` | PR02 token registry (Postgres-backed) |
| `mcp_backends_registry.py` | `McpBackendRegistry` — reads `app.mcp_backends` |
| `backends/` | `StdioMCPBackend`, `HttpMCPBackend` |
| `jobs.py` — `JobService` | Durable job enqueue/poll (app.jobs) |
| `rest.py` | REST API routes |
| `portal_services.py` | Evidence/investigation/report DB services |

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:1-100]

### 3.2 sift-core

**Role**: In-process forensic tools and command execution engine.

| Module | Responsibility |
|--------|----------------|
| `agent_tools.py` | Tool specs, `call_core_tool()`, all core tool logic |
| `execute/executor.py` | Subprocess execution, systemd scope, environment scrubbing |
| `execute/worker.py` | Isolated worker subprocess (runs the actual tool) |
| `execute/security.py` | Path sanitization, command parsing, evidence ref resolution |
| `execute/runtime_acl.py` | `build_sandbox_env()` — scrubs secrets from worker env |
| `execute/catalog.py` | Tool catalog (get_tool_def for forensic tools) |
| `evidence_chain.py` | SHA-256 chain status checking |
| `case_manager.py` | `CaseManager` — findings, TODOs, capabilities |
| `case_ops.py` | Case status data |
| `active_case_context.py` | Context variable for active case (DB-active mode) |
| `investigation_store.py` | `PostgresInvestigationStore` for DB-mode findings |
| `reporting.py` | Report generation |

[VERIFY: packages/sift-core/src/sift_core/agent_tools.py:186-380]

### 3.3 sift-common

**Role**: Shared library used by ALL packages.

| Module | Responsibility |
|--------|----------------|
| `audit.py` — `AuditWriter` | JSONL audit trail writer, thread-safe, fsync |
| `oplog.py` | Operational log (non-audit events) |
| `instructions.py` | Agent instructions/prompts |
| `parsers/` | CSV, JSON, text parsers |

[VERIFY: packages/sift-common/src/sift_common/audit.py:102-418]

### 3.4 opensearch-mcp

**Role**: Forensic event indexing and semantic search. The heaviest add-on.

| Module | Responsibility |
|--------|----------------|
| `server.py` | FastMCP server, tool registration |
| `ingest.py` / `ingest_job.py` | Evidence file ingestion pipeline |
| `tools.py` | Search/query tools |
| `client.py` | OpenSearch HTTP client |
| `parse_*.py` | Format parsers: EVTX, Plaso, CSV, JSON, W3C, Prefetch, etc. |
| `bulk.py` | Bulk indexing |
| `host_discovery.py` | Host name resolution |
| `manifest.py` | Backend manifest |

[VERIFY: packages/opensearch-mcp/src/opensearch_mcp/server.py]

### 3.5 forensic-rag-mcp

**Role**: Vector-embedded forensic knowledge retrieval.

| Module | Responsibility |
|--------|----------------|
| `server.py` | FastMCP server |
| `pgvector_store.py` | PgVector store (Postgres + pgvector extension) |
| `query_embedding.py` | Embedding computation |
| `sources.py` | Knowledge source definitions |
| `ingest.py` | Knowledge ingestion pipeline |
| `refresh.py` | Index refresh |

[VERIFY: packages/forensic-rag-mcp/src/rag_mcp/server.py]

### 3.6 opencti-mcp

**Role**: OpenCTI threat intelligence platform integration.

| Module | Responsibility |
|--------|----------------|
| `server.py` | FastMCP server |
| `client.py` | GraphQL client for OpenCTI API |
| `adaptive.py` | Adaptive rate limiting |
| `cache.py` | Response cache |
| `feature_flags.py` | Feature flag system |
| `validation.py` | Input validation |

[VERIFY: packages/opencti-mcp/src/opencti_mcp/server.py]

### 3.7 windows-triage-mcp

**Role**: Windows forensic artifact analysis with known-good/known-bad databases.

| Module | Responsibility |
|--------|----------------|
| `server.py` | FastMCP server |
| `db/known_good.py` | Known-good file hash database |
| `db/registry.py` | Registry database |
| `importers/lolbas.py` | LOLBAS database import |
| `importers/loldrivers.py` | LOLDrivers import |
| `importers/hijacklibs.py` | HijackLibs import |
| `analysis/` | Filename, hash, path, unicode, verdict analysis |

[VERIFY: packages/windows-triage-mcp/src/windows_triage_mcp/server.py]

### 3.8 case-dashboard

**Role**: Examiner Portal web application for human review and approval.

| Module | Responsibility |
|--------|----------------|
| `routes.py` | FastAPI app + Starlette routes |
| `auth.py` | Portal session auth |
| `session_jwt.py` | JWT session management |
| `frontend/` | React SPA (Vite-built) |

[VERIFY: packages/case-dashboard/src/case_dashboard/routes.py]

### 3.9 forensic-knowledge

**Role**: YAML knowledge base for forensic discipline rules.

| Directory | Content |
|-----------|---------|
| `data/discipline/anti_patterns.yaml` | Anti-patterns to avoid |
| `data/discipline/checkpoints.yaml` | Investigation checkpoints |
| `data/discipline/confidence.yaml` | Confidence level definitions |
| `data/discipline/evidence_standards.yaml` | Evidence quality standards |
| `data/discipline/rules.yaml` | Core forensic rules |

[VERIFY: packages/forensic-knowledge/src/forensic_knowledge/loader.py]

---

## 4. Backend Discovery and Registration

Add-on backends are registered in Supabase table `app.mcp_backends`. Each row contains:
- `name`: unique backend identifier
- `config`: JSON config (type: stdio/http, command, args, env, url)
- `manifest`: JSON manifest (namespace, tools[], capabilities{provides[], requires[]}, authority_contract)
- `enabled`: boolean

**Backend namespaces** (from each package's `sift-backend.json`; every tool name must start with `<namespace>_`):

| Backend | `namespace` | Tool prefix | Example tools |
|---------|-------------|-------------|---------------|
| opensearch-mcp | `opensearch` | `opensearch_` | `opensearch_search`, `opensearch_ingest`, `opensearch_enrich_intel` |
| forensic-rag-mcp | `kb` | `kb_` | `kb_search_knowledge`, `kb_list_knowledge_sources` |
| opencti-mcp | `cti` | `cti_` | `cti_search_threat_intel`, `cti_lookup_ioc` |
| windows-triage-mcp | `wintriage` | `wintriage_` | `wintriage_check_artifact`, `wintriage_check_process_tree` |

> Note: the RAG and OpenCTI namespaces are `kb` and `cti` — **not** `rag_`/`opencti_`. Only opensearch and wintriage have a name resembling the package.

[VERIFY: packages/opensearch-mcp/sift-backend.json]  
[VERIFY: packages/forensic-rag-mcp/sift-backend.json]  
[VERIFY: packages/opencti-mcp/sift-backend.json]  
[VERIFY: packages/windows-triage-mcp/sift-backend.json]

The gateway reads this table at:
1. **Boot**: in `Gateway.__init__()` via `McpBackendRegistry.create_backend_instances()`
2. **30s interval**: in `_late_start_checker()` via `reload_backend_registry()` (OSX1)
3. **Pre-serve**: in lifespan before first request

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:185-215]  
[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:626-685]

---

## 5. Authentication Layers

The gateway has two authentication surfaces:

### 5.1 REST Surface (`/api/v1/...`)
Handled by `AuthMiddleware` (Starlette `BaseHTTPMiddleware`):

```
Incoming REST request
      │
      ├── Public paths (/health, /portal, /) → pass through
      ├── /mcp/* → skip (handled by MCPAuthASGIApp)
      │
      ▼
1. Supabase JWT (when configured):
   - resolver.resolve(token) → Identity or SupabaseAuthError
   - 403 = principal disabled; 401 = bad JWT; 5xx = outage
   
2. Legacy api_keys / token_registry fallback:
   - verify_api_key(token, api_keys) → timing-safe HMAC compare
   - token_registry: Postgres-backed; validates expiry, revocation, scopes
   
3. Anonymous single-user mode: no auth configured
```

[VERIFY: packages/sift-gateway/src/sift_gateway/auth.py:71-239]

### 5.2 MCP Surface (`/mcp/`)
Handled by `MCPAuthASGIApp` + `SiftTokenVerifier` (FastMCP verifier):

- ASGI-level: Origin check, body size guard, IP rate limit
- FastMCP verifier: same credential resolution (Supabase JWT → legacy api_keys)
- Does NOT buffer SSE responses (unlike BaseHTTPMiddleware)

[VERIFY: packages/sift-gateway/src/sift_gateway/mcp_endpoint.py]

---

## 6. Investigation Phases (Tool Categories)

Tools are tagged with an investigation phase (`_CORE_TOOL_PHASES`) for agent orientation. The mapping covers both the 8 `CORE_TOOL_SPECS` and the gateway-local tools (`capability_guide`, `run_command_job`, `running_commands_status`):

| Phase | Tools | Purpose |
|-------|-------|---------|
| `ORIENT` | `case_info`, `evidence_info`, `capability_guide`¹ | Survey case state and capabilities |
| `TRIAGE` | `run_command`, `get_tool_help`, `run_command_job`¹ | Execute forensic commands |
| `FINDINGS` | `record_finding`, `record_timeline_event`, `list_existing_findings`, `manage_todo` | Document findings |
| `INGEST` | `running_commands_status`¹ | Monitor long-running operations |

¹ Gateway-local tool (registered by sift-gateway, not part of `CORE_TOOL_SPECS`). `run_command_job` / `running_commands_status` exist only when a `job_service` is wired (DB-active mode).

[VERIFY: packages/sift-gateway/src/sift_gateway/mcp_server.py:56-68]  
[VERIFY: packages/sift-core/src/sift_core/agent_tools.py:186-380 (CORE_TOOL_SPECS = 8)]

---

## 7. DB-Active vs File-Active Modes

The platform supports two authority modes:

### File-Active Mode (legacy/dev)
- Case state: files under `<case_dir>/` (CASE.yaml, findings.jsonl, etc.)
- Audit trail: JSONL files in `/var/lib/sift/<case_id>/audit/`
- Active case: `~/.sift/active_case` pointer file
- Evidence gate: reads local manifest files

### DB-Active Mode (production)
- Enabled when `SIFT_CONTROL_PLANE_DSN` and `SIFT_DB_ACTIVE=1` are set
- Case state: `app.cases` + `app.active_case_state` Postgres tables (there is **no** `app.active_cases` table)
- Audit trail: `app.audit_events` table (JSONL is export mirror only)
- Active case: resolved per-principal from DB by `ActiveCaseService`
- Evidence gate: `app.evidence_gate_status(case_id)` — a Postgres **function** (not a table) that aggregates the per-case seal status from `app.evidence_chain_heads` / `app.evidence_custody_events`
- Findings: `app.investigation_findings` table

[VERIFY: packages/sift-gateway/src/sift_gateway/evidence_gate.py:137-208]  
[VERIFY: packages/sift-gateway/src/sift_gateway/mcp_server.py:76-135]  
[VERIFY: supabase/migrations/*_evidence_custody.sql (app.evidence_gate_status function)]

---

## 8. Supabase Schema (Key Tables)

| Object | Kind | Purpose |
|--------|------|---------|
| `app.mcp_backends` | table | Add-on backend registry (config + manifest) |
| `app.cases` | table | Case records (case_key, title, status, artifact_path, …) |
| `app.active_case_state` | table | Per-principal active-case assignment (resolved by `ActiveCaseService`) |
| `app.audit_events` | table | Authoritative audit trail (DB-active mode) |
| `app.investigation_findings` | table | Case findings with approval state |
| `app.evidence_chain_heads` / `app.evidence_custody_events` | tables | Per-case evidence custody ledger (hash chain) |
| `app.evidence_gate_status(case_id)` | **function** | Aggregates seal status (`sealed`/`unsealed`/`violated`) → consumed by the evidence gate |
| `app.jobs` | table | Durable async jobs (`ingest`, `enrich`, `report`, `run_command`) |
| `auth.users` | table (Supabase built-in) | Operator/examiner accounts (GoTrue) — referenced via FK, not created by `app` migrations |

> Correction vs. earlier draft: there is no `app.active_cases` table (it is `app.cases` + `app.active_case_state`), and `app.evidence_gate_status` is a function, not a table.

---

## 9. Key Design Decisions

### D27b: FastMCP Proxy Architecture
Add-on backends are mounted as **FastMCP proxy providers** (not started as persistent stdio subprocesses during boot). Each tool call spawns/uses a warm stdio subprocess via `StdioTransport(keep_alive=True)`. This allows lazy startup while keeping the subprocess warm between calls.

[VERIFY: packages/sift-gateway/src/sift_gateway/mcp_server.py:499-604]

### B-MVP-005: OpenSearch Container Hardening
The OpenSearch container runs with `cap_drop: ALL`, `no-new-privileges: true`, and the security plugin disabled (gateway is the sole policy boundary for the single-node lab deployment).

[VERIFY: docker-compose.yml:1-57]

### K5: Secret Isolation
The worker subprocess that runs forensic tools is launched with a **scrubbed environment** (no DB DSNs, API keys, Supabase credentials). Defense in depth: the worker scrubs again before forking the tool binary.

[VERIFY: packages/sift-core/src/sift_core/execute/executor.py:241-250]

### OSX1: Late Backend Discovery
The gateway polls `app.mcp_backends` every 30 seconds and mounts newly-registered backends **without a full restart** (`reload_backend_registry()`).

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:626-685]
