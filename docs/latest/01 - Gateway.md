---
title: Gateway — Single Policy Boundary
source_commit: eadb92b
generated: 2026-06-27
verified_against: code+tests+config
invariants_checked: 17
status: draft
---

## Overview

The Gateway (`sift-gateway`) is the single policy boundary for the Protocol SIFT MCP runtime. It authenticates, authorizes, scopes to a case, gates evidence, audits, redacts, and aggregates all tool access. Every REST call, every MCP tool call, every privileged action passes through it. Routes: operators use the portal at `/portal` via REST; AI agents use `/mcp` via MCP. The Gateway delegates in-process tools to `sift-core` and proxies add-on backends (opensearch-mcp, forensic-rag-mcp, opencti-mcp, windows-triage-mcp).

**Key files**: `packages/sift-gateway/src/sift_gateway/server.py:Gateway`, `mcp_server.py:create_gateway_mcp_server`, `mcp_endpoint.py:SiftTokenVerifier`, `policy_middleware.py`, `auth.py:AuthMiddleware`, `response_guard.py`, `evidence_gate.py`.

## How it works

### Architecture diagram

```
┌─────────────────────────────────────────────────────┐
│                     Gateway                          │
│  ┌────────────────────────────────────────────────┐ │
│  │           HTTP Middleware Stack                  │ │
│  │  SecureHeaders → HTTPSGuard → NormalizePath →   │ │
│  │  CORS → AuthMiddleware                          │ │
│  ├────────────────────────────────────────────────┤ │
│  │          9-Stage MCP Policy Chain               │ │
│  │  ControlPlaneRequired → ToolAuthorization →     │ │
│  │  AddonAuthority → CaseContext → AuditEnvelope → │ │
│  │  ProxyActiveCase → EvidenceGate → ResponseGuard→│ │
│  │  IngestStatusAugment → OpenSearchJobDispatch    │ │
│  ├────────────────────────────────────────────────┤ │
│  │  REST routes     │  Backend Aggregator          │ │
│  │  (/api/v1/...)   │  (mcp_backends_registry,     │ │
│  │                   │   http_backend, stdio_backend)│ │
│  ├────────────────────────────────────────────────┤ │
│  │              Token Registry                     │ │
│  └────────────────────────────────────────────────┘ │
│           ▲                    ▲                     │
│           │                    │                     │
│  ┌────────┴────────┐  ┌───────┴──────────────┐      │
│  │ Operator Portal │  │     AI Agents        │      │
│  │ (/portal REST)  │  │   (/mcp MCP)         │      │
│  └─────────────────┘  └──────────────────────┘      │
└─────────────────────────────────────────────────────┘
```

### Sequence: MCP tool-call policy chain

```
Client → MCPAuthASGIApp
  → ControlPlaneRequiredMiddleware               #1  fails-closed: no DSN → deny all
  → ToolAuthorizationMiddleware                  #2  per-principal auth, rate limit
  → AddonAuthorityMiddleware                     #3  manifest required_scopes check
  → CaseContextMiddleware                        #4  resolve DB active case
  → AuditEnvelopeMiddleware                      #5  pre-dispatch reserve + post-dispatch receipt
  → ProxyActiveCaseMiddleware                    #6  (B-11) inject DB-authoritative case args
  → EvidenceGateMiddleware                       #7  DB-authoritative evidence chain check
  → ResponseGuardMiddleware                      #8  redact secrets + paths, output cap
  → OpenSearchIngestStatusAugmentMiddleware      #9  augment ingest_status with durable job rows
  → OpenSearchJobDispatchMiddleware              #10 redirect ingest to durable worker
  → Tool dispatch (core or proxied add-on)
```

## Reference sections

### auth.py

**`class AuthMiddleware`** · Starlette `BaseHTTPMiddleware`. Checks bearer tokens for REST API routes. Public paths bypass auth: `/health`, `/mcp`, `/portal`, static assets.

**Token verification**: `verify_api_key` uses `hmac.compare_digest` for timing-safe comparison. Rejects tokens > 1024 bytes (DoS protection). Returns `None` if revoked (`revoked_at` set) or expired (`expires_at` in the past).

**`_stamp`**: Sets `request.state.identity`, `examiner`, `role`, `token_id`, `source_ip`, `supabase_enabled`.

**`require_control_plane_operator`**: Deny-by-default for `/api/v1` mutations. Agent/service principal types and readonly roles are denied (403).

**`require_recent_reauth` (SEC-1)**: Step-up password re-entry gate for highest-impact control-plane mutations. Email sourced from authenticated bearer identity (never request body).

### supabase_auth.py

**`class SupabaseAuthConfig`** — Reads env vars `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`. Never logs secrets.

**`class SupabaseAuthClient`** — Async HTTP client for local Supabase Auth (GoTrue) API: `GET /auth/v1/user`, `POST /auth/v1/token`, admin CRUD.

**`class SupabaseIdentityResolver`** — Central resolver. Caches positive results keyed by full SHA-256 hex digest. Cache invalidation per `auth_user_id`. Negative results never cached.

**`class SupabaseAuthCallbacks`** — Decoupled callbacks for portal: login, reverify_password, resolve, refresh, logout, list_principals, forced_reset, issue_principal, revoke_principal.

**`class AgentServiceIssuance`** — Create/revoke agent and service principals. Generates high-entropy temp password. Checks `min_agent_token_ttl_seconds` (default 48h) **AUT2-B0**.

**Tool Authorization (B-10)**: `is_tool_allowed(identity, tool_name)` grammar: `mcp:*` → all tools, `tool:<name>` → exact, `namespace:<pfx>` → prefixed. Principals with no active scope may list/call nothing.
`is_scope_satisfied(identity, required_scope)` for add-on manifest `required_scopes`.

**Typed denial errors**: `InvalidTokenError` (401), `TokenExpiredError` (401), `PrincipalNotMappedError` (403), `PrincipalDisabledError` (403), `AmbiguousPrincipalError` (403), `SupabaseUnavailableError` (503).

### identity.py

**`class Identity`** `@dataclass(frozen=True)` with fields: `principal`, `principal_type` (user|agent|service), `token_id`, `agent_id`, `created_by`, `role` (examiner|agent|service|readonly), `source_ip`, `auth_surface` (mcp|portal|rest), `case_id`, `tool_scopes`, `token_fingerprint`, `auth_user_id`, `principal_id`, `system_role`, `case_memberships`, `email`.

**`resolve_identity()`**: No keys/no registry → anonymous (principal="anonymous", role="examiner"). Token registry present → `lookup_token`. API keys fallback (legacy). Maps `role` to `principal_type`.

### policy_middleware.py — The 10-stage MCP tool-call chain

Stages in execution order (outermost to innermost):

1. **ControlPlaneRequiredMiddleware** — Refuses all tool calls when no `control_plane_dsn`. No DSN = no DFIR tools.
2. **ToolAuthorizationMiddleware (B-10)** — Per-principal auth for list+calls. Fails-closed with no identity. Enforces per-examiner rate limit.
3. **AddonAuthorityMiddleware (H1/BATCH-D2)** — Enforces manifest `authority_contract`: `required_scopes`, `prohibited_operations`.
4. **CaseContextMiddleware** — Resolves DB active case from `ActiveCaseService`. Denies case-scoped tools without active case.
5. **AuditEnvelopeMiddleware** — Pre-dispatch: reserves `requested` envelope in `app.audit_events`. Mutating tools fail-closed on write failure. Post-dispatch: writes success/failure receipt. Injects `audit_id` into response.
6. **ProxyActiveCaseMiddleware (B-11)** — Injects DB-authoritative case args. Case-bound args validated against active-case prefix. Safe args overwrite client values. Unknown tools denied.
7. **EvidenceGateMiddleware** — Blocks all tools when evidence chain not OK. Calls `check_evidence_gate_db()`. No active case = pass through.
8. **ResponseGuardMiddleware** — Redacts secrets, strips ANSI, redacts absolute paths, applies output cap (256 KiB default). Spills oversized to `<case>/agent/tool_outputs/`.
9. **OpenSearchIngestStatusAugmentMiddleware** — Augments `opensearch_ingest_status` with durable job rows from `app.job_status_public` via the gateway's own DSN (the opensearch backend stdio subprocess has no DB creds).
10. **OpenSearchJobDispatchMiddleware** — Redirects `opensearch_ingest` and `opensearch_enrich_intel` to durable worker jobs. Non-blocking dispatch returns `job_id` immediately.

### mcp_server.py — Gateway MCP Server Assembly

**`create_gateway_mcp_server(gateway, api_keys, token_registry, base_url, resolver)`**: Creates FastMCP app named `"sift-gateway"` with aggregated instructions. Registers core tools via `GatewayLocalTool` (run_command, case_info, evidence_info, record_finding, etc.). Mounts add-on proxies via `FastMCPProxy`.

**Tool dispatch flow**: `MCPAuthASGIApp` (ASGI guard) → FastMCP server → 11 middlewares (catalog + 10 policy) → actual tool dispatch (core or proxied).

**Backend proxy types**: stdio (subprocess, `keep_alive=True`), http (`StreamableHttpTransport` with egress pinning **SEC-3**).

### mcp_endpoint.py — MCPAuthASGIApp and SiftTokenVerifier

**`class SiftTokenVerifier`** (FastMCP `TokenVerifier` subclass): Supabase JWT is **sole credential authority**. `verify_token()`: resolve via Supabase, fail-closed on outage. Readonly principals denied MCP access. Returns `AccessToken` with `client_id`, `scopes`, `claims["sift_identity"]`.

**`class MCPAuthASGIApp`**: ASGI connection guard for `/mcp`. IP rate limit pre-auth (localhost bypass). Content-Length validation (max 10 MB). Origin validation (CSRF guard).

### evidence_gate.py — EvidenceGate

**`check_evidence_gate_db(case_id, dsn)`**: DB-authority only. Calls `app.evidence_gate_status(case_id)` in Postgres. Returns `{blocked, status, issues, manifest_version}`. Fail-closed: missing case_id/no DSN/DB error → blocked=True.

### response_guard.py — ResponseGuard Redaction

24 embedded regex patterns at 3 severity levels:

- **Critical** (redacted inline): AWS Access Key, AWS Secret Key, GitHub Token (3 variants: `gh[pus]_...`, `github_pat_...`), OpenAI API Key, Anthropic Key, Stripe Key, Discord Token, Private Keys, Connection Strings, API Key Configs, Mnemonic Seeds, Hex Private Keys.
- **High** (redacted inline): Slack Token, Google API Key, Telegram Bot Token, Generic Password, Bearer Token, JWT Token, Session Auth Blob.
- **Medium** (flagged in findings only, never redacted): .env file content lines, skillsSnapshot JSON key.

**Absolute path redaction (BATCH-B1/F-MVP-2/AUT2)**: Paths under active case dir → relative display paths. Paths under sensitive prefixes → `[REDACTED:absolute_path]`. All other absolute paths pass through.

**Trust layer output cap**: Default 256 KiB. Order: secret redaction → path redaction → cap (prevents straddle).

**Override mechanism**: In-memory per-process. `enable_override(case_dir, examiner, ttl=600)` → skip secret redaction but still report findings. Path redaction ALWAYS runs.

### rate_limit.py

**`class RateLimiter`**: Sliding window, thread-safe. Two singleton instances: IP rate limiter (60 req/60s, localhost bypass), Examiner rate limiter (120 req/60s, post-auth per-identity quota).

### mcp_backends_registry.py — McpBackendRegistry

Postgres-backed (D22A). CRUD on `app.mcp_backends`. `assert_actor_may_mutate_control_plane()`: agent/service/readonly → 403. `normalize_connection_config()`: rejects raw secret keys; secrets by env var only. `assert_stdio_command_allowlisted()`: absolute path only, inside venv/allowlisted dirs. `check_manifest_drift()`: compares on-disk `sift-backend.json` SHA-256 vs registered hash.

### token_gen.py

- `generate_gateway_token()` → `"sift_gw_"` + 48 hex chars (192 bits)
- `generate_service_token()` → `"sift_svc_"` + 48 hex chars
- `token_fingerprint(token)` → first 16 hex chars of SHA-256
- `token_digest(token)` → full 64 hex chars of SHA-256
- `token_hash(token, pepper)` → SHA-256(pepper + token) for DB storage

### token_registry.py — PostgresTokenRegistry

Hash-only storage. Raw token never persisted. `lookup_token()`: computes `token_hash`, queries `app.mcp_tokens` + `app.mcp_token_scopes`. Returns `None` if not active/revoked/expired. Requires at least one scope.

**`class RegistryToken`** `@dataclass(frozen=True)`: `id`, `token_fingerprint`, `role`, `principal`, `principal_type`, `agent_id`, `service_identity_id`, `created_by`, `case_id`, `label`, `expires_at`, `scopes`.

### server.py — Gateway class

**`class Gateway`**: Aggregates multiple MCP backends behind single HTTP service.

- `__init__(config)`: Loads backends from `McpBackendRegistry` (`app.mcp_backends`). Core-only mode when no DSN.
- `_build_tool_map()`: Atomic three-dict snapshot (`ToolSurfaceSnapshot`). Name collision → raises `ValueError`.
- `reload_backend_registry()`: **OSX1** — pick up late-seeded backends without restart.
- `call_tool()`: Routes to correct backend or core tool.
- `get_tools_list()`: Returns `list[Tool]` for all aggregated tools.

### health.py, rest.py, jobs.py, etc.

- `health.py`: Health routes (`/health`, `/api/v1/health`)
- `rest.py`: REST API routes for portal (case CRUD, findings, evidence, backends)
- `jobs.py`, `job_tools.py`: Durable job service and gateway-local job tools
- `active_case.py`: Active case service (DB authority)
- `audit_helpers.py`: Audit extraction and formatting
- `wire.py` (join.py): `POST /api/v1/setup/join` for initial operator creation

## Invariants & Guarantees

- **Single policy boundary**: Every privileged action crosses the Gateway. No backdoor routes to add-ons. Enforced by ASGI routing (`server.py`).
- **Supabase is sole credential authority**: SEC-6. No legacy PR02 hash-token or api-key fallback for MCP. Fail-closed on Supabase outage (`supabase_auth.py`).
- **Evidence gate is DB-authoritative**: No file-manifest fallback (BU3). Missing/no DSN → blocked (`evidence_gate.py`).
- **Mutating tools fail-closed on audit failure**: Pre-dispatch `app.audit_events` write must succeed for mutating tools. Read-only tools proceed with warning (`policy_middleware.py:AuditEnvelopeMiddleware`).
- **Agent session TTL >= 48h**: AUT2-B0. Shorter TTL fails issuance loudly (`supabase_auth.py:AgentServiceIssuance`).
- **No raw token storage**: SHA-256 hash with pepper. Fingerprint = 16 hex chars (audit only). Full digest = cache key (`token_gen.py`, `token_registry.py`).
- **Redact-then-cap**: Output redaction order ensures secrets straddling the truncation boundary are caught. Override never re-exposes host paths (`response_guard.py`).
- **Control plane required for DFIR tools**: No DSN → no tool calls (`policy_middleware.py:ControlPlaneRequiredMiddleware`).

## Gotchas & Edge Cases

> [!warning] `_RETIRED_CORE_BACKENDS` in `server.py` — retired backends (forensic-mcp, case-mcp, sift-mcp, report-mcp) are hardcoded in a frozenset but no longer wired. Do not attempt to re-add them without a full migration plan. (`server.py:143`)

> [!important] Add-on backends in `app.mcp_backends` not `gateway.yaml`. D22A — if there is no control-plane DSN, the stale YAML block is made inert, not treated as fallback authority. (`server.py:246-281`)

> [!warning] Manifest drift check (B-MVP-032) is warn-only, never blocks boot or mutates registry. Operator re-registers to clear. (`mcp_backends_registry.py:check_manifest_drift`)

> [!important] Gateway-local tools (like `opensearch_ingest` in DB-active mode) intentionally shadow add-on tools when the gateway owns the policy boundary. (`server.py:Gateway._build_tool_map`)

## Related

- Core Tools doc (in-process tools including run_command)
- Shared Contracts doc (AuditWriter, ErrorCode, ToolError)
- OpenSearch Data Plane doc (opensearch-mcp add-on)
- Control Plane doc (Supabase schema for app.audit_events, app.mcp_backends, app.mcp_tokens, app.active_case_state)

## Key files

- `auth.py` — REST AuthMiddleware, API key verification, step-up re-auth gates
- `supabase_auth.py` — Supabase JWT integration, identity resolver, principal CRUD
- `identity.py` — Identity dataclass, resolve_identity
- `mcp_endpoint.py` — SiftTokenVerifier, MCPAuthASGIApp ASGI guard
- `mcp_server.py` — create_gateway_mcp_server, tool call flow, proxy mounting
- `policy_middleware.py` — 10-stage MCP tool-call policy chain
- `evidence_gate.py` — DB-authoritative evidence chain gate
- `response_guard.py` — Secret redaction, absolute path redaction, output cap
- `rate_limit.py` — IP and examiner rate limiters
- `mcp_backends_registry.py` — Postgres-backed backend registry CRUD
- `token_gen.py` — Token generation (192-bit entropy)
- `token_registry.py` — PostgresTokenRegistry (hash-only storage)
- `server.py` — Gateway class, backend lifecycle, tool map building
- `rest.py` — REST API routes for portal
- `health.py` — Health check endpoints
- `active_case.py` — Active case service

## Reconciliation log

None — existing doc (`docs/architecture/SIFT-GATEWAY-SECURITY-MODEL.md` and `docs/drafts/architecture/sift-architecture.html`) have been independently confirmed against the code. No contradictions found. The architecture doc references commit `156e810`; current HEAD is `eadb92b` — incremental changes expected.
