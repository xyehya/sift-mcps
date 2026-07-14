---
title: API Contract — REST and MCP Reference
source_commit: eadb92b
generated: 2026-06-27
verified_against: code+tests+config
invariants_checked: 5
status: draft
---

## 1. REST API Overview

The SIFT Gateway exposes two REST surfaces at its root, plus a portal sub-app
at `/portal`. The MCP surface is at `/mcp`.

| Surface | Base URL |
|---------|----------|
| Gateway REST | `http://<host>:4508/api/v1/` |
| Portal REST | `http://<host>:4508/portal/api/` |
| MCP | `http://<host>:4508/mcp` |

## 2. REST API — Gateway

### 2.1 Health & Redirects

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/health` | Gateway health including backends, Supabase, evidence root | Public (no auth) |
| GET | `/api/v1/health` | Same as `/health` | Public (no auth) |
| GET | `/` | Redirect (307) to `/portal/` | Public |
| GET | `/portal` | Redirect (307) to `/portal/` | Public |

The `/health` response shape:

```json
{
  "status": "ok" | "degraded",
  "backends": { "<name>": { "status": "ok", ... } },
  "tools_count": 42,
  "supabase": { "status": "ok" | "disabled" | "error", "url": "..." },
  "evidence_root": { "status": "ok", "path": "...", "readable": true, ... }
}
```

### 2.2 Tool Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/api/v1/tools` | List all aggregated tools. Query: `?backend=name` | Bearer |
| POST | `/api/v1/tools/{tool_name}` | Call a tool by name. Body: `{arguments: {...}}` | Bearer (operator only) |

**GET `/api/v1/tools`** — Response body:

```json
{
  "tools": [
    {
      "name": "tool_name",
      "backend": "backend_name",
      "description": "...",
      "input_schema": { "type": "object", "properties": {} }
    }
  ],
  "count": 42
}
```

**POST `/api/v1/tools/{tool_name}`** — Request body:

```json
{
  "arguments": {
    "key": "value"
  }
}
```

REST tool execution is operator-only (agents must use the MCP surface). Returns
the tool's result content items serialized with the tool's backend name.

### 2.3 Backend Registry (CRUD)

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/api/v1/backends` | List registered backends with health + requires status | Bearer |
| POST | `/api/v1/backends` | Register a new backend. Body: `{name, config, manifest?}` | Bearer + step-up re-auth |
| DELETE | `/api/v1/backends/{name}` | Unregister (restart-to-apply). | Bearer (operator) |
| POST | `/api/v1/backends/{name}/enabled` | Toggle enabled. Body: `{enabled: bool}` | Bearer (operator) |
| POST | `/api/v1/backends/validate` | Validate manifest/config without persisting | Bearer (operator) |
| POST | `/api/v1/backends/reload` | Refresh registry from DB (reports pending state) | Bearer (operator) |

**POST `/api/v1/backends`** registration request:

```json
{
  "name": "my-backend",
  "type": "stdio",
  "command": "/usr/bin/my-mcp-server",
  "args": ["--flag"],
  "env": { "KEY": "val" },
  "manifest_path": "https://...",
  "enabled": true
}
```

**GET `/api/v1/backends`** response includes per-backend:

```json
{
  "backends": [
    {
      "name": "opensearch-mcp",
      "enabled": true,
      "started": true,
      "available": true,
      "on_demand": true,
      "health": { "status": "ok" },
      "requires": ["docker"],
      "unmet_requires": [],
      "pending_apply": false
    }
  ],
  "count": 1,
  "authority": "app.mcp_backends"
}
```

### 2.4 Service Lifecycle

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/api/v1/services` | List all backends with started/health status | Bearer |
| POST | `/api/v1/services/{name}/start` | Start a backend + rebuild tool map | Bearer (operator) + step-up |
| POST | `/api/v1/services/{name}/stop` | Stop a backend + rebuild tool map | Bearer (operator) + step-up |
| POST | `/api/v1/services/{name}/restart` | Restart a backend | Bearer (operator) + step-up |

### 2.5 Setup / Join

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/api/v1/setup/join-code` | Generate a one-time join code. Body: `{expires_hours?, wintools_host?}` | Bearer + step-up re-auth |
| POST | `/api/v1/setup/join` | Exchange join code for gateway credentials | Public (code is auth) |
| GET | `/api/v1/setup/join-status` | Check active join code count | Bearer |

**POST `/api/v1/setup/join`** response carries the gateway URL, backends list,
and a `gateway_token` (for non-wintools joins). Wintools join also returns
`wintools_registered`, `restart_required`, `credential_refs`, and optional
`smb_share`/`smb_user`/`smb_host` for SMB share provisioning.

## 3. REST API — Portal

All portal API routes are mounted under `/portal/api/` on the gateway root
(`http://<host>:4508/portal/api/...`). Auth is via the Supabase session-envelope
cookie (`sift_session_envelope`) or gateway Bearer token (limited set).

### 3.1 Aggregate State

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/portal/state` | `get_portal_state` | Aggregate evidence, custody, add-on, report-eligibility state | Session |

### 3.2 Jobs

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/jobs/{job_id}` | `get_job_status` | Sanitized D2 durable-job status | Session |

### 3.3 Reports

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/reports` | `get_reports` | List reports for active case | Session (examiner) |
| POST | `/api/reports/generate` | `generate_report_route` | Generate a report. Body: `{profile, finding_ids?}` | Session (examiner) + step-up |
| POST | `/api/reports/{id}/save` | `save_report_route` | Save a pending report draft | Session (examiner) |
| GET | `/api/reports/{id}` | `get_report_by_id` | Get report by UUID | Session (examiner) |
| GET | `/api/reports/{id}/download` | `download_report` | Download report as markdown | Session (examiner) |

### 3.4 Findings & Timeline

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/findings` | `get_findings` | List findings with verification status | Session |
| GET | `/api/findings/{id}` | `get_finding_by_id` | Get single finding | Session |
| GET | `/api/timeline` | `get_timeline` | List timeline events with verification status | Session |

### 3.5 Evidence Read

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/evidence` | `get_evidence` | List evidence objects with custody/seal status | Session |
| POST | `/api/evidence/{path:path}/verify` | `verify_evidence` | Verify single evidence object | Session (examiner) |

### 3.6 Agent Activity & Audit

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/agent/activity` | `get_agent_activity` | Recent agent audit events. Query: `?limit=N` | Session |
| GET | `/api/audit/{finding_id}` | `get_audit_for_finding` | Audit trail for a finding | Session |

### 3.7 Review Delta

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/delta` | `get_delta` | Read staged review items | Session |
| POST | `/api/delta` | `post_delta` | Stage review items | Session (examiner) |
| DELETE | `/api/delta/{id}` | `delete_delta_item` | Remove item from staged delta | Session (examiner) |

### 3.8 Case Management

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/case` | `get_case` | Get active case metadata | Session |
| POST | `/api/case/metadata` | `post_case_metadata` | Set case metadata field. Body: `{field, value}` | Session (examiner) + step-up |
| GET | `/api/cases` | `get_cases` | List all DB-visible cases | Session |
| POST | `/api/case/create` | `post_case_create` | Create new case. Body: `{casename, title, description?}` | Session (examiner) |
| GET | `/api/case/activate/challenge` | `get_case_activate_challenge` | Re-auth mode probe | Session (examiner) |
| POST | `/api/case/activate` | `post_case_activate` | Activate case by id | Session (examiner) + step-up |

### 3.9 Todos

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/todos` | `get_todos` | List TODOs for active case | Session |
| POST | `/api/todos` | `post_todo` | Create TODO. Body: `{description, priority?, assignee?}` | Session (examiner) |
| PATCH | `/api/todos/{todo_id}` | `patch_todo` | Update TODO. Body: `{status?, description?, ...}` | Session (examiner) |
| DELETE | `/api/todos/{todo_id}` | `delete_todo` | Delete TODO | Session (examiner) |

### 3.10 IOCs

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/iocs` | `get_iocs` | List IOCs for active case | Session |

### 3.11 Summary

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/summary` | `get_summary` | Aggregated counts: findings/timeline/evidence/todos by status | Session |

### 3.12 Commit

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| POST | `/api/commit` | `post_commit` | Apply delta with Supabase password re-auth | Session (examiner) + step-up |

### 3.13 Evidence Chain

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/evidence/chain/status` | `get_evidence_chain_status` | Evidence chain status + write-block detection | Session |
| POST | `/api/evidence/chain/rescan` | `post_evidence_chain_rescan` | Drop cache and return fresh status | Session (examiner) |
| POST | `/api/evidence/chain/seal` | `post_evidence_chain_seal` | Seal evidence with re-auth | Session (examiner) + step-up |
| POST | `/api/evidence/chain/ignore` | `post_evidence_chain_ignore` | Ignore unregistered file | Session (examiner) + step-up |
| POST | `/api/evidence/chain/delete` | `post_evidence_chain_delete` | Delete non-sealed evidence | Session (examiner) + step-up |
| POST | `/api/evidence/chain/retire` | `post_evidence_chain_retire` | Retire registered evidence | Session (examiner) + step-up |
| POST | `/api/evidence/chain/replace/begin` | `post_evidence_replace_begin` | Persist Replace/Reacquire intent and block gate before protection changes | Session (examiner) + step-up |
| POST | `/api/evidence/chain/restore/begin` | `post_evidence_restore_begin` | Persist exact Restore intent and block gate | Session (examiner) + step-up |
| POST | `/api/evidence/chain/recovery/complete` | `post_evidence_recovery_complete` | Fresh operation-bound re-auth, verify and finalize recovery | Session (examiner) + step-up |
| GET | `/api/evidence/objects/{object_id}/history` | `get_evidence_history` | Case-scoped path-free object history | Session |
| POST | `/api/evidence/chain/verify-hmac` | `post_evidence_chain_verify_hmac` | Passwordless Full Verify Evidence against the active Postgres manifest; returns `full_verify_requires_sealed_evidence` (409) without a receipt when no sealed active set exists (legacy compatibility URL) | Session (examiner) |
| POST | `/api/evidence/chain/anchor` | `post_evidence_chain_anchor` | Anchor manifest on Solana | Session (examiner) |
| POST | `/api/evidence/chain/proof-export` | `post_evidence_chain_proof_export` | Generate DB-derived proof export | Session (examiner) |

### 3.14 Response Guard

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/response-guard/status` | `get_response_guard_status` | Current override status | Session |
| POST | `/api/response-guard/override` | `post_response_guard_override` | Enable override with re-auth. Body: `{ttl_seconds?}` | Session (examiner) + step-up |
| POST | `/api/response-guard/override/cancel` | `post_response_guard_override_cancel` | Cancel active override | Session (examiner) |

### 3.15 Auth

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/auth/setup-required` | `get_auth_setup_required` | Supabase-only: always returns `{required: false}` | Public |
| POST | `/api/auth/login` | `post_auth_login` | Email/password login via Supabase | Public |
| POST | `/api/auth/forced-reset` | `post_supabase_forced_reset` | Complete installer forced reset | Session (envelope cookie) |
| POST | `/api/auth/logout` | `post_auth_logout` | Clear session + revoke upstream | Session |
| POST | `/api/auth/refresh` | `post_supabase_refresh` | Rotate session envelope | Session (refresh token in cookie) |
| GET | `/api/auth/me` | `get_auth_me` | Current operator profile | Session |

### 3.16 Principal Lifecycle

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/auth/principals` | `list_principals` | List agent/service principals | Session (operator) |
| POST | `/api/auth/principals` | `create_principal` | Create agent/service principal + return tokens | Session (owner/admin) + step-up |
| DELETE | `/api/auth/principals/{principal_type}/{principal_id}` | `revoke_principal` | Revoke an agent/service principal | Session (owner/admin) |

### 3.17 Backend Proxy (Portal)

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/api/health` | `get_health_route` | Proxied gateway health (operator panel) | Session |
| GET | `/api/backends` | `get_backends_route` | List backends with health | Session |
| POST | `/api/backends` | `register_backend_route` | Register backend | Session (examiner) + step-up |
| DELETE | `/api/backends/{name}` | `unregister_backend_route` | Unregister backend | Session (examiner) + step-up |
| POST | `/api/backends/{name}/enabled` | `set_backend_enabled_route` | Enable/disable backend | Session (examiner) + step-up |
| POST | `/api/backends/validate` | `validate_backend_route` | Validate manifest | Session (examiner) |
| POST | `/api/backends/reload` | `reload_backends_route` | Reload registry | Session (examiner) + step-up |
| POST | `/api/services/{name}/start` | `start_service_route` | Start service | Session (examiner) + step-up |
| POST | `/api/services/{name}/stop` | `stop_service_route` | Stop service | Session (examiner) + step-up |
| POST | `/api/services/{name}/restart` | `restart_service_route` | Restart service | Session (examiner) + step-up |

### 3.18 Static Assets

| Method | Path | Handler | Description | Auth |
|--------|------|---------|-------------|------|
| GET | `/assets/{filename:path}` | `serve_v2_assets` | Vite hashed chunks (`.js`, `.css`, `.woff2`, etc.) | Public |
| GET | `/{filename}` | `serve_v2_static` | Static files (`.png`, `.svg`, `.ico`, etc.) | Public |
| GET | `/` | `serve_v2_index` | SPA index.html | Public |

## 4. Auth Legend for REST

| Short Name | Mechanism |
|------------|-----------|
| Public | No auth required |
| Bearer | Gateway bearer token in `Authorization: Bearer <token>` header |
| Session | Supabase session-envelope signed cookie (`sift_session_envelope`) |
| Session (examiner) | Session cookie + `request.state.role == "examiner"` |
| Session (operator) | Session cookie + Supabase `principal_type == "operator"` |
| Session (owner/admin) | Session cookie + `system_role in ("owner", "admin")` |
| Step-up re-auth | Supabase password re-verify against GoTrue on top of session |

### REST HTTP Status Code Summary

| Status | Meaning | Common Triggers |
|--------|---------|-----------------|
| 200 | Success | All GET/POST handlers on success |
| 201 | Created | Backend register, principal create, todo create |
| 307 | Redirect | `/` and `/portal` → `/portal/` |
| 400 | Bad Request | Missing field, invalid JSON, validation failure, Origin mismatch |
| 401 | Unauthenticated | Missing/invalid/expired token, no session |
| 403 | Forbidden | Wrong role (not examiner, not operator, agent blocked), re-auth denied |
| 404 | Not Found | Unknown tool, backend, case, finding, todo, evidence path |
| 409 | Conflict | Backend pending restart, case activation conflict, duplicate create |
| 411 | Length Required | MCP POST missing `Content-Length` |
| 413 | Payload Too Large | Body exceeds 10 MB (gateway) or 1 MB (delta/todo) |
| 429 | Rate Limited | Per-IP or per-examiner rate limit exceeded |
| 500 | Internal Error | Unexpected failure (message sanitized) |
| 503 | Service Unavailable | Backend registry unreachable, Supabase down, evidence service absent |
| 504 | Gateway Timeout | Backend start/stop timed out |

## 5. MCP Protocol Contract

### 5.1 Transport

- **Protocol**: JSON-RPC 2.0 over Streamable HTTP + SSE
- **Mount point**: `/mcp`
- **Framework**: FastMCP 3.0 + MCP SDK 1.26+
- **Aggregate**: Single `/mcp` surface aggregates in-process core tools + add-on
  backend proxies (stdio and HTTP). Per-backend `/mcp/{name}` routes are NOT
  mounted (design decision D3).

### 5.2 Auth

- **Primary**: Supabase JWT validated by `SiftTokenVerifier` (FastMCP
  `TokenVerifier` subclass). The Supabase-issued token is resolved to a SIFT app
  principal via `SupabaseIdentityResolver`.
- **Legacy (fallback removed)**: SEC-6 removed the PR02 hash-token registry and
  `gateway.yaml` api-key fallback. Supabase is the sole credential authority.
- **Fail-closed**: A Supabase outage denies access (no legacy fallback).
- **Anonymous mode**: When no credential authority is configured, single-user
  anonymous mode is used (no auth required).
- **Readonly denial**: Principals with `role == "readonly"` are denied MCP
  access.
- **Scope enforcement**: Tool scopes from the DB-backed principal record gate
  which tools a principal may call.

### 5.3 Connection-Level Policy (MCPAuthASGIApp)

Before reaching FastMCP, the ASGI guard enforces:

1. **IP rate limit** — per-client-IP burst cap
2. **Content-Length** — required on POST; max 10 MB
3. **Origin validation** — browser-origin requests must match allowed origins
4. **Token extraction** — Bearer token from `Authorization` header
5. **Identity resolution** — via Supabase resolver or anonymous fallback
6. **Examiner rate limit** — per-principal calls-per-minute cap

### 5.4 Tool Discovery

**`tools/list`** — Returns all aggregated tools filtered by the authenticated
principal's scopes. The `GatewayToolCatalogMiddleware` applies:

- Hidden-from-agent filtering (tools with `hidden_from_agent: true`)
- `evidence_register` is always filtered from agent listings
- Category/phase metadata stamped from `_CORE_TOOL_CATEGORIES` and add-on
  manifests

### 5.5 Tool Call — Request

Standard JSON-RPC 2.0 format over HTTP POST to `/mcp`:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "tool_name",
    "arguments": { "key": "value" }
  },
  "id": "req-1"
}
```

### 5.6 Tool Call — Policy Chain

Every MCP tool call passes through these 10 gates in `gateway_policy_middlewares`:

| Gate | Middleware | What it checks |
|------|------------|----------------|
| ① | AddonAuthorityMiddleware | Add-on manifest `authority_contract` + `required_scopes` |
| ② | ToolAuthzMiddleware | Principal `tool_scopes` against tool requirements |
| ③ | RateLimitMiddleware | Per-examiner calls-per-minute |
| ④ | EvidenceGateMiddleware | Evidence chain seal status (blocks writes when unsealed) |
| ⑤ | ProxyActiveCaseMiddleware | Active-case injection (`case_id`/`case_key`/`case_dir`) + case-bound arg validation |
| ⑥ | ResponseGuardMiddleware | Override active check + output size capping |
| ⑦ | AuditMiddleware | K1 DB-first audit envelope recording |
| ⑧ | DurableJobMiddleware | Job dispatch for `run_command_job` |
| ⑨ | IngestProxyMiddleware | `opensearch_ingest_*` tools via Gateway-local handler |
| ⑩ | ResultRewriteMiddleware | Case context injection on `case_info`/`evidence_info` |

### 5.7 Resources

The aggregate MCP exposes resources from each mounted add-on backend:

| URI Scheme | Backend | Example |
|------------|---------|---------|
| `opensearch://` | opensearch-mcp | `opensearch://cluster/status`, `opensearch://catalog/indices` |
| `cti://` | opencti-mcp | `cti://health`, `cti://catalog/connectors` |
| `wintriage://` | windows-triage-mcp | (per-backend resources) |

Resource access: `resources/read` for registered URIs.

### 5.8 Prompts

The aggregate MCP exposes built-in workflow prompts via `prompts/get`.
Prompt catalog is defined by each add-on backend's manifest.

## 6. Tool Call Response Format

### 6.1 Success

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{ \"key\": \"value\" }"
      }
    ]
  }
}
```

### 6.2 Error

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "error": {
    "code": -32603,
    "message": "Tool execution error",
    "data": {
      "error": "not_found",
      "message": "Entity not found: ...",
      "remediation": "Verify the entity exists and retry.",
      "retryable": false,
      "details": {}
    }
  }
}
```

## 7. Error Response Format

### 7.1 ErrorCode Enum

| Code | Meaning | Retryable |
|------|---------|-----------|
| `invalid_input` | Schema/enum/range violation caught before dispatch | No |
| `not_found` | Entity, index, document, or path absent | No |
| `upstream_unavailable` | OpenSearch, OpenCTI, or Postgres down | Yes |
| `upstream_degraded` | Reachable but partial (yellow cluster, missing optional DB/plugin) | Maybe |
| `rate_limited` | OpenCTI rate limiter tripped | Yes |
| `not_configured` | Backend misconfigured (credentials/paths) | No |
| `no_active_case` | Case-scoped tool with no resolvable active case | No |
| `capacity_refused` | Write refused pre-flight (shard/circuit capacity) | Maybe |
| `internal` | Unexpected error (message is sanitized) | No |

### 7.2 ToolError Model Shape

Both REST and MCP surfaces use this error payload shape (defined in
`sift_common/contracts.py:36`):

```python
class ToolError(BaseModel):
    error: ErrorCode       # Machine-readable category
    message: str           # Human-readable, secret-free explanation
    remediation: str       # Concrete next step the caller can take
    retryable: bool        # True if retrying may succeed
    details: dict          # Optional structured context (e.g. supported types)
```

Serialized:

```json
{
  "error": "not_found",
  "message": "...",
  "remediation": "...",
  "retryable": false,
  "details": {}
}
```

### 7.3 REST Error Responses

REST endpoints return errors as JSON with HTTP status codes:

```json
{
  "error": "Human-readable error message"
}
```

Or for tool call errors:

```json
{
  "error": "Tool call failed",
  "tool": "tool_name",
  "error_type": "ValueError"
}
```

## 8. Auth Error Codes

All auth errors map to standard HTTP status codes:

| Condition | HTTP Status | Error Body |
|-----------|-------------|------------|
| Missing `Authorization` header | 401 | `"Missing or invalid Authorization header"` |
| Invalid/expired bearer token | 401 | `"Invalid or expired token"` |
| Revoked token | 401 | Implicit (treated as invalid) |
| Session token expired | 401 | `"Not authenticated"` |
| Supabase JWT invalid/expired | 401 | `"Invalid or expired token"` |
| Principal not mapped (valid JWT, no app principal) | 403 | `"Forbidden"` |
| Principal disabled | 403 | `"Forbidden"` |
| Ambiguous principal (multiple matches) | 403 | `"Forbidden"` |
| Agent/service blocked from REST tool exec | 403 | `"REST tool execution is operator-only"` |
| Agent token blocked from portal API | 403 | `"Agent tokens cannot access portal"` |
| Readonly role on MCP | 403 | `"Readonly role cannot call MCP tools"` |
| Readonly role on portal write | 403 | `"Readonly role cannot modify portal resources"` |
| Control-plane mutation by non-operator | 403 | `"Operator authority required for control-plane mutation"` |
| Wrong role (not examiner) | 403 | `"Examiner role required"` |
| Wrong principal type (not operator) | 403 | `"Operator role required"` |
| Password re-auth: missing password | 400 | `"Re-auth required: confirm your password."` |
| Password re-auth: wrong password | 401 | `"Incorrect password."` / `"Re-authentication failed."` |
| Password re-auth: identity mismatch | 403 | `"Re-auth denied for this operator."` |
| Password re-auth: control plane unreachable | 503 | `"Control plane unavailable — re-auth could not be verified."` |
| Supabase auth backend outage | 503 | `"Authentication service unavailable"` |
| Join code invalid/expired | 403 | `"Invalid or expired join code"` |
| Join code host mismatch (wintools) | 403 | `"wintools_url host does not match the bound host"` |
| Cross-origin request (MCP) | 403 | `"Forbidden"` |
| No credential authority configured | 401 | `"Authentication required"` |
| No session (portal cookie missing) | 401 | `"Not authenticated"` |
| Agent token TTL below minimum | 503 | `"Agent token TTL below minimum"` |

## 9. Rate Limiting

| Limit | Scope | Default | Enforced At |
|-------|-------|---------|-------------|
| Per-client-IP burst | All `/mcp` POST requests | Configurable (gateway.yaml) | `MCPAuthASGIApp` |
| Per-principal calls/min | All `/mcp` tool calls | 120/min | `ExaminerRateLimiter` |
| Per-client-IP burst | REST `/api/v1/tools/{name}` | Configurable | `rest.call_tool` |
| Join-code failures | Per-IP failed join attempts | 3/min window | `rest.check_join_rate_limit` |
| Per-request body | All POST endpoints | 10 MB (gateway), 1 MB (delta) | Request body read |

## 10. Versioning

- The Gateway REST surface is versioned at `/api/v1/`.
- The Portal REST surface is unversioned under `/portal/api/`.
- The MCP surface at `/mcp` is versioned through the MCP protocol negotiation
  (`MCP-Protocol-Version` header).
- Add-on backends declare their own `spec_version` in `sift-backend.json`
  manifests (must be `1.x`).
