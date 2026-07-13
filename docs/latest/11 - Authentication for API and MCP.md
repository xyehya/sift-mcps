---
title: Authentication for API and MCP
source_commit: eadb92b
generated: 2026-06-27
verified_against: code+tests+config
invariants_checked: 9
status: draft
---

## 1. Overview

The SIFT Gateway has three authentication surfaces: REST API (Bearer tokens + API keys), MCP (Supabase JWT via SiftTokenVerifier), and Portal (HMAC-signed session cookie). All three share the same Supabase identity resolver. Legacy PR02 token registry and gateway.yaml api-key fallback have been removed (SEC-6). Supabase outage = fail closed (503), never fail open.

## 2. Token Types and Formats

### 2.1 Supabase JWT (Current Sole Authority — SEC-6)

| Property | Value |
|---|---|
| Format | Standard JWT issued by Supabase Auth (GoTrue) |
| Validation | `GET /auth/v1/user` with bearer token |
| Session | `access_token` + `refresh_token` pair |
| Agent TTL | 48h (AUT2-B0, enforced at issuance, `min_agent_token_ttl_seconds=172800`) |
| Slop | 300s clock/issuance tolerance (`_TTL_VALIDATION_SLOP`) |
| Cache | Positive results cached by full SHA-256 digest (`token_digest`), configurable TTL (default 30s) |
| Negative cache | Never cached |
| Max token length | 8192 bytes (`_MAX_TOKEN_LENGTH`, DoS guard) |
| HTTP timeout | 10s connect + 10s read (`httpx.Timeout(10.0, read=10.0)`) |

### 2.2 Legacy PR02 Tokens (Removed from MCP, Available for REST)

Legacy tokens still work for REST API access but are **removed from the MCP surface** (SEC-6).

| Property | Gateway Token | Service Token |
|---|---|---|
| Prefix | `sift_gw_` | `sift_svc_` |
| Entropy | 192 bits (48 hex chars) | 192 bits (48 hex chars) |
| Storage | SHA-256(pepper + token) in `app.mcp_tokens` — raw token never stored | Same |
| Fingerprint | First 16 hex chars of SHA-256 (audit-only) | Same |
| Validation | `hmac.compare_digest` (timing-safe) | Same |
| Max length | 1024 bytes (`_MAX_TOKEN_LENGTH`, DoS protection in `auth.py`) | Same |

### 2.3 Portal Session Cookie (`sift_portal_session`)

| Property | Value |
|---|---|
| Format | HMAC-SHA256 signed JSON envelope (NO external JWT library) |
| Cookie flags | `HttpOnly`, `Secure`, `SameSite=Strict`, `path=/portal` |
| Payload keys | `at` (access_token), `rt` (refresh_token), `exp` (expiry), `sub` (auth_user_id), `fp` (fingerprint), `eiat` (original issued-at) |
| Absolute ceiling | 12 hours (preserved across rotations via `eiat`) |
| Sliding window | 8h default max-age (`generate_jwt`) |
| Secret source | `SIFT_PORTAL_SESSION_SECRET` env var (32-byte hex string) |
| Envelope header | `{"alg":"HS256","typ":"SIFTENV"}` (distinct from the legacy `sift_session`) |

The envelope wraps Supabase access/refresh tokens so the portal can re-validate and refresh on each request without re-prompting.

### 2.4 Approval Password

| Property | Value |
|---|---|
| Storage | `/var/lib/sift/passwords/{examiner}.json` (0o600) |
| Algorithm | PBKDF2-HMAC-SHA256, 600K iterations |
| Salt | 32 bytes (random, per-examiner) |
| Min length | 8 characters |
| Input | `/dev/tty` raw mode (blocks LLM-via-Bash automation) |
| Lockout | 3 attempts, 900s (15 min) lockout window |
| Sub-keys | Domain-separated HMAC keys: `sift-auth-v1` (login auth) vs `sift-signing-v1` (ledger signing) |
| Config env | `SIFT_PASSWORDS_DIR` (default `/var/lib/sift/passwords`), `SIFT_LOCKOUT_FILE` (default `~/.sift/.password_lockout`) |

## 3. Identity Resolution

### 3.1 Identity Dataclass

Full field listing from `identity.py`:

```python
@dataclass(frozen=True)
class Identity:
    principal: str
    principal_type: str         # "user" | "agent" | "service"
    token_id: str | None
    agent_id: str | None
    created_by: str | None
    role: str                   # maps from system_role via _system_role_to_role()
    source_ip: str | None
    auth_surface: str           # "mcp" | "portal" | "rest"
    case_id: str | None         # default_case_id from principal record
    tool_scopes: frozenset[str] # global only (case_id IS NULL) — B-11
    token_fingerprint: str | None
    auth_user_id: str | None    # Supabase auth.users.id
    principal_id: str | None    # app principal PK
    system_role: str | None     # owner | admin | readonly | ai | worker
    case_memberships: tuple[CaseMembership, ...]  # operator only
    email: str | None           # for step-up re-auth (never from request body)
```

### 3.2 Resolution Order (Supabase Path)

1. **Cache check** — full SHA-256 digest key (`token_digest(access_token)`), never the 16-hex fingerprint (B8: collision-safe).
2. **`get_user(access_token)`** — `GET /auth/v1/user` with bearer token against Supabase Auth.
3. **`lookup_by_auth_user_id()`** — Postgres `app.principal_identities` view.
4. **Check status == "active"** — non-active principal → `PrincipalDisabledError` (403).
5. **Map to Identity** — `_system_role_to_role()`: operators → examiner/readonly; agents → agent; services → service.
6. **Load global tool scopes** — only `case_id IS NULL` rows from `app.principal_tool_scopes` (B5/B-11: case-scoped grants inert until B-11).
7. **Cache positive result** — keyed by full digest, TTL from config (default 30s).

Ambiguous principal (one `auth.users.id` maps to >1 app principal) → `AmbiguousPrincipalError` (403 fail closed).

### 3.3 Resolution Order (Legacy Path — no Supabase)

1. **Token registry lookup** — peppered hash match against `app.mcp_tokens`.
2. **API key verification** — `hmac.compare_digest` against `gateway.yaml` `api_keys`.
3. **Anonymous single-user fallback** — when no keys, no registry, and `legacy_anonymous_examiner_enabled` is true.

### 3.4 Role Mapping

| Principal Type | System Role | Identity Role |
|---|---|---|
| operator | (any non-readonly) | `examiner` |
| operator | `readonly` | `readonly` |
| agent | any | `agent` |
| service | any | `service` |

## 4. Authentication Flows

### 4.1 REST API Auth Flow

```
Request → AuthMiddleware.dispatch()
  ├─ Public path check (/health, /mcp, /portal, static assets)
  ├─ Agent token portal guard (403 agents from /portal/api/)
  ├─ Anonymous single-user mode (no keys + no registry)
  ├─ Supabase identity resolver (SOLE authority when configured)
  │   ├─ 200 → stamp request.state.{identity,examiner,role,token_id,source_ip,supabase_enabled}
  │   ├─ 403 → "Forbidden" (unmapped/disabled principal)
  │   ├─ 5xx → 503 "Authentication service unavailable" (fail closed)
  │   └─ other → 401 "Invalid or expired token"
  └─ No authority configured → 401 "Authentication required"
```

### 4.2 MCP Auth Flow (Three Layers)

**Layer 1 — ASGI Guard (`MCPAuthASGIApp`):**

| Check | Enforcement |
|---|---|
| IP rate limit | 60 req/60s per client IP; localhost bypass (`127.0.0.1`, `::1`) |
| Content-Length | Max 10MB (`_MAX_REQUEST_BYTES`); POST requires Content-Length header (411) |
| Origin validation | CSRF guard: browser Origin must be in `allowed_origins` |
| Bearer token extraction | From raw ASGI `Authorization` header |
| Per-examiner rate limit | 120 req/60s (post-auth, `RateLimiter` keyed by identity) |

**Layer 2 — FastMCP TokenVerifier (`SiftTokenVerifier`):**

- Supabase JWT is sole authority (SEC-6) — no PR02/api-key fallback.
- Readonly role → denied MCP access entirely.
- Scopes from DB-backed `tool_scopes` (no `mcp:*` compatibility default).
- Returns `AccessToken` with `sift_identity` in claims for downstream middleware.

**Layer 3 — SIFT Policy Middleware (10-stage chain, `policy_middleware.py`):**

| Position | Middleware | Gate |
|---|---|---|
| 1 | `ControlPlaneRequiredMiddleware` | No DSN → deny all DFIR tools (BU3) |
| 2 | `ToolAuthorizationMiddleware` | `is_tool_allowed()` on list+call (B-10); per-examiner rate limit |
| 3 | `AddonAuthorityMiddleware` | Manifest `required_scopes` + `prohibited_operations` (H1) |
| 4 | `CaseContextMiddleware` | Active case resolution from Postgres |
| 5 | `ProxyActiveCaseMiddleware` | DB case arg injection for proxied tools (B-11) |
| 6 | `EvidenceGateMiddleware` | Block on broken evidence chain |
| 7 | `AuditEnvelopeMiddleware` | Pre/post-dispatch DB audit envelope |
| 8 | `ResponseGuardMiddleware` | Secret redaction + output capping |
| 9 | (Backend dispatch) | |
| 10 | (Post-dispatch audit writeback) | |

### 4.3 Portal Auth Flow

```
Cookie extraction → HMAC envelope verify → Supabase resolve
  → Refresh if expired → Set request.state
  → Role mapping (operator → examiner, others → readonly/denied)
```

| Phase | Detail |
|---|---|
| Login | `email/password` → `password_grant` → principal lookup (status check, operator-only gate) → set cookie |
| Cookie verify | `verify_session_envelope()` — HMAC verify + absolute ceiling (12h via `eiat`) |
| Principal resolve | `SupabaseAuthCallbacks.resolve()` — `get_user()` + `lookup_by_auth_user_id()` |
| Session refresh | `SupabaseAuthCallbacks.refresh()` — `refresh_grant()` + re-resolve; fails closed on non-operator |
| Logout | Clear cookie + `resolver.invalidate(access_token)` |
| Forced reset | A1-BOOTSTRAP: invited operator → Supabase Admin API password update → principal status `invited`→`active` |

## 5. Scope Grammar and Enforcement

### 5.1 Tool Scopes (`is_tool_allowed`)

| Scope Pattern | Meaning |
|---|---|
| `mcp:*` | Wildcard — all tools |
| `tool:<name>` | Exact tool name match |
| `namespace:<pfx>` | Any tool whose name starts with `<pfx>_` |

Enforced by `ToolAuthorizationMiddleware` for both `list_tools` (filter results) and `call_tool` (deny before dispatch) — B-10 guarantees list/call consistency.

### 5.2 Add-on Required Scopes (`is_scope_satisfied`)

| Rule | Behavior |
|---|---|
| `mcp:*` held by caller | Satisfies any required scope |
| Exact match | Required scope string is in caller's `tool_scopes` |
| `tool:<name>` required | Delegates to `is_tool_allowed()` |
| `namespace:<pfx>` required | Delegates to `is_tool_allowed()` |
| Everything else | Denied |

### 5.3 Enforcement Points

- **`ToolAuthorizationMiddleware`**: gates `list_tools` and `call_tool`.
- **`AddonAuthorityMiddleware`**: gates manifest `required_scopes` and `prohibited_operations`.
- **`case_id IS NULL` restriction (B5/B-11)**: only global tool scopes loaded from resolver — case-scoped grants inert until B-11 wires active-case context.

## 6. Rate Limiting

| Limiter | Window | Default Limit | Scope | Location | Bypass |
|---|---|---|---|---|---|
| IP (pre-auth) | 60s | 60 | Per client IP | `MCPAuthASGIApp.__call__` | localhost (`127.0.0.1`, `::1`) |
| Examiner (post-auth) | 60s | 120 | Per identity (`identity.principal`) | `ToolAuthorizationMiddleware.on_call_tool` | None — all identities subject |

Both use in-memory sliding-window `RateLimiter` (thread-safe `deque`). Stale entries purged every 120s or when store exceeds 100K entries.

## 7. Step-Up Re-Authentication

Requires Supabase password re-verify. Email sourced from the **authenticated bearer identity's `Identity.email`** (never the request body). Enforced in two surfaces:

### 7.1 REST `/api/v1` Control Plane (`require_recent_reauth` in `auth.py`)

| Endpoint | File | Line |
|---|---|---|
| `POST /api/v1/backends` | `rest.py` | 1238 |
| `POST /api/v1/setup/join-code` | `rest.py` | 647 |

No-op when Supabase is not the active authority (`request.state.supabase_enabled == False`). Fail closed (503) when the re-verify primitive is not wired.

### 7.2 Portal Routes (`_supabase_reverify` in `routes.py`)

- Register backend (`POST /api/v1/backends`)
- Mint join code (`POST /api/v1/setup/join-code`)
- Evidence seal/resume, ignore, delete, retire, Replace/Reacquire begin,
  exact Restore begin, recovery completion, and verify-hmac
- Commit review delta (`POST /api/commit`)
- Case activation
- Response guard override
- Create principal
- Report generation
- Case metadata edits

Fail closed: Supabase outage → 503. Wrong password → 401. Identity mismatch → 403.

## 8. Error Codes and HTTP Status

| Error | HTTP | Condition | Body (`reason`/`error`) |
|---|---|---|---|
| `InvalidTokenError` | 401 | Missing, malformed, or invalid token | `invalid_token` |
| `TokenExpiredError` | 401 | Expired access token | `token_expired` |
| `PrincipalNotMappedError` | 403 | Valid JWT but no app principal | `principal_not_mapped` |
| `PrincipalDisabledError` | 403 | Principal status != "active" | `principal_disabled` |
| `AmbiguousPrincipalError` | 403 | One auth user → multiple principals | `ambiguous_principal` |
| `PrincipalForbiddenError` | 403 | Wrong surface/action for principal | `forbidden` |
| `PrincipalNotFoundError` | 404 | Revoke target not found | `principal_not_found` |
| `SupabaseUnavailableError` | 503 | Supabase Auth unreachable | `supabase_unavailable` |
| `AdminCapabilityError` | 500 | Service-role key missing | `admin_capability_missing` |
| `AgentTokenTtlError` | 503 | Agent token TTL below minimum | `agent_token_ttl_below_minimum` |
| Missing/Invalid Authorization | 401 | No `Bearer` header (REST) | `Missing or invalid Authorization header` |
| Token oversized | 401 | >8192 bytes MCP / >1024 bytes REST | (via resolver) |
| Rate limit (IP) | 429 | Pre-auth IP threshold | `Rate limit exceeded` |
| Rate limit (examiner) | 429 | Post-auth per-identity threshold | `rate_limit_exceeded` |
| Request body too large | 413 | >10MB MCP | `Request body too large` |
| No Content-Length | 411 | POST without Content-Length (MCP) | `Content-Length header required` |
| Agent denied portal | 403 | Agent token on `/portal/api/` | `Agent tokens cannot access portal` |
| Readonly denied MCP | 403 | Readonly principal on `/mcp` | `Readonly role cannot call MCP tools` |
| Readonly denied portal write | 403 | Readonly on non-GET portal API | `Readonly role cannot modify portal resources` |
| Auth service unavailable | 503 | Supabase 5xx (fail closed) | `Authentication service unavailable` |
| No credential authority | 401 | No key/registry/Supabase configured | `Authentication required` |

## 9. Security Invariants (Authentication)

- **SEC-6**: Supabase JWT is sole credential authority. No legacy fallback. Outage = fail closed (503).
- **AUT2-B0**: Agent sessions below 48h TTL fail loudly at issuance (`AgentTokenTtlError`, 503).
- **Step-up identity binding**: re-auth email from session (`Identity.email`), not request body. Grant's subject must match session's `auth_user_id`.
- **Portal cookie**: 12-hour absolute ceiling (C10.3, `eiat` field). HMAC-SHA256 stdlib envelope, no external JWT library.
- **B-10**: `is_tool_allowed` governs both `list_tools` and `call_tool` — consistent enforcement, no bypass via listing.
- **D31**: Revocation deletes the Supabase auth user (GoTrue 1.26.05 lacks admin session logout). Proactive cache invalidation closes residual access-token window.
- **Approval passwords**: `/dev/tty` raw mode blocks LLM automation. 3-attempt lockout (900s window). 600K PBKDF2 iterations. Domain-separated auth vs. ledger sub-keys.
- **Negative identity results never cached**. Cache keyed on full SHA-256 digest (64-hex, B8: collision-safe), never the 16-hex fingerprint.
- **B5/B-11**: Only global tool scopes (`case_id IS NULL`) loaded from resolver — case-scoped grants inert until B-11 wires active-case context.
- **Ambiguous principal fail-closed (B2)**: One `auth.users.id` linked to >1 app principal → `AmbiguousPrincipalError` (403), never silently pick one.
- **B-14**: Exactly one token lookup on the normal `/mcp` path — resolved in `SiftTokenVerifier`, not duplicated in `MCPAuthASGIApp`.
