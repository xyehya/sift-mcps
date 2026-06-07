# 19 - PR03A / Batch A - Unified Supabase JWT Identity

Status: **implemented** (Run 28; unit commits A/B/C on `revamp/pr03a-unified-jwt`; host + VM acceptance green; `/code-review` + `/security-review` passed; B-10/B-14 DONE; F-13 → **D31** revocation model). See `MIGRATION_STATE.md` Run 28 for evidence.
Scope fence: `supabase/migrations/**`, `tests/db/**`,
`packages/sift-gateway/src/sift_gateway/**`, `packages/sift-gateway/tests/**`,
`packages/sift-gateway/pyproject.toml`, `packages/case-dashboard/src/case_dashboard/**`,
`packages/case-dashboard/tests/**`, `packages/case-dashboard/frontend/src/**`,
`packages/case-dashboard/frontend/package.json`, `packages/case-dashboard/frontend/package-lock.json`,
`packages/case-dashboard/pyproject.toml`, `configs/gateway.yaml.template`,
root `pyproject.toml`, `uv.lock`, `docs/migration/**`, `AGENTS.md`, and
`CLAUDE.md`.

No edits to `packages/*-mcp/**`, `packages/sift-core/**`,
`packages/sift-common/**`, OpenSearch config/runtime, evidence vault behavior,
jobs/workers, installer scripts, Docker/Supabase local state, DB dumps, or
unrelated local config.

Decisions referenced: **D1, D2, D3, D4, D8, D11, D12, D17, D24, D26, D29, D30**.
Backlog targeted: **B-10** and **B-14**. Backlog carried: **B-4, B-11, B-12,
B-13, B-15**.

This candidate implements Batch A from `18_target_architecture_acceleration.md`
and Phase ID-3 from `09_identity_auth_cutover.md`: Supabase-issued JWTs become
accepted credentials for REST and FastMCP `/mcp`, and the Gateway resolves those
JWTs into SIFT-owned operator/agent/service principals, memberships, and MCP tool
scope. PR02 hash-token validation remains only as an explicitly enabled
compatibility bridge.

---

## 1. Build Objective

Replace the current split auth target with one Supabase-JWT principal path:

- Human operators authenticate through Supabase Auth and resolve to
  `app.operator_profiles`.
- AI agents and MCP clients authenticate to FastMCP `/mcp` with Supabase-issued
  JWTs and resolve to `app.agents`.
- Services and workers authenticate with Supabase-issued JWTs and resolve to
  `app.service_identities`. Worker job behavior itself remains out of scope.
- REST and MCP use the same SIFT-owned resolver and the same app-principal model.
- Tool authorization is SIFT-owned: list filtering and call rejection use
  DB-backed principal tool-scope rows, not framework-only scopes.
- PR02 `mcp_tokens` and legacy `gateway.yaml api_keys` stay only behind explicit
  compatibility flags until ID-6.

This PR freezes the identity and policy plumbing, not the active-case,
evidence, job, OpenSearch, or RAG migrations.

## 2. Required Reading And Source Grounding

Read these in order before editing:

1. `docs/migration/MIGRATION_STATE.md` - Current Objective and latest Run.
2. This file.
3. `docs/migration/18_target_architecture_acceleration.md` - Batch A target.
4. `docs/migration/09_identity_auth_cutover.md` - foundation track.
5. `docs/migration/14_fastmcp3_supabase_integration.md` - FastMCP/Gateway design KB.
6. `docs/migration/17_gateway_cutover_d27b.md` - landed FastMCP Gateway substrate.
7. `docs/migration/OPERATING_MODEL.md` - D29 loop, Definition of Done, format contract.
8. `docs/migration/00_migration_charter.md` - D1/D2/D3/D4/D11/D12/D24/D29/D30.
9. `docs/migration/REGISTER.md` - B-10/B-14 target, B-4/B-11/B-12/B-13/B-15 carry.
10. `AGENTS.md` - host to VM workflow and Supabase pins.

Ground the implementation in current source, not memory. At minimum read every
file below before editing it or depending on its behavior:

Gateway:

- `packages/sift-gateway/src/sift_gateway/auth.py`
- `packages/sift-gateway/src/sift_gateway/identity.py`
- `packages/sift-gateway/src/sift_gateway/token_registry.py`
- `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
- `packages/sift-gateway/src/sift_gateway/mcp_server.py`
- `packages/sift-gateway/src/sift_gateway/policy_middleware.py`
- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/rest.py`
- `packages/sift-gateway/src/sift_gateway/config.py`
- `packages/sift-gateway/src/sift_gateway/audit.py`
- `packages/sift-gateway/src/sift_gateway/response_guard.py`

Portal/case-dashboard:

- `packages/case-dashboard/src/case_dashboard/auth.py`
- `packages/case-dashboard/src/case_dashboard/session_jwt.py`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/case-dashboard/frontend/src/components/auth/LoginCard.jsx`
- `packages/case-dashboard/frontend/src/components/settings/SettingsTab.jsx`

Schema/config/tests:

- `supabase/migrations/202606070101_identity_foundation.sql`
- `tests/db/test_pr01_identity_schema.py`
- `packages/sift-gateway/tests/test_phase13_auth.py`
- `packages/sift-gateway/tests/test_policy_parity_d27b.py`
- `packages/sift-gateway/tests/test_phase4.py`
- `packages/case-dashboard/tests/test_session_middleware.py`
- `packages/case-dashboard/tests/test_auth_endpoints.py`
- `packages/case-dashboard/tests/test_token_lifecycle.py`
- `configs/gateway.yaml.template`
- `packages/sift-gateway/pyproject.toml`
- `packages/case-dashboard/pyproject.toml`

Build must also re-confirm these runtime APIs against the installed environment:

- `fastmcp==3.4.2` is still the resolved Gateway runtime.
- `from fastmcp.server.auth import AccessToken, TokenVerifier` works.
- `TokenVerifier.verify_token(self, token: str)` may be async and returns
  `AccessToken | None`.
- `AccessToken(..., claims={...})` can carry the resolved SIFT identity.
- FastMCP middleware can read the current access token/claims on `on_call_tool`.
- FastMCP has a server-side list-tools hook usable for SIFT-owned list filtering.

If any of these FastMCP 3.4.2 API facts differ, stop and raise a fork. Do not
replace this plan with the older `BearerAuthProvider` tutorial API or improvise
a framework-only policy path.

Build must also confirm the pinned VM Supabase stack (`v1.26.05`) supports the
Auth endpoints used here. If the local Supabase Auth API differs from this
plan's endpoint assumptions, stop and raise a fork.

## 3. Source Facts That Shape This PR

- `AuthMiddleware` currently validates REST bearer tokens with
  `resolve_identity()` and skips `/mcp`, `/portal`, `/dashboard`, and health
  paths. Empty legacy `api_keys` can still produce an anonymous examiner.
- `Identity` currently models principal/type/role/token metadata and optional
  `case_id`/`tool_scopes`, but it does not carry a Supabase `auth_user_id` or a
  DB app-principal id.
- `token_registry.py` implements the landed PR02 hash-only `mcp_tokens` bridge.
  It remains a bridge, not the target credential authority.
- D27b moved `/mcp` to FastMCP 3.0. `MCPAuthASGIApp` still performs connection
  guards and token resolution, while `SiftTokenVerifier` also resolves identity.
  B-14 tracks this duplicate lookup.
- `PortalSessionMiddleware` accepts the legacy HMAC `sift_session` cookie and a
  portal examiner bearer fallback. Agent principals are currently blocked on the
  portal surface.
- `case-dashboard` is mounted by the Gateway as a sub-app. Do not make
  `case-dashboard` import `sift_gateway`; pass Gateway-owned auth callbacks into
  `create_dashboard_v2_app(...)`.
- PR01 created `operator_profiles.auth_user_id`, `cases`, `case_members`,
  `active_case_state`, `agents`, `service_identities`, `mcp_tokens`,
  `mcp_token_scopes`, and `audit_events`. `agents` and `service_identities` do
  not yet link to `auth.users(id)`.
- RLS is enabled on the PR01 tables, but PR03 must add the first useful
  Supabase-JWT read policies needed by the target portal/API model.

## 4. Target Runtime Shape

### 4.1 Shared Auth Resolver

Add a Gateway-owned resolver, preferably `sift_gateway.supabase_auth`, with these
responsibilities:

1. Extract a bearer JWT from REST, MCP, or a portal session envelope.
2. Validate the token with local Supabase Auth by calling
   `GET {SUPABASE_URL}/auth/v1/user` with:
   - `Authorization: Bearer <jwt>`
   - `apikey: <SUPABASE_ANON_KEY>`
3. Reject invalid, expired, revoked, disabled, or unmapped principals fail-closed.
4. Resolve `auth.users.id` to exactly one app principal:
   - `operator_profiles.auth_user_id`
   - `agents.auth_user_id`
   - `service_identities.auth_user_id`
5. Load principal status, role/type, case memberships, and MCP tool scopes from
   Postgres.
6. Return the existing `Identity` shape extended with `auth_user_id`,
   `principal_id`, `system_role`, `case_memberships`, and `tool_scopes`.
7. Produce a non-secret JWT fingerprint for audit correlation:
   `first 16 hex chars of sha256(access_token)`. Never log or store the raw JWT.

The resolver may cache positive token-to-principal results for at most 30 seconds
by default (`principal_cache_ttl_seconds`). Revocation/status checks must be
bounded by that TTL. Invalid tokens are not cached unless the code already has a
clear negative-cache pattern with short TTL.

Use Supabase Auth API validation in PR03. Do not introduce repo-stored JWT
secrets, dummy public keys, or local JWT-signature shortcuts. A later
signature/JWKS optimization requires a new scoped decision if needed.

### 4.2 REST Auth

Update Gateway REST auth so protected REST routes accept Supabase JWTs first,
then PR02/legacy fallback only when explicitly enabled.

REST principal resolution rules:

- A valid Supabase JWT with no matching app principal returns 403, not anonymous.
- Disabled/revoked app principals return 403.
- Missing token on protected routes returns 401, unless the route is explicitly
  public.
- Empty `api_keys` anonymous examiner mode is retained only when
  `auth.legacy.anonymous_examiner_enabled` is explicitly true.
- Endpoint-specific policy decides whether an agent/service may use a REST
  endpoint. Portal operator routes deny agent/service principals unless this doc
  explicitly names an exception.

### 4.3 FastMCP `/mcp` Auth

Replace the target behavior of `SiftTokenVerifier` with a Supabase-first
`TokenVerifier` that uses the shared resolver. Keep the class name if it avoids
larger churn, but the behavior must be D30-compliant.

MCP path rules:

- The raw ASGI wrapper around `/mcp` keeps only identity-free connection guards:
  IP rate limit, request body size cap, Origin allow-list, path normalization,
  and SSE-safe behavior.
- Token validation moves to the FastMCP `TokenVerifier`.
- Read-only/principal role blocks, per-principal rate limits, tool-scope checks,
  evidence gate, response guard, case context, and audit execute in SIFT-owned
  FastMCP middleware after auth and before tool dispatch.
- No duplicate PR02/Supabase token lookup remains on the normal MCP path
  (B-14 target). If FastMCP cannot expose the verifier claims to middleware in
  3.4.2, stop and raise a fork.
- PR02 `mcp_tokens` fallback is accepted on `/mcp` only when
  `auth.legacy.token_fallback_enabled` is true.
- Legacy `gateway.yaml api_keys` fallback is accepted only when both
  `auth.legacy.token_fallback_enabled` and the current legacy API-key mechanism
  are enabled.

### 4.4 Portal Auth

The portal switches to Supabase-backed sessions while preserving the legacy
portal session only behind an explicit flag.

Implementation shape:

- `case-dashboard` exposes Supabase login/logout/me routes, but delegates actual
  Supabase calls and principal validation to callbacks supplied by the Gateway
  when it mounts `create_dashboard_v2_app(...)`.
- The frontend `LoginCard.jsx` submits email/password to the Gateway/portal auth
  route. It does not add a Supabase JS SDK dependency in PR03.
- The Gateway calls Supabase Auth password grant:
  `POST {SUPABASE_URL}/auth/v1/token?grant_type=password` using the anon key.
- On success, the portal sets a Secure, HttpOnly, SameSite cookie containing a
  signed session envelope with Supabase access token, refresh token, expiry,
  JWT subject, and non-secret fingerprint. Do not log the token values.
- On each portal request, `PortalSessionMiddleware` validates the access token
  through the shared resolver. If expired and a refresh token is present, it may
  refresh through Supabase Auth and rotate the cookie.
- Legacy `sift_session` HMAC cookie and examiner bearer fallback are accepted
  only when `auth.legacy.portal_session_enabled` is true.
- Agent/service principals are denied on normal portal operator APIs even when
  their Supabase JWT is valid. They may use `/mcp` and any explicitly scoped
  agent/service REST endpoint only.

No arbitrary JWT auto-provisions an operator. A Supabase user must already map to
an active `operator_profiles` row. The VM acceptance run seeds the first operator
row using VM-local Supabase/Postgres admin access; installer automation is a
later installer follow-up, not PR03.

### 4.5 Agent And Service JWT Issuance

Replace the operator-facing "agent token" target with "agent JWT/session"
issuance while leaving PR02 token lifecycle available as a legacy bridge when
enabled.

Required behavior:

- Only an authenticated operator with `owner`/`admin` policy may create or revoke
  agent/service principals.
- Gateway/portal creates a Supabase Auth user for the agent/service using the
  Supabase Admin API and the VM-only `SUPABASE_SERVICE_ROLE_KEY`.
- Gateway creates or links the corresponding `app.agents` or
  `app.service_identities` row with `auth_user_id`.
- Gateway generates a high-entropy temporary password in memory, uses it to
  obtain a Supabase session/JWT for the agent/service, then discards the password.
- The access token, refresh token, expiry, principal id/type, and token
  fingerprint are returned to the operator exactly once. No raw token or raw
  password is stored in Postgres, repo files, fixtures, logs, or audit lines.
- Revocation disables the app principal and revokes/deletes the Supabase Auth
  user/session using the Admin API where available. If the pinned Supabase Admin
  API cannot revoke sessions as expected, stop and raise a fork.
- Existing PR02 `mcp_tokens` list/create/revoke UI may remain under a clearly
  legacy compatibility section when `auth.legacy.token_fallback_enabled` is true.

## 5. Schema And RLS Plan

Add one migration:

`supabase/migrations/202606070300_unified_jwt_principals.sql`

This migration must be additive and rollback-safe in a transaction during VM
syntax checks.

### 5.1 Principal Auth Links

Add Supabase Auth links to agent/service principals:

- `app.agents.auth_user_id uuid null references auth.users(id) on delete set null`
- `app.service_identities.auth_user_id uuid null references auth.users(id) on delete set null`
- Partial unique indexes on each non-null `auth_user_id`.
- Comments marking PR02 `mcp_tokens` as a compatibility bridge, not target
  credential authority.

Do not add a jobs/worker table in PR03. Worker principals use
`service_identities.service_type = 'worker'` until the jobs/worker batch creates
worker-specific state.

### 5.2 Operator System Role

Add an app-level system role if the existing schema lacks one:

- `app.operator_profiles.system_role text not null default 'operator'`
- Check constraint: `readonly`, `operator`, `lead`, `owner`, `admin`.

Case membership roles still live in `app.case_members.role`. `system_role` is
for cross-case/bootstrap/admin policy only.

### 5.3 Principal Tool Scopes

Create `app.principal_tool_scopes`:

- `id uuid primary key default gen_random_uuid()`
- `operator_profile_id uuid null references app.operator_profiles(id) on delete cascade`
- `agent_id uuid null references app.agents(id) on delete cascade`
- `service_identity_id uuid null references app.service_identities(id) on delete cascade`
- `case_id uuid null references app.cases(id) on delete cascade`
- `scope text not null`
- `status text not null default 'active'`
- `constraints jsonb not null default '{}'::jsonb`
- `created_at timestamptz not null default now()`
- `updated_at timestamptz not null default now()`
- Check exactly one principal reference is non-null.
- Check `status in ('active', 'disabled', 'revoked')`.
- Index by each principal reference.
- Unique active-scope indexes for `(principal, scope, case_id)` with separate
  null and non-null `case_id` cases, matching the PR01 `mcp_token_scopes` pattern.

Tool-scope grammar for PR03:

- `mcp:*` - may list/call all MCP tools.
- `tool:<exact_tool_name>` - may list/call exactly that normalized tool name.
- `namespace:<prefix>` - may list/call tools whose normalized name begins
  `<prefix>_`.

Do not add `capability:*` in PR03 because capability tags are not yet a stable
control-plane contract. A principal with no active target tool scope may not
list or call ordinary MCP tools. Legacy PR02 tokens may keep their existing
compatibility default only while the legacy fallback flag is enabled.

### 5.4 Principal View

Create `app.principal_identities` as a stable resolver view:

- `principal_type`: `operator`, `agent`, or `service`
- `principal_id`
- `auth_user_id`
- `display_name`
- `email` where available
- `status`
- `system_role` or service/agent type
- `default_case_id` where available

This view is for resolver consistency. It is not a replacement for
table-specific policy checks.

### 5.5 RLS Policies

Add the minimal Supabase JWT read policies required for PR03:

- An operator may select its own `operator_profiles` row by
  `auth.uid() = auth_user_id`.
- An operator may select `cases` where it has an active `case_members` row.
- An operator may select its own active `case_members` rows.
- An operator may select active `principal_tool_scopes` rows for principals it
  owns or for cases where it has `lead`/`owner` membership.
- Agent and service principals do not receive broad direct RLS write access in
  PR03. They use the Gateway.

Privileged writes remain Gateway/service-role mediated per D12. If the build
needs broader browser/direct Supabase writes to complete PR03, stop and raise a
fork.

## 6. Gateway Build Plan

### 6.1 New Shared Supabase Auth Module

Add `sift_gateway.supabase_auth` or equivalent. It should contain:

- `SupabaseAuthConfig`
- `SupabaseAuthError` / typed denial reasons
- `SupabaseAuthClient` for `/auth/v1/user`, password grant, refresh grant, and
  Admin API calls
- `SupabasePrincipalRepository` for Postgres principal/membership/scope lookup
- `SupabaseIdentityResolver` shared by REST, portal callbacks, and FastMCP
  `TokenVerifier`
- `SupabaseJwtVerifier(TokenVerifier)` or an updated `SiftTokenVerifier`

Keep raw JWTs out of `repr`, logs, audit records, exceptions, test snapshots,
and fixtures.

### 6.2 `Identity` Compatibility

Extend `Identity` additively. Existing tests that build `Identity(...)` with the
old arguments must keep working.

Required new fields:

- `auth_user_id: str | None`
- `principal_id: str | None`
- `system_role: str | None`
- `case_memberships: tuple[...]` or an equivalent immutable/read-only structure
- `tool_scopes: tuple[str, ...]` normalized from DB rows
- `token_fingerprint` retained for both legacy tokens and Supabase JWTs

### 6.3 REST Middleware

Update `AuthMiddleware` so:

- Supabase JWT validation runs first when enabled.
- PR02 token-registry fallback runs only when
  `auth.legacy.token_fallback_enabled` is true.
- Legacy `gateway.yaml api_keys` and anonymous examiner behavior are explicit
  flags, not implicit production defaults.
- Denial responses distinguish unauthenticated (401) from authenticated but
  unmapped/disabled/unauthorized (403).

### 6.4 MCP Auth And Policy

Update `mcp_endpoint.py`, `mcp_server.py`, and `policy_middleware.py` so:

- FastMCP `TokenVerifier` uses the shared Supabase resolver and returns
  `AccessToken` claims carrying the SIFT identity.
- The raw ASGI wrapper stops resolving identity on the normal path, closing B-14.
- Readonly/principal denial moves into SIFT policy middleware before
  `call_next`.
- Per-principal rate limiting moves into SIFT policy middleware if it requires a
  principal. IP/body/Origin remain in raw ASGI guards.
- Tool authorization runs before `call_next`.
- Tool list filtering uses the same `tool_allowed(identity, tool_name)` function
  as call enforcement. List and call must be consistent.
- Do not use FastMCP `require_scopes` as the final policy authority. It can carry
  hints/claims, but SIFT-owned middleware decides.

If FastMCP 3.4.2 lacks a usable list-tools middleware/hook, stop and raise a
fork for B-10. Do not ship call-only authorization.

### 6.5 Tool Authorization Function

Add one normalized policy helper, for example:

`is_tool_allowed(identity: Identity, tool_name: str) -> bool`

Required semantics:

- `mcp:*` matches all tools.
- `tool:<name>` matches exactly after gateway/FastMCP normalization.
- `namespace:<prefix>` matches names beginning `<prefix>_`.
- Unknown scope strings do not grant access.
- Inactive/disabled/revoked scope rows do not grant access.
- Denied calls return a normal MCP error result/audit denial without invoking
  the tool.
- Denied tools are absent from `list_tools`.

### 6.6 Audit

Audit every privileged auth/identity operation without secrets:

- Supabase JWT accepted/rejected reason
- principal resolved/unmapped/disabled
- portal login/logout/refresh
- agent/service principal created/revoked
- MCP tool denied by tool-scope policy
- legacy fallback used

Audit records may include `auth_user_id`, app `principal_id`, `principal_type`,
case id, source IP, user agent, denial reason, and token fingerprint. They must
not include access tokens, refresh tokens, raw PR02 tokens, temporary passwords,
Supabase anon key, or service-role key.

## 7. Portal And Frontend Build Plan

### 7.1 Portal Backend

Extend `create_dashboard_v2_app(...)` with Gateway-provided auth callbacks
rather than importing Gateway modules into `case-dashboard`.

Required routes, names may match existing conventions:

- `POST /api/auth/login` - email/password to Supabase via Gateway callback; sets
  the Supabase session cookie.
- `POST /api/auth/logout` - clears cookie and audits logout.
- `GET /api/auth/me` - returns current operator profile, system role, and case
  memberships without token material.
- `POST /api/auth/refresh` - optional explicit refresh endpoint if refresh is
  not automatic in middleware.
- Agent/service principal create/revoke/list endpoints that replace or augment
  the old token lifecycle endpoints.

Legacy auth endpoints stay only when `auth.legacy.portal_session_enabled` is
true.

### 7.2 Frontend

Update the portal login and settings surfaces:

- `LoginCard.jsx` uses email/password, not challenge/response copy.
- It does not display or log JWTs.
- `SettingsTab.jsx` presents agent/service "JWT sessions" or "principals" as
  the target path, with PR02 tokens marked as legacy compatibility only when
  enabled.
- Agent JWT/session issuance returns the token values once and makes clear that
  they cannot be recovered. Do not write them to localStorage.

No frontend Supabase SDK dependency is required for PR03. If the build needs one
anyway, document why in the run log and update lockfiles inside the scope fence.

## 8. Config And Secrets

Update `configs/gateway.yaml.template` with explicit auth config. Suggested
shape:

```yaml
auth:
  supabase:
    enabled: true
    url_env: SUPABASE_URL
    anon_key_env: SUPABASE_ANON_KEY
    service_role_key_env: SUPABASE_SERVICE_ROLE_KEY
    validation: user_api
    principal_cache_ttl_seconds: 30
  legacy:
    token_fallback_enabled: true
    portal_session_enabled: true
    anonymous_examiner_enabled: false
```

No real secrets go in repo files, templates, tests, docs, or fixtures.
`SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` live in the
VM environment only. Tests use fake values and mocked Supabase responses.

If dependency changes are required:

- Prefer adding runtime HTTP client dependency to `packages/sift-gateway` only.
- Add a `case-dashboard` runtime dependency only if the callback boundary cannot
  keep HTTP calls in the Gateway.
- Update `uv.lock` and record the resolved pins in `MIGRATION_STATE.md`.

## 9. Tests Required

Add or update the following suites.

DB schema:

- `tests/db/test_pr03_unified_jwt_schema.py`
  - migration file exists with exact name
  - `agents.auth_user_id` and `service_identities.auth_user_id` exist
  - partial unique indexes exist
  - `operator_profiles.system_role` exists with role constraint
  - `principal_tool_scopes` has exactly-one-principal check
  - active/null-case unique indexes exist
  - `principal_identities` view exists
  - RLS policies for operator self/case reads exist
  - comments mark `mcp_tokens` as compatibility bridge

Gateway auth:

- `packages/sift-gateway/tests/test_pr03_supabase_jwt_auth.py`
  - valid Supabase JWT resolves operator principal on REST
  - valid Supabase JWT resolves agent principal on `/mcp`
  - invalid/expired JWT rejected
  - valid JWT with no app principal is 403
  - disabled agent/operator rejected
  - PR02 token fallback works only when legacy flag enabled
  - legacy `api_keys` fallback works only when enabled
  - raw ASGI `/mcp` path does not perform a duplicate token-registry lookup
  - access/refresh tokens are not logged/audited

Gateway tool authorization:

- `packages/sift-gateway/tests/test_pr03_tool_authorization.py`
  - `mcp:*` lists/calls all tools
  - `tool:<name>` lists/calls only exact tool
  - `namespace:<prefix>` lists/calls only namespace-prefixed tools
  - no target scope denies ordinary tools
  - list filtering and call denial use the same helper
  - denied call does not invoke local or proxied tool
  - denial is audited without secrets

Portal/case-dashboard:

- `packages/case-dashboard/tests/test_pr03_supabase_portal_auth.py`
  - login calls supplied Supabase callback and sets secure HttpOnly cookie
  - `/api/auth/me` returns operator profile and memberships
  - expired access token refreshes or fails closed based on callback result
  - logout clears cookie
  - agent/service principal denied on normal portal operator APIs
  - legacy session accepted only when legacy flag enabled
  - agent JWT/session create returns token once and stores no raw token
  - revoke disables app principal and calls supplied Supabase admin callback

Regression suites to keep green:

- `packages/sift-gateway/tests/test_phase13_auth.py`
- `packages/sift-gateway/tests/test_policy_parity_d27b.py`
- `packages/sift-gateway/tests/test_phase4.py`
- `packages/sift-gateway/tests/test_audit_envelope.py`
- `packages/sift-gateway/tests/test_portal_agent_block.py`
- `packages/case-dashboard/tests/test_session_middleware.py`
- `packages/case-dashboard/tests/test_auth_endpoints.py`
- `packages/case-dashboard/tests/test_token_lifecycle.py`

Run package-compatible chunks if full package test execution is too slow, but
the final Build handoff must state exactly what ran on host and VM.

## 10. VM Acceptance Plan

Use the host-to-VM workflow from `AGENTS.md`.

Sync:

```bash
rsync -avz --exclude '.git' --exclude '.venv' --exclude '__pycache__' --exclude '*.pyc' \
  /home/yk/AI/SIFTHACK/sift-mcps/ sansforensics@192.168.122.81:~/sift-mcps-test/
```

Start/check Supabase:

```bash
sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 \
  'cd ~/supabase-project && docker compose up -d --wait && docker compose ps'
```

Sync dependencies on the VM:

```bash
sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 \
  'cd ~/sift-mcps-test && UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never ~/.local/bin/uv sync --extra core --group dev --python /usr/bin/python3.12'
```

Verify imports:

```bash
sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 \
  'cd ~/sift-mcps-test && .venv/bin/python --version && .venv/bin/python - <<'"'"'PY'"'"'
import yaml
import mcp
import fastmcp
import sift_core
import sift_gateway
print("imports_ok")
PY'
```

Migration syntax check without leaving tables behind:

```bash
sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 \
  'cd ~/supabase-project && (printf "begin;\n"; cat ~/sift-mcps-test/supabase/migrations/202606070300_unified_jwt_principals.sql; printf "\nrollback;\n") | docker compose exec -T db psql -U postgres -d postgres -v ON_ERROR_STOP=1'
```

Live acceptance after applying the migration to the test VM database:

- Create a Supabase human user using VM-local Supabase Auth/Admin API.
- Insert/link an `operator_profiles` row for that `auth.users.id`.
- Seed one active case membership and an explicit `mcp:*` operator/agent tool
  scope row.
- Log into the portal with Supabase email/password.
- Confirm `/api/auth/me` returns the operator and no token material.
- Create an agent principal/JWT through the portal/API.
- Call a protected REST endpoint with the operator JWT.
- Call FastMCP `/mcp` with the agent JWT.
- Confirm invalid/expired JWTs are rejected.
- Confirm a target principal with no tool scope cannot list/call ordinary tools.
- Confirm PR02 legacy token works only when fallback is enabled, then fails when
  fallback is disabled.
- Confirm an agent JWT cannot access normal portal operator APIs.
- Restart the Gateway and verify health:

```bash
sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 \
  'systemctl --user restart sift-gateway && curl -s -k https://localhost:4508/api/v1/health | python3 -m json.tool'
```

Do not copy Supabase `.env` secrets into the repo. Do not paste real JWTs into
docs, tests, commit messages, or logs.

## 11. Acceptance Gates

```text
[ ] Scope fence held; no edits outside the PR03A paths.
[ ] FastMCP 3.4.2 auth/list/middleware APIs reconfirmed against the installed wheel.
[ ] Pinned Supabase v1.26.05 Auth/Admin endpoints reconfirmed on the VM.
[ ] Supabase JWT validation works for REST and FastMCP /mcp through one shared resolver.
[ ] operator, agent, and service principals resolve from auth.users.id to app rows.
[ ] PR02 token fallback is explicit and can be disabled.
[ ] Legacy portal session is explicit and can be disabled.
[ ] No anonymous examiner mode unless explicitly enabled.
[ ] B-10 implemented: DB-backed tool-scope grammar, list filtering, and call denial.
[ ] B-14 implemented: no duplicate MCP token/JWT resolution on the normal path.
[ ] Agent/service JWT issuance returns token material once and stores no raw token/password.
[ ] Audit covers auth decisions, legacy fallback use, principal issuance/revoke, and tool denials with no secrets.
[ ] RLS read policies and schema tests pass.
[ ] Host tests pass for DB, gateway, portal, and changed frontend code.
[ ] VM tests pass using /usr/bin/python3.12, no managed Python downloads.
[ ] Gateway restart health is green on the VM.
[ ] /code-review and /security-review are run; findings fixed or triaged.
[ ] REGISTER.md updates B-10/B-14 to DONE only at Land if gates pass.
[ ] MIGRATION_STATE.md records the Build run, dependency pins, host/VM test evidence, and next phase.
[ ] python3 scripts/validate_migration_docs.py passes.
```

## 12. Explicitly Out Of Scope

- Moving active-case authority from files/env to `app.active_case_state`
  (Batch B / ID-4).
- Propagating control-plane active case into proxied backends (Batch B / B-11).
- Moving evidence gate authority from file manifest/ledger to DB metadata
  (Batch C / ID-5).
- DB-backed audit authority beyond auth/principal events added by this PR.
- Durable jobs, worker claim loops, job APIs, job UI, parser/indexing workflows.
- OpenSearch core move, OpenSearch security roles, or OpenSearch MCP package
  changes.
- `mcp_backends` control-plane registry and `gateway.yaml` backend removal
  (Batch H / F-11).
- RAG/pgvector migration, skills storage, findings/timeline/TODO/report DB
  migrations.
- Installer reproduction work.
- Removing PR02 token registry code entirely. ID-6 handles sunset after clients
  migrate.

If any of these become necessary to make PR03 pass, stop and raise a fork rather
than expanding the PR silently.

## 13. Register And Documentation Outcomes At Land

If PR03 passes Review/Land:

- Mark B-10 DONE with the PR03 Run/commit.
- Mark B-14 DONE with the PR03 Run/commit.
- Keep B-4, B-11, B-12, B-13, and B-15 OPEN unless separately fixed inside an
  approved scope.
- Update `09_identity_auth_cutover.md` Phase ID-3 to implemented.
- Update `18_target_architecture_acceleration.md` Batch A landed-state text.
- Update `MIGRATION_STATE.md` with host/VM evidence and next recommended build:
  PR03B / Batch B active-case DB authority, unless the operator chooses Batch H.
- Update `AGENTS.md` and `CLAUDE.md` if the current-stage handoff changes.

## 14. Ready-To-Copy Build Prompt

```text
ROLE & MODE: You are a Build-stage coding session for SIFT migration PR03A /
Batch A, unified Supabase JWT identity. Implement ONLY what
docs/migration/19_pr03_unified_supabase_jwt_identity.md declares. Do not
redefine scope. If the installed fastmcp 3.4.2 API or the pinned Supabase
v1.26.05 Auth/Admin API differs from this spec, STOP and raise a fork in
REGISTER.md; do not improvise (D29).

REQUIRED READING, IN ORDER:
1. docs/migration/MIGRATION_STATE.md (Current Objective + latest Run)
2. docs/migration/19_pr03_unified_supabase_jwt_identity.md (this implementation candidate)
3. docs/migration/18_target_architecture_acceleration.md (Batch A target)
4. docs/migration/09_identity_auth_cutover.md (foundation track)
5. docs/migration/14_fastmcp3_supabase_integration.md and docs/migration/17_gateway_cutover_d27b.md
6. docs/migration/OPERATING_MODEL.md (D29 loop, DoD, format contract)
7. docs/migration/00_migration_charter.md (D1/D2/D3/D4/D11/D12/D24/D29/D30)
8. docs/migration/REGISTER.md (B-10/B-14 targeted; B-4/B-11/B-12/B-13/B-15 carried)
9. AGENTS.md (host to VM workflow, Python/uv invariants, Supabase pins)

SOURCE GROUNDING BEFORE EDITING:
Read every file listed in doc 19 section 2 under Gateway, Portal/case-dashboard,
and Schema/config/tests. Ground the build in current source. Do not design from
memory.

SCOPE FENCE:
Allowed paths are supabase/migrations/**, tests/db/**,
packages/sift-gateway/src/sift_gateway/**, packages/sift-gateway/tests/**,
packages/sift-gateway/pyproject.toml,
packages/case-dashboard/src/case_dashboard/**,
packages/case-dashboard/tests/**,
packages/case-dashboard/frontend/src/**,
packages/case-dashboard/frontend/package.json,
packages/case-dashboard/frontend/package-lock.json,
packages/case-dashboard/pyproject.toml, configs/gateway.yaml.template,
root pyproject.toml, uv.lock, docs/migration/**, AGENTS.md, and CLAUDE.md.
Do NOT edit packages/*-mcp/**, packages/sift-core/**, packages/sift-common/**,
OpenSearch runtime/config, evidence behavior, jobs/workers, installer scripts,
Docker/Supabase local state, DB dumps, or unrelated config.

DELIVERABLE:
Implement Supabase JWT auth for REST and FastMCP /mcp through one shared
Gateway-owned resolver; map auth.users.id to operator/agent/service principals;
add app principal tool scopes and RLS policies; implement portal Supabase
login/session and agent/service JWT issuance; keep PR02 token fallback only
behind explicit legacy flags; implement B-10 list/call tool authorization and
B-14 duplicate MCP token/JWT lookup cleanup; add the required PR03 tests and VM
acceptance evidence.

HARD CONSTRAINTS:
Supabase Auth proves identity; SIFT Gateway enforces case/tool/evidence/audit
policy (D24/D30). Do not store or log raw JWTs, refresh tokens, temporary
passwords, PR02 tokens, Supabase anon key, or service-role key. No arbitrary JWT
auto-provisions an operator. Agent/service JWTs can use /mcp, but normal portal
operator APIs deny agent/service principals unless doc 19 explicitly scopes an
exception. Active-case DB authority, evidence DB authority, jobs/workers,
OpenSearch core, RAG, mcp_backends registry, and legacy-auth removal are out of
scope.

REQUIRED TESTS:
Add tests/db/test_pr03_unified_jwt_schema.py,
packages/sift-gateway/tests/test_pr03_supabase_jwt_auth.py,
packages/sift-gateway/tests/test_pr03_tool_authorization.py, and
packages/case-dashboard/tests/test_pr03_supabase_portal_auth.py. Keep the listed
regression suites in doc 19 section 9 green. Run host tests, rsync to the VM,
sync dependencies with UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never and
--python /usr/bin/python3.12, syntax-check the migration against the VM
Supabase Postgres in a rollback transaction, run targeted VM tests, restart
sift-gateway, and verify /api/v1/health.

OUTPUT DISCIPLINE:
Record resolved dependency pins and host/VM test evidence in MIGRATION_STATE.md.
Update REGISTER.md only at Land: B-10 and B-14 become DONE only if review gates
pass. Run python3 scripts/validate_migration_docs.py. Run /code-review and
/security-review because this PR touches auth, tokens, secrets handling, MCP,
portal sessions, and Gateway policy. Make one revertable PR/commit.
```
