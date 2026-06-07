# Identity, Auth, and Case-Scope Cutover (Foundation Track)

Last updated: 2026-06-07 (Run 31 D32 active-case cutover update).

Scope: planning only. This document defines the **foundation track** of the
migration: identity, authentication, case membership, active-case authority, and
the transitional MCP/service-token registry. It is cutover-order step 1 in
`00_migration_charter.md` ("Cutover Order") and is a prerequisite for the
evidence, jobs, OpenSearch, findings, reports, RAG, and skills work, because
every case-scoped table and every durable job carries identity and case context
that does not exist in the control plane today.

This document does not create SQL migrations, modify application code, or change
runtime behavior. It defines the target model, locks the previously-open
identity decisions, and gives a phased, additive cutover plan. All locked
decisions trace to `00_migration_charter.md` "Confirmed Decisions (Locked)".

**Run 26 target update:** D30 supersedes the earlier target-auth split in D8/D26.
The final target is Supabase-issued JWTs for humans, AI agents, MCP clients,
workers, and services. PR02's hash-only `mcp_tokens` registry remains landed and
useful as a compatibility bridge/provenance surface, but it is no longer the
final credential model.

**Run 31 active-case update:** D32 supersedes the earlier active-case
compatibility-export plan. PR03B goes directly to Postgres active-case authority:
`SIFT_CASE_DIR`, `SIFT_CASES_ROOT`, `gateway.yaml case.dir`, and
`~/.sift/active_case` are not read or generated as active-case authority. No
historical data migration is part of PR03B.

## 1. Why this is first

The execution docs (`05`-`08`) assume that:

- Every job has `case_id`, `requested_by_user_id`, and `requested_by_token_id`
  sourced from "Gateway-validated session/token context".
- Case scope comes from authenticated identity, not from process environment.
- Principals authenticate with Supabase JWTs and resolve to case/tool scope in
  the control plane.

None of those primitives exist yet. Today:

- Tokens are raw-string-keyed in `gateway.yaml` `api_keys`; `verify_api_key()`
  iterates raw tokens with `hmac.compare_digest(token, candidate)`
  (`packages/sift-gateway/src/sift_gateway/auth.py:40-66`).
- `Identity` has no case-scope field; it is principal/role only
  (`packages/sift-gateway/src/sift_gateway/identity.py:5-18`).
- When `api_keys` is empty the Gateway returns an anonymous `examiner` identity
  (single-user mode) (`packages/sift-gateway/src/sift_gateway/identity.py:24-37`).
- Portal humans use a stdlib HMAC-SHA256 `sift_session` JWT cookie, with an
  examiner-role bearer fallback; agent tokens are explicitly rejected on the
  portal surface (`packages/case-dashboard/src/case_dashboard/auth.py:61-131`,
  `packages/case-dashboard/src/case_dashboard/session_jwt.py:41-110`).
- Active case is `SIFT_CASE_DIR` / `gateway.yaml case.dir` / `~/.sift/active_case`
  (`packages/sift-common/src/sift_common/__init__.py:9-32`,
  `packages/sift-gateway/src/sift_gateway/config.py:49-75`).
- There is no case-membership table; the portal is effectively single-examiner.

Building case-scoped job APIs on this is unsafe. Foundation first.

## 2. Target identity model

One credential family, one enforcement point.

| Principal class | Who | Credential | Validated by | Notes |
| --- | --- | --- | --- | --- |
| Human operator | Examiners/analysts using the portal | Supabase Auth JWT | Gateway verifies JWT; RLS scopes reads | Mapped to `operator_profiles`; case access via `case_members`. |
| AI agent / MCP client | Codex/Claude/local MCP clients | Supabase-issued JWT for an agent principal | FastMCP `TokenVerifier` + Gateway policy | Operator/portal may issue an agent JWT; case/tool scope resolves from DB rows, not arbitrary claims. |
| Worker / service | SIFT VM worker runtime, Gateway-internal services | Supabase-issued JWT for a service/worker principal | Gateway/worker service resolver | Inherits `case_id` from claimed job; never invents case scope. |

The Gateway remains the single policy boundary (charter D2). The browser never
talks to Supabase or a backend directly for privileged mutation; it calls
Gateway endpoints (charter D12). RLS is a defense-in-depth boundary behind the
Gateway, not the primary write path.

## 3. Active-case authority (locked: D32; D4 superseded)

The current single-active-case behavior is preserved, but its **authority moves
from files/env into the control plane**:

- The operator selects the active case in the portal. The portal is the only
  place the active case is set.
- The selection is written authoritatively to the control plane (active-case
  state, see `08_control_plane_schema.md`). One active case per SIFT VM
  deployment, matching today's single `~/.sift/active_case` behavior.
- The Gateway reads the control-plane active case and **propagates** it to every
  backend, REST handler, and MCP tool call as request context.
- Legacy `SIFT_CASE_DIR`, `SIFT_CASES_ROOT`, `gateway.yaml case.dir`, and
  `~/.sift/active_case` are not active-case authority and are not generated as
  active-case compatibility exports by PR03B. Stale values must be ignored.
- Existing case directories and forensic artifacts may remain on disk and may be
  referenced by DB case rows as artifact paths. They do not decide the active
  case, and PR03B does not bulk-import historical file-backed state.
- Durable jobs record the active `case_id` immutably on the job row at creation
  time. A long-running job is unaffected if the operator later switches the
  active case.
- For agent/MCP JWTs, the operative case is the control-plane active case, and
  the Gateway additionally verifies the resolved principal is authorized for that
  case before dispatch. Normal agent principals cannot pass an arbitrary `case_id`.

### Coupling: the evidence gate must move with active case

The Gateway aggregate MCP evidence gate currently resolves case from
`SIFT_CASE_DIR` and the file manifest before blocking/allowing tool calls
(`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:637-675`). When active
case becomes control-plane authoritative, the evidence gate's case resolution
must switch in lockstep, or the gate could check a different case than the call
runs against. This is an explicit, in-scope step of this track (phase ID-5), not
a later cleanup.

## 4. Supabase JWT principal model + transitional token bridge (D30)

The final credential is a Supabase-issued JWT. The Gateway validates the JWT,
then resolves the JWT subject into application principal/membership/scope rows.
For FastMCP 3.4.2 this is implemented through a SIFT-owned `TokenVerifier`
subclass, not the older `BearerAuthProvider` tutorial API.

Required target behavior:

| Aspect | Target value |
| --- | --- |
| Credential material | Supabase Auth access token / JWT for human, agent, worker, or service principal. |
| Validation | Verify issuer, audience, signature, expiry, and subject against local Supabase Auth metadata/JWKS or the local Supabase Auth API. |
| Principal mapping | JWT `sub` resolves to `operator_profiles`, `agents`, `service_identities`, `workers`, or a unified principal view/table. |
| Scope | Case membership and tool/action scope come from DB rows resolved by the Gateway, not from untrusted client-supplied arguments. |
| Revocation/expiry | Supabase session/token validity plus app-level disabled/revoked principal flags fail closed. |
| Audit correlation | Audit rows carry JWT subject, app principal id/type, active case, tool/action, source IP, and optional compatibility fingerprint. |
| Legacy bridge | PR02 `mcp_tokens` and legacy `gateway.yaml api_keys` remain only during cutover. |

### Historical PR02 hash-token bridge

PR02 implemented hash-only registry records. That remains correct for the
transition window and for legacy clients that cannot yet use Supabase JWTs:

| Aspect | Locked initial value |
| --- | --- |
| Token material | High-entropy random secret generated server-side, displayed to the creator exactly once. |
| Stored secret | `token_hash = sha256(server_pepper || token)`; the raw token is never stored. The `server_pepper` is a Gateway secret (env/secret file), rotated only via an explicit re-issue flow. |
| Non-secret fingerprint | `token_fingerprint = first 16 hex chars of sha256(token)`, matching the existing `identity._hash_token()` convention (`packages/sift-gateway/src/sift_gateway/identity.py:15-17`). Safe to display/log for correlation. |
| Lookup | Gateway computes the hash and looks up `mcp_tokens.token_hash` (unique index). No raw-token iteration. |
| Default expiry | Agent tokens 90 days; service/worker tokens 30 days; both overridable per token. Expiry enforced on every validation. |
| Revocation | `revoked_at` set; revoked tokens fail closed immediately. |
| Scope | Required `case_id` (or explicit multi-case admin scope) plus tool/action scopes in `mcp_token_scopes`. A token with no scope can do nothing. |
| Last use | `last_used_at` and `last_used_audit_event_id` updated on validation. |

This superseded the earlier open questions on hash algorithm, pepper/KMS use,
fingerprint format, and default expiry for the PR02 bridge. KMS-backed hashing
remains deferred. Under D30, this registry is not the final credential authority.

### Legacy token fallback during cutover

During the cutover window the Gateway may dual-validate: Supabase JWT first,
then PR02 hash-token registry, then the legacy `gateway.yaml api_keys` map only
while explicitly enabled. The legacy path is removed once target JWT principals
are verified and no active clients depend on raw or PR02 tokens.

## 5. Case membership and roles (locked role set)

Locked initial role set and permissions (resolves the prior "exact role names"
open question). Roles live in `case_members.role`; system-wide `admin` may also
exist on `operator_profiles`/membership per deployment policy.

| Role | Case reads | Create/edit drafts | Run jobs (ingest/parse/index) | Approve findings / seal evidence | Retry/cancel jobs | Export / archive / destructive | Manage members / tokens |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `readonly` | Yes | No | No | No | No | No | No |
| `operator` | Yes | Yes | Yes | No | Own/ordinary jobs | No | No |
| `lead` | Yes | Yes | Yes | Yes | Yes (incl. high-risk) | Yes | Add/remove operators |
| `owner` | Yes | Yes | Yes | Yes | Yes | Yes | Full, incl. leads |
| `admin` | Cross-case (policy) | Per policy | Maintenance/cross-case | Per policy | Yes | Yes | System + token registry |

Approval-gated and destructive actions (charter rules) require `lead`/`owner`
(or `admin`). Agents never approve their own findings regardless of token scope.

## 6. Human auth integration

- Supabase Auth becomes the identity provider for humans, agents/MCP clients,
  workers, and services. `operator_profiles.auth_user_id` links humans to
  `auth.users(id)`; agent/service/worker principal rows also need a Supabase
  Auth subject mapping.
- The Gateway/portal verifies the Supabase session and resolves the operator or
  agent/service profile and case memberships, replacing the bespoke examiner and
  PR02 token model over time.
- Legacy portal auth (HMAC `sift_session` JWT + examiner bearer fallback) keeps
  working behind a config flag during cutover so operators are never locked out
  (`packages/case-dashboard/src/case_dashboard/auth.py:61-131`). It is sunset
  after Supabase Auth is verified end-to-end. Agent JWTs may authenticate to MCP;
  portal access for agent principals remains policy-denied unless explicitly
  allowed for an admin/debug workflow.
- Single-user/anonymous-examiner mode (empty `api_keys`) is retained only as a
  local-dev convenience and must be off in the target deployment.

## 7. Gateway enforcement changes

The Gateway gains, additively:

- Shared Supabase JWT verification for REST/portal requests and MCP `/mcp`.
- DB-backed app-principal resolution from the JWT subject, including
  operator/agent/service/worker type, disabled/revoked flags, memberships, and
  tool/action scopes.
- Transitional DB-backed MCP/service token validation (hash lookup) with legacy
  fallback only while explicitly enabled.
- `Identity` extended with case scope and tool scopes resolved from
  membership/principal records (today `Identity` carries no case scope,
  `packages/sift-gateway/src/sift_gateway/identity.py:5-18`).
- Active-case resolution from the control plane plus propagation to backends and
  tool calls, replacing env/pointer reads as authority.
- Evidence-gate case resolution switched to control-plane active case (§3).
- Per-backend `/mcp/{name}` routes disabled so all MCP calls use the single
  policy/evidence/audit path (charter D3).
- Audit events written for token validation, denials, membership changes, and
  active-case changes.

## 8. Phased cutover plan (additive first)

Each phase is one or more small PRs. Phases are additive and reversible until
the legacy path is explicitly removed.

### Phase ID-0 - Baseline auth/identity tests
- Capture current behavior before change: `verify_api_key()` expiry/revocation,
  `resolve_identity()` role mapping, portal JWT/examiner-bearer acceptance, agent
  rejection on portal, and active-case resolution precedence.
- No runtime change. Pure regression protection.

### Phase ID-1 - Control-plane identity schema
- Apply the foundational tables from `08_control_plane_schema.md`:
  `operator_profiles`, `cases`, `case_members`, `agents`, `service_identities`,
  `mcp_tokens`, `mcp_token_scopes`, `audit_events`, and active-case state.
- Schema only; no runtime wiring. RLS policies for human reads.

### Phase ID-2 - Token hash registry (dual-validate, landed bridge)
- Implemented hash-only token validation (§4 historical bridge) in the Gateway
  with legacy `gateway.yaml` fallback. Portal token lifecycle writes DB records
  and returns the raw token once.
- Under D30 this phase is retained as compatibility/provenance, not the final
  auth target.

### Phase ID-3 / PR03A - Unified Supabase JWT auth + memberships  (IMPLEMENTED — Run 28)
- Build from `19_pr03_unified_supabase_jwt_identity.md`.
- Add Supabase JWT verification and operator/agent/service principal resolution
  behind explicit legacy-auth flags. Seed/bootstrap the first mapped operator
  through VM/admin setup; do not auto-provision arbitrary JWTs as operators.
- Accept Supabase JWTs on REST and FastMCP `/mcp` via shared Gateway auth logic
  and a FastMCP 3.4.2 `TokenVerifier`.
- Add portal Supabase login/session, agent/service JWT issuance, DB-backed tool
  scopes, B-10 list/call authorization, and B-14 shared resolver cleanup.
- Keep PR02 token-registry fallback only as an explicit bridge until ID-6.

### Phase ID-4 - Control-plane active case + propagation
- Write active case to the control plane on portal activation; Gateway reads it
  and propagates request context; ignore/remove active-case env/config/pointer
  authority. Per D32, do not generate `SIFT_CASE_DIR`, `gateway.yaml case.dir`,
  or `~/.sift/active_case` as active-case exports.

### Phase ID-5 - Move evidence gate + case scope onto control-plane context
- Switch the aggregate MCP evidence gate and case-scope checks to the
  control-plane active case and token/session case scope (§3 coupling).
- Per-backend `/mcp/{name}` routes were already removed by D27b; ID-5 does not
  re-open that surface.

### Phase ID-6 - Sunset legacy auth/token paths
- After verification, remove the legacy examiner bearer fallback and legacy
  `gateway.yaml api_keys` validation; remove or disable PR02 token auth as a
  credential authority unless explicitly retained as non-secret issuance/audit
  metadata; ensure config holds no raw service tokens.
- Keep single-user/anonymous mode only as an explicit local-dev flag.

## 9. Compatibility and migration mapping

| Current source | Current role | Future authority | Bridge | Removal condition |
| --- | --- | --- | --- | --- |
| `gateway.yaml api_keys` (raw-keyed) | Token registry | Supabase Auth JWT principals; PR02 `mcp_tokens` only as bridge/provenance | Dual-validate only while explicitly enabled | No active legacy tokens; no raw service tokens in config |
| PR02 `mcp_tokens` hash registry | Transitional MCP/service token registry | Supabase JWT principal model (D30) | Keep fallback during cutover | REST and MCP JWT path verified; clients migrated |
| Portal HMAC `sift_session` JWT + examiner bearer | Human auth | Supabase Auth + `operator_profiles` + `case_members` | Keep behind config flag during cutover | Supabase Auth verified end-to-end |
| `SIFT_CASE_DIR` / `SIFT_CASES_ROOT` / `gateway.yaml case.dir` / `~/.sift/active_case` | Active case | Control-plane active-case state | None for active-case authority in PR03B; stale values are ignored/removed | PR03B lands and tests prove DB active case wins |
| Empty `api_keys` anonymous examiner | Single-user mode | Explicit local-dev flag only | Retain for dev | Off in target deployment |

## 10. Tests and acceptance

- JWT auth: valid Supabase JWT accepted on REST and MCP; invalid/expired/wrong
  audience tokens rejected; JWT subject resolves to an app principal.
- Token bridge: hash lookup matches while enabled; raw token never stored;
  expiry/revocation fail closed; fingerprint is non-secret; legacy fallback
  validates then is removable.
- Identity: case scope and tool scopes resolved from membership/principal rows;
  normal agent principal cannot pass arbitrary `case_id`; cross-case denial.
- Active case: portal sets it; Gateway propagates it; jobs snapshot it; stale
  env/config/pointer values are ignored and not regenerated; evidence gate checks
  the same DB active case the call runs against.
- Membership/roles: role matrix (§5) enforced; approval/destructive actions require
  `lead`/`owner`/`admin`; agents cannot approve their own findings.
- Auth: Supabase JWT accepted; legacy flag path works during cutover and is
  removable; agent principals are accepted on MCP but rejected from portal
  operator workflows unless explicitly authorized.
- Audit: token validation, denials, membership changes, and active-case changes
  are audited.

## 11. Decisions

### Locked (resolved here and in the charter)
- Unified Supabase JWT principal model for human, agent, MCP client, worker, and
  service principals (D30); Gateway-only enforcement (D2, D12).
- Active case portal-set, control-plane authoritative, Gateway-propagated; env/
  config/pointers are not authority and are not generated as active-case exports
  in PR03B (D32; historical D4 superseded).
- Hash-only token bridge policy: SHA-256 + server pepper, 16-hex fingerprint,
  default expiries, one-time raw display, dual-validate then sunset legacy
  (historical D8/PR02, superseded in target by D30).
- Role set: `readonly`, `operator`, `lead`, `owner`, `admin`, with the §5
  permission matrix.
- Legacy examiner bearer + HMAC JWT retained behind a config flag during cutover,
  then removed; single-user mode is local-dev only.
- Cutover order: this track precedes evidence/jobs/findings (D17).

### Deferred (explicitly, not vague)
- KMS-backed token hashing (pepper-in-secret is the v1 target).
- Per-operator (vs per-deployment) active case — single active case per VM in v1.
- SSO/external IdP federation beyond Supabase Auth.

## 12. Next recommended run
Current status: JOB-0, Phase ID-1 (PR01), Phase ID-2 (PR02), D27a, D27b, and
**Phase ID-3 / PR03A (implemented, Run 28)** — unified Supabase JWT auth for REST
and MCP, operator/agent/service principal resolution, portal Supabase
login/session, agent/service JWT issuance, DB-backed tool authorization B-10,
shared-resolver cleanup B-14; revocation model **D31**) are done. The next
recommended run for this foundation track is **Build-stage Phase ID-4 / PR03B /
Batch B** from `21_pr03b_active_case_db_authority.md` (active-case DB authority
+ Gateway propagation, carrying B-11, no historical data migration).
Active-case authority/propagation stays deferred to ID-4/ID-5; legacy auth/token
sunset stays deferred to ID-6.
