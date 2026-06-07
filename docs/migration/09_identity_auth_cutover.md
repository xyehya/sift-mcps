# Identity, Auth, and Case-Scope Cutover (Foundation Track)

Last updated: 2026-06-07.

Scope: planning only. This document defines the **foundation track** of the
migration: identity, authentication, case membership, active-case authority, and
the MCP/service-token registry. It is cutover-order step 1 in
`00_migration_charter.md` ("Cutover Order") and is a prerequisite for the
evidence, jobs, OpenSearch, findings, reports, RAG, and skills work, because
every case-scoped table and every durable job carries identity and case context
that does not exist in the control plane today.

This document does not create SQL migrations, modify application code, or change
runtime behavior. It defines the target model, locks the previously-open
identity decisions, and gives a phased, additive cutover plan. All locked
decisions trace to `00_migration_charter.md` "Confirmed Decisions (Locked)".

## 1. Why this is first

The execution docs (`05`-`08`) assume that:

- Every job has `case_id`, `requested_by_user_id`, and `requested_by_token_id`
  sourced from "Gateway-validated session/token context".
- Case scope comes from authenticated identity, not from process environment.
- Tokens are hash-only, case-scoped, tool-scoped registry records.

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

Two distinct principal classes, one enforcement point.

| Principal class | Who | Credential | Validated by | Notes |
| --- | --- | --- | --- | --- |
| Human operator | Examiners/analysts using the portal | Supabase Auth session (JWT) | Gateway verifies Supabase session; RLS scopes reads | Mapped to `operator_profiles`; case access via `case_members`. |
| AI agent / MCP client | Codex/Claude/local MCP clients | Gateway-issued, hash-only MCP token | Gateway validates against `mcp_tokens` + `mcp_token_scopes` | Never a Supabase user session; case- and tool-scoped. |
| Worker / service | SIFT VM worker runtime, Gateway-internal services | Service token + `service_identities`/`workers` row | Gateway/worker service role | Inherits `case_id` from claimed job; never invents case scope. |

The Gateway remains the single policy boundary (charter D2). The browser never
talks to Supabase or a backend directly for privileged mutation; it calls
Gateway endpoints (charter D12). RLS is a defense-in-depth boundary behind the
Gateway, not the primary write path.

## 3. Active-case authority (locked: D4)

The current single-active-case behavior is preserved, but its **authority moves
from files/env into the control plane**:

- The operator selects the active case in the portal. The portal is the only
  place the active case is set.
- The selection is written authoritatively to the control plane (active-case
  state, see `08_control_plane_schema.md`). One active case per SIFT VM
  deployment, matching today's single `~/.sift/active_case` behavior.
- The Gateway reads the control-plane active case and **propagates** it to every
  backend, REST handler, and MCP tool call as request context.
- Legacy `SIFT_CASE_DIR`, `gateway.yaml case.dir`, and `~/.sift/active_case` are
  **generated compatibility exports** produced from control-plane authority
  during transition, for backends/CLIs that still read them. They are never the
  source of truth.
- Durable jobs record the active `case_id` immutably on the job row at creation
  time. A long-running job is unaffected if the operator later switches the
  active case.
- For agent/MCP tokens, the operative case is the control-plane active case, and
  the Gateway additionally verifies the token is authorized for that case before
  dispatch. Normal agent tokens cannot pass an arbitrary `case_id`.

### Coupling: the evidence gate must move with active case

The Gateway aggregate MCP evidence gate currently resolves case from
`SIFT_CASE_DIR` and the file manifest before blocking/allowing tool calls
(`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:637-675`). When active
case becomes control-plane authoritative, the evidence gate's case resolution
must switch in lockstep, or the gate could check a different case than the call
runs against. This is an explicit, in-scope step of this track (phase ID-5), not
a later cleanup.

## 4. MCP/service-token registry (locked: D8)

Tokens become hash-only registry records. Locked initial policy (configurable
later via Gateway config, but these are the defaults to implement):

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

This supersedes the prior open questions on hash algorithm, pepper/KMS use,
fingerprint format, and default expiry. KMS-backed hashing is explicitly
deferred; the pepper-in-secret approach is the v1 target.

### Legacy token fallback during cutover

During the cutover window the Gateway dual-validates: DB hash registry first,
then the legacy `gateway.yaml api_keys` map (read-only). Legacy raw tokens are
migrated as **disabled/legacy** records (fingerprint + metadata only; the raw
secret is not copied into the DB), and operators re-issue DB-backed tokens. The
legacy path is removed once no active legacy tokens remain and the config holds
no raw service tokens (charter compatibility condition).

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

- Supabase Auth becomes the human identity provider. `operator_profiles.auth_user_id`
  links to `auth.users(id)`.
- The Gateway/portal verifies the Supabase session and resolves the operator
  profile and case memberships, replacing the bespoke examiner model over time.
- Legacy portal auth (HMAC `sift_session` JWT + examiner bearer fallback) keeps
  working behind a config flag during cutover so operators are never locked out
  (`packages/case-dashboard/src/case_dashboard/auth.py:61-131`). It is sunset
  after Supabase Auth is verified end-to-end. Agent tokens remain rejected on
  the portal surface throughout.
- Single-user/anonymous-examiner mode (empty `api_keys`) is retained only as a
  local-dev convenience and must be off in the target deployment.

## 7. Gateway enforcement changes

The Gateway gains, additively:

- Supabase session verification for human REST/portal requests.
- DB-backed MCP/service token validation (hash lookup) with legacy fallback.
- `Identity` extended with case scope and tool scopes resolved from
  membership/token records (today `Identity` carries no case scope,
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

### Phase ID-2 - Token hash registry (dual-validate)
- Implement hash-only token validation (§4) in the Gateway with legacy
  `gateway.yaml` fallback. Migrate existing tokens to disabled/legacy records.
- Portal token lifecycle (create/rotate/revoke/reactivate) writes DB records and
  returns the raw token once, replacing `gateway.yaml` writes
  (`packages/case-dashboard/src/case_dashboard/routes.py:3060-3345`).

### Phase ID-3 - Supabase Auth for humans + memberships
- Add Supabase session verification and operator-profile/membership resolution
  behind the legacy-auth config flag. Map the current examiner as an initial
  `owner`/`admin`.

### Phase ID-4 - Control-plane active case + propagation
- Write active case to the control plane on portal activation; Gateway reads it
  and propagates request context; generate `SIFT_CASE_DIR`/`~/.sift/active_case`
  as compatibility exports from DB authority.

### Phase ID-5 - Move evidence gate + case scope onto control-plane context
- Switch the aggregate MCP evidence gate and case-scope checks to the
  control-plane active case and token/session case scope (§3 coupling).
- Disable per-backend `/mcp/{name}` routes.

### Phase ID-6 - Sunset legacy auth/token paths
- After verification, remove the legacy examiner bearer fallback and legacy
  `gateway.yaml api_keys` validation; ensure config holds no raw service tokens.
- Keep single-user/anonymous mode only as an explicit local-dev flag.

## 9. Compatibility and migration mapping

| Current source | Current role | Future authority | Bridge | Removal condition |
| --- | --- | --- | --- | --- |
| `gateway.yaml api_keys` (raw-keyed) | Token registry | `mcp_tokens` + `mcp_token_scopes` (hash-only) | Dual-validate, migrate as disabled/legacy records | No active legacy tokens; no raw service tokens in config |
| Portal HMAC `sift_session` JWT + examiner bearer | Human auth | Supabase Auth + `operator_profiles` + `case_members` | Keep behind config flag during cutover | Supabase Auth verified end-to-end |
| `SIFT_CASE_DIR` / `gateway.yaml case.dir` / `~/.sift/active_case` | Active case | Control-plane active-case state | DB authority + generated env/pointer exports | Backends accept Gateway-propagated case context |
| Empty `api_keys` anonymous examiner | Single-user mode | Explicit local-dev flag only | Retain for dev | Off in target deployment |

## 10. Tests and acceptance

- Token: hash lookup matches; raw token never stored; expiry/revocation fail
  closed; fingerprint is non-secret; legacy fallback validates then is removable.
- Identity: case scope and tool scopes resolved from membership/token; normal
  agent token cannot pass arbitrary `case_id`; cross-case denial.
- Active case: portal sets it; Gateway propagates it; jobs snapshot it; env/pointer
  exports are generated, not read as authority; evidence gate checks the same case
  the call runs against.
- Membership/roles: role matrix (§5) enforced; approval/destructive actions require
  `lead`/`owner`/`admin`; agents cannot approve their own findings.
- Auth: Supabase session accepted; legacy flag path works during cutover and is
  removable; agent tokens rejected on the portal surface.
- Audit: token validation, denials, membership changes, and active-case changes
  are audited.

## 11. Decisions

### Locked (resolved here and in the charter)
- Two principal classes; Gateway-only enforcement (D2, D8, D12).
- Active case portal-set, control-plane authoritative, Gateway-propagated; env/
  pointers are generated exports (D4).
- Hash-only token policy: SHA-256 + server pepper, 16-hex fingerprint, default
  expiries, one-time raw display, dual-validate then sunset legacy (D8).
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
After this track's schema is approved, the first implementation work is roadmap
phase JOB-0 baseline tests (additive, order-independent), then Phase ID-1 schema
migration for the foundational identity tables.
