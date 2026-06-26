# Validation — Cluster AUTH

> Validator agent: sec-auth (Opus 4.8, xhigh). Read-only. Validates the restored
> Codex assessment against **current HEAD** (`93f8999`, 183 commits past the stale
> scan base `b995491`). No source code was modified — this file is the only output.
>
> Secure-coding lens: `codeguard-security:codeguard` skill run explicitly. Relevant
> rule families applied: **authorization-access-control** (CWE-862 Missing
> Authorization / OWASP A01), **authentication-mfa + session-management** (step-up /
> re-auth), **api-web-services** (control-plane mutation surface), **mcp-security**
> (single policy boundary), and **framework-and-languages** (insecure defaults,
> CWE-1188 / CWE-453 fail-open). Verdict per candidate below.
>
> **Drift:** `git log b995491..HEAD -- <file>`:
> - `sift-gateway/src/sift_gateway/rest.py` → **0 commits** (unchanged; Codex line
>   numbers still accurate).
> - `sift-gateway/src/sift_gateway/supabase_auth.py` → **0 commits** (unchanged).
> - `case-dashboard/src/case_dashboard/routes.py` → audit-shaping commits only
>   (W2 audit trail, CSP); token-lifecycle block drifted down ~40–300 lines, auth
>   gate logic unchanged.

## Summary table

| Candidate | Codex verdict | **Current status** | Current severity | Confidence | Already-fixed-by | Fix effort |
|---|---|---|---|---|---|---|
| DSS-CAN-002 | valid / critical | **STILL-VALID** | **High→Critical (chained)** | high | — | M |
| DSS-CAN-001 | valid / high | **STILL-VALID** | **Medium** (operator-only) | high | — | M |
| DSS-CAN-014 | valid / high | **STILL-VALID** (partial mitigation: case-bound) | **Medium** | high | — | M |
| DSS-CAN-015 | valid / high | **STILL-VALID** | **Medium** | high | — | S |

**Counts:** STILL-VALID = 4 · ALREADY-FIXED = 0 · FALSE-POSITIVE = 0.
**Highest-priority fix:** DSS-CAN-002 — one shared operator-authority dependency on every
`/api/v1` control-plane mutation route (block `agent`/`service` principal_type; require
operator/examiner). It is the AUTH enabler for the BACKENDS code-exec/SSRF chain.

---

## DSS-CAN-002 — Direct Gateway REST control-plane routes lack operator authority / re-auth gates

**Codex claim (verbatim intent):** Raw Gateway REST mutation routes (backend registry,
service lifecycle, join-code state) accept a generically authenticated identity and mutate
the control plane without route-local operator/admin authority, Origin/CSRF protection, or
recent Supabase re-auth.

**Current code located at:** `packages/sift-gateway/src/sift_gateway/rest.py` — route table
`rest_routes()` lines **1235-1253**; mutation handlers: `register_backend` 1108-1117 /
`register_backend_logic` **1027-1094**, `unregister_backend` 1120-1177, `set_backend_enabled`
1180-1232, `reload_backends`, `start_service` 484-523, `stop_service` 526-549, `restart_service`
552-602, `create_join_code` 610-648. Auth wiring: `AuthMiddleware.dispatch`
`packages/sift-gateway/src/sift_gateway/auth.py:116-237`; app assembly `server.py:1469-1524`.
(Codex cited `1027-1064` — still accurate, no drift.)

**CURRENT STATUS:** STILL-VALID

**Evidence (current source):**
`AuthMiddleware` authenticates and stamps identity but applies **no role gate** to `/api/v1`
routes. The *only* role gates in the whole middleware are scoped to `/portal/api/`:
```python
# auth.py:120-148  — agent + readonly blocks apply ONLY to /portal/api/
if path.startswith("/portal/api/") and self.api_keys:
    ...
    if key_info.get("role") == "agent":   # blocked from portal only
        return JSONResponse({"error": "Agent tokens cannot access portal"}, status_code=403)
```
The `/api/v1` mutation handlers themselves perform **zero** authority checks — e.g.
`register_backend` only reads `actor` for the audit column:
```python
# rest.py:1108-1117
async def register_backend(request: Request) -> JSONResponse:
    gateway = request.app.state.gateway
    body, error = await _read_json_body(request)
    ...
    actor = getattr(request.state, "identity", None)
    response, status_code = await register_backend_logic(gateway, body, actor=actor)
```
And the registry layer also does not enforce authority — `actor` becomes only `registered_by`:
```python
# mcp_backends_registry.py:452  (McpBackendRegistry.register)
operator_id = _operator_id(actor)   # → registered_by audit column only; no authz
```
App middleware stack (`server.py:1488-1522`) is `AuthMiddleware → CORS → _NormalizeMCPPath →
_PortalHTTPSGuard → SecureHeaders`. None of these gate `/api/v1` by role, require step-up, or
enforce CSRF.

**Reachability trace:** A request to `POST /api/v1/backends` (or `/services/{n}/start`,
`/setup/join-code`) → `AuthMiddleware.dispatch`: path is not public, not `/portal/api/`, so it
falls to token resolution (Supabase → legacy `resolve_identity` over the same `token_registry`
+ `api_keys` used by `/mcp`) → `_stamp` → `call_next` → handler runs with **no further authority
check**. The reachability set is *any holder of a valid Gateway bearer token*: examiner gateway
token, **agent token (role=agent, principal_type=agent)**, service token, or a Supabase principal.
The agent/service `principal_type` is NOT blocked here (contrast: `call_tool` at rest.py:234
explicitly blocks it; these mutation routes do not).

**Exploit preconditions:** Any valid Gateway bearer token. Most significant: a **compromised or
prompt-injected agent/service principal** — exactly the entity the least-priv sandbox exists to
contain — can register/unregister backends, flip `enabled`, start/stop/restart services, and mint
join codes. (Honesty caveat: the in-band LLM does not normally hold its own raw bearer token —
it is injected into the MCP transport — so naive model-only exploitation needs token exfiltration;
a compromised agent *process* holds the token and is fully capable. The missing-authorization
defect stands regardless of that nuance.)

**Blast radius if valid:**
- `POST /api/v1/backends` → persist a new backend row → after materialization/start the Gateway
  launches it (stdio process under the Gateway account: cross-ref DSS-CAN-003/020; or an HTTP
  backend pointed at an internal/rebound URL: cross-ref DSS-CAN-004) → **code-exec / SSRF**.
- `POST /api/v1/services/{n}/start|stop|restart` → availability control of the tool plane.
- `POST /api/v1/setup/join-code` → mint a one-time join code; `POST /api/v1/setup/join` (public,
  `_PUBLIC_PATHS`) then exchanges it for a **fresh Gateway token** (privilege persistence) or
  registers a caller-supplied wintools HTTP backend (`join_gateway` 699-758; cross-ref
  DSS-CAN-019). So even a non-operator token can bootstrap new credentials + new backends.

In isolation the AUTH-layer gap is **High** (CWE-862 missing function-level authorization on the
control plane); chained to backend registration → process launch it is **Critical**.

**On the CSRF/Origin part of the Codex claim:** these `/api/v1` routes are bearer-token APIs with
no ambient/cookie credential, so classic CSRF largely does not apply and CORS already restricts
browser origins (`server.py:1507-1513`). The load-bearing defect is the **missing authority gate
+ agent/service not blocked**, not CSRF. (CSRF *does* matter for the `/portal/api/*` cookie-session
surface, which is separately gated — out of scope here.) I am downgrading the CSRF emphasis vs Codex.

**Project-invariant check:** Violates **least-privilege sandbox** (agent/service can mutate the
control plane) and **portal-managed lifecycle** (backend/service lifecycle should be operator-only).
Does not touch the MCP output-surfacing layers. Interacts with DB-authority only insofar as the
registry write is the DB manifest snapshot the gateway later trusts.

**FIX APPROACH (secure-by-design):**
- Root cause: authorization is conflated with authentication — `AuthMiddleware` proves *who* but
  never decides *may-they-mutate-the-control-plane*; handlers and `registry.register` trust the
  stamped identity for audit only.
- Proposed change (exact layer): add a single shared authority dependency, e.g.
  `require_control_plane_operator(request)` in `auth.py`, that (a) rejects
  `principal_type in {"agent","service"}` and `role in {"agent","service","readonly"}` with 403,
  and (b) requires an operator/examiner principal. Invoke it at the **top of every mutation
  handler** in `rest.py` (register/unregister/set_enabled/reload, services start/stop/restart,
  create_join_code) — mirroring the existing `is_agent_principal` guard already used in `call_tool`.
  Defense-in-depth: also enforce operator authority inside `McpBackendRegistry.register/unregister/
  set_enabled` (raise an authz error, not just stamp `registered_by`) so a future caller cannot
  bypass the route guard. For true step-up, gate the *highest-impact* mutations (register a NEW
  backend, mint a join-code) behind a recent-Supabase-re-auth check when Supabase is enabled
  (reuse the portal step-up primitive) — this is the "recent re-auth" Codex asks for.
- Why it preserves invariants: it makes the gateway the single authority for control-plane
  mutation (thin policy boundary), keeps add-ons bound by the Backend Contract, and re-asserts
  least-priv (the sandboxed agent/service can no longer reach the control plane). No add-on
  subprocess needs DB creds.
- Test strategy: unit tests asserting 403 for `principal_type=agent` and `=service` and
  `role=readonly` on each mutation route, and 200/201 for operator. **Fail-on-revert surface
  test:** a parametrized `tests/test_rest_control_plane_authz.py` that drives each route in
  `rest_routes()` with an agent identity and asserts denial — so re-adding a route without the
  guard fails CI (a structural test over the route table, not one hand-written case). Live
  deploy-and-prove (behavioral): on the VM, with an agent token, `curl -X POST .../api/v1/backends`
  must return 403 and create no `app.mcp_backends` row; with the examiner token it must still
  succeed — diff `app.mcp_backends` before/after.
- Alternatives rejected: (1) rely on CORS — CORS is not authorization and does not bind
  non-browser clients. (2) Network-segregate `/api/v1` from the agent — brittle, and the agent
  must already reach the same host:port for `/mcp`. (3) Move the whole control plane behind the
  portal session — breaks the `sift` CLI/`gateway.call_tool` bearer-token consumers.

**Cross-cluster dependency:** This is the AUTH root that gates BACKENDS DSS-CAN-003 (stdio command
launch), DSS-CAN-004 (HTTP egress), DSS-CAN-020 (env inheritance) and DSS-CAN-019 (public
wintools join → HTTP backend). One shared operator-authority + step-up dependency is the
upstream control; the BACKENDS findings still need their own depth (command allowlist, egress
policy, minimal env) but become operator-only once this lands.

**Open question for operator:** This system has no `owner`/`admin` tier — all humans are role
`examiner`. Decide whether "operator authority" = any examiner (then the fix only excludes
agent/service/readonly + adds step-up) or whether a new admin tier is warranted for backend
registration specifically.

---

## DSS-CAN-001 — Legacy REST tool route bypasses the MCP policy middleware stack

**Codex claim (verbatim intent):** `POST /api/v1/tools/{tool_name}` calls `Gateway.call_tool`
directly after only blocking agent/service principals — bypassing MCP-only tool authorization,
add-on authority, evidence gate, response guard, DB-first audit envelope, and OpenSearch job
dispatch.

**Current code located at:** `packages/sift-gateway/src/sift_gateway/rest.py:206-349` (handler
`call_tool`; agent block **229-246** — matches Codex citation, no drift). Routed at rest.py:1239.
`Gateway.call_tool` at `packages/sift-gateway/src/sift_gateway/server.py:1037-1199`. Policy chain
that it bypasses: `gateway_policy_middlewares` `policy_middleware.py:1562-1601`, wired only onto the
MCP server in `mcp_server.create_gateway_mcp_server` (mcp_server.py:389).

**CURRENT STATUS:** STILL-VALID

**Evidence (current source):** The REST handler blocks only agent/service, then dispatches:
```python
# rest.py:234-246
if is_agent_principal(request):
    ... return 403 ...
# rest.py:277  (operators fall through to:)
result = await gateway.call_tool(tool_name, arguments,
                                 examiner=identity.get("examiner"),
                                 identity=getattr(request.state, "identity", None))
```
`Gateway.call_tool` (server.py:1037-1199) applies active-case resolution + `case_id`/`case_dir`
injection and a thin HTTP-backend audit log — but it does **not** run `ToolAuthorizationMiddleware`,
`AddonAuthorityMiddleware`, `EvidenceGateMiddleware`, `ResponseGuardMiddleware`,
`AuditEnvelopeMiddleware` (DB-first envelope), `ControlPlaneRequiredMiddleware`, or
`OpenSearchJobDispatchMiddleware`. Those are FastMCP `on_call_tool` hooks registered exclusively on
the `/mcp` server, so the REST path is a **second tool-execution surface outside the policy
boundary**.

**Reachability trace:** `/api/v1/tools/{tool}` is auth-gated by `AuthMiddleware` (any operator
bearer token); agent/service are explicitly denied at rest.py:234. The route is **actively used
internally**: `opensearch-mcp/src/opensearch_mcp/gateway.py:57-88` (`call_tool`) POSTs to it with
the first configured `api_key` (an operator token), consumed by `threat_intel.py`,
`parse_memory.py`, `ingest_cli.py`, `wintools.py` — the OpenSearch worker's callback path for
`record_finding`/`record_timeline_event`/status. So the route is **not dead** and cannot simply be
deleted.

**Exploit preconditions:** An operator/examiner Gateway bearer token. No agent reachability
(blocked). The risk is therefore an *integrity/audit-completeness* gap rather than a privilege
escalation: an operator (or anything holding the operator token, including the OpenSearch worker
config token) executes any tool while skipping the evidence gate, response-guard redaction, the
DB-first audit envelope, add-on required-scope checks, and OpenSearch job dispatch (a REST
`opensearch_ingest` would proxy to the in-gateway stdio child instead of the durable mount-capable
worker — re-introducing the FUSE-in-sandbox problem the worker decoupling fixed).

**Blast radius if valid:** Forensic-integrity: tool runs against unsealed evidence (evidence gate
skipped) and REST tool calls are not captured by the rich DB-authority audit envelope — both
undermine chain-of-custody guarantees the gateway is supposed to enforce *uniformly*, regardless
of who calls. Bounded to operator-token holders → **Medium**.

**Project-invariant check:** Directly violates **"gateway = single thin policy boundary"** (two
tool-exec paths, only one carries policy) and weakens the **evidence gate** + **DB-first audit**
invariants. Cross-touches the OpenSearch worker decoupling invariant (job dispatch skipped).

**FIX APPROACH (secure-by-design):**
- Root cause: the policy decision lives inside FastMCP middleware bolted to the `/mcp` server, not
  in a surface-independent layer; the REST path reaches `Gateway.call_tool` underneath it.
- Proposed change (exact layer): extract the policy decision into a single shared async callable
  (e.g. `Gateway.call_tool_governed(name, args, identity)`) that runs the same ordered checks the
  middleware chain runs (control-plane-required → tool authz → add-on authority → case context →
  audit envelope → evidence gate → response guard → opensearch dispatch) and have BOTH the MCP
  `on_call_tool` terminus and the REST `call_tool` handler call it. Do **not** delete the route —
  the OpenSearch worker depends on it; instead, narrow it: route worker callbacks through the
  governed path too (their `record_finding` etc. run post-evidence-gate so the gate is a no-op for
  them), and restrict the REST route's accepted tool set to what an operator legitimately needs
  over REST (or to loopback for the worker token). If the operator-REST tool surface has no real
  product use beyond the worker, prefer collapsing it to an internal worker-only endpoint bound to
  a dedicated worker principal.
- Why it preserves invariants: re-unifies the policy boundary (one governed entry, two transports),
  keeps evidence gate + DB audit authoritative for every tool call, preserves the worker callback.
- Test strategy: unit test that a REST `call_tool` with unsealed evidence is denied by the evidence
  gate (parity with the existing `test_mcp_evidence_gate_fail_closed_and_audited`). **Fail-on-revert
  surface test:** a parity test asserting REST and MCP dispatch produce the same authz/evidence/audit
  decision for a representative tool set (extend `test_policy_parity_d27b`). Live deploy-and-prove:
  on the VM, call a case-scoped tool over REST against a case whose evidence is unsealed → must be
  denied + audited; confirm a DB `app.audit_events` row exists for the REST call.
- Alternatives rejected: (1) plain delete (Codex option) — breaks the OpenSearch worker callbacks.
  (2) Duplicate the middleware logic inside `Gateway.call_tool` — drift risk; the shared-callable
  approach keeps one source of truth.

**Cross-cluster dependency:** Ties to OPENSEARCH/EXECUTION — the route is the OpenSearch worker's
gateway callback; the fix must preserve `opensearch_mcp.gateway.call_tool`. Shares the "single
policy boundary" theme with DSS-CAN-002 but is a distinct surface (tool exec vs control-plane).

**Open question for operator:** Is there any *human/product* use of `POST /api/v1/tools/{tool}`
beyond the OpenSearch worker callback? If not, collapse it to a worker-only internal endpoint
(smallest attack surface) rather than governing a general operator REST tool surface.

---

## DSS-CAN-014 — Legacy portal token lifecycle mints broad `mcp:*` agent tokens without step-up

**Codex claim (verbatim intent):** Legacy portal token endpoints let any non-readonly examiner
create/rotate/reactivate service/agent tokens; agent tokens get broad `mcp:*` scope, returned once
in raw form.

**Current code located at:** `packages/case-dashboard/src/case_dashboard/routes.py` —
`create_token` **4116-4230**, `revoke_token` 4233-4270, `rotate_token` 4273-4339,
`reactivate_token` 4342-4375, `list_tokens` 4086-4113; gate helpers `_require_examiner_role`
335-342, `_must_reset_check` 544-572; routes mounted `/portal/api/tokens*` at
`_dashboard_api_routes` 5938-5942. Scope assignment in
`packages/sift-gateway/src/sift_gateway/token_registry.py:250`. (Codex cited `3976-4090`; drifted
down ~40–250 lines by the W2 audit commits — gate logic unchanged.)

**CURRENT STATUS:** STILL-VALID (with one partial mitigation already present: tokens are case-bound)

**Evidence (current source):** Gate is examiner-role only — no owner/admin, no step-up re-auth:
```python
# routes.py:4128-4137 (create_token; identical pattern in rotate/reactivate)
role_err = _require_examiner_role(request)   # role == "examiner" (335-342)
if role_err: return role_err
...
must_err = _must_reset_check(request)        # only denies status=="invited" (544-572)
```
The minted agent token gets the broad compatibility scope:
```python
# token_registry.py:250
scopes = ["mcp:*"] if role == "agent" else ["portal:read"]
```
and the raw token is returned once (`"token": raw_token,  # returned exactly once`,
routes.py:4219 / 4328). **Partial mitigation present:** agent tokens are bound to a case
(`case_id` required for agent role, routes.py:4164-4173; persisted at token_registry.py:248-249,
299-301), which narrows blast radius vs Codex's framing.

**Reachability trace:** Mounted under the portal app (`/portal/api/tokens`). `AuthMiddleware`
blocks `agent` and non-GET `readonly` from `/portal/api/` (auth.py:120-148); the portal session
middleware authenticates the examiner; `_require_examiner_role` requires role `examiner`. So the
precondition is **a logged-in portal examiner session** — not an anonymous or agent caller.

**Exploit preconditions:** A logged-in examiner (any examiner — there is no higher tier). No
recent-re-auth/step-up is required for the mint/rotate/reactivate. A single examiner session can
therefore issue a full-power (`mcp:*`) agent token for the active case and read its raw value once.

**Blast radius if valid:** An examiner can mint case-scoped agent credentials with full tool
authority and hand them out / persist them; rotate keeps a valid `mcp:*` token alive; reactivate
un-revokes. Case-binding limits cross-case reach, but within a case the token is unconstrained.
Privilege-management weakness (CWE-269) + missing step-up for a credential-issuing action →
**Medium**.

**Project-invariant check:** Touches **portal-managed lifecycle** (this *is* the portal lifecycle,
but the legacy PR02 variant) and **DB-authority** (token_registry writes `app.mcp_tokens` /
`app.mcp_token_scopes`). The `mcp:*` scope interplays with `is_tool_allowed`
(supabase_auth.py:1710-1738) — `mcp:*` short-circuits to allow-all. Note PR03A added a *new*
Supabase-JWT agent/service lifecycle (routes.py:4378+) and explicitly keeps `/api/tokens/*` as a
"legacy compatibility surface" — so this is intentionally-retained legacy, the same retirement
question as DSS-CAN-015.

**FIX APPROACH (secure-by-design):**
- Root cause: a high-impact credential-issuing action is gated only by steady-state role, with a
  superuser default scope, on a legacy surface kept alive for migration.
- Proposed change: (1) Require **recent Supabase re-auth (step-up)** for create/rotate/reactivate
  when Supabase is enabled — reuse the existing portal step-up primitive (the `_must_reset_check`
  comment references the resolver-driven session model; add a `require_recent_reauth` dependency).
  (2) Replace the `mcp:*` default in `token_registry.create_token` with a **least-privilege default**
  derived from the request (e.g. the active case's needed tool namespaces, or an explicit
  `scopes`/`purpose` body field validated against an allowlist) — keep `mcp:*` only behind an
  explicit operator opt-in. (3) Gate the whole legacy `/api/tokens/*` surface behind an explicit
  "legacy token lifecycle enabled" flag tied to the same migration flag as DSS-CAN-015, defaulting
  off once PR03A is the issuance path. Tokens are already case-bound — preserve that.
- Why it preserves invariants: keeps issuance portal-managed + DB-authoritative; narrows the agent
  principal to least-priv (sandbox intent); makes the legacy plane explicitly opt-in.
- Test strategy: unit tests that create/rotate/reactivate require step-up (401/403 without a recent
  re-auth claim) and that a default-minted agent token does NOT carry `mcp:*`. **Fail-on-revert
  surface test:** assert `token_registry.create_token(role="agent")` returns a scope set that is a
  strict subset of `{"mcp:*"}` only when explicitly requested (a test that fails if someone restores
  the unconditional `["mcp:*"]`). Live deploy-and-prove: mint a token via the portal, inspect
  `app.mcp_token_scopes` for the new `token_id` — must be least-priv, not `mcp:*`, unless opted in.
- Alternatives rejected: (1) Pure "retire the legacy lifecycle" (Codex option) — blocks until PR03A
  is the sole path; do it as the end state behind the flag, but ship step-up + scope-narrowing now.
  (2) Add an admin role just for this — heavier; step-up achieves the intent without a new tier.

**Cross-cluster dependency:** Shares the **legacy-auth-plane retirement** decision with DSS-CAN-015
(both lean on `mcp:*` defaults + the legacy fallback flag). One operator decision ("when does the
PR02 token plane turn off?") resolves the residual in both.

**Open question for operator:** What is the migration cutover date for PR02 `/api/tokens/*` →
PR03A Supabase agent JWTs? That date should drive the default-off flag for both 014 and 015.

---

## DSS-CAN-015 — Supabase-active auth still defaults legacy token fallback to TRUE (insecure default)

**Codex claim (verbatim intent):** When Supabase auth is enabled, legacy token fallback still
defaults to true; invalid/unavailable Supabase resolution falls through to legacy identities, and
MCP compatibility can stamp legacy identities with `mcp:*` scopes. Default fallback to false when
Supabase enabled; require an explicit time-bounded migration flag.

**Current code located at:** `packages/sift-gateway/src/sift_gateway/supabase_auth.py` —
`SupabaseAuthConfig.legacy_token_fallback_enabled` default **202**, parsed at **290** in
`load_supabase_auth_config`. Fallback decision: `AuthMiddleware._legacy_token_fallback`
`auth.py:92-96` + `dispatch` 196-237. MCP `mcp:*` stamping:
`mcp_endpoint.py:SiftTokenVerifier.verify_token` **237-242** + `legacy_default_scopes`
`supabase_auth.py:1774-1776`. (Codex cited `185-204` — the dataclass region; accurate, no drift.)

**CURRENT STATUS:** STILL-VALID

**Evidence (current source):**
```python
# supabase_auth.py:202  (dataclass default — independent of supabase.enabled)
legacy_token_fallback_enabled: bool = True
# supabase_auth.py:290  (parse — defaults True even when sb.enabled is True)
legacy_token_fallback_enabled=_as_bool(legacy.get("token_fallback_enabled"), True),
```
REST fallthrough (auth.py:196-234): Supabase tried first; a Supabase **401 (unknown token)** falls
through to the legacy `resolve_identity` path when `_legacy_token_fallback()` is True (default).
On a Supabase **5xx outage** it also falls through unless fallback is disabled (the 503 fail-closed
branch only triggers when fallback is off, auth.py:211-220). MCP path stamps legacy api-key
identities with the superuser scope:
```python
# mcp_endpoint.py:237-242
if not identity.tool_scopes and legacy and self.legacy_fallback_enabled:
    identity = replace(identity, tool_scopes=legacy_default_scopes())   # frozenset({"mcp:*"})
```
So with the default config and Supabase "on", a retained legacy `api_keys` token that Supabase does
not recognize still authenticates AND (on `/mcp`) receives full `mcp:*` tool authority.

**Reachability trace:** Any retained legacy credential (an `api_keys` entry or a `token_registry`
row) on a Supabase-enabled deployment where the operator did not explicitly set
`auth.legacy.token_fallback_enabled: false`. Token_registry rows carry their own DB scopes; the
`mcp:*` superuser stamp specifically affects legacy **api_keys** identities (which resolve with empty
`tool_scopes`, identity.py:95-104).

**Exploit preconditions:** A valid retained legacy token + default (unchanged) legacy-fallback
config + Supabase enabled. This is an insecure-default / migration-hygiene gap (CWE-1188 insecure
default, CWE-453 insecure default variable initialization), not acceptance of *invalid* tokens —
the legacy token is a real credential the operator failed to revoke during cutover.

**Blast radius if valid:** The old auth plane stays fully live by default after an operator believes
they have "switched to Supabase"; un-revoked legacy api-key tokens retain `mcp:*` on `/mcp`. Operator
-config dependent and requires a real retained credential → **Medium** (I am downgrading from
Codex's High because exploitation needs a valid legacy credential + a default the operator can close
in one line; but the fail-open-on-outage behavior keeps it clearly worth fixing).

**Project-invariant check:** This is the **auth plane** itself; secure-default principle (fail
securely). The `mcp:*` stamp interlocks with DSS-CAN-014's `mcp:*` issuance default. The 5xx
fail-open-when-fallback-on behavior (auth.py:211-220) is a deliberate availability tradeoff that
should be revisited under a Supabase-enabled posture.

**FIX APPROACH (secure-by-design):**
- Root cause: `legacy_token_fallback_enabled` is a flat `True` default that ignores
  `supabase.enabled`; the fail-safe default should depend on whether a stronger authority is active.
- Proposed change (exact layer): in `load_supabase_auth_config` (supabase_auth.py:282-294), when
  `sb.enabled` is True, **default `legacy_token_fallback_enabled` to False** unless the operator
  explicitly sets `auth.legacy.token_fallback_enabled: true` (a time-bounded migration flag — log a
  loud deprecation warning + optional expiry date when it is on). Keep the current `True` default
  only for the pure-legacy (`sb.enabled=False`) deployment so pre-Supabase setups are unchanged.
  Pair with: when fallback is off + Supabase enabled, the existing 503 fail-closed branch
  (auth.py:216-220) and MCP deny path already do the right thing.
- Why it preserves invariants: fail-secure default; keeps a controlled, explicit, observable
  migration window; does not break legacy-only deployments; aligns the gateway auth plane with the
  PR03A direction.
- Test strategy: unit test `load_supabase_auth_config({"auth":{"supabase":{"enabled":true}}})` →
  `legacy_token_fallback_enabled is False`; and `{... "legacy":{"token_fallback_enabled":true}}` →
  True (explicit opt-in). Middleware test: Supabase-enabled + fallback-defaulted-off + a valid legacy
  token → REST 401/403 and MCP `verify_token` → None (no `mcp:*` stamp). **Fail-on-revert** guard:
  the default-False-when-enabled assertion fails if someone reverts the conditional default. Live
  deploy-and-prove: on a Supabase-enabled VM gateway with the default config, a retained legacy
  token must be rejected on `/api/v1/*` and `/mcp` (was previously accepted).
- Alternatives rejected: (1) Remove legacy fallback entirely — breaks in-flight migrations; the
  time-bounded flag is the safe path. (2) Keep True but narrow the `mcp:*` stamp — addresses the
  scope blast radius but not the "old plane silently stays live" core issue.

**Cross-cluster dependency:** Interlocks with DSS-CAN-014 (shared `mcp:*` default + legacy plane
retirement). A single operator migration flag/date should drive both defaults.

**Open question for operator:** Same cutover-date question as DSS-CAN-014 — set the migration window
so the legacy fallback flag can auto-expire/default-off.

---

## Cluster notes for the orchestrator

- **Adjacent finding Codex under-rated (within DSS-CAN-002):** Codex framed the control-plane gap as
  "any *generically authenticated* identity." The sharper, more severe fact is that **agent/service
  `principal_type` is not blocked from `/api/v1/*` at all** (only `/portal/api/` and the single
  `call_tool` route block them). That makes the sandboxed agent/service a control-plane mutator —
  the exact thing the least-priv sandbox exists to prevent. The fix's agent/service block is the
  highest-value single line.
- **The four findings are two themes:** (a) *single-policy-boundary / authority on the gateway REST
  surface* = DSS-CAN-002 (control-plane mutation) + DSS-CAN-001 (tool exec); (b) *legacy auth-plane
  retirement + `mcp:*` defaults* = DSS-CAN-014 + DSS-CAN-015. Two operator decisions (a control-plane
  authority model incl. step-up; a PR02→PR03A cutover date) close the residuals across all four.
- No secrets, tokens, DSNs, or private keys appear in this report.
