# 17 — Gateway Cutover (D27b) — historical implementation candidate/log

Status: **implemented and landed** (build commit `0bb5c5e`; landed Run 24).
Historical landed candidate/log: do not use this as the next build prompt.
Historical scope fence: `packages/sift-gateway/src/sift_gateway/**`,
`packages/sift-gateway/tests/**`, `packages/sift-gateway/pyproject.toml`, `uv.lock`,
and this doc set (`docs/migration/**`). **No** edits to `packages/*-mcp/**` (the
D27a backend surface is consumed, not re-frozen), `packages/case-dashboard/**` (the
portal stays a mounted sub-app), `supabase/**`, or `packages/sift-core/**`.
Decisions referenced: **D2, D3, D8, D24, D25, D26, D27, D27b, D28** (charter);
backlog **B-3, B-5, B-6, B-7** (REGISTER.md).

This was the **Plan-stage** implementation candidate for D27b. The design/knowledge
base is `14_fastmcp3_supabase_integration.md`; this doc turns it into a file-by-file
build plan, a parity-test strategy, the B-3 design, and the forks the operator must
resolve before Build. Run 23 implemented it; Run 24 reviewed and landed it.

Run 26 / D30 supersedes the final identity target that existed when this D27b
spec was built. D27b correctly implemented the then-scoped hash-token
FastMCP verifier and PR02 compatibility path. Future auth work targets
Supabase-issued JWTs for REST and MCP, with PR02 hash-token validation retained
only as an explicit compatibility bridge.

All FastMCP 3.x mechanics below are grounded against the pinned **fastmcp 3.4.2**
(`uv.lock`) via the `/prefecthq/fastmcp` v3.2.x docs (closest published line); the
exact API symbols are confirmed in §4 and must be re-confirmed against the installed
wheel during Build (a build that finds the API differs **stops and raises a fork**,
it does not improvise — D29).

---

## 1. Why (grounded in source, not memory)

The cutover replaces the Gateway's hand-rolled MCP aggregation with FastMCP 3.0
providers/transforms while keeping every policy check SIFT-owned (D24/D2/D3). What
the build must preserve was read from source this run:

**The policy path today** (`mcp_endpoint.py:create_mcp_server._call_tool`,
lines 639–888) runs, in order, for every aggregate `/mcp` tool call:
1. `check_evidence_gate(SIFT_CASE_DIR)` → binary block-all on UNSEALED/violation
   (`evidence_gate.py`), with its own richer audit line.
2. backend dispatch via `gateway.call_tool()` (`server.py:712`), routing core tools
   in-process (`call_core_tool`) and add-on tools to a backend.
3. **response guard**: `redact_tool_result()` then `cap_tool_result()` over each
   content block — **redact-then-cap** so a secret cannot straddle the truncation
   boundary (`response_guard.py`, `mcp_endpoint.py:783–796`).
4. `_append_case_context()` response middleware (`mcp_endpoint.py:394`).
5. a one-line **audit envelope** in `finally` (`gateway_mcp_envelope`,
   `mcp_endpoint.py:856–886`) carrying principal/role/token_id/source_ip +
   `backend_audit_id`, with the gate writing its own line instead when it blocks.

**Connection-level policy** lives one layer out, in the ASGI wrapper
`MCPAuthASGIApp.__call__` (`mcp_endpoint.py:209–320`): IP rate-limit → request-size
cap (10 MB, `_MAX_REQUEST_BYTES`) → Origin allow-list → bearer-token resolution via
`resolve_identity()` (`identity.py`, hash-only `token_registry` first, legacy
`api_keys` fallback) → readonly-role block → per-examiner rate-limit. This is a thin
**raw-ASGI** wrapper *by necessity*: the code comment (lines 181–189) records that
Starlette `BaseHTTPMiddleware` buffers responses and breaks MCP SSE streaming.

**Two source findings that shape the plan:**

- **B-3 is real and unavoidable.** `HttpMCPBackend.call_tool` returns
  `result.content` only (`http_backend.py:224`) — `structured_content` is **dropped
  on the floor today**, so no secret can leak through it *yet*. The moment D27b
  consumes the D27a typed surface (every tool now returns `ToolResult` with
  `structured_content`, M2 made it `anyOf[success, ToolError]`), structured output
  starts flowing to the agent and the text-only response guard
  (`redact_tool_result(tc.text)`, line 789) becomes a redaction bypass. B-3 must
  land **in the same PR** that starts carrying `structured_content`.
- **The per-backend `/mcp/{name}` routes are a policy bypass.**
  `create_backend_mcp_server._call_tool` (`mcp_endpoint.py:913–990`) dispatches
  straight to `backend.call_tool` with **no evidence gate and no response guard** —
  only an audit line. They are mounted live (`server.py:856–867, 977`). D3 already
  says per-backend routes must be **disabled**; the cutover is where that happens
  (fork **F-7**).

**Framework state.** The gateway uses `mcp.server.lowlevel.Server` +
`StreamableHTTPSessionManager` (`mcp_endpoint.py:22–23`) and pins `mcp>=1.26` but
**not** `fastmcp` (`pyproject.toml:15`); fastmcp 3.4.2 is already in `uv.lock` from
D27a. The app is **Starlette**, not FastAPI (`server.py:980`).

---

## 2. Target shape (per D24, consuming D27a)

One **FastAPI** ASGI app (F-8 resolved: adopt FastAPI now — it is also the entry
point for the React operator portal/dashboard, so REST + MCP live under one app).
FastMCP 3.0 owns aggregation/namespacing/discovery; SIFT owns policy.

```
FastAPI ASGI app (single deploy; also serves the React operator portal)
  REST  /api/v1/*, /portal/*, /health      ← token/examiner auth this stage (Supabase-JWT DI lands at D26)
  MCP   mount( mcp.http_app(path=…) )       ← FastMCP 3.0 FastMCP() server instance
        ├─ SIFT policy = FastMCP Middleware (on_call_tool), in this order:
        │    EvidenceGateMiddleware → ResponseGuardMiddleware(B-3) → CaseContextMiddleware → AuditEnvelopeMiddleware
        ├─ providers (aggregation only):
        │    LocalProvider   → in-process core tools (sift-core agent_tools, retired forensic-mcp tools, opensearch per D19 later)
        │    ProxyProvider   → opencti-mcp, windows-triage-mcp  (create_proxy + mount(namespace=…))
        │    SkillsProvider  → deferred (D15, not this stage)
        └─ transforms: Namespace (per-backend prefix) only.
             NO per-case/per-phase/per-role Visibility, NO ToolSearch (F-9 dropped).
  ASGI auth wrapper (rate-limit, size cap, Origin, hash-only token) around the MCP mount  ← keep (F-8b)
  NO per-backend /mcp/{name} routes (F-7 / D3: dropped — they bypass the policy path).
```

Confirmed grounding for each mechanism is in §4. **F-6 (does middleware wrap proxied
tools?) is being empirically grounded against fastmcp 3.4.2 before this design is
committed** — Run 22 spawned a FastMCP-MCP/doc-grounding pass + a security-research
pass; if middleware does not wrap proxied tools, the proxied-tool guard shim (§9 F-6)
is used instead.

---

## 3. File-by-file plan

> Ordering is build order. Each is one logical change; keep the diff revertable.

### 3.1 `pyproject.toml` / `uv.lock`
Add `fastmcp>=3` to `packages/sift-gateway/pyproject.toml` dependencies (today only
`mcp>=1.26`). `uv.lock` already resolves `fastmcp==3.4.2`; re-run `uv lock` to attach
the gateway as a consumer. **Record the pin in `MIGRATION_STATE.md`** (D-pin
discipline; doc 14 §7).

### 3.2 New `mcp_server.py` (FastMCP server + providers)  — replaces aggregation in `server.py`/`mcp_endpoint.py`
- Build a `FastMCP("sift-gateway", instructions=…)` instance.
- **Core tools → LocalProvider.** Register the in-process core tools that
  `server.py:call_tool` routes to `call_core_tool` today (the `core_tool_specs()`
  set) as decorator/`LocalProvider` tools whose body calls the existing
  `call_core_tool` — **no change to sift-core**; the gateway only changes how it
  *exposes* them. Keep `capability_guide`/`case_info` synthetic tools.
- **Add-ons → ProxyProvider.** For each enabled backend in the control-plane
  registry (today still `gateway.yaml` `backends` until D22's `mcp_backends` lands —
  carry that as-is), `mcp.mount(create_proxy(<url-or-cmd>), namespace=<manifest
  namespace>)`. This replaces `backends/{http,stdio}_backend.py` *as the wire layer*;
  keep `load_and_validate_manifest` + the manifest contract (`backends/__init__.py`)
  — the manifest still governs namespace, evidence_class, health, hidden_from_agent.
- Preserve the namespace invariant (`server.py:_build_tool_map` raises on
  prefix/collision) via the `Namespace` transform + a startup assertion.

### 3.3 New `policy_middleware.py` (the heart of the cutover)
Re-host today's per-tool policy as FastMCP `Middleware.on_call_tool` classes so they
wrap **every** tool the server serves (local + proxied — the parity claim to verify,
F-6). One class per concern, composed inner→outer so execution order matches §1:

1. `EvidenceGateMiddleware.on_call_tool`: before `call_next`, run
   `check_evidence_gate`; if blocked, write the gate audit line and **return** the
   `build_block_response` ToolResult (do not call the tool). Byte-identical to
   `mcp_endpoint.py:654–689`. **Invariant (grounded Run 22):** every denial — gate
   block, future per-token authz (B-10) — must be decided **before `call_next`**.
   FastMCP only *logs* an error raised after `call_next`; it does not return it to the
   client (`fastmcp` middleware docs). Reject-before-dispatch is mandatory, not
   stylistic.
2. `ResponseGuardMiddleware.on_call_tool` (**B-3 — see §5**): `result =
   await call_next(context)`; scan+redact+cap **both** `result.content` text blocks
   **and** `result.structured_content`; emit the `gateway_response_guard` /
   `gateway_output_cap` audit lines; attach `_sift_context`.
3. `CaseContextMiddleware`: port `_append_case_context` (only `case_info` today).
4. `AuditEnvelopeMiddleware`: the `finally` one-line envelope
   (`gateway_mcp_envelope`) with `_stamp_identity_extra`, `backend_audit_id`,
   elapsed_ms, `_block_audited` suppression.

Identity is read from the MCP session context (today `_extract_request_context`
pulls `request.state.identity`); confirm the equivalent under `mcp.http_app` and the
ASGI auth wrapper (F-8b).

### 3.4 `response_guard.py` — extend for structured content (B-3)
Add `redact_structured(obj)` + `cap_structured(...)` (or a single
`guard_tool_result(ToolResult)` per B-6). Reuse the existing `_PATTERNS`,
`_REDACT_SEVERITIES`, `output_cap_bytes()`, and disk-spill so the redaction logic has
**one** definition. See §5 for the algorithm and the ToolResult content/structured
coupling hazard.

### 3.5 `server.py` — app assembly (now a **FastAPI** app — F-8)
- The app becomes `FastAPI(...)` (today Starlette). It is the single entry point for
  the React operator portal/dashboard REST **and** the agent MCP endpoint. The
  Supabase-JWT-via-DI human auth (D26) is **not** wired this stage — the REST surface
  keeps today's token/examiner auth; FastAPI is adopted now so the portal/DI work at
  the identity phase has its host, and to honor D24 ("one FastAPI ASGI app").
- Build the FastMCP app: `mcp_app = mcp.http_app(path="/")` (path chosen so the outer
  mount supplies `/mcp`).
- Lifespan: `combine_lifespans(app_lifespan, mcp_app.lifespan)` (the gateway's
  existing `lifespan` start/stop of backends, idle reaper, late-start, evidence
  watcher folds into `app_lifespan`).
- Keep `MCPAuthASGIApp` wrapping the mounted `mcp_app` (F-8b) — rate-limit, 10 MB
  cap, Origin, hash-only token, readonly block, per-examiner rate-limit are all
  connection-level and **SSE-safe as raw ASGI** (FastAPI/Starlette
  `BaseHTTPMiddleware` buffers responses and breaks MCP streaming — the reason this
  wrapper exists; do not replace it with a FastAPI dependency on the streaming path).
- **Remove** the per-backend `/mcp/{name}` mounts and `create_backend_mcp_server`
  (F-7 / D3) — they bypass the policy path (§1). No per-backend MCP route survives.
- Port the Starlette pieces to the FastAPI app unchanged in behavior:
  `health_routes`, `rest_routes`, the `/portal` + `/dashboard` mounts (the React
  portal sub-app stays a mounted ASGI app — `case-dashboard` is **out of fence**),
  `SecureHeadersMiddleware`, `_PortalHTTPSGuard`, CORS, `_sanitized_error`,
  `_NormalizeMCPPath`. (FastAPI is Starlette-based, so these compose; verify each
  middleware ordering is preserved by the parity suite.)

### 3.6 `mcp_endpoint.py` — token verifier + connection-level ASGI wrapper (D-1)
- **New `SiftTokenVerifier(TokenVerifier)`** (D-1): `verify_token()` calls the existing
  `token_registry.lookup_token` (hash-only, Postgres) — falling back to `api_keys` via
  `resolve_identity` for legacy single-user mode — and returns an `AccessToken` whose
  `scopes`/`claims` carry the SIFT `Identity` (principal, principal_type, role,
  case_id, `tool_scopes`, token fingerprint). Pass it as `FastMCP(..., auth=verifier)`
  so auth rejects unauthenticated requests at the transport level **before** middleware,
  and the policy middleware reads the principal via `get_access_token()`. No human JWT
  ever reaches this path (D26); machine tokens only.
- **Keep the connection-level guards** as the raw-ASGI wrapper around the mount (or as
  `http_app(middleware=[…])`): IP + per-examiner rate-limit, 10 MB request cap, Origin
  allow-list, readonly-role block. These are SSE-safe as raw ASGI and are **not** auth
  (F-8b's real concern) — they stay. Reuse `_extract_bearer_token`,
  `_get_content_length`, `log_rate_limit_violation`.
- Delete `create_mcp_server`, `create_backend_mcp_server`, `create_session_manager`
  (replaced by the FastMCP server + `http_app`). The per-tool policy moves to
  `policy_middleware.py` (§3.3).

### 3.7 `rest.py` — REST tool path
`/api/v1/tools` (`list_tools`) and `/api/v1/tools/{tool_name}` (`call_tool`) must
keep returning the same shapes. **F-12 resolved — KEEP AS IS:** the REST `call_tool`
path does **not** run the response guard (humans/examiners are trusted; the guard is
an agent-facing leak/bloat control). `rest.py:251–271` serializes raw and stays that
way; a parity test **freezes** the asymmetry so a future refactor cannot silently add
or drop redaction on the human path. Route REST tool calls through the same FastMCP
server (one tool registry) or keep `gateway.call_tool`; output shape frozen by §6.

### 3.8 `backends/*` — keep manifest, retire wire layer
`load_and_validate_manifest`, `validate_manifest_contract`, the schema, and the
manifest-derived UX metadata (`_tool_manifest_meta`, `capability_guide`) **stay** —
they are SIFT policy/registry, not MCP plumbing. `http_backend.py` /
`stdio_backend.py` as the *session/transport* layer are superseded by
`create_proxy`; keep them only if a proxied backend still needs SIFT-specific TLS
pinning / reconnect that `create_proxy` does not cover (verify in Build; if needed,
pass an MCP client into `create_proxy`). The `result.content`-only drop
(`http_backend.py:224`) disappears because the proxy carries `structured_content`.

### 3.9 Tests — parity suite (§6).

---

## 4. FastMCP 3.x mechanics — grounded (fastmcp 3.4.2 / `/prefecthq/fastmcp`)

| Mechanism | Confirmed API | Source |
| --- | --- | --- |
| Mount remote/local server | `mcp.mount(create_proxy("http://…/mcp"), namespace="api")`; `create_proxy("./server.py")` for stdio | `docs/servers/composition.mdx` |
| FastAPI integration | `mcp_app = mcp.http_app(path="/mcp")`; `app.mount("/mcp", mcp_app)` | `docs/integrations/fastapi.mdx`, `docs/deployment/http.mdx` |
| Combined lifespan | `from fastmcp.utilities.lifespan import combine_lifespans`; `lifespan=combine_lifespans(app_lifespan, mcp_app.lifespan)` | `docs/servers/lifespan.mdx` |
| Middleware (policy host) | `from fastmcp.server.middleware import Middleware, MiddlewareContext`; `async def on_call_tool(self, context, call_next): result = await call_next(context); …; return result` — `context.message.name`/`.arguments` available | `docs/servers/middleware.mdx` |
| Mutate output in middleware | `result.structured_content[...] = …` **and** `result.content` are both reachable/mutable after `call_next` | `docs/servers/middleware.mdx` (`ResponseEnricher`) |
| ToolResult | `ToolResult(content=…, structured_content={…}, meta={…})`; **"if only `structured_content` is provided it is also used as `content` (JSON string)"** | `docs/servers/tools.mdx` |
| Namespace transform | `from fastmcp.server.transforms import Namespace`; `mcp.add_transform(Namespace("api"))` → `api_greet` | `docs/servers/transforms/namespace.mdx` |
| Visibility (session-scoped) | tag tools `@server.tool(tags={"namespace:x"})`; `server.disable(tags={…})`; `await ctx.enable_components(tags={…})` enables **for that session only**; `ctx.reset_visibility()` | `docs/servers/visibility.mdx` |
| ToolSearch | `mcp.add_transform(RegexSearchTransform(always_visible=["help","status"]))` → list becomes `search_tools`+`call_tool`+pinned | `docs/servers/transforms/tool-search.mdx` |
| combine_lifespans import | `from fastmcp.utilities.lifespan import combine_lifespans`; enters in order, exits LIFO; later overrides earlier on key conflict | full-docs `:9253-9279` |
| Custom-token auth | `FastMCP(..., auth=<TokenVerifier>)`; `StaticTokenVerifier(tokens={…})` or **subclass `TokenVerifier`** for a hash-only store (no OAuth endpoints). Auth rejects at transport level **before** middleware; read principal via `get_access_token()`/`CurrentAccessToken()` → `AccessToken(token, client_id, scopes, expires_at, claims)`. Sync or async. HTTP-only. | full-docs `:5207-5221`, `:13764-13911` |
| Per-token tool authz | component `@mcp.tool(auth=require_scopes("x"))` / `restrict_tag(…)` / custom `(AuthContext)->bool` (sees `ctx.token.scopes` + `ctx.component`) governs **both** list-visibility and execution; server-wide `AuthMiddleware(auth=…)`; session-scoped `ctx.enable_components(tags=…)`. Applies to proxied tools too (`:18550`). | full-docs `:13779-13985`, `:24641-24787` |
| Custom routes not auth'd | `@mcp.custom_route` is **never** behind the server auth middleware (health-check by design); for authed HTTP-alongside-MCP use FastAPI `Depends()` | full-docs `:4656-4658`, `:9097-9133` |
| CORS / extra middleware | do **not** app-wide-`CORSMiddleware` an OAuth-protected mount (sub-app pattern); pass Starlette middleware via `mcp.http_app(middleware=[…])` | full-docs `:9247-9251`, `:4688-4739` |

**Must re-confirm against the installed wheel in Build** (exact import paths /
constructor kwargs can differ between v3.2.x docs and 3.4.2): the `create_proxy`
import path, whether `Middleware.on_call_tool` fires for **proxied** (ProxyProvider)
tools (F-6), and the `ResponseGuardMiddleware` access to the final `ToolResult` for
proxied tools. The D27a remediation already verified standalone-FastMCP-3 facts this
way (Run 21, M1) — same discipline.

---

## 5. B-3 design — response guard scans `structured_content` (the gate)

**Requirement (F-3 → B-3):** the response guard must scan and redact
`ToolResult.structured_content` (secret redaction **and** the size cap), not only
text. Hard acceptance gate; `/security-review` mandatory. D27b review cannot start
until this is implemented (charter Run 21 note; CLAUDE.md).

**Single redaction point (folds B-6).** Consolidate today's per-backend envelope
builders and the gateway text path into **one** `guard_tool_result(result:
ToolResult, *, override_active, case_dir, tool_name, cap_bytes) -> (ToolResult,
findings, cap_events)` in `response_guard.py`, called only from
`ResponseGuardMiddleware`. This is the single place B-3 redaction and any future
`ResultMeta` change apply (B-6, B-7).

**Algorithm (order matters):**
1. **Redact text blocks**: for each `TextContent` in `result.content`, run the
   existing `redact_tool_result(text, override_active=…)`.
2. **Redact structured**: walk `result.structured_content` recursively over **all**
   nested values (dict values, list items, scalars) — in fastmcp 3.4.2
   `structured_content` is a `dict | None`, but its values are arbitrary JSON, so the
   walker must descend lists/scalars, not just top-level keys. Serialize each leaf
   string through the same `_PATTERNS`/`_REDACT_SEVERITIES` scanner; replace
   critical+high matches with `[REDACTED:{name}]`. Redaction operates on the **string
   values**, preserving dict shape so the typed `anyOf[success, ToolError]` output
   schema (M2) still validates. Accumulate findings for the audit line. **Bound the
   recursion depth** (DoS guard against pathological nesting) and never dereference
   external `$ref` in any tool-supplied schema. (Forward-compat note: a later MCP spec
   RC widens `structuredContent` to *any* JSON value, not only objects — the recursive
   walker already handles that; flagged so a future fastmcp bump doesn't reopen B-3.)
3. **Coupling hazard (grounded, §4):** because FastMCP uses `structured_content` as
   `content` when content is absent, and many D27a tools populate both, redaction
   that touches only one field leaves the secret in the other. `guard_tool_result`
   **must** redact both fields in the same pass; a parity test asserts a secret
   seeded into `structured_content` only is absent from *both* the serialized
   `content` and `structured_content` of the returned result.
4. **Cap after redact** (redact-then-cap invariant): apply the byte cap to the
   serialized whole (text + structured) using `output_cap_bytes()` + the existing
   disk-spill (`_spill_full_output`), so the central ceiling still holds and a secret
   never straddles the truncation boundary. Decide cap accounting for structured
   output (cap the JSON-serialized structured block; spill the full pre-cap result).
5. **Override / audit** unchanged: `is_override_active(case_dir)` suppresses
   redaction but still records findings; emit `gateway_response_guard` +
   `gateway_output_cap` audit lines and the `_sift_context` note exactly as today.

**B-9 nits to fold while here (single redactor):** the redactor is exact-pattern,
not exact-key — fine for structured walking; keep the `SIFT_ARCHIVE_PASSWORD`-style
note (no live leak, legacy audit curates params) but the structured walk closes that
class generally.

---

## 6. Parity-test strategy (the gate is POLICY parity, not tool surface)

Per D27b: the tool surface is intentionally new (D27a) and is **not** re-frozen. The
parity assertion is **policy behavior byte-stability** across the substrate swap. The
build adds a `tests/test_policy_parity_d27b.py` contract suite that pins, against
both the current (pre-cutover) and new (post-cutover) servers where feasible:

1. **Evidence gate**: UNSEALED and each non-OK `ChainStatus` → block-all; the
   `build_block_response` JSON shape + the `gateway_evidence_gate` audit line are
   byte-stable. (Extends `test_evidence_gate.py`.)
2. **Response guard + B-3**: every `_PATTERNS` severity behaves as today on text;
   **new** — a secret in `structured_content` is redacted in both fields; medium =
   flagged-not-redacted; override path; the `_sift_context` shape. (Extends
   `test_response_guard.py`.)
3. **Output cap**: redact-then-cap; disk-spill pointer + sha256; structured-output
   accounting. 
4. **Audit envelope**: one `gateway_mcp_envelope` per call; `_block_audited`
   suppression; identity stamping (principal/type/agent_id/created_by/auth_surface),
   `backend_audit_id` linkage, hash-only token fingerprint. (Extends
   `test_audit_envelope.py`.)
5. **Active-case propagation**: `SIFT_CASE_DIR` → backend env / case context; portal
   case-activation restart hook (`_on_case_activated`) still fires.
6. **Auth/authz**: token_registry-first then `api_keys` fallback; readonly blocked
   from MCP; agent blocked from portal API; per-examiner + IP rate-limit; 10 MB
   request cap; Origin allow-list. (Extends `test_phase4/5/6`, `test_phase13_auth`,
   `test_portal_agent_block`, `test_secure_headers`.)
7. **ProxyProvider policy coverage (F-6)**: a proxied add-on tool call passes through
   the same four middlewares (gate, guard, case-context, audit) as an in-process
   core tool — asserted by seeding a secret in a proxied tool's `structured_content`
   and confirming redaction + envelope audit.

**Definition of Done additions for D27b:** all ~1146 package tests green on host
**and** on the SIFT VM (AGENTS.md path); the new parity suite green; `/code-review`;
`/security-review` (mandatory — auth, tokens, evidence gate, response redaction,
gateway policy path all touched); `validate_migration_docs.py`. If policy parity
cannot be met, the branch is abandoned (D27b revert plan) — no partial cutover.

---

## 7. Backlog touched here (carry from REGISTER.md)
- **B-3** — implemented by §5 (the gate). Marked DONE at Run 24 Land.
- **B-6** — `guard_tool_result` single envelope/redaction point (§3.4, §5).
  Marked DONE at Run 24 Land.
- **B-5** — `opensearch_case_detections_resource` ignores `case_id`: the cutover
  wires session→active-case; fix the resource scoping here or confirm it stays masked
  by D4 single-active-case and re-defer. (Decide in Build; if code lives in
  `packages/opensearch-mcp/**` it is **out of this scope fence** → keep as B-5, do
  not silently expand scope.)
- **B-7** — OpenSearch `ResultMeta` parity: only relevant once the single
  `guard_tool_result`/`ResultMeta` point exists; if it requires backend edits it is
  out of fence → stays B-7 (re-deferred at Run 24).
- **B-1/B-2** — alias removals are explicitly **at/after** D27b and touch
  `packages/*-mcp/**` → out of fence; not done here.

---

## 8. Acceptance gates (Land is verified against this)
```
[ ] Scope fence held: git diff --stat touches only sift-gateway/**, its tests,
    pyproject.toml, uv.lock, docs/migration/** (no packages/*-mcp, case-dashboard,
    supabase, sift-core)
[ ] fastmcp>=3 added to sift-gateway pyproject; uv.lock pin recorded in STATE
[ ] Aggregate /mcp served by FastMCP http_app; core=LocalProvider, add-ons=ProxyProvider
[ ] Policy is FastMCP Middleware (gate→guard→case-context→audit), proven to wrap
    proxied tools (F-6 parity test green)
[ ] B-3: structured_content redacted+capped in both fields, recursive over nested JSON
    with bounded depth + no external $ref deref (single guard_tool_result; B-6)
[ ] Per-backend /mcp/{name} routes removed (F-7) — no policy-bypass surface remains
[ ] D-1: token auth via SiftTokenVerifier(TokenVerifier) over token_registry; connection
    guards (rate-limit/size/Origin/readonly) kept SSE-safe; auth parity tests green
[ ] D-2: SSRF egress guard on proxied-backend fetches + OAuth-metadata (block private/
    link-local ranges, no redirect-follow); no agent-token passthrough to backends
[ ] D-3: unary-tool-results invariant asserted (guard materializes the full ToolResult)
[ ] B-11: active-case reaches proxied backends (args/result/shared store, not parent ctx)
[ ] Policy-parity suite green (evidence gate, guard, cap, audit envelope, active-case,
    authz) host AND VM; all ~1146 tests green
[ ] /code-review + /security-review run; findings fixed or triaged
[ ] F-7/F-8/F-9/F-10/F-12 resolved (Run 22); F-11 deferred; F-6 grounded (spike proves
    middleware wraps proxied tools, or the guard-shim fallback is in place) before design freeze
[ ] Charter unchanged unless a decision was approved this cycle; STATE Run entry added
[ ] validate_migration_docs.py passes
```

---

## 9. Risks / forks (→ REGISTER.md)

**Status after Run 22 operator review:** F-7, F-8, F-9, F-10, F-12 **resolved**; F-11
deferred to a later run; **F-6 is the one open, design-gating item** and is being
empirically grounded now.

- **F-6 — ProxyProvider policy coverage. RESOLVED: YES (grounded vs fastmcp 3.4.2).**
  Parent server-level `on_call_tool` middleware **does** fire for proxied tools
  mounted via `mcp.mount(create_proxy(...), namespace=…)`, and the parent sees + can
  mutate the proxy's final `ToolResult`. Verbatim doc evidence: *"Parent middleware
  runs for all requests, including those routed to mounted servers"*
  (`fastmcp-full-docs.txt:16103-16125`); `create_proxy()` is a mount
  (`:14166-14180`); *"per-session visibility, auth, and transforms are still applied
  after cache lookup by the server layer"* (`:18550`). The gateway-as-policy-boundary
  design holds for add-ons. **Two caveats carried into Build:** (a) middleware/session
  state does **not** cross the mount boundary — active-case propagation to proxied
  backends must use the call args/result path or a shared `session_state_store`, not
  parent `ctx.set_state` (→ **B-11**); (b) no verbatim guarantee of byte-exact
  `structured_content`/`meta` pass-through *through* the proxy (it follows from full
  MCP-protocol forwarding) — **assert it in an in-memory proxy test** at Build. Also
  noted: each proxied `call_tool` adds ~200–500 ms latency vs ~1–2 ms in-process.
- **F-7 — Drop per-backend `/mcp/{name}` routes. RESOLVED: DROP.** They run no
  evidence gate and no response guard today (§1) — a live policy bypass. Removed in
  this PR; firmed into charter **D3**. No client uses a per-backend path.
- **F-8 — FastAPI vs Starlette. RESOLVED: adopt FastAPI now.** One FastAPI app is
  also the entry point for the React operator portal/dashboard (REST + MCP under one
  ASGI app); brought in now for efficiency (honors D24). Sub **F-8b: keep** the
  raw-ASGI `MCPAuthASGIApp` token auth around the MCP mount (SSE-safe) — not a
  FastAPI dependency on the streaming path.
- **F-9 — Per-case/per-phase/per-role Visibility + ToolSearch. RESOLVED: DROP.** Not
  pursued. The one capability worth keeping is **per-agent-token tool authorization**
  (restrict which tools a generated AI-agent MCP token may call, for benchmarking/
  testing tool updates) → backlog **B-10**. Note: `app.mcp_token_scopes` +
  `Identity.tool_scopes` already exist but default to `mcp:*` and are **not enforced**
  per-tool today; B-10 designs the scope grammar + enforcement (auth/jobs phase).
- **F-10 — `forensic-mcp` fate. RESOLVED: retired → core.** Stays in
  `_RETIRED_CORE_BACKENDS`; its tools/capabilities are in-process core
  (`LocalProvider`), no proxy entry.
- **F-11 — `gateway.yaml` vs `mcp_backends` registry. DEFERRED.** D22's `mcp_backends`
  table is unbuilt; D27b keeps reading `config["backends"]` (`gateway.yaml`). Re-point
  to the control-plane registry on a **separate later run** (tracked open in
  REGISTER.md F-11).
- **F-12 — REST `/api/v1/tools` response-guard asymmetry. RESOLVED: keep as is.** No
  redaction for human/examiner output; the asymmetry is **frozen in a parity test**.
  The response guard stays an agent-facing leak/bloat control only.

---

## 11. Run 22 grounding outcomes & hardening

Two grounding passes ran this session: an empirical FastMCP-3.4.2 pass (official MCP
server `gofastmcp.com/mcp` + local `fastmcp-full-docs.txt` grep) and a security
best-practices web-research pass (MCP spec + 2025–2026 CVEs/advisories). Outcomes:

**Confirmed (no design change):** F-6 holds (§9); the policy-as-middleware design,
the SIFT-owned-policy stance (D24), the dual-principal auth split, and the refusal of
`SupabaseProvider` OAuth (RFC 8707 audience gap) are all independently validated by
the MCP spec and provider-specific advisories.

**Folded into the design:** reject-before-`call_next` invariant (§3.3); cross-mount
state for active-case (→ B-11); B-3 recursive structured-content walk + depth bound +
no `$ref` deref (§5); the native `TokenVerifier`/per-token-authz mechanics (§4 table,
B-10).

**Hardening items to wire where D27b naturally touches them (carry as build tasks /
backlog, not silent):**
- **No token passthrough.** Proxied backends (OpenCTI, wintriage) must authenticate
  with their **own** credentials; the agent's bearer token is never forwarded
  downstream (MCP spec normative). Today's backend config already carries a per-backend
  `bearer_token` — preserve that boundary.
- **SSRF egress guard.** Any proxied/remote backend fetch + OAuth-metadata discovery
  must block private/link-local ranges (`169.254.169.254`, RFC1918, `::1`, `fc00::/7`)
  and not auto-follow redirects (live CVEs: Azure-MCP SSRF CVE-2026-26118; mcp-remote
  RCE CVE-2025-6514). **Decision (D-2 below):** scope this into D27b or a hardening run.
- **Tool-poisoning / schema re-validation.** ProxyProvider caches the remote component
  list (~300 s TTL); a backend that swaps a tool schema mid-session (CVE-2025-54136)
  could be masked. Bind tool-description length, strip zero-width/Unicode, re-validate
  the schema at invocation. The manifest contract (`validate_manifest_contract`) is the
  natural home.
- **Streaming vs redaction (D-3 below).** FastMCP middleware sees **complete** results,
  so B-3 redaction is sound for unary tool results but would buffer/break true SSE
  streaming. Our tools are unary today — **confirm and freeze that assumption**; if any
  tool ever streams, redaction must move to a chunk-aware layer.

**Design decisions locked (operator, 2026-06-07 Run 22):**
- **D-1 — token-auth mechanism → Option A.** Adopt a custom **`TokenVerifier`**
  subclass that validates the hash-only token against `token_registry` and exposes
  `scopes`/`claims` to the policy middleware (the clean home for B-10), with auth
  rejecting at the transport level before middleware. The **connection-level** guards
  (rate-limit, 10 MB size cap, Origin allow-list, per-examiner limit, readonly block)
  stay as raw-ASGI / `http_app(middleware=[…])` — SSE-safe (this is what F-8b was
  protecting; the *token-validation* slice moves to the verifier, the rest does not).
  Supersedes F-8b's "keep the whole wrapper". Touches the auth path →
  `/security-review` mandatory; frozen by the auth parity tests (§6.6).
- **D-2 — SSRF/egress hardening → in the D27b PR.** The proxy path is exactly what
  changes, so the egress guard lands with it: block private/link-local ranges
  (`169.254.169.254`, RFC1918, `::1`, `fc00::/7`) for any proxied-backend fetch +
  OAuth-metadata discovery, and do not auto-follow redirects. Add to §8 + a parity/
  security test.
- **D-3 — streaming policy → ratified: tool results are unary.** "All gateway tool
  results are complete (non-streaming); the response guard materializes the full
  `ToolResult` before redact-then-cap" is an explicit invariant. A future streaming
  tool must revisit B-3 (chunk-aware redaction) — a build that adds one **stops and
  raises a fork**, it does not stream past the guard.

## 10. Archived ready-to-copy build prompt

This prompt is retained as historical provenance for the landed D27b build. Do
not use it as a live next-run handoff.

```
ROLE & MODE: You are a Build-stage coding session for SIFT migration stage D27b
(gateway cutover to FastMCP 3.0). Implement ONLY what doc 17 declares. You do not
redefine scope; if the spec is wrong or the installed fastmcp 3.4.2 API differs from
doc 17 §4, STOP and raise a fork — do not improvise (D29).

REQUIRED READING (ordered): docs/migration/MIGRATION_STATE.md (Current Objective +
latest Run); docs/migration/17_gateway_cutover_d27b.md (this plan); 
docs/migration/14_fastmcp3_supabase_integration.md (design KB);
docs/migration/OPERATING_MODEL.md (loop, Definition of Done, §8 format contract);
00_migration_charter.md D2/D3/D8/D24/D26/D27b/D28; REGISTER.md (F-7/F-8/F-9/F-10/F-12
resolved Run 22; F-11 deferred; **F-6 must be grounded** — confirm middleware wraps
proxied tools or use the guard-shim fallback) + B-3/B-5/B-6/B-7/B-10; AGENTS.md
(host→VM test path).

GROUND IN SOURCE (don't design from memory): read every file named in doc 17 §1 and
§3 in packages/sift-gateway/src/sift_gateway/ before changing it. Re-confirm the
fastmcp 3.4.2 API (create_proxy import, Middleware.on_call_tool firing for proxied
tools, ToolResult.structured_content mutability post-call_next) against the INSTALLED
wheel, not the doc — record what you confirmed.

DELIVERABLE: the gateway served as one ASGI app via FastMCP http_app; core tools on
LocalProvider, add-ons via create_proxy+mount(namespace); SIFT policy re-hosted as
FastMCP Middleware (evidence gate → response guard(B-3) → case context → audit
envelope) proven to wrap proxied tools; B-3 structured_content redaction+cap in a
single guard_tool_result (folds B-6); per-backend /mcp/{name} routes removed (F-7);
the test_policy_parity_d27b.py suite (doc 17 §6).

HARD CONSTRAINTS: scope fence = doc 17 (sift-gateway/** + its tests + pyproject + 
uv.lock + docs/migration/**; NOTHING in packages/*-mcp, case-dashboard, supabase,
sift-core). One revertable PR. Policy stays SIFT-owned (D24); evidence immutability,
hash-only tokens (D8/D26), D5 write-tool behavior unchanged. No secrets in code,
tests, or fixtures.

OUTPUT DISCIPLINE: record the fastmcp pin in MIGRATION_STATE.md; update the golden
behavior via the parity suite (this stage freezes POLICY, not the tool surface); add
a STATE Run entry; resolve B-3/B-6 → DONE only at Land; make NO silent decisions.

ACCEPTANCE: doc 17 §8 checklist; all ~1146 tests + parity suite green on host AND VM;
/code-review + /security-review run. End by listing any forks needing the operator's
call.
```
