# 14 — FastMCP 3.0 + Supabase Integration (Knowledge Base & Target Design)

Status: **design locked**; D27a and D27b are implemented and landed. Remaining
Supabase/Auth/control-plane phases use this as background, not as a pending
D27b build prompt.

Run 25 status note: sections that say "current state" are a **pre-D27a/D27b
snapshot** retained for design history. The current landed state is in
`00_migration_charter.md` Current Migration Status and `MIGRATION_STATE.md` Runs
23-24: FastAPI + FastMCP `http_app` is live, D27a backends are standalone
FastMCP 3.0, D27b removed per-backend MCP routes, add-ons still read from
`gateway.yaml` until F-11/D22, and per-role `Visibility`/`ToolSearch` was
dropped in favor of future SIFT-owned per-token tool authorization (B-10).

This document remains the knowledge base for the FastMCP 3.0 / Supabase /
FastAPI consolidation. It records the verified framework facts, the historical
pre-cutover inventory, the target integration design, the per-package migration
surface, and the cutover plan.

All claims about FastMCP 3.0 below are grounded in the official docs; see
**Sources** at the end. Where the marketing/AI summaries that seeded this work
were wrong, the corrections are called out explicitly (§3).

---

## 1. Why this exists

The operator asked whether the bespoke Gateway could be dropped and the
architecture simplified by leaning on FastMCP 3.0 + Supabase + the React portal.
The investigation produced two findings:

1. **The Gateway is not the MCP aggregator — it is the policy boundary.** FastMCP
   3.0 can replace the *aggregation/proxy/namespacing internals*, but the
   SIFT-specific policy (evidence gate, response redaction, audit envelope,
   active-case propagation, authorization) is domain logic no framework ships.
   So the Gateway is **retained**; FastMCP 3.0 becomes its implementation
   substrate. See §4.
2. **FastMCP 3.0 + FastAPI genuinely delivers the consolidation the operator
   wants** — one ASGI app serving the portal REST API (Supabase-JWT verified) and
   the agent MCP endpoint, with providers/transforms replacing hand-rolled
   backend plumbing. See §4–§5.

Decision: **go all-in on FastMCP 3.0 as the MCP substrate** (D24), with two
explicit exclusions (code-mode, SupabaseProvider OAuth) and one rollout style
(big-bang, parity-gated).

---

## 2. Verified FastMCP 3.0 facts

FastMCP 3.0 rebuilds the framework around three primitives: **components**
(tools/resources/prompts), **providers** (sources of components), and
**transforms** (middleware that modifies components as they flow to clients).

### 2.1 Providers
- `LocalProvider` — decorator-registered components (the classic style).
- `ProxyProvider` — proxies a remote MCP server via an MCP client; powers
  `mount()` (the `prefix` kwarg is renamed `namespace`).
- `OpenAPIProvider` — generates MCP components from an OpenAPI spec.
- `FileSystemProvider` — auto-discovers decorated functions in a directory (hot
  reload).
- `SkillsProvider` — exposes agent skill directories as resources.
- Providers support `async def lifespan()` for DB connections / external clients —
  something a low-level `mcp.server.Server` must hand-code.

### 2.2 Transforms (attach at provider-level then server-level; stack
inner→outer)
- **Namespace** — name prefixes + URI path segments to prevent collisions.
- **ToolTransform** — rename, re-describe, reshape arguments / schema.
- **Visibility / Enabled** — enable/disable components by name, tag, or version;
  `mcp.enable(tags={...}, only=True)` is allowlist mode. **Session-scoped**, with
  **async auth checks** — i.e. per-client/per-auth tool exposure.
- **Tool Search** — replaces a large `list_tools()` catalog with two synthetic
  tools, `search_tools` (regex or BM25 ranking over names/descriptions/params,
  returns full JSON schema) and `call_tool`. Controls *discovery, not access*:
  hidden/unauthorized tools never appear and stay inaccessible. Config:
  `max_results` (default 5), `always_visible`, custom synthetic-tool names.
- **ResourcesAsTools / PromptsAsTools** — expose non-tool components to tool-only
  clients.
- **Code Mode** — programmable search/execute over many tools. **Excluded — see
  §3.1.**

Run 25 note: these are framework capabilities, not active D27b decisions.
F-9 dropped per-case/per-phase/per-role `Visibility` and `ToolSearch` for the
D27b parity PR. Per-token tool authorization is tracked as B-10 and must remain
SIFT-owned if implemented.

### 2.3 Other relevant capabilities
- **Component versioning** — multiple versions coexist; highest exposed by
  default; clients can request a specific version.
- **Result objects** — `ToolResult(content=…, structured_content=…, meta=…)` for
  typed, structured responses (plain returns still work).
- **Concurrent tool execution** — multiple tool calls in one sampling response can
  run concurrently (`tool_concurrency`).
- **Auth token injection / DI** — `CurrentAccessToken`, Azure OBO, async auth
  checks.

### 2.4 FastAPI integration (the consolidation mechanism)
- `mcp.http_app(path="/mcp")` returns an ASGI app you `app.mount(...)` into
  FastAPI, **or** combine routes into one app.
- Lifespans **must** be combined: `combine_lifespans(app_lifespan, mcp_app.lifespan)`.
- REST routes authenticate with **FastAPI dependency injection** (verify Supabase
  JWT per request); the MCP side authenticates independently. The two auth paths
  do not cross-contaminate.
- Caveat: **do not** add app-wide CORS middleware when mounting OAuth-protected
  MCP; FastMCP manages its own CORS for OAuth routes.

---

## 3. Corrections to the seeding assumptions (read before designing)

### 3.1 `code-mode` is NOT a `run_command` replacement — EXCLUDED (D25)
Per the official doc, code-mode is an **experimental** token-optimization
transform: the LLM writes **arbitrary Python** in a sandbox
(`MontySandboxProvider`, 30s/100MB/50-call default caps) whose only capability is
`await call_tool(...)`. The doc states plainly it is *"not ideal for strict
command-execution boundaries requiring pre-audited allowlists … you cannot
pre-audit the exact execution path."*

Implications for SIFT:
- It sits **above** tools (orchestration), it does not replace `run_command`
  (a hardened, allowlisted, audited OS-exec **tool**).
- It would **expand** agent latitude to arbitrary generated Python — the opposite
  of the locked "shell-free, allowlisted, case-jailed" sandbox principle.
- It does **not** fix `run_command`'s actual flakiness, whose root causes are
  Gateway argv/flex handling (pipe/redirect/stderr not reachable → literal argv →
  context bloat), the `evidence/` write-gap, and the missing OS-level sandbox.
  Those are fixed directly, independently of this migration.
- The real "too many tool schemas in context" problem is solved by curated
  descriptions, manifest-derived `capability_guide`, and future SIFT-owned
  list/call authorization where needed, not code-mode. Run 22/F-9 dropped
  `ToolSearch`/`Visibility` from the D27b design.

### 3.2 `SupabaseProvider` is human-OAuth only — NOT adopted (D26)
FastMCP's `SupabaseProvider` is a **Remote OAuth** resource-server validator
(browser flow → Supabase → a consent UI you must self-host). Two blocking caveats:
- *"Supabase Auth does not currently support RFC 8707 resource indicators, so
  FastMCP cannot validate that tokens were issued for the specific resource
  server."* (no audience binding)
- The integration says **nothing** about service/machine/non-interactive
  principals; a headless agent cannot perform the browser flow.

Therefore SIFT keeps:
- **Humans/portal** → verify Supabase JWTs directly via **FastAPI dependency
  injection** on REST routes (supabase-py + DI). No SupabaseProvider, no
  self-hosted consent UI.
- **Agents/workers/services** → **hash-only Gateway-issued tokens** validated
  against the Postgres registry (reaffirms D8).
- Gateway-side authorization (active case, case membership, tool scope) stays
  mandatory regardless of token type — never delegated to an OAuth audience.

---

## 4. Pre-D27a/D27b state vs target

The table below is a historical source scan from before D27a/D27b. It is useful
for why the cutover happened, but it is no longer the live package state.

### 4.1 What each package used before D27a/D27b (verified by source scan then)

| Package | MCP surface today | Notes |
| --- | --- | --- |
| `sift-gateway` | low-level `mcp.server.lowlevel.Server` + `StreamableHTTPSessionManager`, Starlette, client sessions | Hand-rolled aggregation in `server.py`, `backends/{http,stdio}_backend.py`. The diagram label "FastMCP" was aspirational. |
| `opensearch-mcp` | in-SDK **FastMCP 1.x** (`from mcp.server.fastmcp import FastMCP`) | Decorator-style tools. |
| `forensic-rag-mcp` | in-SDK **FastMCP 1.x** | Folding into core per D23. |
| `forensic-mcp` | in-SDK **FastMCP 1.x** | Investigation-state tools. |
| `opencti-mcp` | low-level `mcp.server.Server` | Query-only API client (D20). |
| `windows-triage-mcp` | low-level `mcp.server.Server` | Minimal query-only add-on (D23). |

Key fact: every package pins `mcp>=1.26` (the official SDK). **No package depends
on the standalone `fastmcp` package today.** The in-SDK `mcp.server.fastmcp` is
FastMCP **1.x lineage**, frozen; it has none of the 3.0 providers/transforms.
Adopting 3.0 is a **net-new dependency**, not an import swap.

### 4.2 Target implemented by D27b: the Gateway as one FastAPI app on FastMCP 3.0

```
                 ┌──────────────── one FastAPI ASGI app (single deploy) ────────────────┐
   Portal  ──►   │  REST  /api/v1/*        Supabase-JWT verify via FastAPI DI (humans)   │
   (React)       │  REST  /portal/*        + secure headers, HTTPS guard, CSP            │
                 │                                                                       │
   Agents  ──►   │  MCP   mcp.http_app("/mcp")   hash-only token auth (machines)         │
   (MCP)         │        └─ SIFT policy middleware: evidence gate, response guard,      │
                 │           audit envelope, active-case propagation, authorization      │
                 │        └─ FastMCP 3.0 providers + transforms (aggregation only):      │
                 │             ProxyProvider(add-ons from gateway.yaml until F-11/D22)   │
                 │             LocalProvider(core gateway tools)                         │
                 │             Namespace only unless a later scoped run adds more        │
                 └───────────────────────────────────────────────────────────────────────┘
```

- **Policy stays SIFT-owned.** Providers/transforms do aggregation, namespacing,
  and catalog mechanics. The evidence gate, response redaction, audit
  envelope, active-case propagation, and authorization remain explicit
  middleware/checks (today's `evidence_gate.py`, `response_guard.py`,
  `audit_helpers.py`, `auth.py`) — re-hosted as FastMCP middleware / async auth
  checks, **not** delegated to the framework. (Reaffirms D2/D3.)
- **Provider mapping.**
  - Core tools (OpenSearch read/status/aggregate per D19, core RAG per D23,
    findings/timeline/IOCs/TODO) → `LocalProvider` (in-process, decorator style).
  - Add-on backends (`opencti-mcp`, `windows-triage-mcp`, and OpenSearch until
    its later D19 core move) → proxy mounts. D27b kept registration in
    `gateway.yaml`; the control-plane `mcp_backends` registry is deferred to
    F-11/D22.
  - Agent skills (D15) → deferred.
- **Transform mapping.**
  - `Namespace` enforces the `name_` prefix per backend (formalizes today's
    manual manifest namespace check).
  - Per-case/per-phase/per-role `Visibility` and `ToolSearch` were investigated
    but explicitly dropped for D27b (F-9). Per-token tool authorization is B-10
    and remains SIFT-owned if implemented later.
- **`run_command` is unchanged** by this migration (D25): still the hardened,
  allowlisted, audited OS-exec tool; its flakiness is a separate, tracked fix.

### 4.3 Auth model (target)

| Principal | Mechanism | Where |
| --- | --- | --- |
| Human operator | Supabase JWT, verified via **FastAPI DI** on REST routes | portal/REST |
| AI agent / MCP client | **hash-only** Gateway-issued token, Postgres registry (D8) | MCP endpoint |
| Worker / service | hash-only service token (D8) | internal |

Authorization (active case, case membership, tool scope, evidence gate) is applied
**after** authentication, by the Gateway, for every principal. No OAuth audience is
trusted for resource scoping (RFC 8707 gap, §3.2).

---

## 5. Migration surface (per package)

Standalone FastMCP 3.0 has real breaking changes from the in-SDK 1.x style. The
three FastMCP backends each need:
- Decorators no longer return component objects → set
  `FASTMCP_DECORATOR_MODE=object` to bridge, or adapt call sites.
- State becomes async + session-scoped → `await ctx.get_state(...)`.
- Plural lookups renamed → `get_tools()` → `list_tools()` (returns lists).
- Constructor transport args moved to runtime → `mcp.run(transport="http", …)`.

The Gateway is the larger change: replace `server.py` aggregation +
`backends/*.py` with providers/transforms, mount `mcp.http_app()` into the FastAPI
app, and re-host the policy middleware. `opencti-mcp` / `windows-triage-mcp` may
stay as external MCP servers fronted by `ProxyProvider` (least churn), or be
pulled in-process later.

---

## 6. Cutover plan — staged (D27 → D27a + D27b)

The original "single big-bang PR (gateway + backends together)" framing is
**superseded** by a two-stage plan, because the gateway↔backend boundary is the
MCP wire protocol and backends can move independently. This document (14) governs
**stage 2 (the gateway)**; `15_backend_tooling_revamp.md` governs **stage 1 (the
backends)**.

- **Stage 1 — D27a backend revamp** (`15_backend_tooling_revamp.md`): done. The three
  backend servers moved to FastMCP 3.0 **and** were redesigned to the tool-quality
  contract (D28). Dedicated worktree, scoped to `packages/*-mcp/**`, **parallel to
  PR02**, merged before stage 2. Produced the **new tool-surface golden snapshot +
  change map**.
- **Stage 2 — D27b gateway cutover** (`17_gateway_cutover_d27b.md`): done. The Gateway
  moved to FastMCP 3.0 as one FastAPI ASGI app after PR02 and D27a, before the
  heavier evidence/jobs phases. It consumed the revamped backend surface without
  re-freezing it; add-ons are proxy-mounted from current `gateway.yaml`
  configuration until F-11/D22. OpenSearch's final core/in-process move remains
  a later D19/OpenSearch-core phase.
- **Stage 2 parity gate = policy parity only:** gateway package tests green +
  a policy-behavior contract test asserting the evidence gate, response-guard
  redaction, audit-envelope shape, and active-case propagation are byte-stable
  across the gateway swap. The **tool surface is intentionally new** (from stage
  1) and is therefore not part of the parity assertion.
- **Confirmed:** structured-output redaction/size-cap coverage in the response guard
  scans `structured_content`, not only text (B-3 DONE at Run 24).
- **Revert plan:** each stage's branch is a clean checkpoint; if its gate cannot be
  met the branch is abandoned and the current stack continues — no partial cutover
  lands in `main`.

---

## 7. Open questions / risks

- **`ProxyProvider` policy coverage:** confirm the evidence gate + response guard
  + audit envelope wrap proxied add-on tools exactly as they wrap in-process core
  tools (the parity contract test must assert this for OpenCTI/wintriage).
- **Streamable-HTTP session semantics:** D27b verified `mcp.http_app` integration
  and preserved the raw-ASGI request-size/auth guard.
- **`forensic-mcp` future:** resolved by D27b/F-10; its capabilities are core,
  not a proxy add-on.
- **Per-token tool authorization:** tracked as B-10, implemented SIFT-side in a
  later auth/jobs phase if prioritized.
- **Pin discipline:** D27b recorded `fastmcp==3.4.2` in `MIGRATION_STATE.md`.

---

## 8. Decisions locked by this document

See `00_migration_charter.md` "Confirmed Decisions (Locked)":
- **D24** — FastMCP 3.0 is the MCP substrate; Gateway = one FastAPI app
  (REST + `mcp.http_app`); providers/transforms for aggregation only; policy stays
  SIFT-owned (reaffirms D2/D3).
- **D25** — `code-mode` excluded; `run_command` retained; context bloat is not
  solved by FastMCP code-mode. `ToolSearch`/`Visibility` are not active D27b
  design elements after F-9.
- **D26** — humans: own Supabase-JWT verify via FastAPI DI; machines: hash-only
  tokens; `SupabaseProvider` OAuth not adopted.
- **D27 / D27b** — staged cutover; D27a and D27b are landed. Tool-quality
  contract for backends is **D28**.

---

## Sources

- FastMCP 3.0 — what's new / v3 features: <https://jlowin.dev/blog/fastmcp-3-whats-new>, <https://github.com/PrefectHQ/fastmcp/blob/main/docs/development/v3-notes/v3-features.mdx>
- Transforms (model + list): <https://gofastmcp.com/servers/transforms/transforms>
- Namespace: <https://gofastmcp.com/servers/transforms/namespace>
- Tool Search: <https://gofastmcp.com/servers/transforms/tool-search>
- Code Mode (excluded): <https://gofastmcp.com/servers/transforms/code-mode>
- Visibility: <https://gofastmcp.com/servers/visibility>
- Resources / Prompts-as-tools: <https://gofastmcp.com/servers/resources>, <https://gofastmcp.com/servers/transforms/prompts-as-tools>
- FastAPI integration: <https://github.com/PrefectHQ/fastmcp/blob/main/docs/integrations/fastapi.mdx>
- Supabase integration (human OAuth; not adopted): <https://gofastmcp.com/integrations/supabase>
- Supabase REST/auth (FastAPI DI pattern): <https://supabase.com/docs/guides/api/creating-routes>
- Client transports: <https://gofastmcp.com/clients/transports>
- Schema: <https://github.com/PrefectHQ/fastmcp/blob/main/docs/public/schemas/fastmcp.json/latest.json>
