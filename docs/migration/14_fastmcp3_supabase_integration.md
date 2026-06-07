# 14 — FastMCP 3.0 + Supabase Integration (Knowledge Base & Target Design)

Status: **design locked** (decisions D24–D27 in `00_migration_charter.md`).
This document is the single knowledge base for the FastMCP 3.0 / Supabase /
FastAPI consolidation. It records the verified framework facts, the current-state
inventory, the target integration design, the per-package migration surface, and
the cutover plan. It does not change runtime behavior; it is the spec a future
scoped coding run implements.

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
- The real "too many tool schemas in context" problem is solved by **Tool Search
  + Visibility** (§2.2), not code-mode.

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

## 4. Current state vs target

### 4.1 What each package uses today (verified by source scan)

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

### 4.2 Target: the Gateway as one FastAPI app on FastMCP 3.0

```
                 ┌──────────────── one FastAPI ASGI app (single deploy) ────────────────┐
   Portal  ──►   │  REST  /api/v1/*        Supabase-JWT verify via FastAPI DI (humans)   │
   (React)       │  REST  /portal/*        + secure headers, HTTPS guard, CSP            │
                 │                                                                       │
   Agents  ──►   │  MCP   mcp.http_app("/mcp")   hash-only token auth (machines)         │
   (MCP)         │        └─ SIFT policy middleware: evidence gate, response guard,      │
                 │           audit envelope, active-case propagation, authorization      │
                 │        └─ FastMCP 3.0 providers + transforms (aggregation only):      │
                 │             ProxyProvider(opencti, wintriage)   ← add-on backends     │
                 │             LocalProvider(core OpenSearch/RAG/findings tools)         │
                 │             SkillsProvider(agent skills, D15)                         │
                 │             Namespace · Visibility(per case/phase/role) · ToolSearch  │
                 └───────────────────────────────────────────────────────────────────────┘
```

- **Policy stays SIFT-owned.** Providers/transforms do aggregation, namespacing,
  discovery, and visibility. The evidence gate, response redaction, audit
  envelope, active-case propagation, and authorization remain explicit
  middleware/checks (today's `evidence_gate.py`, `response_guard.py`,
  `audit_helpers.py`, `auth.py`) — re-hosted as FastMCP middleware / async auth
  checks, **not** delegated to the framework. (Reaffirms D2/D3.)
- **Provider mapping.**
  - Core tools (OpenSearch read/status/aggregate per D19, core RAG per D23,
    findings/timeline/IOCs/TODO) → `LocalProvider` (in-process, decorator style).
  - Add-on backends (`opencti-mcp`, `windows-triage-mcp`) → `ProxyProvider`,
    replacing `backends/{http,stdio}_backend.py`. Registration is read from the
    control-plane `mcp_backends` registry (D22), not `gateway.yaml`.
  - Agent skills (D15) → `SkillsProvider`.
- **Transform mapping.**
  - `Namespace` enforces the `name_` prefix per backend (formalizes today's
    manual manifest namespace check).
  - `Visibility` (session-scoped, async auth checks) implements **per-case /
    per-phase / per-role tool exposure** keyed off the active case + role matrix
    (`09_identity_auth_cutover.md` §5). This is the tool-layer expression of
    case-scope.
  - `ToolSearch` (BM25) controls tool-schema context bloat as the catalog grows
    (OpenCTI + future add-ons), `always_visible` for the always-on core set.
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

- **Stage 1 — D27a backend revamp** (`15_backend_tooling_revamp.md`): the three
  backend servers move to FastMCP 3.0 **and** are redesigned to the tool-quality
  contract (D28). Dedicated worktree, scoped to `packages/*-mcp/**`, **parallel to
  PR02**, merges before stage 2. Produces the **new tool-surface golden snapshot +
  change map**.
- **Stage 2 — D27b gateway cutover** (this doc): the Gateway moves to FastMCP 3.0
  as one FastAPI ASGI app, a **single revertable big-bang PR**, **after PR02 and
  after stage 1**, before the heavier evidence/jobs phases. It **consumes** the
  revamped backend surface (does not re-freeze it) — add-ons via `ProxyProvider`,
  opensearch tools in-process via `LocalProvider`.
- **Stage 2 parity gate = policy parity only:** all ~1146 package tests green +
  a policy-behavior contract test asserting the evidence gate, response-guard
  redaction, audit-envelope shape, and active-case propagation are byte-stable
  across the gateway swap. The **tool surface is intentionally new** (from stage
  1) and is therefore not part of the parity assertion.
- **Confirm:** structured-output redaction/size-cap coverage in the response guard
  (it must scan `structured_content`, not only text) — see `15` §11.
- **Revert plan:** each stage's branch is a clean checkpoint; if its gate cannot be
  met the branch is abandoned and the current stack continues — no partial cutover
  lands in `main`.

---

## 7. Open questions / risks

- **`ProxyProvider` policy coverage:** confirm the evidence gate + response guard
  + audit envelope wrap proxied add-on tools exactly as they wrap in-process core
  tools (the parity contract test must assert this for OpenCTI/wintriage).
- **Streamable-HTTP session semantics:** verify `mcp.http_app` session handling
  matches the current `StreamableHTTPSessionManager` behavior the portal/agents
  rely on (keep-alive, request size cap = 10 MB).
- **`forensic-mcp` future:** with findings/timeline folding toward core, decide
  whether it survives as a backend or its tools move to `LocalProvider` during the
  cutover.
- **Visibility ↔ active case wiring:** the session-scoped visibility check needs
  the active case + role at MCP-session establishment; confirm the token/identity
  context (PR02) exposes that to the async auth check.
- **Pin discipline:** record the exact `fastmcp` version in the cutover PR and in
  `MIGRATION_STATE.md`, like every other infra pin.

---

## 8. Decisions locked by this document

See `00_migration_charter.md` "Confirmed Decisions (Locked)":
- **D24** — FastMCP 3.0 is the MCP substrate; Gateway = one FastAPI app
  (REST + `mcp.http_app`); providers/transforms for aggregation only; policy stays
  SIFT-owned (reaffirms D2/D3).
- **D25** — `code-mode` excluded; `run_command` retained; context bloat solved by
  Tool Search + Visibility.
- **D26** — humans: own Supabase-JWT verify via FastAPI DI; machines: hash-only
  tokens; `SupabaseProvider` OAuth not adopted.
- **D27 / D27b** — staged cutover; this doc governs **D27b** (the gateway stage):
  a big-bang, **policy-parity-gated** PR after PR02 and after the backend revamp
  (**D27a**, governed by `15_backend_tooling_revamp.md`), before evidence/jobs.
  Tool-quality contract for backends is **D28**.

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
