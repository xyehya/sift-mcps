## PURPOSE

Protocol SIFT Gateway is a governed DFIR platform for autonomous agents on SANS SIFT: one single-policy-boundary gateway; humans keep authority over evidence/approvals/credentials/reports. Agents reach tools only via `/mcp` (Supabase JWT); humans via `/portal`. This ADR is the **session entry point** — dense invariants + pointers. Prefer it over crawling the monorepo.

**Visual SoT for multi-layer security / defense-in-depth:** `docs/drafts/architecture/sift-architecture.html` (VP-1..VP-5). Text twin: `docs/architecture/SIFT-GATEWAY-SECURITY-MODEL.md`. Code wins on conflict — flag drift. Ops queue: `~/AI/sift-portal-ops/STATUS.md` + `trackers/MASTER_TRACKER.md`.

**`run_command` is simultaneously the critical capability layer and the highest-risk layer** for autonomous DFIR: it is how the agent runs forensic binaries on the SIFT VM against sealed case artifacts/evidence. Without it, agentic investigation is hollow; without its jail, the agent is an uncontained remote executor on evidence. Preserve and prove that hardening on **every** change that touches execution.

## STACK

- **Language**: Python 3.12 monorepo (`uv`); portal React 19 + Vite 8 + Tailwind v4 + shadcn.
- **Gateway**: Starlette/FastMCP (`sift-gateway`) — auth, 10-stage MCP policy chain, REST, backend proxy.
- **Control plane (AUTHORITATIVE)**: Supabase/Postgres 15, `FORCE RLS` on `app.*`, append-only audit/custody/approval, durable jobs. Writes land here under RLS — never in the derived index.
- **Data plane (DERIVED, never SoR)**: OpenSearch — case-scoped `case-*` (+ gated `opencti_*` only under dedicated role, never via case-search). Rebuildable projection with provenance.
- **Execution / `run_command`**: MCP tool in `sift-core` → durable job → `sift-job-worker` → `agent_runtime` uid on SIFT VM (`shell=False`, argv stages). Code: `sift_core/execute/` (`security.py` ceiling, `dfir_exec_launcher.py` floor).
- **Workers**: `sift-job-worker` (`run_command`); `sift-opensearch-worker@` (ingest/enrich, FUSE-capable).
- **Add-ons (stdio)**: `opensearch-mcp`, `forensic-rag-mcp` (pgvector/Qwen), `opencti-mcp` (query-only), `windows-triage-mcp`, `forensic-knowledge`.
- **Shared**: `sift-common`. **Runtime jail**: AppArmor `dfir-exec` + Landlock v4 + seccomp=KILL + cgroup + no-new-privs. Proof VM: `ssh sift-vm`; tunnel `https://localhost:4508`.

## ARCHITECTURE

**Eight planes, one gold gate** (HTML VP-2): Client → **Gateway** → Core tools / add-ons → **Postgres (truth)** / **OpenSearch (derived)** / **sandboxed execution** / evidence vault. Color encodes plane authority.

**Packages:** `sift-gateway` · `sift-core` (tools, evidence chain, **`run_command` jail**) · `case-dashboard` · `opensearch-mcp` · RAG/knowledge · opencti/wintriage · `supabase/migrations`.

**Auth:** MCP = Supabase JWT only (SEC-6; outage → 503). Portal = HMAC session + step-up re-verify on privileged actions.

**VP-3 policy chain** (fail-closed; identity first): ControlPlaneRequired → ToolAuthorization → AddonAuthority → CaseContext → AuditEnvelope → ProxyActiveCase → **EvidenceGate** (registered+sealed+chain OK — prerequisite before any `run_command` on case evidence) → ResponseGuard → IngestStatusAugment → OpenSearchJobDispatch → tool body. Live code may add stages beyond design “9” — verify `policy_middleware.py` / `mcp_server.py`.

**VP-4 STRIDE:** Critical **#2** evidence immutability and **#6** untrusted-output (`ResponseGuard`). **#3** (worker→OS jail) is the `run_command` risk boundary — elevation/DoS/tamper if the floor fails. Also #1 JWT/scopes; #4 Postgres/`FORCE RLS`; #5 derived OpenSearch; #7 operator step-up.

**`run_command` — critical + risk (VP-5):** Agent-facing MCP tool that executes forensic commands over artifacts/evidence on the SIFT VM. **Critical:** enables autonomous DFIR (timeline, carve, parse, hash, registry, memory tools in `@mvp_forensic`). **Risk:** host-side code execution with evidence-path visibility — largest agent blast radius in the system. **Ceiling** (intent): allowlist `@mvp_forensic`, `unlisted_policy=reject`, deny shells/interpreters/launcher smuggling, block cross-case/`/var/lib/sift`. **Floor** (capability): `agent_runtime` fail-closed · Landlock RO case/evidence only · seccomp=KILL · AppArmor enforce · cgroup MemoryMax/TasksMax · `IPAddressDeny=any` · no-new-privs. Deny-default on both. Output is untrusted → ResponseGuard. Jobs: enqueue → claim `FOR UPDATE SKIP LOCKED` → path-free `result_public`.

**Authority:** `app.active_case_state` sole active case; reports APPROVED-only; agent backends **no DB creds**.

**Read next:** `sift-architecture.html` (esp. VP-5) → SECURITY-MODEL.md VP-5 → `docs/latest/02 - Core Tools.md` → `DEVELOPER_ENTRYPOINT.md` → `docs/latest/` 00–18.

## PATTERNS

1. **Never weaken `run_command` hardening for convenience.** Changes to allowlist, `security.py`, launcher, AppArmor, seccomp, Landlock grants, cgroup, runtime-user, or worker env-scrub require explicit threat rationale + negative/red-team proof. Expanding tools ≠ loosening the jail. Prefer adding a narrowly allowlisted wrapper over opening interpreters/network/FS.
2. **Surfacing (#1 agent bug):** land on `*Out` + `result_public` + DB-authority path. Guard: `sift_common.testing.surface`.
3. **Code wins over design/HTML** — flag drift.
4. **Green test ≠ live proof** — VM deploy-and-prove after execution-path changes. Runbooks: `RUN-PORTAL-V3-VM-DEPLOY.md` / `RUN-PORTAL-V3-VM-TEST.md`.
5. **Durable jobs** for `run_command`/ingest/enrich; `result_public` path-free.
6. **No second door** — all privileged flows (including exec) cross the gateway gold band + EvidenceGate.
7. **Discovery:** index → this ADR → graph tools; `rg` if MCP missing.
8. **Security claims need reachability proof** — for `run_command`: tool → gates → argv → worker → OS jail footprint.

## TRADEOFFS

- **Autonomous DFIR needs `run_command`; safety needs the stacked jail.** Capability without jail = uncontained agent on evidence; jail without capability = useless agent. Default bias: keep capability, never trade away floor/ceiling.
- **Single gateway** vs per-backend `/mcp` — one STRIDE story.
- **Postgres authoritative / OpenSearch derived** — never trust OS as SoR.
- **Stacked ceiling+floor** — policy can be wrong and kernel still contains; cost = allowlist + AppArmor maintenance.
- **Fail-closed** (auth, audit, evidence gate, runtime-user) — outages block agents.
- **Docs:** HTML visual SoT → SECURITY-MODEL text twin → `docs/latest/` → `docs/new-docs/`. Domain `docs/adr/` ≠ this MCP ADR. Cursor may omit `manage_adr` — CLI or `.codebase-memory/adr.md`.

## PHILOSOPHY

Governed autonomy: agents investigate via tools (especially `run_command`); humans authorize evidence and release. Deny-by-default at policy **and** kernel. Evidence cannot be silently mutated (#2); command/tool output is hostile until ResponseGuard (#6). The execution jail is load-bearing infrastructure — treat every edit as a security change. Never hardcode secrets. Never weaken auth, evidence, or sandbox to “unblock” an agent. When unsure: HTML VP-5 + SECURITY-MODEL, then ask — do not invent a second door or a softer jail.
