# Agent Operating Contract

Top-level contract for the `sift-mcps` monorepo. All agents (Claude, Codex,
Gemini) read this first. On conflict, this file wins — except inside the portal
frontend, where the frontend `AGENTS.md` (design-system contract) governs UI.

## Repo map & where to work

- **`/home/yk/AI/SIFTHACK/sift-mcps` is the `main` checkout** — Python MCP gateway
  + portal. **`main` is the single canonical line.** (The old two-track separation
  is retired: `portal-v3/p0-foundation` was fast-forwarded into `main` 2026-06-26 and
  that branch + its remote deleted. Do NOT recreate a separate portal track — commit
  portal + gateway work on `main`; if launched on a stale linked worktree, treat its
  branch as a local alias of `main` and push to `main`.)
- **Portal frontend:** `packages/case-dashboard/frontend` — carries its own
  `AGENTS.md` / `DESIGN-SYSTEM.md` (design-system contract); read those before
  touching UI. Inside the frontend, that `AGENTS.md` wins over this file.
- A worktree folder *is* its branch; one branch checks out in one worktree at a time.

## Active focus

Portal v3 frontend rebuild (design-first). Design source of truth = the SIFT
Design System project (synced to Claude Design via `DesignSync` / `/design-sync`);
the codebase is the consumer. Token sync is one-way: when `tokens.css` changes in
the design project, copy it to `packages/case-dashboard/frontend/src/styles/tokens.css`.
Severity is **High / Medium / Low only** — the old `--sev-spec`/violet tier is dropped.

## Operating model, trackers & lessons (read before substantive work)

Internal ops hub lives **outside this repo** (local): `~/AI/SIFTHACK/sift-portal-ops/`.
- **Start here:** `STATUS.md` (current state) + `trackers/OPEN_ITEMS_MASTER.md` (every
  open / deferred item + pending decisions). Read it before "discovering" work — don't
  re-scan the per-topic trackers. Friction history: `trackers/MCP_WORKFLOW_FRICTION_TRACKER.md`;
  coder briefs: `briefs/`.
- **Surfacing lesson (the #1 repeat bug):** a gateway/add-on fix is INERT live unless it
  lands at the **agent-facing surface** — the registry `*Out` Pydantic model + the worker
  `result_public` envelope + the DB-authority path — NOT the impl function. SDK `outputSchema`
  rejects a result with no `structured_content`. The agent backend has **no DB creds by design**
  (DB-reading logic belongs in the gateway, not the add-on subprocess). Full writeup +
  pre-merge checklist: `runbooks/LESSONS-MCP-FIX-SURFACING.md`.
- **Guard:** a conformance harness now catches that class in CI —
  `packages/sift-common/src/sift_common/testing/surface.py`. When you add/change an MCP tool's
  output, write a **fail-on-revert** surface test with it and add the optional key to
  `SURFACE_OPTIONAL_KEYS` (else CI fails). A regression test that can't catch its own bug is theater.

## Deploy-and-prove (standing rule)

A green test is a hypothesis; the **live gateway is the proof for BEHAVIOR** (the harness covers
plumbing only). VM deploy = rsync changed source to `/opt/sift-mcps/packages/.../` → clear
`__pycache__` → restart `sift-gateway` + `sift-opensearch-worker@{1,2}` + `sift-job-worker` →
re-run the exact repro live and diff before/after. If the live setup can't reproduce it, say so —
never imply a live proof that didn't happen. VM coords + live-MCP connection: see the recalled
`reference_harness_mcp_live_connection` / VM-coordinates memories.

## Security model (read before any gateway / security / execution work)

The canonical security architecture is **`docs/architecture/SIFT-GATEWAY-SECURITY-MODEL.md`**
(condensed C4 + STRIDE viewpoints; rendered diagrams in
`docs/drafts/architecture/sift-architecture.html`). It defines the single-policy-boundary
gateway, the 9 fail-closed tool-call gates, the Postgres-authoritative / OpenSearch-derived
split, the seven STRIDE trust boundaries, and the `run_command` ceiling+floor sandbox. **Read
it before touching auth, the policy chain, backends, evidence/audit, or execution.** It is the
DESIGN model — where it conflicts with the code, the **code wins; flag the drift**. Live
opensearch-mcp wiring: `docs/drafts/architecture/OPENSEARCH-INTEGRATION-SPEC.md`.

## Code Discovery

This project uses `codebase-memory-mcp` to maintain a knowledge graph. Prefer MCP
graph tools over grep/glob for code discovery:

1. `search_graph` to find functions, classes, routes, variables.
2. `trace_path` to inspect callers, callees, and data flow.
3. `get_code_snippet` to read exact source for known symbols.
4. `query_graph` for complex relationship queries.
5. `get_architecture` for high-level structure.

Fall back to `rg` for string literals, configs, shell scripts, docs, or when the
graph is insufficient.

## Spawned agents & agent teams — required loadout

Every spawned subagent and agent-team member (coding, reviewing, verifying,
exploring) MUST do the following, and the orchestrator MUST bake these into each
agent prompt by name — plugin skills sometimes do not auto-load in subagents, so
the explicit prompt text is the required fallback:

1. **codeguard-security skill** — invoke `codeguard-security:codeguard` for
   secure-by-default guidance while writing/modifying code (use
   `codeguard-security:security-review` for a full review pass); report which ran
   and its verdict in the closeout.
2. **codebase-memory MCP** — use the graph tools (`search_graph`, `trace_path`,
   `get_code_snippet`, `query_graph`, `get_architecture`) for code discovery over
   grep/glob, plus the `codebase-memory` skill for query syntax (same tool as the
   Code Discovery section above).
3. **LSP validators on changed files before closing** — Python:
   `uv run --extra dev ruff check <paths>` + `uv run --extra dev pyright` (and
   targeted `uv run --extra dev pyright <file>` on each file touched); frontend:
   `npm --prefix packages/case-dashboard/frontend run lint`. `sift-gateway` is the
   type-clean Pyright baseline — keep it at **0 new diagnostics**; non-baseline
   packages (opensearch-mcp, portal/case-dashboard backend, some sift-core) carry
   legacy type debt — report NEW diagnostics from your edits SEPARATELY from
   pre-existing debt, fix only what you introduced, and do NOT expand
   `pyrightconfig.json`. Full guide: `docs/new-docs/LSP_AGENT_WORKFLOW.md`. A
   fresh worktree's uv env may miss dev deps — fall back to repo-root tooling.
4. **Security model** — read `docs/architecture/SIFT-GATEWAY-SECURITY-MODEL.md` to
   understand the single-policy-boundary gateway, the 9 fail-closed gates, the
   Postgres-authoritative / OpenSearch-derived split, the STRIDE boundaries, and the
   `run_command` jail before reasoning about security / policy / backends / evidence /
   execution. The orchestrator MUST point agents to it by name in their prompts. Code wins
   on conflict — flag drift.

LSP/diagnostics catch import/signature/optional-value/rename slips early; they do
NOT prove policy/runtime/DB/live-VM behavior. codebase-memory is first for
call-graphs/architecture; tests + deploy-and-prove remain the final authority.

## Agent Worktrees

The harness `isolation: worktree` flag does NOT create isolated working
directories in this environment: spawned agents fall back to the shared main
working tree and race on the git index (a single tree can only hold one
checked-out branch, so concurrent writer agents serialize onto or clobber each
other's branch and intermingle uncommitted changes). Do not rely on it for
writer agents.

A single agent needs no extra worktrees — `cd` into the target branch's worktree,
work there, commit there. Per-agent worktrees are only for **parallel writers**.
When dispatching parallel coding agents (an agent team), the orchestrator sets up
isolation MANUALLY:

1. Create one worktree per agent off the current integrated `HEAD` (never a
   stale `origin/main` — that base bug drops already-merged work):
   `git worktree add ../wt/<slug> -b <branch> HEAD`
2. In each agent's prompt, set its working directory to that worktree's absolute
   path and instruct it to `cd` there first, run every edit / npm / pytest / git
   command from that directory, and COMMIT its work to its branch in that
   worktree. It must never touch the main checkout.
3. After an agent finishes, the orchestrator merges its branch into main,
   re-validates, then removes the worktree (`git worktree remove`).

Never run two writer agents in the same working tree.

## GitHub

GitHub is for code review and merge proof.

- Do not auto-open PRs for triage or discovery output unless explicitly asked.
- Commit or push only when the operator asks. If on the default branch, branch
  first.
- Do not enable two-way issue sync unless the operator requests it.

## Signoff

Post a closeout before ending substantive work:

```md
Result: DONE | IN REVIEW | BLOCKED
Branch/commit:
Changed:
Validation:
Residual risk:
Next action:
```

Never paste secrets, raw tokens, DSNs, passwords, private keys, service-role
keys, or sensitive full evidence paths into GitHub, docs, or any external service.

## Linear (paused)

The Linear `ProtocolSIFTGateway` issue queue is **paused** during the portal v3
rebuild. The canonical operating model is preserved at
`docs/new-docs/LINEAR_OPERATING_MODEL.md` (and `LINEAR_ORCHESTRATION_GUIDE.md`)
for when the track resumes. Until then, do not gate work on Linear issues.
