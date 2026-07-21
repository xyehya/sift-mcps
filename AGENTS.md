# Agent Operating Contract

## Repo map & where to work
- `main` is the single integration line; on the maintainer's Mac the canonical checkout
  is `~/AI/sift-mcps` (Python MCP gateway + portal). A worktree folder *is* its branch
  (one branch ↔ one worktree at a time). If launched elsewhere, verify branch/base
  explicitly; never treat a stale branch as an alias; don't push/merge unless asked.
- **Portal frontend** `packages/case-dashboard/frontend` carries its own `AGENTS.md` +
  `DESIGN-SYSTEM.md` — read those before UI work; inside the frontend, that `AGENTS.md` wins.

## Herdr — session multiplexer, orchestration & inter-agent comms
All coding sessions run inside **Herdr** (`herdr` CLI on PATH) — the orchestration and agent-to-agent
messaging layer. The full control protocol (spawning agents into panes, `idle`/`done` attention
semantics, wait/read sources, safety rules) is the repo-vendored **`herdr` skill**: canonical
`.agents/skills/herdr/SKILL.md`, symlinked to `.claude/skills/herdr` (Claude Code — invoke `/herdr`)
and `.codex/skills/herdr` (Codex). **Activate it when — and only when — you actually do Herdr
orchestration or inter-agent comms** (spawn/steer another agent, wait on a pane, cross-agent handoff);
skip it for ordinary edits. It self-checks `HERDR_ENV=1` and no-ops outside Herdr. If your harness
doesn't surface the skill, read that `SKILL.md` directly. The quick primitives below cover the common path.
- **Targets** (for `send` / `wait` / `read`): a unique agent name, a terminal id, a reported label, or
  a pane id (`w15:p1M`). The bare type (`claude` / `codex`) is **not** unique — a session usually has
  many `claude` panes — so never address the orchestrator by type, and prefer a stable name over a
  volatile pane id. Give the orchestrator a fixed handle once with `herdr agent rename <self>
  orchestrator` and pass that literal name into every spawned agent's prompt; names survive pane churn.
- **Wait, don't watch — the #1 context destroyer.** NEVER poll in a loop to learn whether another
  agent finished — not the pane (`herdr pane get` / `pane read`) **and not the waiter/background
  process either**. The specific trap this rule exists to kill: launch a watcher correctly, then
  re-check it (or the pane) every minute anyway. That floods context and is what makes long
  orchestration sessions collapse. Instead:
  - Launch **exactly one** event-driven waiter and then continue other work or stop — do not re-check
    it: `herdr wait agent-status <pane_id> --status done --timeout <ms>` (also `idle` / `blocked`), or
    `herdr agent wait <target> --status idle`. Run it as a background command; **its completion is the
    signal that wakes you — you do not watch it.**
  - On completion, inspect the pane **exactly once** (`herdr pane read <pane_id> --source
    recent-unwrapped`) and act. If you have nothing else to do meanwhile, block on that single wait —
    never spin short waits or status reads in a loop.
- **Discover / read on demand (one-shot, after a wait returns — not in a loop):** `herdr agent list`,
  `herdr agent get <target>`, `herdr agent read <target>`.
- **Two-way messaging:** `herdr agent send <target> "<msg>"` only populates the target agent's
  prompt; it does **not** submit it. Follow it with `herdr pane send-keys <target-pane-id> enter`.
  The current interactive-agent integration can also leave `herdr pane run <target-pane-id>
  "<msg>"` populated without submission, so follow that with the same explicit Enter. If text is
  already populated, send **only** Enter so the prompt is not duplicated. Treat visible prompt text
  as unsent until the agent begins processing it.
- **Always-on backup comms (required for every spawned agent):** idle/done detection can lag 2–3 min,
  so in every spawned agent's prompt instruct it to **route its final turn back to the orchestrator via
  `herdr agent send <orchestrator-target> "<result / DONE>"` and then submit it with Enter as above**
  in addition to going idle. Pass both the orchestrator's stable name and current pane id in the
  spawned prompt so the agent can perform both steps. Treat that
  message as the primary completion signal and the status transition as backup — never rely on polling
  to notice completion.

## Start here (read before "discovering" work)
Ops hub (local, outside repo): `~/AI/sift-portal-ops/`.
- **Read these two first:** `STATUS.md` (narrative current state) + `trackers/MASTER_TRACKER.md`
  (single execution queue; self-contained P0–P4 handoff packets). For PR-review work also
  `trackers/GITHUB_PR_TRACKER.md` (deliberately link-only; GitHub is authoritative for live PR
  state/checks). Coder briefs: `briefs/`.
- **Packets are scope contracts:** `Finalize P1` = execute P1's actions/acceptance criteria only,
  expand code discovery as needed, don't pull in adjacent packets. Update packet state + proof when done.
- **P4.23 evidence-custody sprint (active freeze):** sole behavioral authority is
  `docs/architecture/EVIDENCE-CUSTODY-SPEC.md`; execution routing starts at
  `~/AI/sift-portal-ops/briefs/p423-evidence-custody/00-ORCHESTRATION-INDEX.md` (its
  `DECISION-REGISTER.md` is frozen provenance); live state lives in ops `STATUS.md`. Do NOT resume
  the superseded P4.23.1–.8 packets / Gate-C·D matrices, infer requirements from archives, or code
  before the Joint Engineering Design Gate is approved.

## The #1 repeat bug — MCP fix surfacing
A gateway/add-on fix is INERT live unless it lands at the **agent-facing surface**: the registry
`*Out` Pydantic model + the worker `result_public` envelope + the DB-authority path — NOT the impl
function. SDK `outputSchema` rejects a result with no `structured_content`. The agent backend has
**no DB creds by design** (DB-reading logic belongs in the gateway, not the add-on subprocess).
- **Guard:** when you add/change an MCP tool's output, write a fail-on-revert surface test and add the
  optional key to `SURFACE_OPTIONAL_KEYS` (else CI fails) —
  `packages/sift-common/src/sift_common/testing/surface.py`. A regression test that can't catch its
  own bug is theater.
- Full writeup + pre-merge checklist: `~/AI/sift-portal-ops/runbooks/LESSONS-MCP-FIX-SURFACING.md`.

## Deploy-and-prove (standing rule)
A green test is a hypothesis; the **live gateway proves BEHAVIOR** (the harness covers plumbing only).
If the live setup can't reproduce it, say so — never imply a live proof that didn't happen.
- **Deploy:** rsync source to `/opt/sift-mcps/packages/.../` → clear `__pycache__` → restart
  `sift-gateway` + `sift-opensearch-worker@{1,2}` + `sift-job-worker` → re-run the exact repro live
  and diff before/after.
- Procedures (authority; recalled coordinates are convenience only):
  `~/AI/sift-portal-ops/runbooks/RUN-PORTAL-V3-VM-DEPLOY.md` and `…-VM-TEST.md`.

VM facts — disposable test env (Ubuntu 24.04, our repo installed), **not** production; no backups
needed unless for live-proof comparison. Case images are offline, findings/timelines are test data:

| What | How |
|---|---|
| Test VM (proof target) | `ssh sift-vm` — safe to delete/redeploy |
| Gateway/portal (on VM) | `https://localhost:4508` via background tunnel — if down, ensure `ssh sift-gateway-tunnel` is running |
| Hypervisor (Fedora host) | `ssh fedora.local` — VM RAM/CPU/storage via virt-manager |

Redeploy note: the VM was installed as **root** by mistake — use the default user `sansforensics` next redeployment.

## Security model (read before any gateway / security / execution work)
Canonical: **`docs/architecture/SIFT-GATEWAY-SECURITY-MODEL.md`** (condensed C4 + STRIDE; rendered
diagrams in `docs/drafts/architecture/sift-architecture.html`). Defines the single-policy-boundary
gateway, the 9 fail-closed tool-call gates, the Postgres-authoritative / OpenSearch-derived split, the
7 STRIDE trust boundaries, and the `run_command` ceiling+floor sandbox. Read it before touching auth,
the policy chain, backends, evidence/audit, or execution. It is the DESIGN model — **where it conflicts
with code, the code wins; flag the drift.**

### Security reporting — evidence before implication
Don't report an architectural possibility as an agent-reachable vulnerability. Before raising,
escalating, or acting, establish the complete current path and distinguish a demonstrated exposure
from defense-in-depth hardening. Every report states:
1. Exact MCP tool/resource URI, its registration site, and whether a real agent can invoke it.
2. Gateway route + applicable policy gates (identity, authorization, active-case binding, audit,
   evidence, response guard, dispatch).
3. Supplied vs gateway-injected args + the exact backend entrypoint.
4. Precise downstream op: DB/OpenSearch method + target index/query, filesystem path, network target,
   or process/command.
5. OS/process footprint (`run_command`, worker, subprocess, evidence access, sandbox). "Agent-facing"
   alone is not evidence.
6. A current reachability repro. If it can't be reproduced, label it a hardening/design concern with
   the missing proof — don't call it a vuln or block unrelated work on implication.

For case-scoping claims prove active-case source → propagation → final index/query scope. For resource
reads prove the read context (not merely tool-call middleware) carries identity + active-case authority.

## Code discovery — codebase-memory MCP
Prefer the `codebase-memory-mcp` knowledge graph over grep/glob. **Direct MCP tools only, never the
CLI** — `index_repository`, `search_graph`, `trace_path`, `get_code_snippet`, `query_graph`,
`get_architecture`, `manage_adr`. If a needed method isn't exposed, report the gap — don't shell out.
- **Always `index_repository(repo_path=<root>, name="Users-yk-AI-sift-mcps")` first** at discovery
  start and again after substantive edits. Indexing is fast; don't skip because a prior session
  indexed. The graph store (`.codebase-memory/graph.db.zst`, `artifact.json`) is git-ignored so
  indexing won't dirty the tree — only `.codebase-memory/adr.md` is tracked; never commit the index.
- Then: `search_graph` (symbols) → `trace_path` (callers/callees/data-flow) → `get_code_snippet`
  (exact source) → `query_graph` (complex relations) → `get_architecture` (structure). Fall back to
  `rg` for string literals, configs, shell, docs, or when MCP is unavailable.

### Project ADR
`manage_adr(project="Users-yk-AI-sift-mcps", mode="get")` reads the six-section ADR
(PURPOSE / STACK / ARCHITECTURE / PATTERNS / TRADEOFFS / PHILOSOPHY) after indexing. Committed mirror +
bootstrap source: `.codebase-memory/adr.md` (read it if `manage_adr` is missing — don't crawl the repo).
- When a PATTERNS/TRADEOFFS fact changes (policy-stage count, seccomp/AppArmor posture, a resolved
  add-on drift), edit `.codebase-memory/adr.md` and re-run `manage_adr(mode="update", content=<full
  six-section md>)`; keep both in sync (`mode="sections"` for one section, ≤ ~8000 chars). A stale ADR
  is worse than none.
- Content sources (code wins on conflict): `docs/drafts/architecture/sift-architecture.html` →
  `SIFT-GATEWAY-SECURITY-MODEL.md` → `docs/latest/` → `docs/new-docs/DEVELOPER_ENTRYPOINT.md` → other
  `docs/drafts/architecture/` → live `get_architecture()`. Flag drift. Distinct from per-decision notes
  in `docs/adr/`.

## Agent tooling (project-scoped — prefer repo config over user-global)
- Cursor: `.cursor/mcp.json`, `.cursor/settings.json`, `.cursor/rules/`, `.cursor/agents/`.
- Skills: canonical source is `.agents/skills/<name>/`; symlink it into `.claude/skills/` (Claude) and
  `.codex/skills/` (Codex) — one copy, no drift (e.g. `herdr`). Do NOT also mirror under
  `.cursor/skills/` — Cursor loads both `.claude/` and `.cursor/` and duplicates.
- MCP configs: `.mcp.json`, `.claude/settings.json`, `.codex/config.toml`, `opencode.json`.
- **codebase-memory binary:** Cursor uses `${userHome}/.local/bin/codebase-memory-mcp` (GUI apps often
  lack `~/.local/bin` on PATH); Claude/Codex/OpenCode use bare `codebase-memory-mcp`. Install
  host-native via DeusData `install.sh`; cloud/Linux via `scripts/cloud/bootstrap-agent-tools.sh`.
  Never commit the binary or absolute machine paths (`/Users/…`, `/home/…`); keep `~/.cursor/mcp.json`
  empty so project `.cursor/mcp.json` owns memory MCP.
- **CodeGuard security** runs via the `codeguard-security` plugin (`enabledPlugins` in
  `.claude/settings.json`, git-tracked). The marketplace registration + `~/.claude/plugins/` cache is
  machine-local — on a new machine/profile: `/plugin marketplace add cosai-oasis/project-codeguard`
  then `/plugin install codeguard-security@project-codeguard`.
- **Codex browser work** (rendered Portal/frontend repro, live UI verification): invoke `$chrome-fast`
  + `codex-in-chrome-mcp` (`mcp__codex_in_chrome_mcp__*`) at the task start; put
  "Use $chrome-fast and codex-in-chrome-mcp for all browser work" in the operator's prompt. If the
  skill/tools are absent, start a fresh Codex task and recheck; report the gap rather than silently
  falling back to Playwright / built-in Chrome (fallback needs operator approval). **Browser control is
  a single leased resource — only root or one designated operator drives the signed-in Portal; never
  run concurrent Chrome agents.** Host-global tooling (`~/.codex/…`) — never commit its paths/creds/state.

## Spawned agents — required loadout
Every spawned subagent / team-member prompt includes these. Report capability absence, use the stated
fallback, never fabricate a verdict.
1. **Security guidance** — invoke `codeguard-security:codeguard` while editing (or `:security-review`
   for a full pass) and report the verdict; if unavailable, do a manual secure-by-default review
   against the security model and say so.
2. **codebase-memory** — per §Code discovery (index first, MCP tools not CLI, `rg` fallback for
   read-only discovery).
3. **LSP on changed files before closing** — Python `uv run --extra dev ruff check <paths>` +
   `uv run --extra dev pyright <file>` per file touched; frontend
   `npm --prefix packages/case-dashboard/frontend run lint`. `sift-gateway` is the 0-diagnostic Pyright
   baseline — keep it clean; other packages (opensearch-mcp, portal/case-dashboard backend, some
   sift-core) carry legacy type debt — report NEW diagnostics from your edits SEPARATELY, fix only what
   you introduced, don't expand `pyrightconfig.json`. Guide: `docs/new-docs/LSP_AGENT_WORKFLOW.md`. A
   fresh worktree may miss dev deps — fall back to repo-root tooling.
4. **Security model** — point the agent to `SIFT-GATEWAY-SECURITY-MODEL.md` by name before any
   security/policy/backend/evidence/execution reasoning (per §Security model).
5. **Herdr handoff** — give the agent both the orchestrator's stable name and current pane id;
   instruct it to populate the closeout with `herdr agent send <orchestrator-target>
   "<closeout / DONE>"`, then submit it with `herdr pane send-keys <orchestrator-pane-id> enter`
   (per §Herdr). It must not rely on idle-detection alone.

LSP catches import/signature/optional/rename slips early; it does NOT prove policy/runtime/DB/live-VM
behavior. codebase-memory is first for call-graphs/architecture; tests + deploy-and-prove are the final
authority.

## Parallel writers — manual worktree isolation
The harness `isolation: worktree` flag does NOT isolate here — spawned agents fall back to the shared
main tree and race on the git index (one tree holds one checked-out branch, so concurrent writers
serialize onto or clobber each other). Don't rely on it for writers. A single agent needs no extra
worktree: `cd` into the target branch's worktree, work + commit there. For **parallel writers** the
orchestrator sets up isolation manually:
1. One worktree per agent off current integrated `HEAD` (never stale `origin/main` — that drops merged
   work): `git worktree add ../wt/<slug> -b <branch> HEAD`.
2. Each agent's prompt sets its working dir to that worktree's absolute path; it runs every
   edit/npm/pytest/git command there and commits to its branch — never touching the main checkout.
3. After it finishes: merge branch → main, re-validate, `git worktree remove`.

Never run two writer agents in the same tree.

## Root orchestration
**Inert unless the operator explicitly launches this session as the sift-mcps root sprint orchestrator**
with commit/push authority — pastes the kickoff prompt, or says "run/continue as orchestrator" for
`~/AI/sift-mcps`. Every other session ignores it. When triggered, read
**`docs/agents/root-orchestration.md`** (standing authority / worktree-ledger / serialized-proof
contract) plus the ops-hub `SPRINT-ORCHESTRATOR-PROMPT.md` + `WORKTREE_LEDGER.md`, then resume from the
recorded checkpoint. (Kept out of the machine-global config so Claude Code and Codex read the same trigger.)

## GitHub — code review + merge proof only
- Don't auto-open PRs for triage/discovery output unless asked. Commit/push only when the operator
  authorizes; ordinary agents branch before writing from the default branch; only an authorized root
  orchestrator merges/pushes `main`; spawned agents commit to their worktree branch only.
- Don't enable two-way issue sync unless asked. Refresh
  `~/AI/sift-portal-ops/trackers/GITHUB_PR_TRACKER.md` only when the open-PR set/disposition changes;
  keep diffs, reviews, and CI logs in GitHub, not the tracker.

## Guardrails
- Don't fabricate results or claim completion without verification.
- Don't weaken auth, execution, or evidence-handling safeguards.
- Don't change unrelated files or broaden scope without a clear reason.
- If a task is ambiguous, ask before a high-impact change.
- Never paste secrets, raw tokens, DSNs, passwords, private keys, service-role keys, or sensitive
  evidence paths into GitHub, docs, commits, screenshots, proof bundles, or any external service.
  Test-env credentials stay ephemeral — never store them in the repo, ledger, trackers, or durable prompts.

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

## Agent skills & docs
Repo-scoped config for the engineering skills in `.claude/skills/` / `.agents/skills/` (to-tickets,
triage, to-spec, wayfinder, domain-modeling, …):
- **Issues:** GitHub Issues (`gh`; repo inferred from the remote) — except the P4.23 sprint, whose work
  items are the ops-hub packet DAG. See `docs/agents/issue-tracker.md`.
- **Triage labels:** five-role vocabulary over existing labels (`ready-for-agent` → `agent-ready`). See
  `docs/agents/triage-labels.md`.
- **Domain:** single-context — root `CONTEXT.md` + `docs/adr/`. While the P4.23 freeze banner is on
  `CONTEXT.md`, custody vocabulary comes from `EVIDENCE-CUSTODY-SPEC.md` + the decision register, not
  the frozen glossary. See `docs/agents/domain.md`.
- **Cursor Cloud dev env:** see `docs/agents/cursor-cloud.md` (Tailscale reach to the live gateway,
  standalone portal, toolchain quirks, known test failures) — NOT the maintainer's Mac + SIFT-VM setup above.
