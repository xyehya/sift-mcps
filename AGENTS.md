# Agent Operating Contract

Top-level contract for the `sift-mcps` monorepo. All agents (Claude, Codex,
Gemini) read this first. On conflict, this file wins — except inside the portal
frontend, where the frontend `AGENTS.md` (design-system contract) governs UI.

## Repo map & where to work

- **This folder** (`/home/yk/AI/SIFTHACK/sift-mcps`) is the `main` checkout — the
  Python MCP gateway + the *current* portal. Launching an agent here puts you on
  `main`.
- **Portal v3 rebuild does NOT happen on `main`.** It lives in a linked worktree:
  - Frontend: `packages/case-dashboard/frontend`
  - Branch: `portal-v3/p0-foundation`
  - Worktree: `.claude/worktrees/portal-v3-p0-foundation`
  - **For portal work, `cd` into that worktree first** (a worktree folder is
    permanently bound to its branch — entering it = you are on that branch, no
    checkout needed). The frontend there carries its own `AGENTS.md` /
    `DESIGN-SYSTEM.md` — read those before touching UI.
- A worktree folder *is* its branch. One branch can be checked out in only one
  worktree at a time. Walk between folders to switch branches.

## Active focus

Portal v3 frontend rebuild (design-first). Design source of truth = the SIFT
Design System project (synced to Claude Design via `DesignSync` / `/design-sync`);
the codebase is the consumer. Token sync is one-way: when `tokens.css` changes in
the design project, copy it to `packages/case-dashboard/frontend/src/styles/tokens.css`.
Severity is **High / Medium / Low only** — the old `--sev-spec`/violet tier is dropped.

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
