# Agent Operating Contract

This repository is managed through Linear project `ProtocolSIFTGateway`.
Linear is the active queue; repo docs are reference packs; code and tests are
the implementation truth.

## Code Discovery

This project uses `codebase-memory-mcp` to maintain a knowledge graph. Always
prefer MCP graph tools over grep/glob/file-search for code discovery:

1. `search_graph` to find functions, classes, routes, variables.
2. `trace_path` to inspect callers, callees, and data flow.
3. `get_code_snippet` to read exact source for known symbols.
4. `query_graph` for complex relationship queries.
5. `get_architecture` for high-level structure.

Fall back to `rg` for string literals, configs, shell scripts, docs, or when the
graph is insufficient.

## Linear Source Of Truth

Use `docs/new-docs/LINEAR_OPERATING_MODEL.md` as the canonical operating model.
Use `docs/new-docs/LINEAR_ORCHESTRATION_GUIDE.md` only for older prompt
examples and context.

Primary views:

- `PSG Command`: small dashboard and drill-down starting point.
- `PSG Execution`: accepted runnable work.
- `PSG Parked`: operator-gated and decision-only work.
- `PSG Review`: issues awaiting review.
- `PSG All Open Drilldown`: audit view, not daily picking.

## Issue Rules

Before starting work, read the Linear issue, parent issue, relations, latest
comments, and linked docs. Work one accepted issue at a time unless the
orchestrator explicitly assigns a combined session.

Agents must not create top-level issues by default.

When new work appears, use this order:

1. Comment on the current issue.
2. Add checklist items to the current issue.
3. Propose sub-issues in a comment table.
4. Create sub-issues only if explicitly allowed.
5. Create new top-level issues only with operator approval.

Required proposed follow-up format:

```md
## Proposed Follow-Ups

| Candidate | Why | Parent | Type | Tests | Accept / Reject |
|---|---|---|---|---|---|
| <title> | <reason> | <XYE-parent> | sub-issue / discovery / decision | <validation> | pending |
```

## Labels And Relations

- `queue:command`: visible in the condensed dashboard.
- `queue:run-alone`: one agent owns it alone.
- `queue:combine`: plan or execute with its related pair.
- `gate:operator`: do not start without operator timing approval.
- `type:decision`: decision-only until the operator chooses.

Use `duplicate` for duplicate work, `related` for context, and `blocked by` only
for real sequencing dependencies. Do not leave open issues blocked by canceled
issues.

## Agent Worktrees

The harness `isolation: worktree` flag does NOT create isolated working
directories in this environment: spawned agents fall back to the shared main
working tree and race on the git index (a single tree can only hold one
checked-out branch, so concurrent writer agents serialize onto or clobber each
other's branch and intermingle uncommitted changes). Do not rely on it for
writer agents.

When dispatching parallel coding agents (an agent team), the orchestrator sets
up isolation MANUALLY:

1. Create one worktree per agent off the current integrated `HEAD` (never a
   stale `origin/main` — that base bug drops already-merged work):
   `git worktree add ../wt/<issue-slug> -b <branch> HEAD`
2. In each agent's prompt, set its working directory to that worktree's absolute
   path and instruct it to `cd` there first, run every edit / `uv` / pytest /
   git command from that directory, and COMMIT its work to its branch in that
   worktree. It must never touch the main checkout.
3. After an agent finishes, the orchestrator merges its branch into main,
   re-validates, then removes the worktree (`git worktree remove`).

Never run two writer agents in the same working tree.

## GitHub

Linear is the issue source of truth. GitHub is for code review and merge proof.

- Use `Refs XYE-123` for partial, exploratory, or review-only PRs.
- Use `Fixes XYE-123` only when the PR fully satisfies acceptance criteria.
- Do not auto-open PRs for triage or discovery output unless explicitly asked.
- Do not enable two-way GitHub issue sync unless the operator requests it.

## Signoff

Post a Linear closeout comment before ending substantive work:

```md
Result: DONE | IN REVIEW | BLOCKED
Branch/commit:
Changed:
Validation:
Residual risk:
Next action:
```

Never paste secrets, raw tokens, DSNs, passwords, private keys, service-role
keys, or sensitive full evidence paths into Linear, GitHub, or docs.
