# Linear Operating Model

> Covers: Linear project ProtocolSIFTGateway, GitHub PR linkage, agent-created work intake
> Class: living-plan
> Last validated: a7ea369 (2026-06-19)

This is the operating contract for ProtocolSIFTGateway work in Linear. The goal
is a small visible command surface with drill-down, not a growing flat backlog.
Linear is the active queue. Repo docs are reference packs. Code and tests are
the implementation truth.

## Current Linear Shape

Project:

- `ProtocolSIFTGateway`

Primary views:

- `PSG Command`: condensed dashboard for coordinator hubs, accepted execution
  issues, and parked decisions.
- `PSG Execution`: runnable accepted work only. This is the normal coding
  session picker.
- `PSG Parked`: operator-gated or decision-only work.
- `PSG Review`: issues currently in review.
- `PSG All Open Drilldown`: full open issue audit view. Use for inspection, not
  daily picking.
- `PSG Queue - Run Alone`, `PSG Queue - Combine`, `PSG Queue - Frontier`:
  detail queues kept for compatibility with earlier orchestration.

Current command set as of 2026-06-19:

- Coordinator hubs: `XYE-45`, `XYE-46`, `XYE-47`
- Accepted execution: `XYE-96`, `XYE-70`, `XYE-78`, `XYE-84`
- Combine sibling: `XYE-64` with `XYE-84`
- Parked / operator decision: `XYE-7`, `XYE-54`

## Hierarchy

Use Linear as three layers:

1. Project = outcome container.
2. Parent issue = command hub or coherent work package.
3. Sub-issue = independently executable unit with its own branch, tests, and
   signoff.

Use a parent issue when the operator should be able to open one item and drill
into related execution work. Use a sub-issue only when the work is independently
pickable. If the item is just a note, risk, checklist line, or research result,
do not create an issue.

## Issue Creation Rules

Agents must not create top-level issues by default.

When an agent finds more work, use this order:

1. Add proof, notes, or decisions as a comment on the current issue.
2. Add checklist items to the current issue when they fit the same scope.
3. Propose sub-issues in a comment using the table below.
4. Create sub-issues only when explicitly instructed or when the issue prompt
   grants that permission.
5. Create a new top-level issue only with operator approval.

Required proposed follow-up table:

```md
## Proposed Follow-Ups

| Candidate | Why | Parent | Type | Tests | Accept / Reject |
|---|---|---|---|---|---|
| <title> | <reason> | <XYE-parent> | sub-issue / discovery / decision | <validation> | pending |
```

An agent may create a new issue without a separate approval only when the
current issue explicitly says it may create follow-ups and the new issue has a
clear parent, acceptance criteria, and validation plan.

## Status Discipline

- `Backlog`: captured, not selected for current execution.
- `Todo`: accepted and ready to start.
- `In Progress`: actively being worked.
- `In Review`: implementation or research output exists, but review, tests,
  live proof, or acceptance remains.
- `Done`: acceptance is satisfied and proof is recorded.
- `Canceled`: intentionally closed as not planned or no longer useful.
- `Duplicate`: use Linear's duplicate relation when another issue is the
  canonical home for the same work.

Do not move an issue to `Done` from intent. Move it by evidence.

## Labels

Labels are for routing and classification, not for status or priority.

Use a small set:

- `component:*`: installer, gateway, opensearch, addon, core, portal, ci, docs,
  supply-chain.
- `queue:*`: command, run-alone, combine, frontier.
- `gate:*`: operator, live-vm, security-review.
- `type:*`: bug, chore, decision, discovery, docs, follow-up, ops.
- `source:*`: human, codex, claude, linear-agent, only when useful for intake
  audit.

Rules:

- `queue:command` means "show this in the condensed command dashboard."
- `queue:run-alone` means one coding agent should own the issue by itself.
- `queue:combine` means the issue should be planned or executed with its paired
  related issue.
- `gate:operator` and `type:decision` belong in `PSG Parked`, not normal
  execution.
- Do not create new label families without updating this document.

## Relations

Use native Linear relations deliberately:

- `duplicate`: same work already has a canonical issue. Prefer this over
  canceling duplicates.
- `related`: useful context, same theme, or recommended same-session planning.
- `blocked by` / `blocks`: real sequencing dependency only.
- Parent/sub-issue: ownership hierarchy. Use when the child belongs under the
  parent command hub.

Do not leave open issues blocked by canceled issues. Completed blockers are
acceptable as historical dependency context, but remove them if they confuse the
view.

## Agent Intake

Discovery agents and triage agents must not create active backlog items
directly. Their output should be:

- comment on the source issue,
- checklist on the source issue,
- proposed follow-up table,
- or Linear Triage item for operator acceptance when a separate issue is truly
  needed.

The operator accepts, rejects, merges, or converts proposed work. Accepted work
gets a parent, labels, tests, and acceptance criteria before any coding session
starts.

## Required Issue Shape

Every executable issue must include:

```md
## Goal
<one outcome>

## Context
<why it exists, with source issue/docs>

## Scope
### Do
- <bounded action>

### Do Not
- <explicit exclusions>

## Tests / Validation
- <commands or proof>

## Acceptance Criteria
- [ ] <observable finish condition>

## Agent Signoff
Result: DONE | IN REVIEW | BLOCKED
Branch/commit:
Changed:
Validation:
Residual risk:
Next action:
```

## GitHub Policy

Linear is the issue source of truth. GitHub is for code review and merge proof.

Rules:

- Branch names and PR titles may include the Linear issue ID.
- Use non-closing references such as `Refs XYE-123` for partial, exploratory,
  or review-only PRs.
- Use closing words such as `Fixes XYE-123` only when the PR fully satisfies
  the issue acceptance criteria.
- Do not enable two-way GitHub issue sync by default.
- Agents may open draft PRs only for accepted executable issues.
- Agents must not auto-open PRs for triage/discovery output unless the current
  issue explicitly asks for a PR.

Optional AI review workflows should be trigger-based, for example by PR label or
comment, not automatic on every PR. This keeps cost and noise under operator
control.

## Session Cadence

At session start:

1. Open `PSG Command`.
2. Pick from `PSG Execution` unless the task is explicitly planning, parked, or
   review.
3. Read the issue, parent, relations, latest comments, and linked docs before
   editing.
4. Post a start comment with branch, plan, and gates.

At session close:

1. Post validation and signoff.
2. Move to `In Review` or `Done` only when evidence supports it.
3. Do not create follow-up issues unless the prompt allowed it. Otherwise post
   the proposed follow-up table.

Weekly or after large agent runs:

1. Check `PSG Command`.
2. Check `PSG Execution`.
3. Check `PSG Parked`.
4. Check duplicate and canceled-blocker relations.
5. Collapse any agent-created sprawl into parent/sub-issues or duplicate
   relations.

## References

- Linear Projects: https://linear.app/docs/projects
- Parent and sub-issues: https://linear.app/docs/parent-and-sub-issues
- Issue relations: https://linear.app/docs/issue-relations
- Custom views: https://linear.app/docs/custom-views
- Display options: https://linear.app/docs/display-options
- Triage: https://linear.app/docs/triage
- GitHub automations: https://linear.app/docs/github
- Agents in Linear: https://linear.app/docs/agents-in-linear
- Coding sessions: https://linear.app/docs/coding-sessions
