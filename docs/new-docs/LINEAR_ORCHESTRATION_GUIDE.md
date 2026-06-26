# Linear Orchestration Guide

> Covers: Linear project ProtocolSIFTGateway, docs/new-docs/OPTIMIZATION_TRACK.md, docs/new-docs/AXIS_A_BUILD_PLAN.md, docs/new-docs/AXIS_B_BUILD_PLAN.md
> Class: living-plan
> Last validated: dd54eb4 (2026-06-16)

Canonical current policy lives in
`docs/new-docs/LINEAR_OPERATING_MODEL.md`. This guide is retained for older
orchestration prompts and historical context. If the two conflict, the operating
model wins.

Use this guide after the Linear setup to keep the project systematic. Linear is
the active queue. Repo docs are reference packs and stable guardrails.

## Current Linear Shape

Active milestones:

- `MVP Closeout`: remaining pre-optimization work already captured in Linear.
- `OT1: Safety Net + DB Authority`: assessment-driven optimization track 1.

Historical/completed milestone:

- `Linear operating model`: setup proof; leave completed.

Superseded granular milestones:

- `PT2 Portal RAG policy`
- `CL2 ProtocolSiftGateway rename`
- `Rocba DFIR investigation`
- `Ops verification and polish`

Those granular lanes are now represented as issues under `MVP Closeout`. Keep
them as historical context unless Linear UI cleanup is needed.

## Issue Map

MVP Closeout:

- `XYE-6`: portal shared-RAG policy decision
- `XYE-7`: repo rename and add-on layout
- `XYE-8`: Rocba DFIR investigation
- `XYE-9`: AppArmor and migration idempotency live verification
- `XYE-10`: doubled OpenSearch index prefix polish
- `XYE-11`: memory-ingest hostname_source label polish

OT1:

- `XYE-12`: OT1 coordinator
- `XYE-13` / `AU1`: CI workflow
- `XYE-14` / `AU2`: per-package coverage floors
- `XYE-15` / `AU3`: `GatewayProtocol` and pyright gate
- `XYE-16` / `AU4`: retired-test audit
- `XYE-17` / `AU5`: docs freshness checker
- `XYE-18` / `BU0`: case metadata field parity and backfill
- `XYE-19` / `BU1`: DB-native orientation and metadata readers
- `XYE-20` / `BU2`: portal DB-only writes and CASE.yaml export
- `XYE-21` / `BU3`: remove implicit file-mode fallback
- `XYE-22` / `BU4`: retire residual active-case and evidence-ref fallbacks
- `XYE-23` / `BU5`: test sweep and live-VM proof

## Operating Rules

- Start orchestrator sessions from a coordinator issue.
- Start implementation sessions from one assigned executable issue.
- Use comments for session notes, validation, live proof, blockers, and handoff.
- Use fork issues for real out-of-scope work discovered during execution.
- Use discovery issues when the next step is investigation, not implementation.
- Use decision issues when operator choice changes behavior, security posture,
  operator workflow, live-VM risk, or durable architecture.
- Use Linear documents only for durable conventions or accepted decisions that
  should guide many future issues.
- Do not paste secrets, raw JWTs, service-role keys, DSNs, passwords, private
  keys, operator credentials, or sensitive full evidence paths into Linear.
- When running parallel coding agents, the orchestrator must create one git
  worktree per agent manually and point each agent's working directory at it; do
  not rely on the harness `isolation: worktree` flag (it falls back to the shared
  main tree here and races the git index). See the Parallel Agent Worktrees
  section of `LINEAR_OPERATING_MODEL.md`.

## Status Discipline

- `Backlog`: captured, not ready or not currently selected.
- `Todo`: accepted and ready to start.
- `In Progress`: actively being worked.
- `In Review`: work is done but review, tests, live proof, or acceptance remains.
- `Done`: acceptance is satisfied and proof is recorded.

Do not move an issue to `Done` from intent. Move by evidence.

## Recommended Work Order

Default OT1 order:

1. `XYE-13` / AU1
2. `XYE-15` / AU3 and `XYE-16` / AU4, in parallel if file scopes stay separate
3. `XYE-14` / AU2
4. `XYE-17` / AU5
5. `XYE-18` / BU0
6. `XYE-19` / BU1
7. `XYE-20` / BU2
8. `XYE-21` / BU3
9. `XYE-22` / BU4
10. `XYE-23` / BU5

MVP Closeout can proceed in parallel with OT1 only when it does not compete for
the same live VM window or shared files.

## Orchestrator Session Prompt

Use this when you want a session to coordinate Linear, plan next agents, create
forks, or reconcile progress. Replace bracketed fields.

```text
You are coordinating ProtocolSIFTGateway work in Linear.

Start from:
- Project: ProtocolSIFTGateway
- Coordinator issue: [XYE-12 or other coordinator]
- Operating model: Protocol SIFT Gateway Operating Model
- Local guide: docs/new-docs/LINEAR_ORCHESTRATION_GUIDE.md

Goal:
[coordinate OT1 / coordinate MVP Closeout / reconcile branches / prepare next agent batch]

Constraints:
- Linear is the active queue.
- Do not edit code unless explicitly needed for the coordination task.
- Read issues, labels, milestones, relations, and latest comments first.
- Use repo docs only as reference packs.
- If codebase-memory MCP is available, use it for routing before broad file reads.
- Do not paste secrets, raw tokens, DSNs, passwords, private keys, or sensitive full evidence paths.

Tasks:
1. Read the coordinator issue and relevant child issues.
2. Summarize current state, blockers, active branches, and ready-next issues.
3. Identify any stale labels/statuses/dependencies.
4. If new work appears, classify it as comment, fork issue, discovery issue, or decision issue.
5. Create or update Linear objects only after checking for duplicates.
6. End with a concise coordinator comment containing:
   - Current state
   - Next issue to start
   - Blockers/gates
   - Any fork/discovery/decision issues created

Do not mark issues Done unless acceptance and proof are recorded.
```

## Implementation Agent Prompt

Use this when you want an agent to work one issue end to end.

```text
You are implementing one ProtocolSIFTGateway Linear issue.

Start from:
- Project: ProtocolSIFTGateway
- Issue: [XYE-##]
- Operating model: Protocol SIFT Gateway Operating Model
- Local guide: docs/new-docs/LINEAR_ORCHESTRATION_GUIDE.md

Goal:
Complete the assigned issue only.

Constraints:
- Read the issue description, labels, milestone, relations, and latest comments first.
- Read linked docs or local reference packs only for this issue's scope.
- If codebase-memory MCP is available, start with index_status, search_graph, trace_path, and get_code_snippet before broad file reads.
- Verify graph findings against current source and tests before editing.
- Use existing repo patterns.
- Do not create side runbooks.
- Do not revert unrelated user changes.
- Do not paste secrets, raw tokens, DSNs, passwords, private keys, or sensitive full evidence paths into Linear.

Required Linear comments:
1. Start comment:
   Starting.
   Branch: <branch or none yet>.
   Plan: <3-5 concrete steps>.
   Risk/gates: <security/live/operator gates>.

2. Handoff/closeout comment:
   Result: DONE | IN REVIEW | BLOCKED.
   Branch/commits: <branch and commit ids>.
   Changed: <high-signal file/component list>.
   Validation: <commands and results>.
   Live proof: <sanitized proof or N/A>.
   Next: <exact next action>.

Fork rule:
- If you find out-of-scope implementation work, create `Fork: <source issue id> - <specific fork>`.
- If you need investigation before implementation, create `Discovery: <area> - <specific finding>`.
- If a human choice is required, create `Decision: <area> - <choice needed>` and mark `needs-input`.

Stop conditions:
- Stop and report if acceptance requires operator credentials, live VM timing, or a security decision that is not already approved.
- Otherwise continue through implementation, targeted validation, and Linear handoff.
```

## Fork Issue Prompt

Use when an implementation agent finds real work outside the current issue.

```text
Create a Linear fork issue from [SOURCE-ISSUE].

Title:
Fork: [SOURCE-ISSUE] - [specific fork]

Description:
## Source
Raised from [SOURCE-ISSUE] while doing [short context].

## Finding
[What was observed, with sanitized source refs.]

## Why It Is Separate
[Why this is outside the parent scope.]

## Proposed Scope
[Smallest executable next step.]

## Acceptance
[How this fork closes.]

Labels:
[type:follow-up plus component/gate/readiness labels]

Relations:
Relate to [SOURCE-ISSUE]. Use blockedBy/blocks only for hard dependency.
```

## Discovery Issue Prompt

Use when the next step is to learn enough to make a decision or implementation
issue.

```text
Create a Linear discovery issue.

Title:
Discovery: [area] - [specific finding/question]

Description:
## Question
[What needs to be learned.]

## Search Surface
[Repo paths, Linear documents/issues, VM checks, or MCP graph queries allowed.]

## Output
[Expected decision, implementation issue, or no-action closeout.]

## Stop Conditions
[What evidence is enough to stop investigating.]

Labels:
type:discovery plus component/gate labels. Add needs-input only if blocked on the operator.
```

## Decision Issue Prompt

Use when the operator or maintainer must choose.

```text
Create a Linear decision issue.

Title:
Decision: [area] - [choice needed]

Description:
## Decision Needed
[One concrete choice.]

## Options
- Option A: ...
- Option B: ...
- Option C: ...

## Recommendation
[Recommended option and why.]

## Impact
[Code, docs, security, operator workflow, live proof, and follow-up issues.]

## Acceptance
- Decision is recorded.
- Follow-up issues are created or updated.
- Durable docs are updated only if the decision should guide future issues.

Labels:
type:decision, needs-input, and relevant component/gate labels.
```

## Weekly Or Maintenance Review Prompt

Use when the project feels stale or cluttered.

```text
Review ProtocolSIFTGateway Linear hygiene.

Scope:
- Project: ProtocolSIFTGateway
- Milestones: MVP Closeout and OT1: Safety Net + DB Authority
- Include issue statuses, blockers, labels, parent/child relations, and latest comments.

Tasks:
1. Identify issues ready to start.
2. Identify issues blocked by missing operator input, live VM proof, or security review.
3. Identify stale statuses or missing labels.
4. Identify duplicate or superseded issues.
5. Recommend the next 3 actions.

Do not create or modify issues unless explicitly asked. End with a concise action list.
```
