# CLAUDE.md — SIFT MCPs (Claude Code entry point)

`AGENTS.md` is the canonical agent-instruction file for this repo; everything in it
applies to Claude Code too. This file mirrors the parts a Claude session must load
first so the workflow is followed from the opening turn.

## Read first, in this order

1. `docs/migration/MIGRATION_STATE.md` — Current Objective + the latest Run; this is
   where you are.
2. `docs/migration/OPERATING_MODEL.md` — the development loop and gates you must
   follow (charter decision **D29**).
3. `docs/migration/00_migration_charter.md` — "Confirmed Decisions (Locked)" (D#) and
   "Cutover Order", before making any architectural claim.
4. `docs/migration/REGISTER.md` — open Forks (F#) and Backlog (B#).
5. `AGENTS.md` — host/VM workflow, VM coordinates, Supabase pins, safety rules.

## Development Workflow (MUST FOLLOW — D29)

- **Loop:** Plan → Build → Review → Land → Log. Plan and Build are separate sessions;
  a build session must not redefine its own scope.
- **Canonical sources, never contradicted silently:** the charter (Decisions D#),
  `OPERATING_MODEL.md` (process), `REGISTER.md` (Forks F# / Backlog B#).
- **Scope fence:** touch only the paths the active candidate doc declares; parallel
  units have zero file overlap. One worktree per unit off `revamp/spg-v1`; one commit
  per unit; update the golden snapshot / change-map.
- **Definition of Done** (`OPERATING_MODEL.md` §3) gates every PR. Run `/code-review`
  always; run `/security-review` whenever the diff touches auth, MCP/service tokens,
  the evidence chain/gate, secrets, response redaction, or the Gateway policy path.
- **No silent decisions.** If you must decide something not already locked, stop and
  raise a fork in `REGISTER.md` for the operator; it becomes a D# or B#.
- **Documentation-only by default.** `docs/migration/` is planning; do not introduce
  schemas, code, migrations, package/Docker changes, or behavioral rewrites unless the
  current run is explicitly scoped to them.
- **Log** every run in `MIGRATION_STATE.md` and resolve its forks.
- **Doc format is a contract.** `REGISTER.md`, `MIGRATION_STATE.md`, and the charter
  decision table are parsed by tooling (the Mission Control dashboard). Preserve the
  structures in `OPERATING_MODEL.md` §8; run `python3 scripts/validate_migration_docs.py`
  before Land (it is a Definition-of-Done gate). Changing a format = update §8, the
  validator, and the consumer in the same run — no silent drift.

## Where things are

- Locked decisions / cutover order → `00_migration_charter.md`
- Process, Definition of Done, templates → `OPERATING_MODEL.md`
- Open forks + backlog → `REGISTER.md`
- Run history, current objective, next run → `MIGRATION_STATE.md`
- Gateway cutover (D27b): design KB → `14_fastmcp3_supabase_integration.md`;
  **implementation candidate (design-frozen, Build-ready)** → `17_gateway_cutover_d27b.md`
- Backend revamp (D27a) spec + per-tool contracts → `15_backend_tooling_revamp.md`,
  `16_backend_tool_contracts.md`
- Host/VM + Supabase operational details → `AGENTS.md`

---

## Claude's Delivery-Management Playbook (Claude-only)

This section is mine. The operator runs **Build** sessions (the Codex orchestrator + its
subagents create worktrees and implement); I run **Plan**, **Review/GO**, **Land**, and I
own the gateway cutover (**D27b**) and integration. The operator hands me build outputs in a
fresh session; I take over from there. This playbook lets me re-enter cold and act
correctly within one turn.

### Catch-up ritual (every session, before acting)
1. `git log --oneline -8` and `git status -s` — what landed, what's dirty, which branch.
2. `MIGRATION_STATE.md` → Current Objective + latest Run — where we are in the loop.
3. `REGISTER.md` → open **F#** (need my call) and **B#** (must be carried). 
4. `00_migration_charter.md` "Confirmed Decisions" if I'm about to make an architectural claim.
5. Name the loop stage out loud (Plan / Build / Review / Land / Log) before doing anything.

### Pipeline map (update as it moves)
`JOB-0 ✓ → ID-1/PR01 ✓ → ID-2/PR02 ✓ → D27a backend revamp (BUILD Run 20 `c0a404a` ✓;
REVIEW + REMEDIATE + LAND Run 21 `5ab3df5` ✓, merged to `revamp/spg-v1`) →
D27b gateway cutover (PLAN Run 22 ✓ — doc 17 design-frozen; all forks resolved [F-11
deferred]; D-1/D-2/D-3 locked) → [D27b BUILD — NEXT, coding agent] → D27b REVIEW/LAND —
MINE → evidence/audit → jobs/OpenSearch-core → findings/RAG/skills.` The cutover order is
in the charter; D27a merged before D27b.

### Review → GO procedure (when the operator hands me D27a outputs)
1. **Scope fence:** `git diff --stat <base>..<branch>` — only `packages/*-mcp/**` touched. Any
   stray path = NO-GO until explained.
2. **Surface diff:** read the golden-snapshot diff + the change-map. Every rename has a
   deprecated alias; the F-1 resources + aliases and the F-2 legacy aliases are present.
3. **`/code-review`** the collected diff. Triage: fix-now vs new B#.
4. **`/security-review`** — mandatory here. Specifically check: F-5 `password` redaction at the
   tool boundary; that output models don't leak secrets into `structured_content` (B-3 is the
   gateway-side guard, owed at D27b — confirm it's still tracked, not silently assumed done);
   no tokens/evidence/secrets in fixtures or snapshots.
5. **Contract conformance:** spot-check tool blocks against `16_backend_tool_contracts.md` §5
   (typed in/out, annotations, result shaping, error model); ≥1 prompt + ≥1 resource per
   backend; D5 write-tools still `readOnlyHint=false` with execution unchanged.
6. **Tests:** green on host AND on the VM (AGENTS.md path). No green VM run = NO-GO.
7. **Decide.** GO → I Land (merge `revamp/backends-mcp3` into `revamp/spg-v1`), add the Run
   entry, close F#/B# that are done, flip doc statuses to "implemented in <commit>". NO-GO →
   I write precise, file/line remediation back for a follow-up Build session; nothing merges.

### Invariants I enforce on every review/decision
- Charter wins; **no silent decisions** — if a build made one, it's a finding.
- Gateway is the policy boundary; FastMCP is substrate only (D24). Policy (evidence gate,
  response guard, audit, active-case, authz) is never delegated to the framework.
- Principal separation: machines = hash-only tokens; humans = Supabase-JWT via FastAPI DI
  (D26). No human JWT ever handed to an agent.
- D5 write-tool guardrail; evidence immutability; agent findings stay proposed until approved.
- No secrets/tokens in repo files, fixtures, or snapshots.
- The structured_content redaction (B-3) is a **hard gate at D27b** — I do not start D27b
  review without it.

### Backlog I must carry into D27b / later (from REGISTER.md)
- **B-1** remove reclassified tool aliases once skills/RAG use the resource URIs (at/after D27b).
- **B-2** remove the 10 legacy wintriage aliases after one cycle; first update the
  `forensic-knowledge` playbook + `tool_metadata.py` `analyze_filename` reference.
- **B-3** gateway response-guard must scan `structured_content` — **gate for D27b**.
  **Designed in doc 17 §5** (single `guard_tool_result` redacting both `content` and
  `structured_content`, recursive over nested JSON, bounded depth, no external `$ref`).
  M2 (Run 21) gave the typed `anyOf[success, ToolError]` schema; the scan/redaction is
  owed at D27b Build.
- **B-4** replace credential-as-tool-arg (`opensearch_ingest.password`) with a named
  control-plane credential — auth/jobs phase.
- **B-5** `opensearch_case_detections_resource` ignores its `case_id` param — D27b do-by,
  but the code is in `packages/opensearch-mcp/**` (**out of the D27b gateway scope fence**)
  → either keep masked by D4 and re-defer, or a separate backend touch.
- **B-6** consolidate the duplicate per-registry `ToolResult` envelope builders — folded
  into the doc 17 §5 single `guard_tool_result` point at the gateway.
- **B-7** OpenSearch `ResultMeta` parity (examiner/caveats/interpretation_constraint/audit_warning).
- **B-8** dedupe the two byte-identical opensearch resources under different URIs.
- **B-9** D27a robustness nits (error-code substring heuristic; unaudited wintriage generic
  catch; exact-key-match redactor; per-call `inspect.signature`).
- **B-10** per-agent-token **tool authorization** (restrict which tools a token may
  list/call, for benchmarking) — SIFT-enforced in `on_call_tool` (reject before
  `call_next`) + list filtering; infra exists (`mcp_token_scopes`/`Identity.tool_scopes`,
  defaults `mcp:*`, unenforced). Auth/jobs phase.
- **B-11** active-case must reach **proxied** backends via args/result/shared store, not
  parent `ctx.set_state` (FastMCP state does not cross the mount boundary) — D27b Build.

### My next handoff
D27b is **planned and design-frozen** (Run 22, `17_gateway_cutover_d27b.md`): all forks
resolved (F-6 YES/grounded vs fastmcp 3.4.2; F-7 drop per-backend routes → charter D3;
F-8 FastAPI; F-9 drop → B-10; F-10 retired→core; F-12 keep) except **F-11** (deferred);
design decisions **D-1** (`SiftTokenVerifier`), **D-2** (SSRF egress in-PR), **D-3** (unary
results) locked. **Next is a Build session** (coding agent, scoped worktree off
`revamp/spg-v1`) implementing doc 17 — build prompt in doc 17 §10; first commit is the
F-6 in-memory proxy spike. **I (Claude) own the D27b Review/GO + Land**, and I do **not**
start D27b review until **B-3** is implemented. Carry B-5…B-11.
