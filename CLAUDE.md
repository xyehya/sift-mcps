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
- Backend revamp (D27a) spec + per-tool contracts → `15_backend_tooling_revamp.md`,
  `16_backend_tool_contracts.md`
- Gateway cutover (D27b, landed): design KB → `14_fastmcp3_supabase_integration.md`;
  implemented candidate/log → `17_gateway_cutover_d27b.md`
- Target architecture / acceleration plan → `18_target_architecture_acceleration.md`
- PR03A / Batch A unified JWT candidate/log (landed) →
  `19_pr03_unified_supabase_jwt_identity.md`
- Landed Build candidate (PR03B) → `21_pr03b_active_case_db_authority.md`
- Next Build candidate (D22A / Batch H) → `22_d22a_mcp_backends_registry.md`
- Host/VM + Supabase operational details → `AGENTS.md`

---

## Claude's Delivery-Management Playbook (Claude-only)

This section is mine. The operator can hand me Build outputs in a fresh session;
I run Plan, Review/GO, Land, Log, and doc reconciliation under D29. This
playbook lets me re-enter cold without reviving stale D27b or pre-D30
assumptions.

### Catch-up ritual (every session, before acting)
1. `git log --oneline -8` and `git status -s` — what landed, what's dirty, which branch.
2. `MIGRATION_STATE.md` → Current Objective + latest Run — where we are in the loop.
3. `REGISTER.md` → open **F#** (need my call) and **B#** (must be carried). 
4. `00_migration_charter.md` "Confirmed Decisions" if I'm about to make an architectural claim.
5. Name the loop stage out loud (Plan / Build / Review / Land / Log) before doing anything.

### Pipeline map (update as it moves)
`JOB-0 done -> PR01/ID-1 done -> PR02/ID-2 done -> D27a done -> D27b done ->
Run 26 target architecture/D30 done -> Run 27 PR03A candidate done -> Run 28
PR03A BUILD + Review + VM acceptance done -> Run 29 PR03A portal auth-mode
remediation + Land -> Run 30 portal/dashboard inventory captured -> Run 31
PR03B candidate + D32 active-case cutover lock -> Runs 33-34 PR03B/Batch B
active-case DB authority Land (ID-4, B-11 DONE) -> Run 35 D22A/Batch H
mcp_backends registry candidate (doc 22; forks F-14/F-15 open) -> Build D22A
(resolves F-11, B-13) -> evidence/audit DB authority -> jobs/OpenSearch-core ->
findings/RAG/skills -> legacy authority sunset.`

### Historical Review -> GO procedure for PR03A outputs
1. **Scope fence:** diff against the PR03A base. Allowed paths are exactly those
   in `19_pr03_unified_supabase_jwt_identity.md`. Any `packages/*-mcp/**`,
   `sift-core`, evidence, jobs/workers, OpenSearch runtime/config, installer,
   Docker/Supabase state, or unrelated config path is NO-GO unless doc 19 was
   formally amended before Build.
2. **API grounding:** confirm the build recorded FastMCP 3.4.2 auth/list
   middleware facts and pinned Supabase v1.26.05 Auth/Admin endpoint facts. Any
   mismatch without a fork is NO-GO.
3. **`/code-review`:** prioritize correctness, rollback safety, broken auth
   behavior, missing tests, and stale legacy defaults.
4. **`/security-review`:** mandatory. Check Supabase JWT validation, session
   cookies, refresh handling, service-role use, agent JWT issuance, no token
   logging/storage, legacy fallback flags, portal agent denial, MCP policy
   ordering, B-10 list/call consistency, and B-14 duplicate-resolution cleanup.
5. **Schema/RLS:** verify the migration is additive, syntax-checked on the VM,
   and does not grant broad direct writes. Browser direct writes remain narrow
   and explicit per D12.
6. **Tests:** host and VM evidence are required. No VM run with
   `/usr/bin/python3.12`, `UV_NO_MANAGED_PYTHON=1`, and
   `UV_PYTHON_DOWNLOADS=never` means NO-GO.
7. **Decide:** GO means mark B-10/B-14 DONE at Land, log the Run, and update
   doc 19/09/18 state. NO-GO means return concrete remediation; do not merge.

### Invariants I enforce on every review/decision
- Charter wins; **no silent decisions** — if a build made one, it's a finding.
- Gateway is the policy boundary; FastMCP is substrate only (D24). Policy (evidence gate,
  response guard, audit, active-case, authz) is never delegated to the framework.
- D30 wins over the old D26 split: humans, agents/MCP clients, workers, and
  services authenticate with Supabase-issued JWTs in the final target. PR02
  hash-only tokens are a bridge only while explicitly enabled.
- Supabase Auth proves identity; SIFT Gateway resolves app principals and
  enforces case/tool/evidence/audit policy.
- D5 write-tool guardrail; evidence immutability; agent findings stay proposed until approved.
- No raw JWTs, refresh tokens, PR02 tokens, temporary passwords, Supabase anon
  keys, service-role keys, evidence secrets, or credentials in repo files,
  fixtures, snapshots, logs, audit payloads, or docs.
- Agent/service JWTs can authenticate to `/mcp`; normal portal operator APIs
  deny agent/service principals unless a scoped doc explicitly allows an
  exception.

### Backlog I must carry forward (from REGISTER.md)
- **B-1** remove reclassified tool aliases once skills/RAG use the resource URIs (at/after D27b).
- **B-2** remove the 10 legacy wintriage aliases after one cycle; first update the
  `forensic-knowledge` playbook + `tool_metadata.py` `analyze_filename` reference.
- **B-3** DONE at D27b Land: gateway response guard scans `structured_content`.
- **B-4** replace credential-as-tool-arg (`opensearch_ingest.password`) with a named
  control-plane credential — auth/jobs phase.
- **B-5** `opensearch_case_detections_resource` ignores its `case_id` param; out
  of PR03A.
- **B-6** DONE at D27b Land: gateway `guard_tool_result` is the agent-facing
  redaction/cap point.
- **B-7** OpenSearch `ResultMeta` parity (examiner/caveats/interpretation_constraint/audit_warning).
- **B-8** dedupe the two byte-identical opensearch resources under different URIs.
- **B-9** D27a robustness nits (error-code substring heuristic; unaudited wintriage generic
  catch; exact-key-match redactor; per-call `inspect.signature`).
- **B-10** DONE at PR03A Land: per-principal tool authorization under D30, with
  `mcp:*`, `tool:<name>`, and `namespace:<prefix>`, SIFT-side list filtering and
  reject-before-call enforcement.
- **B-11** DONE at PR03B Land: active-case reaches proxied backends through safe
  `case_id`/`case_key` args or typed audited denial, not parent `ctx.set_state`.
- **B-12** preserve capped-result `backend_audit_id`; post-D27b gateway hardening.
- **B-13** proxy namespace/collision assertion; D22/Batch H registry phase.
- **B-14** DONE at PR03A Land: duplicate MCP token/JWT resolution removed with
  one shared Supabase resolver and identity-free raw ASGI connection guards.
- **B-15** DNS-rebinding TOCTOU hardening; network hardening phase.

### My next handoff
PR03A is **landed** on `revamp/spg-v1` (Runs 28-29). All gates passed:
`/code-review` (NO-GO -> 10 findings remediated), `/security-review` (clean),
host tests, VM tests, live Supabase v1.26.05 acceptance, and
`validate_migration_docs.py`. B-10 and B-14 are DONE; F-13 resolved into **D31**
(revocation = DELETE auth user + app-revoke + resolver cache invalidate, since
pinned GoTrue lacks admin session logout). Run 30 added
`docs/migration/20_portal_dashboard_inventory.md` as a normalized portal/API
inventory reference.

PR03B / Batch B (active-case DB authority, ID-4) is landed on `revamp/spg-v1`
from `docs/migration/21_pr03b_active_case_db_authority.md`. D32 locks the
active-case model: Supabase/Postgres `app.active_case_state` wins; no
active-case env/config/pointer authority or generated exports; no historical
data migration. Run 35 planned **D22A / Batch H** in
`docs/migration/22_d22a_mcp_backends_registry.md`: move add-on backend
registration from `gateway.yaml` into the `app.mcp_backends` control-plane
registry, make the Gateway loader DB-authoritative, turn the portal backend
surface over to the DB, and resolve F-11 + B-13 at Land. It raised two blocking
forks for the operator — **F-14** (backend credential storage model) and
**F-15** (FastMCP activation: restart/apply vs live remount) — that must be
resolved before that Build. Carry B-4/B-12/B-15 forward (B-13 is scoped into
D22A) unless a scoped doc closes them. Deployment note: the VM systemd
`sift-gateway` runs the old tree
(`~/sift-mcps`); production rollout of the new auth code/config/env is the
installer follow-up, not PR03A.
