# 21 - PR03B / Batch B Active-Case DB Authority

Status: **Implemented on branch `codex/pr03b-active-case-db-authority` (Run 33);
Land/review pending if unmerged**.
Scope: one large target-zone PR, not a discussion note.
Implements: Phase ID-4 and the active-case parts of ID-5 from
`09_identity_auth_cutover.md`; carries B-11.
Locked decisions: D1-D3, D5, D12, D17, D24, D29-D32 in
`00_migration_charter.md`.

This candidate replaces active-case authority from env/config/pointer files with
Supabase/Postgres authority. It intentionally does **not** migrate historical
case data, findings, timelines, TODOs, evidence metadata, reports, audit logs,
OpenSearch data, RAG data, or backend registration. Existing case directories,
memory images, disk images, and other forensic files remain test/runtime
artifacts. They are not active-case authority.

## 1. Operator Decisions Locked For This Batch

Run 31 locks the PR03B active-case model as D32:

- Supabase/Postgres `app.active_case_state` is the only active-case authority.
- `SIFT_CASE_DIR`, `SIFT_CASES_ROOT`, `gateway.yaml case.dir`, and
  `~/.sift/active_case` are not read as authority.
- PR03B does not generate active-case compatibility exports.
- Stale env/config/pointer values must be ignored and covered by tests.
- No historical data migration is in scope.
- Existing evidence/case artifact files remain on disk and may be referenced by
  DB case rows as artifact paths. That is a data/artifact reference, not active
  governance authority.

If a Build session finds an installed API, schema, FastMCP proxy behavior, or
repo invariant that makes this model impossible without changing scope, stop and
raise a fork under D29. Do not reintroduce env/pointer authority as a fallback.

## 2. Required Reading

Read in this order before coding:

1. `docs/migration/MIGRATION_STATE.md` - Current Objective and latest Run.
2. `docs/migration/00_migration_charter.md` - D24, D29-D32.
3. `docs/migration/REGISTER.md` - B-11 and carried backlog.
4. `docs/migration/09_identity_auth_cutover.md` - ID-4/ID-5.
5. `docs/migration/18_target_architecture_acceleration.md` - Batch B.
6. `docs/migration/20_portal_dashboard_inventory.md` - portal/API map.
7. `docs/migration/OPERATING_MODEL.md` - loop, DoD, review gates.
8. `AGENTS.md` - host to VM test path.

Ground the implementation in source before changing it. At minimum inspect every
file named in §3 and record what changed in the Run log.

## 3. Grounded Current-State Inventory

The current runtime still has broad file/env active-case authority:

| Area | Current source evidence | PR03B target |
| --- | --- | --- |
| Portal case resolution | `packages/case-dashboard/src/case_dashboard/routes.py::_resolve_case_dir()` calls `sift_common.resolve_case_dir()` and errors with "Set SIFT_CASE_DIR" | Portal reads active case from DB callback/service only. |
| Portal case activation | `routes.py::post_case_activate()` writes `gateway.yaml case.dir`, sets process env, writes `~/.sift/active_case`, then restarts backends | Activation updates `app.active_case_state`, audits, and refreshes Gateway request context. No env/config/pointer write. |
| Portal case create | `routes.py::post_case_create()` creates filesystem skeleton and then writes config/env/pointer active case | Create writes `app.cases` + membership + optional artifact path, and sets DB active case only if requested. |
| Gateway config | `packages/sift-gateway/src/sift_gateway/config.py::apply_case_env()` sets `SIFT_CASE_DIR` / `SIFT_CASES_ROOT` from YAML | Stop publishing active-case env. `case.root` may remain an artifact-root bootstrap only. |
| Common resolver | `packages/sift-common/src/sift_common/__init__.py::resolve_case_dir()` reads env then pointer file | Target request path uses DB active-case context, not this resolver. Tests prove stale values do not win. |
| Core case IO | `packages/sift-core/src/sift_core/case_io.py::get_case_dir()` reads `SIFT_CASE_DIR` | Core tools receive active-case context via explicit/contextvar service, not global env. |
| Core case manager | `packages/sift-core/src/sift_core/case_manager.py::_require_active_case()` reads env/pointer fallback | Replace active-case lookup on Gateway/tool path with DB/context authority. |
| Core agent tools | `packages/sift-core/src/sift_core/agent_tools.py` uses `get_case_dir()` and `run_command` uses `SIFT_CASE_DIR` for cwd | LocalProvider tools run under Gateway-provided active-case context. |
| Gateway policy | `packages/sift-gateway/src/sift_gateway/policy_middleware.py` evidence gate, response guard, and case context read `SIFT_CASE_DIR` | Middleware resolves DB active case and artifact path before policy checks. |
| Gateway server | `packages/sift-gateway/src/sift_gateway/server.py::_on_case_activated()` mutates config and env then restarts backends | Active-case change is DB/audit/context refresh. Restart is only used if required by a non-env resource change. |
| FastMCP proxy boundary | REGISTER F-6/B-11: parent middleware state does not cross mounted/proxied servers | Gateway must inject/override allowed case arguments or deny case-scoped proxy calls; it must not rely on parent `ctx.set_state`. |

`packages/*-mcp/**` are intentionally not rewritten by PR03B unless the Build
session raises and resolves a fork before coding. The target direction is to
avoid spending this batch on middle-zone add-on rewrites. Gateway-side proxy
case propagation is required; backend package surgery waits for the OpenSearch
core / backend-registry batches unless a hard blocker is formally approved.

## 4. Scope Fence

Allowed paths for this PR:

- `supabase/migrations/**`
- `tests/db/**`
- `packages/sift-gateway/**`
- `packages/case-dashboard/**`
- `packages/sift-common/**`
- `packages/sift-core/**`
- `configs/gateway.yaml.template`
- `pyproject.toml`, `uv.lock` only if dependencies truly change
- `docs/migration/**`
- `AGENTS.md`, `CLAUDE.md`

Explicitly out of scope:

- `packages/*-mcp/**` unless a fork is raised and resolved before coding.
- OpenSearch runtime/config, OpenSearch version/security rollout, and D19 core
  move.
- Evidence metadata/status migration and evidence-gate DB metadata authority
  beyond selecting the correct active case for the existing gate.
- Findings, timeline, TODO, IOC, audit-log, report, RAG, and skills data
  migration.
- Jobs/workers and durable job schema beyond preserving the active-case context
  contract for later jobs.
- Installer, Docker/Supabase local state, DB dumps, VM service deploy, secrets,
  or generated build artifacts unless the candidate is amended before Build.

## 5. Schema Work

PR01 already created `app.cases`, `app.case_members`, and
`app.active_case_state`. PR03B should reuse those tables and add only what is
necessary for DB active-case authority.

Expected migration: `supabase/migrations/202606070400_active_case_authority.sql`
or the next available timestamp.

Candidate schema changes:

- Clarify comments on `app.cases.legacy_case_dir` and
  `app.cases.legacy_case_yaml_path`: during the transition these may point to
  filesystem artifact locations, but they are not active-case authority.
- Add indexes/helpers only if query plans or repository code need them.
- Add an idempotent SQL helper/view only if it simplifies atomic read/write of
  the deployment active case and can be tested in rollback.
- Do **not** bulk import existing case directories or JSON files.
- Do **not** create evidence/findings/timeline/report/job/RAG tables in PR03B.

Required DB tests:

- `tests/db/test_pr03b_active_case_schema.py` validates the migration text,
  helper/view shape if added, RLS still enabled on the relevant PR01 tables, and
  no raw secrets or file data fixtures.
- VM Postgres syntax check runs inside `BEGIN; ... ROLLBACK;` against the pinned
  Supabase stack.

## 6. Active-Case Service Contract

Add one Gateway-owned active-case service/repository. The exact module names are
left to the Build session, but the behavior is fixed:

| Operation | Required behavior |
| --- | --- |
| `get_active_case()` | Reads `app.active_case_state(scope='deployment')`, joins `app.cases`, returns case UUID, `case_key`, title/status, artifact case path if present, and metadata. Returns typed no-active-case denial when absent. |
| `set_active_case(case_id, actor)` | Requires operator principal with `operator`/`lead`/`owner`/`admin` membership or system admin policy; updates the single deployment row atomically; audits `active_case.changed`; invalidates request/context cache. |
| `list_cases(principal)` | Lists DB cases visible to the principal via membership/system role. No filesystem scan is authority. |
| `create_case(payload, actor)` | Creates `app.cases`, creates creator membership, creates the filesystem skeleton only as artifact storage if this workflow still needs case-local files, audits, and optionally sets DB active case. |
| `get_case_metadata(case_id)` | Reads DB case metadata/title/status/description and optional artifact path. `CASE.yaml` is not authoritative. |
| `update_case_metadata(case_id, actor, patch)` | Updates DB fields/metadata and audits. `CASE.yaml` export is out of scope unless a fork explicitly adds it. |

Request-time policy must authorize the resolved principal against the DB active
case before a REST handler, core tool, or proxy call can access case data.

## 7. Portal API Changes

Update portal case routes to use the Gateway-injected active-case service
instead of file/env helpers:

| Route group | Required PR03B behavior |
| --- | --- |
| `GET /portal/api/cases` | DB-visible cases only. No `gateway.yaml case.root` or filesystem scan as authority. |
| `POST /portal/api/case/create` | Creates DB case + membership + artifact directory/skeleton if still needed. No active-case env/pointer/config write. |
| `GET /portal/api/case/activate/challenge` | Remove legacy password/HMAC challenge from the active-case flow in Supabase mode. If a challenge route remains for legacy mode, it must not be used for Supabase active-case activation. |
| `POST /portal/api/case/activate` | Authenticated Supabase operator write to `app.active_case_state`; role/membership checked; audited; no env/config/pointer write. |
| `GET /portal/api/case` | Active DB case metadata. No `CASE.yaml` authority. |
| `POST /portal/api/case/metadata` | DB metadata update + audit. File export is out of scope. |

Portal polling routes that still read case-local JSON files may keep using the
active case's DB artifact path as a data path until Batch C/D moves those data
sets. They must not call env/pointer resolvers to decide the active case.

Frontend work should be narrow: update labels/errors only where the API contract
changed. Do not redesign the dashboard.

## 8. Gateway And MCP Policy Changes

The Gateway remains the single policy boundary. PR03B updates the existing
FastAPI + FastMCP substrate:

- Resolve the DB active case before case-scoped REST/MCP operations.
- Extend `Identity` or request context with `active_case_id`, `active_case_key`,
  membership role, and artifact path/reference.
- Keep Supabase JWT validation and B-10 tool authorization from PR03A intact.
- Replace `SIFT_CASE_DIR` reads in SIFT-owned Gateway policy middleware with the
  DB active-case context.
- Evidence gate checks the existing manifest/ledger files for the active DB
  case's artifact path. It must not silently check a different env-selected
  case. Full DB evidence metadata authority remains Batch C.
- Response guard output spill path may use the active DB case artifact path when
  present. If no artifact path exists, cap/redact still runs and reports that
  full output was not persisted.
- Audit envelopes include DB `case_id` / `case_key` and the resolved principal.
- REST `/api/v1/tools` and FastMCP `/mcp` must apply consistent case membership
  and active-case denial posture.

No Gateway code may set `SIFT_CASE_DIR` as part of active-case selection.

## 9. Core And Common Changes

PR03B may touch `sift-common` and `sift-core` because Gateway local tools call
core code directly and the old helpers are env-bound.

Required direction:

- Add a small active-case context API usable by Gateway local tools. A
  `contextvars`-based request context is acceptable if tests prove isolation
  across concurrent calls; explicit parameters are preferred where local call
  boundaries already support them.
- Keep old env/pointer helpers only for explicitly legacy CLI surfaces if
  removing them would break out-of-scope command-line behavior. They must not be
  used by Gateway/portal/MCP policy after PR03B.
- Add tests where `SIFT_CASE_DIR` and `~/.sift/active_case` point at a different
  case than Postgres; Gateway/portal/core tool paths must use the DB active case
  or deny.
- Preserve D5 write-tool behavior and evidence immutability. This batch is not a
  run-command sandbox redesign.

## 10. Proxied Tool Active-Case Propagation (B-11)

Grounding: F-6 confirmed FastMCP parent middleware wraps proxied tools, but
parent middleware/session state does not cross into mounted/proxied servers.

PR03B must implement one SIFT-owned guard for proxy calls:

1. Determine whether the mounted tool is case-scoped from the available manifest,
   tool-name namespace, D28 metadata, or explicit Gateway registry data.
2. For case-scoped proxy tools that expose a safe `case_id` or `case_key`
   argument, the Gateway overwrites/injects the DB active case before dispatch.
   Client-supplied cross-case values are rejected unless a later explicit
   cross-case admin policy exists.
3. For case-scoped proxy tools that only accept filesystem paths or implicit
   env active case, PR03B must **deny** with a typed, audited error instead of
   setting env or passing a raw case directory to an arbitrary backend.
4. Global/query-only tools remain callable when tool authorization allows them,
   but their audit envelope still records the active DB case if one is set.

If the installed FastMCP 3.4.2 proxy API cannot support pre-dispatch argument
mutation or deterministic denial for mounted tools, stop and raise a fork. Do
not bypass B-11 by reviving `SIFT_CASE_DIR`.

## 11. No-Data-Migration Rule

This PR may create schema and runtime code, but it must not migrate historical
data from files into DB tables. In practical terms:

- Do not import `findings.json`, `timeline.json`, `todos.json`, `iocs.json`,
  audit JSONL, reports, evidence manifests, RAG stores, or OpenSearch data.
- Do not bulk-register every old case directory.
- Tests may create temporary case directories and DB rows that point at them.
- VM acceptance may use the operator's memory/disk-image test data by creating a
  fresh DB case row that references the case artifact path. That is live
  validation, not a historical migration.

## 12. Required Tests

Host tests:

- DB schema tests for the PR03B migration.
- Gateway active-case repository/service tests:
  - no active case -> typed denial;
  - set active case -> DB row changes and audit write requested;
  - unauthorized principal denied;
  - stale env/pointer/config values ignored.
- Gateway policy tests:
  - evidence gate uses DB active-case artifact path;
  - response guard/capping uses DB context or safely reports no spill path;
  - audit envelope includes DB case id/key.
- FastMCP tests:
  - local core `case_info` returns DB active case;
  - proxied case-scoped tool with `case_id` receives the DB active case;
  - proxied case-scoped tool without a safe case argument is denied;
  - client-supplied mismatched `case_id` is rejected/overwritten per policy;
  - parent middleware still wraps mounted tools after the change.
- Portal tests:
  - case list/create/activate/metadata use injected DB callbacks;
  - legacy challenge is not required in Supabase mode;
  - no writes to `gateway.yaml case.dir`, env, or `~/.sift/active_case`;
  - stale env/pointer cannot alter portal active case.
- Core/common tests:
  - Gateway-local tool path uses active-case context;
  - legacy helper behavior, if retained for CLI, is not used by Gateway paths.

VM acceptance:

- Sync to `~/sift-mcps-test` using `AGENTS.md`.
- `UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never ~/.local/bin/uv sync --extra core --group dev --python /usr/bin/python3.12`.
- Import smoke for `yaml`, `mcp`, `fastmcp`, `sift_core`, `sift_gateway`.
- Apply PR03B migration inside `BEGIN; ... ROLLBACK;` against live Supabase
  Postgres.
- Run targeted DB, Gateway, case-dashboard, and core/common tests.
- Create two DB cases pointing at temporary or operator-provided test artifact
  directories; set active case; confirm portal and `/mcp` see the DB case while
  stale `SIFT_CASE_DIR` and `~/.sift/active_case` point elsewhere.
- Confirm no repo file or test fixture contains raw Supabase secrets or tokens.

Review gates:

- `/code-review` mandatory.
- `/security-review` mandatory because this touches Gateway policy, authz,
  evidence gate case resolution, audit context, and active-case controls.

## 13. Stop/Fork Conditions

Stop and raise a fork if any of these occur:

- The PR01 schema cannot support DB active-case authority without historical
  data migration.
- Pinned Supabase/Postgres behavior differs from the assumptions in this doc.
- FastMCP 3.4.2 cannot mutate/deny mounted proxy tool calls before dispatch.
- Dropping active-case env/pointer/config authority would require changes
  outside the scope fence to preserve a required PR03B acceptance gate.
- A required test can pass only by setting `SIFT_CASE_DIR`,
  `SIFT_CASES_ROOT`, `gateway.yaml case.dir`, or `~/.sift/active_case`.
- A build agent wants to add evidence/findings/jobs/OpenSearch/RAG data
  migration to make tests pass.

## 14. Deliverable

One revertable PR on a worktree/branch off `revamp/spg-v1`, with unit commits
split by non-overlapping responsibility if multiple agents run in parallel:

1. Schema/service foundation.
2. Gateway/FastMCP policy and proxy active-case propagation.
3. Portal case API turnover.
4. Core/common active-case context.
5. Tests/docs/log.

The Land commit must update:

- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/09_identity_auth_cutover.md`
- `docs/migration/18_target_architecture_acceleration.md`
- `docs/migration/20_portal_dashboard_inventory.md` if portal facts changed
- `docs/migration/REGISTER.md` marking B-11 DONE only at Land
- `AGENTS.md`, `CLAUDE.md` handoff state

## 15. Ready Build Prompt

```text
ROLE & MODE: Build-stage coding session for SIFT PR03B / Batch B
(active-case DB authority, ID-4/active-case part of ID-5). Implement ONLY
docs/migration/21_pr03b_active_case_db_authority.md. Do not redefine scope.
If the doc is wrong, the installed FastMCP 3.4.2 proxy API differs, pinned
Supabase/Postgres behavior differs, or dropping env/pointer/config active-case
authority requires out-of-scope changes, STOP and raise a fork under D29.

REQUIRED READING (ordered): docs/migration/MIGRATION_STATE.md current objective
+ latest Run; docs/migration/21_pr03b_active_case_db_authority.md; 
docs/migration/00_migration_charter.md D24/D29-D32; docs/migration/REGISTER.md
B-11 plus carried backlog; docs/migration/09_identity_auth_cutover.md ID-4/ID-5;
docs/migration/18_target_architecture_acceleration.md Batch B; 
docs/migration/20_portal_dashboard_inventory.md; docs/migration/OPERATING_MODEL.md;
AGENTS.md host->VM path.

GROUND IN SOURCE BEFORE CHANGING: inspect every file named in doc 21 §3 and all
tests around the touched routes/middleware. Re-confirm against the INSTALLED
fastmcp 3.4.2 wheel that parent middleware still wraps mounted proxy tools and
that proxy call arguments can be mutated or denied before dispatch. Record the
facts in MIGRATION_STATE.md.

DELIVERABLE: Supabase/Postgres app.active_case_state is the only active-case
authority. Portal case list/create/activate/metadata use DB service/callbacks.
Gateway REST and FastMCP /mcp resolve the DB active case, enforce membership,
feed evidence gate/response guard/audit from DB context, and stop reading
SIFT_CASE_DIR/gateway.yaml case.dir/~/.sift/active_case as authority. Core local
tools receive active-case context without env authority. B-11 is handled:
proxied case-scoped tools get DB case_id/case_key injection/override when safe,
or a typed audited denial when they depend on implicit env/filesystem case.

HARD CONSTRAINTS: no historical data migration; no findings/timeline/TODO/evidence
metadata/report/audit/RAG/job/OpenSearch data migration; no secrets in repo/tests;
do not touch packages/*-mcp/** unless a fork is raised and resolved first; no
installer/Docker/local Supabase state/DB dump changes. Preserve D5 write-tool
behavior, evidence immutability, D30 Supabase JWT model, and PR03A B-10 authz.
No generated active-case env/pointer/config compatibility exports.

TESTS/GATES: add the doc 21 §12 parity suite. Host tests for DB, Gateway, portal,
core/common, and FastMCP proxy behavior. VM tests on 192.168.122.81 with
/usr/bin/python3.12 and UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never,
including Postgres BEGIN/ROLLBACK migration syntax check and a two-case stale
env/pointer negative test. Run /code-review and /security-review. Run
python3 scripts/validate_migration_docs.py and git diff --check. Mark B-11 DONE
only at Land and log the run.
```
