# Migration State

## Current Objective

**PR03B / Batch B active-case DB authority is landed** on `revamp/spg-v1`
(Build Run 33, Land Run 34), from
`docs/migration/21_pr03b_active_case_db_authority.md`. Supabase/Postgres
`app.active_case_state` is now the runtime active-case authority for the scoped
request paths. `SIFT_CASE_DIR`, `SIFT_CASES_ROOT`, `gateway.yaml case.dir`, and
`~/.sift/active_case` are not regenerated as active-case exports and do not win
over the DB active case on Gateway/portal/core/FastMCP request paths. No
historical data migration was added. **B-11 is DONE.**

Landed foundation: D27b gateway cutover is landed on `revamp/spg-v1` (Runs
23-24), serving one FastAPI ASGI app with aggregate FastMCP `http_app` at
`/mcp`; per-backend `/mcp/{name}` routes are removed per D3/F-7. SIFT policy is
FastMCP middleware: evidence gate -> response guard (B-3/B-6) -> case context ->
audit envelope. PR03A / Batch A unified Supabase JWT identity is landed
(Runs 28-29): REST and FastMCP `/mcp` accept Supabase JWTs through the shared
resolver, portal Supabase login/session works, agent/service JWT issuance and
revocation are implemented, B-10 and B-14 are DONE, and D31 locks revocation for
pinned Supabase v1.26.05.

Run 30 added `20_portal_dashboard_inventory.md`, the normalized portal/dashboard
workflow and API inventory. Run 31 reconciled recurring architecture docs and
created doc 21. Run 32 demoted D4 to a historical pointer so new active-case
work cites D32 only. Run 33 implemented PR03B; Run 34 fast-forward landed it on
`revamp/spg-v1`. D30 remains the target credential model; PR02 hash-only tokens
remain a transitional compatibility bridge until ID-6.

FastMCP 3.4.2 grounding was reconfirmed in Run 33 against the installed wheel:
`create_proxy` imports from `fastmcp.server`; `Middleware.on_call_tool(self,
context, call_next)` wraps mounted proxied tools; `context.message.arguments`
can be mutated before `call_next` and those arguments reach the proxied child;
`MiddlewareContext` is frozen, so PR03B uses a Gateway context variable and core
active-case context instead of attaching state to the FastMCP context object.
B-11 is handled by injecting/overriding safe `case_id`/`case_key` arguments or
returning typed audited denials for implicit-env/filesystem case-scoped proxy
tools.

**Next:** **Build D22A / Batch H** from
`docs/migration/22_d22a_mcp_backends_registry.md` (planned in Run 35) once the
operator resolves the two blocking forks it raised — **F-14** (backend
credential storage model) and **F-15** (FastMCP activation: restart/apply vs live
remount). D22A moves add-on backend registration from `gateway.yaml` into a
Supabase `app.mcp_backends` registry, makes the Gateway loader DB-authoritative,
turns the portal backend-management surface over to the DB, and resolves **F-11**
and **B-13** at Land. Keep evidence/audit DB authority (Batch C), jobs/workers
(Batch E), OpenSearch-core, RAG/skills, and findings/timeline/TODO/report data
migration separate unless a new candidate doc explicitly batches them. Carry
B-4/B-12/B-15 forward.

## Run 35 — D22A / Batch H `mcp_backends` Registry Candidate

Plan-stage run (Claude delivery-management). No runtime code, schema migration,
lockfile, Docker, VM, or installer changes.

Trigger: operator scoped the next batch — Plan D22A / Batch H so a later Build
session can move add-on MCP backend registration from `gateway.yaml` into a
Supabase `app.mcp_backends` control-plane registry, resolve F-11, carry B-13, and
preserve the landed PR03A/PR03B Gateway policy model.

Grounded current-state (source read at `335cedd`, not memory):
- `gateway.yaml` is add-on backend authority today: `Gateway.__init__`
  (`server.py:160`) builds `self.backends` from `config["backends"]`;
  `register_backend_logic` (`rest.py:1020`) writes new backends into
  `~/.sift/gateway.yaml` via `_atomic_yaml_write`; `reload_backends` re-reads
  it; the join/wintools path writes there too. Connection secrets
  (`bearer_token`/`env`/`tls_cert`) live in that file.
- FastMCP proxy mounts are fixed at server assembly: `_mount_addon_proxies`
  (`mcp_server.py:219`) runs once inside `create_gateway_mcp_server`, and
  `server.py:970` confirms "MCP proxy mounts are fixed at server startup" — a
  live-registered backend is absent from `/mcp` until restart.
- `assert_mounted_tool_names` (`mcp_server.py:348`) is defined but unused = B-13.
- DB plumbing to mirror already exists: `registry_config` DSN feeds
  `ActiveCaseService` (PR03B) and `PostgresTokenRegistry` (PR02) in `create_app`;
  migrations in `supabase/migrations/`, DB tests in `tests/db/`.

Added:
- `docs/migration/22_d22a_mcp_backends_registry.md` — Build-ready D22A / Batch H
  candidate: `app.mcp_backends` schema (no-raw-secret, credential references,
  health/manifest cache, RLS/D12 write model); DB-authoritative Gateway loader
  (gateway.yaml backends ignored as authority; no-DSN ⇒ core-only, no yaml
  fallback); registry-sourced FastMCP mounts with policy ordering preserved;
  portal/REST turnover; B-13 resolution (§9); F-11 resolution path (Land only);
  VM test plan on pinned Supabase + FastMCP 3.4.2; scope fence + out-of-scope
  list; ready-to-copy Build prompt.

Forks raised (→ REGISTER.md, both OPEN, blocking before Build):
- **F-14** backend credential storage model (recommended: credential references,
  not raw secrets, in `app.mcp_backends`; complements B-4).
- **F-15** activation model (recommended v1: DB authority + restart/explicit-apply
  rebuild; live dynamic remount only if zero-restart is required now).

Updated:
- `REGISTER.md` — F-14/F-15 added; F-11 annotated as D22A/doc 22 (still OPEN,
  resolve at Land); B-13 scoped into D22A §9 (still OPEN, DONE at Land).
- `MIGRATION_STATE.md` — this entry + Current Objective `**Next:**`.
- `00_migration_charter.md`, `README.md`, `AGENTS.md`, `CLAUDE.md` — handoff
  points to doc 22 as the next Build source of truth.

Operator decisions: none yet (F-14/F-15 await the operator). No D# changed.

Verification:
- `python3 scripts/validate_migration_docs.py` — passed.
- `git diff --check` — passed.

Next: operator resolves F-14 + F-15, then Build D22A from doc 22. Do not mark
F-11 RESOLVED or B-13 DONE until that Build lands.

## Run 34 — PR03B Land

Land run on `revamp/spg-v1`.

Trigger: operator requested merge and Land-status documentation update after
Run 33 completed PR03B Build verification.

Changed:
- Fast-forward merged `codex/pr03b-active-case-db-authority` into
  `revamp/spg-v1` at commit `fed4ea7` (`Implement PR03B active-case DB
  authority`).
- Updated recurring migration docs and handoff files from "implemented on
  branch / pending Land" to "landed on `revamp/spg-v1`".
- Marked **B-11 DONE** in `REGISTER.md` because PR03B is now landed.

Verification:
- Run 33 acceptance evidence remains the Land evidence for the merged commit:
  host DB/Gateway/portal/core suites passed; VM migration syntax
  `BEGIN/ROLLBACK`, targeted PR03B suites, broad Gateway/portal/core suites, and
  two-case stale env/pointer negative passed.
- Run 34 docs-only gates: `python3 scripts/validate_migration_docs.py` and
  `git diff --check` passed.

Next: Plan D22A / Batch H (`mcp_backends` registry and `gateway.yaml`
backend-authority removal), carrying F-11 and B-13.

## Run 33 — PR03B Active-Case DB Authority Build

Build-stage run on branch `codex/pr03b-active-case-db-authority`, following
`21_pr03b_active_case_db_authority.md` without redefining scope.

Implemented:
- Added Gateway `ActiveCaseService` for Postgres `app.active_case_state`,
  `app.cases`, memberships, DB audit rows, case list/create/activate/metadata,
  and typed active-case denials.
- Added `202606070400_active_case_authority.sql` comments/helpers only: no
  historical import; `app.deployment_active_case` read helper; legacy case path
  columns documented as artifact references, not active-case authority.
- Portal case list/create/activate/challenge/current-case/metadata now use the
  injected DB active-case service when present. Create may still build the
  artifact directory skeleton, but active-case selection is DB-only and no
  env/config/pointer export is generated.
- Gateway REST and FastMCP policy resolve the DB active case for case-scoped
  operations, enforce membership, feed core local tools through explicit
  active-case context, and stamp evidence gate, response guard, and audit
  envelopes with DB `case_id`/`case_key`.
- B-11 proxy handling implemented: safe proxied case args are injected/overridden
  from DB context; mismatched client case args and implicit-env/filesystem
  case-scoped proxy tools return typed audited denials.
- Core local request paths gained `sift_core.active_case_context`; legacy
  env/pointer fallback remains only for non-Gateway CLI/test compatibility.
- `apply_case_env` no longer publishes or clears `SIFT_CASE_DIR`; template
  `gateway.yaml` no longer declares `case.dir`.

Confirmed before changing code:
- Installed `fastmcp==3.4.2`.
- Parent FastMCP middleware wraps mounted `create_proxy(child)` tools.
- Mutating `context.message.arguments` before proxy dispatch reaches the child
  tool.
- `MiddlewareContext` is frozen, so state is carried by Gateway/core contextvars,
  not by mutating the context object.

Verification:
- Host: `uv run pytest tests/db` — 24 passed.
- Host: `uv run pytest packages/sift-gateway/tests` — 293 passed.
- Host: `uv run pytest packages/case-dashboard/tests` — 309 passed, 64 warnings.
- Host: `uv run pytest packages/sift-core/tests` — 330 passed.
- Host: focused post-fix portal/gateway PR03B tests — passed.
- VM (`192.168.122.81`, `/usr/bin/python3.12`,
  `UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never`): imports OK with
  FastMCP 3.4.2.
- VM Postgres syntax: PR01 + PR03A + PR03B migrations applied inside
  `BEGIN/ROLLBACK` against pinned Supabase/Postgres — clean, rollback left no
  schema.
- VM targeted PR03B suite: 50 gateway/db authz tests, 24 portal tests, and 2 core
  active-case-context tests passed when split by package.
- VM broad suites: `packages/sift-gateway/tests` 293 passed;
  `packages/case-dashboard/tests` 309 passed, 64 warnings;
  `packages/sift-core/tests` 330 passed.
- VM two-case stale-authority negative probe: with stale `SIFT_CASE_DIR` and
  `~/.sift/active_case` pointing at case A, DB active case B was returned by the
  active-case service and portal `/api/case`, used by core active-case context,
  and injected into a mounted FastMCP proxy call.

Review:
- `/code-review` — no blocking findings after the portal active-case metadata
  read path was tightened to use `require_active_case_for_principal` when a
  resolved Supabase principal is present.
- `/security-review` — no blocking findings; no secrets added; DB writes use
  parameterized SQL; active-case proxy denials reject cross-case arguments before
  dispatch.

Land notes:
- Landed by Run 34 on `revamp/spg-v1`; B-11 is DONE.
- No installer, Docker, local Supabase state, DB dump, generated active-case
  export, or `packages/*-mcp/**` change was made.

## Run 32 — D4 Demotion

Docs-only governance cleanup after Run 31.

Trigger: operator asked to "drop D4 down" after D32 became the active-case
cutover decision.

Changed:
- `00_migration_charter.md` now treats **D4** as a historical/superseded pointer
  and keeps the live active-case rule in **D32**.
- D32 now explicitly carries the single deployment-scope active-case-v1 rule,
  portal selection, DB authority, Gateway propagation, no active-case
  env/config/pointer exports, and no historical data migration.
- Current recurring docs and PR03B build instructions now cite D32 instead of D4
  for active-case authority. Historical PR/run documents retain their old D4
  references as provenance.

Next: unchanged — Build PR03B from doc 21.

## Run 31 — PR03B Active-Case DB Authority Candidate

Docs-only Plan run. No runtime code, schema migration, lockfile, Docker, VM, or
installer changes.

Trigger: operator locked the next-batch direction: go full scope on active-case
authority, do **not** do historical data migration, and make
Supabase/Postgres active case win while dropping env/pointer/file active-case
authority.

Decisions:
- Added charter **D32**: PR03B / Batch B goes directly to Postgres
  `app.active_case_state` authority. `SIFT_CASE_DIR`, `SIFT_CASES_ROOT`,
  `gateway.yaml case.dir`, and `~/.sift/active_case` are ignored/dropped as
  active-case authority and are not generated as compatibility exports. Existing
  memory/disk images and case directories remain artifact/data locations only.
- No historical data migration is part of PR03B. Tests may create DB case rows
  pointing at temporary or operator-provided artifact directories.

Added:
- `docs/migration/21_pr03b_active_case_db_authority.md` - Build-ready PR03B /
  Batch B candidate and ready prompt. Scope covers Gateway, portal,
  `sift-common`, `sift-core`, DB migration/tests, docs, and handoff files; it
  excludes `packages/*-mcp/**` unless a fork is raised and resolved first.

Updated:
- `00_migration_charter.md` - PR03A status corrected to landed, D32 added,
  PR03B set as next build.
- `09_identity_auth_cutover.md` - ID-4/ID-5 active-case plan updated to D32
  (no active-case env/config/pointer exports).
- `18_target_architecture_acceleration.md` and `Architecture.mmd` - PR03A
  marked landed, Batch B / D32 target updated.
- `20_portal_dashboard_inventory.md` - portal active-case rows now point to
  doc 21 and D32.
- `02_authoritative_domains_and_boundaries.md`, `05_execution_job_model.md`,
  `07_execution_roadmap.md`, and `08_control_plane_schema.md` - older planning
  references now defer to D32 for active-case exports.
- `REGISTER.md` - B-11 remains OPEN but now names doc 21 and forbids env as the
  proxy active-case bridge.
- `README.md`, `AGENTS.md`, `CLAUDE.md` - current handoff points to doc 21.

Next: Build PR03B from doc 21.

## Run 30 — Portal/Dashboard Inventory Capture

Docs-only grounding run after PR03A Land.

Trigger: operator confirmed the separate portal-inventory worker was
read-only/output-only and pasted its report back into this session. The report
had not been saved to the migration docs.

Added:
- `docs/migration/20_portal_dashboard_inventory.md` — normalized portal/dashboard
  workflow, API, frontend component, backend authority, turnover, risk, and open
  question map. It preserves the separate worker's inventory while removing stale
  old-worktree absolute paths and updating auth rows to the landed PR03A / Run 29
  state.
- `docs/migration/README.md` — index entry for doc 20 and next-run guidance
  refreshed from PR03A Build to PR03B Plan.
- `AGENTS.md` and `CLAUDE.md` — handoff state corrected from "PR03A awaiting
  Land" to "PR03A landed"; doc 20 added as PR03B portal/API grounding.

Important boundary: doc 20 is a **reference inventory, not an implementation
candidate**. A future PR03B build still needs a scoped candidate doc before code
or schema changes.

Verification:
- `python3 scripts/validate_migration_docs.py` — passed.

Next: Plan PR03B / Batch B from doc 9 + doc 18 + doc 20, carrying B-11.

## Run 29 — PR03A Portal Auth-Mode Remediation & Land

Review-remediation/Land run on branch `revamp/pr03a-unified-jwt`, following the
Run 28 acceptance handoff. Runtime scope stayed inside doc 19's PR03A fence:
`packages/case-dashboard/**`, `packages/sift-gateway/**` comment/doc drift, and
`docs/migration/**`.

Trigger: secondary review found that `LoginCard` still queried
`/api/auth/setup-required` before Supabase login, while the backend endpoint only
looked for legacy password JSON. On a fresh Supabase-only deployment with no
legacy password files, the portal could enter the old unauthenticated local
password setup flow. The same review also found that the legacy setup/challenge/
reset endpoints ignored `legacy_portal_session_enabled=False`.

Remediation:
- `case_dashboard.routes` now treats local PBKDF2 setup/challenge/reset password
  auth as disabled whenever Supabase auth callbacks are injected or
  `legacy_portal_session_enabled=False`.
- `/api/auth/setup-required` returns `required=false` in Supabase/disabled-legacy
  mode so a fresh Supabase-only portal starts at email/password login, not local
  password setup.
- `/api/auth/setup`, `/api/auth/challenge`, and `/api/auth/reset-password` fail
  closed with 403 in that mode.
- `sift_gateway.supabase_auth` comment drift corrected: pinned Supabase
  v1.26.05 does not expose admin per-user logout; D31 revocation uses DELETE-user
  + app revoke + resolver cache invalidation.

Verification:
- `uv run pytest packages/case-dashboard/tests/test_pr03_supabase_portal_auth.py`
  — 31 passed.
- `uv run pytest packages/case-dashboard/tests/test_auth_endpoints.py` — 36
  passed.
- `uv run pytest packages/case-dashboard/tests` — 308 passed.
- `uv run pytest packages/sift-gateway/tests/test_pr03_supabase_jwt_auth.py packages/sift-gateway/tests/test_pr03_tool_authorization.py`
  — 61 passed.
- `uv run python -m py_compile packages/case-dashboard/src/case_dashboard/routes.py packages/sift-gateway/src/sift_gateway/supabase_auth.py`
  — passed.
- `python3 scripts/validate_migration_docs.py` — passed.
- Authored-source `git diff --check` — passed; generated Vite bundle whitespace
  remains the accepted Run 28 generated-asset exception.
- SIFT VM (`192.168.122.81`, Python 3.12.3 test venv): copied the four changed
  files to `~/sift-mcps-test`; `packages/case-dashboard/tests/test_pr03_supabase_portal_auth.py`
  + `test_auth_endpoints.py` — 67 passed; PR03A gateway auth/authorization tests
  — 61 passed; changed-file `py_compile` and migration docs validator passed.

Land: fast-forward merge of `revamp/pr03a-unified-jwt` into `revamp/spg-v1`.
No push performed.

Next: Plan PR03B / Batch B (active-case DB authority, ID-4), carrying B-11.

## Run 28 — PR03A / Batch A Unified Supabase JWT Build, Review & VM Acceptance

Coding + review + VM-acceptance run, orchestrated as a 3-agent team (Opus 4.8;
schema / gateway / portal) on branch `revamp/pr03a-unified-jwt` off
`revamp/spg-v1`. Three unit commits; one revertable PR.

Trigger: operator handed off the doc 19 §14 Build prompt and asked to orchestrate
it as an agent team, with all forks escalated (no assumptions).

Scope (doc 19 fence held; `git diff --stat revamp/spg-v1..HEAD` touched only
`supabase/migrations/**`, `tests/db/**`, `packages/sift-gateway/**`,
`packages/case-dashboard/**`, `configs/gateway.yaml.template`):
- **Unit A** — `supabase/migrations/202606070300_unified_jwt_principals.sql`
  (additive): `agents/service_identities.auth_user_id` → `auth.users`,
  `operator_profiles.system_role` (+check), `app.principal_tool_scopes`
  (`mcp:*`/`tool:<name>`/`namespace:<prefix>` grammar, exactly-one-principal +
  active-uniqueness), `app.principal_identities` view (`security_invoker=true`),
  minimal Supabase-JWT operator read RLS (+`agents_owner_select`), `mcp_tokens`
  comment. RLS policies are forward-looking (no `grant ... to authenticated` in
  PR03 — Gateway reads via superuser DSN; browser reads go through the Gateway).
- **Unit B** — `sift_gateway.supabase_auth` (config, typed denials, Auth/Admin
  client, read-only principal repo, shared `SupabaseIdentityResolver`, portal
  callbacks, agent/service issuance, `is_tool_allowed`); additive `Identity`
  fields; REST `AuthMiddleware` + FastMCP `SiftTokenVerifier` Supabase-first with
  PR02/api_keys fallback behind explicit `auth.legacy.*` flags (401 vs 403);
  **B-14** (raw ASGI keeps identity-free guards only, single verifier lookup);
  **B-10** (`ToolAuthorizationMiddleware`: one `is_tool_allowed` for both
  `on_list_tools` and `on_call_tool`, reject-before-dispatch, fail-closed on no
  identity when auth configured); per-principal rate limit moved into policy
  middleware; audit carries fingerprint only. `configs/gateway.yaml.template`
  `auth.*` block.
- **Unit C** — portal Supabase login/session: signed session-envelope cookie
  (Secure/HttpOnly/SameSite, absolute 12h lifetime), `PortalSessionMiddleware`
  via injected callbacks (no `sift_gateway` import), `/api/auth/login|logout|
  refresh|me` + principal `create|list|revoke`, `_require_operator`
  deny-by-default; LoginCard email/password, SettingsTab agent/service
  JWT-session UI (PR02 marked legacy; token shown once, never localStorage).

Review (mandatory gates, both run):
- `/code-review` (high, multi-angle) → **NO-GO**, 10 findings → all remediated:
  list_principals auth-bypass (operator-only), multi-principal ambiguity
  (fail-closed), dropped per-principal rate limit (restored in middleware),
  revoke no-op/false-audit, case-scoped scopes loaded globally (→ global-only at
  PR03, case scopes deferred to B-11), fail-open authz on None identity
  (fail-closed when auth on), 64-bit cache-key (→ full digest), Supabase-outage
  fail-posture (log + 503 when legacy off), RLS view `security_invoker` + dead
  agent-owner branch. (Refuted as design/spec: coalesce uuid-collision index,
  case-lead read breadth per §5.5, `system_role` default per §5.2.)
- `/security-review` → **clean**; SQL-injection ruled out (dynamic identifiers
  allowlisted, values parameterized); surfaced one functional gap
  (`list_principals` callback missing) → added.

Operator decisions / forks (→ D# / B#):
- **F-13 → D31** (operator, 2026-06-07): pinned Supabase **v1.26.05** GoTrue has
  no admin per-user session logout (`POST /admin/users/{id}/logout` → 404,
  confirmed live). Revocation = DELETE the auth user (`DELETE /admin/users/{id}`
  → 200, idempotent on 404) + mark app principal revoked + invalidate resolver
  cache for the `auth_user_id`. Live VM probe confirmed: after revoke the stale
  access JWT is rejected immediately (`invalid_token`), re-revoke idempotent.
- **B-10 DONE**, **B-14 DONE** (review/security gates passed).
- Carried OPEN: B-4, B-11 (case-scoped tool scopes wait here), B-12, B-13, B-15.

Dependency pins: no new runtime deps (httpx 0.28.1 / psycopg 3.3.4 already
present); no `uv.lock` change.

Host evidence (py3.11 `.venv`): `tests/db` 20; `packages/sift-gateway/tests`
286; `packages/case-dashboard/tests` 306; frontend `vitest` 83 + `vite build`
clean; `py_compile` clean; `python3 scripts/validate_migration_docs.py` OK;
scope-fence `git diff --check` clean.

SIFT VM evidence (`192.168.122.81`, `/usr/bin/python3.12`,
`UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never uv sync --extra core --group
dev`): imports OK (`fastmcp 3.4.2`); PR01+PR03 migration applied inside
`BEGIN/ROLLBACK` on the live Supabase Postgres — clean, nothing left behind;
`tests/db` 20, `packages/sift-gateway/tests` 286 (incl. `create_app` boot),
`packages/case-dashboard/tests` 306; live `SupabaseAuthClient` against pinned
v1.26.05 — admin-create, password-grant, JWT validation, and D31 revoke all
confirmed (self-cleaning throwaway users). The deployed systemd `sift-gateway`
runs from `~/sift-mcps` (not the test tree), so new-code runtime is validated via
the test-tree suites + live Supabase probes; a production deploy is the separate
installer follow-up.

Files: `supabase/migrations/202606070300_unified_jwt_principals.sql`;
`tests/db/test_pr03_unified_jwt_schema.py`;
`packages/sift-gateway/src/sift_gateway/{supabase_auth,auth,identity,mcp_endpoint,mcp_server,policy_middleware,config,server,token_gen}.py`;
`packages/sift-gateway/tests/{test_pr03_supabase_jwt_auth,test_pr03_tool_authorization}.py`;
`configs/gateway.yaml.template`;
`packages/case-dashboard/src/case_dashboard/{auth,routes,session_jwt}.py`;
`packages/case-dashboard/frontend/src/**` (LoginCard, SettingsTab, endpoints, build);
`packages/case-dashboard/tests/test_pr03_supabase_portal_auth.py`;
`docs/migration/{00_migration_charter,09_identity_auth_cutover,18_target_architecture_acceleration,19_pr03_unified_supabase_jwt_identity,REGISTER,MIGRATION_STATE}.md`;
`AGENTS.md`; `CLAUDE.md`.

Land: operator merges `revamp/pr03a-unified-jwt` → `revamp/spg-v1` (3 unit
commits + this Log commit; one revertable PR). No push performed in this run.

Next: see Current Objective — Land PR03A, then PR03B / Batch B (active-case DB
authority, ID-4).

## Run 27 - PR03A Unified Supabase JWT Candidate

Plan-stage candidate run. No runtime code changed.

Trigger: operator asked to create a heavy PR03 work package and hand over a
ready prompt for the coding agent, with `AGENTS.md` / `CLAUDE.md` refreshed if
needed.

Findings / reconciliations:
- Added `19_pr03_unified_supabase_jwt_identity.md` as the Build-ready PR03A /
  Batch A implementation candidate. It scopes a large target-zone move:
  Supabase Auth API validation for REST and FastMCP `/mcp`, shared Gateway
  principal resolution, operator/agent/service mappings, portal Supabase
  login/session, agent/service JWT issuance, DB-backed MCP tool scopes, B-10
  list/call authorization, and B-14 duplicate MCP token/JWT lookup cleanup.
- Kept active-case DB authority, evidence DB authority, jobs/workers,
  OpenSearch core, RAG, and `mcp_backends` registry out of PR03A. Those remain
  Batch B/C/E/F/G/H work per `18_target_architecture_acceleration.md`.
- Chose Supabase Auth API validation (`/auth/v1/user`) for PR03 so no JWT
  signing secret or dummy key enters repo/config. The Build session must
  re-confirm the pinned VM Supabase `v1.26.05` Auth/Admin endpoints and the
  installed FastMCP 3.4.2 auth/list middleware API before coding; API mismatch
  is a D29 stop-and-fork condition.
- Updated standing handoff docs so future sessions no longer start from stale
  D27b or pre-D30 machine-token language.

Files changed:
- `docs/migration/19_pr03_unified_supabase_jwt_identity.md`
- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/README.md`
- `docs/migration/09_identity_auth_cutover.md`
- `docs/migration/18_target_architecture_acceleration.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/REGISTER.md`
- `AGENTS.md`
- `CLAUDE.md`

Verification:
- `python3 scripts/validate_migration_docs.py` passed.
- `git diff --check` passed.

Next: run the Build-stage PR03A prompt from doc 19. Review gates are
`/code-review` and `/security-review` because PR03A touches auth, tokens,
portal sessions, MCP, secrets handling, and Gateway policy.

## Run 26 — Target Architecture & Acceleration Plan

Documentation / architecture run. No runtime code changed.

Trigger: operator clarified the desired end state: Supabase and FastAPI/FastMCP
are meant to simplify the architecture by moving file/env/json governance into a
central Supabase control plane, and the final auth target should accept
Supabase-issued JWTs for both humans and AI/MCP principals.

Findings / reconciliations:
- Added `18_target_architecture_acceleration.md` as the target-state reference
  and acceleration batching plan. It documents the final architecture, data
  places, data receivers/enforcers, security zones, Gateway final
  responsibilities, file-authority sunset map, missing inputs, VM gates, and
  parallel batches.
- Locked new charter decision **D30**: humans, AI agents, MCP clients, workers,
  and services authenticate with Supabase-issued JWTs. The Gateway validates
  those JWTs through SIFT-owned FastAPI dependencies and FastMCP 3.4.2
  `TokenVerifier` code, resolves application principals/memberships/scopes, and
  enforces SIFT policy.
- Marked D8/D26 as historical/transition values superseded in target by D30.
  PR02's hash-only `mcp_tokens` registry remains landed and useful as a
  compatibility bridge/provenance surface, but it is no longer the final
  credential target.
- Updated `09_identity_auth_cutover.md` so PR03A / Batch A targets unified
  Supabase JWT auth for REST and MCP, not only human portal auth.
- Updated `REGISTER.md` B-10/B-14 language to track per-principal tool
  authorization and shared JWT resolver cleanup under D30.

Files changed:
- `docs/migration/18_target_architecture_acceleration.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/09_identity_auth_cutover.md`
- `docs/migration/README.md`
- `docs/migration/OPERATING_MODEL.md`
- `docs/migration/REGISTER.md`
- `docs/migration/MIGRATION_STATE.md`

Next: Plan PR03A / Batch A. The candidate should define exact schema changes,
JWT verification method, principal mapping, legacy-token compatibility behavior,
and host→VM Supabase/FastMCP acceptance gates.

## Run 25 — Documentation Invariant Health Check

Documentation health-check run. No runtime code changed.

Trigger: operator requested a review of canonical docs and the Mermaid
architecture graph after noticing `00_migration_charter.md` had drifted from the
current landed architecture.

Findings / reconciliations:
- `00_migration_charter.md` now separates target architecture from current
  landed status. It records JOB-0, PR01/ID-1, PR02/ID-2, D27a, and D27b as done,
  and explicitly lists pending phases: ID-3, ID-4/ID-5, ID-6, D22/F-11,
  OpenSearch-core, and RAG-core.
- Charter Gateway/FastMCP language was tightened: FastMCP providers/transforms
  do aggregation/namespacing/catalog mechanics only; tool authorization, case
  authorization, evidence gate, response guard, active-case propagation, and
  audit remain SIFT-owned.
- The over-broad "case-scoped MCP tools only" phrasing was corrected. Case-data
  tools are case-scoped; global/reference add-ons are tool-scoped and audited
  under the active case.
- `Architecture.mmd` now shows post-D27b status: one FastAPI + FastMCP Gateway,
  Supabase human auth pending ID-3, active-case authority pending ID-4/ID-5,
  add-ons still sourced from `gateway.yaml` until D22/F-11, and OpenSearch as a
  current compatibility add-on until the later D19 core move.
- Historical inventory/design docs now carry supersession notes where they
  describe pre-D27a/D27b facts (`01`, `03`, `04`, `14`). This preserves their
  evidence trail without letting future agents treat old Starlette/low-level MCP
  or per-backend-route facts as current.
- Stale "next run" footers were refreshed in `07`, `08`, `09`, `11`, `12`,
  `13`, and README; the current next run is PR03 / Phase ID-3 planning.
- D27b carryovers were normalized in `14`, `15`, and `16`: F-9
  `Visibility`/`ToolSearch` remains dropped, B-3 is DONE, and `mcp_backends`
  registry timing is deferred to F-11/D22 rather than D27b.

Subagent checks:
- Canonical-doc reviewer found stale scoping wording, stale D3 "current handler"
  phrasing, README/doc-numbering issues, and Operating Model example drift.
- Mermaid reviewer found OpenSearch current/target ambiguity, over-absolute
  case-scope labels, active-case edge ambiguity, and a renderer-sensitive edge
  to a subgraph.
- Stale-reference scanner found pre-D27b "current state" claims in docs 01/03/04
  and old next-run pointers in docs 07/08/09/11/12/13.
- All accepted findings were fixed or intentionally preserved as historical run
  log/source-reference text.

Files changed:
- `docs/migration/00_migration_charter.md`
- `docs/migration/Architecture.mmd`
- `docs/migration/README.md`
- `docs/migration/OPERATING_MODEL.md`
- `docs/migration/01_repo_inventory.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/04_execution_current_state.md`
- `docs/migration/05_execution_job_model.md`
- `docs/migration/06_execution_integration_contracts.md`
- `docs/migration/07_execution_roadmap.md`
- `docs/migration/08_control_plane_schema.md`
- `docs/migration/09_identity_auth_cutover.md`
- `docs/migration/11_first_pr_candidate.md`
- `docs/migration/12_pr01.md`
- `docs/migration/13_pr02.md`
- `docs/migration/14_fastmcp3_supabase_integration.md`
- `docs/migration/15_backend_tooling_revamp.md`
- `docs/migration/16_backend_tool_contracts.md`

Verification:
- `python3 scripts/validate_migration_docs.py` passed.
- `git diff --check` passed.
- Semantic scans for stale high-risk strings now only return intentional
  historical notes, register decisions, or run-log records.

Next: start Plan-stage PR03 / Phase ID-3, unless the operator explicitly
reprioritizes D22/F-11 or a hardening backlog item.

## Run 24 — D27b Review, Triage & Land

Review/Land run. No runtime code changed after reviewed build commit `0bb5c5e`
except migration documentation and register triage.

Trigger: operator routed back the mandatory D27b `/code-review` and
`/security-review` results for build commit `0bb5c5e`.

Review verdict:
- **GO** to Land. Scope fence held: `revamp/spg-v1..0bb5c5e` touched only
  `packages/sift-gateway/**`, `packages/sift-gateway/pyproject.toml`, `uv.lock`,
  and `docs/migration/**`.
- `/security-review` passed: no high/medium security blockers; D-1/D-2/D-3 and
  B-3 policy gates passed.
- `/code-review` passed with no correctness blocker. B-3/B-6 can be marked DONE
  at Land.
- New forks: none. D29 stop condition was not triggered.

Findings triaged:
- S-1 capped results can lose `gateway_mcp_envelope.backend_audit_id` because
  the guard replaces content before envelope extraction. Deferred as **B-12**.
- S-2 `assert_mounted_tool_names` is unused. Deferred as **B-13** for the D22
  backend-registry phase or a gateway hardening pass.
- S-3 ASGI wrapper and `SiftTokenVerifier` both resolve identity. Deferred as
  **B-14**.
- Security residual: DNS-rebinding TOCTOU remains after resolve-before-connect
  SSRF checks. Deferred as **B-15**.
- Nits (double `build_block_response`, unused import) were non-blocking and not
  registered separately.

Backlog/register updates:
- **B-3 DONE** — D27b `guard_tool_result` redacts/caps both text and
  `structured_content`, recursively and after FastMCP proxy pass-through.
- **B-6 DONE** — gateway now has one agent-facing guard/redaction/cap point.
- **B-5**, **B-7**, and **B-11** remain OPEN but were re-deferred out of the
  D27b gateway scope fence.

Verification carried from Build/Review:
- Host: `packages/sift-gateway/tests` — 225 passed; package-compatible chunks
  green; `git diff --check` clean; gateway py_compile clean.
- VM: `uv sync --extra core --group dev --python /usr/bin/python3.12` with
  `UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never`; Python 3.12.3 imports
  passed; `packages/sift-gateway/tests` — 225 passed; restarted Gateway health
  returned `status: ok`.
- Migration docs validator passed.

Files changed/logged:
- `docs/migration/17_gateway_cutover_d27b.md` — status flipped to implemented.
- `docs/migration/REGISTER.md` — B-3/B-6 DONE; B-12…B-15 added; out-of-scope
  D27a/D27b carryovers re-deferred.
- `docs/migration/MIGRATION_STATE.md` — this entry + Current Objective.
- `docs/migration/README.md` — next-run guidance refreshed.

Land: fast-forward `revamp/spg-v1` to the D27b branch after this documentation
commit. No push performed in this run.

Next: Plan PR03 / Phase ID-3 (Supabase Auth for humans and case-membership
resolution behind the legacy-auth flag). Keep the next run as a Plan session
unless the operator supplies an implementation candidate.

## Run 23 — D27b Gateway Cutover Build

Coding run. Branch `revamp/gateway-cutover-d27b`; build commit created on this branch.
Review remains pending.

Trigger: implement design-frozen `17_gateway_cutover_d27b.md` per the Run 22 build
prompt, with no scope expansion outside `packages/sift-gateway/**`, its tests,
`packages/sift-gateway/pyproject.toml`, `uv.lock`, and `docs/migration/**`.

Findings / reconciliations:
- Installed API confirmed against host `.venv`: `fastmcp==3.4.2`,
  `mcp==1.27.1`, `fastapi==0.136.1`, `starlette==1.0.1`.
- `create_proxy` is exported from `fastmcp.server` in the installed wheel. The
  older `fastmcp.server.proxy` module exists but is deprecated and does not expose
  the symbol.
- F-6 empirically grounded in an in-memory proxy spike: parent `on_call_tool`
  middleware fires for `mount(create_proxy(child), namespace="addon")`, and the
  parent can mutate proxied `content`, `structured_content`, and `meta` after
  `call_next`.
- FastMCP `ProxyClient` forwards incoming HTTP authorization headers by default;
  the D27b HTTP proxy factory disables forwarding and uses backend-owned auth only,
  preserving the no-agent-token-passthrough boundary.
- Current manifests already prefix tool names with their namespace. The FastMCP
  mount therefore uses `tool_names` to strip the existing prefix before applying
  `namespace=...`, preserving the landed D27a tool names instead of double-prefixing.

Operator decisions: none. No new forks raised. F-11 remains deferred; B-3/B-6 remain
OPEN until Land per the operating model.

Files created/changed:
- `packages/sift-gateway/src/sift_gateway/mcp_server.py` — FastMCP server assembly:
  local core tools, synthetic capability guide, proxy mounts, namespace preservation,
  HTTP egress guard/no token passthrough.
- `packages/sift-gateway/src/sift_gateway/policy_middleware.py` — SIFT policy as
  FastMCP middleware.
- `packages/sift-gateway/src/sift_gateway/response_guard.py` — single
  `guard_tool_result` redacts/caps text and structured content recursively (B-3/B-6).
- `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py` — raw ASGI MCP connection
  guard retained; `SiftTokenVerifier(TokenVerifier)` added; low-level MCP server
  factories removed.
- `packages/sift-gateway/src/sift_gateway/server.py` — FastAPI app + FastMCP
  `http_app` mount; per-backend MCP mounts removed.
- `packages/sift-gateway/src/sift_gateway/backends/__init__.py` — remote manifest
  SSRF guard/no redirect-follow.
- `packages/sift-gateway/tests/test_policy_parity_d27b.py` plus updated gateway tests.
- `packages/sift-gateway/pyproject.toml` / `uv.lock` — `fastapi>=0.136`,
  `fastmcp>=3`; lock records **fastmcp 3.4.2**.
- `docs/migration/MIGRATION_STATE.md` and `docs/migration/17_gateway_cutover_d27b.md`
  — run/status updates.

Verification:
- Host: `packages/sift-gateway/tests` — 225 passed.
- Host package chunks: case-dashboard 277 passed; sift-core 328 passed; OpenSearch
  979 passed / 71 skipped; OpenCTI 1 passed; Windows triage 12 passed; forensic-mcp
  20 passed; `tests/db` 5 passed.
- Host hygiene: gateway py_compile clean; `git diff --check` clean.
- VM: rsynced to `~/sift-mcps-test`; `uv sync --extra core --group dev --python
  /usr/bin/python3.12` with `UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never`
  passed; Python 3.12.3 imports (`yaml`, `mcp`, `sift_core`, `sift_gateway`) passed;
  `packages/sift-gateway/tests` — 225 passed; `systemctl --user restart
  sift-gateway` plus `https://localhost:4508/api/v1/health` passed (`status: ok`).

Next: `/code-review` and `/security-review`, then Land. B-3/B-6 remain OPEN until
Land.

## Run 22 — D27b Gateway Cutover Plan

Planning run (Claude delivery-management). No runtime code changed.

Trigger: D27a landed (Run 21, `019bc4a`); plan and own the D27b gateway cutover per
`14_fastmcp3_supabase_integration.md`, grounded in the actual gateway code and the
pinned fastmcp 3.4.2 API (no assumptions — operator directive).

Grounding (source read, not memory):
- Mapped the policy path in `mcp_endpoint.py:create_mcp_server._call_tool` (evidence
  gate → backend dispatch → response guard redact-then-cap → case context → audit
  envelope) and the connection-level `MCPAuthASGIApp` (rate-limit, 10 MB cap, Origin,
  hash-only token via `resolve_identity`, readonly block).
- **Finding 1:** `HttpMCPBackend.call_tool` returns `result.content` only
  (`http_backend.py:224`) — `structured_content` is dropped today; B-3 becomes
  load-bearing exactly when the proxy starts carrying the D27a typed surface.
- **Finding 2:** the per-backend `/mcp/{name}` handler (`create_backend_mcp_server`)
  runs no evidence gate and no response guard — a live policy bypass; D3 says disable.
- **Finding 3:** the human REST `/api/v1/tools` path does not run the response guard;
  only the agent/MCP path does (asymmetry to freeze or unify — F-12).
- Gateway pins `mcp>=1.26` but not `fastmcp`; the cutover adds `fastmcp>=3` (3.4.2 is
  already in `uv.lock` from D27a). The app is Starlette, not FastAPI (F-8).

FastMCP 3.4.2 facts confirmed via `/prefecthq/fastmcp` (recorded in doc 17 §4):
`mcp.mount(create_proxy(url), namespace=…)`; `mcp.http_app(path=…)` +
`combine_lifespans`; `Middleware.on_call_tool` reads/mutates `result.structured_content`
and `result.content` after `call_next` (the B-3 interception point); `ToolResult` uses
`structured_content` as `content` when content is absent (the coupling hazard);
`Namespace` transform; tag-based session-scoped `Visibility`; `ToolSearch` `always_visible`.

Operator decisions (same session, after review of the 7 forks):
- **F-7 → DROP** per-backend `/mcp/{name}` completely (policy bypass). Firmed into
  charter **D3**.
- **F-8 → ADOPT FastAPI now** — it is also the entry point for the React operator
  portal/dashboard (REST + MCP under one ASGI app). **F-8b:** keep the raw-ASGI
  hash-only token auth wrapper (SSE-safe).
- **F-9 → DROP** per-case/per-phase/per-role tool exposure (Visibility/ToolSearch not
  pursued). The one capability worth having — per-agent-token tool authorization for
  benchmarking/testing tool updates — becomes **B-10** (infra partly exists:
  `app.mcp_token_scopes` + `Identity.tool_scopes`, but defaults to `mcp:*` and is not
  enforced per-tool today).
- **F-10 → RETIRED**; `forensic-mcp` tools/capabilities are core (`LocalProvider`).
- **F-11 → DEFERRED** to a later run (keep `gateway.yaml`; re-point to `mcp_backends`
  when that phase lands). Stays OPEN in REGISTER.md.
- **F-12 → KEEP AS IS**; no redaction for human/examiner output; freeze the asymmetry
  in a parity test.
- **F-6 → RESOLVED: YES** (grounded vs fastmcp 3.4.2 docs + official MCP server).
  Parent `on_call_tool` middleware fires for proxied tools mounted via
  `mount(create_proxy(...), namespace=…)`; the parent sees+mutates the proxy's
  `ToolResult` ("parent middleware runs for all requests, including those routed to
  mounted servers"; server layer applies auth/visibility after the proxy cache). Two
  caveats carried: **B-11** (session state does not cross the mount boundary —
  active-case to proxied backends via args/result or shared store) and an in-memory
  proxy test asserting `structured_content`/`meta` pass-through. Latency ~200–500 ms
  per proxied call (noted).

Run 22 also ran a security best-practices web-research pass (MCP spec + 2025–2026
CVEs). It validated the SIFT-owned-policy / dual-principal / no-SupabaseProvider-OAuth
choices, and surfaced three design decisions — now **locked** (doc 17 §11):
- **D-1 → Option A:** token auth via a custom `SiftTokenVerifier(TokenVerifier)` over
  `token_registry` (exposes scopes/claims to the policy middleware; clean home for
  B-10); connection-level guards (rate-limit/size/Origin/readonly) stay raw-ASGI
  (SSE-safe). Supersedes F-8b's "keep the whole wrapper".
- **D-2 → in the D27b PR:** SSRF egress guard on proxied-backend fetches + OAuth-metadata
  (block private/link-local ranges, no redirect-follow); no agent-token passthrough.
- **D-3 → ratified:** all gateway tool results are unary; the response guard
  materializes the full `ToolResult` before redact-then-cap. A future streaming tool
  must raise a fork.
New backlog: **B-10** (per-token tool authz, SIFT-enforced), **B-11** (cross-mount
active-case).

No silent decisions; the FastMCP 3.4.2 facts in doc 17 §4 are re-confirmed at Build
against the installed wheel.

Files created/changed:
- `docs/migration/17_gateway_cutover_d27b.md` (new) — D27b implementation candidate:
  scope fence, file-by-file plan, grounded FastMCP 3.4.2 mechanics, B-3 design,
  policy-parity test strategy, forks, ready-to-copy build prompt. Updated for the
  fork resolutions (FastAPI, drop per-backend routes, no Visibility/ToolSearch).
- `00_migration_charter.md` — **D3** firmed (per-backend routes dropped at D27b).
- `REGISTER.md` — F-6…F-12 added; F-7/F-8/F-9/F-10/F-12 resolved; F-11 deferred;
  **B-10** added (per-token tool authz); B-3/B-6 annotated to point at doc 17 §5.
- `MIGRATION_STATE.md` — this entry + Current Objective.
- `README.md` — doc 17 listed.

Next: F-6 grounding completes → fold into doc 17 and freeze the design → Build session
implements doc 17. B-3 must be implemented before D27b review starts.

## Run 21 — D27a Review, Remediation & Land

Review/Land run (Claude delivery-management). Reviewed the Run 20 build
(`c0a040a`), remediated the blockers (`5ab3df5`), and **landed D27a** into
`revamp/spg-v1`.

Review performed (`CLAUDE.md` Review→GO procedure):
- **Scope fence:** `git diff --stat revamp/spg-v1..revamp/backends-mcp3` touched only
  `packages/{opensearch,opencti,windows-triage}-mcp/**`, `uv.lock`, and this log — clean.
- **Surface diff:** `contracts.py` byte-identical across the three backends; `server.py`
  changes are minimal entrypoint wiring; F-1 (resources + deprecated tool aliases),
  F-2 (10 legacy wintriage aliases), the `opensearch_fix_host_mapping`/`opensearch_host_fix`
  rename + alias, F-4 (timeline warn-not-truncate), and F-5 (ingest password redaction)
  all present and matching doc 16.
- **`/code-review` (high) + `/security-review`** run together (small scope). Findings
  verified against source, not taken on trust.

Verdict: **NO-GO**, then remediated. Blockers fixed in `5ab3df5`:
- **M1 (security):** the FastMCP 3 cutover silently dropped DNS-rebinding protection +
  `allowed_hosts` from `opensearch_mcp/http_server.py` (the in-SDK
  `transport_security` settings have no standalone-FastMCP-3 equivalent — confirmed
  against the installed `fastmcp==3.4.2` and context7's prefecthq/fastmcp v3 upgrade
  guide). Re-established the Host-header allowlist via Starlette `TrustedHostMiddleware`
  + added regression tests (`test_http_transport_security.py`).
- **M2 (contract):** opensearch + windows-triage advertised `output_schema` as the bare
  success model; opencti correctly used `anyOf[success, ToolError]`. Every tool can
  return `ToolError` in `structured_content`, so the two were brought to parity — a
  schema-validating client and the D27b response-guard (B-3) would otherwise reject all
  error results. Regenerated their golden snapshots (output_schema only; tool names +
  annotations byte-identical, verified).
- **S1:** `cti_search_entity` now reports the offset actually applied (0) for entity
  types whose client method takes only `(query, limit)`, instead of echoing a false
  page number (silent duplicate/missing pagination).

F-5 confirmed **already satisfied**: the legacy `opensearch_ingest` `audit.log` calls
pass curated param dicts and never the password (used only for the
`SIFT_ARCHIVE_PASSWORD` subprocess env var); the registry redactor is a defensive belt
on the result. Secret sweep of all changed files + golden fixtures: clean (no tokens,
keys, real IPs).

Deferred (triaged to backlog, not blockers) → `REGISTER.md`:
- **B-5** `opensearch_case_detections_resource` ignores its `case_id` param (S2; masked
  by D4 single-active-case).
- **B-6** consolidate the duplicate per-registry `ToolResult` envelope builders (de-risks
  the B-3 redaction at D27b).
- **B-7** OpenSearch `ResultMeta` parity with opencti/wintriage.
- **B-8** dedupe the two byte-identical opensearch resources under different URIs.
- **B-9** robustness nits (error-code substring heuristic; unaudited wintriage generic
  catch; exact-key-match redactor; per-call `inspect.signature`).

Verification:
- Host (py3.11 `.venv`): opensearch 979 passed/71 skipped, opencti 1, windows 12;
  all three golden snapshots + the 3 new HTTP transport-security tests green.
- SIFT VM (py3.12, `uv sync --extra standard --group dev`): opensearch 979 passed/71
  skipped, opencti 1, windows 12 — full host/VM parity.
- `git diff --check` clean; `python3 scripts/validate_migration_docs.py` passes.

Land: fast-forward merge of `revamp/backends-mcp3` into `revamp/spg-v1` (spg-v1 tip was
the merge-base, so no divergence). Doc 15/16 statuses flipped to implemented. No new
forks raised.

**Next:** D27b gateway cutover — see Current Objective.

## Run 20 — D27a Backend Revamp

Coding/build run. Collected branch commit `a2cc404` on `revamp/backends-mcp3`
before this log entry; review/land intentionally not run.

Trigger: implement stage D27a/D28 backend tooling revamp per docs 15/16 after Run 19
resolved F-1..F-5.

Findings / reconciliations:
- Created foundation branch `revamp/backends-mcp3` off `revamp/spg-v1` and pinned
  `fastmcp==3.4.2` in `uv.lock` (`fastmcp>=3` added to all three backend pyprojects).
- Added byte-identical doc-16 shared conventions (`ResultMeta`, `ErrorCode`,
  `ToolError`, `ToolDef`) to each backend package, plus per-backend registry adapters and
  golden MCP-surface snapshot tests/fixtures.
- Created worktrees/branches:
  `../sift-mcps-os` → `revamp/backends-mcp3-opensearch`,
  `../sift-mcps-cti` → `revamp/backends-mcp3-opencti`,
  `../sift-mcps-win` → `revamp/backends-mcp3-wintriage`.
- Collected the three backend branches back into `revamp/backends-mcp3`; did not merge
  into `revamp/spg-v1`.
- F-1 implemented additively: OpenSearch status/shards, OpenCTI health, and Windows
  status are resources with tool forms retained; OpenSearch case summary/detections keep
  tool form with resource/template views.
- F-2 implemented: all 10 legacy Windows triage aliases retained as deprecated aliases.
- F-4 implemented: OpenSearch timeline has a configurable bucket ceiling and advisory.
- F-5 implemented: OpenSearch ingest password is redacted at the tool boundary.
- D5 guardrail held: OpenSearch ingest/enrich/fix-host mapping remain behavior-compatible
  write tools (`readOnlyHint=false`); no durable-job redesign was introduced.

Operator decisions: none in this run; no new forks raised.

Files created/changed:
- `packages/opensearch-mcp/**`: 16 revamped tools + deprecated `opensearch_host_fix`
  alias, 3 prompts, 4 resources, 3 resource templates, registry entrypoint wiring, golden
  snapshot.
- `packages/opencti-mcp/**`: 8 revamped tools, `enrich_ioc` prompt, 3 resources,
  registry entrypoint wiring, golden snapshot.
- `packages/windows-triage-mcp/**`: 6 revamped public tools, 10 deprecated aliases, 2
  prompts, 2 resources, 1 resource template, registry entrypoint wiring, golden snapshot.
- `uv.lock` and the three backend `pyproject.toml` files: FastMCP 3 dependency/pin.
- `docs/migration/MIGRATION_STATE.md`: this draft Run 20 log entry.

Snapshot / surface status:
- OpenSearch: 17 tools (16 canonical + deprecated `opensearch_host_fix`), 3 prompts,
  4 resources, 3 resource templates.
- OpenCTI: 8 tools, 1 prompt, 3 resources.
- Windows-Triage: 16 tools (6 canonical + 10 deprecated aliases), 2 prompts, 2 resources,
  1 resource template.
- Golden snapshots committed for all three backends.

Host verification:
- `git diff --check` — clean.
- Shared convention files byte-identical across all three backends.
- OpenSearch targeted host suite: 200 passed.
- OpenCTI host package tests: 1 passed.
- Windows-Triage host package tests: 12 passed.
- Integrated surface smoke: OpenSearch 17/3/4/3, OpenCTI 8/1/3/0, Windows 16/2/2/1
  (tools/prompts/resources/resource_templates).

SIFT VM verification:
- `sshpass` rsync to `~/sift-mcps-test` completed.
- `UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never ~/.local/bin/uv sync --extra standard
  --group dev --python /usr/bin/python3.12` — passed.
- VM import smoke under Python 3.12.3: `yaml`, `mcp`, `fastmcp`, `sift_core`,
  `sift_gateway`, and all three backend registries imported; `fastmcp 3.4.2`.
- OpenSearch targeted VM suite: 200 passed with test HOME isolated from the VM's live
  active-case pointer.
- OpenCTI VM package tests: 1 passed.
- Windows-Triage VM package tests: 12 passed.
- VM integrated surface smoke: OpenSearch 17/3/4/3, OpenCTI 8/1/3/0, Windows 16/2/2/1.

Next: operator review of `revamp/backends-mcp3`; do not treat this as landed until review
passes and the operator merges it into `revamp/spg-v1`.

## Run 19 - Fork Resolution + Operating Model / Governance (D29)

Planning/governance run. No runtime code changed.

Resolved the five forks raised in Run 18 (doc 16 §7), grounding F-1/F-2 in repo greps:

- **F-1** tool→resource reclassification: **APPROVED additively** — 4 strong candidates
  (`opensearch_status`, `opensearch_shard_status`, `cti_get_health`,
  `wintriage_server_status`) become resources with the tool kept as a deprecated alias;
  2 query-shaped (`opensearch_list_detections`, `opensearch_case_summary`) stay tools +
  optional resource view. Alias removal horizon → B-1.
- **F-2** legacy wintriage aliases: **KEEP as deprecated aliases one cycle, not drop.**
  Grep: zero internal refs to the 10 legacy names except `analyze_filename`, used as a
  tool in `packages/forensic-knowledge/.../suspicious_execution.yaml` and `tool_metadata.py`
  — drop would break it. Removal + playbook update → B-2. (Count confirmed: 10.)
- **F-3** response-guard must scan `structured_content` (not just text): **REQUIRED,
  security** (text-only scan = redaction bypass). D27b gate + `/security-review` → B-3.
- **F-4** `opensearch_timeline` ceiling: cap ~2000 configurable, **warn-not-truncate**.
- **F-5** `opensearch_ingest.password`: **redact** in audit/logs/`ToolResult`;
  credential-as-arg redesign → B-4.

Established the development governance:

- `docs/migration/OPERATING_MODEL.md` (new) — Plan→Build→Review→Land→Log loop, branch/
  worktree governance, Definition of Done, templates (candidate doc, build prompt, run-log,
  register entry), decision/fork lifecycle, review policy.
- `docs/migration/REGISTER.md` (new) — F#/B# register, seeded with F-1..F-5 (resolved) and
  B-1..B-4 (open).
- `00_migration_charter.md` — added **D29** (operating model = process of record).
- `AGENTS.md` — new "Development Workflow (MUST FOLLOW)" section pointing at the operating
  model; root **`CLAUDE.md`** (new) mirrors it as the Claude-session entry point.
- `16_backend_tool_contracts.md` — §2/§6/§7 updated to RESOLVED; F-2 alias action set.
- `README.md` — added the two governance docs.

Config note: set `.claude/settings.json` `worktree.bgIsolation: none` so this background
session could edit the shared `revamp/spg-v1` checkout in place (the planning docs must
live on the integration branch, not an isolated worktree). Operator can revert if undesired.

## Run 18 - Per-Tool Backend Contracts (doc 16, D28 made concrete)

Planning/documentation run. No runtime code changed. (Doc numbering and run numbering
are separate: this is **doc 16, Run 18**. The prior PR02 implementation run is Run 17.)

Objective: turn doc 15 §10's high-level redesign notes into a zero-ambiguity per-tool
contract table the D27a worktree can implement directly.

Files read (grounding):

- `docs/migration/MIGRATION_STATE.md`, `15_backend_tooling_revamp.md` (whole),
  `00_migration_charter.md` (D19/D20/D22/D23/D24/D27a/b/D28 + D2/D3/D5),
  `14_fastmcp3_supabase_integration.md` (FastMCP 3.0 primitives), `README.md`.
- Source of truth for tool I/O:
  `packages/opensearch-mcp/src/opensearch_mcp/server.py` (verified **16** `@server.tool`
  decorators — module docstring says "17" but only 16 exist),
  `packages/opencti-mcp/src/opencti_mcp/server.py` (8 tools, low-level Server),
  `packages/windows-triage-mcp/src/windows_triage_mcp/server.py` (6 listed tools **+ 10
  unlisted legacy dispatch aliases**: check_file/check_hash/analyze_filename/check_lolbin/
  check_hijackable_dll/check_service/check_scheduled_task/check_autorun/get_db_stats/
  get_health).
- `packages/{opencti,windows-triage}-mcp/sift-backend.json` (existing per-tool
  `when_to_use`/`avoid_when`/`output_notes`/`recommended_phase`/`category`/`health`
  metadata folded into descriptions/resource catalogs).

Files created/changed:

- `docs/migration/16_backend_tool_contracts.md` (new) — 30 contract blocks grouped by
  backend; shared conventions (envelope→`ToolResult.meta`, typed `ToolError`/`ErrorCode`,
  annotation defaults, exposure-agnostic registration table); the flagged tool-vs-resource
  reclassification (§2); ≥1 prompt + ≥1 resource per backend; consolidated rename
  change-map (§6); forks (§7).
- `15_backend_tooling_revamp.md` — §10 pointer to doc 16.
- `README.md` — doc 16 added to Documents.
- `MIGRATION_STATE.md` — this section + Current Objective.

Inventory verified against source: opensearch 16, opencti 8, wintriage 6 = **30**. Counts
match doc 15.

Key contract decisions recorded in doc 16 (not charter-level; surfaced as proposals):

- One rename: `opensearch_host_fix` → `opensearch_fix_host_mapping` (deprecated alias kept).
  All other 29 public names kept.
- Result-shaping caps fixed per tool: search limit≤200/offset≤10000/500-char field
  truncation + `_SEARCH_EXCLUDE_FIELDS` projection; aggregate/field_values buckets≤500;
  list_detections≤500; cti per-type≤20 (unified) / ≤50 (entity/reports) / ≤100 (recent) /
  offset≤500; wintriage registry os_versions/values≤10.
- Write tools annotated `readOnlyHint=false` with per-tool destructive/idempotent hints;
  D5 execution behavior explicitly **not** redesigned.

Flagged forks needing operator confirmation (see doc 16 §7):

- **F-1** tool→resource reclassification (opensearch_status, opensearch_shard_status,
  cti_get_health, wintriage_server_status strong; list_detections/case_summary
  medium/weak) — proposed additively (resource + deprecated tool alias), not applied.
- **F-2** the 10 unlisted legacy wintriage aliases — formalize as deprecated aliases or
  drop (grep skills/RAG/configs first).
- **F-3** response-guard must scan `structured_content` (owed to D27b; shape decided in
  doc 16 §1.1).
- **F-4** `opensearch_timeline` bucket ceiling (proposed ~2000 + warn, not truncate).
- **F-5** `opensearch_ingest.password` redaction in audit/guard.

Next run: operator resolves F-1..F-5 (especially F-1, which changes the D27a golden
snapshot), then the D27a worktree implements doc 16 per the doc 15 §4 one-commit-per-tool
method.

## Run 17 - PR02 Token Registry Implementation

Implementation run for Phase ID-2. Runtime behavior changed only for DB-backed
MCP/service token validation and portal token lifecycle writes; legacy raw
`gateway.yaml api_keys` validation remains as fallback.

Implemented:

- `packages/sift-gateway/src/sift_gateway/token_registry.py` - small
  Postgres-backed token registry for `app.mcp_tokens` and
  `app.mcp_token_scopes`; validates active, unexpired, unrevoked, scoped rows;
  updates `last_used_at` on accepted DB tokens; supports narrow create/rotate/
  revoke/reactivate lifecycle writes.
- `packages/sift-gateway/src/sift_gateway/token_gen.py` - locked PR02 helpers:
  `token_hash = sha256(server_pepper || token)` and
  `token_fingerprint = first 16 hex chars of sha256(token)`.
- `packages/sift-gateway/src/sift_gateway/{auth.py,identity.py,mcp_endpoint.py,server.py}`
  - DB-first identity resolution for REST and MCP, with legacy config fallback.
- `packages/case-dashboard/src/case_dashboard/routes.py` - token list uses DB
  registry when configured; create/rotate/revoke/reactivate write DB records and
  return raw token material exactly once; no new raw token writes to
  `gateway.yaml`.
- `packages/sift-gateway/pyproject.toml` and `uv.lock` - added
  `psycopg[binary]` for VM Postgres access.
- `packages/sift-gateway/tests/test_phase13_auth.py` - deterministic tests for
  hash/fingerprint policy, DB-first validation, fail-closed rows, and legacy
  fallback.
- `packages/case-dashboard/tests/test_token_lifecycle.py` - deterministic fake
  registry tests for hash-only lifecycle writes and no raw-token persistence.
- `docs/migration/PR02_token_registry_checks.md` - PR02 test/runbook.

Host verification:

- `.venv/bin/python -m pytest packages/sift-gateway/tests/test_phase13_auth.py packages/sift-gateway/tests/test_phase4.py packages/sift-gateway/tests/test_audit_envelope.py packages/sift-gateway/tests/test_portal_agent_block.py`
  - 51 passed.
- `.venv/bin/python -m pytest packages/case-dashboard/tests/test_token_lifecycle.py packages/case-dashboard/tests/test_session_middleware.py`
  - 27 passed.
- `git diff --check`
  - clean.

SIFT VM verification after `rsync` to `~/sift-mcps-test`:

- `UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never ~/.local/bin/uv sync --extra core --group dev --python /usr/bin/python3.12`
  - passed; installed `psycopg==3.3.4` and `psycopg-binary==3.3.4`.
- `.venv/bin/python --version`
  - Python 3.12.3.
- Post-sync import smoke for `yaml`, `mcp`, `sift_core`, and `sift_gateway`
  - passed.
- `.venv/bin/python -m pytest packages/sift-gateway/tests/test_phase13_auth.py packages/sift-gateway/tests/test_phase4.py packages/sift-gateway/tests/test_audit_envelope.py packages/sift-gateway/tests/test_portal_agent_block.py`
  - 51 passed.
- `.venv/bin/python -m pytest packages/case-dashboard/tests/test_token_lifecycle.py packages/case-dashboard/tests/test_session_middleware.py`
  - 27 passed.
- PR01 migration SQL applied to Supabase Postgres inside `BEGIN`/`ROLLBACK`
  with `ON_ERROR_STOP=1`
  - passed.

Deviations and notes:

- No PR02 schema migration was added; PR01 already had the required
  `app.mcp_tokens` and `app.mcp_token_scopes` surfaces.
- DB audit event writes were not added in PR02; only `last_used_at` is updated
  on successful DB-token validation.
- Supabase human auth, portal login replacement, active-case propagation,
  evidence gates, job tables/workers/APIs/tools, OpenSearch, parser behavior,
  evidence behavior, frontend redesign, audit data migration, and legacy
  fallback removal remain out of scope and untouched.

## Run 16 - Backend Tooling Revamp Orchestration + Staged Cutover (D27a/D27b/D28)

Planning/decision run. No runtime code changed.

Trigger: operator chose to do PR02 now and, in parallel, revamp the three backend
MCP servers to FastMCP 3.0 — not a version bump, but a tool-quality redesign,
because the currently exposed tools perform poorly (weak definitions, no schemas,
no prompts, no multi-request/advanced features).

Grounding audit (`server.py` per backend): tools 16/8/6; **0 output schemas, 0
prompts, 0 resources, 0 Pydantic input models, 0 arg-level Field descriptions**
across all three. Confirmed the bottleneck is tool quality, not framework version.

Key reconciliation: the original D27 "single big-bang PR (gateway + backends)" is
**split**. Backends ↔ gateway is the MCP wire protocol, so backends move
independently → safe to run a backend worktree in parallel with PR02. D27's parity
gate is split into **policy parity** (frozen, owned by D27b) and **tool surface**
(intentionally re-baselined by D27a).

Operator forks (via questions): combined per-tool (one commit/tool guardrail);
renames allowed via change map + deprecated aliases; all three backends, opensearch
authored exposure-agnostic.

Files created/changed in Run 16:

- `docs/migration/15_backend_tooling_revamp.md` (new) - revamp spec + drift-control
  contract + ready-to-copy worktree coding prompt.
- `00_migration_charter.md` - revised D27 to staged; added D27a, D27b, D28; updated
  the Cutover Order FastMCP note.
- `14_fastmcp3_supabase_integration.md` - §6 cutover plan reframed to the two
  stages (this doc governs D27b); §8 decisions updated.
- `README.md` - added doc 15; clarified doc 14 governs D27b.
- `MIGRATION_STATE.md` - this section + Current Objective.

Worktree governance recorded in doc 15 §8: branch off the same base as PR02,
scope-fenced to `packages/{opensearch,opencti,windows-triage}-mcp/**` + the change
map only (no gateway/supabase/shared edits → zero overlap with PR02), merge before
D27b, pin the `fastmcp` version.

## Run 15 - FastMCP 3.0 + Supabase Consolidation Decision (D24-D27)

Planning/decision run. No runtime code changed.

Trigger: operator researched FastMCP 3.0 (providers/transforms/code-mode/
SupabaseProvider) and proposed dropping the bespoke Gateway to simplify. The run
verified the actual framework facts against the official docs and the repo.

Findings that shaped the decision:

- The repo is **not** on standalone FastMCP. Gateway uses low-level
  `mcp.server.lowlevel.Server`; `opensearch-mcp`/`forensic-rag-mcp`/`forensic-mcp`
  use **in-SDK FastMCP 1.x** (`mcp.server.fastmcp`); `opencti-mcp`/
  `windows-triage-mcp` use low-level `mcp.server.Server`. Standalone FastMCP 3.0
  is a net-new dependency, not an import swap.
- The Gateway is the **policy boundary**, not just an aggregator (evidence gate,
  response guard, audit envelope, active-case propagation, hash-token registry,
  REST admin surface). FastMCP 3.0 replaces aggregation internals only.
- `code-mode` runs arbitrary LLM-generated Python in a sandbox and is explicitly
  unsuited to pre-audited command boundaries; it does **not** replace or fix
  `run_command`. Excluded.
- `SupabaseProvider` is human-OAuth only (RFC 8707 audience gap; self-hosted
  consent UI), no machine-principal story. Not adopted.

Operator decisions (via questions): keep run_command / drop code-mode;
**big-bang** cutover; **own Supabase-JWT verify (FastAPI DI)** for humans.

Files created/changed in Run 15:

- `docs/migration/14_fastmcp3_supabase_integration.md` (new) - KB + target design.
- `00_migration_charter.md` - added D24-D27; updated Target Architecture +
  Gateway/Broker text + Non-Negotiable line to "FastAPI + FastMCP 3.0"; added the
  framework-substrate insertion note to "Cutover Order".
- `Architecture.mmd` - Gateway label updated to FastAPI + FastMCP 3.0; note that
  providers/transforms are aggregation only and policy is SIFT-owned.
- `README.md` - added doc 14; refreshed "next recommended run" footer.
- `MIGRATION_STATE.md` - this section + Current Objective + Next Recommended Run.

Open items for the cutover PR (see doc 14 §7): ProxyProvider must carry the
evidence-gate/response-guard/audit wrap for proxied add-ons; verify
`mcp.http_app` session semantics vs current `StreamableHTTPSessionManager`;
decide `forensic-mcp`'s fate; wire session-scoped Visibility to active case+role;
pin the exact `fastmcp` version.

## Run 14 - PR01 Implementation, Supabase VM Setup, AGENTS.md, And PR02 Planning

Created:

- `supabase/migrations/202606070101_identity_foundation.sql` - additive PR01
  `app` schema foundation tables for operator profiles, cases, case members,
  active-case state, agents, service identities, MCP tokens, token scopes, and
  audit events.
- `tests/db/test_pr01_identity_schema.py` - deterministic SQL structure tests
  for the PR01 schema.
- `docs/migration/PR01_identity_schema_checks.md` - PR01 schema-check runbook.
- `AGENTS.md` - root handoff instructions with host/VM workflow, Python/uv
  invariants, Supabase VM setup, PR01 files, PR02 pointer, and installer
  follow-up note.
- `docs/migration/13_pr02.md` - PR02 implementation candidate for Phase ID-2
  hash-only MCP/service token validation with legacy fallback.

Updated:

- `docs/migration/README.md` - linked PR01 and PR02 docs/runbooks.
- `docs/migration/MIGRATION_STATE.md` - this handoff update.

SIFT VM setup completed:

- VM: `192.168.122.81`, user `sansforensics`.
- Supabase installed manually at `/home/sansforensics/supabase-project`.
- Source sparse clone at `/home/sansforensics/supabase-src-v1.26.05`.
- Supabase pinned tag: `v1.26.05`.
- Supabase pinned commit: `23b55d63485e51919d1b4c05b03d33a9edc1f06d`.
- Supabase public/API URL configured as `http://192.168.122.81:8000`.
- Secrets generated with pinned Supabase helper scripts
  `utils/generate-keys.sh` and `utils/add-new-auth-keys.sh`.
- Pinned Docker layout had no `run.sh`; used `docker compose up -d --wait`.
- Stack health checked through `docker compose ps`, JWKS, REST `401`, and
  Postgres `select version()`.
- Installed Ubuntu `nodejs` package because Supabase's pinned
  `add-new-auth-keys.sh` requires Node >= 16.

Files inspected in this run:

- `docs/migration/12_pr01.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/09_identity_auth_cutover.md`
- `docs/migration/08_control_plane_schema.md`
- `docs/migration/README.md`
- `docs/migration/MIGRATION_STATE.md`
- Root `pyproject.toml`
- Narrow file discovery for existing Supabase/migration/schema/test layout.

Verification run on host with `.venv`:

- `.venv/bin/python -m pytest tests/db/test_pr01_identity_schema.py`
  - 5 passed.
- `.venv/bin/python -m pytest tests/db`
  - 5 passed.
- `git diff --check`
  - clean.

Verification run on SIFT VM after rsync to `~/sift-mcps-test`:

- `.venv/bin/python --version`
  - Python 3.12.3.
- Post-sync import smoke for `yaml`, `mcp`, `sift_core`, and `sift_gateway`
  - passed.
- `.venv/bin/python -m pytest tests/db/test_pr01_identity_schema.py`
  - 5 passed.
- `.venv/bin/python -m pytest tests/db`
  - 5 passed.
- PR01 migration SQL applied to Supabase Postgres inside `BEGIN`/`ROLLBACK`
  with `ON_ERROR_STOP=1`
  - passed.

Deviations and notes:

- No existing Supabase migration/test harness existed before PR01, so PR01 used
  deterministic SQL-inspection tests plus an optional live Supabase rollback
  syntax check.
- The SIFT VM `.python-version` file in the synced repo says `3.11`, but VM
  testing must force `/usr/bin/python3.12` per the project invariant.
- A broad `uv sync --all-packages` started pulling large optional GPU/ML
  packages and was stopped; `uv cache prune` recovered about 3.2 GiB. Use the
  narrower `uv sync --extra core --group dev --python /usr/bin/python3.12` for
  Gateway/portal/schema work unless a task really needs all packages.
- Supabase docs mention `run.sh`, but the pinned `v1.26.05` Docker layout does
  not include it; use `docker compose`.
- The root `.DS_Store` modification was pre-existing and intentionally left
  untouched.

Next recommended run:

- Review and commit the current PR01/docs work if desired.
- Implement PR02 as described in `docs/migration/13_pr02.md`.
- Read `AGENTS.md` and `docs/migration/13_pr02.md` first.
- Inspect only the files listed in PR02 section 4.
- Use the host repo as source and test on the SIFT VM after rsync.
- Use `/usr/bin/python3.12` on the VM and set `UV_NO_MANAGED_PYTHON=1` and
  `UV_PYTHON_DOWNLOADS=never` for `uv sync`.
- Run targeted token/auth tests, touched auth/token suites if practical,
  optional rollback-safe Supabase checks, and `git diff --check`.
  Stop and summarize changed files, tests run, and deviations.

## Run 13 - JOB-0 Implementation Commit And PR01 Planning

Committed:

- `c73762c Add JOB-0 execution baseline smoke tests`

JOB-0 files committed:

- `packages/sift-core/tests/test_core_execution_baseline_smoke.py` - evidence
  seal/status and audit JSONL append baseline tests using temp paths.
- `packages/opensearch-mcp/tests/test_opensearch_execution_baseline_smoke.py` -
  OpenSearch index/provenance action-shape and ingest-status metadata tests
  without live OpenSearch.
- `docs/migration/JOB0_baseline_execution_checks.md` - `.venv`-based runbook for
  targeted JOB-0 baseline checks and touched package suites.
- `docs/migration/README.md` - link to the JOB-0 runbook.

Created after the commit:

- `docs/migration/12_pr01.md` - PR01 implementation candidate, replicating the
  structure of `11_first_pr_candidate.md`, for Phase ID-1 identity foundation
  schema only.

Files inspected in this run:

- `docs/migration/11_first_pr_candidate.md`
- `docs/migration/README.md`
- `packages/sift-core/pyproject.toml`
- `packages/sift-common/pyproject.toml`
- `packages/opensearch-mcp/pyproject.toml`
- `packages/sift-core/src/sift_core/evidence_chain.py`
- `packages/sift-common/src/sift_common/audit.py`
- `packages/opensearch-mcp/src/opensearch_mcp/paths.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_json.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`
- Existing adjacent tests under `packages/sift-core/tests/` and
  `packages/opensearch-mcp/tests/` listed in doc 11 as needed.
- `docs/migration/00_migration_charter.md`
- `docs/migration/08_control_plane_schema.md`
- `docs/migration/09_identity_auth_cutover.md`

Verification run with `.venv`:

- `PYTHONPATH=packages/sift-core/src:packages/sift-common/src .venv/bin/python -m pytest packages/sift-core/tests/test_core_execution_baseline_smoke.py`
  - 2 passed.
- `PYTHONPATH=packages/opensearch-mcp/src:packages/opensearch-mcp/tests:packages/sift-core/src:packages/sift-common/src .venv/bin/python -m pytest packages/opensearch-mcp/tests/test_opensearch_execution_baseline_smoke.py`
  - 2 passed.
- `PYTHONPATH=packages/opensearch-mcp/src:packages/opensearch-mcp/tests:packages/sift-core/src:packages/sift-common/src .venv/bin/python -m pytest --import-mode=importlib packages/sift-core/tests/test_core_execution_baseline_smoke.py packages/opensearch-mcp/tests/test_opensearch_execution_baseline_smoke.py`
  - 4 passed.
- `PYTHONPATH=packages/sift-core/src:packages/sift-common/src .venv/bin/python -m pytest packages/sift-core/tests`
  - 328 passed.
- `PYTHONPATH=packages/opensearch-mcp/src:packages/opensearch-mcp/tests:packages/sift-core/src:packages/sift-common/src .venv/bin/python -m pytest packages/opensearch-mcp/tests`
  - 975 passed, 71 skipped.
- `git diff --check`
  - clean.

Deviations and notes:

- JOB-0 test files use package-specific filenames to avoid pytest module-name
  collisions when both package test paths are collected together.
- The audit baseline asserts current JSONL append/shape behavior only. It does
  not assert secret redaction because current `AuditWriter` writes `params` as
  supplied; changing that would be runtime behavior.
- The runbook uses `.venv/bin/python` per the repository environment.
- `docs/migration/12_pr01.md` is planning-only and not part of commit `c73762c`.

Next recommended run:

- Commit `docs/migration/12_pr01.md` if the PR01 candidate should be preserved
  before implementation.
- Then implement PR01 as described in `docs/migration/12_pr01.md`.
- Inspect only the files listed in that document's repository discovery section.
- Add the Phase ID-1 control-plane identity schema, deterministic schema tests,
  and a short PR01 schema-check runbook.
- Use `.venv` for Python test commands.
- Run targeted schema tests, the touched schema suite if practical, and
  `git diff --check`.
- Stop and summarize changed files, tests run, and deviations.

## Run 12 - First PR Candidate Planning (JOB-0)

Created:

- `docs/migration/11_first_pr_candidate.md` - concrete first implementation PR
  candidate for JOB-0 baseline execution smoke tests/fixtures/docs.

Updated:

- `docs/migration/MIGRATION_STATE.md` - current handoff state for the next run.
- `docs/migration/README.md` - moved doc 11 from "Planned Documents" to
  "Documents" and updated the next recommended run.

Files inspected in this run:

- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/04_execution_current_state.md`
- `docs/migration/07_execution_roadmap.md`
- `docs/migration/08_control_plane_schema.md`
- `docs/migration/09_identity_auth_cutover.md` (skimmed for cutover order)
- `docs/migration/README.md`

Narrow repository path discovery was also run to identify existing package
manifests and test directories. No production modules were opened.

First PR decision:

- First implementation PR is JOB-0 only.
- Scope is test/fixture/docs focused.
- No runtime behavior change.
- No schema migrations.
- No Supabase/Postgres dependency.
- No worker/job implementation.
- No frontend/MCP/REST/OpenSearch refactor.

Open questions for the JOB-0 coding run:

- Exact package test commands and dependency runner.
- Whether new smoke tests should live in new files or extend existing package
  tests.
- Exact `AuditWriter.log` JSONL field names to assert.
- Exact `build_index_name()` sanitization output for mixed-case and symbol-rich
  inputs.
- The smallest parser path that exposes provenance/action shaping without a
  live OpenSearch instance.
- Whether ingest-status or ingest-manifest smoke coverage is cheaper and safer
  than parser-output smoke coverage.

Next recommended run:

- Implement the JOB-0 coding PR described in
  `docs/migration/11_first_pr_candidate.md`.
- Inspect only the files listed in that document's repository discovery section.
- Add 2-4 deterministic baseline smoke tests/fixtures and a short runbook.
- Run targeted tests and `git diff --check`.
- Stop and summarize changed files, tests run, and deviations.

## Run 9 - Locked Decisions And Reconciliation

User-confirmed decisions captured this run (full list in the charter):

- D2/D3: Gateway is the single boundary; ALL REST APIs, MCP tools, and actions
  go through it; per-backend `/mcp/{name}` routes are disabled (early hardening).
- D4: active case is portal-set, authoritative in `active_case_state`, propagated
  by the Gateway; `SIFT_CASE_DIR`/`~/.sift/active_case` become generated
  compatibility exports; one active case per SIFT VM in v1. Current
  active-case behavior preserved, authority moved to the control plane.
- D5: long-running tool calls enqueue durable control-plane jobs/pipelines and
  return a job ID; never a direct job/invoke to the Evidence Vault; workers
  CLAIM (poll + SKIP LOCKED), control plane never pushes. (Fixed the diagram's
  Gateway->Evidence job arrow and the push-vs-pull arrow.)
- D6: OpenSearch 3.5.0 with security enabled is canonical; root repo
  `docker-compose.yml` (2.18.0, security off) is pre-migration only.
- D7: local Supabase on the network-restricted (non-air-gapped) SIFT VM.
- D8: hash-only token registry, SHA-256 + server pepper, 16-hex fingerprint,
  default expiries, one-time raw display, dual-validate then sunset legacy.
- D9: single local worker in v1.
- D10/D11: UUID PKs + legacy text keys; `app`+`internal` schemas (not `public`).
- D12: privileged writes via Gateway/worker service paths; RLS = defense-in-depth
  behind the Gateway; browser never talks to a backend/OpenSearch directly.
- D13: lean job core (`jobs`, `job_steps`, `job_logs`, `workers`); defer
  `job_attempts`/`job_cancellations`/`worker_heartbeats`.
- D14: retain Solana anchoring, TODOs, IOCs as first-class (added tables + job
  type `evidence_anchor`).
- D15: centralize RAG and add retrievable agent skills into the control plane
  (added `rag_collections`/`rag_documents`/`agent_skills`).
- D16: evidence dedup never silently drops forensically distinct acquisitions.
- D17: cutover order = cases/tokens/identity first.

Files changed/created in Run 9:

- `docs/migration/Architecture.mmd` (rewritten/corrected).
- `docs/migration/00_migration_charter.md` (locked decisions + cutover order).
- `docs/migration/README.md` (numbering fix + doc set).
- `docs/migration/09_identity_auth_cutover.md` (new foundation track).
- `docs/migration/08_control_plane_schema.md` (lean job core; +`active_case_state`,
  `case_todos`, `iocs`, `evidence_anchors`, `rag_collections`, `rag_documents`,
  `agent_skills`; locked decisions; resolved open questions).
- `docs/migration/02`,`03`,`05`,`06`,`07` (locked-decision banners + resolved
  open-question sections).

## Run 10 - Active-case refinement + OpenSearch write contract (D18)

After a code scan of `packages/opensearch-mcp/`, two refinements were locked:

- D4 refined: **one operator, one active case at a time**; other cases may exist
  but only one is active.
- D18 added: **reuse the existing working OpenSearch ingestion model** - index
  naming `case-{case}-{type}-{host}` via `build_index_name()`, template
  auto-create, shared `flush_bulk` writer, host auto-discovery preflight, and
  `vhir.*`/`host.*`/`pipeline_version` provenance. The control plane *registers*
  these indices in `opensearch_indexes` rather than renaming them; the
  `dfir-case-*-vN` logical-family rename is deferred/optional. A single **write
  contract** (`03` §7A) governs every writer - core worker, addon MCP backend
  (future OpenCTI/Hayabusa enrichment), and enrichment - additively and without
  refactoring working backends: take `case_id` from job/active-case context, name
  via the helper, stamp provenance + control-plane IDs, reuse `flush_bulk`,
  register index/batch, scope `update_by_query` to the case. Gateway-only governs
  the tool/query boundary; execution-plane bulk writes run directly under an
  authorized job.

Code facts confirmed this run: only `opensearch-mcp` writes to OpenSearch today
(OpenCTI/windows-triage/forensic-mcp/forensic-rag do not); enrichers mutate
existing `case-*` docs via `update_by_query`; indices are created implicitly on
first bulk write through installed `case-*-{type}-*` templates.

Files changed in Run 10: `00_migration_charter.md` (D4 refined, D18 added),
`03_opensearch_core_integration.md` (banner + §6 reuse + new §7A write contract +
§13 reconcile), `08_control_plane_schema.md` (`opensearch_indexes` cell + §15).

## Run 11 - MCP backends + OpenSearch core + OpenCTI cohabitation (D19-D23)

User-confirmed decisions this run (full text in the charter):

- D19: **OpenSearch is core, not an add-on.** Read tools = in-process core MCP
  tools (sync); ingest/enrichment = core tools that enqueue worker jobs.
  Standalone server + OpenSearch add-on manifest registration retired; the
  `opensearch-mcp` package remains as the in-process implementation.
- D20: **OpenCTI = full platform** (platform, worker, redis, rabbitmq, minio)
  sharing the **existing SIFT OpenSearch** as its index store (not a 2nd
  cluster). `opencti-mcp` stays query-only. OpenCTI's internal redis/rabbitmq/
  minio are exempt from "No Redis/RQ" (which governs SIFT job authority only).
  (User has tested the full-wiring implementation against case evidence.)
- D21: **Cluster cohabitation + scoped security roles.** Two index classes:
  `case-*` (SIFT) and `opencti_*` (OpenCTI). Per-consumer roles: worker->`case-*`,
  OpenCTI->`opencti_*`, **agent->no cluster creds**. Capacity monitored for both.
- D22: **Add-on spec direction.** Query-only/read-only default; write-capable is
  the declared §7A exception. Per-tool `case_scoped` flag (opencti/wintriage =
  global, audited under active case). Backend `data_plane` declaration. Backend
  registration moves from `gateway.yaml` to a control-plane `mcp_backends`
  registry, portal-managed. Full spec: `10_addon_backend_spec.md`.
- D23: **RAG folds into core** (Supabase pgvector-backed retrieval tool), no
  longer a standalone add-on; `forensic-rag-mcp` Chroma store migrated.
  `windows-triage-mcp` stays the minimal query-only add-on reference.

Code facts confirmed: `opencti-mcp` is an API client to the OpenCTI **platform**
(not an OpenSearch client); the OpenCTI stack is heavy (redis/rabbitmq/minio/
platform/worker); current manifest requires `spec_version,name,version,tier,
transport,namespace,capabilities,tools,health` with rich per-tool metadata but
**no `case_scoped` or `data_plane`** - those are the additive gaps.

Files changed/created in Run 11: `00_migration_charter.md` (D19-D23),
`03_opensearch_core_integration.md` (new §7B: OpenSearch-core + OpenCTI
cohabitation + security roles + portal monitoring), `08_control_plane_schema.md`
(`mcp_backends` registry table; RAG core-served note), **new**
`10_addon_backend_spec.md`, `README.md` (doc 10 + planned docs renumbered to
11/12).

## Decisions Already Made

- Supabase/Postgres is the authoritative control plane.
- Human operators use Supabase Auth and RLS.
- Agents, MCP clients, workers, and backend services use Gateway-issued, case-scoped MCP/service tokens.
- MCP/service tokens are stored in the Postgres token registry as hashes only.
- Gateway validates MCP/service tokens and enforces tool scope, case scope, expiry, revocation, and policy before MCP or workflow actions.
- Postgres is authoritative for token registry state, case permissions, audit events, durable job state, evidence metadata, approval state, and workflow state.
- Immutable raw evidence and cryptographic ledger artifacts are preserved as proof/export while control-plane state moves to Postgres.
- OpenSearch is integrated through Gateway policy as a core derived search/data plane, initially by adapting existing OpenSearch code.
- OpenSearch must not become the authority for cases, tokens, jobs, evidence integrity, or approvals.
- No Redis/RQ.
- Frontend UI state is not forensic state authority.
- Agent-generated findings remain draft/proposed until human approval and are not auto-approved.
- OpenSearch query and ingest paths must be Gateway-mediated and case-scoped by token/session context.
- OpenSearch MCP tools should move into the core SIFT MCP namespace rather than remain only optional add-on tools.
- Normal agent tokens must not pass arbitrary OpenSearch index names, wildcard case patterns, or raw OpenSearch DSL.
- OpenSearch degraded mode must be explicit in Gateway health, MCP responses, frontend views, and job/indexing state.
- Compatibility with current files should be additive first; file-backed behavior is not removed before DB authority and compatibility exports are verified.
- Gateway/API/MCP creates durable job records in Postgres for long-running work.
- SIFT workers poll Postgres and atomically claim jobs using DB row-locking semantics.
- Long-running MCP tools enqueue jobs and return job IDs rather than executing inside request paths.
- OpenSearch indexing status is recorded in Postgres and OpenSearch remains a derived searchable data plane.
- Jobs are explicitly case-scoped from Gateway-validated human session or MCP/service-token context, not from `SIFT_CASE_DIR` or legacy active-case pointers.
- Retry preserves previous attempts, job steps, logs, parser runs, and indexing records.
- Cancellation is explicit and audited.
- Approval-gated work enters `waiting_human`; destructive or final actions require human approval.

## Files Created

- `docs/migration/README.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/01_repo_inventory.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/04_execution_current_state.md`
- `docs/migration/05_execution_job_model.md`
- `docs/migration/06_execution_integration_contracts.md`
- `docs/migration/07_execution_roadmap.md`
- `docs/migration/08_control_plane_schema.md`

## Files Inspected In Run 8

- No prior migration or implementation files were reread in run 8. The run used
  the already-loaded session context from the previous migration documents.

## Key Schema Decisions From Run 8

- Initial schema recommendation is a control-plane layout with Supabase Auth for
  human users, an `app` schema for core RLS-protected tables, an optional
  `internal`/`svc` schema for service-only helpers, and optional frontend-safe
  views. This namespace choice still needs user approval before migration work.
- Recommended identity model separates human `operator_profiles` from
  `agents`, `service_identities`, and hash-only `mcp_tokens`.
- Recommended case model uses UUID DB primary keys plus legacy text
  compatibility keys such as `case_key`; this needs user approval before
  migrations.
- Schema design includes initial tables for cases, memberships, agents,
  service identities, MCP token registry/scopes, evidence metadata and
  integrity, audit, approvals, findings/reviews, reports/artifacts, jobs,
  job attempts/steps/logs, workers, parser runs, parser outputs, ingest
  batches, OpenSearch index registry, indexing status, and optional document
  refs.
- Frontend users should read through RLS and safe views where appropriate, but
  privileged state mutations should go through Gateway service paths.
- MCP/agent clients should not receive direct Postgres access; they interact
  through Gateway-issued, case-scoped, tool-scoped token records.
- Worker service writes should be limited to claimed jobs and should update
  job, step, log, parser, output, ingest, indexing, and audit state.
- First schema-focused PR recommendation is migration infrastructure and schema
  verification harness if missing, not domain tables yet, because the exact
  Supabase Local deployment and migration layout remain open.
- The first overall implementation PR recommendation remains JOB-0 baseline
  execution smoke-test fixtures and lightweight tests.

## Files Inspected In Run 7

- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/04_execution_current_state.md`
- `docs/migration/05_execution_job_model.md`
- `docs/migration/06_execution_integration_contracts.md`
- `docs/migration/README.md`

No implementation code was inspected during run 7. Current repository facts in
`07_execution_roadmap.md` were carried forward from the required migration
documents.

## Key Roadmap Decisions From Run 7

- Execution migration should proceed through JOB-0 through JOB-13:
  baseline tests/fixtures, job interfaces, job schema, repository/service,
  no-op worker, REST job APIs, MCP job tools, evidence jobs, parser/ingest jobs,
  OpenSearch indexing status integration, frontend job monitoring,
  report/finding jobs, file-authority deprecation, and hardening/docs.
- The first execution-focused PR should be JOB-0 only: additive baseline
  smoke-test fixtures and lightweight tests for current execution-critical
  evidence/audit/parser/OpenSearch behavior, with no runtime behavior changes.
- The second recommended PR should add job domain interface skeletons with no
  database dependency and no runtime wiring.
- Real parser conversion should wait until baseline tests, job interfaces,
  schema, repository/service behavior, and worker claiming are tested.
- Evidence vault behavior remains protected during early conversion; evidence
  hash/verify/register jobs are the safest first real workflow conversion after
  job infrastructure exists.
- File-backed workflow/status authority should be deprecated only after DB
  authority, compatibility exports, and migrated readers are validated.
- Future implementation PRs should be narrow enough for one Codex coding
  session and should avoid broad refactors until fixtures and baseline tests
  exist.

## Files Inspected In Run 6

- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/04_execution_current_state.md`
- `docs/migration/05_execution_job_model.md`
- `docs/migration/README.md`

No implementation code was inspected during run 6. Current repository facts in
`06_execution_integration_contracts.md` were carried forward from the required
migration documents.

## Files Inspected

- Attached target architecture image from the user prompt.
- `/home/yk/.codex/attachments/037bdcf4-8981-45cc-ab65-77883484d9b1/sift_vm_dfir_exact_replica.mmd`
- `docs/README.md`
- `docs/revamp/target-architecture.mmd`
- `docs/migration/README.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/01_repo_inventory.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/04_execution_current_state.md`
- `docs/migration/05_execution_job_model.md`
- `pyproject.toml`
- `configs/gateway.yaml.template`
- `configs/apparmor/sift-gateway.template`
- `docker-compose.yml`
- `docker-compose.opencti.yml`
- `packages/case-dashboard/frontend/package.json`
- `packages/case-dashboard/frontend/src/App.jsx`
- `packages/case-dashboard/frontend/src/api/client.js`
- `packages/case-dashboard/frontend/src/api/endpoints.js`
- `packages/case-dashboard/frontend/src/hooks/useDataPolling.js`
- `packages/case-dashboard/frontend/src/store/useStore.js`
- `packages/case-dashboard/frontend/src/components/layout/NavRail.jsx`
- `packages/case-dashboard/frontend/src/components/evidence/EvidenceTab.jsx`
- `packages/case-dashboard/frontend/src/components/reports/ReportsTab.jsx`
- `packages/case-dashboard/frontend/src/components/settings/SettingsTab.jsx`
- `packages/case-dashboard/src/case_dashboard/auth.py`
- `packages/case-dashboard/src/case_dashboard/session_jwt.py`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/sift-core/src/sift_core/case_io.py`
- `packages/sift-core/src/sift_core/case_manager.py`
- `packages/sift-core/src/sift_core/evidence_chain.py`
- `packages/sift-core/src/sift_core/case_ops.py`
- `packages/sift-core/src/sift_core/evidence_ops.py`
- `packages/sift-core/src/sift_core/verification.py`
- `packages/sift-core/src/sift_core/reporting.py`
- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-core/src/sift_core/execute/executor.py`
- `packages/sift-core/src/sift_core/execute/tools/generic.py`
- `packages/sift-common/src/sift_common/audit.py`
- `packages/sift-common/src/sift_common/__init__.py`
- `packages/sift-gateway/src/sift_gateway/auth.py`
- `packages/sift-gateway/src/sift_gateway/identity.py`
- `packages/sift-gateway/src/sift_gateway/token_gen.py`
- `packages/sift-gateway/src/sift_gateway/config.py`
- `packages/sift-gateway/src/sift_gateway/__main__.py`
- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
- `packages/sift-gateway/src/sift_gateway/rest.py`
- `packages/sift-gateway/src/sift_gateway/backends/__init__.py`
- `packages/sift-gateway/src/sift_gateway/backends/base.py`
- `packages/sift-gateway/src/sift_gateway/backends/stdio_backend.py`
- `packages/sift-gateway/src/sift_gateway/backends/http_backend.py`
- `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`
- `packages/forensic-mcp/src/forensic_mcp/server.py`
- `packages/forensic-rag-mcp/src/rag_mcp/server.py`
- `packages/forensic-rag-mcp/sift-backend.json`
- `packages/opencti-mcp/src/opencti_mcp/server.py`
- `packages/opencti-mcp/sift-backend.json`
- `packages/windows-triage-mcp/src/windows_triage_mcp/server.py`
- `packages/windows-triage-mcp/sift-backend.json`
- `packages/opensearch-mcp/pyproject.toml`
- `packages/opensearch-mcp/README.md`
- `packages/opensearch-mcp/sift-backend.json`
- `packages/opensearch-mcp/docker/docker-compose.yml`
- `packages/opensearch-mcp/src/opensearch_mcp/server.py`
- `packages/opensearch-mcp/src/opensearch_mcp/__main__.py`
- `packages/opensearch-mcp/src/opensearch_mcp/http_server.py`
- `packages/opensearch-mcp/src/opensearch_mcp/client.py`
- `packages/opensearch-mcp/src/opensearch_mcp/paths.py`
- `packages/opensearch-mcp/src/opensearch_mcp/gateway.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_evtx.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_accesslog.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_csv.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_defender.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_json.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_delimited.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_memory.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_plaso.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_prefetch.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_srum.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_ssh.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_tasks.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_transcripts.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_w3c.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_wer.py`
- `packages/opensearch-mcp/src/opensearch_mcp/tools.py`
- `packages/opensearch-mcp/src/opensearch_mcp/mappings/__init__.py`
- `packages/opensearch-mcp/src/opensearch_mcp/mappings/*.json`
- Targeted `find`, `tree`, and `rg` scans for repo/package structure, frontend API usage, Starlette routes, MCP registration, JSON state, evidence, audit, tokens, OpenSearch, jobs/workflows, tests, docs, setup files, Redis/RQ/Celery, and Supabase/Postgres presence.

## Key OpenSearch Findings From Run 3

- Current OpenSearch is implemented as `opensearch-mcp`, an optional add-on MCP backend with standalone stdio/HTTP/CLI entry points and a `sift-backend.json` manifest.
- Current query tools validate that index names start with `case-`, but normal search can still accept explicit index names and can fall back to broad `case-*` behavior when no active case is resolved.
- Current case context comes from `SIFT_CASE_DIR` or `~/.sift/active_case`, not from Postgres/Supabase case membership or Gateway-issued case-scoped token state.
- Current ingest and indexing are subprocess-driven and tracked through `~/.sift/ingest-status`, ingest logs, and filesystem manifests, not durable database jobs, parser runs, parser outputs, or indexing batches.
- Current parser documents already include useful partial provenance such as `vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`, host fields, and `pipeline_version`, but do not yet consistently include the target control-plane IDs.
- The recommended initial index strategy is per-case logical indexes with Postgres-registered aliases, because the current code already uses case-prefixed indexes. This recommendation still needs user approval before implementation.
- The safest first OpenSearch implementation slice is additive: add a control-plane-aware OpenSearch service abstraction, case-scope query construction tests, and explicit health/degraded behavior without removing the standalone backend.

## Execution Facts Confirmed From Run 4

- Portal/operator execution is mostly synchronous request/response against
  file-backed state. Evidence operations, approval commit, report generation,
  backend/service management, and polling all resolve active case from
  `SIFT_CASE_DIR`/legacy case resolution rather than durable DB session state.
- Gateway aggregate MCP calls run an evidence-chain gate before dispatch and
  write a transport-envelope audit entry. Per-backend MCP endpoints call a
  single backend directly and have a different policy/audit surface.
- Native `run_command` is synchronous. It validates command plans, executes
  shell-free subprocess stages, can save stdout/stderr under case-controlled
  directories, and writes detailed JSONL audit including input hashes where
  detectable.
- OpenSearch ingest is the main long-running execution path. It starts
  subprocesses with `python -m opensearch_mcp.ingest_cli`, records pid/run_id
  status under `~/.sift/ingest-status`, writes logs under
  `~/.sift/ingest-logs`, and indexes derived documents into case-prefixed
  OpenSearch indices.
- Parser modules generally write directly to OpenSearch bulk actions and stamp
  partial provenance fields such as `vhir.source_file`,
  `vhir.ingest_audit_id`, `vhir.parse_method`, optional `vhir.vss_id`, and
  `pipeline_version`. Durable DB IDs are not present.
- Evidence chain authority is currently the manifest/ledger files, with
  `evidence.json` as compatibility view. Audit and approval records are JSONL
  under the state-root case record directory by default.
- Current workflow/status state is scattered across case JSON files,
  `pending-reviews.json`, in-memory report drafts, `~/.sift/ingest-status`,
  ingest logs, active-case env/pointers, OpenSearch indices, and frontend cache.

## Execution Risks Discovered From Run 4

- Long-running parsers are not durable DB jobs.
- Case scope depends on env or active-case pointers.
- Status is file-based or scattered.
- Worker crash recovery is local pid-file and `/proc` based; durable ownership,
  heartbeat, and stale-claim handling are absent.
- Duplicate ingestion/indexing risk remains because status and idempotency are
  not control-plane-backed.
- OpenSearch indexing status can drift from existing indices and cleaned status
  files.
- Evidence provenance can disconnect from parser outputs because parser docs and
  ingest manifests do not carry durable evidence/job/parser IDs.
- MCP tools may block synchronously, especially native commands and add-on calls.
- Frontend cannot reliably observe parser/native progress through one
  authoritative progress model.
- Audit gaps can occur when parser subprocesses, sidecar writes, or active-case
  resolution fail outside a durable audit/job transaction.
- Per-backend MCP routes may bypass the aggregate evidence-gate behavior.
- Report generation uses in-memory in-flight/draft state only.

## Key Job-Model Decisions From Run 5

- Target job statuses are `pending`, `queued`, `running`, `waiting_human`,
  `succeeded`, `failed`, `retrying`, `cancelled`, `stale`, and `paused`.
- Job scope includes `case_id`, requester identity fields, creator type,
  job type, status, priority, idempotency key, JSON spec, timestamps, worker
  claim/lease fields, heartbeat, attempt counters, cancellation fields, and
  failure summary.
- `case_id` must come from Gateway-validated human session or
  MCP/service-token context, not from process environment or legacy active-case
  pointers.
- Workers claim queued jobs from Postgres using an atomic row-locking /
  `SKIP LOCKED`-style pattern with worker capabilities, priority ordering,
  case fairness, leases, and heartbeats.
- Stale jobs are detected through expired leases and recovered through audited
  retry/requeue/fail/cancel decisions.
- `job_steps` and `job_logs` are the target observability model; stdout/stderr
  should be captured with redaction and linked to steps/jobs.
- Parser runs, parser outputs, ingest batches, and OpenSearch indexing status
  link back to `case_id`, `job_id`, `job_step_id`, `parser_run_id`, evidence
  IDs where applicable, parser versions, source hashes, and schema versions.
- Initial target job types are `evidence_register`, `evidence_hash`,
  `evidence_verify_integrity`, `evidence_ingest`, `parser_run`,
  `opensearch_index`, `timeline_build`, `ioc_extract`, `finding_generate`,
  `report_generate`, `report_export`, `case_archive`,
  `maintenance_reindex`, and `health_check`.
- Worker runtime assumes registration, capabilities, parser/command allowlists,
  no arbitrary shell execution, environment isolation, subprocess timeouts,
  stdout/stderr capture, heartbeat, graceful shutdown, cancellation handling,
  and crash recovery through leases.

## Key Integration Decisions From Run 6

- Gateway REST APIs are the human/operator job surface. They create, list,
  inspect, cancel, retry, and observe jobs, steps, logs, workers, execution
  health, and OpenSearch health through Gateway policy.
- Case authorization for REST job APIs must come from Supabase Auth/RLS plus
  Gateway policy. The Gateway remains the REST policy enforcement point.
- The frontend must not directly mutate authoritative job state. It submits
  actions through Gateway endpoints and reads job/status/health/audit views.
- Core SIFT MCP tools are the AI-agent/service job surface. Long-running tools
  enqueue DB-backed jobs and return `job_id`.
- Target MCP tools include `jobs.enqueue`, `jobs.get`, `jobs.list`,
  `jobs.tail_logs`, `jobs.cancel`, `jobs.retry`, `evidence.ingest`,
  `evidence.verify_integrity`, `parsers.list`, `parsers.run`,
  `opensearch.index_status`, `opensearch.health`, `report.generate`, and
  `finding.generate`.
- MCP case context comes from Gateway-validated token/session context, not
  process environment or legacy active-case pointers. Normal agent tokens cannot
  pass arbitrary `case_id`, raw OpenSearch DSL, raw index names, or wildcard case
  patterns.
- Initial frontend update strategy is polling first, with later SSE/WebSocket or
  Supabase Realtime as an upgrade path after DB/RLS/Gateway event policy is
  stable.
- Evidence vault behavior is preserved. Raw evidence remains immutable while
  operational metadata, integrity status, job state, and audit linkage move into
  Postgres over time.
- OpenSearch indexing jobs link parser runs, parser outputs, ingest batches,
  index registrations, and OpenSearch documents through Postgres IDs and source
  hashes. OpenSearch remains derived and non-authoritative.
- Audit remains mandatory for job lifecycle transitions, parser runs, evidence
  access/checks, OpenSearch indexing, report/finding generation, human
  approvals, destructive/final actions, and policy denials.
- Approval-gated work enters `waiting_human`. Agent-generated findings remain
  proposed/pending and cannot be auto-approved.
- Worker health is observed through registration, capabilities, heartbeat,
  active job, `last_seen_at`, degraded/offline state, health endpoints, and
  stale-job audit/log behavior.

## Open Questions (RESOLVED in Run 9 - historical)

> The list below is historical. All blocking items are now answered by
> `00_migration_charter.md` "Confirmed Decisions (Locked)" (D1-D17) and
> `09_identity_auth_cutover.md`. The few genuinely non-blocking items (exact
> Supabase migration directory shape, compatibility-export lifetime defaults,
> retry/cancellation granularity defaults, pgvector availability) are recorded
> with defaults in the relevant docs' "Decisions still genuinely open" sections.
> Do not treat the items below as still-open.

- What exact Supabase Local deployment shape should this repo target?
- Should active-case state be per human session, per workstation, per Gateway instance, or a combination with explicit precedence?
- What token hashing strategy should be canonical, including algorithm, optional pepper/KMS use, displayed fingerprints, and default expiry?
- What is the safest first cutover order: cases/tokens first, evidence/audit first, or OpenSearch/jobs first?
- How long should generated compatibility files remain supported after Postgres becomes authority?
- Which external scripts or operator workflows still read `~/.sift/active_case`, `~/.sift/ingest-status`, saved report JSON, or flat case JSON directly?
- Must evidence manifest/ledger files remain canonical legal artifacts even after Postgres becomes operational authority?
- What exact worker process model should parser execution target: single Gateway-host worker, multiple local workers, or future distributed workers?
- Should the project approve per-case logical indexes as the initial OpenSearch strategy, or target shared indexes with mandatory `case_id` filters from the start?
- What target index names and aliases should be canonical for artifacts, timeline records, and IOCs?
- How long should the legacy `case-{case_id}-{artifact_type}-{hostname}` indexes remain queryable?
- Should per-backend OpenSearch MCP routes become admin-only, disabled by default, or removed after core tools are available?
- Should any normal agent token ever receive constrained raw OpenSearch DSL access, or should raw DSL be admin-only?
- Which OpenSearch version/profile is canonical: root compose OpenSearch 2.18.0, package compose OpenSearch 3.5.0, or a newly declared target?
- Is semantic/vector search in the first OpenSearch migration scope, or explicitly deferred?
- Should the first implementation slice cover only OpenSearch ingest, or also
  native `run_command`, report generation, and evidence operations?
- Should short native commands remain synchronous while only long-running parser
  workflows become jobs?
- Should legacy `~/.sift/ingest-status` continue as a compatibility export once
  Postgres job state exists, and for how long?
- What cancellation semantics are acceptable for partially indexed OpenSearch
  batches and subprocess trees?
- Should retry happen at whole-job, host, artifact, parser-run, or indexing
  batch granularity first?
- Which report/export workflows should become job-backed first?
- Which evidence operations are too expensive to remain synchronous?
- Which external scripts still consume `~/.sift/ingest-status`,
  `~/.sift/ingest-logs`, active-case pointers, or ingest manifests?
- What exact human role names and permissions should apply to job creation,
  retry, cancel, log reads, worker detail, approvals, final export, archive, and
  destructive cleanup?
- What exact initial REST response schemas and MCP result schemas should be
  frozen before implementation?
- What initial frontend polling intervals should be accepted, and when should
  SSE/WebSocket or Supabase Realtime become part of the roadmap?
- Should raw OpenSearch DSL be admin-only forever, or should a constrained
  normal-agent mode ever exist?
- Which job/action audit events must be fail-closed if the DB audit writer is
  unavailable during the transition?
- What exact test layout and package-specific commands should the first
  baseline execution PR use?
- Which smoke fixtures can cover parser/ingest behavior without requiring a
  live OpenSearch instance?
- What exact Supabase/Postgres table, constraint, index, RLS, and migration
  layout should be used for jobs, job steps, job logs, workers, parser runs,
  parser outputs, ingest batches, and OpenSearch indexing status?
- Should the first schema migration use UUID DB primary keys plus legacy text
  compatibility keys, or text identifiers as primary keys?
- Should the initial Supabase tables live in an `app` schema, `public`, or
  another approved namespace?
- Which optional schema tables should be first-class from the start:
  `service_identities`, `evidence_access_events`, `worker_heartbeats`, and
  `opensearch_document_refs`?
- Should evidence dedupe enforce unique active `(case_id, sha256)`, or preserve
  duplicate acquisitions as separate first-class evidence objects?

## Next Recommended Run

JOB-0 (commit `c73762c`) and PR01 / Phase ID-1 are done. The next coding run is
**PR02 / Phase ID-2** - DB-first hash-only MCP/service token registry
dual-validation against `app.mcp_tokens` with legacy `gateway.yaml api_keys`
fallback. Scope source: `docs/migration/13_pr02.md`. It must not add Supabase
human auth, portal login replacement, active-case propagation, evidence-gate
changes, job/worker tables, REST job APIs, MCP job tools, OpenSearch/parser
changes, audit data migration, frontend redesigns, or legacy fallback removal.

In parallel with PR02, the **backend tooling revamp (D27a)** may start in a
dedicated worktree per `docs/migration/15_backend_tooling_revamp.md` (scope-fenced
to `packages/*-mcp/**`, no overlap with PR02). After **both** PR02 and D27a land,
the **gateway cutover (D27b)** (design in
`docs/migration/14_fastmcp3_supabase_integration.md`) lands as a dedicated,
**policy-parity-gated**, single revertable big-bang PR **before** the heavier
evidence/jobs phases:

- Migrate the Gateway to FastMCP 3.0 as one FastAPI ASGI app (REST via FastAPI DI
  + MCP via `mcp.http_app`); replace `server.py`/`backends/*.py` aggregation with
  providers/transforms; re-host the policy middleware (evidence gate, response
  guard, audit, active-case, authorization) - never delegated to the framework.
- Migrate the three in-SDK FastMCP-1.x backends to standalone 3.0 (decorator
  mode, `await ctx.get_state`, `list_tools()`).
- **Parity gate before merge:** all ~1146 package tests green on the branch +
  a new MCP-surface contract test (tool names/namespaces/schemas byte-stable;
  evidence-gate/response-guard/audit/active-case behavior unchanged).
- `code-mode` is out of scope (D25); `run_command` unchanged.

The remaining cutover (evidence/audit, jobs/OpenSearch-core, findings/RAG/skills)
then follows the charter "Cutover Order", authored natively on FastMCP 3.0.
