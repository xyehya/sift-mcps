# 22 - D22A / Batch H `mcp_backends` Control-Plane Registry (decision D22)

Status: implemented on build branch `codex/d22a-mcp-backends-registry` (not landed)
Scope fence: see §4
Decisions referenced: D2, D3, D12, D22, D24, D30, D32, D33, D34; carries
F-11, B-13; complements B-4.

This Build branch implements **D22A / Batch H**: add-on MCP backend registration
moves out of `gateway.yaml` into a Supabase/Postgres `app.mcp_backends`
control-plane registry, the Gateway backend loader becomes DB-authoritative, the
portal backend-management surface is turned over to that registry, and **B-13**
is wired in code. It preserves every landed policy guarantee: PR03A Supabase JWT
identity, PR03B DB active-case authority, B-10 tool authz, B-11 proxy active-case
handling, D3 no per-backend `/mcp/{name}`, and D24 SIFT-owned policy.

This branch is not Land yet: **F-11** and **B-13** are marked resolved/done only
after the D22A commit lands on `revamp/spg-v1`.

## 1. Operator Decisions Locked For This Batch

From the charter and the D22A prompt:

- **D22** is the locked direction: add-on backends are query-only/read-only by
  default; backend registration moves from `gateway.yaml` into a control-plane
  `mcp_backends` registry, managed/monitored from the portal; the Gateway reads
  registration/enabled/health state from the control plane, not config.
- **DB is the sole add-on backend authority after D22A.** The `gateway.yaml`
  `backends:` block is no longer read as authority. There is no automatic bulk
  migration of existing config; an explicit, operator-run import/seed path may
  populate the DB from an existing `backends:` block, but it is a one-time
  convenience, not authority and not automatic (consistent with the D32 / Batch B
  "no historical data migration" stance).
- Core/in-process tools (case/evidence/findings/TODO/IOC/timeline/report,
  OpenSearch read+job per D19, RAG retrieval per D23) are **not** registry
  entries and are unaffected. `mcp_backends` holds add-ons only.
- No raw backend secrets land in the repo, in migration files, in DB rows, in
  fixtures, in snapshots, in logs, in audit payloads, or in docs.

Two decisions this batch could not make silently were raised as forks for the
operator in §13 and are now locked for Build: **F-14 -> D33** (credential
references only, `env` source in D22A) and **F-15 -> D34** (restart-to-apply for
the FastMCP `/mcp` catalog).

## 2. Required Reading

Ordered, before Build:

1. `docs/migration/MIGRATION_STATE.md` - Current Objective + the D22A Run entry.
2. `docs/migration/00_migration_charter.md` - D2, D3, D12, D22, D24, D30, D32.
3. `docs/migration/REGISTER.md` - F-11, B-13, and carried B-4/B-12/B-15.
4. `docs/migration/10_addon_backend_spec.md` - the locked add-on contract this
   registry serves (§3 manifest additions `case_scoped`/`data_plane`; §4
   registration flow).
5. `docs/migration/18_target_architecture_acceleration.md` §11 Batch H, §13.
6. `docs/migration/20_portal_dashboard_inventory.md` - backend/service management
   rows and authority map.
7. `docs/migration/21_pr03b_active_case_db_authority.md` - current Gateway/portal
   policy and DB-service patterns to mirror (`ActiveCaseService`, DSN wiring).
8. `docs/migration/17_gateway_cutover_d27b.md` - FastMCP proxy mount mechanics.
9. `AGENTS.md` - host->VM workflow, VM coordinates, Supabase pin, safety rules.

## 3. Grounded Current-State Inventory

Read against the source at commit `335cedd` (do not design from memory; the Build
session re-confirms these):

**Authority = `gateway.yaml` today.**
- `Gateway.__init__` (`packages/sift-gateway/src/sift_gateway/server.py:160`)
  reads `config.get("backends", {})` and calls `create_backend(name, conf)` for
  each non-disabled entry, populating `self.backends`. `_RETIRED_CORE_BACKENDS`
  and `sift-core` are rejected as configured backends.
- `create_backend` / `load_and_validate_manifest`
  (`packages/sift-gateway/src/sift_gateway/backends/__init__.py`) load the
  manifest from the well-known path
  `packages/<name>/sift-backend.json` (or `manifest_path` file/URL), validate it
  against `sift-backend.schema.json` (spec_version 1.x) plus
  `validate_manifest_contract` (namespace prefix, >=1 tool, exactly one health
  tool, evidence-class/read-only consistency, valid phases). A missing/invalid
  manifest is a hard reject.
- The portal "Backends & Add-ons" tab
  (`packages/case-dashboard/frontend/src/components/backends/BackendsTab.jsx`)
  calls `GET/POST /api/backends`, `POST /api/backends/validate`,
  `POST /api/backends/reload`, and `POST /api/services/{name}/{start|stop|restart}`
  (`packages/case-dashboard/frontend/src/api/endpoints.js:80-83`), proxied by
  `packages/case-dashboard/src/case_dashboard/routes.py:4830-4998` into
  `sift_gateway.rest` logic.
- `register_backend_logic` (`rest.py:1020`) validates, then **writes the backend
  entry into `~/.sift/gateway.yaml`** via `_atomic_yaml_write` under
  `_CONFIG_LOCK`, mirrors it into `gateway.config["backends"]` and
  `gateway.backends`, rebuilds the tool map, and sets
  `_pending_backends`/`_reload_event`. `reload_backends` (`rest.py:934`)
  re-reads `gateway.yaml` and schedules pending backends. The join/wintools path
  (`rest.py:_add_wintools_backend` / `join_gateway`) also writes a backend block
  into `gateway.yaml`.
- Connection secrets live in `gateway.yaml` today: `bearer_token`, per-backend
  `env`, and `tls_cert` path. REST error/reason sanitizers already special-case
  `bearer_token`/`tls_cert`/`env` so they never echo back.

**FastMCP proxy mounts are fixed at server assembly.**
- `create_gateway_mcp_server` (`mcp_server.py:137`) builds the aggregate
  `FastMCP`, registers core local tools, and calls `_mount_addon_proxies`, which
  iterates `gateway.backends` and `mcp.mount(create_proxy(...), namespace=...,
  tool_names=...)` **once**. The lifespan comment in `server.py:970` states "MCP
  proxy mounts are fixed at server startup." So a backend registered live appears
  in the REST `_tool_map` (via `_build_tool_map`) but its tools are **not** added
  to the FastMCP `/mcp` catalog until the Gateway process restarts. This is the
  core gap D22A must address (see F-15).
- `assert_mounted_tool_names` (`mcp_server.py:348`) is defined but never called -
  this is **B-13**.

**DB plumbing already exists to mirror.**
- `registry_config(config)` (`token_registry.py:69`) resolves the control-plane
  DSN from `token_registry.postgres_dsn` / `control_plane.postgres_dsn` /
  `SIFT_CONTROL_PLANE_DSN`. `create_app` already builds DB-backed services from
  that DSN: `ActiveCaseService(dsn)` (PR03B) and `PostgresTokenRegistry` (PR02).
  The `mcp_backends` repository follows the same construction and the same
  service-role/superuser DSN write path (D12).
- Migrations live in `supabase/migrations/` (`202606070101_identity_foundation`,
  `..0300_unified_jwt_principals`, `..0400_active_case_authority`); DB schema
  tests live in `tests/db/`.

## 4. Scope Fence

Allowed paths for this PR:

- `supabase/migrations/**`
- `tests/db/**`
- `packages/sift-gateway/**`
- `packages/case-dashboard/**`
- `configs/gateway.yaml.template`
- `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json` (the manifest
  schema, additive `case_scoped` / `data_plane` fields per doc 10 §3)
- `pyproject.toml`, `uv.lock` only if dependencies truly change (none expected)
- `docs/migration/**`
- `AGENTS.md`, `CLAUDE.md`

Explicitly out of scope:

- `packages/*-mcp/**` (no backend rewrites). Adding `case_scoped`/`data_plane`
  fields to the shipped `windows-triage-mcp` / `opencti-mcp` `sift-backend.json`
  manifests is **deferred** to a later additive task unless a fork amends this -
  the registry must accept manifests without those fields (treat absent
  `case_scoped` via the existing `is_case_scoped_tool` heuristic;
  `default_case_scoped`/`data_plane` optional).
- OpenSearch/RAG core moves (D19/D23), evidence/audit DB authority (Batch C),
  jobs/workers (Batch E), findings/timeline/TODO/IOC/report data migration.
- Legacy auth sunset: `gateway.yaml api_keys` and PR02 token authority stay as-is
  (Batch I / ID-6). D22A moves **backend registration only**, not credentials of
  human/agent principals.
- Installer, Docker, local Supabase state, DB dumps, VM service deploy, secrets,
  generated build artifacts, unless the candidate is amended before Build.
- Live dynamic FastMCP remount beyond whatever F-15 resolves to.

Parallelism: zero file overlap with Batch C/E planning. Depends on Batch A
(landed) for operator admin auth. If Batch B were still in flight it would
contend on `server.py`/`mcp_server.py`; PR03B is landed, so the lane is clear.

## 5. Schema Work

New migration `supabase/migrations/<next-timestamp>_mcp_backends_registry.sql`,
additive only, syntax-checked on the VM inside `BEGIN; ... ROLLBACK;`.

### 5.1 `app.mcp_backends`

One row per add-on backend. Indicative columns (Build fixes exact types):

| Column | Purpose |
| --- | --- |
| `id uuid` PK (`gen_random_uuid()`) | surrogate key (D10) |
| `name text` UNIQUE NOT NULL | backend key (`^[a-z0-9][a-z0-9-]*$`), matches today's REST name rule |
| `namespace text NOT NULL` | manifest namespace (tool-name prefix) |
| `transport text NOT NULL` | `stdio` \| `http` |
| `tier text` | manifest tier (reuse existing values; D22 §9 open item) |
| `enabled boolean NOT NULL DEFAULT true` | portal enable/disable |
| `connection jsonb NOT NULL` | **non-secret** connection config (stdio: `command`/`args`/`cwd`/non-secret `env`; http: `url`). Secret fields are credential *references*, never raw values (see F-14) |
| `data_plane jsonb` | doc 10 §3.2 declaration (optional) |
| `default_case_scoped boolean` | doc 10 §3.1 backend default (optional) |
| `manifest jsonb NOT NULL` | cached, schema-validated manifest at registration time |
| `manifest_source text` | path/URL the manifest came from |
| `manifest_sha256 text` | integrity/drift marker for the cached manifest |
| `health_status text` | last health result (`ok`/`error`/`gated`/`disabled`/`invalid_manifest`/`unknown`) |
| `health_detail text` | short, non-secret detail |
| `health_checked_at timestamptz` | last health probe time |
| `registered_by uuid` | `auth.users` / app principal who registered it |
| `created_at` / `updated_at timestamptz` | audit timestamps |

Constraints: `name` unique; `transport` check; `namespace` non-empty; reject a
`name` equal to any retired-core name or `sift-core` at the DB layer too
(defense in depth alongside the existing Gateway guard).

### 5.2 Health/manifest state

Keep v1 lean: last-known health on the `mcp_backends` row (mirrors today's
single live `health_check()` surface). Add a separate
`app.mcp_backend_health_events` history table **only if** a portal/health
timeline genuinely needs it — otherwise defer (D13 lean-core discipline). State
the choice explicitly; do not add unused tables.

### 5.3 Credential references (F-14 -> D33)

No raw secret column. `connection` stores only non-secret connection metadata and
structured references, consistent with the existing `auth.*_env` pattern in
`gateway.yaml.template`. D22A implements `env` references now:
`bearer_token_env`, `tls_cert_env`, and `env_refs` (target backend environment
variable -> Gateway process environment variable). The loader resolves these
references from the Gateway process environment at backend-construction time.
Raw secret-bearing fields are rejected at registration. Supabase Vault is an
allowed future reference source only after a separately scoped secret-lifecycle
design; D22A does not enable Vault or write Vault secrets. This complements
**B-4**.

### 5.4 RLS / write model (D12)

- RLS enabled; operators get scoped reads of `app.mcp_backends`
  (status/health/manifest metadata) for the portal, consistent with the PR03A
  Supabase-JWT operator read pattern (Gateway reads via the service-role/superuser
  DSN; browser reads flow through the Gateway, not direct).
- All writes (register/enable/disable/update/health) go through the Gateway
  service-role path. The browser never writes `mcp_backends` directly.
- No `grant ... to authenticated` broad write. Keep parity with the PR03A
  forward-looking RLS posture.

### 5.5 DB tests

`tests/db/test_d22a_mcp_backends_schema.py`: table/columns/constraints exist, RLS
enabled, no-raw-secret invariant (no secret-looking columns; fixtures carry only
references), uniqueness on `name`, retired-core-name rejection, and migration
text applies+rolls back clean. No real secrets, tokens, or live host data in
fixtures.

## 6. Gateway Backend Loader (DB authority)

Add a Gateway-owned `McpBackendRegistry` repository (mirror `ActiveCaseService`
construction from the DSN in `create_app`). Behavior:

| Operation | Required behavior |
| --- | --- |
| `list_backends()` | Returns enabled+disabled DB rows with manifest/connection/health metadata for the loader and portal. |
| `load_for_gateway()` | The startup source of `gateway.backends`: for each enabled row, resolve credential references, build the backend via `create_backend(name, connection)`, attach the cached/validated manifest. Replaces the `config["backends"]` loop in `Gateway.__init__`. |
| `register(name, config, manifest, actor)` | Validates manifest (schema + contract), computes `manifest_sha256`, writes the row, audits `mcp_backend.registered`. |
| `set_enabled(name, enabled, actor)` | Flips `enabled`, audits. |
| `update_health(name, status, detail)` | Persists the last health probe. |
| `unregister(name, actor)` | Removes/soft-disables the row, audits. |

Precedence rules:

- **DB is authority.** `Gateway.__init__` / `start()` build `self.backends` from
  the registry, not from `config["backends"]`.
- `gateway.yaml backends:` is **ignored as authority**. Keep the
  `_RETIRED_CORE_BACKENDS`/`sift-core` rejection. If the DSN is absent (no control
  plane), the Gateway runs with **no add-ons** (core tools only) and logs loudly;
  it does not silently fall back to yaml authority. An explicit operator
  import/seed path (script or one-shot endpoint) may copy an existing
  `backends:` block into the DB, but that is a manual convenience, not automatic
  and not authority.
- The join/wintools registration path writes to the DB registry, not
  `gateway.yaml`.

The loader must preserve the existing manifest gating
(`evaluate_requirement`, namespace prefix enforcement, tool-name collision /
core-tool collision checks in `_build_tool_map`). Those checks stay; only the
**source** of the backend set changes.

## 7. FastMCP Mount / Reload Behavior (policy ordering preserved)

`_mount_addon_proxies` must mount from the DB-loaded `gateway.backends` set
exactly as today, with the same `Namespace`/`tool_names` prefix preservation and
the same egress/no-token-passthrough guards in `_create_http_proxy`. The
middleware stack order is unchanged and non-negotiable:
`GatewayToolCatalogMiddleware` -> `gateway_policy_middlewares` (evidence gate ->
response guard -> case context -> audit) -> tool authz. D24/D2/D3 hold: policy is
SIFT-owned, single `/mcp` path, no per-backend route.

**Activation model is F-15 -> D34.** Registry changes are authoritative
immediately for REST/portal metadata, but the FastMCP `/mcp` catalog applies
them only when the Gateway process restarts and rebuilds the aggregate FastMCP
server from the DB registry. `POST /api/backends/reload` refreshes
registry/runtime metadata and reports `restart_required`; it does not
live-remount providers into the running `http_app`. The portal shows a clear
`pending_apply` state for rows whose registry revision is newer than the current
MCP catalog revision. A future zero-restart dynamic remount requires a new fork.

## 8. Portal Backend Management Turnover

Turn the existing surface from yaml/live-state to the DB registry without
redesigning the dashboard:

| Surface | D22A behavior |
| --- | --- |
| `GET /api/backends` (`list_backends`) | Reads the DB registry (enabled/disabled/manifest/health) joined with live `gateway.backends` runtime status. No `gateway.yaml backends` read as authority. |
| `POST /api/backends` (`register_backend_logic`) | Validates, then writes the **DB row** (not `gateway.yaml`); audits; applies per F-15. Operator challenge/auth unchanged. |
| `POST /api/backends/validate` | Unchanged validation semantics (schema+contract), no persistence. |
| `POST /api/backends/reload` | Re-reads the **DB registry** and applies per F-15 (replaces the `gateway.yaml` re-read). |
| `POST /api/services/{name}/{start\|stop\|restart}` | Operates on DB-registered backends; `enabled`/health reflect/update the DB row. |

Frontend (`BackendsTab.jsx`) work is narrow: keep the table/form; adjust
labels/empty-states so it reads as a DB registry (e.g. show registry vs runtime
status, and the pending-apply state if F-15=(a)). Do not redesign.

Keep the existing secret-sanitization on all responses/reasons
(`bearer_token`/`tls_cert`/`env` never echoed); the same applies to anything read
back from the DB.

## 9. B-13 Resolution

Wire `assert_mounted_tool_names` (`mcp_server.py:348`) at server assembly, after
`_mount_addon_proxies`, with the expected tool-name set derived from the
DB-registry manifests (post-rename, matching `_tool_rename_map`). On mismatch it
raises and the startup fails loudly. If the Build instead chooses DB/manifest
validation as the single guard, it must delete the dead function and document why
in the doc/log. Either way **B-13 is marked DONE only at Land**.

## 10. F-11 Resolution

F-11 ("D27b reads add-ons from `gateway.yaml`; confirm it is in scope, not a
silent dependency") is resolved by this batch moving that authority into
`app.mcp_backends`. **Mark F-11 RESOLVED in `REGISTER.md` only at Land**, citing
the landed migration + loader, not at Plan time.

## 11. Audit, Identity, Active-Case Invariants (must not regress)

- Every privileged registry write (register/enable/disable/unregister/health
  change) emits an audit event with the resolved operator principal. Reuse the
  Gateway `AuditWriter`.
- PR03A identity is untouched: Supabase JWT validation, the shared resolver,
  B-10/B-14 behavior, and operator-only deny-by-default for these mutations.
- PR03B/B-11 is untouched: case-scoped proxied tools still get DB
  `case_id`/`case_key` injection or typed audited denial; the registry only
  changes where the backend set comes from, not active-case propagation. The
  per-tool `case_scoped` flag (`is_case_scoped_tool`) keeps working, now also
  fed by the manifest's `case_scoped`/`default_case_scoped` when present.
- D3 holds: no per-backend `/mcp/{name}` route is introduced.

## 12. Required Tests

Host (`.venv`) and VM (`/usr/bin/python3.12`, `UV_NO_MANAGED_PYTHON=1`,
`UV_PYTHON_DOWNLOADS=never`). Per doc 18 §13:

- **DB authority test:** Gateway loads its add-on set from `app.mcp_backends`;
  add/enable/disable in the DB changes the loaded set after apply.
- **Legacy-staleness test:** a `gateway.yaml` with a `backends:` block is
  **ignored** as authority - those entries do not appear unless present in the DB
  registry. (Negative test, mirrors the PR03B stale-env probe.)
- **No-DSN posture test:** with no control-plane DSN, the Gateway serves core
  tools only and logs; it does not load yaml backends.
- **Registry CRUD + audit:** register/enable/disable/unregister each writes the
  expected row and an audit event; secrets never persisted or echoed.
- **Manifest validation parity:** schema + contract rejects (bad namespace,
  missing/duplicate health tool, evidence-class mismatch) behave as today, now at
  the registry boundary.
- **B-13 assertion:** mounted FastMCP tool names match the expected DB-manifest
  set; a forced mismatch raises.
- **Policy parity:** evidence gate / response guard / case context / audit /
  B-10 authz still wrap a DB-registered proxied tool identically (extend the
  existing D27b policy-parity suite).
- **Cross-case denial:** a `case_scoped` DB-registered proxy tool still denies a
  mismatched client `case_id` (B-11 regression).
- **VM live gates (doc 18 §11 Batch H):** add a backend in the portal against the
  real local Supabase; Gateway applies the DB registry; `gateway.yaml backends`
  entries are absent/ignored; health and audit rows visible; disable removes it
  from the served set after apply.
- **VM Postgres syntax:** migration applies+rolls back inside `BEGIN/ROLLBACK`
  against the pinned Supabase stack.
- Existing gateway/case-dashboard/core/db suites stay green.

## 13. Risks / Forks (-> REGISTER.md)

- **F-14 - backend credential storage model. RESOLVED by D33.** `bearer_token`,
  per-backend `env`, and `tls_cert` are represented by `env` references in D22A;
  raw secrets are rejected. Supabase Vault remains future scoped work.
- **F-15 - activation model. RESOLVED by D34.** FastMCP proxy mounts are fixed at
  server assembly today; D22A uses restart-to-apply and a portal/API
  `pending_apply` state, not live dynamic remount.
- **B-13** is resolved by §9 but only marked DONE at Land.
- Carried unchanged: **B-4** (credential-as-arg; F-14 is adjacent),
  **B-12** (capped-result `backend_audit_id`), **B-15** (DNS-rebinding TOCTOU on
  proxied/remote-manifest fetches - relevant because the registry stores remote
  manifest sources; keep the existing resolve-before-connect SSRF guards, do not
  regress them).

Stop-and-fork (D29) if Build discovers: the FastMCP version's mount/remount API
differs from the recorded `3.4.2` facts; a manifest field the schema cannot
additively express; or any path that would require touching `packages/*-mcp/**`
beyond optional manifest field additions.

## 14. Deliverable

- `supabase/migrations/<ts>_mcp_backends_registry.sql` (additive).
- `tests/db/test_d22a_mcp_backends_schema.py`.
- Gateway `McpBackendRegistry` repository + loader rewire in `server.py`;
  `_mount_addon_proxies` sourced from the registry; `assert_mounted_tool_names`
  wired (B-13); registry-backed `rest.py` register/reload/validate/services
  logic.
- `case_dashboard` route turnover + narrow `BackendsTab.jsx` label/state changes.
- `sift-backend.schema.json` additive `case_scoped`/`data_plane` fields (optional,
  back-compatible).
- `configs/gateway.yaml.template`: `backends:` block documented as
  non-authoritative/removed; control-plane DSN remains the registry source.
- Docs/logs: this doc is flipped to implemented for the Build branch; Run 38 is
  logged in `MIGRATION_STATE.md`; mark **F-11 RESOLVED** and **B-13 DONE** only
  at Land.

## 15. Ready-to-copy Build Prompt

```
ROLE & MODE: Build — implement D22A / Batch H from
docs/migration/22_d22a_mcp_backends_registry.md WITHOUT redefining scope.
Branch off revamp/spg-v1 at/after 335cedd; one revertable PR; one worktree.

PRECONDITION: F-14 (backend credential storage model) and F-15 (FastMCP
activation model) must be operator-resolved in REGISTER.md before coding. If
either is OPEN, stop and request the call — do not pick silently.

REQUIRED READING (ordered): doc 22 §1-§14; charter D2/D3/D12/D22/D24/D30/D32;
REGISTER F-11/B-13/F-14/F-15/B-4/B-12/B-15; doc 10 (add-on contract); doc 21
(ActiveCaseService/DSN pattern to mirror); doc 17 (FastMCP mount mechanics);
AGENTS.md host→VM path + Supabase pin.

GROUND IN SOURCE BEFORE WRITING (re-confirm, do not trust memory):
- packages/sift-gateway/src/sift_gateway/server.py (Gateway.__init__ backends
  loop; create_app DSN wiring; lifespan "mounts fixed at startup")
- packages/sift-gateway/src/sift_gateway/mcp_server.py (_mount_addon_proxies,
  _tool_rename_map, assert_mounted_tool_names, middleware order)
- packages/sift-gateway/src/sift_gateway/backends/__init__.py (create_backend,
  load_and_validate_manifest, validate_manifest_contract)
- packages/sift-gateway/src/sift_gateway/rest.py (register_backend_logic,
  reload_backends, validate_backend_logic, _add_wintools_backend, _atomic_yaml_write)
- packages/sift-gateway/src/sift_gateway/token_registry.py (registry_config DSN)
- packages/case-dashboard/src/case_dashboard/routes.py (/api/backends* routes)
- packages/case-dashboard/frontend/src/components/backends/BackendsTab.jsx
- supabase/migrations/* and tests/db/* for migration+test conventions
- Confirm installed fastmcp==3.4.2 mount/remount API matches doc 17/22 facts.

DELIVERABLE: doc 22 §14 — additive app.mcp_backends migration + DB tests;
Gateway McpBackendRegistry loader making DB the sole add-on authority (gateway.yaml
backends ignored; no-DSN ⇒ core-only, no yaml fallback); registry-sourced FastMCP
mounts with B-13 assertion wired; F-15-chosen activation model; portal/REST
turnover to the DB registry; additive schema fields; template + docs/log updates.

HARD CONSTRAINTS:
- Preserve PR03A Supabase JWT auth, PR03B DB active-case authority, B-10 tool
  authz, B-11 proxy active-case handling, D3 (no /mcp/{name}), D24 SIFT-owned
  policy, and the exact middleware ordering.
- No raw backend secrets in repo/migrations/DB rows/fixtures/snapshots/logs/audit/
  docs — credential references only (F-14 outcome).
- No packages/*-mcp rewrites (optional additive manifest fields only); no
  OpenSearch/RAG core move, no evidence/audit/jobs/findings/timeline/report data
  migration, no api_keys/PR02 auth changes, no installer/Docker/local-Supabase/DB
  dumps.
- Every privileged registry write is audited with the resolved operator principal.

OUTPUT DISCIPLINE: update the golden snapshot/change-map if the tool surface
moves; run python3 scripts/validate_docs.py and git diff --check;
host + VM evidence (VM: /usr/bin/python3.12, UV_NO_MANAGED_PYTHON=1,
UV_PYTHON_DOWNLOADS=never; migration in BEGIN/ROLLBACK on pinned Supabase).
Run /code-review (always) and /security-review (touches secrets/credentials,
Gateway policy path, tokens). No silent decisions — raise forks.

ACCEPTANCE: doc 22 §12 gates all pass on host and VM. End by listing any forks
needing the operator's call. Do NOT mark F-11 RESOLVED or B-13 DONE until Land.
```
