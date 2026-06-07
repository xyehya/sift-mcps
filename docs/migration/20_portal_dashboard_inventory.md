# Portal/Dashboard Inventory Reference

Status: **reference inventory, not an implementation candidate**. Use this to
ground PR03B / Batch B planning and later portal turnover work. Do not implement
runtime changes directly from this document; create a scoped candidate first per
D29.

Source: a separate read-only inventory worker scanned the old detached portal
inventory worktree before PR03A landed. This document preserves the useful
workflow/API map, normalizes paths to the current repository, and updates the
auth rows to the landed PR03A / Run 29 state on `revamp/spg-v1`.

## What Changed Since The Raw Inventory

- PR03A replaced portal login/session with Gateway-injected Supabase Auth
  callbacks and a signed session-envelope cookie.
- PR03A replaced the PR02 token lifecycle UI/API target with agent/service
  Supabase JWT issuance and revocation.
- Run 29 fixed the fresh Supabase-only portal startup trap: legacy local PBKDF2
  setup/challenge/reset endpoints are suppressed whenever Supabase auth is
  active or `legacy_portal_session_enabled=false`.
- Run 31 locked D32 for PR03B: active case must be Supabase/Postgres
  authoritative, with no active-case env/config/pointer compatibility exports
  and no historical data migration.
- Runs 33-34 landed PR03B: case list/create/activate/current-case/metadata
  routes use the injected DB active-case service in scoped request paths, and
  stale env/config/pointers do not win over Postgres.
- Findings, timeline, evidence status, TODOs, reports, backend registry, and
  most audit surfaces remain file/config/process backed and stay in future
  batches.

## Workflow Inventory

| Workflow | Frontend surface | Main API calls | Backend owner | Authority today after PR03A | Target batch |
| --- | --- | --- | --- | --- | --- |
| Portal boot/session check | `frontend/src/App.jsx`, `hooks/useDataPolling.js` | `GET /portal/api/auth/me`, then polling reads for case, summary, findings, delta, timeline, evidence, IOCs, TODOs, reports | `case_dashboard.routes`, `PortalSessionMiddleware` | Supabase session-envelope cookie for auth; active case is DB-backed after PR03B; broader read data still file backed | PR03A done for auth; PR03B done for active case; Batch C/D for data authority |
| Login/logout/session refresh | `LoginCard.jsx`, `Header.jsx`, `CommandPalette.jsx` | `POST /auth/login`, `POST /auth/logout`, `POST /auth/refresh`, `GET /auth/me` | Gateway-injected portal auth callbacks | Supabase Auth validates identity; Gateway resolves SIFT principal; portal stores no token material outside signed HttpOnly cookie | PR03A done |
| Legacy first-time setup/password reset | `LoginCard.jsx` legacy branches | `GET /auth/setup-required`, `POST /auth/setup`, `GET /auth/challenge`, `POST /auth/reset-password` | `case_dashboard.routes` | Disabled in Supabase mode or when legacy portal sessions are disabled; legacy-only compatibility otherwise | PR03A/Run 29 done; remove at legacy sunset |
| Case list/create/activate | `Header.jsx` case menu | `GET /cases`, `POST /case/create`, `GET /case/activate/challenge`, `POST /case/activate` | `case_dashboard.routes` | DB active-case service after PR03B; artifact directories may still be created as storage only | PR03B done |
| Case metadata edit | `CaseBriefCard.jsx` | `GET /case`, `POST /case/metadata` | `case_dashboard.routes`, DB active-case service | DB case row/metadata after PR03B; `CASE.yaml` is no longer active-case metadata authority for these routes | PR03B done for active-case metadata; Batch D handles broader file-backed investigation data |
| Findings/timeline/audit review staging | `FindingsTab.jsx`, `CommandPalette.jsx` | `GET /findings`, `GET /findings/{id}`, `GET /timeline`, `GET /audit/{finding_id}`, `GET/POST/DELETE /delta` | `case_dashboard.routes` | `findings.json`, `timeline.json`, `pending-reviews.json`, approvals JSONL, audit JSONL | Batch D, with DB audit dependencies from Batch C |
| Commit staged findings | `CommitDrawer.jsx` | `GET /commit/challenge`, `POST /commit` | `case_dashboard.routes` | In-memory commit challenge + legacy password material; writes case-local findings/approvals files | Batch D; challenge model must be reworked for Supabase operators |
| Evidence inventory and chain operations | `EvidenceTab.jsx`, `StatusBar.jsx` | `GET /evidence`, `GET/POST /evidence/chain/*`, `POST /evidence/{path}/verify` | `case_dashboard.routes`, evidence helpers | Evidence files remain immutable; metadata/status split across manifest, ledger, `evidence.json`, optional Solana env/state | Batch C |
| TODO management | `TodosTab.jsx` | `GET/POST/PATCH/DELETE /todos` | `case_dashboard.routes` | `todos.json` | Batch D |
| IOC/hosts/accounts/timeline exploration | `IocsTab`, `HostsTab`, `AccountsTab`, `TimelineTab` | Polling reads: `GET /iocs`, `GET /findings`, `GET /timeline` | `case_dashboard.routes` | `iocs.json`, `findings.json`, `timeline.json` | Batch D/F depending on OpenSearch read model |
| Reports | `ReportsTab.jsx` | `GET /reports`, `POST /reports/generate`, `POST /reports/{id}/save`, `GET /reports/{id}`, `GET /reports/{id}/download` | `case_dashboard.routes`, `sift_core.reporting` | In-memory pending drafts + `case/reports/*.json` | Batch D; durable generation may move to jobs in Batch E |
| Agent/service JWT lifecycle | `SettingsTab.jsx` | `GET/POST /auth/principals`, `DELETE /auth/principals/{kind}/{id}` | Gateway portal auth callbacks | Supabase Auth users + app principal tables + tool scopes; token material shown once | PR03A done |
| Legacy PR02 token lifecycle | `SettingsTab.jsx` legacy section | `GET/POST /tokens`, rotate/revoke/reactivate | `case_dashboard.routes`, `token_registry` | PR02 hash-only token registry when compatibility bridge is enabled | Legacy bridge; remove at ID-6/sunset |
| Backend/service management | `BackendsTab.jsx` | `GET/POST /backends`, `POST /backends/validate`, `POST /backends/reload`, `POST /services/{name}/{action}` | Portal proxy + Gateway backend logic | `gateway.yaml backends`, live Gateway backend state, manifests | Batch H / D22/F-11 |
| Response guard override | No active React caller found; wrappers exist in `endpoints.js` | `GET /response-guard/status`, `POST /response-guard/override`, `POST /response-guard/override/cancel` | `case_dashboard.routes`, Gateway response guard callbacks | Gateway process state keyed by active case; override writes are challenge protected | Open; likely Batch C/I policy UI decision |

## Current Portal API Groups

All React `apiFetch()` calls use the `/portal` base and include cookies. The
same route table is still mounted for the legacy `/dashboard` surface, but
`/portal` is the current React/Vite app.

| API group | Representative routes | Auth/session behavior | Current authority | Migration owner |
| --- | --- | --- | --- | --- |
| Supabase portal auth | `/api/auth/login`, `/api/auth/logout`, `/api/auth/refresh`, `/api/auth/me` | Supabase session-envelope cookie, operator-only portal APIs, agent/service denied | Supabase Auth + SIFT app principal mapping | PR03A done |
| Legacy portal auth compatibility | `/api/auth/setup-required`, `/api/auth/setup`, `/api/auth/challenge`, `/api/auth/reset-password` | Public setup/challenge only when legacy local portal auth is enabled and Supabase callbacks are absent | `/var/lib/sift/passwords`, in-memory challenge pools | Legacy sunset |
| Cases and active case | `/api/cases`, `/api/case/create`, `/api/case/activate`, `/api/case`, `/api/case/metadata` | Portal role for reads; operator writes; Supabase mode activation has no legacy active-case password challenge | DB active-case service after PR03B; no env/config/pointer authority | PR03B done |
| Findings and review | `/api/findings`, `/api/findings/{id}`, `/api/timeline`, `/api/audit/{finding_id}`, `/api/delta` | Portal reads; operator writes | Case-local JSON/JSONL | Batch D |
| Evidence | `/api/evidence`, `/api/evidence/chain/*`, `/api/evidence/{path}/verify` | Portal reads; operator challenge for most mutations | Evidence files + manifest/ledger/`evidence.json` | Batch C |
| TODOs and IOCs | `/api/todos`, `/api/iocs` | Portal reads; operator TODO writes | `todos.json`, `iocs.json` | Batch D |
| Reports | `/api/reports*` | Operator only | Pending in-memory drafts + report JSON files | Batch D/E |
| Agent/service principals | `/api/auth/principals*` | Owner/admin operator only | Supabase/app principal tables; no raw token persistence | PR03A done |
| Legacy token bridge | `/api/tokens*` | Compatibility only | PR02 `app.mcp_tokens`; legacy metadata fallback | ID-6/sunset |
| Backend/service management | `/api/backends*`, `/api/services/*` | Portal role reads; operator/challenge for mutations | `gateway.yaml`, live Gateway state | Batch H |
| Response guard override | `/api/response-guard/*` | Portal status; operator/challenge override | Gateway response guard process state | Open |

## Gateway REST Routes To Revisit

These routes are not normal React calls except where the portal proxies backend
management, but they matter for auth and legacy-token sunset.

| Gateway REST group | Routes | Current issue | Target owner |
| --- | --- | --- | --- |
| Tool listing/calls | `GET /api/v1/tools`, `POST /api/v1/tools/{tool_name}` | REST tool path exists beside FastMCP `/mcp`; B-10 policy must remain consistent across both surfaces | PR03A done for auth/tool scopes; future hardening as needed |
| Backend registry/services | `/api/v1/backends*`, `/api/v1/services*` | Still YAML/live-state authority | Batch H |
| Join-code bootstrap | `/api/v1/setup/join-code`, `/api/v1/setup/join`, `/api/v1/setup/join-status` | Can issue/register raw gateway-token style bootstrap material | Open; align with D30/legacy sunset |

## Frontend Component Map

| Frontend source | API/use |
| --- | --- |
| `frontend/src/api/client.js` | Shared `/portal` API client, `credentials: include`, timeout, global unauthorized event |
| `frontend/src/api/endpoints.js` | Central portal endpoint wrappers |
| `frontend/src/App.jsx` | Initial `getMe()` session check |
| `frontend/src/hooks/useDataPolling.js` | 15s polling for case, cases, summary, findings, delta, timeline, chain status, IOCs, TODOs, reports |
| `frontend/src/components/auth/LoginCard.jsx` | Supabase login now; legacy setup/reset compatibility branches |
| `frontend/src/components/layout/Header.jsx` | Logout, case activation, case creation |
| `frontend/src/components/overview/CaseBriefCard.jsx` | Case metadata write and refresh |
| `frontend/src/components/findings/FindingsTab.jsx` | Review staging, delta delete, finding audit view |
| `frontend/src/components/layout/CommitDrawer.jsx` | Commit challenge and staged finding commit |
| `frontend/src/components/evidence/EvidenceTab.jsx` | Evidence inventory/status/chain operations |
| `frontend/src/components/todos/TodosTab.jsx` | TODO CRUD |
| `frontend/src/components/reports/ReportsTab.jsx` | Report list/generate/save/open/download |
| `frontend/src/components/settings/SettingsTab.jsx` | Agent/service JWT issuance plus legacy token bridge display |
| `frontend/src/components/backends/BackendsTab.jsx` | Backend registration/reload/service controls |
| Overview, timeline, IOCs, hosts, accounts, nav/status components | Mostly consume the store populated by polling |

## Backend Authority Map

| Backend handler/group | Authority source today |
| --- | --- |
| `PortalSessionMiddleware` | Supabase session-envelope cookie when callbacks are injected; legacy cookie/bearer fallback only behind flags |
| Portal auth callbacks | Gateway-owned Supabase Auth validation, principal resolution, refresh, logout, issuance, revocation |
| Legacy auth endpoints | `/var/lib/sift/passwords`, in-memory challenge pools; disabled in Supabase/disabled-legacy mode |
| Case resolution | `sift_common.resolve_case_dir()`, `SIFT_CASE_DIR`, legacy pointer/config |
| Case create/activate | `gateway.yaml`, env vars, `~/.sift/active_case`, case directories |
| Findings/timeline/delta/TODO/IOC/report reads/writes | Case-local JSON/JSONL files |
| Evidence chain handlers | Evidence files, manifest, ledger, `evidence.json`, optional Solana env/state |
| Response guard portal handlers | Gateway callbacks and process state |
| Agent/service principal lifecycle | Supabase Auth users + app principal tables and scopes |
| Legacy token lifecycle | PR02 `app.mcp_tokens` and `app.mcp_token_scopes`; raw token returned once |
| Backend management | Gateway object + `sift_gateway.rest` logic; `gateway.yaml backends` |
| Gateway config loader | YAML + env interpolation, still pushes case/execute/trust config into process env |

## Turnover Map

| Workflow | Classification | Target owner |
| --- | --- | --- |
| Portal login/session/me/logout | Replaced | PR03A done |
| Local examiner setup/password reset | Legacy-flag only | PR03A/Run 29 done; sunset later |
| Agent/service token lifecycle | Replaced/adapted to JWT principals | PR03A done |
| Gateway REST bearer auth | Supabase JWT-first with explicit bridge | PR03A done |
| FastMCP `/mcp` auth and tool scope | Supabase JWT-first + B-10 list/call auth | PR03A done |
| Case list/create/activate/active case | Implemented by PR03B; D32 says DB wins and stale env/config/pointers are ignored | Done |
| Case metadata | Active-case display/edit authority moved to DB by PR03B | Done for active-case metadata; Batch D for broader investigation data |
| Findings/timeline review staging/commit | Replace file authority with DB review tables | Batch D |
| Audit lookup | Move to DB audit authority | Batch C/D |
| Evidence status/seal/verify/ignore/retire/anchor | Move metadata/status authority while preserving immutable artifacts | Batch C |
| TODO CRUD | Replace `todos.json` with DB TODOs | Batch D |
| IOC/hosts/accounts/timeline views | Replace JSON authority with DB/OpenSearch-derived reads | Batch D/F |
| Reports generate/save/download | Move report metadata/state; decide job-backed generation | Batch D/E |
| Backend registry/service controls | Replace `gateway.yaml backends` with control-plane registry | Batch H |
| Response guard override | Decide API/UI ownership | Open |
| Legacy `/dashboard` static app | Decide remove vs compatibility mount | Open |

## Risks And Gaps

- Active case is the next high-risk dependency. Many portal reads still resolve
  through process/env/file active-case state, and D32 now freezes the target:
  PR03B must make Postgres win and negative-test stale env/config/pointers.
- File-backed authority remains broad: case metadata, findings, timeline, TODOs,
  reports, evidence status, audit, and backend registration are not yet
  control-plane backed.
- Evidence authority is split: inventory reads prefer manifest/ledger state in
  places while verification/summary paths can still consult `evidence.json`.
- Process-local state remains for challenges, pending report drafts, generation
  locks, response-guard override state, and legacy revoked-session state.
- Portal mutations need stronger DB audit linkage in later batches.
- Backend registration and join-code bootstrap still have legacy raw-token/config
  surfaces that must be reconciled with D30 before legacy auth sunset.
- Frontend tests cover stores and many components, but the migration still lacks
  a consolidated React-to-route contract test suite for the final API shapes.

## Open Questions

1. What exact target behavior should `/api/v1/setup/join*` have under D30 when
   raw gateway-token bootstrap authority is sunset?
2. Should response-guard override gain a first-class React UI, remain API-only,
   or be removed from frontend exports?
3. Should Batch C correct `POST /api/evidence/{path}/verify` to use manifest
   authority where `GET /api/evidence` already does?
4. Should report generation become durable-job backed in Batch E, or should
   Batch D only move report metadata/storage first?
5. What is the intended fate of the legacy `/dashboard` mount after `/portal`
   is fully Supabase/session based?

Resolved from the raw inventory: local setup/password reset routes are not
visible/effective in Supabase mode after Run 29; keep them only as an explicit
legacy compatibility surface until sunset.
