---
title: Portal — Examiner Dashboard Frontend and Backend
source_commit: eadb92b
generated: 2026-06-27
verified_against: code+tests+config
invariants_checked: 8
status: draft
---

# Portal — Examiner Dashboard Frontend and Backend

## Overview

The Portal is the human operator interface for the SIFT forensic investigation platform. Two-tier architecture:

- **Backend**: Starlette sub-app mounted at `/portal` on the Gateway FastAPI app. Provides REST API routes for case management, evidence chain, findings, reports, backends, and auth. HMAC-SHA256 signed session cookies (`sift_portal_session`) wrapping Supabase access/refresh tokens.
- **Frontend**: React 19.2.6 + Vite 8 + Tailwind CSS v4 + shadcn/ui, dark-first with light theme support. Pre-built SPA served as static files from the backend's `static/` directory.

All logins go through Supabase GoTrue — the sole credential authority. Sensitive actions require Supabase password re-verification (step-up auth).

Package: `case-dashboard` at `packages/case-dashboard/`.

## How it works

1. User authenticates via Supabase GoTrue (email/password) at `POST /portal/api/auth/login`.
2. Backend creates an HMAC-SHA256 signed JSON envelope cookie (`sift_portal_session`) containing `{access_token, refresh_token, expires_at, eiat}`.
3. `PortalSessionMiddleware` extracts cookie, verifies HMAC, resolves via Supabase. If expired, transparently rotates using refresh token. Sets `request.state.principal`, `request.state.examiner`, `request.state.role`.
4. SPA (React) served from `static/` — pre-built by Vite, compiled as single-page app, all API calls to `/portal/api/*`.
5. Sensitive mutations (seal, commit, activate, register backend, metadata edit) gate on `_supabase_reverify` — requires operator's password re-entered through Supabase.

## Reference sections

### `routes.py` — Portal REST API

Backend: `packages/case-dashboard/src/case_dashboard/routes.py` (5730 lines).

**Auth/Session:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/portal/api/auth/me` | Current session principal |
| POST | `/portal/api/auth/login` | Supabase login, sets `sift_portal_session` cookie |
| POST | `/portal/api/auth/logout` | Clear cookie + revoke Supabase session |
| POST | `/portal/api/auth/refresh` | Rotate session cookie |
| POST | `/portal/api/auth/forced-reset` | Complete invited→active status |

**Principal management:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/portal/api/auth/principals` | List agents/services |
| POST | `/portal/api/auth/principals` | Create principal (returns tokens once) |
| DELETE | `/portal/api/auth/principals/{type}/{id}` | Revoke principal |

**Cases:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/portal/api/cases` | List cases |
| GET | `/portal/api/case` | Active case metadata |
| POST | `/portal/api/case/create` | Create case + init evidence chain |
| POST | `/portal/api/case/activate` | Activate case (re-auth gated) |
| POST | `/portal/api/case/metadata` | Set metadata field (re-auth gated) |

**Investigation data:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/portal/api/findings` | List findings |
| GET | `/portal/api/findings/{id}` | Finding detail |
| GET | `/portal/api/timeline` | Timeline events |
| GET | `/portal/api/evidence` | Evidence list with custody/seal status |
| GET | `/portal/api/iocs` | IOCs list |
| GET | `/portal/api/todos` | TODOs list/create/update/delete |
| GET | `/portal/api/audit/{finding_id}` | Finding audit trail |

**Evidence chain (DB authority):**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/portal/api/evidence/chain/status` | Chain status + write-block detection |
| POST | `/portal/api/evidence/chain/seal` | Seal file (re-auth) |
| POST | `/portal/api/evidence/chain/ignore` | Mark ignored |
| POST | `/portal/api/evidence/chain/delete` | Delete file |
| POST | `/portal/api/evidence/chain/retire` | Retire file |
| POST | `/portal/api/evidence/chain/replace/begin` | Authorize durable Replace/Reacquire and block the gate |
| POST | `/portal/api/evidence/chain/restore/begin` | Authorize exact Restore and block the gate |
| POST | `/portal/api/evidence/chain/recovery/complete` | Fresh re-auth, verify bytes/posture, and atomically finalize recovery |
| GET | `/portal/api/evidence/objects/{object_id}/history` | Path-free object version/event history |
| POST | `/portal/api/evidence/chain/full-verify` | **Full Verify Evidence** against Postgres custody authority |
| POST | `/portal/api/evidence/chain/anchor` | Anchor on Solana |
| GET | `/portal/api/evidence/{path}/verify` | Single file verify |

**Review workflow:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/portal/api/delta` | Pending reviews |
| POST | `/portal/api/delta` | Stage decisions |
| POST | `/portal/api/commit` | Apply delta (re-auth) |

**Backend management (re-auth on all mutations):**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/portal/api/backends` | List registered backends |
| POST | `/portal/api/backends` | Register backend |
| DELETE | `/portal/api/backends` | Unregister backend |
| POST | `/{name}/enabled` | Toggle enabled |
| POST | `/portal/api/backends/reload` | Reload config |

**Response guard:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/portal/api/response-guard/status` | Guard status |
| POST | `/portal/api/response-guard/override` | Enable guard (re-auth, 10min TTL) |
| POST | `/portal/api/response-guard/override/cancel` | Cancel override |

**Reports:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/portal/api/reports` | List reports |
| POST | `/portal/api/reports` | Generate report |
| GET | `/portal/api/reports/{id}` | Report detail |
| POST | `/portal/api/reports/{id}/save` | Save report |
| GET | `/portal/api/reports/{id}/download` | Download report |

**Other:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/portal/api/portal/state` | DB seal/custody/add-on/report eligibility |
| GET | `/portal/api/agent/activity` | Recent audit events |
| GET | `/portal/api/health` | Proxies Gateway `/health` |
| GET | `/portal/api/jobs/{job_id}` | Job status |

### `auth.py` — Portal Session Middleware

File: `packages/case-dashboard/src/case_dashboard/auth.py` (189 lines).

**`class PortalSessionMiddleware`** (line 56): Starlette `BaseHTTPMiddleware` that implements two-layer auth on every `/portal` request:

1. **Credential authority: Supabase GoTrue**. All logins through Supabase. Local PBKDF2 login fallback removed (B-MVP-011 — confirmed in `routes.py:198-199,537,3595-3855` and `test_auth_endpoints.py:3`).
2. **Session envelope cookie**: `sift_portal_session`. HMAC-SHA256 signed JSON wrapping `{access_token, refresh_token, expires_at}`. No external JWT library — stdlib `hmac` + `hashlib.sha256` (`session_jwt.py:3-5`). HttpOnly, Secure, SameSite=Strict, path=/portal (`session_jwt.py:21-23`).

Flow: extract `sift_portal_session` → verify HMAC → resolve via Supabase → if expired and refresh token present, rotate → set `request.state.principal`, `request.state.examiner`, `request.state.role`.

**Role mapping** (`_examiner_role_from_principal`, `auth.py:38`):
- `operator` principal_type → examiner role
- `readonly` system_role → readonly role
- All others (lead/owner/admin) → examiner role
- Agent/service → denied on operator routes (no examiner/role set)

**Sensitive-action re-auth** (`_supabase_reverify`, `routes.py:678-707`): Password re-entry via Supabase GoTrue. Email sourced from **authenticated session** (`_session_operator_email`), never from request body. Fail-closed: Supabase outage → 503; wrong password → 401; connection error → 503.

### `session_jwt.py` — Session Envelope Cookie

File: `packages/case-dashboard/src/case_dashboard/session_jwt.py` (221 lines).

HMAC-SHA256 signed JSON envelope. Cookie name: `sift_portal_session`. Path: `/portal`. SameSite: strict.

Envelope payload: `{access_token, refresh_token, expires_at, sub, fp, eiat}`. `eiat` (epoch issued at) is preserved across rotations — the absolute 12-hour ceiling is enforced against it (`session_jwt.py:33-38`; `ABSOLUTE_ENVELOPE_LIFETIME_SECONDS = 12 * 60 * 60`). Missing/invalid eiat = fail closed (expired).

`generate_session_envelope`: On first login, eiat = `int(time.time())`. On rotation, caller passes prior envelope's `eiat`. Returns HMAC-signed base64 cookie value.

`verify_session_envelope`: Verifies HMAC, decodes JSON, checks eiat absolute ceiling. Returns payload dict on success.

### `backends_routes.py` — Backend Management

File: `packages/case-dashboard/src/case_dashboard/backends_routes.py` (414 lines).

All mutation endpoints are guarded by `_require_examiner_role` (`backends_routes.py:51`) + `_verify_origin` (CSRF-style same-origin, `backends_routes.py:87`) + `_supabase_reverify` (lazily imported from `routes.py`).

Operations: get list, register (with validate step), unregister, toggle enabled, reload config.

### `file_io.py` — File Operations

File: `packages/case-dashboard/src/case_dashboard/file_io.py` (67 lines).

Evidence helpers support Portal seal, disposition, verification, and durable
Replace/Reacquire or exact Restore. Standalone Unseal and one-shot Reacquire
routes are removed; filesystem mutation occurs only inside a durable operation.

### `static/` — Frontend Build Output

Pre-built SPA compiled by Vite. Served by Starlette `StaticFiles`. Contains compiled JS bundles, CSS, `.woff2` fonts (`@fontsource/inter`, `jetbrains-mono`, `space-grotesk`), images.

### Frontend (`packages/case-dashboard/frontend/`)

**Stack** (from `package.json`):
- React 19.2.6 + React DOM 19.2.6
- Vite 8.0.16 + `@vitejs/plugin-react` 6.0.2
- Tailwind CSS v4.3.1 + `@tailwindcss/vite` 4.3.1
- shadcn/ui via `radix-ui` 1.6.0 + `class-variance-authority` 0.7.1 + `clsx` 2.1.1 + `tailwind-merge` 3.6.0
- `zustand` 5.0.13 (state management)
- `framer-motion` 12.40.0 (animations)
- `recharts` 3.8.1 (charts)
- `sonner` 2.0.7 (toasts)
- `date-fns` 4.3.0 (date formatting)
- `lucide-react` 1.21.0 (icons)
- `cmdk` 1.1.1 (command palette)
- Fonts: Inter (body), JetBrains Mono (code), Space Grotesk (headings)
- Node >=24.13.1, npm >=11.8.0

**Directory structure** (`frontend/src/`):
```
api/            client.js + endpoints.js (106 API bindings)
assets/         Static assets
components/     16 groups: accounts, auth, backends, charts, common, evidence,
                findings, hosts, iocs, layout, overview, reports, settings,
                timeline, todos, ui
hooks/          7 hooks: useDataPolling, useDeltaRefetch, useHashRoute,
                useHotkeys, usePolling, useTheme, useToastBridge
lib/            11 modules: agent-derivations, agent-selectors, agent-state,
                auth-context, auth.jsx, chain-status, motion, nav, theme-context,
                theme.jsx, utils
store/          useStore.js (single Zustand store with 5 slices)
styles/         tokens.css + globals.css (Tailwind @theme)
test/           EvidenceRecovery.test.jsx + useStore.interface.test.js
utils/          Utility modules
App.jsx         Main app shell
main.jsx        Entry point
```

**Navigation** (11 destinations in 3 groups, from `lib/nav.js`):
- **Command**: Overview (with blocked-actions badge)
- **Investigation**: Findings, Timeline, Evidence, Hosts, Accounts
- **Operations**: IOCs, TODOs, Backends, Reports, Settings

**Store** (`store/useStore.js`, 119 lines): Single Zustand store with 5 slice factories merged into one flat store:
1. `createNavigationSlice` — activeTab, commitDrawerOpen, commandPaletteOpen
2. `createSessionSlice` — user, activeCase
3. `createDataSlice` — cases, findings, timeline, evidence, iocs, todos, reports... (all data)
4. `createUiSlice` — toasts, isLoading, lastSync, filters
5. (merged into the above)

Components must use `useStoreSlice()` with `useShallow` — never `useStore()` directly.

**Design System** (from `tokens.css` and `frontend/AGENTS.md`):
- Dark-first, light via `.dark` class removal on `<html>`.
- 3-layer color tokens: primitives (`--bg-void`, `--text-bright`, `--crimson`, etc.) → shadcn (`--background`, `--primary`, etc.) → forensic (`--sev-high/med/low`, `--status-approved/pending/rejected/staged`, `--grade-full/partial/none`, `--chart-1/2/3/4/5`).
- Severity is High/Med/Low only — `--sev-high: var(--crimson)`, `--sev-med: var(--amber)`, `--sev-low: var(--steel)` (`tokens.css:93-95,180-182`). Old `--sev-spec`/violet tier dropped.
- `var(--token)` or Tailwind token utilities only — no raw hex.
- God component limit: 400 lines/file.

**Test contracts:**
- `src/test/EvidenceRecovery.test.jsx` — durable recovery and history behavior
- `src/test/useStore.interface.test.js` — frozen top-level store keys

## Invariants

1. **Supabase is sole credential authority**: Local PBKDF2 login/challenge/reset fallback removed (B-MVP-011, `routes.py:198-199,537,3595-3855`; `test_auth_endpoints.py:3,91,120`; `test_pr03_supabase_portal_auth.py:269`). Session middleware fails closed on Supabase outage (`auth.py`).

2. **Session cookie max lifetime 12 hours**: `ABSOLUTE_ENVELOPE_LIFETIME_SECONDS = 12 * 60 * 60` (`session_jwt.py:38`). `eiat` field preserved across rotations enforces absolute ceiling (`session_jwt.py:164-173,213-217`; `auth.py:156-157`; `routes.py:3786-3787`).

3. **Re-auth email from session only**: `_supabase_reverify` gets email from `_session_operator_email(request)` — authenticated session identity, never `body['email']` (`routes.py:661,686-687,722`).

4. **Agent/service principals denied portal operator routes**: `_examiner_role_from_principal` only sets examiner/role for `operator` principal_type. Agent/service get `None/None` — blocked upstream (`auth.py:38-56`).

5. **Sensitive actions require password re-verification**: 15+ call sites of `_supabase_reverify` in `routes.py` (seal, commit, activate, metadata, backend register/unregister/toggle, report inclusion/export, response guard override) + 7 in `backends_routes.py`. Supabase fail-closed: outage → 503, bad password → 401 (`routes.py:695-707`).

6. **No raw token material in JSON responses or logs**: HMAC envelope verified with stdlib `hmac` + `hashlib.sha256` (`session_jwt.py:3-5`). Token material only in the HttpOnly `sift_portal_session` cookie.

7. **Frontend store keys frozen**: `useStore.interface.test.js` locks 27 state keys + 27 action keys. No addition/deletion without updating test + operator sign-off (`frontend/AGENTS.md §11`, `useStore.js:7-9`).

8. **CSP enforced at Gateway level**: Portal CSP is set in `sift_gateway/server.py:SecureHeadersMiddleware` (lines 61-87), which wraps the portal sub-app. The middleware comment explicitly states: "Future portal-CSP edits MUST land here (routes.py is inert for /portal)."

## Gotchas & Edge Cases

> [!warning] The portal CSP is NOT set in `case_dashboard/routes.py:SecurityHeadersMiddleware` — it is set in Gateway's `SecureHeadersMiddleware` which WRAPS the portal sub-app (`sift_gateway/server.py:61-87`). The middleware comment at line 64-67 explicitly states: "Future portal-CSP edits MUST land here (routes.py is inert for /portal)."

> [!important] Session refresh: When the access token expires but a refresh token exists, `PortalSessionMiddleware` transparently rotates the cookie via Supabase's GoTrue refresh. The 12-hour `eiat` absolute ceiling is preserved across rotations (`auth.py:156-157`; `session_jwt.py:164-173`).

> [!note] The frontend uses a single Zustand store with 5 slices. Components must use `useStoreSlice()` with `useShallow` — never `useStore()` directly (`frontend/AGENTS.md §3`; `useStore.js:1-2`).

> [!warning] `useStore.interface.test.js` remains byte-identical without explicit
> operator approval. `EvidenceRecovery.test.jsx` must remain green for all custody changes.

## Related

- [Gateway doc](./01%20-%20Gateway.md) — portal is mounted as Starlette sub-app; CSP set in Gateway `SecureHeadersMiddleware`
- [Control Plane doc](./03%20-%20Shared%20Contracts.md) — Supabase schema for `operator_profiles`, `cases`, `active_case_state`, `evidence_objects`
- [Core Tools doc](./02%20-%20Core%20Tools.md) — evidence chain operations called from portal routes

## Key files

| File | Description |
|------|-------------|
| `routes.py` | All portal REST endpoints (5730 lines) |
| `auth.py` | `PortalSessionMiddleware`, role mapping, re-auth (189 lines) |
| `session_jwt.py` | HMAC-SHA256 signed session cookie (221 lines) |
| `backends_routes.py` | Backend management routes (414 lines) |
| `file_io.py` | Evidence file operations (67 lines) |
| `static/` | Frontend SPA build output |
| `frontend/src/App.jsx` | Main app shell |
| `frontend/src/store/useStore.js` | Zustand store (119 lines, 5 slices) |
| `frontend/src/api/endpoints.js` | 106 API bindings |
| `frontend/src/lib/nav.js` | Navigation structure (11 destinations) |
| `frontend/src/styles/tokens.css` | Design tokens, 3-layer color system (198 lines) |
| `frontend/package.json` | Dependencies and scripts |

## Reconciliation log

None — independently confirmed against code.
