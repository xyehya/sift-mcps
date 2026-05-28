# Examiner Portal — Architecture & Data Flow

> **Purpose:** Single source of truth for how the portal works. Read this before adding a new tab, extending a store field, or changing how data flows between components. Updated as of session 12 (2026-05-28).

---

## 1. Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│  React SPA (Vite build → static/v2/)                         │
│  - Mounted at /portal/ on SIFT VM                            │
│  - All API calls go to /portal/api/* (same-origin)           │
│  - Session cookie auto-attached via credentials: 'include'   │
└────────────────────────┬─────────────────────────────────────┘
                         │ fetch (same-origin)
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  Starlette sub-app (case_dashboard/routes.py)                │
│  - 35+ REST endpoints under /portal/api/*                    │
│  - Auth: session cookie OR Bearer token                      │
│  - HMAC challenge-response for privileged ops                │
└────────────────────────┬─────────────────────────────────────┘
                         │ Python imports
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  agentir_core (case_io, evidence_chain, identity)            │
│  Filesystem: /cases/<case_id>/                               │
│    findings.jsonl, timeline.jsonl, CASE.yaml,                │
│    evidence/, evidence-manifest.json, ledger.jsonl           │
└──────────────────────────────────────────────────────────────┘
```

**Host:** `/home/yk/AI/SIFTHACK/sift-mcps/packages/case-dashboard/`  
**Target:** SIFT VM at `192.168.122.81:4508/portal/`  
**Frontend source:** `frontend/src/`  
**Build output:** `src/case_dashboard/static/v2/`  

---

## 2. Component Tree & Layout

```
App.jsx
├── LoginCard (unauthenticated state)
└── AuthedApp (authenticated state)
    ├── Header (brand, case selector, agent pulse, sign-out)
    ├── NavRail (vertical icon rail, 9 tabs + settings)
    ├── main (active tab content)
    │   ├── OverviewTab
    │   ├── FindingsTab (primary workflow — two-pane)
    │   ├── TimelineTab
    │   ├── EvidenceTab
    │   ├── HostsTab
    │   ├── AccountsTab
    │   ├── IocsTab
    │   ├── TodosTab
    │   ├── ReportsTab
    │   └── SettingsTab
    ├── StatusBar (seal dot, HMAC state, staged count, sync age)
    ├── CommitDrawer (slide-in, hold-to-commit)
    ├── CommandPalette (Ctrl+K, cmdk-powered search + actions)
    └── Toaster (floating notifications)
```

**Tab activation:** `activeTab` string in Zustand store drives conditional rendering in `App.jsx`. Only one tab is mounted at a time (unmount-on-switch).

---

## 3. Data Flow

### 3.1 Polling → Store → Components

```
useDataPolling()          Zustand store            Components
─────────────────         ─────────────            ──────────
Every 15 seconds:          ┌──────────┐            OverviewTab reads: summary, findings, reports, delta
  getCase() ──────────────→│activeCase│            FindingsTab reads: findings, delta, findingsFilter,
  getCases() ─────────────→│cases     │              findingsHostFilter, findingsAccountFilter
  getSummary() ───────────→│summary   │            TimelineTab reads: timeline, findings
  getFindings() ──────────→│findings  │            EvidenceTab reads: chainStatus
  getDelta() ─────────────→│delta     │            HostsTab reads: findings (aggregates client-side)
  getTimeline() ──────────→│timeline  │            AccountsTab reads: findings (aggregates client-side)
  getChainStatus() ───────→│chainStatus│           IocsTab reads: iocs
  getIocs() ──────────────→│iocs      │            SettingsTab reads: tokens (local fetch)
  getTodos() ─────────────→│todos     │            ReportsTab reads: reports (local fetch)
  getReports() ───────────→│reports   │            TodosTab reads: todos
                         └──────────┘            StatusBar reads: chainStatus, delta, lastSync
```

**Key behavior:**
- All 10 API calls fire in parallel via `Promise.allSettled` — a single failed call does not block others.
- `setIsLoading(false)` fires after the **first** poll cycle completes. All tabs show skeleton until this flips.
- Each subsequent poll updates the store silently (no re-skeleton).
- **Response shape extraction**: Some endpoints return wrapper objects that must be destructured before storing:
  - `getCases()` returns `{ cases: [...], cases_root, active_case_dir }` → store needs `.cases` array (fixed B-01)
  - `getDelta()` returns `{ items: [...], version, case_id }` → store needs `.items` array
  - `getCase()` returns raw CASE.yaml as JSON (keys: `case_id`, `name`, `title`, `status`, `examiner`, `created`, `created_at`)
  - Component code references `activeCase.case_id`, **not** `activeCase.id`
- `setLastSync(Date.now())` updates the sync timestamp shown in the StatusBar.
- **Chain status field names** (`/api/evidence/chain/status`): `status` ("ok"/"unsealed"), `manifest_version` (number, >0 = sealed), `hmac_verify_needed` (bool), `hmac_last_verified_at`, `hmac_last_verified_by`, `write_protected` (bool, not `write_blocked`). There is no `sealed` or `hmac_verified` field in the response.
- **Finding timestamps**: `timestamp` is often `null`. Use fallback chain `modified_at` → `timestamp` → `event_timestamp`. `modified_at` is the system modification time and the most reliable recency indicator.

### 3.2 Write Path (Delta / Commit)

```
User action (approve/reject/edit)
  → stageAction() in FindingsTab
    → POST /api/delta  (full-replacement: { items: [...] })
      → setDelta(newDelta) in store
        → Sidebar re-renders with staged indicators
        → StatusBar staged count updates

User clicks "↑ COMMIT"
  → CommitDrawer opens (commitDrawerOpen = true)
    → GET /api/commit/challenge
      → PBKDF2-HMAC computed client-side (password never leaves modal)
        → POST /api/commit { challenge_id, response }
          → Server applies deltas, returns counts
            → setDelta([]) clears staged items
            → Next poll refreshes findings with new statuses
```

### 3.3 Read Path (First Load)

```
App mounts → getMe() → session check
  ├── null (checking) → blank screen
  ├── false (unauthed) → LoginCard
  └── true (authed) → AuthedApp mounts
        → useDataPolling() starts
          → isLoading: true → all tabs show skeleton
          → first poll completes → isLoading: false → data renders
```

---

## 4. Store Shape Reference

```js
// Zustand store: frontend/src/store/useStore.js

{
  // Navigation
  activeTab: 'overview',          // current tab id
  setActiveTab: (tab) => {},

  // Auth
  user: null,                     // { examiner, role }
  setUser: (user) => {},

  // Case
  activeCase: null,               // CASE.yaml as JSON (keys: case_id, name, title, status, examiner, created, created_at)
  setActiveCase: (c) => {},
  cases: [],                      // array of case objects [{ id, name, status, active }]
  setCases: (cases) => {},

  // Summary (Overview KPIs)
  summary: null,                  // { findings: { total, by_status }, timeline, evidence, todos }
  setSummary: (summary) => {},

  // Reports (polled every 15s — B-05 resolved)
  reports: [],                    // [{ id, profile, created_at, examiner }] from /api/reports
  setReports: (reports) => {},

  // Findings (primary data — drives 5 tabs)
  findings: [],                   // array of finding objects (spec §3.1)
  setFindings: (findings) => {},
  selectedFindingId: null,        // which finding is selected in FindingsTab
  setSelectedFindingId: (id) => {},
  findingsFilter: 'pending',      // 'pending' | 'approved' | 'rejected' | 'all'
  setFindingsFilter: (f) => {},
  findingsHostFilter: null,       // hostname string or null (set by HostsTab)
  setFindingsHostFilter: (host) => {},
  findingsAccountFilter: null,    // account string, '' for N/A, or null (set by AccountsTab)
  setFindingsAccountFilter: (account) => {},

  // Delta (review staging)
  delta: [],                      // array of delta items (spec §3.4)
  setDelta: (delta) => {},

  // IOCs (polled independently)
  iocs: [],                       // array of IOC objects
  setIocs: (iocs) => {},

  // TODOs (polled independently)
  todos: [],                      // array of TODO objects
  setTodos: (todos) => {},

  // Timeline
  timeline: [],                   // array of timeline events (spec §3.2)
  setTimeline: (timeline) => {},

  // Evidence chain
  chainStatus: null,              // full chain status object
  setChainStatus: (chainStatus) => {},

  // UI state
  isLoading: true,                // true until first poll completes
  setIsLoading: (v) => {},
  lastSync: null,                 // Date.now() of last successful poll
  setLastSync: (ts) => {},
  toasts: [],                     // notification queue
  addToast: (msg, type) => {},    // auto-dismiss 4s
  dismissToast: (id) => {},
  commitDrawerOpen: false,        // CommitDrawer visibility
  setCommitDrawerOpen: (v) => {},
  commandPaletteOpen: false,      // reserved for T-06
  setCommandPaletteOpen: (v) => {},
}
```

---

## 5. Component-to-Store Dependencies

| Component | Reads from store | Writes to store (via setters) |
|---|---|---|
| **App.jsx** | `user`, `activeTab` | `setUser` |
| **useDataPolling** | (none — writes only) | `setActiveCase`, `setCases`, `setSummary`, `setFindings`, `setDelta`, `setTimeline`, `setChainStatus`, `setIocs`, `setTodos`, `setReports`, `setLastSync`, `setIsLoading` |
| **OverviewTab** | `activeCase`, `summary`, `findings`, `reports`, `delta`, `isLoading` | `setActiveTab`, `setFindingsFilter`, `setCommitDrawerOpen`, `setSelectedFindingId` |
| **FindingsTab** | `findings`, `delta`, `selectedFindingId`, `timeline`, `isLoading`, `findingsFilter`, `findingsHostFilter`, `findingsAccountFilter` | `setDelta`, `setSelectedFindingId`, `setFindingsFilter`, `setFindingsHostFilter`, `setFindingsAccountFilter`, `addToast` |
| **TimelineTab** | `timeline`, `findings`, `isLoading` | `setSelectedFindingId`, `setActiveTab` |
| **EvidenceTab** | `chainStatus`, `delta`, `findings`, `isLoading` | `setChainStatus`, `setActiveTab`, `setSelectedFindingId`, `setFindingsFilter`, `addToast` |
| **HostsTab** | `findings`, `isLoading` | `setActiveTab`, `setFindingsHostFilter` |
| **AccountsTab** | `findings`, `isLoading` | `setActiveTab`, `setFindingsAccountFilter` |
| **IocsTab** | `iocs`, `findings`, `isLoading` | `setActiveTab`, `setSelectedFindingId` |
| **TodosTab** | `todos`, `summary`, `isLoading` | `setActiveTab`, `setSelectedFindingId` |
| **ReportsTab** | `reports`, `isLoading` | (local fetch for generate/save/download; list reads from store via polling) |
| **SettingsTab** | `isLoading` | (local fetch — no store writes) |
| **CommitDrawer** | `commitDrawerOpen`, `delta` | `setCommitDrawerOpen`, `setDelta`, `addToast` |
| **CommandPalette** | `commandPaletteOpen`, `findings`, `selectedFindingId`, `delta` | `setCommandPaletteOpen`, `setSelectedFindingId`, `setActiveTab`, `setDelta`, `setCommitDrawerOpen`, `setUser`, `addToast` |
| **StatusBar** | `chainStatus`, `delta`, `lastSync`, `user` | `setCommitDrawerOpen`, `setActiveTab` (seal dot → evidence tab) |
| **Header** | `user`, `activeCase`, `cases`, `delta` | `setActiveCase`, `setCases`, `setFindings`, `setTimeline`, `setDelta`, `setChainStatus`, `setIocs`, `setTodos`, `setReports`, `setSummary`, `setIsLoading` (post-activation data reset) |
| **NavRail** | `activeTab`, `findings`, `delta`, `summary` | `setActiveTab` |

---

## 6. Cross-Tab Navigation Map

This is the critical "edges" diagram — how components trigger navigation to other tabs.

```
OverviewTab
  ├── Click "APPROVED" KPI → setActiveTab('findings') + setFindingsFilter('approved')
  ├── Click "PENDING" KPI  → setActiveTab('findings') + setFindingsFilter('pending')
  ├── Click "STAGED" KPI   → setCommitDrawerOpen(true)
  ├── Click activity row   → setSelectedFindingId(f.id) + setActiveTab('findings')
  └── Click report row     → setActiveTab('reports')

HostsTab
  └── Click host row → setFindingsHostFilter(host) + setActiveTab('findings')

AccountsTab
  └── Click account row → setFindingsAccountFilter(account) + setActiveTab('findings')

IocsTab
  └── Click F-ID link → setSelectedFindingId(fid) + setActiveTab('findings')

TodosTab
  └── Click related finding link → setSelectedFindingId(fid) + setActiveTab('findings')

TimelineTab
  └── Click finding_ref badge → setSelectedFindingId(fid) + setActiveTab('findings')

EvidenceTab
  └── Click referenced_by finding ID → setSelectedFindingId(rid) + setFindingsFilter('all') + setActiveTab('findings')

FindingsTab (internal)
  ├── filtered sidebar → setSelectedFindingId(f.id)  (no tab switch)
  ├── host filter banner ✕ → setFindingsHostFilter(null)
  └── account filter banner ✕ → setFindingsAccountFilter(null)

ReportsTab
  └── Overview reports widget → setActiveTab('reports')

StatusBar
  ├── Click "↑ COMMIT" → setCommitDrawerOpen(true) (only when staged > 0)
  └── Click seal dot → setActiveTab('evidence')
```

**Pattern for adding a new cross-tab navigation:**
1. Source component calls `setActiveTab('findings')` to switch tabs.
2. If filtering, set the relevant filter (`findingsHostFilter`, `findingsAccountFilter`, `findingsFilter`, `selectedFindingId`) **before** the tab switch (order doesn't matter — Zustand batches synchronous updates).
3. FindingsTab reads the filter in its `useMemo` on next render.

---

## 7. API Reference

### 7.1 Client (`api/client.js`)

All requests go through three wrappers:
- `apiFetch(path)` — GET, returns parsed JSON, null on 401, throws on error
- `apiPost(path, body)` — POST with JSON body
- `apiDelete(path)` — DELETE

**Auth:** `credentials: 'include'` sends the `agentir_session` cookie automatically. No manual token management in the frontend.

**Error handling:** 401 → fires `sift:unauthorized` event → `App.jsx` listens and redirects to login. Other errors throw with the response body text.

**Timeout:** 15 seconds per request.

### 7.2 Endpoints (`api/endpoints.js`)

| Category | Endpoint | Method | Used by |
|---|---|---|---|
| Auth | `/api/auth/setup-required` | GET | LoginCard |
| Auth | `/api/auth/setup` | POST | LoginCard |
| Auth | `/api/auth/challenge` | GET | LoginCard |
| Auth | `/api/auth/login` | POST | LoginCard |
| Auth | `/api/auth/me` | GET | App.jsx (session check) |
| Auth | `/api/auth/logout` | POST | Header |
| Cases | `/api/cases` | GET | polling, Header |
| Cases | `/api/case` | GET | polling |
| Cases | `/api/case/create` | POST | Header |
| Cases | `/api/case/activate/challenge` | GET | Header |
| Cases | `/api/case/activate` | POST | Header |
| Data | `/api/findings` | GET | polling → 5 tabs |
| Data | `/api/findings/{id}` | GET | (available, not polled) |
| Data | `/api/timeline` | GET | polling → TimelineTab |
| Data | `/api/evidence` | GET | EvidenceTab |
| Data | `/api/iocs` | GET | polling → IocsTab |
| Data | `/api/todos` | GET | polling → TodosTab |
| Data | `/api/summary` | GET | polling → OverviewTab |
| Data | `/api/audit/{finding_id}` | GET | FindingsTab (lazy) |
| Delta | `/api/delta` | GET | polling → FindingsTab, CommitDrawer |
| Delta | `/api/delta` | POST | FindingsTab (stageAction) |
| Delta | `/api/delta/{id}` | DELETE | FindingsTab (unstage) |
| Delta | `/api/commit/challenge` | GET | CommitDrawer |
| Delta | `/api/commit` | POST | CommitDrawer |
| Evidence | `/api/evidence/{path}/verify` | POST | EvidenceTab |
| Evidence | `/api/evidence/chain/status` | GET | polling → EvidenceTab, StatusBar |
| Evidence | `/api/evidence/chain/rescan` | POST | EvidenceTab |
| Evidence | `/api/evidence/chain/challenge` | GET | EvidenceTab |
| Evidence | `/api/evidence/chain/seal` | POST | EvidenceTab |
| Evidence | `/api/evidence/chain/ignore` | POST | EvidenceTab |
| Evidence | `/api/evidence/chain/retire` | POST | EvidenceTab |
| Evidence | `/api/evidence/chain/verify-hmac` | POST | EvidenceTab |
| Evidence | `/api/evidence/chain/anchor` | POST | EvidenceTab |
| Tokens | `/api/tokens` | GET | SettingsTab |
| Tokens | `/api/tokens` | POST | SettingsTab |
| Tokens | `/api/tokens/{id}` | DELETE | SettingsTab |
| Tokens | `/api/tokens/{id}/rotate` | POST | SettingsTab |
| Reports | `/api/reports` | GET | ReportsTab |
| Reports | `/api/reports/generate` | POST | ReportsTab |
| Reports | `/api/reports/{id}` | GET | ReportsTab |
| Reports | `/api/reports/{id}/download` | GET | ReportsTab |

### 7.3 Data Shapes

**Finding** (full shape — spec §3.1):
```
id, title, body, observation, interpretation,
confidence (HIGH|MEDIUM|LOW|SPECULATIVE), confidence_justification,
status (draft|approved|rejected), verified (bool), content_hash,
type (finding|conclusion|attribution|exclusion),
host, affected_account, event_timestamp, timestamp,
tags[], mitre_ids[], iocs[], related_findings[],
artifacts: [{ source, extraction, content, content_type, audit_id }],
artifact_ref, audit_ids[], examiner_notes[], examining_notes,
examiner_modifications, approved_by, approved_at, rejected_by, rejected_at,
provenance (MCP|HOOK|SHELL|MIXED|NONE), provenance_grade (FULL|PARTIAL),
provenance_warnings[], source_evidence
```

**IOC** (from `/api/iocs`):
```
id, value, type, category, description, status (DRAFT|APPROVED|REJECTED),
confidence (HIGH|MEDIUM|LOW|SPECULATIVE), source_findings[],
sightings: [{ host, finding_id }], mitre_techniques[], tags[],
manually_reviewed, examiner, created_at, modified_at, content_hash,
approved_at, approved_by
```

**TODO** (from `/api/todos`):
```
todo_id, description, status (open|completed),
priority (high|medium|low), assignee, related_findings[],
created_by, examiner, created_at, notes[],
completed_at
```

**Timeline event** (spec §3.2):
```
id, timestamp, type, description, host, account,
finding_refs[], related_findings[], status, verified, source
```

**Summary** (spec §3.3):
```json
{
  "findings": { "total": N, "by_status": { "DRAFT": N, "APPROVED": N, "REJECTED": N } },
  "timeline": { "total": N, "by_status": { ... } },
  "evidence": { "total": N },
  "todos": { "total": N, "open": N }
}
```

**Delta item** (spec §3.4):
```json
{
  "id": "F-001",
  "type": "finding",
  "action": "approve" | "reject" | "edit",
  "content_hash_at_review": "...",
  "modifications": {},
  "rejection_reason": "",
  "note": ""
}
```

---

## 8. Auth & Security Model

| Action | Authority required |
|---|---|
| Read any data | Session cookie (HttpOnly, SameSite=strict, 8h expiry) |
| Stage a delta (approve/reject/edit) | Session cookie, role: examiner |
| Commit deltas | Session + fresh password proof (PBKDF2-HMAC challenge-response) |
| Seal / ignore / retire evidence | Session + fresh password proof |
| Manage agent tokens | Session, role: examiner |
| Activate case | Session + case-specific password proof |

**Password handling (hard requirement):**
- Plaintext password never leaves the modal it was typed in.
- Cleared from React state immediately after the `computeSimpleChallengeResponse` call returns, **before** the network round-trip.
- Password field `autocomplete="off"`, cleared on unmount.

**CSRF posture:** SameSite=strict is the primary mitigation. No `X-CSRF-Token` header is sent or checked (decision recorded in spec §7). State-changing endpoints rely on session cookie + per-action HMAC challenge.

---

## 9. Adding a New Tab

Follow this checklist. Numbers in `(S+N)` refer to sections in this document.

### 9.1 If the tab aggregates existing data (like HostsTab, AccountsTab)

1. **Create component** in `frontend/src/components/<name>/<Name>Tab.jsx`.
2. **Import from store** only what you need — `findings`, `isLoading`, and any setter for cross-tab nav (S5).
3. **Aggregate client-side** in a `useMemo` over `findings`. The `findings` array is always fresh from 15s polling.
4. **Handle loading** by returning skeleton when `isLoading` is true.
5. **Handle empty** with icon + message.
6. **Register in NavRail** — add `{ id, label, icon }` to `NAV_ITEMS` (S2).
7. **Register in App.jsx** — import component, add conditional render (S2).
8. **Add cross-tab nav** — on row click, set the relevant filter + `setActiveTab('findings')` (S6).
9. **If filtering is needed**, add a new filter field to the store (S4), wire it in FindingsTab's `useMemo` filter chain, and add a banner for it (S6).
10. **Build, sync, restart, verify** — see spec §8.4.

### 9.2 If the tab fetches its own data (like IocsTab, TODOsTab)

All of the above, plus:

1. **Add endpoint function** in `api/endpoints.js` if not already present (S7.2).
2. **Add state to store** — `dataName: []` + `setDataName` (S4).
3. **Add to polling hook** — import endpoint, add to `Promise.allSettled` array, add setter call in results block (S3.1).
4. **Read from store** in your component.

### 9.3 Cross-tab navigation convention

When navigating from Tab X to Findings:
- To **filter findings by a value**: `setFindings<Filter>(value); setActiveTab('findings')`
- To **select a specific finding**: `setSelectedFindingId(fid); setActiveTab('findings')`
- To **filter + select**: set filter, then set selected, then switch tab (order is cosmetic — Zustand batches)
- **Clear the filter** when the user dismisses the banner in FindingsTab (`setFindings<Filter>(null)`)

### 9.4 Files to touch (minimum set)

| File | Purpose |
|---|---|
| `frontend/src/components/<name>/<Name>Tab.jsx` | New component |
| `frontend/src/App.jsx` | Import + route |
| `frontend/src/components/layout/NavRail.jsx` | Nav item |
| `frontend/src/store/useStore.js` | State + setters (if new data) |
| `frontend/src/hooks/useDataPolling.js` | Polling (if new data) |
| `frontend/src/api/endpoints.js` | Endpoint function (if new data) |
| `frontend/src/components/findings/FindingsTab.jsx` | Filter logic + banner (if filterable) |

---

## 10. Key Files Reference

| Question | File |
|---|---|
| What does endpoint X return? | `packages/case-dashboard/src/case_dashboard/routes.py` |
| Where is cookie X defined? | `packages/case-dashboard/src/case_dashboard/session_jwt.py` |
| Who can call endpoint X? | `packages/case-dashboard/src/case_dashboard/auth.py` |
| What's the store shape? | `frontend/src/store/useStore.js` |
| What endpoints are wired? | `frontend/src/api/endpoints.js` |
| How does polling work? | `frontend/src/hooks/useDataPolling.js` |
| How does the HTTP client work? | `frontend/src/api/client.js` |
| What evidence chain states exist? | `packages/agentir-core/src/agentir_core/evidence_chain.py` |
| Where are the design tokens? | `frontend/src/index.css` |
| Stable spec (what the portal IS) | `ux-spec.md` |
| Task queue (what's LEFT to build) | `ux-tasks.md` |

---

*Updated 2026-05-28, session 14. Covers state through B-07 resolution. All 7 bugs fixed (B-01 through B-07). Reports polling active. Chain status uses correct API field names. Case activation fixed + post-activation refresh. ActivityFeed clickable with time-range filter. Frontend tests: `cd frontend && npm test` (vitest + jsdom, 80 tests: 20 CommandPalette + 60 SessionChanges). Phase 1 complete (T-07/T-08 on hold). Next: Phase 2 security gate (T-09 through T-12).*
