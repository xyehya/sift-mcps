# Examiner Portal — Specification

> **Stable ground truth.** This document defines what the portal IS. The tasks file (`ux-tasks.md`) tracks what's LEFT to build. Update this only when the system itself changes — features added, contracts shifted, design rules revised. Every task in `ux-tasks.md` cites a section here.

**Project:** `packages/case-dashboard/`
**Stack:** Vite + React (SPA) on Starlette sub-app
**Mount path:** `/portal/`
**Backend:** `packages/case-dashboard/src/case_dashboard/routes.py`
**Frontend source:** `packages/case-dashboard/frontend/src/`
**Build output:** `packages/case-dashboard/src/case_dashboard/static/v2/`
**Live test target:** `https://192.168.122.81:4508/portal/` (SIFT VM)

---

## 1. Mission & Operator Workflow

A digital-forensics examiner uses this portal to oversee an AI agent (Hermes) investigating a case on a SIFT VM. The agent records findings via MCP tools; the operator reviews each finding, edits or rejects it, approves the set with a password-signed HMAC challenge, and ships a sealed report. Every destructive or sealing action requires a fresh password proof — no ambient authority.

**Canonical operator loop:**
1. Log in → activate a case
2. Watch findings arrive (15s polling)
3. Review each finding: read evidence, edit fields, approve / reject / note
4. Inspect timeline, IOCs, hosts, accounts for context
5. Commit staged reviews (HMAC challenge with password)
6. Verify evidence chain integrity, seal manifest, anchor on Solana
7. Generate report from approved findings, export

---

## 2. Architecture & Trust Boundaries

```
┌──────────────────────────────────────────────────────────────┐
│  React SPA (frontend/src/)                                   │
│  - Polls /portal/api/* every 15s                             │
│  - Computes PBKDF2-HMAC challenge responses client-side      │
│  - Session cookie auto-attached (HttpOnly, examiner cannot   │
│    read it; fetch sends it on same-origin)                   │
└────────────────────────┬─────────────────────────────────────┘
                         │ fetch credentials: 'include'
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  Starlette routes (case_dashboard/routes.py)                 │
│  - Auth middleware: session cookie OR Bearer token           │
│  - 35 routes under /portal/api/*                             │
│  - Privileged ops require additional challenge-response      │
└────────────────────────┬─────────────────────────────────────┘
                         │ Python imports
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  agentir_core (case_io, evidence_chain, identity)            │
│  Filesystem under /cases/<case_id>/:                         │
│    findings.jsonl, timeline.jsonl, CASE.yaml,                │
│    evidence/, evidence-manifest.json, ledger.jsonl           │
└──────────────────────────────────────────────────────────────┘
```

### Trust model

| Action | Authority required |
|---|---|
| Read any data (findings, timeline, evidence list, etc.) | Session cookie OR Bearer (role: examiner OR readonly) |
| Stage a delta (approve/reject/edit) | Session cookie, role: examiner |
| Commit deltas | Session + fresh password proof (commit challenge) |
| Seal / ignore / retire evidence | Session + fresh password proof (chain challenge) |
| Manage agent tokens | Session, role: examiner |
| Activate case | Session + case-specific password proof |

### Session cookie (verified against `session_jwt.py`)

| Property | Value |
|---|---|
| Cookie name | `agentir_session` |
| Path | `/portal` |
| SameSite | `strict` |
| HttpOnly | yes |
| Lifetime | 8h (28800s) |
| JWT alg | HS256 |
| JWT claims | `sub` (examiner), `role` (`examiner` / `readonly`), `iat`, `exp`, `jti` |

### Bearer auth (agent tokens, not examiner sessions)

```
Authorization: Bearer agentir_svc_<hex>
```
Used by Hermes agent → MCP gateway. The portal's token-management UI mints/rotates/revokes these.

---

## 3. Frozen API Contract

All paths relative to `/portal`. Verified against `routes.py` (audit 2026-05-28). Where this spec disagrees with code, **code wins** — update this section.

### Auth
| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/auth/setup-required` | — | `{ required: bool }` |
| POST | `/api/auth/setup` | `{ examiner, password }` | `{ ok, examiner }` |
| GET | `/api/auth/challenge?examiner=…` | — | `{ challenge_id, nonce, salt, iterations, hash_algorithm }` |
| POST | `/api/auth/login` | `{ examiner, challenge_id, response }` | `{ access_token, examiner }` + cookie |
| POST | `/api/auth/reset-password` | `{ examiner, password, old_password }` | `{ ok }` |
| POST | `/api/auth/logout` | — | `{ ok }` |
| GET | `/api/auth/me` | — | `{ examiner, role }` |

### Cases
| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/cases` | — | `[{ id, name, status, created_at, … }]` |
| GET | `/api/case` | — | CASE.yaml content as JSON |
| POST | `/api/case/create` | `{ case_id, examiner, password }` | `{ created, case_id }` |
| GET | `/api/case/activate/challenge?case_id=…` | — | `{ challenge_id, nonce, salt, iterations }` |
| POST | `/api/case/activate` | `{ case_id, challenge_id, response }` | `{ activated, case_id }` |

### Findings, Timeline, Audit, Summary
| Method | Path | Notes |
|---|---|---|
| GET | `/api/findings` | Returns full array of finding objects (see §3.1 shape) |
| GET | `/api/findings/{id}` | Single finding |
| GET | `/api/timeline` | Array of timeline events (see §3.2) |
| GET | `/api/audit/{finding_id}` | Array of audit entries for a finding |
| GET | `/api/summary` | See §3.3 — shape verified, gotcha-prone |

### Delta (review staging) — **read these notes carefully**
| Method | Path | Notes |
|---|---|---|
| GET | `/api/delta` | Returns **full object** `{ version, case_id, items: [...] }`. Extract `.items`. If file missing, server returns `{ items: [] }`. |
| POST | `/api/delta` | **Full-replacement**, NOT per-item. Body: `{ items: [...], case_id? }`. Server writes atomically. |
| DELETE | `/api/delta/{id}` | `id` is the **finding's own id** (e.g. `F-001`), not a delta UUID. |
| GET | `/api/commit/challenge` | `{ challenge_id, nonce, salt, iterations }` |
| POST | `/api/commit` | `{ challenge_id, response }` → `{ approved_count, rejected_count, edited_count, … }` |

### Evidence & Chain
| Method | Path | Notes |
|---|---|---|
| GET | `/api/evidence` | `[{ path, sha256, registered, referenced_by: [finding_ids], … }]` |
| POST | `/api/evidence/{path}/verify` | Recomputes SHA-256, returns `{ path, computed_sha256, stored_sha256, status }` |
| GET | `/api/evidence/chain/status` | `{ status, issues, manifest_version, unregistered, modified, write_protected, hmac_last_verified_at, anchor: {…}, … }` |
| POST | `/api/evidence/chain/rescan` | Same shape as GET status; invalidates cache |
| GET | `/api/evidence/chain/challenge` | Challenge for seal/ignore/retire/verify-hmac |
| POST | `/api/evidence/chain/seal` | `{ challenge_id, response, file_specs: [{ path, source?, description? }] }` |
| POST | `/api/evidence/chain/ignore` | `{ challenge_id, response, path, reason }` |
| POST | `/api/evidence/chain/retire` | `{ challenge_id, response, path, reason }` |
| POST | `/api/evidence/chain/verify-hmac` | `{ challenge_id, response }` → `{ ok, verified, failed, verified_at, verified_by }` |
| POST | `/api/evidence/chain/anchor` | — → Solana anchor result |

### IOCs, TODOs
| Method | Path | Response |
|---|---|---|
| GET | `/api/iocs` | `[{ id, value, type, status, … }]` |
| GET | `/api/todos` | `[{ id, status, description, … }]` |

### Agent Tokens
| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/tokens` | — | `[{ token_id, examiner, created_at, expires_at, revoked_at }]` |
| POST | `/api/tokens` | `{ examiner, expires_in_days?, description? }` | `{ token_id, token, expires_at }` (token shown once) |
| DELETE | `/api/tokens/{id}` | — | `{ revoked }` |
| POST | `/api/tokens/{id}/rotate` | — | `{ token_id, token, expires_at }` |

### Response Guard (in-scope, currently unused by UI)
| Method | Path |
|---|---|
| GET | `/api/response-guard/status` |
| POST | `/api/response-guard/override` |
| POST | `/api/response-guard/override/cancel` |

### Reports — **planned, not yet implemented in routes.py**
| Method | Path | Notes |
|---|---|---|
| GET | `/api/reports` | List generated+saved reports for active case (id, profile, created_at, examiner) |
| POST | `/api/reports/generate` | `{ profile, finding_ids?, start_date?, end_date? }` → wraps `report_mcp.generate_report` (active case from session). Returns `{ id, profile, report_data, sections, guidance }` |
| POST | `/api/reports/{id}/save` | Wraps `report_mcp.save_report` — persists to case dir |
| GET | `/api/reports/{id}` | Returns saved report content + metadata |
| GET | `/api/reports/{id}/download` | Stream as markdown |

`generate_report` profiles: `full`, `executive`, `timeline`, `ioc`, `findings`, `status` (call `list_profiles` for descriptions). Tool returns a structured dict, not a rendered file — the route is responsible for serialization to markdown on download.

### 3.1 Finding shape (verified fields)
```
id, title, body, observation, interpretation,
confidence ("HIGH"|"MEDIUM"|"LOW"|"SPECULATIVE"),
confidence_justification,
status ("draft"|"approved"|"rejected"),
verified (bool), content_hash, content_hash_at_review (delta only),
type ("finding"|"conclusion"|"attribution"|"exclusion"),
host, affected_account, event_timestamp, timestamp,
tags[], mitre_ids[], iocs[], related_findings[],
artifacts: [{ source, extraction, content, content_type, audit_id }],
artifact_ref, audit_ids[],
examiner_notes[], examining_notes, examiner_modifications,
approved_by, approved_at, rejected_by, rejected_at,
provenance ("MCP"|"HOOK"|"SHELL"|"MIXED"|"NONE"),
provenance_grade ("FULL"|"PARTIAL"),
provenance_warnings[],
source_evidence
```

### 3.2 Timeline event shape
```
id, timestamp, type ("auth"|"execution"|"process"|"file"|"network"|
                    "persistence"|"registry"|"lateral"|"other"),
description, host, account,
finding_refs[], related_findings[],
status ("approved"|"rejected"|"draft"),
verified, source, auto_created_from
```

### 3.3 Summary shape (verified)
```json
{
  "findings": { "total": N, "by_status": { "DRAFT": N, "APPROVED": N, "REJECTED": N, … } },
  "timeline": { "total": N, "by_status": { … } },
  "evidence": { "total": N },
  "todos":    { "total": N, "open": N }
}
```
No top-level `stats` or `coverage` keys.

### 3.4 Delta item shape — correct construction
```js
{
  id: findingId,                          // finding's own id, e.g. "F-001"
  type: finding.type ?? 'finding',        // finding type, NOT action type
  action: 'approve' | 'reject' | 'edit',
  content_hash_at_review: finding.content_hash ?? '',
  modifications: {},                      // for edit; field → new value
  rejection_reason: '',                   // for reject
  note: '',
}
```
Editable modification fields: `title, observation, interpretation, confidence, confidence_justification, mitre_ids, iocs, context, timestamp, description, source, tags`.

---

## 4. Feature Inventory

Per-tab feature truth. Status is verified against current code (audit 2026-05-28). Update on each session.

Legend: ☑ done · ◐ partial · ☐ missing · ✕ explicitly dropped

### Login / Setup
| Feature | Status | Component |
|---|---|---|
| First-run setup form | ☑ | `auth/LoginCard` |
| Challenge-response login (PBKDF2-HMAC) | ☑ | `auth/LoginCard`, `api/crypto.js` |
| Session refresh on mount via `/api/auth/me` | ☑ | `App.jsx` |
| Reset-password flow | ☐ | — |
| Focus trap on login form | ☐ | — (SEC) |

### Header / Case Selector / Status Bar
| Feature | Status | Component |
|---|---|---|
| Case selector dropdown + create | ☑ | `layout/Header` |
| Case activation modal (HMAC) | ☑ | `layout/Header` |
| Agent activity pulse indicator | ☑ | `layout/Header` |
| Examiner + role chip | ☑ | `layout/Header` |
| Sign-out button (labelled, not `⎋`) | ☑ | `layout/Header` |
| Status bar: seal dot · HMAC state · staged count · sync age | ☑ | `layout/StatusBar` |
| Status bar click → CommitDrawer (only when staged>0) | ☑ | `layout/StatusBar` |

### Overview Tab
| Feature | Status | Component |
|---|---|---|
| KPI grid (total / approved / pending / staged) | ☑ | `overview/OverviewTab` |
| KPI cards clickable → Findings filter | ☑ | `overview/OverviewTab` |
| Severity distribution bar | ☑ | `overview/OverviewTab` |
| Activity feed (8 recent findings) | ☑ | `overview/OverviewTab` |
| MITRE tag cloud | ☑ | `overview/OverviewTab` |
| Evidence integrity widget (seal dot + write-block) | ☑ | `overview/OverviewTab` |
| Review velocity sparkline (24h) | ☐ | — |

### Findings Tab (primary workflow)
| Feature | Status | Component |
|---|---|---|
| Sidebar: search, filter tabs, confidence left-border, staged dashed-border | ☑ | `findings/FindingsTab` |
| Detail: title, body, observation, interpretation, confidence, confidence_justification | ☑ | `findings/FindingsTab` |
| Detail: host, account, event timestamp, provenance grade, provenance warnings | ☑ | `findings/FindingsTab` |
| Detail: tags, mitre_ids, iocs, related_findings | ☑ | `findings/FindingsTab` |
| Detail: evidence accordion (source, extraction, content, audit_id) | ☑ | `findings/FindingsTab` |
| Detail: timeline context ±2h | ☑ | `findings/FindingsTab` |
| Detail: inline edit pencils on editable fields (stage as delta `edit`) | ☑ | `findings/FindingsTab` |
| Detail: modification history (strikethrough original + new value) | ☑ | `findings/FindingsTab` |
| Action bar: Approve / Reject / Undo (Undo only when staged) | ☑ | `findings/FindingsTab` |
| Action bar: reject reason templates (FP, dup, insufficient ev, freeform) | ☐ | (port from v2) |
| Audit trail panel (`GET /api/audit/{id}`) inline | ◐ | `findings/FindingsTab` (Zone 2 only) |
| Batch multi-select + toolbar (Approve All / Reject All) | ☑ | `findings/FindingsTab` |
| Keyboard: j/k navigate, a approve, r reject, e edit, s undo, Shift+C commit | ☐ | — |

### Timeline Tab
| Feature | Status | Component |
|---|---|---|
| Date+host separators, type color dots, type/host/search filters | ☑ | `timeline/TimelineTab` |
| Clickable finding_refs styled as inline links | ☑ | `timeline/TimelineTab` |
| Gap banners (hairline pills, not full-width blocks) | ☑ | `timeline/TimelineTab` |
| Expanded row: full event meta + editable description | ☐ | (port from v2) |
| Batch include/exclude toolbar | ☐ | — |
| First/last event scroll anchors | ☐ | — |

### Evidence Tab
| Feature | Status | Component |
|---|---|---|
| Chain status widget (sealed / unsealed / write-protected) | ☑ | `evidence/EvidenceTab` |
| HMAC verify with password modal | ☑ | `evidence/EvidenceTab` |
| Solana anchor status + manual trigger | ☑ | `evidence/EvidenceTab` |
| Unregistered files: seal manifest with notes | ☑ | `evidence/EvidenceTab` |
| Custody violations: retire missing/modified | ☑ | `evidence/EvidenceTab` |
| Registered evidence table: sortable, verify per file, referenced_by links | ☑ | `evidence/EvidenceTab` |
| Ignore file (HMAC) | ☑ | `evidence/EvidenceTab` |

### Hosts Tab
| Feature | Status | Component |
|---|---|---|
| Aggregate findings by host: name, finding count, accounts, best confidence, time range | ☑ | `hosts/HostsTab.jsx` (new) |
| Click row → switch to Findings filtered by host | ☑ | `findings/FindingsTab` |

### Accounts Tab
| Feature | Status | Component |
|---|---|---|
| Aggregate findings by account: account, count, hosts, confidence, time range | ☑ | `accounts/AccountsTab.jsx` (new) |
| Click row → switch to Findings filtered by account | ☑ | `FindingsTab` (banner + filter) |
| N/A badge for empty/unknown affected_account | ☑ | `accounts/AccountsTab.jsx` |

### IOCs Tab
| Feature | Status | Component |
|---|---|---|
| Table: value (monospace + copy), type, category, confidence, hosts, source findings, status | ☑ | `iocs/IocsTab.jsx` |
| Filters: category, status (DRAFT/APPROVED/REJECTED/ALL), search | ☑ | `iocs/IocsTab.jsx` |
| Expandable rows: MITRE techniques, tags, ID footer | ☑ | `iocs/IocsTab.jsx` |
| Click source-finding link → switch to Findings, select that finding | ☑ | `iocs/IocsTab.jsx` |

### TODOs Tab
| Feature | Status | Component |
|---|---|---|
| Table: id, title, description, priority, examiner, status, related findings, created_at | ☑ | `todos/TodosTab.jsx` |
| Filters: priority, status | ☑ | `todos/TodosTab.jsx` |
| Default sort: priority desc → created_at asc | ☑ | `todos/TodosTab.jsx` |
| NavRail badge: open TODOs count | ☑ | `layout/NavRail` |
| Priority shape-disambiguated badge (▲ high, ◆ medium, ● low) | ☑ | `todos/TodosTab.jsx` |

### Reports Tab (planned — backend + UI)
| Feature | Status | Component |
|---|---|---|
| Backend: `GET /api/reports`, `POST /api/reports/generate`, `GET /api/reports/{id}`, `GET /api/reports/{id}/download` | ☑ | `routes.py` |
| UI: list reports, profile selector, generate button, preview pane | ☑ | `reports/ReportsTab.jsx` (new) |
| NavRail icon + badge | ☑ | `layout/NavRail` |

### Settings Tab
| Feature | Status | Component |
|---|---|---|
| Token management: create form (agent_id, label, expiry) | ☑ | `settings/SettingsTab` |
| Token list table: agent_id, label, expires_at, rotate, revoke | ☑ | `settings/SettingsTab` |
| Copy-once token display banner | ☑ | `settings/SettingsTab` |
| Confirmation dialogs for rotate/revoke | ☑ | `settings/SettingsTab` |

### Commit Drawer
| Feature | Status | Component |
|---|---|---|
| Right-side slide-in drawer | ☑ | `layout/CommitDrawer` |
| Staged delta list with per-item undo | ☑ | `layout/CommitDrawer` |
| HMAC password input (PBKDF2 challenge-response) | ☑ | `layout/CommitDrawer` |
| 3-second hold-to-commit (with onBlur/onTouchCancel) | ☑ | `layout/CommitDrawer` |
| Success seal animation | ☑ | `layout/CommitDrawer` |
| Password cleared from state immediately after crypto op | ☑ | `layout/CommitDrawer` |
| Focus trap on drawer | ☐ | (SEC) |

### Cross-cutting
| Feature | Status | Component |
|---|---|---|
| 15s data polling with `Promise.allSettled` | ☑ | `hooks/useDataPolling` |
| Toast system | ☑ | `common/Toaster` |
| Skeleton loading states with `isLoading` flag | ☑ | `common/Skeleton`, `store/useStore` |
| Command palette (Ctrl+K) | ☑ | `layout/CommandPalette.jsx` |
| Empty states with icon + action hint | ☐ | per-tab |
| Error states with retry | ☐ | per-tab |
| Theme toggle (dark/light) | ✕ deferred | rationale: single-operator forensic tool |
| Response-guard UI | ✕ deferred | rationale: backend-only enforcement is enough |

---

## 5. Design System

### Aesthetic — "Editorial DFIR C2"
Mission-critical security console: dense data, sharp grid alignment, color encodes meaning, animations only on state change. No idle sparkle.

### Tokens
CSS variables in `src/index.css`. Tailwind extends colors with the same tokens.

| Token | Hex | Role |
|---|---|---|
| `--bg-base`, `--bg-surface`, `--bg-raise` | dark slate stack | Backgrounds |
| `--border`, `--border-faint` | hairline | Dividers, edges |
| `--text-bright`, `--text-primary`, `--text-muted`, `--text-ghost` | descending contrast | Type |
| `--jade` | green | Workflow: approved/sealed/success · Content: persistence events |
| `--crimson` | red | Workflow: rejected/destructive · Content: HIGH severity · execution events |
| `--amber` | gold | Workflow: staged/pending/warning · Content: MEDIUM · auth/gap events |
| `--cyan` | blue | Workflow: focus/selection · Content: MITRE tags · network events |
| `--violet` | purple | Workflow: agent activity · Content: SPECULATIVE · lateral movement |

### Color/shape disambiguation rule
A single color carries multiple meanings. Shape and prefix disambiguate. Never add tokens to resolve this — use shape.

| Color | Use case | Disambiguator |
|---|---|---|
| Crimson | Rejection (workflow) | `✗` prefix + word "rejected" |
| Crimson | HIGH severity (content) | `▲` badge shape |
| Crimson | Execution event (timeline) | bare `●` dot + `[execution]` label |
| Jade | Approved (workflow) | `✓` prefix |
| Jade | Sealed (workflow) | 🔒 lock icon |
| Jade | Persistence event (timeline) | bare `●` dot + `[persistence]` label |
| Amber | Staged (workflow) | dashed border |
| Amber | Auth event (timeline) | bare `●` dot + `[auth]` label |

A user scanning the timeline must be able to distinguish "this row is red because it's an execution event" from "this item is red because I rejected it" without reading labels.

### Type
| Family | Use | Loaded from |
|---|---|---|
| Syne | KPIs, large headlines, seal confirmation, count-up numbers | `src/index.css` `@import` |
| DM Sans | Body, labels, buttons | `@import` |
| DM Mono | IDs (F-001), hashes, timestamps, paths | `@import` |

### Density floors
- Timeline event row ≥ 32px height
- Finding sidebar row ≥ 36px height
- No 9–10px text in primary reading paths. 11px monospace OK for hashes only.

### Animation budget
- Tab/page transitions: 150ms slide
- KPI count-up on first load: one-shot only
- Live-refresh indicator: subtle pulse on sync icon
- Row hover: 100ms background change
- Drawer slide-in: 200ms
- **Nothing else animates.** No idle pulses on stable content. No background gradients shifting. Investigators want speed, not sparkle.

### Border conventions
- Solid border: committed state
- Dashed border: staged-not-committed (delta items)
- Hairline rule + inline pill: callouts inside data streams (gap banners, etc.)
- Heavy callout boxes: reserved for blocking errors only

---

## 6. Component Reference

For each component: purpose, what it shows, what's editable, what actions exist. Read this before editing the component. If reality differs from this section, update this section before changing code.

### `findings/FindingsTab.jsx`
**Purpose:** Primary review workflow.
**Layout:** Two-pane: sidebar (280px) + detail pane. Optional Zone 2 (audit/evidence) slides in.
**Sidebar shows:** search box, filter tabs (Pending/Approved/Rejected/All), one row per finding with ID · truncated title · confidence left-border · staged dashed-border · action chip.
**Detail pane shows:** sticky header with ID/type/status/provenance/host/timestamp/title; Zone 1 (decision fields: evidence, observation, interpretation, confidence, justification, context, host/account/timestamp); Zone 2 (audit, provenance chain, integrity).
**Editable fields:** title, observation, interpretation, confidence, confidence_justification, context, mitre_ids, iocs, related_findings.
**Actions:** Approve (stage approve delta) · Reject (stage reject delta with reason) · Undo (delete delta for finding) · multi-select Batch Approve/Reject.
**Selection invariant:** `selectedFindingId` persists across filter changes; if not in filtered set, show "Select a finding to review" empty state. Never auto-jump to `filtered[0]`.
**Acceptance:** see §8 Findings smoke test.

### `timeline/TimelineTab.jsx`
**Purpose:** Chronological context across hosts.
**Shows:** date + host separators; one row per event with chevron · time · 4-char type badge · description · delta status pill · finding_ref badges.
**Expanded row (planned):** full event meta + editable description + related findings.
**Filters:** type dropdown, host dropdown, search, status (all/pending/included/excluded).
**Actions:** click finding_ref → switch to Findings tab + select that finding.

### `evidence/EvidenceTab.jsx`
**Purpose:** Chain of custody control.
**Shows:** HMAC verification bar (verified / overdue), write-protection status, Solana anchor status, unregistered files list, custody violations, registered evidence table.
**Actions (all HMAC-gated except verify):** Verify Now, Seal Manifest, Ignore unregistered, Retire registered, Anchor Now, per-file Verify.
**Refresh contract:** chainStatus must update after every state-changing action (seal/ignore/retire/rescan/anchor).

### `layout/CommitDrawer.jsx`
**Purpose:** Final approval and writing of staged reviews.
**Shows:** staged delta items grouped by action (approve / reject / edit), per-item undo, password input, hold-to-commit button.
**Hold contract:** 3-second hold; cancel on mouseup, mouseleave, blur, or touchcancel.
**Password contract:** Cleared from React state immediately after `computeSimpleChallengeResponse` returns, BEFORE the `postCommit` network round-trip.

### `layout/Header.jsx`
**Purpose:** Identity, case context, top-level actions.
**Shows:** brand, case selector with create + activate, agent pulse, examiner+role chip, sign-out button.
**Case activation:** modal with password input + HMAC challenge.

### `layout/StatusBar.jsx`
**Purpose:** Always-visible system state.
**Shows:** seal dot (jade/amber/crimson), HMAC verified label, staged count (pulses when >0), sync age, "↑ COMMIT" badge.
**Click target:** `↑ COMMIT` badge only when `stagedCount > 0`. Not the full bar.

### `overview/OverviewTab.jsx`
**Purpose:** At-a-glance case health.
**Shows:** KPI grid (total/approved/pending/staged), severity bar, activity feed, MITRE tag cloud, evidence integrity widget.
**KPI clickability:** clicking PENDING → Findings tab + pending filter; APPROVED → approved filter; STAGED → opens CommitDrawer.

### `settings/SettingsTab.jsx`
**Purpose:** Agent token lifecycle.
**Shows:** create form (agent_id, label, optional ISO datetime expiry), token table (rotate/revoke per row), copy-once banner for new token.
**Confirmation:** rotate and revoke open a confirm dialog.

### `hosts/HostsTab.jsx` (new)
**Purpose:** Aggregate findings by host.
**Shows:** Table displaying unique hosts, finding counts, unique accounts count, best confidence, time range, and status summary badges.
**Interactions:** Click row → navigates to findings list filtered by that host.

### `accounts/AccountsTab.jsx` (new)
**Purpose:** Aggregate findings by affected_account.
**Shows:** Table displaying unique accounts (split on commas, handles arrays), finding counts, unique host count, host list chips, best confidence, time range, and status summary badges. Findings with missing/empty `affected_account` are grouped under an "N/A" badge with neutral styling.
**Interactions:** Click row → navigates to findings list filtered by that account.

### `iocs/IocsTab.jsx` (new)
**Purpose:** IOC triage and enrichment review.
**Shows:** Table with value (monospace + copy-on-hover), type badge, category, confidence badge (shape+color), host chips, clickable source finding links, status badge. Filters by category dropdown, status dropdown, and free-text search. Expandable rows reveal MITRE technique chips, tags, and metadata footer (ID, examiner, created_at). Data sourced from `/api/iocs` via 15s polling through the store.
**Interactions:** Click source-finding link → navigates to Findings tab and selects that finding. Click chevron → expands/collapses MITRE + tags detail.

### `reports/ReportsTab.jsx` (new)
**Purpose:** Examiner report builder.
**Shows:** List of saved reports, profile selector, generate preview, and save/download actions.

### `todos/TodosTab.jsx` (new)
**Purpose:** Examiner task tracking.
**Shows:** Table with columns: ID (monospace), Title/Description, Priority (shape-disambiguated ▲high/◆medium/●low badge), Examiner, Status (OPEN/COMPLETED badge), Related findings (clickable cyan links), Created at. Header shows open/completed counts from summary.
**Filters:** Priority dropdown (high/medium/low/all), Status dropdown (open/completed/all).
**Sort:** Priority desc (high→medium→low), then created_at asc.
**Interactions:** Click related finding link → switch to Findings tab + select that finding.

### `layout/CommandPalette.jsx` (new)
**Purpose:** Keyboard-driven command palette for rapid navigation and actions.
**Shows:** Search input, recently selected findings group, Findings group (id + title), Actions group (approve current, reject current, open commit drawer, refresh, sign out). Footer with keyboard hints.
**Keyboard:** Ctrl+K / Cmd+K opens; Esc closes; ↑↓ navigate; Enter selects. Built on `cmdk` (Command.Dialog) which provides native focus trap via @radix-ui/react-dialog.
**Security:** Approve/reject only stage deltas (no password); commit opens the normal drawer (password required there); sign out uses standard logout flow. No password action bypasses its normal modal.

### Planned components (live in `ux-tasks.md`)

---

## 7. Security Model (blocking — every task must satisfy)

This portal signs cryptographic evidence chains and authorizes the AI agent. Any new feature touching these surfaces must meet every applicable item below. Tasks list this explicitly in their "Security gate" line.

### Password handling
- Plaintext password never leaves the modal it was typed in.
- Cleared from React state **immediately** after the challenge response is computed, before any network round-trip.
- Never logged, never sent to console, never echoed back from server.

### Session & CSRF
- Session cookie is `agentir_session`, HttpOnly, SameSite=strict, path `/portal`.
- Same-origin fetches send the cookie automatically with `credentials: 'include'`.
- **CSRF posture today**: SameSite=strict is the only mitigation. No `X-CSRF-Token` header is sent or checked. State-changing endpoints (`POST /api/commit`, `POST /api/evidence/chain/*`, `POST /api/delta`, `POST /api/tokens`) rely entirely on the session cookie + the per-action HMAC challenge for sensitive ones. Verify with backend whether double-submit cookie is wanted before declaring done.

### Modal focus management
- Every password modal (login, case activation, commit drawer, evidence chain dialogs) **must** trap focus.
- Initial focus on the first input; Tab cycles inside; Escape closes; focus returns to opener.
- Tabbing into background while a password field is focused is a leak risk.

### Error scrubbing
- `catch` blocks must not pass `ex.message` directly to UI. Server errors can include stack traces, paths, internal IDs.
- Map by operation type:
  - Login → `"Authentication failed. Check your examiner ID and password."`
  - Commit → `"Commit failed — check your password and try again."`
  - Activation → `"Activation failed. Verify password and try again."`
  - Generic → `"Operation failed. Check the console for details."`
- Raw error → `console.error` only.

### Sign-out label
- Use the word "Sign out" or a door/arrow icon with a `title` tooltip. Never `⎋` alone.

### Token display
- Newly created token is shown **once** in a copy-once banner. UI must not store or re-fetch the plaintext token. The server cannot return it again.

### Rate limiting (backend responsibility, UI must surface)
- Failed challenge responses, failed logins, and excessive report-generation are server-throttled. UI displays "Too many attempts" via the normalized error map.

---

## 8. Testing Protocol

### 8.1 Component smoke tests (manual, per tab)

Run after every change to a tab. Each line is pass/fail.

**Login**
- [ ] Setup screen shown when `setup-required` true; create works
- [ ] Login challenge-response succeeds; cookie set; reload preserves session
- [ ] Logout clears cookie and returns to login

**Header / Case**
- [ ] Cases list loads; create new case works
- [ ] Case activate modal requires password; bad password rejected
- [ ] Switching case updates all data (findings, timeline, evidence)

**Overview**
- [ ] KPIs match `GET /api/summary` numbers
- [ ] Click PENDING → Findings tab, pending filter active
- [ ] Severity bar matches confidence distribution
- [ ] Activity feed shows 8 most-recent findings

**Findings**
- [ ] Filter tabs reflect status counts
- [ ] Selecting a finding renders all rich fields (not just title)
- [ ] Edit pencil on observation → save → staged with strikethrough preview
- [ ] Approve → dashed-green border on sidebar item, `✓` chip
- [ ] Reject → dashed-crimson border, `✗` chip, reason captured
- [ ] Undo → delta removed; finding returns to draft style
- [ ] Switching filter does NOT auto-select a different finding
- [ ] Multi-select batch approve works

**Timeline**
- [ ] Type/host filters narrow rows
- [ ] Gap banner is a hairline pill, not a full-width block
- [ ] Clicking a finding_ref navigates to Findings tab + selects

**Evidence**
- [ ] Chain status reflects actual `/api/evidence/chain/status` (sealed/unsealed/write-protected)
- [ ] Verify HMAC with password updates `hmac_last_verified_at`
- [ ] Sealing unregistered files updates status to sealed
- [ ] Solana anchor flow returns a tx hash + explorer link

**Commit**
- [ ] Drawer opens only when staged > 0
- [ ] Hold-to-commit: releasing mouse early cancels
- [ ] Blur or tab-switch cancels the hold
- [ ] Password cleared from React state immediately after challenge response computed
- [ ] Success: drawer closes, staged count → 0, findings reflect new status

**Settings (tokens)**
- [ ] Create token shows copy-once banner; copying to clipboard works
- [ ] List loads; rotate replaces token; revoke removes it
- [ ] Expired tokens visually distinguished from active

### 8.2 API contract checks (SIFT VM)

After backend changes, run these from local against the SIFT VM (host `192.168.122.81:4508`):

```bash
SID=$(sshpass -p forensics ssh sansforensics@192.168.122.81 'cat ~/.session-cookie' 2>/dev/null)
BASE="https://192.168.122.81:4508/portal/api"

curl -sk -b "agentir_session=$SID" $BASE/summary    | python3 -m json.tool
curl -sk -b "agentir_session=$SID" $BASE/delta      | python3 -m json.tool   # expect { items: [...] }
curl -sk -b "agentir_session=$SID" $BASE/findings/F-001 | python3 -m json.tool
curl -sk -b "agentir_session=$SID" $BASE/evidence/chain/status | python3 -m json.tool
```

Any shape mismatch with §3 is a bug in this spec — fix the spec before changing code.

### 8.3 End-to-end flow (manual, before any release)

1. Fresh install → setup admin → log in
2. Create case `TEST-XXX` → activate (password)
3. Trigger agent to record 2 findings (or seed manually)
4. Open Findings → edit one field on F-001 → reject F-002 with reason
5. Open CommitDrawer → hold-to-commit with password → success
6. Evidence tab → verify HMAC → seal manifest → anchor on Solana
7. Reports tab → generate "executive summary" → preview → download
8. Logout → reload → confirm login screen returned

### 8.4 Build & test (host)

```bash
# Frontend build (writes to static/v2/)
cd packages/case-dashboard/frontend && npm run build

# Sync to SIFT VM
rsync -avz --exclude .git --exclude .venv --exclude __pycache__ \
  /home/yk/AI/SIFTHACK/sift-mcps/ sansforensics@192.168.122.81:~/sift-mcps-test/

# Restart gateway
ssh sansforensics@192.168.122.81 'systemctl --user restart sift-gateway'

# Backend unit tests
uv run python -m pytest packages/case-dashboard/ --tb=short -q   # ~243 tests
```

---

## 9. Old-Portal Reference Map

The pre-migration v2 portal is the canonical reference for any behavior in question. Source: commit `1d6d937`, file `packages/case-dashboard/src/case_dashboard/static/v2/index.html`. 5,545 lines.

Fetch specific sections — do **not** read the whole file:

```bash
OLD="1d6d937:packages/case-dashboard/src/case_dashboard/static/v2/index.html"

# CSS tokens, badges, dialogs
git show $OLD | sed -n '60,450p'
# Tabs, tables, dialogs (HTML structure)
git show $OLD | sed -n '586,1048p'
# Evidence chain dialogs (seal / HMAC / ignore / retire)
git show $OLD | sed -n '1050,1200p'
# Token management UI
git show $OLD | sed -n '1680,1800p'
# Approve / reject workflow
git show $OLD | sed -n '1900,2000p'
# Finding detail rendering (Zone 1 + Zone 2)
git show $OLD | sed -n '2140,2500p'
# Inline edit pattern (startEdit, saveEdit, cancelEdit)
git show $OLD | sed -n '2500,2620p'
# Audit trail + integrity panel
git show $OLD | sed -n '3000,3400p'
# Settings + evidence chain controls
git show $OLD | sed -n '3400,4000p'
# Timeline rendering with finding_refs
git show $OLD | sed -n '4000,4920p'

# Function index
git show $OLD | grep -n 'function.*render\|function.*edit\|function.*approve\|function.*reject\|function.*commit\|function.*delta\|function.*token\|function.*seal'
# All API call sites
git show $OLD | grep -n 'apiFetch('
```

**Mapping workflow for any task:** identify the feature in the old portal → note every field/button/state transition → map DOM to React tree → then write code. The most expensive bugs in this migration came from implementing from memory.

---

## 10. Out of Scope

- **Theme toggle (dark/light)**: single-operator forensic tool; one tuned dark theme is enough.
- **Response-guard UI**: enforcement is in the backend and gateway; surfacing it in the portal adds knobs without operator value.
- **PDF rendering in-browser**: reports are generated server-side and streamed; no client-side rendering library.
- **i18n**: English only.
- **Multi-tenant case views**: one case active at a time per session.
- **Real-time push (WebSocket/SSE)**: 15s polling is sufficient; complexity not justified.

---

## Appendix — Source-of-truth file list

| Question | Read this file |
|---|---|
| What does endpoint X return? | `packages/case-dashboard/src/case_dashboard/routes.py` |
| Where is cookie X defined? | `packages/case-dashboard/src/case_dashboard/session_jwt.py` |
| Who can call endpoint X? | `packages/case-dashboard/src/case_dashboard/auth.py` |
| What's the actual store shape? | `packages/case-dashboard/frontend/src/store/useStore.js` |
| What endpoints are wired? | `packages/case-dashboard/frontend/src/api/endpoints.js` |
| What evidence chain states exist? | `packages/agentir-core/src/agentir_core/evidence_chain.py` |
| How does report generation work? | `packages/report-mcp/src/report_mcp/server.py` |
| How does the old portal behave? | `git show 1d6d937:packages/case-dashboard/src/case_dashboard/static/v2/index.html` |
