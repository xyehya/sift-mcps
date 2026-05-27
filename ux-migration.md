# UX Migration Blueprint — sift-mcps Examiner Portal
## Hackathon-Ready Enterprise Overhaul

> **Status:** Pre-implementation · **Scope:** `packages/case-dashboard/src/case_dashboard/static/` only  
> **Author:** Yehya · **Date:** 2026-05-28

---

## 1. Executive Summary

The current v2 portal is a functional but visually undistinguished 5 545-line vanilla-JS monolith. It uses system fonts, a generic slate-blue palette, and tab-based navigation that buries the most important data. The REST API backend (`routes.py`) is **completely clean** — the frontend is only coupled through 35 JSON endpoints under `/dashboard/api/*`. You can surgically replace all HTML/JS/CSS without touching a single line of Python.

**Goal:** Ship a hackathon-demo-quality portal that looks like a Tier-1 SOC platform — think Palantir Gotham × Bloomberg Terminal × modern design system. Dense information density, live data feel, command-palette navigation, and forensic-grade visual language.

---

## 2. Coupling Analysis — What You Can Touch Freely

```
┌───────────────────────────────────────────────────────┐
│          FRONTEND (you own this entirely)             │
│  static/v2/index.html  →  will become a Vite/React   │
│                            SPA or new single HTML     │
└───────────────────────┬───────────────────────────────┘
                        │ fetch('/dashboard/api/*')
                        │ JSON over HTTP
                        ▼
┌───────────────────────────────────────────────────────┐
│          REST API  (stable contract — do not touch)   │
│  packages/case-dashboard/src/case_dashboard/routes.py │
└───────────────────────┬───────────────────────────────┘
                        │ Python imports
                        ▼
┌───────────────────────────────────────────────────────┐
│  agentir_core  (evidence_chain, case_io, verification)│
│  Filesystem: findings.jsonl, timeline.jsonl, CASE.yaml│
└───────────────────────────────────────────────────────┘
```

**Safe to delete:** Everything in `static/v2/` and `static/` (the legacy v1).  
**Do not modify:** `routes.py`, `auth.py`, `session_jwt.py`, or any `agentir_core` package.  
**Mount point:** Gateway serves the dashboard at `/dashboard` — the new app must be served from there.

---

## 3. Current State Audit

### What v2 Does (the good parts to preserve)
| Feature | Current implementation |
|---|---|
| Login / setup / password reset | `POST /api/auth/login` + challenge-response |
| Case creation & switching | `GET /api/cases`, `POST /api/case/create`, `POST /api/case/activate` |
| Findings review queue | `GET /api/findings`, `GET /api/delta`, `POST /api/delta` |
| Approve / reject / edit | Delta staging → `POST /api/commit` with HMAC challenge |
| Timeline view | `GET /api/timeline` with type filters and gap detection |
| Evidence integrity | `GET /api/evidence/chain/status`, HMAC verify flow |
| IOC table | `GET /api/iocs` |
| TODO tracker | `GET /api/todos` |
| Agent tokens | `GET/POST/DELETE /api/tokens` |
| Keyboard shortcuts | `j/k` navigate, `a` approve, `r` reject, `c` commit |
| Dark/light theme | CSS variable toggle |

### What v2 Lacks (where the overhaul wins)
- No data visualization (charts, heatmaps, severity distribution)
- No real command palette — just a `?` shortcut overlay
- No drag-to-resize that feels native (the current one works but looks primitive)
- No activity feed / live-refresh indicator with visual pulse
- No MITRE ATT&CK mapping widget
- No "case health score" KPI at a glance
- Timeline is a plain scrollable list — no visual swim lanes
- Monolithic JS — no component structure, hard to extend

---

## 4. Complete REST API Contract

All endpoints are relative to `/dashboard`. The frontend authenticates via session cookie (set by `/api/auth/login`) or `Authorization: Bearer <token>`.

### Authentication
```
GET  /api/auth/setup-required        → { setup_required: bool }
POST /api/auth/setup                 → { success: bool }   body: { examiner, password }
GET  /api/auth/challenge             → { challenge: str }
POST /api/auth/login                 → sets cookie        body: { examiner, password, challenge_response? }
POST /api/auth/logout                → clears cookie
POST /api/auth/reset-password        → { success: bool }
GET  /api/auth/me                    → { examiner, role }
```

### Case Management
```
GET  /api/cases                      → [{ id, title, active, created_at }]
POST /api/case/create                body: { id, title } → { success: bool, case_id }
GET  /api/case/activate/challenge    → { challenge: str }
POST /api/case/activate              body: { id, password, challenge_response } → { success: bool }
GET  /api/case                       → { id, title, examiner, created_at, state, ... }
```

### Investigation Data (read-heavy, poll every 15–30s)
```
GET  /api/findings                   → [Finding]
GET  /api/findings/{id}              → Finding
GET  /api/timeline                   → [TimelineEvent]
GET  /api/evidence                   → [EvidenceItem]
GET  /api/iocs                       → [IOC]
GET  /api/todos                      → [Todo]
GET  /api/summary                    → CaseSummary { stats, coverage, hosts, accounts }
GET  /api/audit/{finding_id}         → [AuditEntry]
```

### Review Workflow (the core action loop)
```
GET    /api/delta                    → [DeltaItem]   (staged but not committed)
POST   /api/delta                    body: DeltaItem → { id }
DELETE /api/delta/{id}               → { success: bool }
GET    /api/commit/challenge         → { challenge: str }
POST   /api/commit                   body: { challenge_response, password? } → { success: bool }
```

### Evidence Chain
```
GET  /api/evidence/chain/status      → ChainStatus { sealed, hmac_verified, write_blocked, ... }
POST /api/evidence/chain/rescan      → { success: bool }
GET  /api/evidence/chain/challenge   → { challenge: str }
POST /api/evidence/chain/seal        → { success: bool }
POST /api/evidence/chain/anchor      → { success: bool }
POST /api/evidence/chain/verify-hmac body: { proof } → { valid: bool }
```

### Response Guard (agent output oversight)
```
GET  /api/response-guard/status      → { active: bool, pending: int, ... }
POST /api/response-guard/override    → { success: bool }
POST /api/response-guard/override/cancel → { success: bool }
```

### Agent Tokens
```
GET    /api/tokens                   → [Token]
POST   /api/tokens                   body: { agent_id, label, expiry? } → { token: str, id }
DELETE /api/tokens/{id}              → { success: bool }
POST   /api/tokens/{id}/rotate       → { token: str }
```

### Key Data Shapes

```typescript
interface Finding {
  id: string;           // e.g. "F-001"
  title: string;
  type: "finding" | "conclusion" | "attribution" | "exclusion";
  confidence: "HIGH" | "MEDIUM" | "LOW" | "SPECULATIVE";
  status: "draft" | "approved" | "rejected";
  body: string;
  tags: string[];
  host?: string;
  account?: string;
  examiner?: string;
  timestamp: string;    // ISO 8601
  evidence?: EvidenceArtifact[];
  provenance: "MCP" | "HOOK" | "SHELL" | "MIXED" | "NONE";
  verification: "confirmed" | "tampered" | "draft" | "unverified";
}

interface TimelineEvent {
  id: string;
  timestamp: string;
  type: "auth" | "execution" | "process" | "file" | "network" | "persistence" | "registry" | "lateral" | "other";
  description: string;
  host?: string;
  account?: string;
  finding_refs?: string[];
  status: "approved" | "rejected" | "draft";
}

interface DeltaItem {
  id: string;
  finding_id: string;
  action: "approve" | "reject" | "edit";
  note?: string;
  edited_fields?: Record<string, string>;
}
```

---

## 5. Design System Specification

### 5.1 Aesthetic Direction — **"Forensic Command"**

This interface is used by digital forensic examiners under pressure. The aesthetic should communicate:
- **Precision** — every pixel intentional, monospaced data, sharp grid alignment
- **Authority** — deep dark backgrounds, electric accents that demand attention
- **Clarity under load** — high information density without visual noise

Reference points: Bloomberg Terminal, Palantir Gotham, AWS Security Hub, Elastic Security, Criterion's Spine-01.

**One sentence:** *A mission-critical security console that makes data feel alive and investigators feel in control.*

### 5.2 Color Palette

```css
:root {
  /* Backgrounds — layered depth */
  --bg-void:      #07090e;   /* absolute deepest — modals behind */
  --bg-base:      #0a0d14;   /* page background */
  --bg-surface:   #0f1320;   /* cards, panels */
  --bg-raised:    #141928;   /* hover states, inputs */
  --bg-overlay:   #1a2035;   /* tooltips, dropdowns */

  /* Borders */
  --border-faint: #1c2338;
  --border-soft:  #232d45;
  --border-hard:  #2e3d5f;

  /* Text */
  --text-bright:  #eef2ff;   /* primary */
  --text-primary: #c8d4f0;   /* body */
  --text-muted:   #6b7fa3;   /* secondary labels */
  --text-ghost:   #3a4a6b;   /* disabled, placeholders */

  /* Accents — electric forensic palette */
  --cyan:         #00d4ff;   /* primary accent — links, active states */
  --cyan-dim:     rgba(0, 212, 255, 0.12);
  --cyan-glow:    rgba(0, 212, 255, 0.08);

  --amber:        #ffb347;   /* warnings, medium confidence */
  --amber-dim:    rgba(255, 179, 71, 0.12);

  --crimson:      #ff3864;   /* critical, high confidence, rejected */
  --crimson-dim:  rgba(255, 56, 100, 0.12);

  --jade:         #00ff94;   /* confirmed, approved, success */
  --jade-dim:     rgba(0, 255, 148, 0.10);

  --violet:       #a78bfa;   /* speculative, secondary interest */
  --violet-dim:   rgba(167, 139, 250, 0.10);
}
```

### 5.3 Typography

Load from Google Fonts (or self-host for offline/SIFT):

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;500;600;700;800&family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
```

| Role | Font | Weight | Size |
|---|---|---|---|
| App title / section headers | Syne | 700–800 | 18–28px |
| UI labels / buttons / nav | DM Sans | 500–600 | 12–14px |
| Body text / descriptions | DM Sans | 400 | 13–14px |
| Monospace data (IDs, hashes, code) | DM Mono | 400–500 | 11–13px |
| Stat numbers / KPI figures | Syne | 700 | 24–48px |

### 5.4 Spacing & Grid

- Base unit: `4px`
- Panel padding: `20px`
- Card gap: `12px`
- Sidebar width: `280px` (default), `200px–400px` (drag range)
- Header height: `52px`
- Tab bar height: `44px`
- Status bar height: `32px`

### 5.5 Motion

```css
/* Global easing tokens */
--ease-snap:   cubic-bezier(0.16, 1, 0.3, 1);   /* panel slides */
--ease-smooth: cubic-bezier(0.4, 0, 0.2, 1);    /* color transitions */

/* Duration tokens */
--dur-fast:   100ms;
--dur-normal: 200ms;
--dur-slow:   350ms;
```

- Tab switches: `opacity` + `translateY(4px)` slide-in, 150ms
- Sidebar item hover: background `200ms ease`
- Progress bars: `width 400ms ease-snap`
- Toast in: `translateX(calc(100% + 20px))` → `0`, `200ms ease-snap`
- KPI counters: count-up animation on load (CSS `@counter-style` or JS interval)
- Skeleton loaders: CSS `@keyframes shimmer` with gradient sweep

---

## 6. Component Inventory & Wireframes

### 6.1 Global Layout

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ HEADER [52px]                                                                │
│ ▓▓▓ sift-mcps     [case selector ▾]  [◉ agent pulse]  [alice · admin]  [⎋]  │
├──────────────────────────────────────────────────────────────────────────────┤
│ NAV RAIL [left, 48px wide] │ TAB CONTENT AREA                               │
│                            │                                                │
│  ⬡ Overview                │                                                │
│  ⬡ Findings   [14]         │                                                │
│  ⬡ Timeline                │                                                │
│  ⬡ Evidence                │                                                │
│  ⬡ IOCs                    │                                                │
│  ⬡ TODOs       [3]         │                                                │
│  ─────────                 │                                                │
│  ⬡ Settings                │                                                │
│                            │                                                │
├────────────────────────────┘                                                │
│ STATUS BAR [32px]  ● SEALED  ↺ last sync 12s ago  [commit pending: 3]       │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Key change from v2:** Replace horizontal tab bar with a vertical icon nav rail (48px). This frees the full width for content. Badges on nav icons replace tab badges.

### 6.2 Overview Tab (Dashboard)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ CASE: ROCBA-CDRIVE  ·  Intrusion Analysis May 2026  ·  ACTIVE               │
├───────────┬───────────┬───────────┬───────────┬─────────────────────────────┤
│  FINDINGS │  APPROVED │  PENDING  │  COVERAGE │ EVIDENCE INTEGRITY          │
│    48     │    31     │    14     │   67%     │  ████████░░░░  SEALED ✓     │
│  total    │  confirmed│  in queue │  of scope │  HMAC  ·  anchored          │
├───────────┴───────────┴───────────┴───────────┴─────────────────────────────┤
│ SEVERITY DISTRIBUTION                │ REVIEW VELOCITY                      │
│                                      │  last 24h ░░░░░░░░░░ 8 findings/h   │
│  ██ HIGH    12  ──────────           │  ·  ·  ·  ·  ·  ·  ·  ·  (sparkline)│
│  ██ MEDIUM  18  ──────────────       │                                      │
│  ██ LOW      9  ───────              │ HOSTS IN SCOPE: 3                    │
│  ░░ SPECUL   9  ───────              │  WS01  WS02  SRV-DC01               │
├──────────────────────────────────────┼──────────────────────────────────────┤
│ RECENT ACTIVITY FEED                 │ MITRE ATT&CK COVERAGE                │
│  ·  alice approved F-044  2m ago    │  T1078 · T1059 · T1547 · T1021       │
│  ·  F-047 staged (HIGH)   5m ago    │  T1003 · T1055 · T1190               │
│  ·  Hayabusa ingest done  18m ago   │  [7 techniques mapped]               │
│  ·  Evidence re-scanned   1h ago    │                                      │
└──────────────────────────────────────┴──────────────────────────────────────┘
```

**Widgets:**
- `<KPICard>` — large number with label, delta indicator, color-coded border-top
- `<SeverityBar>` — segmented horizontal bar with legend (like GitHub traffic graph)
- `<ActivityFeed>` — 10-item live-refreshing list, each entry has icon + text + relative time
- `<MITREMatrix>` — mini tag cloud of technique IDs, clickable to filter timeline
- `<ReviewSparkline>` — 24h approval velocity as a tiny SVG bar chart

### 6.3 Findings Tab (Primary Workflow)

```
┌─────────────────────┬───────────────────────────────────────────────────────┐
│ SIDEBAR [280px]     │ FINDING DETAIL                                        │
│                     │                                                       │
│ [search…]  [filter] │  ┌─ F-044 ─────────────────────────────────────────┐ │
│ Pending  Approved   │  │ Lateral Movement via RDP to WS02                 │ │
│ Rejected  All       │  │ ● HIGH  · Finding  · MCP  ·  alice               │ │
│ ─────────────────── │  │ confirmed ✓  2026-05-14 03:22:18                 │ │
│ ● F-048  [HIGH] ··· │  └──────────────────────────────────────────────────┘ │
│ ● F-047  [HIGH] ··· │                                                       │
│ ● F-044  [MED]  ··· │  DESCRIPTION ─────────────────────────────────────── │
│ ─── reviewed ─────  │  The threat actor used compromised credentials for    │
│ ✓ F-043  [HIGH] ··· │  user CORP\jsmith to establish an RDP session...      │
│ ✗ F-040  [LOW]  ··· │                                                       │
│                     │  EVIDENCE (3) ──────────────────────────────────────  │
│ 14 pending          │  ▶ evtx/Security.evtx  · EventID 4624                │
│ 34 reviewed         │  ▶ hayabusa/timeline.csv  · row 1847                 │
│ ─────────────────── │                                                       │
│ [□ select mode]     │  TAGS ─────────────────────────────────────────────── │
│                     │  lateral-movement  rdp  credential-abuse              │
│                     │                                                       │
│                     │  TIMELINE CONTEXT (±2h) ───────────────────────────── │
│                     │  03:18  Auth event CORP\jsmith @ WS01                │
│                     │  03:22  ● RDP session established (this finding)      │
│                     │  03:24  Prefetch: mstsc.exe executed                  │
│                     │                                                       │
│                     │  ┌─ ACTIONS ─────────────────────────────────────┐   │
│                     │  │  [✓ Approve]  [✗ Reject]  [✎ Edit]  [↗ Note] │   │
│                     │  └────────────────────────────────────────────────┘  │
└─────────────────────┴───────────────────────────────────────────────────────┘
```

**Key UX improvements:**
- Sticky action bar at bottom of content, always visible (not buried at top)
- Evidence items are `<details>` accordion with raw extract preview
- Timeline context renders inline with finding — no tab switching needed
- Confidence badge uses color-coded left border on sidebar items (not just text)
- Multi-select mode with batch approve/reject toolbar that slides in from bottom

### 6.4 Timeline Tab

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ TIMELINE  ·  2026-05-14  ·  [filter: all types ▾]  [host: all ▾]  [search] │
├─────────────────────────────────────────────────────────────────────────────┤
│   auth        execution      file        network       persistence           │
│   ───────     ──────────     ──────      ──────────    ─────────────         │
│                                                                              │
│ 03:00 ─────────────────────────────────────────── WS01 ──────────────────── │
│   ●  03:14  [auth]     CORP\jsmith logon (type 3)                [F-041]    │
│   ●  03:18  [auth]     CORP\jsmith logon (type 10) ←RDP                     │
│   ●  03:22  [lateral]  RDP session WS01→WS02  ◉ HIGH          [F-044 ✓]   │
│             ╚══ alice approved · confirmed · evtx/Security.evtx:1847        │
│   ●  03:24  [exec]     mstsc.exe (Prefetch hit)                             │
│   ●  03:31  [persist]  HKCU Run key added: svchost32                [F-046] │
│                                                                              │
│ 04:00 ─────────────────────────────────────────── WS02 ──────────────────── │
│   ...                                                                        │
│                                                                              │
│   ▲ GAP: 47 min with no events  (possible log gap / evidence missing)       │
│                                                                              │
│ [Load earlier]                                          [848 events total]  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key improvements:**
- Type swim-lane headers (colored dots) give visual pattern at a glance
- Finding references inline on timeline row, clickable
- Approved findings show examiner initials + confirmation state inline
- Large time gaps rendered as warning banners (already in v2, needs visual upgrade)

### 6.5 Command Palette (new — `Cmd+K` / `Ctrl+K`)

```
┌────────────────────────────────────────────────────────┐
│  ⌘  Search findings, timeline, commands…               │
├────────────────────────────────────────────────────────┤
│  RECENT                                                │
│  → F-044  Lateral Movement via RDP                     │
│  → Commit staged changes (3 pending)                   │
│                                                        │
│  ACTIONS                                               │
│  ⌨  approve current finding         [A]                │
│  ⌨  reject current finding          [R]                │
│  ⌨  commit staged changes           [Shift+C]          │
│  ⌨  open evidence chain panel                          │
│  ⌨  refresh all data                [F5]               │
└────────────────────────────────────────────────────────┘
```

### 6.6 Commit Drawer (replaces modal)

Replace the current commit dialog with a right-side drawer (slide in from right, 400px wide):
- List of staged delta items with undo per item
- HMAC challenge input
- Commit button with 3-second hold-to-confirm (prevents accidents)
- Success state shows animated seal icon

### 6.7 Status Bar (global, always visible)

```
● SEALED · HMAC verified · 3 staged · last sync 12s · alice · admin  [↑ commit]
```

Colors:
- `●` = green when sealed+verified, amber when unverified, red when tampered
- "3 staged" pulses softly when pending commits exist
- Click anywhere on status bar → opens commit drawer

---

## 7. Implementation Plan

### Option A: Vite + React (Recommended for Hackathon)

**Why:** Component reuse, fast hot reload, easy chart libraries (Recharts / Nivo), and the component tree naturally maps to the panel structure.

**Build output:** `dist/` → replace `static/v2/` entirely. Gateway serves `index.html` for all `/dashboard` routes.

```
packages/case-dashboard/
  src/case_dashboard/
    static/v2/          ← REPLACE THIS ENTIRELY
      index.html        ← becomes Vite entry point (after build)
      assets/           ← hashed JS/CSS chunks
  frontend/             ← NEW source directory (sibling to src/)
    src/
      main.jsx
      App.jsx
      api/
        client.js       ← thin fetch wrapper (auth headers, base path)
        endpoints.js    ← typed API calls
      components/
        layout/
          NavRail.jsx
          Header.jsx
          StatusBar.jsx
          CommandPalette.jsx
          CommitDrawer.jsx
        findings/
          FindingsSidebar.jsx
          FindingDetail.jsx
          ActionBar.jsx
          EvidenceAccordion.jsx
          TimelineContext.jsx
          BatchToolbar.jsx
        overview/
          KPICard.jsx
          SeverityBar.jsx
          ActivityFeed.jsx
          MITRETagCloud.jsx
          ReviewSparkline.jsx
        timeline/
          TimelineView.jsx
          TimelineRow.jsx
          GapIndicator.jsx
        evidence/
          EvidenceTable.jsx
          ChainStatusWidget.jsx
        auth/
          LoginCard.jsx
          SetupForm.jsx
        common/
          Badge.jsx
          Toast.jsx
          Skeleton.jsx
          Dialog.jsx
      hooks/
        useFindings.js  ← polling + cache
        useCase.js
        useDelta.js
        useTimeline.js
      store/
        useStore.js     ← Zustand (minimal global state)
    vite.config.js
    package.json
```

### Option B: Enhanced Single HTML File (Zero-Build, Hackathon-Fast)

Keep the single-file approach but overhaul everything: new design tokens, new font loading, restructured JS with `class`-based components pattern. Ship in 2 hours, no toolchain.

**When to choose:** If the hackathon judges are running on the actual SIFT VM with no npm. Otherwise choose Option A.

### Recommended Stack (Option A)

```json
{
  "dependencies": {
    "react": "^18.3",
    "react-dom": "^18.3",
    "zustand": "^4.5",
    "recharts": "^2.12",
    "cmdk": "^1.0",
    "date-fns": "^3.6",
    "clsx": "^2.1"
  },
  "devDependencies": {
    "vite": "^5.4",
    "@vitejs/plugin-react": "^4.3",
    "tailwindcss": "^3.4",
    "autoprefixer": "^10.4",
    "postcss": "^8.4"
  }
}
```

**Tailwind config:** Use the color tokens from §5.2 as Tailwind theme extensions. This lets you write `bg-surface`, `text-cyan`, `border-border-soft` etc.

### Build integration

In `vite.config.js`:
```js
export default {
  base: '/dashboard/',
  build: {
    outDir: '../src/case_dashboard/static/v2',
    emptyOutDir: true,
  },
}
```

The gateway's `serve_v2_static` route already serves any file from `static/v2/` — no gateway changes needed.

---

## 8. Phase Plan

### Phase 0 — Foundation (2–3h)
- [ ] Scaffold Vite + React project in `packages/case-dashboard/frontend/`
- [ ] Implement design tokens (CSS vars + Tailwind config)
- [ ] Build `api/client.js` — thin fetch wrapper with cookie auth, base path `/dashboard`, error handling
- [ ] Implement all API calls in `api/endpoints.js` (copy from v2 JS, make typed)
- [ ] Build `NavRail`, `Header`, `StatusBar` shells — just layout, no data yet
- [ ] Implement auth flow: `LoginCard` → `SetupForm` → session check on mount

### Phase 1 — Overview + Findings (4–5h)
- [ ] `useCase`, `useFindings`, `useDelta` hooks with 15s polling
- [ ] `KPICard` grid (findings total, approved, pending, coverage)
- [ ] `SeverityBar` + `ActivityFeed`
- [ ] `FindingsSidebar` with search, filter presets, multi-select
- [ ] `FindingDetail` — full finding card with evidence accordion + timeline context
- [ ] `ActionBar` — approve / reject / edit (stage to delta)
- [ ] `BatchToolbar` — slides in from bottom when items selected

### Phase 2 — Commit + Evidence (2–3h)
- [ ] `CommitDrawer` — slide-in panel, delta item list, HMAC challenge, hold-to-commit button
- [ ] `StatusBar` live indicators (sealed state, sync time, staged count)
- [ ] `ChainStatusWidget` on evidence tab
- [ ] Evidence table with verify button

### Phase 3 — Timeline + IOCs + TODOs (2–3h)
- [ ] `TimelineView` — grouping by date+host, type color coding, gap indicators
- [ ] Timeline inline finding refs — click to navigate to finding
- [ ] IOC table (sortable, filterable)
- [ ] TODO table

### Phase 4 — Polish (2h)
- [ ] `CommandPalette` (`cmdk`) — search findings + quick actions
- [ ] `ReviewSparkline` on overview
- [ ] `MITRETagCloud` (parse MITRE IDs from finding tags)
- [ ] Toast system (replace `alert()`)
- [ ] Keyboard shortcuts (preserve all current v2 shortcuts)
- [ ] Dark/light theme toggle (Tailwind `dark:` classes)
- [ ] Loading skeletons on initial fetch

---

## 9. Key Developer References

### Files to Read Before Starting
| File | Why |
|---|---|
| `packages/case-dashboard/src/case_dashboard/routes.py` | Full REST API implementation — read handler signatures to understand exact request/response shapes |
| `packages/case-dashboard/src/case_dashboard/static/v2/index.html` | Current v2 — mine the JS for exact API call patterns, auth flow, delta staging logic |
| `packages/case-dashboard/src/case_dashboard/auth.py` | Cookie name (`COOKIE_NAME`), bearer token format, role values |
| `packages/case-dashboard/src/case_dashboard/session_jwt.py` | JWT structure (for `GET /api/auth/me` response understanding) |
| `packages/agentir-core/src/agentir_core/evidence_chain.py` | Understand what "SEALED" / "anchored" / HMAC means for UI labels |

### Cookie Auth
```
Cookie: sift_portal_session=<jwt>
```
The JWT is set `HttpOnly; SameSite=Lax` — JS cannot read it, but `fetch()` sends it automatically. Use `credentials: 'include'` (already implied by same-origin).

### Bearer Auth (for API tokens, not examiner sessions)
```
Authorization: Bearer <token>
```
Used by agent services, not human examiner sessions. The UI token manager creates/revokes these.

### Evidence Chain States (for status indicators)
| State | Display label | Color |
|---|---|---|
| `sealed: true, hmac_verified: true` | SEALED ✓ | `--jade` |
| `sealed: true, hmac_verified: false` | SEALED · verify pending | `--amber` |
| `sealed: false` | UNSEALED | `--crimson` |
| `write_blocked: true` | Write-protected | `--cyan` (good thing) |

### Delta Action Types
| `action` | Meaning | Badge color |
|---|---|---|
| `"approve"` | Examiner approved finding | `--jade` (dashed border = not committed) |
| `"reject"` | Examiner rejected finding | `--crimson` (dashed border) |
| `"edit"` | Fields modified | `--amber` (dashed border) |

---

## 10. Design Details — What Makes It Look Enterprise

### 10.1 The Subtle Things That Matter

1. **Scrollbar styling** — thin, matching bg color (v2 already does this, keep it)
2. **Monospace data** — all IDs (`F-044`), hashes, timestamps use DM Mono
3. **Number formatting** — `Intl.DateTimeFormat` for timestamps, `toLocaleString()` for counts
4. **Relative times** — "2m ago", "1h ago" using `date-fns/formatDistanceToNow`
5. **Loading states** — every panel has a skeleton before data arrives; no "Loading..." text
6. **Error states** — descriptive with a retry button, not just a red banner
7. **Focus rings** — always visible, using `outline: 2px solid var(--cyan)`
8. **Empty states** — illustrated with an icon + helpful text about what will appear here

### 10.2 Confidence Color Mapping
```
HIGH        → crimson left-border, crimson badge
MEDIUM      → amber left-border, amber badge  
LOW         → cyan-dim left-border, ghost badge
SPECULATIVE → violet left-border, violet badge
```

### 10.3 Provenance Indicators
```
MCP  → solid dot  (fully grounded — best)
HOOK → hollow dot
SHELL → triangle warning
MIXED → split circle
NONE → X (no grounding — flag prominently)
```

### 10.4 The "Staged Not Committed" Visual Language
All delta items use **dashed borders** in their respective color. This is a forensic concept (staged ≠ final) and must be visually distinct from committed states. Use `border-style: dashed` or a `border-image` stripe pattern.

### 10.5 Animation Budget
Keep animations minimal and purposeful:
- Page/tab transitions: yes (150ms slide)
- KPI count-up on load: yes (one-shot)
- Live-refresh indicator: yes (subtle pulse on sync icon)
- Row hover: yes (100ms bg)
- EVERYTHING ELSE: no animation. Investigators don't want sparkle, they want speed.

---

## 11. Out of Scope for Hackathon

These exist in `routes.py` and are non-trivial to surface in a demo:
- `POST /api/auth/reset-password` — leave as basic text form
- `POST /api/evidence/chain/anchor` — show button, don't polish the HMAC ceremony
- Case activation password confirmation — basic modal is fine
- Full MITRE ATT&CK matrix — use tag cloud, not full matrix grid

---

## 12. Testing the Migration

The gateway serves the dashboard at `https://localhost:8443/dashboard/` (or whatever port is configured).

```bash
# Start the stack
cd /home/yk/AI/SIFTHACK/sift-mcps
docker compose up -d

# In frontend/ dir, dev mode with proxy
cd packages/case-dashboard/frontend
npm run dev
# vite.config.js should proxy /dashboard/api/* → https://localhost:8443/dashboard/api/*

# Production build → writes to static/v2/
npm run build
# then refresh https://localhost:8443/dashboard/
```

**Smoke test checklist:**
- [ ] Login flow (setup-required → create account → login)
- [ ] Case creation + activation
- [ ] Findings load + filter presets work
- [ ] Approve + reject stages delta items
- [ ] Commit flow reaches the HMAC challenge and succeeds
- [ ] Evidence chain status shows correct sealed/unsealed state
- [ ] Timeline loads and finding refs are clickable
- [ ] Sign out clears session and returns to login

---

## Appendix A — v2 JS Patterns Worth Preserving

These patterns from v2 are solid and should be ported verbatim:

```js
// Auth-aware fetch with auto-redirect on 401
async function apiFetch(path, opts = {}) {
  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), 15000);
  const res = await fetch('/dashboard' + path, { ...opts, headers, signal: controller.signal });
  clearTimeout(tid);
  if (res.status === 401) { showLoginScreen(); return null; }
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// Parallel load on init
const [findings, delta, cas, timeline] = await Promise.all([
  apiFetch('/api/findings'),
  apiFetch('/api/delta'),
  apiFetch('/api/case'),
  apiFetch('/api/timeline'),
]);

// HMAC commit challenge pattern
const challenge = await apiFetch('/api/commit/challenge');
// ... user enters password ...
await apiFetch('/api/commit', { method: 'POST', body: JSON.stringify({ challenge_response }) });
```

---

## Appendix B — ASCII Full-Screen Blueprint

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  ▓ sift-mcps           [ROCBA-CDRIVE ▾]      ◉ live    alice  ADMIN   [⎋]  ║
╠══╦═══════════════════════════════════════════════════════════════════════════╣
║  ║                                                                          ║
║🔲║  ┌── ACTIVE CASE ────────────────────────────────────────────────────┐  ║
║  ║  │  Intrusion Analysis May 2026  ·  ROCBA-CDRIVE  ·  Created 2026-05│  ║
║📋║  └───────────────────────────────────────────────────────────────────┘  ║
║  ║                                                                          ║
║⏱ ║  ┌── KPIs ──────┬──────────────┬──────────────┬─────────────────────┐  ║
║  ║  │ FINDINGS     │  APPROVED    │  PENDING     │  COVERAGE           │  ║
║🗂 ║  │  48   total  │  31  67%     │  14  in rev  │  ██████░░░░  67%    │  ║
║  ║  └──────────────┴──────────────┴──────────────┴─────────────────────┘  ║
║🦠║                                                                          ║
║  ║  ┌── SEVERITY ──────────────────┐  ┌── ACTIVITY FEED ──────────────┐   ║
║☑ ║  │ ██ HIGH     12  ──────────── │  │ · alice approved F-044  2m    │   ║
║  ║  │ ██ MEDIUM   18  ──────────── │  │ · F-047 staged HIGH     5m    │   ║
║⚙ ║  │ ██ LOW       9  ────────     │  │ · Hayabusa done         18m   │   ║
║  ║  │ ░░ SPEC      9  ────────     │  │ · Evidence rescan       1h    │   ║
║  ║  └──────────────────────────────┘  └──────────────────────────────┘   ║
╠══╬══════════════════════════════════════════════════════════════════════════╣
║  ● SEALED · HMAC ✓ · 3 staged ·  sync 12s ago                 [↑ COMMIT]  ║
╚══╩══════════════════════════════════════════════════════════════════════════╝

FINDINGS VIEW:
╔══╦═══════════════╦══════════════════════════════════════════════════════════╗
║  ║ [search…]  ▾  ║  F-044                                                   ║
║🔲║ ─────────────  ║  Lateral Movement via RDP to WS02                       ║
║  ║ Pending  Appr  ║  ● HIGH · Finding · MCP · alice · confirmed ✓            ║
║📋║ ─────────────  ║  ─────────────────────────────────────────────────────  ║
║  ║ ●● F-048 HIGH  ║  DESCRIPTION                                             ║
║  ║ ●● F-047 HIGH  ║  The threat actor used compromised credentials for       ║
║  ║ ●● F-044 MED   ║  user CORP\jsmith to establish an RDP session to WS02.   ║
║  ║ ── reviewed ── ║  Pivot occurred 2026-05-14 03:22:18 UTC. The logon type  ║
║  ║ ✓ F-043  HIGH  ║  was Type 10 (RemoteInteractive)...                      ║
║  ║ ✗ F-040  LOW   ║                                                          ║
║  ║                ║  EVIDENCE (3)                                             ║
║  ║ 14 pending     ║  ▶ evtx/Security.evtx  EventID 4624  row 12847           ║
║  ║ 34 reviewed    ║  ▶ hayabusa/timeline.csv  row 1847                       ║
║  ║ ─────────────  ║  ▶ mft/MFT_parsed.csv  $MFT entry 8821                  ║
║  ║ □ select mode  ║                                                          ║
║  ║                ║  TIMELINE CONTEXT (±2h)                                  ║
║  ║                ║  03:14 ●  auth  CORP\jsmith logon type 3                 ║
║  ║                ║  03:18 ●  auth  CORP\jsmith logon type 10 ←RDP           ║
║  ║                ║  03:22 ◉  THIS FINDING                                   ║
║  ║                ║  03:24 ●  exec  mstsc.exe prefetch hit                   ║
║  ║                ║                                                          ║
║  ║                ║  ┌─────────────────────────────────────────────────┐    ║
║  ║                ║  │  [✓ Approve]  [✗ Reject]  [✎ Edit]  [↗ Note]  │    ║
║  ║                ║  └─────────────────────────────────────────────────┘    ║
╠══╬═══════════════╬══════════════════════════════════════════════════════════╣
║  ● SEALED · HMAC ✓ · 3 staged · sync 12s ago                  [↑ COMMIT]  ║
╚══╩═══════════════╩══════════════════════════════════════════════════════════╝
```
