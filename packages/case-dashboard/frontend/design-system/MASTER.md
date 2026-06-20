# SIFT Examiner Portal v3 — Design System MASTER (FROZEN)

**Status:** Frozen at end of Phase 0 (RUN-1 design system + RUN-2 shell/data +
RUN-3 Overview/Findings reference tabs), **identity relocked in RUN-4a** to the
"Mission Control" graphite-ink + warm-orange identity (tokens both themes,
fonts, motion primitives, shell re-skin), **agent Command & Control built in
RUN-4b** (§12: Mission-Control Overview hero + Authorization Required queue +
KPI tiles, Findings MITRE chips + graded confidence ring + a/s/r keyboard,
multi-case switcher, ambient background, motion-primitive wiring) — the emerald
palette is retired. This is the contract every Phase-1 feature agent (EVID /
ENTITY / REPORT) MUST copy. The Overview and Findings tabs are the worked
examples — when in doubt, read those files, not your memory.

Authoritative inputs: `docs/new-docs/PORTAL_V3_REBUILD_SPEC.md` (§2 tokens/type/
motion/UX, §3 architecture, §5 security). This file records the ACTUAL frozen
implementation, which wins over prose.

---

## 0. Golden rules (do these or the review bounces)

1. **Tokens only — no raw hex** in components. Colour comes from the token
   classes mapped in `styles/globals.css`. The single token source is
   `styles/tokens.css` (`:root` = light, `.dark` = dark). Never add a colour
   anywhere else.
2. **No inline styles** except *data-driven* numeric values (bar widths, chart
   gradient stops). Those use token CSS vars (`var(--chart-1)`), never hex. The
   vendored `Progress` primitive is the reference for this.
3. **≤400 lines per file.** Decompose. One React component export per `.jsx`
   (see §7). Pure logic lives in `*-utils.js` / `*-metrics.js`.
4. **No `dangerouslySetInnerHTML` on untrusted data.** All finding/report text
   renders as escaped React text nodes. (See §8.)
5. **Lucide icons only** (no emoji as icons). **focus-visible** on every
   interactive element. **aria-label** on icon-only controls. **AA contrast in
   both themes.** `prefers-reduced-motion` honoured.
6. **Never** edit `src/test/useStore.interface.test.js` or
   `src/test/EvidenceUnseal.test.jsx`, and never add/remove top-level
   `useStore` keys, without operator + orchestrator sign-off.

---

## 1. Tokens (the only colour source)

Defined in `styles/tokens.css`, mapped to Tailwind utilities in `globals.css`
via `@theme inline { --color-*: var(--*) }`. Consume them as utility classes:

| Group | CSS var | Utility class examples |
|---|---|---|
| Surfaces | `--background --card --popover --muted --secondary` | `bg-background bg-card bg-secondary text-muted-foreground` |
| Brand | `--primary --accent --ring --border --input` | `bg-primary text-primary border-border ring-ring` |
| Destructive | `--destructive` | `bg-destructive text-destructive` |
| Severity (= finding confidence) | `--sev-high --sev-med --sev-low --sev-spec` | `text-sev-high bg-sev-med` |
| Status | `--status-approved --status-pending --status-staged --status-rejected` | `text-status-approved bg-status-staged` |
| Grade | `--grade-full --grade-partial --grade-none` | `text-grade-full` |
| Chart | `--chart-1 … --chart-5` | class `text-chart-1`; **chart libs** use `var(--chart-1)` |

**CRITICAL — Tailwind JIT needs literal class strings.** Never interpolate a
token class (`` `text-${x}` ``); it will not be generated. Map your dynamic value
to a bundle of *complete literal* classes. Reference: `findings-utils.js`
`CONF_CLASS` / `STATUS_CLASS` and `overview-metrics.js severityCounts()`.

```js
export const CONF_CLASS = {
  HIGH: { text: 'text-sev-high', bg: 'bg-sev-high', tint: 'bg-sev-high/10', ring: 'border-sev-high/40' },
  // …
}
```

**Identity values (RUN-4a).** Dark (`.dark`, app default) = neutral graphite ink
(`--background #0A0A0C`, `--card #16171B`) + warm off-white text (`--foreground
#F2EFEA`) + ONE warm orange accent (`--primary #F4754B`), with a redder crimson
(`--destructive #E2554C`, `--sev-high`) kept distinct from the accent. Light
(`:root`) = a clean COOL-NEUTRAL slate (`--background #F8FAFC`, `--card #FFFFFF`,
`--border #E2E8F0`) — never warm-cream — with the orange darkened to `--primary
#C2410C` so it clears WCAG AA (≥4.5:1) as both text and button fill. Forensic
hues: jade/amber/steel/violet/crimson, mapped per theme.

Type: base 15px. Three self-hosted families (`@fontsource` in `main.jsx`, **never**
a Google Fonts link/@import):
- `--font-sans` **Inter** — UI / body (default).
- `--font-display` **Space Grotesk** — page titles (`<h1>`, applied in base CSS)
  + big stat numerals (opt in with the `font-display` utility, e.g. `KpiRow`).
- `--font-mono` **JetBrains Mono** (replaced Fira Code) via `.mono` — every hash,
  ID, timestamp, path, IP, count, ATT&CK id. Pair with `.tnum` for tabular
  figures on numeric/data columns.

---

## 2. Theme

`lib/theme.jsx` `ThemeProvider` (mounted in `main.jsx`) — class strategy: toggles
`.dark` + `data-theme` + `color-scheme` on `<html>`, system-aware, persisted in
`localStorage['sift-theme']`. The single `<ThemeToggle />` lives in the **SideNav
operator footer** (RUN-4a moved it out of the header). Components do nothing
theme-specific beyond using tokens; both themes "just work" because utilities
resolve to `var(--token)` which swaps under `.dark`.

---

## 3. Motion (`lib/motion.js`)

Define once, reuse. Easing `EASE = cubic-bezier(0.16,1,0.3,1)`; `DUR` micro/enter/
exit; `SPRING`; `STAGGER`.

- **Use `useMotionVariants()`** to get the shared variants collapsed to instant
  (no-transform) versions under `prefers-reduced-motion`. Variant names:
  `fadeRise` (page/section entrance), `modal`, `staggerContainer` + `staggerItem`
  (lists/grids), `cardHover` (hover lift `translateY(-2px)` + border-brighten).
- **Mission-Control primitives (RUN-4a, wired in RUN-4b)**, also in
  `useMotionVariants()` and reduced-motion gated: `breathingOrb` + `pingRing`
  (AgentHero orb — render 2 rings + stagger via `transition.delay`),
  `authGlowPulse` (AgentHero awaiting-auth wash), `severityBarFill`
  (`overview/SeverityDistribution.jsx`, `scaleX` from `origin-left`), `chartDraw`
  (`overview/MiniSparkline.jsx` + `findings/ConfidenceRing.jsx`, `pathLength` on a
  `motion.path`/`motion.circle`), `activityTailItem` (`overview/ActivityFeed.jsx`
  slide-in via `AnimatePresence`), `statusDotPulse` (AgentHero/MissionStats/SideNav
  dots; colour via class). Helpers `useCountUp(target,{duration})` (AgentHero +
  MissionStats numerals; easeOutCubic, snaps to final under reduced motion) and
  `easeOutCubic`.
- Transform / opacity / `pathLength` ONLY — never animate width/height/top/left;
  colour is always a token class, never animated in the variant.
- For ad-hoc `motion.*` not using the shared variants (e.g. the severity bar
  `scaleX` grow), gate on `useReducedMotion()` yourself: `initial={reduced ?
  false : {scaleX:0}}` and `transition={reduced ? {duration:0} : {...}}`.
  Reference: `overview/SeverityDistribution.jsx`.
- Reduced-motion invariant: **data must be readable immediately** — animations
  decorate, they never gate content.

---

## 4. shadcn primitives (`components/ui/*`)

Vendored (no CDN). USE them; do not hand-roll equivalents. Common APIs:

- `Button` — variants `default|destructive|outline|secondary|ghost|link`; sizes
  `default|xs|sm|lg|icon|icon-xs|icon-sm|icon-lg`. Icon-only ⇒ `aria-label`.
- `Badge` — variants `default|secondary|destructive|outline|ghost`. Tint with a
  token text class: `<Badge variant="outline" className="text-status-pending">`.
- `Card` + `CardHeader/CardTitle/CardContent/...`.
- `Tooltip` — wrap trigger in `<Tooltip><TooltipTrigger asChild>…</TooltipTrigger>
  <TooltipContent>…</TooltipContent></Tooltip>`. `TooltipProvider` is mounted at
  the app root (and in component tests). Add tooltips to icon-only controls,
  KPIs, status pills, MITRE chips.
- `Select`, `Input`, `Textarea`, `Label`, `Progress`, `Table`, `Sheet`,
  `Dialog`, `DropdownMenu`, `ScrollArea`, `Separator`, `Skeleton`, `Sonner`.
- Toasts: use the store `addToast(msg, type)` (bridged to Sonner) — not raw
  sonner — so tone classes stay token-driven.

`cn()` from `lib/utils` merges classes (clsx + tailwind-merge). Always use it.

---

## 5. Charts (recharts + `--chart-*`)

**Reuse `components/charts/AreaTrend.jsx`** for trend/velocity series; copy its
pattern for new chart types. Every chart MUST have:

- Colour from `var(--chart-N)` props (theme-aware, no hex).
- Legend, interactive tooltip (token-styled custom `content`), **axis labels +
  units**.
- **Empty-data state** (guidance, not a blank canvas) + **>300ms Skeleton** while
  loading.
- **Reduced-motion safe**: `isAnimationActive={!useReducedMotion()}`; data shows
  immediately.
- **A11y fallback**: a one-click data-table view of the same series + an sr-only
  `<figcaption>` summary. (AreaTrend ships both.)
- AA contrast in both themes; grid/axis use `var(--border)` / `var(--muted-
  foreground)`.

Range toggles live in the *card* wrapper (see `overview/VelocityCard.jsx`), the
chart owns presentation.

---

## 6. Routing & navigation (URL-hash)

`hooks/useHashRoute.js` — the zustand store (`activeTab`) is the in-memory source
of truth; `location.hash` (`#/<tab>`) is the reflected state + entry channel.

- **Intentional navigation** (nav click, palette, KPI, row click): call
  `navigateToTab(setActiveTab, '<tab>')` — pushes a real history entry.
- The hash router **validates `#/<tab>` ids and strips query strings**. To deep-
  link to a *filtered* view, navigate to the tab AND set the store filter:
  ```js
  setFindingsFilter('pending'); navigateToTab(setActiveTab, 'findings')
  ```
  Reference: `overview/KpiRow.jsx`. Don't put `?status=` in the hash — it won't
  route.
- Valid tab ids come from `lib/nav.js` (`VALID_TABS`). Add new destinations
  there, not ad hoc.
- **IA grouping (RUN-4a).** The 11 destinations are grouped Mission-Control style
  in `NAV_GROUPS`: **COMMAND** (Overview) · **INVESTIGATION** (Findings, Timeline,
  Evidence, Hosts, Accounts) · **OPERATIONS** (IOCs, TODOs, Backends, Reports,
  Settings). Active item = orange (`bg-primary/15 text-primary` + orange rail).

**Shell composition (RUN-4a re-skin, tokens-only).** `AppShell` = `SideNav` +
(`Header` → `<main>` → `StatusBar`).
- `SideNav`: brand **"Protocol SIFT Gateway / OPERATIONS PORTAL"** (RUN-4b: the
  brand wraps to two lines, sized up + bright — it must never truncate) →
  agent-state panel (`CLAUDE · AGENT` · state · *N gated actions queued*, derived
  via `deriveAgentState()` so it agrees with the hero + StatusBar) → grouped nav →
  operator footer (name · role · CAN ACT / VIEW ONLY · `ThemeToggle` · sign-out).
  Collapses to icon-only <1024; the collapse control is the `ChevronsLeft` /
  `ChevronsRight` console glyph (RUN-4b).
- `Header`: multi-case selector chip (mono id + name + status dot) with a
  dropdown of cases (active / inactive / **sealed** lifecycle badges + "Create
  case") wired to the unchanged activate-challenge / create flows · centered
  "Search · jump ⌘K" palette trigger · agent mini-indicator.
- `StatusBar`: `AGENT · <state>` · `CUSTODY · <X/Y SEALED>` (→ Evidence) ·
  `MCP X/Y ONLINE` (degraded-toned) · staged-count (→ Commit Drawer) · last-sync ·
  `WCAG AA` · `PORTAL v3`. SEALED-X/Y + MCP-online counts come from
  `statusCounts(portalState, chainStatus)` (RUN-4b).

---

## 7. State, RBAC & file structure

**Store (`store/useStore.js`)** — slice-organized, single flat surface pinned by
`useStore.interface.test.js`. Read with `useStoreSlice(selector)` (shallow). Do
NOT add top-level keys for derived data — derive in `*-metrics.js`/`*-utils.js`
from existing slices (Overview derives all KPIs/series from `findings/delta/
summary`). Data arrives via `hooks/useDataPolling` (15s).

**RBAC** — `lib/auth-context.js` `useAuth()` → `{ status, user, login, logout }`;
`user` is also mirrored into `store.user` for feature components. Gate by role:
```js
const canReview = (user?.role || '').toLowerCase() === 'examiner'
```
Examiners review/stage/edit/commit; readonly users get a read-only view with
actions **hidden** and an explicit reason (e.g. "Read-only — sign in as an
examiner to review"). Reference: `findings/FindingsTab.jsx` + `FindingDetail.jsx`.

**File structure / decomposition**
```
components/<feature>/
  <Feature>Tab.jsx        # orchestrator: store wiring, handlers, layout
  <SubComponent>.jsx      # list / row / detail / filters / controls
  <feature>-utils.js      # PURE helpers + token-class maps (no JSX, no store)
components/charts/         # shared recharts wrappers
components/ui/             # vendored shadcn primitives (do not restyle ad hoc)
```
- **One component export per `.jsx`** (ESLint `react-refresh/only-export-
  components`). Internal sub-components stay unexported in the same file.
- **Put exported helper functions in `.js` modules** (no component in the file),
  so the rule doesn't fire and the logic is unit-testable. Constants may be
  co-exported with a component (allowConstantExport), but prefer the `.js` home.
- ≤400 lines/file. The delta/api contract (`POST /api/delta` replaces the WHOLE
  document) is preserved by `findings-utils.js` builders — reuse them.

---

## 8. Security / XSS discipline (codeguard)

- No `dangerouslySetInnerHTML` on untrusted data. Render finding/report text as
  escaped React children. Result previews go in `<pre>` as text.
- No raw hex; no inline styles except data-driven token-var numerics.
- Lucide icons only; no external origins (chips don't link out — CSP stays
  `'self'`). External links, if ever needed, require `rel="noopener noreferrer"`.
- No secrets/tokens/DSNs in client code or bundle. Auth/crypto/EvidenceUnseal are
  a behavior-preserving PORT (spec §6) — changes need operator + security sign-off.
- `aria-live` for async/toast/error regions; error messages state cause + fix.

---

## 9. Accessibility & UX checklist (per component)

- focus-visible ring on every interactive element; keyboard reachable.
- Tables: `overflow-x-auto` wrapper, `.tnum` numerics, sortable headers carry
  `aria-sort` when sortable.
- Empty states: icon + message + next action (never blank space).
- Loading: Skeleton for >300ms loads.
- Destructive actions confirmed (see `CommitDrawer` hold-to-commit).
- Responsive at 375 / 768 / 1024 / 1440; sidebar collapses <1024.
- Bulk actions: checkbox column + action bar (see `FindingsList`).

---

## 10. Test conventions (vitest + jsdom)

- **Pure logic** (`*-utils.js`, `*-metrics.js`) gets fast deterministic unit
  tests with a fixed `now`. Reference: `test/findingsUtils.test.js`,
  `test/overviewMetrics.test.js`.
- **Components** render with `TooltipProvider`, seed state via
  `useStore.setState({...})`, shim `window.matchMedia` (framer `useReducedMotion`),
  and `vi.mock('../api/endpoints', …)` for network. Reference:
  `test/OverviewTab.test.jsx`, `test/FindingsTab.test.jsx`.
- Baseline suites MUST stay green; `useStore.interface` + `EvidenceUnseal` stay
  byte-identical.

---

## 11. DEV-only mock (visual sign-off)

To review a tab populated without a backend: `npm run dev` then open with
`?mock=1` (toggle theme in the SideNav footer). Gated strictly by
`import.meta.env.DEV && ?mock`; fixtures load via dynamic `import()`
(`src/_mock/`) and are tree-shaken out of production (`npm run build` dist
contains none). A runtime flag (`window.__SIFT_MOCK__`) makes `useDataPolling`
skip so fixtures aren't clobbered. Use this for screenshots; never ship mock data
paths into feature logic.

---

## 12. Mission Control & agent Command-and-Control (RUN-4b)

**The store surface stays frozen.** Agent state, gated actions and backend health
ride on the EXISTING `portalState` slice (DB authority; `setPortalState`) — never
a new top-level key. The contract + pure selectors live in `lib/agent-state.js`
(JSDoc documents the `portalState` shape: `agent{state,headline,metrics}`,
`gated_actions[]`, `backends{up,total,degraded}`, `evidence{sealed,total}`,
`iocs`, `severity{open,awaiting}`). All selectors degrade gracefully when
`portalState` is null. The dev mock supplies a matching `portalState`; a backend
populates the same field later. **No fabricated security claims** — "Review &
authorize" surfaces a step-up notice, it does not perform a real authorization.

**Overview = Mission Control** (`overview/OverviewTab.jsx`): an agent-supervision
landing. The hero row is `AgentHero` (living orb + agent state + count-up stat
strip + `MiniSparkline`) beside `MissionStats` (the 2×2 KPI tiles: Evidence
sealed/total · High severity · IOCs · MCP backends up/total + degraded), with
`AuthorizationQueue` — the gated MCP actions the agent CANNOT self-approve — as
the page hero. The RUN-3 analytics are retained below (findings `KpiRow`,
finding-velocity, severity distribution, recent activity, evidence-chain, MITRE,
case brief). Tiles + the agent state read only `portalState` + existing slices.

**Findings agent-C2** (`findings/`): `ConfidenceRing` renders a GRADED ring
(≥85 jade · ≥65 amber · else crimson — graded, not branded; `confidenceScore()`
maps the categorical confidence when no numeric `confidence_score` exists; stroke
is a token CSS var). MITRE ATT&CK technique chips (mono T-codes) sit in the detail
header. Review keyboard is **`j/k` move · `a` approve · `s` stage · `r` reject**;
the action bar is Approve / Stage / Reject. `stage` is a delta action (violet),
committed through the unchanged `CommitDrawer`.

**Ambient field** (`.ambient` in `styles/globals.css`): a faint orange aurora
(`color-mix(in oklab, var(--primary) …%, transparent)` — token-derived, no raw
hex) + drifting hairline grid (`var(--border)`), low opacity, behind the Overview
content. **Both layers' motion is gated by `prefers-reduced-motion`.** Mount it as
`<div className="ambient" />` inside a `relative isolate` wrapper with the content
at `z-10`.
