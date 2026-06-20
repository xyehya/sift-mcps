# Portal v3 — Coverage Map (Phase 0, through RUN-4b)

Proves: all 11 nav destinations present · spec §8 parity flows still work ·
RUN-3 reference-tab features preserved · RUN-4b agent Command-and-Control
features added. "Built" = a real component renders; "Placeholder" = the on-brand
`TabPlaceholder` until its Phase-1 feature agent builds it (shell + routing are
wired). Nothing here regresses the frozen store/api/test surfaces.

## 1. The 11 destinations (`lib/nav.js` `NAV_GROUPS`)

| Group | Tab | State | Notes |
|---|---|---|---|
| COMMAND | Overview | **Built → Mission Control** | RUN-4b hero + auth queue + tiles + RUN-3 analytics |
| INVESTIGATION | Findings | **Built** | RUN-3 + RUN-4b MITRE chips / confidence ring / a·s·r |
| INVESTIGATION | Timeline | Placeholder | routes; Phase-1 (EVID-adjacent) |
| INVESTIGATION | Evidence | Placeholder | routes; EvidenceUnseal contract preserved |
| INVESTIGATION | Hosts | Placeholder | routes; Phase-1 (ENTITY) |
| INVESTIGATION | Accounts | Placeholder | routes; Phase-1 (ENTITY) |
| OPERATIONS | IOCs | Placeholder | routes; mission tile deep-links here |
| OPERATIONS | TODOs | Placeholder | routes; sidebar open-todo badge live |
| OPERATIONS | Backends | Placeholder | routes; mission tile deep-links here |
| OPERATIONS | Reports | Placeholder | routes; Phase-1 (REPORT) |
| OPERATIONS | Settings | Placeholder | routes |

All 11 ids are in `VALID_TABS`; SideNav + command palette + hash router all
resolve them. `AppShell.TabContent` renders Overview + Findings; the rest fall to
`TabPlaceholder`.

## 2. Spec §8 parity flows (still work)

| Flow | Where | Status |
|---|---|---|
| Auth login / me / logout (Supabase) | `api/endpoints` + `lib/auth*` | unchanged port |
| Case activate (challenge → re-auth) | `layout/CaseDialogs.ActivateCaseDialog` | unchanged; now reachable from the enriched multi-case dropdown |
| Case create (auto-activate) | `layout/CaseDialogs.CreateCaseDialog` | unchanged; dropdown label "Create case" |
| Findings list / filter (status·host·account·search) | `findings/FindingsList` + `findings-utils.filterFindings` | unchanged |
| Findings review approve / reject / **stage** | `findings/FindingDetail` + `FindingsTab` | approve/reject preserved; **stage** added (delta action) |
| Inline field edit (delta diff) | `findings/EditableField` | unchanged |
| Commit staged delta (password + 3s hold) | `layout/CommitDrawer` | unchanged security contract; `stage` action gets violet meta |
| `/api/delta` POST-replaces-whole-document | `findings-utils` builders | unchanged |
| Evidence chain seal / **unseal** crypto | `api/endpoints` + `EvidenceUnseal.test` | **byte-identical**, green |
| Command palette ⌘K | `layout/CommandPalette` + `useHotkey` | unchanged |
| URL-hash deep-linking `#/<tab>` | `hooks/useHashRoute` (LOCKED) | unchanged |
| RBAC examiner vs readonly (actions hidden) | `FindingsTab`/`FindingDetail` + `SideNav` footer | unchanged |
| Theme dark / light (token swap, AA) | `lib/theme` + `tokens.css` | unchanged; both themes screenshotted |
| 15s data poll (mock-aware skip) | `hooks/useDataPolling` | unchanged |

Store interface contract: `useStore.interface.test.js` **byte-identical**, green —
no top-level key added/removed (agent/case/backend state rides on `portalState`).

## 3. RUN-3 Overview features (preserved on the Mission-Control page)

Findings `KpiRow` (4 click-through KPIs) · finding-velocity `VelocityCard`
(recharts draw-on, reduced-motion safe, table a11y fallback) · `SeverityDistribution`
(now wires `severityBarFill`) · `ActivityFeed` (now wires `activityTailItem`) ·
`EvidenceChainSummary` (deep-links; **manifest version number removed**) ·
`MitreMatrix` · `CaseContextCard` · empty/no-case state.

## 4. RUN-4b agent Command-and-Control (added)

| Feature | Component / file | Motion / tokens |
|---|---|---|
| Agent-state hero | `overview/AgentHero` | `breathingOrb`+`pingRing`(×2), `authGlowPulse`, `useCountUp`×3, `statusDotPulse` |
| Finding-velocity glance | `overview/MiniSparkline` | `chartDraw` (motion.path), `--chart-1` |
| Authorization Required queue (hero) | `overview/AuthorizationQueue` | risk token classes; "Agent cannot self-approve" |
| Mission KPI tiles | `overview/MissionStats` | `useCountUp`, `statusDotPulse` (degraded), deep-links |
| Graded confidence ring | `findings/ConfidenceRing` | `chartDraw`-style draw; token stroke (jade/amber/crimson) |
| MITRE ATT&CK chips | `findings/FindingDetail` | mono T-codes |
| `a/s/r` keyboard + Stage button | `FindingsTab` + `FindingDetail` | — |
| Multi-case switcher (active/inactive/sealed + Create) | `layout/Header` | tolerant of `{id,active}`-only backends |
| Live SEALED X/Y + MCP X/Y ONLINE | `layout/StatusBar` | `statusCounts()` |
| Contract + selectors | `lib/agent-state.js` | pure; degrades w/o portalState |
| Ambient field (aurora + grid) | `styles/globals.css` `.ambient` | `color-mix(var(--primary))`, reduced-motion gated |

## 5. Polish notes (operator) — done

1. Manifest **version number removed** from the Evidence-chain card (`EvidenceChainSummary`).
2. Brand **"Protocol SIFT Gateway" no longer truncates** — wraps to 2 lines, sized up + bright (`SideNav`).
3. Round-1 **ambient background glow** re-added (faint orange aurora + drifting hairline grid, token-based, reduced-motion gated).
4. Sidebar collapse toggle uses a **console glyph** (`ChevronsLeft` / `ChevronsRight`), not a generic minimize.

## 6. Gate

`npm run build` green · dist hygiene clean (no external fonts, no inline
`<style>`, no mock-fixture leakage) · `npm run lint` authored-clean (legacy
feature-file debt only) · `npm test` 144 passing (14 files), incl. new
`agentState` / `confidence` / `MissionControl` suites, with `EvidenceUnseal` +
`useStore.interface` byte-identical · screenshots in `design/r4b-screens/`.

## 7. Conscious deferrals

- StrictMode double-mount of `useHashRoute` (RUN-4a note E): NOT changed — routing
  is LOCKED (§6) and the behaviour is dev-only StrictMode noise; touching it risks
  the locked deep-link contract. Flagged for a routing-owner pass, not RUN-4b.
