# SIFT Examiner Portal v3 — Ground-Up Rebuild Spec

> Covers: packages/case-dashboard/frontend/**
> Class: point-in-time
> Last validated: 93f8999 (2026-06-26)

**Status:** APPROVED FOR BUILD (design + scope locked) · **Date:** 2026-06-20
**Owner:** Yehya (operator) · **Build mode:** orchestrated agent team, new session
**Package:** `packages/case-dashboard/frontend` · served by gateway (`case_dashboard`)

> This document is the single source of truth for the v3 rebuild. The build
> session orchestrator and every spawned agent MUST read this first and conform
> to it exactly. Deviations require operator approval.

---

## 0. Decisions (locked)

| Axis | Decision |
|---|---|
| Visual identity | **Graphite Emerald** — near-black slate, emerald accent, data-forward, modern, smoothly animated |
| Themes | **Dark + Light**, token-driven, system-aware, persisted |
| Component foundation | **shadcn/ui** (vendored copy-in, no CDN) on Vite + React 19 + **Tailwind 4** |
| Tailwind version | **Tailwind 4** (kickoff decision 2026-06-20). Rebuild ⇒ no migration churn; CSS-first `@theme` *is* the single-token-source mandate (fixes defect #1); drops `autoprefixer`/`postcss-import` (smaller supply chain); shadcn defaults to TW4. See §10. |
| Tab routing | **URL-hash deep-linking** (`#/findings`) — kickoff decision 2026-06-20. Shareable/bookmarkable, back-button works. |
| P0 checkpoint | **Hard stop after Phase 0** for operator visual sign-off on Overview+Findings (both themes) before parallel fan-out — kickoff decision 2026-06-20. |
| Scope | **Ground-up rebuild of EVERYTHING** — shell, components, state, api, hooks. Auth/JWT/crypto = careful **port** (see §6), not blind rewrite |
| Motion | framer-motion, rich but disciplined, `prefers-reduced-motion` honored |
| Type | **Inter** (UI) + **Fira Code** (forensic data: hashes, IDs, timestamps, paths). **Self-hosted** (`@fontsource`) |
| Security | Self-host fonts + kill inline styles ⇒ tighten CSP to `'self'`. codeguard on all agents. Dedicated security agent final verdict |
| Reference (rejected) | Current dark-cyan-on-navy "forensic terminal". Do NOT reproduce its look, density, token drift, or inline-style pattern |

---

## 1. What exists today (baseline to replace)

- Stack: React 19, Vite 8, Tailwind 3, zustand 5, recharts 3, cmdk, date-fns. Hand-rolled, no component lib.
- 11 tabs on a 72px icon rail: Overview, Findings, Timeline, Evidence, Hosts, Accounts, IOCs, TODOs, Backends, Reports, Settings.
- Served as a static build by the gateway from `src/case_dashboard/static/v2/`; SPA fallback + CSP set in `src/case_dashboard/routes.py` (~line 3833–3856).
- **Known defects to eliminate (do not carry forward):**
  1. **Token drift** — colors defined twice and disagree (`index.css :root` vs `tailwind.config`: e.g. `--text-primary #e2e8f0` vs `#c8d4f0`). v3 has ONE token source.
  2. **Inline-style soup** — pervasive `style={{...}}` + JS hover (`onMouseEnter/Leave`). Forces CSP `style-src 'unsafe-inline'`. v3 uses classes/tokens only.
  3. **Monolith components** — EvidenceTab 1691, FindingsTab 1380, ReportsTab 1121, BackendsTab 808 lines. v3 decomposes.
  4. Cramped 13px base, no real type scale, weak elevation, dark-only.
- **Working plumbing to PRESERVE-BY-CONTRACT (port, keep external shape):** `src/store/useStore.js`, `src/api/{client,endpoints,crypto}.js`, `src/hooks/{usePolling,useDataPolling}.js`, auth flow (`getMe`, login, case activate/create challenge), session-envelope cookie + Supabase JWT (backend `session_jwt.py`, `auth.py`).
- Tests (vitest): `CommandPalette`, `SessionChanges`, `useStore.interface`, `EvidenceUnseal`, `BackendsTab`. v3 rewrites these against new components; `useStore.interface` semantics preserved.

---

## 2. Graphite Emerald — design tokens (authoritative)

shadcn CSS-variable convention. Agents copy these verbatim into `src/styles/tokens.css` (or `globals.css`). **No raw hex in components — tokens only.**

### Dark (default)
```
--background:#020617;  --foreground:#F8FAFC;
--card:#0E1223;        --card-foreground:#F8FAFC;
--popover:#0E1223;     --popover-foreground:#F8FAFC;
--primary:#22C55E;     --primary-foreground:#04130A;
--secondary:#131A2E;   --secondary-foreground:#E2E8F0;
--muted:#131A2E;       --muted-foreground:#94A3B8;
--accent:#16A34A;      --accent-foreground:#F8FAFC;
--destructive:#EF4444; --destructive-foreground:#FFFFFF;
--border:#1E293B;      --input:#1E293B;  --ring:#22C55E;
--radius:0.75rem;
/* forensic semantics */
--sev-high:#EF4444; --sev-med:#F59E0B; --sev-low:#38BDF8; --sev-spec:#A78BFA;
--status-approved:#22C55E; --status-pending:#F59E0B; --status-staged:#818CF8; --status-rejected:#EF4444;
--grade-full:#22C55E; --grade-partial:#F59E0B; --grade-none:#64748B;
--chart-1:#22C55E; --chart-2:#38BDF8; --chart-3:#F59E0B; --chart-4:#A78BFA; --chart-5:#EF4444;
```

### Light
```
--background:#F8FAFC;  --foreground:#0F172A;
--card:#FFFFFF;        --card-foreground:#0F172A;
--popover:#FFFFFF;     --popover-foreground:#0F172A;
--primary:#16A34A;     --primary-foreground:#FFFFFF;
--secondary:#F1F5F9;   --secondary-foreground:#0F172A;
--muted:#F1F5F9;       --muted-foreground:#566173;
--accent:#15803D;      --accent-foreground:#FFFFFF;
--destructive:#DC2626; --destructive-foreground:#FFFFFF;
--border:#E2E8F0;      --input:#E2E8F0;  --ring:#16A34A;
/* forensic semantics (light-tuned for WCAG AA) */
--sev-high:#DC2626; --sev-med:#D97706; --sev-low:#0284C7; --sev-spec:#7C3AED;
--status-approved:#16A34A; --status-pending:#D97706; --status-staged:#6366F1; --status-rejected:#DC2626;
--grade-full:#16A34A; --grade-partial:#D97706; --grade-none:#94A3B8;
--chart-1:#16A34A; --chart-2:#0284C7; --chart-3:#D97706; --chart-4:#7C3AED; --chart-5:#DC2626;
```

### Type & scale
- `--font-sans: Inter`; `--font-mono: "Fira Code"`. Self-hosted via `@fontsource/inter`, `@fontsource/fira-code`. **No `fonts.googleapis.com` / `gstatic` anywhere.**
- Base **15px** body (not 13px). Type scale: 12 / 13 / 15 / 18 / 22 / 28 / 36. Tabular figures (`font-feature-settings:"tnum"`) for all numeric/data columns.
- Mono reserved for: hashes, case IDs, finding IDs, timestamps, file paths, IPs, registry keys.

### Motion (shared variants — define once, reuse)
- Easing `cubic-bezier(0.16,1,0.3,1)`; micro 150–220ms; modal spring (damping ~20, stiffness ~90); list/grid stagger 35–50ms/item; exit ~65% of enter.
- Transform/opacity only (never width/height/top/left). Entrance: rise+fade. Cards: hover lift `translateY(-3px)` + ring glow. Bars/charts animate on mount.
- **All motion wrapped to respect `prefers-reduced-motion: reduce` → no transforms/animations, content visible immediately.**

### UX rules (from ui-ux-pro-max — non-negotiable)
- Lucide SVG icons only (no emoji as icons). Consistent stroke/size tokens.
- Tooltip "hints" via Radix Tooltip on icon-only controls, KPIs, status pills, MITRE chips.
- Focus-visible rings on every interactive element. Keyboard nav, aria-labels, `aria-live` for toasts/errors.
- Contrast AA both themes. cursor-pointer on clickables. Skeletons for >300ms loads. Empty states with guidance. Confirm destructive actions. Error messages state cause + fix.
- Responsive: 375 / 768 / 1024 / 1440. Sidebar ≥1024; collapsible below.

---

## 3. Architecture (target)

```
src/
  main.jsx, App.jsx
  styles/ tokens.css, globals.css
  lib/ utils.js (cn), motion.js (variants), theme.jsx (provider+toggle)
  components/ui/        # shadcn primitives (vendored)
  components/layout/    # AppShell, Header, SideNav, StatusBar, CommandPalette, CommitDrawer, ThemeToggle
  components/<feature>/ # decomposed per tab (no >400-line files)
  store/   useStore.js  # zustand — ported, slice-organized
  api/     client.js, endpoints.js, crypto.js  # ported, contract-preserved
  hooks/   usePolling, useDataPolling, useTheme, useHotkeys
  test/    vitest specs (rewritten)
```

- **shadcn primitives to vendor (Phase 0):** button, card, dialog, sheet, dropdown-menu, tooltip, popover, input, label, textarea, select, tabs, table, badge, sonner (toast), command, skeleton, scroll-area, separator, progress, avatar, alert, alert-dialog, switch, tooltip-provider.
- **Deps added:** `tailwindcss@4` + `@tailwindcss/vite` (TW4 Vite plugin — replaces the postcss pipeline; **remove `autoprefixer` + `postcss-import`**, built into TW4), `tw-animate-css` (TW4 successor to `tailwindcss-animate`), `class-variance-authority`, `tailwind-merge`, `clsx` (have), `lucide-react`, `framer-motion`, `@fontsource/inter`, `@fontsource/fira-code`. Keep `recharts`, `cmdk`, `zustand`, `date-fns`. Pin exact versions; commit lockfile.
- **TW4 config model:** CSS-first. Tokens live in `tokens.css`/`globals.css` via `@theme` (+ `@layer base` `:root`/`.dark` for the two themes); **no `tailwind.config.js` color duplication** — this is the single-token-source guarantee. Dark mode via `@custom-variant dark (&:where(.dark, .dark *))`.
- **Theme:** class strategy — provider reads system + localStorage, sets `.dark`/`.light` class + `data-theme` on `<html>`. Toggle in header.
- **Charts:** recharts wrapped via shadcn chart pattern using `--chart-*` tokens. Each chart: legend, tooltip, empty state, skeleton, reduced-motion-safe, AA contrast, table-alt where feasible.
- **Routing/tabs:** **URL-hash deep-linking** (locked) — `activeTab` synced to `location.hash` (`#/findings`), browser back/forward works, links shareable. Store stays the source of truth in-memory; hash is the reflected/entry channel.

---

## 4. Information architecture (Overview redesign)

Keep all 11 destinations. Redesign the Overview landing (the page operator dislikes) to be the rich hero:
- Case header strip: case id (mono) + live chain-status pill + agent status + role badge + theme toggle + ⌘K.
- KPI row (4): Findings / Approved / Pending / Staged (staged → progress + opens Commit Drawer). Click-through to filtered tabs.
- Severity distribution (animated bars) + Finding velocity (recharts area, 7d/24h/all toggle).
- Recent activity feed (time-ranged) + MITRE ATT&CK matrix chips + Evidence chain summary.
- Empty/loading/no-case states designed, not afterthoughts.
SideNav: grouped, labels+icons, active state, badges (pending findings, open todos), collapsible <1024.

---

## 5. Security requirements (the "secure" mandate)

1. **Self-host fonts** — remove all Google Fonts links/`@import`. Bundle via `@fontsource`.
2. **No inline styles** — all styling via Tailwind classes / token vars in CSS. Enables dropping `style-src 'unsafe-inline'`.
3. **Tighten CSP** in `routes.py` to:
   ```
   default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self';
   img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';
   base-uri 'none'; object-src 'none'; form-action 'self'
   ```
   (verify build emits no inline `<style>` requiring nonce; if shadcn/vite injects any, prefer hashed/extracted CSS over `'unsafe-inline'`.)
4. **No new network origins.** shadcn/Radix/framer are vendored or bundled — no runtime CDN.
5. **Auth/JWT/crypto preserved** (§6). No secrets, tokens, or DSNs in client code or bundle.
6. **XSS discipline:** no `dangerouslySetInnerHTML` on untrusted data; sanitize any markdown/report rendering. Mutations carry CSRF/session protection as today.
7. **Dependency surface:** every added dep pinned, in lockfile, justified. Security agent audits Radix/framer/fontsource supply chain.
8. **codeguard skill loaded by every build agent**, applied while writing code (secure-by-default).

---

## 6. Auth/crypto port contract (do NOT reinvent)

Rebuild-everything applies to UI/state, but the auth + crypto layer is security-critical and tested. Treat as a **behavior-preserving port**:
- Preserve external contracts: session-envelope cookie name(s), Supabase JWT handling (`session_jwt.py` server side), `getMe`/login/logout flows, case-activate challenge protocol (DB-authority `{required:false}` vs file-backed re-auth — see old `Header.jsx`), RBAC (examiner vs readonly).
- Preserve `api/crypto.js` scheme and `EvidenceUnseal` semantics exactly (covered by a regression test that must stay green).
- Any change to auth/crypto/RBAC requires operator + security-agent sign-off before merge.

---

## 7. Build phases & agent roles

> Mandatory isolation (CLAUDE.md + memory `reference_agent_worktree_base_bug`):
> orchestrator creates one worktree per agent off the **integrated HEAD**
> (`git worktree add ../wt/<slug> -b <branch> HEAD`), each agent works ONLY in
> its worktree (cd first; all edits / npm / vitest / git there), commits to its
> branch. Orchestrator merges → re-validates → removes worktree. Never two
> writer agents in one tree. Every build agent loads: **codeguard-security**,
> **ui-ux-pro-max**, **caveman**.

### Phase 0 — FOUNDATION (serial, lands first; gates everything)
Single foundation track (1 agent or orchestrator-directed), because parallelizing before the design system is frozen = chaos.
- **F1 Tooling:** shadcn init, add deps, self-host fonts, tailwind config → tokens, `tailwindcss-animate`.
- **F2 Tokens+theme:** `tokens.css` (both themes, §2), theme provider + toggle, `lib/utils cn`, `lib/motion` variants (+ reduced-motion).
- **F3 Primitives:** vendor shadcn components (§3), themed to Graphite Emerald.
- **F4 Shell:** AppShell, Header, SideNav, StatusBar, CommandPalette host, CommitDrawer host, auth gating, tab/route switch.
- **F5 CORE data layer:** port `store/`, `api/`, `hooks/`, auth/crypto per §6 (contract-preserved).
- **F6 Reference tabs:** build **Overview** + **Findings** to spec as the canonical pattern other agents copy.
- **F7 Freeze:** write `design-system/MASTER.md` (ui-ux-pro-max `--persist`); commit. **Phase 0 done = exemplar of all conventions.**

### Phase 1 — FEATURE TABS (parallel, each own worktree off Phase-0 HEAD)
| Agent | Owns | Notes / risk |
|---|---|---|
| **AGENT-EVID** | Evidence, Backends | Heaviest. Evidence = crypto unseal + chain status + seal; preserve `EvidenceUnseal` semantics. Backends = health/manifest. Decompose the 1691/808-line monoliths. |
| **AGENT-ENTITY** | Timeline, IOCs, Hosts, Accounts | Data-table + chart heavy. Shared table/filter primitives. |
| **AGENT-REPORT** | Reports, TODOs, Settings | Reports = generation + render (sanitize). Settings = theme/account/RBAC-aware. |

Each agent: build assigned tab(s) using frozen tokens + shared primitives + motion; **port behavior from old components, preserve store/api contract**; decompose into ≤400-line files; write/port vitest for its tabs; codeguard throughout; commit to branch. No edits outside its tab scope + agreed shared files (coordinate via orchestrator).

### Phase 2 — INTEGRATION (orchestrator + integration agent, serial)
- Merge Phase-1 branches in order, resolve conflicts, re-validate after each.
- Rebuild full vitest suite green; eslint clean; `npm run build` green.
- Wire CSP tighten in `routes.py` (§5); confirm built assets self-only (no inline style / external font).
- `/verify` + `/run` the app; screenshots both themes; responsive pass.

### Phase 3 — SECURITY REVIEW (dedicated security agent → LAST VERDICT)
- **AGENT-SECURITY** loads `codeguard-security` + runs `security-review` skill. Scope: auth flow, `session_jwt`/RBAC, `crypto.js` + EvidenceUnseal, CSP correctness, case activate/create, evidence seal/unseal, new dependency supply chain, secrets-in-bundle scan, XSS/CSRF surface, no inline-style/`unsafe-inline` regressions.
- Output: **verdict (PASS / PASS-WITH-FIXES / FAIL)** + itemized findings + severity. This is the gate. **Operator + orchestrator decide together** on the verdict; remediation loops back to relevant agent.

### Phase 4 — CLOSEOUT
- Validation gate summary. Linear: create project/issue, post CLAUDE.md signoff closeout. Open PR (`Refs`/`Fixes` per completeness). Push only when operator asks.

---

## 8. Validation gates (every phase merge)

- `npm test` (vitest) green · `npm run build` green · `eslint .` clean · codeguard clean.
- **Final additionally:** CSP `'self'`-only verified in served headers + no external font/inline-style in `dist`; both-theme WCAG AA contrast; `prefers-reduced-motion` respected; responsive 375/768/1024/1440; security agent verdict = PASS(-with-fixes resolved).

### Behavior-parity checklist (must all work as before)
auth (login/logout/session expiry redirect) · case switch + create + activate challenge · findings list/filter/review/stage/commit (delta + Commit Drawer) · evidence list/unseal/seal/chain status · reports generate + view · backends health/manifest · hosts/accounts/IOCs/timeline render + filter · TODOs · command palette ⌘K · agent status/pulse · role-based UI (examiner vs readonly).

---

## 9. Orchestrator playbook (next session — my role)

1. Read this spec + `MASTER.md`. Confirm Phase-0 scope with operator.
2. Run **Phase 0** as a single track; validate; freeze design system; operator checkpoint (visual sign-off on Overview+Findings before fan-out).
3. Create 3 worktrees off Phase-0 HEAD; spawn AGENT-EVID / AGENT-ENTITY / AGENT-REPORT with strict per-agent prompts (scope, files, skills to load, isolation rules, parity targets, validation). Run in parallel.
4. As each finishes: merge → re-validate → remove worktree. Intervene on conflicts/parity gaps.
5. Phase 2 integration + CSP. Phase 3 security agent → bring verdict to operator; loop fixes.
6. Phase 4 closeout (Linear + PR). 
7. My posture: orchestration, agent creation, role assignment, final reviews, oversight, intervention — not hand-coding feature work.

### Per-agent prompt skeleton (template)
```
cd <worktree abs path> FIRST. Work only here; commit to <branch>; never touch main checkout.
Load skills: codeguard-security, ui-ux-pro-max, caveman.
Read docs/new-docs/PORTAL_V3_REBUILD_SPEC.md + design-system/MASTER.md. Conform exactly.
Scope: <tabs/files>. Do NOT edit outside scope or shared files without orchestrator OK.
Build with Graphite Emerald tokens (no raw hex), shadcn primitives, shared motion variants.
Port behavior from old <component> preserving store/api contract (§6 for auth/crypto).
Decompose to ≤400-line files. Write/port vitest for your tabs.
Gate before done: vitest green, eslint clean, build green, codeguard clean. Commit + report.
```

---

## 10. Kickoff decisions — RESOLVED (2026-06-20, operator + orchestrator)
- **Tailwind: v4.** Operator delegated conditional on real benefits; orchestrator found them (rebuild ⇒ zero migration churn; CSS-first `@theme` is the single-token-source fix for defect #1; drops autoprefixer/postcss-import → smaller supply chain; shadcn defaults TW4; modern CSS + faster builds; controlled-browser target removes the only risk). See §0 / §3.
- **Deep-linking: URL hash (`#/<tab>`).** Locked. See §3 routing.
- **Phase-0 checkpoint: YES.** Hard stop after P0 builds Overview+Findings; operator signs off on screenshots (both themes) before the 3 feature agents fan out. See §9.
