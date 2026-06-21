# SIFT Examiner Portal — AI Agent Contract
# Read this before writing a single line. All agents: Claude Code, Codex, Gemini.
# This file lives at the root of BOTH the Design project AND the codebase.

---

## 1. What this codebase is
A React + Vite + Tailwind v4 + shadcn/ui forensic operations portal.
Dark-first. Two themes (dark default, light via .dark class removal on html).
Multi-agent AI ops tool — every UI decision affects analyst trust and safety.
Design-first workflow: screens are designed before they are coded.

## 2. Canonical files — read these before every session
- `src/styles/tokens.css`      → ALL color decisions. 3 layers. Never bypass.
- `src/styles/globals.css`     → Tailwind @theme mapping + base styles
- `DESIGN-SYSTEM.md`           → Layout rules, component patterns, scroll model
- `src/lib/nav.js`             → Tab registry (add new tabs here first)
- `src/lib/agent-state.js`     → All agent state logic lives here ONLY
- `src/store/useStore.js`      → Global store. Read via useStoreSlice() only.

## 3. Absolute rules — never break these
- NO raw hex values           → only var(--token) or Tailwind token utilities
- NO new semantic colors      → use --sev-* --status-* --grade-* --chart-*
- NO relative imports         → always @/ path aliases
- NO calc(100vh - Npx)        → use h-full; AppShell handles shell dimensions
- NO god components           → hard limit 400 lines per file; decompose beyond
- NO isMock inside handlers   → mock/real split at the API adapter layer only
- NO business logic in UI     → pure logic → lib/; state → store/; UI → components/
- NO interpolated class names → never template-literal Tailwind classes (JIT won't see them)
- NO useStore() directly      → always useStoreSlice() with useShallow

## 4. Typography rules
- `font-display` class  → Space Grotesk → h1, page titles, stat numerals, wordmark
- default (no class)    → Inter         → all body copy, labels, UI controls
- `mono` class          → JetBrains Mono → IDs, hashes, timestamps, badges, code, section labels

## 5. Color token layers
```
Layer 1 primitives:  --bg-void/base/surface/raised/overlay
                     --text-bright/primary/muted/ghost
                     --border-faint/soft/hard
                     --orange --jade --amber --crimson --violet --steel

Layer 2 shadcn:      --background --foreground --card --primary --secondary
                     --muted --accent --border --ring --destructive

Layer 3 forensic:    --sev-high (crimson)  --sev-med (amber)   --sev-low (steel)
                     (severity is High/Med/Low only — the old --sev-spec/violet tier was dropped)
                     --status-approved (jade)  --status-pending (amber)
                     --status-staged (violet)  --status-rejected (crimson)
                     --grade-full (jade, ≥85%)  --grade-partial (amber, ≥65%)  --grade-none (ghost, <65%)
                     --chart-1 (orange) --chart-2 (steel) --chart-3 (amber) --chart-4 (violet) --chart-5 (jade)
```

CRITICAL: Tailwind JIT needs literal class strings.
❌ className={`text-${sev}`}           → class will NOT be generated
✅ Use a pre-built literal class map    → see CONF_CLASS in findings-utils.js

## 6. How to add a new tab
1. Add entry to `src/lib/nav.js` NAV_GROUPS
2. Create `src/components/[tabId]/[TabId]Tab.jsx` (≤400 lines)
3. Add import + branch in `AppShell.jsx` TabContent()
4. Use `OverviewTab.jsx` as the reference pattern
5. Use `MasterDetailLayout` for any list+detail screen (avoids scroll bugs)
6. Use `h-full` on tab root div (never calc heights)

## 7. File size limits
- Tab components:    ≤ 400 lines
- Hook files:        ≤ 150 lines
- Utility files:     ≤ 200 lines
- If a file exceeds limits: decompose before adding more features

## 8. Scroll architecture
- One primary scroll owner per tab (the tab root or one pane)
- Master-detail tabs: both panes independently scrollable with `min-h-0 overflow-y-auto`
- Never set `overflow: hidden` on a container without explicit intent
- `overscroll-behavior: contain` on independently scrolling panes only

## 9. Copy-paste session starter
Paste this at the start of every new coding session:

```
Read AGENTS.md, DESIGN-SYSTEM.md, and src/styles/tokens.css before writing any code.
Follow all rules in those files strictly.
Use @/ imports. No raw hex values. No god components. No calc(100vh) hacks.
Reference OverviewTab.jsx as the component pattern.
Wire new tabs in AppShell.jsx after building them.
```

## 10. Audit status
`04-handoff/AUDIT-RUN1.md` was run against an EARLIER code snapshot
(`frontend/untitled folder/src/`), NOT the current branch — treat its bug list
as stale. Re-audit against the live branch `portal-v3/p0-foundation` HEAD before
fixing anything. Known-resolved since that audit:
- `--sev-spec` tier DROPPED (not "add it"). High/Med/Low only; historical
  SPECULATIVE findings fold into LOW for backward compat.
- Severity scroll/`calc(100vh)` rules: enforce §8 here; verify per-tab on HEAD.
