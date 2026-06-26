# SIFT Examiner Portal — v3 Design System

> High-fidelity prototype: [`sift-portal-v3.html`](./sift-portal-v3.html)
> Source vision: `~/Downloads/SIFT_Examiner_Portal.pptx` (warm "Mission Control" mockup)
> This system is the **corrected** evolution of that mockup.

## Design brief (operator feedback)

The pptx mockup was directionally right — agent-supervision console, custody-first,
keyboard-driven — but had three problems:

1. **Brown was harsh on the eyes.** Every panel was warm-brown (`#322A20`, `#43392C`),
   so the chrome and the accent shared a temperature and read as one muddy wash.
2. **Orange was over-used.** It flooded the UI instead of meaning something.
3. **It was dead and static.** No motion, no life.

The fix is the premium-dashboard pattern (Linear / Vercel / Raycast):
**neutral graphite ink chrome + ONE warm accent, used sparingly + a real motion layer.**
Warm off-white text keeps it premium rather than clinical.

## Tokens

Mirrors the existing `index.css` variable architecture (same names → drop-in port).

### Surfaces — neutral graphite ink (was warm brown)
| Token | Value | Use |
|---|---|---|
| `--bg-void` | `#0A0A0C` | app canvas / sidebar / statusbar |
| `--bg-base` | `#0E0F12` | main content background |
| `--bg-surface` | `#16171B` | panels / cards |
| `--bg-raised` | `#1C1D22` | rows, inputs, tiles, bar tracks |
| `--bg-overlay` | `#232429` | hover, popovers, command palette |
| `--border-faint` | `#1E1F24` | internal hairlines |
| `--border-soft` | `#2A2B31` | panel borders |
| `--border-hard` | `#3A3C44` | emphasis / hover borders |

### Text — warm off-white (not clinical white)
| Token | Value | Use |
|---|---|---|
| `--text-bright` | `#F2EFEA` | headings, key numerals |
| `--text-primary` | `#CFCCC6` | body |
| `--text-muted` | `#8C8A85` | secondary / labels |
| `--text-ghost` | `#5E5C58` | micro-labels, faint meta |

### Accent — ONE warm hue, reserved for agent · authorize · primary action
| Token | Value | Use |
|---|---|---|
| `--orange` | `#F4754B` | active nav, agent state, primary CTA, focus ring |
| `--orange-bright` | `#FF8A5E` | hover |
| `--orange-deep` | `#D85A33` | gradients / borders |
| `--orange-dim` | `rgba(244,117,75,.12)` | washes / active-nav fill |

**Rule:** if it isn't the agent, an authorization, or the primary action on the page,
it does **not** get orange. This is what "trimmed down" means.

### Semantic hues (meaning defined once)
| Token | Value | Meaning |
|---|---|---|
| `--jade` `#5FB87E` | sealed · online · approved · high-confidence |
| `--amber` `#E0A23E` | warn · medium severity · mid-confidence |
| `--steel` `#6E8BB0` | low severity · informational (cool, recedes) |
| `--violet` `#A795BD` | staged (a STATUS, not a severity) |
| `--crimson` `#E2554C` | high severity · rejected · irreversible (kept redder than orange so they never blur) |

**Severity scale:** HIGH = crimson · MEDIUM = amber · LOW = steel. (High/Med/Low only — there is no fourth severity tier; the old `--sev-spec`/violet tier was dropped. Violet is `--status-staged`, a status.)
**Status scale:** PENDING = ghost-outline · STAGED = violet · APPROVED = jade · REJECTED = crimson.
**Confidence ring:** ≥85 jade · ≥65 amber · else crimson (graded, not branded).

## Typography
- **Display / numerals:** Space Grotesk — characterful but technical (titles, big stats).
- **UI:** Inter.
- **Forensic data:** JetBrains Mono with tabular figures — every hash, ID, timestamp,
  count and ATT&CK technique is monospaced. This is the console's "voice."
- Micro-labels: 10px mono, `letter-spacing:.14em`, uppercase.

## Motion layer (the answer to "dead and static")
| Element | Behaviour |
|---|---|
| Big numerals | count-up on load (easeOutCubic), compact-format aware (`1.28M`) |
| Session timer | ticks every second |
| Agent orb | breathing core + two staggered ping rings |
| Awaiting-auth hero | slow orange glow pulse (3.4s) |
| Severity bars | width fills on load, staggered |
| Finding velocity | SVG path draw-on + live point push every 6s + pulsing NOW dot |
| Agent activity | streaming tail — prepends a new line every ~4.2s with slide-in, capped at 14 |
| MCP / status dots | jade pulse; degraded `yara` blinks amber |
| Ambient field | faint orange aurora + drifting hairline grid, very low opacity |
| Hover | cards lift 2px + border brighten; everything interactive has `cursor-pointer` |

**All non-essential motion is gated by `prefers-reduced-motion`** (count-up snaps to final,
streaming pauses, animations collapse to ~0ms).

## Interaction
- `⌘K` / `Ctrl-K` — command palette (jump to views, findings, hosts, evidence, IOCs).
- Findings review: `j/k` move · `a` approve · `s` stage · `r` reject · click to select.
- Deep-links: `#overview` / `#findings`.

## Porting to the React app
The token names match `frontend/src/index.css` and `frontend/tailwind.config.js`.
To adopt: replace the **values** of `--bg-*`, `--border-*`, `--text-*`, and the accent
(swap `--cyan` → `--orange` as the primary), keep the semantic `--status-*` / `--sev-*`
indirection. Add Space Grotesk + JetBrains Mono to the font import. The motion layer maps
to small hooks (count-up, the live-tail interval already exists as `usePolling`).

## Known prototype caveats
- Loads Tailwind Play CDN + Lucide + Google Fonts (no SRI — they're dynamic `@latest`).
  The production port uses the pinned npm deps already in `package.json`, removing the
  CDN/SRI concern entirely. Do **not** ship the CDN HTML to production as-is.
- Data is illustrative (the NORTHWIND case), hard-coded in the file.
