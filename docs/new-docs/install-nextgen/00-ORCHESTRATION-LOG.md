# Installation Next-Gen — Orchestration Log

**Lead:** Claude (Opus 4.8) · **Started:** 2026-06-19 · **Worktrees:** none (read/doc-only tasks)

## Team

| Agent | Type | Role |
|-------|------|------|
| `Explorer` | feature-dev:code-explorer | Audit install system; produce modernization blueprint (Track A start) |
| `Reviewer` | code-reviewer | Grill blueprint end-to-end: optimized / secure / reusable / idempotent (Track A end) |
| `Inventory` | general-purpose #1 | Track every downloadable asset → endpoint; author inventory doc (Track B) |
| `Auditor` | general-purpose #2 | Review inventory for completeness/accuracy; cycle until cleared (Track B) |

## Track A — Installation Modernization (sequential)

`Explorer` → returns blueprint → lead persists `01-INSTALL-EXPLORATION.md`
→ `Reviewer` grills → lead persists `02-INSTALL-REVIEW.md`
→ lead finalizes `FINAL-INSTALL-BLUEPRINT.md`

## Track B — Download Asset Inventory (cyclic)

`Inventory` writes `03-DOWNLOAD-ASSET-INVENTORY.md`
↔ `Auditor` writes `04-INVENTORY-REVIEW-rN.md` (cycle until "CLEARED")
→ lead persists `FINAL-ASSET-INVENTORY.md` with signoff

## Status

- [x] A1: Explorer dispatched
- [x] A2: Exploration persisted → `01-INSTALL-EXPLORATION.md` (primary, 1262 lines) + `01b-INSTALL-EXPLORATION-ALT.md` (ExplorerW second opinion, 596 lines)
- [x] A3: Reviewer dispatched (grilling 01 vs 01b, D1 baseline, inventory cross-check)
- [x] A4: Review persisted → `02-INSTALL-REVIEW.md` (consolidated Reviewer + Reviewer2; **REVISION REQUIRED** 3 blk/4 maj/2 min + divergence + bonus lock finding; Part A findings/recs + Part B copy-ready patch sets PS1–PS5)
- [x] A5: Final blueprint → `FINAL-INSTALL-BLUEPRINT.md` (5 decisions ratified D2–D6; 8-phase reversible-first roadmap; Linear breakdown proposed) ✅ **TRACK A COMPLETE**
- [x] B1: Inventory dispatched
- [x] B2: Inventory v1 authored (24 assets, 9 gaps G1–G9)
- [x] B3: Auditor review cycle(s) — r1: CHANGES REQUIRED (3 major/6 minor) → Inventory v2 (28 rows, G1-G11) → r2: **CLEARED** (0 blk/0 maj/2 minor); lead applied both nits
- [x] B4: Final signed-off inventory → `FINAL-ASSET-INVENTORY.md` ✅ **TRACK B COMPLETE**

## Decisions (operator)

- **D1 (2026-06-19): Registry publishing is the preferred end-state.** Install-time is NOT air-gapped — the SIFT VM has network during install. Therefore PyPI (workspace packages) + npm/registry (portal frontend) publishing is the RECOMMENDED primary distribution model; `--offline`/air-gap is a SECONDARY supported mode for upgrades/restricted re-installs. Reviewer must judge the blueprint against this. Still honor: system python3.12, no managed-Python, `./install.sh` operator UX preserved (thin bootstrap entrypoint OK).

- **D2 (2026-06-19): Meta-package = Option A.** Flip root `sift-mcps` to a buildable meta-distribution carrying the `core/standard/full` extras (not Option B / extras-on-gateway).
- **D3 (2026-06-19): Registry = PUBLIC PyPI, MIT license.** It's a public hackathon repo. Resolves the public-vs-private pivot → public. Dist-rename is IN (repo is being renamed to `ProtocolSiftGateway` anyway), so `sift-`-prefixed public dist names are adopted (no collision/squat risk).
- **D4 (2026-06-19): Version = hatch-vcs + git tag, line 0.6.2.** Single source of truth; bump the three 0.1.0 packages up; remove `__init__.py` literals.
- **D5 (2026-06-19): Uninstall NEVER wipes case evidence — by design, not just a shim guard.** `install.sh` delegates and never forwards evidence-unlock flags; even the canonical path treats evidence as operator-manual (operator removes `chattr +i` and keeps/deletes `/cases` themselves). Evidence destruction is never an installer action.
- **D6 (2026-06-19): G10 (unpinned RAG feeds) deferred, documented as-is.** Extract/host the ~22 upstream feeds as-is for the current stage; a published-feed release pipeline comes later (post other features). Add honesty note to the blueprint; track as a future fork issue, no fix now.

## Event log

- 2026-06-19 — Workspace created; dispatching Explorer (A1) + Inventory (B1) in parallel (background).
- 2026-06-19 — D1 sent to Explorer live (mid-flight mandate update): prioritize registry publishing over air-gap.
- 2026-06-19 — B3 r1: Auditor returned CHANGES REQUIRED (3 major: M1 missing RAG online-source feeds, M2 CI incomplete, M3 G1 resolvable). Punch-list sent to Inventory for v2.
- 2026-06-19 — Track A FRICTION: read-only `Explorer` (feature-dev:code-explorer) completed analysis but idled 4× without transmitting its blueprint via message; no content delivered. Its only delivery channel (message) is not emitting. CONTINGENCY: spawning write-capable general-purpose `ExplorerW` to redo the audit and write 01-INSTALL-EXPLORATION.md directly. `Explorer` retired.
