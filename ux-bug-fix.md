# DFIR Portal — UX Fix Plan (Validated)

**Portal:** `https://192.168.122.81:4508/portal/` · **Frontend:** `packages/case-dashboard/frontend/src/`
**Method:** Every item below was checked two ways — (1) rendered in Chrome against the live `rocba-drive-20260526-1417` case, and (2) traced to source with `file:line`. This supersedes `dfir-portal-fix.md`.

## How to read this

Each item: `ID · STATUS · Issue · Root cause (file:line) · Fix · Outcome`

- **CONFIRMED** — reproduced; the original fix stands (sometimes sharpened).
- **REVISED** — the symptom is real but the original *diagnosis or fix* was wrong; corrected here.
- **REJECTED** — not reproducible / contradicted by code or pixels. Kept on the list so you don't re-open it. Do **not** implement.

Items that changed verdict vs. the original assessment: BUG-002, BUG-003, BUG-005, CLR-002, CLR-003, TYP-001, COH-002, EMP-001, EMP-002.

> **Verification note:** items citing `Header.jsx`, `StatusBar.jsx`, and `FindingsTab.jsx` (TYP-002, NAV-001/002/003, BUG-004, COH-001) were verified **by rendered pixels**; the file is named from the component map but exact line numbers weren't opened — the dev should confirm on open. All other `file:line` references were read directly.

---

## 0 · Foundation first (do these before the item-by-item pass)

Several "bugs" below are symptoms of three missing system-level decisions. Fixing the foundation collapses ~8 items into 3 edits.

### F-1 · Semantic status/severity/grade tokens
`index.css` defines only raw hues (`--cyan --amber --crimson --jade --violet`). Components reach for them directly, so "approved" is `var(--jade)` in five files and "staged"/"pending" are *both* `var(--amber)`. Add a semantic layer and migrate usages:

```css
:root {
  /* status */
  --status-approved: var(--jade);
  --status-pending:  var(--amber);   /* "draft" / needs review */
  --status-staged:   var(--violet);  /* uncommitted — currently unused token */
  --status-rejected: var(--crimson);
  /* severity */
  --sev-high: var(--crimson);
  --sev-med:  var(--amber);
  --sev-low:  var(--text-muted);
  /* grade */
  --grade-full:    var(--jade);
  --grade-partial: var(--amber);
  --grade-none:    var(--text-ghost);
}
```
This single block resolves **CLR-001** and pre-empts **CLR-003**.

### F-2 · An icon system (kills a whole class of "broken character" bugs)
The UI renders status icons as **Unicode emoji/symbols** — `⛓ ⚠ ✓ ⏳ ▲ ◆ ○ ⊠`. On the SIFT VM these have **no font coverage and render as tofu boxes** (this is the true cause of EMP-002 — see proof there). Replace inline emoji with a tiny SVG set (`<Icon name="chain|warn|check|clock|tri-up|diamond" />`) or, at minimum, restrict to glyphs that *do* render here (`⚠ ✓` render; `⛓ ⊠` do not). One `Icon` component, then sweep `EvidenceTab.jsx`, `OverviewTab.jsx`, finding/account confidence markers. Resolves **EMP-002** and **NEW-04**, and de-risks **CLR-002 / CLR-005 / NAV-002**.

### F-3 · Host-value normalization (data, not CSS)
Host strings arrive in mixed case (`SRL-FORGE` vs `srl-forge` — visible in the IOC table). Normalize at the display boundary with a `displayHost(h) => h.toUpperCase()` helper used by every chip. Resolves **BUG-002** correctly (see its corrected root cause).

---

## 1 · Bugs

### BUG-001 · CONFIRMED (worse than reported) · "Profile Profile" label
- **Root cause:** `reports/ReportsTab.jsx:373` — `<label>Profile Profile</label>`. A **second** instance exists at `reports/ReportsTab.jsx:622` (`<span>Profile Profile:</span>`) that the original assessment missed.
- **Fix:** Both → `Report Type`. (Keep "Report Profile" only where it's prose, e.g. the generated-markdown line `:180`.)
- **Outcome:** No doubled word in the form label or the report-detail panel.

### BUG-002 · REVISED · Lowercase host renders differently
- **Original claim was inaccurate:** there is **no** case-sensitive condition in the chip renderer, and the chip is **not** "dark teal." `iocs/IocsTab.jsx:245‑253` renders *every* host in the identical chip (`color: --text-muted`, `background: --bg-raised`). The last rows differ only because the underlying **data** is lowercase (`srl-forge`). Same pattern in `accounts/AccountsTab.jsx` HOST LIST.
- **Fix:** Apply **F-3** (`displayHost().toUpperCase()`) at every host-chip render site. No renderer condition to remove — it never existed.
- **Outcome:** All host chips read `SRL-FORGE` in the same chip style.

### BUG-003 · REJECTED · "Recent Activity empty under Last 24h"
- **Contradicted by code and pixels.** `overview/OverviewTab.jsx:245` already filters on `f.modified_at || f.timestamp || …`, i.e. it tracks *modification*, not just creation. Live, the widget **does** show `F-claude-002` under the active *Last 24h* filter.
- **Do not implement.** The original assessment captured a transient data state (nothing modified in the trailing 24h at that moment).
- **Optional polish (carry into EMP-001):** the empty-state copy `:277` "No findings in this period." is fine; no code change required.

### BUG-004 · CONFIRMED · Finding ID wraps to 3 lines
- **Root cause:** the sidebar ID cell in `findings/FindingsTab.jsx` (and the Recent Activity row in `OverviewTab.jsx`) lets `F-claude-001` wrap (`F-` / `claude-` / `001`).
- **Fix:** treat the ID as a fixed monospace token — `white-space: nowrap` on the ID element; give it its own column with a small fixed min-width; let the **title** truncate with ellipsis instead.
- **Outcome:** Every ID renders on one line; the title is what truncates.

### BUG-005 · REVISED · `[]` next to every timeline timestamp
- **Original diagnosis wrong** ("empty evidence tags"). `timeline/TimelineTab.jsx:129‑131` renders `[{ev.type}]` as the event **type label** (e.g. `[auth]`). It shows empty because findings-derived events arrive with **no `type`** set, so it prints `[]` and the dot/color falls back to `--text-ghost`.
- **Fix (two parts):** (a) UI guard — render the bracket only when `ev.type` is truthy; (b) better: backfill `type` when synthesizing timeline events from findings (gateway/ingest side) so the category filters (**COH-002**) actually match these rows.
- **Outcome:** No empty `[]`. Typed events show `[auth]` etc.; untyped events show nothing in that slot.

---

## 2 · Color & visual consistency

### CLR-001 · CONFIRMED · PENDING and STAGED both amber
- **Root cause:** `overview/OverviewTab.jsx:93` and `:98` both pass `color="var(--amber)"`.
- **Fix:** STAGED → `var(--status-staged)` (= `--violet`, currently unused) per **F-1**. Also update the staged progress bar `:104` and the inline `staged` label `:296`.
- **Outcome:** FINDINGS cyan · APPROVED jade · PENDING amber · STAGED violet — four distinct colors.

### CLR-002 · REVISED · Finding-header tag row
- **Premise was wrong:** `HIGH` is already crimson with a `▲`, and `GRADE: PARTIAL` is already an amber outlined badge (verified by zoom). Only **two** tags need work: `FINDING` is a low-contrast pill, and `DRAFT` is unstyled plain gray text.
- **Fix:** make `DRAFT` a status chip using `--status-pending`; raise the `FINDING` type-pill contrast (neutral filled chip). Leave HIGH and GRADE as-is.
- **Outcome:** severity (red) / type (neutral) / status (amber) are each legible at a glance — without restyling what already worked.

### CLR-003 · REJECTED · "APPROVED greener in IOC than Hosts/Accounts"
- **Contradicted by code and pixels.** `accounts/AccountsTab.jsx:217`, `hosts/HostsTab.jsx:188`, and `iocs/IocsTab.jsx` (status map → `var(--jade)`) all use the **same token** and the **same `Badge` component**. Rendered green is identical across all three tables.
- **Do not implement.** (The perceived difference was standalone `APPROVED` vs. the `"1 Approved"` count badge — same color, different text.) Adopting **F-1** locks this in permanently.

### CLR-004 · CONFIRMED · MITRE parent vs sub-technique indistinguishable
- **Root cause:** Overview tag cloud + `iocs/IocsTab.jsx:301‑309` render every technique in identical `--cyan` chips; `T1078` and `T1078.001` look equal.
- **Fix:** detect a `.` in the ID → render sub-techniques at reduced emphasis (filled low-opacity chip, or dimmer text), optionally indented under their parent.
- **Outcome:** parents vs. sub-techniques are distinguishable without reading the ID.

### CLR-005 · CONFIRMED (partial) · Grade badge has no system/legend
- **State:** `GRADE: PARTIAL` (amber outline) exists, but there's no visible scale and no other tiers shown.
- **Fix:** formalize tiers with **F-1** grade tokens — FULL (jade) / PARTIAL (amber) / UNGRADED (ghost) — and add a `?` tooltip explaining the scale. Apply in the finding detail header.
- **Outcome:** consistent, self-explaining grade badges.

---

## 3 · Typography & casing

### TYP-001 · REVISED · "Header casing is inconsistent"
- **Mostly a deliberate two-tier hierarchy, not a bug.** Page titles are Title Case (`Hosts in Scope`, `Indicators of Compromise`, `Evidence Chain`, `Settings`); card/section labels are ALL-CAPS tracked (`SEVERITY DISTRIBUTION`, `WRITE BLOCK STATUS`, `ACTIVE AGENT TOKENS`). That system is consistent — **don't flatten it.**
- **The one genuine inconsistency:** the **Reports** page has no Title-Case page title; its top-left element `GENERATE REPORT` is an ALL-CAPS card label doubling as the page heading. Overview/Findings/Timeline also lack a page-title H1.
- **Fix:** give Reports (and ideally Overview/Findings/Timeline) a Title-Case page `<h1>` matching the other tabs; keep card labels ALL-CAPS. Document the rule: *page title = Title Case H1; section/card label = ALL-CAPS; table column = ALL-CAPS.*
- **Outcome:** every page opens with a consistent Title-Case heading; the uppercase card-label system stays intact.

### TYP-002 · CONFIRMED · Examiner shown 3×
- **Root cause:** `layout/Header.jsx` (plain `examiner` text **+** `EXAMINER` pill) and `layout/StatusBar.jsx` (`· examiner`).
- **Fix:** keep only the role pill in the header; remove the standalone text and the status-bar copy (ties into **NAV-001**).
- **Outcome:** the username appears once, in the header role chip.

### TYP-003 · CONFIRMED (worse than reported) · Hashes as the only version differentiator
- **State:** Overview Reports card shows raw hashes (`9a29853e`…). On the **Reports** page the two `Full IR Report · 5/28/2026 · examiner` rows have **no differentiator at all** — not even a hash.
- **Fix:** label saved reports `Full IR Report — v2 · 5/28/2026 14:32`; demote the hash to a muted/hover affordance. Add the time component and a sequence number.
- **Outcome:** two same-type reports are distinguishable at a glance; hash remains for integrity.

---

## 4 · UI coherence

### COH-001 · CONFIRMED · Collapsible arrow on different sides
- **State:** "Examiner Context Notes" has `▶` on the left; "Evidence & Context (Collapsible Details)" has `▶` on the right (`findings/FindingsTab.jsx`).
- **Fix:** standardize `▶`/`▼` on the **left** for both.

### COH-002 · REVISED · Timeline filter pills "no active state"
- **Active state already exists** — `timeline/TimelineTab.jsx:63‑65` gives a selected pill a `TYPE_COLOR+'22'` fill, colored border and colored text (the amber-outlined `Auth` is visible on click). It's just **too subtle**.
- **Fix:** strengthen the selected state — use the type color as a **solid/0x33 fill with dark text** so it reads clearly against the unselected outline. No new logic needed.
- **Outcome:** the active category filter is obvious at a glance.

### COH-003 · CONFIRMED (low priority) · Host inline in timeline has no chip
- By design (timeline has no host column). Optional: wrap inline `SRL-FORGE` mentions in the shared host chip via the description renderer. Defer.

### COH-004 · CONFIRMED · `F-claude-` vs `F-lms-` prefix unexplained
- **State:** both prefixes appear in the timeline; Settings confirms the agent IDs (`claude`, `lms`, `hermes-default`).
- **Fix:** add an `ℹ` tooltip on the Finding ID mapping prefix → source agent; long-term a 2-letter source chip (`CL`/`LM`). Pull the label from the agent registry, don't hardcode.
- **Outcome:** finding provenance is self-explaining.

### COH-005 · CONFIRMED · Single-host column repeats `SRL-FORGE` on every row
- **State:** IOC `Hosts` column and Accounts `HOST LIST` repeat the one in-scope host ~24×.
- **Fix:** when `hosts.length === 1`, suppress the per-row chip and annotate the section header instead (`Indicators of Compromise (24) — Host: SRL-FORGE`). Restore the column when multiple hosts exist.
- **Outcome:** no repeated chips in single-host cases.

### COH-006 · CONFIRMED · `hermes-default` listed twice in Settings
- **State:** `settings/SettingsTab.jsx` token table shows two byte-identical `hermes-default · Installer-created Hermes service token · Never` rows.
- **Fix:** confirm with the gateway whether two tokens genuinely exist. If yes, differentiate by `token_id`/created-at in the Label column; if it's duplicate data, dedupe at the source. Don't hide a real second credential.
- **Outcome:** every token row is uniquely identifiable.

---

## 5 · Empty states & clarity

### EMP-001 · REVISED · "Blank dark voids"
- **Largely outdated.** TODOs, Reports, and Timeline already render **centered empty states with icons** ("No TODOs match the current filters.", "No report selected", etc.). Hosts/Accounts aren't empty.
- **Real, narrow fixes:**
  1. **Evidence** "No evidence registered." (`evidence/EvidenceTab.jsx`) is the only bare one — add an icon + the Rescan CTA, vertically centered.
  2. **TODOs** copy is filter-aware even when truly empty — distinguish *no data* ("No TODOs yet. Create one to track tasks.") from *no filter match* ("No TODOs match the current filters — clear filters").
- **Outcome:** consistent, intentional empty states; no over-engineering of states that already work.

### EMP-002 · SPLIT — glyph CONFIRMED, code-styling REJECTED
- **Glyph: the original was RIGHT.** Source uses `⛓` (U+26D3) at `evidence/EvidenceTab.jsx:407, 443, 457`, but it has **no font on the SIFT VM and renders as a tofu box** (verified by zoom — what the original read as `⊠`). 
- **Code styling: REJECTED.** `AGENTIR_SOLANA_KEYPAIR` (`:457`) is **already** wrapped in a styled `<code>` element — no change needed.
- **Fix:** apply **F-2** (replace `⛓`/`⏳` with SVG or render-safe glyphs). Add a "Setup guide" link beside the not-configured message.
- **Outcome:** clean icon, readable message, no tofu; env var stays in its existing code style.

### EMP-003 · CONFIRMED · Write-protection warning states it twice
- **Root cause:** `evidence/EvidenceTab.jsx:377` (prose) + `:380‑384` (backend `write_block_warning`, mono) restate the same sentence. Note the card **already** uses a `⚠` icon (`:375`) — so EMP-002's "add a warning icon" does **not** apply here.
- **Fix:** keep the one human-readable prose line; replace the mono restatement with the actionable command only — `mount -o ro,noatime /dev/sdX /mnt/evidence`.
- **Outcome:** one warning sentence + one runnable command, no repetition.

---

## 6 · Navigation & chrome

### NAV-001 · CONFIRMED · Status bar overloaded / examiner redundant
- **Root cause:** `layout/StatusBar.jsx` — `● SEALED ✓ · no staged changes · sync … · examiner`.
- **Fix:** drop `examiner` (it's in the header). Reduce to `[seal] · [staged/sync] · [case id]`; consider lock/sync icons (render-safe per **F-2**).
- **Outcome:** status bar carries only session state.

### NAV-002 · CONFIRMED · `● idle` indicator opaque
- **Root cause:** `layout/Header.jsx` gray dot + "idle", no tooltip, no state legend.
- **Fix:** tooltip ("Agent status: idle — no analysis running"); color states gray=idle / amber=processing / crimson=error (reuse tokens).
- **Outcome:** the dot communicates agent state on its own.

### NAV-003 · CONFIRMED · Case selector reads as static label
- **Root cause:** `layout/Header.jsx` — tiny low-contrast `▾`, no hover affordance.
- **Fix:** add a bordered/hover-filled control style, `cursor: pointer`, slightly larger chevron.
- **Outcome:** the selector clearly looks clickable.

---

## 7 · New issues (not in the original assessment)

### NEW-01 · CONFIRMED · Timeline shows the same finding ID twice per row
- `timeline/TimelineTab.jsx:136‑144` prints `auto-linked from [F-claude-008]` **and** `related: [F-claude-008]` when `auto_created_from` equals the sole related finding. Pure redundancy.
- **Fix:** dedupe — if `related_findings` is just `[auto_created_from]`, show only "auto-linked from [id]".

### NEW-02 · CONFIRMED · Gap badges show raw minutes
- `timeline/TimelineTab.jsx:110` renders `▲ {Math.round(gap/60000)}m gap` → "4975m gap", "162m gap".
- **Fix:** humanize (`3d 11h`, `2h 42m`). Small `formatDuration()` helper.

### NEW-03 · CONFIRMED · Inconsistent confidence glyph (Accounts)
- The `N/A` account row shows `○ HIGH` (hollow circle) while other rows show `▲ HIGH` (filled triangle) for the same value (`accounts/AccountsTab.jsx`). Likely a missing-confidence fallback colliding with the HIGH marker.
- **Fix:** one confidence-glyph map keyed by level; render-safe per **F-2**.

### NEW-04 · CONFIRMED · Emoji-as-icon is systemic & fragile
- Generalizes EMP-002: `⛓ ⊠ ⏳ ◆ ○` are font-dependent and break on the SIFT VM. Adopt **F-2** project-wide.

### NEW-05 · CONFIRMED (minor) · Unattributed account labeled `N/A`
- `accounts/AccountsTab.jsx` shows `N/A` for the 19-finding unnamed actor. Prefer a clearer label ("Unattributed").

---

## 8 · Recommended order for the developer

**Phase 0 — foundation (unblocks the rest):**
1. **F-1** semantic tokens → fixes CLR-001, locks CLR-003
2. **F-2** icon system → fixes EMP-002, NEW-04; de-risks CLR-005/NAV-002/NEW-03
3. **F-3** host normalization → fixes BUG-002

**Phase 1 — high-impact, low-risk:**
4. BUG-001 (Profile Profile ×2) → 5. BUG-004 (ID wrap) → 6. TYP-002 + NAV-001 (examiner dedupe) → 7. COH-002 (pill contrast) → 8. COH-001 (arrow side) → 9. CLR-002 (DRAFT/FINDING chips)

**Phase 2 — clarity & polish:**
10. BUG-005 (timeline type guard + backfill) → 11. NEW-01 / NEW-02 (timeline dedupe + humanized gaps) → 12. COH-005 (single-host column) → 13. TYP-003 (report versioning) → 14. EMP-003 (write-block dedupe) → 15. EMP-001 (Evidence empty state)

**Phase 3 — enhancements:**
16. CLR-004 (sub-technique style) → 17. CLR-005 (grade legend) → 18. COH-004 (agent-source tooltip) → 19. COH-006 (token dedupe) → 20. NAV-002 (idle states) → 21. NAV-003 (case selector affordance) → 22. TYP-001 (page-title H1 on Reports/Overview/Findings/Timeline) → 23. NEW-05 → 24. COH-003 (defer)

**Closed (do not implement):** BUG-003, CLR-003, and the `<code>`-styling half of EMP-002 — all contradicted by code/pixels above.

---

*25 original items reviewed: 16 confirmed, 6 revised, 2 rejected, 1 split. 5 new issues added. 3 foundational refactors recommended. (The original `dfir-portal-fix.md` says "21" but lists 5+5+3+6+3+3 = 25.)*
