# Examiner Portal — Tasks

> **Tickable work only.** Stable system definition lives in `ux-spec.md`. Every task here cites a spec section (`Spec §X`). The cited section is the source of truth for "what done means" — this file is just the queue.

**How to use:**
1. Pick the top task in the current phase.
2. Read the cited spec sections (do not skip — that's the whole anti-drift point).
3. Implement against the **Acceptance** checklist. Each item must be true before ticking.
4. Run the **Verify** step on the SIFT VM. If it fails, the task isn't done.
5. Confirm **Security gate** items where listed. Missing = not done.
6. Tick `☐ → ☑` and add a one-line note to the Session Log.
7. **Before ticking anything**, sanity-check that the audited "already done" claim still matches code — the audit was a snapshot.

**Status legend:** ☐ todo · ◐ in progress · ☑ done · ✕ dropped

---

## Status snapshot

| Phase | Total | Done | Remaining |
|---|---|---|---|
| 0 — Reconciliation | 1 | 1 | 0 |
| 1 — Bugs & features | 15 | 13 | 0 |
| 2 — Security gate | 4 | 0 | 4 |
| 3 — Polish | 7 | 0 | 7 |

T-07 and T-08 are on hold (◐), not counted as remaining.

---

## Phase 0 — Reconciliation

### ☑ T-00 — Audit reconciliation (2026-05-28)

Verified against current code that the following claims from the previous task tracker are obsolete (these features are actually implemented):
- BUG-7 evidence chain status updates after seal/rescan
- BUG-8 FindingDetail rich rendering (title/body/observation/interpretation/evidence/tags/mitre_ids/iocs/provenance/host/account/audit_ids/modifications)
- BUG-9 Timeline finding_refs as clickable cyan links
- BUG-12 SettingsTab token management (create/list/rotate/revoke/copy-once)
- BUG-14 Approve/Reject vs Undo correctly switches based on staged state
- F10 finding field remapping
- VIS-1, VIS-2, UX-1, UX-2 visual fixes
- SEC-1, SEC-4, SEC-5 normalized errors, sign-out label, password clearing

If you find one of these claims is **not** actually true in code, demote it back to Phase 1 as a new task with full acceptance criteria. Do not just re-open it as a one-line bug.

---

## Phase 1 — Missing features

Each task is the same five-line block:
**Spec §** · **Files** · **Acceptance** · **Verify** · **Security gate**.

### ☑ T-01 — Reports backend + UI (HIGH priority — completes operator loop)

**Spec:** §3 Reports (planned), §4 Reports Tab, §6 (planned ReportsTab.jsx), §7 (rate limit + error scrubbing)
**Background:** `report_mcp.server.generate_report(profile, case_id, finding_ids?, start_date?, end_date?)` returns a structured dict `{ report_data, sections, guidance }`. `report_mcp.save_report` persists. Profiles: `full, executive, timeline, ioc, findings, status` (see `list_profiles`). The portal routes are a thin REST wrapper — case_id comes from the active session, not the body.
**Files:**
- `packages/case-dashboard/src/case_dashboard/routes.py` — add 5 routes; import `report_mcp.server` helpers directly (or invoke via MCP gateway — pick whichever matches the case-mcp pattern already in this file)
- `packages/case-dashboard/frontend/src/api/endpoints.js` — add `getReports`, `postReportGenerate`, `postReportSave`, `getReport`, `downloadReport`
- `packages/case-dashboard/frontend/src/components/reports/ReportsTab.jsx` (new)
- `packages/case-dashboard/frontend/src/components/layout/NavRail.jsx` — add Reports icon + route
- `packages/case-dashboard/frontend/src/App.jsx` — route case for `'reports'`
**Acceptance (backend):**
- [x] `GET /portal/api/reports` returns saved reports for active case `[{ id, profile, created_at, examiner }]`
- [x] `POST /portal/api/reports/generate` body `{ profile, finding_ids?, start_date?, end_date? }` → calls `generate_report` with active case_id → returns `{ id, profile, report_data, sections, guidance }`. The `id` is server-assigned and held until save.
- [x] `POST /portal/api/reports/{id}/save` persists via `save_report`
- [x] `GET /portal/api/reports/{id}` returns saved report content + metadata
- [x] `GET /portal/api/reports/{id}/download` streams markdown (`Content-Type: text/markdown`, `Content-Disposition: attachment; filename="…"`)
- [x] Unknown profile → 400 with "Unknown profile" message (mirror the MCP tool's error shape)
- [x] All endpoints require examiner role; readonly returns 403
**Acceptance (UI):**
- [x] NavRail icon + Reports tab visible
- [x] Profile selector populated from a static list (mirror the 6 profiles), with descriptions in tooltip
- [x] Generate button → shows preview pane (markdown render of `report_data.summary` / `sections`)
- [x] Save button persists the draft
- [x] List pane shows saved reports; click → preview; Download button per row
- [x] Generate button disabled while a generation is in-flight
**Verify (SIFT VM):**
```bash
SID=…
BASE="https://192.168.122.81:4508/portal/api"
curl -sk -b "agentir_session=$SID" $BASE/reports
curl -sk -b "agentir_session=$SID" -X POST -H 'Content-Type: application/json' \
  -d '{"profile":"executive"}' $BASE/reports/generate | python3 -m json.tool
```
Then UI: Generate `executive` → see preview render → Save → confirm appears in list → Download → file contains approved findings.
**Security gate (Spec §7):**
- [x] Rate-limit generation server-side (max 1 in-flight per case)
- [x] `{id}` validated as UUID (no path traversal)
- [x] Error map: generation failure → "Report generation failed. Check the case status."
- [x] No filesystem paths leak into UI errors

---

### ☑ T-02 — Hosts tab

**Spec:** §4 Hosts Tab, §6 (planned)
**Files:** `frontend/src/components/hosts/HostsTab.jsx` (new), `NavRail.jsx`, `App.jsx`
**Acceptance:**
- [x] Table renders one row per unique `host` value found across findings
- [x] Columns: Host · Findings · Accounts (count) · Best Confidence · Time Range · Status Summary (badges)
- [x] Click row → `setActiveTab('findings')` + filter findings by host (use existing `findingsFilter` or extend store with `findingsHostFilter`)
- [x] Empty state: "No hosts in scope yet."
**Verify:** Open tab → 3 hosts shown matching the case → click `SRV-DC01` → Findings tab opens with sidebar narrowed to that host.
**Security gate:** N/A (read-only client aggregation).

---

### ☑ T-03 — Accounts tab

**Spec:** §4 Accounts Tab, §6 (planned)
**Files:** `frontend/src/components/accounts/AccountsTab.jsx` (new), `NavRail.jsx`, `App.jsx`, `FindingsTab.jsx`, `useStore.js`
**Acceptance:**
- [x] Table: Account · Findings · Hosts (count) · Host List · Best Confidence · Time Range · Status Summary (badges)
- [x] "Unknown" / empty account → "N/A" badge with neutral styling
- [x] Click row → switch to Findings filtered by that account (extended store with `findingsAccountFilter` + banner in FindingsTab)
- [x] Empty state: "No accounts in scope yet."
**Verify:** 26 findings → 5 unique accounts in UI (fred.rocba@outlook.com, fredr, srl-h, srl-helpdesk@outlook.com, N/A). Raw `affected_account` has 4 values (one comma-separated). Account filter banner in Findings clears with ✕.
**Security gate:** N/A.

---

### ☑ T-04 — IOCs tab

**Spec:** §3 (`GET /api/iocs`), §4 IOCs Tab, §6
**Files:** `frontend/src/components/iocs/IocsTab.jsx` (new), `NavRail.jsx`, `App.jsx`, `useStore.js`, `useDataPolling.js`, `endpoints.js` already has `getIocs`
**Acceptance:**
- [x] Table: Value (monospace, copy button) · Type · Category · Confidence badge · Hosts · Source Findings (clickable F-IDs) · Status badge
- [x] Filters: category dropdown, status dropdown (DRAFT/APPROVED/REJECTED/ALL), search box
- [x] Expandable rows show MITRE techniques + tags
- [x] Click F-ID link → switch to Findings, select that finding
- [x] Empty state ("No IOCs match the current filters.")
**Verify (SIFT VM):** 24 IOCs confirmed. API returns 24; UI table shows 24 (4 categories: network/identity/host/unknown; 20 DRAFT, 4 APPROVED). Filters correctly narrow results.
**Security gate:** N/A.

---

### ☑ T-05 — TODOs tab

**Spec:** §3 (`GET /api/todos`), §4 TODOs Tab, §6
**Files:** `frontend/src/components/todos/TodosTab.jsx` (new), `NavRail.jsx`, `App.jsx`, `useStore.js`, `useDataPolling.js`
**Acceptance:**
- [x] Table: ID · Title · Description · Priority (high/med/low — shape disambiguated badge) · Examiner · Status · Related findings (clickable) · Created at
- [x] Filters: priority, status
- [x] Default sort: priority desc, then created_at asc
- [x] NavRail badge: count of open TODOs
**Verify:** open count in NavRail badge matches `/api/summary` `todos.open` (both 0 for test-rocba-2026; badge hidden when count 0).
**Security gate:** N/A.

---

### ☑ T-06 — Command palette

**Spec:** §4 Cross-cutting, §6 (planned CommandPalette.jsx)
**Files:** `frontend/src/components/layout/CommandPalette.jsx` (new), `App.jsx` (Ctrl+K binding), `useStore.js` already has `commandPaletteOpen`
**Acceptance:**
- [x] `Ctrl+K` (and `Cmd+K`) opens palette anywhere
- [x] Search across findings (id, title) + actions
- [x] Quick actions: approve current, reject current, open commit drawer, refresh, sign out
- [x] Esc closes; arrow keys navigate; Enter executes
- [x] Recently selected items at top
- [x] Use the `cmdk` package (already in `package.json`)
**Verify:** 20 frontend tests pass (`npm test`). Ctrl+K → "F-001" → Enter opens finding (manual). cmdk Command.Dialog provides native focus trap + keyboard nav.
**Test files:** `frontend/src/test/CommandPalette.test.jsx` (20 tests: store, delta staging, keyboard shortcuts, security gate, recent items), `frontend/vitest.config.js`
**Security gate:**
- [x] Focus trap inside palette — cmdk's Command.Dialog wraps @radix-ui/react-dialog which provides proper focus trapping
- [x] No actions that require password are executable without going through their normal modal — approve/reject only stage deltas (no password needed); commit opens drawer (password required inside); sign out uses standard flow

---

### ◐ T-07 — Audit trail panel (full surface) — ON HOLD
*On hold per user direction 2026-05-28. Defer to Phase 4. Existing audit panel inside Zone 2 is functional and sufficient for current workflow.*

---

### ◐ T-08 — Review velocity sparkline — ON HOLD
*On hold per user direction 2026-05-28. Defer to Phase 4.*

---

### ☑ B-01 — Case list not populating (BLOCKING)

**Spec:** §3 Cases, §4 Header / Case Selector
**Root cause:** `useDataPolling.js:30` — `setCases(cases.value)` stores the full API response object `{ cases: [...], cases_root, active_case_dir }` instead of extracting the array. `Header.jsx` calls `cases.map()` which silently fails on an object — dropdown renders empty.
**Files:** `frontend/src/hooks/useDataPolling.js`, `frontend/src/components/layout/Header.jsx`
**Acceptance:**
- [x] `useDataPolling.js` extracts `.cases` from the response: `setCases(cases.value?.cases ?? [])`
- [x] Header case dropdown shows all cases from `GET /api/cases`
- [x] Active case is visually distinguished (green dot: `var(--jade)`) from inactive cases (grey dot: `var(--border-hard)`)
- [x] Clicking a non-active case opens the password-protected activation modal (already exists)
**Verify:** On SIFT VM: login → click case selector → see all cases listed → active one has green dot.
**Security gate:** N/A.
**Discovery:** `case_list_data()` confirmed via `.venv` to return `{ cases: [{ id, name, status, active }], cases_root, active_case_dir }`. Case items use `.id` (from `CASE.yaml` `case_id`), not `.case_id`. The `active` boolean is set by comparing `entry.name` against `AGENTIR_CASE_DIR` env var.

---

### ☑ B-02 — Case banner shows wrong identifier

**Spec:** §4 Overview Tab, §6 `overview/OverviewTab.jsx`
**Root cause:** `OverviewTab.jsx:53-54` accesses `activeCase.id` (does not exist — CASE.yaml uses `case_id`) and `activeCase.title` (shows the description "Intrusion and Ransomware"). The primary identifier should be the case_id (e.g. `test-rocba-2026`), with title/description expandable.
**Files:** `frontend/src/components/overview/OverviewTab.jsx`
**Acceptance:**
- [x] Banner primary text is `activeCase.case_id` (the machine identifier), not undefined/description
- [x] Banner is expandable (chevron toggle) to show CASE.yaml metadata: name, title, status, examiner, created
- [x] Metadata section is compact — grid of label/value pairs
- [x] Entire banner element is clickable to expand, not just the chevron
- [x] Chevron sized proportionally to the ACTIVE badge (inline-flex, 22x20px)
**Verify:** Overview → banner shows `rocba-drive-20260526-1417` → click anywhere on banner → metadata expands with name/title/status/examiner/created.
**Security gate:** N/A.
**Discovery:** `/api/case` returns raw CASE.yaml JSON with keys `case_id`, `name`, `title`, `status`, `examiner`, `created`, `created_at`. The `title` and `name` fields both contained "Intrusion and Ransomware" in the test case. Header's active-case display also affected — fixed to use `activeCase?.case_id || activeCase?.id`.

---

### ☑ B-03 — Evidence integrity: retire big Overview widget, use StatusBar indicator with click-to-navigate

**Spec:** §4 Overview Tab, §4 Evidence Tab, §6 `layout/StatusBar.jsx`, §6 `overview/OverviewTab.jsx`
**Root cause:** There were TWO evidence integrity surfaces. The big widget was redundant. The StatusBar checked fields that don't exist in the API response — `chainStatus.sealed` and `chainStatus.hmac_verified`. The actual API returns `status` ("ok"/"unsealed"), `manifest_version` (number, >0 = sealed), `hmac_verify_needed` (bool), `write_protected` (bool, not `write_blocked`). Because the code checked wrong field names, the seal dot always displayed UNSEALED/crimson.
**Files:**
- `frontend/src/components/layout/StatusBar.jsx` — add `setActiveTab`; make seal section a `<button>` with onClick → `setActiveTab('evidence')`; fix field names to `status`/`manifest_version`/`hmac_verify_needed`/`write_protected`
- `frontend/src/components/overview/OverviewTab.jsx` — remove Evidence Integrity widget; remove `chainStatus`/`sealColor`/`sealLabel` from destructure
**Acceptance:**
- [x] StatusBar seal dot + label is clickable → navigates to Evidence tab
- [x] Hover state on seal section: cursor pointer + background change to `var(--bg-raised)`
- [x] The large "EVIDENCE INTEGRITY" widget in Overview middle row is completely removed
- [x] Seal state uses correct API fields: `status !== 'unsealed'` + `manifest_version > 0` = sealed; `!hmac_verify_needed` = verified
- [x] Write-protection field corrected: `write_protected` (not `write_blocked`)
**Verify:** From any tab, click the seal dot in StatusBar → Evidence tab opens. If evidence is sealed and HMAC verified → jade "SEALED ✓". If sealed but unverified → amber "SEALED · verify pending". If unsealed → crimson "UNSEALED".
**Security gate:** The seal indicator must never show a false SEALED state. If chainStatus is null → "LOADING". Uses `manifest_version > 0` as the authoritative seal check (not a separate `sealed` flag).

---

### ☑ B-04 — Recent activity feed not clickable, missing time filter

**Spec:** §4 Overview Tab
**Root cause:** `ActivityFeed` rendered entries as bare `<div>` — no onClick, no cursor, no navigation. Hardcoded `.slice(0, 8)` with no recency filter. Additional root cause: findings have `timestamp: null` — only `event_timestamp` (incident date from Nov 2020) and `modified_at` (system record time from May 2026) are populated. Using `event_timestamp` made all time filters empty because events are 5+ years old.
**Files:** `frontend/src/components/overview/OverviewTab.jsx`
**Acceptance:**
- [x] Each activity row is clickable `<button>` → navigates to Findings tab and selects that finding
- [x] Rows have hover state (background `var(--bg-raised)` on mouse enter)
- [x] Time-range selector: Last hour · Last 24h · Last 7d · Last 30d · All (segmented buttons)
- [x] Feed updates when filter changes (client-side filter, default: Last 24h)
- [x] Timestamp fallback chain: `modified_at` → `timestamp` → `event_timestamp` (findings without any timestamp are filtered out except on "All")
**Verify:** Time filters work correctly against `modified_at` (May 2026 dates). Click a row → Findings tab opens with that finding selected.
**Security gate:** N/A.

---

### ☑ B-05 — Replace evidence integrity widget with Reports section in Overview

**Spec:** §3 Reports, §4 Reports Tab, §6 `overview/OverviewTab.jsx`
**Root cause:** The middle-row right cell was freed by B-03. The `/api/reports` endpoint already returned `[{ id, profile, created_at, examiner }]` — report data was available but not surfaced on Overview.
**Files:**
- `frontend/src/components/overview/OverviewTab.jsx` — replaced evidence integrity widget with Reports section showing: profile (capitalized via `textTransform`), truncated UUID, examiner, locale-formatted date
- `frontend/src/store/useStore.js` — added `reports: []`, `setReports`
- `frontend/src/hooks/useDataPolling.js` — added `getReports` import, `setReports` destructure, `getReports()` to `Promise.allSettled`, `reports` in destructuring array, `setReports(reports.value)` call
**Acceptance:**
- [x] Middle-row right cell shows "REPORTS" section header
- [x] Lists clickable report items: capitalized profile, ID (8-char truncated UUID), examiner, date (toLocaleDateString)
- [x] Clicking a report item navigates to the Reports tab
- [x] Empty state: "No reports generated yet · Generate one from the Reports tab"
- [x] Store updated: `reports: []`, `setReports`, polled via `getReports()` every 15s
- [x] Polling updated: `getReports()` in `Promise.allSettled` batch
**Verify:** Generate a report from Reports tab → return to Overview → see it listed with profile/examiner/date → click → navigates to Reports tab.
**Security gate:** N/A.

---

### ☑ B-06 — MITRE ATT&CK tag cloud extracts from wrong field

**Spec:** §3.1 Finding shape (`mitre_ids[]` vs `tags[]`), §4 Overview Tab
**Root cause:** `OverviewTab.jsx:32-33` computed `mitreIds` from `f.tags` with regex `/^T\d{4}/`. MITRE technique IDs are stored in `f.mitre_ids` — a dedicated array field. The tag cloud was always empty because `tags` doesn't contain MITRE IDs.
**Files:** `frontend/src/components/overview/OverviewTab.jsx`
**Acceptance:**
- [x] Changed source from `f.tags.filter(t => /^T\d{4}/.test(t))` to `f.mitre_ids ?? []` (no regex)
- [x] Tag cloud renders MITRE technique badges (cyan, consistent with FindingsTab)
- [x] Empty state: "No MITRE technique IDs found in findings." (updated from "finding tags")
**Verify:** Findings with `mitre_ids: ["T1059", "T1003"]` → Overview MITRE cloud shows T1059 and T1003 badges.
**Security gate:** N/A.

---

### ☑ B-07 — Case activation sends wrong field name (discovered during B-01 verification)

**Spec:** §3 Cases, §4 Header / Case Selector
**Root cause:** `Header.jsx:31` sent `{ id: activatingCase.id, ... }` but the backend (`routes.py:3223`) expects `{ case_id: ..., challenge_id: ..., response: ... }`. Field name mismatch caused every activation attempt to fail with "Missing case_id". Additionally, after a successful activation, no data was refreshed — old case data persisted until the next 15s poll.
**Files:** `frontend/src/components/layout/Header.jsx`
**Acceptance:**
- [x] `postCaseActivate` payload uses `case_id` (not `id`)
- [x] After successful activation: all case-scoped stores reset to empty (`findings`, `timeline`, `delta`, `chainStatus`, `iocs`, `todos`, `reports`, `summary`, `activeCase`) and `isLoading` set to `true`
- [x] Activate button shows "Activating..." during request, disabled to prevent double-submit
- [x] Cancel button clears password from state
- [x] Click-outside-to-close on case dropdown (useRef + useEffect + mousedown listener)
- [x] Dropdown rows show case name (truncated) + ACTIVE badge for active case
**Verify:** Click non-active case → password modal → submit → "Activating..." → modal closes → skeleton shows → data refreshes for new case.
**Security gate:** Password cleared from React state immediately after challenge-response computation (before network round-trip). Activation requires HMAC-SHA256 challenge-response — cannot be bypassed.

---

## Phase 2 — Security gate (blocking per Spec §7)

### ☐ T-09 — Focus traps on all password modals (SEC-2)

**Spec:** §7 Modal focus management
**Files:**
- `frontend/src/components/layout/CommitDrawer.jsx`
- `frontend/src/components/layout/Header.jsx` (case activation modal)
- `frontend/src/components/evidence/EvidenceTab.jsx` (verify/seal/ignore/retire modals)
- `frontend/src/components/auth/LoginCard.jsx`
- Optional helper: `frontend/src/hooks/useFocusTrap.js` (new, ~20 lines)
**Acceptance:**
- [ ] In each modal: initial focus on first input; Tab cycles within modal; Shift+Tab reverses; Escape closes and returns focus to opener
- [ ] No way to Tab into background while modal is open
**Verify:** Open commit drawer → Tab through fields → confirm focus stays inside → Esc → focus returns to status bar "↑ COMMIT".
**Security gate:** This task IS the gate.

---

### ☐ T-10 — CSRF posture audit (SEC-3)

**Spec:** §7 Session & CSRF
**Files:** Read-only audit + decision; if changes needed: `frontend/src/api/client.js` + a backend dependency.
**Acceptance:**
- [ ] Read `routes.py` and confirm whether any state-changing endpoint validates a CSRF header
- [ ] Document the actual posture in Spec §7 (replace the current placeholder text)
- [ ] If backend requires it: add `X-CSRF-Token` header to all `apiPost`/`apiDelete` calls
- [ ] If backend doesn't: confirm with maintainer that SameSite=strict + per-action HMAC is the accepted threat model, and record the decision in Spec §7
**Verify:** From an arbitrary off-origin page, attempt a `POST /portal/api/commit` and confirm 401/403.
**Security gate:** This task IS the gate.

---

### ☐ T-11 — Error scrubbing audit (extends SEC-1)

**Spec:** §7 Error scrubbing
**Files:** Grep all `.jsx` for `catch` and `ex.message` patterns
```bash
grep -rn "ex\.message\|err\.message\|error\.message" packages/case-dashboard/frontend/src/
```
**Acceptance:**
- [ ] Every catch block uses the normalized error map (login/commit/activation/generic)
- [ ] Raw error → `console.error` only
- [ ] Toast text never contains: server stack traces, paths, internal IDs, raw JSON
**Verify:** Trigger 5 different error paths (wrong password on each modal) and confirm operator-friendly message every time.
**Security gate:** This task IS the gate.

---

### ☐ T-12 — Token expiry surfacing + clipboard hygiene

**Spec:** §7 Token display
**Files:** `frontend/src/components/settings/SettingsTab.jsx`
**Acceptance:**
- [ ] Tokens with `expires_at < now()` are visually distinguished (strikethrough / muted)
- [ ] Tokens within 7 days of expiry show amber "expiring soon" badge
- [ ] Copy-once banner uses `navigator.clipboard.writeText` and shows confirmation
- [ ] Plaintext token cleared from React state when banner dismissed
**Verify:** Create token with expiry 1 day out → see "expiring soon" badge.
**Security gate:** This task IS the gate.

---

## Phase 3 — Polish

### ☐ T-13 — Keyboard shortcuts (P3)

**Spec:** §4 Findings → "Keyboard: j/k navigate, a approve…"
**Files:** `frontend/src/components/findings/FindingsTab.jsx`, `App.jsx`
**Acceptance:**
- [ ] j/k navigate selected finding within current filter
- [ ] a / r stage approve / reject
- [ ] e enter edit on observation
- [ ] s undo (delete delta for current finding)
- [ ] Shift+C open commit drawer
- [ ] / focus search
- [ ] ? open shortcuts help overlay
- [ ] Shortcuts ignored while typing in an input
**Verify:** End-to-end keyboard-only review of 3 findings.

### ☐ T-14 — Empty states (P5)

**Spec:** §4 Cross-cutting → "Empty states"
**Files:** every tab component
**Acceptance:** Each tab with zero data shows an icon + one-line message + action hint (e.g. "No pending findings · Switch to All to see reviewed items").
**Verify:** Fresh case with no findings → every tab is graceful.

### ☐ T-15 — Error states with retry (P6)

**Spec:** §4 Cross-cutting → "Error states"
**Files:** per-tab components + `hooks/useDataPolling.js`
**Acceptance:**
- [ ] On fetch failure, show descriptive message + Retry button
- [ ] If stale data is in store, render it with an "Out of date" amber pill
**Verify:** Stop the gateway → tabs show retry → restart gateway → retry succeeds.

### ☐ T-16 — Loading skeletons wired everywhere (P4)

**Spec:** §4 Cross-cutting → "Skeleton loading states"
**Files:** Audit each tab; ensure `isLoading` from store drives a skeleton, not a "Loading..." string.
**Acceptance:** First load shows skeleton per tab; resolves to data when `isLoading` flips false.
**Verify:** Throttle network → see skeletons → see data.

### ☐ T-17 — KPI count-up animation (P8)

**Spec:** §5 Animation budget → "KPI count-up on first load: one-shot only"
**Files:** `frontend/src/components/overview/KPICard.jsx`
**Acceptance:** Count-up animates from 0 to final value over 600ms on first render only; no re-animation on poll refresh.
**Verify:** Fresh page load → numbers tick up; subsequent poll → no animation.

### ☐ T-18 — Timeline expanded row + batch toolbar (port from v2)

**Spec:** §4 Timeline → "Expanded row" and "Batch include/exclude toolbar"
**Files:** `frontend/src/components/timeline/TimelineTab.jsx`
**Acceptance:**
- [ ] Click event → expand to show: full meta, editable description, related findings (clickable), time gap from previous, sources
- [ ] Multi-select checkboxes → toolbar slides in with Include All / Exclude All
**Verify:** Expand row → edit description → save → confirm staged.

### ☐ T-19 — Reject reason templates (port from v2)

**Spec:** §4 Findings → "Action bar: reject reason templates"
**Files:** `frontend/src/components/findings/FindingsTab.jsx`
**Acceptance:**
- [ ] Reject button opens a small dialog with 3 templated reasons (false positive, duplicate, insufficient evidence) + freeform textarea
- [ ] Selected reason stored in delta item `rejection_reason`
**Verify:** Reject a finding with "false positive" template → confirm reason saved on the delta and visible after commit.

---

## Smoke test checklist (run at session end)

Pulled from Spec §8.1. After any tab change, run the rows that apply.

- [ ] Login flow works end-to-end (setup → login → reload → still authed → logout)
- [ ] Case activation requires password and updates all data
- [ ] KPI numbers match `/api/summary`
- [ ] Findings detail renders all rich fields (Spec §3.1)
- [ ] Edit pencil → stage → commit cycle succeeds
- [ ] Approve / Reject / Undo flip correctly
- [ ] Switching filter does NOT auto-select a different finding
- [ ] Multi-select batch approve works
- [ ] Timeline finding_refs are clickable inline links
- [ ] Gap banners are hairline pills
- [ ] Evidence chain status updates after seal / verify / ignore / retire / anchor
- [ ] Hold-to-commit cancels on early release, blur, tab-switch
- [ ] Password cleared from state immediately after challenge-response computed
- [ ] Sign out button labelled clearly
- [ ] Build passes: `cd packages/case-dashboard/frontend && npm run build`
- [ ] Backend tests pass: `uv run python -m pytest packages/case-dashboard/ --tb=short -q`

---

## Session Log

| Date | Session | Completed | Notes |
|---|---|---|---|
| 2026-05-28 | 1 | I1–I9, A1–A4, S1–S5, O1–O8(exc O7), F1–F8, C1–C3+C5, T1–T6 | Initial scaffold + auth + all major tabs live on SIFT VM |
| 2026-05-28 | 2 | Bug fixes: delta `.items` extraction, summary shape, delta POST format, finding_id→id | Blank-page-after-login crash resolved |
| 2026-05-28 | 3 | Design audit + direction set (Editorial DFIR C2) | No code changed; full audit only |
| 2026-05-28 | 4 | BUG-1 through BUG-6, VIS-1/2, UX-1/2, SEC-1/4/5 | Font weights, isLoading flag, gap pills, color shape disambiguation, etc. |
| 2026-05-28 | 5 | BUG-7 (chain status), C4 (evidence verify) | Client-side PBKDF2/HMAC for chain ops; UI modals responsive |
| 2026-05-28 | 6 | Doc revamp: `ux-migration.md` → `ux-spec.md` (rewritten as stable spec), `ux-tasks.md` (rewritten as clean queue with five-line task format). Audit reconciliation: BUG-7/8/9/12/14/F10/VIS-1-2/UX-1-2/SEC-1/4/5 verified as already done in code; collapsed into T-00. New scope added per user decisions: Hosts/Accounts tabs, Reports backend+UI, security as blocking gate. | Spec is the anti-drift anchor; tasks file has 19 tickable items across 3 phases. |
| 2026-05-28 | 7 | T-01 | Implemented reports REST endpoints and frontend ReportsTab, added unit tests, verified end-to-end on SIFT VM |
| 2026-05-28 | 8 | T-02 | Created HostsTab component, updated store and sidebar findings filtering by host, built and deployed on SIFT VM |
| 2026-05-28 | 9 | T-03 | Created AccountsTab component (aggregates by affected_account, handles comma-separated/array/string), added findingsAccountFilter to store + FindingsTab banner, N/A badge for empty accounts |
| 2026-05-28 | 10 | T-04 | Created IocsTab with table (value+copy, type, category, confidence, hosts, source findings, status), category/status/search filters, expandable MITRE+tags rows, clickable F-ID links, added iocs to store + polling |
| 2026-05-28 | 11 | T-05 | Created TodosTab with priority shape-disambiguated badges, status/priority filters, default sort, NavRail badge wired to summary.todos.open, todos store + polling |
| 2026-05-28 | 12 | T-06 | Created CommandPalette using cmdk: Ctrl+K opens, unified search across findings + actions, approve/reject/commit/refresh/sign-out quick actions, recent items, focus trap via Command.Dialog |
| 2026-05-28 | 13 | B-01 through B-06 filed | T-07 and T-08 placed on hold. 6 bugs identified and filed: case list broken (B-01), wrong case banner (B-02), evidence integrity redundant/stale (B-03), activity feed unclickable (B-04), Reports section missing from Overview (B-05), MITRE tag cloud wrong field (B-06). All root causes traced to specific lines. |
| 2026-05-28 | 14 | B-01 through B-07 resolved | All 7 bugs fixed. B-01: `.cases` extraction. B-02: `case_id` + expandable banner. B-03: StatusBar clickable, field names fixed (`status`/`hmac_verify_needed`/`write_protected`). B-04: `modified_at` fallback chain + clickable rows + time-range selector. B-05: Reports store + polling + Overview widget. B-06: `mitre_ids` source. B-07: `id`→`case_id` + post-activation data reset + click-outside dropdown. 60 new tests (SessionChanges.test.jsx) covering all bugs, activation flow, chain status logic, XSS prevention, bypass resistance, edge cases, response times. 80 total frontend tests passing. |