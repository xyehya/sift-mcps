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
| 1 — Missing features | 8 | 0 | 8 |
| 2 — Security gate | 4 | 0 | 4 |
| 3 — Polish | 7 | 0 | 7 |

Update this table when ticking tasks.

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

### ☐ T-01 — Reports backend + UI (HIGH priority — completes operator loop)

**Spec:** §3 Reports (planned), §4 Reports Tab, §6 (planned ReportsTab.jsx), §7 (rate limit + error scrubbing)
**Background:** `report_mcp.server.generate_report(profile, case_id, finding_ids?, start_date?, end_date?)` returns a structured dict `{ report_data, sections, guidance }`. `report_mcp.save_report` persists. Profiles: `full, executive, timeline, ioc, findings, status` (see `list_profiles`). The portal routes are a thin REST wrapper — case_id comes from the active session, not the body.
**Files:**
- `packages/case-dashboard/src/case_dashboard/routes.py` — add 5 routes; import `report_mcp.server` helpers directly (or invoke via MCP gateway — pick whichever matches the case-mcp pattern already in this file)
- `packages/case-dashboard/frontend/src/api/endpoints.js` — add `getReports`, `postReportGenerate`, `postReportSave`, `getReport`, `downloadReport`
- `packages/case-dashboard/frontend/src/components/reports/ReportsTab.jsx` (new)
- `packages/case-dashboard/frontend/src/components/layout/NavRail.jsx` — add Reports icon + route
- `packages/case-dashboard/frontend/src/App.jsx` — route case for `'reports'`
**Acceptance (backend):**
- [ ] `GET /portal/api/reports` returns saved reports for active case `[{ id, profile, created_at, examiner }]`
- [ ] `POST /portal/api/reports/generate` body `{ profile, finding_ids?, start_date?, end_date? }` → calls `generate_report` with active case_id → returns `{ id, profile, report_data, sections, guidance }`. The `id` is server-assigned and held until save.
- [ ] `POST /portal/api/reports/{id}/save` persists via `save_report`
- [ ] `GET /portal/api/reports/{id}` returns saved report content + metadata
- [ ] `GET /portal/api/reports/{id}/download` streams markdown (`Content-Type: text/markdown`, `Content-Disposition: attachment; filename="…"`)
- [ ] Unknown profile → 400 with "Unknown profile" message (mirror the MCP tool's error shape)
- [ ] All endpoints require examiner role; readonly returns 403
**Acceptance (UI):**
- [ ] NavRail icon + Reports tab visible
- [ ] Profile selector populated from a static list (mirror the 6 profiles), with descriptions in tooltip
- [ ] Generate button → shows preview pane (markdown render of `report_data.summary` / `sections`)
- [ ] Save button persists the draft
- [ ] List pane shows saved reports; click → preview; Download button per row
- [ ] Generate button disabled while a generation is in-flight
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
- [ ] Rate-limit generation server-side (max 1 in-flight per case)
- [ ] `{id}` validated as UUID (no path traversal)
- [ ] Error map: generation failure → "Report generation failed. Check the case status."
- [ ] No filesystem paths leak into UI errors

---

### ☐ T-02 — Hosts tab

**Spec:** §4 Hosts Tab, §6 (planned)
**Files:** `frontend/src/components/hosts/HostsTab.jsx` (new), `NavRail.jsx`, `App.jsx`
**Acceptance:**
- [ ] Table renders one row per unique `host` value found across findings
- [ ] Columns: Host · Findings · Accounts (count) · Best Confidence · Time Range · Status Summary (badges)
- [ ] Click row → `setActiveTab('findings')` + filter findings by host (use existing `findingsFilter` or extend store with `findingsHostFilter`)
- [ ] Empty state: "No hosts in scope yet."
**Verify:** Open tab → 3 hosts shown matching the case → click `SRV-DC01` → Findings tab opens with sidebar narrowed to that host.
**Security gate:** N/A (read-only client aggregation).

---

### ☐ T-03 — Accounts tab

**Spec:** §4 Accounts Tab, §6 (planned)
**Files:** `frontend/src/components/accounts/AccountsTab.jsx` (new), `NavRail.jsx`, `App.jsx`
**Acceptance:**
- [ ] Table: Account · Findings · Hosts (count) · Best Confidence · Time Range · Status Summary
- [ ] Click row → switch to Findings filtered by account
- [ ] Empty state copy
**Verify:** Similar to Hosts. `CORP\jsmith` row → Findings narrowed.
**Security gate:** N/A.

---

### ☐ T-04 — IOCs tab

**Spec:** §3 (`GET /api/iocs`), §4 IOCs Tab, §6
**Files:** `frontend/src/components/iocs/IocsTab.jsx` (new), `NavRail.jsx`, `App.jsx`, `endpoints.js` already has `getIocs`
**Acceptance:**
- [ ] Table: Value (monospace, copy button) · Type · Category · Confidence badge · Hosts · Source Findings (clickable F-IDs) · Status badge
- [ ] Filters: category dropdown, status dropdown (DRAFT/APPROVED/REJECTED/ALL), search box
- [ ] Expandable rows show MITRE techniques + tags
- [ ] Click F-ID link → switch to Findings, select that finding
- [ ] Empty state
**Verify (SIFT VM):**
```bash
curl -sk -b "agentir_session=$SID" $BASE/iocs | python3 -m json.tool | head -50
```
Confirm IOC count in UI matches array length.
**Security gate:** N/A.

---

### ☐ T-05 — TODOs tab

**Spec:** §3 (`GET /api/todos`), §4 TODOs Tab, §6
**Files:** `frontend/src/components/todos/TodosTab.jsx` (new), `NavRail.jsx`, `App.jsx`
**Acceptance:**
- [ ] Table: ID · Title · Description · Priority (high/med/low — shape disambiguated badge) · Examiner · Status · Related findings (clickable) · Created at
- [ ] Filters: priority, status
- [ ] Default sort: priority desc, then created_at asc
- [ ] NavRail badge: count of open TODOs
**Verify:** open count in NavRail badge matches `/api/summary` `todos.open`.
**Security gate:** N/A.

---

### ☐ T-06 — Command palette

**Spec:** §4 Cross-cutting, §6 (planned CommandPalette.jsx)
**Files:** `frontend/src/components/layout/CommandPalette.jsx` (new), `App.jsx` (Ctrl+K binding), `useStore.js` already has `commandPaletteOpen`
**Acceptance:**
- [ ] `Ctrl+K` (and `Cmd+K`) opens palette anywhere
- [ ] Search across findings (id, title) + actions
- [ ] Quick actions: approve current, reject current, open commit drawer, refresh, sign out
- [ ] Esc closes; arrow keys navigate; Enter executes
- [ ] Recently selected items at top
- [ ] Use the `cmdk` package (already in `package.json`)
**Verify:** Ctrl+K → type "F-001" → Enter → finding opens.
**Security gate:**
- [ ] Focus trap inside palette (Spec §7)
- [ ] No actions that require password are executable without going through their normal modal

---

### ☐ T-07 — Audit trail panel (full surface)

**Spec:** §4 Findings → "Audit trail panel" (currently ◐), §6 FindingsTab
**Files:** `frontend/src/components/findings/FindingsTab.jsx`
**Acceptance:**
- [ ] `GET /api/audit/{finding_id}` called lazily when audit panel is opened
- [ ] Panel renders chronological audit entries: timestamp, tool, command, output excerpt, examiner action, audit_id (monospace)
- [ ] Visible from main detail view (not just Zone 2 — surface as a collapsible section above modifications)
- [ ] Errors render as scrubbed message (Spec §7)
**Verify:** Pick a finding with multiple audit entries → expand → all entries render → timestamps human-readable.
**Security gate:** Error scrubbing for the audit fetch.

---

### ☐ T-08 — Review velocity sparkline

**Spec:** §4 Overview → "Review velocity sparkline" (currently ☐), §5 (animation budget — one-shot only)
**Files:** `frontend/src/components/overview/ReviewSparkline.jsx` (new), `OverviewTab.jsx`
**Acceptance:**
- [ ] 24h bar chart of approval velocity, derived from `findings[].approved_at`
- [ ] Inline SVG, no chart library (Recharts is already in deps but a 30-line SVG is simpler and matches the density aesthetic)
- [ ] Tooltip on hover shows count + hour
- [ ] No animation after first render
**Verify:** Approve a finding → reload Overview → bar in the current hour ticks up by 1.
**Security gate:** N/A.

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
