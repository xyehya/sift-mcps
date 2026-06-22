# Portal v3 — Extension / Backwiring Backlog

A separate, operator-led track (kicked off 2026-06-22 during P3.5 live validation) for
**wiring placeholder UI to real backends** and related improvements. These are *not*
P3.5/P4 blockers — the portal is parity-complete with the legacy portal and the live
data path is verified. This file is the seed for that extension project.

Scope rule: anything here is a deliberate deferral, tracked so it isn't mistaken for a
regression. The portal reaches `main` (P4) without these; they land afterward.

---

## B1 — Agent Activity feed is fabricated (real-mode synthetic data) — HIGH priority
- **Where:** `src/components/overview/AgentActivityFeed.jsx`.
- **What:** Renders from a hardcoded `POOL` of ~18 synthetic forensic events
  ("MFT parsing: 412,309 records…", "Lateral movement: RDP session to DC-01",
  "IOC match: 185.66.0.12"…), prepended on a timer. It is **NOT gated by the mock
  flag** (`window.__SIFT_MOCK__`), so it shows invented events **in real mode** too.
  Its own comment admits: "driven from a pool of sample events in mock/demo mode."
- **Why it matters:** trust/safety — a forensic tool must never present invented log
  lines that an examiner could mistake for real agent activity. (It was built as a
  design-mockup visual for handoff Screen 1; the old portal had no such view.)
- **Note:** a *correct* sibling already exists — `src/components/overview/ActivityFeed.jsx`
  derives the "live tail" from **real findings** within a time window ("without
  fabricating synthetic log lines").
- **Backwiring options (operator decision deferred):**
  1. Wire `AgentActivityFeed` to a real source — gateway **audit events** / agent
     activity stream (needs a backend endpoint, e.g. `/api/agent/activity` or reuse
     `portal_state.custody` / `audit_events`). Largest value.
  2. Gate the synthetic feed to `?mock=1` only; render `ActivityFeed` (real) in prod.
  3. Remove `AgentActivityFeed`; keep only the honest `ActivityFeed`.
- **Operator decision (2026-06-22):** keep as-is for now; backwire under this project.

## B2 — Commit-to-record badge is stale up to the poll interval — MED priority
- **Where:** `src/components/findings/FindingsTab.jsx` (`stagedCount = delta.length`),
  `src/components/layout/CommitDrawer.jsx`, fed by `src/hooks/useDataPolling.js`.
- **What:** The "Commit to record N" badge (and the drawer) read `store.delta`, which
  is only refreshed by the **15-second** poll of `/api/delta`. With the autonomous
  agent mutating staged deltas server-side, the badge lags reality — observed live
  flashing **8 → 0** as the poll caught up (server `/api/delta` was `{"items":[]}`).
  This is the "badge says 8 but Commit shows nothing" symptom. **Not fabricated data**
  — it is correctly wired, just stale between polls.
- **Fix (small, safe):** refetch `/api/delta` eagerly on Commit-drawer open and
  immediately after stage/approve/reject/commit, so badge + drawer always reflect
  server truth instead of waiting up to 15s.
- **Note:** "0 findings" itself is **correct** for the current case — `/api/findings`
  = `[]`, `/api/summary` findings.total = 0. Not a bug.

## B3 — (catch-all) other "looks live but isn't yet" surfaces
- All `src/_mock/fixtures.js` data is **properly gated** to `?mock=1` (DEV-only;
  `window.__SIFT_MOCK__` guards the poll; prod-dist scan = zero mock leak). No action
  needed unless a new view bypasses the adapter layer (AGENTS §3).
- Add future placeholder/not-yet-wired views here as they're introduced, so the
  real-mode surface stays honest.

---

## Already fixed during P3.5 (not part of this backlog — listed for context)
- **Favicon 404/401** — `index.html` now declares `<link rel="icon" href="/portal/favicon.svg">`
  (asset already in `public/`), so the browser stops probing the protected root
  `/favicon.ico`. Fixed 2026-06-22.
- **`/` → `/portal/` redirect** — already present in `server.py` (307); verified live.
- **Portal CSP** — hardened at the authoritative gateway layer (`server.py`
  `SecureHeadersMiddleware`); see `RUN-PORTAL-V3-VM-DEPLOY.md`.
