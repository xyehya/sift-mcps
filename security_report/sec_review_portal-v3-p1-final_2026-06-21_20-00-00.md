# CodeGuard Security Review — Portal v3 (P1 final / consolidated)

**Skill:** `codeguard-security:security-review` (Project CodeGuard / CoSAI-OASIS)
**Rules:** CG-AUTH, CG-CRYPTO, CG-INJECT, CG-SECRET, CG-SUPPLY, CG-OWASP-JS
**Branch:** `portal-v3/p0-foundation` @ `1920f45` (all P1 tabs + design polish + D1–D10 remediation)
**Worktree:** `.claude/worktrees/portal-v3-p0-foundation/packages/case-dashboard/frontend/`
**Reviewer:** orchestrator (main session) — the spawned `security-expert` agent went idle without delivering (subagent messaging flakiness); review run directly for reliability.
**Date:** 2026-06-21
**Prior review:** `sec_review_portal-v3-p0_2026-06-21_00-50-00.md` (PASS-WITH-FIXES, 11 findings @ `01d7146`) — carry-forwards re-checked below.

---

## Executive Summary

**VERDICT: PASS-WITH-FIXES** — no Critical/High *blocking* the prototype; clean bundled supply chain, no secrets in bundle, no XSS sinks, sound crypto. Open items are production/P2-gating, not P3-blocking for a branch-stage rebuild.

**Findings:** 0 Critical · 1 High (prototype-mitigated) · 3 Medium · 2 Low · Info.

### Most critical
1. **[HIGH, prototype-mitigated] CG-AUTH** — Findings step-up Approve is still UI-only (`FindingDetail.jsx:251` `onConfirm={() => {…onApprove()…}}` drops the password). Now HONESTLY labeled (`'Finding approved (prototype — auth pending)'` + `TODO(CG-AUTH)` at the call-site) — the prior misleading "step-up verified" toast is fixed. Must wire to a server challenge before production.
2. **[MEDIUM] CSP not yet `'self'`** (`routes.py:3852`) — `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com`. Two problems: (a) the **Google Fonts origins are now DEAD** — the frontend self-hosts via `@fontsource` (D8), so `googleapis.com`/`gstatic.com` should be removed; (b) `'unsafe-inline'` is still required by ~10 data-driven inline styles (see #3).
3. **[MEDIUM] Residual inline styles block strict `style-src`** — 10 files retain `style={{}}`, all **data-driven numeric** (legit per AGENTS §11): `progress.jsx` translateX, `MasterDetailLayout` gridTemplateColumns, `ConfidenceRing`/`Skeleton`/`SeverityDistribution`/`AreaTrend` dims/widths. Not an injection risk, but they force `'unsafe-inline'` (or a nonce) — the blocker to CSP `'self'`.
4. **[MEDIUM] Dev proxy `secure:false` + hardcoded VM IP** (`vite.config.js:41,43`) — carry-forward, dev-only (not in prod bundle). Load the VM CA + move IP to env.

### Posture
Bundled `npm audit` = **0 vulnerabilities**. No secrets/JWTs/private keys in `static/v2`. **No `dangerouslySetInnerHTML`** anywhere (incl. the new Reports module — report content renders as escaped React text; a `<script>` payload test asserts inertness). `api/crypto.js` PBKDF2+HMAC-SHA256 via Web Crypto remains sound and is correctly used by EvidenceUnseal. Frozen auth/crypto tests byte-identical.

---

## Findings & carry-forward status

| ID | Sev | Status vs prior | Location | Finding / fix |
|----|-----|-----------------|----------|---------------|
| F1 CG-AUTH | High | **Partially resolved** (toast+comment fixed; enforcement still UI-only) | `findings/FindingDetail.jsx:251-256`, `StepUpApproveModal.jsx:69` | Step-up approves on any non-empty password. Honestly labeled now. **Prod fix:** `onConfirm(async pass => { challenge→computeChallengeResponse(pass)→POST /api/auth/step-up-approve })`. Same for Commit-to-record. |
| F2 CG-AUTH | — | **RESOLVED** | `FindingDetail.jsx:253` | `TODO(CG-AUTH)` now at the correct call-site. |
| CSP-1 | Med | **NEW/elevated** | `case_dashboard/routes.py:3855-3856` | Drop the now-unused `https://fonts.googleapis.com` (style-src) + `https://fonts.gstatic.com` (font-src) → `font-src 'self'`. Fonts are self-hosted; these origins are dead permissions. |
| CSP-2 (was F4) | Med | **Open** | 10 files w/ data-driven `style={{}}` | Blocks dropping `'unsafe-inline'`. Options: per-request **nonce** from `routes.py` (preferred), or document `style-src 'self' 'unsafe-inline'` as an accepted exception. P2. |
| F3 | Med | **Open** (dev-only) | `vite.config.js:43` | `secure:false` → load `~/.sift-vm-ca-…pem`. |
| F6 | Low | **Open** (dev-only) | `vite.config.js:41` | Hardcode IP → `process.env.VITE_API_PROXY`. |
| SUPPLY-1 | Low | **New** | `package.json` | Deps use caret ranges (`^19.2.6`, `^3.8.1`…) not exact pins (spec §5.7). Lockfile mitigates reproducibility; pin exact for supply-chain hygiene. `npm audit` prod = 0 vulns. |
| F7 | Info | **Open** | `package.json` | Verify `lucide-react` registry/version (network check not run here). |
| F5 | Low | Open | `overview/BlockedActionsPane.jsx` | Add plain-text JSDoc contract + "never dangerouslySetInnerHTML" marker. |
| XSS | Info | **Confirmed clean** | all `src/` incl. `reports/` | 0 `dangerouslySetInnerHTML`; Reports escaped-render proven by test. |
| CRYPTO | Info | **Confirmed sound** | `api/crypto.js` | PBKDF2+HMAC-SHA256, non-extractable key, server-supplied iterations. |
| SUPPLY-bundle | Info | **Clean** | bundle | `npm audit --omit=dev` = 0; no secrets in `static/v2`. (1 HIGH is test-only jsdom/undici devDep, not shipped.) |

---

## Minimum fix set to reach PASS

**P3-blocking (none for prototype/branch stage).** This is a dev/branch rebuild reaching `main` only at P4 — no Critical, supply chain + bundle + XSS + crypto all clean, the one High is honestly labeled prototype behavior.

**Before production (gate at P4/prod):**
- F1: wire the step-up Approve + Commit-to-record to the real server challenge (`crypto.js` infra exists).

**P2 (CSP tighten phase — already a planned deliverable):**
- CSP-1: drop the dead Google-font origins → `font-src 'self'`.
- CSP-2: resolve `'unsafe-inline'` via nonce or documented exception.
- F3/F6: vite proxy CA + env IP.

**Hygiene (low):** SUPPLY-1 exact-pin deps; F5 field contracts; F7 verify lucide-react.

---

## Appendix
- **Methodology:** delta review vs the `01d7146` CodeGuard baseline; full re-check of all 11 prior findings at `1920f45` + grep/audit sweep (`npm audit` prod+dev, dist secrets scan, `dangerouslySetInnerHTML`, inline-style census, CSP read, vite/dep config). chrome/browser checks unavailable (noted).
- **Clean confirmations:** 0 bundled vulns · 0 secrets in `static/v2` · 0 `dangerouslySetInnerHTML` · frozen auth/crypto tests byte-identical · no mock-fixture leak in dist.

---

## Reconciliation with the `portal-security` agent + fixes landed (`f8e47e2`, 2026-06-22)

The spawned `security-expert` agent's review was recovered (operator relay). It was **sharper than this orchestrator pass on three points, all code-verified and accepted**:
1. **`api/crypto.js` is DEAD CODE** — 0 external callers (verified). My/the-prior "crypto sound and used by EvidenceUnseal" was WRONG. The live re-auth model is **plaintext-password→Supabase** (`unsealEvidence(path,reason,password)`, `CommitDrawer → postCommit({password})`, CL3a/B-MVP-017), not challenge-response. The `TODO(CG-AUTH)` pointed at the dead `computeChallengeResponse()`.
2. **CG-AUTH downgraded High→Med** — Findings **Approve only STAGES a reversible `postDelta`**; the irreversible gate, **Commit-to-record, IS server-re-authed** (`CommitDrawer.jsx:95`). No false-security claim ships (toast already honest). So not a production auth bypass on the custody seal — a theater gate on a reversible action.
3. **`font-src` was the one P3-BLOCKING item** — `font-src https://fonts.gstatic.com` had no `'self'`, so the self-hosted `@fontsource` woff2 would be **blocked under the enforced CSP → fonts break in prod**. (I had mis-rated this as P2.)

**Fixed in `f8e47e2`:**
- `routes.py` CSP → `font-src 'self'`, dropped the dead Google origins, added `base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'`, `img-src 'self' data:`; retained `style-src 'self' 'unsafe-inline'` with a comment (the §11 data-driven numeric styles; nonce = the path to pure `'self'`). **P3-blocking item RESOLVED.**
- `FindingDetail.jsx` + `StepUpApproveModal.jsx` `TODO(CG-AUTH)` rewritten to the live plaintext→Supabase model + flagged `crypto.js` as dead (don't wire to it).

**Updated verdict: PASS-WITH-FIXES, P3 gate CLEARED** (the only P3-blocking item is fixed). Remaining are non-blocking: F2 Approve (product decision — server-gate or drop the modal), F3/F6 vite dev-proxy CA+env (dev-only), F4 delete `crypto.js`+vestigial challenge endpoints (cleanup; check the frozen EvidenceUnseal test first), F5 bump `jsdom`→undici (test-only devDep), `style-src` nonce, exact-pin deps, F7 verify lucide-react registry.

---

## Remediation decision + batch (operator, 2026-06-22)

- **F2 — DECIDED: drop the password modal.** Operator chose to make **Approve immediate** (like Stage/Reject — all three write a reversible staged delta via `postDelta`, no server password). Rationale: the real irreversible gate (**Commit-to-record**) is already server-re-authed (plaintext-password→Supabase, `CommitDrawer:95`); a password on the reversible Approve was friction-theater + inconsistent with Stage/Reject. Deviates from the settled handoff's "step-up on Approve" — accepted. `StepUpApproveModal.jsx` removed.
- **DONE — batch landed @ `43abe03`** (orchestrator-verified): F2 immediate Approve + `StepUpApproveModal` deleted (`05bd302`/`bfa75b6`) · F4 `api/crypto.js` + 3 dead `get*Challenge` endpoints deleted, `getCaseActivateChallenge` KEPT (live caller `CaseDialogs.jsx`) (`40e6021`) · F5 undici 7.26.0→7.28.0, **npm audit 0** (`64b8bb2`) · F5b BlockedActions plain-text JSDoc + XSS markers (`2c831b5`) · F6 vite proxy verified-TLS via VM CA, guarded + env (`43abe03`) · SUPPLY-1 20 deps exact-pinned (`d1c7a29`) · F7 lucide-react@1.21.0 verified GENUINE (official, no-fix). 259 tests green · build clean · frozen byte-identical.
- **Deferred (documented):** `style-src 'unsafe-inline'` → nonce — kept as the documented exception in `routes.py` (data-driven §11 numerics); a nonce-injection pass is a separate P4 item, not done now.
- Guardrails: frozen `EvidenceUnseal`/`useStore.interface` byte-identical; source-only; gate on build+tests+eslint+`npm audit` (prod=0).

---

## CORRECTION — CSP was hardened in the wrong layer (P3.5 live finding, 2026-06-22)

A P3.5 live-validation check against the SIFT VM revealed that the P3 CSP
remediation (CSP-1, item #79 above) was applied to **`packages/case-dashboard/src/case_dashboard/routes.py`** `SecurityHeadersMiddleware` — which is **INERT for `/portal/`**.

**Root cause.** The portal is mounted as a sub-app *inside the gateway*. The
gateway's `packages/sift-gateway/src/sift_gateway/server.py`
`SecureHeadersMiddleware` **WRAPS** the mounted case_dashboard app, so for
`text/html` responses under `/portal` the gateway sets the
`Content-Security-Policy` header **last and wins** — overriding whatever
`routes.py` set. The hardened CSP in `routes.py` therefore never reached the
browser for `/portal/`; the live VM served the gateway's un-hardened policy:

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com
```

That policy carries the same two defects CSP-1 set out to fix: **dead Google-font
origins** (`fonts.googleapis.com` / `fonts.gstatic.com` — the portal self-hosts
fonts via `@fontsource` → `/portal/assets/*.woff2`) and **missing hardened
directives** (`default-src 'none'`, `base-uri`, `form-action`, `frame-ancestors`,
`object-src`, `img-src`, `connect-src`).

**Fix (2026-06-22).** The hardened CSP is now set at the **authoritative layer**
— `server.py` `SecureHeadersMiddleware`, gated to `text/html` + `/portal`, with a
code comment marking it authoritative so future portal-CSP edits land there.
`routes.py` is kept byte-consistent (it still governs non-`/portal`-html
case_dashboard responses, e.g. JSON). The corrected effective `/portal` policy:

```
default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'
```

`'unsafe-inline'` is retained in **style-src only** (AGENTS §11 data-driven
numeric inline styles; per-request nonce remains the deferred P4 item).
`packages/sift-gateway/tests/test_secure_headers.py` updated to assert the
corrected policy (2 passed). Gateway diff vs `b995491` = this CSP change + its
test only. **The hardened CSP only becomes live once the gateway is redeployed to
the VM** (the VM predates the D7 refactor — see `design/RUN-PORTAL-V3-VM-DEPLOY.md`).
