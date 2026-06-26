# Codex Security Assessment — Validation Tracker (session 2026-06-26)

Orchestrated re-validation of the restored Codex deep-scan (`docs/codex-assessment/`).
Scan base = `b995491` (2026-06-20); current HEAD has drifted ~183 commits, so every
finding is re-located and re-judged against **current** code.

**Phase:** validation (no fixes applied this session). Fixes → issue tracker after operator review.

## Clusters & agents (all Opus 4.8 / xhigh, read-only, codeguard-security + codebase-memory MCP)

| Cluster | Agent | Candidates | Theme | Verdict file | Round 1 | Verifier | Status |
|---|---|---|---|---|---|---|---|
| AUTH | sec-auth | 001, 002, 014, 015 | REST control-plane access control + token lifecycle + Supabase legacy fallback | `cluster-AUTH.md` | ✅ done: **002 High→Critical-chained** (agent/service NOT blocked from /api/v1) · 001 Med (operator-only; worker dep) · 014 Med · 015 Med (insecure default) — all STILL-VALID | — | — |
| BACKENDS | sec-backends | 003, 004, 019, 020 | Backend registration authority, runtime egress, env inheritance, join flow | `cluster-BACKENDS.md` | ✅ done: 004+020 STILL-VALID High · 019 PARTIAL Med · 003 NEEDS-OP/Low | — | — |
| EXEC | sec-exec | 006, 007, 022 | run_command sudo fallback, privileged mount-worker, systemd isolation downgrade | `cluster-EXEC.md` | ✅ done: all 3 **over-rated vs packaged posture** → 006 Med (inert: agent_runtime can't sudo) · 007 Med (intended design; residual = hostile-image kernel isolation) · 022 Low (prod ships =1 fail-closed) · +3 adjacent findings | — | — |
| OS-ISO | sec-osiso | 010, 011, 012 | OpenSearch cross-case index override, status enumeration, enrichment scope fail-open | `cluster-OS-ISO.md` | ✅ done: 010 STILL-VALID **High** (agent-reachable cross-case read) · 011 STILL-VALID Med (recon) · 012 STILL-VALID but **inert/Low** (real gate at gateway) | — | — |
| ARCHIVE | sec-archive | 008, 009, 017 | tar / 7z / zip extraction containment (zip-slip / traversal) | `cluster-ARCHIVE.md` | ✅ done: 008/009/017 all PARTIALLY-FIXED Low (binaries block escapes) · **cross-cutting Med** = decompression-bomb DoS unmitigated + version-trust fragility; fix = 1 shared hardened extract_container | — | — |
| EGRESS-MISC | sec-egress | 005, 021, 013, 016, 018 | RAG SSRF (allowlist+redirect), DB SECDEF revoke, OpenCTI creds/plaintext | `cluster-EGRESS-MISC.md` | ✅ done: 013 ALREADY-FIXED (residual: no CI test) · 005+021 Low-live (offline CLI) · 016+018 Low (non-live OpenCTI) | — | — |

## Verifier-griller

Skipped per operator instruction (2026-06-26) — operator reviews the 6 cluster files directly.

## Round-1 consolidated outcome (all 22 + adjacent)

**Severity after re-validation against HEAD `93f8999`** (Codex's pre-drift ratings in parens):

- **High (4):** 002 control-plane authority *(crit, chained)* · 010 OpenSearch cross-case read *(high)* · 004 HTTP-backend runtime egress SSRF *(high)* · 020 stdio env DB-creds leak *(high)*
- **Medium (6 + 1 cross-cutting):** 001 REST tool bypass *(high→med, operator-only)* · 014 legacy token mint *(high→med)* · 015 legacy fallback insecure default *(high→med)* · 011 status enumeration recon *(med)* · 019 wintools join *(med)* · 006 sudo fallback *(high→med, inert in prod)* · 007 hostile-image kernel isolation *(high→med, intended design; residual only)* · ARCHIVE cross-cutting bomb-DoS/version-trust *(new)*
- **Low (6 + adjacent):** 022 systemd auto downgrade *(med→low)* · 012 inert enrich gate *(med→low)* · 013 residual: missing SECDEF CI test *(med→low; revoke ALREADY-FIXED)* · 003 backend-reg authority *(high→low/needs-op)* · 005+021 RAG SSRF *(med→low-live, offline CLI)* · 016+018 OpenCTI *(med→low, non-live stack)* · EXEC-adjacent: seccomp=log on sync gateway lane *(new, low-med)*
- **ALREADY-FIXED (1):** 013 PUBLIC-EXECUTE revoke on `app.evidence_unseal` (migration `202606242200`, commit `05e9782`).
- **FALSE-POSITIVE: 0.**

Net: Codex's findings were technically real but **systematically over-rated** because the scan predated 183 commits of hardening (agent_runtime confinement, sudoers minimization, evidence-gate-before-dispatch, the case-prefix index guard, the SECDEF revoke migration) and did not model the packaged production posture. The genuinely urgent, agent-reachable items are **002 and 010**.

Consolidated proposed issues: `ISSUE_LIST_PROPOSED.md` (16 issues; several Codex candidates collapse into one shared fix).

## Phase 2 — operator decisions (RESOLVED 2026-06-26)

All 10 gating decisions settled (full log + impacts in `ISSUE_LIST_PROPOSED.md`):
SEC-1 examiner+step-up · SEC-2 bind index · SEC-4/003 examiner+step-up+command-allowlist ·
SEC-6 **full legacy-fallback removal** · SEC-9 **deferred → standalone live-VM investigation**
(operator: some vol plugins may need sudo — not settle-able statically) · SEC-10 accept+document
residual · SEC-5 worker-only endpoint · SEC-16 flip gateway lane to `kill` after Wave-2 socket
handling · SEC-8 configurable caps · SEC-15 defer OpenCTI.

Two follow-up verifications by sec-exec: SEC-9 root-need (hypothesis refuted by code, but operator
defers to live-VM test) + SEC-16 seccomp (kill is safe — filter is per-tool-stage in the forked
launcher, not the gateway process).

**Validation + scoping phase COMPLETE.** Next: choose tracker destination + batch-launch coding
agents in build order (SEC-9 carried as a live-VM investigation, not a code fix).

## Phase 3 — build (in flight, 2026-06-26)

Tracker destination: **in-repo `ISSUE_LIST_PROPOSED.md` only** (Linear stays paused; no GitHub yet).
Coding agents commit to isolated branches off HEAD `911072b`; **no merge-to-main / push without operator ok.**

Batch 1+2 launched (3 by-domain writer agents, manual worktree isolation):

| Agent | Worktree / branch | Issues | Status |
|---|---|---|---|
| fix-auth-reg | `wt/sec-auth-reg` · `sec/auth-registration-hardening` | SEC-1 (control-plane authority + step-up) · SEC-4 (stdio minimal-env + command allowlist) | ✅ committed `093b129` + orchestrator-verified (deny-by-default gate, NO fail-open — anonymous=operator only in true single-user mode; structural route-table fail-on-revert test; env allowlist not denylist; 736+403 tests green). Flags: step-up=behavioral change (CLI must send creds under Supabase); join_gateway un-gated until SEC-3; allowlist=catalog-containment (XYE-25 for deep argv) |
| fix-opensearch | `wt/sec-opensearch` · `sec/opensearch-case-isolation` | SEC-2 (bind index to active case) · SEC-12 (remove inert enrich gate) | ✅ committed `6cea166` + orchestrator-verified (both-layers binding fails-closed; get_event bound at gateway; active_case non-None guard; 1246+684 tests green, wildcard test flipped). Residual: behavior not live-proven (2-case VM) → **live-prove WITH SEC-7** |
| fix-db-test | `wt/sec-db-test` · `sec/secdef-hardening-test` | SEC-13 (SECDEF-no-PUBLIC-EXECUTE CI test) | ✅ committed `7c0abfd` + orchestrator-verified (folds in NULL-proacl default-grant → catches recurrence class; DSN-gated, ruff clean). Residual: live PASS unproven (no DB) → prove on migration-apply run + wire DSN into integration job |

After commit: verifier-griller pass on each branch → operator review → merge to main (operator ok) → live deploy-and-prove for behavioral fixes (SEC-1/SEC-2).

### Independent verification — Codex (cross-model), 2026-06-26
Routed the full verification through `codex exec --sandbox danger-full-access` (read-only; only wrote
the verdict doc). Full record: `CODEX-VERIFICATION.md`. Reproduced all 3 suites (56 / 41 / 2-skip).

| Branch | Codex verdict | Orchestrator reconciliation |
|---|---|---|
| `sec/secdef-hardening-test` (SEC-13) | **GO** | Agree — confirmed (catches NULL-proacl recurrence; honest skip). |
| `sec/opensearch-case-isolation` (SEC-2/12) | **Conditional GO / PASS-WITH-FIXES** | Agree — gateway-agent path fully protected; residual = backend `_validate_index` falls back to `case-` (allows `case-*`) when NO active case (direct-backend/standalone path, outside agent threat model). Boundary-definition decision: accept-as-standalone-residual vs fail-closed. Minor: reject empty comma segments. |
| `sec/auth-registration-hardening` (SEC-1/4) | **NO-GO** | Agree — **CONFIRMED real gap**: SEC-4 "command allowlist" is a *directory* allowlist (`mcp_backends_registry.py:400-484`); venv `bin` contains `python`/`pip`/`uv`, so `command=<venv>/bin/python -c …` passes → arbitrary stdio exec by an authenticated operator. SEC-1 gate + env-leak fix are solid; only the allowlist is the blocker. Fix = exact-executable catalog + explicit interpreter/shell/pkg-mgr denylist even within allowed dirs + regression test (venv python denied, console-script allowed). |

**Merge blocker:** SEC-4 command allowlist (re-loop fix-auth-reg). SEC-13 ready to merge; SEC-2/12
ready pending the no-active-case boundary decision; SEC-1 ready (ships with the allowlist fix).

### Operator resolution of the Codex findings (2026-06-26)
- **Finding A — SEC-4 command allowlist: DROPPED (risk-accepted).** Operator decision: an
  authenticated operator launching a backend is **not in the threat model** — backend registration
  is intended operator authority (matches DSS-CAN-003 "intended authority"); stolen creds are covered
  by other controls (SEC-1 auth gate + step-up). The command allowlist was guarding a non-threat. The
  SEC-4 **env-leak minimization is KEPT** (real value: no DB secrets to add-on children). Codex NO-GO
  is resolved by this risk decision — the allowlist was the only blocker → **SEC-1/4 now GO.**
  (Existing `assert_stdio_command_allowlisted` is harmless hygiene; not claimed as a security boundary.
  Optional later cleanup, not a blocker.)
- **Finding B — SEC-2 no-active-case fallback: MOOT (confirmed).** In DB-authority mode a case-scoped
  tool hits `require_active_case_for_principal`→`get_active_case`, which RAISES `no_active_case` (404)
  when nothing is active (`active_case.py:622-624`) — case-scoped MCP tools are blocked at the gateway
  with no active case, like the evidence gate. The backend `case-*` fallback is unreachable via the
  agent/gateway path (direct-CLI only). Accept as standalone residual; free empty-segment tidy optional.

**Net: all three branches GO.** SEC-13 as-is · SEC-2/12 as-is (optional empty-segment tidy) · SEC-1/4
as-is (env-leak kept, command-allowlist requirement dropped). Remaining before merge: operator
go-ahead + SEC-1 step-up acceptance (behavioral change) + live deploy-and-prove (SEC-1/SEC-2).

### Phase 3b — final re-loops (in flight) + execution plan (operator-approved 2026-06-26)
Operator: keep step-up but reuse the EXISTING password-re-entry double-auth; then commit → rsync to
VM → live-test → then proceed to the rest.
- **fix-auth-reg** 🔄 — rework SEC-1 step-up to **password re-entry only**, sourcing email/auth_user_id
  from the authenticated bearer-token Identity (not the body), reusing `_supabase_reverify` /
  `reverify_password` (the same primitive used for evidence seal/commit/report/case-activate/backend
  control + API-key issuance). Command-allowlist left as-is (risk-accepted). Authority gate + env-leak
  unchanged.
- **fix-opensearch** 🔄 — reject empty `index` comma-segments at both backend + gateway layers (SEC-2 tidy).
- **fix-db-test** ✅ — no change (SEC-13 done).

Execution after re-loops report + re-verify: merge all three branches → `main` (operator go-ahead) →
rsync changed source to the VM `/opt/sift-mcps/...` → clear `__pycache__` → restart sift-gateway +
opensearch-worker@{1,2} + job-worker → **live deploy-and-prove**: SEC-1 (agent token → 403 on
`/api/v1/backends`, examiner+password → ok), SEC-2 (2 cases: `index="case-*"`/other-case → denied),
SEC-13 (run with DSN → passes). Then proceed to Batch 3 (SEC-3/5/6/7) + SEC-9 (live vol-plugin trace)
+ SEC-16 (seccomp kill after socket handling).

### Phase 3c — merged + deployed + LIVE-PROVEN (2026-06-26)
Merged 3 branches → local `main @ 7acc0c8` (not pushed). Combined SEC suites green (gw 97p/2s, os 45p).
rsync'd changed source to VM `192.168.122.81` (sansforensics), cleared `__pycache__`, restarted all 4
services (active, no errors). Live-prove via host curl + the live MCP connection (active case
`case-test-case-06251017`, evidence chain OK):
- **SEC-1 ✓ LIVE** — agent token → `POST /api/v1/backends` → **403** `{"error":"Operator authority required..."}`; no backend row created.
- **SEC-2 ✓ LIVE (search family)** — `opensearch_search(index="case-seed-evtx-init")` and `index="case-*"` → **DENIED** ("outside the active case ... allowed prefix 'case-test-case-06251017-'"); `index="case-test-case-06251017-prefetch-rocba"` → **works** (1081 hits). Audited.
- **SEC-13 ✓ LIVE** — 0 of 15 `app` SECDEF fns PUBLIC-executable; migration `202606242200` recorded.
- **SEC-12 ✓ / SEC-4 ✓** — deployed (verified in deployed source: enrich env gate gone; `_build_minimal_backend_env` used).

**NEW FINDING (live-caught) — SEC-2 `get_event` agent-path gap:** the SEC-2 gateway-boundary `case_bound`
check was added to `Gateway.call_tool` (REST `/api/v1/tools` path), but the agent/MCP path dispatches via
`policy_middleware.py::CaseContextMiddleware` (case injection 842-851) which has NO `case_bound` check.
`opensearch_get_event` has `safe_case_argument_names: []` → no `case_dir` injected → backend falls back
to the weak `case-` guard → **cross-case exact-index `get_event` is NOT denied on the agent path**
(proven: `get_event(index="case-seed-evtx-init")` → `not_found`, not denied — the cross-case index was
accepted). LOW practical risk (needs an out-of-band exact other-case index + a valid `_id`; search is
denied so `_id`s can't be discovered via the gateway). The DB-manifest refresh I applied enables the
boundary on the REST path only (harmless, removes drift). **Fix (re-loop): port the `case_bound`
active-case validation into `CaseContextMiddleware` (the agent/MCP path), mirroring the
`Gateway.call_tool` boundary — closes get_event + adds defense-in-depth for all query tools on the
agent path.** Then re-deploy + re-prove get_event. This is the project's recurring "fix at the wrong
surface" lesson — caught by deploy-and-prove, not by the green harness.

### Phase 3d — root-cause relocation (per sift-architecture.html), in flight 2026-06-26
Arch names the agent tool-call gate chain (verified in mcp_server.py + policy_middleware.py):
(1)GatewayToolCatalog (2)ToolAuthorization (3)AddonAuthority **(4)CaseContext** (5)AuditEnvelope
**(6)ProxyActiveCase** (7)EvidenceGate (8)ResponseGuard (9)OpenSearchJobDispatch. `rest.py`/`Gateway.call_tool`
is **portal-only**. So the SEC-2 case_bound check belongs at **gate 6 ProxyActiveCaseMiddleware** (where
case args are injected/validated on the agent path), NOT `Gateway.call_tool`. **Monkey patch dropped:**
the case_bound loop in `Gateway.call_tool` (never ran for agents). Re-loop `sec/case-bound-agent-path`
(worktree `wt/sec-casebound` off main 7acc0c8): drop from call_tool -> add to ProxyActiveCaseMiddleware
(before the `if not safe_args` early-return so it covers get_event) -> relocate the 3 boundary tests to the
agent/MCP harness + add a get_event cross-case agent-path denial test. Keep backend `_validate_index` +
manifest declaration + drift guard. Then merge -> redeploy -> re-prove get_event live.

**DONE + LIVE-PROVEN (2026-06-26):** relocated to gate (6) ProxyActiveCaseMiddleware + dropped the
Gateway.call_tool monkey patch + fail-closed when prefix unresolvable (commits 563b851 + d496b7d,
merged `main @ faa782d`). test_ad2 41 passed; redeployed gateway src to VM + restarted. **Live re-prove:**
`opensearch_get_event(index="case-seed-evtx-init")` under active case `case-test-case-06251017` ->
**DENIED** "cross-case access denied" (was `not_found`/accepted before); intra-case get_event of a real
doc -> works. **SEC-2 now fully closed on the agent path (all query tools + get_event).**

## Phase 4 — Wave 2 build (in flight, 2026-06-26)

Batch 1 DONE + LIVE-PROVEN + pushed `origin/main @ faa782d` (SEC-1/2/4/12/13). Batch-1 worktrees
(sec-auth-reg, sec-casebound, sec-db-test, sec-opensearch) removed; branches merged + deleted.

Remaining build order (per ISSUE_LIST): SEC-7 → SEC-3 → SEC-6 → SEC-5 → SEC-8 → SEC-11 → SEC-16
→ SEC-14 → SEC-10. Carried (not auto-built): SEC-9 (live-VM vol-plugin needs-root investigation),
SEC-15 (deferred until OpenCTI live).

| Agent | Worktree / branch | Issue(s) | Status |
|---|---|---|---|
| fix-os-status | `wt/sec-os-status` · `sec/opensearch-status-case-scope` | SEC-7 (bind opensearch_status + shard_status to active case; filter catalog; cluster health/capacity stays unscoped; operator all-case = portal-only, not an MCP tool) | 🔄 in flight (parallel). Live-prove WITH SEC-2 (2-case). |
| fix-egress | `wt/sec-egress` · `sec/http-backend-egress` | SEC-3 (shared resolve-and-pin egress policy at persistence+materialization+every connect; creds-after-validation; no-auto-redirect) + DSS-CAN-019 (join-code→host binding) | 🔄 in flight (parallel). Disjoint files from SEC-7. |

Validation notes captured pre-spawn:
- **SEC-7:** `opensearch_status` is the declared health tool but is ALREADY case-scoped (`default_case_scoped:true`); the operator `/health` endpoint uses backend **lifecycle** state (`health.py::_operator_backend_health`), NOT the MCP tool — so filtering the tool won't break health. Fix = add `case_id`/`case_dir` to both manifest `safe_case_argument_names` + tool signatures (gate-⑥ injects, like `opensearch_case_summary`) → backend filters `indices[]` / `top_indices_by_shard_count` to `case-{active}-` prefix; keep `cluster_status` + capacity numbers unscoped; no-active-case ⇒ cluster-only + EMPTY list (never all `case-*`).
- **SEC-3:** runtime gap = `HttpMCPBackend.start()` connects to DB-registered `url` with no egress check, bearer attached pre-connect, httpx re-resolves on every reconnect (`follow_redirects=True`). `_validate_remote_fetch_url` runs only on manifest fetches and does not pin. Join flow registers `wintools_url` with syntax-only checks, code unbound to host.

After each branch: orchestrator-verify (diff + tests) → security-expert (read-only) → optional Codex cross-model → operator go-ahead → merge → push → live deploy-and-prove on VM (192.168.122.81).

### Phase 4a — batch-2 committed + orchestrator-verified (2026-06-26)
Window-crash recovery: the first two background agents died mid-flight (SEC-7 left uncommitted high-quality edits; SEC-3 had not started). Relaunched both; both now committed.

- **SEC-7 `sec/opensearch-status-case-scope` @ ee09499 (was cc04c14; amended Field(default=""))** — opensearch_status/shard_status bound to active case. `_resolve_active_prefix` mirrors case_summary; `indices[]`+`top_indices_by_shard_count` filtered to `case-{key}-`; cluster health/capacity unscoped; no-active-case ⇒ empty catalog. `StatusIn`/`ShardStatusIn` advertise case_id/case_dir (required for gate-⑥ injection). **Orchestrator-verify PASS:** 198 changed-test pass (worktree PYTHONPATH); scoping test is genuine fail-on-revert incl. the trailing-dash boundary (`case-inc-` ≠ `case-incident-evtx`); src 0-new ruff (server 42=42, registry 5=5) + 0-new pyright (34=34 via extraPaths trap-fix); test-file lint matches existing repo convention (E402/E501/F841/I001 non-gated in tests); surface golden regen = only the case_id/case_dir schema + description deltas; resource forms confirmed non-leaking (empty catalog).
- **SEC-3 `sec/http-backend-egress` @ 58a43ca (was 068622d; +lint cleanup commit)** — shared resolve-and-pin egress (`backends/egress.py`) at persistence+materialization+every connect/reconnect+manifest; creds-after-validation; follow_redirects=False; `_PinnedEgressTransport` dials pinned IP with SNI/Host=hostname (TLS hostname verification preserved) + host-mismatch rejection; DSS-CAN-019 join fail-closed (bound host required, exact match, egress-checked, threaded into persistence). **Orchestrator-verify PASS:** full gateway suite 766 passed / 2 skipped (worktree PYTHONPATH — root .venv editable-installs from MAIN, so PYTHONPATH=src:tests is mandatory or you test main's code, see [[reference_worktree_editable_install_resolution_trap]]); 23 fail-on-revert tests (rebinding/connect-before-token/pin+TLS-SNI/join-binding/IPv6+mapped+unspecified/register-denial/redirect-off/env-allowlist); ruff 0-new (egress.py clean; changed files = main counts); pyright 0-new (egress.py clean; the lone http_backend `call_tool`-on-None finding is pre-existing, present identically on main @ :221).

Both codeguard verdicts PASS (from coding agents). Independent **security-expert pass (sec-review-batch2)** in flight on both branches. After its verdict → operator merge go-ahead → merge both → push → **live deploy-and-prove**: SEC-7 with the SEC-2 2-case setup (status under case A lists only case-A indices; cross-case enumeration gone); SEC-3 mostly unit-proven (live wintools join needs a real Windows host; document SIFT_EGRESS_ALLOWED_HOSTS/CIDRS for wintools restart on a private LAN).

NOTE (carry to deploy runbook): SEC-3 sets `follow_redirects=False` for ALL http backends (was True for the non-tls-pinned path) and pins to the FIRST validated IP (no multi-IP failover) — intended posture; flag if any backend relied on 30x or dual-stack failover.

### Phase 4b — independent security-expert pass (sec-review-batch2, read-only, 2026-06-26)
codeguard-security:codeguard run (codebase-memory MCP was disconnected → ripgrep+Read fallback). Reviewed the CURRENT HEADs via `git diff main`.
- **SEC-7 @ ee09499 → PASS / GO, no findings.** Confirmed: trailing-dash boundary correct; gate-⑥ OVERWRITES+DENIES client case_id/case_dir (no agent override); UUID-shaped case_id ignored → resolves from injected case_dir; no-active-case ⇒ empty (never cluster-wide); prefix agrees with SEC-2 `Gateway._active_case_index_prefix`; fix at all 3 surfaces; resource forms non-leaking.
- **SEC-3 @ 58a43ca → PASS-WITH-FIXES / GO.** Core anti-SSRF/anti-rebinding correct & well-tested (any-internal-rejects, IPv4-mapped unwrap, TLS SNI preserved, creds-after-validation, reconnect re-pins, DSS-CAN-019 fail-closed). Findings:
  - **SEC3-F1 (Low SSRF):** CGNAT `100.64.0.0/10` not blocked (ipaddress: not private/not global/not reserved) → shared/NAT64/cloud-internal reachable. **Being fixed NOW pre-merge** (fix-egress-2): block via `not ip.is_global` primary + keep explicit checks; +fail-on-revert CGNAT test + escape-hatch-still-works test.
  - **SEC3-F2 (Info, DEFERRED):** control-plane Supabase egress (`health.py:146`, `supabase_auth.py:339`) not routed through the pin — OUTSIDE SEC-3 add-on scope, operator-configured (not agent-influenced). Optional defense-in-depth follow-up; tracked, not blocking.
  - **SEC3-F3 (cosmetic):** case-sensitive host compare in `_PinnedEgressTransport` (httpx lowercases in practice, fails-closed anyway) → tidied with explicit `.lower()` in the F1 commit.

**Merge gate:** SEC-7 ready now; SEC-3 ready after SEC3-F1 lands + re-verify. Then → operator go-ahead → merge both → push → live deploy-and-prove (SEC-7 with SEC-2 2-case; SEC-3 unit-proven).

### Phase 4c — SEC3-F1 closed, merged, deployed, LIVE-PROVEN, pushed (2026-06-26)
- **SEC3-F1 closed @ 668bbe3** (fix-egress-2): `_ip_is_blocked` now blocks via `not ip.is_global` (deny-by-default, primary) + explicit terms as belt-and-suspenders; closes CGNAT 100.64.0.0/10 + benchmarking 198.18.0.0/15; escape hatch (allowlist) proven intact. +4 fail-on-revert tests (32 total). Suite 775/2, ruff/pyright 0-new. codeguard PASS. SEC3-F3 host-compare `.lower()` tidied. SEC3-F2 (Supabase egress) DEFERRED (out of scope, tracked).
- **Contract commit `49cdbea`** (operator-requested, standalone): CLAUDE.md + root AGENTS.md required-agent-loadout (codeguard + codebase-memory + LSP validators). Frontend design-system AGENTS.md untouched.
- **Merged → local main**: `ee1620c` (SEC-7) + `4d81e5b` (SEC-3), ort, no conflicts. Re-validated on merged main: opensearch 1260/71, gateway 775/2.
- **Deployed to VM** 192.168.122.81: rsync'd ONLY the committed SEC-changed files (excluded operator's uncommitted policy_middleware.py type-cleanup WIP) → cleared __pycache__ → **refreshed DB manifest** for opensearch-mcp (drift bf925c0f→505ac55b; DB `app.mcp_backends.manifest` now carries `safe_case_argument_names:[case_id,case_dir]` for both status tools — runtime authority) → restarted all 4 services (active, clean, no drift warnings).
- **SEC-7 LIVE-PROVEN** (agent /mcp path, active case `case-test-case-06251017`): cluster has 42 `case-*` indices = 38 active + 4 other-case (`case-seed-{accesslog,evtx,json,ssh}-init`). `opensearch_status` returned exactly the 38 active-case indices, ZERO `case-seed-*`; `opensearch_shard_status.top_indices` all active-case, cluster capacity preserved (48/3000, 98.4%). Cross-case recon CLOSED (pre-fix would have listed all 42).
- **SEC-3 deployed + non-regressive**: gateway /health ok, all 3 backends ok (all stdio — no live HTTP backend exists, so the egress path has nothing to regress); journal shows no egress denials / connect failures; `SIFT_EGRESS_ALLOWED_*` correctly unset (fail-closed default). SEC-3 SSRF/rebinding/join behaviors remain UNIT-proven (32 tests) — a live exercise needs a wintools HTTP backend (real Windows host) + malicious-DNS, out of scope on this VM. Runbook note: when a wintools HTTP backend on a private LAN is added, operator must set `SIFT_EGRESS_ALLOWED_HOSTS`/`_CIDRS` for it to survive restart.
- **Pushed `origin/main` @ 4d81e5b.** SEC worktrees (sec-os-status, sec-egress) removed; branches deleted (merged).

**Wave-2 batch-2 COMPLETE.** Remaining build order: SEC-6 → SEC-5 → SEC-8 → SEC-11 → SEC-16 → SEC-14 → SEC-10. Carried: SEC-9 (live-VM vol-plugin needs-root investigation), SEC-15 (defer OpenCTI). Open follow-ups: SEC3-F2 (pin Supabase control-plane egress, defense-in-depth).

## Phase 5 — Wave-2 batch-3 built + reviewed + integrated + deployed + LIVE-PROVEN + pushed (2026-06-26)
4 parallel writer agents (Opus, isolated worktrees off HEAD) built SEC-6/8/11-16/14; orchestrator-verified each
(trap-corrected pytest + ruff/pyright new-vs-existing); 1 batched security-expert pass over the 3 non-auth branches
(all PASS) + 1 dedicated SEC-6 review (PASS). One cheap NEW finding closed pre-merge (SEC-14 non-2xx body read cap).

- **SEC-14** `sec/rag-egress @ f828bab` — resolve-and-pin + no-auto-redirect + per-hop revalidation + cross-host
  cred-drop in rag_mcp/sources.py; self-contained. 112 tests, 0-new lint. UNIT-proven (offline CLI add-on, no live backend).
- **SEC-8** `sec/archive-extractor @ edd5a93` — single hardened `extract_container` chokepoint (member preflight +
  bomb caps + statvfs + 7z rc==1=fail + memory-path into case jail); rejection rides existing `error`/`status:failed`
  envelope. 198 tests, 0-new. **LIVE-PROVEN:** malicious tar (symlink→/etc/passwd + ../escape.txt) ingested via
  opensearch_ingest → job `failed`, `error_summary="archive_rejected: tar member rejected by data filter: 'evil_symlink'
  is a link to an absolute path"`; 0 docs indexed, nothing extracted.
- **SEC-11+16** `sec/exec-isolation-seccomp @ 9f67ea0` — drop systemd `auto` silent-downgrade (missing systemd-run ⇒
  fail-closed); `isolation` block surfaces (response root + audit_events.details); gateway sync lane flipped seccomp
  log→kill with socket(41) always-LOG first in the BPF program. 47 SEC tests, 0-new. **LIVE-PROVEN:** run_command(id)
  returns `isolation{seccomp_mode:kill, landlock:required, systemd_scope_applied:true}`; curl ran (exit 7 cgroup-egress,
  NOT SIGSYS — socket() not killed); gateway healthy across 4 commands under kill. Kill-fires-on-denylisted-syscall
  NOT live-triggerable (run_command binary allowlist blocks unshare/etc before exec) → unit-proven (47 tests).
- **SEC-6** `sec/legacy-auth-removal @ a6a4896` — FULL legacy auth removal; Supabase sole authority; 5xx⇒503 fail-closed;
  no mcp:* default; `/api/tokens/*` lifecycle retired (modern reverify-gated principal issuance preserved). gw 776/2skip,
  cd 395, 0-new ruff, 0-new pyright baseline (trap-corrected). **LIVE-PROVEN (denial-only, operator-chosen):** legacy
  api-key token 406→**401** on /mcp + /api after deploy (garbage 401 both; health 200). Hard cutover confirmed; the
  harness MCP connection (legacy token) is now down — agents must be re-issued Supabase JWTs. Positive Supabase-JWT path
  stays test-proven (776 tests). VM precheck: `auth.supabase.enabled:true` confirmed before deploy.

**Integration topology (this session):** merged PR#28 (#16/#13/#27, GitHub, live-proven by operator) → origin/main
`d973d73`; replayed local docs/lsp commit `9e4675b` (1 policy_middleware.py overlap with PR#28's cast — resolved to the
unquoted/import-cleanup version) → `28fa7d7`; merged the 4 batch-3 branches (fully file-disjoint, 0 conflicts) → **pushed
`origin/main @ dde083f`.** VM deployed (SEC-8 + SEC-11/16 first via MCP while legacy auth worked, SEC-6 last via curl);
seccomp unit flipped to kill + daemon-reload; all 4 services restarted, healthy.

**Wave-2 batch-3 COMPLETE & PUSHED.** Remaining: **SEC-5** (serialize after SEC-6 — collapse REST tool-exec to a
worker-only governed endpoint), **SEC-10** (accept-risk doc + optional isolation_tier). Carried: SEC-9 (live vol-plugin
needs-root investigation), SEC-15 (OpenCTI). Deferred non-blocking follow-ups: SEC-6 dead `resolve_identity` block excision
(mcp_endpoint.py:414-457, unreachable, has a test at test_pr03:412), SEC-16 BPF arch-guard (32-bit ABI bypass, pre-existing),
SEC-11 non-x86_64 seccomp honesty (inert on target), SEC-8 list↔extract TOCTOU (caps-only, mitigated by sealed evidence),
SEC3-F2 (Supabase egress pin), SEC-14 gateway-posture-drift docstring.

## Legend
STILL-VALID · PARTIALLY-FIXED · ALREADY-FIXED · FALSE-POSITIVE · NEEDS-OPERATOR-DECISION
