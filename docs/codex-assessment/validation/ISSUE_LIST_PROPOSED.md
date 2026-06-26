# Proposed Issue List — Codex Assessment Remediation (2026-06-26)

Consolidated from the 6 validator cluster files. **22 Codex candidates → 16 issues**
(several candidates share one fix). Status: PROPOSED — pending operator review before
anything enters the tracker / coding agents are launched. No fixes applied yet.

Severity = re-validated against HEAD `93f8999` (project scale High/Medium/Low). Effort:
S ≈ <½day, M ≈ 1–2 days, L ≈ multi-day/architectural.

Legend for "Gate": 🔴 needs an operator decision before/while building · 🟢 buildable as-is.

---

## HIGH — fix first (agent-reachable, or core-invariant violations)

### SEC-1 · Enforce operator authority + step-up on all Gateway `/api/v1` control-plane mutation routes
- **Candidate(s):** DSS-CAN-002 (High, chained Critical). **Files:** `sift-gateway/.../rest.py` (route table 1235-1253; register/unregister/enable, services start/stop/restart, create-join-code), `auth.py` (116-237), `mcp_backends_registry.py` (register/unregister/set_enabled).
- **Root cause:** authn ≠ authz — `AuthMiddleware` proves *who* but no route-local authority gate exists on `/api/v1`; only `/portal/api/` and the single `call_tool` route block agent/service. The sandboxed **agent/service principal can mutate the control plane.**
- **Fix:** one shared `require_control_plane_operator()` dependency at the top of every mutation handler — reject `principal_type∈{agent,service}` + `role∈{readonly}`, require operator/examiner; defense-in-depth authz inside `McpBackendRegistry.*` (raise, not just stamp `registered_by`); step-up (recent Supabase re-auth) for register-new-backend + mint-join-code when Supabase enabled. **Test:** structural fail-on-revert test iterating `rest_routes()` asserting agent identity → 403 on every mutation route; live curl proof (agent token → 403, no `app.mcp_backends` row; examiner → 200).
- **Effort:** M. **Gate:** 🔴 define "operator authority" (any examiner + step-up vs new admin tier).
- **Why first:** upstream enabler for the entire BACKENDS chain (SEC-3/SEC-4 become operator-only once this lands).

### SEC-2 · Bind OpenSearch resolved index to the DB-active case (kill cross-case reads)
- **Candidate(s):** DSS-CAN-010 (High). **Files:** `opensearch-mcp/.../server.py` (`_resolve_index` 653, `_validate_index` 144, handlers search/count/aggregate/timeline/get_event), `opensearch-mcp/.../registry.py` (CaseScopedQueryBase), `sift-gateway/.../server.py` (case injection 1112-1135).
- **Root cause:** free-form `index` param overrides the active case; `_resolve_index` short-circuits on it; the only guard checks the `case-` prefix (blocks system indices) **not** the active case; the gateway never constrains `index`. `opensearch_search(query="*", index="case-*")` dumps every case.
- **Fix (both layers per surfacing invariant):** (1) backend — bind resolved index to `build_index_pattern(_get_active_case())`, reject any segment outside the active-case prefix; (2) gateway boundary — validate caller `index` against the active `case_key` exactly as it already validates `case_id`. **Test:** flip `test_security.py::test_case_wildcard_passes` to assert denial under an active case; fail-on-revert surface test on the denial envelope; 2-case live deploy-and-prove.
- **Effort:** M. **Gate:** 🔴 keep `index` (bound to active case) vs replace with a constrained `artifact`/suffix selector. **Pairs with SEC-7** (recon→read chain; prove together).

### SEC-3 · Single shared runtime egress policy for HTTP MCP backends (anti-SSRF / anti-rebinding)
- **Candidate(s):** DSS-CAN-004 (High) + DSS-CAN-019 (Med, wintools join). **Files:** `sift-gateway/.../backends/__init__.py` (279-318) + `http_backend.py`, `rest.py` join flow (651-793).
- **Root cause:** `_validate_remote_fetch_url` runs only on *manifest* fetches; DB-registered runtime URLs are materialized + connected with syntax-only checks, bearer token attached pre-connect, reconnect re-resolves unchecked → persistent gateway-originated SSRF + DNS-rebinding TOCTOU.
- **Fix:** one egress policy applied at **persistence + materialization + immediately before every connect/reconnect**; resolve-then-pin the destination IP (kill rebinding); attach credentials only after destination validation. 019 adds: bind the one-time join code to the expected wintools host identity at creation. **Test:** unit with a rebinding mock (first resolve public, second private → denied); register-time + connect-time validation tests.
- **Effort:** M. **Gate:** 🟢 (019's host-binding is a small design choice, not a blocker).

### SEC-4 · Minimal base environment for stdio MCP backends (restore "add-on has no DB creds")
- **Candidate(s):** DSS-CAN-020 (High) [+ DSS-CAN-003 authority = operator decision]. **Files:** `sift-gateway/.../backends/stdio_backend.py` (88), `case-dashboard/.../backends_routes.py` (171-203).
- **Root cause:** stdio backends start with `env = dict(os.environ)` → every add-on subprocess inherits `SIFT_CONTROL_PLANE_DSN` + `SIFT_AUDIT_WRITER_DSN` + backend tokens. **Direct violation** of the "agent backend has NO DB creds by design" invariant; `env_refs` overlay does not isolate.
- **Fix:** start stdio backends from a minimal allowlisted base env (PATH/HOME/LANG/case vars), overlay only explicitly approved `env_refs`. **Test:** fail-on-revert unit asserting a spawned stdio backend's env contains no `*_DSN`/service-secret keys.
- **Effort:** S (env). **Gate:** 🔴 DSS-CAN-003 only — reserve backend register/start for owner/admin vs any non-readonly examiner, + add a command allowlist (signed/installed add-ons). The env fix itself is 🟢 and should ship regardless.

---

## MEDIUM

### SEC-5 · Route the REST tool-exec surface through the same governed policy stack as MCP
- **Candidate(s):** DSS-CAN-001 (Med, operator-only — agents already blocked). **Files:** `rest.py` (206-349), `server.py` `Gateway.call_tool` (1037-1199), `policy_middleware.py` chain (1562-1601).
- **Root cause:** policy lives in FastMCP `on_call_tool` middleware bolted only to `/mcp`; `POST /api/v1/tools/{tool}` reaches `Gateway.call_tool` underneath it → skips evidence gate, add-on authority, response guard, DB-first audit, OpenSearch job dispatch. **Route is NOT dead** — the OpenSearch worker callback (`opensearch_mcp/gateway.py:57`) uses it.
- **Fix:** extract a shared `Gateway.call_tool_governed()` running the ordered checks once; both MCP terminus and REST handler call it; preserve the worker callback (route it through the governed path too). **Test:** parity test (REST vs MCP produce same authz/evidence/audit decision); REST-with-unsealed-evidence → denied + audited.
- **Effort:** M. **Gate:** 🔴 any human/product use of `POST /api/v1/tools/{tool}` beyond the worker? If not → collapse to a worker-only internal endpoint (smallest surface).

### SEC-6 · Legacy auth-plane hardening: secure-default fallback + least-priv token scopes + step-up
- **Candidate(s):** DSS-CAN-015 (Med, quick) + DSS-CAN-014 (Med). **Files:** `supabase_auth.py` (202/290, 1774-1776), `auth.py` (92-96, 196-237), `mcp_endpoint.py` (237-242), `case-dashboard/.../routes.py` (token lifecycle 4116-4375), `token_registry.py` (250).
- **Root cause:** (015) `legacy_token_fallback_enabled` defaults TRUE even when Supabase enabled; legacy api-key identities stamped `mcp:*` on /mcp; 5xx Supabase outage fails open. (014) any examiner mints/rotates/reactivates agent tokens with `mcp:*`, no step-up.
- **DECIDED: remove legacy fallback ENTIRELY** (no opt-in flag, no default-True path). **Fix:** delete the legacy-token fallback branch in `auth.py` + the `mcp:*` legacy stamp in `mcp_endpoint.py`; make PR03A/Supabase the sole auth path; replace the `mcp:*` mint default with least-priv scopes + step-up on create/rotate/reactivate; retire (not flag-gate) the legacy `/api/tokens/*` lifecycle. **Test:** any legacy token rejected on REST + `/mcp` (no `mcp:*` stamp); minted agent token NOT `mcp:*` unless explicitly requested; Supabase-down → fail-closed (no legacy fallthrough). **⚠️ pre-merge gate:** confirm every deployment has fully migrated off legacy tokens — full removal breaks any straggler immediately.
- **Effort:** M. **Gate:** ✅ decided (full removal). (Tokens already case-bound — preserve.)

### SEC-7 · OpenSearch status/shard-status: bind to active case + operator-scope the all-case catalog
- **Candidate(s):** DSS-CAN-011 (Med). **Files:** `opensearch-mcp/.../server.py` (status 1457-1502/1469-1479; shard_status top_indices 1549-1567), `sift-backend.json` (267/290 `safe_case_argument_names: []`).
- **Root cause:** status tools take no case arg (manifest `safe_case_argument_names=[]`) so the gateway can't bind them → they enumerate every `case-*` index name/docs/size = the targeting map that turns SEC-2 from "guess" into "read this exact index."
- **Fix:** add `case_id`/`case_dir` args + manifest entries so the gateway injects the active case; filter the catalog to the active case; keep cluster health unscoped; gate the all-case capacity view behind an operator scope (`required_scopes`) or a separate operator-only tool. **Test:** active case A → status lists only `case-A-*`; surface test; 2-case live proof. **Ships/proves with SEC-2.**
- **Effort:** M. **Gate:** 🔴 (minor) does the agent need an all-case capacity view, or operators only?

### SEC-8 · Single hardened archive extractor (member preflight + resource caps + warning-as-failure)
- **Candidate(s):** DSS-CAN-008 + 009 + 017 (all PARTIALLY-FIXED Low) → **cross-cutting Medium**. **Files:** `opensearch-mcp/.../containers.py` (extract_container/_extract_7z/_extract_tar), `ingest_cli.py` (memory 7z 2273-2296).
- **Root cause:** no current write-escape (the tar/7z **binaries** block zip-slip/symlink/traversal today), but containment rests entirely on external-binary version defaults across **3 divergent paths**, with **no decompression-bomb/disk-exhaustion cap** anywhere and the worker has no PrivateTmp/quota. Memory path even extracts to `/tmp` outside the case jail.
- **Fix:** make `extract_container` the one hardened chokepoint — member preflight (PEP-706 `data`-filter logic for tar; `7z l -slt` for zip/7z: reject `..`/abs/symlink/hardlink/device/FIFO/setuid), max-uncompressed/ratio/entry-count caps + subprocess timeout + `statvfs` free-space (anti-bomb), treat `7z` rc==1 as failure, generalize the post-walk to dirs+symlinks, **route the memory path through it into the case jail** + `.is_file()`/realpath image selection. Surface rejection via the worker `failed`/`result_public` envelope. **Test:** malicious-archive + declared-bomb fail-on-revert fixtures asserting the **app** rejects (not just "no escape"); surface test; live proof.
- **Effort:** M. **Gate:** 🔴 (minor) confirm pinned tar/7z versions on the VM image + choose bomb caps. **Cross:** the isolation in SEC-10 would also blunt this (same hostile-bytes→worker pipeline).

### SEC-9 · run_command silent sudo-escalation fallback — LIVE-VM INVESTIGATION (decision deferred)
- **Candidate(s):** DSS-CAN-006 (Med — inert in packaged posture) [+ EXEC-adjacent: `_PRIVILEGED_TARGETS` breadth, mount `-o`/`/dev/*` validation]. **Files:** `sift-core/.../execute/tools/generic.py` (248-304), `security.py` (498, 1019-1039, 1122).
- **Root cause:** an automatic *silent* privilege-escalation retry (prepends `sudo -n --`, clears `runtime_user`) gated by a static binary allowlist broader than the sudoers that actually authorizes root. Fail-open by design. Neutralized in the packaged `agent_runtime` posture; a latent foot-gun on dev same-user / broad-NOPASSWD workstation installs.
- **STATUS: investigation issue, NOT a ready fix.** Code analysis (sec-exec) argues no run_command tool needs root, but the operator's prior research found **some Volatility plugins require sudo**. Conflict must be resolved EMPIRICALLY on the live SIFT VM before any code change.
- **Investigation scope (the actual deliverable):** on the live VM, enumerate + test which forensic operations / vol(3) plugins genuinely require root (e.g. live-memory / `/proc/kcore` / kernel-symbol or device-touching plugins vs file-only analysis); capture the exact failing-without-sudo cases; map each to whether run_command (vs the ingest broker / an operator workflow) is the invoking path. Output: a definitive needs-root matrix grounded in live behavior.
- **Then decide (post-investigation):** (A) remove the fallback if nothing run_command runs needs root; or (B) replace the silent retry with an explicit, separately-scoped, operator-approved privileged tool whose `(root)` Cmnd_Alias is narrowed to exactly the proven-needed binaries/plugins — never a silent in-tool upgrade. Either way the *silent* + *runtime_user-clearing* behavior goes; the question is whether a scoped explicit path replaces it.
- **Fallback stays in place until the live trace proves it unneeded.** **Effort:** investigation (live VM) then S–M code. **Gate:** 🟡 operator-owned live-VM investigation.

### SEC-10 · Isolate hostile evidence-image bytes at mount/parse (microVM / userspace-parse)
- **Candidate(s):** DSS-CAN-007 (Med — Codex's proposed sudoers/evidence-gate/least-priv remediations are **already implemented**; only the kernel-isolation residual remains). **Files:** `policy_middleware.py` (OpenSearchJobDispatchMiddleware 1421-1559), `opensearch-mcp/.../containers.py` (MountContext/mount_image 86-260), `configs/systemd/sift-opensearch-worker@.service`, `scripts/setup-ingest-mount-sudoers.sh`.
- **Root cause:** untrusted evidence bytes (suspect disk images / crafted E01/FS) are parsed by **kernel** FS/mount code running as root with only **host-level** isolation (the worker holds `CAP_SYS_ADMIN` for FUSE; `PrivateDevices`/`RestrictNamespaces` documented-omitted because they break FUSE). A kernel-FS-driver exploit = VM-root, not worker-user.
- **DECIDED: accept + document the residual** (no userspace-parse / no microVM now). The existing minimized `SIFT_MOUNT` sudoers + evidence gate + least-priv worker are the accepted controls. **Fix (doc-only + optional surfacing):** write the accepted-risk note — *the evidence gate proves integrity (no tampering since registration), NOT content safety; a legitimately-registered but maliciously-crafted image can exploit kernel FS/FUSE code at mount-as-root*; record it in the security docs / `runbooks`; **optionally** surface `isolation_tier` (`kernel-mount`) in the ingest `*Out` + audit so the posture is visible. Re-open for userspace-parse/microVM if the threat model changes. **Test:** (if `isolation_tier` added) surface test; otherwise none.
- **Effort:** **Low** (doc + optional surfacing — was L). **Gate:** ✅ decided (accept residual). **Cross:** if `isolation_tier` is surfaced it shares the helper with SEC-11.

---

## LOW

### SEC-11 · run_command: drop systemd `auto` silent-downgrade + surface isolation status
- **Candidate(s):** DSS-CAN-022 (Low — production ships `=1` fail-closed). **Files:** `sift-core/.../execute/executor.py` (49-58, 106-127).
- **Fix:** make `auto` dev-only (or remove) — never silently run the direct worker without `IPAddressDeny=any`/cgroup caps; add an `isolation` block `{systemd_scope_applied, runtime_user_applied, seccomp_mode, landlock}` to the run_command `*Out` + `result_public` + `app.audit_events.details` so a downgrade is visible. **Test:** `=required` + missing `systemd-run` → `ExecutionError`; surface test for the `isolation` block; live VM proof `IPAddressDeny=any` is on the scope. **Effort:** S. **Cross:** shared surfacing helper with SEC-10.

### SEC-12 · Remove the inert/fail-open enrichment env gate (keep the gateway authority gate)
- **Candidate(s):** DSS-CAN-012 (Low — `SIFT_ENRICHMENT_SCOPE` is never set anywhere → dead fail-open code; the real gate is `AddonAuthorityMiddleware required_scopes=[enrichment:intel]`). **Files:** `opensearch-mcp/.../server.py` (3348-3364).
- **Fix:** remove the in-process env gate (do **NOT** fail-close it — would break the gateway+worker paths that run with the env unset). If a standalone-CLI DiD gate is wanted, put it at the CLI entrypoint, fail-closed. **Test:** unit asserting `AddonAuthorityMiddleware` denies enrich without the scope. **Effort:** S.

### SEC-13 · CI hardening test: no `app` SECURITY DEFINER function has PUBLIC EXECUTE
- **Candidate(s):** DSS-CAN-013 **residual** (the revoke itself is **ALREADY-FIXED** by migration `202606242200`, commit `05e9782`). **Files:** new `sift-gateway/tests/test_secdef_no_public_execute.py`.
- **Fix:** DSN-importskip-gated test asserting `has_function_privilege('public', oid, 'EXECUTE')=false` for every `app` `prosecdef` function — permanently closes the recurrence class that let `evidence_unseal` slip past the 141400 sweep. **Effort:** S. **Why it matters:** guards a LIVE invariant (evidence custody) — highest-value Low.

### SEC-14 · Harden RAG source fetch: resolve-and-pin + no-auto-redirect
- **Candidate(s):** DSS-CAN-005 + 021 (Low-live — operator-CLI-only `python -m rag_mcp.refresh`, fixed 6-host allowlist). **Files:** `forensic-rag-mcp/.../sources.py` (329-401).
- **Fix:** one hardened fetch — resolve + classify destination (reject private/loopback/link-local/reserved), pin the resolved IP, disable auto-redirect + manual per-hop revalidation. **Self-contained in `sources.py`** — do NOT fold into the gateway egress policy (offline add-on the gateway never invokes). **Test:** rebinding + redirect mock unit. **Effort:** S.

### SEC-15 · OpenCTI optional-stack hardening
- **Candidate(s):** DSS-CAN-016 + 018 (Low — **OpenCTI is NOT a live backend**; minio/platform bound to loopback). **Files:** `docker-compose.opencti.yml` (19-38), `opencti-mcp/.../config.py` (144-183/349-380).
- **Fix:** split per-component secrets (stop `OPENCTI_ADMIN_TOKEN` reuse across 6 creds); pin the 3 `latest` images by digest; enable datastore auth where network access widens; reject non-loopback `http://` by default (+ enforce https/cert for remote). **Effort:** M. **Gate:** 🔴 only build if/when OpenCTI is promoted to a live backend.

### SEC-16 · Enforce seccomp `kill` on the synchronous gateway run_command lane (Wave-2 completion)
- **Candidate(s):** EXEC-adjacent #1 (new, Low–Med). **Files:** `configs/systemd/sift-gateway.service:53` (`SIFT_EXECUTE_SECCOMP_MODE=log`) vs `sift-job-worker.service:51` (`=kill`); filter `dfir_exec_launcher.py` (`_X86_64_LOG_SYSCALLS`, `socket`(41) entry ~440, `prctl(PR_SET_SECCOMP)` install 513-516).
- **DECIDED (investigation complete):** flip the gateway lane to `kill`. The "kill endangers the gateway" risk is **refuted** — the filter is installed per-tool-stage in the forked `dfir-exec-launcher` grandchild (agent_runtime only; refuses uid 0/service uid), immediately before `execvpe`, in a separate process from the gateway event loop/embedder. `SECCOMP_RET_KILL_PROCESS` kills only the forensic-tool process. `log` was phased rollout + one deliberate `socket`(41) LOG-only entry ("enforce AF-specific in Wave 2") because the sync lane runs `curl`/`wget` read-only fetches.
- **Fix:** complete Wave-2 socket handling FIRST — either split `socket()` by address family (allow what curl/wget/AF_UNIX need, kill AF_PACKET/AF_NETLINK/raw) or drop `socket` from the kill action (cgroup `IPAddressDeny=any` already enforces egress) — then set `SIFT_EXECUTE_SECCOMP_MODE=kill` on `sift-gateway.service`. The other ~32 denylisted syscalls (kexec_load, *_module, bpf, ptrace, setns, unshare, mount, swapon, reboot, keyctl, io_uring_*, clone3, pivot_root, chroot, …) are zero-false-positive for parsers → safe to kill now.
- **Test:** unit/integration that a denylisted syscall (e.g. `unshare`/`ptrace`) from a test tool on the sync lane is killed; **live deploy-and-prove:** trigger it → only the tool dies, gateway stays healthy and serves the next run_command; confirm `curl`/`wget` read-only fetch is NOT killed. **Effort:** S. **Gate:** ✅ decided.

---

## Operator decisions — RESOLVED (2026-06-26)

| # | Decision | Resolution |
|---|---|---|
| 1 | Control-plane authority model (SEC-1) | **Examiner + step-up.** Deny `principal_type∈{agent,service}` + `role==readonly`; allow examiner; require recent Supabase re-auth (step-up) for register-new-backend + mint-join-code. No new admin tier. |
| 2 | OpenSearch `index` ergonomics (SEC-2) | **Bind the free-form `index`** to the active-case prefix at both backend + gateway. Keep intra-case artifact-family narrowing; deny `case-*`, other-case, and exact other-case names. |
| 3 | Backend-registration authority (SEC-4/003) | **Examiner + step-up + command allowlist.** Restrict stdio commands to signed/installed add-ons / allowlisted catalog. Env-leak fix (020) ships regardless. |
| 4 | Legacy auth-plane (SEC-6) | **Remove legacy fallback ENTIRELY** — no opt-in flag, no default-True path. Hard-requires PR03A/Supabase as the **sole** auth path; replace `mcp:*` default with least-priv + step-up on mint. ⚠️ confirm no in-flight legacy-token deployments before merge. |
| 5 | run_command sudo fallback (SEC-9) | **DEFERRED → standalone live-VM investigation issue.** sec-exec's code-analysis says no run_command tool needs root (parsers read files as agent_runtime), BUT the operator has prior hands-on research that **some Volatility plugins require sudo** — not settle-able from static analysis. **Do NOT remove the fallback yet.** Trace + test on the live SIFT VM which forensic ops / vol plugins genuinely need root; only then decide remove (A) vs explicit operator-approved acquisition tool (B). The fallback remains in place until proven unneeded live. |
| 6 | Hostile-image isolation (SEC-10) | **Accept + document residual.** No userspace-parse/microVM work now; document the kernel-mount-as-root accepted risk (integrity gate ≠ content safety); optionally surface `isolation_tier`. → downgraded to a documentation issue. |
| 7 | REST tool-exec route (SEC-5) | **Collapse to a worker-only internal endpoint** bound to a dedicated worker principal, routed through the governed `call_tool_governed()` path. |
| 8 | seccomp sync-lane (SEC-16) | **Flip gateway sync lane to `kill`** (REFUTED that kill endangers the gateway — the filter is installed per-tool-stage in the forked `dfir-exec-launcher` grandchild that runs only as agent_runtime; `kill` kills just the tool process). `log` was phased rollout + one deliberate `socket`(41) LOG-only entry (sync lane uses curl/wget). **Complete the planned Wave-2 socket handling first** (AF-specific `socket()` filtering, or drop `socket` from the kill action since cgroup `IPAddressDeny=any` already covers egress), then flip; the other ~32 denylisted syscalls are safe to kill now. Live-prove a denylisted syscall kills only the tool + curl/wget still works. |
| 9 | Archive bomb caps + tar/7z pinning (SEC-8) | **Configurable defaults** (max-uncompressed ≈3× largest expected archive, max-ratio ≈200:1, max-entries ≈1M, 1h timeout, `statvfs` free-space check); confirm pinned tar/7z versions during build. (Operator may override caps.) |
| 10 | OpenCTI (SEC-15) | **Defer** until/unless OpenCTI is promoted to a live backend; keep documented. |

### Decision impacts on the issue list
- **SEC-6** is now *full removal* (was: default-off + flag) — larger blast radius; gate on confirming legacy tokens are fully retired in every deployment.
- **SEC-10** drops from Medium-architectural to a **Low documentation issue** (+ optional `isolation_tier` surfacing). Removes the only L-effort item from the build plan.
- **SEC-5** end state = worker-only endpoint (smallest surface), not a general governed operator surface.
- **SEC-9** and **SEC-16** await sec-exec verification before final scope.

## Suggested build order
1. **SEC-4 (env) + SEC-13 + SEC-12** — small, no-decision, pure hardening / invariant restoration (quick wins).
2. **SEC-1 + SEC-2** — the two genuinely urgent agent-reachable Highs (each needs one decision).
3. **SEC-3 + SEC-7** — egress policy + the case-isolation recon half (SEC-7 ships with SEC-2).
4. **SEC-6 + SEC-9 + SEC-11** — auth-plane defaults + exec foot-guns.
5. **SEC-5 + SEC-8** — policy-boundary unification + shared extractor.
6. **SEC-10** — architectural spike (microVM/userspace-parse), then build.
7. **SEC-14 + SEC-16 + SEC-15** — low-live / non-live / decision-gated.
