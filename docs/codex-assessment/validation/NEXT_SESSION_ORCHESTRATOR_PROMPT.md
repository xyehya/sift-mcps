# Next-Session Orchestrator Prompt — Codex Security-Assessment Wave (resume)

(local-only working doc; do not commit — contains VM coords)

Paste this as the opening prompt for a fresh session to continue the Codex-assessment remediation.

---

You are the ORCHESTRATOR continuing the Codex security-assessment remediation on the `sift-mcps`
monorepo (SIFT forensic MCP gateway + portal). Two batches are DONE, deployed, live-proven, and
pushed. Resume with the remaining issues. Use Opus 4.8 at xhigh for every spawned agent.

## Standing rules (now codified in CLAUDE.md / root AGENTS.md — read them first)
Every spawned agent prompt MUST mandate, and you must bake in by name (plugin skills may not
auto-load in subagents, so name them as prompt text):
1. **codeguard-security:codeguard** skill (report its verdict).
2. **codebase-memory MCP** graph tools (search_graph/trace_path/get_code_snippet) over grep.
3. **LSP validators on changed files before commit** — `uv run --extra dev ruff check <paths>` +
   `uv run --extra dev pyright`. `sift-gateway` is the TYPE-CLEAN Pyright baseline (0 new diagnostics);
   `opensearch-mcp`/`sift-core`/portal are NON-baseline (report new-vs-preexisting, fix only what you
   introduce, don't expand `pyrightconfig.json`). Guide: `docs/new-docs/LSP_AGENT_WORKFLOW.md`.

Approaches: preserve project invariants, secure-by-design, fail-closed, tested (fail-on-revert +
surface tests), NO monkey-patching, fix at the AGENT-FACING SURFACE (registry `*Out` + worker
`result_public` + DB-authority path — not the impl fn; the #1 recurring inert-fix bug).

## ⚠️ Worktree editable-install trap (cost real time twice — DO NOT forget)
The root `.venv` editable-installs each package from the MAIN checkout, so from a worktree BOTH
pytest and pyright silently validate MAIN's code (false green). ALWAYS:
- pytest: run from the worktree package dir with `PYTHONPATH=src:tests` and the root-.venv python.
- pyright: temp config with `extraPaths` = the worktree's `src` (+ venv site-packages) so first-party
  imports resolve to the worktree. Compare worktree-vs-main diagnostic SETs to isolate new-vs-existing.
- opensearch-mcp tests also need the tests dir on PYTHONPATH (for `_helpers`).
See memory `reference_worktree_editable_install_resolution_trap`.

## State (canonical on disk)
- **origin/main @ 4d81e5b** (verify with `git log --oneline -1`).
- Plan: `docs/codex-assessment/validation/ISSUE_LIST_PROPOSED.md` (16 issues SEC-1..16, DECIDED fixes
  + RESOLVED operator-decisions table). Full log: `_MASTER_TRACKER.md` (Phase 4c = latest).
  These validation/ docs are LOCAL-ONLY (VM coords inside) — update, never commit.
- Gate architecture: `docs/drafts/architecture/sift-architecture.html` — agent gates live in
  `policy_middleware.py` (①GatewayToolCatalog ②ToolAuthorization ③AddonAuthority ④CaseContext
  ⑤AuditEnvelope ⑥ProxyActiveCase ⑦EvidenceGate ⑧ResponseGuard ⑨OpenSearchJobDispatch).
  `rest.py`/`Gateway.call_tool` is PORTAL-ONLY — fixing there is inert for agents.

### DONE + live-proven + pushed
- Batch 1 @ faa782d: SEC-1 (control-plane operator authority + password step-up), SEC-2 (index bound
  to active case incl. get_event at gate ⑥, fail-closed), SEC-4 (minimal stdio env; command-allowlist
  DROPPED/risk-accepted), SEC-12 (inert enrich gate removed), SEC-13 (SECDEF CI test).
- Batch 2 @ 4d81e5b: **SEC-7** (opensearch_status/shard_status bound to active case — LIVE-PROVEN:
  agent sees only the 38 active-case indices, not the 4 case-seed-* in the cluster) + **SEC-3** (shared
  resolve-and-pin egress anti-SSRF/anti-rebinding at persistence+materialization+every connect+manifest;
  creds-after-validation; no-redirect; CGNAT/non-global blocked via `not is_global`; DSS-CAN-019 join
  host-binding fail-closed — deployed+non-regressive; SSRF/join behaviors UNIT-proven, no live HTTP
  backend exists to exercise them). Contract commit 49cdbea (agent-loadout rules).

### REMAINING (build order; operator decisions already settled in ISSUE_LIST)
1. **SEC-6 (Med)** — FULL legacy-auth removal. **Operator CONFIRMED 2026-06-26: all deployments fully
   migrated off legacy tokens — safe to remove.** Delete the legacy-token fallback in `auth.py` + the
   `mcp:*` legacy stamp in `mcp_endpoint.py`; PR03A/Supabase = sole auth path; least-priv scopes +
   step-up on mint/rotate/reactivate; retire `/api/tokens/*` lifecycle. Supabase-down ⇒ fail-closed.
   Files: `supabase_auth.py`, `auth.py`, `mcp_endpoint.py`, `case-dashboard/.../routes.py` (token
   lifecycle), `token_registry.py`. Test: legacy token rejected on REST + /mcp; minted token not
   `mcp:*`; Supabase-down fail-closed. **Gateway-auth — serialize with SEC-5 (don't run both as
   parallel writers).**
2. **SEC-5 (Med)** — collapse `POST /api/v1/tools/{tool}` to a worker-only internal endpoint routed
   through a shared `Gateway.call_tool_governed()` (evidence gate + addon authority + response guard +
   DB-audit + OS job dispatch), bound to a dedicated worker principal; preserve the OpenSearch worker
   callback (`opensearch_mcp/gateway.py`). Files: `rest.py` (206-349), `server.py` `Gateway.call_tool`,
   `policy_middleware.py`. **Gateway — serialize with SEC-6.**
3. **SEC-8 (Med)** — single hardened archive extractor in `opensearch-mcp/.../containers.py`: member
   preflight (PEP-706 data-filter for tar; `7z l -slt` reject ../abs/symlink/hardlink/device/FIFO/setuid),
   configurable caps (max-uncompressed ~3× largest expected, ratio ~200:1, entries ~1M, 1h timeout) +
   `statvfs` free-space, treat `7z` rc==1 as failure, route the memory 7z path (`ingest_cli.py`
   2273-2296) through it into the case jail + realpath image selection. Surface rejection via worker
   `failed`/`result_public`. Confirm pinned tar/7z versions on the VM. **Isolated (opensearch) — safe
   to parallelize.**
4. **SEC-11 (Low)** + **SEC-16 (Low)** — run_command isolation surfacing + seccomp kill flip. SEC-11:
   drop systemd `auto` silent-downgrade, add `isolation` block {systemd_scope_applied, runtime_user_applied,
   seccomp_mode, landlock} to run_command `*Out` + `result_public` + `app.audit_events.details`
   (`sift-core/.../execute/executor.py`). SEC-16: flip `SIFT_EXECUTE_SECCOMP_MODE=kill` on
   `sift-gateway.service` AFTER handling `socket()`(41) in `dfir_exec_launcher.py` (split by address
   family, or drop socket since cgroup IPAddressDeny=any covers egress); other ~32 denylisted syscalls
   safe to kill now. Live-prove: a denylisted syscall kills only the tool, gateway stays healthy,
   curl/wget read-only fetch still works. **Related (sift-core exec/configs) — one agent can do both;
   isolated from gateway/opensearch.**
5. **SEC-14 (Low)** — `forensic-rag-mcp/.../sources.py` resolve-and-pin + no-auto-redirect, self-contained
   (do NOT fold into the gateway egress policy — offline add-on). **Isolated — safe to parallelize.**
6. **SEC-10 (Low, doc)** — accepted-risk note: evidence gate proves integrity, NOT content safety;
   a legitimately-registered but malicious image can exploit kernel FS/FUSE at mount-as-root. Record in
   security docs/runbooks; OPTIONALLY surface `isolation_tier` (`kernel-mount`) in the ingest `*Out` +
   audit (shares the surfacing helper with SEC-11).

### CARRIED (do NOT auto-build)
- **SEC-9** — live-VM investigation FIRST: enumerate which forensic ops / vol(3) plugins genuinely need
  root on the live VM (operator's prior research says some vol plugins need sudo; sec-exec's static
  analysis disagrees). Produce a needs-root matrix before touching the run_command silent sudo-fallback.
- **SEC-15** — defer until OpenCTI is a live backend.
- **SEC3-F2** (follow-up, defense-in-depth) — pin the control-plane Supabase egress (`health.py:146`,
  `supabase_auth.py:339`) through the SEC-3 egress policy. Optional, not blocking.

## Suggested batching (avoid parallel writers in the same package)
- Parallel now (disjoint): **SEC-8** (opensearch), **SEC-11+SEC-16** (sift-core/configs), **SEC-14** (RAG).
- Serialize (both gateway-auth, overlapping files): **SEC-6** then **SEC-5**.
- Each writer in its own worktree off HEAD: `git worktree add /home/yk/AI/SIFTHACK/wt/<slug> -b sec/<slug> HEAD`.

## Per-issue workflow
validate (codebase-memory + codeguard) → spawn Opus coding agent in an isolated worktree off HEAD with
fail-on-revert + surface tests + LSP validators → orchestrator-verify the committed branch (diff +
full suite with the PYTHONPATH/extraPaths trap-fix + ruff/pyright delta) → security-expert (read-only)
PASS gate → operator merge go-ahead → merge → push → DEPLOY-AND-PROVE on the VM.

## VM deploy-and-prove (the live gateway is the proof for BEHAVIOR)
- SSH: `export SSHPASS=forensics; sshpass -e ssh -o StrictHostKeyChecking=accept-new sansforensics@192.168.122.81`
  (password sensitive — env only, never echo/commit; sudo NOPASSWD). Gateway on 0.0.0.0:4508.
- Deploy: `rsync -azR` ONLY the committed changed files (exclude operator WIP) →
  `sansforensics@192.168.122.81:/opt/sift-mcps/` → clear `__pycache__` →
  `sudo systemctl restart sift-gateway sift-opensearch-worker@{1,2} sift-job-worker` → check active+journal.
- **DB manifest refresh (REQUIRED when a sift-backend.json changes)** — runtime authority is
  `app.mcp_backends` (DB snapshot), NOT the file. Get the gateway MainPID
  (`systemctl show -p MainPID --value sift-gateway`), read `SIFT_CONTROL_PLANE_DSN` from
  `sudo cat /proc/$PID/environ` (NEVER print it), then with `/opt/sift-mcps/.venv/bin/python`:
  `from sift_gateway.mcp_backends_registry import manifest_sha256`; `psycopg` UPDATE
  `app.mcp_backends set manifest=Json(m), manifest_sha256=<sha>, updated_at=now() where name=<backend>`;
  restart gateway. Verify the DB manifest carries the new fields + no drift warnings in the journal.
- OpenSearch on the VM: `http://127.0.0.1:9200` (plain, no auth); config at `/var/lib/sift/.sift/opensearch.yaml`
  (worker runs as `sift-service`, HOME=/var/lib/sift). `curl -s http://127.0.0.1:9200/_cat/indices?h=index`.
- Live MCP (agent path proof): load `mcp__Siftmcp__*` via ToolSearch (case_info, opensearch_*, run_command).
  Active case `case-test-case-06251017` (evidence chain OK); cross-case `case-seed-{accesslog,evtx,json,ssh}-init`
  exist for isolation proofs. Host curl: `curl -s --cacert /home/yk/.sift-vm-ca-192.168.122.81.pem https://192.168.122.81:4508/health`.
- Standing rule: green test = hypothesis; prove the exact repro live before/after. If the live setup
  can't reproduce it (e.g. no live HTTP backend for SEC-3-style egress), SAY SO — never imply a live
  proof that didn't happen.

## First actions
Read ISSUE_LIST_PROPOSED.md + _MASTER_TRACKER.md (Phase 4c); confirm origin/main @ 4d81e5b; then
launch the parallel batch (SEC-8 + SEC-11/16 + SEC-14) and/or start SEC-6 (legacy removal — operator
already confirmed safe), or ask the operator which to take first.
