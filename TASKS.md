# sift-mcps — Task Tracker

**Plan file:** `SIFT-MCPS-PLAN.md` — normative spec; update it only when the spec changes.
**Principles:** `AGENTS.md` — immutable rules, design requirements, working commands.

---

## ⚡ Start Here Every Session

**Current state:** Phase 16 complete + Phase 17 OS hardening complete (17a chattr+setcap, 17b auditd, 17c AppArmor complain mode, 17d inotify watcher — all verified on SIFT VM 192.168.122.81). Full docs suite written in `docs/`. 547 tests passing. **Next: Phase 18 — Hermes agent profile + orchestration.**

```bash
# Verify tests (run per-package — cross-package rootdir conflict is pre-existing)
uv run python -m pytest packages/agentir-core/ --tb=short -q       # 212 passing
uv run python -m pytest packages/case-dashboard/ --tb=short -q     # 236 passing
uv run python -m pytest packages/sift-gateway/ --tb=short -q       # 99 passing
uv run python -m pytest packages/case-mcp/ --tb=short -q           # 15 passing
uv run python -m pytest packages/sift-mcp/ --tb=short -q           # 3 passing
uv run python -m pytest packages/report-mcp/ --tb=short -q         # 31 passing

# Namespace gate (must stay 0)
grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."
```

**Test breakdown:** agentir-core 212 | case-dashboard 236 | sift-gateway 99 | case-mcp 15 | sift-mcp 3 | report-mcp 31


**Next phase:** Phase 17 OS hardening (see §Phase 17 below and SIFT-MCPS-PLAN.md)

---

## Completed Work

- **Phase 0 — Critical Bug Fixes** ✅
  Key files: `agentir_core/case_io.py`, `sift_gateway/server.py`, `case_dashboard/routes.py`, `opensearch_mcp/gateway.py`
  Insight: Active case is AGENTIR_CASE_DIR env var only — no file pointer fallback.

- **Phase 1 — Workspace Scaffold** ✅
  Key files: `pyproject.toml` (root), all package `pyproject.toml` files, `uv.lock`

- **Phase 2 / 2b — agentir-core Tests + Hardening** ✅  Tests: 139
  Key files: `agentir_core/approval_auth.py`, `agentir_core/verification.py`, `agentir_core/backup_ops.py`
  Insight: `sys.exit()` → `AuthError`/`LockoutError`; all paths env-overridable for test isolation.

- **Phase 3 — Portal Security Hardening** ✅
  Key files: `case_dashboard/routes.py`, `case_dashboard/middleware.py`

- **Phase 4a–4d — Gateway Improvements** ✅
  Key files: `sift_gateway/auth.py`, `sift_gateway/rate_limit.py`, `sift_gateway/mcp_endpoint.py`
  Phase 4e DEFERRED: no `StreamableHTTPSessionManager` session lifecycle hook in mcp==1.27.1.

- **Phase 5 — forensic-rag FastMCP Migration** ✅
  Key files: `forensic_rag_mcp/server.py`

- **Phase 6 — sift-mcp Sanitization** ✅
  Key files: `sift_mcp/security.py`

- **Phase 7 — Install Script** ✅
  Key files: `install.sh`, `configs/systemd/sift-gateway.service`

- **Phase 8 — Docker Compose** ✅
  Key files: `docker-compose.yml`

- **Phase 9 — Configs & Templates** ✅
  Key files: `configs/gateway.yaml.template`, `configs/hermes-forensics-profile.yaml`

- **Phase 10 — Architecture Cleanup** DEFERRED (low priority, do on next touch)

- **Phase 11 — Windows Triage Backend** ✅  Tests: +8
  Key files: `windows_triage_mcp/server.py`, `windows_triage_mcp/scripts/download_databases.py`
  Insight: SQLite-backed, 3 DBs (`known_good.db`, `context.db`, `known_good_registry.db`). Original source at `/home/yk/AI/SIFTHACK/sift-mcp/packages/windows-triage/`.

- **Phase 12-pre — Security Prerequisites** ✅
  Key files: `agentir_core/verification.py` (`derive_auth_key`, `derive_ledger_key`)

- **Phase 12a–12f — Portal Authentication** ✅  Tests: +36
  Key files: `case_dashboard/session_jwt.py`, `case_dashboard/middleware.py`, `case_dashboard/routes.py`
  Insight: R1–R9 security guards all implemented. `must_reset_password` re-read from disk on every write.

- **Phase 13a–13f — Agent RBAC** ✅  Tests: +28
  Key files: `sift_gateway/token_gen.py`, `sift_gateway/rest.py`, `case_dashboard/routes.py`

- **Phase 14a–14g — Dashboard Rewiring** ✅
  Key files: `case_dashboard/templates/index.html`, `case_dashboard/routes.py`
  Insight: Case create endpoint lives in `routes.py` (portal sub-app), not `rest.py` (gateway REST).

- **Phase 15a–15d — Session Security Hardening** ✅  Tests: +5  (total: 271)
  Key files: `case_dashboard/middleware.py` (sliding refresh, JWT revocation), `case_dashboard/routes.py` (login rate limit), `sift_gateway/server.py` (secure headers)

---

## Next Work — Phase 16: Evidence Manifest & Ledger

See SIFT-MCPS-PLAN.md §Evidence Manifest and Chain-of-Custody Design for full spec.

**Key implementation rules before starting:**
- Gateway evidence gate uses stat-check + 30s TTL cache — do NOT full-rehash on every MCP call
- `mtime_ns` is informational only — never use in integrity assertions
- `agentir-core` owns ALL evidence chain logic — no duplicate implementations in other packages

Sub-tasks:

- [x] **16-pre** — `agentir_core/evidence_chain.py`: scan, manifest canonicalization, HMAC sign, hash-chain verify, ledger append with fsync, diff generation. 53 tests. Key: one ledger event per version (MANIFEST_SEALED / FILE_IGNORED); gateway path is key-free (chain_status); portal path uses seal_manifest/ignore_file/verify_chain_hmac with derived_key bytes.
- [x] **16g** — Case create: `init_evidence_chain()` wired into `routes.py` (portal) and `case_ops.py` (CLI). Old stub `{"version":1,"sealed":false}` replaced. Test updated.
- [x] **16b** — `sift-gateway`: `evidence_gate.py` — `check_evidence_gate()` + `invalidate_evidence_cache()` + 30s TTL + mtime change detection. Wired into `mcp_endpoint.py` `_call_tool` before backend routing. Structured block response + audit entry. 17 tests.
- [x] **16a** — `case-dashboard`: evidence intake panel, write-block detection warning, rescan endpoint, register/seal endpoint (requires HMAC confirmation), ignore endpoint, violation display. 32 tests. Cache invalidation wired via `on_chain_mutation` callback to gateway's `invalidate_evidence_cache`. Key: derive_ledger_key for evidence ledger signing; /proc/mounts + statvfs for write-block detection; evidence challenges domain-separated from commit challenges.
- [x] **16c** — `case-mcp`: `evidence_register` blocked (portal-remediation block, audit logged); `evidence_list` reads System B manifest (IGNORED entries excluded); `evidence_verify` delegates to `chain_status()`. 15 tests.
- [x] **16-retire** — `agentir-core`: `retire_file()` + `_set_immutable()` in evidence_chain.py; `diff_manifest` updated to exclude RETIRED (same as IGNORED). Portal `/api/evidence/chain/retire` (HMAC-confirmed, deletes file from disk). 14 new tests (12 agentir-core + 12 portal). Distinct from "Ignore" (for unregistered files).
- [x] **16-gate-tier** — Two-tier gate: `UNSEALED` status allows tools with `annotations.readOnlyHint=true` through with a warning annotation injected; blocks analysis tools. Any violation status (MODIFIED/MISSING/UNREGISTERED/LEDGER_ERROR) blocks everything including read-only. 7 integration tests.
- [x] **16d** — `report-mcp`: include evidence manifest version/hash in report; warn/fail when chain status is not OK. 31 tests.
- [x] **16-verify-remind** — Portal: show "Full integrity verification recommended" reminder when last `verify_chain_hmac` is older than 24h or has never been run. Advisory only, not blocking. 20 tests.
- [x] **16e** — `agentir-core`: `anchor_manifest()` + `load_anchor_proof()` + `_do_solana_anchor()` via stdlib urllib (no httpx). Optional dep: `pip install "agentir-core[solana]"`. Degrades gracefully without `solders`. Proof to `{case_dir}/evidence-anchor-v{N}.json`. Auto-triggers after seal if `AGENTIR_SOLANA_KEYPAIR` set. 6 new tests (212 agentir-core total).
- [x] **16f** — Portal: anchor status section in evidence intake panel (Unanchored / Pending / Anchored with Solscan link). `POST /api/evidence/chain/anchor` for manual re-anchor. Seal response includes anchor info. `AGENTIR_SOLANA_CLUSTER` env var for mainnet/devnet.
- [x] **Phase 16 Integration Verification** — run full acceptance checklist from SIFT-MCPS-PLAN.md §Verification after Phase 16 + 16-retire + 16-gate-tier are done. Code-level gates passed locally (550 package tests, namespace/import gates). Lightweight SIFT VM pass complete on `192.168.122.81`. Remaining: full OpenSearch Docker/template smoke and windows-triage DB download/enable pass.

---

## Liquefy Integration Work

Liquefy repo: `/home/yk/AI/SIFTHACK/liquefy/`
Full assessment + design decisions in SIFT-MCPS-PLAN.md §Liquefy Integration.

- [x] **Approach C (sift-gateway + case-dashboard)** — Secret redaction + examiner override. See SIFT-MCPS-PLAN.md §Approach C for full spec. Implementation checklist:
  1. `packages/sift-gateway/src/sift_gateway/response_guard.py` — `scan_tool_result`, `redact_tool_result`, in-memory override state (`enable_override`, `is_override_active`, `cancel_override`, `get_override_status`). Redact critical+high only; medium/low flag-only. Pattern source: `liquefy/tools/liquefy_leakhunter.py` `SECRET_PATTERNS` list.
  2. Wire `redact_tool_result()` into `mcp_endpoint.py` `_call_tool()` after `gateway.call_tool()` — redact raw text, add `_agentir_context.secret_warning`, log `{pattern_name, char_offset, redact_override_active}` to audit.
  3. Three portal endpoints in `case-dashboard/routes.py`: `GET /api/response-guard/status` (session), `POST /api/response-guard/override` (HMAC, same pattern as evidence seal), `POST /api/response-guard/override/cancel` (session). Import `response_guard` directly — same process, no callback needed.
  4. Tests: scan/redact unit tests, override TTL expiry, portal endpoints with/without HMAC.

- [ ] **Approach A (analyst machine docs, ~1-2h)** — Write `docs/analyst-machine-setup.md`. Cover: Liquefy install (`cd liquefy && make setup`), State Guard init for Hermes config files (SOUL.md, memory.md), per-session safe-run sentinel wrapper script, policy enforcer watch command, vault archive post-session. Reference Liquefy repo at `/home/yk/AI/SIFTHACK/liquefy/`.

- [ ] **Approach B (Phase 16 add-on, ~4-6h)** — `anchor_manifest()` in `evidence_chain.py` (part of 16e above). Integrate into portal sealing flow. Portal shows anchor status.

---

---

## Phase 17: OS-Level Evidence Hardening (Ubuntu 24.04 SIFT VM)

**Delivery: all steps are additions to `install.sh`.** Not standalone deployments.
**Prerequisite:** Phase 16 complete. **Target OS:** Ubuntu 24.04 (SIFT Workstation).
SIFT test VM confirmed: kernel 6.17, AppArmor active, ext4, chattr works, IMA compiled in.
Dev machine is Fedora 44 (no AppArmor) — write and test Phase 17c profile on Ubuntu.
All other sub-tasks work cross-platform.

**Threat model (settled):** chattr +i protects against accidents and converts deliberate tampering
into an auditable act. It does NOT protect against a malicious root user — the cryptographic
ledger (Phase 16) is the actual chain-of-custody proof. See SIFT-MCPS-PLAN.md §OS-Level Evidence
Hardening for the full honest threat model.

- [ ] **17a** — **App code + install.sh.** `agentir-core`: add `_set_immutable(path, bool)` using `fcntl` ioctl (`FS_IOC_SETFLAGS`/`FS_IMMUTABLE_FL`). Wire into `seal_manifest()` (clear then set +i per file) and `retire_file()` (clear -i before rm). Graceful degradation: logs WARNING on EPERM, returns False, does not abort seal. Portal shows `immutable: true/false` per file. `install.sh`: `setcap cap_linux_immutable+ep $(readlink -f $(which python3))`.

- [ ] **17b** — **install.sh only. Zero app code changes.** Add `configs/audit/99-agentir-evidence.rules` to repo. `install.sh`: `apt install -y auditd`, write rules with `perm=wa` on `${AGENTIR_CASES_ROOT}` and `/var/lib/agentir`, run `augenrules --load && systemctl enable --now auditd`. Key insight: `perm=a` catches `chattr -i` calls — records when the immutable flag is deliberately cleared before tampering.

- [ ] **17c** — **Config file + install.sh. Ubuntu 24.04 only.** Add `configs/apparmor/sift-gateway` to repo. Profile the sift-gateway entry point binary (NOT `/usr/bin/python3*` broadly). Rules: read `evidence/**`, DENY write `evidence/**`, rw manifest/ledger/audit/approvals, TCP localhost only, deny bash/sh exec. `install.sh`: detect AppArmor, copy profile, `apparmor_parser -r`, `aa-enforce`. Use `aa-logprof` on SIFT VM to catch legitimate denials before enforcing. Skip silently on non-Ubuntu.

- [ ] **17d** — **App code.** `sift_gateway/evidence_watcher.py`: asyncio inotify watcher (`IN_MODIFY|IN_CREATE|IN_DELETE|IN_MOVED`) on `case_dir/evidence/` via pure ctypes (no external deps). On event: `invalidate_evidence_cache(case_dir_str)` + audit log entry. Wired from `server.py` on case activation, cancelled on case switch. Graceful fallback (NTFS/NFS/FUSE): log warning, fall back to 30s TTL only.

- [ ] **17e** *(optional, advanced)* — **App code + install.sh flag.** `_set_ima_hash(path)` in `evidence_chain.py` via `subprocess.run(['evmctl', 'ima_hash', '--hash=sha256', path])`. Graceful fallback if `ima-evm-utils` not installed. `install.sh --enable-ima` flag: `apt install ima-evm-utils`. No boot param change needed for measure/audit mode (appraise mode is optional and invasive). Portal shows IMA xattr status per file.

- [x] **17-docs** — Full docs suite written: `docs/README.md` (hackathon pitch), `docs/architecture.md` (component + data flow diagrams), `docs/security-controls.md` (all controls with implementation + test traceability), `docs/evidence-chain-of-custody.md` (manifest, ledger, Solana, operational checklist, honest limitations), `docs/dfir-hardening-guide.md` (chattr, auditd, AppArmor, inotify — threat coverage + maintenance checklist).

---

## Deferred Items

- **Phase 4e** — `notifications/tools/list_changed`: blocked. `mcp==1.27.1` has `ServerSession.send_tool_list_changed()` but `StreamableHTTPSessionManager` exposes no public session lifecycle hook. Revisit on next MCP SDK minor release.
- **Phase 10** — Architecture cleanup (split `routes.py`, extract auth/examiner helpers). Low priority; do on next touch of those files.
- **Audit Invariant** ✅ — Gateway transport envelope implemented. Every `/mcp` `call_tool` writes a `sift-gateway.jsonl` entry with role, token_id (SHA-256 fingerprint), examiner, source_ip, backend, status, elapsed_ms, backend_audit_id. Raw token never logged. 15 tests.

---

## Recent Session Notes

**Session 34 — 2026-05-25 — Evidence chain audit + Phase 16e/16f Solana anchoring:**
- Audited full evidence pipeline (evidence_chain.py, routes.py, evidence_gate.py, case-mcp, report-mcp, portal UI) against SIFT-MCPS-PLAN.md. Gemini VM test results validated correct. Two bugs found and fixed:
  - `ignore_file()` path traversal gap: now calls `_resolve_evidence_path()` before modifying manifest (ValueError propagates to portal as 400).
  - `seal_manifest()` was only carrying IGNORED entries forward; now carries RETIRED too — prevents retired-file paths reappearing as UNREGISTERED after reseal.
- Phase 16e implemented: `anchor_manifest()`, `load_anchor_proof()`, `_do_solana_anchor()` in `evidence_chain.py`. stdlib urllib (no httpx dep). Optional dep `agentir-core[solana]` → `solders>=0.21`. Degrades gracefully without solders. Proof written to `{case_dir}/evidence-anchor-v{N}.json`. 6 new tests.
- Phase 16f implemented: anchor status section in portal evidence intake panel (grey/amber/green states + Solscan link). `POST /api/evidence/chain/anchor` for manual re-anchor. Seal response includes anchor info. `triggerAnchor()` JS function.
- Env vars: `AGENTIR_SOLANA_KEYPAIR` (path to keypair JSON) + `AGENTIR_SOLANA_CLUSTER` (mainnet/devnet, default mainnet). Both optional — feature degrades to unanchored if unset.
- SIFT VM keypair generated: pubkey `9PjHRwGUeQTvCq8iF9nsALfFce6dUfXWbVFA57XBk1mW`, file at `/var/lib/agentir/solana-keypair.json`. Devnet airdrop + smoke test instructions in SIFT-MCPS-PLAN.md §Approach B.
- OpenSearch Docker and windows-triage DB download confirmed working on SIFT VM (user verified, not re-tested this session).
- Test counts: agentir-core 212 | case-dashboard 236 | sift-gateway 99 | case-mcp 15 | sift-mcp 3 | report-mcp 31.

**Session 33 — 2026-05-25 — Lightweight SIFT VM installer verification:**
- Target VM: `192.168.122.81` (`sansforensics`), Ubuntu 24.04.4, Python 3.12, Docker present, passwordless sudo, user systemd running.
- Copied current working tree to `/home/sansforensics/sift-mcps-test` and ran installer. First run exposed heavyweight sync issue: `uv sync --all-packages` pulled RAG/ML/CUDA wheels even with `--skip-db --skip-docker`.
- Installer fixes made: root `standard` extra excludes `rag-mcp`; `install.sh --skip-rag` syncs `--extra standard`; gateway template renders RAG disabled; existing configs migrate RAG disabled when rerun with `--skip-rag`.
- Installer config fixes made: template now uses `gateway.tls.certfile/keyfile`; installer migrates existing `cert/key` configs; `/api/v1/health` added as public alias for `/health`; handoff generation preserves existing temp password/tokens on rerun.
- Runtime fixes made from live VM failures: added console scripts for `forensic-mcp` and `sift-mcp`; `--skip-db` disables `windows-triage-mcp` so missing SQLite DBs do not keep failing; Starlette 1.0 uses `add_exception_handler`; `_notify_backend_case` no-op added for current stdio model; stdio backend now always passes parent env so `AGENTIR_CASE_DIR` reaches backends.
- Portal/gate fixes made from live testing: browser login now applies `agentir-auth-v1` domain separation; case-mcp `case_list`, `case_status`, `evidence_list`, and `evidence_verify` registered with `readOnlyHint`; gateway tool cache now preserves annotations/metadata.
- Lightweight install command now passes: `./install.sh -y --skip-rag --skip-db --skip-docker`. Verified service active+enabled, HTTPS portal 200, `/api/v1/health` and `/health` status OK, 5 enabled backends healthy (`forensic-mcp`, `case-mcp`, `sift-mcp`, `report-mcp`, `opensearch-mcp`), service-token aggregate MCP tools/list returns 55 tools.
- Portal workflow live-tested: repaired VM temp password after old handoff had been overwritten, then login returned `must_reset=true`, reset succeeded, relogin returned `must_reset=false`, and portal created `/cases/live-test-16` with canonical files plus empty evidence manifest/ledger.
- Evidence gate live-tested: with unsealed evidence, read-only `case_status` is allowed and receives `_agentir_context.evidence_gate_warning`; analysis `run_command` is blocked with `evidence_chain_unsealed`.
- Verification: full local package tests still pass: agentir-core 206, case-dashboard 196, sift-gateway 99, case-mcp 15, sift-mcp 3, report-mcp 31. Namespace gate returned no non-`vhir.` lines.
- Remaining full install verification: run without `--skip-docker` to start OpenSearch and install templates/pipelines; run without `--skip-db` to download and enable windows-triage SQLite baselines; optional full/RAG install still intentionally downloads ML dependencies.

**Session 32 — 2026-05-25 — Docs sync + Phase 16 verification start:**
- Updated `TASKS.md` for Session 31 completions: 16-gate-tier, 16d, and 16-verify-remind marked done; test breakdown updated to 550; duplicate stale 16b checklist entry removed.
- Updated `SIFT-MCPS-PLAN.md` stale two-tier-gate wording: `UNSEALED` permits read-only tools with warning, blocks analysis/write tools; chain violations block everything. Added HMAC verify reminder to acceptance bullets.
- Verification run: `uv sync --all-packages` passed; package tests passed: agentir-core 206, case-dashboard 196, sift-gateway 99, case-mcp 15, sift-mcp 3, report-mcp 31.
- Namespace/import gates: `grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."` returned no lines; imports passed for case-dashboard, sift-gateway, case-mcp, sift-mcp, report-mcp, agentir-core case_io, and approval_auth.
- Remaining Phase 16 Integration Verification: live gateway/TLS/installer/systemd/OpenSearch checks need a configured SIFT VM or running gateway service. Do not mark Phase 16 Integration Verification complete until those are exercised or explicitly deferred.

**Session 31 — 2026-05-25 — Phase 16-gate-tier + 16d + 16-verify-remind:**
- 16-gate-tier: fixed `test_two_tier_gate.py` integration failures against current MCP SDK API (`server.request_handlers`, `result.root.content`, awaited `gateway.get_tools_list`). Two-tier behavior now allows `UNSEALED` read-only tools with warning, blocks unsealed analysis tools, and blocks all tools on chain violations.
- 16d: `report-mcp` now attaches `evidence_chain` to every report result with status, manifest version/hash, ok count, and issues. `UNSEALED` yields `evidence_chain_warning`; MODIFIED/MISSING/UNREGISTERED/LEDGER_ERROR yield `integrity_warning` with "Do NOT distribute" language. Added 31 report tests and report-mcp pytest config.
- 16-verify-remind: portal evidence status now tracks `evidence-verify-state.json`, exposes `hmac_last_verified_at`, `hmac_last_verified_by`, and `hmac_verify_needed`, and adds `POST /api/evidence/chain/verify-hmac`. v2 UI shows amber/green reminder bar plus HMAC verify modal. Added 20 portal tests.
- Total: 550 tests (agentir-core 206 | case-dashboard 196 | sift-gateway 99 | case-mcp 15 | sift-mcp 3 | report-mcp 31).
- Next: run Phase 16 Integration Verification checklist. 16e/16f Solana anchoring remains optional/low priority; Phase 17 OS hardening should start after verification.

**Session 30 — 2026-05-25 — Phase 16-retire:**
- `evidence_chain.py`: added `_set_immutable(path, bool)` (CAP_LINUX_IMMUTABLE, graceful fallback)
- `evidence_chain.py`: added `retire_file(path, reason, examiner, derived_key)` → clears -i, marks RETIRED, FILE_RETIRED ledger event (HMAC-signed)
- `evidence_chain.py`: updated `diff_manifest()` to track `excluded` set (IGNORED + RETIRED); RETIRED files on disk no longer counted as UNREGISTERED
- `routes.py`: added `post_evidence_chain_retire` handler (same HMAC pattern as ignore; deletes file from disk after ledger update); wired to `/api/evidence/chain/retire`
- `test_evidence_chain.py`: 14 new tests (TestRetireFile 12 + TestDiffManifestRetiredExclusion 2)
- `test_evidence_intake.py`: 13 new portal retire tests
- Total: 473 tests (was 446)

**Session 29 — 2026-05-25 — Phase 16c:**
- `case-mcp/server.py`: replaced `evidence_ops` import with `evidence_chain` (chain_status, load_manifest, ChainStatus)
- `evidence_register`: now blocked — returns portal-remediation block `{blocked, reason, action, portal_hint}`, audit logged, never writes to either registry
- `evidence_list`: reads System B manifest (`evidence-manifest.json`), excludes IGNORED entries, returns `{evidence, manifest_version, source: "manifest_v2"}`
- `evidence_verify`: delegates to `chain_status(case_dir)`, returns `{status, issues, manifest_version, ok_count, source: "manifest_v2"}`, adds `portal_hint` on non-OK/non-UNSEALED
- `packages/case-mcp/tests/test_evidence_tools.py`: 15 new tests (5 register-blocked, 4 list-system-b, 6 verify-system-b)
- Total: 446 tests (was 431 before this session)

**Session 28 — 2026-05-25 — Audit Invariant:**
- Confirmed all 8 backends are stdio (HttpMCPBackend branches were dead code)
- `mcp_endpoint.py`: added `_hash_token` (SHA-256 first 16 hex chars), `_extract_request_context` (examiner + role + token_id + source_ip), replaced `_extract_examiner` with thin wrapper
- `MCPAuthASGIApp.__call__`: now sets `scope["state"]["source_ip"]` and `scope["state"]["token_id"]` on both authed and anonymous paths
- `create_mcp_server._call_tool`: restructured with try/finally — one `gateway_mcp_envelope` audit entry written on every path (ok / error / blocked / transport_error); `_backend_audit_id` extracted from raw response before redaction; params NOT logged (backends own that)
- Moved `_extract_audit_id/_truncate_params/_summarize_result` to top-level imports, removed duplicate local imports in `create_backend_mcp_server`
- 15 new tests in `test_audit_envelope.py`; total 428 passing

**Session 27 — 2026-05-25 — Phase 16a + Approach C:**
- Approach C: `sift_gateway/response_guard.py` — 25 patterns (15 critical, 7 high, 2 medium); `redact_tool_result` redacts critical+high inline; medium flagged only. In-memory override state: `enable_override/cancel_override/is_override_active/get_override_status` with TTL=600s.
- Wired into `mcp_endpoint.py` `_call_tool`: post-normalization redaction, audit log with `{pattern_name, severity, char_offset}` (never matched value), `_agentir_context.secret_warning` appended to TextContent.
- Three portal endpoints in `case-dashboard/routes.py`: `GET /api/response-guard/status` (session), `POST /api/response-guard/override` (HMAC — reuses `_verify_evidence_hmac`), `POST /api/response-guard/override/cancel` (session). Three callbacks wired via `create_dashboard_v2_app(on_override_*)`.
- `server.py` wired: passes `get_override_status/enable_override/cancel_override` from `response_guard`.
- 24 unit tests (sift-gateway) + 16 portal tests (case-dashboard). All 413 tests passing.
- Design: override uses same `_evidence_challenges` HMAC pattern for auth; `_OVERRIDE_GET/ENABLE/CANCEL` callbacks keep package boundary clean without circular imports.

**Session 27 — 2026-05-25 — Phase 16a:**
- 16a: 5 new evidence chain endpoints in `case-dashboard/routes.py` — GET /api/evidence/chain/status, POST /api/evidence/chain/rescan, GET /api/evidence/chain/challenge, POST /api/evidence/chain/seal, POST /api/evidence/chain/ignore
- Write-block detection: reads /proc/mounts (primary) + statvfs ST_RDONLY fallback
- `on_chain_mutation` callback parameter added to `create_dashboard_v2_app()` — gateway passes `invalidate_evidence_cache` so 30s TTL cache drops immediately on seal/ignore
- `_evidence_challenges` store: domain-separated from `_challenges` (commit) and `_login_challenges` (R2)
- `derive_ledger_key(stored_hash_hex)` used for evidence ledger signing (domain-separated from auth key)
- sift-gateway `server.py` wired: passes `on_chain_mutation=invalidate_evidence_cache` to dashboard factory
- 32 new tests: all 5 endpoints, HMAC verification, IP binding, single-use challenges, must_reset block, path traversal, callback invocation
- Total: 373 tests passing (192 agentir-core + 147 case-dashboard + 34 sift-gateway)

**Session 26 — 2026-05-24 — Phase 16-pre + 16g + 16b:**
- 16-pre: `agentir_core/evidence_chain.py` + 53 tests
- 16g: `init_evidence_chain()` wired into portal case create (`routes.py`) and CLI case create (`case_ops.py`); test updated
- 16b: `sift_gateway/evidence_gate.py` (30s TTL cache, mtime invalidation, `check_evidence_gate`, `invalidate_evidence_cache`) + wired into `mcp_endpoint.py` `_call_tool` before backend routing + 17 tests
- Total: 341 tests passing (was 271)
- Cache invalidation: mtime-based (immediate on manifest rewrite) + manual `invalidate_evidence_cache()` for when 16a portal seal is wired up

**Session 26 (cont) — 2026-05-24 — Phase 16-pre: evidence_chain.py:**
- New module: `packages/agentir-core/src/agentir_core/evidence_chain.py`
- New tests: `packages/agentir-core/tests/test_evidence_chain.py` (53 tests, all passing)
- API: `init_evidence_chain`, `load_manifest`, `load_ledger`, `hash_file`, `compute_manifest_hash`, `scan_evidence_dir`, `diff_manifest`, `chain_status`, `verify_chain_integrity`, `verify_chain_hmac`, `seal_manifest`, `ignore_file`
- Design: one MANIFEST_SEALED / FILE_IGNORED event per version (clean hash-chain); gateway path is key-free; mtime_ns informational only; symlinks skipped; path traversal blocked
- 324 total tests passing; cross-package pytest rootdir conflict confirmed pre-existing (not a regression)

**Session 25 — 2026-05-24 — MD Consolidation + Liquefy Assessment:**
- MD files consolidated: AGENTS.md 347→~240 lines, PLAN 1936→~650 lines, TASKS 1573→~250 lines
- Liquefy repo (`/home/yk/AI/SIFTHACK/liquefy/`) fully explored (AGENTS.md, audit chain, policy enforcer, safe-run, fleet, vault pack/restore, MRTV, LSEC v2, state guard)
- Integration decisions: Approach A (analyst machine deployment docs), B (Solana anchoring in Phase 16), C (gateway response scanner ~40 lines)
- DFIR assessment findings injected into PLAN.md: gateway must NOT rehash on every MCP call (stat-check + 30s TTL cache); mtime_ns is informational only; portal should show write-block detection status
- Liquefy audit chain is SHA-256 only (no HMAC) — weaker than our Phase 16 ledger; do not replace ours
- No code changes this session

**Session 24 — 2026-05-24 — Phase 15 Complete:**
- Phase 15 (Portal Session Security Hardening): JWT revocation (`revoke_jti`/`is_revoked`), sliding session refresh in `PortalSessionMiddleware`, login lockout rate limiting (429 after 5 failures), strict secure HTTP headers (HSTS, CSP, XFO, XXP, RP) globally on gateway
- 271 total tests passing (5 new for Phase 15)
- Key files: `case_dashboard/middleware.py`, `case_dashboard/routes.py`, `sift_gateway/server.py`
- Design decision: case create endpoint lives in portal `routes.py`, not gateway `rest.py`
