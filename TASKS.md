# sift-mcps — Task Tracker

**Plan file:** `SIFT-MCPS-PLAN.md` — normative spec; update it only when the spec changes.
**Principles:** `AGENTS.md` — immutable rules, design requirements, working commands.

---

## ⚡ Start Here Every Session

**Current state:** Phase 16-pre + 16g + 16b + 16a + Approach C complete. All 413 tests passing. Next: 16c (case-mcp evidence_register/verify/list), then 16d (report-mcp manifest inclusion).

```bash
# Verify tests (run per-package — cross-package rootdir conflict is pre-existing)
uv run pytest packages/agentir-core/tests/ --tb=short -q          # 192 passing
uv run pytest packages/case-dashboard/tests/ --tb=short -q        # 163 passing
for f in packages/sift-gateway/tests/test_*.py; do uv run pytest "$f" -q --tb=short 2>&1 | tail -1; done  # 58 passing

# Namespace gate (must stay 0)
grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."
```

**Test breakdown:** agentir-core 192 | case-dashboard 163 (+16 response_guard_portal) | sift-gateway 58 (+24 response_guard)

**Next phase:** Phase 16 — Evidence Manifest & Ledger (see §Next Work below and SIFT-MCPS-PLAN.md §Evidence Manifest)

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
- [ ] **16b** — `sift-gateway`: `verify_evidence_chain()` before every agent `/mcp` `call_tool`; implement stat-check + 30s in-memory TTL cache; structured block response + audit entry. Invalidate cache on portal seal.
- [ ] **16c** — `case-mcp`: update `evidence_register`, `evidence_list`, `evidence_verify` to use evidence chain model. Agent calls read status; only examiner portal actions may seal.
- [ ] **16d** — `report-mcp`: include evidence manifest version/hash in report; warn/fail when chain status is not OK.
- [ ] **16e** — `agentir-core`: add `anchor_manifest()` (Liquefy Approach B — Solana SPL Memo, see SIFT-MCPS-PLAN.md §Liquefy Integration). Optional dep: `pip install "agentir-core[solana]"`. Degrades gracefully without `solders`. Proof to `{case_dir}/evidence-anchor-v{N}.json`.
- [ ] **16f** — Portal: show anchor status per manifest version (Unanchored / Anchored — Solana tx: …) in evidence intake panel.
- [ ] **16g** — Installer / case create: write empty `evidence-manifest.json` and `evidence-ledger.jsonl` on case creation.
- [ ] **Phase 11 Integration Verification** — run full acceptance checklist from SIFT-MCPS-PLAN.md §Verification after Phase 16 is done.

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

## Deferred Items

- **Phase 4e** — `notifications/tools/list_changed`: blocked. `mcp==1.27.1` has `ServerSession.send_tool_list_changed()` but `StreamableHTTPSessionManager` exposes no public session lifecycle hook. Revisit on next MCP SDK minor release.
- **Phase 10** — Architecture cleanup (split `routes.py`, extract auth/examiner helpers). Low priority; do on next touch of those files.
- **Audit Invariant** — Every aggregate `/mcp` `call_tool` must write a minimal `sift-gateway.jsonl` envelope: role, token id, agent id/examiner, source IP, active case, tool, backend, status, duration. Link to backend `audit_id` via `backend_audit_id`. Never log raw tokens or HMAC responses. Must close before Phase 16 ships.

---

## Recent Session Notes

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
