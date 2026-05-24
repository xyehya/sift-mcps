# sift-mcps Task Tracker

**Project:** Portable MCP runtime for Hermes agent — digital forensics on SIFT VM  
**Plan:** `SIFT-MCPS-PLAN.md`  
**Brief / agent rules:** `AGENTS.md`  
**Source repos (read-only):**
- `/home/yk/AI/SIFTHACK/Valhuntir/` — original CLI
- `/home/yk/AI/SIFTHACK/Valhuntir/sift-mcp/` — original sift-mcp monorepo
- `/home/yk/AI/SIFTHACK/Valhuntir/opensearch-mcp/` — original opensearch-mcp
- `/home/yk/AI/SIFTHACK/hermes-agent/` — Hermes agent

Valhuntir is a reference source only. Use its README/workflow to understand useful ideas, but do
not replicate it as-is; sift-mcps is a decoupled, hardened, portable installer-first/portal-first runtime.

---

## Status Legend
- `[ ]` Not started
- `[x]` Done
- `[~]` In progress / partial
- `[!]` Blocked / needs input

---

## Documentation Tracking Contract

- `SIFT-MCPS-PLAN.md` is the normative spec: architecture, security requirements, behavioral contracts, and acceptance criteria.
- `TASKS.md` is the execution tracker: detailed tasks, implementation checklist, current next step, and session notes.
- `AGENTS.md` is the operating brief for coding agents: non-negotiable rules, current state summary, and pointers to the plan/tracker.
- If the plan and tracker contradict each other, stop and ask the user before implementing unless current code/tests clearly prove one side obsolete.

---

## Final Required Workflow Contract

Everything in this project must support this workflow:
1. Run one installer on the SIFT VM.
2. Installer provisions all Python packages, gateway, portal UI, OpenSearch Docker, enrichment/RAG assets, TLS, systemd service, default examiner credentials, and first Hermes service token.
3. Examiner/operator signs into the portal, resets the default password on first login, and creates a new case from the portal.
4. Portal case creation writes the selected case directory and `CASE.yaml`, updates the gateway active case, and reloads/restarts backends.
5. Hermes connects only to the gateway aggregate MCP endpoint (`/mcp`) using an `agentir_svc_*` token.
6. Gateway separates examiner and agent identities in auth, audit logs, and response enrichment.
7. Examiner reviews/approves in the portal; report generation includes only approved, signed findings.
8. Examiner uses the portal evidence security chain to seal evidence before agent investigation:
   manual files copied into `evidence/` are detected as unregistered, legitimate additions append a
   new evidence manifest/ledger version, and tampered/missing evidence blocks agent MCP operations.
9. Windows baseline validation is provided by a SIFT-local `windows-triage-mcp` backend. This is
   distinct from `wintools-mcp`; only the separate Windows host execution backend remains dropped.

Functional, resilience, and security tests must prove this workflow. No shortcuts or one-off workarounds.

---

## ⚠️ Start Here Every Session

1. Read `TASKS.md` (this file) — understand current state
2. Read `AGENTS.md` — project rules and design decisions
3. Read `SIFT-MCPS-PLAN.md` when changing architecture, security behavior, or task scope
4. Run `uv sync --all-packages` — confirm workspace installs
5. Run smoke tests:
   ```bash
   uv run pytest packages/agentir-core/tests/ -v --tb=short -q   # must be 139/139
   grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."  # must be 0 lines
   uv run python -c "from case_dashboard.routes import create_dashboard_v2_app; print('OK')"
   uv run python -c "from case_mcp.server import create_server; print('OK')"
   uv run python -c "from windows_triage_mcp.server import WindowsTriageServer; print('OK')"
   ```
6. **Next task: Phase 14** — Dashboard Rewiring (14a namespace cleanup, 14b auth flow rewiring, 14c login screen HTML/CSS, 14d login JS, 14e header additions, 14f case init modal, 14g agent token management UI). Phase 13 is complete. See SIFT-MCPS-PLAN.md §Phase 14.
   **Key settled decision (Session 22):** `POST /portal/api/case/create` lives in
   `routes.py` (portal package), NOT `rest.py` (gateway package). Auth is via
   `PortalSessionMiddleware` cookie session. The lock (`_case_create_lock`) and R5 symlink
   guard are in `routes.py`. See SIFT-MCPS-PLAN.md §14e for the full rationale.

> Newly created feature spec: Phase 16 adds evidence manifest + evidence ledger enforcement.
> It is not implemented yet. Preserve the current Phase 13-15 order unless the user explicitly
> reprioritizes, but do not design new MCP/report/portal behavior that conflicts with Phase 16.

---

## Phase 0 — Critical Bug Fixes ✅

> Completed. These bugs originally made the system non-functional; keep the verification gates passing.
> See SIFT-MCPS-PLAN.md Phase 0 for full specs on each fix.

### 0a. Namespace sweep: vhir → agentir across all packages ✅

- [x] All targeted files from original task list (case-dashboard, sift-gateway, sift-mcp)
- [x] Extended sweep: opensearch-mcp (paths.py, server.py, ingest_cli.py, gateway.py, client.py, containers.py, threat_intel.py, bulk.py, wintools.py, mappings/__init__.py, all parsers, all tests), sift-common (audit.py, __init__.py, oplog.py), forensic-mcp (server.py, case/manager.py), case-mcp (server.py), report-mcp (server.py), opencti-mcp (client.py, errors.py), plus YAML/JSON/shell/docker files
- [x] Verification gate passed: `grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."` → 0 lines

### 0b. Case directory redesign — replace active_case file with AGENTIR_CASE_DIR ✅

- [x] `packages/agentir-core/src/agentir_core/case_io.py`
  - [x] Removed `~/.agentir/active_case` fallback; `get_case_dir()` raises `CaseError` when `AGENTIR_CASE_DIR` not set
  - [x] `packages/sift-gateway/src/sift_gateway/config.py` propagates `AGENTIR_CASE_DIR` after config load
  - [x] `packages/sift-gateway/src/sift_gateway/server.py` dead methods deleted (`_get_active_case`, `_notify_backend_case`)
  - [x] `test_case_io.py` covers new behavior

### 0c. Delete case-dashboard inline duplicates, import from agentir-core ✅

- [x] Deleted `_compute_content_hash()`, `_load_password_entry()`, `_save_protected()`, `_write_hmac_entries()` from routes.py
- [x] Imports added from agentir_core; all call sites updated
- [x] Smoke test: `from case_dashboard.routes import create_dashboard_app` → OK

### 0d. opensearch-mcp TLS fix ✅

- [x] `packages/opensearch-mcp/src/opensearch_mcp/gateway.py`
  - `load_gateway_config()` now extracts `verify_certs` + `ca_cert_path` from `opensearch` config section
  - `call_tool()` TLS block: hardcoded `CERT_NONE` replaced with conditional — CERT_NONE only when `verify_certs=false`, ca_cert loaded if path provided, system CA bundle otherwise
  - Test: `uv run python -c "from opensearch_mcp.gateway import call_tool, load_gateway_config, gateway_available; print('OK')"` ✅

### 0e. Rename vhir_plugin.py ✅

- [x] Renamed `vhir_plugin.py` → `agentir_plugin.py`; fixed module/function docstrings and `--case` help text
- [x] `pyproject.toml` entry point group `vhir.plugins` → `agentir.plugins`; module ref updated
- [x] `test_vhir_plugin.py` → `test_agentir_plugin.py`; import updated
- [x] `grep -rn "vhir_plugin" packages/opensearch-mcp/` → 0 results
- [x] `uv run python -m pytest packages/opensearch-mcp/tests/test_agentir_plugin.py -v` → 3/3 passed ✅

### 0f. Phase 0 verification gate ✅

- [x] `grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."` → 0 lines ✅
- [x] `uv run pytest packages/agentir-core/tests/` → 125/125 passed ✅
- [x] `from case_dashboard.routes import create_dashboard_app` → OK ✅
- [x] `from case_mcp.server import create_server` → OK ✅
- [x] `from agentir_core.case_io import get_case_dir` → OK ✅
- [x] `from sift_gateway.config import load_config` → OK ✅

**Phase 0 COMPLETE** — all blocking bugs fixed, verification gate passed.

---

## Phase 1 — Workspace Scaffold ✅ (Complete — Session 1)

All workspace packages installed, agentir-core extracted, case-mcp and report-mcp imports fixed.
See Session 1 notes below. `uv sync` resolves 190+ packages cleanly.

---

## Phase 2 — agentir-core Tests ✅ (125/125 passing)

All test suites verified passing in Session 3:
- `test_case_io.py` — `get_case_dir()` CaseError on missing env, content hash, atomic write ✅
- `test_approval_auth.py` — PBKDF2 round-trip, lockout, examiner name validation ✅
- `test_verification.py` — HMAC ledger write/read/verify, rehmac on rotation ✅
- `test_case_ops.py` — case_init, case_status, case_list ✅
- `test_evidence_ops.py` — register/verify evidence with SHA-256 ✅
- `test_audit_ops.py`, `test_identity.py` ✅

---

## Phase 2b — agentir-core Library Hardening ✅ (Complete — Session 4)

> **Prerequisite for Phase 12 (portal auth):** approval_auth must raise exceptions, not call sys.exit.
> See AGENTS.md R8 and SIFT-MCPS-PLAN.md Phase 2b for full specs.

### 2b-1. Replace `sys.exit()` with exceptions in `approval_auth.py` ✅

- [x] Added `AuthError(Exception)` and `LockoutError(AuthError)` classes
- [x] `_check_lockout()` → `raise LockoutError(f"...{remaining} seconds.")`
- [x] `require_confirmation()` bad password → `raise AuthError(...)` or `raise LockoutError(...)`
- [x] `require_confirmation()` no password → `raise AuthError("No approval password configured...")`
- [x] `setup_password()` empty/short/mismatch → `raise AuthError(...)`
- [x] `reset_password()` no-password/wrong-password → `raise AuthError(...)`
- [x] `require_tty_confirmation()` no /dev/tty → `raise AuthError(...)`
- [x] No CLI callers exist outside agentir-core — no wrappers needed
- [x] Tests updated: `pytest.raises(AuthError/LockoutError)` throughout

### 2b-2. Make `VERIFICATION_DIR` and `_PASSWORDS_DIR` env-overridable ✅

- [x] `verification.py`: `VERIFICATION_DIR` reads `AGENTIR_VERIFICATION_DIR` env var
- [x] `approval_auth.py`: `_PASSWORDS_DIR` reads `AGENTIR_PASSWORDS_DIR` env var
- [x] `backup_ops.py`: `_PASSWORDS_DIR` reads `AGENTIR_PASSWORDS_DIR` env var
- [x] `_LOCKOUT_FILE` in approval_auth.py reads `AGENTIR_LOCKOUT_FILE` env var

### 2b-3. Remove `subprocess.run(["sudo",…])` from `_ensure_passwords_dir()` ✅

- [x] Replaced subprocess block with `raise PermissionError(f"Cannot create {passwords_dir}/...")`
- [x] Removed `import subprocess` (and unused `import getpass as getpass_mod`) from approval_auth.py
- [x] Test updated: `pytest.raises(PermissionError)` on unwritable dir

### 2b-4. Verification gate ✅

- [x] `uv run pytest packages/agentir-core/tests/ -v --tb=short` → 125/125 passed
- [x] `from agentir_core.approval_auth import AuthError, LockoutError` → OK
- [x] `grep -n "sys.exit\|subprocess" approval_auth.py` → 0 lines

---

## Phase 3 — Portal Security Hardening ✅ (Complete — Session 5)

> See SIFT-MCPS-PLAN.md Phase 3 for detailed code specs.
> Target files: `packages/sift-gateway/src/sift_gateway/server.py`,
>               `packages/case-dashboard/src/case_dashboard/routes.py`

### 3a. HTTPS enforcement middleware ✅
- [x] Added `_PortalHTTPSGuard` ASGI middleware in `server.py` (before `_NormalizeMCPPath`)
  - Returns 400 for `/portal`, `/dashboard` paths over plain HTTP when TLS configured
  - `tls_configured` = True when `config["gateway"]["tls"]["cert"]` is set
  - Added as outermost middleware (after `_NormalizeMCPPath` in add order)

### 3b. Nonce IP binding + TTL reduction in routes.py ✅
- [x] Added `bound_ip: request.client.host` to `_challenges[challenge_id]` in `get_commit_challenge()`
- [x] In `post_commit()`, after popping challenge, check `challenge["bound_ip"] != request.client.host` → return 403
- [x] Changed `_CHALLENGE_TTL = 60` → `_CHALLENGE_TTL = 30`

### 3c. CORS restriction on gateway app ✅
- [x] Added `CORSMiddleware` to `server.py::create_app()`
  - `allow_origins` = [gateway base URL derived from config host/port/TLS, "https://localhost:4508"]
  - `allow_methods` = ["GET", "POST", "DELETE"]
  - `allow_headers` = ["Authorization", "Content-Type", "MCP-Protocol-Version"]

### 3d. Error sanitization ✅
- [x] Added global `@app.exception_handler(Exception)` in `create_app()` — logs exception, returns generic 500
- [x] Fixed `routes.py::post_commit()`: `str(e)` → `"Commit failed — check gateway logs"`
- [x] Fixed `routes.py::get_case()`: `str(e)` → `"Case metadata could not be read — check gateway logs"`

### 3e. opensearch-mcp TLS
- Covered in Phase 0d ✓

---

## Phase 4 — Gateway Improvements ✅ (4a-4d Complete — Session 6)

> See SIFT-MCPS-PLAN.md Phase 4 for detailed code specs.

### 4a. Shared auth helper + bearer token expiry ✅
- [x] Added `verify_api_key(token: str, api_keys: dict) -> dict | None` to `auth.py`
  - Length check, timing-safe iteration, key_info validation, `expires_at` ISO datetime check
- [x] Replaced timing-safe loop in `AuthMiddleware.dispatch` with `verify_api_key()` call
- [x] Replaced timing-safe loop in `MCPAuthASGIApp.__call__` with `verify_api_key()` call
- [x] Removed duplicate `_MAX_TOKEN_LENGTH` and `import hmac` from `mcp_endpoint.py`
- [x] Functional test: expired token → None; future expiry → valid dict; invalid → None ✅

### 4b. Per-examiner rate limiting (post-auth) ✅
- [x] Added examiner rate limiter singleton to `rate_limit.py` (reuses `RateLimiter`, keyed by examiner string)
  - `get_examiner_rate_limiter()`, `reset_examiner_rate_limiter()`, `check_examiner_rate_limit()`
- [x] In `MCPAuthASGIApp.__call__`, after auth succeeds, calls `check_examiner_rate_limit(examiner)`
- [x] `MCPAuthASGIApp.__init__` accepts `examiner_calls_per_minute: int = 120`; initializes singleton
- [x] `server.py::create_app()` reads `gateway.rate_limit.examiner_calls_per_minute` from config; passes to all `MCPAuthASGIApp` instances
- [x] Updated `rate_limit.py` module docstring

### 4c. Origin header validation ✅
- [x] In `MCPAuthASGIApp.__call__`, after IP rate limit check, before auth:
  - Reads `Origin` header from raw ASGI scope headers
  - If present and not in `self.allowed_origins`: returns 403
  - If absent: passes through (Hermes/curl don't set Origin)
- [x] `MCPAuthASGIApp.__init__` accepts `allowed_origins: set[str] | None`
- [x] `server.py::create_app()` computes `gateway_base_url` from config host/port/TLS; builds `allowed_origins` set; passes to all instances

### 4d. Extract examiner helper in mcp_endpoint.py ✅
- [x] Added `_extract_examiner(server: Server) -> str | None` helper
- [x] Replaced both copy-pasted try/except blocks in `create_mcp_server` and `create_backend_mcp_server`

### 4e. notifications/tools/list_changed
- [x] Research: check if `StreamableHTTPSessionManager` exposes session lifecycle hooks
  - Result: installed MCP SDK exposes only `run()` and `handle_request()` on `StreamableHTTPSessionManager`; it privately tracks `StreamableHTTPServerTransport`, not `ServerSession`.
  - `ServerSession.send_tool_list_changed()` exists, but there is no public manager lifecycle hook that hands gateway code active `ServerSession` objects.
  - Version check: `uv pip show mcp` → `1.27.1`; `uv pip install --upgrade mcp --dry-run` found no newer `mcp` package, only newer transitive `pyjwt`/`starlette`.
- [!] Add `_active_mcp_sessions` tracking to `Gateway` class
  - Needs implementation decision: either defer until SDK exposes lifecycle hooks, or add a local `Server` subclass/wrapper that tracks sessions by copying the SDK `Server.run()` flow.
- [ ] Emit `notifications/tools/list_changed` from `_build_tool_map()` when it's not the first build
- [ ] Test: trigger a backend restart, verify Hermes refreshes tool list

---

## Phase 5 — forensic-rag FastMCP Migration ✅

> `packages/forensic-rag-mcp/src/rag_mcp/server.py` uses low-level MCP SDK.
> See SIFT-MCPS-PLAN.md Phase 5 for code template.

- [x] Read `server.py` fully — catalog all tools and their current implementations
  - Tools: `search_knowledge`, `list_knowledge_sources`, `get_knowledge_stats`
  - Note: model allowlist validation, input length limits, ChromaDB integration
- [x] Rewrite using `from mcp.server.fastmcp import FastMCP`
  - Preserve all tool implementations unchanged (only wrap in FastMCP decorators)
  - Add `annotations={"readOnlyHint": True}` to all three tools
  - Keep existing instructions string
- [x] Test: `uv run rag-mcp --help` outputs tool list
- [x] Test: `uv run python -c "from rag_mcp.server import mcp; print('OK')"`

---

## Phase 6 — sift-mcp Argument Sanitization Hardening ✅

> `packages/sift-mcp/src/sift_mcp/security.py`
> See SIFT-MCPS-PLAN.md Phase 6 for exact code.

- [x] Add `import unicodedata` at top of `security.py`
- [x] In `sanitize_extra_args()`, before existing flag checks, add:
  - Null-byte check: `if "\x00" in arg: raise ValueError(...)`
  - Length limit: `if len(arg) > 4096: raise ValueError(...)`
  - NFC normalization: normalize and log if arg changed
- [x] Write tests:
  - `assert raises ValueError` on null-byte arg
  - `assert raises ValueError` on 4097-char arg
  - `assert normalizes` a known non-NFC Unicode string

---

## Phase 7 — Install Script

- [x] Create `/home/yk/AI/SIFTHACK/sift-mcps/install.sh`
  - Executable, bash, target Ubuntu 22.04/24.04
  - Steps per SIFT-MCPS-PLAN.md Phase 7 (Python check, uv install, sync, dirs, OpenSearch Docker, enrichment/RAG prep, TLS gen, token gen, default examiner creation, gateway.yaml write, systemd, health poll, summary)
  - Non-interactive mode: `./install.sh -y`
  - Idempotent: re-running on an already-installed system should not break anything
- [x] Installer creates `/var/lib/agentir/{passwords,verification,enrichment,tokens}` and default case root
- [x] Installer deploys OpenSearch Docker compose and verifies healthy localhost-only binding
- [x] Installer prepares forensic-knowledge, forensic-rag, and OpenSearch enrichment assets
- [x] Installer creates default examiner account with `must_reset_password: true`
- [x] Installer generates first `agentir_svc_*` Hermes service token and stores token metadata without logging raw token in normal logs
- [x] Installer writes gateway config with empty `case.dir` and portal-created-case workflow enabled
- [ ] Test on clean Ubuntu VM or container
- [x] `chmod +x install.sh`

---

## Audit Invariant / Regression Guard

> Do not weaken this while implementing installer, config, auth, token lifecycle, or dashboard work.

- [x] Confirm central audit storage model.
  - `sift_common.audit.AuditWriter` writes append-only JSONL to `AGENTIR_AUDIT_DIR` or `AGENTIR_CASE_DIR/audit/`, one file per writer/MCP (`sift-gateway.jsonl`, `sift-mcp.jsonl`, etc.), with flush + fsync.
  - Existing evidence/provenance readers aggregate all `audit/*.jsonl`: `agentir_core.case_io.load_audit_index()`, `agentir_core.audit_ops._load_audit_entries()`, case-dashboard audit lookup, and forensic-mcp provenance classification.
  - HMAC verification remains separate at `/var/lib/agentir/verification/{case-id}.jsonl`; report reconciliation checks approved findings/timeline against that ledger.
- [~] Current state: tool actions are audited, but not yet in the final gateway-envelope shape for every backend.
  - All intended agent calls enter through gateway HTTP MCP `/mcp`.
  - Gateway then routes to local stdio backends; those backends write detailed per-backend evidence logs through `AuditWriter`.
  - Gateway currently writes centralized proxy audit entries only for `HttpMCPBackend` paths, which are not part of the final normal SIFT backend set.
  - Aggregate `/mcp` auth currently sets examiner/role in request state, and gateway injects examiner identity into `ANALYST_TOOLS`.
- [ ] Close remaining final-spec gap: every aggregate `/mcp` `call_tool` must write a minimal gateway envelope to `audit/sift-gateway.jsonl` with request/correlation id, role, token id, agent id or examiner, source IP, active case, aggregate tool, resolved backend, status, duration, and truncation/result summary.
- [ ] Preserve existing backend `audit_id`s as canonical evidence/provenance IDs; add `backend_audit_id` correlation from gateway envelope when available instead of replacing backend IDs.
- [ ] Ensure raw bearer tokens and HMAC responses are never logged.
- [ ] Add tests before/with Phase 13 proving two different service tokens produce separable gateway logs.

---

## Phase 8 — Docker Compose (OpenSearch)

- [x] Create `/home/yk/AI/SIFTHACK/sift-mcps/docker-compose.yml`
  - OpenSearch 2.18.0, single-node, security disabled, 3GB JVM heap
  - Bound to 127.0.0.1:9200 only
  - Named volume for persistence
  - Healthcheck included
  - `restart: unless-stopped`
- [ ] Test: `docker compose up -d && docker compose ps` — shows healthy

---

## Phase 9 — Configs and Templates

- [x] Create `configs/gateway.yaml.template` (full annotated template per plan Phase 9)
- [x] Template includes `case.root`, empty `case.dir`, portal session settings, OpenSearch settings, enrichment settings, examiner fallback token, and first service-token metadata
- [x] Create `configs/hermes-forensics-profile.yaml` (per plan Phase 9)
- [x] Hermes profile exposes only aggregate `https://SIFT_IP:4508/mcp`, not per-backend MCP URLs
- [x] Create `configs/systemd/sift-gateway.service` (per plan Phase 9)
- [x] Ensure `configs/` directory exists in repo with a `.gitkeep` if needed

---

## Phase 10 — Architecture Cleanup

> Do after all security phases are complete. These are debt-reduction, not blocking.

### 10a. Split case-dashboard/routes.py
- [ ] Create `packages/case-dashboard/src/case_dashboard/auth.py` — challenge store, lockout, examiner resolution
- [ ] Create `packages/case-dashboard/src/case_dashboard/delta.py` — `_apply_delta` and decomposed helpers
- [ ] Create `packages/case-dashboard/src/case_dashboard/files.py` — file utilities, case dir resolution
- [ ] Update `routes.py` to import from new modules (thin route handlers only)
- [ ] Verify all existing endpoints still work

### 10b. Decompose _apply_delta
- [ ] `_process_approvals(items_list, item_by_id, examiner, now) -> (approved_items, log_entries, skipped)`
- [ ] `_process_rejections(items_list, item_by_id, examiner, now) -> (log_entries, skipped)`
- [ ] `_process_edits(items_list, item_by_id, examiner, now) -> (edited_count, log_entries, skipped)`
- [ ] `_cascade_timeline(all_items, item_by_id, examiner, now) -> (approved_items, log_entries)`
- [ ] `_cascade_iocs(iocs, item_by_id, examiner, now) -> (iocs_modified, log_entries, approved_items)`
- [ ] `_write_commit_results(...)` — handles disk writes with correct ordering

### 10c. Windows backend split cleanup
- [ ] Remove dead `wintools-mcp` supported-workflow references from `packages/sift-gateway/`, `packages/case-mcp/`, and `packages/sift-common/`
- [ ] Preserve/add `windows-triage-mcp` references where they mean local baseline validation
- [ ] Replace stale case-mcp wording that says "Windows-triage support has been dropped"
- [ ] Ensure `case_status()` reports separate capabilities for `windows_triage` and `wintools`

---

## Phase 11 — Restore Windows Baseline Validation Backend (NEW)

> See `SIFT-MCPS-PLAN.md` Phase 11. This corrects the earlier misinterpretation:
> `windows-triage-mcp` is local/offline Windows baseline validation and OpenSearch enrichment support.
> `wintools-mcp` is the separate Windows host execution backend and remains out of scope.

### 11a. Source audit and package scaffold
- [x] Locate/verify original `windows-triage-mcp` source or reconstruct from original docs/source lineage
- [x] Add `packages/windows-triage-mcp/pyproject.toml`
- [x] Add FastMCP stdio entry point `windows-triage-mcp`
- [x] Add package to root `pyproject.toml` workspace members and optional dependencies
- [x] Rename all legacy paths/env/config from `vhir` to `agentir`

> Session 21 correction: the original source does exist at
> `/home/yk/AI/SIFTHACK/sift-mcp/packages/windows-triage/`. The current JSON-backed package is
> temporary scaffolding only and must be replaced/upgraded with the original SQLite-backed runtime.

### 11a2. Port original SQLite-backed windows-triage implementation
- [x] Port `src/windows_triage/analysis/` from original source
- [x] Port `src/windows_triage/db/` with `KnownGoodDB`, `ContextDB`, `RegistryDB`, and schemas
- [x] Port `src/windows_triage/importers/` and `data/process_expectations.yaml`
- [x] Port `tool_metadata.py`, audit/oplog behavior, and response caveats/interpretation constraints
- [x] Decide whether to keep original low-level MCP `Server` or adapt to FastMCP without changing tool schemas/behavior
- [x] Replace temporary JSON DB loader with SQLite paths:
  - `known_good.db`
  - `context.db`
  - optional `known_good_registry.db`
- [x] Support installer-facing `AGENTIR_WINDOWS_TRIAGE_DB_DIR` while preserving compatibility aliases for original `WT_*` env vars if useful
- [x] Add dependencies from original package: `zstandard`, `python-registry`, and `pyyaml` if needed
- [x] Ensure missing/invalid required DBs produce clear degraded health and no trusted EXPECTED verdicts

### 11b. Baseline database asset contract
- [x] Define default DB root `/var/lib/agentir/windows-triage/`
- [x] Add env override for tests/non-root installs, e.g. `AGENTIR_WINDOWS_TRIAGE_DB_DIR`
- [x] Add installer provisioning/download/extract step for baseline DB assets
- [x] Add clear missing-DB health/error responses; never silently return trusted verdicts when DBs are absent
- [x] Document expected disk footprint and air-gapped install behavior
- [x] Port `windows_triage.scripts.download_databases` release downloader:
  - download `known_good.db.zst`, `context.db.zst`, and `checksums.sha256`
  - source release repo/tag pattern: `AppliedIR/sift-mcp`, `triage-db-*`
  - verify SHA-256 checksums before decompressing
  - decompress with `zstandard`
  - verify minimum row counts (`baseline_files`, `lolbins`, `vulnerable_drivers`)
- [x] Wire installer to run downloader into `/var/lib/agentir/windows-triage` unless explicitly skipped/offline
- [x] Preserve maintainer build scripts for rebuilding DBs from upstream sources:
  - `init_databases.py`
  - `import_files.py`
  - `import_context.py`
  - `import_registry_extractions.py`
  - `import_registry_full.py`
  - `update_sources.py`
  - `build-release.sh`

### 11c. Restore 13 baseline tools
- [x] `check_file` — backed by original SQLite `KnownGoodDB` + `ContextDB`
- [x] `check_process_tree` — uses original process expectations/context DB logic
- [x] `check_service` — uses original service baseline semantics
- [x] `check_scheduled_task` — uses original task baseline semantics
- [x] `check_autorun` — uses original autorun baseline semantics
- [x] `check_registry` — uses optional original `known_good_registry.db`
- [x] `check_hash` — uses original LOLDrivers context DB
- [x] `analyze_filename` — uses original filename/unicode/path analysis
- [x] `check_lolbin` — uses original LOLBAS context DB
- [x] `check_hijackable_dll` — uses original HijackLibs context DB
- [x] `check_pipe` — uses original Windows pipe + C2 pattern context DB
- [x] `get_db_stats` — reports original SQLite DB stats/coverage
- [x] `get_health` — reports original SQLite DB health/cache/degraded state

### 11d. Gateway and installer integration
- [x] Add `windows-triage-mcp` backend to `configs/gateway.yaml.template`
- [x] Add backend instructions in `sift_gateway/mcp_endpoint.py`
- [x] Ensure Hermes profile still exposes only aggregate `/mcp`, not per-backend URLs
- [x] Update systemd/env template if DB path env vars are needed
- [x] Add gateway list-tools test proving 13 tools appear when backend is enabled

### 11e. OpenSearch enrichment integration
- [x] Audit `opensearch_mcp.triage_remote` and `idx_enrich_triage`
- [x] Ensure calls go through the gateway/backend abstraction, not stale direct client assumptions
- [x] Add degraded-mode tests for missing backend or missing baseline DB
- [x] Add successful enrichment fixture test for EXPECTED/SUSPICIOUS/UNKNOWN verdict stamping

### 11f. Explicitly keep Windows host execution out of scope
- [x] Do not add `wintools-mcp` to Hermes templates
- [x] Do not add SMB share orchestration or Windows join flow to installer-first workflow
- [x] Remove or quarantine stale `wintools` hot-load/join code if it conflicts with the supported contract
- [x] Keep only compatibility stubs if needed for old config detection, with warnings that it is unsupported

### 11g. Verification
- [x] `uv sync --all-packages`
- [x] `uv run pytest packages/windows-triage-mcp/tests/ -v --tb=short`
- [x] `uv run pytest packages/opensearch-mcp/tests/ -v --tb=short`
- [x] `uv run pytest packages/agentir-core/tests/ -v --tb=short`
- [x] `grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."` → 0 lines
- [x] After SQLite port: run restored `windows-triage-mcp` tests against fixture SQLite DBs
- [x] After downloader port: test release-download failure/degraded path without network
- [x] After downloader port: test checksum/row-count verification with local fixture `.zst` assets
- [x] After SQLite port: verify `idx_enrich_triage` stamps EXPECTED/SUSPICIOUS/UNKNOWN through gateway-backed calls

---

## Phase 12-pre — Security Prerequisites (R8) ✅ (Complete — Session 15)

> Target: `packages/agentir-core/src/agentir_core/approval_auth.py`,
>         `packages/agentir-core/src/agentir_core/verification.py`
> Rationale: the stored PBKDF2 hash must never be used directly as a cryptographic key.
> Full spec in SIFT-MCPS-PLAN.md §Phase 12 Security Requirements R8.

- [x] Add `derive_auth_key(stored_hash_hex: str) -> bytes` to `approval_auth.py`
  - `hmac.new(bytes.fromhex(stored_hash_hex), b"agentir-auth-v1", hashlib.sha256).digest()`
- [x] Add `derive_ledger_key(stored_hash_hex: str) -> bytes` to `approval_auth.py`
  - `hmac.new(bytes.fromhex(stored_hash_hex), b"agentir-signing-v1", hashlib.sha256).digest()`
- [x] Update `verification.py::derive_hmac_key()` to call `derive_ledger_key()` internally (lazy import to avoid circular) instead of using the hash bytes directly
- [x] Added `TestKeyDerivation` class in `test_approval_auth.py` (10 tests): existence, output length, domain separation, determinism, different-input-different-output, key ≠ raw hash
- [x] Replaced stale `test_derive_hmac_key` in `test_verification.py` with `TestDeriveHmacKey` class (5 tests): determinism, length, different-passwords-differ, different-salts-differ, key ≠ raw PBKDF2 output (R8 guard)
- [x] `pytest packages/agentir-core/tests/ -v --tb=short` → 139/139 passed (125 original + 14 new)

---

## Phase 12 — Portal Authentication: Login UI, Session JWT, Registration

> See SIFT-MCPS-PLAN.md Phase 12 for full design spec.
> Target files: `packages/case-dashboard/src/case_dashboard/routes.py` (new endpoints),
>               `packages/case-dashboard/src/case_dashboard/auth.py` (session middleware — new file),
>               `packages/sift-gateway/src/sift_gateway/config.py` (portal_session_secret loading)

### 12a. Backend: JWT helpers (new file `case_dashboard/session_jwt.py`) ✅

- [x] `generate_jwt(sub, role, secret, max_age=28800) -> str`
  - Header: `{"alg": "HS256", "typ": "JWT"}` base64url-encoded (module-level constant)
  - Payload: `{sub, role, iat, exp, jti}` base64url-encoded
  - Signature: `HMAC-SHA256(secret, header + "." + payload)` base64url-encoded
  - Returns `header.payload.signature`
- [x] `verify_jwt(token, secret) -> dict | None`
  - Splits on `.`, decodes, checks signature (timing-safe via `hmac.compare_digest`), checks `exp > now`
  - Returns payload dict or None on any failure (never raises)
- [x] `COOKIE_NAME = "agentir_session"`, `COOKIE_PATH = "/portal"`, `COOKIE_SAME_SITE = "strict"`
- [x] 19 tests in `packages/case-dashboard/tests/test_session_jwt.py`: round-trip, tampered sig, tampered payload, wrong secret, expired, malformed, never-raises, jti uniqueness, cookie constants

### 12b. Backend: `portal_session_secret` config ✅

- [x] `packages/sift-gateway/src/sift_gateway/config.py`: log warning if `portal.session_secret` is absent/empty after config load
- [x] `packages/sift-gateway/src/sift_gateway/server.py::create_app()`: reads `portal.session_secret` and `portal.session_max_age` (default 28800) from config; passes both to `create_dashboard_v2_app()`
- [x] `case_dashboard/routes.py::create_dashboard_v2_app(session_secret, session_max_age)`: stores as module-level `_SESSION_SECRET` / `_SESSION_MAX_AGE`; 6 wiring tests in `test_session_wiring.py`

### 12c. Backend: session middleware (`case_dashboard/auth.py`) ✅

- [x] New `PortalSessionMiddleware(BaseHTTPMiddleware)` in `case_dashboard/auth.py`:
  - Cookie → `verify_jwt(_session_secret)` → set examiner/role
  - If no valid cookie: Bearer token → `_verify_bearer` (inline timing-safe check) → examiner role only; agent tokens never accepted
  - If neither: examiner=None, role=None
  - Never returns 401 itself
- [x] `_verify_bearer()` helper with timing-safe compare, expiry check (no sift_gateway import — standalone)
- [x] `_API_KEYS` module-level var added to routes.py; `create_dashboard_v2_app()` gains `api_keys` param; passes both `session_secret` and `api_keys` to `PortalSessionMiddleware`
- [x] `server.py` passes `api_keys` to `create_dashboard_v2_app()`
- [x] 14 tests in `test_session_middleware.py`: cookie auth, tampered/expired cookie, Bearer examiner/agent distinction, no-auth state, middleware-never-returns-401, R9 getattr access

### 12d. Backend: auth endpoints (add to `routes.py`) ✅

- [x] `GET  /api/auth/setup-required` — returns `{"required": bool}` based on passwords dir
- [x] `POST /api/auth/setup` — creates first examiner; 409 if already set up; validates name + password length
- [x] `GET  /api/auth/challenge` — uses `_login_challenges` (separate from `_challenges`)
  - **R3** Always returns 200 with valid-looking challenge even for unknown examiners (fake entries)
  - **R6** Cap 200 total, 5 per examiner; evicts oldest on overflow
- [x] `POST /api/auth/login` — PBKDF2 challenge-response; R8 derive_auth_key; sets session cookie
  - **R3** Fake challenges always fail "Invalid credentials" — same path as real mismatch
  - **R2** Login failures under `login:{examiner}` namespace
  - On success: HttpOnly Secure SameSite=Strict `agentir_session` cookie; returns `{examiner, role, expires_at, must_reset}`
- [x] `POST /api/auth/reset-password` — requires session + login challenge + new password; clears must_reset_password
- [x] `POST /api/auth/logout` — Max-Age=0 cookie clear
- [x] `GET  /api/auth/me` — returns session info or 401; R1 re-reads must_reset from disk
- [x] 36 tests in `test_auth_endpoints.py`: setup/challenge/login/logout/me, R1/R2/R3/R6/R8

### 12e. Backend: update existing route guards ✅

- [x] `_resolve_examiner()` — removed env var fallback; R9 getattr only
- [x] `post_delta`, `delete_delta_item`, `verify_evidence` — 401 if no examiner, 403 if must_reset
- [x] `get_commit_challenge`, `post_commit` — added must_reset check (R1)
- [x] `_login_challenges` separate dict from `_challenges` (commit challenges); login lockout helpers with `login:{examiner}` namespace

### 12f. Gateway: R4 agent→portal block ✅

- [x] `auth.py::AuthMiddleware.dispatch()`: agent tokens → 403 on `/portal/api/` paths
- [x] Portal paths (`/portal/...`) now bypass gateway auth (portal handles own auth via `PortalSessionMiddleware`)
- [x] 8 tests in `packages/sift-gateway/tests/test_portal_agent_block.py`

---

## Phase 13 — Separate Agent Credentials + Role-Based Access Control ✅

> See SIFT-MCPS-PLAN.md Phase 13 for full design spec.
> Target files: `packages/sift-gateway/src/sift_gateway/token_gen.py`,
>               `packages/sift-gateway/src/sift_gateway/auth.py`,
>               `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`

### 13a. Token generation ✅

- [x] `token_gen.py`: `generate_service_token() -> str` → `f"agentir_svc_{secrets.token_hex(24)}"`
- [x] `token_gen.py`: `generate_gateway_token()` → `f"agentir_gw_{secrets.token_hex(24)}"` (192-bit entropy)
- [x] `install.sh` generates BOTH tokens and writes both to `gateway.yaml`
- [x] Stable token metadata schema: `token_id`, `agent_id`, `label`, `role`, `created_by`, `created_at`, `expires_at`, `revoked_at`, last-used metadata — defined in gateway.yaml.template

### 13b. Role enforcement in auth middleware ✅

- [x] `auth.py::AuthMiddleware.dispatch()`: readonly portal write block (403 on non-GET/HEAD)
- [x] `mcp_endpoint.py::MCPAuthASGIApp.__call__()`: `role == "readonly"` → 403 before session manager
- [x] Production Hermes workflow uses only `/mcp`

### 13c. Role enforcement in portal routes ✅

- [x] `_require_examiner_role(request) -> JSONResponse | None` helper in routes.py
- [x] Applied to: `post_delta`, `delete_delta_item`, `post_commit`, `get_commit_challenge`, `verify_evidence`
- [x] Applied to token create/revoke/rotate endpoints (Phase 13f)

### 13d. `gateway.yaml` template with two tokens ✅

- [x] `configs/gateway.yaml.template` shows both `agentir_gw_*` (examiner) and `agentir_svc_*` (agent) keys with role/label/metadata comments
- [x] `configs/hermes-forensics-profile.yaml` shows `agentir_svc_*` token in mcp.json example

### 13f. Portal service-token lifecycle ✅

- [x] `GET /api/tokens` — lists agent/readonly token metadata; never returns raw token values; sorted by created_at
- [x] `POST /api/tokens` — creates `agentir_svc_*` token; validates agent_id, label, role, expires_at; blocks duplicate active agent_id; raw token returned once
- [x] `DELETE /api/tokens/{token_id}` — revokes token (sets revoked_at); blocks double-revoke (409); guards against revoking examiner tokens
- [x] `POST /api/tokens/{token_id}/rotate` — revokes old + creates new atomically; returns new raw token once
- [x] All write endpoints: examiner role + must_reset checks
- [x] `_token_config_write()` writes gateway.yaml atomically (mkstemp+fsync+os.replace, 0o600) and updates `_API_KEYS` in-memory — no restart needed
- [x] `create_dashboard_v2_app()` accepts `gateway_config_path`; `server.py` injects `AGENTIR_GATEWAY_CONFIG` or `~/.agentir/gateway.yaml`
- [x] 28 tests in `test_token_lifecycle.py`: list/create/revoke/rotate, RBAC guards, input validation, disk persistence, in-memory update, token separability

### 13e. Token expiry enforcement ✅ (Satisfied by Phase 4a)

- [x] `auth.py::AuthMiddleware` and `mcp_endpoint.py::MCPAuthASGIApp` use shared `verify_api_key()`
- [x] `verify_api_key()` checks `key_info.get("expires_at")`, parses ISO datetime, and rejects expired tokens
- [x] Functional test recorded in Phase 4a: expired token → None; future expiry → valid dict; invalid → None

---

## Phase 14 — Dashboard Rewiring

> See SIFT-MCPS-PLAN.md Phase 14 for full design spec.
> Target file: `packages/case-dashboard/src/case_dashboard/static/v2/index.html` (188KB)
> Strategy: targeted string replacements + JS section rewrites. Do NOT rewrite the whole file.

### 14a. Namespace / branding cleanup

- [x] Title: `Valhuntir — Examiner Portal` → `sift-mcps — Examiner Portal`
- [x] Header title HTML: `Valhuntir — ` → `sift-mcps — `
- [x] Icon `src`: `valhuntir-icon.png` → `agentir-icon.png`
- [x] Rename icon file: `static/v2/valhuntir-icon.png` → `static/v2/agentir-icon.png`
- [x] localStorage key: `vhir-theme` → `agentir-theme` (replace_all)
- [x] localStorage key: `vhir-sidebar-width` → `agentir-sidebar-width`
- [x] localStorage key: `vhir-has-committed` → `agentir-has-committed`
- [x] All occurrences of `vhir approve --review` → remove or replace with "use the portal commit button"
- [x] `vhir case activate` / `vhir case init` references → replace with portal UI instructions
- [x] Help text "Valhuntir is an AI-assisted..." → update to sift-mcps branding
- [x] "vhir CLI" reference in help → "agentir CLI"
- [x] Smoke test: `grep -c "vhir\|valhuntir\|Valhuntir" index.html` → 0 (case-insensitive)

### 14b. Auth flow rewiring

- [x] Remove `extractToken()` IIFE (the `#token=` URL hash extraction block)
- [x] Remove `sessionStorage.setItem('vhir_dashboard_token', ...)` and `getItem` calls
- [x] Remove `token` variable declaration and all `if (token)` Bearer injection in `apiHeaders()`
- [x] `apiFetch`: remove `Authorization` header injection; keep `Content-Type`
- [x] `apiFetch` error handler: on 401 → call `showLoginScreen()` instead of throwing
- [x] Add `currentExaminer` and `currentRole` module-level variables
- [x] On page load: call `checkSession()` first; on success `showApp()`; on 401 `showLoginScreen()`
- [x] `checkSession()`: `GET /api/auth/me` → set `currentExaminer`, `currentRole`

### 14c. Login screen HTML + CSS

- [x] Add `<div id="loginScreen" style="display:none">` section with:
  - sift-mcps branding (title, subtitle)
  - Examiner name input `#loginExaminer`
  - Password input `#loginPassword`
  - Sign in button `#loginBtn`
  - Error message area `#loginError`
  - "First run? Set up your account" link (shown when `setup-required` returns true)
- [x] Style: centered card, matches existing dark/light theme variables, no external CSS

### 14d. Login JS flow

- [x] `showLoginScreen()`: hides main app, shows `#loginScreen`; checks `GET /api/auth/setup-required`, shows setup link if needed
- [x] `showApp()`: hides `#loginScreen`, shows main app; updates header examiner name + role badge
- [x] Login submit handler:
  1. `GET /api/auth/challenge?examiner=<name>` → `{challenge_id, nonce, salt, iterations}`
  2. `PBKDF2` via `SubtleCrypto.importKey` + `deriveKey` (SHA-256, 600000 iterations)
  3. `HMAC-SHA256` via `SubtleCrypto.sign(...)` on the nonce
  4. `POST /api/auth/login` → `{challenge_id, examiner, response: hex(hmac)}`
  5. On success: `showApp()` + `loadAll()`
  6. On error: show `#loginError` message
- [x] First-run setup flow: separate form (examiner name + password + confirm); `POST /api/auth/setup`

### 14e. Header additions

- [x] Add examiner name display span in header (updated by `showApp()`)
- [x] Add role badge: hidden for examiner, visible (styled amber) for readonly
- [x] Add "Sign out" button → `POST /api/auth/logout` → `showLoginScreen()`
- [x] "New Case" button (examiner only) → opens case init modal (Phase 14f)
- [x] "Agent Tokens" button (examiner only) → opens service-token management UI

### 14f. Case init modal

- [x] Add `<div id="newCaseModal">` with:
  - Case ID input (validated: `[a-z0-9_-]+`)
  - Title input
  - Directory input (pre-populated as `/cases/<case-id>`)
  - Create button → `POST /portal/api/case/create` (portal routes.py — NOT gateway rest.py)
  - Status/error display
- [x] Backend (`routes.py`): `POST /portal/api/case/create` (examiner auth via cookie session):
  - **Decision (Session 22):** in `routes.py`, not `rest.py`. Uses `_require_examiner_role()`,
    `must_reset` re-read, `_resolve_examiner()` — all already available in routes.py.
    Avoids circular cross-package dep (case-dashboard → sift-gateway) that `rest.py` placement
    would require.
  - Validates `case_id` pattern (`[a-z0-9][a-z0-9_-]{0,39}`)
  - **R5** `realpath` symlink guard: `Path(os.path.realpath(requested_dir))` must start with
    `Path(os.path.realpath(case_root)) + os.sep`; return 400 if not
  - **R5** Module-level `_case_create_lock = threading.Lock()` in `routes.py`; entire
    (existence check + dir create + YAML write + env update + backend restart) is inside lock
  - Creates directory + CASE.yaml + empty findings.json/timeline.json/evidence.json/
    evidence-manifest.json/evidence-ledger.jsonl/todos.json/iocs.json/approvals.jsonl/audit/evidence/
  - Initializes `evidence-manifest.json` as unsealed/empty; `evidence-ledger.jsonl` as empty
  - Updates `gateway.yaml → case.dir` with atomic write (same `_token_config_write()` pattern)
  - Sets `AGENTIR_CASE_DIR` in `os.environ` inside the lock
  - Signals backends to reload via gateway reference from portal app state
  - Returns `{ok: true, case_dir: "..."}`
- [x] Test: **R5** symlink pointing outside case_root → 400
- [x] Test: **R5** two simultaneous requests → one 200, one 409 (not both succeed or crash)
- [x] Test: no session / wrong role / must_reset → 401/403
- [x] On success: close modal, reload dashboard data

### 14g. Agent token management UI

- [x] List service token metadata without raw token values
- [x] Create token form: label, `agent_id`, optional expiry
- [x] Show created/rotated raw token exactly once
- [x] Revoke/rotate actions require examiner role and password/HMAC confirmation
- [x] Show last-used timestamp/IP if available

---

## Phase 15 — Portal Session Security Hardening

> See SIFT-MCPS-PLAN.md Phase 15 for full design spec.
> Depends on Phase 12 complete.

### 15a. JWT revocation on logout

- [x] `session_jwt.py`: add `_revoked_jtis: set[str]` module-level set
- [x] `revoke_jti(jti: str)` and `is_revoked(jti: str)` helpers
- [x] `verify_jwt()`: after validating signature, check `is_revoked(payload["jti"])` → return None if revoked
- [x] `POST /api/auth/logout`: extract `jti` from current cookie before clearing it, call `revoke_jti(jti)`
- [x] Test: login → get jti → logout → verify_jwt with old token returns None

### 15b. Sliding session refresh

- [x] In `PortalSessionMiddleware`: if valid session and `exp - now < max_age * 0.9` (token is > 10% into its life), reissue new JWT cookie on the response
- [x] Throttle: only refresh if `now - iat > 300` (don't refresh on every request, only after 5min)

### 15c. Login rate limiting

- [x] Reuse `_check_commit_lockout` / `_record_commit_failure` for login endpoint too
- [x] `GET /api/auth/challenge`: check lockout first — return 429 if locked
- [x] `POST /api/auth/login`: on HMAC mismatch, call `_record_commit_failure(examiner)`; on success `_clear_commit_failures(examiner)`
- [x] Max 5 login failures before lockout (separate from commit failures)

### 15d. Secure response headers middleware

- [x] New `SecureHeadersMiddleware(BaseHTTPMiddleware)` in `sift_gateway/server.py`:
  - Sets `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` on all responses
  - Sets `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'` on portal HTML responses
- [x] Mount as outermost middleware in `create_app()`
- [x] Test: `curl -I https://127.0.0.1:4508/portal/` → confirm headers present


---

## Phase 16 — Evidence Manifest, Evidence Ledger, and MCP Chain Gate (UPGRADE)

> Upgrades the existing `evidence_register` / `evidence_list` / `evidence_verify` registry model
> from the original case-mcp contract. The original/current tools hash and verify registered files,
> but they do not provide a sealed, append-only, portal-visible, gateway-enforced evidence chain.
> Normative design: SIFT-MCPS-PLAN.md §Evidence Manifest and Chain-of-Custody Design.
> Goal: legitimate later evidence additions are allowed, but unregistered, modified, missing, or
> ledger-mismatched evidence blocks agent operations until the examiner takes portal action.

### 16-pre. Legacy evidence behavior audit

- [ ] Document current `agentir_core.evidence_ops` behavior:
  - `register_evidence_data()` writes file path + SHA-256 to mutable `evidence.json`
  - `verify_evidence_data()` detects modified/missing registered files only when called
  - unregistered files under `evidence/` are not detected by legacy verification
  - same-path changed hash currently updates the registry, which must not become authoritative chain behavior
- [ ] Document current portal behavior:
  - `GET /api/evidence` lists only `evidence.json`
  - `POST /api/evidence/{path}/verify` verifies one registered file on demand
  - no automatic portal warning for unregistered, modified, missing, or ledger-mismatched evidence
- [ ] Document current gateway behavior:
  - aggregate `/mcp` does not verify evidence state before routing backend tool calls
  - tools can analyze files in `evidence/` even if they are unregistered or modified
- [ ] Keep the original tool names for compatibility, but redefine authority:
  - `evidence.json` = compatibility view
  - `evidence-manifest.json` + `evidence-ledger.jsonl` = authoritative evidence chain

### 16a. agentir-core evidence chain module

- [ ] Add `packages/agentir-core/src/agentir_core/evidence_chain.py`
- [ ] Data model:
  - `EvidenceFile`: relative path under `evidence/`, sha256, bytes, mtime_ns, registered_at, registered_by, source, description, status
  - `EvidenceManifest`: version, case_id, created_at, created_by, previous_manifest_hash, manifest_hash, files
  - `EvidenceLedgerEvent`: event, case_id, version, path(s), previous_manifest_hash, new_manifest_hash, approved_by, approved_at, hmac_version, hmac
- [ ] Implement chunked SHA-256 hashing for large files; never load full evidence into memory
- [ ] Implement canonical manifest hash with `manifest_hash` excluded
- [ ] Implement `scan_evidence_tree(case_dir) -> list[EvidenceFileCandidate]`
  - Walks only `case_dir/evidence/`
  - Rejects symlink escapes via `os.path.realpath`
  - Skips directories as evidence records; files only
  - Handles unreadable files as explicit scan errors
- [ ] Implement `diff_evidence_manifest(case_dir) -> EvidenceChainStatus`
  - `unregistered`: live files absent from manifest
  - `missing`: manifest files absent from disk
  - `modified`: live hash differs from sealed hash
  - `ledger_errors`: manifest hash-chain/HMAC/parse problems
  - `ok`: no issues
- [ ] Implement `seal_evidence_manifest(case_dir, examiner, additions, ignored, source_notes, derived_key)`
  - Requires explicit additions/ignored decisions from portal
  - Appends new manifest version, never silently rewrites prior state
  - Writes `evidence-manifest.json` atomically
  - Appends one or more `evidence-ledger.jsonl` events with fsync
  - chmods manifest/ledger to `0444` after writes where supported
- [ ] Implement `verify_evidence_chain(case_dir) -> EvidenceChainStatus`
  - Verifies latest manifest hash
  - Verifies ledger hash chain
  - Verifies every sealed file hash
  - Reports unregistered files as blocking issues
- [ ] Keep `evidence.json` as compatibility view until all consumers migrate
- [ ] Ensure same-path changed evidence cannot be silently re-registered as trusted; it must appear as `modified` until examiner resolution
- [ ] Tests in `packages/agentir-core/tests/test_evidence_chain.py`
  - Empty unsealed case reports `evidence_chain_unsealed`
  - Seal empty evidence set succeeds and creates version 1
  - Add file → unregistered warning before seal
  - Seal file → OK
  - Modify sealed file → modified violation
  - Delete sealed file → missing violation
  - Add later file → unregistered warning, then version increments after seal
  - Symlink escape under `evidence/` is rejected
  - Ledger event tamper produces ledger error
  - Manifest tamper produces manifest hash error
  - Large file hashing is chunked
  - Non-POSIX chmod failure returns degraded warning, not false success

### 16b. Portal evidence intake UI and API

- [ ] Add evidence-chain status banner to dashboard header:
  - Green: evidence chain verified
  - Amber: unsealed or unregistered evidence exists
  - Red: registered evidence modified/missing or ledger verification failed
- [ ] Portal must clearly show when files were manually copied into `evidence/` but are unregistered
- [ ] Add Evidence Security Chain panel:
  - Rescan evidence directory
  - Show unregistered files with size/hash/path
  - Register intended files with source/description notes
  - Mark unintended files with reason
  - Show modified/missing registered evidence separately from new additions
  - Show latest manifest version/hash and last sealed by/at
- [ ] Add portal endpoints:
  - `GET /api/evidence-chain/status`
  - `POST /api/evidence-chain/rescan`
  - `POST /api/evidence-chain/seal` with HMAC confirmation
  - `POST /api/evidence-chain/ignore` with HMAC confirmation and reason
- [ ] Write actions require:
  - Valid portal session
  - role `examiner`
  - `must_reset_password == false` re-read from disk
  - HMAC password challenge/response
- [ ] Tests:
  - Unregistered file appears in API status and UI data
  - Seal endpoint rejects readonly/agent role
  - Seal endpoint rejects `must_reset_password`
  - Seal endpoint rejects bad HMAC
  - Seal endpoint appends ledger event and clears warning
  - Modified/missing evidence cannot be auto-sealed without explicit examiner decision
  - Ignore action is audited and does not trust the file

### 16c. Gateway aggregate MCP evidence gate

- [ ] In aggregate `/mcp` `call_tool`, before routing to backend, call `verify_evidence_chain(case_dir)`
- [ ] Gate applies to agent service tokens and examiner API tool calls that invoke MCP backends
- [ ] Allowlist only remediation-safe tools if needed:
  - `case_status`
  - `evidence_chain_status` / `evidence_verify` read-only status tools
  - health/list tools that do not analyze case evidence
- [ ] On violation, do not invoke backend. Return structured MCP content:
  - `blocked: true`
  - `reason: evidence_chain_violation` or `evidence_chain_unsealed`
  - counts for unregistered/missing/modified/ledger_errors
  - portal remediation URL/path
  - message for Hermes to ask the human examiner to resolve evidence intake
- [ ] Audit every block to `audit/sift-gateway.jsonl`
  - role, token_id, agent_id/examiner, source IP, active case, requested tool, status=`blocked`, reason, issue counts
  - never log raw bearer tokens or HMAC responses
- [ ] Tests:
  - No sealed manifest → agent tool call blocked
  - Unregistered new file → agent tool call blocked
  - Modified sealed evidence → agent tool call blocked
  - Missing sealed evidence → agent tool call blocked
  - Verified chain → backend tool invoked
  - Block audit envelope written
  - Read-only evidence status tool remains available

### 16d. case-mcp evidence tools migration

- [ ] Add/read tools:
  - `evidence_chain_status`
  - `evidence_manifest_get`
  - `evidence_verify` returns evidence-chain status, not only legacy `evidence.json` hash checks
- [ ] Keep existing `evidence_register` compatible, but it must not silently update authoritative chain state for modified same-path files
- [ ] For agent/service-token callers, `evidence_register` returns a structured portal-remediation response instead of sealing evidence
- [ ] For examiner callers, either delegate to the same HMAC-confirmed seal path as the portal or return a clear "use portal evidence intake" response
- [ ] Agent role must not be able to seal, ignore, modify, or otherwise mutate evidence chain via MCP
- [ ] Tests:
  - Legacy `evidence_list` still returns registered files
  - New status includes manifest version/hash and issue counts
  - Same-path hash change is reported as modified, not auto-updated
  - Agent cannot mutate evidence chain

### 16e. Report and export integration

- [ ] `report-mcp` includes:
  - latest evidence manifest version/hash
  - evidence file count and total bytes
  - evidence-chain verification status
  - ledger mismatch warnings
- [ ] Report generation refuses or returns prominent `integrity_warning` if evidence chain is not OK
- [ ] Export bundle includes evidence manifest metadata, not raw evidence files
- [ ] Tests:
  - Verified evidence chain appears in report data
  - Modified evidence produces report integrity warning or refusal
  - Missing ledger produces report integrity warning

### 16f. OpenSearch ingest and processing provenance compatibility

- [ ] Keep OpenSearch ingest manifests in `audit/ingest-manifests/`; do not move processing manifests into `evidence/`
- [ ] Ingest tools must rely on gateway gate before processing evidence
- [ ] Preserve `input_files` and `input_sha256s` in backend audit records
- [ ] Tests:
  - OpenSearch ingest of verified evidence proceeds
  - OpenSearch ingest with evidence-chain violation is blocked at gateway before backend call
  - Ingest manifest remains under `audit/ingest-manifests/`

### 16g. Filesystem and operational hardening

- [ ] Detect filesystems that do not honor POSIX chmod (`ntfs`, `exfat`, `vfat`, `fuseblk`) and surface degraded warning in portal
- [ ] Optional admin-only hardening plan: document when `chattr +i` can be used and why it is not the default for evidence growth
- [ ] Ensure manual additions are allowed operationally but never trusted until sealed
- [ ] Tests:
  - chmod failure path returns degraded protection warning
  - Later legitimate evidence addition creates version `N+1` without invalidating prior versions

---

## Phase 11 — Integration Verification

> (Moved below new phases — run last)

- [ ] Installer readiness test passes in clean SIFT-like VM/container and is idempotent
- [ ] OpenSearch Docker is healthy and bound only to `127.0.0.1:9200`
- [ ] Enrichment/RAG assets are present and either healthy or report clear degraded mode
- [ ] Default examiner login forces password reset before case/token/commit operations
- [ ] Portal creates a full case directory and activates it through `AGENTIR_CASE_DIR`
- [ ] Case init creates `evidence/`, `evidence-manifest.json`, and `evidence-ledger.jsonl`
- [ ] Invalid case create inputs are rejected: traversal, relative paths, bad id, unwritable root, existing non-empty directory
- [ ] Backend reload after case create propagates active case to all MCP backends
- [ ] Portal shows unsealed evidence warning after new case creation until examiner seals evidence state
- [ ] Portal detects manually copied unregistered files under `evidence/`
- [ ] Examiner can register later-discovered evidence without breaking prior manifest versions
- [ ] Modified/missing registered evidence blocks agent MCP tool calls
- [ ] Unregistered evidence blocks agent MCP tool calls and returns human-remediation guidance
- [ ] Hermes profile uses only aggregate `/mcp`
- [ ] Service token can use aggregate MCP but cannot access portal APIs
- [ ] Per-backend MCP URLs are disabled in production or diagnostic opt-in only
- [ ] Gateway logs separate examiner and agent actions with token id / agent id metadata
- [ ] Raw bearer tokens and HMAC responses do not appear in logs
- [ ] Additional agent token create/revoke/rotate works from portal
- [ ] Revoked/expired service tokens fail and emit audit records
- [ ] Gateway-enriched responses keep raw backend output distinguishable from added context
- [ ] Full smoke test suite passes (see SIFT-MCPS-PLAN.md Verification Checklist)
- [ ] Portal login flow works end-to-end in browser (login → view findings → commit → logout)
- [ ] Hermes agent connects with service token → calls tools → findings appear in portal
- [ ] Case init from portal creates correct directory structure
- [ ] Role enforcement: agent token → 403 on portal API
- [ ] Session expiry: expired cookie → redirected to login screen
- [ ] Logout: old session cookie rejected after logout (revocation works)
- [ ] Report output includes evidence manifest version/hash and warns/refuses on evidence-chain mismatch

---

## Session Notes

### Session 22 (2026-05-24)

**Completed Phase 11 (Restore Windows Baseline Validation Backend):**
- Resolved all unit test failures in `packages/windows-triage-mcp/tests/test_windows_triage.py`:
  - Updated tool registration tests to retrieve list of Tool models correctly from the `ListToolsResult.tools` attribute inside `ServerResult.root`.
  - Added `cmd.exe` as a LOLBin to the mock unit test database fixture to correctly match the expected `EXPECTED_LOLBIN` verdict.
  - Adjusted registry query parameters in tests: corrected HKLM root mappings, extracted hive names, and aligned case/prefixes in mock insertions to match `RegistryDB` lookup behavior.
  - Implemented named pipe name normalization in `_check_pipe` within `server.py` to strip standard prefixes (e.g. `\pipe\`, `\\.\pipe\`), enabling Cobalt Strike and spoolss patterns to query correctly.
  - Corrected double extension case-sensitivity checking in `invoice.pdf.exe` filename tests.
  - Implemented `is_available` helper methods in `KnownGoodDB` and `ContextDB` classes.
  - Updated `_get_health` check in `server.py` to assert database file existence and check table record counts to report healthy vs degraded modes correctly.
  - Updated all baseline triage tool entry points in `server.py` to gracefully return `UNKNOWN` verdicts in degraded mode (when baseline DBs are absent/invalid).
- Verified that all unit tests across `windows-triage-mcp`, `opensearch-mcp`, and `agentir-core` pass cleanly:
  - `windows-triage-mcp` tests: 8/8 passed.
  - `opensearch-mcp` tests: 887/887 passed (with 71 skipped).
  - `agentir-core` tests: 139/139 passed.
  - Namespace verification gate passed: `vhir` namespace search returns 0 python files.

**Next task:** Proceed with Phase 13 (Separate Agent Credentials & Role-Based Access Control) as both Phase 11 and Phase 12 are fully complete.

### Session 23 (2026-05-24)

**Completed Phase 13 — Separate Agent Credentials + RBAC:**

- Confirmed 13a/13b/13c/13d were already done in prior sessions.
- Implemented Phase 13f — Portal service-token lifecycle in `case_dashboard/routes.py`:
  - `GET /api/tokens` — lists agent/readonly token metadata, never raw token values
  - `POST /api/tokens` — validates agent_id, label, role, expires_at; checks for duplicate active agent_id (409); raw token returned once; 201
  - `DELETE /api/tokens/{token_id}` — sets revoked_at; 409 on double-revoke; 403 on examiner tokens
  - `POST /api/tokens/{token_id}/rotate` — atomically revokes old + creates new; raw new token returned once; 201
  - `_token_config_write()` — atomic gateway.yaml write (mkstemp + fsync + os.replace, 0o600) + in-memory `_API_KEYS` update
  - `_GATEWAY_CONFIG_PATH` + `_GATEWAY_CONFIG_LOCK` module-level state wired via `create_dashboard_v2_app(gateway_config_path=...)`
  - `server.py::create_app()` passes `AGENTIR_GATEWAY_CONFIG` env var or `~/.agentir/gateway.yaml` to portal app
  - 28 tests in `test_token_lifecycle.py` — all 28 passing

**Verification:**
- `uv run pytest packages/agentir-core/tests/ packages/case-dashboard/tests/ packages/sift-gateway/tests/ -q --import-mode=importlib` → 259/259 passed
- `grep -rn "vhir|VHIR" packages/ --include="*.py" | grep -v "vhir\."` → 0 lines

**Next task:** Phase 14 — Dashboard Rewiring (login screen, namespace cleanup, auth flow) or Audit Invariant gap (gateway envelope on every /mcp call_tool).

### Session 24 (2026-05-24)

**Phase 14 planning — Design decision settled:**

- Read TASKS.md and SIFT-MCPS-PLAN.md; confirmed Phase 13 complete, all 105 dashboard tests and
  139 agentir-core tests passing, namespace gate clean.
- Analyzed Phase 14 scope: namespace cleanup, auth rewiring, login screen, header UX, case init
  modal, agent token management modal.
- Identified architectural ambiguity in Phase 14f (case create endpoint location) and resolved:
  - **Decision:** `POST /portal/api/case/create` lives in `routes.py` (portal package), **not**
    `rest.py` (gateway package).
  - Rationale: `PortalSessionMiddleware` cookie-session auth only applies to portal sub-app.
    Placing in `rest.py` would require importing `session_jwt.verify_jwt` from `case-dashboard`
    into `sift-gateway` — a circular cross-package dependency that must not be created.
    `routes.py` already has `_require_examiner_role()`, `must_reset` re-read, `_resolve_examiner()`,
    and the `_token_config_write()` atomic YAML write pattern used by token lifecycle.
  - The `_case_create_lock = threading.Lock()` (R5) and `os.path.realpath` symlink guard (R5) go
    into `routes.py`.
- Updated SIFT-MCPS-PLAN.md §Phase 14e and TASKS.md §14f to reflect this decision.
- Did **not** begin implementation; next session starts from Phase 14a (namespace cleanup).

**State at end of session:**
- All tests still green (no code changes made).
- Documentation up to date.

**Next task:** Phase 14 — start implementation from 14a (namespace/branding sweep of index.html +
icon rename), then 14b (auth rewiring), 14c/14d (login screen + JS), 14e (header), 14f
(case create backend + modal), 14g (agent token management UI).

### Session 21 (2026-05-24)

**Critical Phase 11 source correction:**
- User pointed to the actual original source path:
  `/home/yk/AI/SIFTHACK/sift-mcp/packages/windows-triage/`.
- Confirmed the original package exists there and is substantially more complete than the temporary
  JSON-backed scaffold added in Session 20.
- Original runtime is SQLite-backed:
  - `known_good.db` contains file/path/hash baselines plus service/task/autorun baselines.
  - `context.db` contains LOLBAS, LOLDrivers, HijackLibs, process expectations, suspicious
    filename/pipe patterns, protected process names, and Windows named pipes.
  - `known_good_registry.db` is optional and supports full registry validation for
    `check_registry`.
- Original DB creation/import workflow:
  - `scripts/init_databases.py` initializes `known_good.db` and `context.db`.
  - `scripts/import_all.py` imports VanillaWindowsReference, VanillaWindowsRegistryHives, LOLBAS,
    LOLDrivers, and HijackLibs.
  - `scripts/update_sources.py` incrementally updates DBs from upstream git sources.
  - `scripts/build-release.sh` creates `.zst` release assets and checksums.
- Original install/runtime workflow:
  - `windows_triage.scripts.download_databases` downloads `known_good.db.zst`, `context.db.zst`,
    and `checksums.sha256` from `AppliedIR/sift-mcp` `triage-db-*` GitHub releases.
  - It verifies checksums, decompresses with `zstandard`, and validates minimum row counts before
    declaring DB install success.
- Original MCP exposure:
  - Uses low-level MCP `Server("windows-triage")`, manual `list_tools`, and a single `call_tool`
    dispatcher with validation, audit wrapping, caveats, and interpretation constraints.
  - FastMCP remains preferred for this repo, but exact behavior/tool contract is more important
    than forcing a framework migration during the port.

**Documentation updates:**
- `AGENTS.md`, `SIFT-MCPS-PLAN.md`, and `TASKS.md` now state that the Session 20 JSON-backed
  implementation is an interim scaffold only.
- Phase 11 now explicitly requires porting the original SQLite-backed implementation and release
  downloader before acceptance.

**Next implementation direction:**
- Replace or upgrade `packages/windows-triage-mcp` using the original source from
  `/home/yk/AI/SIFTHACK/sift-mcp/packages/windows-triage/`.
- Preserve the overall `sift-mcps` design changes: `agentir` namespace, installer-first runtime,
  gateway aggregate `/mcp`, no `wintools-mcp`, no Windows host execution, no per-backend Hermes
  URLs, and fail/degrade clearly when DB assets are missing.
- Do not continue Phase 13/14/15 until Phase 11 is real-code parity with the original backend,
  integrated, and tested.

### Session 20 (2026-05-24)

**Completed / partially completed Phase 11 implementation:**
- Audited local reference material for `windows-triage-mcp`. No original package source exists in
  the local Valhuntir checkout; reconstruction is based on the documented 13-tool contract and
  current `opensearch_mcp.triage_remote` expectations.
- Added `packages/windows-triage-mcp` as a FastMCP stdio backend with all 13 required tools:
  `check_file`, `check_process_tree`, `check_service`, `check_scheduled_task`, `check_autorun`,
  `check_registry`, `check_hash`, `analyze_filename`, `check_lolbin`, `check_hijackable_dll`,
  `check_pipe`, `get_db_stats`, `get_health`.
- Added JSON baseline DB loader with default root `/var/lib/agentir/windows-triage` and
  `AGENTIR_WINDOWS_TRIAGE_DB_DIR` override. Missing DB returns `status=degraded` / `UNKNOWN`;
  it never returns trusted `EXPECTED` verdicts without local records.
- Added workspace/root dependency wiring and `windows-triage-mcp` backend config in
  `configs/gateway.yaml.template`; installer now creates the DB directory and renders the env var.
- Updated case-mcp capability reporting to separate `windows_triage` from unsupported `wintools`.
- Updated gateway instructions to remove `wintools-mcp` from the supported/optional backend list.
- Updated OpenSearch triage enrichment so windows-triage backend failures or missing baseline DB
  return degraded artifact results instead of silently reporting complete zero-enrichment.
- Added tests for the 13-tool registration/behavior, missing DB behavior, gateway tool listing, and
  OpenSearch degraded-mode handling.

**Verification:**
- `uv sync --all-packages` passed.
- `uv run pytest packages/windows-triage-mcp/tests/ -v --tb=short` → 8 passed.
- `uv run pytest packages/opensearch-mcp/tests/test_triage_remote.py -v --tb=short` → 11 passed.
- `uv run pytest packages/sift-gateway/tests/test_windows_triage_backend.py -v --tb=short` → 1 passed.
- `uv run pytest packages/opensearch-mcp/tests/ -v --tb=short` → 887 passed, 71 skipped.
- `uv run pytest packages/agentir-core/tests/ -v --tb=short` → 139 passed.
- `grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."` → 0 lines.
- `uv run python -c "from windows_triage_mcp.server import WindowsTriageServer; from case_mcp.server import create_server; print('OK')"` → OK.
- `uv run pytest packages/case-mcp/tests/ -v --tb=short` could not run because
  `packages/case-mcp/tests/` does not exist.

**Still open in Phase 11:**
- Real baseline asset download/extract workflow is not implemented; installer currently provisions
  the target directory and backend fails degraded until JSON assets are present.
- Disk footprint and air-gapped baseline asset documentation still needs to be written.
- Add a fuller OpenSearch success fixture that exercises EXPECTED/SUSPICIOUS/UNKNOWN stamping
  through the enrichment path, not only lower-level stamping and backend tool tests.
- Continue stale `wintools` cleanup where it conflicts with the supported SIFT-local contract.

### Session 19 (2026-05-24)

**Evidence-chain clarification:**
- Reviewed the original/current `case-mcp` evidence contract and current
  `agentir_core.evidence_ops`.
- Confirmed there is existing evidence tracking: `evidence_register` stores path + SHA-256 in
  `evidence.json`, `evidence_list` reads the registry, and `evidence_verify` re-hashes registered
  files to report OK/MODIFIED/MISSING.
- Clarified the gap: the legacy model does not detect unregistered files under `evidence/`, does
  not automatically warn the portal, does not gate agent/backend MCP calls, is not versioned or
  HMAC/hash-chain sealed, and current same-path re-registration can update a changed hash.
- Updated `SIFT-MCPS-PLAN.md`, `TASKS.md`, and `AGENTS.md` so Phase 16 is an upgrade of existing
  evidence tools, not a claim that evidence verification was absent.
- Added `16-pre` audit tasks and explicit requirements that `evidence.json` becomes a compatibility
  view while `evidence-manifest.json` + `evidence-ledger.jsonl` become authoritative.

### Session 18 (2026-05-24)

**Planning correction and verification:**
- Confirmed `Reference MCP Toolsfrom original Valhuntir Documentation.md` distinguishes
  `windows-triage-mcp` from `wintools-mcp`.
- `windows-triage-mcp` is local/offline Windows baseline validation and OpenSearch enrichment
  support: 13 tools (`check_file`, `check_process_tree`, `check_service`, `check_scheduled_task`,
  `check_autorun`, `check_registry`, `check_hash`, `analyze_filename`, `check_lolbin`,
  `check_hijackable_dll`, `check_pipe`, `get_db_stats`, `get_health`).
- `wintools-mcp` is the separate Windows host execution backend and remains out of scope.
- Current workspace has no `packages/windows-triage-mcp`; root workspace deps include only
  forensic-mcp, case-mcp, sift-mcp, report-mcp, opensearch-mcp, rag-mcp, and opencti-mcp.
- Current gateway template includes forensic-mcp, case-mcp, sift-mcp, report-mcp,
  forensic-rag-mcp, opensearch-mcp, and opencti-mcp, but not windows-triage-mcp.
- Current migrated FastMCP tool counts verified for local packages:
  forensic-mcp 9 core tools, case-mcp 15, sift-mcp 5, report-mcp 6. Forensic-mcp discipline
  tools/resources are present in code but not counted in the default FastMCP tool manager output.
- Current opensearch-mcp still exposes `idx_enrich_triage` and `triage_remote.py` gateway calls,
  so the restoration must verify those calls against the new aggregate gateway/backend contract.
- Found stale copied behavior needing follow-up: `case-mcp` still has `_wintools_configured()`
  wording that says Windows-triage support was dropped, and `_resolve_case_dir()` still checks
  `~/.agentir/active_case` before env var despite the portal-first runtime contract.

**Docs updated:**
- `AGENTS.md`: R7 corrected to retain `windows-triage-mcp` and drop only `wintools-mcp`;
  package summary and priorities updated.
- `SIFT-MCPS-PLAN.md`: "not doing" section corrected; architecture and Hermes tool table include
  `windows-triage-mcp`; new Phase 11 defines restoration scope and acceptance.
- `TASKS.md`: workflow contract, Phase 10c, and new Phase 11 task list added.

**Direction:**
- Next implementation should start at Phase 11 before Phase 13 if the user wants parity with the
  original backend inventory before continuing auth/RBAC work.

### Session 17 (2026-05-24)

**Completed:**
- Phase 12d COMPLETE — 7 auth endpoints implemented in `routes.py`:
  - `GET /api/auth/setup-required`, `POST /api/auth/setup` (first-run account creation)
  - `GET /api/auth/challenge` — R3 anti-enumeration (fake challenges for unknown examiners), R6 pool cap (200 total, 5 per examiner)
  - `POST /api/auth/login` — R8 domain-separated auth key (`derive_auth_key`), R2 `login:{examiner}` lockout namespace, HttpOnly Secure SameSite=Strict session cookie
  - `POST /api/auth/reset-password` — requires session + login challenge + new password
  - `POST /api/auth/logout` — Max-Age=0 cookie clear
  - `GET /api/auth/me` — R1 re-reads must_reset from disk
  - 36 tests in `test_auth_endpoints.py`; lockout file isolation via `Path.home()` redirect
- Phase 12e COMPLETE — existing route guards updated:
  - `_resolve_examiner()` — removed env var fallback (R9)
  - `post_delta`, `delete_delta_item`, `verify_evidence` — 401 if no auth, 403 if must_reset (R1)
  - `get_commit_challenge`, `post_commit` — added must_reset check (R1)
- Phase 12f COMPLETE — gateway R4 portal block:
  - `AuthMiddleware.dispatch()` blocks agent tokens on `/portal/api/` paths (403)
  - Portal paths bypass gateway auth — `PortalSessionMiddleware` handles own auth
  - `packages/sift-gateway/tests/` created; 8 tests in `test_portal_agent_block.py`

**Verification:**
- `uv run pytest packages/agentir-core/tests/ -q` → 139/139 passed
- `uv run pytest packages/case-dashboard/tests/ -q` → 75/75 passed (includes 36 new 12d tests + 8 12c tests + others)
- `uv run pytest packages/sift-gateway/tests/ -q` → 8/8 passed
- `grep -rn "vhir|VHIR" packages/ --include="*.py" | grep -v "vhir\."` → 0 lines

**Next session starts at Phase 13** — separate agent credentials + RBAC:
- 13a: `token_gen.py` — generate_service_token() and fix generate_gateway_token()
- 13b: Role enforcement — readonly→403 on MCP writes; (R4 agent→portal already done in 12f)
- 13c: Portal route RBAC guards (`_require_examiner_role` helper)
- 13f: Portal service-token lifecycle endpoints

### Session 16 (2026-05-24)

**Planning update only:**
- Created new Phase 16 specification for evidence manifest, evidence ledger, portal evidence intake,
  and gateway MCP chain-of-custody gate.
- Updated `AGENTS.md`, `SIFT-MCPS-PLAN.md`, and `TASKS.md` to require:
  - Manual evidence copied into `evidence/` is detected but not trusted automatically.
  - Portal shows clear warnings for unregistered, modified, missing, or ledger-mismatched evidence.
  - Examiner can append legitimate later-discovered evidence through an authenticated/HMAC-confirmed flow.
  - Agent MCP calls verify evidence chain before backend routing and fail closed with structured
    human-remediation guidance when the evidence chain is not OK.
- No code implementation yet.

### Session 15 (2026-05-24)

**Completed:**
- Phase 12-pre COMPLETE — R8 domain-separated HMAC sub-keys landed.
  - `derive_auth_key()` and `derive_ledger_key()` added to `agentir_core/approval_auth.py`.
  - `verification.py::derive_hmac_key()` now delegates to `derive_ledger_key()` internally (lazy import, no circular dependency). The raw PBKDF2 output is no longer used directly as a HMAC key anywhere.
  - 14 new plan-aligned tests added; existing obsolete test replaced.
  - 139/139 passing.
- Clarified that existing tests are NOT the driver — plan and tasks are. Tests must be rewritten to match plan requirements when they diverge.

**Phase 12c complete.** Next session starts at **Phase 12d** — auth endpoints (`/api/auth/setup-required`, `/api/auth/challenge`, `/api/auth/login`, etc.) in `routes.py`.

---

### Session 14 (2026-05-24)

**Completed:**
- Full threat model pass against the portal auth design before any Phase 12 code was written.
- Identified 9 security guards (R1–R9) relevant to the IR pipeline attack surface.
- Updated AGENTS.md, SIFT-MCPS-PLAN.md, and TASKS.md to embed guards as implementation requirements — not post-hoc patches.

**Key findings from threat model:**
- R1: `must_reset_password` requires disk re-read on every write operation — JWT alone is insufficient as a gate.
- R2: Login and commit lockout counters must be namespaced separately to prevent cross-interference.
- R3: Challenge endpoint must return fake challenges for unknown examiners to prevent user enumeration.
- R4: Agent→portal block cannot be deferred to Phase 13 — it ships with Phase 12 as Phase 12f.
- R5: Case create endpoint needs `realpath` symlink guard and a serialization lock.
- R6: Login challenge pool needs a size cap (200 entries, 5 per examiner) to bound memory DoS.
- R7: Enrichment must be appended as `_agentir_context` metadata — never interpolated into tool result text.
- R8: Stored PBKDF2 hash must be domain-separated into `auth_key` vs. `ledger_key` before any production case data exists.
- R9: All request.state.examiner access must use `getattr` with default None.
- XSS confirmed NOT a risk — `escapeHtml()` is applied consistently across all 47 data-driven `innerHTML` assignments.

**Documentation changes:**
- AGENTS.md: current state updated to Session 14; Phase 7/8/9 marked done; R1–R9 added as Pre-Implementation Security Requirements; package table updated.
- SIFT-MCPS-PLAN.md: `#### Security Requirements for Phase 12 Implementation` section added with binding behavioral specs for R1–R4, R6, R8, R9. R4 co-ship note added to Phase 13 role enforcement section. R5 symlink+lock spec added to Phase 14e. R7 enrichment isolation strengthened in Phase 13 audit section.
- TASKS.md: Phase 12-pre block added for R8 agentir-core key derivation. Phase 12d/12e/12f updated with per-guard checklist items. Phase 13b updated to note R4 is already handled. Phase 14f updated with R5 guards and tests.

**Next session starts at Phase 12-pre** — `derive_auth_key()` / `derive_ledger_key()` in agentir-core, then Phase 12 backend.

---

### Session 12 (2026-05-24)

**Completed:**
- Implemented Phase 7 installer foundation in `install.sh`.
  - Supports `-y/--yes`, `--skip-docker`, and `--no-start`.
  - Checks Ubuntu target version and Python >= 3.10.
  - Installs/uses `uv`, runs `uv sync --all-packages`, creates agentir state directories, creates default case root, prepares enrichment pointers, generates TLS, creates default examiner password with `must_reset_password: true`, writes one-time handoff material, renders gateway config, installs user systemd service, starts/polls services when enabled.
  - Preserves existing TLS, password, gateway config, OpenSearch config, and service file on rerun.
- Added `.dockerignore` and expanded `.gitignore` with Python/build/cache/env patterns.
- Completed Phase 9 config templates:
  - `configs/gateway.yaml.template`
  - `configs/hermes-forensics-profile.yaml`
  - `configs/systemd/sift-gateway.service`
- Confirmed existing Phase 8 `docker-compose.yml` matches the planned OpenSearch 2.18.0 localhost-only single-node deployment.

**Verification:**
- `.specify/scripts/bash/check-prerequisites.sh --json --require-tasks --include-tasks` failed because current branch is `main`, not a Spec Kit feature branch; continued from root `TASKS.md`.
- `bash -n install.sh` → clean
- `./install.sh --help` → works
- `docker compose -f docker-compose.yml config` → valid, binds `127.0.0.1:9200`
- Rendered `configs/gateway.yaml.template` with sample values and parsed with PyYAML → OK, 2 API keys, empty `case.dir`, aggregate backend config present
- Isolated temp install run:
  - `AGENTIR_HOME=$tmp/home AGENTIR_STATE_DIR=$tmp/state AGENTIR_CASE_ROOT=$tmp/cases SYSTEMD_USER_DIR=$tmp/systemd MATERIALS_FILE=$tmp/state/tokens/handoff.txt ./install.sh -y --skip-docker --no-start`
  - Result: generated gateway config, OpenSearch client config, TLS certs/keys, examiner password JSON, systemd service, and handoff file under temp paths.

**Still needs live validation:**
- Run installer on clean Ubuntu/SIFT VM or container.
- Run live `docker compose up -d && docker compose ps` and confirm OpenSearch healthy.
- Run full gateway start with real user systemd and verify `https://127.0.0.1:4508/health`.

### Session 13 (2026-05-24)

**Completed:**
- Cross-checked the new installer against original setup scripts:
  - `/home/yk/AI/SIFTHACK/sift-mcp/quickstart.sh`
  - `/home/yk/AI/SIFTHACK/sift-mcp/setup-sift.sh`
  - `/home/yk/AI/SIFTHACK/sift-mcp/quickstart-lite.sh`
  - `/home/yk/AI/SIFTHACK/opensearch-mcp/scripts/setup-opensearch.sh`
- Confirmed old `bwrap`/AppArmor/socat setup was for Claude Code direct-Bash sandboxing. It is intentionally not ported because sift-mcps uses remote Hermes → gateway `/mcp` → `sift-mcp` controlled execution instead of granting direct shell access.
- Ported OpenSearch setup details that still apply to the revamp:
  - `docker-compose.yml` now names the container `agentir-opensearch`.
  - Added `/var/lib/agentir/snapshots` bind mount and `path.repo=/usr/share/opensearch/snapshots`.
  - Installer creates the snapshots directory with container-compatible ownership.
  - Installer applies `cluster.max_shards_per_node=3000`.
  - Installer runs an OpenSearch smoke index/search/delete check.
  - Installer configures `agentir-geoip` and applies it to existing IP-bearing case index patterns where available.
- Fixed opensearch-mcp gateway config contract:
  - `configs/gateway.yaml.template` now sets `OPENSEARCH_CONFIG=${AGENTIR_HOME}/opensearch.yaml` for the backend.
  - `packages/opensearch-mcp/src/opensearch_mcp/client.py` now honors `OPENSEARCH_CONFIG` before falling back to `~/.agentir/opensearch.yaml`.
  - Added a regression test for the `OPENSEARCH_CONFIG` path.

**Verification:**
- `bash -n install.sh` → clean
- `docker compose -f docker-compose.yml config` → valid, includes localhost bind, snapshot bind, `path.repo`, and `agentir-opensearch`
- `uv run pytest tests/test_edge_cases.py::TestMissingConnection::test_get_client_honors_opensearch_config_env -q` in `packages/opensearch-mcp` → passed
- Rendered `configs/gateway.yaml.template` with sample values and confirmed `opensearch-mcp` env includes `OPENSEARCH_CONFIG`
- Isolated temp installer run with `--skip-docker --no-start` still succeeds and renders `OPENSEARCH_CONFIG` correctly.

### Session 11 (2026-05-24)

**Completed:**
- Created the project constitution at `.specify/memory/constitution.md` from the placeholder template.
- Ratified constitution v1.0.0 around the settled installer-first, portal-first, aggregate `/mcp`,
  chain-of-custody, agentir-core, and verification-gate requirements.
- Updated Spec Kit templates so future plans/specs/tasks include constitution-aligned checks:
  - `.specify/templates/plan-template.md`
  - `.specify/templates/spec-template.md`
  - `.specify/templates/tasks-template.md`
- Ran mandatory `before_constitution` Git initialization hook; it skipped because the repository is
  already initialized.

**Verification:**
- Checked constitution for placeholder tokens and deferred TODOs — none remain.
- Checked version/date line matches the Sync Impact Report: `1.0.0`, ratified/amended `2026-05-24`.
- Reviewed `.specify/templates/commands/*.md` path — directory is not present in this checkout.

**Next implementation work:**
- Continue Phase 7 installer script if Phase 4e remains deferred.

### Session 10 (2026-05-24)

**Completed:**
- Phase 6 COMPLETE — `packages/sift-mcp/src/sift_mcp/security.py` now rejects null bytes, rejects arguments longer than 4096 chars, and NFC-normalizes non-canonical Unicode before existing flag/metacharacter checks.
- Added focused tests in `packages/sift-mcp/tests/test_security_sanitize.py` for null-byte rejection, long-argument rejection, and non-NFC normalization/logging.
- Phase 4e research COMPLETE — the installed MCP SDK has `ServerSession.send_tool_list_changed()`, but `StreamableHTTPSessionManager` does not expose active `ServerSession` lifecycle hooks.
  - `mcp==1.27.1` is current; `uv pip install --upgrade mcp --dry-run` found no newer MCP SDK.
- Gateway audit review: current tool calls are audited, but final gateway-principal metadata is only partial today. Stdio backends write backend audit logs; gateway proxy audit is centralized for HTTP backends. Added Audit Invariant / Regression Guard above.

**Verification:**
- `uv sync --all-packages` → clean
- `uv run pytest packages/sift-mcp/tests/test_security_sanitize.py -v --tb=short` → 3/3 passed
- `uv run pytest packages/agentir-core/tests/ -v --tb=short -q` → 125/125 passed
- `grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."` → 0 lines
- `uv run python -c "from case_dashboard.routes import create_dashboard_app; print('OK')"` → OK
- `uv run python -c "from case_mcp.server import create_server; print('OK')"` → OK
- `uv run ruff check packages/sift-mcp/src/sift_mcp/security.py packages/sift-mcp/tests/test_security_sanitize.py` → clean

**Next implementation work:**
- Phase 4e implementation is awaiting decision: defer until MCP SDK exposes session hooks, or add a local session-tracking `Server` wrapper/subclass.
- If Phase 4e stays deferred, continue to Phase 7 installer script while preserving the audit invariant.

### Session 9 (2026-05-24)

**Completed:**
- Phase 5 COMPLETE — `packages/forensic-rag-mcp/src/rag_mcp/server.py` migrated from low-level MCP SDK to FastMCP.
  - Exposes module-level `mcp = FastMCP("forensic-rag-mcp", instructions=_INSTRUCTIONS)`.
  - Registered `search_knowledge`, `list_knowledge_sources`, and `get_knowledge_stats` with `annotations={"readOnlyHint": True}`.
  - Preserved lazy ChromaDB/RAG index use, model allowlist behavior in `RAGIndex`, input length limits, audit envelope, examiner attribution, and error response shape.
  - Added `rag-mcp --help` CLI output that terminates and lists tools for the documented smoke test.

**Verification:**
- `uv sync --all-packages` → clean
- `uv run rag-mcp --help` → lists all three tools
- `uv run python -c "from rag_mcp.server import mcp; print('OK')"` → OK
- `uv run pytest packages/agentir-core/tests/ -v --tb=short` → 125/125 passed
- `grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."` → 0 lines
- `uv run python -c "from case_dashboard.routes import create_dashboard_app; print('OK')"` → OK
- `uv run python -c "from case_mcp.server import create_server; print('OK')"` → OK

**Next implementation work:**
- Phase 4e remains open for `notifications/tools/list_changed` SDK lifecycle research.
- If Phase 4e stays deferred, continue to Phase 6 sift-mcp argument sanitization hardening.

### Session 8 (2026-05-24)

**Completed:**
- Final required workflow clarified across `AGENTS.md`, `SIFT-MCPS-PLAN.md`, and `TASKS.md`:
  - One installer prepares the SIFT VM: packages, gateway, portal UI, OpenSearch Docker, enrichment/RAG assets, TLS, systemd, default examiner, first Hermes service token.
  - Examiner/operator starts from the portal, resets default password on first login, and creates cases through the portal.
  - Portal case creation is now the primary active-case workflow; manual `gateway.yaml` edits are administrator fallback only.
  - Hermes connects only to the aggregate gateway MCP endpoint `/mcp` with an `agentir_svc_*` token.
  - Gateway owns auth, role separation, request audit, contextual enrichment, and agent/examiner identity attribution.
  - Portal must support examiner-only service-token creation, revocation, and rotation for additional agents.
- Added required acceptance coverage for installer readiness, portal auth/reset, portal case creation, aggregate MCP routing, token lifecycle, enrichment integrity, logging separation, and chain of custody.
- Reframed Valhuntir as a read-only reference source for workflow ideas; sift-mcps remains a cherry-picked, decoupled, hardened, portable implementation.

**Next implementation work remains Phase 5** unless you decide to prioritize installer/portal workflow phases first.

### Session 7 (2026-05-24)

**Completed:**
- Documentation tracking model clarified:
  - `SIFT-MCPS-PLAN.md` is now explicitly the normative spec and acceptance criteria source.
  - `TASKS.md` is now explicitly the execution checklist, current next-step tracker, and session ledger.
  - `AGENTS.md` is now explicitly the agent operating brief and current-state pointer.
- Removed stale current-state drift from `AGENTS.md`:
  - Phase 2b, Phase 3, and Phase 4a-4d now show as complete.
  - Phase 5 is the next implementation task.
  - Phase 4e remains open for SDK lifecycle research.
- Fixed spec/task contradictions:
  - `~/.agentir/active_case` is not part of the runtime contract.
  - Token entropy wording corrected to 192-bit for 48 hex chars.
  - Install/config specs now generate both `agentir_gw_*` and `agentir_svc_*` tokens plus `portal.session_secret`.
  - Hermes config examples now use the service token.
  - Case creation endpoint is consistently `POST /api/v1/case/create`.
  - Duplicate Phase 11 integration section removed; final integration verification remains after Phase 15.
  - Phase 13e token expiry marked satisfied by Phase 4a.

**Next session starts at Phase 5** — forensic-rag FastMCP migration, unless Phase 4e SDK research is prioritized first.

### Session 6 (2026-05-24)

**Completed:**
- Phase 4a-4d COMPLETE — gateway security improvements, all 125 agentir-core tests still passing
  - `verify_api_key()` shared helper added to `auth.py` — timing-safe lookup + ISO `expires_at` checking
  - `AuthMiddleware.dispatch` and `MCPAuthASGIApp.__call__` both use `verify_api_key()` — no more duplicated timing-safe loops
  - `ExaminerRateLimiter` singleton added to `rate_limit.py` — post-auth quota enforcement per examiner identity
  - `MCPAuthASGIApp` accepts `examiner_calls_per_minute` (default 120) and `allowed_origins`; `server.py::create_app()` computes and passes both
  - Origin header validation in `MCPAuthASGIApp.__call__` — browser CSRF blocked; Hermes (no Origin) passes through
  - `_extract_examiner(server: Server) -> str | None` helper eliminates two duplicate try/except blocks
  - Removed duplicate `_MAX_TOKEN_LENGTH` and `import hmac` from `mcp_endpoint.py`

**Skipped (research needed):**
- Phase 4e `notifications/tools/list_changed` — requires SDK research into `StreamableHTTPSessionManager` session lifecycle hooks. Left as `[ ]` for a dedicated session.

**Next session starts at Phase 5** — forensic-rag FastMCP migration (single server.py file, straightforward decorator-style rewrite).

### Session 1 (2026-05-23)

**Completed:**
- Phase 1 fully done: workspace scaffold, all packages copied, agentir-core extracted
- case-mcp and report-mcp updated to use agentir-core (imports + env vars + wintools removal)
- `uv sync` resolves 190 packages cleanly

**Key discoveries:**
1. `vhir_cli` namespace still in Valhuntir source — not an issue for sift-mcps (we use agentir_core)
2. case-mcp imports MORE from vhir_cli than originally noted: also audit_cmd, evidence, join (wintools), backup, main.py functions — all resolved via agentir-core
3. report-mcp also imported from vhir_cli — fixed
4. forensic-rag package entry point is `rag-mcp` (not `forensic-rag-mcp`) — root pyproject uses `rag-mcp`
5. case-dashboard is optional import in gateway server.py — kept as separate package
6. Gateway already has `rate_limit.py` (per-IP) and `auth.py` — Phase 4 work modifies existing code
7. sift-gateway has no `app.py` — ASGI app assembled in `server.py::Gateway.create_app()`
8. `_set_case_wintools_permissions` was called in case-mcp — replaced with no-op in agentir-core

**Open questions resolved in Session 2:**
- `_resolve_case_dir` in case-mcp/server.py — keep inline for now (low priority); tracked in Phase 10
- `_create_backup_data` module-level import in case-mcp — acceptable, lazy import was just style

### Session 5 (2026-05-24)

**Completed:**
- Phase 3 FULLY COMPLETE — all 4 sub-tasks done, 125/125 tests still passing
  - `_PortalHTTPSGuard` ASGI middleware added to `sift_gateway/server.py` — returns 400 for portal paths over plain HTTP when TLS configured
  - Nonce IP binding added: `_challenges` dict now stores `bound_ip`; `post_commit()` returns 403 on IP mismatch
  - Challenge TTL reduced from 60s → 30s
  - `CORSMiddleware` added to `create_app()` — restricts origins to gateway's own URL + localhost:4508
  - Global `@app.exception_handler(Exception)` added — logs full traceback server-side, returns generic 500 to client
  - `str(e)` leaks removed from `post_commit()` and `get_case()` in routes.py

**Next session must start with Phase 4** — gateway improvements:
  - 4a: `verify_api_key()` shared helper in auth.py + token expiry enforcement
  - 4b: Per-examiner rate limiting in rate_limit.py + mcp_endpoint.py
  - 4c: Origin header validation in mcp_endpoint.py
  - 4d: `_extract_examiner()` helper deduplication in mcp_endpoint.py

### Session 4 (2026-05-24)

**Completed:**
- Phase 2b FULLY COMPLETE — all 4 tasks done, verification gate passed
  - `AuthError` and `LockoutError` exception classes added to `approval_auth.py`
  - All 10 `sys.exit(1)` calls replaced with exceptions (`AuthError`/`LockoutError`/`PermissionError`)
  - `import subprocess` removed; `import getpass as getpass_mod` removed (unused after 2b-3)
  - `_PASSWORDS_DIR`, `_LOCKOUT_FILE` env-overridable in `approval_auth.py`
  - `VERIFICATION_DIR` env-overridable in `verification.py`
  - `_PASSWORDS_DIR` env-overridable in `backup_ops.py`
  - Tests updated: all `pytest.raises(SystemExit)` → `pytest.raises(AuthError/LockoutError/PermissionError)`
  - 125/125 tests passing

**Next session must start with Phase 3** — portal security hardening (HTTPS enforcement, nonce IP binding, CORS, error sanitization). All 4 sub-tasks in Phase 3 are small targeted edits to `server.py` and `routes.py`.

### Session 3 (2026-05-24)

**Completed:**
- Phase 0 FULLY COMPLETE — all 6 sub-tasks done, verification gate passed
- Namespace sweep: ~50 files updated across all packages (Python, YAML, JSON, shell, docker, markdown)
  - opensearch-mcp: paths.py renamed `vhir_home/vhir_dir` → `agentir_home/agentir_dir`; all 10+ callers and all tests updated; OpenSearch template names `vhir-*` → `agentir-*`
  - sift-common: audit.py, __init__.py, oplog.py — all env vars, paths, docs updated
  - forensic-mcp, case-mcp, report-mcp, opencti-mcp: all string/comment/docstring references
  - scripts/setup-opensearch.sh, docker-compose files, README — fully updated
- Fixed bug introduced by sed in server.py: `agentir_dir as _vhir_dir` alias + stale `_agentir_dir()` call
- agentir-core tests: 125/125 pass
- Assessed agentir-core architecture: single-library approach is correct for this use case
  - One dependency (PyYAML), stdlib crypto, 125 tests, clean internal dependency graph
  - Identified 4 hardening issues (Phase 2b): sys.exit, hardcoded paths, sudo call, duplicate identity

**Key architectural decision (Session 3):**
Single agentir-core library is right — not worth splitting into sub-packages. The security primitives
(PBKDF2, HMAC, atomic writes) belong together and tested as a unit. The only structural issue is
`gateway_cfg.py` which will move to sift-gateway when Phase 12 (portal auth) is implemented.

**Next session must start with Phase 2b** — it's small (4 targeted file edits), prerequisite for
Phase 12 (portal auth needs AuthError exceptions, not sys.exit).

### Session 2 (2026-05-23)

**Completed:**
- Full grill/security review of all critical files
- Documentation update (AGENTS.md, SIFT-MCPS-PLAN.md, TASKS.md)

**Critical findings from grill:**

| ID | Severity | File | Issue |
|----|----------|------|-------|
| B1 | 🔴 Critical | `case-dashboard/routes.py:235,247,264,289,314,398` | Wrong paths: `/var/lib/vhir/` — portal auth completely broken |
| B2 | 🔴 Critical | `sift-gateway/server.py:305` + `rest.py:520,562,etc` | `~/.vhir/` throughout gateway — wrong config paths |
| B3 | 🔴 Critical | `case-dashboard/routes.py` | Duplicates agentir-core (hash, HMAC, write) with wrong paths |
| B4 | 🔴 Critical | `sift-gateway/server.py:302-309` | `_get_active_case()` reads `~/.vhir/active_case` — wrong |
| S1 | 🟠 Security | `mcp_endpoint.py` | No Origin header check → CSRF possible |
| S2 | 🟠 Security | `server.py::create_app()` | No CORS restriction |
| S3 | 🟠 Security | `server.py::create_app()` | No HTTPS enforcement |
| S4 | 🟠 Security | `routes.py:1242-1246` | No IP binding on nonce; TTL too long (60s) |
| S5 | 🟠 Security | `auth.py`, `mcp_endpoint.py` | `expires_at` field not checked |
| S6 | 🟠 Security | `mcp_endpoint.py:114` | Rate limit pre-auth, keyed by IP not examiner |
| S7 | 🟠 Security | `routes.py:1328` | `str(e)` leaks exception detail to client |
| S8 | 🟡 Security | `sift-mcp/security.py` | Missing null-byte check, length limit, NFC normalization |
| S9 | 🟡 Security | `routes.py:1362` | CSP `unsafe-inline` without nonces |
| A1 | 🔵 Arch | `routes.py` | 1433 lines; `_apply_delta` is 369 lines — untestable |
| A2 | 🔵 Arch | `auth.py` + `mcp_endpoint.py` | Auth logic duplicated |
| A3 | 🔵 Arch | `forensic-rag-mcp/server.py` | Still uses low-level MCP SDK (only backend that does) |
| A4 | 🔵 Arch | `sift-gateway/server.py` | Dead `wintools-mcp` conditional |
| A5 | 🔵 Arch | `opensearch-mcp/vhir_plugin.py` | Old filename |
| M1 | ⚫ Missing | multiple | All Phase 3-9 items not started |

**Design decision made:** Case directory via `gateway.yaml → case.dir` → `AGENTIR_CASE_DIR` env var.
No CLI activation. No `active_case` file in gateway flow. See Phase 0b in plan.

**Next session must start with Phase 0** — nothing else is safe to work on until the namespace
sweep and duplication fixes are complete. The portal is currently non-functional.

**Remaining question from Session 1 (low priority, Phase 10):**
- Should `case-mcp/server.py`'s inline `_resolve_case_dir` be replaced with `agentir_core.case_io.get_case_dir`?
  Currently inline in original too. Safe as-is since it reads `AGENTIR_CASE_DIR` after Phase 0a fix.
