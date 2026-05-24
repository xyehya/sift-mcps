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

Functional, resilience, and security tests must prove this workflow. No shortcuts or one-off workarounds.

---

## ⚠️ Start Here Every Session

1. Read `TASKS.md` (this file) — understand current state
2. Read `AGENTS.md` — project rules and design decisions
3. Read `SIFT-MCPS-PLAN.md` when changing architecture, security behavior, or task scope
4. Run `uv sync --all-packages` — confirm workspace installs
5. Run smoke tests:
   ```bash
   uv run pytest packages/agentir-core/tests/ -v --tb=short -q   # must be 125/125
   grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."  # must be 0 lines
   uv run python -c "from case_dashboard.routes import create_dashboard_app; print('OK')"
   uv run python -c "from case_mcp.server import create_server; print('OK')"
   ```
6. **Next task: Phase 7/8 live validation** — test installer on clean Ubuntu/SIFT VM or container and run live Docker/OpenSearch health check.

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

### 10c. wintools references cleanup
- [ ] `grep -rn "wintools" packages/sift-gateway/` — find and remove any remaining dead references
- [ ] Same in `packages/case-mcp/`, `packages/sift-common/`

---

## Phase 12 — Portal Authentication: Login UI, Session JWT, Registration

> See SIFT-MCPS-PLAN.md Phase 12 for full design spec.
> Target files: `packages/case-dashboard/src/case_dashboard/routes.py` (new endpoints),
>               `packages/case-dashboard/src/case_dashboard/auth.py` (session middleware — new file),
>               `packages/sift-gateway/src/sift_gateway/config.py` (portal_session_secret loading)

### 12a. Backend: JWT helpers (new file `case_dashboard/session_jwt.py`)

- [ ] `generate_jwt(sub, role, secret, max_age=28800) -> str`
  - Header: `{"alg": "HS256", "typ": "JWT"}` base64url-encoded
  - Payload: `{sub, role, iat, exp, jti}` base64url-encoded
  - Signature: `HMAC-SHA256(secret, header + "." + payload)` base64url-encoded
  - Returns `header.payload.signature`
- [ ] `verify_jwt(token, secret) -> dict | None`
  - Splits on `.`, decodes, checks signature (timing-safe), checks `exp > now`
  - Returns payload dict or None on any failure (never raises)
- [ ] `COOKIE_NAME = "agentir_session"`, `COOKIE_PATH = "/portal"`, `COOKIE_SAME_SITE = "strict"`
- [ ] Test: `generate_jwt` → `verify_jwt` round-trip passes; tampered signature returns None; expired token returns None

### 12b. Backend: `portal_session_secret` config

- [ ] `packages/sift-gateway/src/sift_gateway/config.py`: read `portal.session_secret` and `portal.session_max_age` (default 28800) from loaded config
- [ ] Pass `portal_session_secret` into `create_dashboard_v2_app()` constructor
- [ ] `case_dashboard/routes.py`: accept `session_secret` param in `create_dashboard_v2_app()`; store as module-level `_SESSION_SECRET`

### 12c. Backend: session middleware (`case_dashboard/auth.py`)

- [ ] New `PortalSessionMiddleware(BaseHTTPMiddleware)`:
  - For every request to portal API paths:
    - Read `agentir_session` cookie → call `verify_jwt()` → set `request.state.examiner`, `request.state.role`
    - If no valid cookie: check `Authorization: Bearer` → look up in `api_keys` (backward compat, examiner role only)
    - If neither: set `request.state.examiner = None`, `request.state.role = None`
  - Does NOT return 401 itself — route handlers check `request.state.examiner`
- [ ] Wire `PortalSessionMiddleware` into `create_dashboard_v2_app()` middleware stack

### 12d. Backend: auth endpoints (add to `routes.py`)

- [ ] `GET  /api/auth/setup-required` — no auth; returns `{"required": bool}` based on whether any password file exists in `/var/lib/agentir/passwords/`
- [ ] `POST /api/auth/setup` — no auth; only when `setup-required` is true; body: `{examiner, password}` (plaintext, hashed server-side with PBKDF2); creates password file; returns 409 if already set up
- [ ] `GET  /api/auth/challenge` — `?examiner=<name>`; same logic as `get_commit_challenge` but stores in separate `_login_challenges` dict
- [ ] `POST /api/auth/login` — `{challenge_id, examiner, response}`; verifies HMAC same as commit; on success: set `agentir_session` cookie with 8h JWT; returns `{examiner, role, expires_at}`
- [ ] `POST /api/auth/reset-password` — required for installer-created users with `must_reset_password: true`; clears flag atomically after success
- [ ] `POST /api/auth/logout` — clears `agentir_session` cookie (Max-Age=0); returns 200
- [ ] `GET  /api/auth/me` — reads session cookie/state; returns `{examiner, role, expires_at}` or 401
- [ ] Test each endpoint: 401 on missing session, 200+cookie on valid login, 200 on logout clears cookie
- [ ] Test default examiner cannot create cases, generate tokens, or commit approvals until password reset is complete

### 12e. Backend: update existing route guards

- [ ] `_resolve_examiner()` in `routes.py`: read from `request.state.examiner` (set by middleware) — remove the `VHIR_EXAMINER` env var fallback (that's the 0a namespace fix too)
- [ ] All routes that require auth: return 401 if `_resolve_examiner()` returns None
- [ ] Commit endpoint: remains password-gated on top of session (session proves identity, password proves presence)

---

## Phase 13 — Separate Agent Credentials + Role-Based Access Control

> See SIFT-MCPS-PLAN.md Phase 13 for full design spec.
> Target files: `packages/sift-gateway/src/sift_gateway/token_gen.py`,
>               `packages/sift-gateway/src/sift_gateway/auth.py`,
>               `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`

### 13a. Token generation

- [ ] `token_gen.py`: add `generate_service_token() -> str` → `f"agentir_svc_{secrets.token_hex(24)}"`
- [ ] `token_gen.py`: fix existing `generate_gateway_token()` → `f"agentir_gw_{secrets.token_hex(24)}"` (192-bit entropy, correct prefix)
- [ ] Update `install.sh` (Phase 7) to generate BOTH tokens and write both to `gateway.yaml`
- [ ] Add stable token metadata: `token_id`, `agent_id`, `label`, `role`, `created_by`, `created_at`, `expires_at`, `revoked_at`, last-used metadata

### 13b. Role enforcement in auth middleware

- [ ] `auth.py::AuthMiddleware.dispatch()`: after resolving role, add:
  - If `request.url.path.startswith("/portal/api/")` and `role == "agent"` → return 403 `{"error": "Agent tokens cannot access portal"}`
  - If `request.url.path.startswith("/portal/api/")` and `role == "readonly"` and request method not in ("GET", "HEAD") → return 403
- [ ] `mcp_endpoint.py::MCPAuthASGIApp.__call__()`: add:
  - If `role == "readonly"` → return 403 `{"error": "Readonly role cannot call MCP tools"}`
- [ ] Production Hermes workflow uses only `/mcp`; per-backend endpoints are disabled or diagnostic opt-in and protected by the same auth/audit path

### 13c. Role enforcement in portal routes

- [ ] Create `_require_examiner_role(request) -> JSONResponse | None` helper: returns 403 if role not "examiner", else None
- [ ] Apply to: `post_delta`, `delete_delta_item`, `post_commit`, `get_commit_challenge`, `verify_evidence`
- [ ] Apply equivalent examiner-role enforcement to gateway REST `POST /api/v1/case/create`
- [ ] Apply examiner-role enforcement to portal token create/revoke/rotate endpoints
- [ ] `get_findings`, `get_timeline`, `get_case`, `get_delta`, etc.: allow "examiner" and "readonly"

### 13d. `gateway.yaml` template with two tokens

- [ ] Update `configs/gateway.yaml.template` to show both `agentir_gw_*` (examiner) and `agentir_svc_*` (agent) keys with comments
- [ ] Update `configs/hermes-forensics-profile.yaml` to show `agentir_svc_*` token in mcp.json example
- [ ] Document in template: which token goes where, how to rotate

### 13f. Portal service-token lifecycle

- [ ] `GET /portal/api/tokens` lists token metadata only; never returns raw token values
- [ ] `POST /portal/api/tokens` creates an additional `agentir_svc_*` token with `agent_id`, label, optional expiry; raw token returned once
- [ ] `DELETE /portal/api/tokens/{token_id}` revokes a token
- [ ] `POST /portal/api/tokens/{token_id}/rotate` revokes old token and returns replacement once
- [ ] Gateway rejects revoked/expired tokens and records audit event
- [ ] Tests: two different agent tokens produce separable gateway logs

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

- [ ] Title: `Valhuntir — Examiner Portal` → `sift-mcps — Examiner Portal`
- [ ] Header title HTML: `Valhuntir — ` → `sift-mcps — `
- [ ] Icon `src`: `valhuntir-icon.png` → `agentir-icon.png`
- [ ] Rename icon file: `static/v2/valhuntir-icon.png` → `static/v2/agentir-icon.png`
- [ ] localStorage key: `vhir-theme` → `agentir-theme` (replace_all)
- [ ] localStorage key: `vhir-sidebar-width` → `agentir-sidebar-width`
- [ ] localStorage key: `vhir-has-committed` → `agentir-has-committed`
- [ ] All occurrences of `vhir approve --review` → remove or replace with "use the portal commit button"
- [ ] `vhir case activate` / `vhir case init` references → replace with portal UI instructions
- [ ] Help text "Valhuntir is an AI-assisted..." → update to sift-mcps branding
- [ ] "vhir CLI" reference in help → "agentir CLI"
- [ ] Smoke test: `grep -c "vhir\|valhuntir\|Valhuntir" index.html` → 0 (case-insensitive)

### 14b. Auth flow rewiring

- [ ] Remove `extractToken()` IIFE (the `#token=` URL hash extraction block)
- [ ] Remove `sessionStorage.setItem('vhir_dashboard_token', ...)` and `getItem` calls
- [ ] Remove `token` variable declaration and all `if (token)` Bearer injection in `apiHeaders()`
- [ ] `apiFetch`: remove `Authorization` header injection; keep `Content-Type`
- [ ] `apiFetch` error handler: on 401 → call `showLoginScreen()` instead of throwing
- [ ] Add `currentExaminer` and `currentRole` module-level variables
- [ ] On page load: call `checkSession()` first; on success `showApp()`; on 401 `showLoginScreen()`
- [ ] `checkSession()`: `GET /api/auth/me` → set `currentExaminer`, `currentRole`

### 14c. Login screen HTML + CSS

- [ ] Add `<div id="loginScreen" style="display:none">` section with:
  - sift-mcps branding (title, subtitle)
  - Examiner name input `#loginExaminer`
  - Password input `#loginPassword`
  - Sign in button `#loginBtn`
  - Error message area `#loginError`
  - "First run? Set up your account" link (shown when `setup-required` returns true)
- [ ] Style: centered card, matches existing dark/light theme variables, no external CSS

### 14d. Login JS flow

- [ ] `showLoginScreen()`: hides main app, shows `#loginScreen`; checks `GET /api/auth/setup-required`, shows setup link if needed
- [ ] `showApp()`: hides `#loginScreen`, shows main app; updates header examiner name + role badge
- [ ] Login submit handler:
  1. `GET /api/auth/challenge?examiner=<name>` → `{challenge_id, nonce, salt, iterations}`
  2. `PBKDF2` via `SubtleCrypto.importKey` + `deriveKey` (SHA-256, 600000 iterations)
  3. `HMAC-SHA256` via `SubtleCrypto.sign(...)` on the nonce
  4. `POST /api/auth/login` → `{challenge_id, examiner, response: hex(hmac)}`
  5. On success: `showApp()` + `loadAll()`
  6. On error: show `#loginError` message
- [ ] First-run setup flow: separate form (examiner name + password + confirm); `POST /api/auth/setup`

### 14e. Header additions

- [ ] Add examiner name display span in header (updated by `showApp()`)
- [ ] Add role badge: hidden for examiner, visible (styled amber) for readonly
- [ ] Add "Sign out" button → `POST /api/auth/logout` → `showLoginScreen()`
- [ ] "New Case" button (examiner only) → opens case init modal (Phase 14f)
- [ ] "Agent Tokens" button (examiner only) → opens service-token management UI

### 14f. Case init modal

- [ ] Add `<div id="newCaseModal">` with:
  - Case ID input (validated: `[a-z0-9_-]+`)
  - Title input
  - Directory input (pre-populated as `/cases/<case-id>`)
  - Create button → `POST /api/v1/case/create` (gateway REST, not portal API)
  - Status/error display
- [ ] Backend (`rest.py`): `POST /api/v1/case/create` (examiner auth required):
  - Validates inputs (no path traversal, case_id pattern)
  - Creates directory + CASE.yaml + empty findings.json/timeline.json/evidence.json/todos.json/iocs.json/approvals.jsonl/audit/
  - Updates `gateway.yaml → case.dir` with atomic write
  - Sets `AGENTIR_CASE_DIR` in process env
  - Signals backends to reload (restart stdio subprocesses) via `Gateway.restart_backends()`
  - Returns `{ok: true, case_dir: "..."}`
- [ ] On success: close modal, reload dashboard data

### 14g. Agent token management UI

- [ ] List service token metadata without raw token values
- [ ] Create token form: label, `agent_id`, optional expiry
- [ ] Show created/rotated raw token exactly once
- [ ] Revoke/rotate actions require examiner role and password/HMAC confirmation
- [ ] Show last-used timestamp/IP if available

---

## Phase 15 — Portal Session Security Hardening

> See SIFT-MCPS-PLAN.md Phase 15 for full design spec.
> Depends on Phase 12 complete.

### 15a. JWT revocation on logout

- [ ] `session_jwt.py`: add `_revoked_jtis: set[str]` module-level set
- [ ] `revoke_jti(jti: str)` and `is_revoked(jti: str)` helpers
- [ ] `verify_jwt()`: after validating signature, check `is_revoked(payload["jti"])` → return None if revoked
- [ ] `POST /api/auth/logout`: extract `jti` from current cookie before clearing it, call `revoke_jti(jti)`
- [ ] Test: login → get jti → logout → verify_jwt with old token returns None

### 15b. Sliding session refresh

- [ ] In `PortalSessionMiddleware`: if valid session and `exp - now < max_age * 0.9` (token is > 10% into its life), reissue new JWT cookie on the response
- [ ] Throttle: only refresh if `now - iat > 300` (don't refresh on every request, only after 5min)

### 15c. Login rate limiting

- [ ] Reuse `_check_commit_lockout` / `_record_commit_failure` for login endpoint too
- [ ] `GET /api/auth/challenge`: check lockout first — return 429 if locked
- [ ] `POST /api/auth/login`: on HMAC mismatch, call `_record_commit_failure(examiner)`; on success `_clear_commit_failures(examiner)`
- [ ] Max 5 login failures before lockout (separate from commit failures)

### 15d. Secure response headers middleware

- [ ] New `SecureHeadersMiddleware(BaseHTTPMiddleware)` in `sift_gateway/server.py`:
  - Sets `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` on all responses
  - Sets `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'` on portal HTML responses
- [ ] Mount as outermost middleware in `create_app()`
- [ ] Test: `curl -I https://127.0.0.1:4508/portal/` → confirm headers present

---

## Phase 11 — Integration Verification

> (Moved below new phases — run last)

- [ ] Installer readiness test passes in clean SIFT-like VM/container and is idempotent
- [ ] OpenSearch Docker is healthy and bound only to `127.0.0.1:9200`
- [ ] Enrichment/RAG assets are present and either healthy or report clear degraded mode
- [ ] Default examiner login forces password reset before case/token/commit operations
- [ ] Portal creates a full case directory and activates it through `AGENTIR_CASE_DIR`
- [ ] Invalid case create inputs are rejected: traversal, relative paths, bad id, unwritable root, existing non-empty directory
- [ ] Backend reload after case create propagates active case to all MCP backends
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

---

## Session Notes

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
