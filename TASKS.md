# sift-mcps Task Tracker

**Project:** Extract + repackage SIFT-side MCP functionality into portable `/sift-mcps` workspace.  
**Plan file:** `/home/yk/AI/SIFTHACK/SIFT-MCPS-PLAN.md`  
**Source repos:**
- `/home/yk/AI/SIFTHACK/Valhuntir/` — agentir-cli (still named vhir_cli internally)
- `/home/yk/AI/SIFTHACK/Valhuntir/sift-mcp/` — sift-mcp monorepo
- `/home/yk/AI/SIFTHACK/Valhuntir/opensearch-mcp/` — opensearch-mcp
- `/home/yk/AI/SIFTHACK/hermes-agent/` — Hermes agent

---

## Status Legend
- `[ ]` Not started
- `[x]` Done
- `[~]` In progress / partial
- `[!]` Blocked / needs input

---

## Phase 1 — Workspace Scaffold ✅

- [x] Create `/home/yk/AI/SIFTHACK/sift-mcps/` git repo
- [x] Create root `pyproject.toml` (uv workspace, `package = false`)
- [x] Add `[tool.uv.sources]` for all workspace packages
- [x] Copy packages from sift-mcp monorepo (all except windows-triage)
- [x] Rename `forensic-rag` → `forensic-rag-mcp`, `opencti` → `opencti-mcp`
- [x] Copy `opensearch-mcp` into `packages/`
- [x] Copy `case-dashboard` into `packages/`
- [x] Create `packages/agentir-core/` with pyproject.toml
- [x] `uv sync` resolves without errors

### agentir-core modules created:
- [x] `case_io.py` — case file I/O (AGENTIR_ paths, env vars)
- [x] `identity.py` — examiner identity (AGENTIR_ env vars, ~/.agentir/config.yaml)
- [x] `approval_auth.py` — PBKDF2 password auth (/var/lib/agentir/passwords/)
- [x] `verification.py` — HMAC ledger (/var/lib/agentir/verification/)
- [x] `gateway_cfg.py` — gateway URL builder (~/.agentir/gateway.yaml)
- [x] `case_ops.py` — case lifecycle (init, activate, list, status) + _set_case_wintools_permissions no-op
- [x] `evidence_ops.py` — register/list/verify evidence
- [x] `audit_ops.py` — audit summary data
- [x] `backup_ops.py` — case backup (OpenSearch excluded)

### Packages updated to use agentir-core:
- [x] `case-mcp/pyproject.toml` — vhir-cli → agentir-core
- [x] `report-mcp/pyproject.toml` — vhir-cli → agentir-core
- [x] `case-mcp/server.py` — vhir_cli imports → agentir_core, VHIR_* → AGENTIR_*, wintools removed
- [x] `report-mcp/server.py` — vhir_cli imports → agentir_core, VHIR_* → AGENTIR_*

---

## Phase 2 — agentir-core: Tests + Validation

> Test the extracted functions match original vhir_cli behavior. Many tests in
> Valhuntir/tests/ cover these functions — port the relevant ones.

- [ ] Port tests from `/home/yk/AI/SIFTHACK/Valhuntir/tests/` → `packages/agentir-core/tests/`
  - [ ] `test_case_io.py` (path: tests/test_case_io.py in Valhuntir)
  - [ ] `test_identity.py`
  - [ ] `test_approval_auth.py`
  - [ ] `test_verification.py`
  - [ ] New: `test_case_ops.py` (case_init_data, case_activate_data, etc.)
  - [ ] New: `test_evidence_ops.py`
- [ ] Check that `case-mcp` server still has `_resolve_case_dir` and it uses AGENTIR_* env vars
  - **Note:** `_resolve_case_dir` in `case-mcp/server.py` still has inline logic that should use `agentir_core.case_io.get_case_dir` — but currently it's inline. This is OK for now (it was inline before too). Mark for future cleanup.
- [ ] Verify `report-mcp` server's `_resolve_case_dir` uses AGENTIR_* (done above)
- [ ] Run `uv run pytest packages/agentir-core/tests/ -v`

---

## Phase 3 — Portal Security Hardening (sift-gateway)

> Source: `packages/sift-gateway/src/sift_gateway/`  
> See SIFT-MCPS-PLAN.md Phase 3 for details.

### 3a. HTTPS enforcement for portal access
- [ ] Add `HTTPSRedirectMiddleware` in `server.py` or `__main__.py`
  - When TLS configured: portal paths return 400 if accessed via HTTP
  - MCP and health endpoints not affected
  - **File:** `packages/sift-gateway/src/sift_gateway/server.py` (check Gateway.build_app())

### 3b. Nonce hardening in case-dashboard
- [ ] `packages/case-dashboard/src/case_dashboard/routes.py`
  - Add `bound_ip` field to challenge store
  - Add `used` flag — mark consumed after first verify attempt
  - Reduce TTL from 60s → 30s
  - **Check:** challenge store is currently a dict `_challenges = {}` — add IP+used fields

### 3c. CORS and CSP headers
- [ ] Add `CORSMiddleware` to Gateway app (restrict to gateway origin only)
- [ ] Add CSP header to portal responses via route middleware
- [ ] **File:** `packages/sift-gateway/src/sift_gateway/server.py` (in `build_app()` or `__main__.py`)

### 3d. Error sanitization
- [ ] Add global exception handler in gateway that strips file paths from responses
- [ ] **File:** `packages/sift-gateway/src/sift_gateway/server.py`

### 3e. opensearch-mcp TLS fix
- [ ] `packages/opensearch-mcp/src/opensearch_mcp/gateway.py`
  - Replace hardcoded `CERT_NONE` with configurable `verify_certs` from config
  - Default: `verify_certs = True`; opt-out via gateway.yaml

---

## Phase 4 — Gateway Improvements

### 4a. Bearer token expiry
- [ ] `packages/sift-gateway/src/sift_gateway/auth.py`
  - Add `expires_at` field support in `AuthMiddleware`
  - Return 401 if token is expired
  - **Note:** auth.py already has sophisticated auth — add expiry check after token lookup

### 4b. Per-examiner rate limiting
- [ ] `packages/sift-gateway/src/sift_gateway/rate_limit.py` — currently per-IP
  - Change key from IP to examiner identity (available after auth)
  - Or add a second per-examiner limiter that applies after auth middleware
  - **Gateway config:** `rate_limit.calls_per_minute` and `rate_limit.burst`

### 4c. `notifications/tools/list_changed`
- [ ] `packages/sift-gateway/src/sift_gateway/server.py`
  - After backend restart/reload, emit to all active MCP sessions
  - Find where `_rebuild_tool_map()` is called and add notification send

### 4d. Origin header validation for MCP endpoint
- [ ] `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
  - Reject requests with `Origin:` header not matching gateway URL
  - Exempt health check; agent requests don't set Origin

---

## Phase 5 — FastMCP Migration for forensic-rag

> `packages/forensic-rag-mcp/src/rag_mcp/server.py` uses low-level MCP SDK.

- [ ] Read `server.py` fully — understand tools: `search_knowledge`, `list_knowledge_sources`, `get_knowledge_stats`
- [ ] Rewrite to use `from mcp.server.fastmcp import FastMCP`
- [ ] Preserve: model allowlist, input length limits, ChromaDB integration
- [ ] Test: `uv run rag-mcp --help` works

---

## Phase 6 — sift-mcp Argument Sanitization Hardening

> `packages/sift-mcp/src/sift_mcp/`  
> See SIFT-MCPS-PLAN.md Phase 6.

- [ ] Find current argument validator location
  - **Note:** look for `sanitize` or `validate_args` in `packages/sift-mcp/src/sift_mcp/`
- [ ] Add null-byte check (`\x00`)
- [ ] Add argument length limit (>4096 chars)
- [ ] Add Unicode normalization (NFC) — accept but log
- [ ] Test: send null-byte in command arg → expect 400/error response

---

## Phase 7 — Install Script

- [ ] Create `/home/yk/AI/SIFTHACK/sift-mcps/install.sh`
  - Check Python 3.10+
  - Install uv if absent
  - `uv sync --all-packages`
  - Create `/var/lib/agentir/` (passwords/ + verification/) with sudo
  - Generate `agentir_gw_` token (96 bits, 24 hex chars)
  - Generate self-signed CA + cert at `~/.agentir/tls/`
  - Write `~/.agentir/gateway.yaml` from template
  - Copy systemd service file + enable
  - Start gateway + health poll
  - Print setup summary
  - Non-interactive mode: `./install.sh -y`

---

## Phase 8 — Docker Compose (OpenSearch)

- [ ] Create `/home/yk/AI/SIFTHACK/sift-mcps/docker-compose.yml`
  - OpenSearch 2.18.0, single-node, security disabled
  - JVM heap 3GB, bound to 127.0.0.1:9200
  - Named volume for persistence
  - `restart: unless-stopped`

---

## Phase 9 — Configs and Templates

- [ ] `configs/gateway.yaml.template` — gateway config with TLS, rate limits, token placeholder
- [ ] `configs/hermes-forensics-profile.yaml` — Hermes profile template (per plan Phase 9)
- [ ] `configs/systemd/sift-gateway.service` — systemd user service

---

## Phase 10 — Valhuntir Rename (vhir_cli → agentir_cli)

> The Valhuntir repo (agentir-cli) still uses `vhir_cli` namespace internally.
> This is the rename work described in CLAUDE.md and the plan.

- [ ] Rename `src/vhir_cli/` → `src/agentir_cli/` in Valhuntir
- [ ] Update `pyproject.toml`: `name = "vhir-cli"` → `"agentir-cli"`, `vhir = "vhir_cli.main:main"` → `agentir = "agentir_cli.main:main"`
- [ ] Update all `vhir_cli` imports inside the CLI itself
- [ ] Update `approval_auth.py`: `/var/lib/vhir/` → `/var/lib/agentir/`, `~/.vhir/` → `~/.agentir/`
- [ ] Update `verification.py`: `VERIFICATION_DIR = Path("/var/lib/vhir/verification")` → `/var/lib/agentir/verification`
- [ ] Update `case_io.py`: `VHIR_CASES_DIR` → `AGENTIR_CASES_DIR`, `VHIR_CASE_DIR` → `AGENTIR_CASE_DIR`
- [ ] Update `identity.py`: `VHIR_EXAMINER` → `AGENTIR_EXAMINER`, `~/.vhir/config.yaml` → `~/.agentir/config.yaml`
- [ ] Update all CLI help text ("vhir" → "agentir")
- [ ] Update all existing tests to use new namespace
- [ ] Confirm Valhuntir tests pass: `pytest tests/ -v`

---

## Phase 11 — Integration Verification

- [ ] `uv run sift-gateway --config configs/gateway.yaml.template` starts without error
- [ ] `curl -k https://127.0.0.1:4508/api/v1/health` returns `{"status": "ok"}`
- [ ] `uv run pytest packages/*/tests/ -v --tb=short` — all tests pass
- [ ] Portal accessible and functional (manually verify with test case)
- [ ] Run verification tests from SIFT-MCPS-PLAN.md Phase 11 checklist

---

## Session Notes

### Session 1 (2026-05-23)

**Completed:**
- Phases 1 fully done: workspace scaffold, all packages copied, agentir-core extracted and tested
- case-mcp and report-mcp updated to use agentir-core (imports + env vars + wintools removal)
- `uv sync` resolves 190 packages cleanly

**Key discoveries during implementation:**
1. `vhir_cli` namespace is still in use in Valhuntir — rename is pending (Phase 10)
2. case-mcp imports MORE from vhir_cli than the plan noted: also commands.audit_cmd, commands.evidence, commands.join (wintools), commands.backup, main.py functions
3. report-mcp also imports from vhir_cli (not mentioned explicitly in plan)
4. `forensic-rag` package name is `rag-mcp` (not `forensic-rag-mcp`) — root pyproject uses `rag-mcp`
5. `case-dashboard` is an optional import in gateway server.py — kept as separate package
6. Gateway already has `rate_limit.py` (per-IP) and `auth.py` — Phase 4 work modifies existing code
7. sift-gateway has no `app.py` — ASGI app is assembled in `server.py` Gateway.build_app()
8. `_set_case_wintools_permissions` was called in case-mcp — replaced with no-op in agentir-core

**Open questions for next session:**
- Should `case-mcp/server.py`'s `_resolve_case_dir` be replaced with `agentir_core.case_io.get_case_dir`? Currently it's inline code (was also inline in original). Low priority — it works.
- The `_create_backup_data` import was added at module level in updated case-mcp — but the original was a lazy import inside the tool. Check if this causes any issues at startup.
- Phase 10 (Valhuntir rename) — should this happen before or after sift-mcps work is complete? The agentir-core in sift-mcps already uses agentir namespace, so the CLI rename is independent.

**Next session should start with:**
1. Run `uv sync --all-packages` (confirm all workspace packages install)
2. Run `uv run python -c "from case_mcp.server import create_server"` to verify case-mcp imports clean
3. Begin Phase 2 (port tests for agentir-core)
4. Then Phase 3 (portal hardening — most impactful security work)
