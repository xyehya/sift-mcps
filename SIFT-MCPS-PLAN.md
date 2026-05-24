# Plan: sift-mcps — Portable MCP Runtime for Digital Forensics

## Tracking Contract

This file is the normative project spec: architecture, security requirements, behavioral contracts,
and phase acceptance criteria. It may describe completed work because completed behavior still needs
to remain testable.

`TASKS.md` is the execution tracker: checklists, implementation notes, current next step, and session
ledger. When a task is completed, update `TASKS.md`; update this file only when the spec itself
changes.

If this file and `TASKS.md` disagree:
1. Stop implementation work.
2. Identify the exact conflicting lines.
3. Ask the user which spec should win unless the code/tests already prove one side is obsolete.

## Purpose and End State

Extract and repackage forensic MCP server infrastructure into a single portable Python project
(`/sift-mcps`) installable on any SIFT Workstation VM via a one-shot `install.sh` script.
The original Valhuntir repo at `/home/yk/AI/SIFTHACK/Valhuntir` is a read-only reference for
workflow ideas and source functions. sift-mcps is not a straight replication: we cherry-pick,
improve, decouple, harden, and make the package portable/flexible.

**The operational picture:**
- The SIFT VM is prepared by one installer: packages, gateway, portal UI, OpenSearch Docker,
  enrichment/RAG assets, TLS, credentials, service token, and systemd service
- The human examiner/operator enters through the **Examiner Portal** and creates each new case there
- Portal case creation writes the selected case directory, canonical case files, and active gateway case config
- The AI agent (Hermes) runs on a **separate analyst machine** and connects over HTTPS to the aggregate gateway MCP endpoint
- The agent drives investigation through MCP tools; the examiner maintains control via case creation and human-in-the-loop approval
- The final deliverable is a cryptographically auditable case report

**What we are NOT doing:**
- Granting the agent direct shell access (sift-mcp is the sandboxed gate)
- Replacing the portal with CLI approval (portal is the primary interface)
- Requiring SSH or shell access for normal examiner case creation
- Building for Windows (SIFT is Linux-only; windows-triage-mcp is permanently dropped)
- Copying the source repos as-is (we are refactoring, hardening, decoupling)

## Final Required Workflow

This workflow is the product contract. Implementation phases, tests, and docs must trace back to it.

1. **Install once on a SIFT VM**
   - Run `install.sh` from the repo root.
   - Installer validates OS/runtime prerequisites, syncs all packages, creates `/var/lib/agentir/`,
     deploys OpenSearch Docker, prepares enrichment/RAG assets, generates TLS material, writes
     `~/.agentir/gateway.yaml`, installs/enables `sift-gateway`, and verifies health.
   - Installer creates a default examiner account and marks it `must_reset_password: true`.
   - Installer generates the first Hermes service token and prints/saves operator handoff material.

2. **Examiner signs in through the portal**
   - Browser goes to `https://SIFT_VM:4508/portal/`.
   - Default password must be reset on first login before case or token operations are allowed.
   - Portal sessions use secure cookies; commit actions still require HMAC password confirmation.

3. **Examiner creates a case from the portal**
   - Examiner submits case metadata and target directory.
   - Portal/gateway validates paths and `CASE.yaml` schema, creates the directory and all canonical files,
     writes protected files atomically, updates `gateway.yaml → case.dir`, sets `AGENTIR_CASE_DIR`,
     and restarts/reloads backends.
   - Manual `gateway.yaml` case edits are administrator fallback only.

4. **Hermes connects to the gateway aggregate MCP endpoint**
   - Hermes uses `https://SIFT_VM:4508/mcp` with an `agentir_svc_*` token.
   - Per-backend URLs are not the supported agent workflow and must not be emitted by installer/templates.
   - Gateway performs auth, role enforcement, request audit, response enrichment, and identity injection.

5. **Investigation and enrichment**
   - Gateway routes aggregate tool calls to stdio backends.
   - `sift-mcp` is the only command-execution gate and always uses `shell=False`.
   - OpenSearch indexing/search, forensic-rag semantic context, OpenCTI enrichment, and forensic-knowledge
     guidance are exposed through gateway-mediated MCP tools and/or contextual MCP response enrichment.

6. **Review, approval, report**
   - Hermes can propose findings/timeline events but cannot approve them.
   - Examiner reviews in the portal, edits if needed, and commits via HMAC challenge-response.
   - Report generation includes only approved items and preserves hashes, approvals, verification ledger,
     and gateway/backend audit trail.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ SIFT VM                                                         │
│                                                                 │
│  sift-gateway (Starlette ASGI, :4508 HTTPS)                    │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────────────┐ │
│  │ auth    │  │ rate     │  │ MCP     │  │ Examiner Portal  │ │
│  │ Bearer  │  │ limit    │  │ proxy   │  │ /portal/         │ │
│  │ + expiry│  │ examiner │  │ /mcp    │  │ (case-dashboard) │ │
│  └─────────┘  └──────────┘  └────┬────┘  └──────────────────┘ │
│                                  │                             │
│           stdio subprocesses (FastMCP)                         │
│  ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌───────────────────┐  │
│  │forensic  │ │case-mcp │ │sift-mcp  │ │report-mcp         │  │
│  │-mcp      │ │         │ │shell=F   │ │                   │  │
│  └──────────┘ └─────────┘ └──────────┘ └───────────────────┘  │
│  ┌──────────┐ ┌─────────┐ ┌──────────┐                        │
│  │opensearch│ │forensic │ │opencti   │                        │
│  │-mcp      │ │-rag-mcp │ │-mcp      │                        │
│  └──────────┘ └─────────┘ └──────────┘                        │
│                                                                 │
│  agentir-core library ──▶ /var/lib/agentir/                    │
│                           passwords/, verification/             │
│  Case directory: AGENTIR_CASE_DIR env var (portal-created)     │
└─────────────────────────────────────────────────────────────────┘
```

### What Is Sound — Do Not Change

| Component | Why It Stays |
|-----------|-------------|
| Streamable HTTP transport via `StreamableHTTPSessionManager` | Correct 2025-03-26 MCP spec |
| Gateway subprocess aggregation (Starlette + low-level MCP SDK) | Clean separation of concerns |
| FastMCP in all backends | Low boilerplate, type-safe tool registration |
| Challenge-response HMAC-SHA256 portal auth | Cryptographically sound; no plaintext password over wire |
| HMAC verification ledger at `/var/lib/agentir/verification/` | Non-forgeable integrity layer |
| Atomic writes + `chmod 444` on case files | Crash-safe, tamper-resistant |
| Per-backend audit JSONL | Evidence chain for every tool call |
| Gateway request audit with principal metadata | Separates examiner actions from Hermes/agent actions |
| Gateway aggregate `/mcp` as agent entry point | Single security, audit, enrichment, and routing boundary |
| `subprocess.run(shell=False)` in sift-mcp | Non-negotiable security boundary |
| Portal case creation | Normal examiner workflow; avoids shell/SSH dependency |
| Content hash + stale detection | Detects post-review tampering |
| Append-only `approvals.jsonl` | Immutable approval audit trail |

---

## Case Directory Design (Settled)

The case directory is created and activated through the portal as the primary workflow.
There is no CLI activation command and no `active_case` file used in the gateway workflow.
Manual `gateway.yaml → case.dir` editing remains an administrator fallback for recovery.

### How it works

1. Installer writes an initial gateway config with no active case:
   ```yaml
   case:
     dir: ""   # no active case until the examiner creates one in the portal
   ```
2. Examiner signs into the portal and submits new case metadata + target directory.
3. Gateway REST validates the path, creates the directory, writes `CASE.yaml` and canonical files,
   and atomically updates `gateway.yaml → case.dir`.
4. Gateway sets `AGENTIR_CASE_DIR` in the current process and restarts/reloads stdio backends.
5. `stdio_backend.py` propagates `AGENTIR_*` env vars to all backend subprocesses.
6. `agentir_core.case_io.get_case_dir()` reads `AGENTIR_CASE_DIR` — all backends use this.
7. `case-dashboard/routes.py` reads `AGENTIR_CASE_DIR` — portal uses the same source.

### Case directory structure (created by portal/gateway)

```
/cases/{case-id}/
├── CASE.yaml           # Case metadata (case_id, title, examiner, created_at)
├── findings.json       # AI-proposed findings (DRAFT → APPROVED/REJECTED)
├── timeline.json       # Timeline events
├── evidence.json       # Evidence registry {files: [...]}
├── todos.json          # Investigation todos
├── iocs.json           # Indicators of Compromise
├── pending-reviews.json # Agent's proposed review batch (delta)
├── approvals.jsonl     # Append-only approval audit log
└── audit/              # Per-backend JSONL audit logs
    ├── forensic-mcp.jsonl
    ├── sift-mcp.jsonl
    └── ...
```

`CASE.yaml` minimal schema:
```yaml
case_id: case-2026-001
title: "Ransomware investigation — Contoso"
examiner: alice
created_at: "2026-05-23T10:00:00Z"
```

### Removed Legacy Behavior

- `~/.agentir/active_case` file pointer — removed from `agentir_core.case_io.get_case_dir()` fallback chain (keep only `AGENTIR_CASE_DIR` env var)
- `_get_active_case()` in `sift-gateway/server.py` — delete it; gateway reads case dir from its own environment
- `agentir case activate` — not needed in agent workflow; examiner creates/activates cases in the portal

## Gateway MCP Boundary

Hermes and all other agents use only:

```text
https://SIFT_VM:4508/mcp
```

The gateway aggregates all enabled backend tools, handles name collision prefixing, and injects
principal/context metadata. Backend-specific URLs may exist for local diagnostics, but they are not
the supported agent contract and must not appear in Hermes profile templates.

For every MCP request the gateway must log at least:
- timestamp, request id, method/tool name, backend target, status, duration
- authenticated principal role (`agent`, `examiner`, `readonly`)
- token id or key fingerprint, agent id/examiner name, and source IP
- active case id/path when available

For MCP responses the gateway may add contextual enrichment from forensic-knowledge, forensic-rag,
OpenSearch, and OpenCTI. Enrichment must be auditable and must not mutate original backend output
without preserving the raw backend response in logs or structured response metadata.

---

## Implementation Phases

### Phase 0 — Critical Bug Fixes

Completed behavior that must remain true. These bugs originally made the system non-functional;
the acceptance gates below prevent regression.

#### 0a. Namespace sweep: vhir → agentir

Every occurrence of `vhir`, `VHIR`, `~/.vhir`, `/var/lib/vhir` must become `agentir`/`AGENTIR`/
`~/.agentir`/`/var/lib/agentir` across the sift-mcps workspace.

Critical files:

**`packages/case-dashboard/src/case_dashboard/routes.py`**
- Line 93: `VHIR_CASE_DIR` → `AGENTIR_CASE_DIR`
- Line 107: error message "vhir case activate" → "agentir case activate" (or remove CLI reference)
- Line 225: `VHIR_EXAMINER` → `AGENTIR_EXAMINER`
- Line 232: comment reference
- Line 235: `/var/lib/vhir/passwords/` → `/var/lib/agentir/passwords/`
- Lines 247, 264, 289, 314: `~/.vhir/.password_lockout` → `~/.agentir/.password_lockout`
- Line 398: `/var/lib/vhir/verification/` → `/var/lib/agentir/verification/`

**`packages/sift-gateway/src/sift_gateway/server.py`**
- Line 305: `Path.home() / ".vhir" / "active_case"` → replace with `AGENTIR_CASE_DIR` env var (see 0b)

**`packages/sift-gateway/src/sift_gateway/rest.py`**
- Lines 417, 520, 562, 614, 619, 629, 634, 670: `~/.vhir/` → `~/.agentir/`
- Line 455: `VHIR_EXAMINER` → `AGENTIR_EXAMINER`

**`packages/sift-gateway/src/sift_gateway/join.py`**
- Line 34: `Path.home() / ".vhir"` → `Path.home() / ".agentir"`
- Line 7 docstring: update state file path

**`packages/sift-gateway/src/sift_gateway/token_gen.py`**
- Line 9 docstring: `vhir_gw_` → `agentir_gw_`
- Line 12: `f"vhir_gw_{secrets.token_hex(12)}"` → `f"agentir_gw_{secrets.token_hex(24)}"` (192-bit entropy)

**`packages/sift-gateway/src/sift_gateway/backends/stdio_backend.py`**
- Lines 89-94: propagate `AGENTIR_*` env vars instead of `VHIR_*`

**`packages/sift-mcp/src/sift_mcp/security.py`**
- Line 124: `os.path.expanduser("~/.vhir")` → `os.path.expanduser("~/.agentir")`
- Lines 129-130: `~/.vhir/cases` → `~/.agentir/cases`, `~/.vhir/hayabusa-output` → `~/.agentir/hayabusa-output`

**`packages/sift-gateway/src/sift_gateway/__main__.py`**
- Line 47: update error message referencing `vhir setup client`

**`packages/sift-gateway/src/sift_gateway/rate_limit.py`**
- Line 1 docstring: "Valhuntir gateway" → "sift-mcps gateway"

**`packages/sift-gateway/src/sift_gateway/rest.py`**
- Line 343: "vhir join" instruction → "agentir join" or remove if wintools join path

After the sweep, grep verify:
```bash
grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v ".pyc" | grep -v "opensearch_mcp/vhir_plugin.py"
# Should return zero results (vhir_plugin.py is renamed in 0c)
```

#### 0b. Replace `_get_active_case()` with AGENTIR_CASE_DIR

In `packages/sift-gateway/src/sift_gateway/server.py`:
- Delete `_get_active_case()` method entirely (lines 302-309)
- Delete `_notify_backend_case()` method — wintools-mcp is dropped, this HTTP case sync is no longer needed
- Delete `if name == "wintools-mcp"` reference in `_late_start_checker` (line 297)
- The gateway propagates `AGENTIR_CASE_DIR` to backends via stdio_backend's env merging (0a fixes this)

In `packages/agentir-core/src/agentir_core/case_io.py`:
- Remove the `~/.agentir/active_case` fallback from `get_case_dir()` (lines 91-103)
- Keep only: `AGENTIR_CASE_DIR` env var. If not set, raise `CaseError("No active case: set AGENTIR_CASE_DIR in gateway.yaml")`
- Update the docstring

In `packages/sift-gateway/src/sift_gateway/config.py` — add gateway startup logic to read `case.dir` and set env:
- After loading gateway.yaml, if `config.get("case", {}).get("dir")` is set, do `os.environ["AGENTIR_CASE_DIR"] = case_dir`
- This propagates to all subprocesses spawned later

#### 0c. Remove duplication — case-dashboard must import from agentir-core

In `packages/case-dashboard/src/case_dashboard/routes.py`, delete these inline implementations
and import from `agentir_core` instead:

| Delete | Import from agentir_core |
|--------|--------------------------|
| `_compute_content_hash(item)` (lines 112-116) | `from agentir_core.case_io import compute_content_hash` |
| `_write_hmac_entries(...)` (lines 385-431) | `from agentir_core.verification import write_ledger_entry` |
| `_save_protected(path, data)` (lines 434-458) | `from agentir_core.case_io import _protected_write` |
| `_load_password_entry(examiner)` (lines 231-242) | `from agentir_core.approval_auth import _load_password_entry` |

The `_apply_delta` function calls these helpers — update the call sites.
`_write_approval_log_entry` stays in routes.py for now (it writes case-dir files, acceptable).

#### 0d. opensearch-mcp TLS fix

In `packages/opensearch-mcp/src/opensearch_mcp/gateway.py`:
```python
# Replace hardcoded CERT_NONE (line 68) with:
verify_certs = config.get("verify_certs", True)
ca_cert = config.get("ca_cert_path")
if not verify_certs:
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
elif ca_cert:
    ctx.load_verify_locations(ca_cert)
# else: default SSL context (system CA bundle)
```

Add to gateway.yaml template:
```yaml
opensearch:
  verify_certs: true
  ca_cert_path: ~/.agentir/tls/ca-cert.pem   # or omit to use system CA
```

#### 0e. Rename opensearch vhir_plugin.py

`packages/opensearch-mcp/src/opensearch_mcp/vhir_plugin.py` → `agentir_plugin.py`
Update all imports referencing `vhir_plugin`.

#### 0f. Verification after Phase 0

```bash
# All vhir references gone
grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "agentir_plugin"
# Should return 0 lines

# Import smoke tests
uv run python -c "from case_dashboard.routes import create_dashboard_v2_app; print('OK')"
uv run python -c "from sift_gateway.server import Gateway; print('OK')"
uv run python -c "from agentir_core.case_io import get_case_dir; print('OK')"

# agentir-core tests still pass
uv run pytest packages/agentir-core/tests/ -v --tb=short
```

---

### Phase 1 — Workspace Scaffold ✅ (Complete)

Completed in Session 1. Packages copied, `agentir-core` extracted, `uv sync` passes.
See TASKS.md Session 1 notes for details.

---

### Phase 2 — agentir-core Tests ✅ Complete (Session 3)

125/125 tests passing. All behaviors verified:
- `get_case_dir()` raises `CaseError` when `AGENTIR_CASE_DIR` unset
- PBKDF2 600k-iteration round-trip, lockout after 3 failures
- HMAC ledger write/verify/rehmac cycle
- case_init, case_status, case_list
- evidence register/list/verify with SHA-256

---

### Phase 2b — agentir-core Library Hardening

Completed behavior that must remain true. The assessment of agentir-core (Session 3) identified
4 issues that were fixed before portal auth work.

#### Rationale: why single-library is correct

agentir-core has one external dependency (PyYAML). All security-critical primitives (PBKDF2,
HMAC-SHA256, atomic writes, chmod 444, content hashing) are in one audited, tested place.
Splitting into sub-packages would give no runtime isolation benefit (same process) and
would fragment the test coverage. The only module that doesn't fit is `gateway_cfg.py`
(gateway connectivity, not case data) — it will move to `sift-gateway` in Phase 12.

#### 2b-1. `sys.exit()` → exceptions in `approval_auth.py`

Libraries must not call `sys.exit()`. `approval_auth.py` currently calls it in 6 places.

Add at top of `approval_auth.py`:
```python
class AuthError(Exception): ...
class LockoutError(AuthError): ...
```

Replace every `sys.exit(1)` with the appropriate exception:
- `_check_lockout()` → `raise LockoutError(f"Password locked. Try again in {remaining} seconds.")`
- `require_confirmation()` bad password → `raise AuthError(f"Incorrect password. {remaining} attempt(s) remaining.")` or `raise LockoutError(...)` if count exhausted
- `require_confirmation()` no password → `raise AuthError("No approval password configured. Run agentir config --setup-password")`
- `setup_password()` empty/short/mismatch → `raise AuthError("Password cannot be empty.")` etc.
- `reset_password()` wrong current → `raise AuthError("Incorrect current password.")`

CLI entry points (if any call `require_confirmation`) wrap in:
```python
try:
    require_confirmation(...)
except LockoutError as e:
    print(str(e), file=sys.stderr); sys.exit(1)
except AuthError as e:
    print(str(e), file=sys.stderr); sys.exit(1)
```

Portal routes (Phase 12) will catch `AuthError`/`LockoutError` and return HTTP 401/429.

#### 2b-2. Env-overridable paths (`VERIFICATION_DIR`, `_PASSWORDS_DIR`, `_LOCKOUT_FILE`)

Hardcoded module-level constants prevent test isolation and deployment flexibility.

`verification.py`:
```python
import os
VERIFICATION_DIR = Path(os.environ.get("AGENTIR_VERIFICATION_DIR", "/var/lib/agentir/verification"))
```

`approval_auth.py`:
```python
_PASSWORDS_DIR = Path(os.environ.get("AGENTIR_PASSWORDS_DIR", "/var/lib/agentir/passwords"))
_LOCKOUT_FILE = Path(os.environ.get("AGENTIR_LOCKOUT_FILE", str(Path.home() / ".agentir" / ".password_lockout")))
```

`backup_ops.py` — same pattern for its `_PASSWORDS_DIR`.

No functional change in production. Tests set the env vars to tmpdir. Existing tests already
pass because they write to tmpdir — this change just makes the path injectable without
monkeypatching the constant.

#### 2b-3. Remove `subprocess.run(["sudo",…])` from `_ensure_passwords_dir()`

Libraries must not call sudo. Replace the `for cmd in [["sudo", …],…]` block with:
```python
raise PermissionError(
    f"Cannot create {passwords_dir}/. Run manually:\n"
    f"  sudo mkdir -p {passwords_dir}\n"
    f"  sudo chown $USER:$USER {passwords_dir}\n"
    f"  sudo chmod 700 {passwords_dir}"
)
```

Remove `import subprocess` from approval_auth.py (unused after this change).

#### 2b-4. Verification gate

```bash
uv run pytest packages/agentir-core/tests/ -v --tb=short   # 125/125
uv run python -c "from agentir_core.approval_auth import AuthError, LockoutError; print('OK')"
grep -n "sys.exit\|subprocess" packages/agentir-core/src/agentir_core/approval_auth.py  # 0 lines
```

---

### Phase 3 — Portal Security Hardening

Completed behavior that must remain true.

All items in `packages/sift-gateway/src/sift_gateway/` and `packages/case-dashboard/src/case_dashboard/`.

#### 3a. HTTPS enforcement for portal access

In `sift-gateway/src/sift_gateway/server.py`, add to `create_app()` before mounting routes:
```python
class _PortalHTTPSGuard:
    """Return 400 on plain-HTTP portal requests when TLS is configured."""
    def __init__(self, app, tls_configured: bool):
        self.app = app
        self.tls_configured = tls_configured

    async def __call__(self, scope, receive, send):
        if (
            self.tls_configured
            and scope["type"] == "http"
            and scope.get("scheme") == "http"
            and scope.get("path", "").startswith(("/portal", "/dashboard"))
        ):
            resp = PlainTextResponse(
                "Portal requires HTTPS. Connect via https://...", status_code=400
            )
            await resp(scope, receive, send)
            return
        await self.app(scope, receive, send)
```

`tls_configured = bool(config.get("gateway", {}).get("tls", {}).get("cert"))` — True when TLS cert is set in gateway.yaml.

#### 3b. Nonce IP binding + TTL reduction

In `packages/case-dashboard/src/case_dashboard/routes.py`, `get_commit_challenge()`:
```python
_challenges[challenge_id] = {
    "nonce": nonce,
    "examiner": examiner,
    "created_at": now,
    "bound_ip": request.client.host,  # ADD
}
_CHALLENGE_TTL = 30  # Reduce from 60 to 30
```

In `post_commit()`, before HMAC verification (the nonce is already consumed on pop — correct):
```python
if challenge["bound_ip"] != request.client.host:
    return JSONResponse({"error": "Challenge IP mismatch"}, status_code=403)
# The pop() on line 1287 already consumes the nonce — no additional change needed
```

#### 3c. CORS restriction on gateway

In `packages/sift-gateway/src/sift_gateway/server.py`, `create_app()`:
```python
from starlette.middleware.cors import CORSMiddleware

gateway_origin = f"https://{config['gateway'].get('host', '0.0.0.0')}:{config['gateway'].get('port', 4508)}"
app.add_middleware(
    CORSMiddleware,
    allow_origins=[gateway_origin, "https://localhost:4508"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_credentials=True,
    allow_headers=["Authorization", "Content-Type", "MCP-Protocol-Version"],
)
```

#### 3d. Error sanitization — strip file paths from client responses

In `packages/sift-gateway/src/sift_gateway/server.py`, add to `create_app()`:
```python
import re as _re

_PATH_PATTERN = _re.compile(r"/[^\s:\"']{5,}")

@app.exception_handler(Exception)
async def _sanitized_error(request, exc):
    logger.exception("Unhandled error: %s", exc)
    return JSONResponse({"error": "Internal server error"}, status_code=500)
```

In `packages/case-dashboard/src/case_dashboard/routes.py`, `post_commit()` line ~1328:
```python
# Replace: return JSONResponse({"error": str(e)}, status_code=500)
# With:
logger.exception("Commit failed")
return JSONResponse({"error": "Commit failed — check gateway logs"}, status_code=500)
```

#### 3e. opensearch-mcp TLS fix
Covered in Phase 0d.

---

### Phase 4 — Gateway Improvements

Phase 4a-4c and the extractor helper are completed behavior that must remain true. Phase 4d
(`notifications/tools/list_changed`) remains open pending SDK lifecycle research; see `TASKS.md`.

#### 4a. Bearer token expiry

Extract shared auth logic into `packages/sift-gateway/src/sift_gateway/auth.py`:
```python
def verify_api_key(token: str, api_keys: dict) -> dict | None:
    """Timing-safe key lookup. Returns key_info dict or None.
    
    Checks token length, iterates all keys (constant time), validates
    key_info structure, and enforces expires_at if set.
    """
    if not token or len(token) > _MAX_TOKEN_LENGTH:
        return None
    matched_key = None
    for candidate in api_keys:
        if hmac.compare_digest(token, candidate) and matched_key is None:
            matched_key = candidate
    if matched_key is None:
        return None
    key_info = api_keys.get(matched_key, {})
    if not isinstance(key_info, dict):
        return None
    expires_at = key_info.get("expires_at")
    if expires_at:
        from datetime import datetime, timezone
        try:
            exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > exp:
                logger.warning("Expired token used (examiner=%s)", key_info.get("examiner"))
                return None
        except (ValueError, AttributeError):
            pass  # Malformed date — treat as no expiry
    return key_info
```

Replace the timing-safe loops in both `AuthMiddleware.dispatch` and `MCPAuthASGIApp.__call__` with calls to `verify_api_key()`.

`gateway.yaml` api_keys format:
```yaml
api_keys:
  agentir_gw_abc123:                    # the token value
    examiner: alice
    role: examiner
    expires_at: null                    # null = never; "2027-01-01T00:00:00Z" = hard expiry
```

#### 4b. Per-examiner rate limiting (post-auth)

The current rate limiter keys by IP. After auth succeeds, apply a second check keyed by examiner.

In `packages/sift-gateway/src/sift_gateway/rate_limit.py`:
- Add `ExaminerRateLimiter` class (same sliding window, keyed by examiner string)
- Keep `RateLimiter` for pre-auth IP rate limiting (DoS protection)

In `mcp_endpoint.py`, after auth succeeds:
```python
if not check_examiner_rate_limit(scope["state"]["examiner"]):
    # Return 429
```

`gateway.yaml` config:
```yaml
gateway:
  rate_limit:
    ip_calls_per_minute: 120      # pre-auth, per source IP
    examiner_calls_per_minute: 120  # post-auth, per examiner identity
    burst: 20
```

Localhost (`127.0.0.1`, `::1`) exempt from IP rate limit only — examiner limit still applies.

#### 4c. Origin header validation for MCP endpoint

In `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`, in `MCPAuthASGIApp.__call__`:
```python
# After rate limit check, before auth:
headers = dict(scope.get("headers", []))
origin = headers.get(b"origin", b"").decode("latin-1", errors="replace")
if origin:  # Only browser requests set Origin; agent (Hermes) does not
    allowed_origins = {gateway_base_url, "https://localhost:4508", "https://127.0.0.1:4508"}
    if origin not in allowed_origins:
        resp = JSONResponse({"error": "Forbidden"}, status_code=403)
        await resp(scope, receive, send)
        return
```

`gateway_base_url` comes from `config["gateway"]` host/port/tls settings — pass into `MCPAuthASGIApp` at construction time.

#### 4d. `notifications/tools/list_changed`

In `packages/sift-gateway/src/sift_gateway/server.py`, `Gateway`:
- Add `self._active_mcp_sessions: dict[str, Any] = {}` — populated when sessions connect
- After `_build_tool_map()` completes a rebuild (i.e., not the first build):
  ```python
  async def _notify_tools_changed(self) -> None:
      for session_id, session in list(self._active_mcp_sessions.items()):
          try:
              await session.send_notification("notifications/tools/list_changed", {})
          except Exception as exc:
              logger.debug("tools/list_changed notify failed for %s: %s", session_id, exc)
  ```

Session registration: hook into `StreamableHTTPSessionManager` session lifecycle events if the SDK provides them; otherwise track via a side-channel in `create_mcp_server`.

Current SDK finding (verified 2026-05-24): the installed/current Python MCP SDK is `mcp==1.27.1`
(`uv pip show mcp`, and `uv pip install --upgrade mcp --dry-run` found no newer `mcp`). In this
version, `StreamableHTTPSessionManager` exposes only `run()` and `handle_request()` and privately
tracks `StreamableHTTPServerTransport` instances. `ServerSession.send_tool_list_changed()` exists,
but the session manager does not expose active `ServerSession` lifecycle hooks. Implementing this
phase therefore requires either deferring until the SDK exposes hooks or adding a local
session-tracking `Server` wrapper/subclass that owns the relevant part of the SDK `Server.run()`
flow.

---

### Phase 5 — FastMCP Migration for forensic-rag-mcp

`packages/forensic-rag-mcp/src/rag_mcp/server.py` uses the low-level `mcp.server.Server` with
manual `@server.list_tools()` and `@server.call_tool()` decorators. All other backends use FastMCP.

Migration:
```python
# Before (low-level)
from mcp.server import Server
server = Server("forensic-rag-mcp")

@server.list_tools()
async def handle_list_tools(): ...

@server.call_tool()
async def handle_call_tool(name, arguments): ...

# After (FastMCP)
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("forensic-rag-mcp", instructions=_INSTRUCTIONS)

@mcp.tool(annotations={"readOnlyHint": True})
async def search_knowledge(query: str, top_k: int = 5, source: str | None = None) -> str:
    """Semantic search across 22K forensic knowledge records."""
    return await _search_impl(query, top_k, source)

@mcp.tool(annotations={"readOnlyHint": True})
async def list_knowledge_sources() -> list[str]:
    """List available forensic knowledge source categories."""
    ...

@mcp.tool(annotations={"readOnlyHint": True})
async def get_knowledge_stats() -> dict:
    """Return index statistics (record count, sources, embedding model)."""
    ...
```

Preserve: model allowlist, input length limits (query truncation), ChromaDB integration.
Test: `uv run rag-mcp --help` must work after migration.

---

### Phase 6 — sift-mcp Argument Sanitization Hardening

In `packages/sift-mcp/src/sift_mcp/security.py`, `sanitize_extra_args()`:

```python
import unicodedata

def sanitize_extra_args(extra_args: list[str], tool_name: str = "") -> list[str]:
    if not extra_args:
        return []

    policy = _get_policy()
    tool_allowed = policy["tool_allowed_flags"].get(tool_name, set())
    tool_blocked = policy["tool_blocked_flags"].get(tool_name, set())

    sanitized = []
    for arg in extra_args:
        if not isinstance(arg, str):
            raise ValueError(f"Non-string argument: {type(arg).__name__}")

        # NEW: null byte check
        if "\x00" in arg:
            raise ValueError(f"Null byte in argument for {tool_name}")

        # NEW: length limit
        if len(arg) > 4096:
            raise ValueError(f"Argument too long ({len(arg)} chars) for {tool_name}")

        # NEW: Unicode NFC normalization (accept but normalize; log if changed)
        normalized = unicodedata.normalize("NFC", arg)
        if normalized != arg:
            logger.info("Normalized non-NFC argument for %s: %r → %r", tool_name, arg, normalized)
            arg = normalized

        flag = arg.lower().split("=")[0]
        if flag in tool_blocked:
            raise ValueError(f"Blocked dangerous flag '{arg}' for {tool_name}")
        if flag in policy["dangerous_flags"] and flag not in tool_allowed:
            raise ValueError(f"Blocked dangerous flag '{arg}' for {tool_name}")
        for pattern in _DANGEROUS_PATTERNS:
            if pattern in arg:
                raise ValueError(f"Blocked shell metacharacter in extra_args for {tool_name}")
        sanitized.append(arg)

    # Awk program text scanning (existing, unchanged)
    if tool_name in _PROGRAM_TEXT_TOOLS:
        for arg in sanitized:
            if arg.startswith("-"):
                continue
            if _AWK_DANGEROUS_RE.search(arg):
                raise ValueError(f"Blocked dangerous awk construct for {tool_name}")

    return sanitized
```

---

### Phase 7 — Install Script (`install.sh`)

Target: Ubuntu 22.04/24.04 (SIFT Workstation base).

Steps:
1. Check Python ≥ 3.10
2. Install `uv` if absent (official installer)
3. `uv sync --all-packages` from `/sift-mcps/`
4. Create required state directories:
   - `/var/lib/agentir/{passwords,verification,enrichment,tokens}`
   - default case root, e.g. `/cases`
   - `~/.agentir/{tls,backups}`
5. Install and start OpenSearch Docker compose, bound to `127.0.0.1:9200`
6. Prepare enrichment assets:
   - forensic-knowledge YAML available to all relevant backends
   - forensic-rag index/bootstrap path present and health-checked
   - OpenSearch index templates installed
7. Generate self-signed CA + gateway cert (openssl, 10-year CA, 2-year leaf):
   ```bash
   openssl genrsa -out ~/.agentir/tls/ca-key.pem 4096
   openssl req -new -x509 -days 3650 -key ~/.agentir/tls/ca-key.pem \
     -out ~/.agentir/tls/ca-cert.pem -subj "/CN=sift-mcps-CA"
   openssl genrsa -out ~/.agentir/tls/gateway-key.pem 4096
   openssl req -new -key ~/.agentir/tls/gateway-key.pem \
     -out ~/.agentir/tls/gateway-csr.pem -subj "/CN=$(hostname)"
   openssl x509 -req -days 730 -in ~/.agentir/tls/gateway-csr.pem \
     -CA ~/.agentir/tls/ca-cert.pem -CAkey ~/.agentir/tls/ca-key.pem \
     -CAcreateserial -out ~/.agentir/tls/gateway-cert.pem \
     -extfile <(printf "subjectAltName=IP:$(hostname -I | awk '{print $1}'),IP:127.0.0.1")
   ```
8. Generate examiner fallback token: `agentir_gw_` + 48 hex chars (192-bit entropy)
9. Generate first Hermes service token: `agentir_svc_` + 48 hex chars (192-bit entropy)
10. Generate `portal.session_secret`: 32 random bytes as hex
11. Create default examiner account:
    - username: installer default such as `examiner`
    - password: generated temporary password or installer-supplied value
    - `must_reset_password: true`
12. Write `~/.agentir/gateway.yaml` from template with: both tokens, portal secret, TLS paths, hostname, rate limits, empty `case.dir`, OpenSearch settings, enrichment settings
13. Copy `configs/systemd/sift-gateway.service` → `~/.config/systemd/user/`
14. `systemctl --user daemon-reload && systemctl --user enable sift-gateway && systemctl --user start sift-gateway`
15. Poll health endpoints until ready:
    - `https://127.0.0.1:4508/api/v1/health`
    - OpenSearch container health
    - gateway backend readiness
16. Print summary: gateway URL, portal URL, CA cert path, default examiner username, temporary password handling, first Hermes service token location, and next steps

Non-interactive: `./install.sh -y` skips confirmations and generates credentials. It must print
where the generated password/token material was written and must not silently discard secrets.

---

### Phase 8 — OpenSearch Docker Compose

`docker-compose.yml`:
```yaml
services:
  opensearch:
    image: opensearchproject/opensearch:2.18.0
    environment:
      - discovery.type=single-node
      - DISABLE_SECURITY_PLUGIN=true
      - OPENSEARCH_JAVA_OPTS=-Xms3g -Xmx3g
    volumes:
      - opensearch-data:/usr/share/opensearch/data
    ports:
      - "127.0.0.1:9200:9200"    # localhost only — not exposed externally
    ulimits:
      memlock: { soft: -1, hard: -1 }
      nofile: { soft: 65536, hard: 65536 }
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9200/_cluster/health | grep -v '\"status\":\"red\"'"]
      interval: 30s
      timeout: 10s
      retries: 5

volumes:
  opensearch-data:
```

JVM heap 3GB appropriate for 16GB SIFT VM. Security plugin disabled (trusted private network).
Bound to 127.0.0.1:9200 only — not reachable from Hermes machine (only gateway can reach it via tool calls).

---

### Phase 9 — Configs and Templates

#### `configs/gateway.yaml.template`
```yaml
gateway:
  host: "0.0.0.0"
  port: 4508
  tls:
    cert: "${HOME}/.agentir/tls/gateway-cert.pem"
    key:  "${HOME}/.agentir/tls/gateway-key.pem"
  rate_limit:
    ip_calls_per_minute: 120
    examiner_calls_per_minute: 120
    burst: 20
  lazy_start: false
  idle_timeout_seconds: 0

case:
  root: "/cases"
  dir: ""    # Empty until examiner creates/selects a case in the portal

api_keys:
  ${AGENTIR_GATEWAY_TOKEN}:
    examiner: "${AGENTIR_EXAMINER}"
    role: examiner
    expires_at: null    # null = never; "2027-01-01T00:00:00Z" = hard expiry

  ${AGENTIR_SERVICE_TOKEN}:
    examiner: "hermes-agent"
    agent_id: "hermes-default"
    role: agent
    expires_at: null    # service tokens are rotated manually

portal:
  session_secret: "${AGENTIR_PORTAL_SESSION_SECRET}"
  session_max_age: 28800
  default_examiner: "examiner"
  require_password_reset: true

opensearch:
  url: "http://127.0.0.1:9200"
  verify_certs: true
  ca_cert_path: "${HOME}/.agentir/tls/ca-cert.pem"

enrichment:
  enabled: true
  forensic_knowledge: true
  forensic_rag: true
  opensearch_context: true

backends:
  forensic-mcp:
    enabled: true
    type: stdio
    command: uv
    args: ["run", "--project", "/path/to/sift-mcps", "forensic-mcp"]
    env:
      AGENTIR_CASE_DIR: "${AGENTIR_CASE_DIR}"

  case-mcp:
    enabled: true
    type: stdio
    command: uv
    args: ["run", "--project", "/path/to/sift-mcps", "case-mcp"]

  sift-mcp:
    enabled: true
    type: stdio
    command: uv
    args: ["run", "--project", "/path/to/sift-mcps", "sift-mcp"]

  report-mcp:
    enabled: true
    type: stdio
    command: uv
    args: ["run", "--project", "/path/to/sift-mcps", "report-mcp"]

  forensic-rag-mcp:
    enabled: true
    type: stdio
    command: uv
    args: ["run", "--project", "/path/to/sift-mcps", "rag-mcp"]

  opensearch-mcp:
    enabled: true
    type: stdio
    command: uv
    args: ["run", "--project", "/path/to/sift-mcps", "opensearch-mcp"]
    env:
      OPENSEARCH_HOST: "http://127.0.0.1:9200"

  opencti-mcp:
    enabled: false    # Enable if OpenCTI is deployed
    type: stdio
    command: uv
    args: ["run", "--project", "/path/to/sift-mcps", "opencti-mcp"]
    env:
      OPENCTI_URL: "${OPENCTI_URL}"
      OPENCTI_TOKEN: "${OPENCTI_TOKEN}"
```

#### `configs/hermes-forensics-profile.yaml`
```yaml
# Copy to ~/.hermes/profiles/forensics/config.yaml on the analyst machine
# Replace SIFT_IP with the SIFT VM's IP address or hostname
# Copy ca-cert.pem from SIFT VM to analyst machine and set REQUESTS_CA_BUNDLE

mcp_servers:
  sift-forensics:
    url: "https://SIFT_IP:4508/mcp"
    headers:
      Authorization: "Bearer ${AGENTIR_SERVICE_TOKEN}"
    timeout: 600
    supports_parallel_tool_calls: true
```

Analyst `.env` file (`~/.hermes/profiles/forensics/.env`):
```
AGENTIR_SERVICE_TOKEN=agentir_svc_<your_token_here>
REQUESTS_CA_BUNDLE=/path/to/ca-cert.pem   # or add to OS trust store
```

The gateway exposes all enabled backend tools through this single aggregate endpoint. Hermes should
not be configured with per-backend URLs.

**Tool naming convention** (gateway/Hermes sanitize hyphens to underscores):
| Backend | MCP tool | Hermes registered name |
|---------|----------|----------------------|
| forensic-mcp | `record_finding` | `mcp_forensic_mcp_record_finding` |
| case-mcp | `case_init` | `mcp_case_mcp_case_init` |
| sift-mcp | `run_command` | `mcp_sift_mcp_run_command` |
| opensearch-mcp | `idx_search` | `mcp_opensearch_mcp_idx_search` |
| forensic-rag-mcp | `search_knowledge` | `mcp_forensic_rag_mcp_search_knowledge` |

#### `configs/systemd/sift-gateway.service`
```ini
[Unit]
Description=sift-mcps Gateway — MCP server runtime for digital forensics
After=network.target

[Service]
Type=simple
ExecStart=%h/.local/share/uv/bin/uv run --project %h/sift-mcps sift-gateway --config %h/.agentir/gateway.yaml
WorkingDirectory=%h
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment=AGENTIR_EXAMINER=%h

[Install]
WantedBy=default.target
```

---

### Phase 10 — Architecture Cleanup (Debt Reduction)

These items reduce complexity and maintenance burden. Not blocking but should be done.

#### 10a. Split case-dashboard/routes.py (1433 lines → ~4 files)

`packages/case-dashboard/src/case_dashboard/`:
- `auth.py` — `_resolve_examiner`, `_load_password_entry` (import from agentir_core), challenge store, lockout
- `delta.py` — `_apply_delta` and its decomposed helpers: `_process_approvals`, `_process_rejections`, `_process_edits`, `_cascade_timeline`, `_cascade_iocs`, `_write_commit_results`
- `files.py` — `_load_json`, `_load_yaml`, `_load_jsonl`, `_resolve_case_dir`, `_verify_items`
- `routes.py` — Route definitions, endpoint handlers (which become thin wrappers over the above)

#### 10b. Extract shared gateway auth helper

`packages/sift-gateway/src/sift_gateway/auth.py` — add `verify_api_key(token, api_keys) -> dict | None` (see Phase 4a). Both `AuthMiddleware` and `MCPAuthASGIApp` call this function instead of each having their own timing-safe loop.

#### 10c. Extract examiner identity helper in mcp_endpoint.py

```python
def _extract_examiner(server: Server) -> str | None:
    try:
        ctx = server.request_context
        request = ctx.request
        if request is not None:
            return getattr(request.state, "examiner", None) or getattr(request.state, "analyst", None)
    except LookupError:
        pass
    return None
```

Used in both `create_mcp_server` and `create_backend_mcp_server`.

---

### Phase 12 — Portal Authentication: Login UI, Session JWT, Registration

#### Problem

The portal is the primary examiner entry point. It must support installer-created default
credentials, forced first-login password reset, secure browser sessions, and password-confirmed
approval actions. The examiner's browser must not share Hermes' service token.

#### Design Decisions

**Two distinct principals, two distinct auth paths:**

| Principal | Auth mechanism | Token lifetime |
|-----------|---------------|----------------|
| Browser (examiner) | Session cookie containing signed JWT | 8h idle expiry, set at login |
| Hermes agent | Static service bearer token in `mcp.json` | Long-lived, rotated manually |

The portal session JWT is signed with `portal_session_secret` (32-byte random hex) stored in
`gateway.yaml`. No Auth0 required — this is self-contained and works air-gapped.

**Login flow (challenge-response, no plaintext password over wire):**

```
1. GET  /portal/api/auth/challenge?examiner=yehya
        ← {challenge_id, nonce, salt, iterations: 600000, hash_algorithm: "SHA-256"}

2. Browser: derive_key = PBKDF2(password, salt, 600000, SHA-256)
            response   = HMAC-SHA256(derive_key, nonce).hexdigest()

3. POST /portal/api/auth/login
        → {challenge_id, examiner, response}
        ← Set-Cookie: agentir_session=<JWT>; HttpOnly; Secure; SameSite=Strict; Max-Age=28800
           + {examiner, role, expires_at}

4. All portal requests: browser sends cookie automatically.
   Server reads cookie, validates JWT signature + exp, sets request.state.examiner/role.

5. POST /portal/api/auth/logout → clears cookie (Max-Age=0)
```

**JWT payload:**
```json
{
  "sub":  "yehya",
  "role": "examiner",
  "iat":  1748000000,
  "exp":  1748028800,
  "jti":  "<16-byte random hex>"
}
```
Signed: `HMAC-SHA256(portal_session_secret, base64url(header) + "." + base64url(payload))`

No external JWT library needed — implement directly with `hmac` + `json` + `base64`.

**Session middleware** (new `PortalSessionMiddleware` in `case_dashboard/auth.py`):
- For portal paths: validates cookie JWT → sets `request.state.examiner`, `request.state.role`
- Falls back to Bearer token for backward compatibility (examiner role only)
- Does not decide authorization itself; route handlers return 401/403 based on `request.state`.

**First-run setup** (no password file exists yet):
- `GET /portal/api/auth/setup-required` → `{"required": true}` (no auth needed)
- `POST /portal/api/auth/setup` → `{examiner, password}` over HTTPS only; server creates
  `/var/lib/agentir/passwords/{examiner}.json` using the standard PBKDF2 password format.
  This endpoint is only allowed when zero password files exist.

**Installer default examiner**:
- Installer may create the first examiner user non-interactively.
- That account must include `must_reset_password: true`.
- Until reset is complete, portal permits only password-reset/logout endpoints and blocks case
  creation, token generation, commit approval, and administrative actions.
- After reset, `must_reset_password` is cleared atomically.
- After first user exists, endpoint returns 409 Conflict

#### Security Requirements for Phase 12 Implementation

These guards must be wired in during initial implementation. AGENTS.md has one-line summaries; this section has the binding behavioral spec.

**R1 — must_reset_password is a persistent gate, not a login-time flag**

The JWT may carry `must_reset: true` as a UI hint, but it is NOT the authoritative source. Before executing any write operation — commit, case create, token create, token revoke, reset-password itself — the route handler calls `_load_pw_entry(passwords_dir, examiner).get("must_reset_password")` directly. If `True`, the response is 403 `{"error": "Password reset required before this action"}`. The 8h JWT lifetime must never grant write access on installer credentials.

**R2 — Separate lockout counter namespace**

Login failure counter key: `login:{examiner}`. Commit failure counter key: `commit:{examiner}`. Both share `_LOCKOUT_SECONDS` and `_MAX_PASSWORD_ATTEMPTS`, but `_record_commit_failure`, `_check_commit_lockout`, and `_clear_commit_failures` accept an explicit `namespace` parameter (default `"commit"`) so the same helpers serve both paths without sharing state.

**R3 — Fake challenge prevents examiner enumeration**

`GET /api/auth/challenge?examiner=<name>` always returns a syntactically valid challenge. When the examiner does not exist in `_PASSWORDS_DIR`, generate a random nonce + random salt (32 bytes each) and store the entry in `_login_challenges` with `_fake: True`. The subsequent `POST /api/auth/login` always fails with `{"error": "Invalid credentials"}` — same HTTP status (401), same response shape as a real HMAC mismatch. The failure path for fake challenges must not be measurably faster than for real ones.

**R4 — Agent→403 on `/portal/api/` co-ships with Phase 12**

This is not deferred to Phase 13. Add to `auth.py::AuthMiddleware.dispatch()` immediately after `key_info` is resolved:

```python
if request.url.path.startswith("/portal/api/") and key_info.get("role") == "agent":
    return JSONResponse({"error": "Agent tokens cannot access portal"}, status_code=403)
```

Without this, any holder of a Hermes service token can write to portal API endpoints from day one of Phase 12 deployment.

**R6 — Login challenge pool cap**

`_login_challenges` is capped at 200 total entries. Before inserting a new challenge, if `len(_login_challenges) >= 200`, evict the entry with the smallest `created_at`. Additionally, per examiner: if the examiner already has ≥ 5 in-flight challenges (including fake ones), evict the oldest for that examiner before inserting. This bounds memory growth from unauthenticated flooding.

**R8 — Domain-separated HMAC sub-keys (apply before any production case data)**

The stored PBKDF2 hash (`entry["hash"]`) must never be used directly as a cryptographic key. Add to `agentir_core/approval_auth.py`:

```python
def derive_auth_key(stored_hash_hex: str) -> bytes:
    """Sub-key for login HMAC verification. Domain-separated from ledger signing."""
    return hmac.new(bytes.fromhex(stored_hash_hex), b"agentir-auth-v1", hashlib.sha256).digest()

def derive_ledger_key(stored_hash_hex: str) -> bytes:
    """Sub-key for approval HMAC ledger. Domain-separated from login auth."""
    return hmac.new(bytes.fromhex(stored_hash_hex), b"agentir-signing-v1", hashlib.sha256).digest()
```

- Phase 12 login HMAC verification uses `derive_auth_key(entry["hash"])` as the HMAC key.
- `verification.py::derive_hmac_key()` delegates to `derive_ledger_key()` internally.
- This change must ship before any production HMAC verification ledger entries are written. Development test entries are acceptable to discard. There is no migration path for entries written with the old direct-hash derivation.

**R9 — Safe examiner state access**

Every location that reads examiner identity from request state uses `getattr(request.state, "examiner", None)`. Never `request.state.examiner` directly. `PortalSessionMiddleware` sets this for portal paths, but test fixtures, edge-case middleware ordering, or future route additions may leave it unset. `AttributeError` at this callsite would produce an unhandled 500.

#### New endpoints in `case_dashboard/routes.py`

```python
GET  /portal/api/auth/setup-required    # → {required: bool}
POST /portal/api/auth/setup             # first-run only
GET  /portal/api/auth/challenge         # ?examiner=<name>
POST /portal/api/auth/login             # {challenge_id, examiner, response} → set cookie
POST /portal/api/auth/reset-password    # current challenge + new password, clears must_reset_password
POST /portal/api/auth/logout            # clear cookie
GET  /portal/api/auth/me                # → {examiner, role, expires_at} or 401
```

#### `portal_session_secret` in `gateway.yaml`

```yaml
portal:
  session_secret: "<32-byte hex generated at install>"
  session_max_age: 28800   # seconds (8h)
```

---

### Phase 13 — Separate Agent Credentials + Role-Based Tool Access

#### Two-token model

Install generates at least two credentials in `gateway.yaml`:

```yaml
api_keys:
  agentir_gw_<48hex>:          # Examiner token — portal fallback + MCP, rotate on compromise
    examiner: "yehya"
    role: "examiner"
    expires_at: "2027-06-01T00:00:00Z"

  agentir_svc_<48hex>:         # Agent service token — MCP only, goes into mcp.json
    examiner: "hermes-agent"
    role: "agent"
    # no expires_at — long-lived, rotated by examiner via install script
```

The examiner's browser now uses the **session cookie** (Phase 12), not the examiner bearer token.
The examiner bearer token remains as a fallback for CLI/scripted access.

#### Agent token lifecycle

The installer generates the first Hermes service token. The portal must provide examiner-only token
management for additional agents:

```python
GET    /portal/api/tokens                 # list token metadata only, never full token values
POST   /portal/api/tokens                 # create new agent token, returns token once
DELETE /portal/api/tokens/{token_id}      # revoke token
POST   /portal/api/tokens/{token_id}/rotate # revoke old token and return replacement once
```

Token records must include stable metadata: `token_id`, `role`, `agent_id`, `label`, `created_by`,
`created_at`, `expires_at`, `revoked_at`, and last-used metadata. Gateway logs use `token_id` and
`agent_id`, not raw token values. Raw token values are shown exactly once at creation/rotation.

#### Role enforcement matrix

| Path | role=examiner | role=agent | role=readonly |
|------|:---:|:---:|:---:|
| `GET /portal/api/*` (read) | ✅ | ❌ 403 | ✅ |
| `POST /portal/api/delta` (stage) | ✅ | ❌ 403 | ❌ 403 |
| `POST /portal/api/commit` (approve) | ✅ | ❌ 403 | ❌ 403 |
| `/mcp` — `list_tools` | ✅ all | ✅ agent tools | ❌ 403 |
| `/mcp` — `call_tool` (read-only) | ✅ | ✅ | ❌ 403 |
| `/mcp` — `call_tool` (write) | ✅ | ✅ | ❌ 403 |

**Role enforcement in gateway (R4 — co-ships with Phase 12):**

The agent→403 portal block is added to `auth.py::AuthMiddleware.dispatch()` in the same PR as Phase 12. It is not deferred to Phase 13 in practice. Full spec in §Phase 12 Security Requirements R4.

`mcp_endpoint.py::MCPAuthASGIApp.__call__()` — readonly role block:
```python
if role == "readonly":
    return JSONResponse({"error": "Readonly role cannot call MCP tools"}, status_code=403)
```

`mcp_endpoint.py::MCPAuthASGIApp.__call__()` — for readonly role:
```python
if role == "readonly":
    return JSONResponse({"error": "Readonly role cannot call MCP tools"}, status_code=403)
```

`mcp_endpoint.py` must reject or hide unsupported per-backend agent entry points in production
configuration. If diagnostic per-backend endpoints remain available for local development, they must
require explicit config opt-in and must use the same auth, audit, and rate-limit path as `/mcp`.

**Tool annotation for examiner-only tools** (Phase 13b, future):
If a tool is marked `annotations={"examinerOnly": True}`, it is stripped from the tool list
when `role == "agent"`. Currently no tools are examiner-only; this is for future use.

#### `token_gen.py` update

```python
def generate_gateway_token() -> str:
    return f"agentir_gw_{secrets.token_hex(24)}"   # examiner token

def generate_service_token() -> str:
    return f"agentir_svc_{secrets.token_hex(24)}"  # agent service token
```

#### `mcp.json` for Hermes

```json
{
  "mcpServers": {
    "sift-forensics": {
      "type": "http",
      "url": "https://<sift-vm-ip>:4508/mcp",
      "headers": {
        "Authorization": "Bearer agentir_svc_<token>"
      }
    }
  }
}
```

#### Gateway audit and enrichment requirements

For all gateway-routed MCP calls:
- log principal separation: `role`, `examiner` or `agent_id`, `token_id`, source IP, active case
- log route decision: aggregate tool name, resolved backend, status, duration, output truncation
- never log raw bearer token or HMAC response
- enrichment additions are appended as a distinct `_agentir_context` key in the MCP response metadata dict — never interpolated into the tool result content string. This is the primary defense against prompt injection via enrichment (R7): malicious artifacts processed by `sift-mcp` may be indexed into OpenSearch or forensic-rag, which are enrichment sources. If enrichment content is injected into the tool result string, adversarial text in case data can reach Hermes as apparent tool output. Hermes prompt engineering must treat `_agentir_context` as advisory secondary context, explicitly subordinate to the primary tool result.

Current audit storage model (verified during Session 10):
- `sift_common.audit.AuditWriter` is the shared writer. It writes append-only JSONL files to the
  active case audit directory (`AGENTIR_AUDIT_DIR` when set, otherwise `AGENTIR_CASE_DIR/audit/`),
  flushes, and fsyncs each line.
- The central evidence-provenance repository is the case-local `audit/` directory, not one single
  monolithic file. Each writer has its own file (`sift-gateway.jsonl`, `sift-mcp.jsonl`,
  `forensic-mcp.jsonl`, etc.), and provenance code scans `audit/*.jsonl`.
- `agentir_core.case_io.load_audit_index()`, `agentir_core.audit_ops._load_audit_entries()`,
  `case-dashboard` audit lookups, and `forensic-mcp` provenance classification already aggregate
  all `audit/*.jsonl` entries by `audit_id`.
- The HMAC verification ledger is separate: approved findings/timeline entries are written to
  `/var/lib/agentir/verification/{case-id}.jsonl` through `agentir-core`. Report reconciliation
  checks approved items against that ledger.

Regression guard:
- Existing stdio backend audit IDs are evidence IDs used by findings and reports. Do not replace,
  rename, or stop returning those backend `audit_id`s.
- Add a gateway envelope log for every aggregate `/mcp` `call_tool`, regardless of backend type.
  This should write to `audit/sift-gateway.jsonl` through `AuditWriter` and record minimal viable
  request/routing metadata: request or correlation id, authenticated role, `token_id`, `agent_id`
  or examiner, source IP, active case, aggregate tool name, resolved backend, status, duration,
  and result/truncation summary. It must never log raw bearer tokens or HMAC responses.
- Link gateway entries to backend entries with `backend_audit_id` when the backend response exposes
  one, but keep the backend `audit_id` as the canonical evidence/provenance ID for findings unless
  the finding/report schema is deliberately migrated with tests.
- Final proof must verify both layers: the gateway envelope proves who called what through `/mcp`;
  the backend audit entry proves what the backend/tool actually did; the verification ledger proves
  what the examiner approved.

---

### Phase 14 — Dashboard Rewiring

#### What needs to change

The `index.html` (188KB single-file dashboard) has accumulated technical debt from the Valhuntir
era. These changes bring it in line with the new auth model and namespace.

#### 14a. Namespace / branding cleanup

| Old | New |
|-----|-----|
| `<title>Valhuntir — Examiner Portal</title>` | `<title>sift-mcps — Examiner Portal</title>` |
| `valhuntir-icon.png` (src attribute) | `agentir-icon.png` |
| `valhuntir-icon.png` (filename in static/) | rename to `agentir-icon.png` |
| `sessionStorage.getItem('vhir_dashboard_token')` | remove — auth via cookie |
| `localStorage.getItem('vhir-theme')` | `localStorage.getItem('agentir-theme')` |
| `localStorage.getItem('vhir-sidebar-width')` | `localStorage.getItem('agentir-sidebar-width')` |
| `localStorage.setItem('vhir-has-committed', ...)` | `localStorage.setItem('agentir-has-committed', ...)` |
| `vhir approve --review` (all occurrences) | remove or replace with portal instructions |
| `vhir case activate` / `vhir case init` | replace with portal case init UI |
| "Valhuntir is an AI-assisted..." (help text) | update to sift-mcps branding |

#### 14b. Auth flow rewiring

Remove the `extractToken()` IIFE and the `sessionStorage` token logic entirely.
The browser sends the `agentir_session` cookie automatically — `apiFetch` needs no Authorization
header. Remove `apiHeaders()` Bearer injection.

Add session check on page load:
```javascript
async function checkSession() {
  try {
    const me = await apiFetch('/api/auth/me');
    currentExaminer = me.examiner;
    currentRole = me.role;
    showApp();
  } catch (e) {
    showLoginScreen();
  }
}
```

`apiFetch` 401 handler → call `showLoginScreen()` instead of throwing.

#### 14c. Login screen

Render a login form when not authenticated (before `loadAll()`):
```
┌─────────────────────────────────────┐
│  🔬  sift-mcps Examiner Portal      │
│                                     │
│  Examiner name  [_______________]   │
│  Password       [_______________]   │
│                                     │
│           [ Sign in ]               │
│                                     │
│  First run? Set up your account →   │
└─────────────────────────────────────┘
```

Login JS flow:
1. `GET /api/auth/challenge?examiner=<name>` → get nonce + salt
2. `PBKDF2(password, salt, 600000)` via `SubtleCrypto.deriveKey` (browser Web Crypto API)
3. `HMAC-SHA256(derived_key, nonce)` via `SubtleCrypto.sign`
4. `POST /api/auth/login` → `{challenge_id, examiner, response}`
5. On success: `showApp()`, reload data
6. On failure: show error message under form

**First-run detection**: `GET /api/auth/setup-required` → if `required: true`, show setup form.

#### 14d. Header additions

- Examiner name display: `<span id="examinerName">yehya</span>` next to title
- Role badge: `<span class="role-badge">EXAMINER</span>` (styled, read-only shows "READONLY")
- Logout button: `[ Sign out ]` → `POST /api/auth/logout` → `showLoginScreen()`
- Token management button (examiner only): creates/revokes/rotates `agentir_svc_*` tokens

#### 14e. Case init from portal (new dialog)

"New Case" button in header (examiner role only) opens a modal:
```
┌─────────────────────────────────────┐
│  Create New Case                    │
│                                     │
│  Case ID    [case-2026-001_______]  │
│  Title      [________________________] │
│  Directory  [/cases/case-2026-001_]  │
│             (will be created)        │
│                                     │
│     [ Cancel ]  [ Create Case ]     │
└─────────────────────────────────────┘
```

Calls `POST /api/v1/case/create`:
- Creates the directory structure (CASE.yaml, findings.json, etc.)
- Updates `gateway.yaml → case.dir` atomically
- Sets `AGENTIR_CASE_DIR` for the current gateway process
- Triggers gateway backend reload/restart
- On success: reloads dashboard data

Backend endpoint in `rest.py` (not `routes.py` — this is a gateway-level operation):
```python
POST /api/v1/case/create
→ {case_id, title, examiner, dir}
← {ok: true, case_dir: "/cases/..."}
```

**R5 — Symlink guard and serialized case creation**

Input validation in this endpoint is stricter than a pattern check:

```python
import os, threading

_case_create_lock = threading.Lock()  # module-level in rest.py

# Inside handler, before touching the filesystem:
real_root     = Path(os.path.realpath(case_root))
real_requested = Path(os.path.realpath(requested_dir))
# Symlink escape check — realpath resolves all symlinks before comparing
if not str(real_requested).startswith(str(real_root) + os.sep):
    return JSONResponse({"error": "Directory must be under case root"}, status_code=400)

with _case_create_lock:
    if real_requested.exists():
        return JSONResponse({"error": "Case directory already exists"}, status_code=409)
    # create dir, write canonical files, update gateway.yaml atomically, update env, restart backends
```

The lock serializes: YAML write + `os.environ["AGENTIR_CASE_DIR"]` update + backend restart. Without it, two simultaneous create requests can both pass the existence check, leaving the gateway in inconsistent state between the YAML file and the process environment.

Note: This supersedes the "manual edit gateway.yaml" workflow for new deployments. The manual
method remains valid for advanced users. This is additive, not replacing R4.

#### 14f. Agent token management UI

Examiner-only modal/page:
- Lists existing service token metadata without revealing token secrets
- Creates a new agent token with label, `agent_id`, optional expiry, and role `agent`
- Displays the new token exactly once with copy affordance
- Revokes or rotates existing tokens after password/HMAC confirmation
- Shows last-used timestamp/IP from gateway auth metadata

---

### Phase 15 — Portal Session Security Hardening

Additional hardening on top of Phase 12:

#### 15a. JWT revocation list (in-memory)

```python
_revoked_jtis: set[str] = set()  # populated on logout

def revoke_session(jti: str) -> None:
    _revoked_jtis.add(jti)

def is_revoked(jti: str) -> bool:
    return jti in _revoked_jtis
```

On logout: add `jti` to revocation set. On session validation: check `is_revoked(jti)`.
Set is in-memory — clears on restart. Acceptable since sessions are 8h and restart invalidates
all sessions anyway (secret is loaded from file, not rotated on restart).

#### 15b. Sliding session expiry

Each authenticated request that hits the portal API resets the cookie Max-Age:
```python
response.set_cookie("agentir_session", new_jwt, max_age=28800, httponly=True, ...)
```
Only refresh if token is more than 5 minutes old (avoid per-request churn).

#### 15c. Login rate limiting

Separate rate limiter for `/portal/api/auth/login` (not the main IP rate limiter):
- 5 attempts per examiner per 5 minutes
- Lockout message with time remaining
- Already partially implemented via `_check_commit_lockout` — extend for login

#### 15d. Secure headers

Add to portal responses:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
```

The `unsafe-inline` for style-src covers the inline `<style>` block in index.html. Script nonces
(removing `unsafe-inline` for scripts) is Phase 15e future work.

---

## Verification Checklist (End-to-End)

Run these after each phase to confirm nothing has regressed. The installer-first portal workflow
must have functional, resilience, and security tests; do not accept one-off manual success as proof.

```bash
# 1. All packages install cleanly
uv sync --all-packages

# 2. No vhir namespace leaks
grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "agentir_plugin"
# Expect: 0 lines

# 3. agentir-core tests pass
uv run pytest packages/agentir-core/tests/ -v --tb=short

# 4. Gateway starts before a case exists
uv run sift-gateway --config configs/gateway.yaml.template
# Expect: starts without error; case-dependent tools return clear "no active case" errors until portal case creation

# 5. Gateway health
curl -k https://127.0.0.1:4508/api/v1/health
# Expect: {"status": "ok"}

# 6. Portal HTTPS enforcement (when TLS configured)
curl http://127.0.0.1:4508/portal/
# Expect: 400 "Portal requires HTTPS"

# 7. Nonce consumed on use
# POST /portal/api/commit/challenge to get challenge_id
# POST /portal/api/commit with the challenge_id (valid password)
# POST /portal/api/commit AGAIN with same challenge_id
# Expect: 401 "Invalid or expired challenge"

# 8. Nonce IP binding
# Issue challenge from 127.0.0.1
# POST commit from different IP (if testable)
# Expect: 403 "Challenge IP mismatch"

# 9. Origin validation (CSRF test)
curl -X POST https://127.0.0.1:4508/mcp \
  -H "Origin: http://evil.example.com" \
  -H "Authorization: Bearer $AGENTIR_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# Expect: 403

# 10. Token expiry
# Set expires_at to a past ISO timestamp in gateway.yaml api_keys
# Restart gateway
# Make a tool call
# Expect: 401 or 403

# 11. Rate limit (per-examiner)
# Fire 121 requests in <60s as same examiner
# Expect: 429 after burst exhausted

# 12. opensearch TLS configurable
# Set verify_certs: false in gateway.yaml opensearch section
# Expect: connects without cert error; CERT_NONE only when explicitly configured

# 13. Import smoke tests
uv run python -c "from case_dashboard.routes import create_dashboard_v2_app; print('OK')"
uv run python -c "from sift_gateway.server import Gateway; print('OK')"
uv run python -c "from case_mcp.server import create_server; print('OK')"
uv run python -c "from agentir_core.case_io import get_case_dir; print('OK')"
```

### Workflow Acceptance Tests

Installer readiness:
- Run installer in a clean SIFT-like VM/container and verify it is idempotent.
- Verify generated TLS certs exist and gateway refuses plain HTTP portal access when TLS is configured.
- Verify OpenSearch container is running, healthy, bound only to `127.0.0.1:9200`, and templates are installed.
- Verify enrichment/RAG assets are present and searchable or report a clear degraded mode.
- Verify systemd user service survives restart and gateway health passes after reboot/session restart.

Portal authentication:
- Login with installer default examiner account requires password reset before any case/token operation.
- After reset, old temporary password fails and new password succeeds.
- Session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, path-limited, and expiry-checked.
- Commit still requires HMAC password confirmation even with a valid session.

Portal case creation:
- `POST /api/v1/case/create` creates the full canonical case tree from valid metadata.
- Invalid case ids, path traversal, relative paths, existing non-empty directories, and unwritable roots are rejected.
- `gateway.yaml → case.dir` update is atomic; simulated failure cannot leave partial YAML.
- `AGENTIR_CASE_DIR` updates in process and reaches all restarted backends.
- Concurrent case-create requests serialize safely; one wins and the other returns a clear conflict.

Aggregate MCP gateway:
- Hermes config contains only `https://SIFT_VM:4508/mcp`.
- Service token can list/call allowed aggregate tools through `/mcp`.
- Service token is rejected from portal APIs.
- Per-backend MCP URLs are disabled in production config or require explicit diagnostic opt-in with the same auth/audit path.
- Gateway audit records include request id, principal role, token id, agent id/examiner, tool/backend, status, duration, and active case.
- Raw bearer tokens and HMAC responses never appear in logs.

Agent token lifecycle:
- Installer-generated service token works.
- Examiner can create an additional agent token from the portal; the raw token is shown once.
- Token metadata list never reveals raw token values.
- Revoked/rotated/expired tokens fail for MCP and record appropriate audit events.
- Two agents using different service tokens produce separable gateway logs.

Enrichment and response integrity:
- Gateway-enriched MCP responses keep raw backend output distinguishable from added context.
- Enrichment failures degrade gracefully and do not break the underlying tool response unless policy requires it.
- Enrichment additions are either logged or represented in structured response metadata.

Chain of custody:
- Findings/timeline writes remain atomic/protected.
- HMAC ledger entry is appended for approvals.
- Report generation excludes DRAFT/REJECTED items and includes only APPROVED items.
