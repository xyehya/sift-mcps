# AgentIR — Security Controls

This document enumerates every security control in AgentIR, the threat each addresses, and the specific implementation. Controls are grouped by the attack surface they protect.

---

## 1. Transport Security

### TLS 1.2+ with Per-Installation CA

**Threat:** Network-level interception of agent tool calls or examiner portal sessions.

**Implementation:**
- `install.sh` generates a self-signed CA and server keypair on every fresh installation using `openssl req`
- Server certificate is bound to the SIFT VM's IP/hostname
- Clients (Hermes, browser) trust the CA cert; it is provided in the operator handoff material
- TLS termination is at the Starlette/uvicorn layer; private key is `chmod 600` and owned by the service account
- Key material is stored in `~/.agentir/` (AppArmor profile restricts read access to the gateway process)

**Files:** `install.sh:generate_tls()`, `configs/gateway.yaml.template`

---

## 2. Authentication

### Bearer Token Authentication

**Threat:** Unauthenticated access to MCP tool calls or portal endpoints.

**Implementation:**
- Every request to `/mcp` requires a `Authorization: Bearer <token>` header
- Two token types: `agentir_gw_*` (examiner fallback) and `agentir_svc_*` (Hermes service agent)
- Tokens are cryptographically random, stored in `/var/lib/agentir/tokens/`, and have configurable expiry
- Invalid or expired tokens return 401; the token value is never logged (only its SHA-256 fingerprint)
- `AuthMiddleware` extracts examiner identity, role, and token_id (first 16 hex chars of SHA-256) and adds them to request state for downstream audit use

**Files:** `sift_gateway/auth.py`, `sift_core/token_ops.py`

### PBKDF2 Portal Password (HMAC Challenge-Response)

**Threat:** Brute-force or replay attack on examiner password; password exposure in transit.

**Implementation:**
- Examiner passwords are stored as PBKDF2-HMAC-SHA256 with 600,000 iterations and a random salt (NIST SP 800-132 compliant)
- Portal login uses a challenge-response protocol: server issues a nonce, browser computes `HMAC(stored_hash, nonce)`, server re-derives and compares with constant-time comparison
- The password itself never travels over the wire — only its PBKDF2 hash is used as the HMAC key
- Challenge nonces are single-use, IP-bound, and expire after 5 minutes
- Challenge domains are separated: login challenges, evidence-seal challenges, and response-guard override challenges each use independent stores

**Files:** `sift_core/approval_auth.py`, `case_dashboard/routes.py`

### Domain-Separated Key Derivation

**Threat:** Key reuse across security contexts allowing cross-domain forgeries.

**Implementation:**
- Auth key: `HKDF(stored_hash, info=b"agentir-auth-v1")` — used for login HMAC
- Ledger signing key: `HKDF(stored_hash, info=b"agentir-signing-v1")` — used for evidence ledger HMAC events
- These keys are derived independently and cannot be substituted for each other
- A compromised login challenge cannot forge a ledger event, and vice versa

**Files:** `sift_core/verification.py:derive_auth_key`, `sift_core/verification.py:derive_ledger_key`

---

## 3. Authorization

### Role-Based Access Control (RBAC)

**Threat:** Agent (Hermes) performing examiner-level operations; examiner performing administrative operations.

**Implementation:**
- Two roles: `examiner` and `service-agent`
- Every portal endpoint declares its minimum required role via `_require_portal_role(request)`
- `service-agent` tokens can call MCP tools and read case status but cannot seal evidence, approve findings, or rotate tokens
- `examiner` role required for any evidence-chain mutation, finding commitment, or token management
- Role is embedded in the token and verified at `AuthMiddleware` level — it cannot be escalated by a request parameter

**Files:** `sift_gateway/auth.py`, `case_dashboard/routes.py`

### Must-Reset Password Guard

**Threat:** An attacker using the installer-generated default password before the examiner changes it.

**Implementation:**
- Installer creates the default examiner account with `must_reset_password: true` in the password entry
- `must_reset_password` is re-read from disk on every write operation (not cached in the session)
- Any write endpoint returns 403 with `reason: "must_reset_password"` until the password is changed
- Read-only endpoints and the password-reset endpoint itself are exempt
- This makes the default-credentials window operationally zero: the examiner cannot do anything meaningful without resetting first

**Files:** `case_dashboard/routes.py:R1`, `case_dashboard/middleware.py`

### Session Security

**Threat:** Session hijacking, fixation, CSRF, and session persistence after logout.

**Implementation:**
- Sessions use JWT cookies with `HttpOnly`, `Secure`, `SameSite=Strict` attributes
- JWT tokens use HMAC-SHA256 with a per-installation randomly generated secret
- Sliding session refresh: tokens are re-issued on each authenticated request, extending the window
- JTI revocation: logout invalidates the specific JWT ID; the revocation list is checked on every request
- Login lockout: 5 failed attempts triggers a lockout stored to disk (survives gateway restarts)
- Concurrent login protection: only the most recent JWT JTI is valid per examiner (re-login invalidates old sessions)

**Files:** `case_dashboard/session_jwt.py`, `case_dashboard/middleware.py`

---

## 4. Agent Containment

### No Direct Shell Access

**Threat:** AI agent executing arbitrary commands on the SIFT VM.

**Implementation:**
- Hermes communicates with the SIFT VM only via HTTPS to the MCP endpoint
- The MCP endpoint routes to stdio backends; no direct shell or filesystem access
- `sift-mcp` is the only backend that executes system commands, and it uses `subprocess.run(shell=False)` exclusively
- `sift-mcp` maintains an explicit allow-list of approved binaries; commands not on the list are rejected before execution
- Command arguments are individually validated; shell metacharacters are not interpreted
- Output is byte-limited to prevent exfiltration via oversized responses

**Files:** `sift_mcp/server.py`, `sift_mcp/security.py`

### Evidence Gate — Pre-Tool-Call Chain Verification

**Threat:** AI agent operating on tampered, unsealed, or unregistered evidence — creating a chain-of-custody break.

**Implementation:**
The evidence gate runs before every `/mcp` tool call and enforces the following two-tier policy:

| Chain Status | Tool Type | Decision |
|---|---|---|
| OK (sealed, clean) | Any | Pass |
| UNSEALED (no manifest yet) | `readOnlyHint: true` | Pass + inject warning annotation |
| UNSEALED | Analysis / write tool | Block — return `evidence_chain_unsealed` |
| MODIFIED / MISSING / UNREGISTERED / LEDGER_ERROR | Any | Block — return `evidence_chain_violation` |

- The gate result is cached for 30 seconds to avoid rehashing on every call
- An inotify watcher immediately invalidates the cache on any `evidence/` filesystem event
- A chain violation blocks **all** tools (including read-only) until the examiner resolves it in the portal
- Blocked responses include `blocked: true`, `reason`, issue counts, and `portal_url` for remediation guidance

**Files:** `sift_gateway/evidence_gate.py`, `sift_gateway/mcp_endpoint.py`, `sift_gateway/evidence_watcher.py`

### Response Guard — Secret Redaction

**Threat:** API keys, passwords, SSH private keys, tokens, and PII surfacing in agent tool output and being stored in agent memory or logs.

**Implementation:**
- Every tool response is scanned by `response_guard.scan_tool_result()` before being returned to Hermes
- 25 patterns across three severity tiers:
  - **Critical (15 patterns):** AWS/GCP/Azure credentials, SSH private keys, JWT tokens, API keys, certificate private keys
  - **High (7 patterns):** bearer tokens, generic API keys, database connection strings, Stripe/Twilio keys
  - **Medium (2 patterns):** email addresses, IP addresses in certain contexts
- Critical and high matches are redacted inline: `[REDACTED:aws_access_key]`
- Medium matches are flagged with a `_agentir_context.secret_warning` annotation (not redacted, surfaced to examiner)
- Redaction events are logged to the gateway audit with `{pattern_name, severity, char_offset}` — the matched value itself is never logged
- Examiner can temporarily disable redaction via HMAC challenge-response (same auth pattern as evidence seal), with audit log entry and automatic expiry after 10 minutes

**Files:** `sift_gateway/response_guard.py`, `sift_gateway/mcp_endpoint.py`

---

## 5. Evidence Chain of Custody

See [evidence-chain-of-custody.md](evidence-chain-of-custody.md) for the complete design.

### Summary of controls in this layer:

| Control | Implementation |
|---------|---------------|
| SHA-256 per evidence file | `sift_core/evidence_chain.py:hash_file` |
| Forward-linked HMAC chain | Each ledger event includes HMAC of event content + `derive_ledger_key` |
| Append-only ledger | `evidence-ledger.jsonl`: `chmod 0444`, `fsync` after each event |
| Versioned manifest | `previous_manifest_hash` links each version to its predecessor |
| Path traversal protection | `_resolve_evidence_path` blocks `../` and symlink escapes |
| RETIRED entry carry-forward | Retired files preserved in manifest; re-seal cannot re-register them as unregistered |
| Solana SPL Memo anchoring | Public timestamped hash commitment after each seal |

---

## 6. OS-Level Hardening

See [dfir-hardening-guide.md](dfir-hardening-guide.md) for the complete guide.

### `chattr +i` Immutable Flag (Phase 17a)

**Threat:** Accidental or deliberate modification of sealed evidence files outside the portal.

**Implementation:**
- `seal_manifest()` clears `-i` before hashing each file (required for re-seal) and sets `+i` on each file after the ledger event is written
- Requires `CAP_LINUX_IMMUTABLE` — granted to the uv-managed Python binary via `setcap cap_linux_immutable+ep`
- `get_immutable_flag(path)` is exposed via the portal evidence status API — the portal shows per-file immutable status
- If `setcap` was not run (EPERM), the code logs a warning and degrades gracefully — the cryptographic ledger remains authoritative

**Files:** `sift_core/evidence_chain.py:_set_immutable`, `sift_core/evidence_chain.py:get_immutable_flag`

### Kernel Audit (auditd) — Phase 17b

**Threat:** Deliberate `chattr -i` before tampering, or direct writes to case files, going unrecorded.

**Implementation:**
- `configs/audit/99-agentir-evidence.rules` installs two rules:
  - `perm=wa` on the cases root: records every write and attribute-change in `evidence/`
  - `perm=wa` on `/var/lib/agentir`: records writes to the password/token/verification stores
- `perm=a` (attribute change) specifically captures `chattr -i` — the kernel records the UID, PID, binary path, and timestamp of anyone who clears the immutable flag
- Rules are loaded via `augenrules --load` (survives reboot via `/etc/audit/rules.d/`)
- Query: `ausearch -k agentir_evidence_write --format text`

**Files:** `configs/audit/99-agentir-evidence.rules`, `install.sh:configure_auditd()`

### AppArmor MAC Profile — Phase 17c

**Threat:** Gateway process compromise leading to writes to evidence files.

**Implementation:**
- Profile key rules:
  - `r` on `evidence/**` — gateway can hash files
  - `deny w` on `evidence/**` — gateway process cannot write to evidence files at the OS level
  - `rw` on manifest/ledger/audit/approvals files — gateway can update metadata
  - `network inet tcp` / `deny network udp,raw` — localhost TCP only
  - `deny /bin/bash, /bin/sh, ...` — no shell execution
- Profile is loaded in **complain mode** by default (logs violations, does not block)
- Run `sudo aa-logprof` after exercising all gateway paths, then `sudo aa-enforce /etc/apparmor.d/sift-gateway` to switch to enforce mode
- The profile targets the uv-managed Python binary path (substituted by `install.sh` at deploy time)

**Files:** `configs/apparmor/sift-gateway.template`, `install.sh:configure_apparmor()`

### inotify Evidence Watcher — Phase 17d

**Threat:** Evidence modification between 30-second TTL cache refreshes going undetected until the next tool call.

**Implementation:**
- `evidence_watcher.watch_evidence_dir()` is started as a background asyncio task in the gateway lifespan
- Uses Linux inotify via ctypes/libc.so.6 (no external dependencies)
- Watches `case_dir/evidence/` for `IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED`
- On any event: immediately calls `invalidate_evidence_cache(case_dir_str)` — next tool call will re-verify
- Blocking read in a thread pool (no O_NONBLOCK); fd close at shutdown cleanly unblocks the thread
- Graceful fallback on non-Linux, NTFS/NFS/FUSE: logs warning and falls back to 30s TTL

**Files:** `sift_gateway/evidence_watcher.py`, `sift_gateway/server.py:lifespan`

---

## 7. Audit Trail

### Gateway JSONL Audit Envelope

**Threat:** AI agent actions being unattributable — no record of what Hermes called, when, with what result.

**Implementation:**
- Every `/mcp` `call_tool` request writes a structured JSON entry to `sift-gateway.jsonl` regardless of outcome (success, error, blocked, transport error)
- Entry includes: `ts`, `examiner`, `role`, `token_id` (fingerprint only), `source_ip`, `backend`, `tool_name`, `status`, `elapsed_ms`, `evidence_gate_result`, `redacted_patterns`, `backend_audit_id`
- The raw token value is never logged
- Tool parameters are not logged (backends own that in their per-backend JSONL)

**Files:** `sift_gateway/mcp_endpoint.py`, `sift_common/audit.py`

### Per-Backend JSONL Audit Logs

**Threat:** Backend-level operations (specific commands, queries, file operations) going unrecorded.

**Implementation:**
- Each backend writes its own `audit/{backend-name}.jsonl` with operation-specific fields
- `case-mcp` logs every case operation including examiner identity from `AGENTIR_EXAMINER`
- `sift-mcp` logs every command: binary, arguments, exit code, output length, duration
- Gateway `backend_audit_id` links gateway envelope to the specific backend log entry

### Approval Audit Log

**Threat:** Finding approval being disputed — no independent record of what the examiner approved.

**Implementation:**
- `approvals.jsonl` is append-only and records every examiner commit with: timestamp, examiner, action, item type, item hash, challenge_id
- The challenge_id links the approval to the original HMAC challenge (proving a password was verified)
- File is `chmod 0444` — no application path silently overwrites it

**Files:** `sift_core/approval_auth.py`, `case_dashboard/routes.py`

---

## 8. Report Integrity

### Evidence Chain State in Report

**Threat:** A forensics report being issued when the evidence it's based on is unsealed, tampered, or has outstanding integrity issues.

**Implementation:**
- `report-mcp` embeds the evidence chain state in every generated report:
  - Manifest version and hash
  - Chain status (OK / UNSEALED / MODIFIED / MISSING / UNREGISTERED / LEDGER_ERROR)
  - ok_count and issues list
- If status is UNSEALED: report includes `evidence_chain_warning` with explicit "evidence was not sealed before this report was generated" language
- If status is MODIFIED/MISSING/UNREGISTERED/LEDGER_ERROR: report includes `integrity_warning` with "Do NOT distribute this report" language
- This makes evidence chain state visible to any downstream recipient of the report

**Files:** `report_mcp/server.py`

---

## Control Traceability

| Phase | Control | Tests |
|-------|---------|-------|
| Phase 3 | Portal security hardening (RBAC, session, headers) | 36 |
| Phase 12 | Portal authentication (PBKDF2, HMAC challenge-response) | 36 |
| Phase 13 | Agent RBAC, token management | 28 |
| Phase 15 | Session hardening (JWT revocation, sliding refresh, lockout, headers) | 5 |
| Phase 16-pre | Evidence chain core (manifest, ledger, HMAC, diff) | 53 |
| Phase 16a | Portal evidence intake endpoints | 32 |
| Phase 16b | Gateway evidence gate + 30s TTL cache | 17 |
| Phase 16c | case-mcp evidence integration | 15 |
| Phase 16-retire | retire_file + immutability + diff exclusion | 14 |
| Phase 16-gate-tier | Two-tier gate (UNSEALED vs violation) | 7 |
| Phase 16d | report-mcp evidence chain embedding | 31 |
| Phase 16-verify-remind | HMAC verify reminder, verify-state tracking | 20 |
| Phase 16e | Solana SPL Memo anchoring | 6 |
| Phase 17d | inotify watcher (unit coverage) | within sift-gateway 99 |
| Audit Invariant | Gateway JSONL envelope | 15 |
| Liquefy/Approach C | Response guard (25 patterns, override) | 40 |

**Total: 547 tests**
