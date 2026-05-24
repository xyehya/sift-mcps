# sift-mcps — Project Brief for Claude Code

## What We Are Building

A portable, secure MCP (Model Context Protocol) runtime installable on any SIFT Workstation VM.
The goal: allow a Hermes AI agent (running on a **separate analyst machine**) to drive digital
forensics investigations through authenticated HTTPS tool calls — without ever being granted direct
shell access to the VM. The examiner reviews AI-proposed findings in a browser portal and commits
them with HMAC-authenticated password verification. The final product is a signed, auditable report.

The required end-user workflow is installer-first and portal-first:
1. The operator runs one installer on the SIFT VM.
2. The installer provisions Python packages, gateway, portal UI, OpenSearch Docker, enrichment/RAG assets,
   TLS material, systemd service, default examiner credentials, and at least one Hermes service token.
3. The operator signs into the portal, resets the default password on first login, and creates a new case.
4. Portal case creation writes the complete case directory from the submitted `CASE.yaml` metadata,
   updates the gateway's active case, and restarts/reloads backends as needed.
5. Hermes connects only to the gateway aggregate MCP endpoint with a service token.

```
Analyst Machine                        SIFT VM (sift-mcps installed)
────────────────              ─────────────────────────────────────────
Hermes Agent ────HTTPS────▶  sift-gateway :4508
Browser      ────HTTPS────▶    │
                               ├── /mcp                (only agent MCP entry point; aggregate)
                               └── /portal/            (Examiner Portal — login, case create, review)
                                         │
                               agentir-core library ──▶ /var/lib/agentir/
                                                        passwords/, verification/
```

**Hermes runs the investigation. The examiner reviews and approves in the portal. report-mcp
generates the final signed deliverable. Chain of custody is preserved at every step.**

---

## Project File Locations

**Working repo:** `/home/yk/AI/SIFTHACK/sift-mcps/`
**Source repos (read-only reference):**
- `/home/yk/AI/SIFTHACK/Valhuntir/` — original CLI (uses `vhir_cli` namespace internally — ignore that)
- `/home/yk/AI/SIFTHACK/Valhuntir/sift-mcp/` — original sift-mcp monorepo
- `/home/yk/AI/SIFTHACK/Valhuntir/opensearch-mcp/` — original opensearch-mcp
- `/home/yk/AI/SIFTHACK/hermes-agent/` — Hermes agent

Valhuntir's README is useful context for the original workflow, but sift-mcps is not a direct
replication. We cherry-pick useful functions and ideas, then improve, decouple, harden, and make
the runtime portable/flexible around the installer-first, portal-first workflow.

**Plan file:** `SIFT-MCPS-PLAN.md` — normative architecture/spec and acceptance criteria
**Task tracker:** `TASKS.md` — execution checklist, session ledger, and current next steps

---

## Session Rules (Non-Negotiable)

1. **Read `TASKS.md` at the start of every session.** It tracks current state, blockers, and next steps.
2. **Treat `SIFT-MCPS-PLAN.md` as the grounded spec.** Tests and task checklists should trace back to it.
3. **Update `TASKS.md` as you complete each task.** Mark `[x]` immediately on completion.
4. **Add session notes to `TASKS.md` before stopping.** Capture in-progress state, discoveries, blockers.
5. **When plan and task contradict — stop and ask the user.**
6. **Never use `vhir`, `VHIR`, `vhir_cli`, `~/.vhir`, `/var/lib/vhir` anywhere.** The namespace is `agentir`. The sweep is complete — the grep gate (`grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."`) must return 0 lines.
7. **Test after every structural change:** `uv run pytest packages/agentir-core/tests/ -v --tb=short`
8. **Do not rewrite whole files unless required.** Targeted edits only.
9. **agentir-core is a library — do not add `sys.exit()` calls to it.** Raise exceptions instead. See R8.

---

## Core Non-Negotiable Design Requirements

These are settled. Do not re-debate them; implement them exactly.

### R1. Agent never gets direct shell — sift-mcp is the controlled gate
All command execution goes through `sift-mcp` which uses `subprocess.run(shell=False)`,
argument sanitization, allowed-binary catalog, path validation, output byte limits,
and per-command audit logging.

### R2. Chain of custody at every write
- Atomic writes (`tempfile.mkstemp` + `os.replace`) for all case files
- `chmod 444` protection on findings.json, timeline.json after write
- SHA-256 content hashes on every finding/timeline event
- Append-only `approvals.jsonl` — never modified, only appended
- HMAC verification ledger at `/var/lib/agentir/verification/{case-id}.jsonl`
- All the above is implemented in `agentir-core` — do not duplicate in other packages

### R3. Human-in-the-loop for all findings and cases
Findings proposed by Hermes are DRAFT. They enter the portal's pending-reviews queue.
The examiner reviews, optionally modifies, and commits via HMAC-SHA256 challenge-response.
Only committed findings are APPROVED and included in the final report.
The examiner/operator starts each investigation in the portal by creating or selecting the case.
The CLI (`agentir`) is a maintenance/emergency fallback, not the primary interface.

### R4. Portal-created case directory is the primary workflow
The installer prepares the VM, but the examiner/operator creates each new case from the portal.
The portal accepts case metadata, creates the chosen case directory and canonical files, atomically
updates `gateway.yaml → case.dir`, sets `AGENTIR_CASE_DIR` in the gateway process, and reloads or
restarts backends so every MCP sees the same active case.

```bash
# Primary examiner workflow:
open https://SIFT_VM:4508/portal/
# Sign in, reset default password if required, click New Case, submit CASE.yaml metadata.
```

All code — case-mcp tools, portal endpoints, report-mcp, validators, tests — reads
`AGENTIR_CASE_DIR` env var as the single source of truth. The `~/.agentir/active_case`
file pointer is intentionally not part of this repo's runtime contract. Manual `gateway.yaml`
editing remains an administrator fallback only.

### R5. All MCP transport over TLS
Self-signed CA generated at install time. Hermes configures `REQUESTS_CA_BUNDLE` or
adds the CA to its OS trust store. The gateway listens on HTTPS only for remote access.
The portal returns HTTP 400 if accessed over plain HTTP when TLS is configured.

### R6. Bearer token auth, timing-safe, expiry-checked
Two token types:
- `agentir_gw_{48hex}` — examiner token, 192-bit entropy; used for examiner API fallback and scripted maintenance
- `agentir_svc_{48hex}` — Hermes agent service token, 192-bit entropy; used in mcp.json

Both in `gateway.yaml → api_keys` with `role: examiner` or `role: agent`.
`expires_at` ISO datetime field must be checked in both `auth.py` (REST) and `mcp_endpoint.py` (MCP).
Timing-safe comparison with `hmac.compare_digest`. Expiry failure → 403.

The installer generates the first service token. The portal must also provide an examiner-only token
management flow for creating, listing metadata for, revoking, and rotating additional agent tokens.
Gateway audit logs must preserve principal separation (`examiner`, `agent_id`, `role`, token id)
for every request.

### R7. windows-triage-mcp is dropped
Do not reference, restore, or link to it anywhere.

### R7b. Gateway aggregate MCP is the only agent MCP entry point
Hermes and other agents connect only to `/mcp`. Per-backend MCP endpoints may exist internally for
development diagnostics, but they are not part of the supported agent workflow and must not be
published in Hermes config templates. The gateway owns auth, audit logging, examiner identity
injection, agent identity attribution, tool aggregation, and contextual enrichment of MCP responses.

### R8. agentir-core library design constraints (settled — do not deviate)
agentir-core is a pure library with one external dependency (PyYAML). It must remain:
- **No `sys.exit()` calls** — raise `CaseError`, `AuthError`, `LockoutError` instead. Let callers decide.
- **No hardcoded paths** — `VERIFICATION_DIR` and `_PASSWORDS_DIR` read from env vars with `/var/lib/agentir/…` as default. This enables testability without root.
- **No `subprocess.run(["sudo", …])`** — `_ensure_passwords_dir()` must raise `PermissionError` with manual instructions instead of calling sudo.
- **`gateway_cfg.py` does not belong here** — it will be moved to `sift-gateway` once Phase 12 lands (portal auth needs its own gateway client). Leave it in place until then; do not add more gateway connectivity code to agentir-core.
- **`sift-common/audit.py::resolve_examiner()`** duplicates `agentir_core.identity.get_examiner_identity()`. When touching sift-common, make it delegate to agentir-core. Do not fix proactively — only on touch.

These fixes were completed in TASKS.md Phase 2b.

---

## Current State (as of Session 10 — 2026-05-24)

### What Is Done ✅
- **Phase 0 COMPLETE** — all blocking bugs fixed, namespace sweep finished, verification gate passed
- **Phase 1 COMPLETE** — uv workspace scaffold, all packages, agentir-core extracted
- **Phase 2b COMPLETE** — agentir-core library hardening done
- **Phase 3 COMPLETE** — portal HTTPS/CORS/nonce/error hardening done
- **Phase 4a-4d COMPLETE** — shared auth helper, token expiry, examiner rate limit, Origin validation, extractor dedupe done
- **Phase 4e RESEARCH DONE / IMPLEMENTATION DEFERRED** — current Python MCP SDK `mcp==1.27.1` has `ServerSession.send_tool_list_changed()`, but `StreamableHTTPSessionManager` exposes no public active-session lifecycle hook
- **Phase 5 COMPLETE** — forensic-rag-mcp migrated to FastMCP
- **Phase 6 COMPLETE** — sift-mcp argument sanitizer now rejects null bytes, rejects >4096-char args, and NFC-normalizes Unicode
- **Documentation tracking unified** — plan is spec, task tracker is execution ledger, AGENTS is operating brief
- **Final workflow clarified** — installer prepares SIFT VM; portal creates cases; Hermes uses aggregate `/mcp`; gateway separates identities and enriches responses
- **agentir-core tests: 125/125 passing**
- `grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."` → **0 lines**
- case-dashboard now imports from agentir-core (no more duplicated logic)
- gateway config propagates `AGENTIR_CASE_DIR`; `_get_active_case()` dead code deleted
- opensearch-mcp TLS fix: configurable `verify_certs` + `ca_cert_path`
- `agentir_plugin.py` replaces `vhir_plugin.py` with correct entry point group

### What Needs Fixing Next (See TASKS.md)

**Priority 1 — Phase 7+: deployment foundation**
- Phase 7 install script
- Phase 8 OpenSearch compose
- Phase 9 config templates

**Priority 2 — Phase 4e implementation decision**
- Current SDK finding: `mcp==1.27.1` is current and `uv pip install --upgrade mcp --dry-run` found no newer MCP SDK.
- `StreamableHTTPSessionManager` exposes only `run()` and `handle_request()`; it privately tracks transports, not active `ServerSession` objects.
- `ServerSession.send_tool_list_changed()` exists, but implementing active-session notification requires deferring for SDK hooks or adding a local session-tracking `Server` wrapper/subclass.

**Priority 3 — Audit invariant / regression guard**
- The central audit repository is the active case `audit/` directory. `sift_common.audit.AuditWriter` writes append-only JSONL there (`AGENTIR_AUDIT_DIR` or `AGENTIR_CASE_DIR/audit/`), one file per writer/MCP, with flush + fsync.
- Existing evidence/provenance readers aggregate `audit/*.jsonl`; backend `audit_id`s are canonical evidence IDs used by findings and reports. Do not replace or stop returning them.
- The HMAC verification ledger is separate at `/var/lib/agentir/verification/{case-id}.jsonl`; it proves examiner-approved findings/timeline entries, not raw tool execution.
- Tool actions are audited today, but not yet in the final gateway-envelope shape for every backend. Stdio backends write detailed per-backend evidence logs; gateway proxy audit is currently centralized for `HttpMCPBackend` paths, which are not part of the final normal SIFT backend set.
- Phase 13/integration must close the remaining gap so every aggregate `/mcp` `call_tool` writes a minimal `sift-gateway.jsonl` envelope: request/correlation id, role, token id, agent id or examiner, source IP, active case, aggregate tool, resolved backend, status, duration, and result/truncation summary. Link to backend logs with `backend_audit_id` when available. Never log raw tokens or HMAC responses.

**Priority 4 — Phase 12-15: Portal auth (login UI + sessions)**
- JWT sessions, forced first-login reset, portal case creation, service token lifecycle, RBAC
- See TASKS.md Phase 12-15 for full design

---

## Key Architectural Decisions

### Gateway as aggregator
The gateway aggregate endpoint `/mcp` is the only supported agent MCP entry point.
Backends are stdio subprocesses (FastMCP). The gateway proxy-routes tool calls, enforces auth,
audits, enriches responses, and manages backend lifecycle. Per-backend endpoints, if retained,
are diagnostic-only and must use the same auth/audit path; Hermes templates must not publish them.

### agentir-core is the single source of truth
case_io, approval_auth, verification, identity — all live in `agentir-core`.
No other package reimplements these. case-dashboard and case-mcp import from agentir-core.
If you find duplicate implementations, delete the duplicate and import from agentir-core.

### FastMCP for all backends
All backends use FastMCP decorator style. forensic-rag-mcp is the only exception — it needs
migration. The low-level `mcp.server.Server` approach is for gateway internals only.

### Examiner identity injection
The gateway injects `analyst_override=examiner` into tool calls for tools in `ANALYST_TOOLS`
(forensic-mcp and case-mcp tools that record findings/actions). This prevents Hermes from
spoofing its own identity in audit records.

### Agent identity and enrichment
The gateway identifies Hermes by service token metadata and logs agent calls separately from examiner
portal actions. MCP responses returned through the aggregate gateway can be enriched with contextual
forensic guidance, provenance reminders, and next-step suggestions sourced from forensic-knowledge,
OpenSearch, and forensic-rag without granting the agent direct backend or shell access.

---

## Package Summary

| Package | Purpose | State |
|---------|---------|-------|
| `agentir-core` | Shared library: case I/O, auth, HMAC, identity | ✅ Phase 2b hardening done |
| `sift-gateway` | HTTP gateway, auth, routing, portal mount | ✅ Phase 3/4a-4d done — Phase 4e/13/15 next |
| `case-dashboard` | Examiner Portal Starlette sub-app | ✅ Phase 3 done — Phase 12/14/15 auth+UI next |
| `forensic-mcp` | Record findings, timeline events | ✅ No changes needed |
| `case-mcp` | Case lifecycle (init, status, join) | ✅ Imports fixed |
| `sift-mcp` | Run forensic tools via shell=False | Phase 6 arg hardening needed |
| `report-mcp` | Generate final case report | ✅ Imports fixed |
| `forensic-rag-mcp` | Semantic search over forensic knowledge | Phase 5: FastMCP migration needed |
| `opencti-mcp` | Threat intel enrichment via OpenCTI | ✅ No changes needed |
| `opensearch-mcp` | SIEM evidence indexing and search | ✅ TLS fix done (Phase 0d) |
| `sift-common` | AuditWriter, oplog, parsers | `resolve_examiner()` duplicates identity — fix on touch |
| `forensic-knowledge` | YAML forensic knowledge data | ✅ Unchanged |

---

## Working Commands

```bash
cd /home/yk/AI/SIFTHACK/sift-mcps

# Install all packages
uv sync --all-packages

# Run agentir-core tests
uv run pytest packages/agentir-core/tests/ -v --tb=short

# Run opensearch-mcp tests (many, all parser/ingest)
uv run pytest packages/opensearch-mcp/tests/ -v --tb=short

# Import smoke test
uv run python -c "from case_mcp.server import create_server; print('OK')"
uv run python -c "from agentir_core.case_io import get_case_dir; print('OK')"
uv run python -c "from agentir_core.approval_auth import verify_password; print('OK')"
```

<!-- SPECKIT START -->
For additional context about technologies to be used, project structure,
shell commands, and other important information, read the current plan
<!-- SPECKIT END -->
