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
6. The examiner copies or mounts case evidence into the case `evidence/` directory, then uses the
   portal evidence intake flow to hash, manifest, and ledger-seal the evidence set before agent
   investigation proceeds.

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
- SHA-256 hashes on every registered evidence file, recorded in a versioned evidence manifest
- Append-only `approvals.jsonl` — never modified, only appended
- HMAC verification ledger at `/var/lib/agentir/verification/{case-id}.jsonl`
- All the above is implemented in `agentir-core` — do not duplicate in other packages

### R3. Human-in-the-loop for all findings and cases
Findings proposed by Hermes are DRAFT. They enter the portal's pending-reviews queue.
The examiner reviews, optionally modifies, and commits via HMAC-SHA256 challenge-response.
Only committed findings are APPROVED and included in the final report.
The examiner/operator starts each investigation in the portal by creating or selecting the case.
The CLI (`agentir`) is a maintenance/emergency fallback, not the primary interface.

### R3b. Evidence intake is examiner-controlled and append-only
Evidence may be discovered after the case is created. The system must allow legitimate additions
without breaking the case, but only through an explicit examiner-controlled chain-of-custody flow.
Manual files copied into `evidence/` are not automatically trusted. The portal must detect
unregistered files, show a clear warning, and let the examiner either register/seal them or mark
them unintended. Registering new evidence appends a new manifest version and ledger event; it never
silently rewrites historical evidence state. Existing registered evidence that is modified or
missing must be treated as a chain-of-custody violation until resolved by the examiner.

The original/current `case-mcp` evidence tools are retained as compatibility surfaces, not as the
final authority. `evidence_register`, `evidence_list`, and `evidence_verify` currently manage
`evidence.json`; Phase 16 upgrades them to delegate to the evidence manifest/ledger model. Agent
tokens may read evidence-chain status but must not seal, ignore, or mutate evidence state through
MCP.

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

### R7. windows-triage-mcp is retained; wintools-mcp is dropped
`windows-triage-mcp` is the local/offline Windows baseline validation and enrichment backend
from the original SIFT package. It provides deterministic known-good lookups for files, process
trees, services, scheduled tasks, autoruns, registry keys, LOLDrivers hashes, LOLBins, hijackable
DLLs, named pipes, and filename deception. It runs on the SIFT VM as a gateway-managed stdio
backend and must be restored under the `agentir` namespace.

The real original implementation lives at `/home/yk/AI/SIFTHACK/sift-mcp/packages/windows-triage/`
and is SQLite-backed, not JSON-backed. Its runtime databases are:
- `known_good.db` — Windows file/path/hash plus service/task/autorun baselines
- `context.db` — LOLBAS, LOLDrivers, HijackLibs, process expectations, suspicious filenames/pipes
- `known_good_registry.db` — optional full registry baseline

The package includes a release downloader (`windows_triage.scripts.download_databases`) that pulls
`known_good.db.zst`, `context.db.zst`, and `checksums.sha256` from `AppliedIR/sift-mcp`
`triage-db-*` GitHub releases, verifies checksums and row-count thresholds, then decompresses the
SQLite databases. It also includes builder/import scripts under `scripts/` for rebuilding from
VanillaWindowsReference, VanillaWindowsRegistryHives, LOLBAS, LOLDrivers, and HijackLibs. Phase 11
must port this SQLite-backed behavior. The current reconstructed JSON-backed scaffold is not
sufficient for acceptance; use it only as temporary test scaffolding until replaced.

`wintools-mcp` is different: it is the separate Windows host execution backend that runs forensic
tools on a dedicated Windows machine. That backend remains out of scope for this portable SIFT VM
runtime. Do not restore Windows host execution, SMB share orchestration, or direct Windows command
execution.

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

## Current State (as of Session 21 — 2026-05-24)

### What Is Done ✅
- **Phase 0 COMPLETE** — all blocking bugs fixed, namespace sweep finished, verification gate passed
- **Phase 1 COMPLETE** — uv workspace scaffold, all packages, agentir-core extracted
- **Phase 2b COMPLETE** — agentir-core library hardening done
- **Phase 3 COMPLETE** — portal HTTPS/CORS/nonce/error hardening done
- **Phase 4a-4d COMPLETE** — shared auth helper, token expiry, examiner rate limit, Origin validation, extractor dedupe done
- **Phase 4e RESEARCH DONE / IMPLEMENTATION DEFERRED** — `mcp==1.27.1` has `ServerSession.send_tool_list_changed()` but `StreamableHTTPSessionManager` exposes no public session lifecycle hook
- **Phase 5 COMPLETE** — forensic-rag-mcp migrated to FastMCP
- **Phase 6 COMPLETE** — sift-mcp argument sanitizer now rejects null bytes, rejects >4096-char args, and NFC-normalizes Unicode
- **Phase 7 COMPLETE** — `install.sh` foundation: TLS gen, token gen, default examiner, systemd, gateway config render; live VM run still pending
- **Phase 8 COMPLETE** — `docker-compose.yml`: OpenSearch 2.18.0, localhost-only, snapshots bind mount, `agentir-opensearch` container name
- **Phase 9 COMPLETE** — `configs/gateway.yaml.template`, `configs/hermes-forensics-profile.yaml`, `configs/systemd/sift-gateway.service`
- **Phase 12-pre COMPLETE** — R8 domain-separated HMAC sub-keys (`derive_auth_key`, `derive_ledger_key`)
- **Phase 12a-12c COMPLETE** — `session_jwt.py`, `portal_session_secret` wiring, `PortalSessionMiddleware`
- **Phase 12d COMPLETE** — 7 auth endpoints (setup, challenge, login, reset-password, logout, me); R1/R2/R3/R6/R8 guards; 36 tests
- **Phase 12e COMPLETE** — `_resolve_examiner` env-var fallback removed (R9); must_reset checks on all write routes (R1)
- **Phase 12f COMPLETE** — gateway R4 agent→portal block; portal paths bypass gateway auth; 8 tests
- **Threat model complete (Session 14)** — 9 security guards (R1-R9) specified; all guards from Phase 12 are now implemented
- **Evidence chain-of-custody feature newly specified (Session 16)** — Phase 16 adds versioned evidence manifest, evidence ledger, portal warnings/actions, and gateway MCP fail-closed gate
- **Windows baseline correction newly specified (Session 18)** — restore `windows-triage-mcp` as a SIFT-local baseline/enrichment backend; continue dropping only `wintools-mcp`
- **Windows baseline source audit corrected (Session 21)** — original SQLite-backed source exists at `/home/yk/AI/SIFTHACK/sift-mcp/packages/windows-triage`; Phase 11 must port that implementation and DB downloader, not keep the JSON scaffold
- **agentir-core tests: 139/139 passing**
- **case-dashboard tests: 75/75 passing**
- **sift-gateway tests: 8/8 passing**
- `grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."` → **0 lines**

### What Needs Fixing Next (See TASKS.md)

**Priority 0 — Phase 11: Restore Windows baseline backend**
- Replace the temporary JSON scaffold with the original SQLite-backed `windows-triage-mcp` implementation from `/home/yk/AI/SIFTHACK/sift-mcp/packages/windows-triage`
- Port the prebuilt DB downloader for `known_good.db.zst` and `context.db.zst` into the installer flow, targeting `/var/lib/agentir/windows-triage`
- Preserve clear degraded behavior when DB assets are absent or invalid; never stamp false trusted enrichment
- Keep dropping only `wintools-mcp`, the separate Windows host execution backend
- Cross-check restored tool calls against `Reference MCP Toolsfrom original Valhuntir Documentation.md`
- Verify `opensearch-mcp::idx_enrich_triage` uses the restored backend through the gateway path

**Priority 1 — Phase 13: RBAC, agent credentials, portal route guards**
- 13a: `token_gen.py` — `generate_service_token()` and fix `generate_gateway_token()`
- 13b: readonly→403 on MCP writes (R4 agent→portal already done in Phase 12f)
- 13c: `_require_examiner_role()` helper; apply to delta/commit/token/case-create routes
- 13f: Portal service-token lifecycle endpoints

**Priority 2 — Phase 13/14/15: RBAC, dashboard rewiring, session hardening**
- Portal RBAC, service-token lifecycle, dashboard auth rewiring, login screen, case-init modal, secure headers

**Priority 3 — Audit invariant / regression guard**
- Tool actions are audited today, but not yet in the final gateway-envelope shape for every backend.
- Phase 13 must close the gap: every aggregate `/mcp` `call_tool` writes a minimal `sift-gateway.jsonl` envelope (role, token id, agent id/examiner, source IP, active case, tool, backend, status, duration). Link to backend `audit_id` via `backend_audit_id`. Never log raw tokens or HMAC responses.

**Priority 4 — Phase 7 live validation (non-blocking for Phase 12)**
- Run `install.sh` on clean Ubuntu/SIFT VM, verify `docker compose up -d` → OpenSearch healthy, `https://127.0.0.1:4508/health` responds.

**Priority 5 — New Phase 16: Evidence manifest + evidence ledger chain gate**
- Implement after/alongside portal case creation and auth, because it depends on authenticated
  examiner actions and active `AGENTIR_CASE_DIR`.
- Manual files copied into `evidence/` must trigger portal warnings until registered/sealed.
- Agent MCP calls must verify the evidence chain before backend routing and block with a structured
  human-remediation warning on unsealed, unregistered, modified, missing, or ledger-mismatched evidence.

**Phase 4e — Deferred**
- `notifications/tools/list_changed` requires SDK session lifecycle hooks not yet exposed by `mcp==1.27.1`.

### Pre-Implementation Security Requirements (R1–R9)

These guards are non-negotiable additions to Phase 12-15. Full specs in SIFT-MCPS-PLAN.md §Phase 12 Security Requirements. One-line summaries for quick reference:

- **R1** `must_reset_password` re-read from disk before every write operation — JWT is a UI hint only
- **R2** Separate lockout counter namespace: `login:{examiner}` vs. `commit:{examiner}` — never cross-pollute
- **R3** Fake challenge for unknown examiners — always return a valid-looking challenge to prevent user enumeration
- **R4** Agent→403 on `/portal/api/` co-ships with Phase 12 — not deferred to Phase 13
- **R5** `os.path.realpath` symlink guard + `threading.Lock` on case create — prevent path escape and race
- **R6** Login challenge pool capped at 200 entries, per-examiner limit of 5 in-flight
- **R7** Enrichment appended as `_agentir_context` metadata key only — never interpolated into tool result text (prompt injection defense)
- **R8** Domain-separated HMAC sub-keys before any production case data: `derive_auth_key()` for login, `derive_ledger_key()` for verification ledger
- **R9** `getattr(request.state, "examiner", None)` everywhere — never direct attribute access
- **R10** Evidence chain gate before MCP operations — gateway verifies evidence manifest/ledger state
  before routing agent tool calls; mismatch, missing registered evidence, or unregistered files
  blocks the call and returns a structured warning for human-in-the-loop remediation.

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

### Evidence manifest and chain-of-custody gate
The case-local `evidence/` directory is a controlled intake area. Operators may copy or mount newly
discovered evidence there, but the runtime must not treat those files as trusted until the examiner
uses the portal evidence security chain to register and seal them. The evidence chain creates
`evidence-manifest.json` plus append-only evidence ledger events recording file path, size, SHA-256,
source notes, examiner, timestamp, previous manifest hash, and new manifest hash. Gateway MCP calls
must verify that the live `evidence/` tree matches the latest sealed manifest before routing agent
operations. If verification fails, the agent receives a structured block response instructing the
human operator to use the portal; the gateway does not run the backend tool.

---

## Package Summary

| Package | Purpose | State |
|---------|---------|-------|
| `agentir-core` | Shared library: case I/O, auth, HMAC, identity, evidence chain | Evidence manifest/ledger helpers needed for new Phase 16 |
| `sift-gateway` | HTTP gateway, auth, routing, portal mount | Phase 12 wiring plus new evidence chain gate before MCP routing |
| `case-dashboard` | Examiner Portal Starlette sub-app | Phase 12-15 plus evidence intake warnings/actions in new Phase 16 |
| `forensic-mcp` | Record findings, timeline events | ✅ No changes needed |
| `case-mcp` | Case lifecycle (init, status, join, evidence registry) | Needs evidence-chain-aware register/list/verify behavior |
| `sift-mcp` | Run forensic tools via shell=False | Must stay behind gateway evidence chain gate |
| `report-mcp` | Generate final case report | Must include evidence manifest/ledger status and fail/warn on evidence mismatch |
| `forensic-rag-mcp` | Semantic search over forensic knowledge | ✅ Phase 5 complete |
| `windows-triage-mcp` | Local Windows known-good baseline validation and OpenSearch enrichment support | Must port original SQLite-backed implementation + DB downloader from `/home/yk/AI/SIFTHACK/sift-mcp/packages/windows-triage`; current JSON scaffold is temporary |
| `opencti-mcp` | Threat intel enrichment via OpenCTI | ✅ No changes needed |
| `opensearch-mcp` | SIEM evidence indexing and search | ✅ TLS fix + OPENSEARCH_CONFIG env done |
| `sift-common` | AuditWriter, oplog, parsers | `resolve_examiner()` duplicates identity — fix on touch only |
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
