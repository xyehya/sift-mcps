# TASKS.md — Execution Tracker

## Current State

**Phase:** Phase B COMPLETE (Groups 1+2 deployed and verified on SIFT VM). Group 3 (tool consolidation) next.
**Next:** Group 3a — Unify opensearch-mcp ingest tools (5→1).
**Tests:** 1,551 passing across all packages (+25 from Phase B).
**SIFT VM:** 192.168.122.81 (sansforensics/forensics). Gateway live with Phase B changes, 79 tools, 56 readOnlyHint, 11 categories, 5 phase tags.
**Verify:** Live aggregate MCP at `https://192.168.122.81:4508/mcp` (token in Quick Reference).

```bash
# Verify tests (run per-package)
uv run python -m pytest packages/agentir-core/ --tb=short -q       # 225
uv run python -m pytest packages/case-dashboard/ --tb=short -q     # 243
uv run python -m pytest packages/sift-gateway/ --tb=short -q       # 104
uv run python -m pytest packages/case-mcp/ --tb=short -q           # 23
uv run python -m pytest packages/opensearch-mcp/ --tb=short -q     # 906
uv run python -m pytest packages/sift-mcp/ --tb=short -q           # 3
uv run python -m pytest packages/report-mcp/ --tb=short -q         # 31
uv run python -m pytest packages/forensic-mcp/ --tb=short -q       # 16

# Remediation gate
bash scripts/remediation-gate.sh

# Sync to SIFT VM
rsync -avz --exclude '.git' --exclude '.venv' --exclude '__pycache__' \
  /home/yk/AI/SIFTHACK/sift-mcps/ sansforensics@192.168.122.81:~/sift-mcps-test/
```

---

## Active Tasks — Phase B: Tool Surface Optimization 🟡 P1

Goal: Transform 78 flat, uncategorized tools into a structured, navigable surface
that enables autonomous DFIR orchestration.

Tool audit completed 2026-05-25 → `docs/tool-audit-2026-05-25.md`.

### Group 1 — Fix What's Broken 🔴 (blocks everything else)

#### 1a — Fix `get_tools_list()` Annotations Propagation

- [x] In `packages/sift-gateway/src/sift_gateway/server.py:474-479`, `get_tools_list()`
  constructs new `Tool` objects with only `name`, `description`, `inputSchema` —
  discarding `annotations`, `outputSchema`, `icons`, `meta`, `execution`.
  Fix: propagate ALL fields from the backend's `Tool` object, especially `annotations`.
- [x] Verified live on SIFT VM — 56/79 tools show readOnlyHint (was 0/78).
- [x] **Deployed and verified on SIFT VM 2026-05-25.**

#### 1b — Add Evidence Chain Detection to `workflow_status`

- [x] Call `chain_status()` from `agentir_core.evidence_chain` inside `workflow_status`.
  - On OK → normal phase detection continues
  - On UNSEALED → add "seal evidence first" to next_steps
  - On MODIFIED/MISSING/UNREGISTERED/LEDGER_ERROR → phase = "EVIDENCE_VIOLATION",
    next_steps = HITL signal directing examiner to portal for reseal + HMAC verify.
    All other tool calls are blocked by the gate — the agent MUST know this from
    the entry point, not from a failed tool call.
- [x] Inject `_agentir_context.evidence_gate` into workflow_status response so the
  agent sees the same structured warning the gate would inject.
- [x] Tests: evidence OK, evidence UNSEALED, evidence MODIFIED, evidence MISSING,
  evidence UNREGISTERED, evidence LEDGER_ERROR.

#### 1c — Add `readOnlyHint` to All Read-Only Tools

- [x] **opencti-mcp** (8 tools): Add `annotations={"readOnlyHint": True}` to all
  `Tool(...)` constructors in `packages/opencti-mcp/src/opencti_mcp/server.py`.
  All 8 are read-only (search/lookup/get operations).
- [x] **windows-triage-mcp** (13 tools): Same — all baseline checks are read-only.
  File: `packages/windows-triage-mcp/src/windows_triage_mcp/server.py`.
- [x] **sift-mcp** (4 tools): `list_available_tools`, `get_tool_help`, `check_tools`,
  `suggest_tools` need `readOnlyHint=True` in `packages/sift-mcp/src/sift_mcp/server.py`.
  `run_command` remains without (it executes commands).
- [x] **forensic-mcp** (4 tools): `get_findings`, `get_timeline`, `get_actions`,
  `list_todos` need `readOnlyHint=True` in `packages/forensic-mcp/src/forensic_mcp/server.py`.
  `workflow_status` already has it (B1).
- [x] **report-mcp** (3 tools): `get_case_metadata`, `list_profiles`, `list_reports`
  need `readOnlyHint=True` in `packages/report-mcp/src/report_mcp/server.py`.
- [x] **case-mcp**: Already correct — 7 read-only tools annotated, 7 write tools not.
  Verify no changes needed.
- [x] **forensic-rag-mcp**: Already correct — all 3 annotated. Verify no changes needed.
- [x] **opensearch-mcp**: Already correct — 11 query tools annotated, 9 write tools not.
  Verify `idx_ingest_status` has it.
- [x] Tests: verify each backend's tool list shows correct `readOnlyHint` on read-only tools.

---

### Group 2 — B2-B5: Tool Surface Structure 🟡

#### B2 — Add `container_inspect` Tool

- [x] Add `idx_inspect_container(path)` to `packages/opensearch-mcp/src/opensearch_mcp/server.py`
  - Uses `ewfinfo` (present on SIFT) for E01 metadata without mounting
  - Returns: `{partitions[], filesystem_type, artifact_estimates{evtx_count, registry_hives}, auto_detected_hostname}`
  - Annotated: `readOnlyHint=True`
  - Handles: E01, raw image, non-container path (graceful error)
- [x] Tests: E01 file, raw image, non-container path

#### B3 — Add `environment_summary` Tool

- [x] Add to gateway aggregate tools (new module `packages/sift-gateway/src/sift_gateway/env_summary.py`
  or inline in `mcp_endpoint.py`)
  - Collapses: case_status + evidence_list + OS health + RAG availability +
    OpenCTI connectivity + triage DB status + OpenSearch cluster health
  - Returns single structured dict with all backend health in one call
  - Annotated: `readOnlyHint=True`
- [x] Tests: all backends healthy, degraded modes (OpenSearch down, OpenCTI down, etc.)

#### B4 — Prune Deprecated/Portal-Only Tools from Agent View

- [x] Filter `evidence_register` from agent `tools/list()` response
  - Gateway filter in `_build_tool_map()` or `get_tools_list()` based on `role=agent`
  - Portal/examiner still sees it via per-backend endpoints
  - File: `packages/sift-gateway/src/sift_gateway/server.py`
- [x] Also filter: `case_init`, `case_activate` (dead code, not even registered as tools)
  - Clean up the dead inner functions from `case-mcp/server.py`
- [x] Consider filtering admin tools from agent view:
  - `idx_install_pipelines` (opensearch-mcp) — cluster admin, not investigation
  - `case_host_fix` (opensearch-mcp) — data correction, rare
  - `backup_case` (case-mcp) — examiner operation
  - This is debatable — flag for discussion

#### B5 — Add Tool Categories to Aggregate Listing

- [x] Add `_category` metadata to each tool in aggregate `tools/list()` response
  - Categories: `session-start`, `evidence-survey`, `ingest`, `search-analysis`,
    `enrichment`, `detection`, `baseline-check`, `findings`, `reporting`, `admin`
  - Map each of the 78 tools to a category
  - Gateway enriches the `Tool` object with category in `_meta` or `annotations`
  - File: `packages/sift-gateway/src/sift_gateway/server.py` `get_tools_list()`
- [x] Add `_recommended_for_phase` annotation (preview of Phase D2):
  - ORIENT → case_status, evidence_list, evidence_verify
  - SEALED → idx_ingest, container_inspect
  - TRIAGE → idx_case_summary, idx_search, idx_aggregate, search_knowledge, lookup_ioc
  - FINDINGS → get_findings, record_finding, record_timeline_event
  - REPORTING → generate_report, save_report
- [x] Tests: verify each tool has a category; verify phase-appropriate tools are tagged

**Deployment verified 2026-05-25 on SIFT VM:**
- Live aggregate MCP: 79 tools, 56 readOnlyHint, 11 categories, 5 phase tags
- Categories: admin(4) baseline-check(13) detection(5) enrichment(3) evidence-survey(4) findings(12) ingest(7) reporting(6) search-analysis(11) session-start(4) threat-intel(8)
- Phases: ORIENT(8) SEALED(3) TRIAGE(29) FINDINGS(12) REPORTING(6)
- 2 unmapped tools: case_list, idx_shard_status (both Group 3 cleanup targets)
- Bugs fixed: get_tools_list() dropped annotations, category mapping used wrong prefixed names (only get_health collides), environment_summary meta ordering, Pydantic _meta alias
- Restart: `systemctl --user restart sift-gateway`

---

### Group 3 — Tool Consolidation 🟢 (design complete, implement after G1+G2)

#### 3a — Unify Ingest Tools

- [ ] Merge `idx_ingest_json`, `idx_ingest_delimited`, `idx_ingest_accesslog` into
  `idx_ingest` with a `format` parameter (`auto`|`json`|`delimited`|`accesslog`|`memory`).
  `idx_ingest_memory` also folds in. Default `auto` detects format from file extension.
  - Reduces 6 ingest-surface tools to 1 primary + 1 status (`idx_ingest_status`).
  - Keep old tool names as aliases for one release cycle, log deprecation warning.

#### 3b — Unify Windows Triage Lookups

- [ ] Merge `check_file`, `check_hash`, `check_lolbin`, `analyze_filename` into
  `check_artifact(path="", hash="", filename="")` — one entry point for artifact checks.
- [ ] Merge `check_service`, `check_scheduled_task`, `check_autorun` into
  `check_windows_artifact(type, name, ...)` — one pattern for system artifacts.
- [ ] Keep `check_process_tree`, `check_registry`, `check_hijackable_dll`, `check_pipe`
  as standalone (distinct enough signatures).
- [ ] Target: 13 tools → ~8 tools.

#### 3c — Unify OpenCTI Search

- [ ] Merge `search_threat_intel` + `search_entity` into single `search_intel`
  with optional `entity_type` filter. When omitted → broad search across all types.
  When provided → type-specific with higher result limits.
- [ ] Target: 8 tools → 7 tools.

#### 3d — Add Description Examples

- [ ] Add concise examples to key tool descriptions (top 15 most-used tools).
  Example format: `"Example: idx_search(query='event.code:4624 AND user.name:admin')"`

---

## Phase C: Ingestion Resilience 🟡 P2

### C1 — E01 Hostname Auto-Discovery

- [ ] Modify `idx_ingest` so `hostname` parameter is optional
  - When omitted: mount E01 → read SYSTEM registry hive → extract ComputerName → use as hostname → unmount
  - Files: `packages/opensearch-mcp/src/opensearch_mcp/server.py`, `ingest_cli.py`

### C2 — Ingestion Progress Streaming

- [ ] Add lightweight `idx_ingest_progress(run_id)` tool
  - Returns: `{progress_pct, current_artifact, eta_seconds}`
  - Faster than full `idx_ingest_status` — only reads the status JSON
  - Annotated: `readOnlyHint=True`

### C3 — Ingest Failure Recovery

- [ ] Add `--resume` support to ingest pipeline
  - Skip already-indexed artifacts on re-run of same case/host
  - File: `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`

---

## Phase D: Agent Workflow Engine 🟢 P3

### D1 — Investigation State Machine

- [ ] Add `investigation_state.json` to case directory
  - Tools: `get_investigation_phase()`, `advance_phase(phase)`
  - Phases: ORIENT → SURVEY → INGEST → TRIAGE → DEEP_DIVE → DETECTION → FINDINGS → REPORTING
  - Phase transitions enforce prerequisites
  - File: `packages/forensic-mcp/src/forensic_mcp/server.py`

### D2 — Phase-Aware Tool Filtering

- [ ] Gateway annotates tools with `_recommended_for_phase` based on current investigation phase
  - File: `packages/sift-gateway/src/sift_gateway/server.py`

### D3 — Investigation Playbook Engine

- [ ] Tools: `start_playbook(name)`, `get_next_playbook_step()`
  - Playbooks: ransomware, data_exfil, BEC, insider_threat, malware_outbreak
  - Each step specifies exact tool calls with parameters
  - File: `packages/forensic-mcp/src/forensic_mcp/server.py`

---

## Phase E: Production Hardening 🟢 P3

### E1 — RAG Health Check on Startup

- [ ] Verify index exists at `RAGServer.__init__` — fail fast with clear message
  - Pre-warm embedding model in background thread (don't block first query)
  - Already partially done: `_check_index()` warns, `load()` checks ChromaDB first

### E2 — Gateway Startup Health Check

- [ ] Verify all backends + OpenSearch + OpenCTI + RAG index + triage DBs
  - Report degradations clearly in health endpoint

### E3 — Agent Session State Export

- [ ] Export investigation state on gateway shutdown / case switch
  - Next agent session can resume from where it left off

---

## Phase 17: OS-Level Evidence Hardening

Prerequisites: Phase 16 complete. Target: Ubuntu 24.04 (SIFT VM).

- [ ] **17a — chattr +i Immutable Flag**
  - `agentir_core/evidence_chain.py`: `_set_immutable(path, bool)` via fcntl ioctl
  - Wire into `seal_manifest()` and `retire_file()`
  - `install.sh`: `setcap cap_linux_immutable+ep` on Python interpreter
  - Portal: show immutable status per file

- [ ] **17b — auditd Rules**
  - Add `configs/audit/99-agentir-evidence.rules`
  - `install.sh`: install auditd, write rules, enable service (already wired, needs validation)

- [ ] **17c — AppArmor Profile (Ubuntu only)**
  - Template updated with /tmp/**, forensic tooling, case working dirs
  - Needs reloading on SIFT VM and validation with `aa-logprof`
  - Switch from complain to enforce after validation

- [ ] **17d — inotify Evidence Watcher**
  - `sift_gateway/evidence_watcher.py`: asyncio inotify via ctypes
  - Wire from server.py on case activation
  - Immediate gate cache invalidation on filesystem events

- [ ] **17e — IMA xattr (Optional)**
  - `_set_ima_hash(path)` via evmctl
  - `install.sh --enable-ima` flag

---

## Docs

- [ ] Write `docs/analyst-machine-setup.md` (Liquefy deployment on analyst machine)
- [ ] Solana anchoring user-facing docs (already implemented in Phase 16e/16f)

---

## Completed Work (Summarized)

| Phase | Key Outcome |
|-------|-------------|
| 0-2 | vhir→agentir sweep, workspace scaffold, agentir-core hardened (225 tests) |
| 3-4 | Portal HTTPS, gateway auth/rate-limit |
| 5-6 | forensic-rag FastMCP migration, sift-mcp sanitization |
| 7-9 | install.sh, Docker Compose, configs/templates |
| 11 | Windows triage backend (SQLite, 13 tools) |
| 12-15 | Portal auth, agent RBAC, dashboard rewiring, session hardening |
| 16 | Evidence manifest + ledger + two-tier gate + Solana anchoring (550+ tests) |
| R0-R4 | 93-tool audit, active case propagation, path resolution, portal-first language |
| **A-1** | RAG index auto-build via install.sh (22,268 records, startup health check, fail-fast model loading) |
| **A-2** | hayabusa auto-install via install.sh (v3.9.0, 4,947 YAML rules, `--skip-hayabusa` flag) |
| **A-3** | E01 ingest pipeline: 4-strategy sudo xmount/ntfs-3g ladder, safe_rglob across 7 files, non-fatal SHA-256 hashing, AmcacheParser --nl fix, TLS cert localhost SAN, AppArmor template update. Verified: 38,805 docs indexed across 12 artifact types |

---

## Recent Session Notes

**Session 50 — 2026-05-25 — Hardened Installer + RAG/Venv Fixes:**

Three issues diagnosed and fixed:

1. **forensic-rag-mcp `ModuleNotFoundError`**: `rag-mcp` was in `full` extra but VM used `--extra standard` for `uv sync`. Package never installed. Fixed by moving to standard, installing 73 ML packages (chromadb, torch, sentence-transformers). Subsequently moved back to `full` when install.sh was redesigned to always use `--extra full`.

2. **RAG "Output validation error: outputSchema defined but no structured output returned"**: FastMCP generates `outputSchema` from `-> dict[str, Any]` but not from bare `-> dict`. When outputSchema is present, FastMCP expects `structuredContent` but tools return plain text content. Fixed by changing return type annotations: `-> dict[str, Any]` → `-> dict` in `search_knowledge`, `list_knowledge_sources`, `get_knowledge_stats` (`packages/forensic-rag-mcp/src/rag_mcp/server.py`). Verified: all 3 tools now return `outputSchema=None`, matching all other working tools. RAG tools functional: `search_knowledge` returns 5 results for "ransomware", `list_knowledge_sources` lists 67 sources.

3. **Venv corruption from Python version mismatch**: The VM's venv was Python 3.11 but `uv sync --python /usr/bin/python3.12` triggered a full venv rebuild, dropping all 165 packages. Fixed by running `uv sync --extra full` which reinstalled everything.

**Hardened install.sh rewrite:**
- Uses `/usr/bin/python3.12` (SIFT native) — no uv-managed Python
- Always `--extra full` (single path, no feature toggles)
- Zero required arguments — `./install.sh` just works
- OpenCTI auto-detected: Docker + ≥14 GB RAM
- Venv integrity check: mismatched or broken venvs are rebuilt before sync
- Post-sync verification: import-smoke test of critical packages
- All backends always enabled (RAG, windows-triage always ON)
- Every step idempotent — `"already exists — preserving"`
- Tested: 2 full iterations on SIFT VM, all 8 backends healthy, 80 tools, RAG tools verified

**Updated:**
- `install.sh` — complete rewrite (hardened, idempotent)
- `pyproject.toml` — `rag-mcp` in `full` extra (used by installer's `--extra full`)
- `SESSION-PROMPT.md` — updated sync/reinstall instructions
- `packages/forensic-rag-mcp/src/rag_mcp/server.py` — outputSchema fix

**Current state:** 8/8 backends healthy, 80 tools, status "ok". RAG tools working. Gateway uses system Python 3.12 consistently.

Implemented `workflow_status` tool in `packages/forensic-mcp/src/forensic_mcp/server.py`:
- Single "what do I do now?" entry point replacing 7+ discovery calls
- 7-phase detection: ORIENT → SEALED → INGESTING → TRIAGE → FINDINGS → REPORTING (+ NO_CASE)
- Detects case state from: CASE.yaml, evidence-manifest.json (with evidence.json fallback), ~/.agentir/ingest-status/*.json, findings.json, timeline.json
- Returns structured response with phase, evidence_summary, indexing_status, findings_summary, timeline_events, available_capabilities, next_steps[]
- Annotated `readOnlyHint=True`
- 10 tests: all 7 phases + no-case + evidence.json fallback + complete-trumps-failed priority
- All existing tests pass (agentir-core 225, case-dashboard 243, sift-gateway 104, case-mcp 23, opensearch-mcp 906, sift-mcp 3, report-mcp 31, forensic-mcp 10 = 1,545 total)
- Remediation gate: PASSED. Namespace sweep: clean.
- 3 pre-existing opensearch-mcp test failures (AmcacheParser --nl removal, container mount) — unrelated to B1

**Session 49 — 2026-05-25 — Phase B Groups 1+2 COMPLETE (DEPLOYED & VERIFIED):**

Complete tool surface optimization — 78 flat tools → 79 structured tools with annotations, categories, and phase recommendations. All changes deployed to SIFT VM and verified via live MCP requests.

**Group 1 — Fix What's Broken (deployed):**
- 1a: Fixed `get_tools_list()` annotations propagation (server.py:474-479). Previously dropped `annotations`, `outputSchema`, `icons`, `meta`, `execution` from live backend tools. Now preserves all 9 Tool fields. Verified: 56/79 tools show readOnlyHint (was 0/78).
- 1b: Added evidence chain detection to `workflow_status`. Calls `chain_status()` from `agentir_core.evidence_chain` (same function the gateway uses). On MODIFIED/MISSING/UNREGISTERED/LEDGER_ERROR → `phase="EVIDENCE_VIOLATION"` with HITL next_steps directing examiner to portal. On UNSEALED → normal phase detection with "write tools BLOCKED" note. 16 tests.
- 1c: Added `readOnlyHint=True` to 32 read-only tools across 5 backends (opencti-mcp 8, windows-triage-mcp 13, sift-mcp 4, forensic-mcp 4, report-mcp 3). Used `ToolAnnotations(readOnlyHint=True)` for plain-Tool backends, decorator annotations for FastMCP backends.

**Group 2 — Tool Surface Structure (deployed):**
- B2: `idx_inspect_container(path)` in opensearch-mcp. Uses ewfinfo/fdisk/img_stat. readOnlyHint=True. Category: evidence-survey, Phase: SEALED.
- B3: `environment_summary` synthetic gateway tool. Queries 7 backends (8s timeout each). Category: session-start, Phase: ORIENT.
- B4: Filtered `evidence_register` and `idx_install_pipelines` from agent view. Removed dead `case_init`/`case_activate` from case-mcp. Cleaned imports.
- B5: 11 tool categories + 5 phase recommendations on every tool via `_meta`. Only `get_health` collides across backends; all other tools use unprefixed names.

**Deployment verification (SIFT VM):**
- Code synced via rsync, gateway restarted via `systemctl --user restart sift-gateway`
- Aggregate MCP: 79 tools, 56 readOnlyHint, 11 categories, 5 phase tags
- All key tools verified: workflow_status [RO] session-start/ORIENT, environment_summary [RO] session-start/ORIENT, idx_inspect_container [RO] evidence-survey/SEALED, idx_search [RO] search-analysis/TRIAGE, lookup_ioc [RO] threat-intel/TRIAGE, record_finding findings/FINDINGS, check_file [RO] baseline-check/TRIAGE
- 2 unmapped tools: case_list, idx_shard_status (Group 3 cleanup targets)
- Bugs found+fixed during deployment: annotations dropped by get_tools_list(), category mapping prefixed names (only get_health collides), environment_summary appended after annotation loop, Pydantic _meta alias confirmed

**Test results:**
- agentir-core: 225, case-dashboard: 243, sift-gateway: 104, case-mcp: 23, opensearch-mcp: 906, sift-mcp: 3, report-mcp: 31, forensic-mcp: 16
- Total: 1,551 passing. Remediation gate: PASSED. Namespace sweep: clean.
- 3 pre-existing opensearch-mcp failures (AmcacheParser --nl, container mount) — unchanged

**Group 3 Optimization Plans (7 subagents completed — NOT yet implemented):**
- Full proposals in docs/tool-audit-2026-05-25.md
- case-mcp: 14→13 (remove evidence_register, merge case_list→case_status, export_bundle compact mode)
- forensic-mcp: 10→6 (query_case replaces 3 query tools, manage_todo replaces 3 CRUD tools)
- sift-mcp: 5→3 (discover_tools replaces 3 discovery tools, run_command 8→5 params)
- opensearch-mcp: 21→12 (unify 5 ingest→1 idx_ingest(format=), remove 5 admin tools)
- opencti-mcp: 8→7 (merge search_threat_intel+search_entity→search_entities)
- windows-triage-mcp: 13→6 (check_artifact replaces 5, check_system replaces 3, server_status replaces 2)
- report-mcp: 6→5 (merge list_profiles+list_reports→list, set_metadata batch fields dict)
- Overall target: 80→55 tools (31% reduction)

**Restart procedure (for future sessions):**
```bash
rsync -avz --exclude '.git' --exclude '.venv' --exclude '__pycache__' \
  /home/yk/AI/SIFTHACK/sift-mcps/ sansforensics@192.168.122.81:~/sift-mcps-test/
ssh sansforensics@192.168.122.81 'systemctl --user restart sift-gateway'
# Wait 10s, then verify: curl -s -k https://192.168.122.81:4508/api/v1/health
```

A-2: Added `install_hayabusa()` to install.sh (downloads latest release binary + bundled 4,947 YAML rules, ZIP validation, `--skip-hayabusa` flag). Added `install_hayabusa_system_links()` for /usr/local/bin symlink. Fixed `_HAYABUSA_RULES_CANDIDATES` in ingest.py to include `~/.agentir/hayabusa-rules`. Fixed installer to not overwrite `rules/config` with binary `config/`. Verified: Hayabusa v3.9.0 ELF binary, 4,947 rules, `_resolve_hayabusa_rules_dir()` returns correct path.

A-3: Diagnosed and fixed 5 E01 ingest bugs through live SIFT VM testing:
1. **Mount failure**: ewfmount FUSE files can't be loop-mounted (kernel "Can't lookup blockdev"). Fixed with 4-strategy ladder: sudo xmount→ntfs-3g (works), xmount→loop, ewfmount→loop, ewfmount→direct.
2. **xmount 0.7.6 compat**: --allow-other not supported. Fixed with `sudo xmount`.
3. **rglob crashes**: Corrupted NTFS junctions cause OSError. Fixed with `safe_rglob()` in `discover.py`, applied across 7 files.
4. **Large file hashing**: FUSE EOVERFLOW on >2GB reads. Fixed with non-fatal hash in `manifest.py`.
5. **AmcacheParser --nl**: Crashes on dirty hives (90%+ of forensic images). Removed `--nl` flag in `tools.py`.
Added `configure_fuse()` to install.sh (user_allow_other in /etc/fuse.conf). Fixed TLS cert SAN to include DNS:localhost. Updated AppArmor template with /tmp/**, /usr/local/bin/*, forensic tooling paths.
Verified: 38,805 documents indexed across 12 artifact types (evtx, prefetch, srum, registry, shimcache, jumplists, tasks, lnk, shellbags, recyclebin, wer, httperr) in 0.5 minutes. `idx_case_summary` returns complete case overview.

**Session 51 — 2026-05-26 — Flattened opensearch-mcp into monorepo:**

- Converted `packages/opensearch-mcp` from an orphan gitlink/submodule-style entry into normal files tracked by the main `sift-mcps` repository.
- Preserved recovery artifacts before flattening:
  - `/home/yk/opensearch-mcp-history.bundle` — verified full nested-repo history bundle.
  - `/home/yk/opensearch-mcp-staged-changes.patch` — binary patch for staged nested-repo worktree changes.
  - `/home/yk/opensearch-mcp.git.backup` — moved nested `.git` directory.
- Verification: parent index no longer has mode `160000` for `packages/opensearch-mcp`; namespace sweep returned 0 lines.
- Tests: `uv run python -m pytest packages/opensearch-mcp/ --tb=short -q` still reports the 3 known pre-existing failures (`test_cleanup_fuse_and_nbd`, two Amcache `--nl` assertions): 906 passed, 71 skipped, 3 failed.

---

## Quick Reference

```
SIFT VM:              192.168.122.81 (sansforensics/forensics)
Active case:          /cases/test-rocba-2026
Evidence:             23GB E01 (rocba-cdrive.e01), sealed, INGESTED (38,805 docs, 12 indices)
OpenSearch:           http://127.0.0.1:9200 (admin/admin), 12 case-* indices + 18 opencti_* indices
OpenCTI:              http://127.0.0.1:8080 (healthy), MITRE ATT&CK + CISA KEV connectors active
RAG index:            22,268 records, search verified (<5s)
hayabusa:             v3.9.0 at ~/.agentir/bin/, 4,947 YAML rules at ~/.agentir/hayabusa-rules/
Gateway:              https://192.168.122.81:4508 (running, 8 backends healthy)
Gateway health:       https://192.168.122.81:4508/api/v1/health
Portal:               https://192.168.122.81:4508/portal/
TLS cert SAN:         IP:192.168.122.81, IP:127.0.0.1, DNS:siftworkstation, DNS:localhost
AppArmor:             REMOVED (was blocking /tmp) — re-enable after aa-logprof validation
Active agent token:   agentir_svc_b5152580b0cd2ce8003ee5c9a5c559537b322741f21d4f03

Key binaries:         xmount ✓, ewfmount ✓, ntfs-3g ✓, AmcacheParser ✓, MFTECmd ✓
                      AppCompatCacheParser ✓, RECmd ✓, JLECmd ✓, LECmd ✓, SBECmd ✓
                      hayabusa ✓ (v3.9.0), passwordless sudo ✓
```
