

## Current State (2026-05-25 — end of Session 50)

**Phase B COMPLETE. Hardened installer deployed. Group 3 (tool consolidation) next.**

**Tests:** 1,551 passing. Remediation gate: PASSED. Namespace sweep: clean.

**SIFT VM:** 192.168.122.81
- User/pass: `sansforensics` / `forensics`
- Python: `/usr/bin/python3.12` (SIFT native, 3.12.3)
- Ubuntu 24.04.4 LTS (Noble Numbat)
- Gateway: `https://192.168.122.81:4508` (systemd user service)
- Portal: `https://192.168.122.81:4508/portal/`
- Active case: `test-rocba-2026`, 23GB E01 ingested (40,636 docs, 12 artifact types, 12 indices green)
- RAG index: 22,268 records (67 sources). Hayabusa: v3.9.0, 4,947 rules. OpenCTI: MITRE ATT&CK + CISA KEV live.
- Agent token: `agentir_svc_b5152580b0cd2ce8003ee5c9a5c559537b322741f21d4f03`

**Aggregate MCP (what the agent sees):** 80 tools, 56 readOnlyHint, 11 categories, 5 phase tags
- All 8 backends healthy — including forensic-rag-mcp (3 tools) and windows-triage-mcp (13 tools)
- Live verify: `curl -s -k https://192.168.122.81:4508/api/v1/health | python3 -m json.tool`
- MCP tools/list: initialize session at `/mcp`, then `tools/list` with session ID

**Key fixes applied this session (Session 50):**
- RAG `outputSchema` error fixed — `dict[str, Any]` → `dict` return types (FastMCP generates outputSchema only from parameterized generics)
- `rag-mcp` package installation fixed — was in `full` extra, now always installed via hardened installer
- Venv corruption fixed — Python 3.11→3.12 rebuild during sync dropped all packages; reinstalled 165 deps
- Hardened `install.sh` deployed — zero arguments, idempotent, system Python, single sync path

---

## Hardened Installer (install.sh)

**One command, no arguments, always safe to re-run:**

```bash
ssh sansforensics@192.168.122.81 'cd ~/sift-mcps-test && bash install.sh'
```

**Design invariants (do not break these):**
- Uses `/usr/bin/python3.12` — SIFT native, never downloads a different Python
- Always `uv sync --extra full` — all backends including RAG (single path, no feature toggles)
- `UV_NO_MANAGED_PYTHON=1`, `UV_PYTHON_DOWNLOADS=never` — enforced in installer and systemd service
- OpenCTI auto-detected: Docker available + ≥14 GB RAM → enabled automatically
- Every step is idempotent — checks "already done" before acting
- Venv integrity check: Python version mismatch → rebuild; broken imports → repair via sync
- Post-sync import verification: smokes `yaml`, `mcp`, `agentir_core`, `sift_gateway`



## Where We're Headin

7 subagents completed optimization designs for every backend. Target reductions:

| Backend | Current | Target | Key Changes |
|---------|---------|--------|-------------|
| case-mcp | 14 | 13 | Remove evidence_register, merge case_list→case_status |
| forensic-mcp | 10 | 6 | query_case(record_type) replaces 3 query tools, manage_todo(action) replaces 3 CRUD |
| sift-mcp | 5 | 3 | discover_tools replaces 3 discovery, run_command 8→5 params |
| opensearch-mcp | 21 | 12 | 5 ingest→1 idx_ingest(format=), remove admin tools |
| opencti-mcp | 8 | 7 | search_entities(entity_type=?) replaces 2 search tools |
| windows-triage-mcp | 13 | 6 | check_artifact(type,value) replaces 5, check_system replaces 3 |
| report-mcp | 6 | 5 | list(resource) replaces 2, set_metadata(fields={}) batch mode |
| forensic-rag-mcp | 3 | 3 | No changes (already optimal) |
| **Total** | **80** | **55** | **31% reduction** |

**Optimization principles:**
1. Discriminator fields replace tool proliferation — `format=`, `type=`, `action=`, `record_type=` instead of separate tools
2. Batch operations replace sequential calls — `set_metadata(fields={...})` instead of N calls
3. Dead/admin tools removed — `evidence_register`, `idx_install_pipelines`, `idx_shard_status`, `case_host_fix`
4. Descriptions rewritten — concise, directive, with examples (agent needs WHAT + WHEN in one sentence)
5. Parameters cleaned — remove redundant `analyst_override`, `case_id` on most tools, `input_files`, `preview_lines`, `skip_enrichment`



## Important Tasks

### Unify opensearch-mcp ingest tools (highest impact, start here)

Merge 5 ingest tools into `idx_ingest` with `format` parameter:
- Current: `idx_ingest` (auto-discovery), `idx_ingest_json`, `idx_ingest_delimited`, `idx_ingest_accesslog`, `idx_ingest_memory`
- New: `idx_ingest(path, format="auto", hostname, dry_run=True, ...format-specific params)`
  - `format="auto"` — existing auto-discovery + container detection
  - `format="json"` — current idx_ingest_json behavior
  - `format="delimited"` — current idx_ingest_delimited behavior
  - `format="accesslog"` — current idx_ingest_accesslog behavior
  - `format="memory"` — current idx_ingest_memory behavior (tier param)
- Remove from source: `idx_shard_status`, `idx_list_detections`, `case_host_fix`
- Keep: `idx_status` (cross-case cluster overview — NOT redundant, see [[idx_status-analysis]])
- File: `packages/opensearch-mcp/src/opensearch_mcp/server.py`
- Gateway: update category/phase maps in `packages/sift-gateway/src/sift_gateway/server.py`
- Tests: update `packages/opensearch-mcp/tests/`

### Unify windows-triage-mcp (13 → 6)

- `check_artifact(type, value)` unifies `check_file`, `check_hash`, `analyze_filename`, `check_lolbin`, `check_hijackable_dll`
- `check_system(type, name, os_version)` unifies `check_service`, `check_scheduled_task`, `check_autorun`
- `server_status` unifies `get_db_stats`, `get_health`
- Check wether functionally other tools can be unified eg: `check_process_tree`, `check_registry`, `check_pipe`
- File: `packages/windows-triage-mcp/src/windows_triage_mcp/server.py`

### Unify forensic-mcp (10 → 6)

- `query_case(record_type, status, query, limit, offset)` unifies `get_findings`, `get_timeline`, `get_actions`
- `manage_todo(action, todo_id, ...)` unifies `add_todo`, `update_todo`, `complete_todo`
- Remove `analyst_override` from all tools
- File: `packages/forensic-mcp/src/forensic_mcp/server.py`

### Group 3d — Remaining backends

- **sift-mcp** (5 → 3): `discover_tools(name, category, details)` unifies `list_available_tools`, `check_tools`, `get_tool_help`. `run_command` 8→5 params. Check why `suggest_tools` uses `question` param and remove if not used.
- **opencti-mcp** (8 → 7): `search_entities(query, entity_type=?)` unifies `search_threat_intel`, `search_entity`.
- **report-mcp** (6 → 5): `list(resource)` unifies `list_profiles`, `list_reports`. `set_metadata(fields={})` batch mode.
- **case-mcp** (14 → 13): Merge `case_list`→`case_status`. Add `compact` param to `export_bundle`. Check if required and how used `evidence_register`

### After Group 3: Phase C (Ingestion Resilience)

- C1: E01 hostname auto-discovery from SYSTEM registry hive
- C2: enhance functionality and performance and reslience of all ingestion, progress, failed errors,  `idx_ingest_progress(run_id)` polling
- C3: Ingest failure recovery / `--resume` support

---

## Session 50 Discoveries (2026-05-25)

### Venv fragility
The VM's venv was Python 3.11 but `uv sync --python /usr/bin/python3.12` triggered a silent venv rebuild, dropping all 165 packages. The gateway immediately crashed (exit code 2: "No such file: sift-gateway"). **Never run bare `uv sync` on the VM.** Use `install.sh` which checks venv integrity first.

### FastMCP outputSchema generation
`-> dict[str, Any]` triggers outputSchema generation; `-> dict` does not. When outputSchema is present, FastMCP expects `structuredContent` but tools return plain text content → "Output validation error". **Always use bare `-> dict`** on MCP tool return types.

### rag-mcp was in `full` extra only
The VM synced with `--extra standard` which didn't include `rag-mcp`. The entry point script existed (from a previous install) but the module wasn't importable. **Always sync `--extra full`** (the hardened installer does this).

### idx_status is NOT redundant
User thought `idx_status` monitored OpenCTI enrichment — it doesn't. It provides a cross-case cluster overview (all cases + indices + cluster health). Enrichment monitoring is in `idx_case_summary` (per-case stats) and `idx_ingest_status` (running jobs). Decision: **keep idx_status** — unique cross-case scope.

### DBs and RAG index are fine
The triage databases exist at `/var/lib/agentir/windows-triage/` (known_good.db + context.db). The RAG index exists at `packages/forensic-rag-mcp/data/chroma/`. These were never missing — the symptoms were all from the rag_mcp module not being installed.
