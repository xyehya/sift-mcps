# Session Prompt — sift-mcps

Copy this prompt to start a new session with full context.

---

## Project Identity

**sift-mcps** — A portable, secure MCP runtime for AI-driven digital forensics on SIFT Workstation VMs. One installer provisions the entire stack. The examiner controls cases and approves findings through a web portal. An AI agent (Hermes) drives investigation through authenticated MCP tool calls — without direct shell access. The deliverable is a cryptographically auditable, HMAC-verified forensic report.

```
Analyst Machine                    SIFT VM (sift-mcps installed)
────────────────            ───────────────────────────────────────
Hermes Agent ──HTTPS──▶   sift-gateway :4508
Browser      ──HTTPS──▶     │
                            ├── /mcp      (agent MCP — aggregate endpoint)
                            └── /portal/  (Examiner Portal — cases, review, approval)
```

**Hermes investigates. The examiner reviews and approves. The report is signed and auditable.**

---

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

**The old way (DON'T DO THIS):**
```bash
# NEVER run bare uv sync on the VM — can trigger Python mismatch + venv rebuild
uv sync --extra standard --python /usr/bin/python3.12 ...
```

---

## Where We're Heading

**Immediate next task: Group 3 — Tool Consolidation (80 → 55 tools)**

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

**After Group 3:** Phase C (ingestion resilience), Phase D (agent workflow engine), Phase E (production hardening), Phase 17 (OS-level evidence hardening).

---

## Pro Tips

1. **Read TASKS.md first** — it tracks current state, blockers, next steps. Read AGENTS.md for session rules. Read SIFT-MCPS-PLAN.md §8 for phase roadmap.

2. **Test after every structural change** — run affected package tests + remediation gate:
   ```bash
   uv run python -m pytest packages/<pkg>/ --tb=short -q
   bash scripts/remediation-gate.sh
   ```

3. **Namespace is `agentir`** — `grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."` must return 0.

4. **agentir-core is a library** — no `sys.exit()`. Raise exceptions instead.

5. **Never rewrite whole files** — targeted edits only.

6. **The gateway runs as a systemd user service** — restart with:
   ```bash
   ssh sansforensics@192.168.122.81 'systemctl --user restart sift-gateway'
   ```
   Never use `nohup uv run` — that can trigger venv rebuilds. The service file is at `~/.config/systemd/user/sift-gateway.service`.

7. **Use install.sh for dependency sync — never bare `uv sync` on the VM:**
   ```bash
   ssh sansforensics@192.168.122.81 'cd ~/sift-mcps-test && bash install.sh'
   ```
   The hardened installer handles venv integrity, Python version matching, and always uses `--extra full` + `/usr/bin/python3.12`. Re-run safe: every step is idempotent.

8. **MCP tool annotations** — The Pydantic `Tool` model uses `_meta` as the JSON alias for the `meta` field. Set via attribute: `t.meta = {"category": "session-start"}`. When reading JSON responses, use `t["_meta"]`.

9. **Only `get_health` collides** across backends (opencti + windows-triage). All other tool names are unique — use unprefixed names in category/phase mappings.

10. **`get_tools_list()` must propagate ALL fields** — when building Tool objects from live backend data, copy all 9 fields: `name`, `title`, `description`, `inputSchema`, `outputSchema`, `icons`, `annotations`, `meta`, `execution`.

11. **FastMCP outputSchema pitfall** — `-> dict[str, Any]` generates outputSchema which triggers structuredContent validation; `-> dict` (bare) does not. If you see "outputSchema defined but no structured output returned", change the return type annotation to bare `dict`. All working tools use bare `dict`.

12. **Python version mismatch kills the venv** — `uv sync --python /usr/bin/python3.12` will silently rebuild a Python 3.11 venv, dropping ALL packages. Always check `~/.venv/bin/python --version` matches system Python before syncing. The hardened installer does this automatically.

---

## Sync / Deploy / Reinstall

### Quick deploy (Python source only, no dependency changes)

```bash
# 1. Sync code (from local project root)
rsync -avz --exclude '.git' --exclude '.venv' --exclude '__pycache__' --exclude '*.pyc' \
  /home/yk/AI/SIFTHACK/sift-mcps/ sansforensics@192.168.122.81:~/sift-mcps-test/

# 2. Restart gateway via systemd
ssh sansforensics@192.168.122.81 'systemctl --user restart sift-gateway'

# 3. Wait for startup (10-15s), then verify
ssh sansforensics@192.168.122.81 'curl -s -k https://localhost:4508/api/v1/health | python3 -m json.tool'
```

### Full reinstall (dependency changes, venv issues, asset problems)

```bash
# The hardened installer handles everything — idempotent, always safe
ssh sansforensics@192.168.122.81 'cd ~/sift-mcps-test && bash install.sh'
```

### Test aggregate MCP endpoint

```bash
TOKEN="agentir_svc_b5152580b0cd2ce8003ee5c9a5c559537b322741f21d4f03"

# Initialize and get session ID
SESSION=$(curl -s -k -D - -L \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
  "https://192.168.122.81:4508/mcp" 2>&1 | grep -i "mcp-session-id:" | awk '{print $2}' | tr -d '\r')

# List tools
curl -s -k -L \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: ${SESSION}" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  "https://192.168.122.81:4508/mcp"

# Call a tool
curl -s -k -L \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: ${SESSION}" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_knowledge","arguments":{"query":"lateral movement"}}}' \
  "https://192.168.122.81:4508/mcp"
```

---

## SSH Details

```bash
# Password auth
sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81

# Run commands remotely
ssh sansforensics@192.168.122.81 '<command>'

# Gateway control (via systemd user service)
ssh sansforensics@192.168.122.81 'systemctl --user status sift-gateway'
ssh sansforensics@192.168.122.81 'systemctl --user restart sift-gateway'
ssh sansforensics@192.168.122.81 'journalctl --user -u sift-gateway -n 50'

# Check Python version (must be 3.12)
ssh sansforensics@192.168.122.81 '/usr/bin/python3.12 --version'
```

---

## Core Code File Reference

### Gateway (sift-gateway)
```
packages/sift-gateway/src/sift_gateway/server.py       # Gateway class, get_tools_list(), _build_tool_map(), backend mgmt
packages/sift-gateway/src/sift_gateway/mcp_endpoint.py  # MCP server, create_mcp_server(), _list_tools(), _call_tool(), evidence gate, annotations, categories, environment_summary
packages/sift-gateway/src/sift_gateway/evidence_gate.py # Two-tier gate: check_evidence_gate(), build_block_response(), build_unsealed_warning()
```

### Backends (MCP tools)
```
packages/forensic-mcp/src/forensic_mcp/server.py        # 10 tools: record_finding, workflow_status, get_findings, TODOs, discipline resources
packages/forensic-mcp/src/forensic_mcp/case/manager.py  # CaseManager: findings I/O, timeline, evidence registry, IOC processing
packages/case-mcp/src/case_mcp/server.py                # 14 tools: case_status, evidence_list, evidence_verify, audit, bundles
packages/sift-mcp/src/sift_mcp/server.py                # 5 tools: list_available_tools, run_command, suggest_tools
packages/report-mcp/src/report_mcp/server.py            # 6 tools: generate_report, set_case_metadata, save_report
packages/opensearch-mcp/src/opensearch_mcp/server.py    # 21 tools: idx_ingest, idx_search, idx_aggregate, idx_case_summary, idx_inspect_container
packages/forensic-rag-mcp/src/rag_mcp/server.py         # 3 tools: search_knowledge, list_knowledge_sources, get_knowledge_stats
packages/opencti-mcp/src/opencti_mcp/server.py          # 8 tools: search_threat_intel, lookup_ioc, search_reports
packages/windows-triage-mcp/src/windows_triage_mcp/server.py  # 13 tools: check_file, check_process_tree, check_service, etc.
```

### Core library
```
packages/agentir-core/src/agentir_core/evidence_chain.py  # chain_status(), seal_manifest(), HMAC verification, ChainStatus enum
packages/agentir-core/src/agentir_core/case_io.py         # Case I/O: resolve_case_path, evidence manifest read/write
packages/agentir-core/src/agentir_core/case_ops.py        # Case operations: case_init_data, case_activate_data, case_list_data
```

### Config & install
```
install.sh                                        # Hardened zero-arg installer: venv integrity, system Python, idempotent
configs/gateway.yaml.template                     # Gateway config template (backend definitions, ports, auth)
configs/apparmor/sift-gateway.template            # AppArmor profile template (complain mode on VM)
configs/systemd/sift-gateway.service              # Systemd user service template
scripts/remediation-gate.sh                       # Pre-commit gate: namespace sweep, shell=True check, bare strings
```

### Docs
```
AGENTS.md           # Session rules, package summary, working commands, file locations
TASKS.md            # Current state, active tasks, completed work, session notes, quick reference
SIFT-MCPS-PLAN.md   # Architecture spec, design invariants, phase roadmap (§8), known issues
docs/tool-audit-2026-05-25.md  # Full 78-tool audit with descriptions, parameters, readOnlyHint status, interaction map
SESSION-PROMPT.md   # This file — full onboarding prompt
```

---

## Next Tasks

### Group 3a — Unify opensearch-mcp ingest tools (highest impact, start here)

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

### Group 3b — Unify windows-triage-mcp (13 → 6)

- `check_artifact(type, value)` replaces `check_file`, `check_hash`, `analyze_filename`, `check_lolbin`, `check_hijackable_dll`
- `check_system(type, name, os_version)` replaces `check_service`, `check_scheduled_task`, `check_autorun`
- `server_status` replaces `get_db_stats`, `get_health`
- Keep standalone: `check_process_tree`, `check_registry`, `check_pipe`
- File: `packages/windows-triage-mcp/src/windows_triage_mcp/server.py`

### Group 3c — Unify forensic-mcp (10 → 6)

- `query_case(record_type, status, query, limit, offset)` replaces `get_findings`, `get_timeline`, `get_actions`
- `manage_todo(action, todo_id, ...)` replaces `add_todo`, `update_todo`, `complete_todo`
- Remove `analyst_override` from all tools
- File: `packages/forensic-mcp/src/forensic_mcp/server.py`

### Group 3d — Remaining backends

- **sift-mcp** (5 → 3): `discover_tools(name, category, details)` replaces `list_available_tools`, `check_tools`, `get_tool_help`. `run_command` 8→5 params. Remove `suggest_tools` dead `question` param.
- **opencti-mcp** (8 → 7): `search_entities(query, entity_type=?)` replaces `search_threat_intel`, `search_entity`.
- **report-mcp** (6 → 5): `list(resource)` replaces `list_profiles`, `list_reports`. `set_metadata(fields={})` batch mode.
- **case-mcp** (14 → 13): Merge `case_list`→`case_status`. Add `compact` param to `export_bundle`. Remove `evidence_register` from source.

### After Group 3: Phase C (Ingestion Resilience)

- C1: E01 hostname auto-discovery from SYSTEM registry hive
- C2: Lightweight `idx_ingest_progress(run_id)` polling
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
