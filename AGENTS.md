# Rules applicable to EVERYTHING 

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

# Our workscope 

**EXTREMELY IMPORTANT — All active development is running on this host machine workspace initiated in the root repo directory (sift-mcps) - The SIFT machine runs on a VM accessed through ssh/sshpass/rsync for active testing - CODE on host - Copy Changes - Test on SIFT VM - DIFFERENT PYTHON RUN TIMES DIFFERENT OPERATING SYSTEMS!**


## Project Identity

A portable, secure MCP runtime for AI-driven digital forensics on SIFT Workstation VMs.
One installer provisions the entire stack. The examiner controls cases and approves findings
through a web portal. An AI agent (Hermes) drives investigation through authenticated MCP
tool calls — deliverable is a cryptographically auditable,
HMAC-verified forensic report.

```
Analyst Machine                    SIFT VM (sift-mcps installed)
────────────────            ───────────────────────────────────────
Hermes Agent ──HTTPS──▶   sift-gateway :4508
Browser      ──HTTPS──▶     │
                            ├── /mcp      (agent MCP — aggregate endpoint)
                            └── /portal/  (Examiner Portal — cases, review, approval)
```
### 3. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ SIFT VM                                                         │
│                                                                 │
│  sift-gateway (Starlette ASGI, :4508 HTTPS, localhost SAN)     │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────────────┐ │
│  │ auth    │  │ rate     │  │ MCP     │  │ Examiner Portal  │ │
│  │ Bearer  │  │ limit    │  │ proxy   │  │ /portal/         │ │
│  │ + expiry│  │          │  │ /mcp    │  │ (case-dashboard) │ │
│  └─────────┘  └──────────┘  └────┬────┘  └──────────────────┘ │
│                                  │                             │
│           stdio subprocesses (FastMCP)                         │
│  ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌───────────────────┐  │
│  │forensic  │ │case-mcp │ │sift-mcp  │ │report-mcp         │  │
│  │-mcp      │ │         │ │shell=F   │ │                   │  │
│  └──────────┘ └─────────┘ └──────────┘ └───────────────────┘  │
│  ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌───────────────────┐  │
│  │opensearch│ │forensic │ │opencti   │ │windows-triage-mcp │  │
│  │-mcp      │ │-rag-mcp │ │-mcp      │ │baseline lookups   │  │
│  └──────────┘ └─────────┘ └──────────┘ └───────────────────┘  │
│                                                                 │
│  Docker services: agentir-opensearch, agentir-opencti (+dep)   │
│  Host tools: xmount, ewfmount, ntfs-3g, AmcacheParser, etc.   │
└─────────────────────────────────────────────────────────────────┘
```

#### Design Invariants 
| Component | Why It Stays |
|-----------|-------------|
| Streamable HTTP via `StreamableHTTPSessionManager` | Correct MCP spec |
| Gateway subprocess aggregation | Clean separation of concerns |
| Challenge-response HMAC-SHA256 portal auth | No plaintext password over wire |
| HMAC verification ledger at `/var/lib/agentir/verification/` | Non-forgeable integrity |
| Atomic writes + `chmod 444` on case files | Crash-safe, tamper-resistant |
| Portal case creation | Normal examiner workflow |
| Append-only `approvals.jsonl` | Immutable approval audit trail |
| Versioned evidence manifest + ledger | Tamper-detection |
| Two-tier evidence gate | UNSEALED=read-only pass-through; VIOLATION=full block |
| sudo xmount + ntfs-3g for E01 mount | Works on SIFT xmount 0.7.6 |
| safe_rglob for NTFS filesystem traversal | Survives corrupted junctions |


**SIFT VM:** 192.168.122.81
- User/pass: `sansforensics` / `forensics`
- Python: `/usr/bin/python3.12` (SIFT native, 3.12.3)
- Ubuntu 24.04.4 LTS (Noble Numbat)
- Gateway: `https://192.168.122.81:4508` (systemd user service)
- Portal: `https://192.168.122.81:4508/portal/`
- Active case: `test-rocba-2026`, 23GB E01 ingested (40,636 docs, 12 artifact types, 12 indices green)
- RAG index: 22,268 records (67 sources). Hayabusa: v3.9.0, 4,947 rules. OpenCTI: MITRE ATT&CK + CISA KEV live.
- Agent token: `agentir_svc_b5152580b0cd2ce8003ee5c9a5c559537b322741f21d4f03`

**Aggregate MCP (what the agent sees):** 
- All 8 backends healthy — including forensic-rag-mcp (3 tools) and windows-triage-mcp (13 tools)
- Live verify: `curl -s -k https://192.168.122.81:4508/api/v1/health | python3 -m json.tool`
- MCP tools/list: initialize session at `/mcp`, then `tools/list` with session ID


**If Agent has been configured with the MCP, it can directly use tool calls for testing**

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
- Post-sync import verification: smokes `yaml`, `mcp`, `sift_core`, `sift_gateway`

**The old way (DON'T DO THIS):**
```bash
# NEVER run bare uv sync on the VM — can trigger Python mismatch + venv rebuild
uv sync --extra standard --python /usr/bin/python3.12 ...
```
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
packages/sift-core/src/sift_core/evidence_chain.py  # chain_status(), seal_manifest(), HMAC verification, ChainStatus enum
packages/sift-core/src/sift_core/case_io.py         # Case I/O: resolve_case_path, evidence manifest read/write
packages/sift-core/src/sift_core/case_ops.py        # Case operations: case_init_data, case_activate_data, case_list_data
```

### Config & install
```
install.sh                                        # Hardened zero-arg installer: venv integrity, system Python, idempotent
configs/gateway.yaml.template                     # Gateway config template (backend definitions, ports, auth)
configs/apparmor/sift-gateway.template            # AppArmor profile template (complain mode on VM)
configs/systemd/sift-gateway.service              # Systemd user service template
scripts/remediation-gate.sh                       # Pre-commit gate: namespace sweep, shell=True check, bare strings
```


---

## Core Design Requirements (Abbreviated)

| # | Rule | Summary |
|---|------|---------|
| R1 | No direct shell | All command execution through sift-mcp (`subprocess.run(shell=False)`) |
| R2 | Chain of custody | Atomic writes, SHA-256 hashes, append-only approvals, HMAC verification ledger |
| R3 | Human-in-the-loop | Findings are DRAFT until examiner approves via HMAC challenge-response |
| R3b | Evidence intake | Portal-controlled, append-only, versioned manifest + ledger |
| R4 | Portal case creation | Examiner creates cases in portal; `AGENTIR_CASE_DIR` propagates to all backends |
| R4b | Path resolution | All path args resolve under `AGENTIR_CASE_DIR`; traversal rejected |
| R5 | TLS everywhere | Self-signed CA at install; HTTPS only for remote access; SAN includes localhost |
| R6 | Bearer token auth | Timing-safe, expiry-checked; two roles (examiner, agent) |
| R7 | windows-triage and RAG retained | SQLite-backed baseline validation; wintools-mcp out of scope |
| R7b | Aggregate `/mcp` only | Per-backend endpoints are diagnostic-only |


---

## Package Summary

| Package | Purpose | Status |
|---------|---------|--------|
| `sift-core` | Shared library: case I/O, auth, HMAC, identity, evidence chain | 225 tests |
| `sift-gateway` | HTTP gateway, auth, routing, evidence gate, response guard, tool categories | 104 tests, Phase B |
| `case-dashboard` | Examiner Portal (Starlette sub-app) | 243 tests |
| `forensic-mcp` | Findings, timeline, TODOs, workflow_status entry point | 16 tests, Phase B |
| `case-mcp` | Case lifecycle (status, list, evidence list/verify) | 23 tests |
| `sift-mcp` | Run forensic tools via shell=False | 3 tests |
| `report-mcp` | Generate final case reports (6 profiles) | 31 tests |
| `forensic-rag-mcp` | Semantic search over 22K+ forensic knowledge records | 3 tools, all readOnly |
| `windows-triage-mcp` | Windows baseline validation (13 tools, SQLite-backed) | readOnlyHint added |
| `opencti-mcp` | Threat intel enrichment | 8 tools, readOnlyHint added |
| `opensearch-mcp` | Evidence indexing/search (21 tools), container inspect | 906 tests, Phase B |
| `sift-common` | AuditWriter, parsers, instructions | Fix on touch only |
| `forensic-knowledge` | YAML forensic knowledge data | Unchanged |

---

## Key File Locations

```
sift-core case_io:         packages/sift-core/src/sift_core/case_io.py
sift-core evidence_chain:  packages/sift-core/src/sift_core/evidence_chain.py
sift-gateway server:          packages/sift-gateway/src/sift_gateway/server.py
sift-gateway mcp_endpoint:    packages/sift-gateway/src/sift_gateway/mcp_endpoint.py
sift-gateway evidence_gate:   packages/sift-gateway/src/sift_gateway/evidence_gate.py
opensearch-mcp server:        packages/opensearch-mcp/src/opensearch_mcp/server.py
opensearch-mcp ingest:        packages/opensearch-mcp/src/opensearch_mcp/ingest.py
opensearch-mcp ingest_cli:    packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py
opensearch-mcp containers:    packages/opensearch-mcp/src/opensearch_mcp/containers.py
opensearch-mcp tools:         packages/opensearch-mcp/src/opensearch_mcp/tools.py
opensearch-mcp manifest:      packages/opensearch-mcp/src/opensearch_mcp/manifest.py
opensearch-mcp discover:      packages/opensearch-mcp/src/opensearch_mcp/discover.py
forensic-rag-mcp server:      packages/forensic-rag-mcp/src/rag_mcp/server.py
forensic-rag-mcp index:       packages/forensic-rag-mcp/src/rag_mcp/index.py
case-mcp server:              packages/case-mcp/src/case_mcp/server.py
sift-mcp server:              packages/sift-mcp/src/sift_mcp/server.py
instructions strings:         packages/sift-common/src/sift_common/instructions.py
gateway config template:      configs/gateway.yaml.template
AppArmor template:            configs/apparmor/sift-gateway.template
install script:               install.sh
SIFT VM cases root:           /cases/
```

---

## Working Commands

```bash
cd /home/yk/AI/SIFTHACK/sift-mcps

# Install all packages
uv sync --all-packages

# Run all tests (primary gate)
uv run python -m pytest packages/sift-core/ --tb=short -q       # 225
uv run python -m pytest packages/case-dashboard/ --tb=short -q     # 240
uv run python -m pytest packages/sift-gateway/ --tb=short -q       # 104
uv run python -m pytest packages/case-mcp/ --tb=short -q           # 23
uv run python -m pytest packages/opensearch-mcp/ --tb=short -q     # 909
uv run python -m pytest packages/sift-mcp/ --tb=short -q           # 3
uv run python -m pytest packages/report-mcp/ --tb=short -q         # 31
uv run python -m pytest packages/forensic-mcp/ --tb=short -q       # 16

# Remediation gate (total: 1,551 tests) (run before every commit)
bash scripts/remediation-gate.sh

# Namespace sweep (must return 0 lines)
grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."

# Import smoke tests
uv run python -c "from sift_core.case_io import get_case_dir; print('OK')"
uv run python -c "from case_mcp.server import create_server; print('OK')"
uv run python -c "from sift_gateway.server import Gateway; print('OK')"

# SIFT VM access
sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81

# Sync to SIFT VM
rsync -avz --exclude '.git' --exclude '.venv' --exclude '__pycache__' \
  /home/yk/AI/SIFTHACK/sift-mcps/ sansforensics@192.168.122.81:~/sift-mcps-test/

# Restart gateway on SIFT VM (systemd user service)
ssh sansforensics@192.168.122.81 'systemctl --user restart sift-gateway'
```
