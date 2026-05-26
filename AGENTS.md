# AGENTS.md — sift-mcps

## Project Identity

A portable, secure MCP runtime for AI-driven digital forensics on SIFT Workstation VMs.
One installer provisions the entire stack. The examiner controls cases and approves findings
through a web portal. An AI agent (Hermes) drives investigation through authenticated MCP
tool calls — without direct shell access. The deliverable is a cryptographically auditable,
HMAC-verified forensic report.

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

## Session Rules (Non-Negotiable)

1. **Read TASKS.md first.** It tracks current state, blockers, and next steps.
2. **Read the current phase section of SIFT-MCPS-PLAN.md.** It is the grounded spec.
3. **Update TASKS.md as you complete each task.** Mark `[x]` immediately.
4. **Add session notes to TASKS.md before stopping.**
5. **When plan and task contradict — stop and ask.**
6. **Namespace is `agentir`.** `grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."` must return 0 lines.
7. **Test after every structural change:** run the affected package tests + remediation gate.
8. **agentir-core is a library — no `sys.exit()`.** Raise exceptions instead.
9. **Never rewrite whole files.** Targeted edits only.
10. **Do not commit unless explicitly asked.**

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
| R7 | windows-triage retained | SQLite-backed baseline validation; wintools-mcp out of scope |
| R7b | Aggregate `/mcp` only | Per-backend endpoints are diagnostic-only |

Full details in SIFT-MCPS-PLAN.md.

---

## Package Summary

| Package | Purpose | Status |
|---------|---------|--------|
| `agentir-core` | Shared library: case I/O, auth, HMAC, identity, evidence chain | 225 tests |
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
agentir-core case_io:         packages/agentir-core/src/agentir_core/case_io.py
agentir-core evidence_chain:  packages/agentir-core/src/agentir_core/evidence_chain.py
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
uv run python -m pytest packages/agentir-core/ --tb=short -q       # 225
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
uv run python -c "from agentir_core.case_io import get_case_dir; print('OK')"
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
