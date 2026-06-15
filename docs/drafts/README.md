# docs/regenerate — Index and Status (BATCH-RG1)

**Produced by BATCH-RG1 (2026-06-13).** This index tells future agents which
document owns each fact and whether each `docs/regenerate/` file is active or
archival only.

---

## Fact Ownership Map

Each row names a fact domain, the single document that OWNS it, and the
`docs/regenerate/` file (if any) that covers the same topic in archival form.

| Fact domain | Authoritative owner (DO NOT duplicate) | Archival / supplementary in regenerate |
|---|---|---|
| Core/add-on boundary (what is core, what is external) | `docs/add-ons/spec.md §1` | `backend-contract.md` (archival), `code-structure.md` (archival) |
| Add-on manifest contract (`sift-backend.json` schema) | `docs/add-ons/spec.md` | `backend-contract.md` (archival; manifest schema section remains accurate) |
| Add-on author walkthrough | `docs/add-ons/author-guide.md` | — |
| Add-on registration lifecycle (seed → mount → hot-reload) | `docs/add-ons/spec.md §3` | `backend-contract.md §2` (archival; lifecycle section remains accurate) |
| RAG / forensic-knowledge / Hayabusa provenance and import | `docs/operator/reference-data-provenance.md` | `data-flows-and-lifecycles.md §8` (updated) |
| Current RAG tool names (`kb_*`) and namespace | `docs/add-ons/spec.md`, `packages/forensic-rag-mcp/src/rag_mcp/server.py` | `mcp-contracts.md` (updated; `rag_search_case` section labelled historical) |
| Operator maintenance (services, restart, health, backup) | `docs/operator/maintenance-guide.md` | `operator-journey.md` (archival; journey still useful) |
| Config and secrets (env files, variable dictionary) | `docs/operator/config-and-secrets.md` | `security-architecture.md` (archival; accepted MVP caveats table still useful) |
| RAG / OpenSearch day-to-day maintenance | `docs/operator/rag-and-search-maintenance.md` | `data-flows-and-lifecycles.md §8` (archival) |
| State authority (DB vs file vs derived) | `docs/operator/state-authority-map.md` | `data-flows-and-lifecycles.md` (archival; lifecycle diagrams still accurate) |
| Live tool inventory (packages, paths, modes) | `docs/inventory/sift-tool-inventory.md` | `code-structure.md` (archival; package map still useful as code navigation) |
| Hardening research matrix | `docs/hardening/research-matrix.md` | `dfir-hardening-guide-pre-migration.md` (historical seed; stale paths) |
| Component hardening audit | `docs/hardening/component-audit.md` | `security-architecture.md` (archival; control baseline still accurate) |
| Evidence custody lifecycle (DB authority) | `docs/operator/state-authority-map.md` (custody rows) | `evidence-chain-of-custody-premigration.md` (historical; file-backed model) |
| MCP tool contracts (per-tool input/output) | `packages/sift-core/src/sift_core/agent_tools.py`, `packages/opensearch-mcp/sift-backend.json`, `packages/forensic-rag-mcp/sift-backend.json` | `mcp-contracts.md` (archival; contracts remain accurate except `rag_search_case` → `kb_*`) |
| REST API contracts (portal routes) | `packages/case-dashboard/src/case_dashboard/routes.py` | `api-contracts.md` (archival; contracts remain accurate) |
| Interaction model / agent tool loops | `interaction-model.md` in this directory (archival but accurate) | — |
| SIFT skill coverage (forensic tool gaps) | `docs/inventory/sift-tool-inventory.md` | `matrix-comparison.md` (archival; coverage assessments still useful but pre-migration tool names) |
| Architecture diagrams (planes, trust boundaries) | `architecture.md` in this directory (archival; updated by RG1) | `Architecture.mmd` (archival diagram; updated by RG1) |

---

## File Status

### Active (content accurate after RG1 corrections; safe to read as reference)

These files have been revalidated and corrected by BATCH-RG1. Stale sections
are labelled inline with `> **RG1 (2026-06-13):**` callouts.

| File | Use as | Primary owner for its content |
|---|---|---|
| `architecture.md` | Architecture overview — planes, trust, journeys | This file (archival; no newer replacement) |
| `Architecture.mmd` | Mermaid diagram — corrected for current add-on structure | This file (archival diagram) |
| `data-flows-and-lifecycles.md` | Lifecycle diagrams — install, case, evidence, jobs | Accurate except §8 RAG (updated by RG1); prefer `docs/operator/reference-data-provenance.md` for RAG |
| `mcp-contracts.md` | Per-tool MCP contracts | Accurate except `rag_search_case` (labelled historical by RG1); prefer source for latest |
| `interaction-model.md` | Human ↔ agent handoff, re-auth gates, tool loops | This file (no newer replacement yet) |
| `operator-journey.md` | Operator journey narrative | `docs/operator/maintenance-guide.md` is the current manual; this file is still useful for context |
| `api-contracts.md` | Portal REST contracts | Accurate; prefer source `routes.py` for latest |
| `backend-contract.md` | Add-on manifest reference (OSX2 level) | Superseded by `docs/add-ons/spec.md`; manifest schema sections still accurate |
| `security-architecture.md` | Control baseline, invariant → enforcement map | Accurate with RG1 corrections; prefer `docs/hardening/component-audit.md` for current audit |
| `code-structure.md` | Package map and trust boundary diagram | Accurate with RG1 corrections; prefer `docs/inventory/sift-tool-inventory.md` for live paths |
| `known-limitations-and-improvements.md` | Known gaps and improvement backlog | Accurate with RG1 corrections; service-identity row updated |
| `matrix-comparison.md` | SIFT skill coverage gap analysis | Archival; coverage gaps still useful but pre-migration tool names; updated by RG1 |

### Historical / Archival (pre-migration content; marked with ARCHIVAL headers)

These files describe the pre-migration file-backed system. They are kept for
reference and should NOT be treated as describing the current live system.
The authoritative replacement is noted in each file's header.

| File | Why historical | Current replacement |
|---|---|---|
| `dfir-hardening-guide-pre-migration.md` | Pre-migration `AgentIR` product name, old Python interpreter paths, old auditd key names (`agentir`), old service identity | `docs/hardening/component-audit.md` |
| `evidence-chain-of-custody-premigration.md` | Describes file-backed custody (manifest/ledger as authority); current authority is Postgres DB | `docs/operator/state-authority-map.md` (evidence rows) |

---

## Key Corrections Made by BATCH-RG1

| Issue | Files corrected | Citation |
|---|---|---|
| `rag_search_case` still listed as the RAG tool; `rag_bridge.py` still listed | `mcp-contracts.md`, `data-flows-and-lifecycles.md`, `code-structure.md`, `interaction-model.md`, `architecture.md`, `known-limitations-and-improvements.md` | `packages/forensic-rag-mcp/src/rag_mcp/__init__.py` (BATCH-OSX-RAG note); `server.py` (kb_* tools); `rag_bridge.py` not found in current checkout |
| `packages/windows-triage-mcp/` listed as a core package | `code-structure.md`, `architecture.md`, `security-architecture.md`, `Architecture.mmd`, `matrix-comparison.md` | `ls packages/` — no such directory; `docs/add-ons/author-guide.md §1` (future external add-on candidate only) |
| `~/.sift/` as secret/service config path (now `/var/lib/sift/.sift/`) | `security-architecture.md` | `configs/systemd/sift-gateway.service` (`User=${SIFT_GATEWAY_SERVICE_USER}` → `sift-service`; home is `/var/lib/sift`); `docs/operator/maintenance-guide.md` |
| Gateway/worker still described as running as `sansforensics` | `known-limitations-and-improvements.md` (Ingest mount privilege row) | `configs/systemd/sift-gateway.service` (`sift-service`); BATCH-HR3 |
| `~/.sift/addon-register/` path in `backend-contract.md` not accounting for AD2 fix | `backend-contract.md` | `scripts/setup-addon.sh:87-91` (`$HOME/.sift/addon-register/` for the operator user, not service dir) |
| OpenCTI still treated as a core/native install | `Architecture.mmd`, `architecture.md` | `docs/add-ons/spec.md §1` (`install.sh` line citations); `install.sh:3166-3172` (`SIFT_OPENCTI_ENABLED=true` is ignored with explicit "external add-on only" note) |
| `AGENTIR_CASE_DIR` env var in `matrix-comparison.md` | `matrix-comparison.md` | Pre-migration env var; current code resolves case dir server-side; agent only sees relative paths |
| Pre-migration docs lacked ARCHIVAL headers | `dfir-hardening-guide-pre-migration.md`, `evidence-chain-of-custody-premigration.md` | RG1 added prominent `ARCHIVAL / HISTORICAL` headers |

---

## Promotion Recommendations

The following content in `docs/regenerate/` deserves promotion into
`docs/operator/`, `docs/hardening/`, or `docs/add-ons/` in a future conductor
pass. **Do not duplicate — point at the regenerate source and promote once.**

| Content | Current home | Recommended promotion target | Notes |
|---|---|---|---|
| `interaction-model.md` — Human ↔ agent handoff, re-auth gate model, tool loops | `docs/regenerate/interaction-model.md` | `docs/operator/maintenance-guide.md` §operator-agent-handoff or a standalone `docs/operator/interaction-model.md` | No newer doc covers this yet; content is accurate |
| `api-contracts.md` — Portal REST contracts | `docs/regenerate/api-contracts.md` | `docs/operator/maintenance-guide.md` §API or a standalone `docs/operator/api-contracts.md` | Content accurate; useful for integrators |
| `mcp-contracts.md` — Per-tool MCP contracts (excluding `rag_search_case`) | `docs/regenerate/mcp-contracts.md` | A new `docs/agent/mcp-contracts.md` or integrated into the add-on/operator docs | Very useful for agent authors; deserves a non-archival home |
| `matrix-comparison.md` — SIFT skill coverage gaps | `docs/regenerate/matrix-comparison.md` | `docs/operator/maintenance-guide.md` §skill-gaps or a standalone `docs/operator/skill-coverage.md` (after updating tool names) | Coverage gap analysis is still valuable; needs tool name updates for current `opensearch_*` / `kb_*` names |
