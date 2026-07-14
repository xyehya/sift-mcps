# SIFT MCPs — Reference Documentation

Generated from code at commit `eadb92b`. 14 documents covering the full monorepo.

## Reading Order

| Order | Document | Type | Content |
|-------|----------|------|---------|
| 00a | [Architecture Overview (MD)](00%20-%20Architecture%20Overview.md) | Top-level | Full system architecture, 8 planes, interaction flows, security controls on diagram |
| 00b | [Architecture Overview (HTML)](00%20-%20Architecture%20Overview.html) | Visual | Interactive HTML with SVGs, dark mode, annotated security controls |
| 01 | [Gateway](01%20-%20Gateway.md) | Subsystem | Auth, 10-stage MCP policy chain, evidence gate, response guard |
| 02 | [Core Tools](02%20-%20Core%20Tools.md) | Subsystem | 11 tools, evidence chain, run_command sandbox, reporting |
| 03 | [Shared Contracts](03%20-%20Shared%20Contracts.md) | Subsystem | AuditWriter, contracts, schema, parsers, surface testing |
| 04 | [OpenSearch Data Plane](04%20-%20OpenSearch%20Data%20Plane.md) | Subsystem | 14 tools, case scoping, ingest pipelines, durable jobs |
| 05 | [Add-on Ecosystem](05%20-%20Add-on%20Ecosystem.md) | Subsystem | forensic-rag-mcp, opencti-mcp, windows-triage-mcp |
| 06 | [Portal](06%20-%20Portal.md) | Subsystem | React frontend, Starlette backend, session auth, 86 REST endpoints |
| 07 | [Forensic Knowledge](07%20-%20Forensic%20Knowledge.md) | Subsystem | 23 loader functions, YAML data, offline |
| 08 | [Control Plane](08%20-%20Control%20Plane.md) | Subsystem | 25 migrations, FORCE RLS, append-only evidence chains |
| 09 | [API Contract](09%20-%20API%20Contract.md) | Reference | All 86 REST endpoints, MCP protocol contract, error codes |
| 10 | [Request and Data Flow](10%20-%20Request%20and%20Data%20Flow.md) | Reference | Sequence diagrams for MCP calls, auth, evidence, ingest |
| 11 | [Authentication](11%20-%20Authentication%20for%20API%20and%20MCP.md) | Reference | Token formats, identity resolution, 3 auth surfaces, scope grammar, error codes |
| 12 | [MCP Tool Catalog](12%20-%20MCP%20Tool%20Catalog.md) | Reference | All 42 tools with full input/output schemas |
| 13 | [Security Architecture](13%20-%20Security%20Architecture.md) | Reference | 27 security controls, STRIDE model, defense-in-depth sandbox |

## Invariants checked
All 17 declared invariants from `docs/drafts/architecture/sift-architecture.html` loaded and verified against code. No structural drift found. See individual docs for per-module invariant breakdown.

## Coverage
- 9 Python packages across 8 subsystem docs
- 25 Supabase migrations
- 1 React frontend (Vite + Tailwind + shadcn/ui)
- 42 MCP tools across 6 backends
- 86 REST API endpoints
- 27 security controls across 5 architectural layers
- 3 systemd services (sift-gateway, sift-job-worker, sift-opensearch-worker@)
- AppArmor profiles for dfir execution, the Gateway, fixed local brokers, and isolated add-ons
- 1 auditd rules file
- 1 gateway config template
- 5 add-on manifests (sift-backend.json)

| 14 | [Quick Start](14%20-%20Quick%20Start.md) | Guide | Prerequisites, install, verify, first operator |
| 15 | [Operator Manual](15%20-%20Operator%20Manual.md) | Guide | Login → Case → Evidence → Triage → Review → Report |
| 16 | [Configuration Reference](16%20-%20Configuration%20Reference.md) | Reference | gateway.yaml keys, env vars, manifest schema, Supabase auth |
| 17 | [Development Guide](17%20-%20Development%20Guide.md) | Guide | Dev setup, add tool, add backend, surface testing, conventions |
| 18 | [Troubleshooting](18%20-%20Troubleshooting.md) | Guide | 18 symptom-driven fixes with exact error messages |
| 19 | [Greenfield Uninstaller](19%20-%20Greenfield%20Uninstaller.md) | Guide | Streamlined VM wipe/reinstall contract, `--data` / `--keep-caches`, fail-closed volumes, live proof |

## Status
Complete: 20 documents (1 HTML + 19 MD + 1 README). 00-08 system docs, 09-13 cross-cutting references, 14-19 procedural/operational guides.
