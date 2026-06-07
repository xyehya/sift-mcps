# Repo Inventory

Last updated: 2026-06-06.

Scope: current-state repository inventory only. This file intentionally does
not design the target schema, target services, or final migration roadmap.

Run 25 status note: this is a **pre-PR01/PR02/D27a/D27b inventory snapshot**.
Several Gateway/FastMCP facts below are now historical: the Gateway is no
longer Starlette/low-level MCP, per-backend `/mcp/{name}` routes are removed,
and the backend MCP packages have moved to standalone FastMCP 3.0. Use
`00_migration_charter.md` Current Migration Status and `MIGRATION_STATE.md` for
current landed architecture.

## Repository Shape

- The repo is a `uv` workspace with all packages under `packages/*`
  (`pyproject.toml:1-2`). Optional dependency groups split the product into
  `core`, `standard`, and `full`; `standard` currently adds `opensearch-mcp`,
  `windows-triage-mcp`, and `opencti-mcp`, while `full` adds `rag-mcp`
  (`pyproject.toml:32-50`).
- The Gateway package is `sift-gateway`, exposes the console script
  `sift-gateway = sift_gateway.__main__:main`, and depends on MCP, Starlette,
  Uvicorn, PyYAML, httpx, bcrypt, jsonschema, `sift-common`, and `sift-core`
  (`packages/sift-gateway/pyproject.toml:5-27`).
- The OpenSearch package is `opensearch-mcp`, exposes both
  `opensearch-mcp` and `opensearch-ingest`, and declares a `sift.plugins`
  entry point (`packages/opensearch-mcp/pyproject.toml:5-31`).

## Frontend

- The Examiner Portal frontend is a React + Vite app. `package.json` declares
  Vite scripts (`dev`, `build`, `test`, `preview`) and uses React 19, Zustand,
  Recharts, cmdk, Tailwind, and Vitest
  (`packages/case-dashboard/frontend/package.json:6-40`).
- There is no React Router route tree in the inspected app shell. Navigation is
  in-memory tab state: `useStore` defaults `activeTab` to `overview`, and
  `App.jsx` renders screens by comparing `activeTab` to tab IDs
  (`packages/case-dashboard/frontend/src/store/useStore.js:3-6`,
  `packages/case-dashboard/frontend/src/App.jsx:76-93`).
- Main portal screens are wired in `App.jsx`: overview, findings, timeline,
  evidence, hosts, accounts, IOCs, TODOs, backends, reports, and settings
  (`packages/case-dashboard/frontend/src/App.jsx:10-20`,
  `packages/case-dashboard/frontend/src/App.jsx:82-92`). The left nav exposes
  the same case-facing screens and adds the settings bottom item
  (`packages/case-dashboard/frontend/src/components/layout/NavRail.jsx:4-19`).
- The frontend API client prefixes all API calls with `/portal`, uses
  credentialed cookie requests, applies a 15 second timeout, and emits a
  browser event on HTTP 401 (`packages/case-dashboard/frontend/src/api/client.js:1-5`,
  `packages/case-dashboard/frontend/src/api/client.js:16-50`).
- Portal endpoint wrappers cover auth, cases, investigation data, review delta,
  evidence chain, response guard, service tokens, reports, backends, and
  services (`packages/case-dashboard/frontend/src/api/endpoints.js:3-77`).
- Polling is central and file-shape-specific: every 15 seconds
  `useDataPolling()` fetches current case, cases list, summary, findings,
  pending review delta, timeline, evidence chain status, IOCs, TODOs, and
  reports, then writes them directly into Zustand store slices
  (`packages/case-dashboard/frontend/src/hooks/useDataPolling.js:16-43`,
  `packages/case-dashboard/frontend/src/store/useStore.js:12-58`).
- The Settings screen is specifically an MCP/service-token UI: it lists tokens,
  creates agent-role tokens, rotates, revokes, and reactivates by calling the
  token endpoints (`packages/case-dashboard/frontend/src/components/settings/SettingsTab.jsx:1-99`).
- The Evidence screen calls chain status, rescan, challenge, seal, HMAC verify,
  ignore, retire, anchor, and legacy verify endpoints. It builds `file_specs`
  from `chainStatus.unregistered`, which exposes the current file-manifest
  assumption to the UI (`packages/case-dashboard/frontend/src/components/evidence/EvidenceTab.jsx:3-14`,
  `packages/case-dashboard/frontend/src/components/evidence/EvidenceTab.jsx:57-75`,
  `packages/case-dashboard/frontend/src/components/evidence/EvidenceTab.jsx:94-142`).
- The Reports screen treats reports as generated drafts plus saved JSON-backed
  report records, and downloads markdown directly from
  `/portal/api/reports/{id}/download`
  (`packages/case-dashboard/frontend/src/components/reports/ReportsTab.jsx:53-78`,
  `packages/case-dashboard/frontend/src/components/reports/ReportsTab.jsx:80-160`).

## Gateway/Backend

- Gateway process entry is `sift_gateway.__main__.main()`. It loads
  `gateway.yaml`, validates gateway/TLS config, builds `Gateway(config)`, then
  runs the Starlette app through Uvicorn
  (`packages/sift-gateway/src/sift_gateway/__main__.py:18-42`,
  `packages/sift-gateway/src/sift_gateway/__main__.py:70-112`).
- Config loading recursively interpolates `${VAR}` strings, applies case env
  (`SIFT_CASES_ROOT`, `SIFT_CASE_DIR`), executor security env, and trust output
  cap env, and warns if `portal.session_secret` is absent
  (`packages/sift-gateway/src/sift_gateway/config.py:20-49`,
  `packages/sift-gateway/src/sift_gateway/config.py:49-75`,
  `packages/sift-gateway/src/sift_gateway/config.py:77-118`,
  `packages/sift-gateway/src/sift_gateway/config.py:121-169`).
- `Gateway.create_app()` builds the aggregate MCP endpoint at `/mcp`, optional
  per-backend MCP endpoints under `/mcp/{name}`, health/REST routes, and mounts
  the portal at `/portal` plus legacy dashboard at `/dashboard`
  (`packages/sift-gateway/src/sift_gateway/server.py:840-864`,
  `packages/sift-gateway/src/sift_gateway/server.py:920-973`).
- The portal is a Starlette sub-app created by `create_dashboard_v2_app()`.
  Gateway injects the live `api_keys` dict, `gateway.yaml` path, evidence-chain
  invalidation callback, case activation callback, and response-guard callbacks
  (`packages/case-dashboard/src/case_dashboard/routes.py:4705-4765`,
  `packages/sift-gateway/src/sift_gateway/server.py:931-966`).
- Portal auth uses `PortalSessionMiddleware`: it validates a `sift_session`
  JWT cookie first, then allows bearer fallback only for examiner-role tokens;
  agent tokens are explicitly not accepted by this portal auth surface
  (`packages/case-dashboard/src/case_dashboard/auth.py:1-8`,
  `packages/case-dashboard/src/case_dashboard/auth.py:61-131`). JWTs are
  stdlib HMAC-SHA256 tokens with cookie path `/portal` and SameSite `strict`
  (`packages/case-dashboard/src/case_dashboard/session_jwt.py:1-19`,
  `packages/case-dashboard/src/case_dashboard/session_jwt.py:41-110`).
- Gateway REST v1 exposes tools, backend registration/validation/reload,
  service start/stop/restart, and join-code flows
  (`packages/sift-gateway/src/sift_gateway/rest.py:1082-1098`). Portal proxies
  backend/service management through `/portal/api/backends*` and
  `/portal/api/services/*`
  (`packages/case-dashboard/src/case_dashboard/routes.py:4402-4409`).
- The dashboard API is broad and file-backed: reports, findings, timeline,
  evidence, audit, review delta, case metadata, TODOs, IOCs, summary, evidence
  chain, response guard, auth, service-token lifecycle, cases, and backend
  proxy routes are all registered in `_dashboard_api_routes()`
  (`packages/case-dashboard/src/case_dashboard/routes.py:4344-4410`).
- Realtime surface: no WebSocket route was found in the inspected code. MCP
  streaming is handled through `StreamableHTTPSessionManager`; the auth layer is
  a raw ASGI wrapper because Starlette `BaseHTTPMiddleware` would break SSE
  streaming (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:1-7`,
  `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:174-181`).

## FastMCP and MCP Backends

- The Gateway aggregate MCP server is a low-level MCP `Server("sift-gateway")`
  that lists in-process core tools plus add-on tools, annotates tools with
  category/phase metadata, and adds a synthetic `capability_guide`
  (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:540-622`).
- Every MCP tool call passes through an evidence-chain gate before dispatch.
  If blocked, the Gateway writes a gate audit entry and returns a structured
  block response instead of calling the requested tool
  (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:624-675`).
- Gateway emits a transport-envelope audit entry for non-blocked MCP calls,
  linking the caller identity, role, token ID, source IP, backend, status, and
  backend audit ID without duplicating full params/result payloads
  (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:841-872`).
- Add-on backend manifests are mandatory. `load_and_validate_manifest()` looks
  in `manifest_path`, well-known `packages/<name>/sift-backend.json`, HTTP
  manifest URLs, or `/manifest`; missing or invalid manifests hard-fail backend
  creation (`packages/sift-gateway/src/sift_gateway/backends/__init__.py:133-231`).
- Manifest contract validation enforces at least one tool, namespace prefixes,
  read-only/evidence-class consistency, valid recommended phases, and exactly
  one health tool (`packages/sift-gateway/src/sift_gateway/backends/__init__.py:63-131`).
- Tool routing is manifest-gated: started backends must only expose declared
  names with the declared namespace prefix; stopped manifest-backed backends get
  stub tools from the manifest; duplicate tool names and collisions with core
  tools are rejected (`packages/sift-gateway/src/sift_gateway/server.py:376-497`).
- The add-on manifest schema supports stdio/http transport, namespace,
  `capabilities.provides/requires`, tool metadata, `hidden_from_agent`, and a
  top-level `health` tool (`packages/sift-gateway/src/sift_gateway/sift-backend.schema.json:1-98`).
- `forensic-mcp` is a FastMCP backend for investigation state. It registers
  tools for draft findings, draft timeline events, existing findings, case
  queries, workflow status, TODO management, and optional discipline/reference
  helpers (`packages/forensic-mcp/src/forensic_mcp/server.py:50-68`,
  `packages/forensic-mcp/src/forensic_mcp/server.py:195-228`,
  `packages/forensic-mcp/src/forensic_mcp/server.py:337-388`,
  `packages/forensic-mcp/src/forensic_mcp/server.py:728-760`,
  `packages/forensic-mcp/src/forensic_mcp/server.py:948-1117`).
- `forensic-rag-mcp` is a FastMCP backend with an in-memory Chroma/RAG index
  and three read-only knowledge tools; it starts in degraded mode when the
  Chroma index is absent (`packages/forensic-rag-mcp/src/rag_mcp/server.py:59-88`,
  `packages/forensic-rag-mcp/src/rag_mcp/server.py:122-164`,
  `packages/forensic-rag-mcp/src/rag_mcp/server.py:309-345`).
- `opencti-mcp` and `windows-triage-mcp` use low-level MCP `Server` classes
  rather than FastMCP. OpenCTI registers read-only CTI tools
  (`packages/opencti-mcp/src/opencti_mcp/server.py:120-154`), while
  windows-triage opens local baseline databases in read-only mode by default
  and exposes stdio MCP (`packages/windows-triage-mcp/src/windows_triage_mcp/server.py:140-205`,
  `packages/windows-triage-mcp/src/windows_triage_mcp/server.py:1660-1718`).
- Case scoping is primarily process/env based today. Gateway config applies
  `SIFT_CASE_DIR`, stdio backends inherit it, OpenSearch derives active case
  from it, and legacy CLI paths fall back to `~/.sift/active_case`
  (`packages/sift-gateway/src/sift_gateway/config.py:49-75`,
  `packages/opensearch-mcp/src/opensearch_mcp/server.py:3504-3528`,
  `packages/sift-common/src/sift_common/audit.py:103-144`).

## JSON/File-Based State

- Case roots default to `SIFT_CASES_ROOT`, then `SIFT_CASES_DIR`, then
  `~/cases`; integrity/state records default to `/var/lib/sift`, with
  `SIFT_STATE_DIR` and test-temp fallbacks
  (`packages/sift-core/src/sift_core/case_io.py:21-65`).
- Active case resolution is split across `SIFT_CASE_DIR`, `gateway.yaml`
  `case.dir`, and legacy `~/.sift/active_case`. Core path resolution requires
  an active case and jails relative/absolute paths inside the case directory
  (`packages/sift-core/src/sift_core/case_io.py:136-193`,
  `packages/case-dashboard/src/case_dashboard/routes.py:183-202`,
  `packages/case-dashboard/src/case_dashboard/routes.py:3501-3542`).
- Portal case creation computes the case ID from `casename` plus UTC timestamp,
  creates `audit`, `evidence`, `extractions`, `reports`, and `agent`
  subdirectories, writes `CASE.yaml`, initializes `findings.json`,
  `timeline.json`, `evidence.json`, `todos.json`, and `iocs.json`, initializes
  the evidence chain, and touches the approvals log
  (`packages/case-dashboard/src/case_dashboard/routes.py:3752-3848`).
- Case metadata is `CASE.yaml`; portal reads it through `get_case()`
  (`packages/case-dashboard/src/case_dashboard/routes.py:1797-1815`) and core
  reads it through `load_case_meta()`
  (`packages/sift-core/src/sift_core/case_io.py:222-230`).
- Findings, timeline, TODOs, IOCs, and legacy evidence registry are file-backed
  in the case directory. Core helpers load/save `findings.json`,
  `timeline.json`, `todos.json`, `iocs.json`, and `evidence.json`
  (`packages/sift-core/src/sift_core/case_io.py:252-332`). Findings,
  timeline, and IOCs use chmod-444 protected writes, while TODOs use atomic
  writes without the protected chmod wrapper
  (`packages/sift-core/src/sift_core/case_io.py:119-133`,
  `packages/sift-core/src/sift_core/case_io.py:263-321`).
- Portal read APIs expose these files directly: `get_findings()` reads
  `findings.json`, `get_timeline()` reads `timeline.json`, `get_iocs()` reads
  `iocs.json`, `get_todos()` reads `todos.json`, and `get_summary()` counts
  findings/timeline/evidence/TODOs from JSON files
  (`packages/case-dashboard/src/case_dashboard/routes.py:1624-1673`,
  `packages/case-dashboard/src/case_dashboard/routes.py:1864-1915`,
  `packages/case-dashboard/src/case_dashboard/routes.py:2147-2201`).
- Pending human review is `pending-reviews.json`. Portal reads it in
  `get_delta()` and the approval application code reads/writes
  `pending-reviews.json`, `findings.json`, `timeline.json`, and `iocs.json`
  (`packages/case-dashboard/src/case_dashboard/routes.py:1780-1794`,
  `packages/case-dashboard/src/case_dashboard/routes.py:1221-1598`).
- Approvals are recorded under state-root case records as `approvals.jsonl`,
  not only inside the case directory. `case_approvals_path()` returns
  `case_records_dir(case_dir) / "approvals.jsonl"` and `write_approval_log()`
  appends approval entries there
  (`packages/sift-core/src/sift_core/case_io.py:73-83`,
  `packages/sift-core/src/sift_core/case_io.py:335-360`).
- Reports are generated as in-memory drafts, then saved as JSON files under
  `case_dir/reports/{uuid}.json`; downloads render markdown from the JSON or
  pending draft (`packages/case-dashboard/src/case_dashboard/routes.py:4109-4141`,
  `packages/case-dashboard/src/case_dashboard/routes.py:4144-4341`).
- MCP/service token state currently lives in `gateway.yaml` `api_keys`, keyed
  by the raw token string. The template shows raw token placeholders as mapping
  keys, and `create_token()` writes `{raw_token: key_info}` to the gateway
  config while returning the raw token once to the browser
  (`configs/gateway.yaml.template:113-138`,
  `packages/case-dashboard/src/case_dashboard/routes.py:3060-3199`).
- Audit entries are JSONL files under state-root case audit directories:
  `sift_common.audit.AuditWriter` resolves the audit dir from explicit config,
  `SIFT_AUDIT_DIR`, active `SIFT_CASE_DIR`, or legacy `~/.sift/active_case`,
  then appends `<mcp_name>.jsonl` with fsync
  (`packages/sift-common/src/sift_common/audit.py:21-50`,
  `packages/sift-common/src/sift_common/audit.py:103-144`,
  `packages/sift-common/src/sift_common/audit.py:246-332`).
- Agent/tool output and workflow-like state are also file-backed. Gateway output
  caps spill oversized redacted results under the case agent area
  (`configs/gateway.yaml.template:103-111`), OpenSearch ingest status is JSON
  under `~/.sift/ingest-status`
  (`packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:13-90`), and
  OpenSearch logs go under `~/.sift/ingest-logs`
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:3112-3157`).

## Evidence Vault and Audit

- The strongest existing evidence-integrity subsystem is
  `sift_core.evidence_chain`: its module doc states the authority is
  `evidence-manifest.json + evidence-ledger.jsonl`, with `evidence.json` kept
  as compatibility view (`packages/sift-core/src/sift_core/evidence_chain.py:1-8`).
- Evidence chain records live in the state-root case record directory via
  `manifest_path()`/`ledger_path()`, not necessarily in the case directory
  (`packages/sift-core/src/sift_core/evidence_chain.py:49-66`). Test/temp cases
  can shadow files into the case dir
  (`packages/sift-core/src/sift_core/evidence_chain.py:77-80`).
- Chain initialization writes manifest v0 and an append-only ledger file, and
  later operations HMAC-sign ledger events, compute manifest hashes, detect
  missing/modified/unregistered files, and optionally set Linux immutable flags
  (`packages/sift-core/src/sift_core/evidence_chain.py:87-113`,
  `packages/sift-core/src/sift_core/evidence_chain.py:153-176`,
  `packages/sift-core/src/sift_core/evidence_chain.py:232-338`,
  `packages/sift-core/src/sift_core/evidence_chain.py:431-760`).
- Portal evidence chain endpoints preserve this design: status is built from
  `chain_status`, `load_manifest`, and `diff_manifest`; seal/ignore/retire
  mutate the chain; HMAC verification writes `evidence-verify-state.json`;
  optional anchoring writes Solana proof state
  (`packages/case-dashboard/src/case_dashboard/routes.py:540-592`,
  `packages/case-dashboard/src/case_dashboard/routes.py:714-1026`,
  `packages/case-dashboard/src/case_dashboard/routes.py:1034-1074`).
- Portal `get_evidence()` now prefers ACTIVE entries from the sealed manifest
  and only falls back to legacy `evidence.json` when the manifest has no active
  files (`packages/case-dashboard/src/case_dashboard/routes.py:1676-1712`).
- The evidence gate is preserved at the Gateway MCP layer and blocks all agent
  tool calls when the chain is unsealed or not OK
  (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:637-675`). This is
  a solid policy boundary, but it currently depends on the active case env and
  file-backed manifest/ledger state.
- Audit is also reasonably structured and should be preserved conceptually:
  backend tools write detailed audit records, and Gateway writes a transport
  envelope linking caller identity to backend audit IDs
  (`packages/sift-common/src/sift_common/audit.py:246-332`,
  `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:841-872`). The
  storage authority is still filesystem JSONL.

## Native Linux/SIFT Workflows

- Core agent execution exposes `run_command` as a structured, validated native
  command tool, and case paths are jailed through `resolve_case_path`
  (`packages/sift-core/src/sift_core/agent_tools.py:250-268`,
  `packages/sift-core/src/sift_core/case_io.py:157-193`).
- Native execution is centralized in `sift_core.execute.executor.execute()`,
  which runs `python -m sift_core.execute.worker`, can drop to a configured
  runtime user, captures/truncates stdout/stderr, and saves large output under
  `case/agent/run_commands/outputN`
  (`packages/sift-core/src/sift_core/execute/executor.py:27-87`,
  `packages/sift-core/src/sift_core/execute/executor.py:90-205`,
  `packages/sift-core/src/sift_core/execute/executor.py:253-358`).
- The generic command parser avoids shell execution, supports pipes/sequences
  and redirects as structured plans, defaults cwd to `SIFT_CASE_DIR`, validates
  stages, and can parse large CSV/JSON/text output into saved artifacts
  (`packages/sift-core/src/sift_core/execute/tools/generic.py:72-112`,
  `packages/sift-core/src/sift_core/execute/tools/generic.py:150-384`).
- OpenSearch ingest is the largest native/long-running workflow. MCP launches
  background subprocesses with `systemd-run --user --scope` when available,
  falls back to `Popen`, writes status before/after spawn, enforces concurrency,
  and tells users to poll `opensearch_ingest_status()`
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:2900-3003`,
  `packages/opensearch-mcp/src/opensearch_mcp/server.py:3006-3157`).
- The ingest parser surface is broad and local-file oriented: OpenSearch source
  includes parsers for EVTX, CSV/delimited, JSON, Plaso, memory, Prefetch,
  SRUM, transcripts, W3C/IIS, Defender, tasks, WER, SSH, access logs, and more
  (`packages/opensearch-mcp/src/opensearch_mcp`: file inventory;
  `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:514-1045`).
- Shell/native setup is part of the product shape. `configs/gateway.yaml.template`
  defines the runtime executor user and command security policy
  (`configs/gateway.yaml.template:18-102`), while the AppArmor template grants
  read access to evidence, write access to case metadata/output areas, and
  execution rights for selected forensic tooling
  (`configs/apparmor/sift-gateway.template:30-115`).

## OpenSearch

- Current OpenSearch is both an optional add-on backend and part of the
  `standard` dependency group (`pyproject.toml:41-46`). The Gateway template
  deliberately starts with `backends: {}` and says add-ons are external,
  optional, and registered through the portal/setup flow
  (`configs/gateway.yaml.template:161-169`).
- The OpenSearch backend manifest declares namespace `opensearch`, requires
  `https://localhost:9200`, provides `search`, `ingest`, and `enrichment`, and
  uses `opensearch_status` as health tool
  (`packages/opensearch-mcp/sift-backend.json:1-14`,
  `packages/opensearch-mcp/sift-backend.json:83-93`,
  `packages/opensearch-mcp/sift-backend.json:197-199`).
- OpenSearch MCP tool registration is in `server.py` using FastMCP
  `FastMCP("opensearch-mcp")`. Tools include search/count/aggregate/get event,
  timeline, field values, status, shard status, case summary, container
  inspect, ingest, ingest status, intel enrichment, triage enrichment,
  detections, and host fix (`packages/opensearch-mcp/src/opensearch_mcp/server.py:16-49`,
  `packages/opensearch-mcp/src/opensearch_mcp/server.py:711-1207`,
  `packages/opensearch-mcp/src/opensearch_mcp/server.py:1290-2374`,
  `packages/opensearch-mcp/src/opensearch_mcp/server.py:2786-3665`).
- Connection config is file-based: `get_client()` reads explicit config path,
  `OPENSEARCH_CONFIG`, or `~/.sift/opensearch.yaml`, requiring `user` and
  `password` (`packages/opensearch-mcp/src/opensearch_mcp/client.py:12-44`).
  `_get_os()` caches the client, checks cluster health, and auto-installs the
  winlog pipeline/templates on first verified connection
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:411-452`).
- Index scoping is case-prefixed and guarded. `_validate_index()` rejects index
  segments that do not start with `case-`
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:32-45`), and
  `_resolve_index()` defaults to `case-{active_case}-*` or `case-*`
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:564-573`).
- Canonical index naming is `case-{case_id}-{artifact_type}-{hostname}` with
  lowercased sanitized components
  (`packages/opensearch-mcp/src/opensearch_mcp/paths.py:194-220`). The README
  documents the same convention and examples
  (`packages/opensearch-mcp/README.md:166-174`).
- Ingest code uses this naming for EVTX, Hayabusa, EZ-tool artifacts, Plaso
  artifacts, and custom artifacts (`packages/opensearch-mcp/src/opensearch_mcp/ingest.py:412-459`,
  `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:560-588`,
  `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:732-777`,
  `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:863-911`,
  `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:986-1017`).
- Current document/index schemas are OpenSearch templates under
  `packages/opensearch-mcp/src/opensearch_mcp/mappings/`. They cover
  `case-*-evtx-*`, `case-*-hayabusa-*`, `case-*-json-*`,
  `case-*-vol-*`, `case-*-prefetch-*`, `case-*-srum-*`,
  `case-*-transcripts-*`, `case-*-defender-*`, `case-*-tasks-*`,
  `case-*-wer-*`, `case-*-ssh-*`, `case-*-accesslog-*`, and CSV/delimited
  families such as `case-*-amcache-*`, `case-*-shimcache-*`,
  `case-*-mft-*`, `case-*-usn-*`, `case-*-registry-*`, `case-*-iis-*`,
  `case-*-httperr-*`, and `case-*-firewall-*`
  (`packages/opensearch-mcp/src/opensearch_mcp/mappings/evtx_ecs_template.json:3`,
  `packages/opensearch-mcp/src/opensearch_mcp/mappings/hayabusa_template.json:2`,
  `packages/opensearch-mcp/src/opensearch_mcp/mappings/json_template.json:2`,
  `packages/opensearch-mcp/src/opensearch_mcp/mappings/vol3_template.json:3`,
  `packages/opensearch-mcp/src/opensearch_mcp/mappings/csv_template.json:3-13`,
  `packages/opensearch-mcp/src/opensearch_mcp/mappings/w3c_template.json:2`).
- Availability is checked at two levels: the add-on manifest `requires`
  `https://localhost:9200`, which Gateway evaluates/gates in backend status
  (`packages/sift-gateway/src/sift_gateway/rest.py:166-170`,
  `packages/sift-gateway/src/sift_gateway/rest.py:296-363`), and the tool
  client health check raises a user-facing "OpenSearch not running or not
  reachable" error (`packages/opensearch-mcp/src/opensearch_mcp/server.py:423-451`).
- Gateway does not expose a first-class portal OpenSearch search API in the
  inspected dashboard route list. The current Gateway exposure is MCP add-on
  routing plus backend/service management/status through portal proxy routes
  (`packages/case-dashboard/src/case_dashboard/routes.py:4344-4410`,
  `packages/sift-gateway/src/sift_gateway/server.py:971-973`).
- OpenSearch is optional/standalone in setup today. Root `docker-compose.yml`
  starts a local single-node OpenSearch 2.18.0 with security disabled on
  `127.0.0.1:9200`; `packages/opensearch-mcp/docker/docker-compose.yml` starts
  OpenSearch 3.5.0 with an initial admin password and persistent volume
  (`docker-compose.yml:1-42`,
  `packages/opensearch-mcp/docker/docker-compose.yml:1-17`).

## Tests, Docs, and Setup

- Test coverage is package-local. Current Python tests exist for
  case-dashboard auth/backends/case/evidence/reports/response guard/session/
  tokens/TODOs, forensic-mcp tool consolidation and workflow status,
  opensearch-mcp parsers/ingest/status/templates/security/detections/shards,
  sift-core case/evidence/audit/execution/verification/reporting, sift-gateway
  auth/evidence gate/REST/tool routing/security, and windows-triage
  (`find packages -path '*/tests/*.py' -type f` output, 2026-06-06).
- Pytest discovers both `tests` and `packages`, with package-specific settings
  in package pyprojects (`pyproject.toml:91-93`,
  `packages/opensearch-mcp/pyproject.toml:50-55`).
- Existing docs include high-level docs, hardening, evidence chain of custody,
  this migration workspace, OpenSearch docs/security notes, OpenCTI README,
  and forensic RAG attribution docs (`find docs packages -maxdepth 3 -name '*.md'`,
  2026-06-06).
- Setup files found at repo root and package level include `install.sh`,
  `configs/gateway.yaml.template`, `configs/apparmor/sift-gateway.template`,
  root `docker-compose.yml`, OpenCTI compose files, and OpenSearch package
  compose files (`find . -maxdepth 4 -name 'docker-compose*.yml' -o -name '*.template' -o -name 'install.sh'`,
  2026-06-06).
- OpenCTI compose includes Redis for OpenCTI itself (`docker-compose.opencti.yml:15-24`,
  `docker-compose.opencti.yml:89-103`). A targeted search for
  `supabase|postgres|postgresql|psql|redis|rq|celery` found no Supabase
  implementation/config and no Redis/RQ/Celery job implementation; hits were
  OpenCTI Redis compose, incidental DFIR knowledge text, and response-guard
  secret-pattern tests.

## Current-State Migration-Sensitive Findings

- The largest current-state fact is split authority: case objects live in flat
  case JSON/YAML, integrity/audit/approval state lives under `/var/lib/sift`
  or `SIFT_STATE_DIR`, tokens live in `gateway.yaml`, active case state lives in
  env plus legacy pointer files, and OpenSearch job state lives under
  `~/.sift`. This is visible across `case_io.py`, dashboard routes,
  `AuditWriter`, token lifecycle routes, and OpenSearch ingest status code.
- The evidence chain and Gateway evidence gate are mature enough to preserve as
  invariants, but their current storage and case lookup are file/env based.
- The highest-risk current-state area for migration planning is token and case
  scoping: the future charter expects hash-only, case/tool-scoped service
  tokens, while current token state is raw-token-keyed `gateway.yaml`
  `api_keys` and case scope is inherited primarily through process environment.
