# Execution Current State

Last updated: 2026-06-06.

Scope: current-state inventory for execution, native workflows, parsers,
ingestion, evidence operations, audit operations, and workflow/status tracking.
This document does not design the target job schema, REST APIs, MCP tools, or
execution roadmap.

Run 25 status note: this is a **pre-D27b execution snapshot**. MCP/Gateway rows
that mention low-level `create_mcp_server()`, `create_backend_mcp_server()`, or
per-backend `/mcp/{name}` routes are historical. D27b landed one aggregate
FastMCP `/mcp` policy path and removed per-backend routes. The execution
inventory remains useful for file/env authority, synchronous workflows, parser,
OpenSearch ingest, evidence, and audit grounding.

## 1. Current Execution Entry Points

### Frontend/operator portal

| Entry point | Trigger and inputs | Case context | Sync model | Status recorded | Audit written | OpenSearch involved |
| --- | --- | --- | --- | --- | --- | --- |
| Portal polling | `useDataPolling()` calls case, summary, findings, review delta, timeline, evidence chain, IOCs, TODOs, and reports every 15 seconds (`packages/case-dashboard/frontend/src/hooks/useDataPolling.js:16-43`). Endpoint wrappers live in `endpoints.js` (`packages/case-dashboard/frontend/src/api/endpoints.js:12-77`). | Portal APIs resolve the active case through `_resolve_case_dir()`, which calls `sift_common.resolve_case_dir()` and requires `CASE.yaml` (`packages/case-dashboard/src/case_dashboard/routes.py:183-195`). | Async browser polling, but each API request is synchronous request/response. | Frontend Zustand cache only; authoritative current state is file-backed through portal APIs. | Poll reads do not write audit in the inspected route handlers. | Not directly. |
| Evidence chain operations | Evidence UI calls `getChainStatus`, `postChainRescan`, `getChainChallenge`, `postChainSeal`, `postChainIgnore`, `postChainRetire`, `postChainVerifyHmac`, and `postChainAnchor` (`packages/case-dashboard/frontend/src/components/evidence/EvidenceTab.jsx:3-14`, `packages/case-dashboard/frontend/src/components/evidence/EvidenceTab.jsx:81-142`). Portal routes are registered at `/api/evidence/chain/*` (`packages/case-dashboard/src/case_dashboard/routes.py:4371-4379`). | `_resolve_case_dir()` from active case env/pointer (`packages/case-dashboard/src/case_dashboard/routes.py:183-195`). | Synchronous route calls. Some operations can do expensive hashing or anchoring inline (`packages/case-dashboard/src/case_dashboard/routes.py:714-801`). | Evidence manifest/ledger status under the state-root case records; status response built from `chain_status()` (`packages/case-dashboard/src/case_dashboard/routes.py:635-665`). | Evidence ledger events are appended by evidence-chain functions, not by `AuditWriter` (`packages/sift-core/src/sift_core/evidence_chain.py:431-535`, `packages/sift-core/src/sift_core/evidence_chain.py:753-760`). | No. |
| Review/approval workflow | Portal `post_delta` stages review changes and `post_commit` commits pending reviews; `_apply_delta()` applies `pending-reviews.json` to findings/timeline/IOCs (`packages/case-dashboard/src/case_dashboard/routes.py:1221-1285`, `packages/case-dashboard/src/case_dashboard/routes.py:4347-4370`). | Active case via `_resolve_case_dir()`; `_apply_delta()` validates `delta.case_id` against `CASE.yaml` or case directory name (`packages/case-dashboard/src/case_dashboard/routes.py:1260-1278`). | Synchronous. Uses `pending-reviews.processing` rename as a local lock/crash-recovery mechanism (`packages/case-dashboard/src/case_dashboard/routes.py:1235-1252`). | `findings.json`, `timeline.json`, `iocs.json`, and `pending-reviews.json`/`.processing` (`packages/case-dashboard/src/case_dashboard/routes.py:1280-1285`). | Approval log entries and HMAC ledger entries are best-effort after file writes according to the function comments (`packages/case-dashboard/src/case_dashboard/routes.py:1227-1234`); approvals path is `/var/lib/sift/<case>/approvals.jsonl` unless overridden (`packages/sift-core/src/sift_core/case_io.py:78-83`, `packages/sift-core/src/sift_core/case_io.py:335-360`). | No. |
| Report generation | Reports UI posts `{profile, finding_ids, start_date, end_date}` and later saves/downloads reports (`packages/case-dashboard/frontend/src/components/reports/ReportsTab.jsx:80-160`). Portal `generate_report_route()` calls `generate_report_data()` and stores an in-memory draft (`packages/case-dashboard/src/case_dashboard/routes.py:4144-4218`). | Active case via `_resolve_case_dir()`; `case_id = case_dir.name` for in-flight lock (`packages/case-dashboard/src/case_dashboard/routes.py:4152-4160`). | Synchronous request; duplicate in-flight generation for the same case is blocked with an in-memory set (`packages/case-dashboard/src/case_dashboard/routes.py:4157-4160`). | Drafts in `_PENDING_REPORTS`; saved reports as `case/reports/{uuid}.json` (`packages/case-dashboard/src/case_dashboard/routes.py:4192-4198`, `packages/case-dashboard/src/case_dashboard/routes.py:4220-4256`). | No `AuditWriter` call found in the inspected report route. | No direct OpenSearch call in the inspected route. |
| Backend/service management | Portal proxies backend and service operations through `/api/backends*` and `/api/services/{name}/*` (`packages/case-dashboard/src/case_dashboard/routes.py:4402-4409`, `packages/case-dashboard/src/case_dashboard/routes.py:4471-4665`). | Uses portal session identity; not case-specific in the inspected handlers. | Synchronous route handlers; backend registration can schedule Gateway reload (`packages/sift-gateway/src/sift_gateway/rest.py:986-1057`). | Gateway config `gateway.yaml` for backend registration (`packages/sift-gateway/src/sift_gateway/rest.py:1019-1037`). | No route-local audit found in inspected portal proxy handlers. | Only if the managed backend is OpenSearch; no direct indexing/querying here. |

### Gateway REST APIs

Gateway REST v1 exposes tool calls, backend registration/reload, service
start/stop/restart, and join-code flows (`packages/sift-gateway/src/sift_gateway/rest.py:1082-1098`).
`POST /api/v1/tools/{tool_name}` routes through Gateway tool dispatch. Backend
registration persists config to `gateway.yaml`, creates the backend object, and
rebuilds the tool map (`packages/sift-gateway/src/sift_gateway/rest.py:986-1057`).

The inspected REST route list does not show durable execution jobs. Backend and
service actions are operational control calls, not parser jobs.

### FastMCP/Gateway MCP tools

| Entry point | Trigger and inputs | Case context | Sync model | Status recorded | Audit written | OpenSearch involved |
| --- | --- | --- | --- | --- | --- | --- |
| Aggregate `/mcp` endpoint | `create_mcp_server()` lists tools and calls `gateway.call_tool(name, arguments)` (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:540-624`). | Evidence gate reads `SIFT_CASE_DIR`; core tools and add-on stdio backends inherit Gateway case env (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:637-643`, `packages/sift-gateway/src/sift_gateway/server.py:949-952`). | MCP call is synchronous from caller perspective. Add-on backend calls have a 300 second timeout in `Gateway.call_tool()` (`packages/sift-gateway/src/sift_gateway/server.py:762-787`). | No durable job state; tool-specific file/status writes only. | Evidence-gate block audit and transport envelope audit are written by Gateway (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:656-668`, `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:841-871`). | Yes when OpenSearch add-on tools are registered. |
| Per-backend `/mcp/{name}` endpoints | `create_backend_mcp_server()` exposes a single backend's tools directly (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:876-977`). | Same auth wrapper, but this path calls backend directly and does not run the aggregate evidence-gate block shown above. | Synchronous backend tool call; no 300 second wrapper visible in this per-backend path (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:898-910`). | Backend-specific only. | HTTP backend proxy audit is written here; stdio backend self-audit is relied on (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:947-973`). | Yes if backend is `opensearch`. |
| Core `run_command` tool | Core specs expose `run_command` as a detection-phase tool (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:564-567`, `packages/sift-core/src/sift_core/agent_tools.py:91-220`). `_run_command(args, examiner, audit)` accepts command, purpose, timeout, save_output, working_dir, input_files, and preview_lines (`packages/sift-core/src/sift_core/agent_tools.py:488-610`). | `working_dir` is jailed through `resolve_case_path()`; otherwise cwd defaults to `SIFT_CASE_DIR` (`packages/sift-core/src/sift_core/agent_tools.py:513-519`). | Synchronous native subprocess execution. | Saved stdout/stderr can be written under case `agent/run_commands`, `extractions`, or `tmp` (`packages/sift-core/src/sift_core/execute/executor.py:185-203`, `packages/sift-core/src/sift_core/execute/executor.py:253-365`). | `AuditWriter.log()` records command, purpose, result, input files/hashes, elapsed time, stages, and privilege events (`packages/sift-core/src/sift_core/agent_tools.py:660-705`). | No direct OpenSearch dependency. |
| Core finding/timeline tools | `record_finding` and `record_timeline_event` are core tool specs (`packages/sift-core/src/sift_core/agent_tools.py:107-210`). | `CaseManager` resolves the active case (`packages/sift-core/src/sift_core/case_manager.py:1877-1885`). | Synchronous file writes. | Findings/timeline/IOCs/TODO JSON files (`packages/sift-core/src/sift_core/case_io.py:252-321`). | Core wrapper logs `record_finding`; FastMCP backend also logs record calls (`packages/sift-core/src/sift_core/agent_tools.py:761-790`, `packages/forensic-mcp/src/forensic_mcp/server.py:164-168`, `packages/forensic-mcp/src/forensic_mcp/server.py:221-226`). | No direct OpenSearch dependency. |
| Forensic MCP workflow tools | `forensic-mcp` creates `CaseManager` and `AuditWriter` and exposes `record_finding`, `record_timeline_event`, `query_case`, `workflow_status`, and TODO tools (`packages/forensic-mcp/src/forensic_mcp/server.py:50-68`, `packages/forensic-mcp/src/forensic_mcp/server.py:337-388`, `packages/forensic-mcp/src/forensic_mcp/server.py:728-760`). | `CaseManager._require_active_case()` / active case resolution (`packages/forensic-mcp/src/forensic_mcp/server.py:403-417`). | Synchronous FastMCP calls. | Case JSON files plus `~/.sift/ingest-status` read-only workflow status (`packages/forensic-mcp/src/forensic_mcp/server.py:484-518`). | Tool-level audit for record operations and selected reference tools (`packages/forensic-mcp/src/forensic_mcp/server.py:164-168`, `packages/forensic-mcp/src/forensic_mcp/server.py:221-226`, `packages/forensic-mcp/src/forensic_mcp/server.py:963-970`). | Workflow status reads OpenSearch ingest status files and recommends OpenSearch tools (`packages/forensic-mcp/src/forensic_mcp/server.py:484-518`, `packages/forensic-mcp/src/forensic_mcp/server.py:567-595`). |

### Native Linux backend commands

`run_command()` parses and validates commands, launches argv stages with
`shell=False`, and executes through `execute()` (`packages/sift-core/src/sift_core/execute/tools/generic.py:72-178`).
`execute()` uses an isolated worker, enforces timeouts/output caps, and can save
output files with SHA-256 hashes (`packages/sift-core/src/sift_core/execute/executor.py:122-204`,
`packages/sift-core/src/sift_core/execute/executor.py:273-365`). It is not a
durable background job; the caller waits for completion or timeout.

### Parser scripts/modules and OpenSearch ingest tools

`opensearch_ingest()` is the main MCP entry point. It accepts `path`, `format`,
`hostname`, `index_suffix`, timestamp/delimiter options, include/exclude,
memory tier/plugins, `dry_run`, `force`, VSS/archive options, and related flags
(`packages/opensearch-mcp/src/opensearch_mcp/server.py:1826-1906`). It resolves
case context from `_get_active_case()`, which reads `SIFT_CASE_DIR` and falls
back to `~/.sift/active_case` (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1913-1919`,
`packages/opensearch-mcp/src/opensearch_mcp/server.py:3504-3527`).

For container/auto ingest and non-auto ingest, the MCP tool launches
`python -m opensearch_mcp.ingest_cli ... --case <case_id>` as a subprocess and
tracks status in files (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1702-1823`,
`packages/opensearch-mcp/src/opensearch_mcp/server.py:3006-3168`,
`packages/opensearch-mcp/src/opensearch_mcp/server.py:3292-3501`). OpenSearch
query/status tools run synchronously against the OpenSearch client, for example
`opensearch_search()` and `opensearch_status()` (`packages/opensearch-mcp/src/opensearch_mcp/server.py:711-791`,
`packages/opensearch-mcp/src/opensearch_mcp/server.py:1160-1203`).

## 2. Current Parser and Ingestion Model

### Ingest orchestration

| Workflow | File/function | Purpose | Inputs | Outputs/status | Case/evidence context | Destination | Audit |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Active-case ingest MCP | `opensearch_ingest()` in `server.py` (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1826-1975`). | Preview or start ingestion for containers, JSON, delimited logs, access logs, or memory. | Path, format, hostname, filters, parsing flags, dry_run/force. | Preview response or background run response with pid/run_id. | Case from `_get_active_case()`; evidence path resolved/jail-checked before use (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1913-1971`). | OpenSearch indices. | Start/preview audit in server launch paths (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1794-1823`, `packages/opensearch-mcp/src/opensearch_mcp/server.py:3159-3167`). |
| Generic background ingest | `_launch_background()` (`packages/opensearch-mcp/src/opensearch_mcp/server.py:3006-3168`). | Launch JSON/delimited/accesslog ingest CLI subprocess. | Subcommand, path, hostname, suffix/time/delimiter/recursive options. | `~/.sift/ingest-status/*.json`, `~/.sift/ingest-logs/{run_id}.log`. | Active case from `_get_active_case()`. | OpenSearch. | Audits background start only in parent process. |
| Container scan ingest | `_launch_container_ingest()` (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1702-1823`). | Launch full scan of disk/archive/container evidence. | Resolved evidence path, case_id, hostname, include/exclude, timezone, VSS/archive flags. | Background pid/run_id, log file, optional filesystem metadata sidecar under `case/agent/ingest`. | Explicit `case_id` from active case; source path under case. | OpenSearch. | Start audit with input file and run_id. |
| CLI ingest | `ingest_cli.py` imports `discover()` and `ingest()` and uses `--case` (`packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py:1-27`). | Subprocess/CLI execution target for MCP-launched ingest. | CLI args including case ID and source path. | Writes ingest status through `write_status()` (`packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py:19-24`). | Case directory from `cases_root()/case_id` (`packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py:30-45`). | OpenSearch. | Uses `AuditWriter` imported at CLI top (`packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py:15-24`). |
| Host/artifact ingest loop | `ingest()` and `_ingest_hosts()` (`packages/opensearch-mcp/src/opensearch_mcp/ingest.py:179-305`, `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:514-830`). | Discover selected artifacts, run parsers, update status, count indexed/skipped/failed docs. | `DiscoveredHost` list, OpenSearch client, `AuditWriter`, case_id, include/exclude/full flags, status pid/run_id. | `IngestResult`; status host/artifact records. | Host artifact paths from triage discovery; evidence-relative paths via `relative_evidence_path()` (`packages/opensearch-mcp/src/opensearch_mcp/ingest.py:760-770`). | OpenSearch indices named by case/artifact/host. | Per-artifact success/failure audit with source file, hash, run_id, and bulk failure counts (`packages/opensearch-mcp/src/opensearch_mcp/ingest.py:781-804`, `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:820-827`). |
| Ingest manifest sidecar | `_write_ingest_manifest()` (`packages/opensearch-mcp/src/opensearch_mcp/ingest.py:29-95`). | Write per-source parser provenance JSON. | Source path, hostname, artifact type, sha256, doc_count. | `case/audit/ingest-manifests/*.manifest.json`. | Case from `SIFT_CASE_DIR` or legacy active-case pointer. | Filesystem audit sidecar, not OpenSearch. | Sidecar only; no `AuditWriter` call inside this helper. |
| Hayabusa batch | `run_hayabusa_batch()` (`packages/opensearch-mcp/src/opensearch_mcp/ingest.py:354-505`). | Run Hayabusa over EVTX dirs and ingest generated CSV. | Hosts, client, case_id, optional audit/progress callbacks. | CSV under `~/.sift/hayabusa-output`; OpenSearch hayabusa index; failed halt status on missing rules. | Host EVTX dirs from discovered hosts. | OpenSearch via `ingest_delimited()`. | Logs `ingest_hayabusa` per host when audit is available (`packages/opensearch-mcp/src/opensearch_mcp/ingest.py:390-399`, `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:475-480`). |
| Memory ingest | `idx_ingest_memory()` and `ingest_memory()` (`packages/opensearch-mcp/src/opensearch_mcp/server.py:3292-3501`, `packages/opensearch-mcp/src/opensearch_mcp/parse_memory.py:344-470`). | Run Volatility 3 plugins and index plugin results. | Memory image path, hostname, tier/plugins, dry_run. | Background status/log files; per-plugin results. | Active case for launch; `image_path` passed to parser; best-effort evidence registration attempted through Gateway `evidence_register` (`packages/opensearch-mcp/src/opensearch_mcp/parse_memory.py:328-341`). | OpenSearch per-plugin indices. | Parent launch audit plus per-plugin audit callback when supplied (`packages/opensearch-mcp/src/opensearch_mcp/server.py:3493-3500`, `packages/opensearch-mcp/src/opensearch_mcp/parse_memory.py:452-470`). |

### Parser modules

Most parser modules index directly to OpenSearch by building bulk actions and
calling `flush_bulk()`. They stamp partial provenance fields such as
`vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`, optional
`vhir.vss_id`, and `pipeline_version`:

| Parser | File/function evidence | Purpose and inputs | Output destination | Status/audit behavior |
| --- | --- | --- | --- | --- |
| Access logs | `parse_accesslog.py`, `ingest_accesslog()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_accesslog.py:33-132`). | Parse web access logs from a path, with hostname/source/pipeline metadata. | OpenSearch bulk actions. | Returns indexed/skipped/bulk_failed; audit is caller-owned. |
| CSV/EZ output | `parse_csv.py`, `ingest_csv()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_csv.py:87-206`). | Read CSV rows from Zimmerman/EZ outputs or Hayabusa CSV. | OpenSearch bulk actions. | Returns indexed/skipped/bulk_failed; caller writes audit. |
| Defender MPLog | `parse_defender.py`, `parse_mplog()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_defender.py:124-298`). | Parse Defender logs from a directory. | OpenSearch bulk actions. | Returns indexed/skipped/bulk_failed; caller writes audit. |
| Delimited/Zeek/bodyfile | `parse_delimited.py`, `ingest_delimited()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_delimited.py:169-280`). | Parse CSV/TSV/Zeek-style delimited records. | OpenSearch bulk actions. | Returns indexed/skipped/bulk_failed/host_renamed; caller writes audit/status. |
| EVTX | `parse_evtx.py`, `parse_and_index()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_evtx.py:36-137`). | Parse EVTX with pyevtx-rs; deterministic IDs include index/source/event record. | OpenSearch `evtx` index. | Returns indexed/skipped/bulk_failed; caller writes per-file audit/status. |
| JSON/JSONL | `parse_json.py`, `ingest_json()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_json.py:135-244`). | Parse JSON/JSONL records. | OpenSearch bulk actions. | Returns indexed/skipped/bulk_failed/host_renamed; caller writes audit/status. |
| Plaso-derived prefetch/SRUM | `parse_plaso.py`, `_ingest_jsonl()`, `parse_prefetch()`, `parse_srum()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_plaso.py:72-203`). | Run/ingest Plaso JSONL fallback for prefetch/SRUM. | OpenSearch bulk actions. | Returns counts; caller writes audit/status. |
| Prefetch | `parse_prefetch.py`, `parse_prefetch()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_prefetch.py:12-64`). | Prefer PECmd/wintools where available, fallback through Plaso. | OpenSearch. | Returns indexed/bulk_failed/note; caller writes audit/status. |
| SRUM | `parse_srum.py`, `parse_srum()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_srum.py:13-67`). | Prefer SrumECmd/wintools where available, fallback through Plaso. | OpenSearch. | Returns indexed/bulk_failed/note; caller writes audit/status. |
| SSH logs | `parse_ssh.py`, `parse_ssh_log()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_ssh.py:21-156`). | Parse SSH logs under a directory. | OpenSearch bulk actions. | Returns indexed/skipped/bulk_failed; caller writes audit/status. |
| Scheduled tasks | `parse_tasks.py`, `parse_tasks_dir()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_tasks.py:20-176`). | Parse task XML files. | OpenSearch bulk actions. | Returns indexed/skipped/bulk_failed; caller writes audit/status. |
| PowerShell transcripts | `parse_transcripts.py`, `ingest_transcripts()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_transcripts.py:267-338`). | Parse PowerShell transcript files. | OpenSearch bulk actions. | Returns indexed/bulk_failed; caller writes audit/status. |
| W3C logs | `parse_w3c.py`, `parse_w3c_log()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_w3c.py:24-176`). | Parse IIS, HTTPERR, and firewall W3C-like logs. | OpenSearch bulk actions. | Returns indexed/skipped/bulk_failed; caller writes audit/status. |
| WER | `parse_wer.py`, `parse_wer_dir()` (`packages/opensearch-mcp/src/opensearch_mcp/parse_wer.py:68-125`). | Parse Windows Error Reporting files. | OpenSearch bulk actions. | Returns indexed/skipped/bulk_failed; caller writes audit/status. |
| EZ tool wrappers | `tools.py`, `TOOLS`, `_run_tool()`, `run_and_ingest()` (`packages/opensearch-mcp/src/opensearch_mcp/tools.py:29-150`, `packages/opensearch-mcp/src/opensearch_mcp/tools.py:206-220`). | Run Zimmerman tools such as AmcacheParser, AppCompatCacheParser, RECmd, MFTECmd, etc., then ingest CSV. | OpenSearch via `ingest_csv()`. | Caller writes ingest audit/status; tool subprocess timeout is 2 hours (`packages/opensearch-mcp/src/opensearch_mcp/tools.py:135-150`). |

Index naming is case/artifact/host based:
`build_index_name(case_id, artifact_type, hostname)` returns
`case-{case}-{type}-{host}` after sanitization (`packages/opensearch-mcp/src/opensearch_mcp/paths.py:194-220`).

## 3. Evidence and Audit Execution Behavior

### Evidence vault and integrity

The strongest current integrity authority is explicitly file-backed:
`evidence-manifest.json + evidence-ledger.jsonl` are authoritative and
`evidence.json` is a compatibility view (`packages/sift-core/src/sift_core/evidence_chain.py:1-8`).
Manifest and ledger live under `case_records_dir(case_dir)`, which defaults to
`/var/lib/sift/<case_id>` unless `SIFT_STATE_DIR` or test fallback applies
(`packages/sift-core/src/sift_core/evidence_chain.py:49-66`,
`packages/sift-core/src/sift_core/case_io.py:51-83`).

What works well and should be preserved:

- Evidence status is fast and keyless for the Gateway: `chain_status()` checks
  manifest hash, ledger chain, and file stat differences without rehashing every
  file (`packages/sift-core/src/sift_core/evidence_chain.py:289-338`).
- Sealing hashes registered evidence, records size/mtime/source/description,
  appends an HMAC ledger event, and attempts to set the Linux immutable flag
  (`packages/sift-core/src/sift_core/evidence_chain.py:431-535`,
  `packages/sift-core/src/sift_core/evidence_chain.py:713-760`).
- Gateway aggregate MCP blocks all agent tool calls when the evidence gate is
  blocked and writes a specific gate audit entry (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:637-674`).

### Audit logs

`AuditWriter` resolves audit location from explicit audit dir,
`SIFT_AUDIT_DIR`, active `SIFT_CASE_DIR`, or legacy `~/.sift/active_case`
(`packages/sift-common/src/sift_common/audit.py:103-144`). It writes
`<mcp_name>.jsonl` with `fsync` and returns `None` when no case is active
(`packages/sift-common/src/sift_common/audit.py:246-332`).

Preserve:

- Tool audit IDs are generated before execution and can be returned to agents
  for provenance linking (`packages/sift-core/src/sift_core/agent_tools.py:488-490`,
  `packages/sift-core/src/sift_core/agent_tools.py:627-642`).
- `run_command` audit captures input files and SHA-256 hashes where detectable,
  plus output file/hash, elapsed time, stages, and privilege events
  (`packages/sift-core/src/sift_core/agent_tools.py:586-699`).
- OpenSearch per-artifact audit captures source file, hash, run_id, and bulk
  failures for parser/indexing operations (`packages/opensearch-mcp/src/opensearch_mcp/ingest.py:781-804`,
  `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:917-931`,
  `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:1022-1037`).

### Findings, reports, and approvals

Agent findings are staged as `DRAFT` through `CaseManager.record_finding()`,
which writes `findings.json`, may auto-create a DRAFT timeline event, and may
extract IOCs (`packages/sift-core/src/sift_core/case_manager.py:1339-1478`).
Timeline events are staged as DRAFT in `timeline.json`
(`packages/sift-core/src/sift_core/case_manager.py:1508-1542`). Approval commit
applies pending review deltas to findings/timeline/IOCs and writes approval
logs best-effort after the primary JSON writes (`packages/case-dashboard/src/case_dashboard/routes.py:1221-1285`).

Reports are generated from case files synchronously into in-memory drafts, then
saved as protected JSON files under `case/reports/{uuid}.json`
(`packages/case-dashboard/src/case_dashboard/routes.py:4144-4218`,
`packages/case-dashboard/src/case_dashboard/routes.py:4220-4256`).

## 4. Current Workflow/Status State

| State | Current location | Purpose | Readers/writers | Authoritative today? | Future target authority if known |
| --- | --- | --- | --- | --- | --- |
| Active case | `SIFT_CASE_DIR`, `gateway.yaml case.dir`, `~/.sift/active_case` | Select current case for portal, Gateway, MCP backends, audit, and CLI. | `resolve_case_dir()` and `_get_active_case()` read env/pointer (`packages/sift-common/src/sift_common/__init__.py:9-32`, `packages/opensearch-mcp/src/opensearch_mcp/server.py:3504-3527`). Gateway applies env on activation (`packages/sift-gateway/src/sift_gateway/server.py:949-952`). | Yes operationally, but fragmented. | Postgres active-case/session/job context per charter. |
| Case metadata | `CASE.yaml` | Case ID/status metadata. | Portal/core read through `_resolve_case_dir()` and `load_case_meta()` (`packages/case-dashboard/src/case_dashboard/routes.py:183-195`, `packages/sift-core/src/sift_core/case_io.py:222-230`). | Yes today. | Postgres cases domain. |
| Investigation records | `findings.json`, `timeline.json`, `todos.json`, `iocs.json`, legacy `evidence.json` | Findings, timeline refs, tasks, IOCs, compatibility evidence. | Core load/save helpers (`packages/sift-core/src/sift_core/case_io.py:252-332`); CaseManager writes records (`packages/sift-core/src/sift_core/case_manager.py:1339-1542`, `packages/sift-core/src/sift_core/case_manager.py:1620-1701`). | Yes today. | Postgres findings/review/TODO/IOC/timeline domains. |
| Evidence chain | `/var/lib/sift/<case>/evidence-manifest.json`, `evidence-ledger.jsonl` by default | Evidence integrity authority. | Evidence-chain functions and portal evidence routes (`packages/sift-core/src/sift_core/evidence_chain.py:1-8`, `packages/case-dashboard/src/case_dashboard/routes.py:635-801`). | Yes today. | Postgres metadata/status plus preserved ledger artifacts. |
| Audit logs | `/var/lib/sift/<case>/audit/*.jsonl` by default | Tool/action audit. | `AuditWriter.log()`; Gateway, core tools, MCP backends, OpenSearch ingest (`packages/sift-common/src/sift_common/audit.py:246-332`). | Yes today for audited actions. | Postgres audit events plus compatibility export. |
| Approval log | `/var/lib/sift/<case>/approvals.jsonl` by default | Human approval/rejection events. | `write_approval_log()` and portal commit path (`packages/sift-core/src/sift_core/case_io.py:82-83`, `packages/sift-core/src/sift_core/case_io.py:335-360`, `packages/case-dashboard/src/case_dashboard/routes.py:1221-1234`). | Yes today. | Postgres approval/review state. |
| Pending review delta | `case/pending-reviews.json`, `case/pending-reviews.processing` | Staged human review decisions and local commit lock/crash recovery. | Portal delta/commit code (`packages/case-dashboard/src/case_dashboard/routes.py:1221-1252`). | Yes for current review workflow. | Postgres review state. |
| OpenSearch ingest status | `~/.sift/ingest-status/{case}-{pid}.json` | Background ingest progress, concurrency guard, dead-process detection. | `write_status()` and `read_active_ingests()` (`packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:13-148`); workflow_status reads files directly (`packages/forensic-mcp/src/forensic_mcp/server.py:484-518`). | Yes for ingest visibility today, but local/file-scoped. | Postgres jobs/job_steps/parser_runs/indexing status. |
| OpenSearch ingest logs | `~/.sift/ingest-logs/{run_id}.log` | Subprocess stdout/stderr diagnostics. | Launchers create logs (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1771-1777`, `packages/opensearch-mcp/src/opensearch_mcp/server.py:3112-3118`, `packages/opensearch-mcp/src/opensearch_mcp/server.py:3435-3440`); status surfaces paths. | Diagnostic, not authoritative. | DB job log metadata plus retained log files/object storage. |
| OpenSearch indices | `case-{case_id}-{artifact_type}-{hostname}` | Searchable derived parser documents. | Parsers and ingest loop write; status/query tools read (`packages/opensearch-mcp/src/opensearch_mcp/paths.py:201-220`, `packages/opensearch-mcp/src/opensearch_mcp/server.py:1169-1203`). | Derived data plane, not control authority. | OpenSearch with Postgres index registration. |
| Ingest manifests | `case/audit/ingest-manifests/*.manifest.json` | Per-source parser provenance sidecars. | `_write_ingest_manifest()` writes; comment says no readers yet (`packages/opensearch-mcp/src/opensearch_mcp/ingest.py:29-95`). | No reader found; provenance sidecar only. | Parser output/provenance registrations in Postgres. |
| Report drafts/saved reports | In-memory `_PENDING_REPORTS`; `case/reports/{uuid}.json` | Report draft, saved report record, markdown download source. | Portal report routes (`packages/case-dashboard/src/case_dashboard/routes.py:4109-4256`, `packages/case-dashboard/src/case_dashboard/routes.py:4296-4341`). | Yes for reports today. | Postgres report metadata plus export artifacts. |
| Frontend UI state | Zustand/browser memory | Active tab, cached case data, loading/toast state. | Frontend store/polling; polling writes slices (`packages/case-dashboard/frontend/src/hooks/useDataPolling.js:16-43`). | No; cache only. | Frontend cache only. |
| Native command outputs | `case/agent/run_commands`, `case/extractions`, `case/tmp` | Saved stdout/stderr and generated command outputs. | Executor output saving (`packages/sift-core/src/sift_core/execute/executor.py:185-203`, `packages/sift-core/src/sift_core/execute/executor.py:253-365`). | Artifact/output files exist, but no durable job authority. | Postgres job/output registrations plus filesystem artifacts. |

## 5. Current Risks

| Risk | Current cause from code | Impact | Future control idea | Priority |
| --- | --- | --- | --- | --- |
| Long-running parsers are not durable DB jobs. | OpenSearch ingest launches subprocesses and tracks pid/run_id in files, not a DB job table (`packages/opensearch-mcp/src/opensearch_mcp/server.py:3006-3168`, `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:13-89`). | Lost/duplicated work, weak retries/cancel, hard post-crash reconstruction. | DB jobs, job steps, parser runs, indexing batches. | P0 |
| Case scope depends on env or active-case pointers. | `_resolve_case_dir()` and `_get_active_case()` read `SIFT_CASE_DIR` or `~/.sift/active_case` (`packages/case-dashboard/src/case_dashboard/routes.py:183-195`, `packages/opensearch-mcp/src/opensearch_mcp/server.py:3504-3527`). | Cross-case confusion and stale subprocess context. | Case scope from authenticated session/token/job claim. | P0 |
| Status is file-based or scattered. | Investigation JSON, pending review files, ingest status files, reports, and audit logs are separate files (`packages/sift-core/src/sift_core/case_io.py:252-360`, `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:13-148`). | Frontend/agents cannot build one reliable execution view. | DB status model with compatibility exports. | P0 |
| Worker crash recovery is unclear. | Ingest status sweep can mark dead/zombie pids failed, but there is no durable owner/heartbeat/claim model (`packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:101-197`). | Crash recovery depends on local pid files and `/proc`; no cross-host semantics. | Worker heartbeat and stale-job handling in Postgres. | P0 |
| Duplicate ingestion/indexing risk. | Index names are deterministic, but current status/job model lacks DB idempotency keys; `force` guards accidental reindex at MCP UX level only (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1901-1905`, `packages/opensearch-mcp/src/opensearch_mcp/paths.py:201-220`). | Duplicate docs or partial overwrites can skew counts/search. | Job-level idempotency keys and indexing batch registrations. | P0 |
| OpenSearch indexing status can drift. | Status files can be cleaned after 24 hours while indices remain (`packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:200-215`); `opensearch_status()` reads indices separately (`packages/opensearch-mcp/src/opensearch_mcp/server.py:1169-1203`). | UI may show no run history for existing indexed data, or stale status for failed/partial data. | DB index registry and batch state reconciled with OpenSearch. | P0 |
| Evidence provenance can disconnect from parser outputs. | Parser docs contain `vhir.source_file` and audit IDs, but ingest manifests are sidecars with no reader and no DB evidence ID (`packages/opensearch-mcp/src/opensearch_mcp/parse_evtx.py:115-122`, `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:29-95`). | Search hits may not reliably trace to registered evidence and parser run. | Require evidence_id/job_id/parser_run_id/source hash in outputs. | P0 |
| MCP tools may block synchronously. | Core `run_command` waits for native execution; add-on calls use synchronous MCP request/response with 300s timeout in aggregate Gateway path (`packages/sift-core/src/sift_core/execute/tools/generic.py:72-178`, `packages/sift-gateway/src/sift_gateway/server.py:762-787`). | Agent sessions can block on long work; timeout handling is not job-oriented. | Convert long execution to submitted jobs with polling/cancel. | P1 |
| Frontend cannot reliably observe progress. | Frontend polls case/review/evidence/report files every 15 seconds and has no job-progress endpoint (`packages/case-dashboard/frontend/src/hooks/useDataPolling.js:16-43`). OpenSearch progress is not in portal endpoint wrappers (`packages/case-dashboard/frontend/src/api/endpoints.js:63-77`). | Operators cannot see all parser/native progress from one authoritative surface. | Job/status APIs backed by Postgres. | P1 |
| Audit gaps during parser execution. | Parent process audits launch, per-artifact parser code audits steps, but status writes and sidecar writes are not themselves DB-audited; `AuditWriter.log()` returns `None` when no active case resolves (`packages/sift-common/src/sift_common/audit.py:262-264`, `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:237-255`). | Parser milestones may be hard to reconstruct when env/case resolution or subprocess audit fails. | Mandatory DB audit events for job lifecycle and parser steps. | P0 |
| Per-backend MCP could bypass aggregate evidence gate behavior. | Historical pre-D27b risk: aggregate `create_mcp_server()` checked the evidence gate before dispatch, while `create_backend_mcp_server()` directly called backend tools. | OpenSearch/backend execution policy could differ depending on endpoint path. | **Resolved by D27b:** one aggregate FastMCP `/mcp` policy path; per-backend routes removed. | done |
| Report generation has only in-memory in-flight state. | `_IN_FLIGHT_GENERATIONS` prevents duplicate generation only within one process and drafts live in `_PENDING_REPORTS` until saved (`packages/case-dashboard/src/case_dashboard/routes.py:4157-4198`). | Gateway restart loses drafts/in-flight state; no durable progress/errors. | DB report jobs and report metadata. | P2 |

## 6. Inputs Needed For Next Run

`docs/migration/05_execution_job_model.md` now exists. The items below are
historical inputs that informed the execution/job design and still matter when
execution JOB-* phases resume.

Inputs needed before that run:

- Confirm whether the initial worker model is single local worker, multiple
  local workers, or Gateway-hosted worker plus future distributed workers.
- Confirm the first job types to model: OpenSearch ingest only, native
  `run_command`, report generation, evidence operations, or a smaller subset.
- Confirm whether all long-running MCP tools should return `job_id` immediately,
  or whether short commands remain synchronous.
- Confirm whether legacy `~/.sift/ingest-status` files must be exported during
  transition and for how long.
- Confirm desired cancellation semantics for subprocess trees and partially
  indexed OpenSearch batches.
- Confirm retry boundaries: whole job, per host, per artifact, per parser, or
  per indexing batch.
- Confirm whether parser output files under `agent/`, `extractions/`, and
  `tmp/` should become registered outputs before or after OpenSearch job state.
