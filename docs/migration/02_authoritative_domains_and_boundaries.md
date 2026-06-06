# Authoritative Domains And Boundaries

Last updated: 2026-06-06.

Scope: planning only. This document defines target authoritative domains,
trust boundaries, and migration mapping from current file-based authority into
Supabase/Postgres. It intentionally does not create schemas, migrations, or
runtime code changes.

## 1. Executive Summary

The target architecture splits authority by plane:

- Supabase/Postgres is the control plane and source of truth for cases, active
  case state, permissions, operators, service-token registry state, jobs,
  evidence metadata, audit events, approvals, findings review state, report
  metadata, parser runs, and OpenSearch indexing metadata.
- OpenSearch is a core search/data plane for derived searchable forensic data:
  parsed artifacts, timeline events, IOCs, full-text forensic search, optional
  vector search, and derived investigative documents.
- Evidence Vault remains the immutable evidence storage layer. Raw evidence
  stays immutable; Postgres stores metadata, hashes, integrity status, and
  references.
- Gateway is the policy, authentication, authorization, routing, and MCP broker.
  It validates human sessions or MCP/service tokens, applies case/tool scope,
  routes to MCP tools and services, and writes privileged audit events.
- Workers are the execution plane. They claim durable work, run native SIFT and
  parser workflows, emit logs/status, and write results through authorized
  control-plane paths.
- Frontend is the operator UI. It may cache UI state and call APIs, but it is
  not forensic state authority.
- AI agents are controlled clients. They operate through Gateway-mediated,
  case-scoped MCP tools, and their findings remain draft/proposed until human
  approval.

## 2. Current Authority Fragmentation

### Flat case JSON/YAML

- Current location: case directories under `SIFT_CASES_ROOT`,
  `SIFT_CASES_DIR`, or `~/cases`; metadata in `CASE.yaml`; investigation state
  in `findings.json`, `timeline.json`, `todos.json`, `iocs.json`, and legacy
  `evidence.json` (`packages/sift-core/src/sift_core/case_io.py:21-65`,
  `packages/sift-core/src/sift_core/case_io.py:222-332`).
- Current role: primary case metadata and investigation records. Portal case
  creation writes the directory tree and initializes these files
  (`packages/case-dashboard/src/case_dashboard/routes.py:3726-3848`).
- Current readers/writers: portal route handlers read case files directly
  (`packages/case-dashboard/src/case_dashboard/routes.py:1624-1712`,
  `packages/case-dashboard/src/case_dashboard/routes.py:1780-1876`);
  `sift_core.case_io` loads/saves flat JSON/YAML; `forensic-mcp` stages
  findings and timeline events through `CaseManager`
  (`packages/forensic-mcp/src/forensic_mcp/server.py:68-175`,
  `packages/forensic-mcp/src/forensic_mcp/server.py:195-226`,
  `packages/sift-core/src/sift_core/case_manager.py:772-840`).
- Risks: file drift, weak concurrency across processes, no central membership
  model, active-case ambiguity, and difficult authorization/audit joins.
- Future authority target: Supabase/Postgres for case lifecycle, findings
  review state, TODOs, IOCs, timeline references, evidence metadata, and report
  metadata. Compatibility files may be exported during transition.

### `/var/lib/sift` records

- Current location: default state root is `/var/lib/sift`, overridable by
  `SIFT_STATE_DIR`; per-case records live under
  `state_root/case_id` (`packages/sift-core/src/sift_core/case_io.py:21-83`).
- Current role: integrity records, evidence manifest/ledger, audit JSONL, and
  approvals JSONL. The evidence-chain module declares
  `evidence-manifest.json + evidence-ledger.jsonl` as current authority with
  `evidence.json` as compatibility view
  (`packages/sift-core/src/sift_core/evidence_chain.py:1-8`,
  `packages/sift-core/src/sift_core/evidence_chain.py:49-66`).
- Current readers/writers: evidence-chain functions initialize, seal, ignore,
  retire, verify, and append HMAC ledger events
  (`packages/sift-core/src/sift_core/evidence_chain.py:87-113`,
  `packages/sift-core/src/sift_core/evidence_chain.py:431-760`); audit writers
  append JSONL with fsync (`packages/sift-common/src/sift_common/audit.py:246-332`);
  approval logging appends `approvals.jsonl`
  (`packages/sift-core/src/sift_core/case_io.py:335-380`).
- Risks: strong local provenance is split from portal/MCP state; active-case
  lookup still depends on env/pointer files; audit gaps are possible when no
  active case resolves.
- Future authority target: Postgres for evidence metadata, integrity status,
  audit events, and approvals, while preserving immutable manifest/ledger files
  as proof/export artifacts during and after migration.

### `~/.sift/gateway.yaml` tokens

- Current location: `api_keys` in gateway config, conventionally
  `~/.sift/gateway.yaml`; template keys are raw tokens
  (`configs/gateway.yaml.template:113-138`,
  `packages/sift-gateway/src/sift_gateway/server.py:934-941`).
- Current role: bearer-token registry for examiner, agent, and readonly access.
  Verification iterates raw token keys and checks expiry/revocation metadata
  (`packages/sift-gateway/src/sift_gateway/auth.py:40-66`).
- Current readers/writers: Gateway auth reads the in-memory `api_keys`; portal
  token routes list, create, revoke, rotate, and reactivate by writing
  `gateway.yaml` (`packages/case-dashboard/src/case_dashboard/routes.py:3060-3345`).
- Risks: raw-token-keyed authority, secrets in config files, global token scope,
  weak case/tool binding, and Gateway config becoming the long-term authority.
- Future authority target: Postgres token registry with hash-only token
  records, case scope, allowed tools, expiry, revocation, created-by, last-use,
  and audit linkage. Gateway issues and validates tokens but does not store raw
  tokens.

### Environment and legacy active-case pointers

- Current location: `gateway.yaml` `case.dir`, process env
  `SIFT_CASE_DIR`/`SIFT_CASES_ROOT`, and legacy `~/.sift/active_case`
  (`configs/gateway.yaml.template:14-17`,
  `packages/sift-gateway/src/sift_gateway/config.py:49-75`,
  `packages/sift-common/src/sift_common/__init__.py:9-32`).
- Current role: active case selection and case path resolution for portal,
  Gateway, MCP backends, audit, and CLI compatibility.
- Current readers/writers: portal activation and creation update gateway config,
  process env, and the legacy pointer
  (`packages/case-dashboard/src/case_dashboard/routes.py:3598-3717`,
  `packages/case-dashboard/src/case_dashboard/routes.py:3858-3888`,
  `packages/case-dashboard/src/case_dashboard/routes.py:3468-3481`);
  OpenSearch derives active case from env or pointer
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:3504-3527`).
- Risks: cross-case confusion, subprocess inheritance bugs, stale pointer files,
  and unclear semantics for multiple simultaneous operators or agents.
- Future authority target: Postgres active-case/session context and explicit
  case_id on privileged requests. Compatibility env/pointer writes should be
  generated from database authority only during transition.

### OpenSearch ingest/status files

- Current location: ingest status JSON under `~/.sift/ingest-status` and logs
  under `~/.sift/ingest-logs`
  (`packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:13-90`,
  `packages/opensearch-mcp/src/opensearch_mcp/server.py:3112-3157`).
- Current role: background ingest visibility, concurrency guard, PID tracking,
  terminal-state persistence, and operator diagnostics.
- Current readers/writers: OpenSearch MCP launch paths write status before and
  after spawning workers; status readers detect dead/zombie processes
  (`packages/opensearch-mcp/src/opensearch_mcp/server.py:3006-3165`,
  `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:101-130`).
- Risks: no durable job ownership, per-host files can drift from index state,
  process crash recovery is local, and status does not link to Postgres
  approvals/evidence metadata.
- Future authority target: Postgres durable jobs, job steps, job logs, parser
  runs, and OpenSearch indexing metadata. Existing status/log files can be
  mirrored temporarily for CLI compatibility.

### Frontend assumptions

- Current location: React/Zustand portal state and `/portal` API wrappers
  (`packages/case-dashboard/frontend/src/store/useStore.js:1-70`,
  `packages/case-dashboard/frontend/src/api/endpoints.js:1-78`).
- Current role: operator UI state plus polling of current case, cases,
  findings, review delta, timeline, evidence chain, IOCs, TODOs, and reports
  every 15 seconds (`packages/case-dashboard/frontend/src/hooks/useDataPolling.js:16-43`).
- Current readers/writers: frontend calls portal APIs for case creation,
  activation, token lifecycle, evidence chain mutation, report generation, TODO
  changes, and review commits.
- Risks: UI can accidentally encode file shapes as product contracts, especially
  evidence `file_specs`, pending reviews, and saved-report JSON assumptions.
- Future authority target: frontend remains a thin operator UI backed by
  Supabase Auth/RLS for human data paths and Gateway REST APIs. It must not own
  forensic lifecycle, approval, token, or job authority.

### Native Linux backend workflow state

- Current location: command output under case `agent/run_commands`,
  `extractions`, or `tmp`; execution policy in gateway config/env; OpenSearch
  long-running ingest in local subprocesses and status files
  (`configs/gateway.yaml.template:18-111`,
  `packages/sift-core/src/sift_core/execute/executor.py:122-205`,
  `packages/sift-core/src/sift_core/execute/executor.py:253-365`,
  `packages/opensearch-mcp/src/opensearch_mcp/server.py:2941-3165`).
- Current role: local execution, parser output generation, large-output spill,
  and background ingest.
- Current readers/writers: core executor and OpenSearch MCP launchers; generic
  command validation defaults cwd to active case env
  (`packages/sift-core/src/sift_core/execute/tools/generic.py:72-125`).
- Risks: no central durable job table, incomplete retry semantics, local output
  files can exist without database-visible job lineage, and worker crashes can
  strand partially complete state.
- Future authority target: Postgres durable jobs, job steps, job logs, parser
  runs, parser output registrations, and audit events. Workers execute but do
  not become the state authority.

## 3. Target Authoritative Domains

| Domain | Future authoritative system | Current source/location | Transitional strategy | Long-term target | Main risks |
| --- | --- | --- | --- | --- | --- |
| Case lifecycle | Supabase/Postgres | `CASE.yaml`, case directories; portal create/activate (`packages/case-dashboard/src/case_dashboard/routes.py:3726-3888`) | Read files and mirror to Postgres, then create/update in Postgres and export compatibility files | Postgres `cases` domain; files are compatibility/export | Duplicate case IDs, stale `CASE.yaml`, partial create failures |
| Active case selection | Supabase/Postgres plus Gateway request context | `SIFT_CASE_DIR`, `gateway.yaml case.dir`, `~/.sift/active_case` (`packages/sift-common/src/sift_common/__init__.py:9-32`) | Write active case in Postgres, export env/pointer for legacy tools | Explicit case context per human session/token/job | Cross-case confusion, stale process env |
| Case membership/operator authorization | Supabase/Postgres | Current examiner role and local password/session model; no central membership table found in inventory | Introduce DB membership; mirror existing examiner as initial owner/operator | RLS-backed memberships and service-side checks | Over-broad operator access during bridge |
| Human operator identity | Supabase Auth | Portal HMAC JWT cookie and examiner bearer fallback (`packages/case-dashboard/src/case_dashboard/auth.py:61-131`, `packages/case-dashboard/src/case_dashboard/session_jwt.py:41-110`) | Keep portal auth while adding Supabase Auth path behind Gateway/portal | Supabase Auth users plus RLS | Split session state, migration lockouts |
| AI agent identity | Supabase/Postgres token/agent registry via Gateway | `api_keys` entries with `role=agent`, `agent_id` (`packages/case-dashboard/src/case_dashboard/routes.py:3160-3172`) | Mirror gateway tokens to DB as disabled/legacy records; issue new DB-backed tokens | Agent registry records linked to service tokens and cases | Token ambiguity, agent impersonation |
| MCP/service tokens | Supabase/Postgres token registry; Gateway validation | Raw-token-keyed `gateway.yaml api_keys` (`configs/gateway.yaml.template:113-138`) | Dual-validate: DB hash registry first, legacy config fallback during cutover | Hash-only, expiring, revocable, case/tool-scoped records | Raw token leakage, revocation drift |
| Tool authorization/scopes | Gateway policy backed by Postgres | Role-only token metadata; manifest-gated tools (`packages/sift-gateway/src/sift_gateway/auth.py:40-66`, `packages/sift-gateway/src/sift_gateway/server.py:376-497` from inventory) | Add DB tool scopes and enforce before MCP dispatch | Per-token allowed tools, phases, and policy rules | Over-broad agent tools, hidden tool exposure |
| Evidence metadata | Supabase/Postgres | Manifest active files and legacy `evidence.json` (`packages/sift-core/src/sift_core/evidence_chain.py:1-8`, `packages/case-dashboard/src/case_dashboard/routes.py:1676-1712`) | Mirror manifest entries to Postgres; keep manifest authoritative until parity | Postgres metadata with vault references and hashes | Metadata drift from manifest |
| Evidence vault immutable files | Evidence Vault/filesystem | Case `evidence/` plus immutable flag behavior (`packages/sift-core/src/sift_core/evidence_chain.py:431-535`, `packages/sift-core/src/sift_core/evidence_chain.py:713-747`) | Preserve file behavior; register DB references | Immutable raw evidence storage; never mutable DB blobs | Accidental mutability, path traversal |
| Evidence integrity events | Supabase/Postgres plus preserved ledger artifacts | `evidence-ledger.jsonl`, manifest hash chain (`packages/sift-core/src/sift_core/evidence_chain.py:341-360`, `packages/sift-core/src/sift_core/evidence_chain.py:753-760`) | Mirror ledger events into Postgres, preserve JSONL as proof/export | DB integrity events linked to evidence records; ledger export retained | Loss of provenance, broken HMAC chain |
| Audit events | Supabase/Postgres plus export JSONL during bridge | `/var/lib/sift/<case>/audit/*.jsonl` (`packages/sift-common/src/sift_common/audit.py:103-144`, `packages/sift-common/src/sift_common/audit.py:246-332`) | Write DB audit event, optionally export JSONL compatibility | Postgres audit events for every privileged action | Audit gaps, duplicate IDs |
| Approval records | Supabase/Postgres plus preserved existing logs | `approvals.jsonl`, pending reviews, HMAC ledger entries (`packages/sift-core/src/sift_core/case_io.py:82-83`, `packages/case-dashboard/src/case_dashboard/routes.py:1221-1605`) | Import/mirror approvals; keep pending review JSON until portal cutover | DB approval/review state with human actor and content hash | Approval/state mismatch |
| Findings | Supabase/Postgres | `findings.json`; MCP stages DRAFT (`packages/forensic-mcp/src/forensic_mcp/server.py:68-175`) | Mirror JSON to DB; write new findings to DB and export JSON | DB findings with review lifecycle | Agent draft accidentally treated final |
| Timeline references | Supabase/Postgres for reviewed references; OpenSearch for searchable events | `timeline.json`; OpenSearch timeline docs (`packages/sift-core/src/sift_core/case_io.py:270-285`) | Mirror reviewed timeline refs to DB; index searchable derived events | DB canonical review refs; OpenSearch query plane | Duplicate timeline rows |
| Parser runs | Supabase/Postgres | OpenSearch ingest `run_id`, PID/status files (`packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:16-90`) | Mirror status files to DB parser runs; new runs created as jobs | DB parser_run records linked to jobs/evidence | Lost run lineage |
| Parser outputs | OpenSearch for searchable docs; Evidence Vault/filesystem for generated files; Postgres for registrations | Case `extractions`, `agent`, OpenSearch indices (`packages/sift-core/src/sift_core/execute/executor.py:253-365`, `packages/opensearch-mcp/src/opensearch_mcp/paths.py:201-207`) | Register outputs in DB while preserving files/index docs | Output metadata in DB; documents in OpenSearch | Orphan outputs, hash mismatch |
| Durable jobs | Supabase/Postgres | No Postgres/RQ/Celery job authority found; OpenSearch status files approximate jobs | Create additive DB job records before replacing local status | DB jobs claimed by workers | Crash recovery, duplicate execution |
| Job steps | Supabase/Postgres | Parser/subprocess phases implicit in status/logs | Mirror high-level phases from status/logs | DB job_steps with ordered status | Weak observability |
| Job logs | Supabase/Postgres metadata plus filesystem/log storage as needed | `~/.sift/ingest-logs/{run_id}.log` (`packages/opensearch-mcp/src/opensearch_mcp/server.py:3112-3157`) | Store metadata and tail pointers; optionally ingest structured log lines | DB job_logs or object/log references | Large logs, retention |
| Reports/exports | Supabase/Postgres metadata; file/object export artifacts | In-memory drafts and `case/reports/{uuid}.json` (`packages/case-dashboard/src/case_dashboard/routes.py:4109-4341`) | Mirror saved reports; keep download rendering | DB report metadata plus immutable/generated artifacts | Expired drafts, file drift |
| OpenSearch indexes | Supabase/Postgres registration; OpenSearch stores indexes | `case-{case_id}-{artifact_type}-{hostname}` (`packages/opensearch-mcp/src/opensearch_mcp/paths.py:201-207`) | Discover/register current indexes in DB | DB index registry with OpenSearch index names and case/evidence/job links | Unregistered indexes, naming drift |
| OpenSearch documents | OpenSearch | Indexed parser artifacts and timelines (`packages/opensearch-mcp/src/opensearch_mcp/mappings/*.json`, inventory) | Add required metadata to new docs; backfill where feasible | Case-scoped derived docs with DB provenance links | Missing provenance, cross-case query |
| OpenSearch ingest status | Supabase/Postgres | `~/.sift/ingest-status/*.json` (`packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py:13-90`) | DB status first, export files while CLI still needs them | DB job/parser/indexing status | Status drift |
| Frontend UI state | Browser/local UI store only | Zustand store (`packages/case-dashboard/frontend/src/store/useStore.js:1-70`) | Keep UI-only state in frontend; fetch authority from APIs | UI cache only | Frontend encodes stale authority |
| Native workflow execution state | Supabase/Postgres for state; workers/filesystem for execution artifacts | Native executor, case output dirs, OpenSearch subprocesses (`packages/sift-core/src/sift_core/execute/executor.py:122-205`, `packages/opensearch-mcp/src/opensearch_mcp/server.py:2941-3165`) | Wrap current execution with DB job records | Worker execution plane with DB state | Stranded outputs, retries causing duplicates |

## 4. Human Auth Versus MCP/Service-Token Authority

- Supabase Auth is for human operators.
- MCP/service tokens are for AI agents, MCP clients, workers, and service automation.
- MCP/service tokens are not Supabase user sessions.
- MCP/service tokens are issued by the Gateway and stored only as hashes in Postgres.
- The Gateway is the enforcement point.
- Postgres/Supabase is the registry and authority.
- RLS protects human/operator-facing data paths.
- Service-side authorization protects MCP/worker paths.
- Every privileged action must create an audit event.

The target model intentionally separates human operator identity from
agent/service automation. Human operators need login sessions, browser security,
RLS-protected reads/writes, membership checks, and interactive approval flows.
Supabase Auth fits that path because it provides human session identity and
integrates with RLS.

"All Supabase Auth" is not the right fit for MCP agents and workers. Agents,
MCP clients, background parser workers, and backend services need scoped,
machine-issued credentials that can be constrained to a case, tool set, expiry,
revocation state, and policy version. Treating every agent or worker as a normal
Supabase user session would blur human accountability, complicate tool-scoped
authorization, and risk bypassing the Gateway enforcement point.

"Gateway registry only" is also not the right fit. The current system already
shows the danger: token authority lives in `gateway.yaml`, keyed by raw token
strings (`configs/gateway.yaml.template:113-138`), and portal token management
writes that file (`packages/case-dashboard/src/case_dashboard/routes.py:3060-3345`).
If the Gateway alone becomes the registry, it becomes too authoritative and the
migration risks recreating file-based state in a different module. The Gateway
should issue, validate, and enforce. Postgres should remain the durable registry
and source of truth.

## 5. OpenSearch Target Authority Boundary

OpenSearch becomes core, not optional/standalone. Today it is packaged as both
a standard dependency and an add-on backend, and the gateway template treats
add-ons as optional external backends (`pyproject.toml:41-46`,
`configs/gateway.yaml.template:161-169`). The target state promotes
OpenSearch-backed search into the core SIFT MCP surface while preserving the
control-plane boundary.

OpenSearch search tools become core SIFT MCP tools. They must be exposed through
the Gateway and FastMCP aggregator so tool calls can inherit Gateway identity,
case context, tool scope, audit policy, and evidence gates.

OpenSearch queries must be case-scoped by Gateway policy and token/session
context. The current OpenSearch backend validates that explicit index segments
start with `case-`, and default index resolution uses the active case when one
is available (`packages/opensearch-mcp/src/opensearch_mcp/server.py:32-45`,
`packages/opensearch-mcp/src/opensearch_mcp/server.py:564-573`). That is useful
but not enough for the target trust boundary. Gateway policy must prevent an
agent from choosing arbitrary `case-*` patterns outside its authorized case.

OpenSearch must not be queried by agents in a way that bypasses case
authorization. Direct agent access to OpenSearch credentials, raw OpenSearch
URLs, unrestricted index patterns, or non-Gateway MCP endpoints would bypass
the control plane and is outside the target model.

OpenSearch document metadata must link back to Postgres/Supabase state. Minimum
eventual metadata for every OpenSearch document:

- `case_id`
- `evidence_id` where applicable
- `job_id`
- `parser_run_id`
- `parser_name`
- `parser_version`
- `source_path` or source logical reference
- `source_hash`
- `indexed_at`
- `schema_version`

The following remain in Postgres/Supabase instead of OpenSearch:

- case lifecycle
- active case
- membership
- MCP token registry
- approvals
- audit
- evidence metadata
- job state
- finding review state
- report metadata

OpenSearch can store derived searchable copies and denormalized fields for
query performance. It must not decide whether a case exists, who may access it,
whether a token is valid, whether evidence is registered, whether a finding is
approved, or whether a job is complete.

## 6. Transitional Compatibility Strategy

Migration should be additive first. Do not remove file-backed behavior until
Postgres authority, compatibility exports, tests, and operator workflows are
verified.

| Current file/path | Current purpose | Future table/domain | Bridge strategy | Cutover phase | Deletion/deprecation condition |
| --- | --- | --- | --- | --- | --- |
| `case_dir/CASE.yaml` | Case metadata and case_id | Case lifecycle | Read from file and mirror to Postgres; later write Postgres and export `CASE.yaml` | Phase 1 mirror, Phase 2 DB-write/export | All case readers use DB or compatibility exporter |
| `case_dir/findings.json` | Draft/reviewed findings | Findings, finding review state | Mirror file to DB; then write DB and export JSON | Phase 1 mirror, Phase 2 dual-write/export | Forensic MCP and portal read DB |
| `case_dir/timeline.json` | Reviewed/draft timeline refs | Timeline references | Mirror to DB; index derived event docs separately in OpenSearch | Phase 1 mirror | Portal/MCP no longer need JSON file |
| `case_dir/iocs.json` | IOC records and review state | Findings/IOCs review state plus OpenSearch docs as needed | Mirror to DB; keep OpenSearch for searchable IOC views | Phase 1 mirror | Review APIs use DB |
| `case_dir/todos.json` | Investigation TODOs | Case tasks/TODOs | Mirror to DB; later DB-write/export | Phase 1 mirror, Phase 2 export | Portal/MCP task tools use DB |
| `case_dir/evidence.json` | Legacy evidence compatibility view | Evidence metadata | Preserve as compatibility export from manifest/DB | Phase 1 preserve | Only retired after all legacy tools stop reading it |
| `state_root/<case>/evidence-manifest.json` | Current evidence metadata/integrity manifest | Evidence metadata, integrity status | Read from file and mirror to DB; preserve artifact | Phase 1 mirror | Preserve indefinitely as proof/export, not primary authority after DB cutover |
| `state_root/<case>/evidence-ledger.jsonl` | HMAC evidence integrity event ledger | Evidence integrity events | Mirror events into DB; preserve immutable ledger artifact | Phase 1 mirror | Preserve indefinitely as proof/export |
| `state_root/<case>/audit/*.jsonl` | MCP/backend/Gateway audit | Audit events | Write DB audit first when available; export JSONL during bridge | Phase 1 mirror, Phase 2 DB-write/export | JSONL consumers migrated and export verified |
| `state_root/<case>/approvals.jsonl` | Human approval log | Approval records | Import/mirror to DB; keep append/export during bridge | Phase 1 mirror | Approval APIs and reports use DB |
| `case_dir/pending-reviews.json` | Pending human review delta | Findings review state/approvals | Keep file-only temporarily, then migrate review queue to DB | Phase 1 keep, Phase 2 DB review queue | Portal review/commit uses DB transactionally |
| `case_dir/pending-reviews.processing` | Crash recovery lock for review commit | Findings review state/approvals | Keep file-only until review queue moves to DB | Phase 1 keep | DB transactional review commit replaces file lock |
| `case_dir/reports/{uuid}.json` | Saved report records | Report metadata and export artifacts | Mirror metadata to DB; keep JSON as export artifact | Phase 1 mirror | DB report list/download can render from DB or managed artifact |
| `gateway.yaml api_keys` | Raw-token-keyed token registry | MCP/service token registry | DB hash registry first; legacy fallback read-only/limited; export only if needed | Phase 1 dual-validate, Phase 2 DB-only | No active legacy tokens; config contains no raw service tokens |
| `gateway.yaml case.dir` | Active case pointer for Gateway env | Active case state | DB active case/session; export config/env for legacy backends | Phase 1 export | Backends accept explicit case context |
| `~/.sift/active_case` | Legacy CLI active-case pointer | Active case compatibility | Export from DB active-case selection temporarily | Phase 1 export | CLI/tools read DB or explicit case argument |
| `~/.sift/opensearch.yaml` | OpenSearch client credentials | OpenSearch service config/secrets | Keep file-only temporarily; move service config to managed deployment path later | Phase 1 keep | Gateway/OpenSearch service config is centralized and no agents read credentials |
| `~/.sift/ingest-status/*.json` | Background ingest status | Jobs, job steps, parser runs, indexing status | Read from file and mirror to DB; then DB-write/export | Phase 1 mirror, Phase 2 DB-write/export | CLI/status tools use DB or generated compatibility files |
| `~/.sift/ingest-logs/*.log` | Ingest log files | Job logs/log artifact refs | Register log metadata in DB; preserve files | Phase 1 register | Retention/export policy exists |
| `case_dir/agent/run_commands/output*` | Native command large-output spill | Job logs/parser output registrations | Register outputs in DB with hashes; preserve files | Phase 1 register | Output-producing tools create DB records |
| `case_dir/extractions/*` | Parser/native extracted artifacts | Parser outputs/evidence-derived artifacts | Register outputs in DB; index searchable derivations in OpenSearch | Phase 1 register | All parser outputs have DB lineage |
| OpenSearch `case-*` indexes | Derived searchable artifacts | OpenSearch index registry plus documents | Discover/register existing indexes; enforce Gateway case scope | Phase 1 register | All query paths are Gateway-mediated and registered |

## 7. Proposed Target Service Boundaries

| Service/module | Allowed reads | Allowed writes | Forbidden responsibilities | Migration notes from current implementation |
| --- | --- | --- | --- | --- |
| Portal frontend | Supabase Auth session, Gateway REST responses, RLS-protected operator data | UI-only browser state; API requests | Direct forensic file writes, direct OpenSearch queries, direct token validation, direct job state mutation | Current frontend polls file-shaped portal APIs every 15 seconds (`packages/case-dashboard/frontend/src/hooks/useDataPolling.js:16-43`); keep it as UI/cache only |
| Gateway REST API | Supabase/Postgres through service role or constrained server clients; OpenSearch through OpenSearch service; evidence metadata through Evidence service | Audit events, token issuance requests, case actions, job requests through services | Becoming a standalone state registry; exposing raw OpenSearch or file authority to clients | Current portal sub-app is mounted by Gateway and receives live `api_keys`/config callbacks (`packages/sift-gateway/src/sift_gateway/server.py:954-966`) |
| FastMCP aggregator | Tool registry, token/session context, case policy, evidence gate state, backend manifests | MCP transport audit envelope, policy-denied audit events | Bypassing Gateway policy, accepting direct unscoped OpenSearch index patterns, allowing raw tool backends to self-authorize | Current aggregator already gates evidence and writes envelope audit (`packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:637-675`, `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:841-872`) |
| Auth/policy wrapper | Supabase Auth claims for humans, token registry records for agents/services, case memberships, tool scopes | Authorization decisions as auditable events or denials | Storing raw tokens, trusting frontend-provided case scope, trusting OpenSearch index names as authorization | Current auth is role-based over raw `api_keys`; future adds DB case/tool scope |
| Token registry service | Postgres token hashes, scopes, expiry/revocation, agent records | Token hash records, rotation/revocation metadata, last-use metadata, audit events | Raw token persistence, Supabase user-session issuance for agents | Current token routes write `gateway.yaml`; replace with DB-backed issuance and compatibility fallback |
| Case service | Cases, active-case records, memberships, compatibility file metadata | Case lifecycle, active case/session context, compatibility exports | Evidence file mutation, OpenSearch document writes, token validation | Current case creation writes directories and config/env pointers; future creates DB case first and exports files |
| Evidence service | Evidence metadata, integrity status, vault refs, manifest/ledger artifacts | Metadata rows, integrity status/events, compatibility manifest/export, audit events | Making raw evidence mutable, hiding ledger provenance, allowing unregistered evidence use | Preserve evidence-chain invariants and immutable raw evidence behavior |
| Audit service | Audit events, actor identities, token/job/case references | Append-only audit events, JSONL export during bridge | Best-effort-only audit for privileged actions, mutable audit rows without history | Current AuditWriter is conceptually strong but filesystem-backed |
| Job service | Jobs, job steps, parser runs, worker leases, logs | Durable job state, leases, retries, cancellation, completion | Redis/RQ authority, local PID files as source of truth | No Redis/RQ; OpenSearch status files become compatibility exports |
| Worker dispatcher | Pending jobs, worker leases, policy-approved job specs | Lease claims, step/log updates, parser run status, output registrations | Deciding operator authorization, issuing tokens, approving findings | Wrap current native execution and OpenSearch subprocesses in DB jobs |
| Parser registry | Parser definitions, versions, supported artifacts, schema versions | Parser registration metadata and compatibility declarations | Storing parser outputs as authority, bypassing job service | Current parser logic is embedded in OpenSearch ingest modules; register versions before deep refactor |
| OpenSearch service | Registered indexes, OpenSearch credentials, DB case/index metadata | OpenSearch documents/indexes; index registration metadata through Postgres service boundary | Case lifecycle, permissions, approvals, audit authority, token authority | Promote from optional add-on to core service while keeping OpenSearch a data plane |
| Report service | Cases, approved findings, timeline refs, evidence metadata, integrity status, report metadata | Report metadata, generated/export artifact refs, audit events | Treating in-memory drafts as durable authority, auto-approving agent content | Current report drafts are in memory and saved as JSON files (`packages/case-dashboard/src/case_dashboard/routes.py:3899-4259`) |

## 8. Risks And Controls

| Risk | Why it exists today | Migration control | Target-state control | Priority |
| --- | --- | --- | --- | --- |
| Raw MCP token leakage | `gateway.yaml api_keys` are keyed by raw token strings (`configs/gateway.yaml.template:113-138`) | Introduce DB hash registry and legacy-token sunset; never mirror raw tokens into DB | Hash-only token storage, one-time raw display, audit token use | P0 |
| Cross-case access by AI agents | Case scope is inherited from env/pointers rather than token-bound case claims | Add explicit case_id to token records and Gateway request context before broad rollout | Gateway enforces token case scope and service-side authorization | P0 |
| Active-case confusion from env/legacy pointers | `SIFT_CASE_DIR`, `gateway.yaml case.dir`, and `~/.sift/active_case` can diverge | DB active-case authority; export compatibility pointers from DB only | Explicit case context per session/token/job | P0 |
| OpenSearch cross-case search | Current validation blocks non-`case-*` indexes but can still allow broad `case-*` patterns | Gateway rewrites/filters index patterns by authorized case | OpenSearch tools never receive unscoped agent-supplied index patterns | P0 |
| Loss of evidence integrity provenance | Manifest/ledger are strong but outside DB authority | Mirror manifest/ledger events and preserve proof artifacts | DB integrity events linked to immutable ledger exports | P0 |
| Audit gaps during migration | Audit JSONL write can be skipped when no active case resolves (`packages/sift-common/src/sift_common/audit.py:262-264`) | Dual-write audit to DB and JSONL, fail closed for privileged actions where required | Postgres append-only audit with required actor/case/action refs | P0 |
| Duplicate parser/indexing runs | Status files approximate jobs but do not provide central idempotency | Add DB job/run idempotency keys before changing ingest launch | Durable jobs, parser_runs, leases, and unique output/index registrations | P1 |
| Frontend accidentally becoming source of truth | Frontend store mirrors file-shaped API responses and token/evidence workflows | Keep frontend API-only; move state authority behind services | Supabase Auth/RLS and Gateway APIs; no direct data-plane writes | P1 |
| Worker crash during long-running parser execution | OpenSearch ingest uses subprocesses, PID status, and local logs | Mirror PID/status to DB; add worker heartbeat/lease model | Durable jobs with leases, retries, cancellation, and terminal states | P1 |
| Inconsistent state between Postgres and OpenSearch | OpenSearch indexes currently stand apart from case/evidence/job authority | Register existing indexes; write DB indexing metadata before/after ingest | DB index registry and document provenance metadata | P1 |
| Compatibility files drifting from database authority | Transition requires exports for legacy tools | Single compatibility exporter; mark file writes generated and audit them | Deprecate file authority after all readers migrate | P1 |

## 9. Decisions And Open Questions

### Confirmed decisions

- No Redis/RQ.
- Supabase/Postgres is the authority.
- OpenSearch is core search/data plane.
- MCP/service tokens are DB-backed hash-only registry records.
- Frontend does not become forensic authority.
- Agent findings are not auto-approved.
- Human operators authenticate through Supabase Auth and RLS.
- AI agents, MCP clients, workers, and backend services use
  Gateway-issued MCP/service tokens.
- Gateway remains the enforcement point for case scope, tool scope, expiry,
  revocation, and policy checks.
- Evidence Vault remains immutable evidence storage; raw evidence must not
  become mutable database state.

### Decisions needing user approval

- Exact Supabase Local deployment shape for this repo and installer.
- Whether active-case state is per human session, per workstation, per Gateway
  instance, or all three with explicit precedence.
- Token hash strategy and metadata policy, including hash algorithm, optional
  pepper/KMS use, token prefix/fingerprint display, and default expiry.
- First compatibility cutover order: cases/tokens first, evidence/audit first,
  or OpenSearch/jobs first.
- How long generated compatibility files should remain supported after DB
  authority is available.
- Whether legacy examiner bearer fallback should exist during Supabase Auth
  rollout, and for how long.

### Code facts still needing confirmation

- Complete list of all direct writers to `findings.json`, `timeline.json`,
  `iocs.json`, `todos.json`, and `evidence.json` outside the inspected modules.
- Exact OpenSearch document fields currently emitted by every parser family and
  which can be backfilled with `evidence_id`, `job_id`, and `parser_run_id`.
- Whether any external scripts or operator workflows read `~/.sift/ingest-status`
  or `~/.sift/active_case` directly.
- Whether current report exports are consumed by downstream tooling that
  requires the saved JSON file shape.
- Whether evidence manifest/ledger files must remain canonical legal artifacts
  even after Postgres becomes the operational authority.
- Exact worker process model desired for parser execution: single Gateway host
  worker, multiple local workers, or future distributed workers.

## 10. Next Recommended Run

The next focused run should create:

`docs/migration/03_opensearch_core_integration.md`

Recommended scope: map current OpenSearch standalone/add-on MCP backend behavior
to the target integrated core SIFT MCP and control-plane-aware design. Keep the
run limited to OpenSearch boundaries, current tool surfaces, index/query
scoping, ingest status/job mapping, document provenance metadata, and
Gateway-mediated authorization. Do not implement code, do not write migrations,
and do not design the full database schema.
