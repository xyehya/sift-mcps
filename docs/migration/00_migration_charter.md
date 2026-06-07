# Migration Charter

Last updated: 2026-06-07 (Run 26 target architecture acceleration).

This charter is the single source of truth for locked migration decisions. Where
any other document under `docs/migration/` conflicts with the "Confirmed
Decisions (Locked)" section below, this charter wins and the other document must
be corrected.

## Target Architecture

The target architecture is a SIFT VM Autonomous DFIR Agent system with four clear boundaries:

- Presentation layer: React + Vite operator portal for case lifecycle, findings, timeline, evidence integrity, and MCP token management.
- Gateway/Broker layer: **FastAPI + FastMCP 3.0** (one ASGI app: REST via FastAPI, MCP via `mcp.http_app`) for REST, WebSocket/SSE where needed, MCP tool mediation, authentication, authorization, audit, and policy enforcement. FastMCP 3.0 providers/transforms handle aggregation/namespacing/catalog mechanics only; the policy logic, tool authorization, and case authorization stay SIFT-owned. See D24 and `14_fastmcp3_supabase_integration.md`.
- Case control plane: Supabase Local/Postgres as the authoritative store for case and workflow state.
- Execution and data planes: SIFT VM workers execute durable jobs from Postgres, while OpenSearch stores derived searchable artifacts, timelines, IOCs, full-text data, and vector-search data.

AI agents and MCP clients interact only through Gateway-mediated MCP tools.
Case-data tools are case-scoped; global/reference add-ons are tool-scoped and
audited under the active case. In the final target (D30), humans, agents, MCP
clients, workers, and services authenticate with Supabase-issued JWTs; the
Gateway then applies SIFT-owned case/tool/evidence/audit policy. Agents must not
bypass Gateway policy, Postgres authorization, evidence controls, or approval
gates.

The detailed end-state reference and batching plan is
`18_target_architecture_acceleration.md`.

## Current Migration Status

This charter defines the target architecture and locked decisions. The current
landed implementation is intentionally transitional:

- **Done:** JOB-0 baseline checks, PR01 / Phase ID-1 identity schema foundation,
  PR02 / Phase ID-2 hash-only MCP/service token registry with legacy
  `gateway.yaml` fallback, D27a backend FastMCP/tool-contract revamp, and D27b
  Gateway FastMCP cutover. Per D30, PR02 is now a transitional compatibility
  bridge rather than the final identity target.
- **Current Gateway substrate:** landed D27b serves one FastAPI ASGI app with
  the aggregate FastMCP `http_app` mounted at `/mcp`; per-backend `/mcp/{name}`
  routes are removed. Core gateway tools are local FastMCP tools; configured
  add-ons are FastMCP proxy mounts. SIFT-owned middleware enforces the evidence
  gate, response guard, case-context injection, and audit envelope.
- **Still pending:** unified Supabase JWT authentication for human operators,
  agents, MCP clients, workers, and services (D30 / accelerated Phase ID-3);
  case-membership/principal resolution; control-plane active-case authority and
  propagation (ID-4/ID-5); evidence-gate case resolution from control-plane
  context (ID-5); legacy auth/token-path sunset (ID-6); D22 `mcp_backends`
  control-plane registry replacing `gateway.yaml` add-on registration (F-11);
  OpenSearch and RAG final core/control-plane integration (D19/D23).
- **Next planned session:** Plan-stage PR03A / Batch A from
  `18_target_architecture_acceleration.md`: unified Supabase JWT authentication
  and principal resolution for REST and MCP, with PR02 token-registry
  compatibility explicitly scoped. Do not treat D22/F-11 or active-case
  propagation as implicitly in scope for that run.

## Plane Boundaries

### Control Plane

Supabase/Postgres is authoritative for:

- Cases, case lifecycle, and case permissions.
- Active case state. The operator selects the active case in the portal; that
  selection is authoritative in the control plane and the Gateway propagates it
  to every backend, API, and MCP tool call.
- Human operator authorization state through Supabase Auth and RLS.
- MCP/service-token registry state.
- Durable jobs, ingestion/parser/indexing pipeline state, job steps, and logs.
- Audit events.
- Evidence metadata, evidence status, evidence verification state, and evidence
  anchoring (e.g. Solana proof) state.
- Findings, timeline items, IOCs, TODOs, approvals, and review state.
- Reports and report/export artifact metadata.
- RAG knowledge collections registered/centralized into the control plane.
- Agent skill documents (`skills.md`-style operator/agent playbooks) the agent
  or operator can retrieve.

Why Supabase/Postgres specifically (recorded rationale): the project wants one
centralized control plane that unifies auth, the MCP token registry, audit
events, ingestion and other pipelines, case management, the AI-agent review
surface (checking and approving findings, managing TODOs, checking timelines),
report storage, an opportunity to centralize the RAG database, storage for
retrievable agent skill documents, and evidence status/integrity monitoring,
approval, and sealing. All of that is file-based today and must align with the
new control-plane and Gateway-mediated model.

The SIFT VM is not air-gapped but is network-restricted; offline-only
constraints are explicitly out of scope. Local Supabase deployment is acceptable
in that restricted environment.

Current JSON/file-based state should migrate gradually into this control plane and must not remain the long-term authority. The migration moves away from file-based artifacts as authority except where a file artifact is absolutely necessary (notably immutable raw evidence and preserved manifest/ledger proof artifacts).

### Data Plane

OpenSearch is a core integrated data plane for derived investigative data:

- Parsed artifacts.
- Timeline/search indexes.
- IOC search and enrichment views.
- Full-text search.
- Vector search.

OpenSearch must not become authoritative for case permissions, token validity, durable job ownership, evidence integrity, approvals, or final finding state. It is a query and retrieval plane fed by controlled ingestion and parser workflows.

Canonical OpenSearch profile: OpenSearch 3.5.0 with security enabled. The root
`docker-compose.yml` in the current repository (OpenSearch 2.18.0 with security
disabled) is pre-migration and not the target; security-disabled localhost
exposure is incompatible with the Gateway-mediated, case-scoped access boundary
and must not be carried into the target deployment.

### Execution Plane

The execution plane is the SIFT VM worker runtime:

- Workers claim durable jobs from Postgres (poll + `SKIP LOCKED`); the control
  plane never pushes work to workers.
- Workers run Python parsers and native Linux/SIFT workflows.
- Workers perform ingestion, parsing, normalization, indexing, and report generation.
- Workers write status, logs, proposed findings, audit updates, and job completion through authorized control-plane paths.
- AI-agent deeper analysis (the existing `run_command` and extraction tooling)
  runs here as sandboxed, shell-free, allowlisted, case-jailed execution. The
  agent reaches it only through Gateway MCP tools, never directly. This covers
  analysis that is not inherently available in OpenSearch (deeper inspection,
  targeted file extraction, running forensic tools on the SIFT VM).

Initial worker topology is a single local worker on the SIFT VM (confirmed). The
model must remain compatible with adding more local workers later, but v1 does
not need multi-worker fairness machinery.

There is no Redis/RQ job authority. Durable job state must go through Postgres/Supabase.

### Gateway/Broker Layer

The Gateway/Broker is **FastAPI + FastMCP 3.0** (one ASGI app: REST via FastAPI
dependency injection, MCP via `mcp.http_app`; D24) and is the **single,
mandatory** policy boundary. ALL REST APIs, ALL MCP tool calls, and ALL
privileged actions go through the Gateway. FastMCP 3.0 providers/transforms do
aggregation and namespacing only; the evidence gate, response guard, audit
envelope, active-case propagation, and authorization remain SIFT-owned
middleware or Gateway service logic. There is no compliant path that reaches a
backend, OpenSearch, evidence, or the control plane without passing Gateway
policy.

- Operator actions enter through REST/API surfaces.
- Agent actions enter through MCP tool calls.
- Gateway enforces authentication, authorization, case scope, tool scope, evidence policy, audit policy, and response policy.
- Gateway mediates access to Postgres, OpenSearch, evidence controls, and execution workflows.
- Gateway propagates the control-plane active case to backends and tool calls.
- Per-backend direct MCP routes (`/mcp/{name}`) are disabled. Every MCP tool
  call is served only through the aggregate Gateway policy path so the evidence
  gate, case scope, tool scope, response guard, and audit envelope apply
  uniformly. D27b removed the old per-backend route surface because it bypassed
  the aggregate evidence gate and response guard.

## Non-Negotiable Rules

- Supabase/Postgres is the authoritative control plane.
- OpenSearch is a core integrated search/data plane, not an optional standalone MCP backend in the long-term architecture.
- Existing evidence vault and audit functionality must be preserved and integrated through control-plane capabilities.
- Current JSON/file-based state migrates gradually and must not remain the long-term authority.
- No Redis/RQ.
- Durable job state must go through Postgres/Supabase.
- Gateway/Broker is FastAPI + FastMCP 3.0 (D24); the policy boundary is SIFT-owned, not delegated to the framework.
- AI agents interact through Gateway-mediated MCP tools only. Case-data tools are case-scoped; global/reference add-ons are tool-scoped and audited under the active case. Agents must not bypass Gateway policy or Postgres authorization.
- Target authentication is Supabase JWT for humans, AI agents, MCP clients,
  workers, and backend services (D30). Legacy Gateway-issued hash-only MCP/service
  tokens are a transitional compatibility path until explicitly sunset.
- Human operators authenticate through Supabase Auth and RLS.
- AI agents, MCP clients, workers, and backend services authenticate with
  Supabase-issued JWTs in the final target; Gateway validates the JWT, resolves
  the application principal, and enforces case/tool/evidence/audit policy.
- Raw evidence remains immutable.
- Agent-generated findings are proposed or draft state until human approval.
- Agent-generated findings must not be auto-approved.
- OpenSearch-derived results must be traceable to registered evidence and auditable ingestion/parsing activity.
- The Gateway is the single policy boundary; ALL APIs, MCP tools, and actions go through it. Per-backend direct MCP routes are disabled.
- Active case is set in the portal only, is authoritative in the control plane, and is propagated by the Gateway. It is never read from process environment or pointer files as authority.
- Long-running tool calls (ingestion, parsing, indexing, evidence verification, report/finding generation) enqueue durable jobs/pipelines in the control plane and return a job ID. There is never a direct job or invoke to the Evidence Vault.
- OpenSearch is OpenSearch 3.5.0 with security enabled.
- All existing operator/agent capability is retained through the migration, including evidence anchoring (Solana proof), TODOs, and IOCs. Nothing is dropped or left as a vague "future" item.
- Migration cutover order is cases/tokens/identity first (see "Cutover Order").

## Confirmed Decisions (Locked)

These decisions are approved and must be treated as fixed by all other migration
documents and by future coding sessions. They resolve the prior "Decisions
needing user approval" / "Open Questions" entries scattered across docs 02-08.

| # | Decision | Locked value |
| --- | --- | --- |
| D1 | Control-plane authority | Supabase Local / Postgres is authoritative for everything listed under Control Plane above. |
| D2 | Gateway boundary | Single mandatory boundary. ALL REST APIs, MCP tools, and privileged actions go through the Gateway. |
| D3 | Per-backend MCP routes | **Dropped.** Only the aggregate Gateway policy path (`/mcp`) serves MCP tool calls. The per-backend `/mcp/{name}` routes were **removed at the D27b gateway cutover** (confirmed Run 22, F-7): the pre-D27b handler (`create_backend_mcp_server`) ran **no evidence gate and no response guard**, so the routes were a live policy bypass, not just a hardening nicety. All agents/clients use the aggregate `/mcp`. |
| D4 | Active case | **One operator, one active case at a time.** Other cases may exist but only one is marked active. The operator selects it in the portal; it is authoritative in the control plane (`active_case_state`); the Gateway propagates it to backends/APIs/tools. Legacy `SIFT_CASE_DIR` / `~/.sift/active_case` become generated compatibility exports during transition, never authority. (`active_case_state.scope` leaves room for per-operator active case later without a schema change.) |
| D5 | Long-running work | Enqueues durable control-plane jobs/pipelines and returns a job ID. Never a direct job/invoke to the Evidence Vault. Workers claim jobs (poll + `SKIP LOCKED`); the control plane never pushes. |
| D6 | OpenSearch profile | OpenSearch 3.5.0, security enabled, Gateway-mediated and case-scoped. Root repo `docker-compose.yml` (2.18.0, security disabled) is pre-migration only. |
| D7 | Supabase deployment | Local Supabase on the network-restricted (non-air-gapped) SIFT VM. Offline-only constraints are out of scope. |
| D8 | Identity model (superseded in target by D30) | Historical/transition value implemented by PR02: humans authenticate via Supabase Auth + RLS, while AI agents, MCP clients, workers, and backend services use Gateway-issued, hash-only, case-scoped, tool-scoped, expiring, revocable MCP/service tokens validated against the Postgres registry. **D30 supersedes the final target:** Supabase-issued JWTs become the credential for all external principal classes; the hash-token registry remains a compatibility bridge until ID-6. |
| D9 | Worker topology v1 | Single local worker on the SIFT VM, extensible to multiple local workers later. No multi-worker fairness machinery required in v1. |
| D10 | Key strategy | New DB records use UUID primary keys plus explicit legacy text keys (e.g. `case_key`, `legacy_case_id`). |
| D11 | Schema namespace | Tables live in an `app` schema with RLS, plus an `internal`/`svc` schema for service-only helpers. |
| D12 | Write model | Privileged writes go through Gateway/worker service-role paths. RLS protects human reads and a small set of explicitly safe human writes; the browser never mutates authoritative state directly and never talks to a backend or OpenSearch directly. RLS is a defense-in-depth boundary behind the Gateway, not the primary write path. |
| D13 | Job model size (v1) | Lean core: `jobs`, `job_steps`, `job_logs`, `workers`. `attempt_count` lives on the job row; `job_attempts`, `job_cancellations`, and `worker_heartbeats` are deferred (folded into `jobs` + `audit_events`) until a concrete need exists. `SKIP LOCKED` fairness across cases is added only when a second worker exists. All job types and step types are enumerated, but only a few are implemented first. |
| D14 | Retained capabilities | Evidence anchoring (Solana), TODOs, and IOCs are first-class and migrated, not deferred. |
| D15 | Control-plane scope additions | RAG knowledge collections and retrievable agent skill documents are centralized into the control plane as concrete (net-new) capabilities, Gateway-mediated like everything else. |
| D16 | Evidence dedup | Dedup must never silently drop forensically distinct acquisitions. Default is preserve; any `(case_id, sha256)` uniqueness is an explicit, opt-in policy, not the default. |
| D17 | Cutover order | Cases/tokens/identity first (see below). |
| D18 | OpenSearch write contract + index naming | **Reuse the existing, working ingestion model**; do not refactor parsers/enrichments. v1 keeps the current index naming `case-{case_id}-{artifact_type}-{hostname}` (already case-prefixed, already template-backed and auto-created on first bulk write), the shared `flush_bulk` writer, the host auto-discovery preflight, and the `vhir.*`/`host.*`/`pipeline_version` provenance stamping. The control plane **registers** these indices in `opensearch_indexes` (discovery/registration, not renaming). The logical-family rename (`dfir-case-{case_id}-{artifacts\|timeline\|iocs}-vN` + aliases) is a **deferred, optional** evolution, not required for v1. **Any writer** (core worker, addon MCP backend such as a future OpenCTI/Hayabusa enrichment, or future addon) must conform additively to the shared write contract in `03` §7A: case-scoped name via `build_index_name()`, mandatory provenance/metadata, registration of new indices/batches, and `case_id` taken from job/active-case context - without a full refactor of the working backend. Data-plane writes (workers/enrichments) write to OpenSearch directly under an authorized job; the Gateway-only rule (D2) governs the control/tool-call boundary, not internal execution-plane bulk writes. |
| D19 | OpenSearch is core, not an add-on | OpenSearch search/status/aggregate are exposed as in-process **core** SIFT MCP tools (synchronous); ingest/enrichment/reindex are core tools that **enqueue durable jobs** run by the worker. The standalone stdio/http server and the add-on **manifest registration** for OpenSearch are retired. The `opensearch-mcp` package remains as the in-process implementation imported by the Gateway (read tools) and the worker (ingest/enrichment). |
| D20 | OpenCTI = full platform, shared OpenSearch backend | Run the **full OpenCTI stack** (platform, worker, redis, rabbitmq, minio) but point its index store at the **existing SIFT OpenSearch cluster** rather than standing up a second one. `opencti-mcp` stays a **query-only** API client to the OpenCTI platform; the agent never touches OpenCTI indices directly. OpenCTI's internal redis/rabbitmq/minio are third-party platform internals and are **not** subject to the "No Redis/RQ" rule (which governs only SIFT durable-job authority). |
| D21 | OpenSearch cluster cohabitation + security roles | The shared OpenSearch 3.5.0 (security on) cluster hosts two index classes: SIFT case indices (`case-*`) and OpenCTI platform indices (`opencti_*`). Each consumer gets a **scoped security role**: SIFT worker/service → `case-*`; OpenCTI → `opencti_*`; the **AI agent gets no cluster credentials** (only Gateway-mediated, case-scoped tools). Capacity/shard monitoring accounts for both classes. |
| D22 | Add-on MCP backend spec direction | The Gateway is the single enforcement point; per-backend MCP routes disabled (D3). Add-on backends are **query-only/read-only by default**; a write-capable add-on must declare it and obey the §7A write contract + control-plane registration. The manifest gains a per-tool **`case_scoped`** flag (global add-on tools like OpenCTI/wintriage queries are case-agnostic but still audited under the active case) and a backend **data-plane dependency** declaration. **Backend registration moves from `gateway.yaml` into a control-plane `mcp_backends` registry**, managed/monitored from the portal. Full spec: `10_addon_backend_spec.md`. |
| D23 | RAG folds into core | The RAG capability is no longer a standalone add-on backend. Its vector store moves to **Supabase (pgvector; `rag_collections`/`rag_documents`)** and retrieval is exposed as a **core, control-plane-backed** tool. `forensic-rag-mcp`'s Chroma store is migrated; the package is retired or reduced to a thin core retrieval path. `windows-triage-mcp` remains a minimal query-only add-on (local baseline-DB package). |
| D24 | MCP framework: FastMCP 3.0 substrate | The Gateway and the FastMCP-style backends migrate to **standalone FastMCP 3.0** (`pip install fastmcp` / `import fastmcp`), replacing the low-level `mcp.server.lowlevel.Server` gateway plumbing and the in-SDK `mcp.server.fastmcp` (1.x) backends. The Gateway becomes **one FastAPI ASGI app** serving (a) the portal REST API and (b) the MCP endpoint via `mcp.http_app(...)` with combined lifespans. FastMCP 3.0 **providers** (`ProxyProvider`/`LocalProvider`; future providers only when separately scoped) and minimal transforms such as `Namespace` provide aggregation and namespacing **only**. **This is an implementation-substrate change: the Gateway remains the single policy boundary (D2/D3). The evidence gate, response guard, audit envelope, active-case propagation, and authorization remain SIFT-owned middleware/service logic, never delegated to the framework.** Per-case/per-phase/per-role `Visibility` and `ToolSearch` were explicitly dropped for D27b (F-9); per-token tool authorization remains a SIFT-owned backlog item (B-10). Full design: `14_fastmcp3_supabase_integration.md` plus D27b implementation doc `17_gateway_cutover_d27b.md`. |
| D25 | code-mode excluded; run_command retained | FastMCP `code-mode` is **out of scope**: it is an experimental token-optimization layer that executes arbitrary LLM-generated Python and is explicitly *not* suited to strict, pre-audited command boundaries. It does **not** replace `run_command` and does **not** fix its known flakiness (Gateway argv/flex handling, `evidence/` write-gap, missing OS-level sandbox), which are fixed directly. `run_command` remains the hardened, allowlisted, audited OS-exec boundary. Tool-schema/context bloat is handled by curated tool descriptions, the manifest-derived `capability_guide`, and future SIFT-owned list/call authorization where needed; `ToolSearch`/`Visibility` are not active D27b design elements and require a new scoped decision if revived. |
| D26 | Human auth = own Supabase-JWT verify (superseded in target by D30) | Historical D27b/ID planning value: human/operator auth verifies **Supabase JWTs directly via FastAPI dependency injection** on REST routes; machine/agent/worker/service principals remained hash-only Gateway-issued tokens. **D30 supersedes the target-auth split:** REST and MCP both accept Supabase-issued JWTs through SIFT-owned FastAPI/FastMCP verifier code. FastMCP's `SupabaseProvider` remote-OAuth remains **not adopted**; Gateway-side authorization (active case, case membership, tool scope, evidence gate) is mandatory for every principal and is never delegated to an OAuth audience. |
| D27 | FastMCP cutover — staged (supersedes the original single-PR framing) | The migration is **two stages**, not one PR. Stage **D27a** revamps the backends; stage **D27b** cuts over the gateway. Rationale: the gateway↔backend boundary is the MCP wire protocol, so backends can move to 3.0 independently, de-risking the gateway PR. |
| D27a | Backend tooling revamp (stage 1, parallel-safe) | **Done (Run 21).** The three backend MCP servers (`opensearch-mcp`, `opencti-mcp`, `windows-triage-mcp`) migrated to **standalone FastMCP 3.0** and were redesigned to the tool-quality contract (D28). The work was scoped to `packages/*-mcp/**`, merged before D27b, and preserved rename/change-map discipline. OpenSearch was authored **exposure-agnostic** (function + Pydantic models + registration table) so its later in-process/core move (D19) reuses the definitions. Full spec: `15_backend_tooling_revamp.md`. |
| D27b | Gateway cutover (stage 2, after PR02 + after D27a) | **Done (Runs 23-24).** The Gateway moved to FastMCP 3.0 as one FastAPI ASGI app (D24), a single cleanly-revertable big-bang PR. Parity gate was **policy parity only**: the evidence gate, response guard, audit envelope, and active-case compatibility behavior had to remain stable across the substrate swap. The tool surface was not re-frozen; D27b consumed the D27a backend surface. Current landed shape: core gateway tools through local FastMCP tools, add-ons through FastMCP proxy mounts from existing `gateway.yaml` configuration, and per-backend `/mcp/{name}` routes removed. The OpenSearch final in-process/core move remains a later D19/OpenSearch-core phase, not a D27b side effect. |
| D28 | Tool-quality contract + exposure-agnostic authoring | Every revamped backend tool must meet a written contract: typed **Pydantic input model** with per-arg `Field` descriptions + constraints; **structured output** via `ToolResult` (no untyped blobs); complete **annotations** (`readOnly/destructive/idempotent/openWorld` + title); task-oriented **description** with when-to-use + example; **result shaping** (projection/pagination/size caps); typed **error model**; plus ≥1 **prompt** and ≥1 **resource** per backend. Tools are authored **exposure-agnostic** (pure function + models + registration table + thin adapter) so the same definitions serve a standalone server or an in-process LocalProvider. This contract is the drift-control backbone; a tool that does not meet it is not "done." Full spec: `15_backend_tooling_revamp.md` §5, §7. |
| D29 | Operating model = process of record | Development and governance follow `OPERATING_MODEL.md`: the **Plan → Build → Review → Land → Log** loop, the Definition of Done, scope-fenced worktrees, and `/code-review` (always) + `/security-review` (auth/tokens/evidence/secrets/Gateway). Open decisions are tracked as **Forks (F#)** and deferred work as **Backlog (B#)** in `REGISTER.md`; a fork resolves into a charter Decision (D#) or a B#. **No run invents or silently changes a decision** — it stops and raises a fork. Locked 2026-06-07 (Run 19). |
| D30 | Unified Supabase JWT principal model | **Final target:** humans, AI agents, MCP clients, workers, and services authenticate with Supabase-issued JWTs. The operator/portal may create agent/service principals and issue Supabase sessions/JWTs for them; those JWTs are acceptable on both REST and the FastMCP `/mcp` endpoint. The Gateway verifies JWTs with SIFT-owned FastAPI dependencies and FastMCP `TokenVerifier` subclasses (FastMCP 3.4.2 API), resolves the JWT subject to application principal/membership/tool-scope rows, and enforces SIFT policy. PR02's hash-only `mcp_tokens` registry and legacy `gateway.yaml` fallback become a transitional compatibility path and/or non-secret issuance/provenance metadata until ID-6 removes raw-token authority. Locked by operator 2026-06-07 (Run 26). Full target and batching plan: `18_target_architecture_acceleration.md`. |

## Cutover Order

The migration proceeds foundation-first because every case-scoped table and every
job carries identity and case context that does not exist yet:

1. **Cases / identity / JWT principals (foundation).** Supabase Auth,
   `operator_profiles`, agent/service/worker principal mappings, `cases`,
   `case_members`, active-case state, compatibility `mcp_tokens`/scope metadata,
   and `audit_events`. The Gateway validates Supabase JWTs for REST and MCP,
   resolves application principals, and propagates the control-plane active case.
   See `09_identity_auth_cutover.md` and
   `18_target_architecture_acceleration.md`.
2. **Evidence + audit metadata.** Mirror manifest/ledger/audit into the control
   plane while preserving immutable files and proof artifacts.
3. **Jobs / pipelines / OpenSearch integration.** Durable jobs, worker runtime,
   parser/indexing lineage, and OpenSearch 3.5.0 promotion to a core
   Gateway-mediated search plane. See `05`-`08`.
4. **Findings / TODOs / IOCs / timeline / reports / RAG / skills.** Move
   remaining file-backed investigation state and the new control-plane scope
   additions onto DB authority with compatibility exports.

Baseline protective tests (roadmap phase JOB-0) are additive and may be written
in parallel at any time; they do not depend on the cutover order.

**FastMCP 3.0 migration is staged (D24/D27/D27a/D27b/D28).** Stage 1 (**D27a**,
`15_backend_tooling_revamp.md`) and stage 2 (**D27b**,
`17_gateway_cutover_d27b.md`) are landed. The later evidence/jobs/OpenSearch-core
and findings work should now be authored on the FastMCP 3.0 Gateway substrate.

## Implementation Status

The planning workspace remains the source for future scoped implementation
candidates, but several early slices are now complete: JOB-0, PR01/ID-1,
PR02/ID-2, D27a, and D27b. The next recommended run is a **Plan-stage PR03A /
Batch A** candidate for unified Supabase JWT authentication and principal
resolution across REST and MCP (`18_target_architecture_acceleration.md`,
`09_identity_auth_cutover.md`). D22/F-11 (`mcp_backends` registry), ID-4/ID-5
active-case authority/propagation, and OpenSearch-core/RAG-core moves remain
separate later scopes unless a candidate doc explicitly batches them.

## Out Of Scope Until A Run Is Explicitly Scoped To It

The following remain out of scope for any documentation-only run and must not be
started unless a future prompt explicitly authorizes that implementation slice:

- Code implementation and runtime behavior changes.
- Supabase/Postgres migration files (beyond the agreed schema design).
- Token format/implementation changes in running code.
- OpenSearch refactor in running code.
- Evidence or audit data migration in running code.
- Docker or installer changes (the OpenSearch 3.5.0 / security-on target is a
  decision; applying it to compose/installer files is a scoped implementation
  task, not part of planning).
- Rewriting existing functionality.
- Changing tests or test expectations (other than additive baseline tests in
  JOB-0).
