# Protocol SIFT Gateway Developer Entrypoint

> Covers: pyproject.toml, packages/**, portal/**, scripts/**, .github/workflows/
> Class: live-reference
> Last validated: 35e0d33 (2026-06-16)

Status: stable developer onboarding map. This file explains how the repo fits
together for engineers and agents. It is not the active task queue; use Linear
for current status, session notes, forks, blockers, and decisions.

Start here when you need to understand the codebase before changing it.
Use `docs/new-docs/LSP_AGENT_WORKFLOW.md` for Codex, Claude Code, and editor
language-server setup.

## 1. Mental Model

Protocol SIFT Gateway is a governed DFIR platform around one rule: agents work
through Gateway MCP, while human operators keep authority over evidence,
approvals, credentials, and report release.

The repo has eight practical planes:

| Plane | Main paths | Role |
| --- | --- | --- |
| Gateway policy | `packages/sift-gateway/src/sift_gateway/` | MCP aggregation, auth, policy middleware, evidence gate, response guard, backend registry, jobs, portal API integration. |
| Core forensic tools | `packages/sift-core/src/sift_core/` | Case tools, evidence-chain logic, `run_command`, findings, timeline, report primitives, worker execution. |
| Operator portal | `packages/case-dashboard/` | Human examiner portal backend and frontend. |
| Control plane | `supabase/migrations/` | Postgres/Supabase schema, transition RPCs, audit, custody, jobs, identity, reports. |
| Search plane | `packages/opensearch-mcp/` | Case-scoped derived ingest, indexing, timeline, and search over forensic artifacts. |
| Knowledge plane | `packages/forensic-rag-mcp/`, `packages/forensic-knowledge/` | Shared reference RAG and forensic guidance. |
| Add-on plane | `packages/opencti-mcp/`, `packages/windows-triage-mcp/` | Optional/reference MCP backends registered through Gateway contracts. |
| Runtime/ops | `install.sh`, `scripts/`, `configs/` | VM install, services, AppArmor, Supabase, audit, runtime helpers. |

## 2. High-Level Flow

```text
AI agent
  |
  | MCP over HTTP
  v
sift-gateway /mcp
  |
  | auth, scope, active case, evidence gate, audit, response guard
  v
Core tools and proxied add-on tools
  |
  +-- sift-core: case_info, evidence_info, run_command, findings, timeline
  +-- opensearch-mcp: ingest/search/timeline over case-derived indexes
  +-- forensic-rag-mcp: shared reference knowledge
  +-- opencti/windows-triage: optional reference/intel/baseline add-ons
  |
  v
Supabase/Postgres, OpenSearch, pgvector, filesystem evidence
```

Human operators use `/portal` for sensitive workflows: case activation,
evidence seal/unseal/re-acquisition, finding approval, report inclusion/export,
and agent credential issuance.

## 3. Package Map

### `sift-gateway`

Role: the single policy boundary for agent and portal operations.

Important modules:

| Module | Responsibility |
| --- | --- |
| `server.py` | Gateway object, app assembly, backend lifecycle, control-plane wiring. |
| `mcp_server.py` | FastMCP server assembly, core tool wrapping, proxied backend mounting, tool metadata. |
| `mcp_endpoint.py` | ASGI-level MCP auth wrapper and request guard. |
| `policy_middleware.py` | Tool authorization, add-on authority, active-case context, audit, evidence gate, response guard, proxy case injection. |
| `auth.py`, `supabase_auth.py`, `identity.py` | REST/session/JWT/API-key auth and principal resolution. |
| `active_case.py` | Active-case lookup, DB authority helpers, and CASE.yaml metadata parity/backfill planning for `app.cases`. |
| `evidence_gate.py` | Fail-closed evidence gate checks. |
| `response_guard.py` | Secret/path scanning, redaction, output capping. |
| `mcp_backends_registry.py`, `backends/` | Add-on manifest/config loading and stdio/http backend construction. |
| `jobs.py`, `job_tools.py` | Durable job enqueue/poll tools and public job specs. |
| `portal_services.py`, `rest.py` | Portal-facing services and route integration. |

Start here for: MCP tool exposure, auth, policy, backend registration, active
case behavior, evidence gate blocks, response redaction, durable job routing,
and portal API behavior.

### `sift-core`

Role: in-process forensic tool logic and command execution.

Important modules:

| Module | Responsibility |
| --- | --- |
| `agent_tools.py` | Core MCP tool specs and `call_core_tool()`. |
| `case_manager.py`, `case_ops.py`, `case_io.py` | Case state helpers and file-backed compatibility paths. |
| `active_case_context.py` | Request-scoped authority context passed from Gateway. |
| `evidence_chain.py`, `evidence_ops.py`, `verification.py` | Evidence registration/seal/proof helpers and integrity checks. |
| `investigation_store.py` | DB-backed findings, timeline, TODOs, and stale-write guards. |
| `reporting.py`, `report_profiles.py` | Report assembly and approved-only filtering. |
| `execute/` | `run_command`, sandbox policy, worker subprocess, runtime ACL, command catalog. |

Start here for: core tool behavior, `run_command`, finding/timeline writes,
evidence-chain behavior, report generation, and worker execution.

### `case-dashboard`

Role: human operator portal.

Important areas:

| Path | Responsibility |
| --- | --- |
| `src/case_dashboard/routes.py` | Portal routes and re-auth callbacks. |
| `src/case_dashboard/auth.py`, `session_jwt.py` | Portal login/session handling. |
| `frontend/src/` | React SPA for cases, evidence, findings, reports, settings, and health. |
| `tests/` | Portal route and frontend behavior tests. |

Start here for: operator UX, portal approval workflows, evidence actions,
report UI, token/session UX, and frontend regressions.

### `opensearch-mcp`

Role: case-scoped derived search plane.

Important modules:

| Module | Responsibility |
| --- | --- |
| `registry.py` | Deployed typed FastMCP tool contract. |
| `server.py` | Implementation engine delegated to by the registry. |
| `ingest.py`, `ingest_job.py` | Ingest pipeline and durable job path. |
| `parse_*.py` | Artifact parsers such as EVTX, CSV, JSON, Plaso, Prefetch, memory output. |
| `client.py`, `bulk.py`, `tools.py` | OpenSearch query/index helpers and tool implementations. |
| `host_discovery.py`, `host_identity_db.py` | Derived host identity metadata. |
| `sift-backend.json` | Gateway add-on manifest. |

Start here for: ingest, case index naming, search/timeline behavior, parsed
artifact fields, host derivation, and OpenSearch backend manifest changes.

#### Execution routes: worker vs direct

opensearch-mcp tools split into two execution routes. The split is one invariant —
`_OPENSEARCH_JOB_DISPATCH_TOOLS` in
`packages/sift-gateway/src/sift_gateway/policy_middleware.py`
(`OpenSearchJobDispatchMiddleware`, the innermost gateway middleware):

- **Worker / durable-job route** — long-running, non-blocking. The gateway
  ENQUEUES a durable job (kinds `ingest` / `enrich`; handlers in
  `opensearch_mcp/ingest_job.py`, registered in
  `sift_core/execute/job_worker_cli.py`, claimed by `sift-opensearch-worker@`)
  and returns an opaque `job_id` immediately; poll `running_commands_status`.
  Required because the pipeline FUSE-mounts evidence, which the gateway's private
  mount namespace forbids.
  - `opensearch_ingest` (only when `dry_run=False`)
  - `opensearch_enrich_intel`
- **Direct route** — fast, synchronous, proxied straight to the backend (no
  worker): every query (`search`, `count`, `aggregate`, `get_event`, `timeline`,
  `field_values`, `case_summary`, `list_detections`), every read/status
  (`status`, `shard_status`, `ingest_status`, `inspect_container`), and the
  `opensearch_ingest(dry_run=True)` preview.

**Invariant:** ingestion + enrichment go to the worker route; queries, reads, and
idempotent admin stay direct. A new long-running / FUSE / privileged opensearch
tool MUST be added to `_OPENSEARCH_JOB_DISPATCH_TOOLS` **and** given a worker
handler in the same change; a query/read tool must not. A guard test in
`packages/sift-gateway/tests/test_opensearch_dispatch_middleware.py` pins the set
so a new long-running tool cannot silently ship as direct.

**Exception:** `opensearch_fix_host_mapping` is a long-running `update_by_query`
reindex but runs DIRECT by design — it is idempotent and continues server-side
after a client timeout (re-call resumes), and it does not FUSE-mount, so it does
not need the worker. In DB-active mode it records an authoritative Postgres
host-identity receipt.

### `forensic-rag-mcp` and `forensic-knowledge`

Role: shared reference knowledge plane.

Important modules:

| Path | Responsibility |
| --- | --- |
| `packages/forensic-rag-mcp/src/rag_mcp/server.py` | MCP tool surface for knowledge search. |
| `pgvector_store.py` | pgvector query/store logic. |
| `query_embedding.py` | Embedding model integration. |
| `pgvector_seed.py`, `pgvector_chroma_import.py` | Knowledge seeding/import paths. |
| `packages/forensic-knowledge/data/` | Curated forensic reference material. |

This plane is reference-only. It does not authorize cases, approve findings,
or become case evidence.

### Add-on backends

Role: optional MCP backends registered through Gateway.

Current reference add-ons:

| Package | Namespace | Role |
| --- | --- | --- |
| `packages/opencti-mcp/` | `cti` | OpenCTI threat-intel lookup/enrichment. |
| `packages/windows-triage-mcp/` | `wintriage` | Windows baseline, LOLBin, registry, and artifact triage. |

Each add-on has a `sift-backend.json` manifest. Served tool names must match the
manifest contract and namespace. Gateway remains the policy boundary.

## 4. Tool Surface

Core in-process tools are defined in `sift_core.agent_tools`.

Typical core tools:

| Tool | Purpose |
| --- | --- |
| `case_info` | Inspect active case state and platform capabilities. |
| `evidence_info` | Inspect evidence registration and chain status. |
| `run_command` | Execute forensic commands under policy and sandbox controls. |
| `record_finding` | Draft or record investigation findings. |
| `record_timeline_event` | Record timeline events. |
| `list_existing_findings` | Read existing finding records. |
| `manage_todo` | Manage investigation TODOs. |
| `get_tool_help` | Return tool guidance. |

Gateway-local tools such as `capability_guide`, `run_command_job`, and
`running_commands_status` may be registered by `sift-gateway` when the needed
services are wired.

Add-on tools use their manifest namespace, for example:

- `opensearch_*`
- `kb_*`
- `cti_*`
- `wintriage_*`

## 5. Request And Policy Flow

Agent MCP calls enter through Gateway:

```text
POST /mcp
  -> MCPAuthASGIApp
  -> FastMCP router
  -> ToolAuthorizationMiddleware
  -> AddonAuthorityMiddleware
  -> CaseContextMiddleware
  -> AuditEnvelopeMiddleware
  -> ProxyActiveCaseMiddleware
  -> EvidenceGateMiddleware
  -> ResponseGuardMiddleware
  -> Gateway-local core tool or proxied add-on backend
```

The exact order is implementation-owned by `policy_middleware.py` and
`mcp_server.py`; check those files before changing policy semantics.

Key rule: policy and case context are resolved before tool execution. Response
redaction happens after execution and before the agent sees the result.

## 6. `run_command` Flow

`run_command` is intentionally flexible but not raw shell execution.

High-level path:

```text
agent calls run_command
  -> Gateway policy middleware checks identity, active case, evidence gate
  -> sift_core.agent_tools._run_command
  -> command parsing and evidence/output reference resolution
  -> execute executor with scrubbed environment
  -> isolated worker subprocess
  -> optional systemd scope / runtime user / sandbox controls
  -> forensic tool subprocess with shell=False
  -> provenance, output handling, redaction, audit
```

Start points:

- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-core/src/sift_core/execute/executor.py`
- `packages/sift-core/src/sift_core/execute/worker.py`
- `packages/sift-core/src/sift_core/execute/security.py`
- `packages/sift-core/src/sift_core/execute/runtime_acl.py`
- `configs/apparmor/`
- `configs/systemd/sift-job-worker.service`

Archived RUN-3 research/spec files are no longer default repo context. Use them
only when an issue or operator links an archive path for targeted extraction.

## 7. DB-Active Authority Model

Production-style operation is DB-active. Postgres owns mutable case authority;
files are evidence bytes, derived artifacts, fallback state, or exported proof.

Key authority objects:

| Object | Kind | Purpose |
| --- | --- | --- |
| `app.cases` | table | Case records. |
| `app.active_case_state` | table | Per-principal active-case assignment. |
| `app.operator_profiles`, principal/scope tables | tables | Operator and agent identity mapping. |
| `app.mcp_backends` | table | Add-on backend config and manifest registry. |
| `app.audit_events` | table | Authoritative audit trail. |
| `app.evidence_objects`, `app.evidence_versions` | tables | Evidence registry and versions. |
| `app.evidence_chain_heads`, `app.evidence_custody_events` | tables | Custody chain and seal status. |
| `app.evidence_gate_status(case_id)` | function | Aggregated evidence gate status consumed by Gateway. |
| `app.jobs`, `app.job_steps`, `app.job_logs` | tables | Durable job state. |
| `app.investigation_findings`, timeline/report tables | tables | Investigation and report authority. |
| `app.rag_*` | tables | Shared knowledge/reference pgvector plane. |

Migration files in `supabase/migrations/` are the schema authority. Read them
with the service code when changing transitions or state semantics.

## 8. Backend Registration

Gateway discovers add-on backends from `app.mcp_backends`. A backend row carries
transport config, enabled state, and manifest metadata. The manifest describes
namespace, tools, scopes, authority contract, and safe case argument behavior.

Developer rules:

- Tool names served by a backend must be declared in the manifest.
- Tool names should use the backend namespace prefix.
- Reference-plane backends must not claim case authority.
- Secrets should be provided through environment references or runtime config,
  not pasted into manifests or Linear.
- After manifest changes, update golden fixtures when present and re-register or refresh the
  backend row as required by the issue.

## 9. Common Change Routing

| Change type | Start with |
| --- | --- |
| MCP tool behavior | `sift-gateway/mcp_server.py`, `sift-core/agent_tools.py`, related package tests. |
| Policy/auth/evidence gate | `sift-gateway/policy_middleware.py`, `auth.py`, `supabase_auth.py`, `evidence_gate.py`, migrations. |
| Portal workflow | `case-dashboard/src/case_dashboard/routes.py`, `portal_services.py`, `case-dashboard/frontend/src/`. |
| Evidence lifecycle | `sift-core/evidence_chain.py`, `sift-gateway/portal_services.py`, evidence custody migrations. |
| `run_command` | `sift-core/agent_tools.py`, `sift-core/execute/`, AppArmor/systemd configs. |
| Durable jobs | `sift-gateway/jobs.py`, `job_tools.py`, `sift-core/execute/job_worker.py`, durable-job migrations. |
| OpenSearch ingest/search | `opensearch-mcp/registry.py`, `server.py`, `ingest_job.py`, parsers, manifest. |
| RAG/knowledge | `forensic-rag-mcp/src/rag_mcp/`, `forensic-knowledge/`, pgvector migration. |
| Reports/findings | `sift-core/reporting.py`, `investigation_store.py`, portal report routes/components. |
| Add-on contract | Add-on `sift-backend.json`, `sift-gateway/mcp_backends_registry.py`, add-on conformance tests. |
| Install/runtime | `install.sh`, `scripts/`, `configs/systemd/`, `configs/apparmor/`. |

## 10. Existing Deep-Dive Docs

Use these for deeper code reading:

- [`DATA_FLOW.md`](DATA_FLOW.md): end-to-end request/data flows.
- [`KEY_FUNCTIONS.md`](KEY_FUNCTIONS.md): major functions and call paths.
- [`DATA_STRUCTURES.md`](DATA_STRUCTURES.md): important models and structures.
- [`ALGORITHM_FLOWS.md`](ALGORITHM_FLOWS.md): middleware and algorithm flow notes.
- [`KEY_QUESTIONS.md`](KEY_QUESTIONS.md): implementation questions and answers.
- [`CODEBASE_ASSESSMENT.md`](CODEBASE_ASSESSMENT.md): generated assessment notes.
- [`../drafts/code-structure.md`](../drafts/code-structure.md): archival package map.
- [`../drafts/architecture.md`](../drafts/architecture.md): archival architecture detail.

Some draft files predate later cleanup. Treat `docs/drafts/` as useful context,
not authority, and verify claims against current source before acting on them.

## 11. Validation

For documentation-only changes:

```bash
python3 scripts/validate_docs.py
python3 scripts/validate_migration_docs.py
git diff --check
```

For implementation changes, add targeted tests for touched packages. Common
patterns:

```bash
bash -n install.sh scripts/setup-addon.sh scripts/setup-supabase.sh
uv run --extra dev --extra full pytest <targeted test paths>
```

### Supported pytest invocation forms (XYE-68 / C4)

Run tests from the **repo root**; never `cd` into a package directory. There are
three supported entry points:

```bash
# 1. Cross-cutting root suite (CI parity)
uv run --locked --extra full --extra dev pytest tests

# 2. Full per-package suites + coverage floors (CI parity)
uv run --locked --extra full --extra opencti --extra windows-triage --extra dev \
  python scripts/check_package_coverage.py

# 3. One package at a time (fast local loop)
uv run --extra dev --extra full pytest packages/<pkg>/tests
```

Per-package extras / env that some suites require:

| Package | Extra requirement |
|---|---|
| `windows-triage-mcp` | `--extra windows-triage` |
| `opencti-mcp` | `--extra opencti` |
| `opensearch-mcp` | `-m "not integration"` for the unit subset; some local runs also need `PYTHONPATH=packages/opensearch-mcp/tests` so `_helpers` resolves |

Regenerate MCP surface goldens with `UPDATE_MCP_GOLDENS=1` on the targeted run.

**Do not** run `pytest packages` (all packages at once). Every package's
`tests/` directory is an importable package (each contains an `__init__.py`), so
they all import under the same top-level module name `tests`; collecting them
together makes `tests.conftest` and `tests.<module>` resolve ambiguously across
packages and fails with `ImportPathMismatchError` / `ModuleNotFoundError` (and
`--import-mode=importlib` only narrows it to the duplicate-`conftest` clash).
`check_package_coverage.py` avoids this by running each package as its own pytest
subprocess. A real fix (give each package's test package a unique name, or drop
those `__init__.py` files) is a deliberate layout change deferred as an optional
follow-up; the invocation forms above are the supported contract today.

For live-impacting fixes, follow the Linear issue acceptance: host change,
targeted validation, VM sync, service restart, health/tool proof, sanitized
Linear comment.
