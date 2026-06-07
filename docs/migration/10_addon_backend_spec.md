# Add-on MCP Backend Spec (Target)

Last updated: 2026-06-07.

Scope: planning only. This document locks the **direction** of the add-on MCP
backend contract for the migrated architecture (charter D22), designed against
the real backends in the repo. It does not finalize the JSON Schema or change
code; the concrete `sift-backend.schema.json` changes are a later scoped task.

Locked decisions referenced: D2/D3 (Gateway is the single boundary; per-backend
`/mcp/{name}` routes disabled), D12 (no direct backend/Postgres access from the
browser; service-path writes), D18/§7A (OpenSearch write contract), D19
(OpenSearch is core), D20/D21 (OpenCTI full platform + shared OpenSearch +
security roles), D22 (this spec), D23 (RAG folds into core).

## 1. What is an add-on (vs core)

**Core** tools are first-class platform capabilities exposed in-process through
the Gateway aggregate policy path: case/evidence/findings/TODO/IOC/timeline/
report tools, jobs, **OpenSearch** (search/status/aggregate + job-backed ingest,
D19), and **RAG retrieval** (control-plane/`pgvector`-backed, D23). Core tools
are not registered through the add-on manifest path.

**Add-on** backends are optional MCP servers that register with the Gateway
aggregator through a validated manifest and are recorded in the control-plane
`mcp_backends` registry. After the migration the remaining add-ons are:

| Add-on | Shape | Case scope | Data plane | Notes |
| --- | --- | --- | --- | --- |
| `windows-triage-mcp` | query-only over a shipped baseline-DB package | global (case-agnostic) | local package (no OpenSearch, no control plane) | the **minimal** reference add-on |
| `opencti-mcp` | query-only API client to the **full OpenCTI platform** | global (case-agnostic) | external platform; OpenCTI uses the shared OpenSearch (`opencti_*`) as its own store | agent never touches OpenCTI indices directly |

`forensic-rag-mcp` is **no longer an add-on** - it folds into core (D23).
`opensearch-mcp` is **no longer an add-on** - it becomes core (D19); its package
remains as the in-process implementation.

## 2. Non-negotiable platform guarantees (the Gateway's job, not the add-on's)

The Gateway, backed by the control plane, owns all of this so add-ons never
re-implement or bypass it:

- Authentication and **principal validation** (D30 Supabase JWT target; PR02
  hash-token registry only as compatibility bridge while enabled).
- **Case authorization** for case-scoped tools; **active-case** context injection
  for audit on every call.
- **Evidence gate** for case-scoped, non-read-only tools.
- **Audit envelope** for every tool call (identity, case, tool, status, backend).
- **Tool-scope** enforcement from the resolved principal's scopes.
- Single policy path only: per-backend `/mcp/{name}` routes are disabled (D3).
- Rate limiting / response policy.

An add-on **trusts the Gateway-injected identity, case, and scope context**. It
must never self-authorize, accept a raw `case_id` from the caller as authority,
or expose a side channel that bypasses the Gateway.

## 3. Manifest contract

The current manifest already requires `spec_version, name, version, tier,
transport, namespace, capabilities, tools, health` with rich per-tool metadata
(`read_only`, `readOnlyHint`, `evidence_class`, `category`, `recommended_phase`,
`health`, `hidden_from_agent`, `when_to_use`, `avoid_when`, `output_notes`). The
migration **adds** the following (additive schema changes):

### 3.1 Per-tool `case_scoped: boolean`

Declares whether the tool's data access is bound to a case.

- `case_scoped: true` - the Gateway enforces case authorization and passes the
  active case; the tool operates within that case.
- `case_scoped: false` - **global/reference** tool (OpenCTI IP/actor lookup,
  wintriage baseline lookup). No case authorization is required to run it, but
  the call is **still audited under the operator's active case** for provenance.

Default: `true` (safe default; global tools opt out explicitly). A backend may
declare `default_case_scoped` and override per tool.

### 3.2 Backend `data_plane` declaration

Declares what the backend reads/writes so the platform can reason about
credentials, health, and capacity:

```json
"data_plane": {
  "type": "none | local_package | control_plane | opensearch | external_platform",
  "opensearch_role": "opencti",          // when it touches the shared cluster
  "index_prefix": "opencti_*",            // its isolated index namespace
  "writes": false,                         // read-only default (see §3.3)
  "external_services": ["redis", "rabbitmq", "minio"]  // informational
}
```

Examples:
- wintriage: `{"type": "local_package", "writes": false}`.
- opencti: `{"type": "external_platform", "opensearch_role": "opencti",
  "index_prefix": "opencti_*", "writes": false, "external_services":
  ["redis","rabbitmq","minio"]}`.

### 3.3 Read-only / write-capable

Add-ons are **query-only/read-only by default**. A write-capable add-on must:
- declare `data_plane.writes: true` and the target (`opensearch` role/prefix or
  `control_plane`), and
- obey the §7A **OpenSearch write contract** (case-scoped index naming via the
  shared helper, mandatory provenance + control-plane IDs, `flush_bulk`
  discipline, index/batch registration) and write only under an authorized job.

All three current add-ons are read-only, so this is the exception path, designed
for future writers (e.g. a Hayabusa autodetection addon).

### 3.4 Health

Exactly one health tool per backend (existing requirement). Health status is
recorded in `mcp_backends.health_status` and surfaced in the portal.

## 4. Registration flow (control-plane authority)

Backend registration moves out of `gateway.yaml` into the control plane (D22):

1. Operator registers an add-on (portal or admin) by pointing at its manifest.
2. The Gateway **validates** the manifest (namespace uniqueness, >=1 tool,
   exactly one health tool, namespace prefixes on tool names, read-only/
   evidence-class consistency, `case_scoped`/`data_plane` well-formed, no
   collision with core tool names).
3. On success, the Gateway writes an `mcp_backends` row (manifest, namespace,
   tier, transport, `data_plane`, `default_case_scoped`, `enabled`).
4. The Gateway exposes the add-on's tools through the **aggregate** policy path
   only, gated by token scope, case scope (for `case_scoped` tools), evidence
   policy, and audit.
5. The portal enables/disables and monitors the add-on; the Gateway reads
   registration/enabled/health state from the control plane, not config.

Stopped/disabled manifest-backed backends still expose **stub** tool metadata
(existing behavior) so the agent sees capability availability/degradation
explicitly.

## 5. Call patterns

- **Synchronous query tools** (wintriage, opencti, opensearch read, rag
  retrieval): Gateway validates token + (case authz if `case_scoped`) + writes
  audit -> dispatches to the backend/core tool -> returns. The control plane is
  consulted/written, not a data-path proxy.
- **Long-running tools** (opensearch ingest/enrichment/reindex - core, not
  add-on today): Gateway enqueues a durable control-plane job, returns `job_id`;
  the worker runs it. A future write-capable add-on with long work follows the
  same enqueue-and-job pattern.

## 6. OpenCTI specifics (D20/D21)

- Run the full OpenCTI stack (platform, worker, redis, rabbitmq, minio); point
  its index store at the **existing SIFT OpenSearch** cluster (`opencti_*`
  indices), not a second cluster.
- `opencti-mcp` is a **query-only** API client to the OpenCTI platform; declare
  all its tools `case_scoped: false`, `read_only: true`,
  `data_plane.type: external_platform`.
- The OpenCTI OpenSearch user is scoped to `opencti_*` only; the SIFT worker user
  to `case-*` only; the agent gets no cluster credentials (D21). This is the
  isolation boundary - OpenCTI cannot read case evidence and case-search cannot
  read CTI.
- OpenCTI's redis/rabbitmq/minio are platform internals, exempt from the SIFT
  "No Redis/RQ" rule (which governs only SIFT durable-job authority).
- Connector-driven reference-data population (MITRE/CVE/...) is OpenCTI-managed,
  runs outside the SIFT job/worker model, and is not registered in
  `opensearch_indexes` (case-scoped). Cohabitation is by isolation, not by
  SIFT-side registration.

## 7. wintriage specifics (minimal add-on reference)

- Query-only MCP over a shipped baseline-DB package (windows services, tools,
  binaries). `case_scoped: false`, `read_only: true`,
  `data_plane.type: local_package`.
- No OpenSearch, no control-plane data dependency. It is the simplest conformant
  add-on and the best smoke test for the spec: if the manifest can express
  wintriage trivially, the contract is right.

## 8. RAG folds into core (D23) - not an add-on

RAG retrieval becomes a **core** tool backed by Supabase `pgvector`
(`rag_collections`/`rag_documents`). `forensic-rag-mcp`'s Chroma store is
migrated into the control plane; the package is retired or reduced to a thin core
retrieval path. RAG access is Gateway-mediated like all core tools; collections
may be `global` (shared knowledge) or `case`-scoped.

## 9. Decisions

### Locked
- Add-ons are query-only/read-only by default; write-capable is the declared
  exception obeying §7A (D22).
- Per-tool `case_scoped` flag; global add-on tools are audited under the active
  case (D22).
- Backend registration in the control-plane `mcp_backends` registry; portal
  managed; Gateway reads from it (D22).
- OpenSearch and RAG are core, not add-ons (D19/D23).
- OpenCTI: full platform, shared OpenSearch, scoped security roles (D20/D21).
- Single Gateway policy path; per-backend MCP routes disabled (D3).

### Open (non-blocking, decide at implementation)
- Final `sift-backend.schema.json` field names/shapes for `case_scoped` and
  `data_plane` (this doc fixes intent; JSON Schema edit is a scoped task).
- Whether `tier` values are reused as-is or extended for the control-plane
  registry.
- Exact OpenCTI OpenSearch role/index-prefix names and shard budget on the shared
  single-VM cluster (sizing task).

## 10. Migration notes

- `packages/opencti-mcp` stays a query-only API client; add `case_scoped:false` +
  `data_plane` to its manifest; ensure its OpenCTI deployment points at the shared
  OpenSearch with a scoped role.
- `packages/windows-triage-mcp` stays an add-on; add `case_scoped:false` +
  `data_plane:local_package` to its manifest.
- `packages/forensic-rag-mcp` is retired/reduced; its retrieval becomes a core
  tool over Supabase `pgvector`.
- `packages/opensearch-mcp` stops being an add-on; its read tools become core and
  its ingest/enrichment become worker-run jobs (D19).
- `packages/sift-gateway` backend registration moves from `gateway.yaml` to the
  `mcp_backends` control-plane registry; `sift-backend.schema.json` gains
  `case_scoped` and `data_plane`.
