# Migration Charter

## Target Architecture

The target architecture is a SIFT VM Autonomous DFIR Agent system with four clear boundaries:

- Presentation layer: React + Vite operator portal for case lifecycle, findings, timeline, evidence integrity, and MCP token management.
- Gateway/Broker layer: Starlette + FastAPI + FastMCP for REST, WebSocket/SSE where needed, MCP tool mediation, authentication, authorization, audit, and policy enforcement.
- Case control plane: Supabase Local/Postgres as the authoritative store for case and workflow state.
- Execution and data planes: SIFT VM workers execute durable jobs from Postgres, while OpenSearch stores derived searchable artifacts, timelines, IOCs, full-text data, and vector-search data.

AI agents and MCP clients interact only through case-scoped MCP tools exposed by the Gateway. They must not bypass Gateway policy, Postgres authorization, evidence controls, or approval gates.

## Plane Boundaries

### Control Plane

Supabase/Postgres is authoritative for:

- Cases, case lifecycle, and case permissions.
- Human operator authorization state through Supabase Auth and RLS.
- MCP/service-token registry state.
- Durable jobs and pipeline state.
- Audit events.
- Evidence metadata, evidence status, and evidence verification state.
- Findings, timeline items, IOCs, TODOs, approvals, and review state.

Current JSON/file-based state should migrate gradually into this control plane and must not remain the long-term authority.

### Data Plane

OpenSearch is a core integrated data plane for derived investigative data:

- Parsed artifacts.
- Timeline/search indexes.
- IOC search and enrichment views.
- Full-text search.
- Vector search.

OpenSearch must not become authoritative for case permissions, token validity, durable job ownership, evidence integrity, approvals, or final finding state. It is a query and retrieval plane fed by controlled ingestion and parser workflows.

### Execution Plane

The execution plane is the SIFT VM worker runtime:

- Workers claim durable jobs from Postgres.
- Workers run Python parsers and native Linux/SIFT workflows.
- Workers perform ingestion, parsing, normalization, indexing, and report generation.
- Workers write status, logs, proposed findings, audit updates, and job completion through authorized control-plane paths.

There is no Redis/RQ job authority. Durable job state must go through Postgres/Supabase.

### Gateway/Broker Layer

The Gateway/Broker remains Starlette + FastAPI + FastMCP and is the mandatory policy boundary:

- Operator actions enter through REST/API surfaces.
- Agent actions enter through MCP tool calls.
- Gateway enforces authentication, authorization, case scope, tool scope, evidence policy, audit policy, and response policy.
- Gateway mediates access to Postgres, OpenSearch, evidence controls, and execution workflows.

## Non-Negotiable Rules

- Supabase/Postgres is the authoritative control plane.
- OpenSearch is a core integrated search/data plane, not an optional standalone MCP backend in the long-term architecture.
- Existing evidence vault and audit functionality must be preserved and integrated through control-plane capabilities.
- Current JSON/file-based state migrates gradually and must not remain the long-term authority.
- No Redis/RQ.
- Durable job state must go through Postgres/Supabase.
- Gateway/Broker remains Starlette + FastAPI + FastMCP.
- AI agents interact through case-scoped MCP tools and must not bypass Gateway policy or Postgres authorization.
- MCP tokens are case-scoped, tool-scoped, expiring, revocable, and stored only as hashes.
- Human operators authenticate through Supabase Auth and RLS.
- AI agents, MCP clients, workers, and backend services use Gateway-issued service/MCP tokens validated against the Postgres token registry.
- Raw evidence remains immutable.
- Agent-generated findings are proposed or draft state until human approval.
- Agent-generated findings must not be auto-approved.
- OpenSearch-derived results must be traceable to registered evidence and auditable ingestion/parsing activity.

## Out Of Scope For This Workspace Step

- Full migration roadmap.
- Database schema design.
- Supabase migrations.
- Code implementation.
- Runtime behavior changes.
- Token implementation or token format changes.
- OpenSearch refactor.
- Evidence or audit data migration.
- Docker or installer changes.
- Rewriting existing functionality.
- Changing tests or test expectations.
