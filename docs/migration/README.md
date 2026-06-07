# Migration Workspace

This directory is the controlled workspace for migrating SIFT toward the new architecture:

- Supabase/Postgres is the authoritative control plane.
- OpenSearch is a core derived search/data plane.
- The Gateway/Broker remains the mandatory policy boundary for operators, agents, MCP tools, and workflows.
- Native SIFT workers perform execution through durable Postgres-backed job state.

This workspace exists to keep future Codex runs narrow, resumable, and auditable.
Files under `docs/migration/` are the governance/documentation control plane for
the migration. Runtime code, schemas, Docker changes, and behavioral rewrites
happen only through separately scoped runs that update these docs as part of
their Definition of Done.

All locked decisions live in [00_migration_charter.md](00_migration_charter.md) under "Confirmed Decisions (Locked)". If any other document conflicts with the charter, the charter wins and the other document must be corrected.

## Documents

- [Architecture.mmd](Architecture.mmd) - target architecture diagram (overview, not a binding spec).
- [00_migration_charter.md](00_migration_charter.md) - target architecture, non-negotiables, **Confirmed Decisions (Locked)**, cutover order, and plane boundaries.
- [OPERATING_MODEL.md](OPERATING_MODEL.md) - **process of record (D29)**: the Plan→Build→Review→Land→Log loop, Definition of Done, branch/worktree governance, and templates. Every run follows it.
- [REGISTER.md](REGISTER.md) - open-items register: Forks (F#) awaiting a call and Backlog (B#) deferred work.
- [MIGRATION_STATE.md](MIGRATION_STATE.md) - short handoff state that every future migration run must read and update.
- [01_repo_inventory.md](01_repo_inventory.md) - current-state repository inventory from the first inspection-only run.
- [02_authoritative_domains_and_boundaries.md](02_authoritative_domains_and_boundaries.md) - target authoritative domains, trust boundaries, and compatibility mapping from current file-based authority into Supabase/Postgres.
- [03_opensearch_core_integration.md](03_opensearch_core_integration.md) - OpenSearch integration as a core SIFT MCP/search data-plane service with control-plane-aware indexing and Gateway-mediated query boundaries.
- [04_execution_current_state.md](04_execution_current_state.md) - current execution, parser/ingest, evidence/audit, and workflow/status inventory grounded in repository evidence.
- [05_execution_job_model.md](05_execution_job_model.md) - target Postgres-backed durable job model for execution lifecycle, worker claiming, steps/logs, parser/indexing lineage, idempotency, worker assumptions, and degraded behavior.
- [06_execution_integration_contracts.md](06_execution_integration_contracts.md) - REST, MCP, frontend, OpenSearch, evidence, audit, approval, worker, and degraded-mode integration contracts for the DB-backed execution/job model.
- [07_execution_roadmap.md](07_execution_roadmap.md) - practical execution/jobs migration roadmap, phased work plan, first PR plan, testing strategy, rollback strategy, and risks.
- [08_control_plane_schema.md](08_control_plane_schema.md) - practical initial Supabase/Postgres control-plane schema design for identity, authorization, evidence, audit, approvals, findings, TODOs, IOCs, reports, jobs, workers, parser lineage, OpenSearch indexing status, RAG/skills, and compatibility mapping.
- [09_identity_auth_cutover.md](09_identity_auth_cutover.md) - the foundation track (cutover order step 1): Supabase JWT auth, operator/agent/service principal mapping, case membership, active-case state, transitional token-registry compatibility, and Gateway propagation. This precedes evidence/jobs/findings work.
- [10_addon_backend_spec.md](10_addon_backend_spec.md) - target MCP add-on backend contract: core vs add-on, per-tool `case_scoped`, `data_plane` declaration, query-only-by-default with the write-capable exception, the control-plane `mcp_backends` registry, and the OpenCTI/wintriage/RAG reference backends.
- [11_first_pr_candidate.md](11_first_pr_candidate.md) - first implementation PR candidate: roadmap phase JOB-0 baseline execution smoke tests/fixtures and a small runbook, with no runtime behavior change.
- [12_pr01.md](12_pr01.md) - PR01 implementation candidate: Phase ID-1 control-plane identity foundation schema, schema tests, and runbook only.
- [13_pr02.md](13_pr02.md) - PR02 implementation candidate: Phase ID-2 DB-first hash-only MCP/service token validation with legacy `gateway.yaml` fallback.
- [14_fastmcp3_supabase_integration.md](14_fastmcp3_supabase_integration.md) - FastMCP 3.0 + Supabase + FastAPI consolidation knowledge base and target design (decisions D24-D27): providers/transforms substrate, one ASGI app, own Supabase-JWT verification (FastAPI DI), code-mode excluded. Governs the **gateway cutover (D27b)**.
- [15_backend_tooling_revamp.md](15_backend_tooling_revamp.md) - backend tooling revamp spec and drift-control contract (decisions D27a/D27b/D28): migrate opensearch/opencti/windows-triage to FastMCP 3.0 **and** redesign every tool to the quality contract (typed Pydantic in/out, prompts, resources, annotations). Dedicated worktree, parallel to PR02, exposure-agnostic authoring, rename change-map.
- [16_backend_tool_contracts.md](16_backend_tool_contracts.md) - per-tool D28 contracts for all 30 backend tools (16 opensearch / 8 opencti / 6 wintriage), grounded in current `server.py` I/O: typed Pydantic input/output models, full annotations, result shaping/caps, typed error model, ≥1 prompt + ≥1 resource per backend, consolidated rename change-map, and the flagged tool-vs-resource reclassification + write-tool forks. Implements doc 15 §5/§7/§10.
- [17_gateway_cutover_d27b.md](17_gateway_cutover_d27b.md) - implemented **D27b gateway cutover** candidate/log: re-hosted the SIFT policy (evidence gate / response guard / case context / audit envelope) as FastMCP 3.0 Middleware, swapped aggregation to local core tools + proxy-mounted add-ons, implemented the **B-3** structured-content redaction design, and removed per-backend `/mcp/{name}` routes. Grounded in the gateway source + the pinned fastmcp 3.4.2 API. Implements the design in doc 14.
- [18_target_architecture_acceleration.md](18_target_architecture_acceleration.md) - final target-state architecture reference and acceleration batching plan: Supabase JWT principal model for REST/MCP, Gateway policy boundary, data places/enforcers, security zones, file-authority sunset map, missing inputs, and parallel batch plan.
- [JOB0_baseline_execution_checks.md](JOB0_baseline_execution_checks.md) - targeted commands and no-service assumptions for the additive JOB-0 baseline smoke tests.
- [PR01_identity_schema_checks.md](PR01_identity_schema_checks.md) - commands for running the deterministic PR01 schema checks and optional Supabase syntax validation.

## Document Numbering Note

Documents `04`-`06` are the **execution** track
(`04_execution_current_state`, `05_execution_job_model`,
`06_execution_integration_contracts`). Earlier drafts of this README reserved
`04`/`05`/`06` for control-plane/token/evidence topics; that numbering was
superseded. Those topics now live in `02`, `08`, and `09`. Do not recreate
`04_control_plane_plan.md`, `05_gateway_token_policy.md`, or
`06_evidence_audit_migration.md` - they would collide with existing files.

## Future Codex Run Protocol

Every future migration run should:

1. Read [MIGRATION_STATE.md](MIGRATION_STATE.md) first.
2. Read [00_migration_charter.md](00_migration_charter.md), especially "Confirmed Decisions (Locked)" and "Cutover Order", before making architectural claims.
3. Inspect only the files needed for the requested subsystem.
4. Avoid implementation, schema, generated files, package changes, Docker changes, and broad rewrites unless the user explicitly scopes the run to those changes.
5. Keep new docs focused on the current run's objective.
6. Update [MIGRATION_STATE.md](MIGRATION_STATE.md) at the end with files inspected, decisions, open questions, and the next recommended run.

JOB-0, PR01 / Phase ID-1, PR02 / Phase ID-2, D27a, and D27b are done. The next
recommended run is a **Plan-stage PR03A / Batch A** candidate from
[18_target_architecture_acceleration.md](18_target_architecture_acceleration.md)
and [09_identity_auth_cutover.md](09_identity_auth_cutover.md): unified
Supabase JWT authentication for REST and FastMCP `/mcp`, plus
operator/agent/service principal and membership resolution behind the legacy-auth
flag. Keep D22/F-11 (`mcp_backends` control-plane registry) and ID-4/ID-5
active-case propagation separate unless a candidate doc explicitly batches them.
