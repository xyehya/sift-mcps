# Migration Workspace

This directory is the controlled workspace for migrating SIFT toward the new architecture:

- Supabase/Postgres is the authoritative control plane.
- OpenSearch is a core derived search/data plane.
- The Gateway/Broker remains the mandatory policy boundary for operators, agents, MCP tools, and workflows.
- Native SIFT workers perform execution through durable Postgres-backed job state.

This workspace exists to keep future Codex runs narrow, resumable, and auditable. It is documentation-only for now. It must not be used to introduce schemas, code, migrations, Docker changes, or behavioral rewrites unless a future run is explicitly scoped to do that work.

All locked decisions live in [00_migration_charter.md](00_migration_charter.md) under "Confirmed Decisions (Locked)". If any other document conflicts with the charter, the charter wins and the other document must be corrected.

## Documents

- [Architecture.mmd](Architecture.mmd) - target architecture diagram (overview, not a binding spec).
- [00_migration_charter.md](00_migration_charter.md) - target architecture, non-negotiables, **Confirmed Decisions (Locked)**, cutover order, and plane boundaries.
- [MIGRATION_STATE.md](MIGRATION_STATE.md) - short handoff state that every future migration run must read and update.
- [01_repo_inventory.md](01_repo_inventory.md) - current-state repository inventory from the first inspection-only run.
- [02_authoritative_domains_and_boundaries.md](02_authoritative_domains_and_boundaries.md) - target authoritative domains, trust boundaries, and compatibility mapping from current file-based authority into Supabase/Postgres.
- [03_opensearch_core_integration.md](03_opensearch_core_integration.md) - OpenSearch integration as a core SIFT MCP/search data-plane service with control-plane-aware indexing and Gateway-mediated query boundaries.
- [04_execution_current_state.md](04_execution_current_state.md) - current execution, parser/ingest, evidence/audit, and workflow/status inventory grounded in repository evidence.
- [05_execution_job_model.md](05_execution_job_model.md) - target Postgres-backed durable job model for execution lifecycle, worker claiming, steps/logs, parser/indexing lineage, idempotency, worker assumptions, and degraded behavior.
- [06_execution_integration_contracts.md](06_execution_integration_contracts.md) - REST, MCP, frontend, OpenSearch, evidence, audit, approval, worker, and degraded-mode integration contracts for the DB-backed execution/job model.
- [07_execution_roadmap.md](07_execution_roadmap.md) - practical execution/jobs migration roadmap, phased work plan, first PR plan, testing strategy, rollback strategy, and risks.
- [08_control_plane_schema.md](08_control_plane_schema.md) - practical initial Supabase/Postgres control-plane schema design for identity, authorization, evidence, audit, approvals, findings, TODOs, IOCs, reports, jobs, workers, parser lineage, OpenSearch indexing status, RAG/skills, and compatibility mapping.
- [09_identity_auth_cutover.md](09_identity_auth_cutover.md) - the foundation track (cutover order step 1): Supabase Auth, operator profiles, case membership, active-case state, the hash-only MCP/service-token registry, and Gateway propagation. This precedes evidence/jobs/findings work.
- [10_addon_backend_spec.md](10_addon_backend_spec.md) - target MCP add-on backend contract: core vs add-on, per-tool `case_scoped`, `data_plane` declaration, query-only-by-default with the write-capable exception, the control-plane `mcp_backends` registry, and the OpenCTI/wintriage/RAG reference backends.

## Document Numbering Note

Documents `04`-`06` are the **execution** track
(`04_execution_current_state`, `05_execution_job_model`,
`06_execution_integration_contracts`). Earlier drafts of this README reserved
`04`/`05`/`06` for control-plane/token/evidence topics; that numbering was
superseded. Those topics now live in `02`, `08`, and `09`. Do not recreate
`04_control_plane_plan.md`, `05_gateway_token_policy.md`, or
`06_evidence_audit_migration.md` - they would collide with existing files.

## Planned Documents

These are planned but intentionally not created yet:

- `11_first_pr_candidate.md` - future: first implementation PR candidate (roadmap phase JOB-0 baseline smoke tests), planned only when a session is scoped to it.
- `12_test_acceptance_plan.md` - future: migration tests, security gates, and acceptance scenarios.

## Future Codex Run Protocol

Every future migration run should:

1. Read [MIGRATION_STATE.md](MIGRATION_STATE.md) first.
2. Read [00_migration_charter.md](00_migration_charter.md), especially "Confirmed Decisions (Locked)" and "Cutover Order", before making architectural claims.
3. Inspect only the files needed for the requested subsystem.
4. Avoid implementation, schema, generated files, package changes, Docker changes, and broad rewrites unless the user explicitly scopes the run to those changes.
5. Keep new docs focused on the current run's objective.
6. Update [MIGRATION_STATE.md](MIGRATION_STATE.md) at the end with files inspected, decisions, open questions, and the next recommended run.

The next recommended run is the first implementation PR candidate planning
(`11_first_pr_candidate.md`), focused only on roadmap phase JOB-0 baseline
execution smoke-test fixtures and lightweight tests. The first feature-bearing
implementation then follows the cutover order, starting with the
cases/tokens/identity foundation in
[09_identity_auth_cutover.md](09_identity_auth_cutover.md).
