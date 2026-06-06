# Migration Workspace

This directory is the controlled workspace for migrating SIFT toward the new architecture:

- Supabase/Postgres is the authoritative control plane.
- OpenSearch is a core derived search/data plane.
- The Gateway/Broker remains the mandatory policy boundary for operators, agents, MCP tools, and workflows.
- Native SIFT workers perform execution through durable Postgres-backed job state.

This workspace exists to keep future Codex runs narrow, resumable, and auditable. It is documentation-only for now. It must not be used to introduce schemas, code, migrations, Docker changes, or behavioral rewrites unless a future run is explicitly scoped to do that work.

## Documents

- [00_migration_charter.md](00_migration_charter.md) - target architecture, non-negotiables, out-of-scope items, and plane boundaries.
- [MIGRATION_STATE.md](MIGRATION_STATE.md) - short handoff state that every future migration run must read and update.
- [01_repo_inventory.md](01_repo_inventory.md) - current-state repository inventory from the first inspection-only run.
- [02_authoritative_domains_and_boundaries.md](02_authoritative_domains_and_boundaries.md) - target authoritative domains, trust boundaries, and compatibility mapping from current file-based authority into Supabase/Postgres.
- [03_opensearch_core_integration.md](03_opensearch_core_integration.md) - OpenSearch integration as a core SIFT MCP/search data-plane service with control-plane-aware indexing and Gateway-mediated query boundaries.
- [04_execution_current_state.md](04_execution_current_state.md) - current execution, parser/ingest, evidence/audit, and workflow/status inventory grounded in repository evidence.
- [05_execution_job_model.md](05_execution_job_model.md) - target Postgres-backed durable job model for execution lifecycle, worker claiming, steps/logs, parser/indexing lineage, idempotency, worker assumptions, and degraded behavior.
- [06_execution_integration_contracts.md](06_execution_integration_contracts.md) - REST, MCP, frontend, OpenSearch, evidence, audit, approval, worker, and degraded-mode integration contracts for the DB-backed execution/job model.
- [07_execution_roadmap.md](07_execution_roadmap.md) - practical execution/jobs migration roadmap, phased work plan, first PR plan, testing strategy, rollback strategy, risks, and next schema-design run.
- [08_control_plane_schema.md](08_control_plane_schema.md) - practical initial Supabase/Postgres control-plane schema design for identity, authorization, evidence, audit, approvals, findings, reports, jobs, workers, parser lineage, OpenSearch indexing status, and compatibility mapping.

## Planned Documents

These are planned but intentionally not created yet:

- [04_control_plane_plan.md](04_control_plane_plan.md) - future/deferred: Supabase/Postgres control-plane model and migration sequencing.
- [05_gateway_token_policy.md](05_gateway_token_policy.md) - future/deferred: Gateway authorization, MCP/service-token registry, scopes, expiry, revocation, and hashing rules.
- [06_evidence_audit_migration.md](06_evidence_audit_migration.md) - future/deferred: evidence vault, immutable raw evidence, audit events, approvals, and proof/export preservation.
- [09_first_pr_candidate.md](09_first_pr_candidate.md) - future/deferred: first implementation PR candidate focused on baseline execution smoke-test fixtures and lightweight tests.
- [10_test_acceptance_plan.md](10_test_acceptance_plan.md) - future/deferred: migration tests, security gates, and acceptance scenarios.
- [99_migration_roadmap.md](99_migration_roadmap.md) - future/deferred: full roadmap, deliberately postponed until the repo inventory and focused subsystem plans exist.

## Future Codex Run Protocol

Every future migration run should:

1. Read [MIGRATION_STATE.md](MIGRATION_STATE.md) first.
2. Read [00_migration_charter.md](00_migration_charter.md) before making architectural claims.
3. Inspect only the files needed for the requested subsystem.
4. Avoid implementation, schema, generated files, package changes, Docker changes, and broad rewrites unless the user explicitly scopes the run to those changes.
5. Keep new docs focused on the current run's objective.
6. Update [MIGRATION_STATE.md](MIGRATION_STATE.md) at the end with files inspected, decisions, open questions, and the next recommended run.

The next recommended run is to create [09_first_pr_candidate.md](09_first_pr_candidate.md), focused only on the first implementation PR candidate for baseline execution smoke-test fixtures and lightweight tests.
