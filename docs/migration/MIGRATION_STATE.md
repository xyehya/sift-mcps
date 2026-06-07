# Migration State

## Current Objective

Run 14 implemented PR01 Phase ID-1, installed a pinned self-hosted Supabase
stack on the SIFT VM for migration testing, created the root `AGENTS.md`
handoff/invariant file, and drafted `docs/migration/13_pr02.md`, the next
implementation PR candidate for Phase ID-2: DB-first hash-only MCP/service token
registry validation with legacy `gateway.yaml` fallback.

JOB-0 is complete in commit `c73762c`:
**Add JOB-0 execution baseline smoke tests**. The committed work added
deterministic baseline tests for current evidence, audit, OpenSearch
index/provenance, and ingest-status behavior, plus
`docs/migration/JOB0_baseline_execution_checks.md`. Runtime behavior was not
changed.

PR01 is implemented in the current worktree but not committed unless a later run
commits it. It added the conventional Supabase migration layout, deterministic
schema tests, and a PR01 schema-check runbook. Runtime behavior was not changed.

The workspace is now handoff-ready for PR02 planning/implementation. The next
recommended feature-bearing PR is **Phase ID-2: token hash registry
dual-validation** from `09_identity_auth_cutover.md`. PR02 should use the PR01
schema to validate MCP/service tokens against `app.mcp_tokens` first, with
legacy `gateway.yaml api_keys` fallback. It must not add Supabase human auth,
portal login replacement, active-case propagation, evidence gate changes, job
tables, workers, REST job APIs, MCP job tools, OpenSearch changes, parser
changes, evidence behavior changes, audit data migration, frontend redesigns, or
legacy fallback removal.

Current worktree note: `.DS_Store` was already modified and remains unrelated.
PR01 implementation files, `AGENTS.md`, and `docs/migration/13_pr02.md` are
uncommitted unless a later run commits them.

## Run 14 - PR01 Implementation, Supabase VM Setup, AGENTS.md, And PR02 Planning

Created:

- `supabase/migrations/202606070101_identity_foundation.sql` - additive PR01
  `app` schema foundation tables for operator profiles, cases, case members,
  active-case state, agents, service identities, MCP tokens, token scopes, and
  audit events.
- `tests/db/test_pr01_identity_schema.py` - deterministic SQL structure tests
  for the PR01 schema.
- `docs/migration/PR01_identity_schema_checks.md` - PR01 schema-check runbook.
- `AGENTS.md` - root handoff instructions with host/VM workflow, Python/uv
  invariants, Supabase VM setup, PR01 files, PR02 pointer, and installer
  follow-up note.
- `docs/migration/13_pr02.md` - PR02 implementation candidate for Phase ID-2
  hash-only MCP/service token validation with legacy fallback.

Updated:

- `docs/migration/README.md` - linked PR01 and PR02 docs/runbooks.
- `docs/migration/MIGRATION_STATE.md` - this handoff update.

SIFT VM setup completed:

- VM: `192.168.122.81`, user `sansforensics`.
- Supabase installed manually at `/home/sansforensics/supabase-project`.
- Source sparse clone at `/home/sansforensics/supabase-src-v1.26.05`.
- Supabase pinned tag: `v1.26.05`.
- Supabase pinned commit: `23b55d63485e51919d1b4c05b03d33a9edc1f06d`.
- Supabase public/API URL configured as `http://192.168.122.81:8000`.
- Secrets generated with pinned Supabase helper scripts
  `utils/generate-keys.sh` and `utils/add-new-auth-keys.sh`.
- Pinned Docker layout had no `run.sh`; used `docker compose up -d --wait`.
- Stack health checked through `docker compose ps`, JWKS, REST `401`, and
  Postgres `select version()`.
- Installed Ubuntu `nodejs` package because Supabase's pinned
  `add-new-auth-keys.sh` requires Node >= 16.

Files inspected in this run:

- `docs/migration/12_pr01.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/09_identity_auth_cutover.md`
- `docs/migration/08_control_plane_schema.md`
- `docs/migration/README.md`
- `docs/migration/MIGRATION_STATE.md`
- Root `pyproject.toml`
- Narrow file discovery for existing Supabase/migration/schema/test layout.

Verification run on host with `.venv`:

- `.venv/bin/python -m pytest tests/db/test_pr01_identity_schema.py`
  - 5 passed.
- `.venv/bin/python -m pytest tests/db`
  - 5 passed.
- `git diff --check`
  - clean.

Verification run on SIFT VM after rsync to `~/sift-mcps-test`:

- `.venv/bin/python --version`
  - Python 3.12.3.
- Post-sync import smoke for `yaml`, `mcp`, `sift_core`, and `sift_gateway`
  - passed.
- `.venv/bin/python -m pytest tests/db/test_pr01_identity_schema.py`
  - 5 passed.
- `.venv/bin/python -m pytest tests/db`
  - 5 passed.
- PR01 migration SQL applied to Supabase Postgres inside `BEGIN`/`ROLLBACK`
  with `ON_ERROR_STOP=1`
  - passed.

Deviations and notes:

- No existing Supabase migration/test harness existed before PR01, so PR01 used
  deterministic SQL-inspection tests plus an optional live Supabase rollback
  syntax check.
- The SIFT VM `.python-version` file in the synced repo says `3.11`, but VM
  testing must force `/usr/bin/python3.12` per the project invariant.
- A broad `uv sync --all-packages` started pulling large optional GPU/ML
  packages and was stopped; `uv cache prune` recovered about 3.2 GiB. Use the
  narrower `uv sync --extra core --group dev --python /usr/bin/python3.12` for
  Gateway/portal/schema work unless a task really needs all packages.
- Supabase docs mention `run.sh`, but the pinned `v1.26.05` Docker layout does
  not include it; use `docker compose`.
- The root `.DS_Store` modification was pre-existing and intentionally left
  untouched.

Next recommended run:

- Review and commit the current PR01/docs work if desired.
- Implement PR02 as described in `docs/migration/13_pr02.md`.
- Read `AGENTS.md` and `docs/migration/13_pr02.md` first.
- Inspect only the files listed in PR02 section 4.
- Use the host repo as source and test on the SIFT VM after rsync.
- Use `/usr/bin/python3.12` on the VM and set `UV_NO_MANAGED_PYTHON=1` and
  `UV_PYTHON_DOWNLOADS=never` for `uv sync`.
- Run targeted token/auth tests, touched auth/token suites if practical,
  optional rollback-safe Supabase checks, and `git diff --check`.
  Stop and summarize changed files, tests run, and deviations.

## Run 13 - JOB-0 Implementation Commit And PR01 Planning

Committed:

- `c73762c Add JOB-0 execution baseline smoke tests`

JOB-0 files committed:

- `packages/sift-core/tests/test_core_execution_baseline_smoke.py` - evidence
  seal/status and audit JSONL append baseline tests using temp paths.
- `packages/opensearch-mcp/tests/test_opensearch_execution_baseline_smoke.py` -
  OpenSearch index/provenance action-shape and ingest-status metadata tests
  without live OpenSearch.
- `docs/migration/JOB0_baseline_execution_checks.md` - `.venv`-based runbook for
  targeted JOB-0 baseline checks and touched package suites.
- `docs/migration/README.md` - link to the JOB-0 runbook.

Created after the commit:

- `docs/migration/12_pr01.md` - PR01 implementation candidate, replicating the
  structure of `11_first_pr_candidate.md`, for Phase ID-1 identity foundation
  schema only.

Files inspected in this run:

- `docs/migration/11_first_pr_candidate.md`
- `docs/migration/README.md`
- `packages/sift-core/pyproject.toml`
- `packages/sift-common/pyproject.toml`
- `packages/opensearch-mcp/pyproject.toml`
- `packages/sift-core/src/sift_core/evidence_chain.py`
- `packages/sift-common/src/sift_common/audit.py`
- `packages/opensearch-mcp/src/opensearch_mcp/paths.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_json.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`
- Existing adjacent tests under `packages/sift-core/tests/` and
  `packages/opensearch-mcp/tests/` listed in doc 11 as needed.
- `docs/migration/00_migration_charter.md`
- `docs/migration/08_control_plane_schema.md`
- `docs/migration/09_identity_auth_cutover.md`

Verification run with `.venv`:

- `PYTHONPATH=packages/sift-core/src:packages/sift-common/src .venv/bin/python -m pytest packages/sift-core/tests/test_core_execution_baseline_smoke.py`
  - 2 passed.
- `PYTHONPATH=packages/opensearch-mcp/src:packages/opensearch-mcp/tests:packages/sift-core/src:packages/sift-common/src .venv/bin/python -m pytest packages/opensearch-mcp/tests/test_opensearch_execution_baseline_smoke.py`
  - 2 passed.
- `PYTHONPATH=packages/opensearch-mcp/src:packages/opensearch-mcp/tests:packages/sift-core/src:packages/sift-common/src .venv/bin/python -m pytest --import-mode=importlib packages/sift-core/tests/test_core_execution_baseline_smoke.py packages/opensearch-mcp/tests/test_opensearch_execution_baseline_smoke.py`
  - 4 passed.
- `PYTHONPATH=packages/sift-core/src:packages/sift-common/src .venv/bin/python -m pytest packages/sift-core/tests`
  - 328 passed.
- `PYTHONPATH=packages/opensearch-mcp/src:packages/opensearch-mcp/tests:packages/sift-core/src:packages/sift-common/src .venv/bin/python -m pytest packages/opensearch-mcp/tests`
  - 975 passed, 71 skipped.
- `git diff --check`
  - clean.

Deviations and notes:

- JOB-0 test files use package-specific filenames to avoid pytest module-name
  collisions when both package test paths are collected together.
- The audit baseline asserts current JSONL append/shape behavior only. It does
  not assert secret redaction because current `AuditWriter` writes `params` as
  supplied; changing that would be runtime behavior.
- The runbook uses `.venv/bin/python` per the repository environment.
- `docs/migration/12_pr01.md` is planning-only and not part of commit `c73762c`.

Next recommended run:

- Commit `docs/migration/12_pr01.md` if the PR01 candidate should be preserved
  before implementation.
- Then implement PR01 as described in `docs/migration/12_pr01.md`.
- Inspect only the files listed in that document's repository discovery section.
- Add the Phase ID-1 control-plane identity schema, deterministic schema tests,
  and a short PR01 schema-check runbook.
- Use `.venv` for Python test commands.
- Run targeted schema tests, the touched schema suite if practical, and
  `git diff --check`.
- Stop and summarize changed files, tests run, and deviations.

## Run 12 - First PR Candidate Planning (JOB-0)

Created:

- `docs/migration/11_first_pr_candidate.md` - concrete first implementation PR
  candidate for JOB-0 baseline execution smoke tests/fixtures/docs.

Updated:

- `docs/migration/MIGRATION_STATE.md` - current handoff state for the next run.
- `docs/migration/README.md` - moved doc 11 from "Planned Documents" to
  "Documents" and updated the next recommended run.

Files inspected in this run:

- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/04_execution_current_state.md`
- `docs/migration/07_execution_roadmap.md`
- `docs/migration/08_control_plane_schema.md`
- `docs/migration/09_identity_auth_cutover.md` (skimmed for cutover order)
- `docs/migration/README.md`

Narrow repository path discovery was also run to identify existing package
manifests and test directories. No production modules were opened.

First PR decision:

- First implementation PR is JOB-0 only.
- Scope is test/fixture/docs focused.
- No runtime behavior change.
- No schema migrations.
- No Supabase/Postgres dependency.
- No worker/job implementation.
- No frontend/MCP/REST/OpenSearch refactor.

Open questions for the JOB-0 coding run:

- Exact package test commands and dependency runner.
- Whether new smoke tests should live in new files or extend existing package
  tests.
- Exact `AuditWriter.log` JSONL field names to assert.
- Exact `build_index_name()` sanitization output for mixed-case and symbol-rich
  inputs.
- The smallest parser path that exposes provenance/action shaping without a
  live OpenSearch instance.
- Whether ingest-status or ingest-manifest smoke coverage is cheaper and safer
  than parser-output smoke coverage.

Next recommended run:

- Implement the JOB-0 coding PR described in
  `docs/migration/11_first_pr_candidate.md`.
- Inspect only the files listed in that document's repository discovery section.
- Add 2-4 deterministic baseline smoke tests/fixtures and a short runbook.
- Run targeted tests and `git diff --check`.
- Stop and summarize changed files, tests run, and deviations.

## Run 9 - Locked Decisions And Reconciliation

User-confirmed decisions captured this run (full list in the charter):

- D2/D3: Gateway is the single boundary; ALL REST APIs, MCP tools, and actions
  go through it; per-backend `/mcp/{name}` routes are disabled (early hardening).
- D4: active case is portal-set, authoritative in `active_case_state`, propagated
  by the Gateway; `SIFT_CASE_DIR`/`~/.sift/active_case` become generated
  compatibility exports; one active case per SIFT VM in v1. Current
  active-case behavior preserved, authority moved to the control plane.
- D5: long-running tool calls enqueue durable control-plane jobs/pipelines and
  return a job ID; never a direct job/invoke to the Evidence Vault; workers
  CLAIM (poll + SKIP LOCKED), control plane never pushes. (Fixed the diagram's
  Gateway->Evidence job arrow and the push-vs-pull arrow.)
- D6: OpenSearch 3.5.0 with security enabled is canonical; root repo
  `docker-compose.yml` (2.18.0, security off) is pre-migration only.
- D7: local Supabase on the network-restricted (non-air-gapped) SIFT VM.
- D8: hash-only token registry, SHA-256 + server pepper, 16-hex fingerprint,
  default expiries, one-time raw display, dual-validate then sunset legacy.
- D9: single local worker in v1.
- D10/D11: UUID PKs + legacy text keys; `app`+`internal` schemas (not `public`).
- D12: privileged writes via Gateway/worker service paths; RLS = defense-in-depth
  behind the Gateway; browser never talks to a backend/OpenSearch directly.
- D13: lean job core (`jobs`, `job_steps`, `job_logs`, `workers`); defer
  `job_attempts`/`job_cancellations`/`worker_heartbeats`.
- D14: retain Solana anchoring, TODOs, IOCs as first-class (added tables + job
  type `evidence_anchor`).
- D15: centralize RAG and add retrievable agent skills into the control plane
  (added `rag_collections`/`rag_documents`/`agent_skills`).
- D16: evidence dedup never silently drops forensically distinct acquisitions.
- D17: cutover order = cases/tokens/identity first.

Files changed/created in Run 9:

- `docs/migration/Architecture.mmd` (rewritten/corrected).
- `docs/migration/00_migration_charter.md` (locked decisions + cutover order).
- `docs/migration/README.md` (numbering fix + doc set).
- `docs/migration/09_identity_auth_cutover.md` (new foundation track).
- `docs/migration/08_control_plane_schema.md` (lean job core; +`active_case_state`,
  `case_todos`, `iocs`, `evidence_anchors`, `rag_collections`, `rag_documents`,
  `agent_skills`; locked decisions; resolved open questions).
- `docs/migration/02`,`03`,`05`,`06`,`07` (locked-decision banners + resolved
  open-question sections).

## Run 10 - Active-case refinement + OpenSearch write contract (D18)

After a code scan of `packages/opensearch-mcp/`, two refinements were locked:

- D4 refined: **one operator, one active case at a time**; other cases may exist
  but only one is active.
- D18 added: **reuse the existing working OpenSearch ingestion model** - index
  naming `case-{case}-{type}-{host}` via `build_index_name()`, template
  auto-create, shared `flush_bulk` writer, host auto-discovery preflight, and
  `vhir.*`/`host.*`/`pipeline_version` provenance. The control plane *registers*
  these indices in `opensearch_indexes` rather than renaming them; the
  `dfir-case-*-vN` logical-family rename is deferred/optional. A single **write
  contract** (`03` §7A) governs every writer - core worker, addon MCP backend
  (future OpenCTI/Hayabusa enrichment), and enrichment - additively and without
  refactoring working backends: take `case_id` from job/active-case context, name
  via the helper, stamp provenance + control-plane IDs, reuse `flush_bulk`,
  register index/batch, scope `update_by_query` to the case. Gateway-only governs
  the tool/query boundary; execution-plane bulk writes run directly under an
  authorized job.

Code facts confirmed this run: only `opensearch-mcp` writes to OpenSearch today
(OpenCTI/windows-triage/forensic-mcp/forensic-rag do not); enrichers mutate
existing `case-*` docs via `update_by_query`; indices are created implicitly on
first bulk write through installed `case-*-{type}-*` templates.

Files changed in Run 10: `00_migration_charter.md` (D4 refined, D18 added),
`03_opensearch_core_integration.md` (banner + §6 reuse + new §7A write contract +
§13 reconcile), `08_control_plane_schema.md` (`opensearch_indexes` cell + §15).

## Run 11 - MCP backends + OpenSearch core + OpenCTI cohabitation (D19-D23)

User-confirmed decisions this run (full text in the charter):

- D19: **OpenSearch is core, not an add-on.** Read tools = in-process core MCP
  tools (sync); ingest/enrichment = core tools that enqueue worker jobs.
  Standalone server + OpenSearch add-on manifest registration retired; the
  `opensearch-mcp` package remains as the in-process implementation.
- D20: **OpenCTI = full platform** (platform, worker, redis, rabbitmq, minio)
  sharing the **existing SIFT OpenSearch** as its index store (not a 2nd
  cluster). `opencti-mcp` stays query-only. OpenCTI's internal redis/rabbitmq/
  minio are exempt from "No Redis/RQ" (which governs SIFT job authority only).
  (User has tested the full-wiring implementation against case evidence.)
- D21: **Cluster cohabitation + scoped security roles.** Two index classes:
  `case-*` (SIFT) and `opencti_*` (OpenCTI). Per-consumer roles: worker->`case-*`,
  OpenCTI->`opencti_*`, **agent->no cluster creds**. Capacity monitored for both.
- D22: **Add-on spec direction.** Query-only/read-only default; write-capable is
  the declared §7A exception. Per-tool `case_scoped` flag (opencti/wintriage =
  global, audited under active case). Backend `data_plane` declaration. Backend
  registration moves from `gateway.yaml` to a control-plane `mcp_backends`
  registry, portal-managed. Full spec: `10_addon_backend_spec.md`.
- D23: **RAG folds into core** (Supabase pgvector-backed retrieval tool), no
  longer a standalone add-on; `forensic-rag-mcp` Chroma store migrated.
  `windows-triage-mcp` stays the minimal query-only add-on reference.

Code facts confirmed: `opencti-mcp` is an API client to the OpenCTI **platform**
(not an OpenSearch client); the OpenCTI stack is heavy (redis/rabbitmq/minio/
platform/worker); current manifest requires `spec_version,name,version,tier,
transport,namespace,capabilities,tools,health` with rich per-tool metadata but
**no `case_scoped` or `data_plane`** - those are the additive gaps.

Files changed/created in Run 11: `00_migration_charter.md` (D19-D23),
`03_opensearch_core_integration.md` (new §7B: OpenSearch-core + OpenCTI
cohabitation + security roles + portal monitoring), `08_control_plane_schema.md`
(`mcp_backends` registry table; RAG core-served note), **new**
`10_addon_backend_spec.md`, `README.md` (doc 10 + planned docs renumbered to
11/12).

## Decisions Already Made

- Supabase/Postgres is the authoritative control plane.
- Human operators use Supabase Auth and RLS.
- Agents, MCP clients, workers, and backend services use Gateway-issued, case-scoped MCP/service tokens.
- MCP/service tokens are stored in the Postgres token registry as hashes only.
- Gateway validates MCP/service tokens and enforces tool scope, case scope, expiry, revocation, and policy before MCP or workflow actions.
- Postgres is authoritative for token registry state, case permissions, audit events, durable job state, evidence metadata, approval state, and workflow state.
- Immutable raw evidence and cryptographic ledger artifacts are preserved as proof/export while control-plane state moves to Postgres.
- OpenSearch is integrated through Gateway policy as a core derived search/data plane, initially by adapting existing OpenSearch code.
- OpenSearch must not become the authority for cases, tokens, jobs, evidence integrity, or approvals.
- No Redis/RQ.
- Frontend UI state is not forensic state authority.
- Agent-generated findings remain draft/proposed until human approval and are not auto-approved.
- OpenSearch query and ingest paths must be Gateway-mediated and case-scoped by token/session context.
- OpenSearch MCP tools should move into the core SIFT MCP namespace rather than remain only optional add-on tools.
- Normal agent tokens must not pass arbitrary OpenSearch index names, wildcard case patterns, or raw OpenSearch DSL.
- OpenSearch degraded mode must be explicit in Gateway health, MCP responses, frontend views, and job/indexing state.
- Compatibility with current files should be additive first; file-backed behavior is not removed before DB authority and compatibility exports are verified.
- Gateway/API/MCP creates durable job records in Postgres for long-running work.
- SIFT workers poll Postgres and atomically claim jobs using DB row-locking semantics.
- Long-running MCP tools enqueue jobs and return job IDs rather than executing inside request paths.
- OpenSearch indexing status is recorded in Postgres and OpenSearch remains a derived searchable data plane.
- Jobs are explicitly case-scoped from Gateway-validated human session or MCP/service-token context, not from `SIFT_CASE_DIR` or legacy active-case pointers.
- Retry preserves previous attempts, job steps, logs, parser runs, and indexing records.
- Cancellation is explicit and audited.
- Approval-gated work enters `waiting_human`; destructive or final actions require human approval.

## Files Created

- `docs/migration/README.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/01_repo_inventory.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/04_execution_current_state.md`
- `docs/migration/05_execution_job_model.md`
- `docs/migration/06_execution_integration_contracts.md`
- `docs/migration/07_execution_roadmap.md`
- `docs/migration/08_control_plane_schema.md`

## Files Inspected In Run 8

- No prior migration or implementation files were reread in run 8. The run used
  the already-loaded session context from the previous migration documents.

## Key Schema Decisions From Run 8

- Initial schema recommendation is a control-plane layout with Supabase Auth for
  human users, an `app` schema for core RLS-protected tables, an optional
  `internal`/`svc` schema for service-only helpers, and optional frontend-safe
  views. This namespace choice still needs user approval before migration work.
- Recommended identity model separates human `operator_profiles` from
  `agents`, `service_identities`, and hash-only `mcp_tokens`.
- Recommended case model uses UUID DB primary keys plus legacy text
  compatibility keys such as `case_key`; this needs user approval before
  migrations.
- Schema design includes initial tables for cases, memberships, agents,
  service identities, MCP token registry/scopes, evidence metadata and
  integrity, audit, approvals, findings/reviews, reports/artifacts, jobs,
  job attempts/steps/logs, workers, parser runs, parser outputs, ingest
  batches, OpenSearch index registry, indexing status, and optional document
  refs.
- Frontend users should read through RLS and safe views where appropriate, but
  privileged state mutations should go through Gateway service paths.
- MCP/agent clients should not receive direct Postgres access; they interact
  through Gateway-issued, case-scoped, tool-scoped token records.
- Worker service writes should be limited to claimed jobs and should update
  job, step, log, parser, output, ingest, indexing, and audit state.
- First schema-focused PR recommendation is migration infrastructure and schema
  verification harness if missing, not domain tables yet, because the exact
  Supabase Local deployment and migration layout remain open.
- The first overall implementation PR recommendation remains JOB-0 baseline
  execution smoke-test fixtures and lightweight tests.

## Files Inspected In Run 7

- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/04_execution_current_state.md`
- `docs/migration/05_execution_job_model.md`
- `docs/migration/06_execution_integration_contracts.md`
- `docs/migration/README.md`

No implementation code was inspected during run 7. Current repository facts in
`07_execution_roadmap.md` were carried forward from the required migration
documents.

## Key Roadmap Decisions From Run 7

- Execution migration should proceed through JOB-0 through JOB-13:
  baseline tests/fixtures, job interfaces, job schema, repository/service,
  no-op worker, REST job APIs, MCP job tools, evidence jobs, parser/ingest jobs,
  OpenSearch indexing status integration, frontend job monitoring,
  report/finding jobs, file-authority deprecation, and hardening/docs.
- The first execution-focused PR should be JOB-0 only: additive baseline
  smoke-test fixtures and lightweight tests for current execution-critical
  evidence/audit/parser/OpenSearch behavior, with no runtime behavior changes.
- The second recommended PR should add job domain interface skeletons with no
  database dependency and no runtime wiring.
- Real parser conversion should wait until baseline tests, job interfaces,
  schema, repository/service behavior, and worker claiming are tested.
- Evidence vault behavior remains protected during early conversion; evidence
  hash/verify/register jobs are the safest first real workflow conversion after
  job infrastructure exists.
- File-backed workflow/status authority should be deprecated only after DB
  authority, compatibility exports, and migrated readers are validated.
- Future implementation PRs should be narrow enough for one Codex coding
  session and should avoid broad refactors until fixtures and baseline tests
  exist.

## Files Inspected In Run 6

- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/04_execution_current_state.md`
- `docs/migration/05_execution_job_model.md`
- `docs/migration/README.md`

No implementation code was inspected during run 6. Current repository facts in
`06_execution_integration_contracts.md` were carried forward from the required
migration documents.

## Files Inspected

- Attached target architecture image from the user prompt.
- `/home/yk/.codex/attachments/037bdcf4-8981-45cc-ab65-77883484d9b1/sift_vm_dfir_exact_replica.mmd`
- `docs/README.md`
- `docs/revamp/target-architecture.mmd`
- `docs/migration/README.md`
- `docs/migration/00_migration_charter.md`
- `docs/migration/MIGRATION_STATE.md`
- `docs/migration/01_repo_inventory.md`
- `docs/migration/02_authoritative_domains_and_boundaries.md`
- `docs/migration/03_opensearch_core_integration.md`
- `docs/migration/04_execution_current_state.md`
- `docs/migration/05_execution_job_model.md`
- `pyproject.toml`
- `configs/gateway.yaml.template`
- `configs/apparmor/sift-gateway.template`
- `docker-compose.yml`
- `docker-compose.opencti.yml`
- `packages/case-dashboard/frontend/package.json`
- `packages/case-dashboard/frontend/src/App.jsx`
- `packages/case-dashboard/frontend/src/api/client.js`
- `packages/case-dashboard/frontend/src/api/endpoints.js`
- `packages/case-dashboard/frontend/src/hooks/useDataPolling.js`
- `packages/case-dashboard/frontend/src/store/useStore.js`
- `packages/case-dashboard/frontend/src/components/layout/NavRail.jsx`
- `packages/case-dashboard/frontend/src/components/evidence/EvidenceTab.jsx`
- `packages/case-dashboard/frontend/src/components/reports/ReportsTab.jsx`
- `packages/case-dashboard/frontend/src/components/settings/SettingsTab.jsx`
- `packages/case-dashboard/src/case_dashboard/auth.py`
- `packages/case-dashboard/src/case_dashboard/session_jwt.py`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/sift-core/src/sift_core/case_io.py`
- `packages/sift-core/src/sift_core/case_manager.py`
- `packages/sift-core/src/sift_core/evidence_chain.py`
- `packages/sift-core/src/sift_core/case_ops.py`
- `packages/sift-core/src/sift_core/evidence_ops.py`
- `packages/sift-core/src/sift_core/verification.py`
- `packages/sift-core/src/sift_core/reporting.py`
- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-core/src/sift_core/execute/executor.py`
- `packages/sift-core/src/sift_core/execute/tools/generic.py`
- `packages/sift-common/src/sift_common/audit.py`
- `packages/sift-common/src/sift_common/__init__.py`
- `packages/sift-gateway/src/sift_gateway/auth.py`
- `packages/sift-gateway/src/sift_gateway/identity.py`
- `packages/sift-gateway/src/sift_gateway/token_gen.py`
- `packages/sift-gateway/src/sift_gateway/config.py`
- `packages/sift-gateway/src/sift_gateway/__main__.py`
- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
- `packages/sift-gateway/src/sift_gateway/rest.py`
- `packages/sift-gateway/src/sift_gateway/backends/__init__.py`
- `packages/sift-gateway/src/sift_gateway/backends/base.py`
- `packages/sift-gateway/src/sift_gateway/backends/stdio_backend.py`
- `packages/sift-gateway/src/sift_gateway/backends/http_backend.py`
- `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`
- `packages/forensic-mcp/src/forensic_mcp/server.py`
- `packages/forensic-rag-mcp/src/rag_mcp/server.py`
- `packages/forensic-rag-mcp/sift-backend.json`
- `packages/opencti-mcp/src/opencti_mcp/server.py`
- `packages/opencti-mcp/sift-backend.json`
- `packages/windows-triage-mcp/src/windows_triage_mcp/server.py`
- `packages/windows-triage-mcp/sift-backend.json`
- `packages/opensearch-mcp/pyproject.toml`
- `packages/opensearch-mcp/README.md`
- `packages/opensearch-mcp/sift-backend.json`
- `packages/opensearch-mcp/docker/docker-compose.yml`
- `packages/opensearch-mcp/src/opensearch_mcp/server.py`
- `packages/opensearch-mcp/src/opensearch_mcp/__main__.py`
- `packages/opensearch-mcp/src/opensearch_mcp/http_server.py`
- `packages/opensearch-mcp/src/opensearch_mcp/client.py`
- `packages/opensearch-mcp/src/opensearch_mcp/paths.py`
- `packages/opensearch-mcp/src/opensearch_mcp/gateway.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_evtx.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_accesslog.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_csv.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_defender.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_json.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_delimited.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_memory.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_plaso.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_prefetch.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_srum.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_ssh.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_tasks.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_transcripts.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_w3c.py`
- `packages/opensearch-mcp/src/opensearch_mcp/parse_wer.py`
- `packages/opensearch-mcp/src/opensearch_mcp/tools.py`
- `packages/opensearch-mcp/src/opensearch_mcp/mappings/__init__.py`
- `packages/opensearch-mcp/src/opensearch_mcp/mappings/*.json`
- Targeted `find`, `tree`, and `rg` scans for repo/package structure, frontend API usage, Starlette routes, MCP registration, JSON state, evidence, audit, tokens, OpenSearch, jobs/workflows, tests, docs, setup files, Redis/RQ/Celery, and Supabase/Postgres presence.

## Key OpenSearch Findings From Run 3

- Current OpenSearch is implemented as `opensearch-mcp`, an optional add-on MCP backend with standalone stdio/HTTP/CLI entry points and a `sift-backend.json` manifest.
- Current query tools validate that index names start with `case-`, but normal search can still accept explicit index names and can fall back to broad `case-*` behavior when no active case is resolved.
- Current case context comes from `SIFT_CASE_DIR` or `~/.sift/active_case`, not from Postgres/Supabase case membership or Gateway-issued case-scoped token state.
- Current ingest and indexing are subprocess-driven and tracked through `~/.sift/ingest-status`, ingest logs, and filesystem manifests, not durable database jobs, parser runs, parser outputs, or indexing batches.
- Current parser documents already include useful partial provenance such as `vhir.source_file`, `vhir.ingest_audit_id`, `vhir.parse_method`, host fields, and `pipeline_version`, but do not yet consistently include the target control-plane IDs.
- The recommended initial index strategy is per-case logical indexes with Postgres-registered aliases, because the current code already uses case-prefixed indexes. This recommendation still needs user approval before implementation.
- The safest first OpenSearch implementation slice is additive: add a control-plane-aware OpenSearch service abstraction, case-scope query construction tests, and explicit health/degraded behavior without removing the standalone backend.

## Execution Facts Confirmed From Run 4

- Portal/operator execution is mostly synchronous request/response against
  file-backed state. Evidence operations, approval commit, report generation,
  backend/service management, and polling all resolve active case from
  `SIFT_CASE_DIR`/legacy case resolution rather than durable DB session state.
- Gateway aggregate MCP calls run an evidence-chain gate before dispatch and
  write a transport-envelope audit entry. Per-backend MCP endpoints call a
  single backend directly and have a different policy/audit surface.
- Native `run_command` is synchronous. It validates command plans, executes
  shell-free subprocess stages, can save stdout/stderr under case-controlled
  directories, and writes detailed JSONL audit including input hashes where
  detectable.
- OpenSearch ingest is the main long-running execution path. It starts
  subprocesses with `python -m opensearch_mcp.ingest_cli`, records pid/run_id
  status under `~/.sift/ingest-status`, writes logs under
  `~/.sift/ingest-logs`, and indexes derived documents into case-prefixed
  OpenSearch indices.
- Parser modules generally write directly to OpenSearch bulk actions and stamp
  partial provenance fields such as `vhir.source_file`,
  `vhir.ingest_audit_id`, `vhir.parse_method`, optional `vhir.vss_id`, and
  `pipeline_version`. Durable DB IDs are not present.
- Evidence chain authority is currently the manifest/ledger files, with
  `evidence.json` as compatibility view. Audit and approval records are JSONL
  under the state-root case record directory by default.
- Current workflow/status state is scattered across case JSON files,
  `pending-reviews.json`, in-memory report drafts, `~/.sift/ingest-status`,
  ingest logs, active-case env/pointers, OpenSearch indices, and frontend cache.

## Execution Risks Discovered From Run 4

- Long-running parsers are not durable DB jobs.
- Case scope depends on env or active-case pointers.
- Status is file-based or scattered.
- Worker crash recovery is local pid-file and `/proc` based; durable ownership,
  heartbeat, and stale-claim handling are absent.
- Duplicate ingestion/indexing risk remains because status and idempotency are
  not control-plane-backed.
- OpenSearch indexing status can drift from existing indices and cleaned status
  files.
- Evidence provenance can disconnect from parser outputs because parser docs and
  ingest manifests do not carry durable evidence/job/parser IDs.
- MCP tools may block synchronously, especially native commands and add-on calls.
- Frontend cannot reliably observe parser/native progress through one
  authoritative progress model.
- Audit gaps can occur when parser subprocesses, sidecar writes, or active-case
  resolution fail outside a durable audit/job transaction.
- Per-backend MCP routes may bypass the aggregate evidence-gate behavior.
- Report generation uses in-memory in-flight/draft state only.

## Key Job-Model Decisions From Run 5

- Target job statuses are `pending`, `queued`, `running`, `waiting_human`,
  `succeeded`, `failed`, `retrying`, `cancelled`, `stale`, and `paused`.
- Job scope includes `case_id`, requester identity fields, creator type,
  job type, status, priority, idempotency key, JSON spec, timestamps, worker
  claim/lease fields, heartbeat, attempt counters, cancellation fields, and
  failure summary.
- `case_id` must come from Gateway-validated human session or
  MCP/service-token context, not from process environment or legacy active-case
  pointers.
- Workers claim queued jobs from Postgres using an atomic row-locking /
  `SKIP LOCKED`-style pattern with worker capabilities, priority ordering,
  case fairness, leases, and heartbeats.
- Stale jobs are detected through expired leases and recovered through audited
  retry/requeue/fail/cancel decisions.
- `job_steps` and `job_logs` are the target observability model; stdout/stderr
  should be captured with redaction and linked to steps/jobs.
- Parser runs, parser outputs, ingest batches, and OpenSearch indexing status
  link back to `case_id`, `job_id`, `job_step_id`, `parser_run_id`, evidence
  IDs where applicable, parser versions, source hashes, and schema versions.
- Initial target job types are `evidence_register`, `evidence_hash`,
  `evidence_verify_integrity`, `evidence_ingest`, `parser_run`,
  `opensearch_index`, `timeline_build`, `ioc_extract`, `finding_generate`,
  `report_generate`, `report_export`, `case_archive`,
  `maintenance_reindex`, and `health_check`.
- Worker runtime assumes registration, capabilities, parser/command allowlists,
  no arbitrary shell execution, environment isolation, subprocess timeouts,
  stdout/stderr capture, heartbeat, graceful shutdown, cancellation handling,
  and crash recovery through leases.

## Key Integration Decisions From Run 6

- Gateway REST APIs are the human/operator job surface. They create, list,
  inspect, cancel, retry, and observe jobs, steps, logs, workers, execution
  health, and OpenSearch health through Gateway policy.
- Case authorization for REST job APIs must come from Supabase Auth/RLS plus
  Gateway policy. The Gateway remains the REST policy enforcement point.
- The frontend must not directly mutate authoritative job state. It submits
  actions through Gateway endpoints and reads job/status/health/audit views.
- Core SIFT MCP tools are the AI-agent/service job surface. Long-running tools
  enqueue DB-backed jobs and return `job_id`.
- Target MCP tools include `jobs.enqueue`, `jobs.get`, `jobs.list`,
  `jobs.tail_logs`, `jobs.cancel`, `jobs.retry`, `evidence.ingest`,
  `evidence.verify_integrity`, `parsers.list`, `parsers.run`,
  `opensearch.index_status`, `opensearch.health`, `report.generate`, and
  `finding.generate`.
- MCP case context comes from Gateway-validated token/session context, not
  process environment or legacy active-case pointers. Normal agent tokens cannot
  pass arbitrary `case_id`, raw OpenSearch DSL, raw index names, or wildcard case
  patterns.
- Initial frontend update strategy is polling first, with later SSE/WebSocket or
  Supabase Realtime as an upgrade path after DB/RLS/Gateway event policy is
  stable.
- Evidence vault behavior is preserved. Raw evidence remains immutable while
  operational metadata, integrity status, job state, and audit linkage move into
  Postgres over time.
- OpenSearch indexing jobs link parser runs, parser outputs, ingest batches,
  index registrations, and OpenSearch documents through Postgres IDs and source
  hashes. OpenSearch remains derived and non-authoritative.
- Audit remains mandatory for job lifecycle transitions, parser runs, evidence
  access/checks, OpenSearch indexing, report/finding generation, human
  approvals, destructive/final actions, and policy denials.
- Approval-gated work enters `waiting_human`. Agent-generated findings remain
  proposed/pending and cannot be auto-approved.
- Worker health is observed through registration, capabilities, heartbeat,
  active job, `last_seen_at`, degraded/offline state, health endpoints, and
  stale-job audit/log behavior.

## Open Questions (RESOLVED in Run 9 - historical)

> The list below is historical. All blocking items are now answered by
> `00_migration_charter.md` "Confirmed Decisions (Locked)" (D1-D17) and
> `09_identity_auth_cutover.md`. The few genuinely non-blocking items (exact
> Supabase migration directory shape, compatibility-export lifetime defaults,
> retry/cancellation granularity defaults, pgvector availability) are recorded
> with defaults in the relevant docs' "Decisions still genuinely open" sections.
> Do not treat the items below as still-open.

- What exact Supabase Local deployment shape should this repo target?
- Should active-case state be per human session, per workstation, per Gateway instance, or a combination with explicit precedence?
- What token hashing strategy should be canonical, including algorithm, optional pepper/KMS use, displayed fingerprints, and default expiry?
- What is the safest first cutover order: cases/tokens first, evidence/audit first, or OpenSearch/jobs first?
- How long should generated compatibility files remain supported after Postgres becomes authority?
- Which external scripts or operator workflows still read `~/.sift/active_case`, `~/.sift/ingest-status`, saved report JSON, or flat case JSON directly?
- Must evidence manifest/ledger files remain canonical legal artifacts even after Postgres becomes operational authority?
- What exact worker process model should parser execution target: single Gateway-host worker, multiple local workers, or future distributed workers?
- Should the project approve per-case logical indexes as the initial OpenSearch strategy, or target shared indexes with mandatory `case_id` filters from the start?
- What target index names and aliases should be canonical for artifacts, timeline records, and IOCs?
- How long should the legacy `case-{case_id}-{artifact_type}-{hostname}` indexes remain queryable?
- Should per-backend OpenSearch MCP routes become admin-only, disabled by default, or removed after core tools are available?
- Should any normal agent token ever receive constrained raw OpenSearch DSL access, or should raw DSL be admin-only?
- Which OpenSearch version/profile is canonical: root compose OpenSearch 2.18.0, package compose OpenSearch 3.5.0, or a newly declared target?
- Is semantic/vector search in the first OpenSearch migration scope, or explicitly deferred?
- Should the first implementation slice cover only OpenSearch ingest, or also
  native `run_command`, report generation, and evidence operations?
- Should short native commands remain synchronous while only long-running parser
  workflows become jobs?
- Should legacy `~/.sift/ingest-status` continue as a compatibility export once
  Postgres job state exists, and for how long?
- What cancellation semantics are acceptable for partially indexed OpenSearch
  batches and subprocess trees?
- Should retry happen at whole-job, host, artifact, parser-run, or indexing
  batch granularity first?
- Which report/export workflows should become job-backed first?
- Which evidence operations are too expensive to remain synchronous?
- Which external scripts still consume `~/.sift/ingest-status`,
  `~/.sift/ingest-logs`, active-case pointers, or ingest manifests?
- What exact human role names and permissions should apply to job creation,
  retry, cancel, log reads, worker detail, approvals, final export, archive, and
  destructive cleanup?
- What exact initial REST response schemas and MCP result schemas should be
  frozen before implementation?
- What initial frontend polling intervals should be accepted, and when should
  SSE/WebSocket or Supabase Realtime become part of the roadmap?
- Should raw OpenSearch DSL be admin-only forever, or should a constrained
  normal-agent mode ever exist?
- Which job/action audit events must be fail-closed if the DB audit writer is
  unavailable during the transition?
- What exact test layout and package-specific commands should the first
  baseline execution PR use?
- Which smoke fixtures can cover parser/ingest behavior without requiring a
  live OpenSearch instance?
- What exact Supabase/Postgres table, constraint, index, RLS, and migration
  layout should be used for jobs, job steps, job logs, workers, parser runs,
  parser outputs, ingest batches, and OpenSearch indexing status?
- Should the first schema migration use UUID DB primary keys plus legacy text
  compatibility keys, or text identifiers as primary keys?
- Should the initial Supabase tables live in an `app` schema, `public`, or
  another approved namespace?
- Which optional schema tables should be first-class from the start:
  `service_identities`, `evidence_access_events`, `worker_heartbeats`, and
  `opensearch_document_refs`?
- Should evidence dedupe enforce unique active `(case_id, sha256)`, or preserve
  duplicate acquisitions as separate first-class evidence objects?

## Next Recommended Run

The first-PR candidate is now planned in `docs/migration/11_first_pr_candidate.md`.
The next run is the **actual JOB-0 coding implementation** - this is a coding
session, not another planning run.

Required reading before that run: `docs/migration/11_first_pr_candidate.md`
(scope source), then only the files listed in its section 4 as needed to confirm
test layout, commands, and helper behavior. Use the ready-to-copy coding prompt
in section 12 of that document.

Scope of the coding run:

- JOB-0 only: additive baseline execution smoke tests/fixtures + a short runbook,
  no runtime behavior change (see `11_first_pr_candidate.md` sections 3, 5, 7).
- 2-4 deterministic tests using temp dirs; no live OpenSearch, no real forensic
  samples, no real evidence paths.
- Run targeted tests + `git diff --check`; stop and summarize.

After JOB-0 lands, the first feature-bearing implementation is the identity
foundation (Phase ID-1 schema in `09_identity_auth_cutover.md`), per the cutover
order. JOB-1 should not precede ID-1.
