# Session Notes

Status: sprint log and decision register.
Last updated: 2026-06-08.

Format rules:

- Latest change entry stays at the top of `Current Change Log`.
- Use `Status: DONE`, `Status: IN_PROGRESS`, or `Status: BLOCKED`.
- Keep forks, blockers, and needs-input in the single table below.
- Use IDs beginning with `F-MVP-` for forks and `B-MVP-` for backlog.
- Do not create more migration runbooks.

## Current Change Log

### 2026-06-08 - Dependent wave landed and integrated (E1/F1/G1/I1)

Status: DONE

Changed (merged into `revamp/spg-v1`, one `--no-ff` merge per batch; branch
filesets verified fully disjoint, no conflicts):

- BATCH-E1 (`0390a9c`): Portal authority migration. `routes.py` gains four
  Gateway-injected service slots (`evidence_service`, `investigation_service`,
  `report_service`, `job_service`) following the established DI seam
  (`_ACTIVE_CASES`/`_SUPABASE_AUTH`); each route prefers DB authority when wired
  and falls back to the file path when `None`. Evidence seal/ignore/retire refuse
  403 without a `reauth_audit_event_id` (C1 contract); reports gate 409 on no
  approved findings; new `GET /api/portal/state` and `GET /api/jobs/{job_id}`
  (D2 `JobService`). Report generation internals left to J1. Frontend evidence/
  reports tabs + polling + rebuilt v2 bundle.
- BATCH-F1 (`4a27aba`): OpenSearch ingest job adapter. `job_ingest.py` concrete
  `ingest` handler for the D1 `JobWorker` (resolves path from worker-only
  `spec_internal`, never echoed); central provenance stamping at the `flush_bulk`
  choke point (no parser-module edits); migration
  `202606081300_opensearch_provenance.sql` (index + ingest-provenance tables,
  service-only RPCs, sanitized coverage view, case-member RLS); registry surfaces
  `default_case_scoped`/`data_plane`. Owned `mcp_backends_registry.py` this wave.
- BATCH-G1 (`cc8c7a8`): RAG pgvector. Migration `202606081400_rag_pgvector.sql`
  (collections/documents/chunks, `vector(768)`, IVFFlat cosine, knowledge-vs-derived
  CHECK, RLS); `pgvector_store.py` case-scoped path-free adapter; `rag_search`
  returns shared knowledge UNION only the querying case's derived chunks. No
  gateway source touched (one new bridge test only).
- BATCH-I1 (`3fd86bd`): run_command uplift. `evidence_refs`/`output_ref` instead
  of arbitrary paths; `MVP_FORENSIC_ALLOWLIST` + `@mvp_forensic` alias; deep
  agent-response path sanitization (audit keeps absolutes); hash-linked provenance
  receipt. Deny-floor preserved (`bash` denied even when requested; dd/mount/losetup
  excluded). Updated 2 existing gateway tests that asserted the old absolute-path
  contract.

Validation:

- Passed: `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`.
- Passed (integrated, main worktree): sift-gateway 355, sift-core 364,
  case-dashboard 344, forensic-rag 18, opensearch-mcp 987 (+71 skipped),
  tests/db 45. No regressions.
- Not run in this environment: live `supabase db` apply of migrations
  `202606081300`/`202606081400`, live OpenSearch ingest, and live VM portal journey.
  Validation was structural + unit-level, consistent with prior waves.

Last-mile binding gap (every consuming batch deferred this; no defined batch owns
it yet): the DB-authority code paths are built but not yet bound to live services.
Captured as B-MVP-5/6/7. These block BATCH-V1's live end-to-end journey but not the
individual batch acceptances (each passes with fallbacks/units).

Next:

- Launch BATCH-J1 (approved-only report generation/export; depends on E1, now landed).
- Resolve the binding batch (B-MVP-5/6/7) before BATCH-V1.

### 2026-06-08 - BATCH-D2 landed and integrated (Gateway job/authority seam)

Status: DONE

Changed (merged into `revamp/spg-v1`, `--no-ff`):

- BATCH-D2 (`e80ad41`): Gateway integration seam.
  - `jobs.py` (new) `JobService` over D1's `app.enqueue_job` /
    `app.job_status_public` / `app.expire_stale_jobs`. Enqueue writes the Gateway
    enqueue audit event first and passes its id as `p_enqueue_audit_event_id`,
    returning only `{job_id}`. Status reads go through an explicit agent-safe
    allow-list with case-membership enforcement (no `spec_internal`, `worker_id`,
    lease internals, local paths, or DB errors). `expire_stale_jobs` runs from a
    Gateway-owned periodic reaper wired into the FastAPI lifespan (mirrors the
    existing idle-reaper pattern). No grant/wrapper migration needed — same
    service DSN path as `ActiveCaseService`.
  - `AddonAuthorityMiddleware` (in `policy_middleware.py`) runs before the
    evidence gate/audit/dispatch: denies `addon_scope_missing` when the caller
    lacks a tool's `required_scopes`, denies `addon_prohibited_operation` when a
    backend's `prohibited_operations` is invoked; `non_authoritative` surfaced as
    advisory. `transport: library` manifests stay accepted but non-routable.
  - `server.py` indexes `required_scopes`/`authority_contract` into tool meta and
    exposes `Gateway.job_service` + `addon_authority_for_tool()`;
    `supabase_auth.is_scope_satisfied()` helper added.

Resolved B-MVP-3 and B-MVP-4 (both implemented by D2).

Validation:

- Passed: `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`.
- Passed: sift-gateway 348 (335 baseline + 13 new); existing manifest/registry/policy
  tests green. D2 touched only the gateway package.
- Not run in this environment: live `supabase`/Postgres execution of the job RPCs
  (D2 pins to D1's frozen RPC/view names; D1 verified them on a Postgres 16 container).

Launch readiness: E1/F1/G1/I1 need no further Gateway glue — they wire their own
call sites onto `gateway.job_service` and inherit the authority enforcement. D2
deliberately did not add REST/MCP route handlers surfacing `JobService` (out of its
fence); the consuming batches own those call sites.

Next:

- Launch BATCH-E1, BATCH-F1, BATCH-G1, BATCH-I1 in parallel worktrees. BATCH-J1
  follows E1. BATCH-V1 follows all implementation batches.

### 2026-06-08 - Next-wave seams assigned to BATCH-D2

Status: DONE

Changed:

- Checked `revamp/spg-v1` after the first parallel wave: branch is clean,
  integration commits are present, and both doc validators pass.
- Solved the two open cross-batch seams by adding BATCH-D2 as a Gateway-only
  integration batch before the dependent wave.
- Assigned B-MVP-3 to BATCH-D2: Gateway adapter over D1 job enqueue/status/reaper
  surfaces.
- Assigned B-MVP-4 to BATCH-D2: runtime enforcement of add-on
  `authority_contract` and tool `required_scopes`.
- Updated dependent batch dependencies so E1/F1/G1/I1/J1/V1 consume D2 instead
  of each implementing Gateway glue independently.

Validation:

- Passed: `python3 scripts/validate_docs.py`.
- Passed: `python3 scripts/validate_migration_docs.py`.

Next:

- Launch BATCH-D2 first. After D2 lands cleanly, launch E1/F1/G1/I1 in parallel;
  J1 follows E1, and V1 follows all implementation batches.

### 2026-06-08 - First parallel wave landed and integrated (A1/B1/C1/D1/H1)

Status: DONE

Changed (merged into `revamp/spg-v1`, one `--no-ff` merge per batch + one integration commit):

- BATCH-A1 (`4effda6`): Supabase-first installer/bootstrap. `~/.sift/supabase.env`
  (chmod 600) secrets via systemd `EnvironmentFile`; Admin-API invite + one-time
  temp password; `invited->active` forced-reset transition (`POST /api/auth/forced-reset`,
  `must_reset` login flag); frozen case path `case-<slug>-<MMDDHHSS>` + `-NN` with
  slug traversal guard; rewritten `/health` (Gateway, Supabase, evidence root,
  tools_count).
- BATCH-B1 (`55e6933`): Gateway policy parity + agent redaction. Agent/service
  tokens 403 on `POST /api/v1/tools/{tool}` before dispatch (F-MVP-3, closes the
  REST bypass the prior R4 block missed); path-redaction at the MCP choke point
  (in-case absolute -> relative, all other host paths -> `[REDACTED:absolute_path]`,
  audit retains absolute) (F-MVP-2). Made no edits to `evidence_gate.py`.
- BATCH-C1 (`67d0dbb`): DB evidence authority + custody ledger. Migration
  `202606081000_evidence_custody.sql` (evidence_objects/versions, append-only
  hash-linked custody events, chain heads as fail-closed read model, proof exports);
  service-only transition RPCs (seal/ignore/retire require a re-auth audit event id);
  added `check_evidence_gate_db()` alongside the untouched file-backed gate.
- BATCH-D1 (`df93104`): Durable Postgres jobs + worker. Migration
  `202606081200_durable_jobs.sql` (jobs/job_steps/job_logs/worker_heartbeats);
  `FOR UPDATE SKIP LOCKED` claim/lease RPCs; `job_status_public` sanitized view;
  `JobWorker` claim loop with path-scrubbed logs/results. Lease/race verified on a
  live Postgres 16 container.
- BATCH-H1 (`ed5f27a`): Add-on contract hardening. `authority_contract` +
  tool `required_scopes` on OpenCTI/Windows-triage; new library manifest for
  forensic-knowledge.
- Integration (`be4d7f4`, conductor): reconciled H1 into the Gateway manifest layer
  (the gateway-side glue H1 deferred) — backend schema now permits optional
  `authority_contract` + tool `required_scopes`; `load_and_validate_manifest` skips
  `transport: library` / `standalone_server: false` manifests as non-routable;
  `test_phase6` enumerates routable backends only.

Branch fileset was fully disjoint across the five batches; merges were
conflict-free. The B1/C1 `evidence_gate.py` overlap I pre-split did not
materialize (B1 worked in `policy_middleware`/`response_guard` instead).

Validation:

- Passed: `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`.
- Passed: sift-gateway 335, sift-core 346, case-dashboard 322, tests/db 45,
  opencti 11, windows-triage 24, forensic-knowledge 31. No regressions.
- Not run in this environment: live SIFT VM smoke (installer bootstrap, Supabase
  Admin API) and live `supabase db` apply of the two new migrations. C1 used the
  repo's text-based migration tests; D1 applied on a Postgres 16 container.

Carried-forward integration follow-ups (feed the dependent wave):

- Gateway enqueue/status adapter over D1's `enqueue_job` / `job_status_public`
  (returns only `job_id`; set `enqueue_audit_event_id`; schedule `expire_stale_jobs`
  reaper). New B-MVP-3.
- Switch the MCP evidence gate to prefer `check_evidence_gate_db()` once cases
  carry DB evidence state (B1/C1 seam) — consumed by BATCH-E1.
- Runtime enforcement of `authority_contract` (`non_authoritative`,
  `prohibited_operations`, `required_scopes`) in the Gateway backend registry;
  schema acceptance is done, routing-time enforcement is not. New B-MVP-4.
- Concrete job handlers (ingest/enrich/report/run_command) for `JobWorker` belong
  to BATCH-F1 and BATCH-I1.

Next:

- Launch the dependent wave: BATCH-E1 (portal DB authority), BATCH-F1 (OpenSearch
  ingest adapter), BATCH-G1 (RAG pgvector), BATCH-I1 (job-backed run_command),
  BATCH-J1 (approved-only reports), then BATCH-V1.

### 2026-06-08 - MVP forks closed for parallel sprint

Status: DONE

Changed:

- Resolved F-MVP-1: case directories use
  `/cases/case-<slug>-<MMDDHHSS>` with a lowercase filesystem-safe slug and
  `-NN` collision suffix if needed.
- Resolved F-MVP-2: agents may see evidence IDs, display names, relative
  display paths, size, hash, seal status, and provenance IDs. Absolute case,
  evidence, and mount paths remain forbidden.
- Resolved F-MVP-3: agents use MCP only for the MVP. REST tool execution is
  operator-only.
- Resolved F-MVP-4: hackathon report export keeps the current profile output
  and adds DB metadata, approved-only filtering, custody/provenance appendix,
  and downloadable artifact.
- Deferred B-MVP-1 and B-MVP-2 as post-MVP presentation/backlog items.

Validation:

- Passed: `python3 scripts/validate_docs.py`.
- Passed: `python3 scripts/validate_migration_docs.py`.

Next:

- Launch parallel worktrees using the prompts generated from
  `task-batches.md`.

### 2026-06-08 - Migration docs collapsed to MVP operating model

Status: DONE

Changed:

- Purged the previous `docs/migration` document forest.
- Added `Migration-Spec.md` as the architecture, journey, constraints, and DoD
  source of truth.
- Added `task-batches.md` as the parallel-execution tracker with grep-friendly
  checkboxes.
- Added `Session-Notes.md` as the top-loaded change log and fork/backlog table.
- Recreated root `AGENTS.md` and `CLAUDE.md` as compact sprint instructions.
- Updated the Python document validator to enforce the new three-file model.

Validation:

- Passed: `python3 scripts/validate_docs.py`.
- Passed: `python3 scripts/validate_migration_docs.py`.

Next:

- Start BATCH-A1, BATCH-B1, and contract prep for BATCH-C1/BATCH-D1 in separate
  worktrees after the operator confirms or resolves the open forks below.

## Forks / Backlog / Needs Input

| ID | Type | Status | Decision or work needed | Recommendation | Blocks |
| --- | --- | --- | --- | --- | --- |
| F-MVP-1 | Fork | RESOLVED | Case directory format is `/cases/case-<slug>-<MMDDHHSS>`, with lowercase filesystem-safe slug and `-NN` collision suffix if needed. | Locked for BATCH-A1 and BATCH-C1. | none |
| F-MVP-2 | Fork | RESOLVED | Agents may see `evidence_id`, display name, relative display path, size, hash, seal status, and provenance ID. Absolute case/evidence/mount paths are forbidden. | Locked for BATCH-B1 and BATCH-C1. | none |
| F-MVP-3 | Fork | RESOLVED | Agents use MCP only for the MVP. REST tool execution is operator-only. | Locked for BATCH-B1. | none |
| F-MVP-4 | Fork | RESOLVED | Hackathon report export keeps current profile output and adds DB metadata, approved-only filtering, custody/provenance appendix, and downloadable artifact. | Locked for BATCH-J1. | none |
| B-MVP-1 | Backlog | DEFERRED | Enterprise object-lock/WORM evidence vault option. | Post-MVP architecture appendix only. | none |
| B-MVP-2 | Backlog | DEFERRED | ContextForge/Envoy-style external gateway integration. | Post-MVP presentation/backlog only; Gateway policy remains in SIFT Gateway for MVP. | none |
| B-MVP-3 | Backlog | DONE | Gateway enqueue/status adapter over D1's `enqueue_job`/`job_status_public` (job_id only, sets `enqueue_audit_event_id`, schedules `expire_stale_jobs` reaper). | Landed in BATCH-D2 (`e80ad41`) as `JobService` + lifespan reaper. | E1, F1, G1, I1, J1 |
| B-MVP-4 | Backlog | DONE | Runtime enforcement of add-on `authority_contract` (non_authoritative, prohibited_operations, required_scopes) in the Gateway backend registry; schema acceptance landed in this wave. | Landed in BATCH-D2 (`e80ad41`) as `AddonAuthorityMiddleware`. | F1 |
| B-MVP-5 | Backlog | OPEN | Bind `create_dashboard_v2_app` service slots (`evidence_service`/`investigation_service`/`report_service`/`job_service`) to live Postgres/C1 RPCs/D2 `JobService`. Method contracts are documented in `routes.py` and exercised by E1's fakes. | Dedicated binding batch before V1. | V1 |
| B-MVP-6 | Backlog | OPEN | Worker bootstrap + enqueue call sites: register D1 `JobWorker` handlers (F1 `ingest`, I1 `run_command`) and the enqueue call sites that place the resolved evidence path in `spec_internal`. | Dedicated binding batch before V1. | V1 |
| B-MVP-7 | Backlog | OPEN | Wire a case-scoped pgvector RAG query tool (G1 `app.rag_search`/`PgVectorRagStore`) into the Gateway tool surface with a worker service DSN; current `kb_*` tools are ChromaDB knowledge-only. | Dedicated binding batch; routes results through the existing response guard. | V1 |
