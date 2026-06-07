# First Implementation PR Candidate

Last updated: 2026-06-07.

Status: implemented. This document is retained as the historical JOB-0
candidate; do not use it as the next-run pointer.

Scope was planning only. This document defined the first real implementation PR
candidate after the migration planning docs.

Candidate PR title:

> Add baseline execution smoke-test fixtures and lightweight tests for current
> execution-critical paths, without changing runtime behavior.

## 1. Executive Summary

The first implementation PR should be roadmap phase JOB-0 only: additive
baseline execution smoke tests, tiny deterministic fixtures, and a short note
explaining how to run those checks.

This PR is intentionally protective. It should lock down the current
evidence, audit, parser, OpenSearch index-naming/provenance, ingest-status, and
case-context assumptions that the migration depends on before adding new
control-plane or durable-job behavior.

This PR must be:

- Additive only.
- No runtime behavior changes.
- No schema migrations.
- No worker dispatcher.
- No REST, MCP, or frontend refactors.
- No parser conversion.
- No OpenSearch architecture changes.
- No Supabase/Postgres dependency yet.
- No job tables, job repository, job APIs, or DB-backed execution.

The purpose is confidence, not feature work. The tests should prove that the
existing pre-migration behavior is understood and guarded before later PRs
move authority into Supabase/Postgres, introduce durable jobs, or adapt
OpenSearch execution paths.

## 2. Why This PR Comes First

Per charter D17, the locked feature cutover order is cases/tokens/identity
first. JOB-0 is still the correct first implementation PR because it is
additive, order-independent, and does not add a feature-bearing migration
slice. The first feature-bearing PR after JOB-0 is the identity foundation
track, Phase ID-1 in `09_identity_auth_cutover.md`, not JOB-1.

JOB-0 should happen before job schema migrations because the current execution
state has several file-backed authorities and implicit contracts that later DB
tables will mirror or replace. Baseline tests make it easier to tell whether a
future schema or repository change preserved evidence, audit, parser, and
OpenSearch assumptions.

JOB-0 should happen before a worker dispatcher because current long-running
work is not durable DB work. OpenSearch ingest launches subprocesses, stores
status in `~/.sift/ingest-status`, writes logs under `~/.sift/ingest-logs`,
and relies on process/file state. Tests should capture the current behavior
before a worker starts claiming jobs from Postgres.

JOB-0 should happen before REST job APIs and MCP job tools because current
Gateway and MCP execution paths are synchronous or subprocess-backed and still
derive case context from `SIFT_CASE_DIR`, `gateway.yaml`, or
`~/.sift/active_case`. Baseline checks reduce the risk of silently changing the
existing case-context and audit behavior while later APIs are added.

JOB-0 should happen before the OpenSearch core refactor because charter D18
locks reuse of the existing working OpenSearch ingestion model: index naming
through `build_index_name()`, shared `flush_bulk`, template auto-create,
host auto-discovery preflight, and `vhir.*`/`host.*`/`pipeline_version`
provenance. The migration commits to registering current indices in the
control plane, not renaming or replacing them in v1. A small test around index
naming and provenance is high value because it protects that reuse contract.

JOB-0 should happen before frontend job monitoring because the current
frontend observes scattered file-backed state and has no authoritative job
view. Tests should document the execution assumptions before a new UI surface
depends on DB-backed job state.

JOB-0 should happen before parser conversion because parser output currently
includes provenance fields and deterministic OpenSearch action shaping in
individual parser modules. A tiny parser/ingest smoke fixture can guard output
shape without requiring live OpenSearch or large forensic samples.

JOB-0 should happen before Phase ID-1 even though ID-1 is the first
feature-bearing cutover step. ID-1 creates the identity schema foundation.
JOB-0 does not create schema or runtime wiring; it simply protects current
behavior so ID-1 and later feature work have a regression baseline.

## 3. Exact PR Scope

The first PR should include only:

1. Identify the existing test framework, test layout, and package commands.
2. Add or improve lightweight smoke tests/fixtures for current
   execution-critical behavior.
3. Add a small documentation note explaining how to run the baseline execution
   checks.
4. Avoid any production behavior change.

The PR may include tests around:

- Evidence vault/hash/integrity behavior, if safely testable with temporary
  case and state directories.
- Audit event writing and JSONL format behavior, if safely testable with an
  explicit temporary audit directory or mock sink.
- Current parser/ingest metadata shaping, if testable without large forensic
  samples.
- OpenSearch index-naming and provenance-stamping shaping, especially the
  reused `case-{case}-{type}-{host}` model from charter D18 and doc 03 section
  7A, if testable without a live OpenSearch instance.
- OpenSearch ingest/status metadata shaping or degraded behavior, if testable
  without a live OpenSearch instance.
- Current case context resolution behavior, if safely testable without
  mutating real active-case pointers.

The PR must not include:

- Schema migrations.
- Supabase/Postgres setup.
- Worker process or dispatcher.
- Job tables.
- Job repository or service layer.
- REST job APIs.
- MCP job tools.
- Frontend changes.
- Parser refactors.
- OpenSearch refactor.
- Evidence vault behavior changes.
- Audit behavior changes.
- Token registry changes.
- Cleanup of unrelated `.DS_Store`, config, generated, or local-state changes.

## 4. Repository Discovery Needed For The Coding Run

The coding run should inspect only this focused set before implementing tests.
Do not perform a broad repository read.

| Area | Paths to inspect | Why inspect |
| --- | --- | --- |
| Migration instructions | `docs/migration/11_first_pr_candidate.md` | This is the scope source for the coding PR. |
| Test layout and package commands | `packages/sift-core/pyproject.toml`, `packages/sift-common/pyproject.toml`, `packages/opensearch-mcp/pyproject.toml`, `packages/sift-gateway/pyproject.toml`, existing tests under `packages/sift-core/tests/`, `packages/opensearch-mcp/tests/`, and only if needed `packages/sift-gateway/tests/` | Confirm pytest invocation, dependency extras, fixture style, import paths, and whether tests should be new files or additions to existing smoke files. |
| Evidence vault behavior | `packages/sift-core/src/sift_core/evidence_chain.py`, existing `packages/sift-core/tests/test_evidence_chain.py`, `packages/sift-core/tests/test_evidence_ops.py` | Confirm safe temp-dir setup for manifest, ledger, hash/status, and integrity checks. |
| Audit behavior | `packages/sift-common/src/sift_common/audit.py`, existing audit-related tests such as `packages/sift-core/tests/test_audit_ops.py` and `packages/sift-gateway/tests/test_audit_envelope.py` if needed | Confirm JSONL field names, append behavior, explicit audit-dir support, and secret redaction expectations. |
| OpenSearch index naming | `packages/opensearch-mcp/src/opensearch_mcp/paths.py`, existing `packages/opensearch-mcp/tests/test_ingest.py`, `packages/opensearch-mcp/tests/test_host_identity_wiring.py`, `packages/opensearch-mcp/tests/test_hostname.py` | Confirm `build_index_name(case_id, artifact_type, hostname)` sanitization and current test helper patterns. |
| Parser provenance shaping | One smallest parser path only, preferably `packages/opensearch-mcp/src/opensearch_mcp/parse_json.py` plus `packages/opensearch-mcp/tests/test_parse_json.py`; use another parser only if existing tests make it safer | Confirm how parser actions stamp `vhir.*`, `host.*`, `pipeline_version`, and stable `_id` without live OpenSearch. |
| OpenSearch ingest/status metadata | `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`, existing `packages/opensearch-mcp/tests/test_ingest_status.py`, and `packages/opensearch-mcp/tests/test_ingest_manifest.py` | Confirm file-backed status/manifest shape that later DB jobs must preserve or export. |
| Case context resolution | Only if a case-context smoke test is chosen: `packages/sift-common/src/sift_common/__init__.py`, `packages/opensearch-mcp/src/opensearch_mcp/server.py` active-case helper references, and existing case-env tests | Confirm safe environment monkeypatching without touching real `~/.sift/active_case`. |
| Documentation note location | `docs/migration/README.md` and proposed new `docs/migration/JOB0_baseline_execution_checks.md` | Keep run instructions discoverable without renumbering architecture docs. |

Narrow path discovery in this planning run found existing tests under
`packages/sift-core/tests/`, `packages/opensearch-mcp/tests/`,
`packages/sift-gateway/tests/`, `packages/case-dashboard/tests/`, and
`packages/case-dashboard/frontend/src/test/`. The first PR should use only the
core and OpenSearch test areas unless the exact smoke test requires Gateway
audit or evidence-gate coverage.

## 5. Proposed Files To Add Or Change

| File path | Add/change | Purpose | Risk level | Notes |
| --- | --- | --- | --- | --- |
| `packages/sift-core/tests/test_execution_baseline_smoke.py` | Add | Evidence and audit baseline smoke tests using temp dirs only. | Low | Prefer a new focused file unless existing test patterns clearly favor extending `test_evidence_chain.py` or `test_audit_ops.py`. |
| `packages/opensearch-mcp/tests/test_execution_baseline_smoke.py` | Add | OpenSearch index-naming and parser/provenance shape smoke tests without live OpenSearch. | Low | Highest-value protection for charter D18/doc 03 section 7A reuse. |
| `packages/opensearch-mcp/tests/fixtures/baseline/mini_records.jsonl` | Add, optional | Deterministic one- or two-record parser fixture. | Low | Add only if existing tests use fixture files; otherwise inline fixture data in the test. |
| `docs/migration/JOB0_baseline_execution_checks.md` | Add | Short runbook for targeted baseline checks and expected no-service assumptions. | Low | Do not use number `12`; doc 12 remains planned for the broader test acceptance plan. |
| Package test config, if needed | Change, optional | Add marker or fixture config only if tests cannot run without it. | Medium | Avoid unless necessary. Do not change runtime package configuration. |
| Existing `conftest.py` in the touched package | Change, optional | Add a reusable temp-dir fixture only if repeated setup would otherwise be duplicated. | Medium | Keep tiny and test-only. Do not add global service dependencies. |

Files explicitly not to touch in this PR:

- Supabase/Postgres migration directories or generated SQL.
- `packages/sift-core/src/sift_core/evidence_chain.py`.
- `packages/sift-common/src/sift_common/audit.py`.
- Runtime parser modules unless a tiny testability issue is impossible to
  avoid and is explained before coding.
- `packages/opensearch-mcp/src/opensearch_mcp/paths.py`.
- `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`.
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`.
- `packages/opensearch-mcp/src/opensearch_mcp/server.py`.
- `packages/sift-gateway/src/sift_gateway/*` runtime modules.
- `packages/case-dashboard/frontend/*`.
- Docker, installer, service, or OpenSearch deployment files.
- Token/auth registry runtime files.
- Unrelated `.DS_Store`, local config, generated cache, or formatting-only
  churn.

## 6. Test Plan

Test strategy:

- Use unit and smoke tests only.
- Use temporary directories for case roots, state roots, audit directories,
  ingest-status directories, and parser inputs.
- Use deterministic tiny sample data created in the test or stored as a small
  fixture.
- Do not require a live OpenSearch instance.
- Do not require real forensic images, EVTX corpora, VSS data, memory images,
  or external tools.
- Do not mutate `/var/lib/sift`, real case directories, real evidence vaults,
  real audit logs, or `~/.sift/active_case`.
- Mock or fake OpenSearch bulk/client calls where parser output shape must be
  inspected.
- Assert shape and provenance, not full forensic correctness.
- Prefer 2 to 4 tests total.

Commands need final confirmation from package manifests in the coding run. The
likely targeted commands are:

```bash
python -m pytest packages/sift-core/tests/test_execution_baseline_smoke.py
python -m pytest packages/opensearch-mcp/tests/test_execution_baseline_smoke.py
python -m pytest packages/sift-core/tests/test_execution_baseline_smoke.py packages/opensearch-mcp/tests/test_execution_baseline_smoke.py
git diff --check
```

If imports are package-local, run the same tests from the affected package
directory or through the repo's manifest-defined test runner. If a full suite
is practical after targeted tests pass, run the touched package suites:

```bash
python -m pytest packages/sift-core/tests
python -m pytest packages/opensearch-mcp/tests
```

If these commands are not valid in the current environment, the coding agent
must inspect the relevant `pyproject.toml` files and record the actual commands
in `docs/migration/JOB0_baseline_execution_checks.md`.

## 7. Suggested Smoke Tests

Prioritize only the first three tests. Add the fourth only if existing parser
helpers make it cheap.

| Test name | Purpose | Target module/function | Fixture input | Expected assertion | Why safe | Migration risk protected |
| --- | --- | --- | --- | --- | --- | --- |
| `test_evidence_integrity_baseline_uses_temp_state` | Prove current evidence chain/hash/status behavior can be exercised without touching real evidence state. | Existing `sift_core.evidence_chain` seal/status/hash helpers after confirming current test pattern. | A temp case dir, temp state dir, and one tiny text file. | Manifest/ledger or chain-status output contains stable hash/status fields for the temp file; no writes occur outside temp dirs. | Uses only temporary directories and tiny data. | Protects evidence vault behavior before DB evidence metadata and evidence jobs are added. |
| `test_audit_writer_baseline_jsonl_append_shape` | Prove current audit writer emits append-like JSONL with expected event metadata and no raw secrets. | `sift_common.audit.AuditWriter.log`. | Explicit temp audit dir, fixed actor/tool/action payload with a fake token-like value that must not appear raw. | Exactly one JSONL event is appended per call; required timestamp/id/tool/action/result fields match current format; raw token/secret fixture value is absent. | Uses explicit temp audit dir or existing mock pattern. | Protects audit format and provenance before audit events move to Postgres. |
| `test_opensearch_index_name_and_provenance_contract` | Lock the reused OpenSearch index naming and provenance contract from charter D18/doc 03 section 7A. | `opensearch_mcp.paths.build_index_name`; one parser helper that shapes OpenSearch actions, preferably JSON. | `case_id`, artifact type, hostname with mixed case/spaces/symbols; one tiny in-memory record. | Index name is the current lowercased/sanitized `case-{case}-{type}-{host}` shape; shaped record includes `vhir.*`, `host.*`, `pipeline_version`, and a stable dedup `_id` across repeated runs. | No live OpenSearch; inspect shaped actions via fake bulk writer/client. | Protects the current ingestion model that the migration commits to reusing rather than refactoring. |
| `test_ingest_status_or_manifest_shape_baseline` | Optional check for file-backed ingest status or ingest manifest shape. | `opensearch_mcp.ingest_status` or ingest manifest helper, depending on existing tests. | Temp status dir or temp case audit dir with a minimal status/manifest payload. | Status/manifest JSON contains current run/case/host/artifact/source/hash fields and remains under temp paths. | No live services, no parser execution. | Protects migration from losing current status/provenance fields when DB job/indexing state is introduced. |

Do not add a smoke test that requires large fixture data, native forensic tools,
network services, OpenSearch, Supabase, Docker, or real case/evidence paths. If
the smoke test cannot be isolated, mark it as a documented gap instead of
forcing a broad test harness.

## 8. Manual Validation Steps

After implementation, the coding agent should verify:

- Run the targeted new smoke tests.
- Run the touched package suite if practical.
- Run `git diff --check`.
- Review `git diff` and confirm only intended test, fixture, and docs files
  changed.
- Confirm no production code behavior changed unless a tiny testability seam
  was explicitly approved and documented.
- Confirm no schema migration or Supabase/Postgres setup was added.
- Confirm no real evidence path, `/var/lib/sift`, or real `~/.sift/active_case`
  was touched.
- Confirm no live OpenSearch dependency was introduced.
- Confirm no frontend, REST, MCP, OpenSearch architecture, parser, worker, or
  token registry refactor slipped into the PR.
- Confirm no unrelated `.DS_Store`, generated, cache, config, or formatting-only
  changes were included.

## 9. Acceptance Criteria

The first PR is acceptable only if:

- Tests are small and deterministic.
- Tests pass locally.
- No runtime behavior changed.
- No schema migrations were added.
- No worker or job implementation was added.
- No frontend, MCP, REST, parser, or OpenSearch refactor was added.
- Evidence/audit behavior is protected by at least one baseline test, or a
  specific not-testable-yet gap is documented with the reason.
- Documentation explains how to run the baseline checks.
- The diff is clean except intended files.
- `git diff --check` passes.

## 10. Rollback Strategy

Rollback is simple because the PR is additive and test/docs-only:

- Revert the added tests, tiny fixtures, and baseline check note.
- No data migration rollback is needed.
- No DB rollback is needed.
- No runtime config rollback is needed.
- No worker/job rollback is needed.
- No evidence vault rollback is needed if the tests use temporary directories
  only.
- No OpenSearch rollback is needed because tests must not write to a live
  OpenSearch instance.

## 11. Context Guardrails For The Coding Agent

Rules for the future coding session:

- Do not inspect the whole repo.
- Do not rewrite architecture docs.
- Do not renumber, move, or recreate existing docs. Docs `09` and `10` already
  exist; this document is `11`.
- Do not start Phase JOB-1, JOB-2, or identity Phase ID-1.
- Do not add Supabase/Postgres yet.
- Do not add Redis/RQ/Celery/Temporal.
- Do not add a worker process, dispatcher, job repository, job tables, REST job
  APIs, MCP job tools, or frontend job monitoring.
- Do not fix unrelated issues.
- Do not include unrelated `.DS_Store`, config, generated, or local-state
  changes.
- Do not touch production behavior unless a tiny testability seam is absolutely
  required. If that happens, explain the seam before coding and keep it
  separate from runtime behavior.
- Stop and ask if the smoke tests require large fixture data, live services,
  real forensic images, Docker, OpenSearch, Supabase, or real evidence paths.

## 12. Next Coding Prompt

Ready-to-copy prompt for the next Codex coding session:

```text
Implement the first migration PR candidate for SIFT VM Autonomous DFIR Agent.

Read only docs/migration/11_first_pr_candidate.md first. Then inspect only the
files listed in section 4 of that document as needed to confirm test layout,
test commands, and exact helper behavior.

Implement JOB-0 only: additive baseline execution smoke tests/fixtures and a
small docs note for running them. Do not change runtime behavior. Do not add
schema migrations, Supabase/Postgres, workers, job tables, REST job APIs, MCP
job tools, frontend changes, parser refactors, OpenSearch refactors, evidence
behavior changes, audit behavior changes, or token registry changes.

Prioritize 2 to 4 deterministic tests that use temp dirs and do not require
live OpenSearch or real forensic samples. Run the targeted tests, run the
touched package suite if practical, run git diff --check, then stop and
summarize changed files, tests run, and any deviations from
docs/migration/11_first_pr_candidate.md.
```

## 13. Decisions And Open Questions

### Confirmed Decisions

- First implementation PR is Phase JOB-0 only.
- First PR is test/fixture/docs focused.
- First PR is additive and order-independent.
- No schema migrations in the first PR.
- No runtime behavior change in the first PR.
- No Supabase/Postgres in the first PR.
- No worker/job implementation in the first PR.
- No frontend/MCP/REST/OpenSearch refactor in the first PR.
- Current OpenSearch index naming and provenance behavior is a protected
  contract because charter D18/doc 03 section 7A commit to reusing it.
- The first feature-bearing PR after JOB-0 is identity foundation Phase ID-1,
  not JOB-1.

### Decisions Needing User Approval

- None for this planning document.
- If the coding session discovers that a tiny production-code testability seam
  is required, it must ask before making that change.

### Code Facts Still Needing Confirmation

- Exact package test commands and dependency runner.
- Whether new smoke tests should live in new files or extend existing package
  tests.
- Exact `AuditWriter.log` JSONL field names to assert.
- Exact `build_index_name()` sanitization output for mixed-case and symbol-rich
  inputs.
- The smallest parser path that exposes provenance/action shaping without a
  live OpenSearch instance.
- Whether an ingest-status or ingest-manifest smoke test is cheaper and safer
  than a parser-output smoke test.

## 14. Next Recommended Run

JOB-0 is complete. This section is historical; use `MIGRATION_STATE.md` for the
current objective and next recommended run.
