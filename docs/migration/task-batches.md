# Task Batches

Status: operator-readiness, hardening, add-on, and documentation tracker.
Last updated: 2026-06-14.

This is the primary execution tracker. `docs/migration/Session-Notes.md` holds the session-level
status log and backlog decisions. Older implementation notes are in git history, not in this file.

## Rules

- Read `AGENTS.md`, this file, and the latest `docs/migration/Session-Notes.md` entry before work.
- Runner sessions start with **RUN-3** sections if the task touches `run_command`.
- Keep entries compact and context-frugal: only in-session essentials, acceptance criteria, and required
  owner actions.
- `docs/regenerate/**` is reference seed only; treat it as stale until revalidated by active batches.
- For `run_command` hardening, treat `docs/research/run_command-FINAL-SPEC.md` as authoritative.
  Do **targeted extraction only** (specific sections), not full-file dump.
- Keep batch planning in this file only; do not add extra migration runbooks.
- Keep batch checkboxes unchecked until acceptance checks pass.

## Current Baseline

Core remains: `sift-gateway`, `sift-core`, operator portal, Supabase/Postgres, OpenSearch,
forensic-rag-mcp/pgvector, forensic-knowledge, Hayabusa, installer/services, and local worker.
External add-ons are OpenCTI and future Windows-triage-style integrations via add-on contract only.
Live baseline (from prior sessions): clone-entry `./install.sh` stages into `/opt/sift-mcps`; services run as
`sift-service`; `/health` is `status=ok` when green; MCP auth is via portal-issued credentials.

## Wave Order

Completed waves (landed): RUN-3 (R3-CEIL/FLOOR/AA/GATE), Discovery/operators (OR1-OR4),
Hardening (HR1-HR3), Add-on (AD1-AD2), PT1, TLS1, DB1, CL1, CL3a/b, UN1, RG1.

Remaining sequence (operator decision 2026-06-14):

1. **Optimizations first** — run_command / agent execution optimizations (define + sequence; see
   B-MVP-028). This is the immediate next priority before any product-gap batch.
2. **Portal RAG** — BATCH-PT2 (knowledge-plane document management).
3. **Supabase default-key research** — BATCH-SB1, reframed: research a lighter remediation for the
   default CLI demo keys (rotate/replace post-install) that does NOT require a full self-managed
   compose. Full compose is the fallback, not the first move.
4. **Repo rename at the end** — BATCH-CL2 (`ProtocolSiftGateway` + add_ons layout).
5. **Legacy removal sweep** — resolve B-MVP-023: remove `legacy_portal_session_enabled` fallback and
   delete any remaining legacy code paths/tests (fold under CL-cleanup discipline).
6. **End-to-end LAST** — BATCH-LV1 is the final closeout run, after the above. Do not pull it forward.

Baseline constraint (operator): the SIFT VM ships a fixed default kernel; kernel upgrades are NOT
encouraged. Every Floor control must hold at that baseline (Landlock ABI v4). ioctl-scoping (ABI v5)
is therefore NOT a planned dependency — ioctl is covered by the seccomp filter at the v4 baseline.

## Batch Index

- [x] BATCH-R3-CEIL - Ceiling hardening (`run_command`: allowlist policy, scanners, output sanitation)
- [x] BATCH-R3-FLOOR - Floor hardening (`run_command`: launcher, cgroup, runtime user, Landlock, seccomp log mode)
- [x] BATCH-R3-AA - AppArmor + unit backstop (`run_command`)
- [x] BATCH-R3-GATE - Red-team harness + acceptance gate (`run_command`)
- [x] BATCH-OR0 - Rebase docs operating model around operator-hardening track
- [x] BATCH-OR1 - Live VM inventory and SIFT tool path map
- [x] BATCH-OR2 - File-state versus database-authority discovery map
- [x] BATCH-OR3 - Full operator maintenance manual and variable dictionary
- [x] BATCH-OR4 - RAG/forensic-knowledge/Hayabusa provenance manual
- [x] BATCH-HR1 - Official hardening research matrix
- [x] BATCH-HR2 - Component hardening audit guides
- [x] BATCH-HR3 - Installer and runtime hardening implementation wave
- [x] BATCH-AD1 - Add-on specification and author guide
- [x] BATCH-AD2 - Add-on conformance tests and OpenCTI proof
- [x] BATCH-CL1 - Legacy, pre-migration, and dead-reference cleanup
- [ ] BATCH-CL2 - ProtocolSiftGateway rename and add_ons repository layout
- [x] BATCH-PT1 - Portal operator workflow and health features
- [ ] BATCH-PT2 - Portal RAG document management flow
- [x] BATCH-TLS1 - Installer certificate and trust strategy
- [ ] BATCH-SB1 - Self-managed Supabase compose with generated secrets
- [x] BATCH-CL3a - Supabase fail-closed operator-password re-verification
- [x] BATCH-CL3b - Complete re-auth migration (delete dead plane + close gaps)
- [x] BATCH-DB1 - FORCE RLS on `app.*` tables
- [x] BATCH-UN1 - Component uninstaller and selective teardown
- [x] BATCH-RG1 - Documentation regeneration modernization pass
- [ ] BATCH-LV1 - End-to-end live VM validation and Rocba proof

## BATCH-R3-CEIL - Ceiling hardening (`run_command`: allowlist policy, scanners, output sanitation)

Dependencies: none.

Scope:

- `packages/sift-core/src/sift_core/execute/{security.py, security_policy.py, runtime_acl.py}`
- `packages/sift-gateway/src/sift_gateway/response_guard.py` (response sanitation path)
- `packages/sift-core/tests` and `packages/sift-gateway/tests` security slices

Exact work:

- Move from open policy to allowlist model with `@mvp_forensic`, and enforce `unlisted_policy: contained`.
- Add/confirm per-tool blocked flags and program-text scanners for sed/sqlite3/tshark/vol/exiftool.
- Extend deny-floor to include additional high-impact command/tooling vectors; add `/var/lib/sift` hard block.
- Enforce env deny-after-allow for runtime/code-injection vector names (`dotnet`, `ld`, `python`, `perl`, `ruby`, `node`, etc.).
- Extend output sanitation with ANSI/OSC control stripping and untrusted-output provenance label.
- Preserve command parser behavior (`command:str`, `shell=False`) for flexibility.

Acceptance:

- No `run_command` path returns `approval_required` and no added human-in-loop behavior.
- `run_command` closes known red-team negative rows at Ceiling layer where appropriate.
- Targeted `sift-core`/gateway security tests pass.
- `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`, and `git diff --check` pass.

Validation:

- `uv run --extra dev --extra full pytest packages/sift-core/tests/security/test_security.py -k policy -q`
- `uv run --extra dev --extra full pytest packages/sift-gateway/tests -k response_guard -q`

## BATCH-R3-FLOOR - Floor hardening (`run_command`: launcher, cgroup, runtime user, Landlock, seccomp log mode)

Dependencies: BATCH-R3-CEIL.

Scope:

- `packages/sift-core/src/sift_core/execute/{worker.py, executor.py}`
- New `packages/sift-core/src/sift_core/execute/dfir_exec_launcher.py`
- `packages/sift-core/tests` (execution/security slices)

Exact work:

- Add runtime-user fail-closed guard (`SIFT_EXECUTE_REQUIRE_RUNTIME_USER=1`) and UID checks.
- Wrap execution with `systemd-run --scope` for bounded resources and network deny posture.
- Implement launcher with Landlock ABI handling (v4+ active baseline), deny-by-default, case/evidence grants, and FD closure.
- Enforce no secret directory / cross-case reads from Floor model.
- Add seccomp in LOG mode with minimal kill set for risky syscalls.
- Keep `runtime_acl.build_sandbox_env(...)` as read-only import seam.

Validation / tests:

- `SIFT_EXECUTE_REQUIRE_RUNTIME_USER=1` fail-closed unit/fixture checks.
- `uv run --extra dev --extra full pytest packages/sift-core/tests/security -q`
- `SIFT_RUN3_GATE_STRICT=1 uv run --extra dev --extra full pytest packages/sift-core/tests/security -q` (or equivalent strict gate).

Acceptance:

- Launch path executes only under validated runtime user and enforced namespace/FS/FD rules.
- Floor red-team probes are demonstrably blocked at the right layer.
- Local strict slice remains green before Wave-2 deployment.

## BATCH-R3-AA - AppArmor + unit backstop (`run_command`)

Dependencies: BATCH-R3-FLOOR, BATCH-R3-CEIL.

Scope:

- `configs/apparmor/**`
- `configs/systemd/sift-job-worker.service`
- `install.sh` helper integration points for AppArmor / sudoer helper references

Exact work:

- Finalize `dfir-exec` AppArmor profile aligned with FUSE and mount constraints.
- Update worker service hardening flags to keep helper invocation possible (no over-broad protections that break execution flow).
- Keep default install behavior safe; enforce flip remains live-governed.
- Wire helper/grant notes for `systemd-run --scope` privilege path.

Acceptance:

- Unit-level helper and unit file edits are syntax-valid (`bash -n` where applicable).
- AppArmor profile can be exercised in complain mode and promoted to enforce only after burn-in.
- No new path regressions in protected services from existing install baseline.

Validation:

- `bash -n install.sh scripts/setup-addon.sh scripts/setup-supabase.sh`
- `systemd-analyze verify configs/systemd/sift-job-worker.service`
- `SIFT_RUN3_GATE_STRICT=1 uv run --extra dev --extra full pytest packages/sift-core/tests/security -q`

## BATCH-R3-GATE - Red-team harness + acceptance gate (`run_command`)

Dependencies: BATCH-R3-CEIL and BATCH-R3-FLOOR deployed in integration branch.

Scope:

- New/updated `packages/sift-core/tests/security/test_red_team_positive.py`
- New/updated `packages/sift-core/tests/security/test_red_team_negative.py`
- `packages/sift-core/tests/security/` runbook/fixtures as needed

Exact work:

- Add machine-asserted red-team negative matrix rows for command, FS, env, privilege, network, and approval-path abuse cases.
- Keep positive forensic matrix assertions for unlisted/allowed tool paths in the `contained` tier.
- Ensure tests reflect live-MCP-only required execution path where MCP matrix is mandated.
- Keep evidence integrity checks (pre/post hash and immutable checks) in gate validation.

Validation:

- `uv run --extra dev --extra full pytest packages/sift-core/tests/security -q`
- `SIFT_RUN3_GATE_STRICT=1 uv run --extra dev --extra full pytest packages/sift-core/tests/security/test_red_team_negative.py -q`
- `SIFT_RUN3_GATE_STRICT=1 uv run --extra dev --extra full pytest packages/sift-core/tests/security/test_red_team_positive.py -q`

Acceptance:

- Negative rows all fail closed; positive rows all pass within their acceptance window.
- Gate remains explicit, reproducible, and runnable from the active branch.

Note for agent behavior:

- Use `docs/RUN3-run_command-hardening-BUILD-PLAN.md` for sequencing (`WAVE 1/WAVE 2`) and status checks.
- Use targeted extracts from `docs/research/run_command-FINAL-SPEC.md` for exact policy constants.
- Do not load the entire FINAL-SPEC file in one session context.

## BATCH-OR0 - Rebase docs operating model around operator-hardening track

Dependencies: none.

Scope:

- `AGENTS.md`
- `docs/migration/task-batches.md`
- `docs/migration/Session-Notes.md`

Exact work:

- Keep tracker/model coherent with two active docs and fresh-session launch flow.
- Remove drift from legacy assumptions in these files; keep only active rules and references.
- Preserve the short-form migration model with no extra trackers.

Acceptance:

- Docs track updates validate with migration docs validators and are sufficient to onboard a session from context zero.

## BATCH-OR1 - Live VM inventory and SIFT tool path map

Dependencies: BATCH-OR0.

Scope:

- New `docs/inventory/sift-tool-inventory.md`
- `scripts/inventory-sift-tools.sh` (if kept)
- `install.sh` (if non-invasive fix discovered)

Exact work:

- Produce operator-usable inventory (tools, paths, symlink targets, provenance).
- Distinguish default/native tools vs. optional/operator-managed tools.
- Capture service/user/env/runtime anchor facts in one command-backed doc.

Acceptance:

- Inventory output is command-backed and safe; no secrets committed.

## BATCH-OR2 - File-state versus database-authority discovery map

Dependencies: BATCH-OR0.

Scope:

- New `docs/operator/state-authority-map.md`
- `supabase/migrations/**`, `packages/**`, `install.sh`

Exact work:

- For each mutable state surface, record DB authority vs file authority with migration status.
- Identify remaining legacy file-authority surfaces explicitly and mark follow-up owners.

Acceptance:

- Authority map table is complete enough to drive all future refactors and live-proof assertions.

## BATCH-OR3 - Full operator maintenance manual and variable dictionary

Dependencies: BATCH-OR1; BATCH-OR2; BATCH-OR4.

Scope:

- New `docs/operator/maintenance-guide.md`

Exact work:

- Add real-world maintenance, resets, handoff, service checks, backups, and incident recovery.
- Add a variable dictionary for installer, runtime, portal, and DB integration paths.

Acceptance:

- A fresh operator can execute core maintenance without opening source.

## BATCH-OR4 - RAG, forensic knowledge, and Hayabusa provenance manual

Dependencies: BATCH-OR0.

Scope:

- New `docs/operator/reference-data-provenance.md`
- `docs/regenerate/**` for stale claims cleanup handoff

Exact work:

- Document download, seed, cache, and refresh paths for RAG/knowledge/Hayabusa data and models.
- Call out immutable policy constraints and offline modes.

Acceptance:

- Provenance and refresh workflows are operationally executable and evidence-safe.

## BATCH-HR1 - Official hardening research matrix

Dependencies: BATCH-OR0.

Scope:

- New `docs/hardening/research-matrix.md`

Exact work:

- Build concise, source-backed hardening matrix with current component posture, risks, validation, and owner.
- Keep references to authoritative sources for every major component.

Acceptance:

- Every mapped component has risk + validation + owner and maps forward to an implementation batch or an explicit N/A decision.

## BATCH-HR2 - Component hardening audit guides

Dependencies: BATCH-HR1; BATCH-OR1; BATCH-OR2.

Scope:

- `docs/hardening/component-audit.md`

Exact work:

- Convert matrix into an executable audit check list for operator/reviewer workflows.
- Include concrete commands, expected signals, and residual risk notes.

Acceptance:

- Audit sections can be executed in order with deterministic outcomes.

## BATCH-HR3 - Installer and runtime hardening implementation wave

Dependencies: BATCH-HR2.

Scope:

- `install.sh`, `scripts/setup-supabase.sh`, `scripts/setup-addon.sh`
- `configs/**`, docker compose templates

Exact work:

- Land known hardening deltas from HR2 and keep changes incremental.
- Preserve clone-entry install flow and harden config loading/posture safely.

Acceptance:

- Targeted unit/shell checks pass and `/health` remains green on fresh/clean install.

## BATCH-AD1 - Add-on specification and author guide

Dependencies: BATCH-OR2; BATCH-HR1.

Scope:

- `docs/add-ons/spec.md`
- `docs/add-ons/author-guide.md`

Exact work:

- Document add-on boundary, manifest schema, transport, authority, registration, and conformance checklist.
- Keep OpenCTI and future Windows-triage clearly external/add-on-only.

Acceptance:

- Third-party authors can onboard add-on contracts without Gateway code changes.

## BATCH-AD2 - Add-on conformance tests and OpenCTI proof

Dependencies: BATCH-AD1; BATCH-OR1.

Scope:

- `scripts/setup-addon.sh`
- `packages/opencti-mcp/**`
- Gateway registry tests and operator workflows tied to add-ons

Exact work:

- Prove OpenCTI remains external and not part of native core installer behavior.
- Add conformance checks for manifest validity, env refs, gating, and hot reload behavior.

Acceptance:

- Proof for external add-on flow is repeatable and not mixed into core path.

## BATCH-CL1 - Legacy, pre-migration, and dead-reference cleanup

Dependencies: BATCH-OR2.

Scope:

- `packages/**`, `scripts/**`, `install.sh`, docs and tests with stale references

Exact work:

- Remove or reclassify stale names, pre-migration docs, and dead references as active or deprecated.
- Do not couple cleanup with behavior changes.

Acceptance:

- No live code points to removed assumptions or deprecated native paths unless intentionally retained.

## BATCH-CL2 - ProtocolSiftGateway rename and add_ons repository layout

Dependencies: BATCH-AD1; BATCH-CL1.

Scope:

- Repository layout, imports, installer path assumptions, docs, and setup references

Exact work:

- Execute rename/layout only with operator decision and migration-safe path planning.
- Preserve clone-entry install and compatibility where explicitly required.

Acceptance:

- New naming/layout supports clean build/install workflows and documented migration path.

## BATCH-PT1 - Portal operator workflow and health features

Dependencies: BATCH-OR3.

Scope:

- `packages/case-dashboard/frontend/src/**`
- `packages/case-dashboard/src/case_dashboard/routes.py`

Exact work:

- Keep portal operator workflow usable without REST-based analysis shortcuts.
- Improve health visibility, backend status, and case workflow.

Acceptance:

- Operator can login, create cases, and access operational health/status without exposing secrets.

## BATCH-PT2 - Portal RAG document management flow

Dependencies: BATCH-OR4; BATCH-PT1.

Scope:

- Portal upload/manage UI and API surfaces for knowledge documents
- `packages/forensic-rag-mcp/**`

Exact work:

- Add document add/list/refresh/retire for global knowledge plane only.
- Preserve provenance fields and anti-evidence-mixing policy.

Acceptance:

- Knowledge document lifecycle is operator-managed and queryable; no case-evidence auto-ingest.

## BATCH-TLS1 - Installer certificate and trust strategy

Dependencies: BATCH-HR1; BATCH-OR3.

Scope:

- `install.sh`, TLS assets and trust handoff instructions

Exact work:

- Finalize local-CA or domain-based trust path for installer and MCP endpoints.
- Add rotate/renew steps and explicit trust import guidance.

Acceptance:

- TLS posture is usable in lab and documented for operator trust bootstrap and renewals.

## BATCH-SB1 - Supabase default-key remediation (research-first; compose is fallback)

Status: RESEARCH-FIRST (operator 2026-06-14). The concern is the well-known default demo JWT secret +
anon/service_role keys that ship with every `supabase` CLI install. Before committing to a full
self-managed compose, research a lighter path that removes the default-key risk without it.

Dependencies: BATCH-HR3.

Scope:

- `scripts/setup-supabase.sh`, install bootstrap path; compose files only if research concludes they
  are required.

Exact work:

- RESEARCH (do first, write findings note): can the install rotate/replace the CLI's default
  `JWT secret` + regenerate `anon`/`service_role` keys in-place on the existing CLI/loopback stack
  (e.g. `supabase` config override + key re-mint + restart) so no installation runs with the public
  demo keys — WITHOUT standing up a full self-managed compose?
- Only if research shows in-place rotation is infeasible/insufficient: fall back to self-managed
  compose with generated secrets, keeping clone-entry flow and migration-safe rotation.

Acceptance:

- No installation runs with the public default demo keys. Documented remediation (rotation or compose)
  with end-to-end auth proven before any non-lab deployment.

## BATCH-CL3a - Supabase fail-closed operator-password re-verification

Dependencies: BATCH-PT1; BATCH-HR3.

Scope:

- `packages/case-dashboard/**`
- `packages/sift-gateway/**`
- `configs/gateway.yaml.template`

Exact work:

- Enforce Supabase fail-closed re-verification on sensitive operations.
- Migrate session-plane tests to Supabase-enveloped harness; keep behavior scoped.

Acceptance:

- Sensitive actions re-auth vs Supabase and fail-closed if control plane is unavailable.

## BATCH-CL3b - Complete the re-auth migration and cover remaining gaps

Dependencies: BATCH-CL3a.

Scope:

- `packages/case-dashboard/**`
- `packages/sift-core/src/sift_core/verification.py`
- `packages/sift-core/src/sift_core/backup_ops.py` and related re-auth tests

Exact work:

- Delete dead file-HMAC plane after proving zero live callers.
- Close known re-auth gaps (`create_principal`, DB-active branch activation) and retain commit-ledger concerns separately.

Acceptance:

- No dead re-auth call path remains for operator-sensitive actions; tests for fail-closed behavior stay green.

## BATCH-DB1 - FORCE RLS on `app.*` tables

Dependencies: none.

Scope:

- `supabase/migrations/**`

Exact work:

- Migrate to `FORCE ROW LEVEL SECURITY` for all RLS-enabled `app.*` tables with idempotent checks.
- Keep `service_role` behavior and confirm unaffected gateway path.

Acceptance:

- Migration runs cleanly and policy posture is provable by redacted DB checks.

## BATCH-UN1 - Component uninstaller and selective teardown

Dependencies: BATCH-AD2; BATCH-OR1; BATCH-OR2.

Scope:

- `scripts/uninstall.sh`
- `docs/operator/maintenance-guide.md`

Exact work:

- Ship one safe, dry-run-first teardown utility with explicit component flags.
- Preserve evidence safety as highest blast radius.

Acceptance:

- Dry-run is default; destructive mode is explicit; core teardown/reinstall path is documented.

## BATCH-RG1 - Documentation modernization pass

Dependencies: BATCH-OR2; BATCH-OR3; BATCH-OR4; BATCH-AD1; BATCH-HR2.

Scope:

- `docs/regenerate/**`

Exact work:

- Revalidate or archive stale migration-era docs and add fact-ownership index.
- Remove contradictory assumptions from active docs references.

Acceptance:

- `docs/regenerate/**` no longer contradicts current core/add-on boundaries and active operating facts.

## BATCH-LV1 - End-to-end live VM validation and Rocba proof

Dependencies: BATCH-OR3; BATCH-HR3; BATCH-AD2; BATCH-PT1; BATCH-TLS1; BATCH-DB1; BATCH-CL3a; BATCH-CL3b.

Scope:

- Live proof steps and `docs/migration/Session-Notes.md` closeout

Exact work:

- Full operator + MCP workflow proof on live VM: install, portal credentialing, tool listing, and forensic workflow.
- Confirm `opensearch_*`, `kb_*`, and hardened `run_command` posture with targeted real evidence.

Acceptance:

- `/health` and services remain healthy post-restart.
- MCP positive + negative proofs are recorded in session notes with sanitized evidence.
