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
