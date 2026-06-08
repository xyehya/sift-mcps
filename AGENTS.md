# SIFT MVP Sprint Agent Instructions

This repo is in fast MVP sprint mode. The previous migration document forest was
purged. Do not use stale migration docs from memory or old branches as authority.

## Source of truth

Read these three files first and keep them current:

- `docs/migration/Migration-Spec.md` - architecture, data flow, journey,
  constraints, and Definition of Done.
- `docs/migration/task-batches.md` - executable batch tracker for parallel work.
- `docs/migration/Session-Notes.md` - latest change log plus forks, blockers,
  and backlog.

`AGENTS.md` and `CLAUDE.md` are instruction pointers only. They must not carry
volatile project state.

## Sprint operating rules

- No deferral on dependent work: resolve the blocker or fork before continuing
  the dependent batch.
- Independent batches may proceed in parallel in separate worktrees.
- One worktree per batch. Keep scope to the files listed in that batch.
- Update the batch checkbox only after its acceptance checks pass.
- In a single-session change, add the latest session note at the top of
  `Session-Notes.md`.
- In parallel worker branches, do not edit shared migration docs unless the
  batch scope explicitly owns docs. Return a landing log block instead; the
  integration/conductor session updates `task-batches.md` and
  `Session-Notes.md` after merge.
- Run `python3 scripts/validate_docs.py` before landing any doc/governance
  change.
- Keep implementation docs minimal. Do not create more files under
  `docs/migration` unless `Migration-Spec.md` is explicitly changed first.

## Security invariants

- Gateway is the only policy boundary for portal and AI-agent operations.
- Supabase/Postgres is the authoritative control plane.
- Agents use MCP only for the MVP. Portal REST is for human operators.
- The AI agent never receives absolute evidence paths, case paths, mount paths,
  DB credentials, OpenSearch credentials, service-role keys, or shell access.
- Evidence bytes are mounted or copied only by the operator on the SIFT VM.
- Evidence must be registered and sealed before analysis.
- Sensitive human actions require password/HMAC re-auth: case activation,
  evidence seal/ignore/retire, finding approval, report inclusion/export, and
  agent credential issuance.
- OpenSearch, RAG, OpenCTI, Windows triage, and forensic knowledge are derived
  or reference planes. They do not authorize cases or evidence.
- Reports include approved findings and approved supporting data only.

## Host and VM constraints

- Host repo path: `/home/yk/AI/SIFTHACK/sift-mcps`.
- SIFT VM target Python: `/usr/bin/python3.12`.
- Do not install or download managed Python on the SIFT VM.
- Use `UV_NO_MANAGED_PYTHON=1` and `UV_PYTHON_DOWNLOADS=never` on the VM.
- Do not store raw MCP/service tokens, Supabase secrets, OpenSearch passwords,
  or local VM secrets in repo files.

## Work discipline

- Prefer existing package patterns over new abstractions.
- Keep changes tightly scoped to the active batch.
- Do not revert unrelated user changes.
- Run targeted tests for touched code and return validation evidence in the
  final response or landing log.

## Live VM Smoke Tests

Live VM coordinates, replay steps, and current BATCH-V1 validation state live in
`docs/migration/Session-Notes.md`. Do not put raw passwords, Supabase keys,
OpenSearch credentials, or local VM secrets in repo files; use local shell
environment variables such as `SSHPASS` when a test session needs them.
