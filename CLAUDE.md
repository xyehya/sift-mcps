# CLAUDE.md — SIFT MCPs (Claude Code entry point)

`AGENTS.md` is the canonical agent-instruction file for this repo; everything in it
applies to Claude Code too. This file mirrors the parts a Claude session must load
first so the workflow is followed from the opening turn.

## Read first, in this order

1. `docs/migration/MIGRATION_STATE.md` — Current Objective + the latest Run; this is
   where you are.
2. `docs/migration/OPERATING_MODEL.md` — the development loop and gates you must
   follow (charter decision **D29**).
3. `docs/migration/00_migration_charter.md` — "Confirmed Decisions (Locked)" (D#) and
   "Cutover Order", before making any architectural claim.
4. `docs/migration/REGISTER.md` — open Forks (F#) and Backlog (B#).
5. `AGENTS.md` — host/VM workflow, VM coordinates, Supabase pins, safety rules.

## Development Workflow (MUST FOLLOW — D29)

- **Loop:** Plan → Build → Review → Land → Log. Plan and Build are separate sessions;
  a build session must not redefine its own scope.
- **Canonical sources, never contradicted silently:** the charter (Decisions D#),
  `OPERATING_MODEL.md` (process), `REGISTER.md` (Forks F# / Backlog B#).
- **Scope fence:** touch only the paths the active candidate doc declares; parallel
  units have zero file overlap. One worktree per unit off `revamp/spg-v1`; one commit
  per unit; update the golden snapshot / change-map.
- **Definition of Done** (`OPERATING_MODEL.md` §3) gates every PR. Run `/code-review`
  always; run `/security-review` whenever the diff touches auth, MCP/service tokens,
  the evidence chain/gate, secrets, response redaction, or the Gateway policy path.
- **No silent decisions.** If you must decide something not already locked, stop and
  raise a fork in `REGISTER.md` for the operator; it becomes a D# or B#.
- **Documentation-only by default.** `docs/migration/` is planning; do not introduce
  schemas, code, migrations, package/Docker changes, or behavioral rewrites unless the
  current run is explicitly scoped to them.
- **Log** every run in `MIGRATION_STATE.md` and resolve its forks.
- **Doc format is a contract.** `REGISTER.md`, `MIGRATION_STATE.md`, and the charter
  decision table are parsed by tooling (the Mission Control dashboard). Preserve the
  structures in `OPERATING_MODEL.md` §8; run `python3 scripts/validate_migration_docs.py`
  before Land (it is a Definition-of-Done gate). Changing a format = update §8, the
  validator, and the consumer in the same run — no silent drift.

## Where things are

- Locked decisions / cutover order → `00_migration_charter.md`
- Process, Definition of Done, templates → `OPERATING_MODEL.md`
- Open forks + backlog → `REGISTER.md`
- Run history, current objective, next run → `MIGRATION_STATE.md`
- Migration document index → `docs/migration/README.md`
- Per-phase specs and reference inventories → `docs/migration/NN_*.md`
- Host/VM + Supabase operational details → `AGENTS.md`

---

## Claude-specific note

Do not maintain a Claude-only pipeline map, backlog copy, or handoff summary in
this file. Use `MIGRATION_STATE.md` for current state and `REGISTER.md` for
open/carry-forward work so a fresh session cannot start from stale duplicated
state.
