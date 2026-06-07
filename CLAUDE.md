# CLAUDE.md — SIFT MCPs (Claude Code entry point)

## Documentation Conventions (load-bearing)

Rules marked **[V]** are enforced by `scripts/validate_docs.py` and gate every change.
The rest are review rules. Keep this section short; it mirrors `docs/migration/CONVENTIONS.md`.

### Principles
- **One home per fact.** Each fact lives in exactly one file; everywhere else *references* it. Never copy state - derive it.
- **No silent decisions.** Don't assume or invent; raise a Fork (`F#`) and let the operator decide.
- **No silent format change.** Changing a **[V]** structure means editing, in the same change: this section + `docs/migration/CONVENTIONS.md` + `validate_docs.py` + every consumer (dashboards/tools).
- **Append-only history.** Mark superseded items `superseded by D#` / `historical`; never delete.
- **Ground claims.** Cite a file/section or command output; never write from memory.

### Where each fact lives (single source of truth)
- **Where we are / what's next** -> `MIGRATION_STATE.md` - one Current Objective + one `**Next:**` line. Nothing else states "what's next"; everything derives it.
- **Locked architecture** -> charter `00_migration_charter.md` `D#` table.
- **Open decisions / deferred work** -> `REGISTER.md` (`F#` forks / `B#` backlog).
- **Per-phase design** -> `NN_<phase>.md` (one per unit; declares its scope-fence paths). Landed/obsolete specs are relabelled `historical`.
- **Entry points** `CLAUDE.md` / `AGENTS.md` -> pointers + invariants only, never project state.

### Machine-readable structures

#### REGISTER.md
- **[V]** Has the headings `## Forks (F#)` and `## Backlog (B#)`.
- **[V]** Forks = markdown table; each row starts `| F-<n> |` with **exactly 7 columns**, in order: `ID | Question | Raised | Status | Decision | Becomes | Affects`. `Status` in {`OPEN`, `RESOLVED`}.
- **[V]** Backlog = markdown table; each row starts `| B-<n> |` with **exactly 5 columns**, in order: `ID | Deferred work | Source | Status | Do-by`. `Status` in {`OPEN`, `DONE`}.
- **[V]** IDs unique. A `RESOLVED` fork has a non-empty Decision. If a fork's Becomes cites `B-<n>`, that backlog row exists.
- **[V]** An `OPEN` fork has empty Decision and Becomes cells. A `RESOLVED` fork has a non-empty Becomes cell that cites a `D#`, `B#`, or `rejected`.
- Append columns only at the end - never reorder/rename. Bold (`**RESOLVED**`) is allowed.

#### MIGRATION_STATE.md
- **[V]** Exactly one `## Current Objective`, and it contains a `**Next:**` line.
- **[V]** Exactly one global bold `**Next:**` marker exists in the file. Historical run entries use plain `Next:` only.
- **[V]** No standalone `## Next Recommended Run` section; live handoff belongs under `## Current Objective`.
- **[V]** Run entries are `## Run <n> - <title>` (hyphen or en/em-dash); run numbers unique. Append-only.

#### 00_migration_charter.md
- **[V]** Decisions = table; each row starts `| D<n> |` (suffixes like `D27a` ok); IDs unique.
- **[V]** Has a `## Cutover Order` section.
- **[V]** Does not carry volatile current-status or next-session handoff sections; those belong in `MIGRATION_STATE.md`.

### Definition of Done (docs)
`python3 scripts/validate_docs.py` passes - run entry appended - Current Objective + `**Next:**` refreshed -
every fork resolved -> `D#`/`B#` - no duplicated state introduced - superseded items relabelled.

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
  structures in `docs/migration/CONVENTIONS.md`; run `python3 scripts/validate_docs.py`
  before Land (it is a Definition-of-Done gate). Changing a format = update
  `CONVENTIONS.md`, the validator, and the consumer in the same run — no silent drift.

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
