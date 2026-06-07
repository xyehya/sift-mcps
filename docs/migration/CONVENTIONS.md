# Documentation Conventions (load-bearing)

Rules marked **[V]** are enforced by `scripts/validate_docs.py` and gate every change.
The rest are review rules. Keep this file short; it is the contract.

## Principles
- **One home per fact.** Each fact lives in exactly one file; everywhere else *references* it. Never copy state - derive it.
- **No silent decisions.** Don't assume or invent; raise a Fork (`F#`) and let the operator decide.
- **No silent format change.** Changing a **[V]** structure means editing, in the same change: this file + `validate_docs.py` + every consumer (dashboards/tools).
- **Append-only history.** Mark superseded items `superseded by D#` / `historical`; never delete.
- **Ground claims.** Cite a file/section or command output; never write from memory.

## Where each fact lives (single source of truth)
- **Where we are / what's next** -> `MIGRATION_STATE.md` - one Current Objective + one `**Next:**` line. Nothing else states "what's next"; everything derives it.
- **Locked architecture** -> charter `00_migration_charter.md` `D#` table.
- **Open decisions / deferred work** -> `REGISTER.md` (`F#` forks / `B#` backlog).
- **Per-phase design** -> `NN_<phase>.md` (one per unit; declares its scope-fence paths). Landed/obsolete specs are relabelled `historical`.
- **Entry points** `CLAUDE.md` / `AGENTS.md` -> pointers + invariants only, never project state.

## Machine-readable structures

### REGISTER.md
- **[V]** Has the headings `## Forks (F#)` and `## Backlog (B#)`.
- **[V]** Forks = markdown table; each row starts `| F-<n> |` with **exactly 7 columns**, in order:
  `ID | Question | Raised | Status | Decision | Becomes | Affects`. `Status` in {`OPEN`, `RESOLVED`}.
- **[V]** Backlog = markdown table; each row starts `| B-<n> |` with **exactly 5 columns**, in order:
  `ID | Deferred work | Source | Status | Do-by`. `Status` in {`OPEN`, `DONE`}.
- **[V]** IDs unique. A `RESOLVED` fork has a non-empty Decision. If a fork's Becomes cites `B-<n>`, that backlog row exists.
- **[V]** An `OPEN` fork has empty Decision and Becomes cells. A `RESOLVED` fork has a non-empty Becomes cell that cites a `D#`, `B#`, or `rejected`.
- Append columns only at the end - never reorder/rename. Bold (`**RESOLVED**`) is allowed.

### MIGRATION_STATE.md
- **[V]** Exactly one `## Current Objective`, and it contains a `**Next:**` line.
- **[V]** Exactly one global bold `**Next:**` marker exists in the file. Historical run entries use plain `Next:` only.
- **[V]** No standalone `## Next Recommended Run` section; live handoff belongs under `## Current Objective`.
- **[V]** Run entries are `## Run <n> - <title>` (hyphen or en/em-dash); run numbers unique. Append-only.

### 00_migration_charter.md
- **[V]** Decisions = table; each row starts `| D<n> |` (suffixes like `D27a` ok); IDs unique.
- **[V]** Has a `## Cutover Order` section.
- **[V]** Does not carry volatile current-status or next-session handoff sections; those belong in `MIGRATION_STATE.md`.

## Definition of Done (docs)
`python3 scripts/validate_docs.py` passes - run entry appended - Current Objective + `**Next:**` refreshed -
every fork resolved -> `D#`/`B#` - no duplicated state introduced - superseded items relabelled.
