# new-docs Maintenance Policy

**Purpose**: keep `docs/new-docs/` a *live* reference so changes don't drift into a stale map,
and nobody has to re-derive the codebase from scratch in a future session. Efficiency rule:
**tie doc updates to changes, at the commit/PR gate — not per keystroke, not "someday."**

> Origin: these docs were generated in one pass by an AI coding agent (the same one that wrote
> `CODEBASE_ASSESSMENT.md`). They are a solid reference but were point-in-time; a few commits
> have landed since. This policy makes freshness a process step instead of a periodic rescue.

## 1. Doc taxonomy (different docs, different rules)

| Class | Docs | Maintenance rule |
|-------|------|------------------|
| **Point-in-time** | `CODEBASE_ASSESSMENT.md` | Frozen judgement at a date. **Never silently rewrite history.** Correct factual drift in place; record changes as a **dated addendum** (see the 2026-06-16 addendum there). |
| **Live-reference** | `SYSTEM_OVERVIEW.md`, `DATA_FLOW.md`, `DATA_STRUCTURES.md`, `KEY_FUNCTIONS.md`, `ALGORITHM_FLOWS.md`, `KEY_QUESTIONS.md`, `DEVELOPER_ENTRYPOINT.md` | Must track code. Update the affected sections **in the same commit** that changes the code they describe. |
| **Living-plan** | `OPTIMIZATION_TRACK.md`, `AXIS_*_BUILD_PLAN.md`, this file | Update as decisions land / units complete. Mark resolved decisions with a date. |

## 2. Per-doc header contract

Every live-reference and living-plan doc carries, near the top:

```
> Covers: <comma-separated paths/globs this doc describes>
> Class: live-reference | living-plan | point-in-time
> Last validated: <git short-sha> (<YYYY-MM-DD>)
```

`Covers:` is what makes targeted updates possible — a change knows which docs it must touch by
intersecting its scope-fence paths with each doc's `Covers:`.

## 3. The cadence (answer to "every change / group / major / gate?")

**Per logical unit / change-group, at the commit-PR gate.** Concretely, a unit's Definition of
Done gains one line:

> **Docs**: for each live-reference doc whose `Covers:` intersects this unit's scope fence,
> update the affected section and bump its `Last validated:` to this commit. Point-in-time docs
> get a dated addendum only if a fact they assert changed.

- **Small/grouped changes** → update the intersecting sections in the same commit.
- **Major/structural changes** (e.g. Axis B deleting file-mode) → update the doc's prose, not
  just numbers, and bump `Last validated:`.
- **No change to covered code** → do nothing; the checker won't flag it.

This is the efficient middle: you touch only intersecting sections, never re-map the whole repo.

## 4. Automated staleness checker (CI — Axis A)

`scripts/check_newdocs_refs.py` (to build in Axis A), run in CI:

1. **Reference resolution** — parse `file:line` and backticked `path` / `symbol` references in
   each live-reference doc; **fail** on a dangling file path; **warn** when a cited symbol no
   longer appears in the named file (line numbers drift constantly, so treat raw line numbers
   as hints — verify by symbol, not by line).
2. **Covers-vs-diff drift** — for each doc, if the PR diff touches a path under its `Covers:`
   but the doc's `Last validated:` sha didn't advance, **warn**: "`<doc>` may be stale —
   covered code changed." This points the author at the exact doc/section instead of a rescan.
3. Scope: `docs/new-docs/` only. Keep separate from `scripts/validate_docs.py` /
   `validate_migration_docs.py` (those govern `docs/migration/` and are a different contract).

Checker output is advisory-with-teeth: dangling file ref = hard fail; symbol/Covers drift =
warning surfaced on the PR.

## 5. Update-vs-append rule (so docs stay current *and* auditable)

- **Facts** (counts, file refs, behavior) → correct **in place**.
- **Decisions / history / judgements** → **append** a dated note; don't overwrite the prior
  statement (mirrors the repo's append-only history discipline).

## 6. Bootstrapping (do once, in Axis A)

- Add the §2 header to each live-reference + living-plan doc (`OPTIMIZATION_TRACK.md` and
  `AXIS_B_BUILD_PLAN.md` already carry decision dates; add explicit `Covers:` lines).
- Build `scripts/check_newdocs_refs.py` and wire it into the CI workflow.
- One-time pass: skim the 6 live-reference docs for the same drift classes already fixed in
  `CODEBASE_ASSESSMENT.md` (counts, retired-subsystem mentions, moved symbols) and stamp
  `Last validated:`.
