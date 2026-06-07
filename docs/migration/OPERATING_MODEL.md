# Operating Model — SIFT Migration Development & Governance

This is the **process of record** for the SIFT migration (charter decision **D29**).
Every planning run, coding run, and review follows it. It exists to keep work
narrow, resumable, reviewable, and free of drift while the migration is delivered
by a single operator driving AI coding agents.

Three things are canonical and must never be contradicted silently:
- **`00_migration_charter.md`** — locked architecture **Decisions (D#)**.
- **This file** — the development loop, gates, and templates.
- **`REGISTER.md`** — open **Forks (F#)** awaiting a call and **Backlog (B#)** items.

If any other document conflicts with the charter, the charter wins and the other
document is corrected.

---

## 1. The loop: Plan → Build → Review → Land → Log

| Stage | Who | Output | Gate to advance |
| --- | --- | --- | --- |
| **Plan** | planning session | an `NN_*` candidate doc (§4 template): scope fence, decisions referenced, acceptance gates, ready-to-copy build prompt, forks raised | operator resolves blocking forks (logged in `REGISTER.md`) |
| **Build** | coding session in a **scoped worktree** | code, **one commit per unit**, golden snapshot / change-map updated | tests green per commit; scope fence respected |
| **Review** | operator + tools | `/code-review` (always); `/security-review` (auth/tokens/evidence/secrets/gateway); snapshot diff read | Definition of Done (§3) met; findings fixed or triaged |
| **Land** | operator | merge to integration branch `revamp/spg-v1` | merge-order rules honored (e.g. D27a before D27b; ID phases in cutover order) |
| **Log** | closing session | `MIGRATION_STATE.md` Run entry (§4 template); forks → D# or B# | Current Objective + Next Run refreshed |

Plan and Build run in **separate sessions**. The implementer must not redefine
scope; if the spec is wrong, it goes back to Plan, it is not "fixed" mid-build.

---

## 2. Branch & worktree governance

- **Integration branch:** `revamp/spg-v1`. `main` is the stable line. PRs merge into
  the integration branch; promotion to `main` is a separate, deliberate step.
- **One worktree per work unit**, branched off the current integration HEAD so merges
  are clean: `git worktree add ../sift-mcps-<unit> revamp/<unit>`.
- **Scope fence (hard):** each candidate doc declares the exact paths the build may
  touch. Nothing else is edited. Two units running in parallel must have **no file
  overlap** (this is what makes parallel work safe — e.g. backend revamp touches only
  `packages/*-mcp/**`, never the gateway/supabase, so it cannot collide with an
  identity-phase PR).
- **Merge order** is stated in the charter / candidate doc and honored on Land.
- **Pins** (Supabase tag, `fastmcp` version, etc.) are recorded in `MIGRATION_STATE.md`
  when introduced.

---

## 3. Definition of Done (every PR)

```
[ ] Only the declared scope-fence paths were touched (git diff --stat confirms)
[ ] Every acceptance gate in the candidate doc is met
[ ] Tests green; golden snapshot / change-map updated and diff reviewed
[ ] /code-review run; findings fixed or triaged with reasons
[ ] /security-review run IF this PR touches auth, tokens, evidence, secrets, or the gateway
[ ] MIGRATION_STATE Run entry added; forks resolved → D# (charter) or B# (register)
[ ] Charter unchanged UNLESS a decision was explicitly approved this cycle (no silent decisions)
[ ] Migration-docs format contract holds: `python3 scripts/validate_docs.py` passes (§8)
```

For runtime-behavior PRs, "tests green" includes the VM verification path in
`AGENTS.md` (host → rsync → VM) where the change runs on the SIFT VM.

---

## 4. Templates

### 4.1 Candidate / spec doc (`NN_<phase>.md`)
```
# NN — <Phase> (decision <D#>)
Status: planned | in-build | implemented (commit <hash>)
Scope fence: <exact paths the build may touch>
Decisions referenced: <D#, D#, …>

## Why (grounded)        # numbers/source, not assertion
## Design / contract     # the spec the build implements
## Acceptance gates      # the checklist Land is verified against
## Risks / forks         # anything raised → REGISTER.md F#
## Ready-to-copy build prompt
```

### 4.2 Build handoff prompt (proven shape — see docs 15 §12, 16 prompt)
```
ROLE & MODE → REQUIRED READING (ordered) → GROUND IN SOURCE (don't design from memory)
→ DELIVERABLE → HARD CONSTRAINTS (scope fence, decisions, guardrails)
→ OUTPUT DISCIPLINE (snapshot/change-map, STATE update, no silent decisions)
→ ACCEPTANCE → "end by listing any forks needing the operator's call"
```

### 4.3 Run-log entry (append to `MIGRATION_STATE.md`)
```
## Run <n> — <title>
<planning | coding> run. <"No runtime code changed." | commit <hash>>
Trigger: …
Findings / reconciliations: …
Operator decisions: …  (→ D# / F# / B#)
Files created/changed: …
Next: …
```

### 4.4 Register entry (`REGISTER.md`) — markdown tables, fixed columns (see §8)
```
| ID  | Question   | Raised           | Status        | Decision (date) | Becomes              | Affects           |
| F-n | <question> | Run <r>, <doc §> | OPEN|RESOLVED | <call + date>   | D-n / B-n / rejected | <D#/doc/snapshot> |

| ID  | Deferred work   | Source        | Status   | Do-by phase  |
| B-n | <deferred work> | F-n / Run <r> | OPEN|DONE | <phase/date> |
```
Fork rows = exactly 7 columns; backlog rows = exactly 5. These tables are parsed
by tooling — obey §8 and run the validator.

---

## 5. Decision & fork lifecycle

1. A planning run surfaces a **Fork (F#)** in its candidate doc and in `REGISTER.md`.
2. The operator decides. The decision becomes either:
   - a locked **Decision (D#)** in the charter (with date + the Run that locked it), or
   - a **Backlog item (B#)** in `REGISTER.md` (deferred work with a do-by phase), or
   - rejected (recorded, with reason).
3. A superseded decision is never deleted — it is marked **superseded by D#** so history
   is auditable (chain-of-custody discipline applies to decisions too).
4. No build run invents or changes a decision. If it must, it stops and raises a fork.

---

## 6. Reviews

- **`/code-review`** on every PR diff before Land.
- **`/security-review`** is mandatory when the diff touches: authentication, MCP/service
  tokens, the evidence chain/gate, secrets/credentials, response redaction, or the
  Gateway policy path. These are the surfaces where a regression is a security incident,
  not a bug. (Active examples: F-3 structured-content redaction, F-5 credential handling.)
- The **golden MCP-surface snapshot** diff is reviewed on any PR that changes tools,
  namespaces, schemas, prompts, or resources.

---

## 7. Pointers

- Locked decisions, cutover order, plane boundaries → `00_migration_charter.md`.
- Running state, run history, current objective, next run → `MIGRATION_STATE.md`.
- Open forks + backlog → `REGISTER.md`.
- Host/VM workflow, VM coordinates, Supabase pins → `AGENTS.md`.
- Per-phase specs → `NN_*.md` (e.g. 14 FastMCP design KB, 15 backend revamp,
  16 tool contracts, 17 gateway cutover, 18 target architecture acceleration).

---

## 8. Machine-readable conventions (load-bearing)

These three documents are not only read by humans and agents — they are **parsed
mechanically** by tooling (the Migration Mission Control dashboard, and any future
status/report generator). The structures below are therefore a **contract**: when a
run edits these files it must preserve them. If a format genuinely needs to change,
that is a decision — update this section, the validator, and the consumer together,
in the same run; do not let them drift apart silently (same chain-of-custody
discipline as the golden snapshot).

`docs/migration/CONVENTIONS.md` is the short contract loaded by agents.
`scripts/validate_docs.py` is the executable form of this contract. It is a
Definition-of-Done gate (§3) and must pass before Land. The legacy
`scripts/validate_migration_docs.py` wrapper remains for historical runbooks.

**`REGISTER.md`**
- `## Forks (F#)` and `## Backlog (B#)` H2 headers exist verbatim.
- Forks are a markdown table; rows begin `| F-<n> |` with **exactly 7 columns** in
  order: ID, Question, Raised, Status, Decision (date), Becomes, Affects.
- Backlog is a markdown table; rows begin `| B-<n> |` with **exactly 5 columns** in
  order: ID, Deferred work, Source, Status, Do-by phase.
- `Status` vocabulary: forks ∈ {`OPEN`, `RESOLVED`}; backlog ∈ {`OPEN`, `DONE`}
  (surrounding `**bold**` allowed). A `RESOLVED` fork has a non-empty Decision.
- IDs are unique. A fork whose Becomes cites `B-<n>` must have that backlog row.
- An `OPEN` fork has empty Decision and Becomes cells. A `RESOLVED` fork has a
  non-empty Decision and a Becomes cell that cites a `D#`, `B#`, or `rejected`.
- **Append-only columns:** add new columns at the end; never reorder/rename/remove.

**`MIGRATION_STATE.md`**
- Exactly **one** `## Current Objective` H2.
- The Current Objective contains a line with **`**Next:**`** — the dashboard and
  pipeline view derive the current stage from it.
- Exactly one global bold **`**Next:**`** marker exists in the file. Historical
  run entries use plain `Next:` only.
- A standalone `## Next Recommended Run` section is not allowed; live handoff
  belongs under `## Current Objective`.
- Run entries use `## Run <n> — <title>` (en/em-dash or hyphen). Run numbers unique.

**`00_migration_charter.md`**
- Decisions are a markdown table; rows begin `| D<n> |` (suffixes like `D27a` ok).
  IDs unique. A `## Cutover Order` section exists.
- The charter does not carry volatile current-status or next-session handoff
  sections; those belong in `MIGRATION_STATE.md`.
