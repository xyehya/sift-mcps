# SIFT MCPs Agent Instructions

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

This repository is the host-side source workspace for the SIFT VM Autonomous
DFIR Agent migration. Active code edits happen on the host in:

```bash
/home/yk/AI/SIFTHACK/sift-mcps
```

The SIFT machine is a separate VM used for active runtime testing. Do not assume
the host Python, OS, services, or paths match the VM.

## Migration Project

The migration moves SIFT from file/env authority toward a Gateway-mediated
control-plane architecture:

- Supabase Local/Postgres is the authoritative control plane for cases,
  identity/JWT principal mappings, transitional MCP/service tokens, jobs, audit,
  evidence metadata, findings, reports, RAG, and skills.
- The Gateway remains the mandatory policy boundary for REST, portal, MCP tools,
  token validation, authorization, audit, and active-case propagation.
- Per D30, the final credential target is Supabase-issued JWTs for humans,
  agents/MCP clients, workers, and services. PR02 hash-only MCP/service tokens
  remain only as an explicit compatibility bridge until the legacy auth sunset.
- OpenSearch remains the derived search/data plane, not authority for case
  permissions, token validity, evidence integrity, jobs, or audit.
- SIFT VM workers execute durable jobs claimed from Postgres.

Locked migration decisions and cutover order are in
`docs/migration/00_migration_charter.md`. Current handoff state is in
`docs/migration/MIGRATION_STATE.md`.

## Development Workflow (MUST FOLLOW)

All work on this migration follows the operating model in
`docs/migration/OPERATING_MODEL.md` (charter decision **D29**). Do not freelance
around it. In short:

- **Loop:** Plan → Build → Review → Land → Log. Plan and Build are separate
  sessions; a build session must not redefine its own scope.
- **Three canonical sources, never contradicted silently:**
  `00_migration_charter.md` (locked Decisions D#), `OPERATING_MODEL.md` (process),
  `REGISTER.md` (open Forks F# + Backlog B#).
- **Scope fence:** every build run touches only the paths its candidate doc
  declares. Parallel work units must have zero file overlap.
- **One worktree per work unit**, branched off `revamp/spg-v1`; one commit per unit;
  update the golden snapshot / change-map.
- **Definition of Done** (OPERATING_MODEL §3) gates every PR. `/code-review` always;
  `/security-review` whenever the diff touches auth, tokens, evidence, secrets, or
  the Gateway.
- **No silent decisions.** A run that needs to decide something stops and raises a
  fork in `REGISTER.md`; the operator turns it into a D# or B#.
- **Log** every run in `MIGRATION_STATE.md` and resolve its forks.
- **Doc format is a contract** (parsed by tooling): keep the structures in
  `docs/migration/CONVENTIONS.md` and run `python3 scripts/validate_docs.py`
  before Land — it is a Definition-of-Done gate.

## Where things are

- Locked decisions (D#) + cutover order → `docs/migration/00_migration_charter.md`
- Process, Definition of Done, templates → `docs/migration/OPERATING_MODEL.md`
- Open Forks (F#) + Backlog (B#) → `docs/migration/REGISTER.md`
- Run history, Current Objective, next run → `docs/migration/MIGRATION_STATE.md`
- Per-phase specs and reference inventories → `docs/migration/NN_*.md`; use
  `docs/migration/README.md` as the index.

## Current stage

Read `docs/migration/MIGRATION_STATE.md` for the live Current Objective, latest
run, next action, landed history, and carried backlog. Do not copy that state
into this entry point.

## Mandatory Host/VM Workflow

Code on host, copy changes to VM, test on VM:

```bash
rsync -avz --exclude '.git' --exclude '.venv' --exclude '__pycache__' --exclude '*.pyc' \
  /home/yk/AI/SIFTHACK/sift-mcps/ sansforensics@192.168.122.81:~/sift-mcps-test/
```

The VM accepts password auth:

```bash
sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 '<command>'
```

VM details:

- Host: `192.168.122.81`
- User/password: `sansforensics` / `forensics`
- OS: Ubuntu 24.04.4 LTS
- SIFT Python: `/usr/bin/python3.12` (Python 3.12.3)
- Gateway: `https://192.168.122.81:4508`
- Portal: `https://192.168.122.81:4508/portal/`
- VM uv binary: `/home/sansforensics/.local/bin/uv`

The VM's non-interactive SSH PATH may not include `uv`; use the absolute path.

## Python And uv Invariants

- Never download or install a managed Python on the SIFT VM.
- Always use `/usr/bin/python3.12` on the VM.
- Always set these when syncing dependencies on the VM:

```bash
UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never
```

For the SIFT test copy, prefer a narrow sync matching the requested tests. For
core Gateway/portal/schema work:

```bash
cd ~/sift-mcps-test
UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never \
  ~/.local/bin/uv sync --extra core --group dev --python /usr/bin/python3.12
```

Avoid `uv sync --all-packages` unless the task genuinely needs every optional
package. It can pull large GPU/ML packages and stress VM disk space.

After syncing, verify imports:

```bash
cd ~/sift-mcps-test
.venv/bin/python --version
.venv/bin/python - <<'PY'
import yaml
import mcp
import fastmcp
import sift_core
import sift_gateway
print("imports_ok")
PY
```

## Gateway Runtime Checks

For Python source-only deploys after syncing:

```bash
sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 \
  'systemctl --user restart sift-gateway'

sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 \
  'curl -s -k https://localhost:4508/api/v1/health | python3 -m json.tool'
```

Useful VM commands:

```bash
sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 \
  'systemctl --user status sift-gateway'

sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 \
  'journalctl --user -u sift-gateway -n 50'
```

## Supabase On The SIFT VM

Supabase was installed manually on the VM for PR01 testing:

- Project directory: `/home/sansforensics/supabase-project`
- Source sparse clone: `/home/sansforensics/supabase-src-v1.26.05`
- Pinned Supabase tag: `v1.26.05`
- Pinned commit: `23b55d63485e51919d1b4c05b03d33a9edc1f06d`
- Public/API URL configured in `.env`: `http://192.168.122.81:8000`
- Secrets live only in the VM `.env`; do not copy them into the repo.
- Key generation used Supabase's pinned `utils/generate-keys.sh` and
  `utils/add-new-auth-keys.sh`.
- The pinned Docker layout does not include `run.sh`; use `docker compose`.

Start/check the stack:

```bash
sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 \
  'cd ~/supabase-project && docker compose up -d --wait && docker compose ps'
```

Postgres syntax check pattern for migrations without leaving tables behind:

```bash
sshpass -p 'forensics' ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 \
  'cd ~/supabase-project && (printf "begin;\n"; cat ~/sift-mcps-test/supabase/migrations/<migration>.sql; printf "\nrollback;\n") | docker compose exec -T db psql -U postgres -d postgres -v ON_ERROR_STOP=1'
```

## Migration history and runbooks

Use `docs/migration/README.md` for the migration document index,
`docs/migration/MIGRATION_STATE.md` for landed run history and current handoff,
and the `docs/migration/PR*_checks.md` files for phase-specific verification
runbooks. Keep phase status and passed-test evidence in the migration docs, not
in this entry point.

## Installer Follow-up

After all required VM packages and services have been installed and tested
end-to-end, update the repository installer script (`install.sh`, or any future
installer wrapper) so the setup becomes reproducible and idempotent. Preserve
these invariants in the installer:

- `/usr/bin/python3.12` only on the SIFT VM.
- `UV_NO_MANAGED_PYTHON=1`.
- `UV_PYTHON_DOWNLOADS=never`.
- Venv integrity check: rebuild on Python-version mismatch; repair broken
  imports with `uv sync`.
- Post-sync smoke imports for `yaml`, `mcp`, `fastmcp`, `sift_core`, and
  `sift_gateway`.
- Do not hand-roll Supabase secrets or JWT keys; use pinned Supabase helper
  scripts.

## Safety Rules

- Do not change runtime behavior unless the current PR explicitly scopes it.
- Do not touch `.DS_Store`, generated caches, local Supabase state, DB dumps, or
  unrelated local config.
- Do not store raw MCP/service tokens or Supabase secrets in repo files.
- Do not add job tables/workers/evidence/OpenSearch/frontend changes to identity
  phases unless the phase explicitly includes them.
