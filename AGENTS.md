# SIFT MCPs Agent Instructions

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
  `OPERATING_MODEL.md` §8 and run `python3 scripts/validate_migration_docs.py`
  before Land — it is a Definition-of-Done gate.

## Where things are

- Locked decisions (D#) + cutover order → `docs/migration/00_migration_charter.md`
- Process, Definition of Done, templates → `docs/migration/OPERATING_MODEL.md`
- Open Forks (F#) + Backlog (B#) → `docs/migration/REGISTER.md`
- Run history, Current Objective, next run → `docs/migration/MIGRATION_STATE.md`
- Per-phase specs → `docs/migration/NN_*.md`. Active specs:
  - D27a backend revamp (landed) → `15_backend_tooling_revamp.md`, `16_backend_tool_contracts.md`
  - D27b gateway cutover (landed): design KB → `14_fastmcp3_supabase_integration.md`;
    implemented candidate/log → `17_gateway_cutover_d27b.md`
  - Final target architecture / acceleration plan → `18_target_architecture_acceleration.md`
  - PR03A / Batch A unified JWT implementation candidate/log (landed) →
    `19_pr03_unified_supabase_jwt_identity.md`
  - Portal/dashboard workflow + API inventory reference for PR03B planning →
    `20_portal_dashboard_inventory.md`
  - PR03B / Batch B active-case DB authority build candidate →
    `21_pr03b_active_case_db_authority.md`

## Current stage (read MIGRATION_STATE for the live version)

D27a, D27b, and **PR03A / Batch A (unified Supabase JWT identity)** are landed on
`revamp/spg-v1` (Runs 23-30). PR03A delivered Supabase JWT validation for REST
and FastMCP `/mcp`, shared Gateway principal resolution, portal Supabase
login/session, agent/service JWT issuance + revocation (D31), B-10 tool
authorization, and B-14 duplicate resolver cleanup. Run 33 implemented
**PR03B / Batch B: active-case DB authority** on branch
`codex/pr03b-active-case-db-authority`.

PR03B should be reviewed/landed if still unmerged. D32 locks the model:
Supabase/Postgres `app.active_case_state` wins; `SIFT_CASE_DIR`,
`SIFT_CASES_ROOT`, `gateway.yaml case.dir`, and `~/.sift/active_case` are not
authority and are not regenerated as active-case exports; no historical data
migration is in scope. If a future run discovers an installed API, Supabase
behavior, FastMCP proxy behavior, or repo invariant mismatch, **stop and raise a
fork** - do not improvise (D29).

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

## Current Migration Files

PR01 added the initial schema/test layout:

- `supabase/migrations/202606070101_identity_foundation.sql`
- `tests/db/test_pr01_identity_schema.py`
- `docs/migration/PR01_identity_schema_checks.md`
- `docs/migration/12_pr01.md`

PR02 implemented Phase ID-2, hash-only MCP/service token registry validation
with legacy `gateway.yaml` fallback:

- `packages/sift-gateway/src/sift_gateway/token_registry.py`
- `packages/sift-gateway/src/sift_gateway/token_gen.py`
- `packages/sift-gateway/src/sift_gateway/{auth.py,identity.py,mcp_endpoint.py,server.py}`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/sift-gateway/tests/test_phase13_auth.py`
- `packages/case-dashboard/tests/test_token_lifecycle.py`
- `docs/migration/13_pr02.md`
- `docs/migration/PR02_token_registry_checks.md`

For PR02 verification, use the runbook in
`docs/migration/PR02_token_registry_checks.md`. The targeted VM suites that
passed after rsync were:

```bash
cd ~/sift-mcps-test
.venv/bin/python -m pytest packages/sift-gateway/tests/test_phase13_auth.py packages/sift-gateway/tests/test_phase4.py packages/sift-gateway/tests/test_audit_envelope.py packages/sift-gateway/tests/test_portal_agent_block.py
.venv/bin/python -m pytest packages/case-dashboard/tests/test_token_lifecycle.py packages/case-dashboard/tests/test_session_middleware.py
```

PR02 did not add Supabase human auth, portal login replacement, active-case
propagation, evidence gate changes, job tables/workers/APIs/tools, OpenSearch
changes, parser changes, evidence behavior changes, audit data migration,
frontend redesigns, or legacy fallback removal.

PR03A is **landed** on `revamp/spg-v1`. Spec + status:

- `docs/migration/19_pr03_unified_supabase_jwt_identity.md` (status: implemented)
- `docs/migration/20_portal_dashboard_inventory.md` (reference inventory for
  PR03B portal/API turnover planning; not an implementation candidate)
- `docs/migration/21_pr03b_active_case_db_authority.md` (implemented PR03B
  candidate; Land/review source if branch is still unmerged)

It delivered unified Supabase JWT auth, principal mapping, portal Supabase auth,
agent/service JWT issuance + revocation (D31), and DB-backed MCP tool
authorization (B-10). One operational note for the deployed VM: the systemd
`sift-gateway` runs from `~/sift-mcps` with config `~/.sift/gateway.yaml`; a
production rollout of the new auth code + the `auth:` config block + Supabase env
(`SUPABASE_URL`/`SUPABASE_ANON_KEY`/`SUPABASE_SERVICE_ROLE_KEY`) is part of the
installer follow-up below, not PR03A.

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
