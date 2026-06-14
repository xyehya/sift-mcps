# Protocol SIFT Gateway Agent Instructions

This repo is in operator-readiness and hardening after the core MVP migration. The
active workflow is the compact two-doc model plus execution-first tracking.

## Source Of Truth

Read in this order before work:

- `docs/migration/task-batches.md` (execution list, batch priorities, acceptance)
- `docs/migration/Session-Notes.md` (latest state, next actions, open backlog)
- `docs/RUN3-run_command-hardening-BUILD-PLAN.md` (run-command task execution order)
- `docs/research/run_command-FINAL-SPEC.md` (authoritative spec, read via targeted extraction only)

Do not create extra migration runbooks.

## Current Architecture Decisions

- Gateway is the only policy boundary for portal and AI-agent operations.
- Supabase/Postgres is the authoritative control plane.
- Agents use MCP only. Portal REST is human-operator only.
- Evidence bytes are mounted or copied only by the operator on the SIFT VM.
- Evidence must be registered and sealed before analysis.
- Sensitive human actions require re-auth: case activation, evidence seal/ignore/retire, finding
  approval, report inclusion/export, and agent credential issuance.
- Reports include approved findings and approved supporting data only.
- RAG in shared pgvector is knowledge/reference only. Case evidence must not be silently embedded in shared
  RAG without explicit design.
- Core stack: Gateway, sift-core, portal, Supabase/Postgres, OpenSearch, forensic-rag-mcp/pgvector,
  forensic-knowledge, Hayabusa, local worker, installer/system services.
- External add-ons (OpenCTI, Windows-triage candidate): add-on contract only, not native core install.

## Host And VM Constraints

- Host repo path: `/home/yk/AI/SIFTHACK/sift-mcps`.
- Intended repo rename target: `ProtocolSiftGateway` (tracked in BATCH-CL2). Do not assume rename has landed.
- SIFT VM: `sansforensics@192.168.122.81`.
- VM SSH password (operator): `forensics`.
- SIFT VM target Python: `/usr/bin/python3.12`.
- Do not install/download managed Python on VM.
- Use `UV_NO_MANAGED_PYTHON=1` and `UV_PYTHON_DOWNLOADS=never` on VM.
- Normal install: `git clone <repo> && cd <repo> && ./install.sh`; installer stages to `/opt/sift-mcps`.
- Services are system services. Prefer `sudo systemctl status|restart sift-gateway.service sift-job-worker.service` after
  confirming unit details.
- Portal URL: `https://192.168.122.81:4508/portal/`.
- Portal login email: `examiner@operators.sift.local`.
- Temporary password is in `/var/lib/sift/tokens/installer-handoff.txt` before forced reset.

## Live VM Discipline

For live-impacting fixes:

- Code on the host first, then targeted local validation, then VM sync.
- For VM work: sync to active tree, restart services, and prove health.
- Record sanitized live proof in `docs/migration/Session-Notes.md`.
- Never commit raw JWTs, service-role keys, DSNs, passwords, private keys, or full case paths.

Useful live checks:

```bash
sudo systemctl show sift-gateway.service -p WorkingDirectory -p User -p EnvironmentFiles
sudo systemctl status sift-gateway.service sift-job-worker.service
curl -sk https://127.0.0.1:4508/health
sudo cat /var/lib/sift/tokens/installer-handoff.txt
```

Use a portal-issued agent/service credential for MCP smoke. Operator Supabase login tokens are not expected
for `/mcp`.

## Work Discipline

- For every `run_command` code change, start with the RUN-3 section at top of
  `docs/migration/task-batches.md` and the latest `Session-Notes.md` entry.
- Prefer existing repo patterns over new abstractions.
- Use `rg` or `rg --files` for search.
- Use `apply_patch` for manual file edits.
- Do not revert user changes in the working tree.
- Keep `docs/migration/task-batches.md` and `docs/migration/Session-Notes.md` synchronized.
- Update batch checkbox only after acceptance checks pass.
- In single-session changes, add the latest `Session-Notes.md` note at the top.

## Verification

Run for documentation/planning changes:

```bash
python3 scripts/validate_docs.py
python3 scripts/validate_migration_docs.py
git diff --check
```

For implementation changes, also run targeted tests and script syntax checks for touched files:

```bash
bash -n install.sh scripts/setup-addon.sh scripts/setup-supabase.sh
uv run --extra dev --extra full pytest <targeted test paths>
```

Use the repo `uv` environment; avoid system Python imports when workspace packages are required.
