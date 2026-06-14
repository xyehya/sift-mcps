# Protocol SIFT Gateway Agent Instructions

This repo is in the operator-readiness and hardening phase after the core MVP
migration. Work from the real checkout, verify current code/runtime state, and
keep the docs useful for the next session.

## Source Of Truth

Read only last updates from 

- `docs/migration/Session-Notes.md` - latest decisions, live proof, blockers,
  and needs-input table.

## Current Architecture Decisions

- Gateway is the only policy boundary for portal and AI-agent operations.
- Supabase/Postgres is the authoritative control plane.
- Agents use MCP only. Portal REST is for human operators.
- Evidence bytes are mounted or copied only by the operator on the SIFT VM.
- Evidence must be registered and sealed before analysis.
- Sensitive human actions require re-auth: case activation, evidence
  seal/ignore/retire, finding approval, report inclusion/export, and agent
  credential issuance.
- Reports include approved findings and approved supporting data only.
- Core stack: `sift-gateway`, `sift-core`, operator portal, Supabase/Postgres,
  OpenSearch, forensic-rag-mcp/pgvector, forensic-knowledge, Hayabusa, local
  worker, installer/system services.
- External add-ons: OpenCTI and future Windows-triage style integrations. They
  must install/register separately through the add-on contract. They are not
  part of the native core installer.
- RAG is currently knowledge/reference only in Supabase pgvector. Case evidence
  must not be silently embedded into shared RAG without an explicit new design.

## Host And VM Constraints

- Host repo path: `/home/yk/AI/SIFTHACK/sift-mcps`.
- Intended repo rename target: `ProtocolSiftGateway` is tracked in BATCH-CL2;
  do not assume the rename has happened until that batch lands.
- SIFT VM: `sansforensics@192.168.122.81`.
- VM SSH password for operator login: `forensics`.
- SIFT VM target Python: `/usr/bin/python3.12`.
- Do not install or download managed Python on the SIFT VM.
- Use `UV_NO_MANAGED_PYTHON=1` and `UV_PYTHON_DOWNLOADS=never` on the VM.
- Normal VM install flow: `git clone <repo> && cd <repo> && ./install.sh`.
  The installer stages into `/opt/sift-mcps` before provisioning.
- Services are system services. Prefer `sudo systemctl status|restart
  sift-gateway.service sift-job-worker.service` after confirming current unit
  details.
- Portal URL: `https://192.168.122.81:4508/portal/`.
- Portal login email: `examiner@operators.sift.local`.
- Current temporary portal password lives in
  `/var/lib/sift/tokens/installer-handoff.txt` before forced reset. After reset,
  the operator password is not recoverable from docs; rotate/reset it through the
  supported operator/Supabase path.

## Live VM Discipline

For live-impacting fixes:

- Code on the host first.
- Run targeted local tests and doc validators before VM changes.
- Sync or pull to the active VM tree, restart services, and prove health.
- Record sanitized live proof in `docs/migration/Session-Notes.md`.
- Never paste raw JWTs, service-role keys, DSNs, passwords, private keys, or
  full case paths into committed docs.

Useful live checks:

```bash
sudo systemctl show sift-gateway.service -p WorkingDirectory -p User -p EnvironmentFiles
sudo systemctl status sift-gateway.service sift-job-worker.service
curl -sk https://127.0.0.1:4508/health
sudo cat /var/lib/sift/tokens/installer-handoff.txt
```

Use a portal-issued agent/service credential for MCP smoke. An operator Supabase
login token is not expected to authenticate to `/mcp`.

## Work Discipline

- Prefer existing repo patterns over new abstractions.
- Use `rg` or `rg --files` for search.
- Use `apply_patch` for manual file edits.
- Do not revert user changes in the working tree.
- Keep docs current when a batch lands.
- Update the batch checkbox only after acceptance checks pass.
- In a single-session change, add the latest note at the top of
  `docs/migration/Session-Notes.md`.

## Verification

Run for documentation/planning changes:

```bash
python3 scripts/validate_docs.py
python3 scripts/validate_migration_docs.py
git diff --check
```

For implementation changes, also run targeted tests for touched packages and any
shell syntax checks for touched scripts, for example:

```bash
bash -n install.sh scripts/setup-addon.sh scripts/setup-supabase.sh
uv run --extra dev --extra full pytest <targeted test paths>
```

Use the repo virtualenv/`uv` setup; do not rely on system Python imports when
package-local tests need workspace packages.
