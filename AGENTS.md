# Protocol SIFT Gateway Agent Instructions

This file is auto-loaded for agent sessions opened from this repo. Keep it as a
compact guardrail: stable invariants, safety rules, and validation expectations.
Do not use it as the active task queue.

## Operational Source Of Truth

Start from Linear for active work:

- Linear project `ProtocolSIFTGateway`: active issue queue, milestones, comments,
  assignments, relations, and current status.
- Linear document `Protocol SIFT Gateway Operating Model`: workflow, labels,
  issue/comment format, branch conventions, and agent handoff rules.
- The assigned Linear issue: goal, scope, hard constraints, acceptance, latest
  comments, blockers, linked decisions, and branches.
- `README.md`: stable product and architecture overview for this repo.
- `docs/new-docs/DEVELOPER_ENTRYPOINT.md`: package, flow, and code-routing map
  when a task needs developer onboarding context.
- `docs/new-docs/OPTIMIZATION_TRACK.md` and `docs/new-docs/AXIS_*_BUILD_PLAN.md`:
  optimization reference packs only when linked from Linear. They are not the
  active queue.

Repo `docs/migration/` is historical proof and migration context, not the active
queue. Use it only for targeted background when an issue needs a prior proof,
backlog ID, or migration-era decision.

Heavy temporary plans and research specs are intentionally outside the default
repo context. If a Linear issue links a local archived plan or spec, read only
the targeted sections needed for that issue.

When the codebase-memory MCP graph is available, use it to reduce context before
broad file reads: confirm index freshness, then prefer `search_graph`,
`trace_path`, and `get_code_snippet` for targeted routing. Verify graph findings
against current source and tests before editing.

Do not create extra migration runbooks. Working notes, blockers, branch names,
forks, decisions-needed, and handoffs belong in Linear issue comments.

## Current Architecture Decisions

- Gateway is the only policy boundary for portal and AI-agent operations.
- Supabase/Postgres is the authoritative control plane.
- Agents use MCP only. Portal REST is human-operator only, except when an issue
  explicitly asks for portal route implementation or tests.
- Evidence bytes are mounted or copied only by the operator on the SIFT VM.
- Evidence must be registered and sealed before analysis.
- Sensitive human actions require re-auth: case activation, evidence
  seal/unseal/ignore/retire, finding approval, report inclusion/export, and
  agent credential issuance.
- Reports include approved findings and approved supporting data only.
- RAG in shared pgvector is knowledge/reference only. Case evidence must not be
  silently embedded in shared RAG without explicit design.
- Core stack: Gateway, sift-core, portal, Supabase/Postgres, OpenSearch,
  forensic-rag-mcp/pgvector, forensic-knowledge, Hayabusa, local worker,
  installer/system services.
- External add-ons such as OpenCTI and Windows triage are add-on contract
  integrations, not native core install assumptions.
- `opensearch-mcp` has two live layers: `registry.py` is the deployed typed
  FastMCP 3 tool contract, and `opensearch_mcp.server` is the implementation
  engine it delegates into. Trace the served contract before deleting or
  renaming engine code.
- The real operator app is v2 at `/portal`.

## Host And VM Constraints

- Host repo path: `/home/yk/AI/SIFTHACK/sift-mcps`.
- Intended repo rename target: `ProtocolSiftGateway`; do not assume it has
  landed until the Linear rename issue is complete.
- SIFT VM: `sansforensics@192.168.122.81`.
- VM credentials are operator-held. Do not write passwords into Linear, commits,
  or docs.
- SIFT VM target Python: `/usr/bin/python3.12`.
- Do not install/download managed Python on the VM.
- Use `UV_NO_MANAGED_PYTHON=1` and `UV_PYTHON_DOWNLOADS=never` on the VM.
- Normal install: `git clone <repo> && cd <repo> && ./install.sh`; installer
  stages to `/opt/sift-mcps`.
- Services are system services. Confirm unit details before restart.
- Portal URL: `https://192.168.122.81:4508/portal/`.
- Portal login email: `examiner@operators.sift.local`.
- Temporary installer handoff credentials, when present, are on the VM and must
  not be copied into Linear or committed docs.

Useful live checks:

```bash
sudo systemctl show sift-gateway.service -p WorkingDirectory -p User -p EnvironmentFiles
sudo systemctl status sift-gateway.service sift-job-worker.service
curl -sk https://127.0.0.1:4508/health
```

Use a portal-issued agent/service credential for MCP smoke. Operator Supabase
login tokens are not expected for `/mcp`.

## Live VM Discipline

For live-impacting fixes:

- Code on the host first.
- Run targeted local validation.
- Sync only the needed changes to the active VM tree.
- Restart affected services.
- Prove `/health` and relevant MCP/portal behavior.
- Record sanitized proof in the Linear issue comment. Mirror it into repo docs
  only when the proof changes a durable invariant or must version with code.

Never commit raw JWTs, service-role keys, DSNs, passwords, private keys, or full
sensitive case/evidence paths.

## Work Discipline

- Start from the assigned Linear issue. If no issue exists, create one or ask for
  one before non-trivial work.
- Move issues by evidence: `Backlog` -> `Todo` -> `In Progress` -> `In Review`
  -> `Done`. Do not mark `Done` until acceptance is satisfied.
- Use Linear issue comments as session notes: start comment, material progress,
  handoff, validation, live proof, and blockers.
- For parallel work, use a parent/coordinator issue plus sub-issues or related
  issues. Freeze contracts up front and use manual worktrees off current local
  `main`.
- For `run_command` changes, treat the current code/tests and the assigned
  Linear issue as authority. Archived RUN-3/spec material is background only
  when explicitly linked by the issue or operator, and should be read by
  targeted extraction.
- Prefer existing repo patterns over new abstractions.
- Use `rg` or `rg --files` for search.
- Use `apply_patch` for manual file edits.
- Do not revert user changes in the working tree.
- Keep Linear and repo docs consistent when repo docs are touched.

## Verification

Run for documentation/planning changes:

```bash
python3 scripts/validate_docs.py
python3 scripts/validate_migration_docs.py
git diff --check
```

For implementation changes, also run targeted tests and script syntax checks for
touched files:

```bash
bash -n install.sh scripts/setup-addon.sh scripts/setup-supabase.sh
uv run --extra dev --extra full pytest <targeted test paths>
```

Use the repo `uv` environment; avoid system Python imports when workspace
packages are required.
