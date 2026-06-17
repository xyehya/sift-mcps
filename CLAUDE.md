# Protocol SIFT Gateway Agent Instructions

## Operational Source Of Truth

Linear is the active queue for this repo. Start from Linear before broad repo
search or old planning docs:

- Project: `ProtocolSIFTGateway`.
- Operating model document attached to the Linear project:
  `Protocol SIFT Gateway Operating Model`.
- Assigned issue or coordinator issue: goal, scope, hard constraints,
  acceptance, latest comments, blockers, linked decisions, and branch names.
- `docs/new-docs/DEVELOPER_ENTRYPOINT.md`: package, flow, and code-routing map
  when developer onboarding context is needed.
- `docs/new-docs/OPTIMIZATION_TRACK.md` and
  `docs/new-docs/AXIS_*_BUILD_PLAN.md`: reference packs only when linked from
  Linear. They are not the active queue.


The codebase-memory MCP graph is available; use it to reduce context before
broad file reads. Confirm index freshness and reindex if needed, then prefer
`search_graph`, `trace_path`, and `get_code_snippet` for targeted routing.
Verify graph findings against current source and tests before editing.

Working notes, blockers, branch names, forks, decisions-needed, and handoffs
belong in Linear issue comments.

## Linear CLI Workflow

Use `linear-cli` for Linear work. Prefer JSON output, compact fields, and
explicit filters so agents do not flood context.

### Fast helpers (verified)

Known IDs — do not re-query:

- Team `XYE`. Project `ProtocolSIFTGateway`
  (id `c0396776-2026-47ad-8ef1-4580315f9adf`).

JSON shapes (for `jq`; `jq` 1.8 is installed): `i get` is a FLAT object —
`.identifier`, `.state.name`, `.project.name`, `.priority`,
`.labels.nodes[].name`, `.parent.identifier`, `.title`, `.url`. `cm list` is
`{identifier, title, comments:{nodes:[{body, createdAt, user:{name}, id}]}}`.

Slim reads (keep context small):

```bash
# one issue, key fields only
linear-cli i get XYE-26 --no-cache -o json \
  | jq -c '{id:.identifier, state:.state.name, prio:.priority, labels:[.labels.nodes[].name]}'

# last 3 comments, one truncated line each (newest last)
linear-cli cm list XYE-26 -o json \
  | jq -r '.comments.nodes[-3:][] | "[\(.createdAt[0:16])] \(.user.name): \(.body|gsub("\n";" ")|.[0:120])"'

# project issue list, compact, only the fields you need
linear-cli i list --project ProtocolSIFTGateway --output json --compact \
  --fields identifier,title,state.name,priority
```

Add a comment / set state:

```bash
linear-cli cm create XYE-26 -b "Result: ... Validation: ... Next: ..."
linear-cli i update XYE-26 -s "In Review"   # Backlog|Todo|In Progress|In Review|Done
```

Create an issue in the project — note `i create` has NO `--project` flag; set it
afterward with `i update`:

```bash
ID=$(linear-cli i create "Title" -t XYE -d "markdown body" --id-only -q | tail -1)
linear-cli i update "$ID" --project ProtocolSIFTGateway -p 3   # -p = priority 0-4
```

Use `--no-cache` when reading state right after a write.

First checks:

```bash
linear-cli p list --output json --compact --fields id,name,state,url
linear-cli d list --output json --compact --fields id,title,url
linear-cli i get XYE-12 --output json
linear-cli cm list XYE-12 --output json
linear-cli rel list XYE-13 --output json
```

Useful query patterns:

```bash
linear-cli i list --project ProtocolSIFTGateway --output json --compact \
  --fields identifier,title,state.name,priority,labels.nodes.name
linear-cli i list --project ProtocolSIFTGateway --state Todo --output json \
  --compact --fields identifier,title,parent.identifier,labels.nodes.name
linear-cli i list --project ProtocolSIFTGateway --label agent-ready \
  --output json --compact --fields identifier,title,state.name
linear-cli ms list -p ProtocolSIFTGateway --output json
linear-cli v list --output json
```

Known CLI friction and fallbacks:

- `linear-cli ms list -p ProtocolSIFTGateway --output json --compact` returns
  milestone objects, but not milestone issue membership or progress. Use raw
  GraphQL when you need the issues inside a milestone.
- `linear-cli i list --fields projectMilestone.name` may omit the milestone
  field even when requested. Verify milestone assignment with `linear-cli i get`
  for specific issues, or use raw GraphQL for bulk checks.
- `linear-cli d get "<title>"` may fail for Linear documents. Run
  `linear-cli d list --fields id,title,url`, then fetch the document by id.
- `linear-cli l list` may return no labels without a type filter. Use
  `linear-cli l list --type issue --output json --compact` for issue labels.
- `linear-cli rel list <issue>` returns both `relations` and
  `inverseRelations`. Build dependency graphs from both directions: a
  `relations[].type == "blocks"` edge means the queried issue blocks the
  related issue; an `inverseRelations[].type == "blocks"` edge means the listed
  issue blocks the queried issue.

GraphQL fallbacks for missing CLI fields:

```bash
linear-cli api query 'query {
  projectMilestone(id: "MILESTONE_ID") {
    name
    issues(first: 50) { nodes { identifier title state { name } } }
  }
}' --output json

linear-cli api query 'query {
  issue(id: "XYE-12") {
    identifier
    state { name }
    projectMilestone { name }
    labels { nodes { name } }
    comments(first: 3) { nodes { createdAt body user { name } } }
  }
}' --output json
```

Common updates:

```bash
linear-cli cm create XYE-13 -b "Starting..."
linear-cli i update XYE-13 -s "In Progress"
linear-cli i update XYE-13 -l agent-ready -l component:ci
linear-cli rel add XYE-13 -r blocks XYE-14
linear-cli rel parent XYE-13 XYE-12
linear-cli v create "ProtocolSIFTGateway Ready" --shared -t XYE \
  --filter-json filters.json
```

Use raw GraphQL only when the CLI command surface cannot express a needed read
or mutation:

```bash
linear-cli api query '{ viewer { id name } }' --output json
```

CLI discipline:

- Use `linear-cli <command> --help` before uncommon mutations.
- Use `--dry-run` where supported for bulk or risky edits.
- Do not use `linear-cli done`; this repo requires proof before `Done`.
- Do not delete milestones, labels, views, comments, projects, or webhooks.
- Use `--no-cache` when checking current state after recent changes.
- Keep comments concise: summarize proof, do not paste large logs.

## Linear Operating Rules

- Start from the assigned Linear issue. If no issue exists, create one or ask for
  one before non-trivial work.
- Move issues by evidence: `Backlog` -> `Todo` -> `In Progress` -> `In Review`
  -> `Done`. Do not mark `Done` until acceptance and proof are recorded.
- Use Linear issue comments as session notes: start comment, material progress,
  handoff, validation, live proof, and blockers.
- For orchestration, start from the coordinator issue, read children, relations,
  labels, milestones, and latest comments, then select the earliest
  `agent-ready` issue with no open blockers.
- For implementation, work exactly one assigned executable issue unless the
  issue says otherwise.
- Create fork issues for real out-of-scope work, discovery issues for
  investigation, and decision issues when operator choice changes behavior,
  security posture, workflow, live-VM risk, or durable architecture.
- For parallel work, use a parent/coordinator issue plus sub-issues or related
  issues. Freeze contracts up front and use manual worktrees off current local
  `main`.
- Keep Linear and repo docs consistent when repo docs are touched.

Start comment format:

```text
Starting.
Branch: <branch or none yet>.
Plan: <3-5 concrete steps>.
Risk/gates: <operator/live/security gates>.
```

Handoff comment format:

```text
Result: DONE | IN REVIEW | BLOCKED.
Branch/commits: <branch and commit ids>.
Changed: <high-signal file/component list>.
Validation: <commands and results>.
Live proof: <sanitized proof or N/A>.
Next: <exact next action>.
```

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
- SIFT VM: `sansforensics@192.168.122.81` - ssh key-based login - no passwsord needed
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
- Sync only the needed changes to the active VM tree using rsync.
- Restart affected services.
- Prove `/health` and relevant MCP/portal behavior.
- Record sanitized proof in the Linear issue comment.

Never commit raw JWTs, service-role keys, DSNs, passwords, private keys, or full
sensitive case/evidence paths.

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

Test-invocation gotchas (root `.venv`, run from repo root):

- `opensearch-mcp` tests need the tests dir on `PYTHONPATH` — its `conftest.py`
  does `from _helpers import ...`, so collection from the repo root fails with
  `ModuleNotFoundError: No module named '_helpers'`. Run:
  `PYTHONPATH=packages/opensearch-mcp/tests uv run --extra dev --extra full pytest packages/opensearch-mcp/tests`.
- `windows-triage-mcp` is NOT in the `full` extra — add `--extra windows-triage`
  (otherwise collection fails with a ModuleNotFoundError).
- Fresh git worktrees build their own `uv` env that may omit optional deps;
  validate via
  `uv run --directory <worktree> --extra dev --extra full [--extra windows-triage] pytest ...`.
- Regenerate the golden MCP-surface snapshot with
  `UPDATE_MCP_GOLDENS=1 pytest <surface test>`.
