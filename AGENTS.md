# Agent Operating Contract

## Repo map & where to work

- **`/Users/yk/AI/sift-mcps` is the canonical `main` checkout** — Python MCP gateway
  + portal. **`main` is the single integration line.** If launched in another worktree, verify its
  branch and base explicitly; do not treat a stale branch as an alias and do not push/merge unless the
  operator asked for it.
- **Portal frontend:** `packages/case-dashboard/frontend` — carries its own
  `AGENTS.md` / `DESIGN-SYSTEM.md` (design-system contract); read those before
  touching UI. Inside the frontend, that `AGENTS.md` wins.
- A worktree folder *is* its branch; one branch checks out in one worktree at a time.

## Operating model, trackers & lessons (read before substantive work)

Internal ops hub lives **outside this repo** (local): `~/AI/sift-portal-ops/`.
- **Start there (only these two):** `STATUS.md` (short narrative current state) +
  `trackers/MASTER_TRACKER.md` (the single execution queue with self-contained P0–P4 handoff packets).
  Read them before "discovering" work. For GitHub review work only, also open
  `trackers/GITHUB_PR_TRACKER.md`; it is deliberately link-only, and GitHub remains authoritative for
  live PR state/checks. The old
  per-topic trackers (OPEN_ITEMS_MASTER, MCP_WORKFLOW_FRICTION_TRACKER, P3.5_LIVE_VALIDATION_TRACKER,
  AUDIT_STATE_VERIFICATION, P35-3_AUDIT_ID_FLOW, PORTAL_V3_EXTENSION_BACKLOG) were consolidated into it
  on 2026-06-27 and archived under `_archive-trackers/` — do not cite them. Coder briefs: `briefs/`.
- **Packet handoffs are scope contracts:** an instruction such as `Finalize P1` means execute the P1
  actions/acceptance criteria in `MASTER_TRACKER.md`, expand code discovery only as needed, and do not
  pull in adjacent packets. Update the packet state and proof record when finished.
- **Surfacing lesson (the #1 repeat bug):** a gateway/add-on fix is INERT live unless it
  lands at the **agent-facing surface** — the registry `*Out` Pydantic model + the worker
  `result_public` envelope + the DB-authority path — NOT the impl function. SDK `outputSchema`
  rejects a result with no `structured_content`. The agent backend has **no DB creds by design**
  (DB-reading logic belongs in the gateway, not the add-on subprocess). Full writeup +
  pre-merge checklist: `~/AI/sift-portal-ops/runbooks/LESSONS-MCP-FIX-SURFACING.md`.
- **Guard:** a conformance harness now catches that class in CI —
  `packages/sift-common/src/sift_common/testing/surface.py`. When you add/change an MCP tool's
  output, write a **fail-on-revert** surface test with it and add the optional key to
  `SURFACE_OPTIONAL_KEYS` (else CI fails). A regression test that can't catch its own bug is theater.

## Deploy-and-prove (standing rule)

A green test is a hypothesis; the **live gateway is the proof for BEHAVIOR** (the harness covers
plumbing only). VM deploy = rsync source to `/opt/sift-mcps/packages/.../` → clear
`__pycache__` → restart `sift-gateway` + `sift-opensearch-worker@{1,2}` + `sift-job-worker` →
re-run the exact repro live and diff before/after. If the live setup can't reproduce it, say so — never imply a live proof that didn't happen. 
**The testing VM should reachable via: ssh sift-vm**
**The VM is our proof and there is nothing on it that is sensitive or unsafe for delete or redoployment, it is purely a SIFT VM based on Ubuntu 24.04 with our repo installed (as root this time by mistake - do not repeat on redeployment - use default user sansfornesics for best practices), the two ingested case images on the VM are maintained offline so they are safe to delete, and all the findings, timelines, etc... are testing data so do not treat this as a real live production environment - no need for rigorous backups unless needed for comparison or live proof - keep it simple***
**The VM is deployed on the Fedora Host which can be reached via ssh fedora.local if any VM-level changes on are needed like RAM,CPU Storage etc.. It is using virt manager or for troubleshooting connectivity**
**The Gateway/Portal are running on the VM on the Fedora Host which is not directly reachable from the current MacOS Host - a running background tunnel should be forwarding the gateway portal to https://localhost:4508 so if the tunnel is not active or gateway is not reachable make sure ssh sift-gateway-tunnel is running in the background as its the ssh port forwarding command**


Canonical procedures: `~/AI/sift-portal-ops/runbooks/RUN-PORTAL-V3-VM-DEPLOY.md` and
`~/AI/sift-portal-ops/runbooks/RUN-PORTAL-V3-VM-TEST.md`. Use recalled coordinates only as a convenience;
the runbooks and observed live state are the authority.

## Security model (read before any gateway / security / execution work)

The canonical security architecture is **`docs/architecture/SIFT-GATEWAY-SECURITY-MODEL.md`**
(condensed C4 + STRIDE viewpoints; rendered diagrams in `docs/drafts/architecture/sift-architecture.html`). It defines the single-policy-boundary
gateway, the 9 fail-closed tool-call gates, the Postgres-authoritative / OpenSearch-derived
split, the seven STRIDE trust boundaries, and the `run_command` ceiling+floor sandbox. **Read
it before touching auth, the policy chain, backends, evidence/audit, or execution.** It is the DESIGN model — where it conflicts with the code, the **code wins; flag the drift**.

## Agent tooling (project-scoped)

Prefer **repo** config over user-global installs. Canonical locations:

- Cursor MCP / plugins: `.cursor/mcp.json`, `.cursor/settings.json`
- Cursor rules / agents: `.cursor/rules/`, `.cursor/agents/`
- Skills (Claude + Cursor): `.claude/skills/` → `.agents/skills/` (do not also mirror under `.cursor/skills/` — Cursor loads both and duplicates)
- Claude / Codex / OpenCode MCP: `.mcp.json`, `.claude/settings.json`, `.codex/config.toml`, `opencode.json`

CodeGuard is vendored as `.cursor/rules/codeguard-*.mdc` + `.cursor/agents/codeguard-reviewer.md` — do not also enable the CodeGuard marketplace plugin in this project.

Keep `~/.cursor/mcp.json` empty so project `.cursor/mcp.json` owns memory MCP.
Cursor uses `${userHome}/.local/bin/codebase-memory-mcp` (GUI apps often lack `~/.local/bin` on `PATH`).

## Code Discovery

This project uses `codebase-memory-mcp` to maintain a knowledge graph. Prefer MCP
graph tools over grep/glob for code discovery.

**Direct MCP tools only — never the CLI.** Invoke registered `codebase-memory-mcp`
tools through the agent tool interface (`index_repository`, `search_graph`,
`trace_path`, `get_code_snippet`, `query_graph`, `get_architecture`, and
`manage_adr`). Do not run `codebase-memory-mcp cli ...` or communicate with its
executable through a shell command. If a required direct MCP method is not exposed
(for example, project deletion), report that capability gap and do not substitute a
CLI fallback.

**Always index before any graph query.** Call
`index_repository(repo_path=<repo root>, name="Users-yk-AI-sift-mcps")` (or the
derived project name) at the start of discovery and again before querying after
substantive code edits. Indexing is fast; a fresh index keeps results current.
Do not skip this step because a prior session "already indexed."

Then use:

1. `search_graph` to find functions, classes, routes, variables.
2. `trace_path` to inspect callers, callees, and data flow.
3. `get_code_snippet` to read exact source for known symbols.
4. `query_graph` for complex relationship queries.
5. `get_architecture` for high-level structure.

Fall back to `rg` for string literals, configs, shell scripts, docs, or when the
graph tools / MCP are unavailable.

### Architecture Decision Record (ADR)

`codebase-memory-mcp` also persists a project-level ADR (PURPOSE / STACK /
ARCHITECTURE / PATTERNS / TRADEOFFS / PHILOSOPHY) in the same graph store as the
code-discovery tools above — shared across Claude Code, Codex CLI, and OpenCode
since all three point at the identical local binary + DB.

- **Index first**, then read the ADR at session start before touching gateway /
  security / execution code: `manage_adr(project="Users-yk-AI-sift-mcps", mode="get")`.
  Committed mirror (also the bootstrap source): `.codebase-memory/adr.md`.
  If `manage_adr` is missing from the MCP tool surface, read that file and continue
  — do not invoke the CLI or crawl the monorepo first.
- **Update it, don't let it rot**: when a PATTERNS/TRADEOFFS entry changes (policy-chain
  stage count, seccomp/AppArmor default posture, an add-on drift gets resolved, etc.),
  edit `.codebase-memory/adr.md` and re-run
  `manage_adr(mode="update", content=<full six-section markdown>)` through the MCP
  tool. Keep both in sync. A stale ADR is worse than none — agents will trust it.
- **Targeted access**: `mode="sections"` reads/writes one named section instead of the
  whole document. Official format requires exactly six `##` headers: PURPOSE, STACK,
  ARCHITECTURE, PATTERNS, TRADEOFFS, PHILOSOPHY (≤ ~8000 chars). This is the project
  brain for codebase-memory-mcp — distinct from per-decision notes in `docs/adr/`.
- Source material for the ADR content (prefer in this order, code wins on conflict):
  `docs/drafts/architecture/sift-architecture.html` (VP-1..VP-5 visual SoT) →
  `docs/architecture/SIFT-GATEWAY-SECURITY-MODEL.md` (text twin) → `docs/latest/` →
  `docs/new-docs/DEVELOPER_ENTRYPOINT.md` → other `docs/drafts/architecture/` → live
  `get_architecture()` graph output. Flag drift.

## Spawned agents & agent teams — required loadout

Every spawned subagent and agent-team member (coding, reviewing, verifying,
exploring) receives the following loadout in its prompt. Capability absence must be reported, not hidden;
use the stated fallback instead of blocking or fabricating a tool verdict.

1. **Security guidance** — when installed, invoke `codeguard-security:codeguard` while modifying code
   (or `codeguard-security:security-review` for a full pass) and report its verdict. If unavailable, use
   the canonical security model plus a manual secure-by-default review and state that fallback clearly.
2. **codebase-memory MCP** — use direct MCP tool calls only: always `index_repository`
   before graph queries, then use
   `search_graph` / `trace_path` / `get_code_snippet` / `query_graph` / `get_architecture`
   for code discovery over grep/glob, plus the `codebase-memory` skill for query syntax.
   Never invoke its CLI. If a required MCP method is unavailable, report it; for
   read-only discovery, fall back to `rg` and exact source reads.
3. **LSP validators on changed files before closing** — Python:
   `uv run --extra dev ruff check <paths>` + `uv run --extra dev pyright` (and
   targeted `uv run --extra dev pyright <file>` on each file touched); frontend:
   `npm --prefix packages/case-dashboard/frontend run lint`. `sift-gateway` is the
   type-clean Pyright baseline — keep it at **0 new diagnostics**; non-baseline
   packages (opensearch-mcp, portal/case-dashboard backend, some sift-core) carry
   legacy type debt — report NEW diagnostics from your edits SEPARATELY from
   pre-existing debt, fix only what you introduced, and do NOT expand
   `pyrightconfig.json`. Full guide: `docs/new-docs/LSP_AGENT_WORKFLOW.md`. A
   fresh worktree's uv env may miss dev deps — fall back to repo-root tooling.
4. **Security model** — read `docs/architecture/SIFT-GATEWAY-SECURITY-MODEL.md` to
   understand the single-policy-boundary gateway, the 9 fail-closed gates, the
   Postgres-authoritative / OpenSearch-derived split, the STRIDE boundaries, and the
   `run_command` jail before reasoning about security / policy / backends / evidence /
   execution. The orchestrator MUST point agents to it by name in their prompts. Code wins
   on conflict — flag drift.

LSP/diagnostics catch import/signature/optional-value/rename slips early; they do
NOT prove policy/runtime/DB/live-VM behavior. codebase-memory is first for
call-graphs/architecture; tests + deploy-and-prove remain the final authority.

## Security reporting — evidence before implication

Do not report an architectural possibility as an agent-reachable vulnerability. Before
raising, escalating, or acting on a security finding, establish the complete current
path and distinguish a demonstrated exposure from defense-in-depth hardening.

Every security report must state:

1. The exact MCP tool or resource URI, its registration site, and whether a real agent
   can invoke it.
2. The gateway route and the policy gates that apply (identity, authorization,
   active-case binding, audit, evidence, response guard, and dispatch as applicable).
3. The supplied versus gateway-injected arguments and the exact backend entrypoint.
4. The precise downstream operation: database/OpenSearch method, target index/query,
   filesystem path, network target, or process/command.
5. The OS/process footprint: whether `run_command`, a worker, a subprocess, evidence
   access, or the execution sandbox is involved. “Agent-facing” alone is not evidence.
6. A current reachability reproduction. If it cannot be reproduced, label it clearly as
   a potential hardening/design concern and give the missing proof; do not call it a
   vulnerability or block unrelated work on implication alone.

For case-scoping claims, prove the active-case source, propagation path, and final
index/query scope. For resource reads, prove that resource-read context—not merely
tool-call middleware—carries the required identity and active-case authority. Code wins
over design docs; report any drift precisely.

## Agent Worktrees

The harness `isolation: worktree` flag does NOT create isolated working
directories in this environment: spawned agents fall back to the shared main
working tree and race on the git index (a single tree can only hold one
checked-out branch, so concurrent writer agents serialize onto or clobber each
other's branch and intermingle uncommitted changes). Do not rely on it for
writer agents.

A single agent needs no extra worktrees — `cd` into the target branch's worktree,
work there, commit there. Per-agent worktrees are only for **parallel writers**.
When dispatching parallel coding agents (an agent team), the orchestrator sets up
isolation MANUALLY:

1. Create one worktree per agent off the current integrated `HEAD` (never a
   stale `origin/main` — that base bug drops already-merged work):
   `git worktree add ../wt/<slug> -b <branch> HEAD`
2. In each agent's prompt, set its working directory to that worktree's absolute
   path and instruct it to `cd` there first, run every edit / npm / pytest / git
   command from that directory, and COMMIT its work to its branch in that
   worktree. It must never touch the main checkout.
3. After an agent finishes, the orchestrator merges its branch into main,
   re-validates, then removes the worktree (`git worktree remove`).

Never run two writer agents in the same working tree.

## Guardrails
- Do not fabricate results or claim completion without verification.
- Do not weaken auth, execution, or evidence-handling safeguards.
- Do not change unrelated files or broaden scope without a clear reason.
- If a task is ambiguous, ask for clarification before making a high-impact change.

## GitHub

GitHub is for code review and merge proof.

- Do not auto-open PRs for triage or discovery output unless explicitly asked.
- Commit or push only when the operator asks. If on the default branch, branch
  first.
- Do not enable two-way issue sync unless the operator requests it.
- For review-queue work, refresh `~/AI/sift-portal-ops/trackers/GITHUB_PR_TRACKER.md` only when the open
  PR set or recommended disposition changes. Keep diffs, reviews, and CI logs in GitHub, not the tracker.

## Signoff

Post a closeout before ending substantive work:

```md
Result: DONE | IN REVIEW | BLOCKED
Branch/commit:
Changed:
Validation:
Residual risk:
Next action:
```

Never paste secrets, raw tokens, DSNs, passwords, private keys, service-role
keys, or sensitive full evidence paths into GitHub, docs, or any external service.

## Cursor Cloud specific instructions

This section describes the **Cursor Cloud agent VM** dev environment, which is
NOT the maintainer's macOS + SIFT-VM setup described in "Deploy-and-prove" above.
The Mac-side paths there (`ssh sift-vm`, `ssh sift-gateway-tunnel`, the
`localhost:4508` SSH port-forward) are the maintainer's machines and do NOT work
from this VM — ignore them. The live gateway IS reachable from a cloud agent, but
over Tailscale, not that SSH tunnel — see "Reaching the LIVE gateway over
Tailscale" below.

### Toolchain (already installed in the base snapshot; refreshed by the update script)
- **uv** lives at `~/.local/bin` — the update script prepends it to `PATH`.
- **Node 24.13.1** is installed via nvm at `~/.nvm/versions/node/v24.13.1/bin`.
  A stale `/exec-daemon/node` (v22) is earlier on the default `PATH` and shadows
  it, so `node -v` in a fresh shell shows v22. The frontend requires Node 24
  (`packages/case-dashboard/frontend/package.json` engines), so **prepend the
  nvm bin** for any frontend command:
  `export PATH="$HOME/.nvm/versions/node/v24.13.1/bin:$PATH"`.

### Commands (standard invocations; authoritative source is `.github/workflows/ci.yml`)
- Python lint/typecheck/test/coverage all use `uv run --locked ... <tool>` exactly
  as in `ci.yml`. The supported pytest entrypoints are in
  `docs/new-docs/DEVELOPER_ENTRYPOINT.md` §11; CI runs the full suite via
  `pytest tests packages -m "not integration"` (importlib mode handles the
  cross-package collisions the doc warns about).
- Frontend (from `packages/case-dashboard/frontend`, Node 24 on PATH): `npm run dev`,
  `npm run lint`, `npm test` (vitest), `npm run build`.

### Docker is NOT installed here — and the standard dev/test loop does not need it
CI and the normal loop are Docker-free (`-m "not integration"`). The full backend
gateway (`sift-gateway` + OpenSearch from `docker-compose.yml` + Postgres/Supabase)
requires Docker and is out of scope for the standalone cloud dev env.

### Running the portal standalone (no backend) — the demoable app
`npm run dev` serves the examiner portal at `http://localhost:5173/portal/`.
Append `?mock=1` (`http://localhost:5173/portal/?mock=1`) to boot it fully seeded
with demo fixtures behind a mock auth context — no gateway needed. The mock/real
split lives ONLY at the API adapter (`src/api/client.js` + `src/_mock/routes.js`).
**Caveat:** only the endpoints enumerated in `src/_mock/routes.js` are mocked
(reports generate/save, backends register/validate/reload/enable, service
start/stop/restart, auth principals issue/revoke, and the GET reads). Any other
write — e.g. **findings Approve/Stage/Reject** — falls through to the real fetch,
hits the Vite `/portal` proxy, and returns **HTTP 502** with no backend. For a
standalone portal demo use report generation, backend register/validate, or agent
token issuance, not finding approval.

### Reaching the LIVE gateway over Tailscale (verified 2026-07-12)
The live SIFT gateway (libvirt VM `sift` on hypervisor `fedora44`) is reachable
from a cloud agent over the maintainer Tailscale tailnet. `fedora44` is a
Tailscale **subnet router** advertising an approved **`192.168.122.81/32`**
(only the VM). Gateway TLS: `https://192.168.122.81:4508` (`/health`, `/portal/`,
`/mcp`).

Required Cursor Cloud secrets (never commit or paste into chat/logs):
- `TS_AUTHKEY` — reusable, ephemeral auth key tagged **`tag:cursor-cloud`**.
  Tailnet ACL must grant only `tag:cursor-cloud → 192.168.122.81:tcp:4508`.
- `SIFT_CA_CERT` — PEM of the **public** SIFT CA (use `--cacert`, never `-k`).

Cloud VMs cannot use kernel Tailscale. Use **userspace** networking (rootless):

```sh
mkdir -p /tmp/tailscaled.state
tailscaled --tun=userspace-networking \
  --socks5-server=localhost:1055 \
  --socket=/tmp/tailscaled.sock \
  --statedir=/tmp/tailscaled.state &
tailscale --socket=/tmp/tailscaled.sock up \
  --authkey="$TS_AUTHKEY" \
  --accept-routes \
  --hostname=cursor-cloud-agent
printf '%s\n' "$SIFT_CA_CERT" > /tmp/sift-ca.pem
curl --proxy socks5h://localhost:1055 --cacert /tmp/sift-ca.pem \
  --max-time 8 https://192.168.122.81:4508/health
```

`--accept-routes` is required to use the advertised `/32`. Least-privilege:
only `tcp:4508` on that address is intended to be reachable; OpenSearch `:9200`
and Supabase `:54321/:54322` stay loopback-only on the VM. `/mcp` returns 401
without gateway auth — reachability ≠ authorization. Hypervisor SSH from the
maintainer Mac: `ssh fedora44` (not `fedora.local`).

### Known pre-existing test failures on a clean checkout (NOT environment issues)
- `tests/test_opencti_shared_target_contract.py::test_shared_check_is_read_only_and_requires_secure_core_contract`
  — requires the `docker` CLI to validate a compose contract; skips/fails when
  Docker is absent.
