# Kanban Board Ops (Cline Kanban)

Local agent-orchestration board for this repo. UI: `http://127.0.0.1:3484`.
CLI: `kanban` (npm pkg `kanban`). Each card is a task that can spawn a coding-agent
session. This doc is operator-facing; it is the handoff for managing the board and
for having another session's agent self-populate it.

## Project binding

- Project id: `sift-mcps`, bound to host path `/home/yk/AI/SIFTHACK/sift-mcps`.
- Every command needs `--project-path /home/yk/AI/SIFTHACK/sift-mcps`, or run the
  command from that directory (defaults to the current-dir workspace).
- Columns / flow: `backlog` -> `in_progress` -> `review` -> `done` (`trash` is also
  accepted as a column alias).

## Create vs start (read this first)

- `kanban task create` ALWAYS lands a card in `backlog`. It does NOT run an agent.
  Safe to batch-create freely.
- `kanban task start --task-id <id>` moves the card to `in_progress` and SPAWNS an
  agent session (consumes runs/tokens). Only start when you actually want work to run.

## CLI cheatsheet

All examples assume `P=/home/yk/AI/SIFTHACK/sift-mcps`.

```bash
# Create a backlog card (does not start an agent)
kanban task create --title "<short title>" --prompt "<actionable agent brief>" --project-path "$P"

# List tasks (JSON: tasks[].id, .column, .session.state). Optional column filter.
kanban task list --project-path "$P"
kanban task list --project-path "$P" --column backlog

# Update an existing card (same flags as create; target by id)
kanban task update --task-id <id> --title "<new>" --prompt "<new>" --project-path "$P"

# Start a card -> in_progress, spawns agent
kanban task start --task-id <id> --project-path "$P"

# Move a card (or a whole column) to done; cleans up task worktrees
kanban task done  --task-id <id> --project-path "$P"
kanban task done  --column in_progress --project-path "$P"

# Permanently delete a card (or a whole column)
kanban task delete --task-id <id> --project-path "$P"

# Link a dependency: --task-id waits on --linked-task-id
kanban task link --task-id <waiter> --linked-task-id <prerequisite> --project-path "$P"
```

Useful `create`/`update` flags:

- `--base-ref <branch>` task base branch (defaults to `main`).
- `--start-in-plan-mode [true|false]` start the agent in plan mode.
- `--auto-review-enabled [true|false]`, `--auto-review-mode commit|pr`.
- `--agent-id cline|claude|codex|droid|gemini|opencode|default`.
- `--cline-provider`, `--cline-model`, `--cline-reasoning-effort default|low|medium|high|xhigh`.

Notes:

- Task ids are short hashes (e.g. `2cde0`); read them from `kanban task list`.
- Dependency direction: when both linked tasks are in `backlog`, `--task-id` waits on
  `--linked-task-id`. When the prerequisite finishes `review` -> `done`, the waiting
  backlog task becomes ready to start.
- The CLI is the supported write surface. The tRPC API (`/api/trpc`) is read-only for
  projects state; do not script card writes against it.

## Agent self-populate prompt

Paste the block below into the session whose context already holds the backlog you
want on the board. That agent turns its own context into backlog cards via the CLI.
It is create-only and idempotent; it will not start agents or touch existing cards.

```text
Populate the Cline Kanban board for project sift-mcps from YOUR current session
context. Use the `kanban` CLI only. Do not start any agents and do not modify or
delete existing cards.

Setup:
- P=/home/yk/AI/SIFTHACK/sift-mcps
- First run: `kanban task list --project-path "$P"` and note existing card titles.

For each distinct, actionable work item in your context:
1. Skip it if a card with an equivalent title already exists (idempotent — do not
   create duplicates).
2. Otherwise create a BACKLOG card (leave it in backlog; do NOT `kanban task start`):
   kanban task create \
     --title "<=60 char imperative title" \
     --prompt "<self-contained brief>" \
     --project-path "$P"
3. Write the prompt so a fresh agent can pick the card up cold. Include:
   - Goal / definition of done.
   - Touch-points: files, packages, or commands to look at.
   - Acceptance check: how to prove it's done (tests, validator, live smoke).
4. If you know ordering, link it after both cards exist:
   kanban task link --task-id <waiter> --linked-task-id <prerequisite> --project-path "$P"

Guardrails:
- NO secrets in titles or prompts: no JWTs, service-role keys, DSNs, passwords,
  private keys, or full case paths (this repo's live-VM discipline).
- Create only — never `start`, `done`, `delete`, or `trash` unless the operator
  explicitly says so.

Finish:
- Run `kanban task list --project-path "$P"` and report the created card ids + titles.
```

Concrete example card (pattern to mirror):

```bash
kanban task create \
  --title "LV1: end-to-end live VM validation + Rocba proof" \
  --prompt "Run the BATCH-LV1 end-to-end proof on the live SIFT VM. Issue a portal agent/service credential, run aggregate MCP initialize + tools/list, smoke OpenSearch and RAG tools, and capture sanitized live proof in docs/migration/Session-Notes.md. Acceptance: see BATCH-LV1 acceptance in docs/migration/task-batches.md. No secrets in committed proof." \
  --project-path /home/yk/AI/SIFTHACK/sift-mcps
```

## Verify

```bash
kanban task list --project-path /home/yk/AI/SIFTHACK/sift-mcps
```

Confirm the board at `http://127.0.0.1:3484/sift-mcps` shows the new backlog cards.
