# Root orchestration contract

> **Inert unless the operator explicitly launches this session as the sift-mcps root
> sprint orchestrator** and grants commit/push authority — i.e. pastes the kickoff
> prompt, or says "run/continue as orchestrator" for `~/AI/sift-mcps`. Any other
> session (coding, review, a spawned agent, plain chat, a different repo) ignores this
> whole document. `AGENTS.md` §Root orchestration points here so both Claude Code and
> Codex resolve the same trigger; this file holds the detail so the always-on contract
> stays lean.

## Session bootstrap (read before doing anything)

When triggered, **do not rediscover the workflow — read these first, in order, then
resume from the recorded checkpoint:**

1. `~/AI/sift-portal-ops/briefs/p423-evidence-custody/SPRINT-ORCHESTRATOR-PROMPT.md` — the role
   contract + full read-order + the Execution Playbook (the per-packet loop, and the
   maintain-three-things-and-notify + never-compact/checkpoint discipline, all baked in).
2. `~/AI/sift-portal-ops/briefs/p423-evidence-custody/WORKTREE_LEDGER.md` — the resumable state;
   reconcile against live git first, then resume at its "Context checkpoint note".

**You orchestrate, never implement:** dispatch teammate agents (writers/reviewers), integrate + push
`main` yourself, keep all state in files. The per-packet loop, the ledger·canvas·notify maintenance
triad, and the context/checkpoint rule live in the prompt above — this document does not restate them
(one source, no drift). The rest is the standing authority / worktree-ledger / serialized-proof
contract that the prompt's playbook builds on. (Currently scoped to the P4.23 custody sprint;
generalizes to future sprints by swapping the brief path above.)

## Authority and scheduling

- The root orchestrator is the sole writer to the canonical `main` checkout and the
  sole agent permitted to integrate, commit, or push `main` / `origin/main`.
  Coding agents commit only to assigned worktree branches; they never mutate the
  canonical checkout, deploy, update trackers, or push.
- Build a dependency DAG before dispatch. Run actionable, non-overlapping packets in
  parallel when their prerequisites are integrated. Serialize writers whose expected
  files, migrations, schemas, or API contracts overlap materially.
- The root alone updates `STATUS.md`, `MASTER_TRACKER.md`, GitHub disposition, packet
  state, and the orchestration ledger. Read-only discovery, test-design, security,
  verification, VM-diagnostic, and tracker-drift agents should run in parallel when useful.
- **Coordinate over Herdr, never by polling** (see `AGENTS.md` §Herdr — the #1 context destroyer).
  Watch each teammate pane with a single blocking `herdr wait agent-status <pane> --status done` /
  `herdr agent wait <target> --status idle` — never a per-few-seconds `pane read` loop, and **never
  re-poll the waiter/background process itself**; launch one waiter, do other integration work, inspect
  the pane once on completion. Give every writer both the stable root target and current root pane id;
  require it to populate the result with `herdr agent send <root-target> "<closeout>"` and then
  submit it with `herdr pane send-keys <root-pane-id> enter`. (`agent send` alone only populates the
  prompt.) Treat that submitted message as the completion signal and the status transition as backup
  (detection can lag 2–3 min).

## Worktree ledger and writer lifecycle

Before spawning a writer, manually create its branch/worktree from current integrated
`HEAD`. Maintain a root-owned ledger containing packet, agent, branch, worktree, base
commit, expected surfaces, state, worker commits, changed files, validation/review
evidence, integration commit, and cleanup proof.

Every writer prompt must require the agent to verify and use its exact worktree, remain
within packet scope, load the mandated security and discovery guidance, run appropriate
tests/LSP/security review, commit every intended change to its branch, and report exact
commits/files/evidence/residual risk. A returned message is not completion: the root
directly verifies branch head and worktree status.

After coding, dispatch independent read-only functional and security verifiers against
the committed branch. Return defects to the same writer/worktree for repair. Integrate
accepted branches one at a time in dependency order and rerun cross-packet tests from
canonical `main`. Before removing any worktree, prove its required commits are reachable
from `main` and no uncommitted or untracked packet output remains. Reconcile the ledger
against `git worktree list --porcelain`, branch heads, and commit reachability before push.

## Serialized external proof

- Treat Chrome/Portal interaction as a single leased resource. Only the root or one
  explicitly designated browser operator may control the signed-in Portal at a time;
  never run concurrent browser agents.
- Serialize deployments and VM-mutating proofs. Batch live proof at logical integration
  gates rather than every internal commit. At each gate, record integrated `HEAD`, sync
  the exact changed source/config/migrations, verify VM source hashes or a revision
  manifest, clear stale bytecode/cache state, restart all required services, and rerun
  exact positive and negative reproductions. A stale installed process is not proof.
- Credentials supplied for a disposable test environment remain ephemeral. Never store
  passwords, tokens, cookies, or browser state in the repo, worktree ledger, trackers,
  commits, GitHub, screenshots, proof bundles, or durable agent prompts.

A packet is DONE only when intended code is committed, independent reviews pass,
required tests and live proof pass, its commits are integrated/pushed as authorized,
and trackers contain the proof. Otherwise record the exact remaining gate.
