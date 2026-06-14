# Orchestrator Handoff — 2026-06-14 (post worker-decoupling)

> ## STATUS UPDATE 2026-06-14 — RUN-1 COMPLETE + PUSHED
> RUN-1 (OSW + TOOL + HARDEN + RESEARCH) landed, live-proven on the VM, and
> `main` was **pushed to origin** (`87be91a`, origin synced). Plan is now **4 runs**
> (sandbox split into its own run, per the open question below — confirmed).
> - **DONE:** tool rename `job_status`→`running_commands_status` + tool inventory
>   real-names (vol/EvtxECmd live); opensearch B3 K4-fix (Option C) + case_dir
>   injection; AppArmor COMPLAIN→ENFORCE (0 denials, live); sandbox survey at
>   `docs/research/sandbox-survey-2026-06-14.md` (pick: bwrap+socat for agent
>   code-exec; Landlock+seccomp+AppArmor-fuse for run_command).
> - **Bonus fix (B-MVP-025):** gateway `_stdio_base_env()` did not propagate
>   `SIFT_DB_ACTIVE` to stdio add-on backends → K4/B3 DB-active path never ran in
>   the opensearch backend; found+fixed+proven live.
> - **Deferred to RUN-3/4:** OSW B4 memory durable-lane live proof; Option A
>   (gateway-injected app.job_status_public realtime) = B-MVP-024; F-HARDEN-01
>   (Bearer/JTI flag-gated deletion) under B-MVP-023; F3 cross-case gate.
> - **NEXT = RUN-3 (sandbox impl):** implement bwrap+socat agent code-exec sandbox
>   + callMCPTool shim for Hermes (verify kernel/nested-KVM prereqs from the survey
>   §"Open Questions" on the VM first), optionally the run_command Landlock+seccomp
>   layer; then RUN-4 = PMI4/OS6 e2e + fresh Hermes autonomous run.
> See `docs/migration/Session-Notes.md` RUN-1 entry for full live proof + B-MVP-018/023/024/025.

Pick up here in a fresh orchestrator session. This is the source of truth for the
next runs. (RUN-1 above is done; the RUN sections below are the original plan —
RUN-2 reconcile+review+push is folded into RUN-1's completion.) The Cline kanban board is flaky (cascade-trashes, lost cards across
CLI rebuilds) — trust THIS doc + `mcp_tool_assessment.md` §0 + Session-Notes, not
the board. Repopulate the board from §"Batches" if you want the GUI.

## Current state
- `main` @ ~`4d70882`, **60 commits ahead of origin, NOT pushed** (operator: push
  after all fixes, before end-to-end).
- **Decoupled OpenSearch worker: LANDED on main + security-reviewed (SHIP-WITH-FIXES,
  all fixes applied) + live-proven.** Gateway stays thin policy boundary; ingest
  dispatched non-blocking to `sift-opensearch-worker@` units (CAP_SYS_ADMIN + host
  mount ns for FUSE; gateway untouched); N-worker parallel (FOR UPDATE SKIP LOCKED);
  realtime `job_status`. Live: E01→14 disk indices, Hayabusa 888k alerts, crown-jewel
  queryable, osw-1+osw-2 concurrent. B1 (case_dir resolver), B2 (case_info xmount),
  F1 (no hostname in worker_label), F2 (docs) all fixed.
- VM (sansforensics@192.168.122.81, ssh/sudo pw `forensics`): services active —
  sift-gateway, sift-job-worker (--job-types run_command), sift-opensearch-worker@1.
  Active case human id `case-rocba-case-06132304`; evidence /cases/<case>/evidence/
  {rocba-cdrive.e01, Rocba-Memory.raw} (sealed, chattr +i).
- Branches: feat/opensearch-workers (merged), fix/b1*, fix/b2* (merged). Worktrees
  sift-os-workers / sift-b1 / sift-b2 can be pruned.

## Operating rules (carry forward)
- Work in worktrees off LOCAL `main` (origin is 60 behind — Agent isolation:worktree
  would branch off stale origin/main; make worktrees manually). One concern/agent;
  disjoint file fences for parallel agents.
- Dev/fix/validation agents MAY ssh to the VM for deploy+live-test. The HERMES
  *investigation* agent stays MCP-only (next round it ALSO gets a sandboxed code-exec
  env — see RUN 2).
- Do NOT push to origin until all RUN-1/RUN-2 fixes land. Do NOT loosen the gateway
  unit. Keep deny-floor, evidence immutability, DB audit, append-only chains,
  FORCE RLS, SECURITY DEFINER revoke, secret redaction, out-of-case jail, anti-spoof.
- Commit msgs end: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Run `/security-review` on the combined diff before merge to main (RUN 2).

## Operator decisions (2026-06-14) — per item
1. ingest_status: fix opensearch tool to show REAL status (reuse the durable
   job_status data / app.job_status_public). Rename the CORE `job_status` tool →
   `running_commands_status` (run_command-scoped). [DO]
2. ALL opensearch MCP tools use the new gateway-injected `case_dir` path model
   (extend B1 beyond the 5 query tools). [DO]
3. Cross-case `index=` gate (F3): KEEP OPEN, minor, per-case setup — defer to end,
   do NOT close. [PARKED-OPEN]
4. Zimmerman tools: installed at `/opt/zimmermantools`, dotnet installed, run
   NATIVELY (e.g. `evtxecmd --help`, no extension). TEST them + surface via
   `list_available_tools` with real invocable names. [DO — part of tool inventory]
5. Tool inventory: real names (vol NOT vol3; Zimmerman; etc.), symlink alignment
   like SIFT does, DOWNLOAD missing tools in install.sh, make names obvious, cross-
   align ALL tools, surface via list_available_tools so agents stop guessing. [DO]
6. Hermes: ran MCP-only WITHOUT a harness exec tool → couldn't do the programmatic
   python-MCP-client calling (which we proved works inline). Next round: grant the
   live agent a SANDBOXED code-exec env + callMCPTool shim. [DO in RUN 2]
7. Solana/keyed-MAC: anchoring exists for the EVIDENCE chain (evidence-ln-v1.json /
   sift.evidence-*.v1, on-chain tx) — closes detached verification FOR EVIDENCE.
   The APPROVAL ledger is NOT anchored. DECISION: do NOT build keyed-MAC; instead
   (optional) extend the existing Solana anchor to the approval-commit head. [OPTIONAL]
8. AppArmor: flip COMPLAIN→enforce BEFORE the next Hermes autonomous run (aa-logprof
   vs ingest+run_command, rerun, flip). [DO]
9. Sandbox research: assess bwrap / nsjail / lxc / openshell / github
   tastyeffectco/sandboxd + trending AI-agent sandboxes. HARD CONSTRAINT: the host
   runtime must still run the SIFT forensic tools (vol, Zimmerman+dotnet, TSK,
   hayabusa). Output = recommendation for (a) the agent code-exec sandbox Hermes
   gets, and (b) replacing run_command's cgroup-only containment with a real
   sandbox. [RESEARCH]
10. Retire `sift_session` cookie-verify branch (B-MVP-023) + migrate ~11 test
    fixtures to the Supabase harness. [DO]
11. PARKED (open, not scheduled this cycle): repo rename CL2 (B-MVP-002), portal RAG
    PT2 (B-MVP-006), self-managed Supabase SB1 (B-MVP-012), vol-symbols air-gap doc
    (B-MVP-008), setup-addon staged paths (B-MVP-019), F3 cross-case index gate.
12. PUSH main→origin after all fixes, before end-to-end. [RUN 2 end]
13. End-to-end (PMI4/OS6) + a fresh Hermes autonomous run AFTER fixes+push. [RUN 3]

## Batches — target 3 runs

### RUN 1 — 4 parallel agents (disjoint fences)
**Agent OSW** — opensearch realtime + paths + memory lane. Fence: `packages/opensearch-mcp/**`,
`packages/sift-gateway/src/sift_gateway/{policy_middleware.py(dispatch),jobs.py,server.py}`.
Do NOT touch sift-core catalog or the `job_status` tool (Agent TOOL owns naming).
- opensearch_ingest_status (and case-scoped status) reflect DURABLE worker jobs in
  realtime (read app.job_status_public / the jobs table), not just the legacy path. (B3)
- EVERY opensearch tool resolves via the gateway-injected `case_dir` (extend B1 to
  ingest/enrich/inspect/status/ALL tools, not just the 5 query tools). (item 2)
- memory ingest (`format=memory`) runs on the durable multi-worker model — dispatched
  job, worker_label, realtime current_step, parallel — parity with the disk lane. (B4)
- Acceptance: live — memory ingest shows realtime worker status + parallelism;
  ingest_status shows in-flight durable jobs; all opensearch tools work with no
  explicit case arg.

**Agent TOOL** — naming/catalog/install. Fence: `packages/sift-core/src/sift_core/`
(catalog, execute/catalog.py, the `job_status`→`running_commands_status` rename +
its registration, list_available_tools), `install.sh`, tool symlink config. Do NOT
touch opensearch-mcp. NOTE: the DB VIEW `app.job_status_public` name stays (OSW reads
it) — only rename the run_command TOOL.
- Rename core `job_status` → `running_commands_status` (assess callers; update tool
  def + gateway registration + catalog + docs). (item 1)
- Tool inventory + real-name alignment: vol (not vol3), Zimmerman at /opt/zimmermantools
  run natively (evtxecmd/ecmd suite, dotnet present), symlink alignment, DOWNLOAD any
  missing tools in install.sh, fix catalog↔binary mismatches (regripper→rip.pl etc.),
  surface ALL via list_available_tools with correct invocable names. TEST Zimmerman +
  vol live on the VM. (items 4,5)
- Acceptance: list_available_tools shows real names; a sample Zimmerman tool
  (evtxecmd) + vol run via run_command on the VM; no name guessing needed.

**Agent HARDEN** — apparmor + cleanup. Fence: `configs/apparmor/**`,
`packages/case-dashboard/**` (auth + fixtures), VM apparmor. Disjoint from OSW/TOOL.
- AppArmor COMPLAIN→enforce: aa-logprof against ingest+run_command, rerun, flip to
  enforce; confirm no functional regression (ingest, run_command, FUSE mount). (item 8)
- Retire `sift_session` cookie-verify branch + migrate the ~11 test fixtures to the
  Supabase-envelope harness; delete dead examiner Bearer fallback / JTI logout if also
  dead. (item 10)
- Acceptance: apparmor enforce active + ingest/run_command still work; sift_session
  branch gone, suites green.

**Agent RESEARCH** — read-only (deep-research/web). No code.
- Compare bwrap, nsjail, lxc, openshell, github.com/tastyeffectco/sandboxd + trending
  AI-agent sandboxes. Constraint: host runtime must still run SIFT tools (vol,
  Zimmerman/dotnet, TSK, hayabusa, FUSE mounts). Recommend (a) the agent code-exec
  sandbox for Hermes, (b) the run_command OS-sandbox to replace cgroup-only. Output a
  decision doc with tradeoffs + a concrete integration sketch. (item 9)

### RUN 2 — reconcile + integrate + security-review + push
- Merge RUN-1 branches → main (disjoint; resolve the OSW/TOOL status seam carefully).
- Gate (per-package pytest; doc validators). Deploy to VM; live-smoke each fix.
- `/security-review` on the combined RUN-1 diff (dispatch, tool exec, apparmor, auth).
  Fix findings.
- Implement the chosen sandbox (from RESEARCH) + grant Hermes a sandboxed code-exec
  env with a callMCPTool shim (enables programmatic tool calling next round). [if large,
  this becomes its own run].
- (optional) extend Solana anchor to approval-commit head (item 7).
- PUSH main → origin. (item 12)

### RUN 3 — validate end-to-end
- PMI4/OS6 end-to-end live gate (sanitized proof in Session-Notes).
- Fresh Hermes autonomous run: now with working ingest (durable worker), aligned tool
  names, apparmor enforce, AND a sandboxed code-exec env — validate all 7 requirements
  incl R5 programmatic tool calling (previously blocked). Capture feedback.
- Final security review if the sandbox/exec env changed the boundary.

## Open question for the operator
- "PUSH main before 11" — assumed "before the end-to-end". Confirm.
- RUN-2 sandbox impl may be big — may need its own run (→ 4 runs total).
