# OpenSearch Worker Decoupling — Handoff

**Branch:** `fix/mcp-assessment-p0` (off `main` 49189af).
**Status:** P0 + quick-wins + run_command in-case relaxation LANDED & live-proven.
OpenSearch-worker decoupling is **DESIGN-ONLY, approved, NOT built** — this doc is
the build spec. Assume zero prior context.

This file is self-sufficient. A fresh builder with host + VM (ssh
`sansforensics@192.168.122.81`, sudo pw `forensics`) + the `mcp__siftgateway__*`
tools can execute the build plan at the end.

---

## 1. Commits on this branch (hash → one line)

```
445bb1e feat(run_command): in-case read/write relax (DB-authority aware), evidence + secrets stay hard
349bb23 feat(run_command): group-readable umask (0027) for artifact handoff
b93d9ed fix(ingest): skip systemd-run --user when no user D-Bus (service accounts)
03f5753 fix(active-case): stop dropping case_dir in safe_case_argument_names builder
aaa885d fix(record_finding): credit reference-backend grounding + add supersedes field
6bcbb0f fix(run_command): collapse \r progress floods (vol3/tqdm) at the executor
ef41e85 fix(run_command): allow harmless grep -e/-E pattern flags
1863fe2 fix(record_finding): import hashlib so IOC content-hash stops raising
1e660ea fix(active-case): propagate DB active case dir to opensearch backend
```

What each changed:
- **1e660ea (P0, crown-jewel unlock):** under DB authority the gateway resolves the
  active case from Postgres but never told the long-lived opensearch stdio
  subprocess (no DB access, no `SIFT_CASE_DIR` by design) which case dir to use →
  ingest/inspect/enrich/summary/host-fix returned `no_active_case`, so no index
  was ever created and search/aggregate/timeline were starved. Fix: gateway
  injects the DB-authoritative case dir (`ActiveCase.artifact_path`) into each
  filesystem-touching backend tool call via a new gateway-injected `case_dir`
  arg (alongside `case_id`/`case_key`). Backend resolves the case from the
  injected dir (`active_case_dir()` contextvar in opensearch server.py).
  `SIFT_CASE_DIR`/pointer demoted to standalone-CLI fallback. Anti-spoof: a
  client-supplied `case_dir` mismatching DB is denied before dispatch. Manifest +
  JSON schema + MCP-surface golden updated in lockstep.
- **03f5753:** `_build_tool_map` filtered `safe_case_argument_names` to
  `{case_id,case_key}`, silently dropping `case_dir` → disabled the P0 injection
  at runtime AND let an unchecked client `case_dir` pass through. Allow `case_dir`
  in both the manifest-meta filter and the schema-fallback set.
- **b93d9ed:** `opensearch_ingest` spawned its worker via `systemd-run --user`,
  which fails for system service accounts (no user D-Bus → "Failed to connect to
  bus") so ingest never ran. Probe for a user bus; fall back to bare Popen.
- **6bcbb0f:** vol3/tqdm `\r Progress:` floods (139k lines / 9.4 MB) collapsed at
  the executor before byte-counting/saving.
- **ef41e85:** `grep -e`/`-E` were lowercased to the globally-dangerous `-e` and
  blocked; allow them for grep/egrep/zgrep (sed/xargs `-e` stay blocked).
- **1863fe2:** `case_manager._compute_ioc_hash` used `hashlib` without importing
  it → every IOC finding raised `NameError`. Added the import.
- **aaa885d:** record_finding grounding credits reference-backend `audit_ids` the
  finding cites (fixes false "WEAK / forensic-rag missing" in DB-active mode);
  added native `supersedes` field for self-correction chains.
- **349bb23:** worker preexec sets `umask 0027` so extracted files under the case
  jail are group-readable (0640, group `sift` shared by `sift-service` +
  `agent_runtime`) → extract→parse handoff works across stages/calls.
- **445bb1e:** run_command may now read/write ANYWHERE under the ACTIVE case dir
  (not just agent//extractions//tmp/), reusing the existing target-detection
  (`validate_output_path`, dd `of=` jail, `validate_mutating_command_targets`).
  Path validators now resolve the active case via the AuthorityContext
  (`_active_case_dir_str()`), not bare `SIFT_CASE_DIR`. Sealed evidence +
  integrity records + out-of-case + secret paths stay hard-denied; secret
  redaction unchanged.

`git status` at handoff: **clean** (all committed). Operator already merged the
first 8 commits to main once; 445bb1e is the newest and not yet merged.

---

## 2. VM deploy + live state

**VM:** `sansforensics@192.168.122.81`, sudo pw `forensics`. Staged runtime
`/opt/sift-mcps` (editable installs). Control-plane DSN in
`/var/lib/sift/.sift/control-plane.env` (source as sift-service; never print).
Active case: human `case-rocba-case-06132304`, UUID `674425ae-78ea-4c9c-9a14-3c9d0b6f900c`,
artifact_path `/cases/case-rocba-case-06132304`. Sealed evidence:
`evidence/rocba-cdrive.e01` (disk, 22 GB) + `evidence/Rocba-Memory.raw` (memory).

**Deployed to /opt (matches branch HEAD):** opensearch `server.py`, `registry.py`,
`sift-backend.json`; gateway `server.py`, `policy_middleware.py`,
`sift-backend.schema.json`; sift-core `case_manager.py`, `agent_tools.py`,
`execute/executor.py`, `execute/security_policy.py`, `execute/worker.py`,
`execute/security.py`. The opensearch backend was **re-registered in
`app.mcp_backends`** (the gateway loads manifests from the DB, not the file) so the
stored manifest carries `case_dir` in `safe_case_argument_names`.
File backups from the first deploy: `/tmp/sift-p0-backup-1781398686/`.

**Deploy method** (editable): `scp` file to `/tmp`, then
`sudo install -o sift-service -g sift-service -m 644 /tmp/X /opt/sift-mcps/<path>`,
then `sudo systemctl restart sift-gateway.service sift-job-worker.service`.

**Pending restart:** none outstanding — last restart loaded all deployed files.
Gateway is HARDENED: `MountFlags=` (empty), `ProtectSystem=strict` (the FUSE
band-aid was fully reverted — see §6).

**PROVEN LIVE (crown jewel):** memory-image ingest (tier 3, full, 24 vol3
plugins) created **23 case indices / ~180,892 docs**. Verified:
- `opensearch_search` (pslist) → 2,186 processes w/ full fields (PID/PPID/
  ImageFileName/CreateTime, host=rocba).
- `opensearch_aggregate` (ImageFileName.keyword) → Teams 1901, svchost 103,
  chrome 26, **GoogleDriveFS/OneDrive/Slack** (exfil vectors).
- `opensearch_timeline` (CreateTime) → spike 2020-11-14 04:00 (43 vs ~17/hr).
- `opensearch_search` (netscan) → **RDP intrusion**: inbound `LocalPort:3389` on
  `192.168.1.5` from `81.30.144.115` & `213.202.233.104` (svchost PID 1248).
- run_command in-case relax proven: write `extractions/handoff-probe.txt` →
  cross-call grep read it back; evidence write DENIED; `/var/lib/sift/.sift/
  control-plane.env` read BLOCKED+REDACTED; `/etc/...` write DENIED.

**STILL BLOCKED:**
- **E01 disk ingest** — FUSE mount fails (`fusermount: mount failed: Operation
  not permitted` / "Unable to create fuse channel"). This is the entire reason
  for the decoupling design below. The active-case resolution + spawn now work
  (ingest reaches the mount step); only the mount is blocked.
- **Hayabusa detections** — produced from EVTX during the DISK ingest, so blocked
  by the E01 mount issue. No `*-hayabusa-*` / `*-evtx-*` indices yet. Memory
  ingest does not produce Hayabusa.
- **`opensearch_case_summary` (no args)** resolves the case as the UUID while
  indices are named by case_key → returns empty. Minor pre-existing
  id-vs-index-naming mismatch; search/aggregate/timeline work with explicit
  `index=`/`case_id=case-key`. Not fixed (one-line note only). Fix later: make
  case_summary derive the index pattern from `case_key` (basename), not the UUID.

---

## 3. FUSE root cause (why decoupling fixes it)

The gateway and worker units run under `ProtectSystem=strict` + `ProtectHome=tmpfs`
+ `PrivateTmp=true`, each of which puts the unit in a **private mount namespace**
whose root mount uses **slave** propagation by default. In a slave namespace the
kernel refuses to create a new FUSE mount → `fusermount: Operation not permitted`.
The opensearch backend is a **stdio child of the gateway process**
(`create_proxy(StdioTransport(...))`) so it inherits the gateway unit's sandbox,
and `opensearch_ingest` mounts the E01 from inside that sandbox. A band-aid
(`systemd-run --scope` to escape to the host ns, and/or `MountFlags=shared`) was
tried and **reverted** (operator: don't relax the gateway). Decoupling fixes it
properly: move the privileged pipeline into a **dedicated worker** with the FUSE
profile it needs, keeping the gateway thin & hardened.

---

## 4. Decoupling design (APPROVED — build this)

**Principle:** Gateway = thin policy boundary (auth, evidence gate, active-case
authority, audit envelope, redaction). Worker(s) = execution (ingest:
FUSE-mount E01 + Hayabusa + vol3 → index; AND query: search/aggregate/timeline).

### 4.1 Where opensearch execution runs
A **dedicated worker** — NOT a stdio child of the gateway. Two sub-cases:
- **Ingest/enrich (async, long):** reuse the existing durable Postgres job queue.
  `JOB_TYPES` already includes `ingest` and `enrich`
  (`packages/sift-core/src/sift_core/execute/job_worker.py:37`) — only handlers +
  a worker with the right privilege profile are missing. Add a
  `sift-opensearch-worker` unit (or extend `sift-job-worker`) that registers
  `ingest`/`enrich` handlers.
- **Query (sync, sub-second):** search/aggregate/timeline/count/field_values/
  list_detections must return inline (no job round-trip). These do NOT need FUSE
  or sudo — they only talk to OpenSearch over HTTP. Run them in a **long-lived
  query worker** the gateway proxies to (HTTP or a warm stdio child **without**
  the ingest privilege profile), OR keep them as the current in-gateway proxy
  (they already work — the crown-jewel query proof used them). **Recommendation:**
  split the manifest — query tools stay a thin proxy (no privilege need); ingest/
  enrich/inspect become job-dispatched to the privileged worker. This keeps the
  privileged surface as small as possible.

### 4.2 Gateway → worker dispatch (gateway stays the boundary)
Model exactly on the existing `run_command_job` flow:
- Gateway tool handler resolves active case + evidence refs at the gateway
  (`handle_run_command_job`, `packages/sift-gateway/src/sift_gateway/job_tools.py:92`),
  then `job_service.enqueue_job(job_type="ingest", case_id=..., spec_internal={
  "case_dir": case.artifact_path, ...})` (job_tools.py:127) and returns the opaque
  `job_id` immediately (NON-BLOCKING — satisfies the new req).
- Worker claims atomically via `app.claim_next_job` (`FOR UPDATE SKIP LOCKED`,
  `job_worker.py:291`, `run_once`/`run_forever` at 255/277), runs the handler,
  writes typed status/steps/sanitized logs back to Postgres.
- Gateway polls `app.job_status_public` via `handle_job_status`
  (job_tools.py:148) — already the realtime read model.
- **Every** ingest/query call still passes the gateway middleware chain first
  (auth → addon authority → CaseContext/active-case → audit envelope → evidence
  gate → response guard); the worker only ever sees opaque IDs + the resolved
  `case_dir` in `spec_internal`. Boundary preserved.

### 4.3 Worker privilege + security profile (the minimal loosening)
Run-as: `sift-service` (same non-root user), sudo for mounts via the EXISTING
narrow allowlist `/etc/sudoers.d/sift-ingest-mount` (`Cmnd_Alias SIFT_MOUNT =
xmount,ewfmount,mount,umount,ntfs-3g,losetup,qemu-nbd,partprobe,fusermount,
fusermount3, modprobe nbd max_part=8`). The worker unit differs from the gateway
ONLY by what the FUSE pipeline needs:
- **`MountFlags=shared`** (or omit `PrivateTmp`/`ProtectHome`-induced private ns
  for mount propagation) — THE fix: makes FUSE mounts succeed AND be visible to
  the worker's own TSK/EvtxECmd/Hayabusa reads. (Verified in testing: with the
  worker namespace shared, a plain `sudo ewfmount` as sift-service succeeds RC=0
  and `ewf1` is visible; the band-aid failure was because the mount was made in
  the gateway's slave ns.)
- Keep: `ProtectSystem=strict` + `ReadWritePaths=/var/lib/sift /cases
  /var/cache/sift`, `NoNewPrivileges` OFF (sudo needs it), `CapabilityBoundingSet`
  = `CAP_LINUX_IMMUTABLE CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_AUDIT_WRITE` (the
  gateway's set — sudo's privilege drop + the immutable-cap interpreter need
  these), `DeviceAllow=/dev/fuse rw` may be required depending on `DevicePolicy`.
- **Why acceptable in an isolated worker (not the gateway):** the worker holds no
  portal/agent auth surface, no MCP listener, no secret-bearing request path; it
  only claims jobs and runs forensic tooling on already-sealed evidence. Loosening
  mount-namespace propagation on THIS unit does not widen the gateway's attack
  surface. The gateway keeps every HR3 directive.
- Spell out exactly what is loosened vs the gateway: **only `MountFlags=shared`
  (+ possibly `DeviceAllow=/dev/fuse rw`).** Everything else stays identical to
  the current hardened units in `configs/systemd/`.

### 4.4 How case_dir/active-case reaches the worker
Build on the merged P0 `case_dir` injection. The gateway already puts
`case.artifact_path` into `spec_internal["case_dir"]` for jobs
(job_tools.py:121) and the run_command_job handler consumes it into an
`ActiveCaseContext` (`run_command_job.py:32,43`). The opensearch ingest/enrich
handlers do the same: read `spec_internal["case_dir"]`, build the context, and
the opensearch backend's `active_case_dir()` (server.py contextvar accessor added
in 1e660ea) resolves from it. No file/env authority in the worker.

### 4.5 NEW operator requirements (fold into the build)
- **Non-blocking dispatch:** gateway returns `job_id` immediately; ingest/query
  never blocks further MCP calls. (Job model already async.)
- **N workers / parallel ingest:** the `app.claim_next_job` `FOR UPDATE SKIP
  LOCKED` pattern already supports N concurrent workers safely. Run the
  opensearch-worker unit as a systemd **template** (`sift-opensearch-worker@.service`,
  start `@1..@N`) or with multiple claim loops. Parallelize ingest by enqueuing
  one job **per host / per artifact-family / per shard** (the ingest already
  detects hosts + artifact families) so several workers index concurrently.
- **Realtime status:** workers heartbeat their lease and write per-step progress
  to the job row; `job_status` surfaces live per-job/per-worker state (extend
  `app.job_status_public` + the worker's step writes). The agent polls true state.
- **Lifecycle mgmt:** gateway (or systemd) supervises spawn/restart/reap/timeout.
  Prefer systemd-managed long-lived workers (Restart=on-failure) over
  gateway-spawned children, so worker crashes never touch the gateway and scaling
  is `systemctl start sift-opensearch-worker@N`.

---

## 5. Exact code references

- **opensearch-mcp stdio proxy mount (child of gateway → inherits sandbox):**
  `packages/sift-gateway/src/sift_gateway/mcp_server.py:570` `_create_backend_proxy`
  → `:576` `create_proxy(transport,...)`, transport built at `:580` `_stdio_transport`
  → `:589` `StdioTransport(command, args, env, ...)`. Mounted by `:504`
  `mount_single_addon_proxy`.
- **opensearch_ingest sub-worker spawn:**
  `packages/opensearch-mcp/src/opensearch_mcp/server.py:3051` `_spawn_ingest`
  (systemd-run --user → bare-Popen fallback from b93d9ed). The ingest worker
  module is `opensearch_mcp.ingest_cli` (spawned with `--case <id>` + env).
- **Durable job claim pattern:**
  `packages/sift-core/src/sift_core/execute/job_worker.py` — `JOB_TYPES` `:37`,
  `run_forever` `:255`, `run_once`/`claim_next_job` `:277/:291`, `run_job` `:301`.
  CLI/entrypoint + handler registration:
  `packages/sift-core/src/sift_core/execute/job_worker_cli.py:18`
  (`handlers = {"run_command": run_command_job_handler}`), `:39` `main`, `:55`
  `JobWorker(...)`, `:64` `run_forever(job_types=...)`.
- **Gateway → job dispatch:**
  `packages/sift-gateway/src/sift_gateway/job_tools.py:92` `handle_run_command_job`,
  `:121` `spec_internal["case_dir"]=case.artifact_path`, `:127`
  `enqueue_job(job_type="run_command", ...)`, `:148` `handle_job_status`.
  Enqueue/status service: `packages/sift-gateway/src/sift_gateway/jobs.py:162`
  `enqueue_job` (RPC `app.enqueue_job`), status via `app.job_status_public`.
- **Worker handler consuming case_dir (template for ingest/enrich handlers):**
  `packages/sift-core/src/sift_core/execute/run_command_job.py:16`
  `run_command_job_handler`, `:32` reads `spec_internal["case_dir"]`, `:43`
  builds `ActiveCaseContext`.
- **systemd units + HR3 hardening:**
  `configs/systemd/sift-gateway.service:50-94` (BATCH-HR3 block);
  `configs/systemd/sift-job-worker.service:44-69`. Both: `ProtectSystem=strict`,
  `ProtectHome=tmpfs`, `PrivateTmp=true`, `MountFlags=` (empty),
  `CapabilityBoundingSet` as above. (On the VM, units live at
  `/etc/systemd/system/sift-{gateway,job-worker}.service`.)
- **case_dir injection (P0, build on this):** backend accessor
  `packages/opensearch-mcp/src/opensearch_mcp/server.py` `active_case_dir()` +
  `_INJECTED_CASE_DIR` contextvar; gateway injection
  `packages/sift-gateway/src/sift_gateway/policy_middleware.py:764` and
  `packages/sift-gateway/src/sift_gateway/server.py:1002`
  (`("case_dir", active_case.artifact_path or "")`); manifest
  `packages/opensearch-mcp/sift-backend.json` (`safe_case_argument_names`
  includes `case_dir` for ingest/inspect/case_summary/ingest_status/enrich_intel/
  fix_host_mapping); schema enum
  `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json` (`case_dir`).
- **Mount code (where FUSE happens):**
  `packages/opensearch-mcp/src/opensearch_mcp/containers.py` — `_mount_ewf` (4
  strategies: xmount/ntfs-3g, xmount/loop, ewfmount/loop, ewfmount/direct), all
  via `sudo`. **Currently at HEAD (band-aid reverted) — plain `["sudo", ...]`.**
- **Ingest mount sudoers:** `scripts/setup-ingest-mount-sudoers.sh` →
  `/etc/sudoers.d/sift-ingest-mount` (`SIFT_MOUNT` alias). At HEAD (no SCOPED
  additions).

---

## 6. Reverted band-aid (confirm it stays reverted)

For the FUSE attempt I had: wrapped mount cmds in `sudo systemd-run --scope`
(containers.py), added a `SIFT_MOUNT_SCOPED` sudoers alias, added
`MountFlags=shared` drop-ins, and edited unit HR3 comments. **ALL REVERTED:**
- Branch: `git checkout` restored containers.py, both unit files,
  setup-ingest-mount-sudoers.sh, test_containers.py to HEAD (verified: no
  `_mount_cmd`/`systemd-run`/`MountFlags` in containers.py).
- VM: removed `/etc/systemd/system/sift-{gateway,job-worker}.service.d/
  10-fuse-mount-propagation.conf`, restored `/etc/sudoers.d/sift-ingest-mount` to
  the original `SIFT_MOUNT`-only content (visudo-validated), restored the original
  `containers.py` in /opt, `daemon-reload` + restart. Confirmed
  `systemctl show sift-gateway.service -p MountFlags` → `MountFlags=` and
  `ProtectSystem=strict`. Gateway is hardened.

---

## 7. Step-by-step build plan (fresh builder)

1. **Migration:** add a DB migration if needed so `app.job_status_public` exposes
   per-step progress + worker id (realtime status). Confirm `app.claim_next_job`
   accepts a `job_types` filter (it does — `run_once(job_types=...)`).
2. **Worker handlers (sift-core):** add `ingest_job_handler` and
   `enrich_job_handler` in `packages/sift-core/src/sift_core/execute/` modeled on
   `run_command_job.py`: read `spec_internal["case_dir"]`, build
   `ActiveCaseContext`, call the existing opensearch ingest/enrich code paths
   (factor the body of `opensearch_mcp.ingest_cli` / `opensearch_ingest` so the
   handler can call it in-process or spawn it within the worker's own — now
   shared — namespace). Register them in `job_worker_cli.py:build_handlers`.
3. **New unit:** `configs/systemd/sift-opensearch-worker@.service` (template,
   start `@1..@N`). Copy the worker unit's HR3 block; change ONLY
   `MountFlags=shared` (+ `DeviceAllow=/dev/fuse rw` if `DevicePolicy` needs it).
   `ExecStart=.../sift-opensearch-worker --job-types ingest,enrich`. Document the
   single relaxation in the unit comment + update
   `docs/skills/agentic-security/references/repo-security-baseline.md` (control
   B/H, FUSE item: OPEN → RESOLVED-via-decoupled-worker).
4. **Gateway dispatch:** add `handle_opensearch_ingest_job` /
   `handle_opensearch_enrich_job` in `job_tools.py` (resolve case + evidence at
   the gateway, `enqueue_job(job_type="ingest"|"enrich", spec_internal={case_dir,
   ...})`, return job_id). Route the `opensearch_ingest`/`opensearch_enrich_intel`
   gateway tools to dispatch instead of proxying to the stdio child. KEEP query
   tools (search/aggregate/timeline/count/field_values/list_detections) on the
   thin proxy (no privilege need).
5. **Parallelism:** in the ingest dispatch, enqueue one job per host /
   artifact-family so multiple `@N` workers index concurrently. Confirm
   `FOR UPDATE SKIP LOCKED` prevents double-claim.
6. **Install wiring:** `install.sh` must `systemctl enable --now
   sift-opensearch-worker@1` (and a configurable N), and the sudoers + fuse.conf
   (`user_allow_other`, already set) must be present.
7. **Live-prove (the gate):** `opensearch_ingest(evidence/rocba-cdrive.e01,
   dry_run=false, force=true)` → mounts (no `Operation not permitted`) → indexes
   disk artifact families (mft/usn/evtx/registry/...) → **Hayabusa indices land**
   (`case-*-hayabusa-*`). Then `opensearch_list_detections` + `opensearch_search`/
   `timeline` on the evtx/hayabusa indices return real Sigma hits (ideally the
   RDP/logon detections around 2020-11-13). Capture counts + representative hits.
8. **Verify gateway stays hardened** (`MountFlags=` empty on the GATEWAY unit;
   only the worker unit relaxed) and the run_command security invariants still
   hold (in-case write OK, evidence write denied, secret read blocked).

---

## 8. Security invariants (must hold throughout)
Gateway = sole policy boundary; run_command shell=False + deny-floor; in-case
writable but evidence/ + integrity records + out-of-case + secret paths denied;
secret redaction always on; evidence gate; chattr +i immutability; append-only
hash-chained audit; FORCE RLS; SECURITY DEFINER revoke. The decoupled worker must
NOT widen the gateway; the ONLY new relaxation is `MountFlags=shared` (±
`DeviceAllow=/dev/fuse`) on the isolated opensearch-worker unit.
