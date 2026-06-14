# RUN-3 — `run_command` Hardening: Build Plan + Operating Model

> **This file is the executable operating model for RUN-3.** A fresh orchestrator session
> picks up here and launches. The AUTHORITATIVE design is
> [`docs/research/run_command-FINAL-SPEC.md`](research/run_command-FINAL-SPEC.md) — this plan
> sequences its §9 phases into disjoint-fence agent batches. If this plan and the spec ever
> disagree, the spec wins; fix this plan.

Status: **READY TO LAUNCH** (design frozen; not started). Created 2026-06-14.
Branch base: LOCAL `main` (origin synced @ `2015b94`). Worktrees made MANUALLY off local main
(`isolation:worktree` branches off stale origin — see `[[reference-agent-worktree-base-bug]]`).

---

## 0. What we are building (one paragraph)

`run_command` is the autonomous DFIR agent's deep-dive exec escape hatch. We add a **Floor**
(kernel jail: Landlock + seccomp + systemd-cgroup + AppArmor, all in the host mount namespace so
FUSE/mmap/dotnet survive — **NOT bwrap/LXD**) and harden the **Ceiling** (validator: allowlist
default + per-tool code-exec scanners + env-deny + output sanitation). Floor bounds blast radius
(G3/G4/G5/G7) at the kernel regardless of validator bugs; Ceiling stops code-exec-as-tool
(G1/G2/G9). Both required. Closes red-team gaps G1–G9.

## 1. Non-negotiable invariants (carry into every batch prompt)

- **AUTONOMOUS — ZERO human-in-the-loop.** No `run_command` path may prompt a human, block on
  approval, return `approval_required`, or wait on a flag flip mid-run. Hackathon rule. Unlisted
  forensic tools run kernel-jailed in the `contained` tier (never blocked, never approved). Evidence
  is operator-pre-mounted RO at case setup (provisioning, outside the agent loop) — acceptable.
- **Both layers required** — never ship Floor-only or Ceiling-only; the spec §3 invariant.
- **Flexibility preserved** — keep the `command:str` + `shell=False` parser public API (C1); the
  jail is what lets the allowlist stay generous. Positive forensic matrix MUST stay green.
- **Don't weaken existing controls** — keep shell=False, DENY_FLOOR, env scrub (strongest control),
  evidence immutability (`chattr +i` + write-deny), basename-shadow prevention, redaction.
- **No secrets in committed files/docs** (JWT/keys/DSN/passwords/full case paths).
- Commit messages end: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Run `/security-review` on the combined diff before merge to main; run it because this touches the
  command-exec/policy/secret-redaction path. Do NOT push origin until reviewed + live-proven.

## 2. Live VM facts (verified for the spec — don't re-derive)

`sansforensics@192.168.122.81` (ssh/sudo pw `forensics`). **Ubuntu 24.04, kernel 6.8.0-110**,
LSM `lockdown,capability,landlock,yama,apparmor` (**Landlock ACTIVE, ABI v4** = native TCP
connect/bind denial; ioctl-scoping is v5/6.10 = ABSENT → ioctl stays a seccomp job), **cgroup2**,
systemd 255, **`agent_runtime` uid 995 present**, AppArmor 78 enforce profiles. Active case
`case-rocba-case-06132304`. Services: `sift-gateway`, `sift-job-worker` (run_command lane),
`sift-opensearch-worker@1`. Gateway apparmor profile already ENFORCE (from RUN-1).

**VM ops gotchas (from RUN-1):** Bash tool needs `dangerouslyDisableSandbox: true` for ssh/network;
call `sshpass -p forensics ssh …` INLINE (zsh won't word-split a `$VAR` holding the cmd); deploy =
`rsync` host worktree → `/opt/sift-mcps` (editable installs, live on restart; NOT a git tree);
restart `sift-job-worker` + `sift-gateway`. The MCP `run_command`/`opensearch_*` tools are wired
into the orchestrator session = the authenticated agent path (no token mint needed).

---

## 3. Batches (grouped by FILE OWNERSHIP → disjoint fences)

The spec's P0–P8 share files (security.py spans P1/P2; executor.py spans P2/P3/P4). To parallelize
safely, batches own **non-overlapping file sets**:

### B-CEIL — Ceiling: validator + output sanitation  (spec P1 + P2-belt + P7)
- **Fence (OWNS):** `packages/sift-core/src/sift_core/execute/{security.py, security_policy.py, runtime_acl.py}`;
  the gateway output path `packages/sift-gateway/src/sift_gateway/response_guard.py` (locate; spec calls it
  "response.py"); their tests under `packages/sift-core/tests/` + `packages/sift-gateway/tests/`.
- **Does NOT touch:** `executor.py`, `worker.py`, the new launcher, apparmor, systemd (other batches).
- **Gaps/work:** G1 default `mode: allowlist` seeded `@mvp_forensic` + new `contained` tier
  (`unlisted_policy: contained`); G2 per-tool blocked-flags + program-text scanners for
  `sed`(`s///e`)/`sqlite3`(`.shell/.load/.import/-cmd`)/`tshark`(`-X/--lua-script`)/`vol`(`--plugin-dirs/-p`)/`exiftool`(`-config/-execute`),
  mirroring the existing awk scanner (`security.py:41`); G6 add
  `chattr,lsattr,setfattr,getfattr,setcap,getcap,mount,umount,umount2,losetup,qemu-nbd,modprobe,insmod,rmmod,unshare,nsenter,capsh`
  to `DENY_FLOOR`; G3-belt add `/var/lib/sift` to `_BLOCKED_DIRECTORIES` (`security.py:274`);
  G9 deny `DOTNET_*,CORECLR_*,LD_*,PYTHON*,PERL5*,RUBYOPT,NODE_OPTIONS,LUA_*,BASH_ENV,GCONV_PATH,IFS`
  in env build (deny-after-allow); P7 strip ANSI/OSC/control-chars + attach untrusted-output
  provenance label.
- **Keep stable for B-FLOOR:** `runtime_acl.build_sandbox_env(...)` signature (the launcher imports it).
- **Done:** ceiling negative red-team rows blocked + positive rows pass; `uv run --extra dev --extra full pytest`
  on touched packages green; commit on `run3/ceil`.

### B-FLOOR — Floor: launcher + cgroup + exec wiring + G4  (spec P3 + P4 + P5)
- **Fence (OWNS):** NEW `packages/sift-core/src/sift_core/execute/dfir_exec_launcher.py`;
  `packages/sift-core/src/sift_core/execute/{worker.py, executor.py}`; their tests.
- **Does NOT touch:** security.py / security_policy.py / runtime_acl.py (B-CEIL), apparmor/systemd (B-AA).
- **Gaps/work:** G4 fail-closed runtime_user — `SIFT_EXECUTE_REQUIRE_RUNTIME_USER=1` rejects if no
  distinct runtime_user; launcher aborts if uid 0 or service uid (use `agent_runtime` uid 995).
  G5 wrap each exec in `systemd-run --scope -p MemoryMax/MemoryHigh/CPUQuota/TasksMax/RuntimeMaxSec/OOMPolicy=kill/IPAddressDeny=any`
  in `executor._run_isolated_worker`. G3/G7 the launcher: ABI-detect Landlock (v4), grant RX on
  `/usr,/bin,/sbin,/lib,/lib64,/opt/{sift-mcps,zimmermantools,volatility3,hayabusa},/proc/self`,
  R on `<case_dir>/evidence`, RW+MAKE on `<case_dir>/{agent,extractions,tmp}`, deny all else
  (incl `/var/lib/sift`, other cases) + Landlock NET deny; FD-close before restrict; PR_SET_NO_NEW_PRIVS
  then landlock_restrict_self; prod fail-closed `SIFT_EXECUTE_REQUIRE_LANDLOCK=1`. seccomp filter
  in launcher in **`SECCOMP_RET_LOG` (burn-in) mode this wave** (flip to KILL is a Wave-2 live step) —
  allow forensic syscalls, (log) kill set per spec §4 (ptrace/unshare/setns/pivot_root/bpf/kexec/
  init_module/perf_event_open/keyctl/io_uring/mount). Launcher exec'd as worker stage argv wrapper:
  `[dfir-exec-launcher, --policy=<fd>, --, <real_tool>, <args>]`. Pure-Python `ctypes` (~250 lines;
  VM forbids managed toolchains).
- **Coordinate seam:** imports `runtime_acl.build_sandbox_env` (B-CEIL) — read-only use; don't edit it.
- **Done:** Landlock + FD-close + uid-assert + cgroup rows green; positive matrix green with seccomp
  in LOG mode; commit on `run3/floor`.

### B-AA — AppArmor + systemd-unit backstop  (spec P6 + unit hardening)
- **Fence (OWNS):** `configs/apparmor/**` (new `dfir-exec`/job-worker profile, complain mode);
  `configs/systemd/sift-job-worker.service` (`NoNewPrivileges=yes`, `RestrictSUIDSGID`, `LockPersonality`,
  `SystemCallArchitectures=native`; keep `ProtectSystem` OFF for FUSE); `install.sh` apparmor-gen if needed;
  a `configs/` note for the `systemd-run --scope` sudoers/polkit grant the worker needs.
- **Does NOT touch:** any execute/*.py.
- **Done:** profile authored (complain), unit hardened, `bash -n install.sh` ok; the complain→enforce
  flip is a Wave-2 live step. Commit on `run3/aa`.

### B-GATE — Red-team harness + acceptance gate  (spec P8 + §8 + §10)
- **Fence (OWNS):** NEW `packages/sift-core/tests/security/**` (or `tests/security/`) — the negative
  + positive red-team matrix from spec §8 as runnable tests + a runbook of the live positive matrix.
- **Does NOT touch:** production code (tests only).
- **Work:** encode every negative PoC (sqlite3 `.shell`, sed `s///e`, tshark `-X lua_script:`,
  vol `--plugin-dirs`, `xxd /var/lib/sift/...`, `chattr -i evidence/x`, symlink→/var/lib/sift,
  fork-bomb, DOTNET_STARTUP_HOOKS, LD_PRELOAD, cross-case read, evidence write, OSC escape,
  `approval_required` MUST-NOT-EXIST) as asserts-blocked; positive matrix (vol/TSK/EZ/tshark/yara/rg/
  pipelines) as asserts-pass; evidence pre/post hash assert.
- **Done:** harness runs (negative green=blocked; positive may be partially xfail until Floor lands
  live); commit on `run3/gate`. Final validation in Wave 2.

---

## 4. Sequencing / dependency graph

```
WAVE 0 (done): P0 inventory — VM facts logged §2. No action.

WAVE 1 — PARALLEL, host-code only, disjoint fences (4 agents, like RUN-1):
   B-CEIL ∥ B-FLOOR ∥ B-AA ∥ B-GATE
   - seccomp ships LOG-mode (no positive-matrix break)
   - each: code + LOCAL targeted tests; STOP before VM; report changes/tests/forks/VM-proof steps
   - seam: B-FLOOR imports B-CEIL's build_sandbox_env (stable signature) — no edit overlap
        ↓  (orchestrator reconciles)
RECONCILE → branch run3/integrate off local main; merge ceil+floor+aa+gate (disjoint → clean);
   per-package pytest + validate_docs + bash -n; resolve any seam.
        ↓
/security-review on combined diff (command-exec/policy/secret path) → fix findings.
        ↓
WAVE 2 — SERIAL on live VM (orchestrator drives; mirrors RUN-1 VM protocol):
   1. rsync deploy → restart sift-job-worker + sift-gateway → health.
   2. Verify runtime_user: confirm run_command runs as agent_runtime (uid 995), not service user (G4).
   3. POSITIVE forensic matrix via MCP run_command on real evidence (vol/fls/icat/EvtxECmd/tshark/
      yara/rg/pipelines) — all succeed (flexibility intact).
   4. NEGATIVE red-team harness via MCP — every case fails closed.
   5. seccomp burn-in: run positive matrix under RET_LOG, harvest syscalls (auditd), patch allow-set,
      then FLIP launcher seccomp LOG→KILL; re-run positive matrix (must stay green) + negative.
   6. AppArmor dfir-exec profile complain→enforce (RUN-1 audit-log-driven method: exercise → harvest
      AVCs → patch → apparmor_parser -r → smoke; aa-complain fallback). 0 denials on positive matrix.
   7. Evidence integrity: sha256 pre/post + chattr +i intact after full matrix.
   8. Walk spec §10 go/no-go checklist — every box.
        ↓
LAND: merge run3/integrate → main; push origin (after review + live-proof). Log Session-Notes; update memory.
```

Dependencies: B-GATE's live pass depends on B-CEIL+B-FLOOR deployed. B-AA enforce flip is last
(needs CEIL+FLOOR traffic exercised). seccomp KILL flip depends on the positive-matrix burn-in.

---

## 5. Status tracker (update as batches land)

- [ ] WAVE 1 launched (4 agents off local main)
- [ ] B-CEIL — `run3/ceil` — G1/G2/G6/G3-belt/G9 + output sanitation; local tests green
- [ ] B-FLOOR — `run3/floor` — launcher (Landlock+FD+uid) + cgroup + G4; seccomp LOG; local green
- [ ] B-AA — `run3/aa` — apparmor profile (complain) + unit hardening; bash -n ok
- [ ] B-GATE — `run3/gate` — negative+positive harness encoded
- [ ] RECONCILE → `run3/integrate`; gate green
- [ ] `/security-review` combined diff — clean / fixed
- [ ] WAVE 2 deploy + positive matrix green (flexibility)
- [ ] WAVE 2 negative harness all-blocked
- [ ] seccomp LOG→KILL flipped; positive still green
- [ ] AppArmor dfir-exec complain→enforce; 0 denials
- [ ] evidence integrity pre/post intact
- [ ] spec §10 checklist all-true
- [ ] merge main + push origin + log + memory

---

## 6. Fresh-session launch prompt (paste to start RUN-3)

```
You are the orchestrator for RUN-3 (run_command hardening). Operating model + tracker:
docs/RUN3-run_command-hardening-BUILD-PLAN.md. Authoritative design: docs/research/
run_command-FINAL-SPEC.md. Read both first, plus the §1 invariants (AUTONOMOUS — zero HITL)
and §2 live VM facts.

Execute the plan:
1. Confirm local main is clean + synced to origin; make 4 worktrees MANUALLY off LOCAL main
   (run3/ceil, run3/floor, run3/aa, run3/gate) — do NOT use isolation:worktree (stale-origin bug).
2. Launch WAVE 1: 4 parallel agents, one per batch (§3), each hard-bound to its FENCE + the §1
   invariants + repo conventions (no new abstractions; raise a fork, don't decide; no secrets).
   Suggested agents: B-CEIL/B-FLOOR = voltagent-core-dev:backend-developer; B-AA =
   general-purpose; B-GATE = voltagent-qa-sec test author or general-purpose. seccomp ships LOG-mode.
3. Reconcile → run3/integrate; per-package pytest + validate_docs + bash -n; /security-review the
   combined diff; fix findings.
4. WAVE 2 serial on the live VM (rsync deploy; sshpass inline + dangerouslyDisableSandbox; restart
   sift-job-worker+gateway): runtime_user check → positive forensic matrix → negative red-team
   harness → seccomp LOG→KILL burn-in → AppArmor complain→enforce (audit-log-driven) → evidence
   integrity → spec §10 checklist.
5. Land: merge run3/integrate→main, push origin, log Session-Notes + update memory.

Gate every step; the positive forensic matrix must stay green (flexibility) and every negative PoC
must fail closed. Update the §5 status tracker as batches land.
```

---

## 7. Backlog (out of RUN-3 scope; B# in Session-Notes)
- `run_command_structured({stages})` second entrypoint (C1 migration) — no deprecation of string API.
- LXD/microVM Tier-2 for malware-adjacent binaries (C4 dropped for hackathon).
- Landlock ioctl-scoping (ABI v5) when VM kernel ≥ 6.10.
- Make AppArmor enforce the install.sh default (carry-over from RUN-1 B-MVP-018 note).
