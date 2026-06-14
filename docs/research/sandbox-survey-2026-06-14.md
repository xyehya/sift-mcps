# Sandbox Survey — SIFT MCP Gateway (2026-06-14)

> Source: RUN-1 RESEARCH agent (voltagent-research:research-analyst), web-cited.
> Input for RUN-3 (sandbox implementation). Decision-grade; verify the two host
> prerequisites (kernel version, nested KVM) on the live SIFT VM before committing.

## Executive Recommendations

**For (A) — Hermes agent code-exec sandbox:** Use **bubblewrap (bwrap) with socat network proxy**, following the same pattern Claude Code already deploys in production. The agent's Python glue code runs inside a bwrap process jail with `--unshare-all` plus a bind-mounted Unix socket to the gateway `/mcp` endpoint; all other filesystem access is denied by default, and network egress is forced through a host-side socat proxy. This is battle-tested, unprivileged, requires no daemon, and imposes no KVM/nested-virtualization requirement.

**For (B) — run_command forensic tool-exec sandbox:** The pragmatic and architecturally correct ceiling is **Landlock + seccomp-bpf layered on top of the existing cgroup+rlimit baseline**, with an AppArmor profile permitting `mount fstype=fuse.`. Full container or VM isolation is structurally incompatible with FUSE mounts (which need host mount namespace + CAP_SYS_ADMIN), large mmap on RAM images, and dotnet's runtime syscall surface. Landlock scopes every forensic child process to the resolved `case_dir` subtree; seccomp filters out privilege-escalation syscalls while leaving `mount`, `mmap`, `ioctl`, and `open` intact for forensic use. No bwrap/nsjail wrapping of the forensic binary path is recommended — wrap the boundary at the gateway (policy) level, not the execution level.

---

## Comparison Table

| Technology | Isolation Mechanism | Self-host / Offline | License | FUSE compat | dotnet / large mmap | Escape Surface | (A) Agent Exec | (B) Forensic Exec |
|---|---|---|---|---|---|---|---|---|
| **bubblewrap (bwrap)** | User namespaces, mount ns, net ns, seccomp-bpf | Yes, single binary, offline | LGPL-2+ | Blocked by mount-ns unless CAP_SYS_ADMIN given; /dev/fuse passthrough possible but collapses isolation | Pass-through if allowed; mmap OK | User-ns kernel bugs; Ubuntu 24.04 AppArmor restriction on userns (fixable) | **High** — lightweight, battle-tested, no daemon, exact Claude Code production pattern | **Low** — private mount-ns blocks FUSE; CAP_SYS_ADMIN defeats confinement |
| **nsjail** | Namespaces (all 7) + cgroups + rlimits + seccomp-bpf (Kafel DSL) | Yes, needs build or binary, offline | Apache-2.0 | Same mount-ns problem as bwrap; FUSE requires relaxed policy | mmap fully configurable via Kafel | User-ns surface + protobuf config parser | **High** — zero-daemon, sub-20ms startup, Windmill uses it for Python prod | **Low** — mount-ns kills FUSE; complex config |
| **Landlock LSM** | Kernel-enforced path ACL, TCP port scope, IPC scope (ABI v1-v6, kernel 5.13-6.12+) | Kernel built-in, zero deps | GPL (kernel) | No restriction on FUSE — limits open/read/write by path, not the mount syscall | Fully compatible; no mmap restriction | Cannot be lifted once set; attacker limited to allowed paths | **Med** — best as add-on layer | **High** — ideal path confinement: allow case_dir, deny rest; no FUSE/mmap block |
| **seccomp-bpf** | Syscall-level filter (allow/denylist BPF) | Kernel built-in | GPL (kernel) | Compatible if mount/ioctl/openat allowed | mmap/ioctl/openat allowable; dotnet needs broad surface | BPF JIT bugs; spec-exec leaks | **High** — deny shell/exec/ptrace/unshare | **High** — denylist ptrace/unshare/mount-nonfuse/pivot_root; whitelist forensic |
| **AppArmor** | LSM path+cap MAC policy | Already deployed on SIFT | GPL (kernel) | Fully compatible — `mount fstype=fuse.` rules | No mmap/dotnet restriction | Profile transitions; complain-mode bypass | **Med** — adds path+cap confinement, no ns isolation | **High** — clean fuse mount rule, restrict out-of-case writes, already used |
| **systemd unit directives** | ProtectSystem, PrivateUsers, CapabilityBoundingSet, SystemCallFilter | Built-in, zero deps | LGPL | ProtectSystem=strict creates private mount-ns → FUSE fails (proven live on SIFT) | No mmap restriction; dotnet OK | Root escape if caps not dropped | **Med** — service hardening, no per-invocation sandbox | **Med** — existing worker proved FUSE needs ProtectSystem removed |
| **gVisor (runsc)** | User-space kernel (Sentry); KVM-accel Systrap | Self-hostable, no KVM required (Systrap) | Apache-2.0 | FUSE mmap is a tracked open bug (#3234); virtiofs unsupported (#12396) | mmap "Full" but FUSE-mmap open; dotnet may hit unsupported syscalls | Sentry Go bugs; 74 unsupported syscalls | **Med** — good isolation, ~50ms; some lib compat issues | **Low** — FUSE mmap broken → blocks ewfmount/xmount |
| **Firecracker microVM** | KVM hardware virtualization; guest kernel per VM | Self-hostable but requires /dev/kvm | Apache-2.0 | Guest FUSE needs guest driver; host FUSE tools unreachable | Guest-local mmap isolated; dotnet in guest | VMM escape; needs nested KVM on SIFT | **High** strongest isolation; complex ops | **Low** — host forensic FUSE/binaries unreachable |
| **LXC/LXD** | Namespaces + cgroups + seccomp + AppArmor | Self-hostable, offline | Apache-2.0 | Privileged: FUSE w/ CAP_SYS_ADMIN; unprivileged needs LXCFS shim | Compatible in privileged mode | Privileged = host root | **Med** — heavier than bwrap | **Med** — FUSE needs privileged (widens surface); Landlock+seccomp simpler |
| **Docker/Podman rootless** | Namespaces + seccomp default + AppArmor | Self-hostable, offline | Apache-2.0 / Moby | FUSE needs --device /dev/fuse + AppArmor rule; Ubuntu 25.04 friction | mmap/dotnet OK | Escape CVEs (CVE-2024-21626) | **Med** — image mgmt overhead | **Low** — FUSE complexity, no advantage over Landlock+seccomp |
| **microsandbox** | libkrun microVMs (KVM); sub-200ms | Self-hostable, air-gap; requires /dev/kvm | Apache-2.0 | Guest-local FUSE; host paths not accessible | Isolated guest; dotnet in guest | VMM escape; needs nested KVM | **High** — air-gap MCP-native; KVM prereq risk | **Low** — host-path/FUSE isolation problem |
| **E2B** | Firecracker microVMs; BYOC cloud | BYOC AWS/GCP; not single-VM offline | Apache-2.0 SDK; cloud infra | N/A cloud | Guest-local | Cloud egress | **Low** — cloud dep | **Low** — air-gap impossible |
| **Daytona** | Containers, hardened runc | Self-host (AGPL-3.0) | AGPL-3.0 | Container: FUSE needs /dev/fuse | Works in sandbox | Container escape; AGPL copyleft | **Med** — sub-90ms; AGPL risk | **Low** — Docker FUSE problem |
| **Sandlock (Multikernel)** | Landlock + seccomp + user-notif supervisor; BranchFS CoW | Self-host, offline; needs Linux 6.12+ | MIT | BranchFS uses FUSE CoW; supervisor intercepts mmap | mmap intercepted (overhead); dotnet overhead | Kernel escape if Landlock/seccomp bypassed | **High** — no-root, 1ms, CoW FS (needs 6.12+) | **Med** — mmap interception may slow vol; needs 6.12+ |
| **sandboxd (tastyeffect)** | Hardened runc Docker; dropped caps, ro rootfs | Self-host (Docker req) | MIT | No (Docker-level) | Works in container | Container escape; recommends gVisor/Kata | **Low** — web-preview design | **Low** |
| **Anthropic sandbox-runtime (srt)** | bwrap (Linux) + socat; macOS Seatbelt | Self-host, offline | Apache-2.0 | Not addressed (bwrap mount-ns blocks FUSE) | Pass-through if configured | Same as bwrap | **High** — purpose-built for agent code exec | **Low** — FUSE unsupported |

---

## Per-Technology Notes (key points + citations)

- **bubblewrap** — unprivileged ns sandbox; Flatpak/Claude Code production. Private mount-ns is the FUSE blocker (confirmed live on SIFT worker). Ubuntu 24.04: `kernel.apparmor_restrict_unprivileged_userns=1` blocks userns; fix with a `bwrap` AppArmor `userns` profile (Claude Code documents this). [containers/bubblewrap](https://github.com/containers/bubblewrap), [FUSE #132](https://github.com/containers/bubblewrap/issues/132), [Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing).
- **nsjail** — Google; all 7 ns + Kafel seccomp DSL; Windmill prod. Sub-20ms. Same mount-ns FUSE problem. [google/nsjail](https://github.com/google/nsjail), [Kafel](https://google.github.io/kafel/).
- **Landlock** — kernel 5.13+ self-imposed, irreversible path/net ACL. Does NOT restrict mount/mmap/ioctl → forensic-compatible; only scopes which files can be opened. Ubuntu 22.04=kernel 5.15 (v1/v2 path rules, sufficient). [kernel.org Landlock](https://docs.kernel.org/userspace-api/landlock.html), [landlock(7)](https://man7.org/linux/man-pages/man7/landlock.7.html).
- **seccomp-bpf** — kernel 3.5+ syscall filter. Denylist ptrace/unshare/pivot_root/kexec/bpf/keyctl while allowing mount/mmap/ioctl/openat/execve → forensic-safe. [Seccomp wiki](https://en.wikipedia.org/wiki/Seccomp), [USENIX 2025 usability](https://www.usenix.org/system/files/soups2025-alhindi.pdf).
- **AppArmor** — already on SIFT. `mount fstype=fuse.` supported (Docker ships it). Watch Ubuntu fusermount3 bug #2100295. [Docker/AppArmor FUSE](https://wikitech.wikimedia.org/wiki/Docker/apparmor), [bug #2100295](https://bugs.launchpad.net/bugs/2100295).
- **systemd** — `ProtectSystem=strict`/`PrivateTmp` create private mount-ns → FUSE fails (proven on SIFT worker). Use `SystemCallFilter`/`CapabilityBoundingSet`/`NoNewPrivileges` only. [systemd sandboxing](https://www.justsem.org/posts/systemd-sandbox/).
- **gVisor** — FUSE-mmap broken (#3234), virtiofs unsupported (#12396), dotnet uses unsupported syscalls → incompatible with forensic toolchain. [gvisor.dev](https://gvisor.dev/docs/), [#3234](https://github.com/google/gvisor/issues/3234).
- **Firecracker / microsandbox** — strong isolation but host forensic FUSE/binaries unreachable from guest; need /dev/kvm + nested KVM on the SIFT guest. [firecracker](https://firecracker-microvm.github.io/), [microsandbox](https://microsandbox.dev/).
- **LXC/LXD, Docker/Podman, Daytona, sandboxd** — container FUSE needs privileged/`--device /dev/fuse`; no advantage over Landlock+seccomp for (B); container-escape CVEs. [Docker rootless](https://docs.docker.com/engine/security/rootless/), [moby #50013](https://github.com/moby/moby/issues/50013).
- **Sandlock** — best-in-class agent sandbox (Landlock+seccomp+supervisor+BranchFS, 1ms, MIT) but needs Linux 6.12+ (SIFT 22.04 = 5.15) and mmap interception may slow Volatility3. [arXiv](https://arxiv.org/html/2605.26298v1), [blog](https://multikernel.io/2026/03/14/introducing-sandlock/).
- **Anthropic sandbox-runtime (srt)** — the package under Claude Code `/sandbox`: bwrap + socat on Linux. Embeddable directly as Hermes's process wrapper. [anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime).

---

## Integration Sketch: (A) Hermes Agent Code-Exec Sandbox

**Chosen: bubblewrap + socat (Anthropic sandbox-runtime pattern).**

The gateway spawns Hermes's Python glue subprocess wrapped by bwrap. The `callMCPTool` shim reaches the gateway via a Unix domain socket bind-mounted into the jail. No raw TCP to the internet; no host FS access.

```
gateway process
└─ bwrap \
     --unshare-all \                    # isolate all namespaces
     --new-session \                    # prevent TIOCSTI injection
     --ro-bind /usr/lib /usr/lib \      # Python runtime, read-only
     --ro-bind /usr/bin/python3 /usr/bin/python3 \
     --ro-bind /opt/sift-mcps /opt/sift-mcps \   # agent code, read-only
     --bind /tmp/hermes-session-XYZ /tmp \        # ephemeral writable tmpdir
     --bind /run/sift/mcp.sock /run/sift/mcp.sock \  # gateway Unix socket (RW)
     --dev /dev --proc /proc --tmpfs /run \
     -- python3 /opt/sift-mcps/hermes/agent.py
```

- **callMCPTool connectivity:** shim connects to `/run/sift/mcp.sock`; gateway authenticates via a session-scoped short-lived token injected into the subprocess env. Gateway is the policy boundary — sandbox does NOT re-implement MCP authz.
- **Network:** `--unshare-net` (loopback only); MCP via the Unix socket. Any non-MCP HTTP routes through a host socat allowlist proxy.
- **Mounts:** runtime + agent code read-only; ephemeral `/tmp` rw; the MCP socket rw; everything else denied.
- **Resource caps (systemd/cgroup before exec):** `MemoryMax=512M`, `CPUQuota=50%`, `TasksMax=32`, no capabilities.
- **Optional seccomp:** denylist ptrace/unshare/mount/pivot_root/setns/kexec_load/add_key/request_key.
- **Ubuntu 24.04:** install the `bwrap` AppArmor `userns` profile if unprivileged userns is restricted.

## Integration Sketch: (B) run_command Forensic Tool-Exec

**Chosen: Landlock + seccomp-bpf on the existing cgroup+rlimit baseline + AppArmor fuse rule. No bwrap wrapper.**

Today: cgroup + rlimit + `shell=False` argv parsing. Gaps: forensic binary can open any host file (secrets, other cases, tokens), call ptrace/unshare, no FS-scope.

- **Landlock (primary):** applied in the `run_command` handler immediately before `execve` via `landlock_restrict_self`. Grant read on resolved `case_dir` + `/usr` + `/opt/sift-mcps` + `/tmp`; grant write on `case_dir/agent/`; deny all else. FUSE/mmap/dotnet unaffected.
- **seccomp-bpf (secondary):** denylist `ptrace, unshare, setns, pivot_root, chroot, kexec_load, init_module, perf_event_open, bpf, add_key, request_key, keyctl`. MUST allow: `mount` (FUSE), `mmap/mremap` (vol), `ioctl` (FUSE/TSK), `openat/read/write/close`, `execve/clone/fork/wait4`, dotnet CLR syscalls (`futex, epoll_*, eventfd2, getrandom, set_robust_list, arch_prctl`).
- **AppArmor:** forensic-exec profile allows `mount fstype=fuse.` + `case_dir/** rwk` + `/usr/bin/* rix`; denies writes to `/etc /root /home`; keeps `capability sys_admin` for ewfmount/xmount. Apply the same "remove ProtectSystem for FUSE" lesson the opensearch worker proved.
- **Migration:** no change to argv parsing. Add Landlock + seccomp pre-exec (ctypes or pylandlock; fall back to seccomp-only if kernel <5.13). Roll out in complain/log mode before KILL/ERRNO. Add a regression test: attempt `/etc/passwd` open from inside run_command → Landlock blocks.

| Gap today | Fixed by |
|---|---|
| Reads any host file | Landlock: case_dir only |
| Writes anywhere | Landlock: agent/ only |
| ptrace/unshare escalation | seccomp denylist |
| FUSE/mmap/dotnet must keep working | seccomp allows mount/mmap; AppArmor fuse rule; no mount-ns |

---

## Open Questions / Tradeoffs for the Operator

1. **Nested KVM on the SIFT VM** — microsandbox/Firecracker (option-A alternatives) need `/dev/kvm` inside the guest (nested virt on the physical host). Verify `ls /dev/kvm` before committing to any microVM option.
2. **Kernel version** — SIFT 22.04 = kernel 5.15 → Landlock v1/v2 (path rules, sufficient). TCP-port (v4) / abstract-socket (v6) need 6.5/6.12. Sandlock needs 6.12+. Upgrade to 24.04 HWE only if max Landlock capability is wanted.
3. **CAP_SYS_ADMIN scope** — gateway has no CAP_SYS_ADMIN; the worker does (for FUSE). If a future `run_command` forensic tool needs FUSE directly, route it through the worker lane rather than granting the gateway CAP_SYS_ADMIN. (Fork.)
4. **Landlock + dotnet temp paths** — Zimmerman tools write temp files; `strace -e trace=openat` a test run and add their paths to the allowlist or they hit EACCES.
5. **AppArmor profile maintenance** — prefer one `sift-forensic-exec` profile (generous case_dir + strict system-path denylist) over per-tool profiles.
6. **Agent escape via MCP socket** — in (A), the only exit is the gateway socket (re-authed per call). Mitigate stolen-JWT replay: scrub creds from subprocess env, inject only a short-lived session token.
7. **seccomp denylist drift** — audit any new forensic tool's syscall surface (strace) before adding; burn-in with `SECCOMP_RET_TRACE`+logging.
8. **Air-gap** — bwrap (A) and Landlock+seccomp (B) need no cloud, no daemon, no registry. Fully air-gap compatible.

---

## TL;DR

For Hermes agent code-exec (A), deploy **bubblewrap** with `--unshare-all` + a socat Unix-socket bridge to the gateway MCP endpoint — the exact pattern Anthropic's sandbox-runtime and Claude Code use in production: strongest namespace sandbox that runs without KVM, offline-capable, Apache-2.0, natural Python fit. For forensic tool-exec (B), the SIFT-proven constraint is that FUSE mounts need the host mount namespace + CAP_SYS_ADMIN, making bwrap/nsjail/gVisor/Docker structurally incompatible with ewfmount/Volatility3/dotnet; the correct ceiling is **Landlock** path-confinement (lock each forensic exec to `case_dir`) + a **seccomp-bpf** denylist (ptrace/unshare/pivot_root/kexec/bpf/keyctl) + an **AppArmor** profile allowing `mount fstype=fuse.`, layered on today's cgroup+rlimit baseline with zero change to the `shell=False` path — defense-in-depth against lateral FS access and privilege escalation while leaving every forensic capability fully functional.
