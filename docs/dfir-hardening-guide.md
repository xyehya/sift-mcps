# AgentIR — DFIR OS Hardening Guide

This guide documents the OS-level evidence hardening implemented in Phase 17. It covers what each mechanism does, what it protects against, how to verify it is active, and — critically — what it cannot protect against.

**The honest premise:** Cryptographic controls (HMAC-signed ledger, SHA-256 manifest) are the chain-of-custody proof. OS hardening is the accident guard and audit paper trail. Both are necessary; neither is sufficient alone.

---

## Overview of Mechanisms

| Mechanism | Phase | Threat it addresses | What it cannot stop |
|-----------|-------|--------------------|--------------------|
| `chattr +i` immutable flag | 17a | Accidental modification; converts deliberate tampering into an auditable act | Root user with `chattr -i` |
| `setcap cap_linux_immutable` | 17a | Allows gateway to manage +i without running as root | Anything after a kernel compromise |
| auditd kernel rules | 17b | Records `chattr -i`, writes, attribute changes — creates a dated paper trail | Root user clearing audit logs |
| AppArmor MAC profile | 17c | Denies gateway process write access to evidence files at kernel level | Root user unloading the profile |
| inotify evidence watcher | 17d | Detects evidence directory changes in real time (sub-30s, not TTL-dependent) | Changes outside `evidence/` |

---

## 17a — `chattr +i` Immutable Flag

### What It Does

The Linux `chattr +i` flag tells the kernel to make a file immutable — no writes, no deletions, no renames, no permission changes, even by root. The flag is stored in the filesystem inode and enforced at the VFS layer.

AgentIR sets `+i` on every evidence file after it is sealed into the manifest. The flag is cleared before rehashing (for re-seal) and set again after the ledger event.

### Why It Matters

Without `+i`, a file in `evidence/` can be:
- Overwritten by any process with write permission
- Deleted
- Renamed

With `+i`, clearing the flag before tampering is a separate, explicitly auditable step. This is where auditd picks up the trail.

### How It Is Implemented

`sift-core` uses Linux `fcntl` ioctl:

```python
_FS_IOC_GETFLAGS = 0x80086601
_FS_IOC_SETFLAGS = 0x40086602
_FS_IMMUTABLE_FL = 0x00000010

def _set_immutable(path, immutable: bool) -> bool:
    flags_val = ctypes.c_int(0)
    with open(path, "rb") as f:
        fcntl.ioctl(f.fileno(), _FS_IOC_GETFLAGS, flags_val)
    if immutable:
        flags_val.value |= _FS_IMMUTABLE_FL
    else:
        flags_val.value &= ~_FS_IMMUTABLE_FL
    with open(path, "rb") as f:
        fcntl.ioctl(f.fileno(), _FS_IOC_SETFLAGS, flags_val)
    return True
```

This requires `CAP_LINUX_IMMUTABLE`. Rather than running the gateway as root, `install.sh` grants this capability to the specific Python binary:

```bash
setcap cap_linux_immutable+ep /path/to/uv-python3.11
```

If the capability is not present (EPERM), `_set_immutable` returns `False` and logs a WARNING. The seal operation does not fail — the cryptographic ledger remains authoritative.

### Verifying It Is Active

```bash
# Check capability on the Python binary
getcap ~/.local/share/uv/python/cpython-3.11.*/bin/python3.11

# Check a sealed evidence file
lsattr /cases/your-case/evidence/host1/disk.E01
# Should show: ----i--------e-- /cases/.../disk.E01

# Portal: evidence chain status panel shows per-file immutable flag status
```

### Supported Filesystems

Requires ext4, XFS, btrfs, or any Linux filesystem that supports the `FS_IMMUTABLE_FL` ioctl. Does not work on NFS, NTFS, FAT32, or FUSE. On unsupported filesystems, the gateway logs a WARNING and falls back to cryptographic-only protection.

---

## 17b — auditd Kernel Audit Rules

### What It Does

The Linux kernel audit subsystem records security-relevant events independently of any application. AgentIR installs rules that watch the cases directory and the agentir state directory for any write or attribute-change event.

### The Key Insight

`perm=a` (attribute change) catches `chattr -i`. When anyone clears the immutable flag before tampering, the kernel records:
- Exact timestamp (monotonic, from kernel time)
- UID and effective UID of the process
- PID and process executable path
- System call (setxattr / ioctl with `FS_IOC_SETFLAGS`)
- Filepath

This is recorded before any tampering occurs. Even if log files are cleared afterward, the record exists in the kernel ring buffer and (if forwarded) in remote syslog.

### The Rules

`configs/audit/99-agentir-evidence.rules`:

```
-a always,exit -F dir=CASES_ROOT -F perm=wa -F key=agentir_evidence_write
-a always,exit -F dir=/var/lib/agentir -F perm=wa -F key=agentir_core_write
```

`CASES_ROOT` is substituted with `/cases` (or the configured value) by `install.sh` at deploy time.

`perm=wa` watches:
- `w` — write access (file modification, creation, deletion)
- `a` — attribute change (chmod, chattr, chown)

### Verifying It Is Active

```bash
# Check loaded rules
sudo auditctl -l | grep agentir

# Check rule file
cat /etc/audit/rules.d/99-agentir-evidence.rules

# Query evidence write events (human-readable)
sudo ausearch -k agentir_evidence_write --format text

# Query state directory events
sudo ausearch -k agentir_core_write --format text

# Watch live events
sudo ausearch -k agentir_evidence_write -ts recent --format text

# Test: touch an evidence file and check the record
touch /cases/your-case/evidence/test-file
sudo ausearch -k agentir_evidence_write --format text | tail -20
```

### Integration with chattr

The chain of evidence for a tampering event:

1. `chattr -i /cases/{case}/evidence/{file}` → auditd records UID, PID, executable, timestamp
2. File is modified → auditd records the write event
3. `chattr +i /cases/{case}/evidence/{file}` → auditd records the re-set (or it is left clear)
4. Gateway re-hashes at next tool call → finds SHA-256 mismatch → MODIFIED status → blocks agent → portal shows violation

The cryptographic detection (step 4) is independent of whether the kernel logs were tampered with. Both paths converge on the same finding.

---

## 17c — AppArmor MAC Profile

### What It Does

AppArmor is a Linux Mandatory Access Control system. Even if a process is running as a user with write permissions to evidence files, an AppArmor profile can deny that specific write at the kernel level — below any application-level check.

The sift-gateway AppArmor profile enforces:
- Gateway can **read** evidence files (needed for SHA-256 hashing)
- Gateway **cannot write** evidence files (denied at MAC level even if POSIX permissions allow)
- Gateway can read+write manifest, ledger, audit, and approvals files
- Gateway can only use localhost TCP (no arbitrary outbound connections)
- Gateway cannot execute bash or sh

### Profile Highlights

```
# Evidence: read-only (hashing)
/cases/*/evidence/            r,
/cases/*/evidence/**          r,
deny /cases/*/evidence/**     w,

# Metadata: read+write (ledger, manifest, anchor, audit)
/cases/*/evidence-manifest.json     rw,
/cases/*/evidence-ledger.jsonl      rw,
/cases/*/evidence-anchor-v*.json    rw,
/cases/*/audit/                     rw,
/cases/*/audit/**                   rw,

# Network: localhost TCP only
network inet tcp,
network inet6 tcp,
deny network udp,
deny network raw,

# No shell execution
deny /bin/bash   x,
deny /bin/sh     x,
deny /usr/bin/bash x,
deny /usr/bin/sh   x,
deny /bin/dash   x,
```

The profile is keyed to the exact Python binary path (the uv-managed interpreter, substituted by `install.sh`).

### Complain Mode vs Enforce Mode

**Default: complain mode.** In complain mode, AppArmor logs all profile violations but does not block them. This is safe for initial deployment — it surfaces legitimate operations that the profile needs to allow before switching to enforce.

**Switching to enforce mode:**

```bash
# 1. Run all gateway functionality (portal, agent calls, evidence seal, report)
#    while the profile is in complain mode

# 2. Review logged violations
sudo aa-logprof

# 3. aa-logprof will show each logged denial and let you add allow rules
#    Accept legitimate rules, reject unexpected ones

# 4. Once clean, switch to enforce
sudo aa-enforce /etc/apparmor.d/sift-gateway

# 5. Exercise all functionality again and watch for new denials
sudo aa-status | grep sift-gateway
journalctl -k --grep="apparmor.*sift-gateway" | tail -20
```

### Verifying It Is Active

```bash
# Check profile is loaded
sudo aa-status | grep -A2 "sift-gateway\|python3.11"

# The gateway Python binary should appear in the profile list
# In complain mode: listed under "profiles are in complain mode"
# In enforce mode: listed under "profiles are in enforce mode"

# View the installed profile
cat /etc/apparmor.d/sift-gateway

# Test: attempt a write to an evidence file as the gateway user (enforce mode)
# Should fail with "Permission denied" even if POSIX perms allow it
```

---

## 17d — inotify Evidence Watcher

### What It Does

The gateway maintains a 30-second TTL cache of the evidence chain verification result. Without the watcher, a tampered file would not be detected until the next cache refresh — up to 30 seconds of agent tool calls on compromised evidence.

The inotify watcher listens for any filesystem event in `case_dir/evidence/` and immediately invalidates the cache on change. The next agent tool call re-verifies the chain from disk.

### Events Watched

```
IN_MODIFY   — file content change
IN_CREATE   — new file created
IN_DELETE   — file deleted
IN_MOVED    — file renamed/moved (IN_MOVED_FROM | IN_MOVED_TO)
```

### Implementation

`sift_gateway/evidence_watcher.py` uses Linux inotify via ctypes/libc.so.6 (no external dependencies). The watcher runs as a background asyncio task started in the gateway lifespan:

```python
# server.py lifespan
if _case_dir_str:
    from sift_gateway.evidence_watcher import watch_evidence_dir
    from sift_gateway.evidence_gate import invalidate_evidence_cache
    watcher_task = asyncio.create_task(
        watch_evidence_dir(_case_dir_str, invalidate_evidence_cache)
    )
```

The watcher uses a blocking `os.read` in a thread pool (no `O_NONBLOCK`). Closing the inotify file descriptor at gateway shutdown cleanly unblocks the thread via `EBADF`. No threads accumulate.

### Fallback

If inotify is unavailable (non-Linux, NFS, NTFS, FUSE), the watcher logs a warning and exits cleanly. The 30-second TTL remains the invalidation mechanism. Gateway functionality is not affected.

### Verifying It Is Active

```bash
# After gateway restart, check journal for watcher startup log
journalctl --user -u sift-gateway -n 20 --no-pager | grep "evidence_watcher"
# Should show: "evidence_watcher: watching /cases/{case}/evidence (inotify fd=N)"

# Test: touch an evidence file and verify cache invalidation log
touch /cases/your-case/evidence/.watcher-test
journalctl --user -u sift-gateway --since "10 seconds ago" --no-pager | grep "change detected"
rm /cases/your-case/evidence/.watcher-test
```

---

## Combined Threat Coverage

### Scenario 1: Accidental file overwrite

Examiner accidentally saves a file to `evidence/` with the same name as a sealed artifact.

| Layer | Response |
|-------|---------|
| `chattr +i` | Write fails — kernel rejects it without a `chattr -i` first |
| auditd | Write attempt is logged (even if it fails) |
| Gateway | SHA-256 mismatch → MODIFIED → agent blocked (if +i was somehow cleared) |

### Scenario 2: Deliberate tampering by a user with sudo

Attacker with sudo access clears the flag, modifies evidence, re-sets the flag.

| Layer | Response |
|-------|---------|
| `chattr +i` | Does not stop this — requires `chattr -i` which sudo can do |
| auditd | `chattr -i` is recorded with UID, PID, binary path, timestamp |
| inotify watcher | Evidence change immediately invalidates gate cache |
| Gateway | SHA-256 mismatch → MODIFIED → agent blocked; portal shows violation |
| Ledger | HMAC-signed ledger events cannot be retroactively forged without the examiner password |
| Solana anchor | The original manifest hash is on-chain; a new seal would produce a different hash at a later timestamp |

**The attacker's dilemma:** To cover their tracks, they must: clear the audit log (requires root and leaves its own trace), forge new HMAC ledger events (requires the examiner password), and forge a Solana transaction with a past timestamp (impossible — Solana consensus prevents backdating).

### Scenario 3: Gateway process compromise (RCE in the Python code)

An attacker achieves code execution in the gateway process.

| Layer | Response |
|-------|---------|
| AppArmor | Write to `evidence/**` is denied at MAC level regardless of POSIX perms |
| `chattr +i` | Write fails — even the gateway process cannot clear -i without CAP_LINUX_IMMUTABLE, and the capability is on the binary, not the process |
| Network | AppArmor `deny network udp,raw` prevents exfiltration via UDP/raw sockets |
| No shell | `deny /bin/bash, /bin/sh` prevents shell execution from the compromised process |

---

## What These Controls Cannot Protect Against

**Physical access.** An attacker with physical access to the SIFT VM can boot from external media, mount the filesystem, and bypass all OS controls.

**Root compromise.** A root attacker can: unload AppArmor profiles, clear auditd logs (leaves a trace but can be done), use `chattr -i` to clear immutable flags. The cryptographic ledger (HMAC-signed, Solana-anchored) is the last line of defense.

**Kernel compromise.** A rootkit-level attacker can bypass all kernel-enforced controls. At this level, the only remaining defense is the cryptographic ledger and the Solana anchor (both verifiable externally).

**Examiner credential compromise.** If the examiner password is stolen, a forged ledger event can be constructed. The Solana anchor provides an out-of-band reference — a forged event cannot have a timestamp earlier than the original seal's block time.

**These controls are layered deliberately.** The goal is not to achieve perfect security against a fully compromised machine — that is not achievable. The goal is to:
1. Convert accidental mistakes into prevented accidents
2. Convert deliberate tampering into auditable acts
3. Ensure the cryptographic record (ledger + anchor) can prove integrity to an external auditor even if OS controls were circumvented

---

## Maintenance Checklist

### After Installing

- [ ] `getcap .venv/bin/python3.11` shows `cap_linux_immutable=ep`
- [ ] `sudo auditctl -l | grep agentir` shows two rules
- [ ] `sudo aa-status` shows the sift-gateway profile in complain mode
- [ ] Gateway journal shows `evidence_watcher: watching ...` after startup

### Before Switching AppArmor to Enforce

- [ ] Run all portal workflows (login, case create, evidence seal, findings review, report)
- [ ] Run all agent tool categories (read-only, analysis, report generation)
- [ ] `sudo aa-logprof` — accept any legitimate denials, reject unexpected ones
- [ ] `sudo aa-enforce /etc/apparmor.d/sift-gateway`
- [ ] Re-run all workflows — no unexpected denials

### Periodically

- [ ] `sudo ausearch -k agentir_evidence_write --format text` — review for unexpected events
- [ ] Portal evidence panel — verify all ACTIVE files show `immutable: true`
- [ ] Portal evidence panel — run HMAC verification if last run > 24h
