# `run_command` Revamp — Consolidated Findings & A-to-Z Remediation

> **Scope:** `packages/sift-core/src/sift_core/execute/` — security.py, generic.py, executor.py, worker.py, security_policy.py, agent_tools.py (
> `_run_command` wrapper), `get_tool_help('run_command')` in discovery.py.  
> **Context:** SPG Phase 6 gate; product = core + gateway + portal + MCP server. Chain of custody and auditability are hard
> requirements.  
> **Date:** 2026-06-02

---

## Part A — Consolidated Findings

### A.0 Executive summary

The revamp replaces a restrictive argv-list executor (`shell=False`, per-binary flag allowlist) with a flexible string-based executor
that runs commands through `/bin/bash -c`. The ergonomic win is real and directly addresses 7+ items from the friction log. The
security regression is equally real: the implementation validates commands with a hand-rolled Python shell parser, then discards the
parse and hands the **original raw string** to bash — a parser-differential design that leaves at least three independent,
one-line bypass paths. For a product whose framing document calls chain of custody and auditability its core value proposition, the
control layer is currently friction, not enforcement. The fix is architecturally contained because the parsing work is already done;
what remains is executing from the parsed plan instead of from the raw string.

---

### A.1 The core architectural flaw: validate-then-`bash -c`

`validate_shell_command` (`security.py:503`) performs a thorough parse — splitting on operators, extracting argv and redirects,
checking binaries against the denylist, validating paths — and then `run_command` (`generic.py:141`) discards that entire parse
result:

```python
direct_argv = ["/bin/bash", "-c", command]   # the ORIGINAL, unmodified string
```

Bash re-parses from scratch. Any construct the Python parser models differently from bash produces a gap. Three are confirmed:

#### A.1.1 Newline / carriage-return — unhandled statement separator

**Location:** `security.py:512`, `security.py:382-401`

The control-character block regex is `[\x00-\x08\x0E-\x1F\x7F]`. This **excludes** `0x09` (tab), `0x0A` (LF/newline), `0x0B` (VT),
`0x0C` (FF), and `0x0D` (CR). `split_command_by_operators` splits only on `&&`, `||`, `|`, `;` — it does **not** split on LF,
CR, or lone `&`. `shlex.split` collapses all of those to whitespace token boundaries.

```
Input:  "true\nshred /dev/sdb"
Parser: argv = ["true", "shred", "/dev/sdb"]  → binary=true, clean args
Bash:   two statements; both execute
```

The denylist, `rm` jail, privileged-target jail (`dd`/`mount`/`losetup`), and output-path jail are all evaluated against binary
`true` only. Everything after the newline executes unvalidated. **CRITICAL.**

#### A.1.2 Single `&` — unhandled background operator

**Location:** `security.py:382-386`

`&&` is explicitly handled. A lone `&` falls through every branch to `current.append(char)` at line 403. Bash interprets `&` as
the background control operator; the Python validator treats it as punctuation or a literal character. Same class of bypass as
A.1.1. **CRITICAL.**

#### A.1.3 Nested interpreters — opaque payload channel

**Location:** `security_policy.py:14-31` (deny floor), `security_policy.py:37-45` (dangerous flags), `security.py:20` (dangerous
patterns)

`sh`, `bash`, `dash`, `python3`, `perl`, `ruby` are **not** on the deny floor. `-c` is **not** in `dangerous_flags`.
`` ` `` and `$(` are the only patterns in `_DANGEROUS_PATTERNS` — trivially avoided.

```
Input:  "python3 -c \"import os; os.system('shred /dev/sdb')\""
Parser: binary=python3, args=["-c", "import os; os.system('shred /dev/sdb')"]
        No backticks, no $(...) — passes clean.
Bash:   runs python3, which runs os.system(), which runs shred.
```

The MCP server instructions literally advertise `python3` and `curl` as available. This is not an exotic path; it's the normal
workflow for any agent doing data transformation. **CRITICAL.**

#### A.1.4 Net effect

Under the default `denylist` mode (`security_policy.py:35` — `is_allowed_by_mode` returns `True` for everything not on a 13-entry
floor), `run_command` is **effectively unrestricted shell execution as the gateway service user.** The validator provides
friction against an uncreative caller; it does not constitute a security boundary. The doc's own §7 threat model names "highly
creative agents" and the caller is an LLM that can be steered via prompt injection from the very evidence it parses. This is
in-scope, not theoretical.

---

### A.2 Auto-escalation to root

**Location:** `generic.py:149-207`, `security.py:296-299`

When a command fails with a permission error and the binary is in `_PRIVILEGED_TARGETS` (`mount`, `umount`, `losetup`, `dd`,
`dc3dd`, `dcfldd`, `vol`, `vol3`, `palso`, `yara`), the **entire original string** is silently retried as root:

```python
sudo_cmd = ["/usr/bin/sudo", "-n", "--", "/bin/bash", "-c", command]
```

Any bypass smuggled into a privileged-candidate invocation (e.g., `"mount /dev/sdb1 /cases/x/tmp\nyara -C /etc/shadow"`) escalates
to root. The escalation wraps the **un-trusted bash interpretation**, not the **validated parse**. Escalation should be explicit,
narrowly scoped to the single intended binary (never `bash -c`), and logged as a distinct, reviewable event. **CRITICAL.**

---

### A.3 "Isolation" is oversold

**Location:** `executor.py:57-66`, `executor.py:107-117`, `worker.py:32-44`

The doc (§7) claims "systemd-run container limits" provide isolation. The code runs `systemd-run --user --scope` with **only**
`MemoryMax` and `MemoryHigh`. No `ProtectSystem`, no `PrivateTmp`, no `ReadOnlyPaths`, no `NoNewPrivileges`, no seccomp filter,
no network namespace, no user namespace. On failure or absence of systemd-run, it **silently degrades** to a raw `subprocess.run`
with only `RLIMIT_AS`/`RLIMIT_CPU` from the worker preexec. Calling this a "container" is misleading and will cause operators to
make security decisions they'll regret. **HIGH.**

---

### A.4 The control set is a coding-agent denylist, not a forensics denylist

**Location:** `security.py:301-317`, `security_policy.py:14-31`

`_DESTRUCTIVE_PATTERNS` blocks `git reset --hard`, `kubectl delete`, `terraform destroy`, `DROP TABLE`, `DELETE FROM` — patterns
transferred from the staged `BashTool/bashSecurity.ts` TypeScript (see A.6). These are relevant to a development environment and
irrelevant to a SIFT forensics VM.

Meanwhile, the following are **not** denied and **not** guarded:

| Tool | Forensic danger |
|------|----------------|
| `wipefs` | Wipes filesystem signatures from raw devices |
| `shred` | Overwrites files/devices |
| `blkdiscard` | Discards all blocks on a device |
| `sgdisk`, `parted` | Repartitions devices |
| `mkswap` | Creates swap signature (destroys prior content) |
| `cryptsetup` | LUKS format/erase operations |
| `dmsetup` | Device mapper manipulation |
| `hdparm` | Low-level ATA commands including secure-erase |

The deny floor (`security_policy.py:14`) has ~13 entries; it lacks the tools most likely to destroy forensic evidence. The
destructive patterns protect git history but leave raw device writers open. **HIGH.**

---

### A.5 Accountability / chain-of-custody gaps

**What works:**
- Raw command string logged verbatim to `sift-gateway.jsonl` per execution (`agent_tools.py:532-548`)
- Input file auto-detection + SHA-256 hashing (`agent_tools.py:409-470`)
- Output saved with `os.fsync` + SHA-256 to case dirs (`executor.py:328-333`)
- `parser_partial_failure` scan catches exit-0-but-actually-failed forensic tools (`generic.py:241-248`)

**What doesn't:**

| Gap | Impact |
|-----|--------|
| Audit `binary` field is only the **first** binary (`generic.py:131`). A `shred` smuggled after a newline is recorded as `true`. | Structured metadata lies; the raw string is the only truth. |
| Audit log lives on the same filesystem the execution user controls. `~/.sift` is input-blocked but `~/.sift/cases` is excepted (`security.py:171-174`), and the A.1.1 bypass ignores all path checks. | Agent can read `gateway.yaml` (service tokens) or append/truncate `sift-gateway.jsonl`. **Chain-of-custody record is tamperable.** |
| No `audit_id` field in structured `supporting_commands` for findings (D-013). Audit IDs must be scraped from free-text excerpts. | Findings-provenance linking is fragile. |
| `record_finding` artifact source validation diverges from `evidence_list.path` (D-012). | Registered evidence paths rejected; findings downgraded to PARTIAL. |

**HIGH** — the audit-record tamperability alone is blocking for chain-of-custody.

---

### A.6 Repository hygiene

**Location:** `BashTool/` directory (staged), repository root

14,154 lines of TypeScript are staged under `BashTool/` (`BashTool.tsx`, `bashSecurity.ts`, `bashPermissions.ts`,
`pathValidation.ts`, `sedValidation.ts` — imports from `src/services/analytics`, `src/utils/bash/heredoc.js`). These are
Claude Code's **own** internal Bash tool source. They are:

- Not imported by any Python code in the repository
- Dead weight (2,622 lines of `bashPermissions.ts` + 2,593 lines of `bashSecurity.ts`)
- The apparent source of the misplaced DevOps destructive patterns in A.4
- A licensing/provenance problem

`update_friction_log.py` at repo root is a throwaway script; it belongs under `scripts/` or nowhere. **BLOCKER for commit.**

---

### A.7 Testing surfaces the happy path only

**Location:** `packages/sift-core/tests/test_execute_executor.py` (565 lines), `packages/sift-gateway/tests/test_inprocess_core_tools.py`

The test suite covers: pipeline splitting, redirections, destructive pattern rejection, IFS injection, process substitution,
proc/environ access, output path jail, privileged-target validators, systemd-run integration, sudo fallback, allowlist mode.
All pass. **Zero tests** exist for:

- Newline statement injection (`\n`, `\r`)
- Background operator injection (`&`)
- Nested interpreter bypass (`sh -c`, `python3 -c`, `bash -c`)
- Basename-evasion (copy binary to case dir, run by relative path)
- TOCTOU symlink swap between validation and execution

The tests verify the design against its own stated threat model, but the threat model doesn't include the parser-differential
attack surface. This is how the doc can claim "exhaustive guards" while the code has the gaps in A.1 — the tests never probe
the gap between the Python parser and bash.

---

### A.8 Friction-log resolution audit

Cross-referencing every `[RESOLVED]` marker against the actual code:

| Friction | Resolution claim | Code reality | Verdict |
|----------|-----------------|--------------|---------|
| **F-016** (_case envelope bloat) | RESOLVED | Gateway `_append_case_context` selectively emits `_case` vs `_case_ref`. Verified live in phase6 log. | **Accurate** |
| **F-031** (policy opaque) | RESOLVED — "blocked exact tokens and safe equivalents" | `get_tool_help('run_command')` returns a policy block with blocked_constructs + safe_alternatives. Individual block error messages remain generic — only `rm` has real guidance. | **Partial** — help text improved; per-error safe equivalents not systematic |
| **F-033** (parser partial failure) | RESOLVED | `generic.py:241-248` scans 6 patterns, sets `warnings` + `agent_action`. Real code. NB: D-014 in phase6 log still shows OPEN — the two logs disagree. | **Accurate** for the scan; phase6 log needs update |
| **F-034** (noisy previews) | RESOLVED (partial) | "Indirectly helped via F-033 warning extraction; full truncation requires further optimization." Doc is honest about the partial state. | **Honest** |
| **F-035** (derivative provenance) | RESOLVED | `supporting_commands` takes `audit_id`; `input_files` param + SHA-256 hashing. D-012/D-013 in phase6 log still OPEN — end-to-end not verified. | **Code present; live verification incomplete** |
| **F-037** (catalog gaps) | RESOLVED | `ewfinfo`, `img_stat`, `fsstat`, `ewfverify`, `pinfo.py` added to catalog YAMLs. Verified in git diff. | **Accurate** |

---

### A.9 What to keep and amplify

| Component | Why it's good |
|-----------|--------------|
| Quote-aware state machine (`security.py:329-409`) | Correct for the injection cases it models. Serves as the foundation for P0 execution. |
| Per-tool privileged jails (`security.py:609-708`) | Mandatory `mount` target under case dirs, mandatory `losetup -r`, `dd if=/of=` jail, `fdisk` read-only — exactly the right forensics-specific constraints. |
| Output budget + auto-save + SHA-256 (`executor.py:203-228`) | Directly resolves F-013/F-016/F-034 (context bloat). The `_parsed` envelope pattern is clean. |
| `parser_partial_failure` scan (`generic.py:241-248`) | Simple, effective, catches the forensic-tool false-success class. |
| `get_tool_help('run_command')` policy block (`discovery.py:88-108`) | Tells the agent what will be blocked and suggests alternatives. Model for all tool policy surfacing. |
| Catalog additions (`sleuthkit.yaml`, `timeline.yaml`) | Resolves D-010/F-037. |

---

## Part B — A-to-Z Remediation

### Guiding principles

1. **One parser, one truth.** Never validate with Python and execute with bash. The parse tree is the authority.
2. **Fail closed.** If a sandbox is unavailable, refuse to execute; do not silently degrade.
3. **OS-level containment is the security boundary.** String matching is an ergonomic guide, not a control.
4. **Evidence is sovereign.** Chain-of-custody records must be tamper-proof at the OS level.
5. **Every byte counts.** Tool responses compete with evidence for the agent's context window.

---

### Phase P0 — Eliminate the parser differential (architectural fix)

**Objective:** The parsed plan becomes the single source of truth. Bash is no longer the interpreter.

**Steps:**

#### P0.1 — Build a pipeline executor in `generic.py`

`split_command_by_operators` + `parse_subcommand_argv_and_redirects` already produce per-stage `(argv, redirects)` tuples. Build
a `_execute_plan()` that:

1. Validates **every** stage individually (denylist, path jail, privileged guards, sanitize_extra_args) against the parsed argv.
2. Creates a chain of `subprocess.Popen` stages (`shell=False`), wiring `stdout→stdin` pipes between stages for `|` operators.
3. Opens redirect target files directly (after `validate_output_path` / `validate_input_path`) for `>`, `>>`, `<`, `<<`.
4. Implements `&&` / `||` / `;` sequencing by checking exit codes between stages.
5. Runs the entire pipeline and collects stdout from the final stage, stderr from all stages.

**Result:** Ergonomic shell syntax (pipes, redirects, chaining) preserved. Bash re-interpretation eliminated. All bypasses in
A.1 closed.

#### P0.2 — Add newline, CR, and `&` as hard separators (or reject them)

In `split_command_by_operators`, add `\n` (`0x0A`), `\r` (`0x0D`), and `&` as operator delimiters:

```python
# In split_command_by_operators, add:
elif char == "&":
    subcommands.append(("".join(current).strip(), "&"))
    current = []
elif char in ("\n", "\r"):
    subcommands.append(("".join(current).strip(), ";"))  # treat as ;
    current = []
```

Each resulting subcommand stage is individually validated by P0.1.

#### P0.3 — Handle nested interpreters

**Option A (preferred):** Reject nested interpreters unless the payload is itself re-parsed. Add to deny floor:

```python
_NESTED_INTERPRETERS = {"sh", "bash", "dash", "zsh", "python", "python3",
                         "perl", "ruby", "env", "xargs", "nohup",
                         "timeout", "stdbuf"}
```

**Option B (permissive):** When a nested interpreter is detected, extract the `-c` argument payload (using the already-parsed
argv), validate it through the same `validate_shell_command` → `_execute_plan` pipeline, and if it passes, allow the nested
call. This preserves the "agent can use python3 for data transforms" ergonomic while closing the opaque-payload channel.

**Recommendation:** Start with Option A for core-only gate; implement Option B as a follow-on when agent workflows demand
inline scripting.

#### P0.4 — Stop passing `bash -c` to the worker

Remove `direct_argv=["/bin/bash", "-c", command]` from `CommandPlan` (`generic.py:141`). Replace with the P0.1 pipeline
executor's argv list for the primary stage. The worker (`worker.py`) already accepts arbitrary `cmd_list` and runs with
`shell=False` — no change needed there.

#### P0.5 — Wire the per-tool privileged jails into the pipeline

The jails (`validate_shell_command:609-708`) currently run inside `validate_shell_command` against the parsed tokens. Move
them to `_execute_plan()` so they execute against the authoritative parsed argv per stage, including stages extracted by
P0.2.

**P0 test requirements:**

- `test_newline_injection_rejected_or_split` — confirm `\n`, `\r` produce either rejection or two separately-validated stages
- `test_background_operator_rejected_or_split` — confirm lone `&` same behavior
- `test_nested_interpreter_rejected` — `sh -c`, `python3 -c`, `bash -c` rejected (Option A)
- `test_pipeline_executor_wires_stages` — `ls | grep txt` → two Popen stages, stdout→stdin pipe, final stdout correct
- `test_redirect_handles_files` — `echo hi > out.txt` → output file created via open(), content correct
- `test_and_or_semicolon_sequencing` — `true && echo ok` succeeds; `false && echo nope` skips second stage
- `test_sudo_escalation_wraps_single_stage_not_bash_c` — mount permission error → sudo wraps only the `mount` stage argv, not `bash -c`

---

### Phase P1 — OS-level containment (the real security boundary)

**Objective:** Even if the validator is bypassed (parser bug, novel attack, compromised agent prompt), the OS prevents evidence
tampering, token exfiltration, and system compromise.

#### P1.1 — Dedicated execution user

Run the gateway and executor as a dedicated low-privilege user (e.g., `sift-exec`):

```bash
useradd -r -s /sbin/nologin -M sift-exec
usermod -aG sift-exec sift-exec
```

This user:
- Cannot write to raw evidence devices (`/dev/sd*`, `/dev/nvme*`)
- Cannot read `~/.sift/gateway.yaml` (service tokens)
- Cannot write to `~/.sift/sift-gateway.jsonl` (audit log) — see P1.3
- Has write access only to `<case_dir>/agent/`, `<case_dir>/extractions/`, `<case_dir>/tmp/`

The gateway service runs as this user; `sudo` rules grant it access to specific forensic binaries (not `bash -c`) when root
is genuinely needed.

#### P1.2 — Evidence mount policy

Evidence devices are mounted read-only before case sealing:

```bash
blockdev --setro /dev/sdX
mount -o ro,noexec,nosuid,nodev /dev/sdX /cases/<case>/evidence/
```

The mount is performed by a human operator or a privileged init script — never by the agent. The `mount` privileged jail in
P0.5 enforces that agent-requested mounts can only target case-controlled directories with read-only flags.

#### P1.3 — Append-only audit log

```bash
touch ~/.sift/sift-gateway.jsonl
chattr +a ~/.sift/sift-gateway.jsonl
```

The `+a` (append-only) attribute means the file can only be appended to — no truncation, no overwrite, no deletion. Only
root can remove the attribute. The execution user (`sift-exec`) cannot read the file if it's owned by a separate `sift-audit`
user with mode `600`, and a small audit daemon (or the gateway process running as `sift-audit`) is the sole writer.

#### P1.4 — Token isolation

Service tokens (`sift_svc_*` in `gateway.yaml`) must be readable only by the gateway process, not by the execution user. Options:

- **Simple:** `chmod 600 ~/.sift/gateway.yaml` owned by `sift-gateway` user; `sift-exec` cannot read it
- **Better:** Token stored in a separate file (`~/.sift/token`) with `600` perms, referenced by path in `gateway.yaml`; the
  gateway reads it at startup and holds it in memory only

#### P1.5 — Real sandbox (bwrap or systemd with full isolation)

**Target:** Replace the current `systemd-run --user --scope` with either:

**Option A — bubblewrap:**
```bash
bwrap \
  --ro-bind /usr /usr \
  --ro-bind /bin /bin \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /etc/alternatives /etc/alternatives \
  --bind <case_dir>/agent <case_dir>/agent \
  --bind <case_dir>/extractions <case_dir>/extractions \
  --bind <case_dir>/tmp <case_dir>/tmp \
  --ro-bind <case_dir>/evidence <case_dir>/evidence \
  --ro-bind /dev /dev \
  --proc /proc \
  --dev /dev \
  --unshare-all \
  --share-net \
  --die-with-parent \
  -- <command> <args...>
```

**Option B — systemd-run with full isolation:**
```bash
systemd-run --user --scope \
  --property=MemoryMax=... \
  --property=ProtectSystem=strict \
  --property=ProtectHome=yes \
  --property=ReadOnlyPaths=/usr /bin /lib /lib64 /etc/alternatives \
  --property=ReadWritePaths=<case_dir>/agent <case_dir>/extractions <case_dir>/tmp \
  --property=NoNewPrivileges=yes \
  --property=PrivateTmp=yes \
  --property=SystemCallFilter=@default @file-system @process @signal \
  ...
```

**Fail closed:** If the sandbox binary (`bwrap` or `systemd-run`) is unavailable, `_run_isolated_worker` must **refuse to
execute** and return a clear error. Remove the silent fallback at `executor.py:107-117`.

#### P1.6 — Explicit, narrow sudo escalation

Replace the auto-sudo fallback (`generic.py:163-207`) with:

1. If a privileged binary needs elevation, log the intent, then execute **only that binary's argv** (not `bash -c`) under
   `sudo -n`.
2. The sudoers rule is binary-specific: `sift-exec ALL=(root) NOPASSWD: /usr/bin/mount, /usr/bin/umount, /bin/mount, ...`
   — never `/bin/bash`.
3. The escalation always logs a distinct, human-reviewable audit event.

---

### Phase P2 — Right-size the controls for DFIR

#### P2.1 — Replace coding-agent patterns with forensics patterns

Remove from `_DESTRUCTIVE_PATTERNS` (`security.py:301-317`): `git reset --hard`, `git push --force`, `git stash drop`,
`git branch -D`, `git checkout .`, `git restore .`, `kubectl delete`, `terraform destroy`. These protect a development
workflow, not a forensics VM.

Add to `DENY_FLOOR` (`security_policy.py:14-31`):

```python
DENY_FLOOR = frozenset({
    # Existing
    "mkfs", "mkfs.*", "shutdown", "reboot", "poweroff", "halt",
    "init", "kill", "killall", "pkill", "env", "printenv",
    "nc", "ncat", "socat",
    # Added — media/device destruction
    "wipefs", "shred", "blkdiscard", "sgdisk", "parted", "mkswap",
    "cryptsetup", "dmsetup", "hdparm",
    # Added — nested interpreters (P0.3)
    "sh", "bash", "dash", "zsh", "python", "python3",
    "perl", "ruby", "xargs", "nohup", "timeout", "stdbuf",
})
```

#### P2.2 — Add privileged-target jails for new tools

If any of the newly-denied tools have legitimate forensic use cases (e.g., `cryptsetup` for BitLocker analysis), add them to
`_PRIVILEGED_TARGETS` with read-only/jailed guards, not the deny floor.

#### P2.3 — Stop trusting basename-only denial

`matches_denied_binary` (`security_policy.py:186`) matches against the lowercased basename only. This is defeated by
copying a binary to a case-writable directory under a different name. After `find_binary` resolves the real path:

1. Verify the resolved binary is not under a case-writable directory (`agent/`, `extractions/`, `tmp/`).
2. Verify the resolved binary's realpath is not a symlink into a case-writable directory.
3. If the binary is under a case directory, reject it regardless of its basename.

---

### Phase P3 — Audit & provenance hardening

#### P3.1 — Structured audit reflects every pipeline stage

Currently `binary` and `privilege_escalation` reflect only the first stage (`generic.py:131`). After P0.1, each stage has its
own parsed argv and exit code. The audit entry must include:

```json
{
  "audit_id": "siftgateway-...",
  "command": "raw string (for human review)",
  "stages": [
    {"binary": "true", "argv": ["true"], "exit_code": 0},
    {"binary": "shred", "argv": ["shred", "/dev/sdb"], "exit_code": 0}
  ],
  "privilege_escalation": {"stage": 1, "mechanism": "sudo_fallback"}
}
```

#### P3.2 — OS-level audit log protection (see P1.3)

Already covered. Re-stated here because it's the most important chain-of-custody control.

#### P3.3 — Fix D-012/D-013 (artifact source + audit_id in findings)

- Align `record_finding` artifact `source` validation with `evidence_list.path` namespace (D-012)
- Add explicit `audit_id` field to `supporting_commands` schema so agents don't need to embed audit IDs in free-text excerpts
  (D-013)

---

### Phase P4 — Documentation & test truth

#### P4.1 — Correct the `run_command_updated.md` doc

| Current claim | Correction |
|--------------|------------|
| "hardened, direct shell execution tool" | "flexible shell execution tool with defense-in-depth guards; OS containment is the security boundary" |
| "Exhaustive guards" | "Multi-layer validators that reduce but do not eliminate the attack surface; see [link to this doc] for residual risks" |
| "systemd-run container limits" | "systemd `--scope` with MemoryMax/MemoryHigh; full namespace isolation is P1 (planned)" |
| "hardcoded deny floor + operator additions" | Keep this — it's accurate |

#### P4.2 — Write red-team test cases

In `test_execute_executor.py`, add:

| Test | What it proves |
|------|---------------|
| `test_newline_bypass_blocked` | `\n` and `\r` are handled as statement separators, not whitespace |
| `test_background_bypass_blocked` | `&` is handled as a statement separator |
| `test_nested_shell_rejected` | `sh -c '...'` is denied |
| `test_nested_python_rejected` | `python3 -c '...'` is denied |
| `test_basename_evasion_blocked` | Binary copied to case dir and executed by path is rejected |
| `test_toctou_symlink_blocked` | Symlink created between validation and execution is caught or fails safe |
| `test_pipeline_all_stages_audited` | Each pipeline stage appears in structured audit fields |
| `test_sandbox_unavailable_fails_closed` | Missing bwrap/systemd-run → `ExecutionError`, not silent fallback |

#### P4.3 — Reconcile friction log with phase6 log

Update the following entries so the two logs are consistent:

| Phase6 log | Friction log | Action |
|-----------|-------------|--------|
| D-010 (OPEN) | F-037 (RESOLVED) | Mark D-010 RESOLVED — catalog entries exist; verify live |
| D-012 (OPEN) | F-035 (RESOLVED) | P3.3 work needed; keep D-012 OPEN until done |
| D-013 (OPEN) | F-035 (RESOLVED) | P3.3 work needed; keep D-013 OPEN until done |
| D-014 (OPEN) | F-033 (RESOLVED) | Mark D-014 RESOLVED for the generic scan; add note that tool-specific classifiers are future work |

---



---

### Phase P5 — Validation gate (Stage 6 invariants re-test)

Before ticking Stage 6, verify on the live VM (192.168.122.81):

| Invariant | Test | Expected |
|-----------|------|----------|
| **F-A** (corrupt evidence) | Modify one byte of sealed evidence → `evidence_verify` | `chain.status != ok`; all tools blocked |
| **R-B** (jail) | `run_command("true\nwipefs /dev/sdb")` | Rejected (newline separator) or both stages validated and second denied |
| **R-B** (jail) | `run_command("sh -c 'id'")` | Rejected (nested interpreter deny floor) |
| **R-B** (jail) | `run_command("echo hi > /etc/pwned")` | Rejected (output path jail) |
| **Executor deny-floor** | `run_command("shred /dev/zero")` | Rejected (deny floor) |
| **Traversal** | `run_command("cat ../../../etc/shadow")` | Rejected (input path jail) |
| **Output cap** | `python3 -c "print('A'*50000)"` (if python3 allowed under P0.3 Option B) | Auto-saved to disk; ≤10KB inline |
| **R-core-survives** | Disable an add-on backend → `tools/list` | Core tools present; add-on tools absent |
| **R-roles** | Portal rejects agent service token on examiner endpoint | 403 |

---

### Dependency order

```
P5 (repo cleanup) ─────────────────────────────────────────┐
P0 (parser differential) ──┐                                │
P1 (OS containment) ───────┤── can run in parallel ─────────┤
P2 (right-size controls) ──┘                                │
P3 (audit hardening) ────── depends on P0 (staged audit) ───┤
P4 (docs + tests) ───────── after P0/P1/P2/P3 ─────────────┤
P6 (validation gate) ────── after all above ────────────────┘
```

P0, P1, and P2 are independent and can proceed in parallel. P3 depends on P0 (the staged audit structure requires the pipeline
executor). P4 and P6 are final.

---
