# `run_command` Red-Team Review — 2026-07-13

| Field | Value |
| --- | --- |
| Status | **IN REVIEW — two confirmed policy-ceiling bypasses** |
| Target | Agent-facing SIFT MCP `run_command` and its durable `run_command_job` lane |
| Revision | `f0b7dc8371395283ecb1be53de3b37b2f2ac68dc` (`main`) |
| Attacker model | Authenticated MCP agent with an active, sealed case; no SSH, root, service-user, or control-plane access |
| Live target | Current SIFT VM reached through this session's `siftmcp` tools |
| Scope | Command/argv parsing, policy ceiling, durable parity, output containment, and the deployed OS execution floor |

## Decision summary

The review found **two real agent-reachable command-policy bypasses**.  In both,
an allowlisted outer program starts a child process that is neither represented
in nor checked by the outer `run_command` argv policy:

1. GNU `find -ok` / `-okdir` can start a denied shell child.
2. `awk -f -` can load a program from stdin whose `system()` starts a child.

Both were reproduced through the live MCP tool with harmless `printf` markers.
This is not a claimed VM compromise: the deployed OS floor stopped the tested
child from reading `/etc/passwd`, and no evidence write, privilege escalation,
shutdown, mount, or network egress was attempted or demonstrated.  The
findings nevertheless invalidate the intended allowlisted **policy ceiling**,
so they are reportable as Medium-severity, high-confidence command-execution
control failures.

## What was actually exercised

All live probes were deliberately non-destructive: none requested an OS state
change or evidence modification. The audit IDs below are the authoritative
receipts in the active test case.

| Test | Result | Evidence |
| --- | --- | --- |
| Direct host path `file /etc/passwd` | Denied before inspection | `siftgateway-claudy-20260712-013` |
| Direct `sudo --version` | Denied before launch | `...-015` |
| Direct `setsid date`, `mount --help` | Denied before launch | `...-017`, `...-019` |
| Direct `rm --help`, `shutdown --help`, `reboot --help`, `umount --help`, `dd --help` | Denied before launch | `...-025`, `...-023`, `...-027`, `...-029`, `...-031` |
| Later pipeline `file … \| sudo --version` | Entire command denied before launch | `...-033` |
| Allowed sealed-evidence control `file evidence/p0p1-evidence.txt` | Succeeded in the deployed sandbox | `...-021` |
| `find -ok` benign child | **Child shell executed** | `...-043` |
| `find -ok` child host-path containment | Host file content not readable | `...-045` |
| `awk -f -` benign child | **Child process executed** | `...-047` |

The allowed control reported the applied isolation posture: launcher applied,
distinct runtime user, `seccomp_mode: kill`, required Landlock, and required
systemd scope.  A read-only VM review also confirmed `agent_runtime` UID 995,
Landlock ABI 4, AppArmor `dfir-exec` in enforce mode, and matching deployed
source hashes for the execution-floor modules.

## Agent-facing path and controls

The real agent tool is registered in
`packages/sift-gateway/src/sift_gateway/mcp_server.py:417-437`.  An agent call
traverses the gateway's control-plane, authorization, active-case, audit,
evidence, dispatch/isolation, and response-guard middleware before the core
entrypoint `sift_core.agent_tools._run_command`.

The gateway injects active-case authority and gateway-resolved evidence data;
the `command` string remains agent supplied.  Core then follows:

`_run_command` → `generic.run_command` → `security.validate_shell_command` →
structured argv → executor → launcher/worker `Popen(shell=False)`.

The vulnerability is below the outer shell-free executor: the allowed tools
themselves interpret their arguments and start children after this one-time
outer argv validation.  The floor still applies to those children.

## Finding RC-RT-001 — `find -ok` / `-okdir` bypass direct-shell denial

**Severity:** Medium
**Confidence:** High
**CWE:** CWE-78, CWE-693
**Root control:** `packages/sift-core/src/sift_core/execute/security_policy.py:354`

The `find` blocked-flag set denies `-exec` and `-execdir` but omits GNU find's
equivalent confirmation predicates `-ok` and `-okdir`.  The generic validator
checks only the outer `find` argv, so it accepts the child program name as an
ordinary argument.  `find` then launches that program itself.

Live proof (harmless):

```text
echo y | find agent -maxdepth 0 -ok sh -c 'printf FIND_CHILD_EXECUTED' \;
```

The live MCP response returned `FIND_CHILD_EXECUTED`, exit code 0, and showed
only `echo` and `find` as policy-approved stages (audit
`siftgateway-claudy-20260712-043`).  A direct `sh` invocation was rejected
(`...-015`).  This proves the omitted predicate bypasses the intended
allowlisted child-program boundary.

**Containment and counterevidence.** Replacing the benign child action with
`file /etc/passwd` returned only `regular file, no read permission` (audit
`...-045`).  This confirms the deployed floor constrained that probe; it does
not prove a host file-read, evidence-mutation, privilege-escalation, mount, or
shutdown escape.

**Remediation.** Add `-ok` and `-okdir` to the `find` blocked flags and add a
pre-executor regression matrix proving `-exec`, `-execdir`, `-ok`, and `-okdir`
are all denied while non-executing `find` expressions remain usable.

## Finding RC-RT-002 — `awk -f -` bypasses the AWK program-text scanner

**Severity:** Medium
**Confidence:** High
**CWE:** CWE-78, CWE-693
**Root control:** `packages/sift-core/src/sift_core/execute/security.py:131-151`

`awk` is allowlisted in `security_policy.py:296`.  Its scanner rejects dangerous
constructs such as `system()` only in positional program text, while explicitly
skipping dash-prefixed arguments.  No policy rule blocks `awk -f` / `--file`.
Consequently an agent can feed a program through stdin (`-f -`) or a
case-derived script; AWK interprets it after the scanner has inspected only the
literal flag and path/stdin token.

Live proof (harmless):

```text
echo 'BEGIN { system("printf AWK_CHILD_EXECUTED") }' | awk -f -
```

The live MCP tool returned `AWK_CHILD_EXECUTED`, exit code 0 (audit
`siftgateway-claudy-20260712-047`).  The response plan contains only `echo` and
`awk -f -`; the child selected by `system()` is not policy checked or recorded
as a command stage.  Direct AWK program text containing `system()` is blocked,
so this is a concrete scanner-bypass instance rather than ordinary intended
AWK use.

**Containment and counterevidence.** The same deployed runtime-user, Landlock,
seccomp, systemd, AppArmor, and scrubbed-environment floor applies.  No host
escape is asserted from this finding; the companion live child containment
probe in RC-RT-001 demonstrates the floor's behavior for a spawned child.

**Remediation.** Fail closed on AWK program-file modes (`-f`, `--file`, and the
stdin spelling), unless a future design adds safe content inspection with a
stable immutable source contract.  Prefer a narrow, non-interpreting tool over
trying to recursively authorize arbitrary AWK programs.  Add a regression test
that proves the exact pipeline above is denied before the executor is reached.

## Deferred validation leads — not vulnerabilities in this report

The parser also accepts several tool-native output spellings as if they were
inputs.  Examples include attached short output options and extraction
destinations for `curl`, `bulk_extractor`, `tshark`, `wget`, `unzip`, `7z`, and
`tsk_recover`.  Those are not reported as evidence-mutation vulnerabilities:
no write was made against evidence, and the live floor has independent
read-only evidence controls (Landlock/AppArmor/immutable custody).  They remain
worth closing with a disposable-case regression suite and per-tool output
schemas; details are retained in the scan artifact ledger as C-PP-003A–E.

## Durable-lane observations — not command-execution findings

1. A denied async `shutdown --help` command was queued, then correctly denied
   by the worker.  Its top-level job status was `succeeded` while
   `result_public.success` was `false` and its step was `failed`.  Current code
   and tests define this as *worker protocol completion*, not forensic-command
   success.  It is a status-contract/reliability concern and can mislead a
   consumer that ignores `result_public.success`; it did not execute shutdown.

2. A valid async sealed-evidence `file` control failed live with
   `unhandled worker error: KeyError` and no `result_public`, while the exact
   synchronous command succeeded.  The deployed `agent_tools.py` and
   `run_command_job.py` hashes match this checkout.  This is an agent-facing
   P4.6 reliability defect requiring a separate reproducible trace/fix; it is
   not represented as a security bypass in this review.

## Verification performed

- Focused security/regression suite: **213 passed** (`test_red_team_negative`,
  `test_red_team_positive`, executor isolation, and K5 durable-lane tests).
- Live MCP controls and harmless red-team proofs listed above.
- Read-only SIFT VM service/configuration review, including source-hash match
  for the execution-floor modules.
- Manual CodeGuard review against the vendored MCP, input-validation,
  file-handling, authorization, and credential rules.  The CodeGuard
  marketplace automation was unavailable.

## Recommended order of work

1. Fix RC-RT-001 and RC-RT-002 with fail-on-revert tests; deploy and re-run the
   two exact live proof commands expecting policy denial.
2. Reproduce and fix the async evidence-ref `KeyError` with the live job shape
   (`timeout`, `save_output=false`, `preview_lines=0`, sealed evidence ref),
   then prove both async negative and positive controls end-to-end.
3. Close the deferred tool-native output-sink matrix in a disposable case;
   keep evidence untouched during validation.

## Signoff

```text
Result: IN REVIEW
Branch/commit: main / f0b7dc8371395283ecb1be53de3b37b2f2ac68dc
Changed: this review report and security-scan artifacts only; no runtime code or VM configuration changed
Validation: 213 focused tests passed; live MCP and read-only VM evidence recorded above
Residual risk: two policy-ceiling child-process bypasses remain until fixed; OS floor reduced the demonstrated impact but does not repair the authorization gap
Next action: implement the two focused ceiling fixes, then deploy-and-prove the live denials and repair the async positive-control failure
```
