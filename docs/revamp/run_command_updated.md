# `run_command` Native User Isolation Baseline

Date: 2026-06-02

This document describes the current `run_command` baseline in `sift-core` and
`sift-gateway`.

## Contract

`run_command` accepts:

- a command string for composition: pipes, `;`, `&&`, `||`, and supported
  redirects;
- a legacy string-array only for simple argv calls.

Arrays are literal argv. If an array contains shell operators, the tool rejects
it with guidance to use a command string. This avoids the silent wrong behavior
seen in Session 31, where operators were swallowed as ordinary arguments.

The executor never calls `/bin/bash -c` and never uses `shell=True`. The parser's
stage plan is the execution plan.

## Execution Model

1. `agent_tools._run_command` validates the MCP schema, resolves `working_dir`
   inside the active case, extracts input-file provenance, hashes small inputs,
   and records the audit envelope.
2. `security.validate_shell_command(command, cwd=...)` parses the string into
   stages, validates every binary and path, rewrites every `argv[0]` to the
   resolved binary path, and rejects protected evidence/state mutations.
3. `generic.run_command` executes each pipeline/logical group through
   `executor.execute`.
4. `executor.execute` starts a short-lived Python worker directly. There is no
   `systemd-run` cgroup layer.
5. `worker.py` launches each stage with `subprocess.Popen(shell=False)`. When
   `execute.runtime_user` is configured, the worker prefixes each stage with:

   ```text
   sudo -n -u <runtime_user> -- <resolved-binary> <args...>
   ```

The production default runtime user is `agent_runtime`. Tests and local dev can
set `execute.runtime_user: "__current__"` or `SIFT_EXECUTE_AS_USER=__current__`.

## Host Boundary

Native user isolation depends on host ACLs. The setup helper is:

```bash
sudo scripts/setup-agent-runtime.sh \
  --service-user sansforensics \
  --runtime-user agent_runtime \
  --cases-root /cases \
  --state-root /var/lib/sift
```

The script:

- creates `agent_runtime` as a restricted local account;
- adds it to the `fuse` group when the group exists;
- grants case-root traversal;
- grants read-only access to `<case>/evidence`;
- grants read/write access to `<case>/agent`, `<case>/agent/outputs`,
  `<case>/extractions`, and `<case>/tmp`;
- denies access to SIFT integrity records under the state root and legacy
  case-local record shadows;
- writes `/etc/sudoers.d/sift-agent-runtime` so the gateway service user can
  drop to `agent_runtime` without a password prompt.

The sudoers rule is intentionally target-user scoped:

```text
sansforensics ALL=(agent_runtime) NOPASSWD: ALL
```

It does not grant root. Existing privileged forensic fallbacks, if used, require
separate narrow root sudoers rules and remain audited as privilege events.

## Path Policy

`run_command` statically enforces the same write model as the ACL layer:

- outputs and redirects must resolve under `agent/`, `extractions/`, or `tmp/`;
- `/dev/null` is allowed as an output sink;
- reads from integrity records are blocked;
- writes, deletes, moves, or metadata changes under `evidence/`, record dirs,
  manifests, ledgers, and approvals are blocked before execution;
- relative paths are resolved against the command `cwd`, not the gateway
  process cwd.

The ACL layer is still required. Static parsing is a usability and defense-in-
depth layer; POSIX permissions are the kernel boundary.

## Context Management

The executor captures stdout/stderr, enforces timeouts, and caps captured bytes.
Small output is returned inline. Output larger than the response budget is saved
under:

```text
<case>/agent/outputs/
```

The response includes the saved path, SHA-256, and byte count. This preserves
DFIR workflow usability without filling the agent context with full tool output.

## Supported And Rejected Composition

Supported:

- pipelines: `fls evidence/disk.E01 | grep Users`
- logical sequencing: `test -f agent/x && grep needle agent/x`
- redirects: `>`, `>>`, `<`
- stderr handling: `2>&1`, `2>`, `2>>`, `&>`, `&>>`, `/dev/null`

Rejected:

- agent-supplied `sudo`;
- nested interpreters/shells from the deny floor;
- background operator `&`;
- heredocs;
- exotic fd duplication such as `>&2`, `1>&2`, `3>file`;
- write/delete/move/metadata operations against evidence and integrity records.

## Operational Notes

Native user isolation is deliberately not a container. This is useful for SIFT:
FUSE mounts such as `ewfmount` run natively on the host and can persist across
subsequent tool calls when the tool daemonizes normally. The tradeoff is that
operators must maintain the ACL/sudoers boundary and must not run the gateway as
the same account used for unrestricted case administration.
