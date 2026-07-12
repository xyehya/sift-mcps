# `run_command` security scan — 2026-07-12

## Scope and basis

This scoped review covered the real agent-facing aggregate `/mcp` `run_command`
path at revision `5119c18197fcc84c8c3727aecb39721bda2958bf`: core registration and
wrapper, Gateway policy chain, active-case/evidence/audit/response boundary,
execution parser and allowlist, executor/worker/launcher, AppArmor, and the
transient systemd scope contract.

The review used the seven-layer model as counterevidence, not as an assumption:

1. authenticated aggregate Gateway entry and policy gates;
2. command ceiling: fixed wrappers, positive allowlist, parsed argv, no shell;
3. DB-injected active case, sealed evidence, and case/path floor;
4. distinct unprivileged runtime identity with scrubbed environment;
5. required transient systemd scope and resource/network controls;
6. enforced `dfir-exec` AppArmor; and
7. Landlock grants plus seccomp kill mode for the denied syscall set.

Codebase-memory indexing succeeded. One delegated reviewer received stale graph-query
results after indexing and used exact-source reads as the permitted fallback. CodeGuard
was applied manually for MCP/authz/input-validation/file-handling/logging/secrets;
no CodeGuard MCP runner is exposed in this harness.

## Finding

### P2 — Deprecated `input_files` bypasses the provenance path floor

`run_command` publicly accepts deprecated `input_files`
([agent_tools.py](../../../packages/sift-core/src/sift_core/agent_tools.py)). The Gateway's
core argument preparation preserves that field, and `_run_command` catches a failed
case-path resolution before retaining the client value. It then resolves, opens, and
hashes an existing file before `_execute_command` begins. The returned provenance
includes the digest.

This is not an arbitrary-file-content disclosure or an execution escape: validation
returned only a digest, and no sensitive file, secret, raw evidence path, or DoS case
was tested. It is nevertheless a confirmed agent-to-gateway boundary break: an
authorized agent can select a non-case, gateway-readable file for a content-derived
metadata read before the runtime-user/systemd/AppArmor/Landlock/seccomp floor applies.

Recommended fix: remove `input_files` from the agent schema, or accept it only as a
private Gateway-injected field containing resolved sealed-evidence references or
canonical active-case paths. Hash only after that validation. Add a fail-on-revert
agent-surface test that proves a harmless non-case fixture produces neither a digest
nor an open attempt.

## Live proof matrix

| Control | Current proof |
| --- | --- |
| Reviewed/deployed source | Hashes for the reviewed gateway/core/confinement set exactly matched `/opt/sift-mcps`. |
| Service and profile state | Gateway, job worker, and both OpenSearch workers were active; `sift-gateway` and `dfir-exec` AppArmor profiles were loaded in enforce mode. |
| Approved execution | An agent-facing fixed forensic wrapper succeeded and reported launcher, runtime user, required Landlock, seccomp kill, and required systemd scope as applied. |
| Command ceiling | An argv-rewriting launcher and a mount command were denied before execution. |
| Command path floor | A harmless host absolute path in command position was denied. |
| Evidence write floor | Redirecting output into sealed evidence was denied. |
| Provenance bypass | The same class of non-case fixture supplied through `input_files` produced an agent-visible input digest before execution. |
| Internal sudo fallback | The runtime account has no sudo policy; a privileged-marked approved forensic tool completed direct-unprivileged. No agent-to-root path was demonstrated. |

Focused local contracts passed: **270 tests** covering launcher, executor, seccomp,
negative controls, AppArmor contract, Gateway core tools, policy parity, response guard,
and audit detail. The worktree-local environment initially lacked monorepo extras; the
established repository environment was used while importing this exact review tree.

## Rejected or deferred concerns

- The internal permission-triggered sudo fallback is not a finding on the live VM:
  the execution scope is already the restricted runtime account and that account has
  no sudo authority.
- `clone3`/socket compatibility logging, dynamic 60%-available-memory scopes, and
  removal of the default output file-size limit remain documented defense-in-depth or
  resource-management follow-ups. No complete agent-reachable escape was shown.
- Potential evidence-gate database-error detail leakage was not reproduced because
  intentionally breaking the control plane was outside this safe scan. It remains a
  hardening follow-up, not a vulnerability claim.
- One ordinary diagnostic utility is currently blocked by the intentionally narrow
  runtime read set. That is legitimate-tool friction, not a security exposure.

## Limitations and next action

The detailed vulnerability-writeup worker failed to initialize once and then stalled
without producing an artifact after a retry; it was stopped. The scan's detailed
temporary discovery/validation/attack-path records and a local-remediation hardening
assessment were retained, but no sealed canonical Codex Security projection is claimed.

Implement the P2 provenance-boundary fix, add the regression test, deploy it, and
repeat the exact safe MCP reproduction. No broader execution-sandbox redesign is
indicated by this scan.
