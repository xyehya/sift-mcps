# Validation — Cluster EXEC

> Validator agent: sec-exec (Opus 4.8, xhigh). Read-only. Validates the restored
> Codex assessment against **current HEAD** (`93f8999`), not the stale scan base
> `b995491` (≈183 commits old). The line numbers in `codex_review_directives.txt`
> were re-located. No source code was modified — this file is the only output.
>
> Secure-coding lens: `codeguard-security:codeguard` skill invoked (Python rules
> applied: input-validation/injection, authorization/access-control, file-handling,
> logging). Verdict basis below.
>
> **Crux of this cluster:** the EXEC findings are sandbox/privilege behaviors whose
> exploitability is **conditional on deployment posture**. I traced the *actual*
> packaged systemd posture (gateway as `sift-service`, `SIFT_EXECUTE_SYSTEMD_SCOPE=1`,
> worker confined to `agent_runtime`) and the sudoers drop-ins that define the real
> privilege boundary — not just the Python control flow. That changes the verdicts.

## Summary table

| Candidate | Codex verdict | **Current status** | Current severity | Confidence | Already-fixed-by | Fix effort |
|---|---|---|---|---|---|---|
| DSS-CAN-006 | valid / high | **PARTIALLY-MITIGATED → NEEDS-OPERATOR-DECISION** (neutralized in packaged posture; latent foot-gun + redundant with ingest broker) | **Medium** (was High) | high | sudoers split (`sift-agent-runtime` = drop-to-user only; root grants are command-specific in `sift-ingest-mount`) + production `agent_runtime` confinement | S–M |
| DSS-CAN-007 | valid / high | **PARTIALLY-FIXED → NEEDS-OPERATOR-DECISION** (redirection is intended design; sudoers already minimized exactly as Codex proposed; residual = hostile-image-byte kernel isolation) | **Medium** (was High) | high | `setup-ingest-mount-sudoers.sh` (full-path, no-wildcard allowlist; modprobe pinned; tee excluded) + EvidenceGate-before-dispatch + least-priv worker unit | L (residual is architectural) |
| DSS-CAN-022 | valid / med | **PARTIALLY-MITIGATED** (production ships fail-closed `=1`; `auto` silent-downgrade + missing isolation surfacing still valid) | **Low** (was Medium) | high | `configs/systemd/*.service` set `SIFT_EXECUTE_SYSTEMD_SCOPE=1` (= "required"/fail-closed) | S |

**Counts:** STILL-VALID(as-written) 0 · PARTIALLY-MITIGATED/FIXED 3 · ALREADY-FIXED 0 · FALSE-POSITIVE 0. All three are real code paths but materially over-rated vs. the current packaged posture; none is a clean "still-valid-high".

---

## DSS-CAN-006 — Privileged `run_command` sudo fallback bypasses runtime-user isolation

**Codex claim (verbatim intent):** `run_command` validates the pipeline and denies caller-supplied sudo, but if a privileged allowlisted stage fails with a permission error it RETRIES internally by prepending `/usr/bin/sudo -n --` and CLEARS per-stage `runtime_user`, crossing the restricted-user boundary where sudoers permits it.

**Current code located at:** `packages/sift-core/src/sift_core/execute/tools/generic.py:248-304` (codex cited `219-267` on `b995491`).

**Drift since scan:** `git log --oneline b995491..HEAD -- generic.py` → 4 commits (c6e0a1a, fd1961c, fc8d927, 2e36212), all F3/F12 stderr + broken-pipe surfacing fixes. **`git diff b995491..HEAD` shows ZERO changes to the sudo/escalation/runtime_user block** — the +46 lines are downstream of it. The mechanism is present exactly as scanned.

**CURRENT STATUS:** PARTIALLY-MITIGATED → NEEDS-OPERATOR-DECISION. The escalation mechanism exists and is agent-reachable, but in the **packaged production posture it is neutralized** (the worker runs as `agent_runtime`, which has *zero* sudoers, so the inner `sudo -n` always fails). It remains a latent foot-gun in non-production postures and is architecturally redundant with the ingest broker.

**Evidence (current source):**
```python
# generic.py:248-289 — direct attempt, then a silent sudo retry that clears runtime_user
if pipeline_result["exit_code"] != 0 and _is_permission_error(...):
    raise PermissionError(...)
except (PermissionError, ExecutionError) as exc:
    is_perm = isinstance(exc, PermissionError) or "Permission denied" in str(exc) or "only root can do that" in str(exc)
    if not is_perm or not pipeline_privileged:
        raise
    ...
    escalated_argv = ["/usr/bin/sudo", "-n", "--", stage["resolved"]] + stage["argv"][1:]
    ...
    if stage["privileged"]:
        escalated_stage["runtime_user"] = ""   # <-- clears the drop-to-restricted-user marker
    ...
    pipeline_result = execute(escalated_stages, ...)   # re-run as whatever the worker user can sudo to
```
The "privileged" flag is set in `security.py:1122` (`binary in _PRIVILEGED_TARGETS`). `_PRIVILEGED_TARGETS` (security.py:498) = `{mount, umount, losetup, blkid, fdisk, dd, dc3dd, dcfldd, vol, vol3, palso, yara}`.

**The real privilege boundary is the sudoers, not the Python.** Two drop-ins:
- `scripts/setup-agent-runtime.sh:163` → `SERVICE_USER ALL=(RUNTIME_USER) NOPASSWD: ALL` — lets the **service user** become `agent_runtime`. It grants `agent_runtime` *nothing*.
- `scripts/setup-ingest-mount-sudoers.sh:87-88` → `Cmnd_Alias SIFT_MOUNT = <full paths of xmount,ewfmount,mount,umount,ntfs-3g,losetup,qemu-nbd,partprobe,fusermount,fusermount3, modprobe nbd max_part=8>` then `SERVICE_USER ALL=(root) NOPASSWD: SIFT_MOUNT` — root, but **only for the mount helpers and only for the SERVICE_USER**.

**Reachability trace (this is the decisive part):**
- The escalated stage does `sudo -n -- <bin>` (no `-u <user>` → targets **root**). It succeeds only if the *process that runs it* has a root NOPASSWD sudoers rule for `<bin>`.
- **Packaged production** (`configs/systemd/sift-gateway.service`): `User=sift-service`, `SIFT_EXECUTE_SYSTEMD_SCOPE=1`, helper set. `executor._systemd_scope_command` → `sudo -n <scope-helper> --runtime-user agent_runtime -- <worker>`; the helper runs `systemd-run` as root with `--uid agent_runtime`, so **the run_command worker (and the escalated stage) execute as `agent_runtime`**. `agent_runtime` has no sudoers at all → `sudo -n -- mount` → *"agent_runtime is not allowed to run sudo"* → exit≠0 → `escalation_info.status="failed"`. **The boundary is never crossed; the fallback is dead in production.** (As a side effect, `mount`/`losetup` via `run_command` simply *cannot* succeed in production — privileged mount is served by the ingest broker, DSS-CAN-007, not by `run_command`.)
- **Where it DOES fire:** (a) dev same-user mode (`runtime_user` unset → worker runs as the service user; `sudo -n -- mount` succeeds as root for the mount-family **only**, since only those have a root grant); (b) the documented "single workstation" install where the service runs as the human admin carrying a broad `ALL=(ALL) NOPASSWD: ALL` (then **every** `_PRIVILEGED_TARGETS` binary — incl. `dd`, `vol`, `yara` — escalates to root). `setup-ingest-mount-sudoers.sh:19-23` explicitly calls this posture out: "on a workstation where the service runs as the human admin account ... this allowlist is documentary."
- **Auditability:** not actually silent in the record — `generic.py:382-385` stamps `privilege_escalation` + `privilege_events` into the result, which the gateway audit envelope persists to `app.audit_events.details` (RUN-3 provenance). It *is* silent to the agent in that the tool just returns success.

**Exploit preconditions:** authenticated agent identity with `mcp:*` (or run_command scope), an active case, and the evidence gate satisfied (registered+sealed+chain OK). AND a deployment where the run_command worker user holds a root sudoers grant for the target binary — i.e. **NOT** the packaged `agent_runtime`-confined posture.

**Blast radius if valid (non-prod postures):** dev same-user → agent can `mount`/`losetup`/`umount` as root, bounded by the `security.py` arg validator (mount source must be `/dev/*` or under the case/cases-root; target under case `tmp/extractions/agent`; losetup read-only; dd if/of constrained). Note the validator allows `mount /dev/sdaN <case>/tmp/x` (source `startswith("/dev/")`) and does **not** constrain `-o` options — so on a sudo-capable worker the agent could mount a host block device or pass arbitrary mount options as root. Admin-broad-sudo workstation → full root via `dd`/`vol`/`yara` on attacker-influenced bytes. In the canonical VM posture: **no escalation.**

**Project-invariant check:** Interacts with the least-priv sandbox (the whole point — `agent_runtime` confinement is what neutralizes this) and the DB-authority audit path (escalation events do reach `app.audit_events.details`). The fix must preserve: run_command stays the hardened DFIR exec tool; privileged mount continues to be available **via the ingest broker** (DSS-CAN-007), not via a silent in-tool retry.

**FIX APPROACH (secure-by-design — recommendation, not a menu):**
- Root cause: an *automatic, silent* privilege-escalation retry baked into the agent-facing exec tool, gated only by a static binary allowlist that is broader than (and decoupled from) the sudoers that actually authorizes root. It is fail-*open* by design (try unprivileged, then silently upgrade).
- **Recommended change: remove the sudo-fallback block from `generic.py` entirely** (lines ~250-304: drop the `except`-branch escalation, the `escalated_stages` construction, and the `runtime_user=""` clearing). Rationale: it is *already inert in the canonical deployment* (agent_runtime can't sudo), so removal costs **zero functionality in production**; and the legitimate privileged-mount need is already served by the dedicated, sudoers-minimized ingest worker broker. Privileged mount belongs in the broker, not in a transparent retry inside the sandboxed agent tool. This is the "fail-closed vs ergonomics" call: there is no real ergonomics loss because the path doesn't work in prod anyway.
- If the operator wants run_command-initiated privileged mount on workstation installs, do **not** restore the silent retry — expose it as an **explicit, separately-scoped, operator-approved** privileged action (its own tool + its own narrow `(root)` sudoers Cmnd_Alias), never an implicit upgrade, and never with `runtime_user` cleared silently.
- Why it preserves invariants: keeps run_command in the `agent_runtime` jail; keeps root capability concentrated in the minimized broker; keeps the gateway a thin policy boundary.
- Test strategy: (1) **fail-on-revert unit test** in `packages/sift-core` asserting that a privileged stage hitting EPERM raises/returns a permission failure and **never** emits `privilege_escalation.mechanism == "sudo_fallback"` (assert the key is absent); add `privilege_escalation` to `SURFACE_OPTIONAL_KEYS` if it is surfaced. (2) **Live deploy-and-prove on the VM** (this is sandbox behavior the harness can't fully prove): on the packaged `agent_runtime`-confined gateway, run `run_command("mount <case-image> <case>/tmp/x")` and confirm it fails closed with no root mount and no `sudo_fallback` event in `app.audit_events.details`; diff before/after removal. Restart `sift-gateway` + workers, clear `__pycache__`, re-run the exact repro.
- Alternatives rejected: (a) "keep the retry but log louder" — leaves the fail-open foot-gun and the runtime_user clearing; rejected. (b) "narrow `_PRIVILEGED_TARGETS` to the mount-family" — reduces the blast radius on broad-sudo hosts but keeps the silent-escalation design and still escalates mount as root invisibly; rejected as monkey-patching the symptom.

**Cross-cluster dependency:** Tightly coupled to **DSS-CAN-007** (same cluster) — both converge on "agent causes a root mount of attacker-influenced bytes." The correct end-state is: run_command never mounts as root (this finding), all privileged mount flows through the broker (007). Loosely related to **DSS-CAN-001** (cluster AUTH): a REST-tool bypass that reaches `Gateway.call_tool` could invoke run_command outside the normal policy stack — verify any such path still routes through the same `agent_runtime`-confined executor (it should, since confinement is in `executor.py`, not the middleware).

**Open question for operator:** Do any supported deployments actually rely on `run_command` mounting/imaging as root (vs. the ingest broker)? If "no" (expected), removal is pure hardening. If "yes" on workstation installs, that requires the explicit operator-approved privileged tool above — confirm before removal so we don't silently drop a workflow.

**Root-need verification (SEC-9 follow-up — operator hypothesis "vol/plaso/parsers/extractors need sudo"): REFUTED.** Per-tool reality:
| Tool | Needs root? | Why / what run_command feeds it |
|---|---|---|
| mount / umount / losetup | **YES** | kernel mount / loop-attach — but served by the ingest broker (DSS-CAN-007), not run_command; in prod run_command *can't* mount (agent_runtime has no sudoers) |
| blkid / fdisk | only on raw `/dev/*` | metadata read; on a regular image file just needs read perms. `fdisk` is restricted to `-l/--list/-s`. |
| dd / dc3dd / dcfldd | only when `if=/dev/*` | raw-device read needs root; `if=`file→`of=`file needs only perms |
| **vol / vol3** | **NO** | reads a memory-image FILE in userspace (`vol -f evidence/mem.raw <plugin>`). `parse_memory.py` has no `sudo`; `worker.py` keeps a vol3 symbol cache *shared with agent_runtime* → vol3 demonstrably runs as agent_runtime |
| **palso (plaso)** | **NO** | `log2timeline.py … <input_path>` reads images via dfvfs/pytsk3/libewf in userspace (no kernel mount); `parse_plaso.py` has no `sudo` (ingest worker, not run_command) |
| **yara** | **NO** | scans files — agent instructions (`instructions.py:77`): `run_command(['yara','-r','-s','rules.yar','evidence/'])` |

Decisive empirical proof: in the packaged posture `agent_runtime` has zero sudoers, so the fallback is already inert — vol3/yara/plaso/EZ-parsers run today as `agent_runtime` without escalation and work (live-proven on the VM). That is direct proof they don't need root. The fallback is **vestigial** (predates the worker-decoupling architecture, when ingest mount still went through run_command). **Verdict reinforces option (A): remove the fallback.** Reserve option (B) — an explicit, operator-approved, narrowly-sudoered acquisition tool for `dd`/`blkid`/`fdisk` on `/dev/*` only — *only if* the operator confirms agent-driven raw physically-attached-device acquisition is a real workflow (likely not; agent_runtime ACLs don't grant `/dev` access regardless). The named parsers need nothing.

---

## DSS-CAN-007 — OpenSearch ingest privileged mount path runs outside the generic validator/sandbox

**Codex claim (verbatim intent):** Non-dry-run OpenSearch ingest is redirected out of the gateway sandbox into a mount-capable worker that launches `ingest_cli` + direct `sudo` mount/FUSE helpers on attacker-supplied evidence images.

**Current code located at:** redirect = `packages/sift-gateway/src/sift_gateway/policy_middleware.py:1421-1559` (`OpenSearchJobDispatchMiddleware`; codex cited `1123-1164`). Mount helpers = `packages/opensearch-mcp/src/opensearch_mcp/containers.py:86-260` (`MountContext`, `mount_image`, `_mount_ewf`/`_mount_raw`/`_mount_nbd`). Worker unit = `configs/systemd/sift-opensearch-worker@.service`. Sudoers = `scripts/setup-ingest-mount-sudoers.sh`.

**Drift since scan:** `git log` shows 9 commits touching policy_middleware (+328 lines), all M-INGSTATUS augmentation + audit-provenance (Unit 1/Gap A/B, L-1b least-priv DSN). The `_enqueue` redirect gained only an additive B-D1/L-1b audit-DSN injection (lines 1483-1499); the redirect/dispatch behavior is structurally unchanged.

**CURRENT STATUS:** PARTIALLY-FIXED → NEEDS-OPERATOR-DECISION. The "runs outside the generic validator/sandbox" framing is **by design and correct** (FUSE cannot mount inside the gateway's private mount namespace — see the unit comment). The remediations Codex *proposed* (minimized sudoers, evidence-gate, least-priv broker) are **already implemented**. The genuine residual is kernel-level isolation of hostile image bytes.

**Evidence (current source):**
```python
# policy_middleware.py:1446-1462 — non-dry-run ingest/enrich → durable worker job
async def on_call_tool(self, context, call_next):
    name = _tool_name(context)
    if name not in _OPENSEARCH_JOB_DISPATCH_TOOLS:   # {opensearch_ingest, opensearch_enrich_intel}
        return await call_next(context)
    ...
    if name == "opensearch_ingest" and _is_truthy(args.get("dry_run", True)):
        return await call_next(context)             # previews stay on the thin proxy
    return await asyncio.to_thread(self._enqueue, name, dict(args), case)
```
```python
# containers.py:113-141 — the broker uses sudo for the SPECIFIC mount-family helpers only
subprocess.run(["sudo", "umount", str(mp)], ...)
subprocess.run(["sudo", "fusermount", "-u", str(mp)], ...)
subprocess.run(["sudo", "qemu-nbd", "-d", dev], ...)
subprocess.run(["sudo", "losetup", "-d", dev], ...)
```
Sudoers (`setup-ingest-mount-sudoers.sh:83-89`): a single `SIFT_MOUNT` Cmnd_Alias of **full-path** helpers, **no shell/wildcard**, `modprobe` pinned to exactly `nbd max_part=8`, `tee` deliberately excluded — `SERVICE_USER ALL=(root) NOPASSWD: SIFT_MOUNT`.

**Reachability trace:** `gateway_policy_middlewares` (policy_middleware.py:1577-1595) places `OpenSearchJobDispatchMiddleware` **INNERMOST**, after `ToolAuthorizationMiddleware`, `AddonAuthorityMiddleware`, `CaseContextMiddleware`, `AuditEnvelopeMiddleware`, `ProxyActiveCaseMiddleware`, and **`EvidenceGateMiddleware`**. So a non-dry-run ingest reaches the enqueue only with: a valid identity, the `opensearch_ingest` tool authorized, an active case, a pre-dispatch audit row, and **evidence registered+sealed+chain-OK**. The job is claimed by `sift-opensearch-worker@` (runs as `sift-service`, `FOR UPDATE SKIP LOCKED` → N parallel), which `sudo`-mounts via the `SIFT_MOUNT` allowlist. The gateway itself never mounts and never gains privilege (enqueues opaque ids + a path-free `spec_public`; `case_dir` travels only in `spec_internal`, never to the agent).

**Exploit preconditions:** authenticated agent, active case, **operator-registered+sealed evidence**, non-dry-run ingest. The "attacker-supplied image bytes" are bytes the operator has registered as case evidence — but in DFIR the evidence image is *inherently untrusted* (it's a suspect's disk), so a crafted filesystem/E01 designed to exploit a kernel FS driver or FUSE helper is a realistic threat.

**Blast radius if valid:** a kernel filesystem-driver or mount-helper memory-safety exploit triggered while `sudo`-mounting a crafted image executes **as root** on the production VM (the worker holds `CAP_SYS_ADMIN` in its bounding set for FUSE). There is no microVM/container/gVisor boundary around the parse, so a successful kernel exploit is VM-root, not merely worker-user. (Same end-state as DSS-CAN-006's mount path.)

**Project-invariant check:** This *is* the canonical worker-decoupling architecture (gateway = thin policy boundary; N least-priv mount-capable workers; non-dry-run ingest intentionally redirected out of the FUSE-incompatible sandbox). Any fix must preserve it. The sudoers minimization, evidence gate, and least-priv worker are already the intended posture. The residual is explicitly **documented** in the unit: `sift-opensearch-worker@.service` notes `PrivateDevices`/`RestrictNamespaces` are omitted because they break FUSE — a known residual.

**FIX APPROACH (secure-by-design):**
- Root cause: hostile, untrusted evidence bytes are parsed by **kernel** filesystem/mount code paths running as root, with host-level (not VM/container-level) isolation. Codex's stated remediation list is mostly satisfied; the unsatisfied item is byte-level isolation.
- Proposed change (defense-in-depth, operator-gated — not a code one-liner): (1) **Prefer userspace, read-only forensic parsers** over kernel mounts where the format allows — `libtsk`/`pytsk3` or `dissect.target` read E01/raw/NTFS without a privileged kernel mount, removing the root-mount step for the common path; reserve `sudo` FUSE/loop mount for formats that truly require it. (2) For the remaining kernel-mount path, **isolate the mount+parse in a disposable microVM/container** (e.g. a per-job firecracker/qemu microVM or a `RestrictNamespaces`-compatible container that *can* FUSE) so a kernel exploit is contained to the throwaway guest, not VM-root. (3) Keep the `SIFT_MOUNT` sudoers as-is (already minimized). (4) Surface the isolation tier used (`kernel-mount` vs `userspace-parse` vs `microvm`) in the ingest `result_public`/`*Out` and in `app.audit_events.details` so the examiner knows the trust posture of each ingest.
- Why it preserves invariants: keeps the gateway thin, keeps the broker model, keeps root concentrated in the minimized allowlist; only narrows what touches hostile bytes as root.
- Test strategy: (1) **fail-on-revert surface test** asserting non-dry-run `opensearch_ingest` returns a `dispatched_to: "opensearch-worker"` job envelope (never an in-gateway mount) and, once added, an `isolation_tier` key in the `*Out` model (register it in `SURFACE_OPTIONAL_KEYS`). (2) **Live deploy-and-prove on the VM**: ingest a benign E01 end-to-end; confirm the mount happens only on the worker, only via `SIFT_MOUNT` binaries (audit/`journalctl`), and that `isolation_tier` is reported. A malicious-image kernel-exploit test is out of scope for the harness — call it out as a manual red-team / fuzzing item, not a CI gate.
- Alternatives rejected: (a) "block ingest of untrusted images" — defeats the product's purpose (DFIR is analyzing untrusted images); rejected. (b) "add NoNewPrivileges/PrivateDevices to the worker unit" — empirically breaks FUSE mount (documented in the unit); rejected as a direct measure, which is *why* microVM/userspace-parse is the right lever.

**Cross-cluster dependency:** Shares the root-mount blast radius and the end-state with **DSS-CAN-006** (same cluster). Adjacent to **DSS-CAN-008/009/017** (cluster OPENSEARCH — archive/tar/7z extraction containment on the same ingest path; the same hostile-bytes-into-the-worker pipeline). The microVM/userspace-parse isolation here would also blunt those extraction findings — design the isolation boundary once for the whole ingest worker.

**Open question for operator:** Is a per-job microVM/container acceptable operationally (it adds ingest latency + a VMM dependency), or is the documented host-level residual accepted for now with userspace-parse adopted only for the formats that support it? This is a deliberate cost/assurance trade — needs an operator decision.

---

## DSS-CAN-022 — `run_command` systemd `auto` mode silently downgrades cgroup/network isolation

**Codex claim (verbatim intent):** With `SIFT_EXECUTE_SYSTEMD_SCOPE=auto`, if `systemd-run` is unavailable the executor logs a warning and runs the direct worker — silently losing systemd cgroup properties incl. `IPAddressDeny=any`.

**Current code located at:** `packages/sift-core/src/sift_core/execute/executor.py:106-114` (the `auto` fallback), with mode resolution at `49-58` (`_systemd_scope_mode`, which is what codex cited `49-58`). The property set incl. `IPAddressDeny=any` is at `117-127`.

**Drift since scan:** `git log b995491..HEAD -- executor.py` → **no commits; zero drift.** Behavior is exactly as scanned.

**CURRENT STATUS:** PARTIALLY-MITIGATED. The `auto` silent-downgrade code is real and present, but it is **not the shipped default** — production units pin `=1` (fail-closed). The valid residual is (a) `auto` is a silent foot-gun if an operator chooses it, and (b) isolation status is not surfaced to the tool result / audit.

**Evidence (current source):**
```python
# executor.py:49-58 — mode resolution: unset → "off" (unless REQUIRE_RUNTIME_USER), "auto" → "auto", anything else → "required"
def _systemd_scope_mode() -> str:
    raw = os.environ.get("SIFT_EXECUTE_SYSTEMD_SCOPE")
    if raw is None:
        return "required" if _env_flag("SIFT_EXECUTE_REQUIRE_RUNTIME_USER") else "off"
    value = raw.strip().lower()
    if value in {"", "0", "false", "no", "off"}: return "off"
    if value == "auto": return "auto"
    return "required"

# executor.py:106-114 — auto silently downgrades; required fails closed
if not systemd_run:
    if mode == "auto":
        logger.warning("systemd-run requested in auto mode but not found; using direct worker")
        return worker_cmd, False          # <-- no IPAddressDeny=any, no MemoryMax, no cgroup scope
    raise ExecutionError("SIFT run_command cgroup isolation was requested, but systemd-run was not found. ...")
```

**Reachability trace:** The silent path runs only when the env is literally `auto` **and** `systemd-run`/`/usr/bin/systemd-run` is absent. **Packaged production sets `SIFT_EXECUTE_SYSTEMD_SCOPE=1`** in both `configs/systemd/sift-gateway.service:51` and `sift-job-worker.service:49` → mode `"required"` → missing `systemd-run` **raises `ExecutionError`** (fail-closed), never downgrades. So in the shipped posture this is unreachable. It becomes reachable only on a deployment that explicitly opts into `auto`. Separately confirmed: nothing in the returned worker `result` dict reports whether the scope (and thus `IPAddressDeny=any`) was actually applied — `payload["runtime_user_already_applied"]` is sent *to* the worker, but no `systemd_scope_applied`/`isolation` field comes back to the agent surface, so the surfacing invariant ("surface isolation status in tool results") is unmet.

**Exploit preconditions:** an operator who sets `SIFT_EXECUTE_SYSTEMD_SCOPE=auto` on a host lacking `systemd-run`. Then run_command stages run with no cgroup/network confinement and no signal to the agent/audit that isolation silently dropped. Not reachable on the default packaged units.

**Blast radius if valid:** loss of `IPAddressDeny=any` (forensic tool gains network egress), `MemoryMax`/`TasksMax`/`CPUQuota`/`OOMPolicy=kill` (resource-exhaustion / OOM blast). Bounded by the still-present Landlock + runtime-user ACLs; the network egress loss is the most security-relevant (a malicious/compromised forensic tool could exfiltrate or call home).

**Project-invariant check:** Touches the least-priv sandbox (cgroup/network layer of the OS sandbox) and the **MCP surfacing layers** — per the invariant, "surface isolation status in tool results" means it must reach the registry `*Out` model + worker `result_public` envelope + audit `details`, not just `logger.warning`. Currently it reaches only a log line.

**FIX APPROACH (secure-by-design — recommendation, not options):**
- Root cause: an isolation control with a *silent fail-open* fallback mode, plus no positive reporting of whether isolation was applied.
- Recommended change: (1) **Treat `auto` as production-unsafe** — either remove it, or make it emit a loud one-time **startup** warning (not a per-call debug) and, better, refuse to start in a hardened profile. Production is already fail-closed (`=1`); keep it that way and document `auto` as dev-only. (2) **Surface isolation status**: add a small `isolation` block to the run_command result — `{ "systemd_scope_applied": bool, "runtime_user_applied": bool, "seccomp_mode": "log|kill", "landlock": bool }` — threaded from `_systemd_scope_command`'s second return value (already computed: `runtime_user_already_applied`) and the worker, exposed in the registry `*Out` model + `result_public`, and copied into `app.audit_events.details`. Then a downgrade is *visible*, not silent.
- Why it preserves invariants: no change to the fail-closed production default; the surfacing addition follows the registry-`*Out` + `result_public` + DB-audit pattern the project already mandates.
- Test strategy: (1) **fail-on-revert unit test**: with `SIFT_EXECUTE_SYSTEMD_SCOPE=required` and `systemd-run` absent, assert `ExecutionError` is raised (fail-closed contract). (2) **surface test**: assert the run_command `*Out` carries the `isolation` block and add its keys to `SURFACE_OPTIONAL_KEYS`. (3) **Live deploy-and-prove on the VM** (sandbox behavior the harness can't fully prove): on the packaged `=1` gateway, confirm `isolation.systemd_scope_applied == true` and `IPAddressDeny=any` is actually on the transient scope (`systemd-cgls`/`systemctl show` the scope unit); diff a forensic-tool egress attempt before/after to prove network is denied.
- Alternatives rejected: (a) "leave `auto` as-is, just document it" — keeps a silent fail-open in a security control; rejected. (b) "fail-closed always, remove `off` too" — breaks legitimate local dev where no systemd is present; rejected (keep `off` explicit + dev-only).

**Cross-cluster dependency:** none hard. Thematically tied to DSS-CAN-006/007 (all EXEC sandbox integrity). The `isolation`-status surfacing pattern proposed here is the same mechanism DSS-CAN-007's `isolation_tier` reporting would use — implement the surfacing helper once.

**Open question for operator:** Keep `auto` at all? Recommendation is to drop it (or gate it behind a dev-only flag); confirm no current deployment depends on `auto`.

---

## Adjacent EXEC observations (not in the 3 assigned candidates — flagged per directive)

1. **seccomp `kill` invariant is NOT enforced on the synchronous gateway run_command lane.** `configs/systemd/sift-gateway.service:53` sets `SIFT_EXECUTE_SECCOMP_MODE=log` (audit-only), while `sift-job-worker.service:51` sets `=kill`. The worker reads this per-call (`worker.py:108`). So a forensic tool invoked through the **synchronous** gateway run_command path runs seccomp in non-enforcing **log** mode; only the durable job-worker lane enforces `kill`. The recalled project invariant is "seccomp=kill (agent_runtime)". This is a real partial gap in that invariant for the sync lane. **Severity Low–Medium.**

   **SEC-16 follow-up — WHY `log`, and is `kill` safe?** The "kill mode would take down the gateway" hypothesis is **REFUTED**. The seccomp filter is installed via `prctl(PR_SET_SECCOMP, ...)` inside the forked `dfir-exec-launcher` grandchild **immediately before `os.execvpe`** (`dfir_exec_launcher.py:513-516`), per-tool-stage (`worker.py` loops stages → `_argv_for_launcher`). The launcher runs only as `agent_runtime` (it refuses uid 0 and the service uid — `dfir_exec_launcher.py:231-235`), in a separate process from the gateway (and usually a separate systemd scope). `SECCOMP_RET_KILL_PROCESS` therefore kills **only the forensic-tool process**; the gateway never carries the filter. So kill-mode is already correctly *scoped* to the tool stage (option B is the existing design). The real reasons for `log` on the sync lane: (a) **phased rollout** — `kill` was the "RUN-3 Wave-2 live gate" applied to the job-worker (`4ee3d1f`, 2026-06-14 17:34) ~3h after the gateway got `log` (`963bb1b`, 14:55); (b) the filter is a **default-ALLOW denylist** (`_X86_64_LOG_SYSCALLS`, ends `SECCOMP_RET_ALLOW`) of ~33 unambiguously-dangerous syscalls (kexec_load, init_module/finit_module/delete_module, bpf, ptrace, setns, unshare, mount/umount2, swapon, reboot, keyctl, io_uring_*, clone3, …) — **zero-false-positive for forensic parsers** — EXCEPT `socket`(41), which is deliberately LOG-only: the inline comment says *"socket; LOG all socket use in Wave 1, enforce AF-specific in Wave 2"* (`dfir_exec_launcher.py:440`). Flipping the sync lane to `kill` today would kill any tool that calls `socket()` — including the `curl`/`wget` read-only fetches the gateway sync lane explicitly advertises. The job-worker lane runs only ingest/parse of local files (no curl/wget) → `kill` is safe there now. **Recommendation: (A)-conditional — complete the planned Wave-2 socket handling first** (drop `socket`(41) from the kill action and rely on the cgroup `IPAddressDeny=any` already on the scope for egress control, *or* split `socket()` by address family), **then flip the gateway lane to `kill`** so the invariant holds on both lanes. The other ~32 syscalls are safe to `kill` immediately. Do **not** settle on (C)/`log` as the end state — the blocker is the small, already-planned socket change, not gateway-process safety. **Live-prove:** after the change, on the sync lane trigger a denylisted syscall from a test tool (e.g. `unshare`/`ptrace`) → confirm only the tool dies and the gateway stays healthy + serves the next run_command; and confirm a `curl`/`wget` read-only fetch is NOT killed. (Outside my 3 assigned candidates; recommend a separate issue.)

2. **`_PRIVILEGED_TARGETS` is broader than any root sudoers grant.** `dd, dc3dd, dcfldd, vol, vol3, palso, yara, blkid, fdisk` are marked privileged (so they trigger the DSS-CAN-006 fallback) but have **no** root sudoers entry (`SIFT_MOUNT` is mount-family only). On the packaged posture the fallback for them is harmless dead weight; on a broad-NOPASSWD workstation it silently escalates *all* of them to root. Removing the DSS-CAN-006 fallback (recommended above) resolves this too.

3. **`mount` validator does not constrain `-o` options and allows any `/dev/*` source.** `security.py:1019-1039` checks only positional source/target. On a sudo-capable worker (non-prod posture) this permits `mount /dev/sdaN <case>/tmp/x` (host block device) and arbitrary `-o` flags as root. Mooted in the packaged posture by `agent_runtime` confinement, but it widens DSS-CAN-006's non-prod blast radius — tighten if the explicit privileged-mount tool is ever built.
