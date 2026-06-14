# Session Notes

Status: sprint log and decision register.
Last updated: 2026-06-14.

## Format Rules

- Latest change entry stays at the top of `Current Change Log`.
- Use `Status: DONE`, `Status: IN_PROGRESS`, or `Status: BLOCKED`.
- Keep forks/backlog/needs-input in the single table below.
- Use IDs beginning with `B-MVP-` for backlog/needs-input.
- Do not create extra migration runbooks.

## Current Change Log

### 2026-06-14 - RUN-3 live MCP gate complete; seccomp=kill + apparmor=enforce live; evidence sealed

Status: DONE

Changed:
- Live MCP gate run on the active case via in-session SIFT MCP tools (no curl/Python/API shims).
- Positive forensic matrix GREEN on real sealed evidence under the jail: TSK `img_stat`/`fsstat`/`fls`,
  a multi-stage `fls | grep` pipe (shell=False), and volatility3 `windows.pslist` (python+mmap+symbol
  cache). Output carried the untrusted-provenance label and saved-output sha256 receipts.
- Negative red-team matrix GREEN: ~25 live rows all fail closed with zero `approval_required`
  (sqlite `.shell/.load`, sed `s///e`, `python3`/`python3.12`/`bash`/`busybox`, find `-exec`, tar
  `--checkpoint-action`, vol `--plugin-dirs`, exiftool `-config`, curl `-d`, wget `--post-file`,
  `/var/lib/sift` read, evidence write, findings.json/CASE.yaml, `chattr`/`setfattr`/`mount`); Floor
  live: curl egress → exit 7 (Landlock/cgroup deny); P7 stripped an OSC escape sequence.
- Floor flexibility fix: volatility3 automagic reads `/etc/mime.types` via stdlib mimetypes; granted
  it in BOTH the launcher Landlock set and the AppArmor profile (both layers must allow).
- AppArmor enforce-readiness: added `/proc/[0-9]*/fd/` grant + `PYTHONDONTWRITEBYTECODE=1` on the
  launcher spawn env (worker.py) and worker unit to stop `.pyc` writes into the read-only /opt tree.
- seccomp burn-in clean (0 LOG violations), then flipped template + live worker unit `log → kill`;
  vol+TSK stay green under kill (no SIGSYS).
- `dfir-exec` AppArmor flipped `complain → enforce` with 0 AVC denials on the positive matrix.
- Evidence immutability restored: `chattr +i` on both evidence files (`lsattr` shows `i`); post-matrix
  sha256 of both files equals the sealed manifest hashes (matrix altered nothing).
- spec §10 walked and all-true, incl. G5: 34 transient `sift-run-command-*.scope` units proven via
  journal (`MemoryMax=4G TasksMax=64 CPUQuota OOMPolicy=kill IPAddressDeny=any` per exec).

Validation:
- Host: strict security slice + executor + k5 isolation = 144 passed / 2 xfailed (with the new
  launcher/template/unit changes); earlier full strict slice 64 passed / 2 xfailed.
- Live VM: `/health` ok; gateway + job-worker active; `agent_runtime` uid 995; Landlock ABI present;
  seccomp=kill + apparmor=enforce live; 0 dfir-exec AVCs; evidence sha256 == sealed.

Next:
- Host code changes (worker.py, dfir_exec_launcher.py, dfir-exec.template, sift-job-worker.service,
  2 test files) are deployed live but uncommitted — run `/security-review` on the combined diff, then
  commit and `git push origin main` only on operator authorization.
- Re-render/reinstall is NOT required for the live VM (changes applied in place), but a fresh install
  now carries seccomp=kill + the mime.types/proc-fd profile grants by default.
- Follow-up: fix the `run_command_job` durable-lane `KeyError` (B-MVP-027).

### 2026-06-14 - RUN-3 is locally merged on main; non-MCP live gate is green

Status: DONE (superseded by the live MCP gate entry above)

Changed:
- `run3/integrate` changes are now in local `main`.
- Local gates are green for `sift-core`/`sift-gateway`; strict security slice is green under local run3 settings.
- Live gate run (operator-restricted): `health` and restart checks pass; direct non-MCP floor probes confirm runtime confinement and network/FS denies.

Validation:
- `uv run --extra dev --extra full pytest packages/sift-core/tests -q`
- `uv run --extra dev --extra full pytest packages/sift-gateway/tests -q`
- `SIFT_RUN3_GATE_STRICT=1 uv run --extra dev --extra full pytest packages/sift-core/tests/security -q`
- `python3 scripts/validate_docs.py`
- `python3 scripts/validate_migration_docs.py`
- `git diff --check`

Next:
- Complete MCP-only positive forensic matrix and negative red-team matrix via in-session configured SIFT MCP tools.
- Flip `SIFT_EXECUTE_SECCOMP_MODE` to `kill` only after positive matrix is green.
- Patch AppArmor enforcement findings from burn-in and prove evidence immutability/sha checks end-to-end.
- Push only after final `security-review` + MCP/portal gates pass.

### 2026-06-14 - RUN-3 design and build model frozen

Status: DONE

Changed:
- Canonical spec set for `run_command` hardening is `docs/research/run_command-FINAL-SPEC.md`.
- Canonical execution model for implementation is `docs/RUN3-run_command-hardening-BUILD-PLAN.md` (4 batches in Wave-1/Wave-2 flow).

Validation:
- `docs/migration/Session-Notes.md` and `docs/migration/task-batches.md` updated as the two active planning docs.
- Existing implementation artifacts were lint/validator aligned at that time.

Next:
- Keep RUN-3 batch gates as the first startup priority in future sessions.
- Treat the full FINAL-SPEC as reference-only and use targeted extraction from key sections only.

### 2026-06-12 - Operator readiness model refreshed; decision log reset to two-file tracker

Status: DONE

Changed:
- Operating model was collapsed from long historical batch prose to the active two-doc mode:
  `docs/migration/task-batches.md` + `docs/migration/Session-Notes.md`.
- AGENTS/CLAUDE were aligned to this model and live proofs were standardized around `/health`, service status, and MCP-auth via portal-issued credentials.

Validation:
- `python3 scripts/validate_docs.py`
- `python3 scripts/validate_migration_docs.py`
- `git diff --check`

Next:
- Continue with BATCH-OR/LV hardening flow and complete RUN-3 MCP gates before push.

## Forks / Backlog / Needs Input

| ID | Type | Status | Decision / Input Needed | Owner Batch |
| --- | --- | --- | --- | --- |
| B-MVP-002 | Backlog | OPEN | Rename repo to `ProtocolSiftGateway` is decided at architecture level; CL2 pending operator/infra timing. | BATCH-CL2 |
| B-MVP-006 | Backlog | OPEN | Confirm portal knowledge-document policy for shared/reference-only behavior in PT2. | BATCH-PT2 |
| B-MVP-012 | Backlog | DEFERRED | Self-managed Supabase compose remains deferred after LV1; confirm non-lab deployment timing. | BATCH-SB1 |
| B-MVP-019 | Backlog | OPEN | Ensure add-on register path fields are sourced from staged `/opt/sift-mcps` paths for first real add-on launch. | BATCH-LV1 |
| B-MVP-023 | Backlog | OPEN | Decide whether to keep legacy `legacy_portal_session_enabled` fallback or fully delete legacy session branch/tests. | BATCH-HR3 |
| B-MVP-026 | Backlog | DONE | RUN-3 MCP positive/negative matrix, seccomp kill flip, AppArmor enforce flip, and evidence integrity proof all green on live VM 2026-06-14. Push pending operator authorization. | BATCH-R3-* |
| B-MVP-027 | Backlog | OPEN | `run_command_job` durable lane (Postgres job state machine) fails with `unhandled worker error: KeyError` before exec; synchronous `run_command` lane unaffected. Pre-existing; fix the durable path. | BATCH-R3-* |

## Validation Commands

Run at the end of documentation/planning sessions:

```bash
python3 scripts/validate_docs.py
python3 scripts/validate_migration_docs.py
git diff --check
```

Add targeted code tests for any touched implementation package.
