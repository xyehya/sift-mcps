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

### 2026-06-14 - Tool-surface audit + host-side PTC (bridge/recipes/skill) landed

Status: DONE (B-MVP-028 optimization track; pushed `4138092`)

Changed:
- Full MCP tool-surface audit (live brute-force on the 2.08M-doc Rocba index + a qa-expert
  static code pass) → `docs/optimization/tool-audit-2026-06-14.md`. Two axes: response efficiency
  (run_command quadruple provenance receipt; `opensearch_search` has no large-result autosave;
  `case_brief`/`case_context` dumped every call; per-hit constants `vhir.*`/`host.id`; compact
  `event_data` = unparseable `str(dict)[:500]`) and schema accuracy (zero `outputSchema`; ingest
  poll dead-end `run_id` vs `job_id`; `audit_ids` OPTIONAL-but-rejection-required; `input_files`
  deprecated-unmarked) + SECURITY (opensearch-mcp leaks absolute host paths past the redactor).
- PTC (programmatic tool calling) runs HOST-SIDE in the local terminal (operator correction), not
  in the run_command jail → full Python, gateway still the policy boundary. Bridge + recipes + skill:
  `scripts/ptc/ptc.py` (CA-pinned MCP-over-HTTPS, live token from `~/.claude.json`),
  `scripts/ptc/recipes/{ioc_pivot,aggregate_then_fetch,timeline_drill}.py`, `scripts/ptc/README.md`,
  `.claude/skills/ptc/SKILL.md`. `out/` + `ca-cert.pem` gitignored.

Validation:
- Live-proven: 200-hit `opensearch_search` = ~256 KB on disk / ~10 lines in context (~99% cut);
  2-IOC pivot over 2M docs correlated both external RDP IPs (F-claude-004) into vol-netscan+netstat.
- `python3 -m py_compile` all PTC scripts; recipes run green on the live case.

Next:
- On-wire response-efficiency + schema fixes (B-MVP-029) — complement PTC by slimming the summaries
  that DO return; touch live opensearch-mcp + sift-core, so deploy + re-validate.
- QA-probe artifacts left on the case: timeline event `T-claude-007` + completed `TODO-claude-008`
  (labeled QA-TEST; no delete tool — operator cleanup).

### 2026-06-14 - Post-RUN-3 pipeline decisions locked (sequence, Supabase, legacy, kernel baseline)

Status: DONE

Changed (operator decisions, persisted to task-batches.md Wave Order + the backlog table):
- Remaining sequence: (1) run_command/agent OPTIMIZATIONS first (B-MVP-028), (2) Portal RAG (PT2),
  (3) Supabase default-key research (SB1), (4) repo rename (CL2) near the end, (5) legacy removal
  sweep (B-MVP-023), (6) end-to-end LV1 LAST. LV1 is not to be pulled forward.
- Kernel baseline: SIFT VM ships a fixed default kernel; kernel upgrades NOT encouraged. Every Floor
  control must hold at Landlock ABI v4. ioctl-scoping (ABI v5) is dropped as a dependency — ioctl is
  covered by the seccomp filter at the v4 baseline.
- Supabase (SB1): reframed research-first. Research rotating/re-minting the default `supabase` CLI demo
  JWT secret + anon/service_role keys in place post-install (no install runs with public demo keys),
  avoiding a full self-managed compose unless rotation proves insufficient.
- Legacy (B-MVP-023): DECISION = REMOVE the `legacy_portal_session_enabled` fallback and sweep/delete
  any remaining legacy code paths/tests. Re-owned to CL2 cleanup discipline.

Validation:
- `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`, `git diff --check`.

Next:
- Define the optimization scope (B-MVP-028) and start there before PT2.

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
| B-MVP-012 | Backlog | OPEN | DECISION (2026-06-14): research-first. Research a lighter remediation for the default `supabase` CLI demo JWT secret + anon/service_role keys (rotate/re-mint in place post-install) that avoids a full self-managed compose; compose is the fallback only if rotation is insufficient. No install may run with the public demo keys. | BATCH-SB1 |
| B-MVP-019 | Backlog | OPEN | Ensure add-on register path fields are sourced from staged `/opt/sift-mcps` paths for first real add-on launch. | BATCH-LV1 |
| B-MVP-023 | Backlog | OPEN | DECISION (2026-06-14): REMOVE. Delete the `legacy_portal_session_enabled` fallback and sweep + delete any remaining legacy code paths/tests (operator: remove anything legacy still in code). | BATCH-CL2 |
| B-MVP-026 | Backlog | DONE | RUN-3 MCP positive/negative matrix, seccomp kill flip, AppArmor enforce flip, and evidence integrity proof all green + committed 4ee3d1f pushed to origin/main 2026-06-14. | BATCH-R3-* |
| B-MVP-027 | Backlog | OPEN | `run_command_job` durable lane (Postgres job state machine) fails with `unhandled worker error: KeyError` before exec; synchronous `run_command` lane unaffected. Pre-existing; fix the durable path. | BATCH-R3-* |
| B-MVP-028 | Backlog | DONE | Optimization track defined + first deliverable landed: tool-surface audit (`docs/optimization/tool-audit-2026-06-14.md`) + host-side PTC bridge/recipes/skill (`scripts/ptc/**`, `.claude/skills/ptc/`), pushed `4138092`. On-wire fixes split to B-MVP-029. | B-MVP-028 |
| B-MVP-029 | Backlog | OPEN | On-wire MCP response-efficiency + schema fixes from the audit: run_command receipt dedup (audit_id/job_id/provenance ×4), `opensearch_search` large-result autosave, hoist per-hit constants, define `outputSchema`, fix ingest poll dead-end + `audit_ids` required-labeling, and the opensearch-mcp absolute-path leaks (SECURITY). Touches live opensearch-mcp + sift-core → deploy + re-validate. | B-MVP-029 |

## Validation Commands

Run at the end of documentation/planning sessions:

```bash
python3 scripts/validate_docs.py
python3 scripts/validate_migration_docs.py
git diff --check
```

Add targeted code tests for any touched implementation package.
