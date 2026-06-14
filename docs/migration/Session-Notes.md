# Session Notes

Status: sprint log and decision register.
Last updated: 2026-06-15.

## Format Rules

- Latest change entry stays at the top of `Current Change Log`.
- Use `Status: DONE`, `Status: IN_PROGRESS`, or `Status: BLOCKED`.
- Keep forks/backlog/needs-input in the single table below.
- Use IDs beginning with `B-MVP-` for backlog/needs-input.
- Do not create extra migration runbooks.

## Current Change Log

### 2026-06-15 - windows-triage-mcp restored + re-bound as external add-on (add-on contract proof #2)

Status: DONE (landed on local `main`; not pushed). Self-provisioning add-on (operator decision).

Restored the windows-triage-mcp package (removed by BATCH-NW2 `77dfb58`) and re-bound it to the
gateway via the Backend Contract as the SECOND conformant add-on after opencti — a query-only OFFLINE
**known-good/known-bad baseline** database backend (LOLBAS / LOLDrivers / HijackLibs / process
expectations; namespace `wintriage`, global reference plane, no case_dir). Exercises the add-on
spec→registration→binding chain end to end.

- **Restore:** `git checkout 77dfb58^ -- packages/windows-triage-mcp/` (46 files; byte-identical to the
  `sift-mcps-v1` backup — confirmed). Manifest already spec_version 1.0 conformant (matches the opencti
  gold standard).
- **Bug fix:** collapsed a package-wide doubled-module typo `windows_triage_mcp_mcp` → `windows_triage_mcp`
  (14 files incl. `scripts/__main__.py`, `config.py`, `exceptions.py`, `analysis/*`, `db/*`) that broke
  `python -m windows_triage_mcp.scripts.*`; package now `compileall`-clean.
- **Re-bind (reverse the NW2 gateway/workspace removals, opensearch stays decoupled):**
  `pyproject.toml` (`windows-triage-mcp` workspace source + opt-in `windows-triage` extra, NOT in
  `standard` — mirrors opencti); `sift_common/instructions.py` (restore `WINDOWS_TRIAGE` constant only —
  opensearch `enrich_triage`→`enrich_intel` decoupling left intact); `test_phase6.py` (windows-triage-mcp
  back in shipped-manifests + reference-backends sets); restored `test_windows_triage_backend.py`.
- **External discipline preserved:** AD2 conformance (`test_ad2_addon_conformance`) still green — core
  installer seeds NO wintriage; it is operator-registered only. install.sh left untouched (no core wiring).
- **Registration + provisioning:** restored `setup_wintriage()` in `scripts/setup-addon.sh` (menu 4;
  `a`→"1 2 3 4") as a SELF-PROVISIONING add-on — it calls the package's OWN
  `windows_triage_mcp.scripts.download_databases`, not the (deleted) install.sh `download_triage_databases`.
  env_refs only (`SIFT_WINDOWS_TRIAGE_DB_DIR` name→name, gateway-resolved); no raw path stored.

Verification: windows-triage 24 tests; gateway phase6 + backend + ad2 + f1-opensearch-registry 59 tests;
`compileall` clean; `bash -n` setup-addon/install OK; `git diff --check` clean; both doc validators pass.

### 2026-06-15 - Backlog parallel sweep: B-MVP-027 + B-MVP-030 + B-MVP-032 (3-worktree orchestration)

Status: DONE (landed on local `main`; not pushed)

Orchestrated 3 background agents, one per backlog item, each in its own manual worktree off
`main@495037d` (caveat 1) with a zero-overlap file scope-fence. All merged clean (disjoint files),
reviewed, tested on merged `main`.

- **B-MVP-027** (`e95692d`, merge `035ff41`) - durable `run_command_job` KeyError. Root cause: handler
  dropped `_resolved_evidence_refs` + `db_active=True` from the sync-lane contract; teardown surfaced as
  opaque `unhandled worker error: KeyError`. Code fix had ALREADY landed in `0d440a7` (AUT2, 2026-06-10)
  but the row was never closed and had no regression guard. Added 2 regression tests driving the real
  `JobWorker.run_once` loop to exec; evidence-ref test proven to fail against the pre-`0d440a7` handler.
  Tests-only change.
- **B-MVP-030** (`457dc11`, merge `f06ae2e`) - single-file rename `_legacy_token_id`->`_resolve_db_token_id`
  in `audit_helpers.py` + docstring reframed as a correctness FK guard. New `test_audit_token_fk_guard.py`
  (3 tests, no DB dep) asserts a Supabase principal id never lands in `audit_events.actor_token_id`.
- **B-MVP-032** (`9584a97`, merge `f36b0fc`) - startup manifest-drift DETECTION (warn-only) in
  `mcp_backends_registry.py` (`detect_manifest_drift`/`log_manifest_drift`/`check_manifest_drift`) wired
  into `Gateway.__init__` (`server.py`), try/except-guarded so it never blocks boot and never mutates the
  registry. Auto-refresh deliberately NOT done (authority-plane write stays an explicit operator action).
  5 unit tests.

Verification (merged `main`, root env, per-package): sift-core durable/job 45 passed; sift-gateway
audit+drift+job 47 passed; registry (d22a/osx1/backends_registry) 15 passed. `/code-review low` = (none);
both production diffs (b030 rename, b032 warn-only) reviewed, record-field names verified against
`BackendRegistryRecord`. No `/security-review`: b030 is a pure rename + docstring with unchanged FK-guard
logic (now better tested); no new security surface.

NOT pulled forward: **B-MVP-023** (legacy `/dashboard` + `legacy_portal_session_enabled` removal) - large
and coupled to the CL2 rename; wave order pins it to step 5. Left OPEN for the operator to sequence.

### 2026-06-15 - B-MVP-029 on-wire MCP response fixes (dedup + path-leaks + autosave + ingest-poll + rename)

Status: DONE (landed on local `main`; live-proven on VM)

Changed (2-unit parallel team off `main`, orchestrator reviewed/merged/cherry-picked):
- Unit A (`5233cd8`): run_command receipt dedup — one canonical of each field (`provenance.job_id`
  kept, root `job_id` dropped; root `audit_id` kept, `provenance.audit_id` dropped; `full_output_ref`
  kept, `full_output_path` alias dropped). Durable lane unaffected (`receipt.job_id == job.id` set
  independently). Added `output_schema` to `CoreToolSpec` + JSON schema for `case_info`/`evidence_info`/
  `list_existing_findings`; gateway passes `outputSchema` and normalizes it.
- Unit B (`ec9b8d6`): closed F-MVP-2 agent-facing absolute-path leaks in opensearch-mcp via new
  `_case_relative_ref` (reuses `sift_core...sanitize_path_value`, fail-closed + non-absolute fallback):
  `resolved_path`, `log_file` (status + background-launch responses/messages), `dict_path`,
  `coverage_state.filesystem_meta_path`, dry_run container `path`, host-fix "not found" errors.
  `opensearch_search` large-result autosave (>20 hits → full set to `agent/searches/search_<uuid>.json`,
  case-relative `full_path`, top-20 inline) + equality-guarded per-hit constant hoist into
  `common_fields`. Ingest-poll dead-end wording corrected (run_id vs job_id; DB-job-row injection
  deferred → B-MVP-027). Renamed `_legacy_*`→`_impl_*` in `registry.py` + contract/engine docstring.
- Follow-up (`7977fa7`): added gateway-injected `case_dir` field to `SearchIn` so the manifest-declared
  case_dir injection reaches the autosave write (was being dropped at pydantic validation).
- Security audit (DoD gate) found + we closed 3 extra pre-existing path leaks (F2 HIGH coverage_state,
  F1 MED dry_run container path, F5 LOW host-fix case_dir error).

Validation (host, merged `main`, root env):
- sift-core run_command slice 165 passed (2 xfail); gateway response/binding/refactor 110 passed;
  opensearch-mcp 1027 passed (71 skip). `validate_docs.py` + `validate_migration_docs.py` OK;
  `git diff --check` clean.

Live VM proof (`sansforensics@…`, gateway `WorkingDirectory=/opt/sift-mcps`, services active, `/health`
status=ok), portal-credential `/mcp` smoke:
- run_command receipt slim — `audit_id` once at root, `provenance.job_id` once (no root `job_id`),
  `full_output_ref` only (no `full_output_path`), no `provenance.audit_id`.
- opensearch responses carry no absolute paths (`case_dir` redacted; `full_path` case-relative).
- ingest-poll wording corrected live.
- per-hit hoist live (`common_fields` populated with `vhir.case_id`/`vhir.provenance_id`).
- search autosave live: 30-hit query → 20 inline + `full_path=agent/searches/search_<uuid>.json`;
  confirmed 30-doc file on disk under the case write-jail.

Root-cause fix for autosave (live deployment-state): autosave initially no-op'd live because the
opensearch-mcp manifest registered in `app.mcp_backends` (install 2026-06-13) listed
`opensearch_search.safe_case_argument_names=['case_id']` — stale; the current `sift-backend.json`
lists `['case_id','case_dir']`. The Gateway honours the DB-registered manifest (priority over schema),
so it never injected `case_dir`. Refreshed the registered manifest in `app.mcp_backends` to the current
source (recomputed `manifest_sha256` via `mcp_backends_registry.manifest_sha256`) and restarted the
gateway. A fresh install registers the current manifest, so this stale state is install-age-specific;
manifest-drift auto-refresh tracked as B-MVP-032.

Next:
- B-MVP-029 closed. Next sanctioned item is BATCH-PT2 (Portal RAG). `main` is ahead of origin
  (`5233cd8`, `ec9b8d6`, `7977fa7` + this doc commit) — operator to `git push origin main`.

### 2026-06-14 - case-dashboard React subscription optimization

Status: DONE (B-MVP-031 guard slice; frontend behavior unchanged)

Changed:
- Added `useStoreSlice`, a Zustand shallow-selector helper, and converted `case-dashboard` shell/tabs
  from whole-store `useStore()` subscriptions to explicit state/action slices.
- Indexed repeated finding/delta lookups in the command palette, commit drawer, findings list/detail,
  and consolidated Overview KPI/ATT&CK derivation into one memoized findings scan.
- Added `packages/case-dashboard/frontend/src/test/useStore.interface.test.js` to freeze the current
  `useStore.js` state/action contract before future portal store refactors.
- Rebuilt the checked-in portal v2 static dashboard bundle.

Validation:
- `npm test` (85 passed), `npm run build`.
- `uv run --extra dev --extra full pytest packages/case-dashboard/tests -q` (361 passed).
- `git diff --check -- packages/case-dashboard`.
- Live VM: active gateway `WorkingDirectory=/opt/sift-mcps`; rsynced `packages/case-dashboard` there,
  restarted `sift-gateway.service`, verified service active, `/health` returned `status=ok`, and portal
  v2 index references deployed asset `index-DwBgAHAv.js`.
- `npm run lint` still fails on existing package-wide React compiler/no-unused findings unrelated to
  this selector pass.

Next:
- B-MVP-031's store-coupling guard is landed; gateway complex-density remains a later review target.

### 2026-06-14 - Knowledge-graph codebase assessment; "legacy" markers grounded against real code

Status: DONE (planning; no behavior change)

Changed:
- Ran a 4-lens assessment off `.understand-anything/knowledge-graph.json` (2,126 nodes / 3,201 edges)
  and grilled the 4 graph "legacy" markers against actual code. All 4 were false positives for deletion:
  - `_legacy_token_id` (sift-gateway/audit_helpers.py) is a correctness guard, not legacy — stops a
    Supabase principal id being written into `audit_events.actor_token_id` (FK → `app.mcp_tokens.id`).
  - opensearch-mcp `_legacy_server`/`_legacy_error`/`_search_hit_from_legacy` are NOT dead: `registry.py`
    is the deployed typed contract (`create_server()` is what `server.main()` stdio + `http_server` build),
    and `opensearch_mcp.server` is the live implementation engine it delegates into. Stale naming, not cruft.
  - v1 `/dashboard` mount (`create_dashboard_app` + `serve_index`) is the `legacy_portal_session_enabled`
    plane; v2 `/portal` is the real app. Genuine residue, already owned by B-MVP-023/CL2.
- Operator decision: KEEP the locked 2026-06-14 sequence. Do NOT spin a parallel de-legacy sprint.
  - opensearch `_legacy_*`→`_impl_*` rename folds into B-MVP-029 (same files, zero extra scope).
  - v1 `/dashboard` removal stays in B-MVP-023 / CL2 (step 5), not pulled forward.
- AGENTS.md gained two durable invariants (opensearch two-layer contract/engine; v1 /dashboard = legacy
  portal-session plane) so the graph/Opus misread does not recur.

Validation:
- `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`, `git diff --check`.

Next:
- Architecture diagram revamped: new code-grounded Excalidraw at `docs/architecture/sift-architecture.excalidraw`
  (84 elements, 7 zones, validated; 4 anchor facts spot-checked against code). Old
  `docs/regenerate/Architecture.mmd` relabelled SUPERSEDED (kept for its charter D# annotations).
- B-MVP-029 remains the next sanctioned implementation item (now carries the opensearch rename bolt-on).

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
| B-MVP-027 | Backlog | DONE | Durable lane KeyError root-caused: handler dropped `_resolved_evidence_refs` + `ActiveCaseContext(db_active=True)` from the sync-lane contract → teardown surfaced as opaque `unhandled worker error: KeyError`. Code fix already landed in `0d440a7` (2026-06-10, AUT2) but row was never closed and had NO regression guard. Added regression coverage 2026-06-15 (`e95692d`): two tests drive the real `JobWorker.run_once` loop (plain + evidence-ref) to exec; evidence-ref test proven to FAIL against the pre-`0d440a7` handler. No prod change needed. | BATCH-R3-* |
| B-MVP-028 | Backlog | DONE | Optimization track defined + first deliverable landed: tool-surface audit (`docs/optimization/tool-audit-2026-06-14.md`) + host-side PTC bridge/recipes/skill (`scripts/ptc/**`, `.claude/skills/ptc/`), pushed `4138092`. On-wire fixes split to B-MVP-029. | B-MVP-028 |
| B-MVP-029 | Backlog | DONE | On-wire MCP response fixes landed + live-proven 2026-06-15 (`5233cd8`/`ec9b8d6`/`7977fa7`): run_command receipt dedup, opensearch_search large-result autosave + per-hit hoist, `outputSchema` on core tools, ingest-poll wording, opensearch-mcp absolute-path leaks closed (SECURITY; +3 found by audit), `_legacy_*`→`_impl_*` rename. Autosave live-activation required refreshing the stale DB-registered opensearch manifest (case_dir in safe_case_argument_names). DB-job-row injection for real ingest polling deferred → B-MVP-027; manifest-drift auto-refresh → B-MVP-032. | B-MVP-029 |
| B-MVP-030 | Backlog | DONE | 2026-06-15 (`457dc11`): single-file rename `_legacy_token_id`→`_resolve_db_token_id` in `audit_helpers.py` (helper is module-private, def+call both internal) + docstring reframed as a correctness FK guard (not a legacy shim). New `tests/test_audit_token_fk_guard.py` (3 tests, no DB dep via injected fake conn) asserts a Supabase principal id never lands in `audit_events.actor_token_id` while legitimate agent attribution is still recorded. | BATCH-CL2 |
| B-MVP-031 | Backlog | OPEN | Dashboard coupling guard source slice DONE 2026-06-14: `useStore.js` interface characterization test added and dashboard selectors landed. Remaining: track gateway complex-density (21/32 nodes) as a review target. No deletion. | BATCH-PT1 |
| B-MVP-032 | Backlog | DONE | 2026-06-15 (`9584a97`): startup manifest-drift DETECTION (warn-only) added. `detect_manifest_drift()` (pure, DB-free) + `log_manifest_drift()` + `McpBackendRegistry.check_manifest_drift()` in `mcp_backends_registry.py`; wired into `Gateway.__init__` after the `app.mcp_backends` load (`server.py`), try/except so it never blocks boot and never mutates the registry. Recomputes on-disk `sift-backend.json` sha via existing `manifest_sha256` + `load_and_validate_manifest`, WARNs naming backend + both shas on mismatch; operator re-registers to clear. Auto-refresh deliberately NOT done (authority-plane write must stay explicit operator action). 5 unit tests; fresh installs unaffected (shas match). | BATCH-LV1 |

## Validation Commands

Run at the end of documentation/planning sessions:

```bash
python3 scripts/validate_docs.py
python3 scripts/validate_migration_docs.py
git diff --check
```

Add targeted code tests for any touched implementation package.
