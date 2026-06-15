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

### 2026-06-15 - LV2 live-VM re-verify (post-LV1 fix wave) + B-MVP-036 real fix

Status: DONE (host + live VM). Non-destructive surgical deploy to the running `/opt/sift-mcps` install
(rsync'd the 3 changed package `src/` trees host→VM, `sift-service`-owned, service restart; NO `uv sync`, NO
`.venv` touch, live Rocba case `case-rocba-exfiltration-06150051` preserved). All sanitized; agent used a
minimal MCP client (process-env `SIFT_AGENT_TOKEN` + current VM CA) for gateway calls.

- **B-MVP-038 LIVE-PROVEN**: wintriage re-enabled, `/health` tools_count 18→24, strict gateway `tools/list`
  clean (NO `-32001`), verdicts correct. Left `enabled=true`.
- **B-MVP-037 RESOLVED**: 0-docs was a missing `hostname` arg for `format=memory` (not vol/symbols); re-run
  with `hostname=SRL-FORGE` → 2186 docs. Vol healthy.
- **B-MVP-036 was a REAL miss, now fixed (`84546ee`) + LIVE-PROVEN**: the served `registry.create_server()`
  tools advertise the `*In` model schema; `CountIn`/`AggregateIn`/`TimelineIn`/`FieldValuesIn` lacked
  `case_dir` (only `SearchIn` had it) so the gateway's FastMCP proxy `_forward` rejected the injected kwarg.
  Hoisted `case_dir` into `CaseScopedQueryBase`; regression guard rewritten to the served-schema layer. All 5
  case-scoped tools verified live (count=7985, aggregate/timeline/field_values OK, search regression OK). The
  prior tracker "did not reproduce" note (Unit C `530b1b4`) was corrected — its test checked the wrong
  (unserved `server.py`) surface (footgun → B-MVP-041).

Operator-gated: the harness loading all 24 tools needs a full `claude` relaunch; `~/.claude.json` token is
currently `invalid_token` and the host VM CA is stale (rotated during the LV1 fresh install) — both must be
refreshed first. New backlog: B-MVP-041 (dual opensearch tool surface), B-MVP-042 (memory-ingest `hostname`
UX). **Next:** the destructive fresh-install session (B-MVP-033 hardlink root-cause + B-MVP-034 fresh-register
confirm) and B-MVP-002 rename, both operator-gated; push `main` to origin when ready.

### 2026-06-15 - Post-LV1 fix wave: B-MVP-034/035/036/038 + B-MVP-031 (4-worktree parallel orchestration)

Status: DONE (host-side; LV2 live re-verify pending). Four independent host-only units, one manual worktree
off `main` each, zero file overlap, landed via integration branch `lv1/integrate` → `main`.

- **A — gateway** (`00898ae`, pkg `sift-gateway`): B-MVP-035 `.strip()` stdio `command`/`args`/`manifest_path`/`cwd`/`url` in `normalize_connection_config` (secrets are `*_env`, untouched) + B-MVP-038 gateway-side defense `_sanitize_output_schema` (never-raises) on the tools/list aggregation. 524 tests.
- **B — windows-triage** (`1522e96`, pkg `windows-triage-mcp`): B-MVP-038 primary — root `type:object` outputSchema via opensearch `$defs`-hoist; dropped 10 legacy un-namespaced aliases so the exposed surface = the 6 `wintriage_*` the manifest declares; golden regenerated. 24 tests.
- **C — opensearch** (`530b1b4`, pkg `opensearch-mcp`): B-MVP-036 — did NOT reproduce on main (LV1 was a stale staged tree); added a manifest-driven `case_dir` arg-injection regression guard + fixed a pre-existing ContextVar test-pollution leak. 1044 tests.
- **D — setup** (`f65d830`, `scripts/setup-addon.sh`): B-MVP-034 — `stage_runtime_command` emits the staged console-script launch (`/opt/.../.venv/bin/<script>`) for all 4 reference add-ons, not the operator uv.
- **Review follow-up** (`9b43b8c`): unified `_sanitize_output_schema` across core+cached+proxied tools/list paths (was non-uniform). `/code-review` (high) → 1 fix applied, rest → B-MVP-039/040. `/security-review` CLEAN.

Cross-package proof: gateway+wintriage merged suites **548 passed** (A+B compose). Deferred to LV2 by operator
decision: **B-MVP-037** (memory pslist vol symbols — needs live image) and **B-MVP-033** (uv hardlink EPERM —
investigate the hardening regression via an uninstall→reinstall cycle with the hardened profile active; do NOT
flip `UV_LINK_MODE`). Note: D's new `uv sync --inexact` step exercises the same uv-sync path as B-MVP-033, so
LV2 will surface that signal directly. **Next:** LV2 live re-verify on the VM (re-enable wintriage, confirm
~36 tools + live `wintriage_check_artifact`/`opensearch_count`, then B-MVP-037 + B-MVP-033); B-MVP-002 rename
stays a dedicated solo session.

### 2026-06-15 - BATCH-LV1: fresh first-run install + live MCP forensic proof (SB1 / B-MVP-019 / wintriage / E2E)

Status: DONE. True clean-slate first-run install + live operator/agent forensic workflow proven on the SIFT
VM. All proof sanitized (no raw keys/tokens/DSNs/passwords/absolute case paths). Harness MCP reached the
gateway over TLS via `NODE_EXTRA_CA_CERTS` (VM CA copied to host; leaf SAN carries the VM IP, openssl verify
rc 0); agent credential portal-minted.

Step 1 - install (`git clone` @`235fe3c` -> `setup-supabase.sh` -> `./install.sh`): `/health`=status=ok
supabase=ok; `sift-gateway` + `sift-job-worker` active; operator `examiner@operators.sift.local` provisioned
(forced-reset); `db_migrations_applied`; `opensearch_backend_seeded`; handoff written.
- FIRST-RUN INSTALL BUG (blocks any fresh install): `uv sync` aborts with a hardlink EPERM
  (`fs.protected_hardlinks=1` vs uv's read-only cache) on `nvidia-cufft`. Worked around this run with
  `UV_LINK_MODE=copy`. Fix -> B-MVP-033 (set it in `install.sh` `sync_workspace` + addon uv calls).

Step 2 - SB1 / B-MVP-012 (was UNVERIFIED on VM): PROVEN. `supabase/.env` 600 holds the per-install secret;
emitted ANON/SERVICE keys are re-signed (iss label stays `supabase-demo`, but token strings differ from the
public demo constants). Live REST vs `127.0.0.1:54321/rest/v1/`: our `service_role` -> 200, public demo
`service_role` JWT -> 401 (instance validates against our secret, not the demo one). Re-run `setup-supabase`
-> emitted keys byte-identical (secret reused).

Step 3 - B-MVP-019 + AD2 + windows-triage add-on: PROVEN.
- Payload: `setup-addon.sh` run FROM staged `/opt` (REPO_DIR derives from script location) -> `env_refs`-only
  + `manifest_path` = `/opt` staged path. Running from the operator clone would emit the wrong (clone) path.
- AD2: core install seeded ONLY `opensearch-mcp` + `forensic-rag-mcp` (`app.mcp_backends`); 0 opencti, 0
  wintriage. windows-triage appeared only after an explicit operator register (re-auth password prompt =
  sensitive-action gate proven).
- Provisioning gaps surfaced: (a) generated payload command = operator uv (`~/.local/bin/uv`), NOT
  executable by `sift-service` -> worked around by syncing the `windows-triage` extra into the runtime venv
  (`/opt/sift-mcps/.venv/bin/windows-triage-mcp`, sift-service-exec), matching the seeded console-script
  pattern -> B-MVP-034. (b) the portal register form stored the command with a TRAILING SPACE ->
  `FileNotFoundError` on backend start AND it hung the aggregated `tools/list` (`-32001`); fixed by `btrim`
  on the stored command + restart -> gateway should `.strip()` the command -> B-MVP-035.
- Registered (DB row: `manifest_path`=`/opt` staged, sha `0601cd54...`). Restart (D34) -> `/health`
  `tools_count` 18->24, `windows-triage-mcp` mounted, 6 `wintriage_*` in catalog. After the command-fix the
  server launches; it hard-fails closed without baseline DBs, so `known_good.db`/`context.db` were
  provisioned to `/var/lib/sift/windows-triage` (1.14 GB `known_good.db.zst`) for the live tool-call capstone.
- Live wintriage capstone (DIRECT stdio to the backend, bypassing the harness): server boots healthy, BOTH
  baselines loaded (`known_good` + `context` healthy). Real `wintriage_check_artifact` verdicts vs the
  2.68 M-row baseline: `lolbin certutil.exe` -> EXPECTED_LOLBIN (funcs ADS/Decode/Download/Encode, MITRE
  T1105/T1140/T1027.013/T1564.004); `file C:\Windows\System32\svchost.exe` -> EXPECTED (path matches Windows
  baseline); `filename scvhost.exe` -> SUSPICIOUS (typosquat of svchost.exe, edit distance 2). Add-on is
  FULLY FUNCTIONAL.
- HARNESS BLOCKER (B-MVP-038): enabling wintriage in the gateway broke the Claude Code harness `tools/list`
  (`-32001`, then schema-reject). The backend exposes 16 tools (manifest declares only 6; the 10
  un-namespaced `check_*`/`get_*` also leak through -> namespacing gap), and ALL 16 carry
  `outputSchema.type=null`, which the strict MCP client rejects (it requires `"object"`), failing the WHOLE
  tools/list. Left wintriage `enabled=false` in the gateway so the harness surface stays valid; the
  registration row is kept. Fix tracked B-MVP-038.

Step 4 - E2E MCP on live case `case-rocba-exfiltration-06150051` (real SANS Rocba evidence: `rocba-cdrive.e01`
~81 GiB + `Rocba-Memory.raw`, both sealed, chain ok):
- run_command POSITIVE: `ewfinfo` on sealed E01 (audit `...-022`) -> real acquisition metadata; response
  redaction (`[REDACTED:Generic Password]` + `secret_warning`), untrusted-output wrapper, evidence_ref ->
  sealed `evidence_id` provenance, autosave + preview cap.
- run_command POSITIVE pipe: `ewfinfo | grep` -> 2 parsed argv stages, both rc 0 (RUN-3 shell=False
  multi-stage).
- run_command NEGATIVE: `bash -c` blocked ("Binary 'bash' is blocked"); `cat /etc/shadow` denied (path-jail
  `/etc`). Both audited.
- Ingest: decoupled `opensearch-worker` (osw-1/osw-2 units) indexed 4800 evtx docs from the E01 (scoped
  `evtx`/`reduced_ids`/`no_hayabusa`) in ~11s. Memory `pslist` ingest returned 0 docs (vol symbol/profile
  issue -> note B-MVP-037).
- opensearch_search >20 autosave (B-MVP-029): total 5799, returned 50, full set saved to `agent/searches/...`
  (relative path, no leak), top-20 inline. Real Rocba content surfaced (host `SRL-FORGE`, `SRL-FORGE\fredr`
  RDP/local sessions, 7045 MagnetRAMCapture driver install, BITS jobs).
- record_finding `F-claude-001` + record_timeline_event `T-claude-002` staged DRAFT (examiner approval gate).
- manifest-drift (B-MVP-032) quiet at boot AND after the wintriage register/restart.
- Bug: `opensearch_count` rejects the gateway-injected `case_dir` kwarg -> B-MVP-036.

Outcome: BATCH-LV1 acceptance met (`/health` healthy post-restart; MCP positive + negative proofs recorded
with sanitized evidence). B-MVP-012 + B-MVP-019 CLOSED. windows-triage add-on proven fully functional
(direct-stdio capstone) but left DISABLED in the gateway pending B-MVP-038 (its tool outputSchemas break the
harness `tools/list`). New backlog from this run: B-MVP-033..038.

### 2026-06-15 - Pushed to origin + SIFT VM wiped to a fresh slate (for live-test reinstall)

Status: DONE. `main` pushed `495037d..82d82c5` (origin now current — was 14 behind). SIFT VM
(192.168.122.81) torn down to bare for a clean fresh-install live test next session.

Teardown (irreversible, operator-authorized): `install.sh --uninstall --purge-data -y` from the VM clone
(services, docker-compose stack + volumes, AppArmor/auditd/sudoers, venv, SIFT_HOME, `/var/lib/sift`,
`/cases`) + manual removal of what the uninstaller does NOT cover: the CLI-managed Supabase stack (4
`supabase_*` containers + `supabase_db` volume), `sift-opensearch` container + `opensearch-data` volume,
`docker system prune -af --volumes` (1.95 GB reclaimed), `/opt/sift-mcps`, the clone
`/home/sansforensics/sift-mcps`, `~/.sift`, the `sift-opensearch-worker@` template unit, leftover
`sift-ingest-mount` + `sift-run-command-systemd-scope` sudoers, and the `sift-service`/`agent_runtime`
system users.

Verified bare: 0 sift units, 0 docker containers/volumes/images, all dirs gone
(`/opt/sift-mcps`, clone, `/var/lib/sift`, `/cases`, `~/.sift`), no sift users/sudoers/AppArmor, port 4508
down. The VM now exercises a true first-run install path next session.

Pending live proof (LV1, next session — see `.remember/remember.md` handoff): fresh
`git clone && setup-supabase.sh && ./install.sh`, then prove B-MVP-012/SB1 (emitted `ANON_KEY` != demo
constant + `service_role` smoke), B-MVP-019 (add-on staged-path register), windows-triage add-on register
via `setup-addon.sh`, and the end-to-end Rocba MCP path.

### 2026-06-15 - B-MVP-023: legacy v1 /dashboard + legacy_portal_session_enabled plane REMOVED

Status: DONE (landed on local `main` via `44b120d`, merge `620dceb`; not pushed). Auth-plane change —
`/security-review` run (CLEAN).

Executed the saved impact trace (`docs/B-MVP-023-legacy-dashboard-removal-impact.md`) in an isolated
worktree (builder agent), reviewed + security-reviewed, merged. Net −3361 lines.

- Removed: v1 `/dashboard` mount + `create_dashboard_app` + `serve_index` + v1 `static/index.html`; the
  `legacy_portal_session_enabled` flag end-to-end (supabase_auth field/parse, server.py kwarg, routes.py
  param/var/passthrough, auth.py param/branch, gateway.yaml.template key); the legacy `sift_session`
  cookie branch + the examiner Bearer fallback (`_verify_bearer`) + `COOKIE_*`/`revoke_jti`.
- KEPT (guardrails): `_dashboard_api_routes()` (shared v1+v2 REST backbone); `generate_jwt`/`verify_jwt`/
  `is_revoked` (internal utils + still test-used); the `post_auth_logout` cookie-clear (literals inlined);
  v2 `/portal` fully intact (`create_dashboard_v2_app`, `serve_v2_*`, redirects, middleware).
- Auth path now collapses to EXACTLY: valid Supabase session-envelope → operator principal; else
  unauthenticated (principal/examiner/role=None) → route handlers 401/403. No elevated default; fail-closed
  verified. Non-operator principals get role=None (denied); refresh accepts operator only.
- Deviation (flagged + reviewed): `test_token_lifecycle.py` (not in the original plan) authenticated its
  `/api/tokens` suite via the now-deleted Bearer fallback → migrated to the Supabase-envelope harness; it
  still asserts the real gate (401 unauth, 403 readonly, 201 examiner). Removed orphaned `_verify_bearer`
  + dead imports as a direct consequence.
- Security review (auth-plane): CLEAN — no weakened-auth/bypass introduced; points 1-4 confirmed against
  post-change code. Fixed one stale docstring (`routes.py` create_dashboard_v2_app: "legacy auth path").

Verify (merged `main`): case-dashboard 357 passed; sift-gateway 519 passed; 0 failed; doc validators pass.

### 2026-06-15 - BATCH-SB1 / B-MVP-012: per-install Supabase JWT secret (kill the public demo keys)

Status: IMPL DONE on host (verified); VM key-minting propagation is the LV1 proof step.

Operator decision: fresh installs are cheap (2 images) → fix at INSTALL time so a fresh install never
comes up on the public demo keys; no in-place rotation of a running prod DB needed.

Root mechanism (verified against the Supabase CLI source at the PINNED tag v2.105.0 —
`apps/cli-go/pkg/config/apikeys.go`+`auth.go`): the CLI HS256-mints local `anon`/`service_role` over
`auth.jwt_secret`; when empty it falls back to the public demo secret
(`super-secret-jwt-token-with-at-least-32-characters-long`), so `supabase status` emits the well-known
PUBLIC keys. Our `config.toml [auth]` had no `jwt_secret` → demo keys. (Research addendum in
`docs/research/supabase-default-key-remediation.md`.)

Fix (config-time, no container hand-re-keying — the CLI owns GoTrue/PostgREST/Kong wiring):
- `supabase/config.toml [auth]`: `jwt_secret = "env(SUPABASE_AUTH_JWT_SECRET)"`.
- `scripts/setup-supabase.sh`: new `ensure_jwt_secret()` (runs before `ensure_config_toml`/`supabase_start`)
  generates a per-install 256-bit secret (`openssl rand -hex 32`), persists it to `supabase/.env`
  (chmod 600, gitignored) which the CLI auto-loads on EVERY `supabase start` (keys stable across restarts,
  incl. manual ones), and exports it. Idempotent: explicit env wins, else reuse persisted, else generate.
  Refuses the public demo secret. Plus a `capture_credentials` GUARD that DIES if `supabase status` still
  emits the known demo anon/service_role JWTs — a default-key install is impossible (fails loud, not silent).
- Verified on host: bash -n OK; `supabase/.env` gitignored; generate→persist(600)→reuse-stable→demo-reject
  all pass (extracted-logic harness).

UNVERIFIED (VM proof, folds into B-MVP-019/LV1): confirm a fresh `supabase start` with the custom secret
propagates to all CLI-managed containers in one shot — diff emitted `ANON_KEY` vs the demo constant +
one `service_role` smoke against local `/rest`. `db reset` not needed; `supabase stop && start` reloads.

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
| B-MVP-012 | Backlog | DONE | 2026-06-15: resolved at INSTALL time (operator: fresh installs are cheap, 2 images). NOT a self-managed compose. `supabase/config.toml [auth] jwt_secret = env(SUPABASE_AUTH_JWT_SECRET)` + `setup-supabase.sh ensure_jwt_secret()` generates a per-install 256-bit secret, persists to gitignored `supabase/.env` (CLI auto-loads on every start), and a `capture_credentials` guard DIES if `supabase status` still emits the known demo anon/service_role keys → default-key install impossible. Mechanism verified vs CLI source @v2.105.0; host-verified (gen/persist/reuse/demo-reject). VM key-minting propagation proof folds into B-MVP-019/LV1. VM-PROVEN 2026-06-15 (LV1): public demo `service_role` JWT -> 401, our `service_role` -> 200, emitted keys byte-stable on `setup-supabase` re-run. | BATCH-SB1 |
| B-MVP-019 | Backlog | DONE | 2026-06-15 (LV1, live VM): PROVEN end-to-end. `setup-addon.sh` run FROM the staged `/opt/sift-mcps` emits an `env_refs`-only payload with `manifest_path`=`/opt/sift-mcps/packages/windows-triage-mcp/sift-backend.json` (REPO_DIR derives from script location, so running from the operator clone would emit the wrong path). The registered `app.mcp_backends` row carries the staged `/opt` `manifest_path` (sha `0601cd54...`); after register+restart the 6 `wintriage_*` tools surface (`/health` `tools_count` 18->24). AD2 held (only seeded after explicit operator re-auth'd register). | BATCH-LV1 |
| B-MVP-023 | Backlog | DONE | 2026-06-15 (`44b120d`, merge `620dceb`): legacy v1 `/dashboard` mount + `create_dashboard_app`/`serve_index`/v1 static, the `legacy_portal_session_enabled` flag end-to-end, and the `sift_session` cookie + examiner Bearer (`_verify_bearer`) legacy auth branches REMOVED (−3361 lines). Kept shared `_dashboard_api_routes`, `generate_jwt`/`verify_jwt`, logout cookie-clear; v2 `/portal` intact. Auth collapses to Supabase-envelope→401, fail-closed. `/security-review` CLEAN (no bypass). case-dashboard 357 + gateway 519 green. Plan: `docs/B-MVP-023-legacy-dashboard-removal-impact.md`. | BATCH-CL2 |
| B-MVP-026 | Backlog | DONE | RUN-3 MCP positive/negative matrix, seccomp kill flip, AppArmor enforce flip, and evidence integrity proof all green + committed 4ee3d1f pushed to origin/main 2026-06-14. | BATCH-R3-* |
| B-MVP-027 | Backlog | DONE | Durable lane KeyError root-caused: handler dropped `_resolved_evidence_refs` + `ActiveCaseContext(db_active=True)` from the sync-lane contract → teardown surfaced as opaque `unhandled worker error: KeyError`. Code fix already landed in `0d440a7` (2026-06-10, AUT2) but row was never closed and had NO regression guard. Added regression coverage 2026-06-15 (`e95692d`): two tests drive the real `JobWorker.run_once` loop (plain + evidence-ref) to exec; evidence-ref test proven to FAIL against the pre-`0d440a7` handler. No prod change needed. | BATCH-R3-* |
| B-MVP-028 | Backlog | DONE | Optimization track defined + first deliverable landed: tool-surface audit (`docs/optimization/tool-audit-2026-06-14.md`) + host-side PTC bridge/recipes/skill (`scripts/ptc/**`, `.claude/skills/ptc/`), pushed `4138092`. On-wire fixes split to B-MVP-029. | B-MVP-028 |
| B-MVP-029 | Backlog | DONE | On-wire MCP response fixes landed + live-proven 2026-06-15 (`5233cd8`/`ec9b8d6`/`7977fa7`): run_command receipt dedup, opensearch_search large-result autosave + per-hit hoist, `outputSchema` on core tools, ingest-poll wording, opensearch-mcp absolute-path leaks closed (SECURITY; +3 found by audit), `_legacy_*`→`_impl_*` rename. Autosave live-activation required refreshing the stale DB-registered opensearch manifest (case_dir in safe_case_argument_names). DB-job-row injection for real ingest polling deferred → B-MVP-027; manifest-drift auto-refresh → B-MVP-032. | B-MVP-029 |
| B-MVP-030 | Backlog | DONE | 2026-06-15 (`457dc11`): single-file rename `_legacy_token_id`→`_resolve_db_token_id` in `audit_helpers.py` (helper is module-private, def+call both internal) + docstring reframed as a correctness FK guard (not a legacy shim). New `tests/test_audit_token_fk_guard.py` (3 tests, no DB dep via injected fake conn) asserts a Supabase principal id never lands in `audit_events.actor_token_id` while legitimate agent attribution is still recorded. | BATCH-CL2 |
| B-MVP-031 | Backlog | DONE | 2026-06-15: closed as tracked (doc-only, no code). Source slice already landed 2026-06-14 (`useStore.js` characterization test + dashboard selectors). Gateway complex-density (21/32 nodes) recorded as a standing review target; no deletion. | BATCH-PT1 |
| B-MVP-032 | Backlog | DONE | 2026-06-15 (`9584a97`): startup manifest-drift DETECTION (warn-only) added. `detect_manifest_drift()` (pure, DB-free) + `log_manifest_drift()` + `McpBackendRegistry.check_manifest_drift()` in `mcp_backends_registry.py`; wired into `Gateway.__init__` after the `app.mcp_backends` load (`server.py`), try/except so it never blocks boot and never mutates the registry. Recomputes on-disk `sift-backend.json` sha via existing `manifest_sha256` + `load_and_validate_manifest`, WARNs naming backend + both shas on mismatch; operator re-registers to clear. Auto-refresh deliberately NOT done (authority-plane write must stay explicit operator action). 5 unit tests; fresh installs unaffected (shas match). | BATCH-LV1 |
| B-MVP-033 | Backlog | OPEN | First-run install blocker (LV1): `uv sync` aborts with a hardlink EPERM (`fs.protected_hardlinks=1` vs uv's read-only cache, `~/.cache/uv` -> `/opt/sift-mcps/.venv`, same ext4 fs) on `nvidia-cufft`. Worked around this run via `UV_LINK_MODE=copy` env var. ROOT-CAUSE FIRST, do not just force copy mode: prior installs on this VM completed WITHOUT copy mode, so investigate whether recent HARDENING regressed the hardlink path (e.g. file ownership/perms or umask changes, uv cache location/ownership, the `sift-service`/`agent_runtime` user setup, or an install re-exec under a different uid than the cache owner). Only then decide between `UV_LINK_MODE=copy` in `install.sh` `sync_workspace` vs a perms/cache fix. | BATCH-LV1 |
| B-MVP-034 | Backlog | DONE | 2026-06-15 (lv1/setup `f65d830`, integrate `45302cd`): added `stage_runtime_command` to `setup-addon.sh` — emits `$SIFT_MCPS_ROOT/.venv/bin/<console-script>` (no args) for all 4 reference add-ons, the exact shape `install.sh::_seed_one_addon_backend` writes; syncs the add-on extra into the staged venv via `uv sync --inexact` (keeps the installer's `full` deps); operator-uv fallback with a loud warning + remediation if the staged script can't be produced. `bash -n` clean; custom-backend path untouched. MUST be confirmed on a FRESH install in LV2 (console scripts land in `/opt/.../bin`, backend comes up GREEN under sift-service). Robustness follow-ups → B-MVP-040. | BATCH-LV1 |
| B-MVP-035 | Backlog | DONE | 2026-06-15 (lv1/gateway `00898ae`): `normalize_connection_config` now `.strip()`s the stdio `command`/`args`/`manifest_path`/`cwd`/`url` (secrets are `*_env` refs, untouched). Whitespace-only command strips to empty → still trips the existing `stdio backend requires command` guard. +2 registry tests; backend-isolation (one failing backend omitted from `tools/list`, core stays up) verified with a new test. | BATCH-LV1 |
| B-MVP-036 | Backlog | DONE | **CORRECTION** — the lv1/opensearch `530b1b4` "did not reproduce" conclusion was WRONG (it inspected `server.py`'s separate `@server.tool` surface + the function signature — the wrong layer). LV2 live test (2026-06-15) proved `opensearch_count`/`aggregate`/`timeline`/`field_values` STILL reject the gateway-injected `case_dir` through the gateway (search worked). Real root cause: `server.py:main` serves `registry.create_server()`, so the SERVED tool's advertised schema = the `*In` pydantic model; `CountIn`/`AggregateIn`/`TimelineIn`/`FieldValuesIn` did not declare `case_dir` (only `SearchIn` did) → FastMCP proxy `tool_transform._forward` rejects the injected kwarg before the impl. NO manifest drift (sha matched). Fix (`84546ee`): hoisted `case_dir` into `CaseScopedQueryBase` (all 5 are manifest-listed); regression guard rewritten to assert the SERVED `create_server().list_tools()` schema advertises `case_dir` (layer-correct); golden regenerated; 1044 passed. **LIVE-PROVEN on VM (LV2)**: all 5 tools accept injected `case_dir` (count=7985; aggregate/timeline/field_values OK; search regression OK). Dual-surface footgun → B-MVP-041. | BATCH-LV1 |
| B-MVP-037 | Backlog | DONE | 2026-06-15 (LV2, live VM): NOT a Volatility/symbol gap. The `indexed_docs=0 in ~5s` was a missing required `hostname` arg for `format=memory` — the job failed validation in <1s (server.py enforces it) before vol ran. Re-run WITH `hostname=SRL-FORGE` SUCCEEDED: indexed_docs=2186, queryable (index `case-...-vol-pslist-srl-forge`). Volatility healthy (vol3 2.27.0, Win10 ISF symbols cached at `/var/cache/sift/volatility-symbols/windows/`, `windows.pslist` ~3s on the 19GB image). No provisioning fix needed. UX nit (surface the `hostname` requirement in the tool schema/when_to_use) → B-MVP-042. | BATCH-LV1 |
| B-MVP-038 | Backlog | DONE | 2026-06-15: BOTH halves landed. PRIMARY (lv1/wintriage `1522e96`): `_output_schema()` now emits root `type:object` via the opensearch `$defs`-hoist pattern (no PointerToNowhere); legacy un-namespaced aliases no longer advertised → exposed surface = the 6 `wintriage_*` the manifest declares; golden regenerated; 24 tests. DEFENSE (lv1/gateway `00898ae` + consolidation `9b43b8c`): `_sanitize_output_schema` repairs/strips any invalid `outputSchema` (never-raises) on ALL tools/list paths — core + cached + proxied — so no single tool can drop the aggregate list. A+B compose: gateway+wintriage suites 548 passed; `/security-review` CLEAN. Cleanup follow-ups → B-MVP-039. **LIVE-PROVEN on VM (LV2, 2026-06-15)**: wintriage re-enabled (`enabled=true`), `/health` tools_count 18→24, windows-triage backend mounted, strict gateway `tools/list` returned the full surface with NO `-32001`, verdicts correct (`certutil`→EXPECTED_LOLBIN, `scvhost`→SUSPICIOUS). Harness-relaunch confirmation still operator-gated (see LV2 notes: `~/.claude.json` token + VM CA need refresh). | BATCH-LV1 |
| B-MVP-039 | Backlog | OPEN | Cleanup (from B-MVP-038 review, non-blocking): the wintriage `_output_schema` `$defs`-hoist is a verbatim copy of opensearch-mcp's — hoist into `sift_common` as a shared `output_schema(success_model, error_model)` helper, and add a guard against `$defs` name collisions across the success/error branches. Also delete or move-to-historical the now-unreachable wintriage `ALIAS_REGISTRY`/`ToolAliasDef` machinery (no longer registered by `register_all`). No behavior change. | BATCH-LV1 |
| B-MVP-040 | Backlog | OPEN | Harden `setup-addon.sh stage_runtime_command` (from B-MVP-034 review): (a) verify the resolved console-script path is under the STAGED runtime root and warn if not — running from an operator checkout passes the `-x` check but yields a path `sift-service` cannot exec, with no fallback warning; (b) guard empty `SIFT_MCPS_ROOT`/`PYTHON_BIN` before building the payload; (c) collapse the always-equal console/entry doubled arg; (d) empirically confirm `uv sync --inexact --extra <addon>` does NOT prune the `full`-synced core backends (opensearch/rag) when registering opencti/windows-triage — verify on LV2 fresh install. | BATCH-LV1 |
| B-MVP-041 | Backlog | OPEN | Footgun (surfaced by the B-MVP-036 miss): opensearch-mcp has TWO parallel tool surfaces — `server.py`'s `@server.tool`-decorated `server` (a `mcp.server.fastmcp` FastMCP, NOT served over stdio) shadowing the live `registry.create_server()` (standalone `fastmcp`, what `server.py:main` runs). The unserved surface has DIFFERENT schemas (its functions take `case_dir`; the served `*In` models did not) and misled both Unit C's audit and the initial LV2 diagnosis. Reconcile: confirm `registry.create_server()` is canonical and remove or clearly-mark `server.py`'s `@server.tool` surface as impl-only (no parallel MCP registration). Mechanical/cleanup. | BATCH-LV1 |
| B-MVP-042 | Backlog | DONE | 2026-06-15 (`a573a3f`, merge `432c2e5` on main): memory-ingest hostname AUTO-DERIVATION implemented + LIVE-PROVEN (Sonnet 4.6). `_derive_hostname_from_image()` in `parse_memory.py` REUSES the existing `run_vol3_plugin` (extended with backward-compat `plugin_args`): PRIMARY vol3 `windows.registry.printkey` ControlSet001→002 / ActiveComputerName→ComputerName (`-r json`, strip REG_SZ quotes), SECONDARY `windows.envars` COMPUTERNAME majority. Wired into `ingest_memory` + server.py `idx_ingest_memory` (derives before subprocess spawn since `--hostname` is required); early hard-guard removed → error is now last-resort after both probes fail; explicit `hostname=` still overrides; `hostname_source` surfaced. 16 new unit tests, 1060 passed. **LIVE on VM**: `opensearch_ingest(format=memory)` with NO hostname auto-derived `SRL-FORGE` (source=registry) → 2186 docs; explicit override bypassed derivation. Spec: `docs/B-MVP-042-memory-hostname-autoderive.md`. Deliberately NOT routed through `host_discovery.py` (dir-walk, no memory source). Minor non-blocking polish noted: subprocess-report `_meta.hostname_source` can read `operator` when server.py pre-derived (agent-facing response is authoritative/correct); redundant `except (RuntimeError, Exception)`; cosmetic double `case-case-` index prefix. | BATCH-LV1 |

## Validation Commands

Run at the end of documentation/planning sessions:

```bash
python3 scripts/validate_docs.py
python3 scripts/validate_migration_docs.py
git diff --check
```

Add targeted code tests for any touched implementation package.
