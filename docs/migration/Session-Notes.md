# Session Notes

Status: sprint log and decision register.
Last updated: 2026-06-12.

Format rules:

- Latest change entry stays at the top of `Current Change Log`.
- Use `Status: DONE`, `Status: IN_PROGRESS`, or `Status: BLOCKED`.
- Keep forks, blockers, and needs-input in the single table below.
- Use IDs beginning with `F-MVP-` for forks and `B-MVP-` for backlog.
- Do not create more migration runbooks.

## Current Change Log

### 2026-06-12 - Gateway startup with DB-seeded native backends

Status: DONE (host patch; operator/agent should pull and rerun installer)

Live rerun on commit `8fe4ea2` confirmed the installer now registers native backend rows with
service-readable venv entrypoints, but the gateway still crash-looped during FastMCP lifespan
startup. The backends did start and list tools; the crash came from the startup assertion calling
the public FastMCP `list_tools()` path without an MCP identity while auth middleware was installed,
so the public catalog could be filtered before the assertion. Logs also showed the intentional
`opensearch_ingest` duplicate between the Gateway-local DB-backed job tool and the add-on proxy; the
Gateway-local tool must own that name in DB-active mode.

Changed: Gateway tool-map construction now skips add-on tools shadowed by Gateway-local tools, so
`opensearch_ingest` remains owned by the Gateway policy/job adapter. The startup assertion now checks
the Gateway's built catalog (`gateway.list_tools()`) instead of invoking the public FastMCP
middleware path without identity, and the expected mounted tool set excludes Gateway-local shadows.

Validation: `bash -n install.sh scripts/setup-addon.sh scripts/setup-supabase.sh` OK;
focused gateway suite OK (`test_phase6.py`, `test_osx1_late_seeded_backends.py`,
`test_f1_opensearch_backend_registry.py`, `test_mvp_binding_job_tools.py`: 61 passed);
`validate_docs.py` and `validate_migration_docs.py` OK; `git diff --check` clean.

### 2026-06-12 - Native backend runtime command fix for system service user

Status: DONE (host patch; operator/agent should pull and rerun installer)

Live rerun on commit `2bdcb35` proved OpenSearch template bootstrap and DB backend registration, but
the system gateway crash-looped after restart. Logs showed the root cause: seeded backend rows used
`/home/sansforensics/.local/bin/uv` as the stdio command, and the `sift-service` system user cannot
traverse the operator home directory. The RAG row also required `RAG_MODEL_NAME` through `env_refs`,
but the service environment does not need that variable because rag-mcp has a built-in allowlisted
default model.

Changed: native installer backend seeding now stores absolute venv entrypoints under
`/opt/sift-mcps/.venv/bin/` (`opensearch-mcp`, `rag-mcp`) as the stdio commands, with no `uv`
dependency at service runtime. The native RAG row now requires only `SIFT_CONTROL_PLANE_DSN`; custom
`RAG_MODEL_NAME` remains an optional add-on/operator configuration path.

Validation: `bash -n install.sh scripts/setup-addon.sh scripts/setup-supabase.sh` OK;
`packages/sift-gateway/tests/test_f1_opensearch_backend_registry.py` and
`test_d22a_mcp_backends_registry.py` OK (19 passed); `validate_docs.py` and
`validate_migration_docs.py` OK; `git diff --check` clean.

### 2026-06-12 - Installer backend seeding and OpenSearch template bootstrap fix

Status: DONE (host patch; operator/agent should pull and rerun installer)

Live installer run on commit `1660b0a` completed successfully through OpenSearch startup, Supabase
operator bootstrap, and handoff generation, proving the bounded health wait fix. The monitored output
exposed two follow-up installer bugs:

- OpenSearch template bootstrap called `opensearch_mcp.client.get_client()` without `OPENSEARCH_CONFIG`,
  so it fell back to `/home/sansforensics/.sift/opensearch.yaml` instead of the service-owned
  `/var/lib/sift/.sift/opensearch.yaml`.
- `seed_addon_backends` passed `actor={"principal_type": "service", "principal_id": "install.sh"}`.
  Registry audit columns expect UUID service identities, so Postgres rejected `"install.sh"` and no
  backend rows were registered even though OpenSearch was healthy.
- Handoff then reported `opensearch_backend_seeded=true` because it was derived from OpenSearch
  availability instead of the actual registration result. Gateway `/health` correctly showed
  `backends={}` and `tools_count=0`.

Changed: OpenSearch template bootstrap now uses a temporary readable copy of the installer-managed
OpenSearch config; install-time backend seeding audits as system/no UUID; `_seed_one_addon_backend`
returns failure on registration errors; and `OPENSEARCH_SEEDED` is set only after opensearch-mcp is
actually registered.

Validation: `bash -n install.sh scripts/setup-addon.sh scripts/setup-supabase.sh` OK;
`packages/sift-gateway/tests/test_f1_opensearch_backend_registry.py` and
`test_d22a_mcp_backends_registry.py` OK (19 passed); `validate_docs.py` and
`validate_migration_docs.py` OK; `git diff --check` clean.

### 2026-06-12 - OpenSearch installer health wait robustness

Status: DONE (host patch; operator should stop the stuck installer, pull, and rerun)

Fresh VM rerun on commit `a1d83b0` completed direct RAG seeding (`4318` pgvector chunks) and then
appeared stuck at `Waiting for OpenSearch health (up to 600 s)`. Live trace showed the service itself
was healthy: `docker inspect sift-opensearch` reported `healthy`, and a fresh
`curl http://127.0.0.1:9200/_cluster/health` returned `status=yellow` immediately. The live installer
process tree showed a child `curl | python3.12` health command still running under the wait loop,
which means a single stuck health request could block the loop indefinitely because the curl had no
request timeout.

Changed: `start_opensearch` now treats OpenSearch HTTP status and Docker health as independent
success signals, uses a bounded curl timeout, logs periodic wait state, and reports both API and
Docker status on timeout. This makes an already-healthy `sift-opensearch` break the wait loop
immediately and lets the installer continue to cluster setup, backend seeding, service restart, and
handoff.

Validation: `bash -n install.sh scripts/setup-addon.sh scripts/setup-supabase.sh` OK; fake
Docker-health smoke proved `start_opensearch` sets `OPENSEARCH_UP=1` when Docker reports
`healthy` even if the API parse path is unavailable; `validate_docs.py` and
`validate_migration_docs.py` OK; `git diff --check` clean.

### 2026-06-12 - Fresh VM installer policy correction: OpenCTI external, direct RAG seed, portal handoff

Status: DONE (host patch; operator should pull and rerun after stopping the stale live installer if it is still active)

Fresh VM trace exposed five policy/UX issues:

- FUSE warning was non-fatal: SIFT/Ubuntu may not have a literal `fuse` group, but
  `/etc/fuse.conf user_allow_other` was enabled and the mount sudoers allowlist was installed.
- `install.sh` still auto-detected and deployed OpenCTI despite the locked add-on decision. Live
  proof showed OpenCTI writing `opencti_*` indices into the native `sift-opensearch` cluster.
- RAG loaded through a Chroma release bundle and then imported into pgvector. That remains a useful
  compatibility path, but the native installer should seed Supabase pgvector directly with the
  allowlisted BGE model.
- The OpenSearch warning text still said 180 s after the timeout was extended to 600 s; live VM
  inspection showed OpenSearch healthy/yellow while the currently running installer was still active.
- The handoff file exposed `examiner=examiner` while the portal form expects Supabase email login.
  The pasted handoff was stale from the previous run and had `supabase_auth=not_bootstrapped`, but
  the installer should still write an explicit `portal_login_email` and retry transient Auth failures.

Changed: native `full` extra no longer installs `opencti-mcp` or `chromadb`; new explicit extras
`opencti` and `chroma-import` keep those paths available. `install.sh` no longer auto-installs
OpenCTI or writes OpenCTI secrets in the native path; `--no-opencti` is accepted only as a no-op
compatibility flag. Optional OpenCTI compose now uses its own `sift-opencti-opensearch` datastore and
`sift-opencti-net`, so it cannot contaminate the forensic OpenSearch cluster. RAG install defaults to
`rag-mcp-seed-pgvector --embedding-mode model`; `SIFT_RAG_IMPORT_SOURCE=chroma` preserves the old
download/import path. Supabase operator bootstrap now retries transient Admin API failures, handoff
writes `expected_supabase_operator_email` and `portal_login_email`, and the frontend honors
`must_reset` by calling `/api/auth/forced-reset`.

Validation: `uv lock` and `uv lock --check` OK; `bash -n install.sh scripts/setup-addon.sh
scripts/setup-supabase.sh` OK; `py_compile` OK for `rag_mcp.pgvector_seed`; targeted RAG seed/import
pytest OK; portal frontend build OK; compose configs render OK for native OpenSearch and optional
OpenCTI stacks; `validate_docs.py` and `validate_migration_docs.py` OK; `git diff --check` clean.
Live recheck after host patch: no installer process remained active; native OpenSearch was
healthy/yellow; the stale handoff still showed `supabase_auth=not_bootstrapped`; old OpenCTI
containers and `opencti_*` indices still existed from the previous native installer behavior.

### 2026-06-12 - Fresh VM install trace: RAG import + backend seeding fixes

Status: DONE (host patch; operator should pull and rerun installer)

Fresh VM install now reaches service provisioning. Live trace showed Supabase healthy, gateway/worker
running as `sift-service`, and `/health status=ok`, but the acceptance surface was incomplete:
`app.mcp_backends` loaded 0 add-on backends, RAG import had 0 chunks, and the installer had timed out
OpenSearch before it later became healthy. Root causes:

- `full` installed `rag-mcp` without the `chroma-import` extra, while `download_index` and
  `rag-mcp-import-chroma-pgvector` require `chromadb` for the Chroma release bundle path.
- `_seed_one_addon_backend` used `local env_refs_json="${4:-{}}"`; Bash parsed the default expression
  so a supplied JSON object gained one extra `}`, exactly matching the live `JSONDecodeError: Extra data`.
- OpenSearch first-start on the VM took longer than the installer's 180 s wait, then later became
  healthy/yellow.
- Supabase CLI had already applied migrations during `supabase start`; the installer reapply path
  printed a scary `fatal:` on duplicate foundational constraints.

Changed: root `pyproject.toml` `full` now depends on `rag-mcp[chroma-import]`; `uv.lock` refreshed;
`install.sh` fixes the Bash JSON default, treats duplicate first migration DDL as a warning, and
extends OpenSearch health wait to 600 s.

Validation: `uv lock` + `uv lock --check` OK; `bash -n install.sh scripts/setup-supabase.sh` OK;
`validate_docs.py` + `validate_migration_docs.py` OK; `git diff --check` clean; shell reproduction
confirmed `_seed_one_addon_backend` env JSON stays length 88 and parses without the extra brace.

### 2026-06-12 - Supabase CLI shim installs `supabase-go` sibling

Status: DONE (host patch; operator should pull and rerun installer)

Fresh VM Supabase bootstrap downloaded the pinned Supabase CLI v2.105.0 tarball and installed only the
`supabase` shim into `/usr/local/bin`; `supabase start` then failed because the shim requires the
co-located `supabase-go` binary. Context7 official Supabase CLI docs confirm the platform package
contains both `supabase` and `supabase-go` in the same `bin/` directory. Patched
`scripts/setup-supabase.sh` to treat them as one package: version detection now requires the sibling
`supabase-go`, and install copies both binaries to the same install directory.

Validation: `bash -n scripts/setup-supabase.sh install.sh` OK; `validate_docs.py` +
`validate_migration_docs.py` OK; `git diff --check` clean.

### 2026-06-12 - Installer apt update resilience for stale third-party repo keys

Status: DONE (host patch; operator should pull/re-clone and rerun installer)

Fresh VM install progressed past clone self-staging and then failed in `install_host_prereqs` while
installing `ripgrep`: `apt-get update` was blocked by an unrelated GitHub CLI apt source with missing
public key `23F3D4EA75716059`. Patched `install.sh` so host package installs warn on `apt-get update`
failure, continue with existing package indexes, and attempt the package install anyway. `acl` remains
required for run_command native-user isolation; `ripgrep` is useful but no longer blocks provisioning
if the third-party apt source prevents installation.

Validation: `bash -n install.sh` OK; `validate_docs.py` + `validate_migration_docs.py` OK;
`git diff --check` clean.

### 2026-06-12 - Installer Docker readiness before Supabase provisioning

Status: DONE (host patch; operator should pull/re-clone and rerun installer)

Fresh VM clone-entry install reached self-staging successfully, then failed when `scripts/setup-supabase.sh`
found Docker installed but the daemon unreachable before local Supabase provisioning. Patched the
installer ordering so `install_host_prereqs` + `ensure_docker_ready_for_supabase` run before OpenCTI
auto-detection and Supabase preflight: local Supabase installs now verify Docker + Compose, attempt
`sudo systemctl start docker` when `docker ps` fails, and stop with an actionable docker-group/login
refresh message if the operator still cannot access the daemon. Patched `scripts/setup-supabase.sh`
directly to attempt the same daemon start before its fatal Docker reachability message.

Validation: `bash -n install.sh scripts/setup-supabase.sh` OK; `validate_docs.py` +
`validate_migration_docs.py` OK; `git diff --check` clean.

### 2026-06-11 - Installer clone-entry self-staging

Status: DONE (host installer UX patch; live proof remains PMI4/OS6)

Patched `install.sh` so the operator can use the normal repo flow:
`git clone https://github.com/xyehya/sift-mcps.git && cd sift-mcps && ./install.sh`. If the script is
run outside `${SIFT_MCPS_INSTALL_ROOT:-/opt/sift-mcps}`, it stages the checkout into that runtime tree
with `.git`, `.venv`, caches, `.mcp.json`, and `node_modules` excluded, then re-execs
`/opt/sift-mcps/install.sh` with the original arguments. This keeps systemd `WorkingDirectory`, Docker
Compose files, backend manifest paths, and venv paths anchored to the hardened runtime tree while
preserving the familiar downloaded-repo install experience.

Changed: `install.sh` (self-stage + re-exec helper, help text); `docs/status.md`,
`docs/migration/task-batches.md`, and this note (VM install flow now clone + `./install.sh` with
self-staging).

Validation: `bash -n install.sh` OK; `validate_docs.py` + `validate_migration_docs.py` OK;
`git diff --check` clean; Bash smoke sourced `install.sh`, staged the checkout into a temp install
root, verified `install.sh`/`pyproject.toml` copied and `.git` excluded, and intercepted the re-exec.

### 2026-06-11 - HARD1 host build: non-admin `sift-service` cutover + shared vol3 symbol cache (decisions locked)

Status: IN_PROGRESS (host code/docs landed in commit `30596a7`; live enforcement proof folds into
PMI4/OS6 on the fresh VM)

Locked the hardening end-state and opened **BATCH-HARD1**. This entry records the landed host-side
build of the non-admin service-user cutover, the shared Volatility symbol cache, and the de-staling
of the install command across the docs. Live proof (run-as-user, warm cache, no-restart catalog) is
pending a fresh VM and folds into PMI4/OS6.

Decisions locked (frozen contract constants — the agreed build end-state):

- **Single dedicated non-admin service user `sift-service`** — system user, `nologin`, home
  `/var/lib/sift`; runs the gateway + worker + all stdio backends. Holds ONLY two narrow sudoers
  grants: `sift-ingest-mount` (mount helpers) and `sift-agent-runtime` (the `agent_runtime` sandbox).
  `sansforensics` keeps its own operator login/sudo; `agent_runtime` stays the run_command sandbox
  user. This replaces running the stack as `sansforensics` with a blanket `NOPASSWD: ALL`.
- **System services** at `/etc/systemd/system/`, `User=sift-service`, managed via `sudo systemctl`
  (NOT `systemctl --user`).
- **Deploy tree relocates to `/opt/sift-mcps`**; operators can use the normal
  `git clone ... && cd sift-mcps && ./install.sh` flow because `install.sh` stages the checkout into
  `/opt/sift-mcps` and re-execs from there before provisioning services.
- **Shared writable vol3 symbol cache** at `/var/cache/sift/volatility-symbols` (group `sift`), env
  override `SIFT_VOL_SYMBOLS`; first run warms it online — no pre-seeding. Drops the read-only
  `/opt/volatility3` chmod hack.
- **`install.sh` is ZERO-ARGUMENT** (single native `--extra full`; OpenCTI external via
  `scripts/setup-addon.sh`; windows-triage removed in NW2). `--no-opencti` is accepted only as a
  no-op compatibility flag; the native operator command is still just `./install.sh`.

Work-streams (4):

- **Group A — shared vol3 symbol cache:** `parse_memory` + worker point at
  `/var/cache/sift/volatility-symbols` via `SIFT_VOL_SYMBOLS`; chmod hack dropped (distributed).
- **Group B — installer/systemd (lead-owned):** create `sift-service`, stage the cloned checkout into
  `/opt/sift-mcps`, narrow sudoers to the two grants, relocate secret env files to
  `sift-service`-readable `0600`, convert units to system services.
- **Group C — this doc work (distributed):** `status.md` + `task-batches.md` + `Session-Notes.md`.
- (3 distributed work-streams + the installer/systemd stream owned by the lead.)

Changed: `docs/status.md` (install command de-staled in Wave Execution Order #2 + BATCH-PMI4 step 1;
VM Quick Reference active tree/install flow → clone + `./install.sh` with self-staging to
`/opt/sift-mcps`, restart via `sudo systemctl`);
`docs/migration/task-batches.md` (PMI4 install command de-staled; new BATCH-HARD1 batch + HARD track);
`docs/migration/Session-Notes.md` (this note).

Security: **`/security-review` PASS** — no high-confidence exploitable issue. Verified line-by-line:
every secret lands `sift-service:sift-service 0600` under `SIFT_HOME` (`0700`); group `sift` is applied
ONLY to the symbol cache, so `agent_runtime` (in `sift`, not `sift-service`) cannot read secrets;
`%h`→absolute `${SIFT_HOME}` is correct for a system service. Noted (not a vuln, DFIR integrity): the
shared writable symbol cache lets an adversarial agent plant a bogus ISF a later trusted `vol3` run
reads — backlog item, not a blocker.

Review fixes (from `/code-review`, recall pass — caught a real HIGH the security review missed):
- **HIGH — shared symbol cache was DOA.** `setup-agent-runtime.sh` stamps a recursive
  `u:agent_runtime:---` deny ACL over all of `/var/lib/sift`, which overrode the `sift`-group grant and
  made the cache unwritable by the `run_command` runtime user. **Fixed: relocated the cache to
  `/var/cache/sift/volatility-symbols`** (outside the deny sweep, FHS-correct) + default `g:sift:rwx` ACL
  for bidirectional writes; added `/var/cache/sift/** rwk` to the AppArmor profile.
- AppArmor `/home/*/.sift/bin/* rix` (hayabusa exec) repointed to `/var/lib/sift/.sift/bin/*` (the
  `/var/lib/sift/** rw` rule grants no exec).
- `setup-opensearch.sh` restart was still `systemctl --user` (no-op post-cutover) → system `sudo systemctl`.
- `reset-vm-test.sh` had a stale `~/.sift/gateway.yaml` path and read/wrote it as the operator → repointed
  to `${SIFT_HOME}` and made the read/write `sudo`+ownership-preserving.

Validation: `validate_docs.py` + `validate_migration_docs.py` OK; `git diff --check` clean;
opensearch-mcp symbol/tier tests 13 pass, sift-core executor/worker/k5 85 pass; `bash -n` OK on
`install.sh`, `reset-vm-test.sh`, `setup-opensearch.sh`.

Next: prove live on the fresh VM as part of PMI4/OS6 — `git clone` → `cd sift-mcps` → `./install.sh`
(self-stages to `/opt/sift-mcps`) →
`status:ok`, `systemctl show sift-gateway -p User` = `sift-service`, `run_command` vol3 warms
`/var/cache/sift/volatility-symbols`, no-restart `opensearch_*` catalog. VM-verify the two flagged
open items: snapshots dir (`uid 1000`, no runtime writer found) and hayabusa reachability under `agent_runtime`.

### 2026-06-11 - NW cleanup Wave 1 (NW1∥NW2∥NW3∥NW4) LANDED on `main`

Status: DONE (four batches built in parallel scope-fenced worktrees, integrated, and fast-forwarded
to `main`; full end-to-end stays BATCH-PMI4/OS6)

Conductor ran NW1∥NW2∥NW3∥NW4 as four parallel workers, one manual worktree per batch off `main`
(`git worktree add ../sift-mcps-nwN main` — NOT Agent isolation:worktree). File-disjoint by design;
all four merged into an integration branch with ZERO conflicts, then fast-forwarded to `main`. Landed
commits, in order:

- `a9602f0` **BATCH-NW1** - `compute_content_hash` consolidated to the single `investigation_store`
  authority (19-key WIDE set, strips `_`-keys); narrow 15-key copies removed from `case_io`/`reporting`/
  `case-dashboard routes`. New test proves all call sites hash identically. Existing-deployment re-hash
  need documented in code; no migration written (fresh DB needs none). Tests: 23 + 84 adjacent.
- `068e5c6` **BATCH-NW4** - RAG hardened knowledge-only (B-MVP-RAG-DERIVED REJECTED). New append-only
  `202606111200_rag_knowledge_only.sql`: `app.rag_search` 6-arg knowledge-only overload, old 9-arg
  revoked from service_role, BEFORE-INSERT triggers block `kind='derived'` at the DB layer.
  `pgvector_store.search`/kb tools drop `case_id`/`include_derived`/`include_knowledge`. Tests: 56.
- `77dfb58` **BATCH-NW2** - `windows-triage-mcp` deleted entirely (32 files); refs purged from
  `pyproject.toml`/`uv.lock`, `install.sh`, `setup-addon.sh`, `sift-common/instructions.py`, gateway
  tests. OpenSearch coupling severed: `triage_remote.py` + `opensearch_enrich_triage` removed;
  `mcp_surface_golden.json` regenerated. Grep-proven no live importers. Tests: opensearch surface 40 +
  gateway phase6/f1 29; `bash -n` clean.
- `a200f66` **BATCH-NW3** - new `docs/backend-contract.md` (manifest schema incl OSX2 advanced-tool-use
  fields + authority_contract; seed/mount/late-seed lifecycle; worked add-on example). Docs-only.
- `c32a291` **conductor follow-up** - dropped the stale `wintriage_check_artifact` hint from sift-core
  `execute/response.py` `_RELATED_TOOLS` (NW2 flagged it; outside both NW1/NW2 fences).

Integrated sweep on the merged tree (root `.venv`): NW1 23 + NW4 56 + opensearch 40 + gateway 29 +
execute 47 all pass; `validate_docs.py` + `validate_migration_docs.py` OK; `bash -n install.sh
setup-addon.sh` clean; `git diff --check` clean; `uv lock --check` resolved 222 pkgs (lock coherent).

Carry-forward: NW2 left two intentional/cosmetic windows-triage strings — `case_ops.py:349` docstring
(`"No-op: windows-triage support has been dropped."`, correct as-is) and `forensic-knowledge/data/*.yaml`
reference data (out of scope; non-functional cross-refs). NW4's old 9-arg `app.rag_search` is revoked
but not dropped (append-only) — future cleanup migration may DROP it once callers confirmed migrated.

Validation: `validate_docs.py` + `validate_migration_docs.py` OK; `git diff --check` clean.

**Next:** push `main`, then Wave 2 = bare-SIFT `./install.sh` (PMI4/OS6, operator-run, the
only end-to-end gate), then Wave 3 = NW6 (PTC) validated post-install.

### 2026-06-10 - OSX wave merged to `main`; NW track opened (operator decisions)

Status: DONE (docs/planning; merge to main; NW build wave handed off)

- **Merged the OSX wave into `main`** by clean fast-forward (`origin/main` dd7214d was a strict
  ancestor of `revamp/spg-v1`; 0 commits lost, 239 ahead). `main` is now the integration trunk; the
  fresh VM install clones `main`.
- **Operator decisions recorded** (resolving the OSX backlog):
  - **B-MVP-RAG-DERIVED -> REJECTED.** No per-case RAG — keep case-sensitive derived text OUT of the
    vector store. Becomes **NW4** (harden RAG to knowledge-only; remove the dormant `derived` branch).
  - **B-MVP-HASH-CONSOLIDATION -> NW1** (operator priority #1; fix now, fresh install is the test bed).
  - **B-MVP-WINTRIAGE-SCRIPTS -> NW2** (remove ALL of windows-triage-mcp; future need served by a fresh
    add-on plugging via the Backend Contract, which **NW3** documents as the hackathon modularity story).
  - **OSX3 reframed -> NW6.** Operator correction: PTC executes CLIENT-SIDE in the agent harness (not
    on the VM), tools fire as normal callbacks, only the code's final stdout enters context. The
    "evidence leaves the VM" worry is moot — the Gateway already sanitizes every result (proven live
    this session: `case_info` returned `case_dir: "[REDACTED:absolute_path]"`). NW6 = enable PTC on the
    heavy read-only tools + validate live with the native harness; the on-VM sandbox is a FALLBACK only.
  - **opensearch run_command duplicate check -> NW5 RESOLVED, no action:** opensearch-mcp exposes NO
    run_command/execute/shell tool (16 tools = search/ingest/enrich/status); no duplicate of the
    sift-core run_command worker.
- **Grounding for NW2 scope:** windows-triage is COUPLED into opensearch-mcp via `triage_remote.py` +
  the `opensearch_enrich_triage` tool (plus refs in `sift-common/instructions.py`, gateway tests,
  pyproject, install.sh) — NW2 must decouple that path, not just delete the package.
- NW track (operating model, wave order, parallelization, per-batch paste-ready prompts) is in
  `task-batches.md` "Next Conductor Wave (NW) Track". Wave: NW1∥NW2∥NW3∥NW4 (cleanup) -> fresh VM
  install + PMI4/OS6 -> NW6 (PTC) validated post-install.

Validation: `validate_docs.py` + `validate_migration_docs.py` OK; `git diff --check` clean.

Next: operator pushes `main` (enables the VM clone), then runs the NW cleanup wave and the fresh
install. Next: run NW1∥NW2∥NW3∥NW4, then bare-SIFT `./install.sh` (PMI4/OS6), then NW6.

### 2026-06-10 - OSX build wave LANDED (OSX1 + OSX-RAG + OSX-PURGE + OSX2 + OSX3 + PMI3)

Status: DONE (six batches landed on `revamp/spg-v1`; NOT pushed; full end-to-end stays BATCH-PMI4/OS6)

Orchestrated build wave (conductor + scope-fenced agent teammates in manual worktrees off
`revamp/spg-v1` — NOT Agent isolation:worktree). Each batch: one commit, targeted tests, conductor
review + independent re-run. Landed commits, in order:

- `e3d7414` **BATCH-OSX1** - OpenSearch backend mounting fix (P1) + double-spawn dedupe. Race fixed
  TWO ways: (a) install.sh reordered so `seed_addon_backends` runs BEFORE `install_systemd_service`
  (gateway's first `__init__` registry read already includes opensearch-mcp; removed the FM-1
  post-seed restart workaround); (b) new `Gateway.reload_backend_registry()` called by
  `_late_start_checker` every 30s re-reads `app.mcp_backends` and mounts late-seeded backends live
  (no restart). Double-spawn confirmed real and deduped: factored `mount_single_addon_proxy()` +
  `_mounted_proxy_backends` set; `_late_start_checker` skips eager `StdioMCPBackend.start()` for
  proxy-served backends. Tests: 25 targeted; full gateway 450 pass.
- `8940a32` **BATCH-OSX-RAG** - forensic-rag-mcp tools ported to pgvector at parity; `rag_search_case`
  shim removed. Restored `kb_search_knowledge` (query, top_k≤50, source, source_ids≤20-precedence,
  technique, platform-enum), `kb_list_knowledge_sources`, `kb_get_knowledge_stats` backed by
  `PgVectorRagStore`; BGE query embed moved gateway->`rag_mcp/query_embedding.py`. Deleted
  `sift-gateway/rag_bridge.py` + `_register_rag_tool` + `PgVectorRagQueryService` +
  `_CORE_TOOL_CATEGORIES`/`_gateway_local_tools` entries. NEW append-only migration
  `202606101100_rag_search_filters.sql` extends `app.rag_search` with
  `p_source/p_source_ids/p_technique/p_platform` (defaulted -> backward-safe). forensic-rag re-registered
  as a backend (install.sh seed + setup-addon.sh). `chromadb`->optional `[chroma-import]` extra;
  `sentence-transformers` stays required. Tests: 55 forensic-rag + full gateway 450 (the 3 PMI2-era
  manifest failures now GREEN).
- `978bdb8` **BATCH-OSX-PURGE** - deleted dead `packages/forensic-mcp/` (whole pkg; in
  `_RETIRED_CORE_BACKENDS`, zero importers; guard kept) + its 2 root-pyproject refs; deleted 7 dead
  Chroma index modules in forensic-rag-mcp (`index/build/status/analyze_queries/tuning_config/fs_safety` +
  `scripts/build_release.py`). KEPT `refresh.py`+`sources.py` (reachable from live
  `scripts/download_index.py`, invoked by install.sh:411) and curated `tool_metadata.py`. Conservative;
  grep proofs in commit. Tests: 55 + 450 green.
- `38e1f65` **BATCH-OSX2** - raised all 16 OpenSearch tools to the advanced-tool-use bar
  (when_to_use/avoid_when, output_shape, response_shaping, usage_examples, defer_loading candidacy)
  in registry + `sift-backend.json`; regenerated golden snapshot (additive meta only). Behavior
  unchanged. Tests: 108 opensearch-mcp.
- `ef6e229` **BATCH-PMI3** - wired `FK_DATA_DIR=$SIFT_ENRICHMENT_DIR/forensic-knowledge` via new
  install.sh `write_fk_env()` + `EnvironmentFile=` in both systemd units, so FK enrichment fires
  under the service user (loader resolution step #1 honors the env var). Tests: 34 FK loader.
- `aaa244b` **BATCH-OSX2 integration (conductor)** - extended the gateway backend-manifest schema
  (`sift-backend.schema.json`) to permit OSX2's 5 new tool fields. Caught by the INTEGRATED sweep:
  each batch passed in isolation, but OSX2's new manifest + the gateway's `additionalProperties:false`
  validator failed `test_phase6` only in the combined tree. "No silent format change" — manifest
  structure + schema contract landed together. Full gateway suite back to 450/0.
- **BATCH-OSX3** (doc-first spike; no code commit) - feasibility verdict below.

Integration testing note (why the wave needed a conductor sweep): OSX2 (opensearch manifest) and the
gateway schema are in different scope fences, so the schema-vs-manifest mismatch only surfaced when
all branches were combined on `revamp/spg-v1`. Per-batch suites were green; the integrated sweep was
the gate that caught it. Landing strategy: ff the linear OSX1->OSX-RAG->OSX-PURGE stack, cherry-pick
OSX2 + PMI3 (proven conflict-free via `git merge-tree`), then the conductor schema fix.

Forks resolved this wave:

- **F-MVP-OS-WIRING** RESOLVED -> implemented as P1 (OSX1: race fix both ways + double-spawn dedupe;
  stdio add-on kept). P2/P3 remain future options, not taken.
- **F-MVP-RAG-PORT** RESOLVED -> implemented (OSX-RAG: kb_ tools on pgvector at parity;
  `rag_search_case` removed). SUPERSEDES BATCH-PMI2's "single-home = rag_search_case" (PMI2 entry kept
  as history; index relabelled superseded).
- **F-MVP-RAG-DERIVED** RESOLVED -> SAFE to drop. Probe proved case-derived RAG chunks are NEVER
  written today (importers hardcode `kind="knowledge", case_id=None`; zero `kind="derived"` writers),
  so `rag_search_case`'s case-scoping was a dormant no-op. Schema's `derived` branch kept dormant
  (zero-cost). -> B-MVP-RAG-DERIVED.

Backlog opened:

- **B-MVP-RAG-DERIVED** (OPEN): a future case-derived RAG ingest would re-light the dormant `derived`
  branch in `app.rag_search` (kb_search_knowledge re-enabling `include_derived` under an active case).
  No schema change needed; only a writer + a case-scoped query path. Source: OSX-RAG / F-MVP-RAG-DERIVED.
- **B-MVP-HASH-CONSOLIDATION** (OPEN): `compute_content_hash` has 2 diverging shapes across 5 sites.
  Authority = `investigation_store.compute_content_hash` (19-key wide set + strips `_`-prefixed keys).
  Narrow copies (`case_io.HASH_EXCLUDE_KEYS`, `reporting._HASH_EXCLUDE_KEYS`,
  `case-dashboard/routes._HASH_EXCLUDE_KEYS`) omit `provenance_detail/chain/grade/gaps` and don't strip
  `_`-prefixed keys -> can produce a different content_hash for the same item. Behavior-touching (gate
  with a migration/re-hash plan); deferred out of the OSX-PURGE deletion pass. Source: OSX-PURGE.
- **B-MVP-WINTRIAGE-SCRIPTS** (OPEN): `packages/windows-triage-mcp/scripts/*` (10 files) import a
  non-existent `windows_triage_mcp_mcp` module (double find/replace bug); broken, not wired to any
  live path (install.sh uses `src/windows_triage_mcp/scripts/download_databases.py`). Add-on/non-MVP
  corpus-regeneration provenance. Decide: fix the token + keep, or delete. Kept untouched (conservative).
  Source: OSX-PURGE.

BATCH-OSX3 feasibility verdict (programmatic tool-calling / code-execution-with-MCP): **needs harness
work.** API-level Programmatic Tool Calling (`allowed_callers:["code_execution_20250825"]`) + Tool
Search (`defer_loading`) are OUT of this tree — no Anthropic Messages-API loop lives here (the repo is
the server/tool side; the agent reaches tools via the Gateway aggregate `/mcp`), and PTC would run
model code in Anthropic's sandbox so large OpenSearch results would transit OFF the VM (poor fit for
"evidence bytes never leave the VM"). The right fit is the on-VM "MCP-as-code-APIs in a sandbox"
pattern, but the existing `run_command` stack is the WRONG executor to reuse: interpreters
(python/perl/ruby/node/bash) are deny-floored and there is no network/egress jail. Recommended path
(smallest secure footprint): a NEW Gateway tool `opensearch_query_code` running model-written Python in
a dedicated, network-jailed (no-egress; OpenSearch reachable only via a parent bridge), restricted
interpreter that can ONLY import a frozen `os_api` shim over the existing read-only OS tools — reusing
sift-core's env-scrub (`build_sandbox_env`), RLIMITs, `sanitize_paths_deep`, and `AuditWriter` belts,
plus a NEW OS sandbox (nsjail/bubblewrap+seccomp — absent today). Only `emit()`ed, byte-budgeted output
returns (the article's 150k->2k ≈ 98.7% saving, on-VM). Outlined as follow-on **OSX4** (new
`sift-core/execute/code_runner.py` + `os_api` shim + one gateway tool; escape-test battery; live VM
smoke deferred to PMI4/OS6). API-level PTC/defer_loading recorded as a separate harness/posture fork
for the operator (where the agent's Messages-API loop runs).

Validation (targeted-per-batch + a conductor INTEGRATED sweep on the landed tree):

- gateway full **450 passed/0**; opensearch-mcp surface+server+tools **100+**; forensic-rag-mcp **55**;
  forensic-knowledge loader **34**. `bash -n install.sh` + `setup-addon.sh`: OK. `git merge-tree`
  pre-checks: all branch pairs conflict-free.

Next:

- **BATCH-PMI4 / OS6** is the ONLY remaining gate: operator-run VM proof. On the bare SIFT VM,
  `./install.sh`; confirm `status:ok`, aggregate `/mcp` lists `opensearch_*` + the forensic-rag
  `kb_*` tools WITHOUT a restart (OSX1 race fix), `app.rag_chunks` is populated from the direct
  model-backed bundled-knowledge seed, Hayabusa detections queryable; then the Rocba case
  end-to-end. Push / PR to integrate this wave awaits operator go-ahead.

### 2026-06-10 - OSX track planned (OpenSearch excellence + RAG-port + purge); architecture discovery; hygiene

Status: DONE (planning/docs/hygiene; builds handed off)

This was a plan + code-discovery + hygiene session (Plan != Build). It opened the OSX track in
`task-batches.md` (OSX1, OSX2, OSX-RAG, OSX3, OSX-PURGE) with paste-ready prompts and an
orchestration wave, injected the verified architecture below, and did safe hygiene. No production
behavior changed.

Architecture discovered + verified (full landmarks in `task-batches.md` "Discovered architecture"):

- **OpenSearch today = stdio add-on branded core, NOT worker-run.** Seeded into `app.mcp_backends`
  (`transport=stdio`) by `install.sh seed_addon_backends`; the GATEWAY (`Gateway.__init__` ->
  `create_backend_instances` -> `StdioMCPBackend.start`) spawns + proxies it; the job worker only
  runs `opensearch_mcp.job_ingest` as a library for durable ingest jobs. The "no tools until
  restart" symptom is a seed-after-`__init__` race: `_late_start_checker` never re-reads the DB.
  Plus a likely double stdio spawn (backend instance + proxy).
- **Worker provides** a durable Postgres job plane (`JobWorker` claim/lease/heartbeat loop) with two
  handlers: `run_command` (sift-core sandboxed exec) and `ingest` (opensearch library). It does not
  host the MCP surface — the gateway does.
- **RAG: `rag_search_case` is a migration-era duplicate, not the spec.** Pre-migration
  (`/home/yk/AI/SIFTHACK/sift-mcp/.../rag_mcp/server.py`) forensic-rag registered its OWN tools with
  `source/technique/platform` filters; `rag_search_case` did not exist. BATCH-G1 built a thinner
  gateway pgvector tool instead of porting; PMI2 then deleted the forensic-rag tools. **Vector
  parity is intact** (importer copies the original BGE 768-d vectors 1:1 from the big Chroma bundle,
  model-guarded; runtime query uses the same BGE model). Decision: keep pgvector, restore the tool
  surface on it, remove the shim. `sentence-transformers` is a required runtime dep (query embed);
  only `chromadb` is import-only.
- **Structure audit:** the hub-and-spoke architecture is sound but carries consolidation debt:
  `forensic-mcp/` is a fully dead package (`_RETIRED_CORE_BACKENDS`); forensic-rag-mcp ships dead
  Chroma index modules + ~500MB optional-able deps; `windows-triage-mcp/scripts/*` import a
  non-existent `windows_triage_mcp_mcp` module; `compute_content_hash` has 3 diverging copies.

Decisions / forks (recorded in `task-batches.md` "OSX forks"):

- F-MVP-OS-WIRING -> **P1** (fix race + dedupe spawn; keep stdio). P2/P3 deferred.
- F-MVP-RAG-PORT -> **port forensic-rag-mcp tools to pgvector at parity + remove rag_search_case**.
  This SUPERSEDES the BATCH-PMI2 "single-home = rag_search_case" decision (append-only; PMI2 entry
  below stays as history, its decision relabelled superseded in the Batch Index).
- F-MVP-RAG-DERIVED (OPEN) -> resolve in OSX-RAG whether case-derived rag chunks are used before
  dropping that path with the shim.

Hygiene done this session (committed with the plan):

- Removed `scripts/test_mcp.py` (git-tracked probe with a HARDCODED bearer token
  `sift_svc_b5152…`). The token must be ROTATED separately (deletion does not invalidate it).
- Added `.understand-anything/` to `.gitignore`.
- (Earlier this session) crashed-team worktree debris already cleaned; tree is clean.

Validation:

- `python3 scripts/validate_docs.py`: OK. `python3 scripts/validate_migration_docs.py`: OK.
- `git diff --check`: clean. No code/behavior changed; doc + hygiene only.

Next:

- Build sessions, in wave order: **OSX1** then **OSX-RAG** (serial — shared gateway+install fence);
  **OSX2 ∥ OSX3 ∥ PMI3** in parallel (file-disjoint); **OSX-PURGE** after OSX-RAG+OSX2; **PMI4/OS6**
  VM proof last. Paste-ready prompts + the orchestration wave are in `task-batches.md` "OSX Track".
  Reminder: do NOT use Agent `isolation:worktree` here (branches off stale `origin/main`); create
  worktrees manually off `revamp/spg-v1`.

### 2026-06-10 - BATCH-PMI1 + BATCH-PMI2 landed (OS 3.5 cutover ∥ RAG single-home); crashed-team recovery

Status: DONE

Recovery context (a prior agent-teams run crashed mid-flight ~12:47-12:52):

- The crash left the main worktree's index clobbered with stale `agentir`-era blobs
  (a `sift-*`->`agentir-*` "revert" of the two OpenSearch composes + a 1294-line
  `install.sh` shrink that dropped the PMI0 hardening). Root cause: the PMI1 agent's
  isolated worktree had branched off `origin/HEAD` = `origin/main` (`dd7214d`, May 30),
  which predates the entire sift-branding migration — NOT off `revamp/spg-v1` (`9a031db`).
  Restored the main worktree to clean `9a031db`; verified the good hardened `install.sh`
  (2388 lines, 10x `setup-supabase`) is intact.
- The PMI2 agent's worktree HAD branched off the correct base (`9a031db`) and produced a
  clean, scope-correct diff — salvaged it as-is (patch in `.crash-recovery/`).
- Re-running PMI1 via the worktree-isolation path reproduced the wrong-base bug, so PMI1
  was redone inline in the main worktree (file-disjoint from PMI2). All four crash
  worktrees/branches removed.

Changed (BATCH-PMI1 - OpenSearch 2.18->3.5 cutover, security-disabled/loopback posture):

- `docker-compose.yml` (root, the one `install.sh` uses): image `2.18.0` -> `3.5.0`,
  heap `-Xms3g/-Xmx3g` -> `-Xms4g/-Xmx4g`. KEPT `DISABLE_SECURITY_PLUGIN=true`, loopback
  `127.0.0.1:9200`, snapshot mount, `thread_pool.search.queue_size=5000`, sift branding.
- `packages/opensearch-mcp/docker/docker-compose.yml`: reconciled to the SAME posture -
  dropped `OPENSEARCH_INITIAL_ADMIN_PASSWORD`, added `DISABLE_SECURITY_PLUGIN=true`
  (it had been the only "security-enabled 3.5" artifact, contradicting the root compose).
- `install.sh`: added `configure_opensearch_detections()` (http, NO auth - server security
  is disabled, :9200 is loopback) ported from the package setup script's Phase-4 block -
  keeps Sigma detectors DISABLED (3.5 percolator field-alias regression
  opensearch-project/security-analytics#755 -> 0 findings; detection is Hayabusa during
  evtx ingest), deletes dead `sift-` detectors + orphaned monitors, seeds the
  `sift-sigma-{windows,linux,web,network}` aliases. Wired into `main()` right after
  `install_opensearch_templates` (so alias templates exist), gated on `OPENSEARCH_UP`,
  best-effort (never fails the install). `client.py` unchanged: its http + dummy
  admin/admin config already works against a security-disabled server.
- `packages/opensearch-mcp/scripts/setup-opensearch.sh`: reconciled this standalone helper
  from `https`+`admin:$OS_PASSWORD` to plain `http`/no-auth (it was writing an `https`
  `opensearch.yaml` that would have broken the client against a disabled-security server);
  all detector/geoip/alias LOGIC preserved.

Changed (BATCH-PMI2 - RAG single-home, salvaged from the crashed run):

- Removed the three Chroma-backed agent-facing tools (`kb_search_knowledge`,
  `kb_list_knowledge_sources`, `kb_get_knowledge_stats`) from `forensic-rag-mcp`:
  `sift-backend.json` (now `provides:[]`, `tools:[]`, v2.0.0, retained only for the
  import/seed CLI), `src/rag_mcp/{__init__.py,server.py,tool_metadata.py}` (server kept as
  a zero-tool harness; `pgvector_store` + Chroma->pgvector importers kept). Removed
  `setup_rag` from `scripts/setup-addon.sh` and renumbered the add-on menu. Net: pgvector
  (`rag_search_case`, gateway core - untouched) is the only agent-facing RAG; Chroma
  survives only as an internal import source.

Fork resolved (operator decision this session):

- F-MVP-OS35-SEC: OpenSearch 3.5 security posture. RESOLVED -> keep
  `DISABLE_SECURITY_PLUGIN=true` with `:9200` bound to loopback as the boundary (plain
  http, no TLS/admin password). Smallest consistent diff for the bare-VM one-session
  install; the whole `install.sh` curl/config path stays unchanged. Supersedes the
  `CLAUDE.md` component-table note "keep security enabled" for the MVP -> B-MVP-OS35-SEC.
- B-MVP-OS35-SEC (backlog): post-MVP, evaluate enabling the 3.5 security plugin
  (TLS + admin password + https client). Deferred; out of scope for the one-session install.

Validation (targeted only, per PMI operating model; full end-to-end stays BATCH-PMI4):

- `opensearch-mcp`: `1025 passed, 73 skipped` (skips = live-cluster tests), incl.
  `test_phase4_config` which asserts the package compose + setup-script structure.
- `forensic-rag-mcp`: `27 passed` (all pgvector; no test referenced the removed tools).
- `bash -n install.sh` + `bash -n setup-opensearch.sh`: clean. Both composes parse as YAML.
  `install.sh` embedded detections Python compiles (93 lines).

Next:

- BATCH-PMI3 (FK enrichment fires - wire `FK_DATA_DIR`): touches `install.sh` env region +
  the two systemd units; verify-only in `forensic_knowledge/loader.py` and
  `sift_core/execute/response.py`. Then BATCH-PMI4 (VM proof: bare-SIFT -> live stack ->
  Rocba run) - the only full end-to-end gate. Paste-ready prompts in `task-batches.md`.

### 2026-06-10 - BATCH-PMI0 landed; PMI track opened (bare-SIFT one-session install)

Status: DONE

Changed:

- Audited `install.sh` for a BARE SIFT VM (3 parallel audits): found it does not stand
  up Supabase, does not apply migrations, silently degrades, OpenCTI auto-enable overrides
  opt-out, opensearch seed needs a gateway restart + missing gateway env. All addressed.
- BATCH-PMI0 (commit `1742172`): installer hardening + a Supabase CLI provisioner.
  `install.sh` now honors `--no-opencti`/`--no-windows-triage`/`--no-rag`/`--external-supabase`,
  preflights+auto-runs Supabase, applies `supabase/migrations/*.sql` via psycopg, writes the
  opensearch gateway env + restarts the gateway after seeding, enables linger, and hardens
  `poll_gateway` (status:ok). `scripts/setup-supabase.sh` uses the official Supabase CLI
  v2.105.0 (lean db+auth+kong; storage/realtime/studio/analytics/edge/inbucket disabled;
  `jwt_expiry=172800`) with `--network-id` loopback isolation (all containers on one network),
  writing the `sift-supabase.env` contract install.sh consumes. `bash -n` clean; live-VM
  proof deferred to BATCH-PMI4.
- Decisions locked: OpenSearch -> 3.5 (Hayabusa detection; Sigma stays disabled); RAG
  single-home = pgvector (`rag_search_case`), delete the redundant standalone Chroma
  `kb_search_*`; `forensic-knowledge` FK-enrichment is core context-injection to KEEP
  (just unwired — FK_DATA_DIR unset); Hayabusa is already wired end-to-end.
- Opened the PMI track with a LEAN operating model (targeted tests only per batch; one full
  end-to-end gate at BATCH-PMI4) and ready-to-paste prompts for PMI1 (OS 3.5 cutover) ∥ PMI2
  (RAG single-home), then PMI3 (FK_DATA_DIR), then PMI4 (VM proof + Rocba run).

Validation:

- `python3 scripts/validate_docs.py`: OK. `python3 scripts/validate_migration_docs.py`: OK.
- Current one-session install command: `./install.sh`.

### 2026-06-10 - BATCH-OS5 landed (host identity + enrichment + mutating-tool policy)

Status: DONE

Changed:

- OS5 ran solo in worktree `revamp/os5-host-enrichment-policy` off `revamp/spg-v1`;
  landed as merge `ba781c5` plus follow-up `ade8442`.
- server.py: fail-closed receipt gate in `_case_host_fix_impl` (DB-active + no recorder
  -> deny before any mutation; receipt records source/canonical/actor/tool/affected-IDs/
  audit-ID; no `host-dictionary.yaml` path leak). Scope gate + audit + poll guidance for
  `opensearch_enrich_intel`; scope gate + prohibited_operations for `opensearch_enrich_triage`.
- sift-backend.json: `required_scopes`, `scope_enforcement`, `enrichment_policy`,
  `prohibited_operations`, `secret_leak_guarantee` on the enrich tools; `receipt_policy` +
  `prohibited_operations` on `opensearch_fix_host_mapping`. OS2 `safe_case_argument_names`
  and OS3 read-only surface fields preserved. `opensearch_fix_host_mapping` stays canonical;
  `opensearch_host_fix` remains the deprecated alias.

Consolidation fixes (orchestrator):

- `ade8442` (gateway schema): OS5 added manifest fields but did not extend the Gateway
  backend manifest contract schema (`sift-backend.schema.json`), so `validate_manifest_contract`
  rejected the manifest and broke two `test_phase6` manifest tests. Added the fields additively
  (same coupled manifest+schema update OS2 did) — caught only by running the FULL gateway suite
  at consolidation, not OS5's targeted subset.
- psycopg test hardening: a deep investigation of a "1 failed" in the OS5 worktree traced to
  psycopg being an OPTIONAL/transitive opensearch-mcp dependency that is simply NOT installed in
  a fresh worktree's uv env. The opensearch-mcp package intentionally lazy-guards psycopg.
  Fix: guard the psycopg-provenance test (test_job_ingest) and the degrade test (test_k4) with
  `pytest.importorskip("psycopg")` / patch-on-real-module so they SKIP (not fail) where psycopg
  is absent. Not a production bug.

Validation (on main `revamp/spg-v1`, psycopg present in root `.venv`):

- opensearch-mcp suite: 1027 passed, 71 skipped, 0 failed.
- gateway suite: 447 passed, 0 failed.
- `python3 scripts/validate_docs.py`: OK. `python3 scripts/validate_migration_docs.py`: OK.

Next:

- OS6 (live VM OpenSearch proof) is the only remaining batch. Requires the live VM.

### 2026-06-10 - BATCH-OS3 + BATCH-OS4 landed (read-only surface verified; job-backed ingest)

Status: DONE

Changed:

- OS3 and OS4 ran in parallel in worktrees off `revamp/spg-v1`; OS4 landed as merge `cff7378`
  + follow-up `aae168b`.
- OS3 - read-only surface: NO code change required. Verified manifest <-> registry <-> golden
  <-> aggregate Gateway catalog already agree. The 16-tool manifest vs 17-tool golden delta is
  intentional (the 17th is the deprecated `opensearch_host_fix` alias generated at registration).
  Confirmed all 10 read-only investigator tools advertise with concrete (non-placeholder) schemas.
  RESOLVED the OS2 carry-in: `opensearch_get_event/status/shard_status/list_detections` have NO
  `case_id` parameter in their real Pydantic models, so OS2's `safe_case_argument_names: []`
  (pass-through, no injection) is correct as-is. Tests: surface snapshot + server tools 50 passed;
  full opensearch-mcp suite 1015 passed / 71 skipped.
- OS4 - job-backed ingest: the worker/provenance machinery (`make_ingest_job_handler` +
  `psycopg_provenance_recorder`, `job_worker_cli`) was already correctly wired, so OS4 added the
  missing Gateway policy boundary in `job_tools.py`: a Gateway-local `opensearch_ingest` shadow
  registered only when `job_service` is wired (DB-active mode). `dry_run=False` -> typed denial
  `opensearch_ingest_direct_write_denied` with redirect to `ingest_job`; `dry_run=True` -> survey
  validated against sealed evidence, path-free response (relative display_path only). +13 tests.
- OS4 follow-up (`aae168b`): updated `test_phase6::test_gateway_core_has_no_hardcoded_addon_names`
  to exempt OpenSearch. DECISION (operator): OpenSearch is a first-party/core capability, so the
  gateway core may reference it by name; the add-on-agnostic invariant disciplines only EXTERNAL
  add-ons (OpenCTI, windows-triage, forensic-rag/KB), which remain forbidden and still enforced.

Validation:

- Full gateway suite on landed `revamp/spg-v1`: 447 passed.
- `python3 scripts/validate_docs.py`: OK. `python3 scripts/validate_migration_docs.py`: OK.

### 2026-06-10 - BATCH-OS1 + BATCH-OS2 landed (OpenSearch catalog + active-case proxy)

Status: DONE

Changed:

- OS1 and OS2 ran in parallel in dedicated worktrees off `revamp/spg-v1`, integrated OS1-first
  and landed on `revamp/spg-v1` as merge `ce3748e`.
- OS1 - DB backend seed: `install.sh` gains `seed_addon_backends()`, an idempotent upsert of
  `opensearch-mcp` into `app.mcp_backends` gated on `SIFT_OPENSEARCH_ENABLED=true` + control-plane
  DSN present. Stores env-ref metadata only, never raw secrets. Corrected stale manifest `requires`
  URL to `http://localhost:9200`. `test_f1_opensearch_backend_registry.py` grew 3->11 tests.
- OS2 - active-case proxy: manifest-declared `safe_case_argument_names` per tool replaces
  placeholder-schema detection. `Gateway.safe_case_argument_names()` now returns `set|None` with a
  tri-state honored at BOTH enforcement paths: `None`=unknown->deny fail-closed, `set()`=no-injection->
  pass through, non-empty->inject DB active case. Explicit mismatched `case_id` still denied
  pre-dispatch. `sift-backend.schema.json` updated.

Validation:

- Integrated branch: gateway suite `439 passed`; opensearch-mcp suite `1015 passed, 71 skipped`;
  targeted OS1+OS2 set `107 passed`.
- `python3 scripts/validate_docs.py`: OK. `python3 scripts/validate_migration_docs.py`: OK.

### 2026-06-10 - OpenSearch standalone restoration track reopened

Status: DONE

Changed:

- Reopened OpenSearch as a critical autonomy track because the live aggregate MCP catalog was last
  recorded with 13 Gateway tools and no `opensearch_*`, while the standalone package still owns
  the richer search/ingest/enrichment surface.
- Kept the operating model trimmed: `docs/migration` is this log plus `task-batches.md`.
- Added BATCH-OS0..OS6 to `task-batches.md`. Locked the main decisions.
- Prioritized restore order: DB backend visibility and active-case proxy first, read-only search
  surface next, job-backed ingest and mutating policy after, live VM proof last.

Validation:

- `python3 scripts/validate_docs.py`: OK.
- `python3 scripts/validate_migration_docs.py`: OK.
- `git diff --check`: clean.

### 2026-06-10 - BATCH-FRZ1 portal principal UX + MCP schema compatibility

Status: IN_PROGRESS

FRZ1 conductor pass landed the portal principal/session table cleanup and fixed
a client-breaking MCP schema issue found during Codex tool-surface validation.
The Settings page now uses the post-migration Supabase JWT principal surface only
for normal operation: token type, display name, active/expired/revoked status,
TTL remaining, scopes, and last issued expiry are shown in the principal table;
the revoke button is disabled/dimmed after local success or for already-revoked
rows. Legacy PR02 token create/rotate/reactivate controls were removed from the
normal Settings page so operators do not see two competing token-management
surfaces. Backend listing remains secret-safe: raw access/refresh tokens are
still returned only at issuance time and are stripped from principal roster
responses; non-secret last-issued expiry/fingerprint metadata is persisted on
the app principal rows for TTL display.

Live deploy/smoke: synced the repo to the active VM service tree
`/home/sansforensics/sift-mcps-test`, restarted `sift-gateway.service` and
`sift-job-worker.service`, retried the known startup-race health check, and got
Gateway health `status=ok`, Supabase OK, evidence root `/cases` OK. A fresh
portal-issued agent principal returned `token_ttl_seconds=172800`; MCP
initialize and `tools/list` returned HTTP 200 with 13 tools including
`rag_search_case` and `run_command_job`.

RAG/schema fix: `rag_search_case_schema()` no longer emits top-level `anyOf`.
The schema is a plain JSON object with optional `query` and `query_embedding`;
runtime validation now returns `query_or_query_embedding_required` when neither
is supplied and still rejects non-768-dimensional embeddings. This fixed the
Codex/client tool-registration failure (`invalid_function_parameters` on
top-level `anyOf`) while preserving the live Gateway contract. Live MCP proof:
`tools/list` showed `rag_search_case` schema type `object`,
`composition_keys=[]`, and props `include_derived`, `include_knowledge`,
`query`, `query_embedding`, `top_k`; a direct `rag_search_case` call returned
HTTP 200 with `status=ok` and two result rows.

Installer hardening source changes landed but were not destructively replayed on
a throwaway VM in this truncated session: `install.sh` now installs missing host
prereqs (`ripgrep`, `acl`), repairs the system `pyewf` binding inside the venv
after `uv sync`, renders/enables/restarts both Gateway and job-worker user unit
files, invokes both runtime sudoers and ingest mount sudoers helpers, and uninstalls
both unit files. The sudoers helper defaults no longer hard-code
`sansforensics`; they default to `SIFT_GATEWAY_SERVICE_USER` or the invoking
user. Remaining service-identity caveat: the prepared demo VM still runs the
user services as `sansforensics`; true least-privilege enforcement still needs a
dedicated non-admin service-user cutover/proof on a throwaway VM or planned VM
rebuild.

Validation run before handoff: `bash -n install.sh scripts/setup-agent-runtime.sh
scripts/setup-ingest-mount-sudoers.sh`; `pytest
packages/sift-gateway/tests/test_pr03_supabase_jwt_auth.py -q` (51 passed);
`pytest packages/case-dashboard/tests/test_pr03_supabase_portal_auth.py -q`
(32 passed); `pytest packages/sift-gateway/tests/test_mvp_binding_job_tools.py
-q` (21 passed); frontend `npm --prefix packages/case-dashboard/frontend run
build` passed with only the existing large chunk warning. Final doc validators
and `git diff --check` were run immediately before commit.

Left for the next session by operator request/context pressure: decide and
implement, or explicitly defer, only the remaining two FRZ1 polish items:
offline Volatility symbol packaging/pre-warm, and progress-stderr filtering for
durable command previews. BATCH-FRZ1 remains open.

### 2026-06-10 - BATCH-FRZ1 portal auth clarified + fresh agent TTL verified

Status: DONE

Operator clarified the actual portal credentials: `examiner@operators.sift.local`
with the current local password. Fresh live smoke confirms the portal path is
not blocked: login returned HTTP 200 with `must_reset=false`; evidence-chain
HMAC challenge returned HTTP 200; HMAC verify returned HTTP 200 / `ok=true`.
The earlier "operator password blocker" was specifically the VM-local
`~/.sift/operator-newpw.txt` smoke artifact being stale, not a real portal
login failure.

Operator issued a fresh portal GUI agent principal
`agent/8a91de13-630b-4e41-a63e-c130ee911e2b`. JWT payload verification shows
`iat=2026-06-10T01:42:31Z`, `exp=2026-06-12T01:42:31Z`, and
`ttl_seconds=172800` (48 hours). The fresh token initialized MCP successfully
and `tools/list` returned HTTP 200 with the expected 13-tool catalog including
`rag_search_case` and `run_command_job`. Do not store the raw access or refresh
token in repo files.

New portal UX backlog from operator observation: the principal/token table shows
all token rows as active, including expired rows, and only exposes a revoke
button. Logged in `known-limitations-and-improvements.md` as `IMP-FRZ1-01`.

### 2026-06-10 - BATCH-FRZ1 MCP freeze rehearsal proof + portal password blocker

Status: BLOCKED

FRZ1 conductor pass refreshed the final demo docs against live state and ran the
MCP-only readiness path on the active VM tree. Active unit working directory is
`/home/sansforensics/sift-mcps-test`; `sift-gateway.service` and
`sift-job-worker.service` are active; Gateway health reports `status=ok`,
Supabase OK, and evidence root `/cases` OK.

Live MCP proof used the VM-local agent token because the local `.mcp.json` token
returned HTTP 401. `tools/list` returned the 13-tool catalog including
`rag_search_case`, `run_command`, `run_command_job`, `job_status`,
`record_finding`, `manage_todo`, `list_existing_findings`, `case_info`, and
`evidence_info`. `case_info` returned `case-v1gate-06081857`, evidence chain
`ok`, `manifest_version=4`, and DB-authoritative finding counters. `evidence_info`
returned `chain_status=ok`, `listing_authority=db`, no required examiner action,
and exactly four active sealed objects: `rocba-cdrive.e01`,
`Rocba-Memory2.raw`, `v1-gate.log`, and `v1-ingest.jsonl`.

DB proof via VM `psycopg` showed `app.evidence_gate_status` =
`sealed`, `manifest_version=4`, `active_count=4`, no issues; `Rocba-Memory.raw`
is `retired`; finding counts are APPROVED=1, DRAFT=1, REJECTED=1; and
`app.rag_chunks=26586` with all rows `kind='knowledge'` / `case_id NULL`
(`22268` from `chroma_release_pgvector`). `rag_search_case` returned
`status=ok` with shared knowledge hits.

Forensic-tool proof ran through MCP `run_command` with sealed `evidence_refs`:
`cat evidence/v1-gate.log` and `cat evidence/v1-ingest.jsonl` returned saved
output refs and audit IDs; `vol -f evidence/Rocba-Memory2.raw windows.info`
exited 0 and identified Windows 10 build 19041 (audit
`siftgateway-codex2-20260610-042`); `fls evidence/rocba-cdrive.e01 | head -20`
exited 0 and listed the logical E01 filesystem root (audit
`siftgateway-codex2-20260610-045`).

Blocker: the VM-local `~/.sift/operator-newpw.txt` is stale. Portal login with
that file returned HTTP 401 / `invalid_token`, and the current password is
needed for HMAC re-auth, fresh portal `mcp:*` agent issuance, re-acquisition
click proof, finding approval, and report export. BATCH-FRZ1 remains open until
the human provides or resets the current operator password and the portal/HMAC
path is rerun.

### 2026-06-10 - Narrow sudoers allowlist for forensic disk-image mounting

Status: DONE

Path-B follow-up (operator-chosen) to the privilege discussion. The opensearch-mcp
INGEST path needs root to MOUNT disk images: `containers.py` shells out to
`sudo xmount/ewfmount/mount/ntfs-3g/losetup/qemu-nbd/modprobe nbd/partprobe/
umount/fusermount`, and `check_sudo` requires non-interactive sudo. On the live
VM this currently works only because `sansforensics` carries a blanket
`ALL=(ALL) NOPASSWD: ALL` grant (`/etc/sudoers.d/sansforensics`) - i.e. the
service relies on full admin root, the over-privilege the product thesis warns
against. (This is the service-user path, distinct from the `run_command`
writable-jail fix above.)

Landed: `scripts/setup-ingest-mount-sudoers.sh` writes
`/etc/sudoers.d/sift-ingest-mount` granting the gateway service user NOPASSWD
root for ONLY the resolved mount-helper full paths - no shell/wildcards (charter
D3); `modprobe` pinned to its exact `nbd max_part=8` args (no arbitrary module
loads); `tee` (the optional Samba-repoint root-write primitive,
`ingest_cli.py:_repoint_samba_if_configured`) deliberately EXCLUDED. `--print`
mode lets the operator review the exact rule before applying; install is
`visudo -cf`-validated and mode 0440. `scripts/setup-agent-runtime.sh` now
cross-references it.

Live: deployed + installed on the VM; `visudo -c` reports both drop-ins
`parsed OK`; rule resolves VM paths; `sudo -n /usr/sbin/losetup --version` and
`sudo -n /usr/bin/xmount --version` run as root non-interactively; `tee` absent.

Caveat / next step: the narrow allowlist is **documentary until the broad grant is
removed** - on this single-account VM the `sansforensics ALL=(ALL) NOPASSWD: ALL`
rule still masks it. To actually enforce least privilege, run the gateway/worker as
a DEDICATED non-admin service user. Tracked in known-limitations ("Ingest mount
privilege").

### 2026-06-10 - Executor writable HOME/XDG jail + unprivileged vol symbols

Status: DONE

Follow-up to the memory-depth finding: `run_command`/`run_command_job` forensic
tools run as the restricted `agent_runtime` user, whose real HOME and the tools'
read-only install dirs are not writable, so any tool that persists under
`~/.cache`, `~/.config`, `~/.local`, or a tool symbol store fails before analysis.
Volatility specifically writes generated ISF symbols into its read-only install
symbol store (not HOME/XDG), and there is no symbol-dir env var - only the
`--symbol-dirs` CLI flag prepends a path vol also writes to first.

Landed (`packages/sift-core/src/sift_core/execute/worker.py`, +3 tests in
`test_execute_executor.py`, suite 40 green):

- General fix: when the case cache jail is set, the worker also provisions a
  writable `HOME` + `XDG_CONFIG_HOME`/`XDG_DATA_HOME`/`XDG_STATE_HOME` inside
  `<case>/tmp` and applies them through the existing sudo `/usr/bin/env` path. No
  root; everything stays in the case write-jail. Fixes the broad "tool can't
  write under ~" class, not just vol.
- vol-specific: inject `--symbol-dirs <case>/tmp/vol-symbols` into Volatility
  invocations so vol generates symbols into the jail as the unprivileged user.

Live proof (rigorous): moved the operator's root-cached ISF aside to force
regeneration, then ran `vol -f evidence/Rocba-Memory2.raw windows.info` through
Gateway MCP (`run_command_job` `5785eb5b-...`). Result: `exit_code 0`,
`mechanism: direct_unprivileged`, full `windows.info` (Win10 19041, 4 CPUs,
`C:\WINDOWS`, SystemTime 2020-11-16); vol downloaded the PDB and wrote the ISF to
`<case>/tmp/vol-symbols/windows/...` owned by `agent_runtime` (585 KB). Install
symbol restored after the test. Closes the memory-depth caveat - see
known-limitations "Memory analysis symbols (RESOLVED)".

### 2026-06-10 - Evidence re-acquisition transition + ghost-violation unblock

Status: DONE

Closed a chain-of-custody dead-end found during AUT2/FRZ1 live QA: once a sealed
evidence item's bytes changed on disk (legitimate re-imaging of a corrupted
acquisition), the case latched to `violated` with NO operator path back to
`sealed`. Root causes: `verify` excludes violated objects from re-hash and
`app.evidence_recompute_seal_status` never de-escalates; the portal `seal` path
crashed because `_ensure_registered` -> `app.evidence_register` rejects any
status outside detected/registered; and the Evidence tab rendered "Modified
Files" as a dead list with no action. Net effect: the agent evidence gate was
fail-closed forever.

Operator decisions: build the full re-acquisition feature; and retire the live
ghost (on-disk `evidence/Rocba-Memory.raw` was gone, its 17.7 GB replacement
already sealed as `evidence/Rocba-Memory2.raw`).

Landed (live-proven on the active VM tree `sift-mcps-test` unless noted):

- DB: new `app.evidence_reacquire` RPC (migration
  `supabase/migrations/202606101000_evidence_reacquire.sql`), re-auth-gated and
  reason-required. Supersedes a sealed/violated item at freshly re-imaged bytes:
  append-only `evidence_versions` snapshot + a `MANIFEST_SEALED` custody event
  whose details carry `reacquired:true`, the superseded sha/bytes, the new
  sha/bytes, and the operator reason; flips the item violated->sealed and
  recomputes the gate. The prior sealed hash is superseded, never deleted.
- Gateway: `EvidenceAuthorityService.reacquire()` hashes the mounted replacement
  and calls the RPC; missing bytes -> `evidence_file_missing_cannot_reacquire`
  (409, "retire instead"). Hardened `_ensure_registered` to skip
  `app.evidence_register` for already sealed/violated/ignored/retired items.
- Portal: `POST /api/evidence/chain/reacquire` (examiner role + must_reset + HMAC
  + reason + reauth event), mirrors retire.
- Frontend: Evidence tab "Modified Files" block now offers per-file Re-seal
  (re-acquire) and Retire actions + a re-acquire modal; new `postChainReacquire`
  client (`components/evidence/EvidenceTab.jsx`, `api/endpoints.js`).
- Tests: `packages/sift-gateway/tests/test_evidence_reacquire.py` (6) +
  `TestEvidenceChainReacquire` in
  `packages/case-dashboard/tests/test_evidence_intake.py` (9). Full suites green:
  sift-gateway 424, case-dashboard 364.

Live unblock + MCP proof:

- Retired the ghost `evidence/Rocba-Memory.raw` (status violated) via an audited
  service-role `app.evidence_retire`. Chain head -> `sealed` (manifest_version 4,
  active_count 4); `evidence_gate_status` -> `sealed`.
- Re-proven through fresh Gateway MCP calls: `case_info` now returns
  `evidence_chain.status=ok` (was `blocked: evidence_chain_violation`);
  `evidence_info` lists 4 sealed files (ghost filtered out as retired),
  `requires_examiner_action=false`. Agent unblocked end-to-end.

Notes / still open:

- The live retire and the live reacquire-guard test were executed by the conductor
  via service RPCs (the live operator password has drifted from `~/.sift`, so the
  portal HMAC flow was not usable this session). The new portal/Evidence-tab
  Re-seal/Retire actions are unit-proven and deployed but not click-proven live —
  flagged for the next session that has the current operator password.

### 2026-06-10 - AUT2 blocker-fix pass (B0-B8) + run_command output/redaction revamp

Status: DONE

Conductor session fixed every open AUT2 blocker in source, deployed to the
active VM service tree `/home/sansforensics/sift-mcps-test`, restarted
Gateway/worker, and live-proved each fix through fresh Gateway MCP calls
against `case-v1gate-06081857`. All four package suites pass locally
(sift-core 465, sift-gateway 418, case-dashboard 355, opensearch-mcp 1015).

Fixes landed (all live-proven unless noted):

- AUT2-B0 agent credential TTL: `AgentServiceIssuance.issue_principal` now
  fails loudly (`agent_token_ttl_below_minimum`, HTTP 503, principal rolled
  back) when Supabase Auth issues an agent session below
  `auth.supabase.min_agent_token_ttl_seconds` (default 172800); the portal
  returns `token_ttl_seconds`; new source-controlled template
  `configs/supabase/auth-jwt.env.template` records the GOTRUE_JWT_EXP /
  JWT_EXPIRY=172800 deployment requirement. Live TTL proof: throwaway
  Supabase auth user password-grant returned `expires_in=172800` (48.0h,
  expiry 2026-06-11T22:48:25Z).
- run_command output revamp (operator directive): inline stderr capped at
  4 KB, duplicated structured command echo dropped for single-stage commands
  (kept for compound commands per QA finding 5 contract), and gateway
  absolute-path redaction narrowed to SENSITIVE prefixes only (cases root,
  /evidence, /mnt, /media, /var/lib/sift, /dev, SIFT_STATE_DIR). Benign
  system/tool/traceback paths now pass through to the agent; in-case
  absolutes still collapse to relative refs.
- AUT2-B1 primary-image ingest: `ingest_job` accepts single-file forensic
  images (.e01/.ex01/.raw/.dd/.img/.vmdk/.vhd/.vhdx) with bounded streaming
  strings extraction (ASCII + UTF-16LE, 4 MiB chunks, 2 GiB scan budget,
  500k-string cap) indexed into per-evidence OpenSearch indexes with full
  job-step and provenance recording. Live: `Rocba-Memory.raw` job
  `08c061cf-be23-4a85-9253-7509e96ba8d3` and `rocba-cdrive.e01` job
  `d68f9d03-8054-46c4-a106-acd6f151707f` both succeeded, 500k strings each,
  E01 read through pyewf.
- AUT2-B3 finding provenance: `record_finding` artifact validation accepts
  audit ids from a multi-directory JSONL scan OR DB audit authority
  (`app.audit_events.details->>'backend_audit_id'`), including `rc-` receipt
  forms; rejections list recent known-good ids. Live: finding `F-codex3-001`
  STAGED citing fresh audit id `siftgateway-codex3-20260609-295`.
- AUT2-B4 memory triage: executor passes `cache_dir=<case>/tmp/cache`; the
  worker exports `XDG_CACHE_HOME` (re-applied through sudo `/usr/bin/env`,
  no sudoers SETENV needed). Live: `vol windows.info` completed its
  symbol-cache update with no PermissionError.
- AUT2-B5 pipeline masking: worker captures per-stage stderr tails; pipeline
  responses report `success=false` + `failed_stages` (binary, exit_code,
  stderr_tail or hint) when an upstream stage fails; SIGPIPE (141/-13) on
  non-final stages stays exempt. Live: `mmls rocba-cdrive.e01 | head -8`
  surfaced mmls exit 1; follow-up `ewfinfo` (newly allowlisted with
  ewfverify/ewfexport) revealed the E01 is a LOGICAL image (no partition
  table).
- AUT2-B6 stale counters: `case_info` findings counters are DB-sourced
  (core `case_status_data` DB snapshot + gateway overlay on
  `app.investigation_findings`) and stamped `authority: db`. Live: counters
  matched `list_existing_findings` before and after staging a new DRAFT.
- AUT2-B7 binary ergonomics: binary stdout detection (NUL/replacement-char
  heuristic) switches to saved-file-first: bytes persisted with sha256,
  inline preview suppressed. Live: `head -c 300 Rocba-Memory.raw` returned
  `binary_output=true`, empty inline stdout, reusable saved ref.
- AUT2-B8 tool inventory: `get_tool_help('inventory')` returns availability
  for 70 cataloged tools + 27 allowlisted extras (no absolute paths);
  `capability_guide` gained a cached `core_tools` summary; `rg` 14.1.0
  installed on the VM and added to the forensic allowlist. Live: inventory
  returned 63/70 available.

AUT2 score after this pass: **22/24** (was 17/24). See
`docs/product/agent-autonomy-assessment.md` for the per-category basis.

### 2026-06-10 - AUT2 autonomy remediation live smoke

Status: DONE with remaining phase blockers

Follow-up remediation after the AUT2 benchmark fixed several agent-autonomy
failures on the active VM service tree `/home/sansforensics/sift-mcps-test`,
then re-ran the proof through a fresh Codex MCP session using a portal-issued
`mcp:*` agent. Supabase Auth JWT expiry was corrected for self-hosted Auth by
setting both live VM-local expiry knobs to `172800` seconds; a fresh agent token
showed about 48 hours of remaining TTL and expired on `2026-06-11T21:45:37Z`.

Live MCP proof after restart:

- `case_info` showed the active case `case-v1gate-06081857`, DB evidence gate
  `status=ok`, `authority=db`, `manifest_version=3`.
- `evidence_info` now uses DB listing authority and returned all four sealed
  evidence objects (`rocba-cdrive.e01`, `Rocba-Memory.raw`, `v1-gate.log`,
  `v1-ingest.jsonl`) with evidence IDs, hashes, sizes, and relative display
  paths. No local absolute evidence path was exposed.
- `run_command` with `evidence_refs=["evidence/v1-gate.log"]` succeeded.
- `run_command_job` with the same DB evidence ref queued, reached `succeeded`
  through `job_status`.
- Saved outputs now return reusable relative refs.
- `rag_search_case` returned `status=ok` with SANS/REMnux PowerShell analysis
  knowledge hits.

AUT2 remediation score: **17/24**. Carried to BATCH-FRZ1 / next implementation
pass: `.e01`/`.raw` ingest (fixed in AUT2 blocker-fix pass above), DB-audit-backed
`record_finding` artifact provenance, Volatility cache execution, reliable EWF
triage, stale `case_info` counters, and an agent-facing installed-DFIR-tool
inventory.

Remaining caveats before the next phase:

- `.e01` and `.raw` single-file `ingest_job` remains blocked.
- `record_finding` strong artifact/audit provenance still needs DB-audit authority
  validation.
- Volatility cache permissions and EWF/TSK triage behavior remain unresolved.
- `case_info.findings` counters are still stale/mirror-derived.
- There is still no agent-facing installed-DFIR-tool catalog; `rg` was not
  installed even though `grep` worked. Add a tool inventory or improve
  `get_tool_help`/capability guidance before a polished autonomy demo.
- Large binary searches still need stronger saved-file-first ergonomics and
  preview defaults despite the output-ref fix.
