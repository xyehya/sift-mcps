# Session Notes

Status: sprint log and decision register.
Last updated: 2026-06-14.

## Format Rules

- Latest change entry stays at the top of `Current Change Log`.
- Use `Status: DONE`, `Status: IN_PROGRESS`, or `Status: BLOCKED`.
- Keep forks, blockers, and needs-input in the single table below.
- Use IDs beginning with `F-MVP-` for forks and `B-MVP-` for backlog/needs-input.
- Do not create more migration runbooks.

## Current Change Log

### 2026-06-14 - RUN-3 implementation merged locally; non-MCP live gate green, MCP/portal matrix pending

Status: IN_PROGRESS (code + local gate + security review + live non-MCP proof done; final MCP/portal
acceptance still pending).

RUN-3 `run_command` hardening is now on local `main` after fast-forwarding `run3/integrate`. The
one pending main-worktree diff was only the stale Wave-1 tracker checkbox; the integrated tracker
superseded it and this note records the landing point.

Host validation on local `main`:
- `uv run --extra dev --extra full pytest packages/sift-core/tests -q` -> 597 passed, 2 xfailed.
- `uv run --extra dev --extra full pytest packages/sift-gateway/tests -q` -> 510 passed.
- `SIFT_RUN3_GATE_STRICT=1 uv run --extra dev --extra full pytest packages/sift-core/tests/security -q`
  -> 64 passed, 2 xfailed.
- `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`, touched script
  `bash -n`, and `git diff --check` passed.

Live VM non-MCP proof (operator asked to exclude MCP tool calls and portal APIs):
- Services active from `/opt/sift-mcps`; `/health` returned `status=ok`.
- Landlock ABI 4 confirmed by syscall; cgroup v2, systemd 255, and `agent_runtime` uid 995 confirmed.
- Root-owned RUN-3 systemd scope helper installed, sudoers parsed, unit verify passed, stale broad
  polkit `systemd-run` rule absent.
- Direct executor/helper smoke (not MCP) ran `id -u` as `agent_runtime` and returned uid 995.
- Direct floor probes (not MCP) failed closed for control-plane read, evidence write, and outbound
  connect. A direct `seccomp=kill` network probe died with `SIGSYS`, proving kill-mode behavior.

Remaining gates:
- Configure/use the in-session SIFT MCP tools for `tools/list`, `evidence_info`, the positive
  forensic matrix, and the negative red-team harness. Do not use curl/Python MCP API shims unless the
  operator changes this constraint.
- Keep service units in `SIFT_EXECUTE_SECCOMP_MODE=log` until the MCP positive matrix is green; then
  flip to `kill`, restart, and rerun positive + negative matrices.
- `dfir-exec` is still AppArmor complain-mode. Audit burn-in showed launcher `/proc/<pid>/fd` reads
  and Python `__pycache__` create attempts under `/opt/sift-mcps`; patch/profile these before enforce.
- Evidence is root-owned and floor-protected from the runtime user, but the host immutable bit was
  absent in `lsattr`. Restore/prove immutable sealing plus pre/post hashes before checking the final
  evidence-integrity box.
- Push origin only after the final MCP/portal/security gates pass and the operator authorizes it.

### 2026-06-14 - RUN-3 DESIGN FROZEN: run_command hardening spec + build plan (ready to launch)

Status: DONE (design); build NOT started.

Designed the autonomous (zero-HITL) hardening of the agent's `run_command` deep-dive exec path.
Three analyses fused into one authoritative spec: a hard red-team of the live exec code (gaps G1-G9),
a web-grounded sandbox survey, and an operator-supplied research draft — reconciled by an Opus 4.8
spec-writer that also SSH-corrected the kernel assumption (VM is Ubuntu 24.04 / kernel 6.8 /
**Landlock ACTIVE ABI v4**, not 22.04/5.15/v1).

- **Authoritative spec:** `docs/research/run_command-FINAL-SPEC.md` (Floor = Landlock+seccomp+cgroup+
  AppArmor in host mount ns — NOT bwrap/LXD, FUSE physics; Ceiling = allowlist default + per-tool
  code-exec scanners + env-deny + output sanitation; `contained` tier runs unlisted tools kernel-jailed
  with NO human approval = the autonomous replacement for HITL).
- **Operating model / build tracker:** `docs/RUN3-run_command-hardening-BUILD-PLAN.md` — 4 disjoint-fence
  batches (B-CEIL, B-FLOOR, B-AA, B-GATE) Wave-1 parallel + Wave-2 serial live VM (positive matrix /
  negative red-team / seccomp LOG->KILL burn-in / apparmor complain->enforce). Self-sufficient fresh-session
  launch prompt in its §6. Tracks B-MVP-026.
- Supporting artifacts: `docs/research/sandbox-survey-2026-06-14.md`, `docs/run_command_research.md`
  (operator draft). (The orchestrator's interim hardening plan was folded into the FINAL-SPEC.)

### 2026-06-14 - RUN-1 (post-MVP orchestrator): 4 parallel agents reconciled + LIVE-PROVEN on run1/integrate

Status: DONE (code + local gate + `/security-review` + serial VM live-proof all GREEN on `run1/integrate`).
NOT yet merged to main / pushed (RUN-2 push decision pending operator).

VM live-proof (rsync deploy to /opt/sift-mcps editable tree + restart; case case-rocba-case-06132304):
- TOOL: `running_commands_status` live on MCP surface (old `job_status` disconnected); inventory
  real-names (`vol` not vol3, `regripper`->rip.pl, plaso .py) via list_available_tools; `vol` AND
  Zimmerman `EvtxECmd` (v1.5.2.0, dotnet 9.0.116) run via run_command (incl pipe `vol|head`).
- OSW: `case_dir` injection live (no-arg ingest_status resolves active case); K4 DB-active
  ingest_status redirect live (after the B-MVP-025 fix). B4 memory durable-lane deferred to RUN-3.
- B-MVP-025: pre-existing gateway env-propagation bug FOUND+FIXED+proven live (see row below).
- HARDEN: AppArmor flipped COMPLAIN->ENFORCE, 0 AVC denials, regression green (B-MVP-018).
- /security-review on the combined diff: clean (no HIGH/MEDIUM); fixed a non-security srumecmd typo.

Orchestrated 4 disjoint-fence agents off LOCAL main (origin 63 behind), reconciled to
`run1/integrate` (zero file overlap). Plan + decisions: `docs/ORCHESTRATOR-HANDOFF-2026-06-14.md`.

- **TOOL** (run1/tool): renamed core MCP tool `job_status` -> `running_commands_status`
  (DB view app.job_status_public + JobService method intentionally NOT renamed); tool
  inventory real-name alignment — catalog `vol3`->`vol`, Zimmerman at /opt/zimmermantools
  run natively + allowlisted + symlink installer in install.sh, `regripper`->`rip.pl` via
  new `invoke_as` field; surfaced via list_available_tools. 503+505 tests green, bash -n ok.
- **OSW** (run1/osw): B3 ingest_status realtime + B4 memory-lane durable parity + item-2
  case_dir injection audit (only ingest_status lacked it). RECONCILE BLOCKER caught + fixed:
  first B3 cut served the tamperable local mirror JSON in DB-active mode, reopening the
  BATCH-K4 anti-tamper vector; corrected to Option C (K4-preserving redirect + job_id
  pointer, no local-file read). Option A (gateway DB-status injection) -> B-MVP-024.
  opensearch-mcp full suite 1014 passed, K4 test untouched + green.
- **HARDEN** (run1/harden): migrated ~11 sift_session test fixtures to the Supabase harness
  (progress on B-MVP-023); AppArmor profile prep (added cases/*/agent/** rw, dedup, scope
  note) + an enforce-flip runbook for the VM pass. Residual fork F-HARDEN-01 (Bearer/JTI
  flag-gated deletion) logged under B-MVP-023. 361 tests green. The COMPLAIN->enforce flip
  is the LAST serial VM step (after OSW+TOOL load exercised so aa-logprof sees real syscalls).
- **RESEARCH** (web): sandbox survey -> `docs/research/sandbox-survey-2026-06-14.md`. Picks:
  bwrap+socat for Hermes agent code-exec (A); Landlock+seccomp+AppArmor-fuse for run_command
  forensic-exec (B). RUN-3 input. Supersedes B-MVP-018's "revisit enforce post-LV1" only for
  the apparmor flip, which RUN-1 brings forward.

Local gate on run1/integrate: sift-core 503, sift-gateway 505, opensearch-mcp 1014,
case-dashboard 361, validate_docs + validate_migration_docs PASS, bash -n install.sh ok,
git diff --check clean. NEXT: serial VM live-proof (OSW -> TOOL -> HARDEN enforce-flip last),
then RUN-2 (/security-review combined diff + push main->origin).

### 2026-06-14 - BUILT: OpenSearch decoupled scalable workers (branch feat/opensearch-workers; deployed to TEST)

Status: IN_PROGRESS (build + unit tests DONE; deployed to VM; first live smoke pending joint test).

Implements the 2026-06-14 DECISION below. Branch `feat/opensearch-workers` (do NOT
merge/push yet — `/security-review` required before merge). 5 commits:
- 5628af0 gateway dispatch boundary + realtime status (`OpenSearchJobDispatchMiddleware`,
  innermost; redirects `opensearch_ingest`/`opensearch_enrich_intel` to a NON-BLOCKING
  durable job, returns opaque job_id; query tools stay on the thin proxy).
- fedd6d1 ingest/enrich job handlers + lane-scoped worker CLI
  (`opensearch_mcp/ingest_job.py`; `job_worker_cli.build_handlers(job_types=...)` wires
  only the requested lane).
- 3817a98 `configs/systemd/sift-opensearch-worker@.service` template (only relaxation vs
  sift-job-worker: `MountFlags=shared`) + install.sh render/enable N instances.
- 402851b unit + concurrency + anti-spoof tests.
- a2dfc51 agentic-security skill docs (environment-profile + repo-security-baseline:
  control A dispatch + control H FUSE OPEN→RESOLVED-via-decoupled-worker).
Migration `202606150900_opensearch_worker_status.sql` (per-step/worker realtime status).

Architecture honored: gateway stays the SOLE policy boundary and is NOT loosened
(`MountFlags=` empty kept); every ingest/query call still passes auth → active-case →
audit → evidence-gate before dispatch; worker sees only the gateway-resolved
DB-authoritative `case_dir` in `spec_internal` (client-supplied `case_dir`/`case_id`/
`case_key` dropped — anti-spoof); N workers claim distinct jobs via `FOR UPDATE SKIP
LOCKED`; non-blocking dispatch.

Test proof (per-package, host .venv): sift-core job worker 18 passed; opensearch-mcp
ingest-job handler 7 passed; sift-gateway dispatch middleware 6 passed + job/binding
regression (test_mvp_d2 + test_mvp_binding) 35 passed. 4 build commits confirmed green
after the API-interruption resume.

Live proof (sanitized, VM siftworkstation, case-rocba, 2026-06-14): deployed editable
to /opt/sift-mcps; migration 202606150900 applied (worker_label + current_step in
app.job_status_public); created the `sift-opensearch-worker` console script;
installed+enabled `sift-opensearch-worker@1`; restarted gateway + job-worker.
- THE CROWN-JEWEL GATE PASSED: `opensearch_ingest(evidence/rocba-cdrive.e01,
  dry_run=false, force=true)` → non-blocking dispatch → `osw-1` CLAIMED the durable
  job → FUSE MOUNT SUCCEEDED (xmount → ntfs-3g ro,noexec; NO `Operation not
  permitted`) → parsed the E01 disk artifacts → job `succeeded`. 14 disk-family
  indices for host srl-forge landed (evtx 12,440, registry 7,278, srum 18,516,
  amcache 1,112, prefetch 1,081, shimcache, shellbags, jumplists, lnk, recyclebin,
  tasks, wer, httperr) — artifacts that were UNREACHABLE before (the entire reason
  for the build).
- Realtime status proven through the agent MCP surface: `job_status(job_id)` returns
  `status=running`, `worker_label=osw-1`, `current_step` with live `indexed_docs` +
  `artifacts_complete n/14`, path-free `spec_public`.
- Hardened gateway untouched: `MountFlags=` empty, `ProtectSystem=strict`.

THREE LIVE-DISCOVERED BUILD DEFECTS FIXED THIS SESSION (commits b5d6d91, 521230c):
1. The decoupling's core premise was WRONG. `MountFlags=shared` does NOT let a
   private-mount-namespace unit do FUSE. Empirically (live systemd-run probes vs the
   real E01): fusermount needs (a) CAP_SYS_ADMIN in the bounding set AND (b) the HOST
   mount namespace — i.e. NO ProtectSystem/ProtectHome/PrivateTmp/ReadWritePaths/
   ProtectKernel*/ProtectControlGroups (each forces a private ns and fails the mount
   even WITH CAP_SYS_ADMIN+MountFlags=shared). Worker now runs the namespace-free
   hardening subset + gateway privilege-drop caps + CAP_SYS_ADMIN. NET POSTURE
   REDUCTION vs design (worker loses ProtectSystem=strict) — DECISION-PENDING, FLAGGED
   for /security-review before merge.
2. Worker bounding set was cap_linux_immutable-only (copied from sift-job-worker) →
   sudo→root mount failed `unable to change to root gid`. Now has SETUID/SETGID/
   SETPCAP/AUDIT_WRITE.
3. `sift-job-worker.service` wasn't lane-restricted → the cap-starved default worker
   ALSO claimed ingest jobs and failed the mount. Pinned to `--job-types run_command`.
4. (commit 521230c) Dispatch returned `status=queued` but IngestOut's Literal lacked
   it → the gateway output-validator REJECTED the response, so the agent never got the
   job_id (the job still ran). Added `queued` + job_id/job_type/dispatched_to/next_step
   to IngestOut; regenerated the surface golden; redeployed + restarted gateway; now
   the dispatch returns the job_id cleanly.

STOPPED for joint testing (per operator). System left clean: services active+idle, no
stuck jobs, disk indices persisted. STILL OPEN: full 40GB E01 completion; Hayabusa
`*-hayabusa-*` index verify (Hayabusa RAN on the parsed EVTX live but the dedicated
detection index wasn't confirmed this pass); N-worker (@2..@N) parallel proof;
`/security-review` of the worker posture reduction BEFORE merge. Updated
mcp_tool_assessment.md §0 (FUSE/Hayabusa/single-threaded → RESOLVED; WOF extractor +
PTC bridge + sandbox still OPEN).



### 2026-06-12 - Operator readiness and hardening track opened

Status: DONE (docs/planning reset; implementation batches opened)

Changed: Replaced the long completed-batch tracker with a second-phase
operator-readiness program in `docs/migration/task-batches.md`, and refreshed
`AGENTS.md` around the current operating model. The new track covers the user
requested work: full operator maintenance docs, variables/secrets/config maps,
file-state versus DB-authority discovery, official hardening research and audit
guides, live SIFT tool inventory, RAG/FK/Hayabusa provenance, legacy cleanup,
ProtocolSiftGateway/add_ons restructuring, add-on spec and conformance proof,
portal health/case/RAG improvements, certificate strategy, regenerate-doc
modernization, and final live VM validation.

Reasoning: The current codebase has crossed the main migration milestone. The
remaining risk is no longer "does the core migration exist?" but "can an
operator understand, maintain, harden, extend, and prove it without rediscovery?"
The old detailed batch history was useful during migration but now slows future
sessions down. It is retained in git history; this file now keeps only the
current baseline, decisions, open inputs, and proof notes.

Current baseline:

- Core stack: Gateway, sift-core, portal, Supabase/Postgres, OpenSearch,
  forensic-rag-mcp/pgvector, forensic-knowledge, Hayabusa, local worker, and
  installer/systemd services.
- External add-ons: OpenCTI and future Windows-triage style tools. They must
  install through the add-on contract, not the native core installer.
- Fresh installer baseline from the last live run: clone-entry `./install.sh`
  stages into `/opt/sift-mcps`; `/health` is `status=ok`; `sift-gateway.service`
  and `sift-job-worker.service` are active; OpenSearch and RAG backend rows use
  `/opt/sift-mcps/.venv/bin/opensearch-mcp` and
  `/opt/sift-mcps/.venv/bin/rag-mcp`; `app.rag_chunks` is populated; portal auth
  works for `examiner@operators.sift.local`; MCP auth still needs a portal-issued
  agent/service credential for final tools/list smoke.
- Docs seed material: `docs/regenerate/**` is useful but stale. Future batches
  must verify it against source/live state before promoting it.

Validation: `python3 scripts/validate_docs.py` OK;
`python3 scripts/validate_migration_docs.py` OK; `git diff --check` clean.

Next: Start BATCH-OR1, BATCH-OR2, BATCH-OR4, and BATCH-HR1 in parallel. Then use
their outputs to write BATCH-OR3, the operator maintenance manual.

### 2026-06-12 - Installer health contract for mounted native stdio backends

Status: DONE (host patch; live VM rerun verified)

Changed: Gateway `/health` now treats mounted idle stdio proxy backends as ready,
while unmounted stopped backends remain degraded. Installer idempotent Supabase
bootstrap now preserves an existing operator mapping so handoff text points at
the actual Supabase login path.

Live proof: Fresh rerun cleaned stale installer probes, confirmed no OpenCTI
containers/volumes/indices, ran `./install.sh` from `~/sift-mcps`, and exited 0.
Post-run `/health` returned `status=ok`, both system services were active, RAG
pgvector had rows, OpenSearch was healthy, and portal login with the handoff
operator succeeded with `must_reset=true`. An operator Supabase login token
correctly failed MCP auth with `invalid_token`; final MCP tools/list waits on a
portal-issued agent/service credential.

Validation: `bash -n install.sh scripts/setup-addon.sh scripts/setup-supabase.sh`
OK; focused gateway tests OK; `python3 scripts/validate_docs.py` OK;
`python3 scripts/validate_migration_docs.py` OK; `git diff --check` clean.

Next: Continue with the operator-issued MCP credential smoke under BATCH-LV1
after portal reset/credential issuance.

## Forks / Backlog / Needs Input

| ID | Type | Status | Decision / Input Needed | Owner Batch |
| --- | --- | --- | --- | --- |
| B-MVP-001 | Backlog | DONE | DONE 2026-06-12 (TLS1, live-proven): internal-CA profile hardened (CA basicConstraints critical, leaf serverAuth EKU, derived SANs), reruns preserve the CA (fingerprint-proven), scripts/rotate-tls.sh gives leaf renewal + DANGER-gated CA rotation, handoff/docs carry client trust-bundle steps; ACME/domain documented as deferred profile. | BATCH-TLS1 |
| B-MVP-002 | Needs input | OPEN | DECIDED 2026-06-12: rename GitHub repo/docs to `ProtocolSiftGateway`; keep `/opt/sift-mcps` runtime path and Python package import names unchanged. Implementation in BATCH-CL2. | BATCH-CL2 |
| B-MVP-003 | Backlog | RESOLVED | DECIDED 2026-06-12: Windows triage stays an author-guide example only; no rebuild now. AD2 proves the add-on contract with OpenCTI alone. | BATCH-AD1 / BATCH-AD2 |
| B-MVP-004 | Backlog | DONE | DONE 2026-06-12 (HR3, live-proven): uv/Hayabusa/BGE/RAG-bundle pinned with SHA-256 hard gates, Supabase CLI SHA warn->die, GeoIP off by default behind --enable-geoip, SIFT_OFFLINE=1/--offline skips all fetches with staged-artifact messages. | BATCH-HR3 |
| B-MVP-005 | Backlog | DONE | DONE 2026-06-12 (HR3, live-proven): OpenSearch container runs CapDrop=ALL, no-new-privileges, digest-pinned image; security plugin stays disabled per decided loopback lab posture. | BATCH-HR3 |
| B-MVP-006 | Backlog | OPEN | DECIDED 2026-06-13: all portal-managed RAG documents are GLOBAL KNOWLEDGE ONLY; no case-derived chunks. PT2 implements add/list/refresh/retire for the shared knowledge plane only; case-derived RAG stays out of scope and would require a separate future design with evidence provenance. | BATCH-PT2 |
| B-MVP-010 | Backlog | DONE | DONE 2026-06-12 (HR3, live-proven): gateway.yaml carries session_secret_env only; value lives in 0600 control-plane.env; loader resolves the reference; migration strips inline literals. | BATCH-HR3 |
| B-MVP-011 | Backlog | DONE | DONE 2026-06-12 (HR3+PT1, live-proven): portal login is Supabase-only (examiner.json fallback + local setup/challenge/reset endpoints removed; fails closed 503 when control plane is down); sift-core reporting is DB-content-hash-only. Remaining file-HMAC re-auth bridge tracked as B-MVP-017. | BATCH-HR3 / BATCH-PT1 |
| B-MVP-012 | Needs input | OPEN | DECIDED 2026-06-12 (BATCH-SB1): repo-owned self-managed compose generating GOTRUE_JWT_SECRET, anon/service-role keys, non-default DB password. DEFERRED 2026-06-13 (operator): SB1 runs AFTER BATCH-LV1; LV1 proceeds on the current CLI loopback stack with demo secrets accepted as documented lab posture. SB1 no longer gates LV1; it must precede any non-lab deployment. | BATCH-SB1 |
| B-MVP-013 | Needs input | OPEN | DECIDED 2026-06-13: ADOPT FORCE ROW LEVEL SECURITY on the 31 RLS-ENABLED `app.*` tables (BATCH-DB1). Defense-in-depth: gateway `service_role` has BYPASSRLS so the gateway path is unaffected; FORCE makes RLS apply to the table OWNER too, enforcing default-deny on the 0-policy tables. DB1 LANDED 2026-06-13 (916f0e6): migration FORCEs all 31; applies at next install/LV1 (not yet live-applied). | BATCH-DB1 |
| B-MVP-007 | Backlog | OPEN | DECIDED 2026-06-13: keep the OpenCTI add-on images for now; build a component uninstaller (BATCH-UN1) that removes ALL or operator-SELECTED components, dry-run by default, evidence never removed without its own flag. UN1 LANDED 2026-06-13 (c98ec90): scripts/uninstall.sh + maintenance-guide §14, bash -n clean, evidence triple-gated; live teardown/reinstall proof folded into LV1. | BATCH-UN1 |
| B-MVP-008 | Backlog | OPEN | PARKED 2026-06-13 (operator): keep open. Volatility symbol cache is empty (on-demand fetch); document symbol provisioning for air-gapped operation later. | BATCH-OR3 / BATCH-HR3 |
| B-MVP-009 | Backlog | DONE | DONE 2026-06-12 (CL1): `.DS_Store` excluded from both installer staging branches; vol3/yara scan clean - catalogs already map `vol3`->`vol` and yara CLI exists via python3-yara. | BATCH-CL1 |
| B-MVP-014 | Backlog | DONE | DONE 2026-06-12 (HR3, live-proven): installer installs+enables auditd; 12 SIFT rules loaded live (secrets/config, install-root binaries, identity files, units). | BATCH-HR3 |
| B-MVP-015 | Backlog | DONE | DONE 2026-06-12 (HR3, live-proven): BAAI/bge-base-en-v1.5 canonical with revision pin; explicit HF_HOME under the service home wired into both units; offline-aware loader. | BATCH-HR3 |
| B-MVP-016 | Backlog | RESOLVED | RESOLVED 2026-06-12 (AD2): KEEP scope_enforcement - the premise was wrong; packages/opensearch-mcp/sift-backend.json ships it on opensearch_enrich_intel, so schema removal would reject a live manifest. It is advisory metadata in the OS5 family; regression tests added (shipped manifest validates, unknown fields still rejected). | BATCH-AD2 |
| B-MVP-017 | Needs input | DONE | DONE 2026-06-13: file-HMAC re-auth plane RETIRED. CL3a (636f425) built the fail-closed Supabase password re-verify; CL3b (718684e) deleted the dead verifiers, re-homed must-reset to the Supabase `invited` signal, and closed B-MVP-021/022. Both security-reviewed (APPROVE-WITH-NITS, no bypass); suites green; live smoke folded into LV1. RESIDUAL (test-coupled session-establishment, NOT the re-auth plane): `sift_session` cookie-verify -> B-MVP-023. | BATCH-CL3a / BATCH-CL3b |
| B-MVP-018 | Backlog | DONE | DECIDED 2026-06-13: keep AppArmor COMPLAIN-only through BATCH-LV1; revisit enforce after e2e. SUPERSEDED + DONE 2026-06-14 (RUN-1 HARDEN, live): enforce-flip brought forward and proven. Profile (configs/apparmor/sift-gateway.template, +cases/*/agent rw, evidence-write-deny intact) regenerated to /etc/apparmor.d/sift-gateway, loaded complain, gateway traffic exercised (run_command vol/EvtxECmd incl pipes + ingest_status), audit-log harvest showed ZERO AVC violations, then flipped to ENFORCE via apparmor_parser -r (aa-enforce util absent on VM). Post-enforce regression GREEN: gateway active+healthy, run_command + ingest_status work, DENIED_count=0. NOTE: live runtime is ENFORCE; install.sh configure_apparmor still loads complain by default (safe install default) — operator may opt to make enforce the install default in a follow-up. | RUN-1 HARDEN / live |
| B-MVP-019 | Backlog | OPEN | Operator briefed 2026-06-13 (detail in change log). setup-addon.sh embeds operator-home paths (command=`~/.local/bin/uv`, `--project ~/sift-mcps`, manifest under `~/sift-mcps`) in register payloads, but the hardened gateway runs ProtectHome=tmpfs and can only see `/opt/sift-mcps` + system paths, so a so-registered add-on would fail to launch under the live gateway. Fix = derive command/project/manifest from the staged `/opt/sift-mcps` tree. Operator confirmed 2026-06-13: FOLD INTO BATCH-LV1 — fix when LV1 first launches a real add-on under the hardened gateway, using live-confirmed staged paths. | BATCH-LV1 |
| B-MVP-020 | Backlog | DONE | DONE 2026-06-13 (operator-requested, live-proven): ran rotate-tls.sh --rotate-ca on the existing VM. New CA CN="Protocol SIFT Gateway local CA" with critical basicConstraints CA:TRUE + critical keyUsage(keyCertSign,cRLSign); leaf re-issued with serverAuth EKU + IP/DNS SANs; keys 0600 / certs 0644 sift-service; gateway restarted, /health ok, both services active; curl --cacert verifies WITHOUT -k on the IP SAN. Clients must re-import /var/lib/sift/.sift/tls/ca-cert.pem. | BATCH-TLS1 / live |
| B-MVP-021 | Backlog | OPEN | Pre-existing gap (surfaced by CL3a security review, NOT a CL3a regression): `post_case_activate` DB-active branch (`_ACTIVE_CASES is not None`, the live VM path) returns before any re-auth, so case activation — a CLAUDE.md sensitive action — is NOT re-authed under DB authority. DONE 2026-06-13 (CL3b, 718684e): the DB-active branch now `await _supabase_reverify` before `set_active_case`; fail-closed tested (wrong-pw 401, control-plane-down 503, success). | BATCH-CL3b |
| B-MVP-022 | Backlog | OPEN | Pre-existing gap (surfaced by CL3a security review): agent/service credential issuance (`create_principal`, POST /api/auth/principals) gates only on owner/admin role — no operator-password re-verify, though agent-credential issuance is a CLAUDE.md sensitive action. DONE 2026-06-13 (CL3b, 718684e): `create_principal` now requires Supabase re-verify in addition to the owner/admin gate; fail-closed tested (wrong-pw 401, missing-pw 400, success). | BATCH-CL3b |
| B-MVP-023 | Backlog | OPEN | CL3b refused-as-fork (2026-06-13): the `sift_session` cookie-verify branch in case-dashboard auth.py is session-ESTABLISHMENT (not the file-HMAC re-auth plane), provably unminted in production but load-bearing for ~11 test suites' auth fixtures (generate_jwt + COOKIE_NAME). Migrate those fixtures to the Supabase-envelope harness, then delete the branch (and its examiner Bearer fallback / JTI logout if also dead). Not security-blocking (reaching it needs an already-secret-signed JWT). PROGRESS 2026-06-14 (RUN-1 HARDEN, run1/harden): the ~11 test fixtures migrated off generate_jwt/COOKIE_NAME to the Supabase-envelope harness (6 files), unblocking deletion from the test side; 361 case-dashboard tests green. RESIDUAL fork F-HARDEN-01: the examiner Bearer fallback (auth.py) + JTI logout revoke (routes.py) are gated by `legacy_portal_session_enabled` (default false in new installs) — unreachable at runtime but flag-controlled, not dead in general. DECISION NEEDED before code deletion: (a) set legacy_portal_session_enabled=false in all remaining installs and delete the sift_session branch + Bearer + JTI code, or (b) keep the flag. Code retained until decided. | Future legacy-session retirement batch |
| B-MVP-024 | Backlog | OPEN | OPENED 2026-06-14 (RUN-1 OSW, run1/osw): Option A deferred for opensearch_ingest_status realtime status. RUN-1 took Option C (K4-preserving): in DB-active mode the tool returns ingests:[] + authority "postgres-durable-jobs" + a job_id/next_step pointer and never reads the tamperable local mirror JSON (preserves BATCH-K4). FUTURE: have the gateway inject authoritative app.job_status_public rows for in-flight jobs of the active case into the ingest_status call (same mechanism class as case_dir injection), so agents see realtime worker_label/current_step/indexed_docs without any local-file read — satisfies both K4 and B3's realtime goal. Requires gateway middleware/plumbing outside RUN-1's dispatch-only scope fence. | Future opensearch realtime batch (RUN-3+) |
| B-MVP-025 | Backlog | DONE | FOUND + FIXED 2026-06-14 (RUN-1 VM proof, run1/integrate): the gateway's `_stdio_base_env()` (mcp_server.py) built a minimal whitelist env (PATH/HOME/USER/LOGNAME/SHELL/LANG/TMP*/LC_*) for stdio add-on backends and OMITTED `SIFT_DB_ACTIVE`. So the opensearch-mcp backend subprocess never saw the DB-authority flag → `db_status_active()` defaulted to legacy → the BATCH-K4/B3 DB-active ingest-status contract NEVER engaged in the backend (it would have served tamperable local status JSON instead of the durable-job redirect). PRE-EXISTING (not introduced by RUN-1; surfaced by live proof). FIX: propagate the non-secret `SIFT_DB_ACTIVE` boolean only (never the control-plane DSN) in `_stdio_base_env`; 2 regression tests added. Live-proven on VM: ingest_status now returns the K4 durable-job-authority redirect (ingests=[], no local-mirror read). Workers were a false alarm (job_worker_cli self-sets SIFT_DB_ACTIVE at runtime; not visible in /proc/environ). | RUN-1 reconcile (orchestrator) |
| B-MVP-026 | Backlog | OPEN | RUN-3 run_command hardening: add kernel Floor (Landlock ABI v4 + seccomp + systemd-cgroup + AppArmor, host mount ns — NOT bwrap/LXD per FUSE physics) + harden Ceiling (allowlist default + `contained` kernel-jailed tier for unlisted tools = autonomous no-HITL; per-tool code-exec scanners sed/sqlite3/tshark/vol/exiftool; DENY_FLOOR adds; .NET/LD/PYTHON env-deny; /var/lib/sift read-block; output ANSI/OSC sanitation). Closes red-team gaps G1-G9. DESIGN FROZEN 2026-06-14: authoritative spec `docs/research/run_command-FINAL-SPEC.md`; build plan + fresh-session launch prompt `docs/RUN3-run_command-hardening-BUILD-PLAN.md` (4 disjoint batches B-CEIL/B-FLOOR/B-AA/B-GATE, Wave-1 parallel + Wave-2 serial live VM). Sub-backlog: C1 run_command_structured entrypoint; C4 LXD/microVM Tier-2; Landlock ioctl-scoping at kernel>=6.10. | RUN-3 (run_command hardening) |

## Active References

- `AGENTS.md` - operating instructions, VM constraints, Context7 docs rule, and
  current architecture invariants.
- `docs/migration/task-batches.md` - executable batch tracker and worker hints.
- `docs/regenerate/**` - stale first-phase docs to be verified and regenerated,
  not source of truth until BATCH-RG1.

## Validation Commands

Run at the end of documentation/planning sessions:

```bash
python3 scripts/validate_docs.py
python3 scripts/validate_migration_docs.py
git diff --check
```

Add targeted code tests for any touched implementation package.
