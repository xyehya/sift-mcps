# Session Notes

Status: sprint log and decision register.
Last updated: 2026-06-10.

Format rules:

- Latest change entry stays at the top of `Current Change Log`.
- Use `Status: DONE`, `Status: IN_PROGRESS`, or `Status: BLOCKED`.
- Keep forks, blockers, and needs-input in the single table below.
- Use IDs beginning with `F-MVP-` for forks and `B-MVP-` for backlog.
- Do not create more migration runbooks.

## Current Change Log

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
- Decisions locked (full context in `task-batches.md` PMI track): OpenSearch -> 3.5 (Hayabusa
  detection; Sigma stays disabled); RAG single-home = pgvector (`rag_search_case`), delete the
  redundant standalone Chroma `kb_search_*`; `forensic-knowledge` FK-enrichment is core context-
  injection to KEEP (just unwired — FK_DATA_DIR unset); Hayabusa is already wired end-to-end.
- Opened the PMI track with a LEAN operating model (targeted tests only per batch; one full
  end-to-end gate at BATCH-PMI4) and ready-to-paste prompts for PMI1 (OS 3.5 cutover) ∥ PMI2
  (RAG single-home), then PMI3 (FK_DATA_DIR), then PMI4 (VM proof + Rocba run).

Validation:

- `python3 scripts/validate_docs.py`: OK. `python3 scripts/validate_migration_docs.py`: OK.
- One-session install command: `./install.sh --no-windows-triage --no-opencti`.

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
  a fresh worktree's uv env (a fresh `uv run python -c "import psycopg"` fails in the worktree,
  succeeds on the root `.venv`). The opensearch-mcp package intentionally lazy-guards psycopg.
  Fix: guard the psycopg-provenance test (test_job_ingest) and the degrade test (test_k4) with
  `pytest.importorskip("psycopg")` / patch-on-real-module so they SKIP (not fail) where psycopg
  is absent. Not a production bug.

Validation (on main `revamp/spg-v1`, psycopg present in root `.venv`):

- opensearch-mcp suite: 1027 passed, 71 skipped, 0 failed (the two psycopg tests RUN and pass).
- gateway suite: 447 passed, 0 failed.
- `python3 scripts/validate_docs.py`: OK. `python3 scripts/validate_migration_docs.py`: OK.

Follow-ups:

- Worktree env gotcha for future parallel-agent runs: a fresh `git worktree` may use a uv env
  WITHOUT optional deps (psycopg). Run final validation on the main `.venv`, or treat
  importorskip-gated tests as expected-skips in worktrees.
- OS6 (live VM OpenSearch proof) is the only remaining batch: deploy/smoke on the SIFT VM,
  restart gateway + job-worker, prove aggregate `/mcp tools/list` advertises restored
  `opensearch_*`, run one read-only path + one sealed-evidence ingest job. Requires the live VM.
- DoD review gates (`/code-review`, `/security-review`) over the full OS1-OS5 diff still deferred
  per operator; OS1-OS5 unit branches retained.

### 2026-06-10 - BATCH-OS3 + BATCH-OS4 landed (read-only surface verified; job-backed ingest)

Status: DONE

Changed:

- OS3 and OS4 ran in parallel in worktrees off `revamp/spg-v1` (`revamp/os3-readonly-surface`,
  `revamp/os4-job-ingest`); OS4 landed as merge `cff7378` + follow-up `aae168b`.
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

- Full gateway suite on landed `revamp/spg-v1`: 447 passed. opensearch-mcp `test_job_ingest.py`:
  27 passed. Verified no external add-on names present in gateway core (guard still meaningful).
- `python3 scripts/validate_docs.py`: OK. `python3 scripts/validate_migration_docs.py`: OK.

Follow-ups:

- OS4 noted optional defense-in-depth: add `"hidden_from_agent": true` to `opensearch_ingest` in
  the manifest. Not required (the Gateway shadow enforcement is sufficient) — deferred.
- Next wave: OS5 (host identity/enrichment/mutating-tool policy) — overlaps OS3's `server.py` +
  manifest so it runs solo next; then OS6 (live VM smoke) last, only after OS1-OS5 local tests pass.
- DoD review gates (`/code-review`, `/security-review`) over the full OS1-OS4 diff still deferred
  per operator; OS branches retained for re-review.

### 2026-06-10 - BATCH-OS1 + BATCH-OS2 landed (OpenSearch catalog + active-case proxy)

Status: DONE

Changed:

- OS1 and OS2 ran in parallel in dedicated worktrees off `revamp/spg-v1`
  (`revamp/os1-backend-seed`, `revamp/os2-active-case-proxy`), integrated OS1-first
  per the operating model, and landed on `revamp/spg-v1` as merge `ce3748e`.
- OS1 - DB backend seed: `install.sh` gains `seed_addon_backends()`, an idempotent
  upsert of `opensearch-mcp` into `app.mcp_backends` gated on
  `SIFT_OPENSEARCH_ENABLED=true` + control-plane DSN present. Stores env-ref metadata
  only (`OPENSEARCH_CONFIG`/`OPENSEARCH_HOST`), never raw secrets. Corrected stale
  manifest `requires` URL to `http://localhost:9200`. `test_f1_opensearch_backend_registry.py`
  grew 3->11 tests proving requirement gating and aggregate-catalog presence/absence.
- OS2 - active-case proxy: manifest-declared `safe_case_argument_names` per tool replaces
  placeholder-schema detection. `Gateway.safe_case_argument_names()` now returns
  `set|None` with a tri-state honored at BOTH enforcement paths (`call_tool` and
  `ProxyActiveCaseMiddleware`): `None`=unknown->deny fail-closed, `set()`=no-injection->
  pass through, non-empty->inject DB active case. Explicit mismatched `case_id` still
  denied pre-dispatch. `sift-backend.schema.json` updated to allow the new field.

Validation:

- Integrated branch: gateway suite `439 passed`; opensearch-mcp suite
  `1015 passed, 71 skipped`; targeted OS1+OS2 set `107 passed`.
- `sift-backend.json` auto-merged cleanly (OS1 `requires` line and OS2 per-tool fields
  are disjoint regions). Merged manifest validated: 16 tools, all carry
  `safe_case_argument_names`.
- `python3 scripts/validate_docs.py`: OK. `python3 scripts/validate_migration_docs.py`: OK.

Follow-ups (carry into OS3 / live smoke):

- `opensearch_get_event`, `opensearch_status`, `opensearch_shard_status`,
  `opensearch_list_detections` were declared `safe_case_argument_names: []` (case-scoped
  but no injection arg -> pass through). Verify in live smoke they resolve the active case
  internally and cannot leak cross-case events.
- Deployment: gateway service env must carry `OPENSEARCH_HOST`/`OPENSEARCH_CONFIG` for
  `resolve_runtime_config` at startup (install.sh writes the config file but does not yet
  export these into the gateway unit env).
- DoD: `/code-review` and `/security-review` over this diff are still pending (touches the
  Gateway policy path + MCP backend registration). OS branches retained for re-review.

### 2026-06-10 - OpenSearch standalone restoration track reopened

Status: DONE

Changed:

- Reopened OpenSearch as a critical autonomy track because the live aggregate
  MCP catalog was last recorded with 13 Gateway tools and no `opensearch_*`,
  while the standalone package still owns the richer search/ingest/enrichment
  surface.
- Kept the operating model trimmed: `docs/migration` is this log plus
  `task-batches.md`; do not restore the removed `Migration-Spec.md` or add a
  separate OpenSearch runbook.
- Added BATCH-OS0..OS6 to `task-batches.md`. Locked the main decisions:
  `packages/opensearch-mcp/**` remains owner of parser/search/ingest/enrichment;
  Gateway remains the only agent-facing policy boundary; Supabase/Postgres
  remains authority; OpenSearch is derived and rebuildable.
- Prioritized restore order: DB backend visibility and active-case proxy first,
  read-only search surface next, job-backed ingest and mutating policy after,
  live VM proof last.

Validation:

- `python3 scripts/validate_docs.py`: OK.
- `python3 scripts/validate_migration_docs.py`: OK.
- `git diff --check`: clean.

Next:

- Run OS1 and OS2 in parallel after OS0 lands. Land OS1 before OS3 so aggregate
  catalog visibility is proven before read-only tool restoration. Keep OS4/OS5
  parallel after active-case proxy behavior is fixed. OS6 is live-only and last.

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
button. The portal should show token type, display name, active/expired/revoked
status, TTL remaining, and a revoke button that becomes disabled/dimmed after
successful revoke. Logged in `known-limitations-and-improvements.md` as
`IMP-FRZ1-01`.

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

Cut line for freeze: B2(a/d) are no longer FRZ1 blockers (`record_finding`
artifact audit checks accept DB audit IDs in DB-active mode, and `evidence_info`
listing is DB-backed/live-proven). Keep B1 live click proof, B0/B6 fresh portal
issuance, and report export in-scope once the password is available. Document
B3/B5 service-user and installer hardening, offline symbols, progress-stderr
filtering, scope introspection, and optional `EVIDENCE_REACQUIRED` as
post-freeze backlog.

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
`parsed OK`; rule resolves VM paths (`/usr/sbin/losetup`, `/usr/sbin/modprobe nbd
max_part=8`, `/usr/bin/xmount`, ...); `sudo -n /usr/sbin/losetup --version` and
`sudo -n /usr/bin/xmount --version` run as root non-interactively; `tee` absent
from the allowlist.

Caveat / next step (the real enforcement): the narrow allowlist is **documentary
until the broad grant is removed** - on this single-account VM the
`sansforensics ALL=(ALL) NOPASSWD: ALL` rule still masks it. To actually enforce
least privilege, run the gateway/worker as a DEDICATED non-admin service user
whose only root capability is this drop-in, then drop the blanket grant for that
user (keep it for the human admin). Tracked in known-limitations
("Ingest mount privilege").

### 2026-06-10 - Executor writable HOME/XDG jail + unprivileged vol symbols

Status: DONE

Follow-up to the memory-depth finding: `run_command`/`run_command_job` forensic
tools run as the restricted `agent_runtime` user, whose real HOME and the tools'
read-only install dirs are not writable, so any tool that persists under
`~/.cache`, `~/.config`, `~/.local`, or a tool symbol store fails before analysis
(AUT2-B4 only patched `XDG_CACHE_HOME`). Volatility specifically writes generated
ISF symbols into its read-only install symbol store (not HOME/XDG), and there is
no symbol-dir env var - only the `--symbol-dirs` CLI flag prepends a path vol
also writes to first.

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

Scope note (architecture, operator-confirmed): this is the `run_command` (agent
tool) path only. The opensearch-mcp INGEST path is separate - it spawns
`opensearch_mcp.ingest_cli scan` as the service user (writable home) and its real
privilege need is MOUNTING disk images (`containers.py` uses
`sudo xmount/ewfmount/mount/losetup/qemu-nbd/umount/fusermount`; `check_sudo`
requires non-interactive sudo). Next track (operator-chosen): a scoped, audited
sudoers NOPASSWD allowlist for those specific mount helpers (not blanket sudo).
A bubblewrap/LXC per-exec sandbox for `run_command` was discussed as a later
hardening track.

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
fail-closed forever (live: `case_info` -> `blocked: evidence_chain_violation` on
`case-v1gate-06081857`). The lifecycle doc already claimed a `violated -> sealed`
transition (`data-flows-and-lifecycles.md`) that the code never implemented.

Operator decisions (this session, via AskUserQuestion): build the full
re-acquisition feature; and retire the live ghost (on-disk
`evidence/Rocba-Memory.raw` was gone, its 17.7 GB replacement already sealed as
`evidence/Rocba-Memory2.raw`).

Landed (live-proven on the active VM tree `sift-mcps-test` unless noted):

- DB: new `app.evidence_reacquire` RPC (migration
  `supabase/migrations/202606101000_evidence_reacquire.sql`), re-auth-gated and
  reason-required. Supersedes a sealed/violated item at freshly re-imaged bytes:
  append-only `evidence_versions` snapshot + a `MANIFEST_SEALED` custody event
  whose details carry `reacquired:true`, the superseded sha/bytes, the new
  sha/bytes, and the operator reason; flips the item violated->sealed and
  recomputes the gate. The prior sealed hash is superseded, never deleted.
  Service-role grant only. Applied live via libpq (no psql on VM); function
  installed (10 args); guard proven (`reacquire_requires_reauth` on null re-auth).
- Gateway: `EvidenceAuthorityService.reacquire()` hashes the mounted replacement
  and calls the RPC; missing bytes -> `evidence_file_missing_cannot_reacquire`
  (409, "retire instead"). Hardened `_ensure_registered` to skip
  `app.evidence_register` for already sealed/violated/ignored/retired items (the
  crash root cause) - it registers only detected/registered now
  (`packages/sift-gateway/src/sift_gateway/portal_services.py`).
- Portal: `POST /api/evidence/chain/reacquire` (examiner role + must_reset + HMAC
  + reason + reauth event), mirrors retire
  (`packages/case-dashboard/src/case_dashboard/routes.py`).
- Frontend: Evidence tab "Modified Files" block now offers per-file Re-seal
  (re-acquire) and Retire actions + a re-acquire modal; new `postChainReacquire`
  client (`components/evidence/EvidenceTab.jsx`, `api/endpoints.js`).
- Tests: `packages/sift-gateway/tests/test_evidence_reacquire.py` (6) +
  `TestEvidenceChainReacquire` in
  `packages/case-dashboard/tests/test_evidence_intake.py` (9). Full suites green:
  sift-gateway 424, case-dashboard 364.

Live unblock + MCP proof:

- Retired the ghost `evidence/Rocba-Memory.raw` (object `ea451498-...`, status
  violated) via an audited service-role `app.evidence_retire` (reauth event
  `1ad19a5a-...`; reason records the Rocba-Memory2.raw supersession). Chain head
  -> `sealed` (manifest_version 4, active_count 4); `evidence_gate_status` ->
  `sealed`.
- Re-proven through fresh Gateway MCP calls: `case_info` now returns
  `evidence_chain.status=ok` (was `blocked: evidence_chain_violation`);
  `evidence_info` lists 4 sealed files (ghost filtered out as retired),
  `requires_examiner_action=false`. Agent unblocked end-to-end.

New finding (memory depth - operator hypothesis confirmed): durable job
`a1a56196-...` (`vol -f evidence/Rocba-Memory2.raw windows.info`) ran cleanly
through the job/provenance/saved-output path (409 B out, `failed_stages`
surfaced) and shows the re-acquired image is a VALID Windows image - vol's
PdbSignatureScanner positively identified the kernel PDB (`ntkrnlmp.pdb` GUID
`15B12C74F0E177581B6B27DD4C5022C2`), where the old corrupted image yielded no
banner at all. The remaining blocker is NOT corruption or a missing symbol table
but a writable-symbols-dir permission: vol cannot write the generated/downloaded
symbol JSON to `/opt/volatility3/.../symbols/windows/` (read-only for
`agent_runtime`). Fix is a B4-family executor change: point vol's symbol dir to a
case-writable path (`VOLATILITY3_SYMBOL_DIRS` / `--symbol-dirs`) alongside the
existing `XDG_CACHE_HOME` cache_dir, then re-run windows.info. See the
next-session prompt.

Notes / still open:

- The live retire and the live reacquire-guard test were executed by the
  conductor via service RPCs (the live operator password has drifted from
  `~/.sift`, so the portal HMAC flow was not usable this session). Both are fully
  audited in the custody ledger. The new portal/Evidence-tab Re-seal/Retire
  actions are unit-proven and deployed but not click-proven live for the same
  reason - flagged for the next session that has the current operator password.

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
  expiry 2026-06-11T22:48:25Z); live `.env` knobs confirmed at 172800.
  Operator-portal issuance smoke was NOT run because the live operator
  password has drifted from `~/.sift/operator-newpw.txt` (human-changed);
  enforcement path is unit-proven (5 new tests).
- run_command output revamp (operator directive): inline stderr capped at
  4 KB, duplicated structured command echo dropped for single-stage commands
  (kept for compound commands per QA finding 5 contract), and gateway
  absolute-path redaction narrowed to SENSITIVE prefixes only (cases root,
  /evidence, /mnt, /media, /var/lib/sift, /dev, SIFT_STATE_DIR). Benign
  system/tool/traceback paths now pass through to the agent; in-case
  absolutes still collapse to relative refs. This is a deliberate,
  documented loosening of the blanket path-redaction posture in favor of
  agent autonomy; secret redaction is unchanged.
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
  forms; rejections list recent known-good ids. Root cause was cross-process
  audit-dir divergence plus DB authority never being consulted. Live:
  finding `F-codex3-001` STAGED citing fresh audit id
  `siftgateway-codex3-20260609-295`, provenance summary MCP.
- AUT2-B4 memory triage: executor passes `cache_dir=<case>/tmp/cache`; the
  worker exports `XDG_CACHE_HOME` (re-applied through sudo via
  `/usr/bin/env`, no sudoers SETENV needed). Live: `vol windows.info`
  completed its symbol-cache update with no PermissionError. Remaining gap
  is forensic: no matching Windows symbol table for `Rocba-Memory.raw`
  (`banners.Banners` returned no banner; operator must provision symbols or
  validate the image).
- AUT2-B5 pipeline masking: worker captures per-stage stderr tails; pipeline
  responses report `success=false` + `failed_stages` (binary, exit_code,
  stderr_tail or hint) when an upstream stage fails; SIGPIPE (141/-13) on
  non-final stages stays exempt. Live: `mmls rocba-cdrive.e01 | head -8`
  surfaced mmls exit 1; follow-up `ewfinfo` (newly allowlisted with
  ewfverify/ewfexport) revealed the E01 is a LOGICAL image (no partition
  table) - the true root cause of the AUT2 mmls mystery.
- AUT2-B6 stale counters: `case_info` findings counters are DB-sourced
  (core `case_status_data` DB snapshot + gateway overlay on
  `app.investigation_findings`) and stamped `authority: db`. Live: counters
  matched `list_existing_findings` before and after staging a new DRAFT.
  Root cause: `case_status_data` counted from module-level file loaders,
  bypassing the DB-aware CaseManager path.
- AUT2-B7 binary ergonomics: binary stdout detection (NUL/replacement-char
  heuristic) switches to saved-file-first: bytes persisted with sha256,
  inline preview suppressed. Live: `head -c 300 Rocba-Memory.raw` returned
  `binary_output=true`, empty inline stdout, reusable saved ref.
- AUT2-B8 tool inventory: `get_tool_help('inventory')` returns availability
  for 70 cataloged tools + 27 allowlisted extras (no absolute paths);
  `capability_guide` gained a cached `core_tools` summary; `rg` 14.1.0
  installed on the VM and added to the forensic allowlist. Live: inventory
  returned 63/70 available; `rg` search of sealed evidence succeeded with
  hash provenance.

File-backed state still surfaced to agents (kept, documented per operator
rule "no file state without justification"):

- Artifact source registry gate in `record_finding` still checks the file
  `evidence-manifest.json` (AUT1-B1 family) - flagged for post-FRZ1.
- Grounding score (`_score_grounding`) checks JSONL existence only.
- Audit summary aggregates the file JSONL mirror (labelled
  `legacy-file-mirror` in DB mode).
- `case_info.file_structure` and `agent/findings_list.json` snapshot dumps
  are filesystem-derived by design.

VM-local operational notes:

- pyewf is symlinked from system dist-packages into the service venv
  (`.venv/.../site-packages/pyewf.so`); re-create the symlink after any
  `uv sync` (candidate for install.sh hardening).
- `ripgrep` installed via apt on the VM.
- Supabase Auth `.env` retains GOTRUE_JWT_EXP/JWT_EXPIRY=172800; the new
  gateway-side issuance validation makes regressions loud.

Known small wart (logged, not fixed): durable-job `result_public` stderr can
carry Volatility \r progress spam (capped at 4 KB); a progress-line filter is
a future context optimization.

AUT2 score after this pass: **22/24** (was 17/24). See
`docs/product/agent-autonomy-assessment.md` for the per-category basis.


### 2026-06-10 - AUT2 autonomy remediation live smoke

Status: DONE with remaining phase blockers

Follow-up remediation after the AUT2 benchmark fixed several agent-autonomy
failures on the active VM service tree
`/home/sansforensics/sift-mcps-test`, then re-ran the proof through a fresh
Codex MCP session using a portal-issued `mcp:*` agent. Supabase Auth JWT expiry
was corrected for self-hosted Auth by setting both live VM-local expiry knobs to
`172800` seconds; a fresh agent token showed about 48 hours of remaining TTL
and expired on `2026-06-11T21:45:37Z`. Gateway and worker were synced,
restarted, and live health returned OK after each restart.

Live MCP proof after restart:

- `case_info` showed the active case `case-v1gate-06081857`, DB evidence gate
  `status=ok`, `authority=db`, `manifest_version=3`.
- `evidence_info` now uses DB listing authority and returned all four sealed
  evidence objects (`rocba-cdrive.e01`, `Rocba-Memory.raw`, `v1-gate.log`,
  `v1-ingest.jsonl`) with evidence IDs, hashes, sizes, and relative display
  paths. No local absolute evidence path was exposed.
- Repeated case context was trimmed from non-orientation tool responses:
  `get_tool_help`, `manage_todo`, `run_command`, `job_status`, and
  `rag_search_case` did not append the extra `case_context` block.
- `run_command` with `evidence_refs=["evidence/v1-gate.log"]` succeeded,
  hashed one input, and returned provenance tied to DB evidence object
  `b69fd920-14d4-4891-af6c-a9385667d2f7`.
- `run_command_job` with the same DB evidence ref queued, reached `succeeded`
  through `job_status`, and returned the same evidence ID/hash provenance.
- Saved outputs now return reusable relative refs. The synchronous smoke
  returned
  `agent/run_commands/aut3-evidence-ref-wc/20260609_215106_wc_stdout.txt`, and
  a follow-up `run_command cat <that ref>` succeeded. The durable job smoke also
  returned a reusable `agent/run_commands/aut3-job-wc/..._stdout.txt` ref.
- `grep -a -m 1 -i powershell evidence/Rocba-Memory.raw` succeeded against the
  DB-sealed memory image with evidence-ref provenance. `rg` itself is not
  installed on the VM, so the observed `rg` failure is now tool availability,
  not DB evidence-ref/path-guard behavior.
- `rag_search_case` returned `status=ok` with SANS/REMnux PowerShell analysis
  knowledge hits.

AUT2 remediation score: **17/24**. The score improves from 14/24 because
discoverability/orientation, context efficiency, evidence-ref provenance, and
saved-output composability are materially better. This still does **not** make
the project ready for a full fresh-environment install and full Rocba
disk+memory investigation claim.

Remaining caveats before the next phase:

- `.e01` and `.raw` single-file `ingest_job` remains blocked.
- `record_finding` strong artifact/audit provenance still needs DB-audit
  authority validation; do not claim provenance-grade findings until fixed.
- Volatility cache permissions and EWF/TSK triage behavior remain unresolved.
- `case_info.findings` counters are still stale/mirror-derived: live
  `case_info` reported old draft/approved counts while `list_existing_findings`
  showed `F-codex-1-001` as `APPROVED` and `F-hermes-v1-gate-001` as
  `REJECTED`.
- There is still no agent-facing installed-DFIR-tool catalog; `rg` was not
  installed even though `grep` worked. Add a tool inventory or improve
  `get_tool_help`/capability guidance before a polished autonomy demo.
- Large binary searches still need stronger saved-file-first ergonomics and
  preview defaults despite the output-ref fix.

### 2026-06-09 - BATCH-AUT2 live demo-case autonomy benchmark

Status: DONE with limitations

Ran the prepared demo case `case-v1gate-06081857`
(`57a06521-c9b8-4654-92ac-42b4f2bb0915`) through the AUT2 benchmark. The case
was not recreated. Portal/DB readiness was verified first: active case open,
DB-authority evidence gate OK at `manifest_version=3`, four active sealed
evidence objects (`rocba-cdrive.e01`, `Rocba-Memory.raw`, `v1-gate.log`,
`v1-ingest.jsonl`), and the ignored hidden/temp history rows remained inactive.
Live health was checked on the active VM service tree
`/home/sansforensics/sift-mcps-test`; Gateway and worker were active, and RAG
baseline remained `app.rag_chunks=26586`.

Fresh portal-issued `mcp:*` agents saw the full 13-tool catalog including
`rag_search_case`. The core benchmark used 30 fresh-client MCP calls across two
fresh principals, plus supplemental conductor MCP calls for record staging and
failure reproduction. Human intervention after agent start was limited to the
intended operator portal approval/report path. RAG was callable and redacted;
`run_command ls -la evidence` enumerated the four active sealed files, which is
still required because the agent-facing `evidence_info.evidence_files` list is
file-listing-backed and empty when the local file manifest is absent.

Positive AUT2 results:

- `case_info`/`evidence_info` orientation reflects DB gate authority
  (`authority=db`, `status=ok`, `manifest_version=3`).
- `rag_search_case` is present and callable for fresh `mcp:*` agents.
- `run_command` protected delete of sealed evidence failed closed with the
  forensic-integrity operator-workflow message.
- The agent staged `F-codex-1-001`, `T-codex-1-002`, and
  `TODO-codex-1-001`.
- Portal review/report was verified: commit approved 1 finding with DB
  authority, report eligibility flipped from `eligible=false` to
  `eligible=true`, findings-profile report
  `1ff91996-5666-4b36-9568-c701f5204c24` generated/saved/downloaded, and the
  downloaded markdown passed the AUT2 quick secret-shape scan.

AUT2 blockers/caveats:

- `ingest_job` cannot ingest `.e01` or `.raw` single evidence files. Both Rocba
  primary images failed terminally with `unsupported single-file evidence format
  for ingest job`; `v1-ingest.jsonl` succeeded as a positive control.
- `run_command.evidence_refs` still resolves against file-manifest state and
  reported "the case has no sealed evidence" on a DB-sealed case. `input_files`
  worked as a degraded smoke workaround only.
- `record_finding` strong artifact provenance rejected a fresh `run_command`
  audit id as missing because artifact validation still scans the local JSONL
  audit trail while Gateway audit authority is DB-first. The AUT2 finding could
  only be staged with supporting-command provenance, yielding PARTIAL/NONE
  provenance.
- Volatility cannot start under `run_command` due a cache-path permission error;
  MCP policy blocked attempted env/cache-directory workarounds.
- EWF disk triage is not yet reliable: `mmls` returned exit 1 with no useful
  stderr, and `fls ... | head` masked an upstream failure because the final
  pipeline stage succeeded.
- Some summaries are still mirrors: after portal approval,
  `list_existing_findings` saw `F-codex-1-001` as `APPROVED`, while
  `case_info.findings` counters still showed the old draft/approved counts.
- Context bloat remains possible from binary-memory greps despite preview caps;
  response redaction produced benign false positives on URL-like text and an
  `ewfinfo` heading.

Final AUT2 score: **14/24**. BATCH-FRZ1 may present a controlled MCP-only
smoke/custody demo, but must not claim full autonomous Rocba disk+memory
analysis until the large-evidence ingest, DB-backed evidence refs, provenance,
Volatility, and EWF-analysis issues are fixed or explicitly worked around by an
approved operator extraction flow.

Validation for this closeout: `python3 scripts/validate_docs.py` passed;
`python3 scripts/validate_migration_docs.py` passed; `git diff --check` passed;
targeted package-scoped pytest passed
(`test_mvp_binding_job_tools.py`, `test_e1_portal_db_authority.py`,
`test_mvp_k2_investigation_store.py`). A combined cross-package pytest command
hit the repo's known top-level `tests.*` import collision, so the same targets
were run package-by-package. Touched-doc secret-shape scan found no secret-shaped
values.

### 2026-06-09 - Portal evidence DB-authority excision + hidden-file/delete fix

Status: DONE

Operator-side (portal) evidence hardening discovered while preparing the AUT2
demo case (`case-v1gate-06081857`, the Rocba memory+disk case). Two commits on
`revamp/spg-v1` after the BATCH-INST1 commit `6ea96c9`:

- `2ac667c` - Excise the file-backed "V0" evidence path from the portal. The
  operator evidence cycle (status / rescan / list / seal / ignore / retire /
  verify-hmac / anchor / proof-export / summary) is now **DB-authority only**
  (`app.evidence_gate_status` + `app.evidence_objects`). Root cause of the bug
  the operator saw: `post_evidence_chain_rescan` returned the file-backed builder
  (empty local manifest -> "V0") while `chain/status` read the DB ("V2"), so the
  header flapped V0<->V2 and sealed files showed unregistered. `_db_evidence_chain_status`
  is now the single builder, extended with `unregistered`/`missing`/`modified`/
  `ok`/write-block/`hmac_*`/anchor. Fresh-install carve-out: no DB service / no
  active case degrades to an empty `no_case` payload at HTTP 200 (never 500/block).
  HMAC re-auth on seal/ignore/retire preserved.
- `cc76677` - Close a hidden-file backdoor. Detection (`_scan_evidence`) was
  briefly changed to skip dotfiles/temp files; reverted because the AI agent can
  read any file under `evidence/` via `run_command` (relative paths) once the gate
  is OK, so hiding files made a planted hidden file agent-readable yet operator-
  invisible. Detection now surfaces every file. Added a real operator **delete**
  (`POST /api/evidence/chain/delete`, examiner role + HMAC) that physically unlinks
  a non-sealed stray file's bytes (sealed evidence is custody-protected -> 409),
  recording the removed file's sha256+size in the append-only custody log; new
  Delete button/modal in the Evidence tab.

Live evidence (operator API + agent MCP, after sync/restart):

- The V0 flap is gone: `chain/status` and `rescan` return identical DB authority.
- A planted hidden file `.planted-test` was detected/visible, deleted
  (`file_removed=true`, sha256 logged, gone from disk); deleting sealed
  `v1-gate.log` returned `409 cannot_delete_sealed_evidence`.
- The operator then sealed the two Rocba images through the portal: demo case is
  now **sealed at manifest_version 3**, gate OK. A fresh `mcp:*` agent sees the
  full 13-tool catalog incl `rag_search_case`; `case_info.evidence_chain` =
  `{status: ok, ok: true, authority: db, manifest_version: 3}`.
- Carried-forward residual (unchanged, AUT2 to mind): the **agent** tool
  `evidence_info.evidence_files` is still file-listing-backed, so with the local
  file manifest absent it can show `chain_status: ok` with an empty
  `evidence_files`. The agent should enumerate evidence via `run_command ls
  evidence` (lists `rocba-cdrive.e01`, `Rocba-Memory.raw`, `v1-*`). This is the
  next DB-authority follow-up (make `evidence_info` list DB evidence objects).

Seal timeout fix: the portal client used a global 15s fetch timeout, so sealing
a large image (23 GB disk) aborted client-side with "Request timed out" even
though the backend completed the seal (the hash of the mounted bytes runs
synchronously in the request). Added a per-call `timeoutMs` override
(`LONG_TIMEOUT_MS` = 15 min) for the evidence-hashing operations (seal /
proof-export / verify-hmac / delete) and an operator note in the Seal modal.

Validation: case-dashboard 355 passed (5 new delete tests); gateway portal/
proof/gate 28 passed; ruff clean; frontend rebuilt + deployed; `git diff --check`
clean; secret-shape scan clean.

### 2026-06-09 - BATCH-INST1 closed; AUT1-B1 fixed live; AUT2 unblocked

Status: DONE

Conductor remediation pass against the live VM service tree
`/home/sansforensics/sift-mcps-test` (active unit confirmed before sync). This
closes BATCH-INST1 and the AUT1 pre-AUT2 gates.

Changed (code):

- AUT1-B1 (HIGH) fixed with the recommended Gateway overlay seam. New
  `_overlay_db_evidence_gate` in
  `packages/sift-gateway/src/sift_gateway/mcp_server.py` rewrites the
  `evidence_chain`/`chain_status` block of `case_info`/`evidence_info` to the
  DB-authority gate (`app.evidence_gate_status` via `check_evidence_gate_db`)
  when a control-plane DSN is present. Core tools stay file-based for legacy
  mode. The overlay is fail-safe (any DB/parse error returns the original text),
  grants no new authority, and adds an explicit `authority: "db"` marker. The
  gate `ChainStatus` enum is emitted as its plain value (`"ok"`), matching the
  rest of the surface.
- Tests: `packages/sift-gateway/tests/test_mvp_binding_job_tools.py` adds four
  overlay tests (sealed overlay for both tools, non-OK gate still surfaces
  `ok=false`, and legacy no-DSN no-op), using the real `ChainStatus` enum to
  guard the value-vs-repr regression.

Live evidence (post sync + Gateway/worker restart, health `ok`):

- AUT1-B1 resolved through the agent MCP channel: `case_info.evidence_chain` =
  `{status: ok, ok: true, manifest_version: 2, authority: db}` and
  `evidence_info` = `{chain_status: ok, requires_examiner_action: false,
  manifest_version: 2, authority: db}` on demo case `case-v1gate-06081857`
  (`57a06521-...`). Previously orientation said `unsealed/ok=false/mv=0` while
  the DB gate was `sealed, mv=2` and tools executed - the stall trap is gone.
- `rag_search_case` is in the live 13-tool catalog (direct `tools/list` with an
  `mcp:*` agent) and callable: `status=ok`, knowledge results, `kind=knowledge`,
  `case_id=null`, query-relevant SANS titles; leak scan over the payload found no
  `/cases`, `/home`, `/var/lib/sift`, loopback, DSN, service-role, OpenSearch, or
  JWT strings. Note: the gateway was never unwired - the AUT1 "absent" reading
  reflected that probe's deployment; the running Gateway exposes RAG to any
  `mcp:*` principal.
- pgvector corpus matches the B-MVP-18 baseline: `app.rag_chunks=26586`, all
  `kind='knowledge'`, `case_id NULL`, `seed_source='chroma_release_pgvector'`
  =22268 (+4318 bundled seed).
- `~/.sift/control-plane.env` mode `600`. `agent_runtime` (uid 996) ACLs on the
  demo case: `evidence/` `r-x`, `agent/`/`extractions/`/`tmp/` `rwx`, `CASE.yaml`
  effective `---`, `/var/lib/sift` `---`. `/cases` root is traverse-only `--x`.
- Worker heartbeating (`worker-...`, `idle`, recent `last_heartbeat_at`);
  OpenSearch container healthy (Docker healthcheck) with V1 ingest intact; VM
  Python `3.12.3`, venv interpreter `/usr/bin/python3.12`. `install.sh` `bash -n`
  OK with idempotency/Python-constraint guards present.

Residual / caveats (carried to FRZ1 backlog, not AUT2 blockers):

- `evidence_info` still lists evidence files from the file manifest, so a
  DB-sealed case with an absent local manifest shows `chain_status=ok` but
  `evidence_files=[]`. The stall-trap fields (`chain_status`,
  `requires_examiner_action`) are now DB-correct; the evidence *listing* staying
  file-backed is a sufficiency gap, tracked as a follow-up (DB-derived evidence
  listing).
- A full destructive `./install.sh` re-run was not executed on the live demo VM
  to preserve prepared demo state, sealed evidence, and downloaded corpora;
  idempotency was checked structurally and remains covered by the BATCH-V1
  install.
- For AUT2 the demo agent must be issued with `mcp:*` (or
  `tool:rag_search_case`) so the CORRELATE/RAG plane is reachable.

Validation:

- `uv run pytest packages/sift-gateway/tests/` (full): all passed (incl. 4 new
  overlay tests); `test_mvp_binding_job_tools.py` 13 passed.
- VM `python -m py_compile` on the synced `mcp_server.py`: OK.
- `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`,
  `git diff --check`, touched-file secret-shape scan: recorded with this commit.

Next:

- Run BATCH-AUT2 against the hackathon demo case through MCP only. Prepare the
  demo case via the portal (create/activate, register/seal, issue an `mcp:*`
  agent), then drive orient -> gate -> ingest -> search/RAG -> record -> hand
  back, capturing the autonomy benchmark. AUT1-B1 and AUT1-B2 are closed.

### 2026-06-09 - Conductor live-sync rule hardened

Status: DONE

Changed:

- Expanded `Conductor.md` so live-impacting fixes must be synced by the
  conductor to the active VM service tree, followed by Gateway/worker restart,
  health proof, and a targeted live smoke before session closeout.
- Added copy-paste host-to-VM rsync, dependency refresh, service restart,
  health/log check, portal login/HMAC smoke, fresh agent-principal issuance,
  and MCP initialize/tools-list proof commands.
- Preserved the operational rule that large VM downloads/corpora are not
  removed by routine sync: the standard rsync command excludes local state and
  does not use `--delete`.
- Kept raw passwords, tokens, DSNs, service-role keys, OpenSearch credentials,
  and private keys out of tracked docs; the runbook uses local environment
  variables and VM-local secret files.

Validation:

- `python3 scripts/validate_docs.py`: OK.
- `python3 scripts/validate_migration_docs.py`: OK.
- `git diff --check`: clean.
- Secret-shape scan over touched docs: no matches.

### 2026-06-09 - Live portal reauth and MCP issuance repaired

Status: DONE

Changed:

- Diagnosed the live VM portal issue reported after AUT1/BATCH-INST1 prep:
  Supabase login worked, but password/HMAC confirmation prompts returned 401
  and the frontend treated those local re-auth failures as global session
  expiry.
- Hot-reset the VM-local local-HMAC reauth verifier to match the working
  Supabase operator login, then fixed the code path so successful Supabase
  login and forced password reset sync only a salted PBKDF2 verifier into the
  local MVP reauth bridge.
- Updated the portal frontend client so password/HMAC confirmation endpoints
  surface their own errors without triggering a global logout.
- Fixed portal evidence verify for DB-active cases:
  - slash-bearing display paths are encoded client-side;
  - the route uses DB evidence authority before legacy filesystem fallback;
  - the injected DB evidence adapter is called with its keyword-only
    `case_id` contract.
- Corrected the live deployment target: the active user service runs from
  `/home/sansforensics/sift-mcps-test`, not the stale sibling checkout.

Live evidence:

- `sift-gateway.service` restarted from the active tree and remained active.
- Portal login, evidence-chain challenge, and HMAC verify returned HTTP 200.
- Per-file evidence verify for `evidence/v1-gate.log` returned HTTP 200 with
  `authority=db` and `status=verified`.
- Fresh agent principal issuance through `/portal/api/auth/principals`
  returned HTTP 201; returned token material was written only to VM-local
  `~/.sift/` files with mode `600`.
- MCP initialize and `tools/list` with the fresh token returned HTTP 200 and
  all 13 demo-critical tools, including `rag_search_case` and
  `run_command_job`.

Validation:

- `uv run pytest packages/case-dashboard/tests/test_e1_portal_db_authority.py
  packages/case-dashboard/tests/test_a1_bootstrap.py
  packages/case-dashboard/tests/test_pr03_supabase_portal_auth.py`:
  `67 passed`.
- Earlier in the repair branch:
  `uv run pytest packages/case-dashboard/tests/test_a1_bootstrap.py
  packages/case-dashboard/tests/test_pr03_supabase_portal_auth.py`:
  `44 passed`.
- Earlier in the repair branch:
  `npm --prefix packages/case-dashboard/frontend test`: `86 passed`.
- Earlier in the repair branch:
  `npm --prefix packages/case-dashboard/frontend run build`: OK.

Next:

- Keep BATCH-INST1 open for full installer idempotency, VM refresh, ACL,
  OpenSearch, RAG, and component hardening proof; this repair closes the
  immediate live portal reauth and MCP-token issuance blockers.

### 2026-06-09 - BATCH-INST1 live operations guidance expanded

Status: DONE

Changed:

- Expanded root `Conductor.md` with a reusable live operations runbook for:
  host-to-VM rsync, VM dependency refresh, Gateway/worker restart, installer
  replay, `~/.sift/*.env` permission checks, `agent_runtime` ACL checks,
  OpenSearch health, RAG release download/import repair, pgvector count proof,
  MCP catalog proof for `rag_search_case`, and AUT1-B1 evidence-orientation
  handling.
- Updated BATCH-INST1 tracking so the next live-readiness pass must close the
  AUT1 gates before AUT2: live-prove AUT1-B3/B4/B5/B6 after redeploy, make
  `rag_search_case` visible/callable through MCP, verify full forensic RAG
  pgvector counts, and fix or neutralize AUT1-B1.
- Kept raw credentials, DSNs, service-role keys, OpenSearch credentials, and
  agent tokens out of repo docs. The runbook references VM-local secret files
  and local shell variables only.

Validation:

- `python3 scripts/validate_docs.py`: OK.
- `python3 scripts/validate_migration_docs.py`: OK.
- `git diff --check`: clean.
- Secret-shape scan over touched docs: no matches.

Next:

- Run BATCH-INST1 / live-readiness remediation from current `revamp/spg-v1`
  using `Conductor.md`, then launch BATCH-AUT2 only after AUT1-B1 and AUT1-B2
  are closed or explicitly accepted with live proof.

### 2026-06-09 - BATCH-AUT1 integrated and autonomy gates identified

Status: DONE

Changed:

- Integrated BATCH-AUT1 into root `revamp/spg-v1`:
  - Worker commit `3813033`: live MCP autonomy assessment and `job_status`
    malformed-id/raw-error leak fix.
  - Conductor commit `0d27706`: closed AUT1-B4/B5/B6 low-friction tool guidance
    gaps before merge.
  - Merge: `Merge BATCH-AUT1 agent autonomy assessment`.
- Marked BATCH-AUT1 complete in `task-batches.md`.
- Added or updated product documentation:
  - `docs/product/agent-autonomy-assessment.md`: filled scorecard, per-tool
    table, run metrics, AUT1-B1..B6 findings, carry-in resolution, and
    AUT2-readiness decision.
  - `docs/product/mcp-contracts.md`: promoted demo-critical tools to
    live-proven where verified, documented `job_status` poll/terminal states,
    recorded `rag_search_case` live-catalog absence, and clarified
    `run_command` versus `run_command_job`.
  - `docs/product/ai-agent-journey.md`: added orientation-versus-gate caveat,
    RAG availability note, and job recovery hints.
- Code fixes:
  - `packages/sift-gateway/src/sift_gateway/job_tools.py`: `job_status` now
    validates durable job IDs as UUIDs before DB lookup and returns typed
    `invalid_job_id`; unexpected job-tool exceptions now return generic
    `internal_error` to the agent while logging detail server-side.
  - `packages/sift-core/src/sift_core/agent_tools.py`: `run_command`
    description now states it is synchronous and returns a non-pollable `rc-*`
    receipt; points long-running/parallel work to `run_command_job`.
  - `packages/sift-gateway/src/sift_gateway/job_tools.py`: `run_command_job`
    description now states it returns a pollable UUID for `job_status`.
  - `packages/sift-core/src/sift_core/execute/security.py`: evidence-dir
    deletion denial now tells the agent to hand back to operator/approved
    evidence workflow, not to leave the MCP harness and run `rm` directly.
  - `packages/sift-core/src/sift_core/execute/tools/discovery.py`: sanitized
    `get_tool_help("run_command")` stderr-control example so response guard no
    longer self-redacts an absolute-path example.

Live AUT1 evidence:

- AUT1 worker reported 17 direct Gateway MCP calls against
  `case-v1gate-06081857` / `57a06521-c9b8-4654-92ac-42b4f2bb0915`.
- Promoted to live-proven by MCP calls: `evidence_info`, `capability_guide`,
  `get_tool_help`, `list_existing_findings`, `manage_todo`, `job_status`,
  `run_command`, and `run_command_job`.
- Surface scores: Discoverability 2, Sufficiency 2, Context efficiency 2,
  Composability 3, Error recovery 2, Provenance 3, Security 3, Autonomy
  friction 2.
- Live side effects reported: one completed probe TODO (`TODO-aut1-001`),
  benign audit entries, one succeeded `run_command_job`; no findings staged and
  no evidence mutated.

Validation:

- AUT1 branch: `uv run pytest
  packages/sift-gateway/tests/test_mvp_binding_job_tools.py`: `8 passed`.
- AUT1 branch: `uv run pytest
  packages/sift-gateway/tests/test_mvp_d2_jobs_and_authority.py
  packages/sift-gateway/tests/test_mvp_b1_policy_redaction.py`: `27 passed`.
- Conductor additions before merge:
  `uv run pytest packages/sift-core/tests/test_execute_executor.py`: `33 passed`.
- Conductor additions before merge:
  `uv run pytest packages/sift-gateway/tests/test_mvp_binding_job_tools.py`:
  `9 passed`.
- Conductor additions before merge repeated the gateway D2/B1 suites:
  `27 passed`.
- AUT1 branch `python3 scripts/validate_docs.py`: OK.
- AUT1 branch `python3 scripts/validate_migration_docs.py`: OK.
- AUT1 branch `git diff --check`: clean.
- Touched-file secret-shape scan: no matches.
- Pending after this integration edit: root validators and final commit.

Remaining gates before BATCH-AUT2:

- AUT1-B1 (HIGH): `case_info`/`evidence_info` still use file-backed
  evidence-chain orientation and can contradict the DB-authority evidence gate.
  Fix by making DB-active orientation reflect `app.evidence_gate_status`, or at
  minimum prepare the demo case so file manifest and DB gate agree before AUT2.
- AUT1-B2 (MEDIUM): `rag_search_case` was absent from the live agent catalog in
  the AUT1 deployment because `rag_query_service` was unwired. Before AUT2,
  live-prove Gateway has RAG service wired and the agent principal has
  `tool:rag_search_case` or `mcp:*`.
- AUT1-B3/B4/B5/B6 fixes require live Gateway redeploy/restart before they are
  live-proven.

Next:

- Run BATCH-INST1 / conductor remediation next, focused on live deploy and
  readiness: sync root to the VM, restart Gateway/worker, verify
  `rag_search_case` appears in the MCP catalog, verify pgvector corpus counts,
  verify `job_status` invalid-id behavior is fixed live, verify env-file
  permissions and per-case `agent_runtime` ACLs, and verify demo evidence
  preparation path.
- Then run BATCH-AUT2 against the hackathon E01/raw-memory demo case through MCP
  only after portal create/activate/register/seal and portal-issued agent
  credential handoff.

### 2026-06-09 - Wave 1 product docs and security assessment integrated

Status: DONE

Changed:

- Integrated the three Wave 1 post-MVP QA branches into root `revamp/spg-v1`:
  - BATCH-PDOC1: worker commit `eca5b10`, merge
    `Merge BATCH-PDOC1 product architecture docs`.
  - BATCH-PDOC2: worker commit `d0fcc31`, merge
    `Merge BATCH-PDOC2 API and MCP contracts`.
  - BATCH-SEC1: worker commit `73f5d38`, merge
    `Merge BATCH-SEC1 security assessment docs`.
- Marked BATCH-PDOC1, BATCH-PDOC2, and BATCH-SEC1 complete in
  `task-batches.md`.
- Reconciled the PDOC2 interaction-model handoff into
  `docs/product/interaction-model.md`: HMAC challenge/action loop,
  pre-seal gate handback, DRAFT-to-portal commit boundary, phase-ordered
  tool/job polling loop, and redaction recovery as an operator/debug-only path,
  not an agent bypass.
- Left BATCH-INST1 open as the independent installer/component hardening QA
  stream.

Validation:

- Worker validation reported by the parallel orchestrator: PDOC1/PDOC2/SEC1
  each passed `python3 scripts/validate_docs.py`, `git diff --check`, and
  no-raw-secret shape checks.
- Conductor re-ran before branch commits: PDOC1/PDOC2/SEC1 each passed
  `python3 scripts/validate_docs.py` and `git diff --check`.
- Root `python3 scripts/validate_docs.py`: OK.
- Root `python3 scripts/validate_migration_docs.py`: OK.
- Root `git diff --check`: clean.
- Root product/migration docs secret-shape scan for DSNs, key-like tokens,
  private-key headers, and assignment-shaped passwords: no matches after
  excluding a false-positive short `sk-` substring in `task-batches.md`.

Next:

- Run BATCH-INST1 when ready: verify installer/setup idempotency, service
  restart/health, `~/.sift/*.env` permissions, per-case `agent_runtime` ACLs,
  OpenSearch setup, and pgvector RAG import reproducibility.
- Launch BATCH-AUT1 after this integration validation passes. AUT1 carry-ins:
  promote source-derived MCP tools to live-proven or file defects
  (`evidence_info`, `capability_guide`, `get_tool_help`,
  `list_existing_findings`); verify demo-agent scopes cover all demo-critical
  tools; resolve `run_command` vs `run_command_job` description ambiguity;
  assess command pipeline/redirect/stderr and evidence-write gaps; clarify
  `capability_guide` empty results; advertise `job_status` poll/terminal-state
  contract; score SEC-A2 challenge reset behavior and SEC-D1 regex-scanner
  residual from the agent autonomy perspective.

### 2026-06-09 - Post-MVP QA and product documentation phase opened

Status: DONE

Changed:

- Created `docs/product/**` as the product documentation workspace for
  architecture, data/process lifecycles, operator journey, AI-agent journey,
  interaction model, API contracts, MCP contracts, autonomy assessment, security
  architecture, security assessment, code structure, limitations/improvements,
  and demo runbook.
- Kept `docs/migration` as the execution tracker/log only. No new migration
  runbook files were added.
- Added post-MVP batch tracking to `task-batches.md`: BATCH-PQA0, BATCH-PDOC1,
  BATCH-PDOC2, BATCH-SEC1, BATCH-INST1, BATCH-AUT1, BATCH-AUT2, and BATCH-FRZ1.
- Made AI-agent autonomy a first-class acceptance axis. BATCH-AUT1 will score
  MCP tools for discoverability, sufficiency, context efficiency,
  composability/parallel safety, error recovery, provenance, security, and
  autonomy friction before the demo-case benchmark.
- Locked the execution order: PQA0 first; then PDOC1/PDOC2/SEC1/INST1 in
  parallel; then AUT1 as the serial MCP/autonomy gate; then AUT2 and remaining
  remediation in parallel; FRZ1 last for final demo freeze.

Validation:

- `python3 scripts/validate_docs.py`: OK.
- `python3 scripts/validate_migration_docs.py`: OK.
- `git diff --check`: clean.

Next:

- Start Wave 1 from clean `revamp/spg-v1` worktrees: PDOC1, PDOC2, SEC1, and
  INST1. If only three workers are available, run PDOC1/PDOC2/SEC1 first and
  start INST1 immediately after or as a fourth independent worker.
- Do not start AUT1 until PDOC2 has captured the live MCP inventory and PDOC1
  has the architecture/journey draft. AUT1 is the gate that decides whether the
  MCP surface is good enough for autonomous DFIR or needs fixes before the demo
  benchmark.
