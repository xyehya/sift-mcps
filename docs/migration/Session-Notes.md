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

### 2026-06-08 - Full RAG corpus pgvector import landed

Status: DONE

Post-BATCH-V1 review found that the live pgvector RAG smoke loaded only the
small bundled JSONL corpus (`4318` chunks) through `rag-mcp-seed-pgvector`. The
legacy/full forensic RAG grounding corpus is the downloaded Chroma release bundle
(`rag-index.tar.zst`, expected `20K+` records) installed by `install.sh`; that
bundle was not imported into Supabase pgvector during BATCH-V1.

Fix added and proved in this session:

- Added `rag-mcp-import-chroma-pgvector`, which opens the downloaded Chroma
  collection (`ir_knowledge`), streams documents/metadata/768-d BGE embeddings,
  and writes them to `app.rag_collections`, `app.rag_documents`, and
  `app.rag_chunks` as shared `kind='knowledge'`, `case_id NULL` rows.
- The importer treats Chroma as a source artifact only. Query serving remains
  Gateway -> Supabase pgvector through `rag_search_case`; agents never query
  Chroma or receive DB credentials/paths.
- The importer preserves real Chroma/BGE embeddings, rejects embedding-model
  mismatches by default, drops path-like metadata keys, and emits stable opaque
  provenance IDs for imported documents/chunks.
- `install.sh` now runs the importer after `download_rag_index` in non-core
  installs when `SIFT_CONTROL_PLANE_DSN` is available, with degraded-mode
  warnings if the download/import is missing or fails.
- Live VM download used the existing host proxy through an SSH remote tunnel:
  host `127.0.0.1:10808` forwarded into the VM as `127.0.0.1:10809`, then
  `HTTPS_PROXY=socks5h://127.0.0.1:10809` for the GitHub release downloader.
  Release tag: `rag-index-v2026.03.01`; extracted Chroma collection count:
  `22268`.
- Installed VM venv SOCKS helpers `PySocks` and `socksio` for the downloader /
  Hugging Face verifier path, then cached the BGE query model once through the
  proxy. Token material and VM credentials were not written to repo files.
- Imported the release bundle into live Supabase pgvector:
  `rag-mcp-import-chroma-pgvector --chroma-dir
  packages/forensic-rag-mcp/data/chroma` returned `status=ok`,
  `chroma_records=22268`, `documents=22268`, `chunks=22268`, `skipped=0`.
- Live DB proof after import: `app.rag_chunks=26586`, all `kind='knowledge'`,
  all `case_id NULL`, `case_bound_chunks=0`; `22268` chunks carry
  `seed_source='chroma_release_pgvector'` across `67` Chroma-derived
  collections.
- Live Gateway MCP proof used a short-lived Supabase agent principal bound to
  active case `57a06521-c9b8-4654-92ac-42b4f2bb0915`; the principal was revoked
  immediately after the check. `rag_search_case` returned `status=ok`,
  `count=5`, `kinds=["knowledge"]`, `case_ids=[None]`,
  `source_refs_are_chroma=true`, and the result leak scan found no `/cases`,
  `/home`, loopback, DB DSN, service-role/password, OpenSearch, or
  `SIFT_CONTROL_PLANE_DSN` strings. Top returned titles included
  `References - SANS FOR518`, `Data Exfiltration via an MCP Server used by
  Cursor`, `File Name Lookup Enrichment`, `Memory Forensics - Topics Covered`,
  and `MacOSCoreAnalyticsFile`.

Validation:

- `uv run pytest packages/forensic-rag-mcp/tests/test_pgvector_chroma_import.py
  packages/forensic-rag-mcp/tests/test_pgvector_seed.py
  packages/forensic-rag-mcp/tests/test_pgvector_store.py`: `19 passed`.
- `bash -n install.sh`: OK.
- `uv run --extra full rag-mcp-import-chroma-pgvector --help`: OK.
- Local dry-run against the default path correctly reports the Chroma index is
  absent (`packages/forensic-rag-mcp/data/chroma` does not exist in this
  checkout). The live VM import/search proof above closes B-MVP-18.

### 2026-06-08 - BATCH-V1 live cutover completed

Status: DONE

Ran the live BATCH-V1 cutover/smoke on the SIFT VM from integrated root
`revamp/spg-v1`. The VM was synced to `~/sift-mcps-test`, Gateway and the durable
job worker were restarted with `~/.sift/control-plane.env`, and the demo journey
completed through portal + Gateway MCP without exposing service secrets or
absolute evidence paths to the agent surface.

Live VM readiness:

- Root disk was expanded after the run hit space pressure: `/` now has a 200G
  logical volume with roughly 94G free. Docker uses the VM reverse SOCKS proxy
  for image pulls.
- Gateway health on `https://127.0.0.1:4508/api/v1/health`: `status=ok`,
  Supabase `status=ok`, evidence root `status=ok`.
- OpenSearch was started through Docker after proxy configuration; cluster
  health is `yellow` on the single-node VM and indexing/search works.
- Supabase migration fixup applied live through `psycopg` because the VM image
  lacks `psql`: new additive migration
  `202606081602_investigation_iocs_content_hash.sql` adds
  `app.investigation_iocs.content_hash`. This aligns IOC authority rows with the
  K2 store's hash-guarded approve/report contract. The self-hosted DB has no
  `supabase_migrations.schema_migrations` table to stamp.

Live journey evidence:

- Active case: `case-v1gate-06081857`, UUID
  `57a06521-c9b8-4654-92ac-42b4f2bb0915`, active case authority from Postgres.
- Evidence seal: `evidence/v1-gate.log` was registered/sealed with DB proof
  export `d93bc9db-f283-4b23-ad81-0c2c3a3b7cb1`; `evidence/v1-ingest.jsonl`
  registered/sealed as evidence `f8c0c7bf-1838-4ca6-b2c1-38c436ff25b0`,
  `manifest_version=2`, proof export `d3736f53-4242-43ec-9416-76d326388c19`,
  proof hash
  `sha256:e7d20083ce0b15ae975f37ccb51693f8f721098841432935dd28f5cce1e473bc`.
- Agent issuance: live agent token was issued with default case binding to
  `57a06521-c9b8-4654-92ac-42b4f2bb0915`. Token material stayed VM-local.
- Evidence gate: pre-seal agent execution failed closed with the unsealed
  evidence gate; post-seal `run_command_job`
  `884c3641-7bfa-4801-a3de-7eb7b69f0d2e` succeeded and redacted absolute-path
  output.
- OpenSearch ingest: `ingest_job`
  `e6572af3-e894-4b06-ab8a-37db87c7246d` succeeded for
  `evidence/v1-ingest.jsonl`; provenance
  `3f90b65a-b829-4ef8-ac2b-419b8f3c65e6`, indexed `1`, bulk failures `0`,
  index `case-57a06521-c9b8-4654-92ac-42b4f2bb0915-json-v1-ingest-host01`.
  DB provenance, `app.opensearch_indices`, and
  `app.host_identity_decisions` all recorded the same job/provenance/index.
- RAG: `rag_search_case` returned `status=ok`, `count=3`, `kinds=["knowledge"]`,
  `has_abs_path=false` from Supabase pgvector. Top titles were
  `Intelligence Requirements Definition`, `SIFT Workstation`, and
  `oledump.py Overview`; shared knowledge rows retain `case_id NULL`.
- Report approval/export: agent staged finding `F-hermes-v1-gate-001`; portal
  HMAC re-auth approved it (`authority=db`, `approved=1`). Report
  `41e0a5ff-4e43-4a38-8e9c-5ce128160a16` was generated/saved/downloaded with
  the approved finding, IOC/MITRE sections, and DB sealed custody appendix.
  Export size was 5570 bytes; a leak scan found no `/cases`, `/home`,
  `127.0.0.1`, Supabase/service-role/password, Postgres, or OpenSearch strings.
- Custody proof export: DB proof export
  `f06b6bb7-ae55-4d44-85be-d34d8c198668`, `manifest_version=2`, proof hash
  `sha256:e7d20083ce0b15ae975f37ccb51693f8f721098841432935dd28f5cce1e473bc`.

Live defects found and fixed in this cutover:

- DB audit actor FK: Supabase JWT agent principals no longer populate
  `actor_token_id` with a non-token principal UUID.
- Gateway local MCP handlers now pass the gateway instance to job/RAG handlers.
- Agent `job_status` accepts the token's `case_id`/`default_case_id` for the job
  case.
- OpenSearch ingest now handles sealed single JSON/JSONL/NDJSON evidence files
  without leaking paths or requiring directory discovery.
- Report generation now uses DB custody for the visible evidence-chain block
  when the portal supplies custody, avoiding stale legacy-manifest warnings.
- Added `202606081602_investigation_iocs_content_hash.sql` so IOC rows can use
  the same content-hash authority contract as findings/timeline.

Validation:

- Local focused tests after fixes: core report/K2 store `25 passed`; gateway
  audit/local-binding/job authorization `30 passed`; OpenSearch ingest
  `10 passed`.
- Live report export leak scan: clean for local paths and service-secret terms.
- `bash -n install.sh`: OK.
- `uv lock --check`: OK.
- `python3 scripts/validate_docs.py`: OK.
- `python3 scripts/validate_migration_docs.py`: OK.
- `git diff --check`: clean.

### 2026-06-08 - V1 enablers integrated before live cutover

Status: DONE

Integrated the remaining V1 enabler tracks into root `revamp/spg-v1` from clean
worktrees based on `49fb044`. BATCH-V1 is still not complete; the next session
should run the live VM cutover/smoke journey against the integrated root.

Integration:

- Auth/installer/agent: worker commit `58c669b`, merge `84404ba`. Closes
  B-MVP-8 and B-MVP-9 by writing `~/.sift/control-plane.env`, keeping DSN/pepper
  out of gateway YAML, creating/repairing Supabase Auth users with matching
  `app.operator_profiles`, and issuing MVP agents with global tool scopes plus
  `default_case_id` bound to the active DB case.
- RAG: worker commit `db47c71`, merge `2c34520`. Closes B-MVP-11 and B-MVP-15 by
  exempting Gateway-local `rag_search_case` from proxy case-arg rewriting/denial
  and adding `rag-mcp-seed-pgvector` plus pgvector collection/document/chunk
  upserts. Knowledge RAG is treated as a shared forensic case-study/reference
  corpus (`kind='knowledge'`, `case_id NULL`); the active case remains only the
  Gateway policy/audit boundary and the filter for future `kind='derived'` rows.
- Runtime/evidence journey: worker commit `0acd60f`, merge `09a0023`. Closes
  B-MVP-12, B-MVP-13, and B-MVP-14 by applying per-case ACLs for
  `agent_runtime`, making the local password/HMAC re-auth bridge explicit as MVP
  behavior (`reauth_method=local_hmac_mvp_bridge`), and making register+seal the
  MVP evidence journey (`registration_mode=atomic_register_and_seal`). The DB
  seal path already calls `app.evidence_register` before `app.evidence_seal`.

Branch validation before integration:

- Auth/installer/agent: `bash -n install.sh`; `git diff --check`; dashboard
  token/auth/bootstrap tests `58 passed`; gateway Supabase/JWT auth tests
  `57 passed`.
- RAG: Gateway RAG/proxy/local-tool tests `14 passed`; forensic pgvector store
  and seed tests `15 passed`; `uv lock --check`; seed CLI dry run; Ruff targeted
  check; `git diff --check`.
- Runtime/evidence: portal case/evidence DB/intake tests `87 passed`; Ruff
  targeted check; `git diff --check`.

Post-integration validation on root `revamp/spg-v1`:

- `python3 scripts/validate_docs.py`: OK.
- `bash -n install.sh`: OK.
- `uv lock --check`: OK.
- `uv run --extra full rag-mcp-seed-pgvector --dry-run --max-files 1
  --max-records-per-file 2`: OK (`store=supabase_pgvector`, 1 collection,
  1 document, 2 chunks).
- Pytest: dashboard auth/bootstrap/token suites `58 passed`; gateway
  Supabase/JWT + active-case/RAG/local binding suites `71 passed`; forensic
  pgvector store/seed suites `15 passed`; portal case/evidence DB/intake suites
  `87 passed`.
- `git diff --check`: clean.

Next:

- Run BATCH-V1 live on the SIFT VM from root `revamp/spg-v1`: apply migrations,
  restart gateway/job worker with the new control-plane env, seed pgvector
  knowledge, create/activate a case, register+seal evidence, issue an agent,
  prove denied and allowed `run_command`, drive `ingest_job`/OpenSearch,
  `rag_search_case`, report export, and custody proof export.

### 2026-06-08 - K2-K5 integrated, K6 landed, authority cutover closed

Status: DONE

Integrated the four parallel authority-cutover branches into `revamp/spg-v1`,
ran BATCH-K6 as the tamper-regression gate, and closed the DB-active file-authority
cutover (B-MVP-16). BATCH-V1 is now unblocked.

Integration:

- Cherry-picked the four single-commit worker branches onto `revamp/spg-v1` for
  linear history: K4 `89abafe`, K5 `bcba5db`, K2 `5b1cf9c`, K3 `9048da6`
  (K3 last to absorb the K2/K3 `portal_services.py` + `routes.py` overlap; git
  auto-merged cleanly because K2 = `InvestigationService` and K3 =
  `EvidenceAuthorityService` touch disjoint regions).
- `59e0267`: deduped the colliding `202606081600_*` migration version. K2
  (`investigation_authority`) and K4 (`host_identity`) both landed at
  `202606081600` on parallel branches; bumped host_identity to `202606081601`
  (no SQL change; neither depends on the other) so each has a unique Supabase
  migration version. Updated its structural test path.
- Post-integration full suites green: sift-core 424, sift-gateway 388,
  case-dashboard 354, opensearch-mcp 995 (+71 skip), tests/db 58.

BATCH-K6 (`b76eba9`) - portal/report tamper regression + DB-active file-authority
removal:

- `reporting.py`: in DB-active mode report verification reconciles against the
  per-row DB `content_hash` (K2) via new `reconcile_verification_db` and never
  reads the local verification JSONL ledger; the file-ledger path is retained
  only for legacy non-DB mode. Adds a `verification_authority` label.
- `portal_services.py`: `InvestigationService.audit_events` reads the audit trail
  from `app.audit_events` scoped to the case.
- `routes.py`: `GET /api/audit/{finding_id}` sources the finding's audit_ids from
  the DB investigation record and entries from `app.audit_events` in DB-active
  mode; `findings.json` / `audit/*.jsonl` are consulted only in legacy mode.
- `audit_ops.py`: the file-mirror summary is explicitly labelled
  `legacy-file-mirror` (non-authoritative) in DB-active mode and can derive from
  an injected DB reader.
- `backup_ops.py`: backup manifest marks `authority: db-postgres` +
  `snapshot_only` in DB-active mode so a backup cannot masquerade as authority.
- B-MVP-17 decided (see register): pre-context denials stay on the local audit
  mirror for the MVP; hardened DB projector deferred to V1. Locked by test.

Validation:

- Full suites green after K6: sift-core 435 (+11 K6), sift-gateway 392 (+4 K6),
  case-dashboard 356 (+2 K6), opensearch-mcp 995, tests/db 58. `git diff --check`
  clean on each commit.
- `python3 scripts/validate_docs.py`: OK.
- Resolved this run: B-MVP-10 (DONE, K2), B-MVP-16 (DONE, K1-K6), B-MVP-17
  (DONE/decided, K6).
- Not run: live-VM apply of the integrated migrations and the live end-to-end
  journey (BATCH-V1).

Next:

- **Resume BATCH-V1** end-to-end validation and cutover on the live SIFT VM. The
  authority cutover (K1-K6) no longer blocks approval, report, ingest status, RAG
  verification, or run-command proof. V1 carry-ins to exercise live: the
  K2 `PostgresInvestigationStore.apply_review` `WHERE version=%s` atomic guard
  under READ COMMITTED concurrency; live apply ordering of the two
  `202606081600/...1601` migrations; the K4 Gateway-side host-fix receipt for the
  pure agent→proxy path; and the still-open V1 enablers B-MVP-8 (installer
  operator-profile insert + control-plane env), B-MVP-9 (case-bound agent
  issuance), B-MVP-11 (`rag_search_case` proxy denial), B-MVP-12 (agent_runtime
  case-dir ACL), and B-MVP-15 (pgvector population path).

### 2026-06-08 - BATCH-K2/K3/K4/K5 landed on worker branches

Status: DONE

Ran the four parallel authority-cutover batches in dedicated worktrees off
`revamp/spg-v1`. Each is one commit on its own branch (not yet integrated into
`revamp/spg-v1`); all reuse the K1 `AuthorityContext`/DB-audit contracts and none
edited `docs/migration`.

Landed (per-branch):

- BATCH-K2 `5a9fe4b` on `revamp/mvp-k2-investigation-db-authority` - typed
  `InvestigationAuthorityStore` port + `PostgresInvestigationStore`; `case_manager`
  findings/timeline/IOC/TODO write DB-first and fail closed; portal JSON->DB sync
  gated off by default; portal approve/reject/edit + report reads route to DB
  authority with optimistic `version` locking and `reauth_audit_event_id`. New
  migration `202606081600_investigation_authority.sql`. Tests: sift-core 398,
  gateway 377, dashboard 354, db 52.
- BATCH-K3 `662c6aa` on `revamp/mvp-k3-evidence-proof-cutover` - evidence gate
  reads only `app.evidence_gate_status`; added seal-tamper detection
  (`_detect_seal_tamper` -> `evidence_mark_violation`), DB-derived proof export
  (re-hash mounted bytes -> `evidence_record_proof_export`), and `anchor_db_proof()`
  Solana-as-external-proof-only. Tests: sift-core 386, gateway 382, dashboard 350,
  db 49.
- BATCH-K4 `717a548` on `revamp/mvp-k4-opensearch-host-authority` - new migration
  `202606081600_host_identity.sql` (`app.host_identity_decisions` ledger +
  `record_host_identity_decision` + `opensearch_ingest_status` RPC); DB-active
  ingest status from durable jobs/provenance; `host-dictionary.yaml` is parser-compat
  only and `dict_path` no longer leaked to agents in DB-active mode; canonical
  `opensearch_fix_host_mapping` + deprecated `opensearch_host_fix` alias preserved;
  MCP surface golden regenerated. No Gateway registry edits. Tests: opensearch-mcp
  995, sift-core 384, gateway 371, db 55.
- BATCH-K5 `63b5f48` on `revamp/mvp-k5-run-command-authority-isolation` - closed the
  root env-leak defect (sandbox subprocess inherited the full worker env incl.
  `~/.sift/supabase.env` secrets). New `runtime_acl.py` (`build_sandbox_env()`
  allowlist + post-allowlist secret deny; authority-path write/redirect refusal);
  scrubbed env on every `Popen`; path-free DB receipts; fixed a latent non-UUID
  `provenance_id` bug in the `complete_job` path. Tests: sift-core 408, gateway 371,
  db 49, +24 new K5 tests.

Two known shared-file overlaps to reconcile at integration (each batch on its own
branch, so only a merge concern): K2 and K3 both touch
`sift_gateway/portal_services.py` and `case-dashboard routes.py` (changes are
service-scoped and additive - K2 only added a `legacy_sync=False` kwarg to the base
service and edited `InvestigationService`; K3 only added `EvidenceAuthorityService`
methods + evidence routes); K4 and K5 are disjoint and neither touched
`job_worker.py`.

Both K2 and K4 introduce a `202606081600_*` migration; the two filenames differ
(`_investigation_authority` vs `_host_identity`) so they coexist, but confirm
timestamp ordering at integration.

Validation:

- All four worker suites green as listed above; `git diff --check` clean on each.
- Per-batch `python3 scripts/validate_docs.py` reported OK where run.
- Not run: cross-branch integration build and live-VM apply of the two new
  `202606081600_*` migrations (deferred to integration + BATCH-V1, consistent with
  prior K-series).

Next:

- Integrate K2-K5 into `revamp/spg-v1` (resolve the K2/K3 `portal_services.py` +
  `routes.py` overlap additively; confirm `202606081600_*` migration ordering), then
  run BATCH-K6 as the tamper-regression gate. K6 must cover: end-to-end portal/report
  tamper regression for findings/timeline/todos/iocs + approvals (K2), the seal-tamper
  / proof-export verify path (K3), DB-active ingest/host authority vs local-file
  tampering (K4), the run_command authority-write deny path (K5), and the B-MVP-17
  pre-context denial DB-audit decision. BATCH-V1 stays blocked until K1-K6 close the
  cutover.

### 2026-06-08 - BATCH-K1 landed with security-review correction

Status: DONE

Changed:

- Landed BATCH-K1 as `0e9577a` on `revamp/spg-v1`.
- Added the `AuthorityContext` contract in `sift_core.active_case_context`
  with principal, principal type, tool scopes, evidence-gate snapshot fields,
  request ID, DB-active flag, and audit event IDs.
- Hardened `CaseManager._require_active_case()` so DB-active mode uses the
  request/worker authority context only and fails closed instead of reading
  `SIFT_CASE_DIR` or `~/.sift/active_case`.
- Set the durable job worker CLI to `SIFT_DB_ACTIVE=1` after requiring a
  control-plane DSN.
- Added `DbAuditWriter` for DB-first `app.audit_events` writes and wired the
  Gateway MCP audit envelope to reserve `requested` rows and write
  result/failure receipts. Mutating calls fail closed when the required
  pre-dispatch DB audit write cannot persist.
- Conductor security review found one pre-merge audit gap: the new DB audit
  envelope initially ran after proxy/evidence-gate denials. Fixed it by moving
  `AuditEnvelopeMiddleware` after case-context setup but before proxy active
  case and evidence gate middleware, and by marking evidence-gate block results
  as MCP errors so DB result receipts record `failure`.
- Root pre-existing candidate patches were stashed before integration as
  `stash@{0}: pre-k1-root-candidate-patches-20260608` so K1 could land cleanly
  without mixing unreviewed work.

Validation:

- Passed: `uv run pytest` in `packages/sift-core` - 384 tests.
- Passed: `uv run pytest` in `packages/sift-gateway` - 371 tests.
- Passed: `uv run pytest tests/db` - 49 tests.
- Passed: `git diff --check` before K1 commit.
- Security report generated and validated:
  `/tmp/codex-security-scans/sift-mcps/ef52331_20260608T141952Z/report.md`
  and `report.html`. Result: no remaining reportable findings; K1-001 fixed
  before merge.

Next:

- Launch BATCH-K2, BATCH-K3, BATCH-K4, and BATCH-K5 in parallel worktrees from
  `revamp/spg-v1`.
- BATCH-K6 follows after K2-K5 and must include tamper regressions plus the
  pre-context denial DB-audit decision tracked as B-MVP-17.

### 2026-06-08 - Authority cutover model frozen

Status: DONE

Changed:

- Added the authority cutover impact model to `Migration-Spec.md`. DB-active
  mode now has an explicit invariant: critical mutable DFIR state cannot be
  decided from case-local files, env pointers, or legacy JSON/JSONL artifacts.
- Classified remaining files into authority, append-only ledger, evidence
  bytes, derived/rebuildable state, immutable proof/export artifacts, and
  legacy compatibility. Postgres is authority for mutable state; Supabase
  Storage/case files are export/workspace/debug/parser-compatibility only.
- Mapped the discovered split-brain touchpoints to implementation files:
  active case resolution, audit writer, evidence manifest/ledger, findings,
  timeline, TODOs, IOCs, approvals, reports, OpenSearch ingest status/manifests,
  host identity, and `run_command`.
- Locked the hostname carve-out: parser/indexer hostname detection is required
  derived metadata for OpenSearch index naming and `host.name`/`host.id`.
  `opensearch_fix_host_mapping` is canonical; `opensearch_host_fix` remains a
  deprecated alias. Host corrections may mutate derived OpenSearch/host
  metadata only, not case/evidence/report authority.
- Locked the Solana carve-out: optional SPL Memo anchoring remains proof export
  only. DB custody chain heads and custody events are authority; anchor proof is
  recorded/exported through `app.evidence_proof_exports` when configured.
- Split the blocking authority cutover into K-series batches:
  K1 authority context + DB audit, K2 core investigation DB authority, K3
  evidence/proof/Solana export, K4 OpenSearch/host identity derived-state
  cutover, K5 `run_command` authority isolation, and K6 portal/report tamper
  regression. BATCH-V1 now depends on K1-K6.

Validation:

- Passed: `python3 scripts/validate_docs.py`.
- Passed: `python3 scripts/validate_migration_docs.py`.

Next:

- Launch BATCH-K1 first. After K1 lands, K2-K5 can run in parallel worktrees;
  K6 follows as the tamper/regression gate before BATCH-V1 resumes.

### 2026-06-08 - BATCH-V1 live VM validation partial

Status: IN_PROGRESS

First real end-to-end run on the live SIFT VM. Prior waves were unit/structural;
this run deployed the integrated MVP to `~/sift-mcps-test`, applied all
migrations to live Supabase, re-pointed Gateway to the control plane, and drove
the Phase 3 journey through portal + MCP.

Validated live:

- Migrations: all `supabase/migrations/*.sql` apply clean in timestamp order to
  fresh Supabase. Schema, RPCs, and pgvector are present.
- Health: Gateway reports `status: ok`; Supabase and control-plane DB are
  connected; evidence root is OK after F-MVP-5.
- Operator bootstrap and forced reset: invited operator can log in, receives
  `must_reset`, completes forced reset, and transitions `invited -> active`
  after F-MVP-6.
- Case create/activate: persisted to `app.cases`; active case is DB authority
  (`deployment_active_case`, `authority: postgres`), not a file pointer. Frozen
  case naming confirmed with `case-v1smoke-06081250`.
- Evidence detect/register/seal: DB evidence detect path works; seal with HMAC
  re-auth writes custody events; `app.evidence_gate_status` returns `sealed`
  after F-MVP-7.
- Custody hash chain: `EVIDENCE_DETECTED -> EVIDENCE_REGISTERED ->
  MANIFEST_SEALED`, append-only and prev/event-hash linked.
- Agent credential + MCP: one-time agent credential issued; MCP connects through
  `/mcp`; scoped catalog exposes the expected tools including `ingest_job`,
  `run_command_job`, `job_status`, and `rag_search_case`.
- Path redaction and evidence gate: `case_info` redacts `case_dir`; pre-seal
  agent calls fail closed with `evidence_chain_unsealed`; post-seal calls allow.
- Agent writes and command controls: `manage_todo`, `record_timeline_event`, and
  provenance-enforced `record_finding` work at the agent surface; `run_command`
  deny floor blocks `bash` and redacts error paths.
- RAG status: new pgvector schema and `rag_search_case` tool surface exist, but
  live Supabase row counts are `app.rag_collections=0`, `app.rag_documents=0`,
  and `app.rag_chunks=0`. Any successful VM knowledge/RAG-looking answers came
  from legacy `kb_*` forensic-rag/Chroma or core forensic-knowledge guidance,
  not from the new Supabase pgvector path.

Defects fixed on this branch:

- F-MVP-5: `health.py` Supabase health probe omitted the `apikey` header, so
  Kong returned 401. The probe now sends the configured anon key as `apikey`.
- F-MVP-6: `supabase_auth.py` rejected `invited` operators before a session
  cookie existed, making `/api/auth/forced-reset` unreachable. Login now allows
  `active` and `invited`; resolver/protected actions remain active-only.
- F-MVP-7: `202606081000_evidence_custody.sql` used pgcrypto `digest()`, which
  was unresolved under Supabase's extension schema and the function search path.
  Custody hashing now uses built-in `sha256(v_payload::bytea)`.

Validation:

- Passed live/unit after fixes: sift-gateway 361, sift-core 376,
  case-dashboard 350, forensic-rag 18, tests/db 48, opensearch job-ingest 8.
- Passed: `python3 scripts/validate_docs.py`,
  `python3 scripts/validate_migration_docs.py`.

Remaining before BATCH-V1 can be checked:

- Resolve B-MVP-8/9/10 first. B-MVP-10, the agent file-to-DB investigation
  bridge, is the blocker for portal approval and approved-only report.
- Then drive `ingest_job`/`job_status` with the worker, populate/verify
  pgvector RAG, drive `rag_search_case`, allowed `run_command`, approved-only
  report export, and custody proof export.

Live VM replay notes for the next session:

- VM host/user: `192.168.122.81` / `sansforensics`. Use local `SSHPASS` or SSH
  agent configuration; do not commit the test VM password.
- Gateway/portal: `https://192.168.122.81:4508`,
  `https://192.168.122.81:4508/portal/`.
- VM runtime: Ubuntu 24.04, `/usr/bin/python3.12`, uv at
  `/home/sansforensics/.local/bin/uv`.
- Supabase project: `/home/sansforensics/supabase-project`; sparse source clone:
  `/home/sansforensics/supabase-src-v1.26.05`; pinned Supabase tag `v1.26.05`,
  commit `23b55d63485e51919d1b4c05b03d33a9edc1f06d`. Supabase secrets stay in
  VM-local `.env` / `~/.sift/control-plane.env` files only.
- Deployed V1 copy: `~/sift-mcps-test`; all migrations applied; Gateway
  re-pointed to the control plane; old Gateway unit/config backed up on the VM
  as `*.bak.<ts>`.
- Current live state: operator `examiner@operators.sift.local` active owner;
  active sealed case `case-v1smoke-06081250` with UUID
  `31831057-0de9-4781-b6fd-c38043f0aa23`; global `mcp:*` test agent
  `hermes-v1-global` with token stored VM-local in `~/.sift/agent-token.txt`.

Replay command patterns:

- Sync host to VM:
  `rsync -avz --exclude '.git' --exclude '.venv' --exclude '__pycache__' --exclude '*.pyc' /home/yk/AI/SIFTHACK/sift-mcps/ sansforensics@192.168.122.81:~/sift-mcps-test/`
- VM command wrapper:
  `sshpass -e ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 '<command>'`
- VM dependency sync:
  `cd ~/sift-mcps-test && UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never ~/.local/bin/uv sync --extra core --group dev --python /usr/bin/python3.12`
- Start/check Supabase:
  `cd ~/supabase-project && docker compose up -d --wait && docker compose ps`
- Apply migrations from a fresh DB:
  `for m in $(ls ~/sift-mcps-test/supabase/migrations/*.sql | sort); do cat "$m" | docker compose exec -T db psql -U postgres -d postgres -v ON_ERROR_STOP=1; done`
- Restart/check Gateway:
  `systemctl --user restart sift-gateway && curl -s -k https://localhost:4508/api/v1/health | python3 -m json.tool`

### 2026-06-08 - BATCH-L1 landed (live service binding before V1)

Status: DONE

Changed:

- Resolved B-MVP-5: Gateway startup now wires portal service slots to live
  Postgres-backed adapters for evidence/custody, investigation records, report
  metadata, and D2 job status. Added migration
  `202606081500_report_metadata.sql` for findings/timeline/IOCs/TODOs/report
  metadata used by the portal/report seams.
- Resolved B-MVP-6: added `sift-job-worker` bootstrap and systemd unit, registered
  `ingest` and `run_command` handlers, and filtered worker claims to supported
  job types. Added Gateway-owned durable MCP tools: `ingest_job`,
  `run_command_job`, and `job_status`. Public job specs stay path-free;
  worker-only `spec_internal` carries resolved local paths.
- Resolved B-MVP-7: added Gateway `rag_search_case` over G1 pgvector RAG with
  case scope, embedding validation, and normal Gateway policy/response guard.
- Switched MCP evidence gating for DB active cases to prefer C1
  `app.evidence_gate_status`; legacy file gate remains only as bridge fallback.
- Kept Gateway source add-on-name-neutral by exposing a generic `ingest_job`
  tool rather than hardcoding a derived-plane backend name.

Validation:

- Passed: `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`.
- Passed: sift-gateway 361, sift-core 376, case-dashboard 350,
  forensic-rag/tests + `tests/db` 66, opensearch job-ingest 8.
- Not run here: live `supabase db` migration apply, live OpenSearch indexing,
  or SIFT VM end-to-end journey.

Next:

- Run BATCH-V1 on the SIFT VM: apply migrations in timestamp order, start
  Gateway + `sift-job-worker`, and execute the Phase 3 smoke journey from
  `Migration-Spec.md`.

### 2026-06-08 - BATCH-J1 landed and integrated (approved-only reports)

Status: DONE

Changed (merged into `revamp/spg-v1`, `--no-ff`):

- BATCH-J1 (`e12a990`): Approved-only report generation/export to the locked
  F-MVP-4 shape. `reporting.py` hard-filters to `status == "APPROVED"` (draft/
  rejected finding IDs and text proven absent from output and API response) and
  adds `build_custody_appendix()` (seal status + manifest/chain-head/ledger-tip
  hashes + provenance refs). Portal `generate_report_route` now re-auths
  (`/api/reports/challenge`), folds in custody, persists metadata via E1's
  `report_service.record_report` seam, and renders the appendix into the
  downloadable markdown. ReportsTab gains a re-auth modal. E1's approved-only 409
  eligibility gate preserved and re-verified. API JSON sanitized (no absolute
  paths). J1 deliberately did not add a report-metadata migration — deferred to
  the binding batch (B-MVP-5).
- Conductor (`<this entry's commit>` precursor): rebuilt the portal v2 bundle
  (`vite build`) so the committed `static/v2/` includes both E1 and J1 frontend
  changes (the worker worktrees lacked node_modules); closes J1 frontend-bundle
  follow-up.

Validation:

- Passed: `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`.
- Passed (integrated): sift-core 374, case-dashboard 350, sift-gateway 355.
  `vite build` succeeded. No regressions.
- Not run here: live `supabase`/VM report journey (depends on the B-MVP-5 binding).

Status: all implementation batches (A1, B1, C1, D1, D2, E1, F1, G1, H1, I1, J1)
are landed and integrated on `revamp/spg-v1`. Remaining before BATCH-V1 is the
live-service binding (B-MVP-5/6/7), which is the only thing standing between the
built code paths and a working SIFT VM end-to-end journey.

Next:

- Resolve the binding work (B-MVP-5 portal service adapters, B-MVP-6 worker
  handler bootstrap + enqueue call sites, B-MVP-7 pgvector RAG query tool) as one
  focused batch — it spans portal + worker + gateway tool surface and should not
  be parallelized.
- Then BATCH-V1 end-to-end validation and cutover.

### 2026-06-08 - Dependent wave landed and integrated (E1/F1/G1/I1)

Status: DONE

Changed (merged into `revamp/spg-v1`, one `--no-ff` merge per batch; branch
filesets verified fully disjoint, no conflicts):

- BATCH-E1 (`0390a9c`): Portal authority migration. `routes.py` gains four
  Gateway-injected service slots (`evidence_service`, `investigation_service`,
  `report_service`, `job_service`) following the established DI seam
  (`_ACTIVE_CASES`/`_SUPABASE_AUTH`); each route prefers DB authority when wired
  and falls back to the file path when `None`. Evidence seal/ignore/retire refuse
  403 without a `reauth_audit_event_id` (C1 contract); reports gate 409 on no
  approved findings; new `GET /api/portal/state` and `GET /api/jobs/{job_id}`
  (D2 `JobService`). Report generation internals left to J1. Frontend evidence/
  reports tabs + polling + rebuilt v2 bundle.
- BATCH-F1 (`4a27aba`): OpenSearch ingest job adapter. `job_ingest.py` concrete
  `ingest` handler for the D1 `JobWorker` (resolves path from worker-only
  `spec_internal`, never echoed); central provenance stamping at the `flush_bulk`
  choke point (no parser-module edits); migration
  `202606081300_opensearch_provenance.sql` (index + ingest-provenance tables,
  service-only RPCs, sanitized coverage view, case-member RLS); registry surfaces
  `default_case_scoped`/`data_plane`. Owned `mcp_backends_registry.py` this wave.
- BATCH-G1 (`cc8c7a8`): RAG pgvector. Migration `202606081400_rag_pgvector.sql`
  (collections/documents/chunks, `vector(768)`, IVFFlat cosine, knowledge-vs-derived
  CHECK, RLS); `pgvector_store.py` case-scoped path-free adapter; `rag_search`
  returns shared knowledge UNION only the querying case's derived chunks. No
  gateway source touched (one new bridge test only).
- BATCH-I1 (`3fd86bd`): run_command uplift. `evidence_refs`/`output_ref` instead
  of arbitrary paths; `MVP_FORENSIC_ALLOWLIST` + `@mvp_forensic` alias; deep
  agent-response path sanitization (audit keeps absolutes); hash-linked provenance
  receipt. Deny-floor preserved (`bash` denied even when requested; dd/mount/losetup
  excluded). Updated 2 existing gateway tests that asserted the old absolute-path
  contract.

Validation:

- Passed: `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`.
- Passed (integrated, main worktree): sift-gateway 355, sift-core 364,
  case-dashboard 344, forensic-rag 18, opensearch-mcp 987 (+71 skipped),
  tests/db 45. No regressions.
- Not run in this environment: live `supabase db` apply of migrations
  `202606081300`/`202606081400`, live OpenSearch ingest, and live VM portal journey.
  Validation was structural + unit-level, consistent with prior waves.

Last-mile binding gap (every consuming batch deferred this; no defined batch owns
it yet): the DB-authority code paths are built but not yet bound to live services.
Captured as B-MVP-5/6/7. These block BATCH-V1's live end-to-end journey but not the
individual batch acceptances (each passes with fallbacks/units).

Next:

- Launch BATCH-J1 (approved-only report generation/export; depends on E1, now landed).
- Resolve the binding batch (B-MVP-5/6/7) before BATCH-V1.

### 2026-06-08 - BATCH-D2 landed and integrated (Gateway job/authority seam)

Status: DONE

Changed (merged into `revamp/spg-v1`, `--no-ff`):

- BATCH-D2 (`e80ad41`): Gateway integration seam.
  - `jobs.py` (new) `JobService` over D1's `app.enqueue_job` /
    `app.job_status_public` / `app.expire_stale_jobs`. Enqueue writes the Gateway
    enqueue audit event first and passes its id as `p_enqueue_audit_event_id`,
    returning only `{job_id}`. Status reads go through an explicit agent-safe
    allow-list with case-membership enforcement (no `spec_internal`, `worker_id`,
    lease internals, local paths, or DB errors). `expire_stale_jobs` runs from a
    Gateway-owned periodic reaper wired into the FastAPI lifespan (mirrors the
    existing idle-reaper pattern). No grant/wrapper migration needed — same
    service DSN path as `ActiveCaseService`.
  - `AddonAuthorityMiddleware` (in `policy_middleware.py`) runs before the
    evidence gate/audit/dispatch: denies `addon_scope_missing` when the caller
    lacks a tool's `required_scopes`, denies `addon_prohibited_operation` when a
    backend's `prohibited_operations` is invoked; `non_authoritative` surfaced as
    advisory. `transport: library` manifests stay accepted but non-routable.
  - `server.py` indexes `required_scopes`/`authority_contract` into tool meta and
    exposes `Gateway.job_service` + `addon_authority_for_tool()`;
    `supabase_auth.is_scope_satisfied()` helper added.

Resolved B-MVP-3 and B-MVP-4 (both implemented by D2).

Validation:

- Passed: `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`.
- Passed: sift-gateway 348 (335 baseline + 13 new); existing manifest/registry/policy
  tests green. D2 touched only the gateway package.
- Not run in this environment: live `supabase`/Postgres execution of the job RPCs
  (D2 pins to D1's frozen RPC/view names; D1 verified them on a Postgres 16 container).

Launch readiness: E1/F1/G1/I1 need no further Gateway glue — they wire their own
call sites onto `gateway.job_service` and inherit the authority enforcement. D2
deliberately did not add REST/MCP route handlers surfacing `JobService` (out of its
fence); the consuming batches own those call sites.

Next:

- Launch BATCH-E1, BATCH-F1, BATCH-G1, BATCH-I1 in parallel worktrees. BATCH-J1
  follows E1. BATCH-V1 follows all implementation batches.

### 2026-06-08 - Next-wave seams assigned to BATCH-D2

Status: DONE

Changed:

- Checked `revamp/spg-v1` after the first parallel wave: branch is clean,
  integration commits are present, and both doc validators pass.
- Solved the two open cross-batch seams by adding BATCH-D2 as a Gateway-only
  integration batch before the dependent wave.
- Assigned B-MVP-3 to BATCH-D2: Gateway adapter over D1 job enqueue/status/reaper
  surfaces.
- Assigned B-MVP-4 to BATCH-D2: runtime enforcement of add-on
  `authority_contract` and tool `required_scopes`.
- Updated dependent batch dependencies so E1/F1/G1/I1/J1/V1 consume D2 instead
  of each implementing Gateway glue independently.

Validation:

- Passed: `python3 scripts/validate_docs.py`.
- Passed: `python3 scripts/validate_migration_docs.py`.

Next:

- Launch BATCH-D2 first. After D2 lands cleanly, launch E1/F1/G1/I1 in parallel;
  J1 follows E1, and V1 follows all implementation batches.

### 2026-06-08 - First parallel wave landed and integrated (A1/B1/C1/D1/H1)

Status: DONE

Changed (merged into `revamp/spg-v1`, one `--no-ff` merge per batch + one integration commit):

- BATCH-A1 (`4effda6`): Supabase-first installer/bootstrap. `~/.sift/supabase.env`
  (chmod 600) secrets via systemd `EnvironmentFile`; Admin-API invite + one-time
  temp password; `invited->active` forced-reset transition (`POST /api/auth/forced-reset`,
  `must_reset` login flag); frozen case path `case-<slug>-<MMDDHHSS>` + `-NN` with
  slug traversal guard; rewritten `/health` (Gateway, Supabase, evidence root,
  tools_count).
- BATCH-B1 (`55e6933`): Gateway policy parity + agent redaction. Agent/service
  tokens 403 on `POST /api/v1/tools/{tool}` before dispatch (F-MVP-3, closes the
  REST bypass the prior R4 block missed); path-redaction at the MCP choke point
  (in-case absolute -> relative, all other host paths -> `[REDACTED:absolute_path]`,
  audit retains absolute) (F-MVP-2). Made no edits to `evidence_gate.py`.
- BATCH-C1 (`67d0dbb`): DB evidence authority + custody ledger. Migration
  `202606081000_evidence_custody.sql` (evidence_objects/versions, append-only
  hash-linked custody events, chain heads as fail-closed read model, proof exports);
  service-only transition RPCs (seal/ignore/retire require a re-auth audit event id);
  added `check_evidence_gate_db()` alongside the untouched file-backed gate.
- BATCH-D1 (`df93104`): Durable Postgres jobs + worker. Migration
  `202606081200_durable_jobs.sql` (jobs/job_steps/job_logs/worker_heartbeats);
  `FOR UPDATE SKIP LOCKED` claim/lease RPCs; `job_status_public` sanitized view;
  `JobWorker` claim loop with path-scrubbed logs/results. Lease/race verified on a
  live Postgres 16 container.
- BATCH-H1 (`ed5f27a`): Add-on contract hardening. `authority_contract` +
  tool `required_scopes` on OpenCTI/Windows-triage; new library manifest for
  forensic-knowledge.
- Integration (`be4d7f4`, conductor): reconciled H1 into the Gateway manifest layer
  (the gateway-side glue H1 deferred) — backend schema now permits optional
  `authority_contract` + tool `required_scopes`; `load_and_validate_manifest` skips
  `transport: library` / `standalone_server: false` manifests as non-routable;
  `test_phase6` enumerates routable backends only.

Branch fileset was fully disjoint across the five batches; merges were
conflict-free. The B1/C1 `evidence_gate.py` overlap I pre-split did not
materialize (B1 worked in `policy_middleware`/`response_guard` instead).

Validation:

- Passed: `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`.
- Passed: sift-gateway 335, sift-core 346, case-dashboard 322, tests/db 45,
  opencti 11, windows-triage 24, forensic-knowledge 31. No regressions.
- Not run in this environment: live SIFT VM smoke (installer bootstrap, Supabase
  Admin API) and live `supabase db` apply of the two new migrations. C1 used the
  repo's text-based migration tests; D1 applied on a Postgres 16 container.

Carried-forward integration follow-ups (feed the dependent wave):

- Gateway enqueue/status adapter over D1's `enqueue_job` / `job_status_public`
  (returns only `job_id`; set `enqueue_audit_event_id`; schedule `expire_stale_jobs`
  reaper). New B-MVP-3.
- Switch the MCP evidence gate to prefer `check_evidence_gate_db()` once cases
  carry DB evidence state (B1/C1 seam) — consumed by BATCH-E1.
- Runtime enforcement of `authority_contract` (`non_authoritative`,
  `prohibited_operations`, `required_scopes`) in the Gateway backend registry;
  schema acceptance is done, routing-time enforcement is not. New B-MVP-4.
- Concrete job handlers (ingest/enrich/report/run_command) for `JobWorker` belong
  to BATCH-F1 and BATCH-I1.

Next:

- Launch the dependent wave: BATCH-E1 (portal DB authority), BATCH-F1 (OpenSearch
  ingest adapter), BATCH-G1 (RAG pgvector), BATCH-I1 (job-backed run_command),
  BATCH-J1 (approved-only reports), then BATCH-V1.

### 2026-06-08 - MVP forks closed for parallel sprint

Status: DONE

Changed:

- Resolved F-MVP-1: case directories use
  `/cases/case-<slug>-<MMDDHHSS>` with a lowercase filesystem-safe slug and
  `-NN` collision suffix if needed.
- Resolved F-MVP-2: agents may see evidence IDs, display names, relative
  display paths, size, hash, seal status, and provenance IDs. Absolute case,
  evidence, and mount paths remain forbidden.
- Resolved F-MVP-3: agents use MCP only for the MVP. REST tool execution is
  operator-only.
- Resolved F-MVP-4: hackathon report export keeps the current profile output
  and adds DB metadata, approved-only filtering, custody/provenance appendix,
  and downloadable artifact.
- Deferred B-MVP-1 and B-MVP-2 as post-MVP presentation/backlog items.

Validation:

- Passed: `python3 scripts/validate_docs.py`.
- Passed: `python3 scripts/validate_migration_docs.py`.

Next:

- Launch parallel worktrees using the prompts generated from
  `task-batches.md`.

### 2026-06-08 - Migration docs collapsed to MVP operating model

Status: DONE

Changed:

- Purged the previous `docs/migration` document forest.
- Added `Migration-Spec.md` as the architecture, journey, constraints, and DoD
  source of truth.
- Added `task-batches.md` as the parallel-execution tracker with grep-friendly
  checkboxes.
- Added `Session-Notes.md` as the top-loaded change log and fork/backlog table.
- Recreated root `AGENTS.md` and `CLAUDE.md` as compact sprint instructions.
- Updated the Python document validator to enforce the new three-file model.

Validation:

- Passed: `python3 scripts/validate_docs.py`.
- Passed: `python3 scripts/validate_migration_docs.py`.

Next:

- Start BATCH-A1, BATCH-B1, and contract prep for BATCH-C1/BATCH-D1 in separate
  worktrees after the operator confirms or resolves the open forks below.

## Forks / Backlog / Needs Input

| ID | Type | Status | Decision or work needed | Recommendation | Blocks |
| --- | --- | --- | --- | --- | --- |
| F-MVP-1 | Fork | RESOLVED | Case directory format is `/cases/case-<slug>-<MMDDHHSS>`, with lowercase filesystem-safe slug and `-NN` collision suffix if needed. | Locked for BATCH-A1 and BATCH-C1. | none |
| F-MVP-2 | Fork | RESOLVED | Agents may see `evidence_id`, display name, relative display path, size, hash, seal status, and provenance ID. Absolute case/evidence/mount paths are forbidden. | Locked for BATCH-B1 and BATCH-C1. | none |
| F-MVP-3 | Fork | RESOLVED | Agents use MCP only for the MVP. REST tool execution is operator-only. | Locked for BATCH-B1. | none |
| F-MVP-4 | Fork | RESOLVED | Hackathon report export keeps current profile output and adds DB metadata, approved-only filtering, custody/provenance appendix, and downloadable artifact. | Locked for BATCH-J1. | none |
| F-MVP-5 | Fork | RESOLVED | Gateway Supabase health probe omitted `apikey`; Kong returned 401 and health read degraded. | Fixed in `health.py`: send configured anon key as `apikey`. | none |
| F-MVP-6 | Fork | RESOLVED | First-login deadlock: login rejected `invited` operators, but forced reset requires a session cookie. | Fixed in `supabase_auth.py`: login admits `active` and `invited`; protected resolution stays active-only. | none |
| F-MVP-7 | Fork | RESOLVED | Custody append used pgcrypto `digest()`, unresolved on Supabase under the function search path. | Fixed in `202606081000_evidence_custody.sql`: use built-in `sha256(v_payload::bytea)`. | none |
| F-MVP-8 | Fork | RESOLVED | Critical mutable DFIR state authority is Postgres. Supabase Storage and case files are immutable exports, workspace/debug artifacts, parser compatibility artifacts, or legacy fallback only. | Locked in `Migration-Spec.md` authority cutover model and K-series batches. | none |
| F-MVP-9 | Fork | RESOLVED | Hostname detection/correction is required for parser/indexer metadata and OpenSearch index naming, but it is derived state only. | Keep `opensearch_fix_host_mapping` canonical and `opensearch_host_fix` as deprecated alias; record corrections in DB provenance/host identity. | K4 |
| F-MVP-10 | Fork | RESOLVED | Solana anchoring is optional external proof, not local authority. DB custody chain heads decide evidence gate state. | Record DB-derived anchor proof in `app.evidence_proof_exports`; export to file/storage when configured. | K3 |
| B-MVP-1 | Backlog | DEFERRED | Enterprise object-lock/WORM evidence vault option. | Post-MVP architecture appendix only. | none |
| B-MVP-2 | Backlog | DEFERRED | ContextForge/Envoy-style external gateway integration. | Post-MVP presentation/backlog only; Gateway policy remains in SIFT Gateway for MVP. | none |
| B-MVP-3 | Backlog | DONE | Gateway enqueue/status adapter over D1's `enqueue_job`/`job_status_public` (job_id only, sets `enqueue_audit_event_id`, schedules `expire_stale_jobs` reaper). | Landed in BATCH-D2 (`e80ad41`) as `JobService` + lifespan reaper. | E1, F1, G1, I1, J1 |
| B-MVP-4 | Backlog | DONE | Runtime enforcement of add-on `authority_contract` (non_authoritative, prohibited_operations, required_scopes) in the Gateway backend registry; schema acceptance landed in this wave. | Landed in BATCH-D2 (`e80ad41`) as `AddonAuthorityMiddleware`. | F1 |
| B-MVP-5 | Backlog | DONE | Bind `create_dashboard_v2_app` service slots (`evidence_service`/`investigation_service`/`report_service`/`job_service`) to live Postgres/C1 RPCs/D2 `JobService`. | Landed in BATCH-L1 with Gateway-owned `portal_services.py` and migration `202606081500_report_metadata.sql`. | none |
| B-MVP-6 | Backlog | DONE | Worker bootstrap + enqueue call sites: register D1 `JobWorker` handlers (`ingest`, `run_command`) and enqueue call sites that place resolved local paths in worker-only `spec_internal`. | Landed in BATCH-L1 with `sift-job-worker`, generic `ingest_job`, `run_command_job`, and `job_status`. | none |
| B-MVP-7 | Backlog | DONE | Wire a case-scoped pgvector RAG query tool (G1 `app.rag_search`/`PgVectorRagStore`) into the Gateway tool surface with a worker service DSN. | Landed in BATCH-L1 as `rag_search_case`, routed through existing Gateway policy/response guard. | none |
| B-MVP-8 | Backlog | DONE | Installer bootstrap created Supabase `auth.users` without matching `app.operator_profiles` and lacked full control-plane DSN/env wiring. | Landed in V1 enabler integration (`58c669b`, merge `84404ba`): installer writes `~/.sift/control-plane.env`, keeps DSN/pepper out of YAML, and creates/repairs Auth + `app.operator_profiles` together. | verified in BATCH-V1 |
| B-MVP-9 | Backlog | DONE | Case-bound agent issuance was inconsistent: case-scoped scopes did not load, while global scopes lacked an active-case default. | Landed in V1 enabler integration (`58c669b`, merge `84404ba`): MVP agents use global tool scopes plus `agents.default_case_id`/token `case_id` bound to the active DB case. | verified in BATCH-V1 |
| B-MVP-10 | Backlog | DONE | Agent `record_finding`/`record_timeline_event` stage to case files, not `app.investigation_*`; portal approval and approved-only report DB authority do not see them. | Landed in BATCH-K2 (`5b1cf9c`): `case_manager` writes findings/timeline/IOC/TODO DB-first via `PostgresInvestigationStore`; portal review + approved-only report read DB authority. | verified in BATCH-V1 |
| B-MVP-11 | Backlog | DONE | `rag_search_case` denied live with `active_case_proxy_denied`; case-scoped Gateway-local tool was treated like a proxied tool without safe case args. | Landed in V1 enabler integration (`db47c71`, merge `2c34520`): `ProxyActiveCaseMiddleware` skips Gateway-local tools; RAG still resolves active case internally and remains response-guarded. | verified in BATCH-V1 |
| B-MVP-12 | Backlog | DONE | `run_command` deny floor worked, but allowed execution failed because `agent_runtime` lacked read ACL on new case dirs. | Landed in V1 enabler integration (`0acd60f`, merge `09a0023`): portal case creation applies per-case `setfacl` for `agent_runtime` read/write areas and denies legacy authority artifacts. | verified in BATCH-V1 |
| B-MVP-13 | Backlog | DONE | Evidence seal/ignore/retire re-auth still uses legacy local-password PBKDF2 HMAC, not Supabase password re-auth. | MVP decision landed in V1 enabler integration (`0acd60f`, merge `09a0023`): local password/HMAC remains the MVP re-auth bridge and endpoints surface `reauth_method=local_hmac_mvp_bridge`; Supabase password re-auth is deferred. | none |
| B-MVP-14 | Backlog | DONE | No standalone register-evidence endpoint exists. Operator journey said detect -> register -> seal, but implementation folded registration into seal `file_specs` while emitting `EVIDENCE_REGISTERED`. | MVP decision landed in V1 enabler integration (`0acd60f`, merge `09a0023`): register+seal is one atomic operator action (`registration_mode=atomic_register_and_seal`); DB seal calls `app.evidence_register` before `app.evidence_seal`. | verified in BATCH-V1 |
| B-MVP-15 | Backlog | DONE | Supabase pgvector RAG was schema/query-surface only; live VM tables were empty and any knowledge answers came from legacy `kb_*`/forensic-knowledge. | Landed in V1 enabler integration (`db47c71`, merge `2c34520`): `rag-mcp-seed-pgvector` seeds shared knowledge collections/documents/chunks (`kind='knowledge'`, `case_id NULL`) with 768-d embeddings through pgvector, not Chroma. | verified in BATCH-V1 |
| B-MVP-16 | Backlog | DONE | DB-active mode still has split-brain file authority touchpoints: active-case pointer/env fallbacks, JSONL audit, evidence manifest/ledger, findings/timeline/TODO/IOC JSON, approval JSONL, OpenSearch ingest status/manifests, host dictionary, and run-command access to case-local authority artifacts. | Closed by K1-K6 (landed/integrated on `revamp/spg-v1`): active-case + audit (K1), investigation (K2), evidence/proof (K3), OpenSearch/host (K4), run_command env/ACL (K5), and report/audit/backup file-authority removal + tamper regressions (K6). Remaining file paths are explicit legacy fallback, parser compatibility, workspace/debug, or immutable export only. | verified in BATCH-V1 |
| B-MVP-17 | Backlog | DONE | K1 DB audit envelope covers case-context-established tool attempts and now wraps proxy/evidence-gate denials, but tool-scope authorization denials and active-case lookup denials still use pre-existing denial audit paths before an authority context can attach. | Decided in K6 (`b76eba9`) and accepted for MVP live cutover: pre-context denials stay on the local audit mirror (`status=denied`) for security telemetry and are NOT projected into `app.audit_events` (projecting unresolved principals/null case_id would write unattributable rows and expose a DB write path to unauthenticated callers). The K1 envelope remains the sole DB-audit write path for allowed calls + post-context denials. Locked by `test_k6_precontext_denial_audit.py`. | none |
| B-MVP-18 | Backlog | DONE | Full forensic RAG release corpus was expected in Supabase pgvector, but BATCH-V1 only seeded the small bundled JSONL corpus (`4318` chunks). The downloaded Chroma release bundle (`20K+` records) remained legacy-only. | Closed on the live VM: downloaded `rag-index-v2026.03.01`, imported `22268` Chroma/BGE records with `rag-mcp-import-chroma-pgvector`, and proved `app.rag_chunks=26586`, all `kind='knowledge'`, all `case_id NULL`; live `rag_search_case` returned Chroma-backed knowledge hits with no local path/secret leakage. `install.sh` is wired to run the importer after `download_rag_index` when a control-plane DSN exists. | none |
