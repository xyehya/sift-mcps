# Session Notes

Status: sprint log and decision register.
Last updated: 2026-06-12.

## Format Rules

- Latest change entry stays at the top of `Current Change Log`.
- Use `Status: DONE`, `Status: IN_PROGRESS`, or `Status: BLOCKED`.
- Keep forks, blockers, and needs-input in the single table below.
- Use IDs beginning with `F-MVP-` for forks and `B-MVP-` for backlog/needs-input.
- Do not create more migration runbooks.

## Current Change Log

### 2026-06-12 - Implementation wave landed: HR3 hardening + PT1 portal

Status: DONE (ten commits merged to local main; not pushed; live VM re-proven)

Changed (HR3, six commits): download pinning + SIFT_OFFLINE mode + GeoIP
gating (B-MVP-004); canonical bge-base-en-v1.5 with revision pin and
service-owned HF_HOME (B-MVP-015); systemd hardening taking both services
from `systemd-analyze security` 9.2/UNSAFE to 4.4/OK; auditd installed with a
forensic ruleset, 12 SIFT rules live (B-MVP-014); OpenSearch container
CapDrop=ALL + no-new-privileges + digest pin (B-MVP-005); portal session
secret env-indirected (B-MVP-010); sift-core file-HMAC verification ledger
retired from reporting (B-MVP-011 half).

Changed (PT1, three commits + one conductor fix): portal login is
Supabase-only and fails closed 503 when the control plane is down (B-MVP-011
half); forced-reset UX explains the handoff origin and unrecoverability;
root `/` and bare `/portal` now 307 to `/portal/` (conductor live smoke
caught the auth middleware intercepting `/` - fixed by adding `/` to
_PUBLIC_PATHS with a regression test); System Health panel on the Backends
tab fed by a new portal `/api/health` proxy; per-backend Enable/Disable via
new gateway REST `POST /api/v1/backends/{name}/enabled` (registry-owned
write, re-auth gated); DB-mode case-activation bug fixed (modal no longer
demands a file-mode HMAC challenge under Supabase authority).

Key negative result (B-MVP-012): Supabase demo-secret rotation is infeasible
on the CLI local stack - v2.105.0 bakes the demo JWT secret/keys/DB password
with no override. Documented manual external-rotation procedure and guard
rails in config-and-secrets.md section 5.1; row reopened for an operator
decision (accept loopback lab posture vs self-managed compose redesign).

Validation: per-package suites on merged main - sift-core 483, case-dashboard
350, sift-gateway 461, forensic-rag-mcp 90, all passed; frontend vitest 83/83
+ build green; bash -n OK; both doc validators OK; git diff --check clean;
secret scans clean. Live proof: rsync + cleaned `./install.sh` exit 0,
`/health` status=ok, both services active as sift-service, `/` and `/portal`
307 to `/portal/`, new frontend bundle served, bad-credential login returns
Supabase `invalid_token` (no local fallback), systemd exposure 4.4 OK,
auditd active with 12 rules.

Follow-ups registered: B-MVP-017 (remaining file-HMAC re-auth bridge +
legacy sift_session middleware retirement decision), B-MVP-018 (AppArmor
enforce transition). Maintenance guide sections 1.5/1.6/3.1 updated to match
the new login/case/health behavior.

Next: BATCH-AD2 (add-on conformance + OpenCTI proof) and BATCH-TLS1
(certificate/trust per decided internal-CA profile) are the remaining
implementation batches before CL2/PT2/RG1/LV1. Operator decisions pending on
B-MVP-012 and B-MVP-017.

### 2026-06-12 - Audit wave landed: HR2, AD1, CL1

Status: DONE (three parallel worktree batches merged to local main; not pushed)

Changed:

- BATCH-HR2 `docs/hardening/component-audit.md` (804 lines) - executable
  per-component audit guide with sanitized live evidence from 2026-06-12.
- BATCH-AD1 `docs/add-ons/spec.md` + `docs/add-ons/author-guide.md` (955
  lines) - normative manifest/contract spec plus author tutorial with a
  hypothetical windows-triage-style query-only worked example per B-MVP-003;
  verified OpenCTI is absent from the core install path (install.sh
  seed_addon_backends seeds only opensearch-mcp and forensic-rag-mcp).
- BATCH-CL1 three commits - AppArmor template repointed from the stale
  `/home/*/sift-mcps-test/**` checkout to `/opt/sift-mcps/**`; dead
  `docs/product/` doc path fixed; `.DS_Store` excluded from both installer
  staging branches (B-MVP-009; the vol3/yara reference scan came back clean,
  catalogs already map names to real binaries).

Live verification results recorded by HR2 (read-only):

- B-MVP-012 CONFIRMED: anon and service-role JWTs carry `iss=supabase-demo`
  and the control-plane DSN uses the default `postgres` password - all three
  demo secrets are in live use; rotation goes to HR3.
- B-MVP-013 verdict: all 31 `app.*` tables have RLS ENABLED, none FORCEd;
  gateway connects as service-role which bypasses RLS. Report-only as decided.
- `systemd-analyze security` exposure 9.2/UNSAFE for both services; auditd is
  NOT installed at runtime (HR1 assumed it was); AppArmor live profile path is
  already correct but complain-mode; OpenSearch container runs non-root;
  gateway cert carries IP SAN 192.168.122.81 (valid to 2028, informs TLS1);
  live RAG embedding model is `BAAI/bge-base-en-v1.5`, cached under the
  operator home rather than the service home.

B-MVP-011 deliberately NOT actioned by CL1: live evidence shows the
`examiner.json` PBKDF2 fallback and file-mode HMAC verification ledger are
unexercised on the VM, but both are reachable, test-covered, supported
non-Supabase/non-DB deployment modes - retiring them removes a deployment
mode and needs an explicit operator decision (row updated below).

New rows below: B-MVP-014 (auditd absent), B-MVP-015 (RAG model allowlist
mismatch), B-MVP-016 (dead `scope_enforcement` manifest field).

Validation: `python3 scripts/validate_docs.py` OK;
`python3 scripts/validate_migration_docs.py` OK; `git diff --check` clean;
`bash -n install.sh scripts/setup-ingest-mount-sudoers.sh` OK; targeted
`uv run --extra dev --extra full pytest packages/sift-core/tests/test_verification.py`
13 passed; secret scans clean on all three branch diffs.

Next: BATCH-HR3 (hardening implementation) and BATCH-AD2 (conformance tests)
are unblocked; CL2 is unblocked after AD1+CL1. Operator decisions pending on
B-MVP-011/014/015/016 before the relevant HR3/AD2 sub-tasks.

### 2026-06-12 - Operator decisions recorded for open needs-input rows

Status: DONE (decisions captured; implementation stays with owner batches)

The operator resolved the open decision rows. Summary (full text in the table
below):

- B-MVP-001 TLS: internal/local CA profile with a documented client trust
  bundle; ACME/domain profile deferred. Owner BATCH-TLS1.
- B-MVP-002 rename: rename GitHub repo/docs to ProtocolSiftGateway; keep the
  `/opt/sift-mcps` runtime path and Python package import names. Owner CL2.
- B-MVP-003 Windows triage: stays an author-guide example only; AD2 proves the
  add-on contract with OpenCTI alone. RESOLVED, no build.
- B-MVP-004 downloads: pin + SHA-256 verify all live downloads (Supabase CLI
  check upgraded warn-to-die as the pattern), GeoIP off by default, plus an
  offline mode using operator-staged artifacts. Owner HR3.
- B-MVP-005 OpenSearch: accept security-plugin-disabled on loopback for the
  single-node lab; harden the container instead (cap_drop, no-new-privileges,
  digest pin, non-root) and document snapshot policy. Revisit only if
  OpenSearch leaves loopback. Owner HR3.
- B-MVP-010..013 defaults approved: env-indirect the gateway session secret
  (HR3); verify-then-retire legacy file fallbacks (CL1); verify Supabase demo
  keys on the VM (HR2) and rotate if present (HR3); verify RLS posture
  read-only (HR2) with no schema change without a separate go-ahead.

Next: Run BATCH-HR2, BATCH-AD1, and BATCH-CL1 in parallel worktrees; HR3 and
TLS1 follow with the decisions above as their contract.

### 2026-06-12 - BATCH-OR3 operator maintenance manual landed

Status: DONE (committed to local main; not pushed)

Changed: Wrote the operator manual as a three-doc set under `docs/operator/`,
synthesized from the OR1/OR2/OR4 discovery docs plus live read-only VM
verification:

- `maintenance-guide.md` - login, handoff password discovery, forced reset and
  rotation (post-reset password is explicitly unrecoverable from any file),
  service status/restart, health checks, backup/restore, evidence mount/seal,
  add-on registration, logs, audit, TLS trust, and failure recovery, with
  DANGER markers on destructive steps.
- `config-and-secrets.md` - full variable dictionary (env files, installer
  variables, Supabase exports, gateway.yaml, DB-backed settings, OpenSearch,
  RAG/FK/Hayabusa, Docker, systemd) plus the do-not-hand-edit table.
- `rag-and-search-maintenance.md` - RAG seed/re-seed/query-smoke/offline,
  OpenSearch health/index/template/rebuild, and Hayabusa run/query/refresh
  procedures.

Live-verified facts recorded: `/health` `status=ok` with 17 tools and both
stdio backends mounted; OpenSearch yellow single-node with 9 indices; gateway
unit loads four env files while the worker loads three (no `opensearch.env`,
consistent with worker scope); handoff file key names confirmed without
reading values.

Gaps flagged for later batches: no supported one-command backup/restore
(manual pg_dump/tar documented; HR3 candidate), no admin CLI for operator
password reset (PT1 candidate), lab-CA-only TLS trust (BATCH-TLS1/B-MVP-001),
download pinning and OpenSearch posture already tracked as B-MVP-004/005.

Validation: `python3 scripts/validate_docs.py` OK;
`python3 scripts/validate_migration_docs.py` OK; `git diff --check` clean;
independent secret-pattern scan of all three docs clean.

Next: Start BATCH-HR2 (component hardening audit guides) from the HR1 matrix
plus OR1/OR2 facts; AD1 and CL1 are also unblocked. Operator input still
needed on B-MVP-001..013 before TLS1/CL2/HR3 decision points.

### 2026-06-12 - Discovery wave landed: OR1, OR2, OR4, HR1

Status: DONE (four parallel worktree batches merged to local main; not pushed)

Changed: Landed the first operator-readiness discovery wave as four parallel
worker batches, one commit each, merged linearly onto main:

- BATCH-OR1 `docs/inventory/sift-tool-inventory.md` plus read-only helper
  `scripts/inventory-sift-tools.sh` - live-VM command-backed tool/path/service/
  Docker inventory with missing-tool grouping.
- BATCH-OR2 `docs/operator/state-authority-map.md` - 40+ row mutable-state
  authority table; confirms evidence custody is DB-authoritative
  (`app.evidence_seal`; manifest/ledger are export/proof only) and lists
  `docs/regenerate/**` stale-authority claims for RG1.
- BATCH-OR4 `docs/operator/reference-data-provenance.md` - RAG/forensic-
  knowledge/Hayabusa provenance traces plus an external-download ledger
  (D1-D8): uv, Hayabusa, and BGE model downloads are unpinned/unverified;
  GeoIP datasource hits a live endpoint; only uv.lock/PyPI passes cleanly.
- BATCH-HR1 `docs/hardening/research-matrix.md` - 16-component official-source
  hardening matrix (URLs + 2026-06-12 retrieval dates). Top gaps: systemd units
  have zero hardening directives; AppArmor complain-only with stale profile
  paths; OpenSearch security plugin disabled; sentence-transformers has no
  offline/revision pin; Supabase CLI demo keys vs production posture.

Notable live-VM facts from OR1: Volatility 3 is `vol`/`volshell` (no `vol3`
name); yara is python3-yara only (no CLI); `uv` lives in the operator home, off
the service PATH; config/env files live under `/var/lib/sift/.sift/` with 0600
modes; ~4.4 GB of OpenCTI add-on images are present but not running on the
core VM; Volatility symbol cache is empty; `/opt/sift-mcps/.DS_Store` is stray.

New backlog/needs-input rows registered below: B-MVP-007..013 (the four
decision items from worker landing logs are typed Needs input per the
validator contract that bans persistent OPEN fork rows).

Validation: `python3 scripts/validate_docs.py` OK;
`python3 scripts/validate_migration_docs.py` OK; `git diff --check` clean;
`bash -n scripts/inventory-sift-tools.sh` OK; secret-pattern scan over all
four diffs clean (paths/modes recorded, values redacted).

Next: Run BATCH-OR3 (operator maintenance manual + variable dictionary)
consuming OR1/OR2/OR4 outputs. Then HR2 can start from the HR1 matrix plus
OR1/OR2 facts.

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
| B-MVP-001 | Needs input | OPEN | DECIDED 2026-06-12: internal/local CA profile for the IP-only lab VM; handoff documents client trust-bundle import, SAN verification, and rotation. ACME/domain profile deferred. Implementation in BATCH-TLS1. | BATCH-TLS1 |
| B-MVP-002 | Needs input | OPEN | DECIDED 2026-06-12: rename GitHub repo/docs to `ProtocolSiftGateway`; keep `/opt/sift-mcps` runtime path and Python package import names unchanged. Implementation in BATCH-CL2. | BATCH-CL2 |
| B-MVP-003 | Backlog | RESOLVED | DECIDED 2026-06-12: Windows triage stays an author-guide example only; no rebuild now. AD2 proves the add-on contract with OpenCTI alone. | BATCH-AD1 / BATCH-AD2 |
| B-MVP-004 | Backlog | DONE | DONE 2026-06-12 (HR3, live-proven): uv/Hayabusa/BGE/RAG-bundle pinned with SHA-256 hard gates, Supabase CLI SHA warn->die, GeoIP off by default behind --enable-geoip, SIFT_OFFLINE=1/--offline skips all fetches with staged-artifact messages. | BATCH-HR3 |
| B-MVP-005 | Backlog | DONE | DONE 2026-06-12 (HR3, live-proven): OpenSearch container runs CapDrop=ALL, no-new-privileges, digest-pinned image; security plugin stays disabled per decided loopback lab posture. | BATCH-HR3 |
| B-MVP-006 | Backlog | OPEN | Portal RAG document management must decide whether operator-added docs are global knowledge only or can create case-derived chunks with strict provenance. | BATCH-PT2 |
| B-MVP-010 | Backlog | DONE | DONE 2026-06-12 (HR3, live-proven): gateway.yaml carries session_secret_env only; value lives in 0600 control-plane.env; loader resolves the reference; migration strips inline literals. | BATCH-HR3 |
| B-MVP-011 | Backlog | DONE | DONE 2026-06-12 (HR3+PT1, live-proven): portal login is Supabase-only (examiner.json fallback + local setup/challenge/reset endpoints removed; fails closed 503 when control plane is down); sift-core reporting is DB-content-hash-only. Remaining file-HMAC re-auth bridge tracked as B-MVP-017. | BATCH-HR3 / BATCH-PT1 |
| B-MVP-012 | Needs input | OPEN | DECIDED 2026-06-12: replace the Supabase CLI local stack with a repo-owned self-managed compose that generates GOTRUE_JWT_SECRET, anon/service-role keys, and a non-default DB password at install. Registered as new BATCH-SB1; must land before BATCH-LV1. | BATCH-SB1 |
| B-MVP-013 | Needs input | OPEN | HR2 verdict 2026-06-12: RLS ENABLED on 31/31 `app.*` tables, none FORCEd; several tables default-deny with 0 policies; gateway service-role bypasses RLS. DECISION PENDING: adopt FORCE ROW LEVEL SECURITY (schema change) or accept current posture with documented rationale. | Operator / BATCH-HR3 |
| B-MVP-007 | Backlog | OPEN | ~4.4 GB of OpenCTI add-on images sit on the core VM unused. Document add-on image lifecycle/cleanup so core installs do not silently carry add-on payloads. | BATCH-AD2 |
| B-MVP-008 | Backlog | OPEN | Volatility symbol cache is empty (on-demand fetch). Document symbol provisioning for air-gapped operation. | BATCH-OR3 / BATCH-HR3 |
| B-MVP-009 | Backlog | DONE | DONE 2026-06-12 (CL1): `.DS_Store` excluded from both installer staging branches; vol3/yara scan clean - catalogs already map `vol3`->`vol` and yara CLI exists via python3-yara. | BATCH-CL1 |
| B-MVP-014 | Backlog | DONE | DONE 2026-06-12 (HR3, live-proven): installer installs+enables auditd; 12 SIFT rules loaded live (secrets/config, install-root binaries, identity files, units). | BATCH-HR3 |
| B-MVP-015 | Backlog | DONE | DONE 2026-06-12 (HR3, live-proven): BAAI/bge-base-en-v1.5 canonical with revision pin; explicit HF_HOME under the service home wired into both units; offline-aware loader. | BATCH-HR3 |
| B-MVP-016 | Needs input | OPEN | Manifest schema field `scope_enforcement` exists but no shipped manifest uses it and AddonAuthorityMiddleware never reads it (dead schema). Decide in AD2: implement enforcement or remove the field from the schema. | BATCH-AD2 |
| B-MVP-017 | Needs input | OPEN | DECIDED 2026-06-12: retire the legacy file-HMAC re-auth bridge, orphaned sift_session middleware, and sift-core verification.py writer funcs in a scoped cleanup batch. Registered as new BATCH-CL3. | BATCH-CL3 |
| B-MVP-018 | Backlog | OPEN | AppArmor enforce-mode transition: profile is correct-path but complain-only; needs aa-logprof profiling against ingest/run_command plus a dedicated live rerun before flipping to enforce. | Future hardening batch |

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
