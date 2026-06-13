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

### 2026-06-14 - DB-audit unit landed: run_command/add-on audit detail + approval ledger DB hash chain (security-reviewed, live-proven)

Status: DONE (local main, not pushed; deployed + live-verified on VM). Built by two
parallel opus worktree agents (S1, S2), adversarially security-reviewed by a third,
findings fixed, reconciled into main, deployed, and proven on the live Supabase/gateway.

Commits: 8100ed1 (S1) + f8953f1 (S2) + 4db84b3 (merge) + d830511 (S3 doc) +
831e71f (sec fixes F1-F5) + c24b60b (install SIFT_DB_ACTIVE wiring).

S1 — audit DETAIL to DB (closes the LV1 "run_command detail dropped" gap):
- The gateway MCP envelope (AuditEnvelopeMiddleware) now records REDACTED tool
  arguments (pre-dispatch) and a bounded result_summary + run_command provenance
  `detail` (post-dispatch) into app.audit_events.details — for core AND proxied
  add-on tools. Redaction reuses response_guard (redact_structured +
  redact_paths_structured, override_active=False) then bounds; no secret/abs path
  reaches details. The misleading DB-mode "Audit write failed" warning is retired.
- install.sh now writes SIFT_DB_ACTIVE=1 to control-plane.env when a DSN is set, so
  the gateway AND the async job worker (no per-request AuthorityContext) agree on
  DB-authority mode. Set live on the VM.
- LIVE PROOF: run_command via MCP -> NO warning; call-row details.arguments captured;
  result-row details.detail = {exit_code, provenance, stages}; redaction probe ->
  `/cases/...` collapsed to relative, `/var/lib/sift/...` -> [REDACTED:absolute_path],
  zero raw sensitive paths in the DB.

S2 — HMAC ledger -> DB-only (FORK-2 closed):
- Retired the file HMAC ledger (verification.py write_ledger_entry/compute_hmac
  deleted). Approval-commit events now go to app.approval_commit_events, an
  append-only per-case SHA-256 hash chain (prev_hash/event_hash) + heads tip,
  appended atomically by SECURITY DEFINER RPC, immutable via append-only triggers.
  Keyless (mirrors the locked evidence_custody pattern); keyed-MAC detached
  verification flagged as a separate operator fork, not implemented.
- LIVE PROOF (migration 202606141200 applied to Supabase): chain links correctly,
  head advances, UPDATE/DELETE/TRUNCATE all blocked, F5 (APPROVED=>reauth) and F2
  (item_id no-'|') checks reject, F4 public-execute revoked; test rows rolled back
  (zero pollution).

Security review (SHIP-WITH-FIXES) — S1 clean; S2 fixes applied + regression-tested:
- F1 (HIGH): approval-commit loop attested APPROVED for items the content authority
  SKIPPED (and could null-bind content). Now driven off the authoritative
  ReviewResult (request-approved MINUS skipped); missing content_hash is a hard
  skip surfaced as ledger_failure. +3 regression tests.
- F2/F3/F4/F5 (LOW/MED): item_id no-delim CHECK; BEFORE TRUNCATE triggers; REVOKE
  EXECUTE FROM public on both RPCs; APPROVED=>non-null reauth CHECK + reauth FK on
  delete RESTRICT.

S3 — docs/operator/case-directory-layout.md: every case dir/file role + DB-authority
vs mirror, the app.audit_events details-by-source schema, and the new approval ledger.

Gate: sift-gateway 496, sift-core 480, case-dashboard 361, doc validators OK.

DONE 2026-06-14 — evidence-chain hardening backfilled (migration 202606141400, live-verified):
F3 BEFORE TRUNCATE guards on evidence_custody_events/evidence_versions/evidence_chain_heads;
F4 revoke-execute-from-public + grant service_role on ALL app SECURITY DEFINER functions
(required: evidence_append_custody_event had no explicit grantee, ran via PUBLIC default).
F2 N/A for evidence custody (event_type enum-constrained; no request-supplied free-form
field; live hash NOT rewritten). Live proof: 3 guards present, public-execute=False/
service_role=True, 6 custody events intact, TRUNCATE blocked, app USAGE = service_role-only.
STILL OPEN: keyed-MAC detached approval-ledger verification (operator fork).

CORRECTION to an earlier S-1 note: sealed evidence/ IS write/delete-protected — the seal
flow applies chattr +i (immutable) / +a via CAP_LINUX_IMMUTABLE on the venv python
(install.sh configure_immutable_capability; evidence_chain.py clears +i only transiently to
hash, then re-applies). run_command runs as agent_runtime (no CAP_LINUX_IMMUTABLE) so cp/rm
cannot overwrite/delete a sealed immutable file; uninstall must chattr -i/-a before rm. The
prior "cp/rm can mutate evidence/" framing was stale.

### 2026-06-13 - LV1 follow-up: add-on outputSchema made MCP-spec compliant (full tool aggregation unblocked)

Status: DONE (committed local main 5e61c55, not pushed; deployed + live-proven on VM).

Symptom: after the proxy keep-alive + pre-warm fix (4766a10) the aggregate finally
enumerated all ~30 tools, but a strict MCP client (Claude Code loader) rejected the
whole list with `Invalid input: expected "object"` at `tools[14..29].outputSchema.type`
(the 16 opensearch add-on tools) and dropped every tool.

Root cause: opensearch-mcp `_output_schema` advertised a bare `anyOf` outputSchema with
NO root `type`. The MCP spec requires `outputSchema` to be an object-typed JSON Schema;
the strict validator rejected the missing-root-type and discarded the entire aggregated
surface. forensic-rag-mcp tools carry no outputSchema, so only opensearch was affected.

Fix (two layers):
- Source: opensearch `_output_schema` now emits root `"type": "object"` alongside the
  `anyOf` (both branches are pydantic objects -> root type always satisfied).
  Regenerated the opensearch mcp_surface golden (diff = only root `type:object`
  insertions). registry.py.
- Gateway aggregator (defense-in-depth): `_normalize_output_schema` in the
  `GatewayToolCatalogMiddleware.on_list_tools` path repairs any forwarded
  non-object outputSchema (`anyOf`/`oneOf`/`allOf` of objects -> inject `type:object`)
  or, last resort, strips it -- one misbehaving backend can no longer poison the whole
  `tools/list`. mcp_server.py.

Proof:
- Host: gateway suite 488 passed; opensearch suite green except the pre-existing
  `test_tool_count` (15-vs-16, fails on clean tree too); normalizer unit-checked
  (anyOf->object, object untouched, array->dropped, None->None).
- Live VM (editable installs at /opt/sift-mcps, files synced sift-service:644, gateway
  restarted): `is-active`, `/health` ok, both add-on proxies mounted, tool map = 18
  add-on + 8 core. In-process wire-format check (`to_mcp_tool()`) over the live
  opensearch backend: 16/16 tools now expose `outputSchema.type == "object"` with
  `anyOf` preserved; ZERO non-object roots (was 16 before). e.g. `opensearch_search`
  flipped from anyOf-without-type to `type: object`.

Operator reconnect CONFIRMED: the full 28-tool surface (11 core + 3 kb_* + 14
opensearch_*) loaded in the siftmcp client with no outputSchema error.

Exercising the now-reachable add-on tools surfaced two latent bugs (masked while the
tools were unreachable) — both fixed and live-proven:

- cc02ee5 (opensearch $defs hoist): adding the root type made the tools loadable,
  which exposed that _output_schema merged two model_json_schema() outputs into one
  anyOf with each branch's $defs left NESTED. A nested $ref (#/$defs/IndexInfo)
  resolves against the document root, which had no $defs -> the structured-output
  validator raised PointerToNowhere the moment opensearch_status actually returned.
  Fix hoists both branches' $defs to the document root; FastMCP then inlines them.
  Live: opensearch_status returns clean StatusOut (6 indices, 1M imgstrings docs).
- 15a8c8b (kb default_case_scoped=false): the reachable kb_* tools were denied with
  active_case_proxy_denied because is_case_scoped_tool()'s heuristic treats any
  category-bearing non-"reference" tool as case-scoped; kb_* carry category
  "enrichment". forensic-rag-mcp is a global reference plane, so its manifest now
  declares default_case_scoped=false (live DB row patched in lockstep — gateway
  reads manifest from app.mcp_backends, not the file). Live: kb_get_knowledge_stats
  returns corpus stats (4318 chunks, BGE-base).

Programmatic-tool-calling / output-filtering verification (operator-requested):
- True Anthropic PTC (code_execution) is a raw-API feature NOT exposed to the Claude
  Code MCP client; the gateway-native equivalents were exercised instead.
- Server-side filtering: 1,000,000 indexed imgstrings; query 'dropbox' -> count 19,
  search returns the matches with byte offsets + evidence provenance. A 40GB image
  collapses to 19 hits in context. This is the context-economics win.
- run_command pipelines WORK (prior QA's "literal argv / pipes unreachable" finding is
  RESOLVED): `ls -la evidence | wc -l` parsed into 2 staged argv (shell=False);
  `fls ... 2>... | grep | head` parsed into 3 stages with the 2> redirect captured and
  per-stage exit codes + failed_stages diagnostics returned.

OPEN FINDING (B-MVP, needs operator decision before Hermes): run_command returns
`"Audit write failed — action not recorded"` on every call. Investigation: the gateway
MCP envelope (source=gateway_mcp_envelope) DOES record mcp.tool.call + mcp.tool.result
per call in app.audit_events with identity/access/outcome + a backend_audit_id pointer
(chain-of-custody for "who/what/when" is intact). BUT the sift-core run_command DETAIL
audit (exact command, input/output SHA256s, exit code, pipeline stages, privilege
events) still targets the retired FILE JSONL ledger (sift_common.audit.AuditLogger);
in DB-only mode there is no audit dir, so audit.log() returns None, the rich forensic
detail is persisted NOWHERE, and the envelope's backend_audit_id dangles. This is the
same shape as the deferred "move HMAC ledger to DB-only" task: the file ledger is
retired but run_command's DB detail-recorder is not wired. Fix options: (a) give the
run_command audit path a DB recorder writing detail into app.audit_events.details
(authoritative), or (b) at minimum stop emitting the misleading agent-facing warning
when the gateway envelope is the authority. Recommend folding into the deferred
DB-audit / case-folder-doc unit before the Hermes run.

### 2026-06-13 - CL3b landed: file-HMAC re-auth plane retired (security-reviewed)

Status: DONE (merged to local main, not pushed; live re-auth smoke folded into LV1).

BATCH-CL3b built by an opus agent, adversarially security-reviewed by a second
opus agent, test-fidelity fix applied, conductor-reconciled. With CL3a this
COMPLETES the Supabase re-auth migration (B-MVP-017 DONE).

What landed (718684e):
- MUST-RESET re-homed: `_must_reset_check` now keys on the Supabase
  `status='invited'` signal (was the file-HMAC `_PASSWORDS_DIR`). The security
  review found the PRIMARY forced-reset enforcement is actually the portal
  resolver returning None for any non-active principal (supabase_auth.py:1186 ->
  invited operators denied 401/403 upstream); `_must_reset_check` is kept as
  defense-in-depth, and a new `TestForcedResetEnforcedByResolver` proves the real
  prod path (the defense-in-depth tests are now explicitly labeled).
- DELETED (each rg-proven dead): `_verify_evidence_hmac`,
  `_verify_password_challenge_helper`, `_sync_local_reauth_password`, dead
  in-memory challenge stores + the commit/report/evidence-chain challenge-GET
  endpoints (zero frontend callers after CL3a); sift-core verification.py re-auth
  cluster (`derive_hmac_key`/`verify_items`/`read_ledger`/`rehmac_entries`/
  `copy_ledger_to_case`) and backup_ops password-hash snapshot block.
- KEPT (live, by design): `_load_pw_entry`/`_PASSWORDS_DIR` (out-of-scope
  file-authority COMMIT ledger key + a must_reset UI hint); the file-authority
  COMMIT ledger (`write_ledger_entry`/`_apply_delta`) untouched.
- B-MVP-021/022 closed: case-activate DB-active branch and `create_principal`
  now require the fail-closed Supabase re-verify (DONE rows).

Security review (adversarial, opus): VERDICT APPROVE-WITH-NITS, no auth bypass,
no weakened forced-reset, no fail-open. Confirmed no surviving sensitive route
lost its guard (24->22 must-reset sites = exactly the 2 deleted challenge GETs);
the two new re-auth additions await `_supabase_reverify` before the privileged
action; deletions broke no live caller; tests re-pointed not weakened; the kept
`sift_session` branch is unminted in prod. The one LOW finding (must-reset test
fidelity) was fixed before merge.

REFUSED-AS-FORK -> B-MVP-023: the `sift_session` cookie-verify branch is
session-establishment (not the re-auth plane), provably unminted in prod but
load-bearing for ~11 test suites' fixtures; deleting it needs a fixture
migration first. Left intact with its examiner Bearer fallback + JTI logout.

Validation on merged main: case-dashboard 356, sift-gateway 492, sift-core 473,
both doc validators PASS, git diff --check clean, secret scans clean, fence held
(case-dashboard/sift-gateway/sift-core only; no configs, no frontend source ->
no bundle rebuild). Worktree wt7-cl3b + branch removed.

Next: BATCH-CL2 (repo rename) + BATCH-PT2 (portal RAG, global-knowledge-only) are
the last two before LV1; both collide with case-dashboard so they run after this.
Then LV1 (end-to-end live + Rocba on the current CLI Supabase stack), where
DB1/UN1/CL3a/CL3b get their live proof. SB1 deferred past LV1. Open: B-MVP-023
(sift_session retirement), B-MVP-008 (parked), B-MVP-018 (AppArmor enforce
post-LV1).

### 2026-06-13 - CL3a landed: Supabase fail-closed re-auth (security-reviewed)

Status: DONE (merged to local main, not pushed; live re-auth smoke folded into LV1).

BATCH-CL3a built by an opus agent, adversarially security-reviewed by a second
opus agent, fix round applied, conductor-reconciled.

What landed (636f425 + bundle rebuild 4b89ac0):
- New `SupabaseAuthCallbacks.reverify_password(email, password, source_ip,
  expected_auth_user_id=...)` (supabase_auth.py): GoTrue password-grant verify,
  session-bound (grant `sub` must equal the session principal's auth_user_id),
  tokens discarded, audit row only after success. Portal wrapper
  `_supabase_reverify` (routes.py) takes the email from the SESSION (never the
  body), password from the body; fail-closed denials 503/401/400/403 with no
  fallback to the file-HMAC plane.
- All file-HMAC verify call sites switched (evidence seal/ignore/retire/
  reacquire/verify, response-guard override, commit, case-activate file branch,
  report generate, 7 backend/service control routes). The file-HMAC functions
  remain dead-but-present (CL3b deletes them).
- `configs/gateway.yaml.template` `portal_session_enabled: false`; the
  `supabase_auth.py` code default stays True so existing installs are unaffected
  until they adopt the new template.
- Frontend switched to POST `{password}` over the existing TLS portal channel;
  served `static/v2` bundle REBUILT (install.sh serves the committed bundle, it
  does not build the frontend) — conductor caught the stale-bundle gap on the
  build gate and committed the rebuild.

Security review (adversarial, opus): VERDICT APPROVE-WITH-NITS, no exploitable
bypass. Confirmed: fail-closed on every error path; identity binding enforced on
the production path; file-HMAC verifiers now have zero live callers; no
password/token logging; audit row only after a passing verify; tests assert
denial + no-action + no-audit-row. One MED finding fixed: an `except TypeError`
branch in `_supabase_reverify` re-invoked the verifier WITHOUT the identity
binding — removed so any TypeError denies. Added an endpoint-level cross-operator
binding rejection test. Docstring nit corrected.

Two PRE-EXISTING re-auth gaps surfaced (present on main before CL3a, now
ticketed): B-MVP-021 (case-activate DB-active branch performs no re-auth) and
B-MVP-022 (agent-credential issuance has no re-auth). Both are CLAUDE.md
sensitive actions; operator to decide whether to close them before LV1.

Validation on merged main: case-dashboard 353, sift-gateway 492, frontend vitest
82, vite build clean, both doc validators PASS, git diff --check clean, secret
scans clean, fence held (case-dashboard/sift-gateway/config template only;
sift-core + file-authority commit ledger untouched). Worktree wt6-cl3a + branch
removed.

Next: BATCH-CL3b (delete the now-dead file-HMAC plane; re-home the must-reset
gate off `_PASSWORDS_DIR` to the Supabase `invited` signal), then CL2 + PT2,
then LV1 (with DB1/UN1/CL3a live-proven during the fresh install). Operator
decision pending on B-MVP-021/022 timing.

### 2026-06-13 - CL3 re-scoped (operator option A): CL3a -> CL3b before LV1

Status: DECISION recorded; CL3a build launched.

Operator resolved the B-MVP-017 fork with option A: build a fail-closed Supabase
operator-password re-verification (GoTrue password grant) for the sensitive
actions and flip `portal_session_enabled` false (BATCH-CL3a), then delete the
now-dead file-HMAC re-auth plane (BATCH-CL3b). CL3a lands BEFORE LV1 so the
end-to-end proof validates the final re-auth design. CL3a is auth-touching ->
`/security-review` is part of its Definition of Done. Scope fence: re-auth only;
the file-authority COMMIT ledger (`verification.write_ledger_entry` via
`_apply_delta`) is explicitly OUT of scope (separate follow-up). LV1 now depends
on CL3a + CL3b.

### 2026-06-13 - Wave landed: DB1 + UN1 + RG1; CL3 refused (re-scope fork)

Status: DONE for 3 of 4 (merged to local main, not pushed); CL3 BLOCKED.

Four fenced worktree agents ran off main e69c491 (CL3 opus; DB1/UN1/RG1
sonnet). Conductor reconciled: independent secret-scan of each branch diff
(clean), file-fence verified (zero cross-branch overlap), cherry-picked the
three mergeable branches linearly onto main, combined gates green.

- DB1 (916f0e6): new `supabase/migrations/202606131000_force_rls_app_tables.sql`
  FORCEs ROW LEVEL SECURITY on all 31 RLS-ENABLED `app.*` tables (explicit
  per-table ALTERs grouped by source migration; idempotent). Conductor caught a
  false-alarm grep (case-sensitive) and confirmed all 31 tables are covered and
  match the HR2 list. component-audit §8 updated. Applies at next install/LV1.
- UN1 (c98ec90): new `scripts/uninstall.sh` (all-or-selected component teardown)
  + maintenance-guide §14. Dry-run by default; add-on removal needs `--yes`,
  core/`--all` needs `--yes --i-understand`, evidence `/cases` needs a separate
  `--remove-evidence --i-understand-evidence-loss` plus a typed confirmation.
  Each teardown branch cites the install.sh function it reverses. bash -n clean.
  Live teardown/reinstall proof folded into the LV1 fresh-install sequence.
  Minor backlog noted by the agent (not yet ticketed): optional
  `--supabase-purge-data` sub-flag (current behavior preserves Postgres volume).
- RG1 (245322a): 15 `docs/regenerate/**` files modernized against current code +
  the new operator/hardening/add-on docs (rag_search_case -> kb_*, OpenCTI
  external, windows-triage removed, sift-service + /var/lib/sift/.sift paths,
  no systemctl --user); new `docs/regenerate/README.md` fact-ownership index;
  promotion recommendations captured there for a later pass. No forks.

CL3 (file-HMAC re-auth retirement) REFUSED - no commit. The opus build agent
proved (and the conductor independently confirmed two load-bearing facts) that
the B-MVP-017 premise is false: there is NO DB/Supabase operator-password
re-verification in the code. `portal_services.record_reauth_event` only inserts
an unconditional `status='success'` audit row; the ONLY operator-password
re-auth verifier is the file-HMAC challenge (`_load_pw_entry` + HMAC compare)
gating evidence seal/ignore/retire, commit, report inclusion, and case-activate;
`_sync_local_reauth_password` bridges that file verifier to the live Supabase
password on login/forced-reset; and the plane ships ENABLED
(`configs/gateway.yaml.template:134 portal_session_enabled: true`). Deleting it
removes the only password re-verify with no replacement = a security regression.
Per CL1 discipline the agent refused rather than force a half-gutted module.
CL3 is a build-replacement-then-delete batch; re-scope is an OPEN operator
decision (see B-MVP-017). The current file-HMAC plane WORKS, so LV1 can proceed
on it; whether LV1 waits for the CL3 re-scope is part of that decision.

Worktrees wt5-{cl3,db1,rg1,un1} and branches wave5/* removed after reconcile.
Validation: both doc validators PASS, git diff --check clean, bash -n
uninstall.sh clean, secret scans clean. No package code changed (DB1=SQL,
UN1=shell, RG1=docs) so no pytest needed; CL3 made no changes.

Next: operator decision on B-MVP-017 (CL3 re-scope). Remaining program:
BATCH-CL2 (rename), BATCH-DB1/UN1 live-prove at LV1, BATCH-PT2 (portal RAG,
global-knowledge-only), then BATCH-LV1 (end-to-end live + Rocba on the current
CLI Supabase stack); BATCH-SB1 deferred to after LV1.

### 2026-06-13 - Operator decision round + B-MVP-020 live CA rotation

Status: DONE (decisions recorded; one live VM action proven; docs-only commit)

Operator cleared the remaining open backlog and resequenced the program:

- B-MVP-012 / BATCH-SB1 DEFERRED to after LV1. The end-to-end proof (LV1) now
  runs first on the current Supabase CLI loopback stack with demo secrets
  accepted as documented lab posture; SB1 (self-managed compose with generated
  secrets) follows LV1 and must precede any non-lab deployment. LV1's
  dependency on SB1 is dropped; SB1 no longer gates LV1.
- B-MVP-013 DECIDED: adopt FORCE ROW LEVEL SECURITY on the 31 RLS-ENABLED
  `app.*` tables. New BATCH-DB1 (schema migration). Gateway `service_role` has
  BYPASSRLS so the gateway path is unaffected; FORCE is defense-in-depth that
  makes RLS apply to the table OWNER and enforces default-deny on the 0-policy
  tables.
- B-MVP-006 DECIDED: all portal-managed RAG documents are GLOBAL KNOWLEDGE
  ONLY; no case-derived chunks. PT2 scope is now add/list/refresh/retire for the
  shared knowledge plane only.
- B-MVP-007 DECIDED: keep the OpenCTI add-on images for now; new BATCH-UN1
  builds a component uninstaller that removes ALL or operator-SELECTED
  components, dry-run by default, with evidence under `/cases` never removed
  without its own explicit flag.
- B-MVP-008 PARKED (kept open): air-gapped Volatility symbol provisioning later.
- B-MVP-018 DECIDED: keep AppArmor COMPLAIN-only through LV1; revisit
  enforce-mode only after the end-to-end test passes.

B-MVP-020 (live-proven, operator-requested): ran
`rotate-tls.sh --rotate-ca --i-understand-clients-lose-trust` on the existing
VM to migrate it to the full hardened CA profile and test the adoption path.
Before: CA `CN=sift-mcps-CA` already carried critical basicConstraints CA:TRUE
(the row's "no CA extensions" premise was partly stale) but lacked an explicit
critical keyUsage; leaf already had serverAuth EKU. After: new CA
`CN=Protocol SIFT Gateway local CA` with critical basicConstraints CA:TRUE +
critical keyUsage(keyCertSign,cRLSign); fingerprint rotated
`D4:93:87…` -> `E5:34:F9…`; leaf re-issued with serverAuth EKU and
IP:192.168.122.81/IP:127.0.0.1/DNS SANs; keys 0600, certs 0644, all
sift-service-owned; gateway restarted, `/health` status=ok, both services
active; `curl --cacert ca-cert.pem` verifies WITHOUT `-k` on the IP SAN.
Operator note: every client that imported the OLD ca-cert.pem must re-import
`/var/lib/sift/.sift/tls/ca-cert.pem`.

B-MVP-019 (operator asked for detail): `setup-addon.sh` builds the gateway
register payload from the OPERATOR's checkout — `command` resolves to the
operator's `uv` (`~/.local/bin/uv`), `--project` to `~/sift-mcps`, and
`manifest_path` under `~/sift-mcps/packages/...`. The hardened gateway runs
`ProtectHome=tmpfs`, so it sees an empty `/home/*` and can only reach
`/opt/sift-mcps` + system paths. An add-on registered with those operator-home
paths would pass validate/register but FAIL TO LAUNCH when the gateway tries to
exec the stdio child (the AD2 OpenCTI proof was a stub and never launched a
real child end to end, so this did not surface). AD2 already fixed the related
register-DIR permission half (payload now written to operator-writable
`~/.sift/addon-register`). The remaining path-derivation half: derive
`command`/`--project`/`manifest_path` from the staged `/opt/sift-mcps` tree and
a gateway-visible `uv`. Re-pointed to BATCH-LV1 (best fixed when LV1 first
launches a real add-on under the hardened gateway, using live-confirmed staged
paths). Operator to confirm: fix now as a standalone patch, or fold into LV1.

New batches: BATCH-DB1 (FORCE RLS), BATCH-UN1 (component uninstaller).
Validation: both doc validators pass; `git diff --check` clean. No secret
values committed; the live rotation printed no key material.

Next: remaining program is BATCH-CL2 (rename), BATCH-CL3 (file-HMAC retire),
BATCH-DB1 (FORCE RLS), BATCH-PT2 (portal RAG, global-knowledge-only),
BATCH-UN1 (uninstaller), BATCH-RG1 (regenerate docs), then BATCH-LV1
(end-to-end live + Rocba, on the current CLI Supabase stack); BATCH-SB1
deferred to after LV1.

### 2026-06-12 - Trust and add-on wave landed: TLS1 + AD2

Status: DONE (six commits merged to local main; not pushed; live VM re-proven)

Changed (TLS1, three commits): installer local-CA profile hardened - CA gets
critical basicConstraints + keyCertSign/cRLSign, leaf gets serverAuth EKU
(previously missing), SANs stay derived from the real host; reruns provably
preserve the CA (fingerprint unchanged across installer reruns); new
`scripts/rotate-tls.sh` with `--renew-leaf` (live-proven: gateway served the
renewed leaf) and DANGER-gated `--rotate-ca`; handoff and maintenance-guide
section 11 now carry exact client trust steps (browser import,
REQUESTS_CA_BUNDLE/SSL_CERT_FILE, curl --cacert) and the deferred ACME
profile. New tests/test_tls1_cert_profile.py (5 tests) guards the profile.

Changed (AD2, three commits): conformance suite +31 tests closing the AD1 gap
list (scope/prohibited-op denial, duplicate tools, clean-disable, hot-reload,
env_refs negatives, requirement gating, manifest negatives, core-stays-clean
regression). THREE real bugs found and fixed: setup-addon.sh emitted raw
secret env maps the registry rejects (now env_refs-only payloads);
empty namespace bypassed prefix enforcement (now fail-closed); register dir
pointed at the service-owned .sift dir so the script could not run on a
hardened install (now operator-writable ~/.sift/addon-register).

B-MVP-016 RESOLVED as KEEP: the "dead field" premise was wrong -
opensearch-mcp ships `scope_enforcement` on opensearch_enrich_intel, so
schema removal would reject a live manifest. Regression tests added.

Live OpenCTI add-on proof (contract-mechanics level, stub endpoint, no
platform stack provisioned): validate ok (namespace=cti, 8 query-only
tools); registry register -> audit `mcp_backend.registered`; hot-appeared in
/health ~15 s after row seed WITHOUT gateway restart (tools_count 17->25,
MainPID unchanged); OpenSearch indices byte-identical before/after (no
contamination); disable -> `enabled_changed` audit + restart-applied catalog
removal per D34; unregister -> row deleted, full audit lifecycle; final state
back to exactly 2 core backends, /health ok, no OpenCTI containers ever ran,
no temp/token files left. Operator-session REST and agent-credential /mcp
listing remain the known LV1 gap (operator principal still `invited`).

New backlog: B-MVP-019 (setup-addon payload paths vs ProtectHome),
B-MVP-020 (pre-TLS1 CA on existing installs; fresh installs get the new
profile).

Validation: gateway+opencti suites 503 passed on merged main, +42 on the VM
tree (Python 3.12); TLS profile tests 5/5; bash -n clean; both doc
validators OK; git diff --check clean; secret scans clean; post-merge VM
rerun exit 0 with /health status=ok and both services active.

Next: Remaining program is BATCH-SB1 (self-managed Supabase compose),
BATCH-CL2 (ProtocolSiftGateway rename + add_ons layout), BATCH-CL3
(file-HMAC plane retirement), BATCH-PT2 (portal RAG management), BATCH-RG1
(regenerate-docs modernization), and BATCH-LV1 (end-to-end live validation +
Rocba proof, including the agent-credential MCP smoke).

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
| B-MVP-018 | Backlog | OPEN | DECIDED 2026-06-13: keep AppArmor COMPLAIN-only through BATCH-LV1; revisit enforce-mode only after the end-to-end test passes (then aa-logprof profiling against ingest/run_command + a dedicated live rerun before flipping to enforce). | Future hardening batch (post-LV1) |
| B-MVP-019 | Backlog | OPEN | Operator briefed 2026-06-13 (detail in change log). setup-addon.sh embeds operator-home paths (command=`~/.local/bin/uv`, `--project ~/sift-mcps`, manifest under `~/sift-mcps`) in register payloads, but the hardened gateway runs ProtectHome=tmpfs and can only see `/opt/sift-mcps` + system paths, so a so-registered add-on would fail to launch under the live gateway. Fix = derive command/project/manifest from the staged `/opt/sift-mcps` tree. Operator confirmed 2026-06-13: FOLD INTO BATCH-LV1 — fix when LV1 first launches a real add-on under the hardened gateway, using live-confirmed staged paths. | BATCH-LV1 |
| B-MVP-020 | Backlog | DONE | DONE 2026-06-13 (operator-requested, live-proven): ran rotate-tls.sh --rotate-ca on the existing VM. New CA CN="Protocol SIFT Gateway local CA" with critical basicConstraints CA:TRUE + critical keyUsage(keyCertSign,cRLSign); leaf re-issued with serverAuth EKU + IP/DNS SANs; keys 0600 / certs 0644 sift-service; gateway restarted, /health ok, both services active; curl --cacert verifies WITHOUT -k on the IP SAN. Clients must re-import /var/lib/sift/.sift/tls/ca-cert.pem. | BATCH-TLS1 / live |
| B-MVP-021 | Backlog | OPEN | Pre-existing gap (surfaced by CL3a security review, NOT a CL3a regression): `post_case_activate` DB-active branch (`_ACTIVE_CASES is not None`, the live VM path) returns before any re-auth, so case activation — a CLAUDE.md sensitive action — is NOT re-authed under DB authority. DONE 2026-06-13 (CL3b, 718684e): the DB-active branch now `await _supabase_reverify` before `set_active_case`; fail-closed tested (wrong-pw 401, control-plane-down 503, success). | BATCH-CL3b |
| B-MVP-022 | Backlog | OPEN | Pre-existing gap (surfaced by CL3a security review): agent/service credential issuance (`create_principal`, POST /api/auth/principals) gates only on owner/admin role — no operator-password re-verify, though agent-credential issuance is a CLAUDE.md sensitive action. DONE 2026-06-13 (CL3b, 718684e): `create_principal` now requires Supabase re-verify in addition to the owner/admin gate; fail-closed tested (wrong-pw 401, missing-pw 400, success). | BATCH-CL3b |
| B-MVP-023 | Backlog | OPEN | CL3b refused-as-fork (2026-06-13): the `sift_session` cookie-verify branch in case-dashboard auth.py is session-ESTABLISHMENT (not the file-HMAC re-auth plane), provably unminted in production but load-bearing for ~11 test suites' auth fixtures (generate_jwt + COOKIE_NAME). Migrate those fixtures to the Supabase-envelope harness, then delete the branch (and its examiner Bearer fallback / JTI logout if also dead). Not security-blocking (reaching it needs an already-secret-signed JWT). | Future legacy-session retirement batch |

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
