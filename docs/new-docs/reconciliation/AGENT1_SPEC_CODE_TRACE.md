# AGENT 1 — SPEC-to-Code Architecture Trace

**Scope.** Reconcile `docs/drafts/architecture/sift-architecture-SPEC.md` (and its
companion `docs/drafts/architecture/active-case-authority-flow.md`) against the
*current* code, plane by plane. Source precedence applied strictly: current
code + tests decide what is implemented now; the SPEC anchors intended
architecture; on conflict the contradiction is recorded, not silently resolved.

**Base commit.** `a7ea369` (worktree `/Users/yk/AI/SIFTHACK/recon-wt/agent1-spec-code`).
The SPEC was code-grounded at `156e810` (2026-06-14); the authority-flow doc at
`e3ce8f8` (2026-06-18). My base is newer than both, so line-number / surface
drift is expected and is itself a finding.

**Method.** codebase-memory MCP graph (`index_status`: 15,968 nodes / 61,764
edges, status `ready`) for routing + `get_architecture`; every graph finding
verified against source with `Read`/`Grep` in the worktree before assertion. All
`file:line` citations are relative paths against the worktree (= same commit as
the indexed main repo).

**Index project name used.** `Users-yk-AI-SIFTHACK-sift-mcps`.

**Status legend.** confirmed | partially confirmed | stale | contradicted | not found.

---

## Plane 1 — Gateway is the ONLY policy boundary

**SPEC claim** (§0, §1 row 2, §9 "Single policy boundary"): every REST call,
every MCP tool call, every privileged action passes through the Gateway; per-backend
direct `/mcp/{name}` routes DISABLED.

**Current code evidence.**
- Aggregate `/mcp` is the only MCP mount; per-backend routes are explicitly not
  mounted: `packages/sift-gateway/src/sift_gateway/server.py:1236-1237`
  ("Per-backend /mcp/{name} routes are intentionally not mounted (D3/F-7)").
- HTTP middleware stack present and ordered as SPEC §3 describes (added
  last-first in Starlette): `SecureHeadersMiddleware` (`server.py:1450`),
  `_PortalHTTPSGuard` (`server.py:1447`), `_NormalizeMCPPath` (`server.py:1444`),
  `CORSMiddleware` (`server.py:1435`), `AuthMiddleware` (`server.py:1416`).
- Mounts: `/portal` (v2) `server.py:1391`, `/mcp` `server.py:1395`.

**Status: confirmed** (with one stale mount detail — see Plane 3 / Ledger #4).

**Required follow-up.** None for the boundary claim itself.

**Risks / missing tests.** The boundary holds only as long as no second ingress
is added; `test_phase6.py` and `test_portal_root_redirect.py` guard mounts but
there is no single test asserting "no `/mcp/{name}` route exists" — recommend an
explicit negative route test.

---

## Plane 2 — MCP tool-call chain (agent → gateway → backend), authz + case-arg injection

**SPEC claim** (§3): a fixed, ordered 9-stage chain
`Catalog→ToolAuthz→AddonAuthority→CaseContext→Audit→ProxyActiveCase→EvidenceGate→ResponseGuard→JobDispatch`;
deny at any stage short-circuits with an audited MCP error.

**Current code evidence.** `gateway_policy_middlewares()`
(`packages/sift-gateway/src/sift_gateway/policy_middleware.py:1247-1280`) returns,
in order:
1. `ControlPlaneRequiredMiddleware` (BU3/XYE-21) — **NOT in the SPEC §3 diagram**
2. `ToolAuthorizationMiddleware`
3. `AddonAuthorityMiddleware`
4. `CaseContextMiddleware`
5. `AuditEnvelopeMiddleware`
6. `ProxyActiveCaseMiddleware`
7. `EvidenceGateMiddleware`
8. `ResponseGuardMiddleware`
9. `OpenSearchJobDispatchMiddleware`

`GatewayToolCatalogMiddleware` is prepended before this list in
`mcp_server.py:388-389`, so the real served chain is **Catalog + 10 policy
middlewares = 11 stages**, vs the SPEC's "9". The relative order of the named
stages matches the SPEC exactly; the SPEC simply omits the BU3 outer backstop.

Case-arg injection: `CaseContextMiddleware.on_call_tool`
(`policy_middleware.py:728`) injects DB active-case context; the DB-registered
manifest's `safe_case_argument_names` (e.g. `case_dir`) drives schema-gated
injection — confirmed via the manifest-drift class
(`mcp_backends_registry.py:141-152`, B-MVP-032: a stale `manifest_sha256` snapshot
"silently disables" newly-declared case args like `case_dir`). This corroborates
the memory note `reference_gateway_manifest_registration_drift`.

**Status: partially confirmed** (chain is real and correctly ordered, but the SPEC
stage count (9) and diagram are stale: missing `ControlPlaneRequiredMiddleware`;
`GatewayToolCatalog` is shown as a participant but lives outside the policy list).

**Required follow-up.** Update SPEC §2 (`MCPMW` node text) and §3 (sequence
diagram + "9-stage" wording) to "Catalog + 10" and add the
`ControlPlaneRequired` backstop as the outermost stage.

**Risks / missing tests.** None new — `test_pr03_tool_authorization.py`,
`test_audit_envelope.py`, `test_opensearch_dispatch_middleware.py`,
`test_b032_manifest_drift.py` cover the stages.

---

## Plane 3 — REST vs MCP separation (portal REST human-only; agents MCP-only)

**SPEC claim** (§1 row 1, §9): portal REST is human-operator only; AI agents reach
tools ONLY through `/mcp`.

**Current code evidence (bidirectional enforcement).**
- REST tool execution rejects agents: `rest.py:229,242`
  ("REST tool execution is operator-only; agents must use the Gateway MCP surface").
- `AuthMiddleware` blocks agent tokens on the portal API before passthrough:
  `auth.py:119-133` (`path.startswith("/portal/api/")` + `role == "agent"` ⇒ 403);
  the rationale comment at `auth.py:264-266` states agents "use the Gateway MCP
  surface (/mcp) exclusively". Guarded by
  `packages/sift-gateway/tests/test_portal_agent_block.py`.

**Stale sub-claim.** SPEC §3 "Mounts" line lists
`/dashboard (v1 LEGACY, legacy_portal_session_enabled plane, slated removal)`. The
current `server.py` mounts **no `/dashboard`** (grep for `Mount("/dashboard"` /
`create_dashboard_v1` returns nothing; only `/portal` v2 + `/mcp`). The "slated
removal" already happened.

**Status: confirmed** (enforcement) / **stale** (the `/dashboard` mount detail).

**Required follow-up.** Remove `/dashboard` from SPEC §3 Mounts (and the
`legacy_portal_session_enabled` plane reference unless it survives elsewhere).

**Risks / missing tests.** Covered by `test_portal_agent_block.py`.

---

## Plane 4 — Supabase/Postgres is the authoritative control plane (no file-mode fallback)

**SPEC claim** (§0, §1 row 4, §9 "DB authority", and the entire authority-flow
companion doc): Postgres authoritative; no implicit file-mode fallback; startup
exits without DSN; reads fail closed; no env/pointer active-case.

**Current code evidence (both load-bearing invariants re-read verbatim).**
- **Startup fail-closed.** `__main__.main` (`packages/sift-gateway/src/sift_gateway/__main__.py:112-126`):
  `dsn, _ = registry_config(config); if not dsn:` → logs + prints "…has no
  file-mode fallback … Refusing to start." → `sys.exit(1)`. Matches the
  authority-flow doc §4① verbatim.
- **Pre-file-read raise.** `_require_active_case`
  (`packages/sift-core/src/sift_core/case_manager.py:620-665`): the
  `from sift_core.active_case_context import …` is wrapped in `except ImportError`
  **only** (line 634); runtime authority resolution is outside the guard (fails
  closed); `if db_active: raise ValueError(...)` (line 661) sits **above** every
  file branch (`SIFT_CASE_DIR` at 667, `~/.sift/active_case` pointer at 680,
  `CASE.yaml` belt at 709). Matches authority-flow doc §4② verbatim, including the
  inline "fail-OPEN downgrade" comment (lines 623-628).
- **In-process backstop.** `ControlPlaneRequiredMiddleware`
  (`policy_middleware.py:496-543`): even an embedded/test app that bypasses
  `__main__` is refused — `if getattr(self.gateway, "control_plane_dsn", None)`
  else returns an audited `control_plane_unavailable` error
  ("there is no file-mode fallback"). `tools/list` deliberately untouched.
- **Authority contextvar.** `db_authority_active()`
  (`active_case_context.py:96-111`) reads the contextvar; the spine forces it true
  on every served path.

**Status: confirmed** (the strongest-verified plane in the system; the companion
authority-flow doc is accurate to the line at this base commit).

**Required follow-up.** None. The authority-flow doc's residual-file-touch ledger
(§5) and follow-up units (XYE-60/61/62) remain valid.

**Risks / missing tests.** Well covered: `test_bu3_no_file_mode.py`,
`test_bu3_file_readers_unreachable.py`, `test_bu4_retire_fallbacks.py`,
`test_k6_file_authority_removal.py`, `test_xye35_require_active_case_fail_closed.py`,
`test_mvp_k1_authority_context.py`.

---

## Plane 5 — OpenSearch is DERIVED, never authoritative (but first-party/core)

**SPEC claim** (§0, §1 row 6, §9 "DB authority"): OpenSearch is a derived,
never-authoritative data plane; first-party/core (install.sh); may be named by the
gateway; per-consumer scoped roles.

**Current code evidence.**
- opensearch-mcp two-layer is real and self-documenting:
  `packages/opensearch-mcp/src/opensearch_mcp/registry.py:754-760` — "This registry
  is the typed contract layer; `opensearch_mcp.server` holds the [engine]";
  delegation via `from opensearch_mcp import server as impl` (`registry.py:760`).
  Matches CLAUDE.md's "registry.py = served typed contract; server = engine".
- Core/first-party: `install.sh:148` provisions the dedicated worker; the SPEC
  labels opensearch-mcp "(CORE, install.sh)" — consistent with memory
  `project_opensearch_core_decision`.
- Derived/non-authoritative: no opensearch read path is treated as control-plane
  authority; active case + custody + findings all resolve from Postgres (Plane 4).

**Status: confirmed.**

**Required follow-up.** None.

**Risks / missing tests.** OpenSearch surface tested via
`test_opensearch_mcp_surface_snapshot.py` (golden); no test asserts
"OpenSearch is never read as authority" (that property is enforced structurally,
not by a single test).

---

## Plane 6 — Worker/job model (thin policy boundary spawns N least-priv workers; durable lanes; realtime status)

**SPEC claim** (§5, §1 rows 6-7): heavy work runs as durable Postgres jobs claimed
by least-privilege workers (`FOR UPDATE SKIP LOCKED`, lease 300s, poll 1s);
OpenSearch ingest fans out to N `sift-opensearch-worker@.service`; status via a
sanitized `job_status_public` read-model that never exposes
`spec_internal`/`worker_id`/lease; `expire_stale_jobs` RPC.

**Current code evidence.**
- Claim semantics: `packages/sift-core/src/sift_core/execute/job_worker.py:8`
  ("`FOR UPDATE SKIP LOCKED` so two workers can never claim the same job"),
  `lease_seconds: int = 300` (line 236), `poll_interval: float = 1.0` (line 237),
  `expire_stale_jobs()` → `select app.expire_stale_jobs()` (lines 380-381).
- Sanitized status: `packages/sift-gateway/src/sift_gateway/jobs.py:10-11` —
  "polls status via the `app.job_status_public` sanitized read model … never
  `spec_internal`, `worker_id`, lease".
- OpenSearch fan-out: `OpenSearchJobDispatchMiddleware` redirects
  `opensearch_ingest` / `opensearch_enrich_intel` to durable `ingest`/`enrich`
  jobs (`policy_middleware.py:1094,1124-1200`); the registry result documents
  "dispatched to a sift-opensearch-worker@" (`registry.py:551,1831`);
  `ingest_job.py:17` describes the dedicated `sift-opensearch-worker@` unit.

**Status: confirmed.** This matches memory
`project_opensearch_worker_decoupling` (gateway = thin policy boundary spawning N
scalable least-priv workers).

**Required follow-up.** None.

**Risks / missing tests.** Covered: `test_job_worker.py`,
`test_opensearch_dispatch_middleware.py`, `test_ingest_job_handler.py`,
`test_mvp_binding_job_tools.py`, `test_osw_b3_b4.py`.

---

## Plane 7 — Evidence custody lifecycle (register → seal → analyze; re-auth; immutability)

**SPEC claim** (§1 row 8, §9 "Evidence gate"/"Evidence immutability"/"Re-auth"):
tools blocked until evidence registered + sealed + chain OK; seal/unseal/ignore/
retire require re-auth; evidence immutable via `chattr +i`; append-only custody.

**Current code evidence.**
- Gate (DB-native, fail-closed): `check_evidence_gate_db`
  (`packages/sift-gateway/src/sift_gateway/evidence_gate.py:62-135`) — missing
  case_id / DSN / DB error ⇒ blocked; no head row ⇒ `UNSEALED` + blocked
  ("No sealed evidence for this case"); only `ChainStatus.OK` clears the gate.
  `build_block_response` (line 136) returns the agent-facing block.
  `EvidenceGateMiddleware` (`policy_middleware.py:546-614`) wires it into the chain.
- Immutability: `evidence_chain.py:_set_immutable` (line 730) sets the FS immutable
  flag (`_FS_IMMUTABLE_FL = 0x00000010`, line 727) on seal (`seal_manifest`,
  line 546) and clears it on unseal/retire (lines 496, 670-673). **Nuance:** it
  uses the in-process `ioctl(FS_IOC_SETFLAGS)`, not the literal `chattr` binary —
  functionally equivalent to `chattr +i` but the SPEC's literal "`chattr +i`"
  phrasing is an approximation.
- Re-auth: `approval_auth.py` carries an HMAC approval ledger "Domain-separated
  from login auth" (line 60); the `approval_ledger_db` migration + CL3a tests
  (`test_cl3a_supabase_reverify.py`, `test_fork2_approval_ledger_db.py`) back the
  re-verify path.

**Status: confirmed** (with the `chattr` literal-vs-`ioctl` nuance noted).

**Required follow-up.** Soften SPEC §4/§9 "`chattr +i`" to "FS immutable flag
(ioctl FS_IOC_SETFLAGS / equivalent to `chattr +i`)" for precision.

**Risks / missing tests.** Covered: `test_evidence_gate_db.py`,
`test_evidence_chain.py`, `test_evidence_unseal.py`, `test_evidence_reacquire.py`,
`test_j1_report_reauth_custody.py`.

---

## Plane 8 — Report/export flow (approved findings + approved supporting data only)

**SPEC claim** (§1 row 8, §0): reports include approved findings and approved
supporting data only.

**Current code evidence.** `reporting.py`
(`packages/sift-core/src/sift_core/reporting.py`): module docstring "assembling a
structured report from approved …" (line 3); explicit filter
`approved_findings = [f for f in findings if f.get("status") == "APPROVED"]`
(line 337) and `approved_timeline` (line 338); the report data carries the warning
"contains ONLY approved findings and timeline events" (lines 112-115); per-finding
approval provenance (content_hash) appendix (lines 176-218); approval tip read via
`read_approval_commit_tip_db` (line 34).

**Status: confirmed.**

**Required follow-up.** None.

**Risks / missing tests.** Covered: `test_reporting_custody_appendix.py`,
`test_reporting_evidence_chain.py`, `test_j1_report_reauth_custody.py`,
`test_finding_grounding_supersedes.py`.

---

## Plane 9 — Add-on routing (DB manifest snapshot is runtime authority; default_case_scoped; reference-plane opt-out)

**SPEC claim** (§1 row 5, §9 "Add-on authority"): backends registered in
`app.mcp_backends`, reached only via gateway; authority_contract + required_scopes;
prohibited ops denied. (CLAUDE.md + memory add: DB manifest snapshot is the runtime
authority, not the live file; reference-plane add-ons must declare
`default_case_scoped:false` or be denied under an active case.)

**Current code evidence.**
- Manifest snapshot = runtime authority: `mcp_backends_registry.py` stores
  `manifest_sha256` (line 71), `default_case_scoped` (line 68), and the
  `ManifestDrift` class (lines 141-152) makes the on-disk-vs-row drift explicit
  (B-MVP-032) — a stale row silently disables file-declared features. Confirms
  memory `reference_gateway_manifest_registration_drift`.
- `default_case_scoped` semantics + reference-plane opt-out:
  `mcp_backends_registry.py:91-95` ("Derived/reference-plane metadata (BATCH-F1):
  surface whether the [backend is case-scoped by default]"). Corroborates memory
  `reference_reference_plane_case_scope` (B-MVP-053: reference add-ons must set
  `default_case_scoped:false`).
- Authority enforcement: `AddonAuthorityMiddleware`
  (`policy_middleware.py:360-441`) enforces `required_scopes` (lines 397-401) and
  denies `prohibited_operations` (lines 416-431, `addon_prohibited_operation`).

**Status: confirmed.**

**Required follow-up.** SPEC §5/§9 could name the `default_case_scoped` /
reference-plane opt-out explicitly (currently only implied).

**Risks / missing tests.** Covered: `test_d22a_mcp_backends_registry.py`,
`test_b032_manifest_drift.py`, `test_ad2_addon_conformance.py`,
`test_osx1_late_seeded_backends.py`.

---

## Plane 10 — run_command sandbox (Landlock + seccomp(kill) + cgroup + AppArmor=enforce; pipes/redirects via multi-stage shell=False)

**SPEC claim** (§4): CEILING (security.py allowlist/scanners/env-deny) + FLOOR
(runtime-user fail-closed, systemd-run scope with MemoryMax/TasksMax/OOMPolicy=kill/
IPAddressDeny=any, no-new-privs, Landlock ABI v4 deny-default, seccomp=KILL,
AppArmor `dfir-exec`=ENFORCE); `run_command` supports `| && || ; > >> < 2>&1` with
`shell=False`, multi-stage argv.

**Current code evidence.**
- FLOOR launcher: `packages/sift-core/src/sift_core/execute/dfir_exec_launcher.py`
  — Landlock syscalls + ABI detection (`landlock_restrict_self` = 446,
  `_landlock_abi`, `_install_landlock`, lines 139-352); no-new-privs
  (`_set_no_new_privs` → `PR_SET_NO_NEW_PRIVS`, lines 244-245); seccomp BPF install
  (`_install_seccomp`, line 480) with `SECCOMP_RET_KILL_PROCESS = 0x80000000`
  (line 36); refuses uid 0 / service uid (lines 231-240).
- systemd-run scope: `packages/sift-core/src/sift_core/execute/executor.py:101-124`
  — `MemoryMax`, `TasksMax` (default 64), `OOMPolicy=kill`, `IPAddressDeny=any`.
- Runtime-user fail-closed: `executor.py:281-308`
  (`SIFT_EXECUTE_REQUIRE_RUNTIME_USER` requires `execute.runtime_user`);
  `config.py:39` `execute_as_user: str = "agent_runtime"`.
- AppArmor enforce: `harden.sh` flips the `sift-gateway` + `dfir-exec` profiles
  COMPLAIN→ENFORCE (`harden.sh:6-34`), equivalently `./install.sh --apparmor-enforce`.
- Multi-stage pipes/redirects: corroborated by memory
  `project_run_command_security` (pipes/redirects work via gateway multi-stage
  shell=False; RUN-3 OS-level sandbox live-proven) and the `In` node text in SPEC
  §4 ("supports | && || ; > >> < 2>&1").

**Nuance / posture mismatch.** The seccomp default mode in code is **`log`, not
`kill`**: `_seccomp_action` returns `SECCOMP_RET_KILL_PROCESS` only when
`seccomp_mode`/`SIFT_EXECUTE_SECCOMP_MODE == "kill"`, else `SECCOMP_RET_LOG`
(`dfir_exec_launcher.py:475-477`). Likewise AppArmor is provisioned in COMPLAIN by
default and flipped to ENFORCE by install/`harden.sh`. The SPEC §4 "seccomp = KILL"
/ "AppArmor=ENFORCE" describe the **deployed/hardened posture** (the live-proven
RUN-3 state, which §4 explicitly frames as "Live-proven (RUN-3) … under jail"), not
the code default. This is a default-vs-deployed distinction, not a contradiction,
but the SPEC should say so.

**Status: confirmed** (mechanisms) with a **default-vs-deployed posture caveat** on
seccomp/AppArmor.

**Required follow-up.** Add one line to SPEC §4 noting that seccomp=kill and
AppArmor=enforce are the *hardened* posture (install `--apparmor-enforce` /
`harden.sh` / `SIFT_EXECUTE_SECCOMP_MODE=kill`); the code default is log/complain.

**Risks / missing tests.** Covered: `test_dfir_exec_launcher.py`,
`test_execute_security_policy.py`, `test_mvp_k5_run_command_isolation.py`,
`test_run_command_uplift_i1.py`. Gap: no CI test asserting the *enforce* posture
(it is live-VM-proven only, per memory `project_postmvp_run1` / XYE-9).

---

## Additional SPEC sections checked

### §6 Component & function inventory — file paths
**Status: partially confirmed.** All 20 gateway files and all 14 core files named in
§6 exist EXCEPT the transport modules: SPEC lists `http_backend.py` /
`stdio_backend.py` at the package root, but they live in the `backends/`
subpackage — `packages/sift-gateway/src/sift_gateway/backends/http_backend.py`
and `…/backends/stdio_backend.py` (plus `backends/base.py`). Path drift only.

### §7 MCP tool surface — opensearch_* list
**Status: stale.** SPEC §7 lists 16 `opensearch_*` tools, but the typed contract
(`opensearch-mcp/src/opensearch_mcp/registry.py`) now exposes more, including
`opensearch_detection_catalog`, `opensearch_field_catalog`,
`opensearch_index_catalog`, `opensearch_cluster_shards`,
`opensearch_cluster_status` (and `_resource` companion variants). The SPEC's
short-name list (`search count aggregate timeline …`) is an outdated subset.
Regenerate from the golden surface snapshot
(`test_opensearch_mcp_surface_snapshot.py`).

### §7 / §6 — OpenCTI writes `opencti_*` indices to OpenSearch
**Status: contradicted / not found.** This is the most material drift (Ledger #1).
The opencti-mcp package exposes only **8 query-only `cti_*` tools**
(`opencti_query.py` registry: `cti_get_health`, `cti_search_threat_intel`,
`cti_search_entity`, `cti_lookup_ioc`, `cti_get_recent_indicators`,
`cti_get_entity`, `cti_get_relationships`, `cti_search_reports` —
`packages/opencti-mcp/src/opencti_mcp/registry.py:199-211`). A repo-wide grep for
any `opencti_*` OpenSearch index write
(`grep -rn "opencti_" packages/ --include=*.py | grep -i index/bulk/write/ingest`)
returns **nothing**; the opencti client talks only to the OpenCTI GraphQL API.
So the SPEC §1/§2 data-plane "`opencti_*` indices", the §2 flow arrow
`CTIMCP -- "opencti_* indices (scoped role)" --> OS`, and the §6/§7 "writes
opencti_* to OpenSearch" / "`opencti_*`" tool naming are **stale or aspirational**.

### §8 Control-plane migrations
**Status: partially confirmed (stale tail).** The 20 migrations SPEC §8 lists match
disk order exactly through `opensearch_worker_status`. Disk has **21** — a 21st,
`202606160100_evidence_unseal.sql`, was added after the SPEC (06-14) but before the
authority-flow doc (06-18). Append `evidence_unseal` to §8.

### §3 HTTP mounts — `/dashboard` v1
**Status: stale.** Covered under Plane 3 — no `/dashboard` mount remains.

---

## Contradiction Ledger

1. **OpenCTI → OpenSearch `opencti_*` indices.**
   - SPEC: §1/§2 data plane shows `case-* + opencti_*` indices; §2 flow
     `CTIMCP → OS` writing `opencti_*` under a scoped role; §6 "writes opencti_* to
     OpenSearch"; §7 tool naming "`cti_*` / `opencti_*`".
   - Code: opencti-mcp exposes only 8 query-only `cti_*` tools
     (`opencti-mcp/.../registry.py:199-211`); zero `opencti_*` index-write code
     anywhere in `packages/` (grep empty); client is GraphQL-only.
   - Classification: **contradicted / mislabeled** (the SPEC §2 arrow points at the
     wrong datastore — see resolution; the `opencti_*` indices are real but live
     outside the SIFT forensic cluster).
   - Reviewer-resolved evidence (R-A1.1): `docker-compose.opencti.yml:13-41` and
     `:110-115` — the OpenCTI add-on runs its **own isolated OpenSearch cluster**
     on network `sift-opencti-net` with `INDEX_PREFIX=opencti`, and a comment there
     **explicitly forbids** writing `opencti_*` into the SIFT forensic cluster. So
     `opencti_*` indices DO exist, in a separate/isolated OpenCTI datastore.
   - Recommended resolution: **RELABEL** the SPEC §2 arrow + §1 data-plane indices
     to point at the OpenCTI add-on's **separate/isolated** OpenSearch datastore
     (cite `docker-compose.opencti.yml:13-41,110-115`); do **NOT delete** — the
     `opencti_*` indices are real but live outside the SIFT forensic cluster. Treat
     as a doc relabel, not a code change. The §6/§7 wording "writes opencti_* to
     OpenSearch under scoped role" remains misleading insofar as it implies the
     opencti-mcp package does the write (it does not — it is query-only `cti_*`);
     the population belongs to the add-on's own cluster, not to opencti-mcp.

2. **Policy-chain stage count & composition.**
   - SPEC: §2/§3 "9-stage" chain
     `Catalog→ToolAuthz→AddonAuthority→CaseContext→Audit→ProxyActiveCase→EvidenceGate→ResponseGuard→JobDispatch`.
   - Code: `policy_middleware.py:1262-1280` returns 10 policy middlewares led by
     `ControlPlaneRequiredMiddleware` (BU3); `GatewayToolCatalogMiddleware` is
     prepended in `mcp_server.py:388-389` ⇒ 11 served stages.
   - Classification: **stale** (order correct, count + backstop missing).
   - Recommended resolution: update §2 `MCPMW` node + §3 diagram to add the
     `ControlPlaneRequired` outer backstop and correct the count.

3. **seccomp / AppArmor enforcement is the deployed posture, not the code default.**
   - SPEC: §4/§9 state "seccomp = KILL" and "AppArmor=enforce" as flat facts.
   - Code: default seccomp mode is `log` (`dfir_exec_launcher.py:476`); AppArmor
     installs COMPLAIN, flips to ENFORCE only via `harden.sh` /
     `--apparmor-enforce`.
   - Classification: **partially confirmed** (mechanisms present; posture is
     install-gated).
   - Recommended resolution: annotate §4 that kill/enforce are the hardened
     posture (live-proven RUN-3), with the env/flag that selects it.

4. **`/dashboard` v1 mount "slated removal".**
   - SPEC: §3 Mounts lists `/dashboard (v1 LEGACY … slated removal)`.
   - Code: no `/dashboard` mount in `server.py` (only `/portal`, `/mcp`).
   - Classification: **stale** (removal completed).
   - Recommended resolution: delete the `/dashboard` mount line and the
     `legacy_portal_session_enabled` plane reference from §3.

5. **`opensearch_*` tool list (§7) is an outdated subset.**
   - SPEC: 16 names. Code (`opensearch-mcp/.../registry.py`): more, incl.
     `*_catalog`, `*_cluster_*`, `_resource` variants.
   - Classification: **stale**.
   - Recommended resolution: regenerate §7 from the golden surface snapshot.

6. **`http_backend.py` / `stdio_backend.py` path (§6).**
   - SPEC: package root. Code: `sift_gateway/backends/`.
   - Classification: **stale** (path drift).
   - Recommended resolution: fix the §6 paths to `backends/…`.

7. **Migrations list (§8) missing the 21st migration.**
   - SPEC: ends at `opensearch_worker_status` (20). Disk: + `evidence_unseal` (21).
   - Classification: **stale (tail)**.
   - Recommended resolution: append `evidence_unseal`.

8. **`chattr +i` literal vs `ioctl FS_IOC_SETFLAGS`.**
   - SPEC: §4/§9 say `chattr +i`. Code: in-process `ioctl` immutable flag
     (`evidence_chain.py:727-730`).
   - Classification: **partially confirmed** (semantically equivalent; literal
     command not used).
   - Recommended resolution: reword to "FS immutable flag (equivalent to
     `chattr +i`)".

---

## Top Risks / Missing Tests (prioritized)

1. **[High — doc trust] OpenCTI `opencti_*`/OpenSearch claim (Ledger #1).** A
   reader (or AI diagram tool consuming this SPEC as "data source") will model a
   data flow that does not exist. Highest-value correction. No test gap (the path
   simply isn't built); the risk is purely documentation fidelity.

2. **[Medium — security posture] No CI assertion of the enforce posture.** seccomp=
   kill and AppArmor=enforce are live-VM-proven only (memory `project_postmvp_run1`,
   XYE-9). A regression that leaves the install in log/complain would pass CI.
   Recommend a deploy-time/post-install smoke that asserts the profiles are in
   ENFORCE and `SIFT_EXECUTE_SECCOMP_MODE=kill` on the served unit.

3. **[Low — boundary] No negative test that per-backend `/mcp/{name}` is absent.**
   The single-policy-boundary invariant (Plane 1) is asserted by a code comment
   (`server.py:1236-1237`) but not by a route-enumeration test. Add one so an
   accidental re-mount fails CI.

4. **[Low — derived-authority] No test pins "OpenSearch is never read as control
   authority."** The property is structural (everything authoritative resolves from
   Postgres) but unasserted; a future reader could add an OpenSearch-backed
   active-case/custody read without tripping a test.

---

## Assumptions Made

- **A1.** The codebase-memory graph is keyed to the main repo path
  (`Users-yk-AI-SIFTHACK-sift-mcps`) and my worktree is the same commit
  (`a7ea369`); I treated graph `file:line` as valid against the worktree but
  **verified every load-bearing claim with a direct `Read`/`Grep`** before
  asserting it. Where I cite a line, it came from a direct read, not the graph
  alone.
- **A2.** *(Updated — R-A1.1.)* For the OpenCTI contradiction (#1) my original claim
  was scoped to: *the opencti-mcp package does not write `opencti_*` indices, and no
  repo Python writes them* — and I had not ruled out an out-of-repo connector. **That
  residual is now RESOLVED** by `docker-compose.opencti.yml:13-41,110-115`: the
  OpenCTI add-on runs its own isolated OpenSearch cluster (`sift-opencti-net`,
  `INDEX_PREFIX=opencti`) and the compose file explicitly forbids writing `opencti_*`
  into the SIFT forensic cluster. So `opencti_*` indices are real but live in a
  separate datastore, and the SPEC §2 arrow is **mislabeled (wrong datastore)**, not
  nonexistent (Ledger #1 updated accordingly). The only remaining open item is an
  architect/intent call — **HUMAN-DECISION H1**: was a mirror of `opencti_*` into the
  SIFT forensic cluster ever intended? That is a design/intent question, **not a code
  gap**.
- **A3.** I read the SPEC's "9-stage" wording as the count of policy middlewares
  excluding the catalog. Even under that reading the count is now wrong because of
  the BU3 backstop (10 policy middlewares), so the conclusion (stale) holds either
  way.
- **A4.** "AppArmor=enforce" / "seccomp=kill" in §9's flat table is read as the
  intended hardened end-state. I classified it partially-confirmed rather than
  contradicted because the SPEC §4 prose itself frames the jail as "live-proven
  (RUN-3)", implying the hardened posture.
