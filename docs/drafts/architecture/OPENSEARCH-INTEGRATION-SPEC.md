# OpenSearch-MCP Integration — Current-State Architecture Spec

**Scope:** exact, code-verified description of how `opensearch-mcp` is wired into the SIFT gateway.
**Authority rule:** code wins over diagram/docs. Every claim carries a `file:line` cite or is marked `INFERRED` / `UNVERIFIED`.

**Baseline:** **`origin/main` = `713b87d`**, read from the authoritative current-main worktree **`/home/yk/AI/SIFTHACK/wt/main-cur`** (`git rev-parse --short HEAD` → `713b87d`). This HEAD includes Wave-2 **batch-3** (`0ff4d11`): SEC-6 (`a6a4896`), SEC-7 (`ee09499`/`ee1620c`), SEC-8 (`edd5a93`), SEC-11/SEC-16 (`9f67ea0`), SEC-14 (`f828bab`), plus batch-2 SEC-2/SEC-3. **Every `file:line` below was re-verified with Read/grep against this worktree at `713b87d`** — the codebase-memory graph indexes a now-deleted worktree (`wt/sec-auth-rm`) and was NOT used for line numbers.
Companion design doc: **`docs/architecture/SIFT-GATEWAY-SECURITY-MODEL.md`** (operator's C4+STRIDE model) — this spec is its named opensearch annex; §H cross-checks it against code.

---

## A. What opensearch-mcp is

**Origin / why core.** `opensearch-mcp` began as a standalone dedicated FastMCP backend that connected to the gateway. It still ships a standalone server (`create_server()` builds a full `FastMCP("opensearch-mcp", …)` from the same registry — `registry.py:2528`). It is wired into the gateway as a **stdio add-on backend** but treated as **first-party / core, not a "reference" add-on**, for governance + security. The security model lists it as plane ⑤ "**opensearch-mcp (CORE, ns `opensearch`)**" (SECURITY-MODEL.md:45). In code this first-party status manifests as:

- **Not a reference backend.** `test_phase6.py:308` (`test_opensearch_is_not_reference_but_other_reference_manifests_drive_grounding`) asserts `get_reference_backends() == {forensic-rag-mcp, opencti-mcp, windows-triage-mcp}` (`test_phase6.py:321`) and `"opensearch-mcp" not in reference_backends` (`test_phase6.py:326`). The other three add-ons are reference/baseline grounding planes; opensearch is the live evidence plane.
- **`default_case_scoped: true`** in its manifest (`packages/opensearch-mcp/sift-backend.json`). Reference/baseline add-ons must instead declare `default_case_scoped:false` or the gateway denies all their tools under an active case (recalled `reference_reference_plane_case_scope`). Opensearch is the opposite — every tool is case-scoped unless its manifest entry says otherwise.
- **Manifest `tier:"addon"`, `namespace:"opensearch"`** (sift-backend.json) — see §H-D1: the operator/diagram call it "CORE" but the manifest tier string is literally `addon`. First-party/CORE is a *behavioral* status (non-reference, deep-integrated, naming-allowed), not a manifest tier value.
- **Deep gateway integration no other add-on has:** a dedicated worker fleet (`sift-opensearch-worker@`), a job-dispatch middleware (gate ⑨), and an ingest-status-augment middleware all live in the gateway *specifically for opensearch* (§C/§D).

**How it is registered / mounted.** A **stdio FastMCP proxy backend**. The gateway spawns the `opensearch-mcp` entry point as a stdio child and mounts its FastMCP proxy onto the live aggregate server (`server.py:211` `_mounted_proxy_backends`; `mount_single_addon_proxy` imported at `server.py:774`; `mcp_backends_registry.py:404` "install.sh registers `command=<venv>/bin/<entry-point>`"). Backend authority (case-scope, safe args, scopes) is read from the **DB manifest snapshot** `app.mcp_backends`, not the on-disk file at runtime (§G).

**In-process vs worker split (the headline).**

| Plane | Tools | Mechanism |
|---|---|---|
| **Proxied to the in-gateway stdio child (synchronous)** | All 13 query/status/admin tools + `ingest(dry_run=True)` + `enrich_intel(dry_run=True)` previews | FastMCP proxy → opensearch stdio child in the gateway process |
| **Dispatched to `sift-opensearch-worker@` (async durable job)** | `opensearch_ingest(dry_run=False)`, `opensearch_enrich_intel(dry_run=False)` | gate ⑨ `OpenSearchJobDispatchMiddleware` enqueues a Postgres durable job; returns `status:"queued"` + `job_id` immediately (`policy_middleware.py:1505-1611`) |

So **no tool is "worker-only" as a whole**: ingest/enrich have a *cheap synchronous preview path* (dry_run, proxied) and a *privileged async execution path* (non-dry-run, worker). Everything else is synchronous proxy-only. Ingest/enrich execute on a worker because FUSE-mounting an E01 cannot happen inside the gateway's hardened private-mount-namespace unit (`policy_middleware.py:1506-1525`; `configs/systemd/sift-opensearch-worker@.service` header).

---

## B. Complete tool catalog (15 tools)

Typed contract: `registry.py`. Impl engine: `server.py`. Case authority: `sift-backend.json` (mirrored into `app.mcp_backends`).
All 15 inherit `default_case_scoped:true`; none set a per-tool `case_scoped`, so all are case-scoped. `safe` = injected/overwritten case args; `bound` = SEC-2 validated-not-overwritten.

| Tool | Plane | Sync/Job | safe (injected) | bound (validated) | required_scopes | Purpose | `registry.py` |
|---|---|---|---|---|---|---|---|
| `opensearch_search` | proxy | sync | `case_id, case_dir` | `index` | – | query_string search of indexed evidence | `:2192` |
| `opensearch_count` | proxy | sync | `case_id, case_dir` | `index` | – | exact doc count | `:2211` |
| `opensearch_aggregate` | proxy | sync | `case_id, case_dir` | `index` | – | top-N terms agg | `:2434` |
| `opensearch_get_event` | proxy | sync | `[]` | `index` | – | one full doc by `_id` | `:2416` |
| `opensearch_timeline` | proxy | sync | `case_id, case_dir` | `index` | – | date-histogram of events | `:2398` |
| `opensearch_field_values` | proxy | sync | `case_id, case_dir` | `index` | – | distinct field values | `:2381` |
| `opensearch_status` | proxy | sync | **`case_id, case_dir`** | – | – | cluster health + **active-case** index counts + hayabusa health (**SEC-7**) | `:2457` |
| `opensearch_shard_status` | proxy | sync | **`case_id, case_dir`** | – | – | shard capacity + **active-case** top-indices (**SEC-7**) | `:2536` |
| `opensearch_case_summary` | proxy | sync | `case_id, case_dir` | – | – | coverage map + gaps (call first) | `:2502` |
| `opensearch_inspect_container` | proxy | sync | `case_dir` | – | – | survey E01/raw without mounting | `:2484` |
| `opensearch_ingest` | proxy (dry_run) / **worker** (write) | sync preview / **job** | `case_dir` | – | – | discover + index forensic artifacts | `:2362` |
| `opensearch_ingest_status` | proxy + gateway augment | sync | `case_id, case_dir` | – | – | poll ingest/enrich progress | `:2345` |
| `opensearch_enrich_intel` | proxy (dry_run) / **worker** (write) | sync preview / **job** | `case_id, case_dir` | – | `enrichment:intel` | extract IOCs → OpenCTI lookup → stamp docs | `:2327` |
| `opensearch_list_detections` | proxy | sync | `[]` | – | – | Security-Analytics/Sigma findings (Hayabusa fallback) | `:2228` |
| `opensearch_fix_host_mapping` | proxy | sync (mutating) | `case_dir` | – | – | correct a wrong host.id + reindex | `:2309` |

Mutating (write annotations, `registry.py:780-792`): `opensearch_ingest`, `opensearch_enrich_intel`, `opensearch_fix_host_mapping`. All others read-only. `opensearch_status`/`opensearch_shard_status` are deprecated tool-forms mirrored as resources `opensearch://cluster/status` / `…/shards` (removal horizon "at/after D27b").

The registry is a **typed contract layer** over an **implementation engine**: `run_opensearch_*` wrappers validate the `*In` model, call `_impl_server().opensearch_*(**params)` (raw OpenSearch I/O in `server.py`), and reshape into the `*Out` model. This is the surface a fix must land at (recalled `reference_mcp_fix_surfacing_layers`).

---

## C. Process / deployment topology

- **Gateway process** (`sift-gateway.service`): the single policy boundary + REST/MCP listener (security model plane ②). Holds the control-plane DSN and all DB creds. Hosts the FastMCP aggregate server with the opensearch stdio child mounted as a proxy.
- **Opensearch stdio child:** spawned by the gateway as a mounted stdio proxy (`server.py` mount path). Inherits the gateway's hardened sandbox → cannot FUSE-mount → cannot run privileged ingest itself.
- **`sift-opensearch-worker@{1,2}`** (`configs/systemd/sift-opensearch-worker@.service`): security model plane ⑥.
  - Template unit; `systemctl enable --now sift-opensearch-worker@1 sift-opensearch-worker@2` → N parallel workers claiming jobs `FOR UPDATE SKIP LOCKED`.
  - Runs as the **same non-admin service user** as the gateway (`User=${SIFT_GATEWAY_SERVICE_USER}`); **no new user, no listener, no inbound request path, no portal/agent auth surface** — it only claims durable jobs from Postgres.
  - `ExecStart=… sift-opensearch-worker --job-types ingest,enrich` — restricted to the opensearch lane; never services `run_command`.
  - **DB creds:** gets `control-plane.env` + `supabase.env`. The gateway additionally injects a per-job `control_plane_dsn` into `spec_internal`, preferring the least-priv `SIFT_AUDIT_WRITER_DSN` (`policy_middleware.py:1568-1584`).
  - **FUSE-constrained hardening profile:** carries `CAP_SYS_ADMIN` + the gateway privilege-drop caps and **cannot** carry `ProtectSystem=strict` / private-namespace protections (empirically these break `fusermount`). Mounts gated by `/etc/sudoers.d/sift-ingest-mount`. A documented, narrow posture reduction vs the gateway, flagged for `/security-review` (unit header).
- **OpenSearch itself:** `http://localhost:9200` (manifest `capabilities.requires`); single-node, security ON, per-consumer scoped roles (security model plane ⑥).
- **`sift-job-worker.service`:** the default durable-job worker (other job types).

The worker has **no DB-authority for cases/evidence** by design — DB-reading authority lives in the gateway. Hence the worker's `evidence_register` callback (§E).

---

## D. The agent tool-call chain (security-model VP-3 mapped to code)

VP-3 (SECURITY-MODEL.md:50-72) defines **Identity (pre-chain) + 9 fail-closed gates**. Runtime objects live in two places — `GatewayToolCatalogMiddleware` in `mcp_server.py`, the rest in `gateway_policy_middlewares()` (`policy_middleware.py:1646`). Mapping (design # → code), with the two **code-only extras** flagged:

| VP-3 gate | Code object | `file:line` |
|---|---|---|
| **Identity** (pre-chain) | `SiftTokenVerifier` (Supabase JWT → principal). **SEC-6**: legacy PR02 hash/api_key fallback removed; Supabase sole authority, 503 fail-closed on outage | `supabase_auth.py:201` (removal), `:156`/`:175` (503) |
| *(code extra, outermost)* | `ControlPlaneRequiredMiddleware` — no DSN ⇒ refuse every tool (BU3/XYE-21) | `policy_middleware.py:530` |
| 1 GatewayToolCatalog | `GatewayToolCatalogMiddleware` (filter the advertised catalog) | `mcp_server.py:328` |
| 2 ToolAuthorization | `ToolAuthorizationMiddleware` (fail-closed no-identity; tool_scope deny; per-principal rate limit) | `policy_middleware.py:280` |
| 3 AddonAuthority | `AddonAuthorityMiddleware` (`required_scopes` e.g. `enrichment:intel`; `prohibited_operations`) | `policy_middleware.py:394` |
| 4 CaseContext | `CaseContextMiddleware` (resolve + bind DB active case) | `policy_middleware.py:756` |
| 5 AuditEnvelope | `AuditEnvelopeMiddleware` (DB-first pre-dispatch `requested`; fail-closed for mutating; gateway-owned canonical `audit_id`) | `policy_middleware.py:979` |
| **6 ProxyActiveCase** | `ProxyActiveCaseMiddleware` — **the opensearch case-isolation chokepoint** | `policy_middleware.py:839` |
| 7 EvidenceGate | `EvidenceGateMiddleware` (require registered+sealed+`chain_status` OK) | `policy_middleware.py:580` |
| 8 ResponseGuard | `ResponseGuardMiddleware` (redact secrets, cap, untrusted-output labelling) | `policy_middleware.py:649` |
| *(code extra)* | `OpenSearchIngestStatusAugmentMiddleware` — merge durable job rows into `opensearch_ingest_status` | `policy_middleware.py:1344` |
| **9 OpenSearchJobDispatch** | `OpenSearchJobDispatchMiddleware` (innermost) | `policy_middleware.py:1505` |

**Gate ⑥ ProxyActiveCase — the chokepoint (`policy_middleware.py:839-949`):**
- **SEC-2 case-bound validation** (`:857-907`): for every case-scoped tool, each `bound` arg (the opensearch `index`) is validated segment-by-segment against the active-case prefix `case-{key}-`. A value naming another case (`case-*`, another case's pattern, an exact other-case index) or a blank comma segment is **denied** (`case_bound_cross_case` / `case_bound_empty_segment`). Fail-closed if the prefix can't be resolved (`case_bound_prefix_unresolved`). Relocated to this agent-path gate by `563b851`/`d496b7d` so `opensearch_get_event` (no injected `case_dir`) is still bound.
- **safe-arg injection** (`:908-949`): inject DB-authoritative `case_id`/`case_key`/`case_dir`; mismatching client value denied (`client_case_mismatch`). `None` ⇒ deny fail-closed (`proxy_requires_implicit_case`); empty set ⇒ pass through (the `get_event`/`list_detections` case).

**Gate ⑨ OpenSearchJobDispatch (`policy_middleware.py:1505-1611`):** dispatch set = `{opensearch_ingest, opensearch_enrich_intel}` (`policy_middleware.py:1306`). If a job service + active case exist and it's not a `dry_run` ingest preview, **enqueue a durable job and return `queued`+`job_id`** instead of proxying. `_spec_public` (`:1613-1644`) is path-free; the DB-authoritative `case_dir` travels only in `spec_internal` and never reaches the agent.

---

## E. The REST tool-exec callback surface and the 4 worker callbacks

**Endpoint:** `POST /api/v1/tools/{tool_name}` → `rest.py:211` `call_tool`; route `rest.py:1371`. **Operator-only**: agent/service principals are rejected 403 (`rest.py:234-251`, "REST tool execution is operator-only; agents must use the Gateway MCP surface"). Workers/CLI authenticate with a **gateway api-key bearer token** (`gateway.py:41-42`), not an agent principal, so the callback is allowed.

**Governance asymmetry (SEC-5 context, §H-D6).** REST `call_tool` invokes `gateway.call_tool(...)` directly (`rest.py:282-295`); the FastMCP policy chain (§D) is mounted on `/mcp`, not on this REST route. `gateway.call_tool()` still does its own active-case injection for case-scoped tools and proxy audit (`server.py:1112`, `1165-1234`), but **not** the evidence gate / response guard / addon-authority / job-dispatch middleware. `INFERRED` (from middleware placement): the REST callback path is partially governed, not the full agent chain. Acceptable-by-design (agents 403'd; only operators/workers reach REST).

The worker→gateway client is `opensearch_mcp/gateway.py:call_tool` → `POST /api/v1/tools/{tool}` (`gateway.py:57-109`), retry/backoff on 502/503/504.

| Callback | Caller `file:line` (@713b87d) | Target | Status |
|---|---|---|---|
| `cti_lookup_ioc` | `threat_intel.py:454` | **opencti-mcp** | **DEFERRED / conditionally-live.** Live code, exercised by the worker during `enrich_intel`. `opencti-mcp` ships a manifest with `cti_lookup_ioc` (security model marks it EXTERNAL/query-only). But OpenCTI is **not built/integrated/running** (recalled `project_opencti_not_integrated`): with no opencti backend registered the gateway returns 404 and the worker records the IOC skipped. Not dead — activates the moment opencti-mcp is registered. |
| `run_windows_command` | `wintools.py:49` | **wintools-mcp** (deferred Windows-VM backend) | **DEAD on this deployment.** No Windows VM exists; backend only registered via the `join` flow `machine_type=="wintools"` (`rest.py:725-745`), which stores DB metadata + needs a restart and does **not** persist the token (D22A). `wintools_available()` gates only on `gateway_available()` (`wintools.py:15-23`), so parsers *attempt* the call and dead-end on a 404 `RuntimeError`. **Recommend removing `wintools.py`, the `parse_srum`/`parse_prefetch` wintools fallbacks, and the `rest.py:725` `machine_type=="wintools"` join branch** unless a Windows-VM backend is planned (§H-D3). |
| `case_activate` | `ingest_cli.py:526` | **gateway CORE tool** (not opensearch) | **LIVE (CLI path only).** Called by `sift ingest`'s `_ensure_case_active` (`ingest_cli.py:509-530`) to activate a case before a CLI-driven ingest; handles SMB repoint + wintools notification, local `active_case` file fallback. Not on the agent MCP path (portal/CLI-managed; instructions tell agents not to call it). |
| `evidence_register` | `parse_memory.py:549` | **gateway CORE tool** | **LIVE, best-effort.** During vol3 memory ingest the worker registers the memory image via `_register_memory_evidence` (`parse_memory.py:544-557`), wrapped in `try/except: pass`. The worker has **no DB creds**, so it cannot write `app.evidence_objects` itself — it calls back to the gateway (which owns the DSN). This is the "memory callback." |

---

## F. End-to-end workflow traces

### F1. Agent `opensearch_search` (in-process query)
1. Agent calls `opensearch_search(query=…)` on `/mcp`.
2. Identity (Supabase JWT) + gates 1–5 pass (catalog, scope, addon-authority, case context resolved, audit `requested` row).
3. ⑥ ProxyActiveCase: if `index` supplied, validate every segment starts with `case-{key}-` (`policy_middleware.py:868-907`); inject `case_id`/`case_dir` (`:933-948`).
4. ⑦ evidence gate OK; ⑨ not a dispatch tool → `call_next` proxies to the opensearch stdio child.
5. Child: `run_opensearch_search` validates `SearchIn`, calls `server.opensearch_search` (`server.py:901`). `server._resolve_index(index, case_id)` (`server.py:700`) builds the concrete `case-{key}-*` pattern; `_validate_index` (`server.py:159`) is defense-in-depth; `_get_os()` issues the query against `127.0.0.1:9200`.
6. Raw dict → `SearchOut` → `ToolResult`.
7. Post-dispatch: gateway-owned canonical `audit_id` stamped; ⑧ response guard redacts/caps; result returned.

### F2. Agent `opensearch_ingest(dry_run=False)` (worker-dispatched job, SEC-8 extraction)
1. Agent calls `opensearch_ingest(path="evidence/x.e01", dry_run=False)`.
2. Gates 1–7 as above; ④ active case resolved, ⑥ injects `case_dir`, ⑤ writes `requested` audit row.
3. ⑨ `OpenSearchJobDispatchMiddleware._enqueue` (`policy_middleware.py:1556`): builds `spec_public` (path-free args) + `spec_internal` (DB `case_dir`/`case_key`/examiner + least-priv `control_plane_dsn`); `job_service.enqueue_job(job_type="ingest", …)`. Returns `{status:"queued", job_id, dispatched_to:"opensearch-worker", next_step}` immediately (`:1597-1611`).
4. A `sift-opensearch-worker@N` claims the job (`FOR UPDATE SKIP LOCKED`).
5. Worker resolves `case_dir` from `spec_internal`. For an archive, extraction funnels through the **SEC-8 hardened chokepoint `extract_container`** (`containers.py:122`, header `:50-58`). Order is deliberate and fail-closed (`containers.py:122-145`): **(a) enumerate members** — `_list_7z_members` (`containers.py:276`) or `_list_tar_members` (PEP-706 `data` filter + stricter link/setid rejection); **(b) `_enforce_policy`** (`containers.py:178`) — `_reject_unsafe_member` rejects path-traversal/absolute (`_is_unsafe_path`), device/fifo/link kinds (`_UNSAFE_KINDS`), and setuid/setgid *before any byte is written*, then anti-bomb caps: entry count, declared uncompressed total, compression ratio, and `_check_free_space` via `os.statvfs` (`containers.py:212`); **(c) extract** — `_extract_7z` (`containers.py:368`) treats **any non-zero 7z rc (incl. rc==1 warning) as FAILURE** (`containers.py:380`, "partial extraction must never be mistaken for clean"), password stripped from errors; **(d) `_verify_no_escape(dest)`** (`containers.py:401`) post-walks the output for any escape the binary produced. Raises `ArchiveRejected(ValueError)` (`containers.py:61`) on any violation. Memory-path extraction lands under the case jail `cases_root()/case_id` (`containers.py:1226`). For E01/disk, FUSE strategy ladder `_try_xmount_ntfs3g → _try_xmount_loop → _try_ewfmount_loop → _try_ewfmount_direct` under the sudoers allowlist.
6. Worker parses (EZ tools / `parse_memory` vol3 / csv / [wintools fallback — dead, §E]) and bulk-indexes into `case-{key}-{type}-{host}`, stamping `sift.case_id`/`sift.provenance_id`.
7. For memory: worker calls back `evidence_register` (§E).
8. Worker writes `current_step` progress + a terminal `result_public` to the durable job row.
9. Agent polls `running_commands_status(job_id)` or `opensearch_ingest_status` — the latter augmented at the gateway (`policy_middleware.py:1390-1503`) from `app.job_status_public` because the stdio child has no DB creds.

### F3. Operator activates a case (`case_activate` propagation)
1. Operator activates a case in the portal → gateway writes `app.active_case_state` (the DB authority; resolved per-principal by `CaseContextMiddleware` / `active_case.py`).
2. Subsequent agent calls resolve that case at gate ④ and have `case_id`/`case_dir` injected at gate ⑥. The agent never sets the case (security model boundary #4: "no env/pointer trust").
3. The CLI/legacy path additionally calls the **gateway core** `case_activate` tool (`ingest_cli.py:516-526`) to repoint the SMB `[cases]` share + notify wintools; **not** an opensearch tool.

### F4. Enrichment / `cti_lookup_ioc`
1. Agent calls `opensearch_enrich_intel(dry_run=False)` (requires `enrichment:intel`, enforced at gate ③).
2. ⑨ dispatches an `enrich` durable job (`_spec_public` for enrich = `{force}` only, `policy_middleware.py:1622`).
3. Worker extracts unique IOCs from indexed docs, then for each calls back `cti_lookup_ioc` via REST (`threat_intel.py:454`) with pacing/rate-limit/breaker logic.
4. On a hit it stamps `threat_intel.verdict`/`confidence`/`labels` and `stamp_documents` writes them via update-by-query.
5. **Today this no-ops** because opencti-mcp is not registered (§E) — every IOC recorded skipped.

---

## G. Manifest / DB authority

- **Runtime authority = the DB snapshot, not the file.** The gateway reads `app.mcp_backends` (`mcp_backends_registry.py:500`) and builds `_tool_map` + `_tool_manifest_meta` (`server.py:462` `_build_tool_map`). `is_case_scoped_tool` (`server.py:890`), `safe_case_argument_names` (`server.py:912`), `case_bound_argument_names` (`server.py:946`) all read `self._tool_surface.manifest_meta` first, falling back to the live schema only when the manifest is silent.
- **`safe_case_argument_names` tri-state** (`server.py:912-944`): `set` (inject), empty `set` (case-scoped, no injection — pass through), `None` (unknown → middleware denies fail-closed). This is why `get_event`/`list_detections` (empty list) pass gate ⑥ without injection.
- **`case_bound_argument_names`** (`server.py:946-960`): SEC-2 free-form args validated-not-overwritten; for opensearch this is `["index"]` on the 6 query tools. Gateway active-case prefix from `_active_case_index_prefix` (`server.py:963`) mirrors `opensearch_mcp.paths.build_index_pattern(key, tail="")` = `case-{key}-`; the backend re-derives the same via `_resolve_active_prefix` (`server.py:1511`, SEC-7) and `_active_index_prefix` (`server.py:144`) so gateway and backend agree (a unit test pins them).
- **manifest_sha drift:** a first-party backend whose on-disk manifest no longer matches the DB row is flagged (`mcp_backends_registry.py:142`); stale registration silently disables features until refreshed (recalled `reference_gateway_manifest_registration_drift`). Authority remains the DB snapshot.
- **Env propagation to the stdio child:** `SIFT_DB_ACTIVE` (non-secret authority flag) is propagated so the child agrees on Postgres ingest-status authority; the control-plane DSN (secret) is **not** (`test_phase6.py:560-580`).

---

## H. DRIFT FINDINGS (incl. cross-check vs SECURITY-MODEL.md)

**D1 — `tier:"addon"` vs "CORE" framing.** Manifest sets `tier:"addon"`, `namespace:"opensearch"` (`sift-backend.json`). The security model + operator call it "CORE". The first-party *status* is real but behavioral (non-reference via `get_reference_backends`, `default_case_scoped:true`, dedicated worker/middleware, naming allowed), not a tier value. Any doc claiming a literal `core` tier is wrong. *(documentation.)*

**D2 — SEC-7 verified PRESENT (status/shard filtered to the active case).** At `713b87d`: `opensearch_status(case_id="", case_dir="")` (`server.py:1533`) and `opensearch_shard_status(case_id="", case_dir="")` (`server.py:1597`) resolve the active-case prefix via `_resolve_active_prefix(case_id, case_dir)` (`server.py:1511`) and enumerate **only** the active case's `case-{key}-*` indices — empty when no active case, never the cluster-wide `case-*` targeting map. Both carry `safe_case_argument_names:["case_id","case_dir"]` so gate ⑥ injects the active case. **Cross-case index/shard enumeration is closed** (operator live-proved on the VM: `opensearch_status` returned only active-case indices). No action — this is the verified secure state. *(verified present.)*

**D3 — wintools / `run_windows_command` is unwired dead code (foot-gun).** No Windows VM; never registered live. `wintools_available()` (`wintools.py:15-23`) gates only on `gateway_available()`, so parsers attempt the call and dead-end on a 404. Recommend removing `wintools.py`, the `parse_srum`/`parse_prefetch` fallbacks, and the `rest.py:725-745` `machine_type=="wintools"` join branch unless a Windows-VM backend is planned. *(dead code / correctness.)*

**D4 — cti_lookup_ioc enrichment is inert (opencti deferred).** The enrich write-path + worker IOC loop + `cti_lookup_ioc` (`threat_intel.py:454`) are live code, but opencti-mcp is not built/registered (`project_opencti_not_integrated`), so enrichment no-ops (every IOC skipped). The security model (VP-1, plane ⑤) presents OpenCTI as an operational query-only dependency — accurate as *design*, but **ready-but-deferred** in this deployment. *(documentation / deferred-feature.)*

**D5 — VP-3 design-doc drift (operator-acknowledged), confirmed in code.** SECURITY-MODEL.md:56 still mentions a "PR02 hash / api_key fallback" in the Identity stage; **SEC-6 (`a6a4896`) removed it** — `supabase_auth.py:201` ("the legacy PR02 token fallback was removed entirely") with 503 fail-closed (`:156`, `:175`). The doc already flags this at its lines 12-14/56-57. **Nuance:** the `mcp:*` *scope* still exists as a definable superuser wildcard (`supabase_auth.py:1715, 1729, 1762`) — SEC-6 removed the legacy *default-grant of it on the fallback path*, not the scope itself. *(documentation — already acknowledged; code wins.)*

**D6 — REST callback plane is only partially governed (SEC-5 surface).** The 4 worker/CLI callbacks enter via `POST /api/v1/tools/{tool}` → `gateway.call_tool()`, which runs active-case injection + proxy audit but **not** the full FastMCP gate chain (no evidence gate, response guard, addon-authority, dispatch). `/mcp` and REST therefore have different governance. Acceptable-by-design (REST operator/worker-only; agents 403'd at `rest.py:239`), but any statement that "all tool calls pass the 9 gates" is inaccurate for the REST plane. *(documentation / security-nuance — confirm evidence-gate absence on REST is intended.)*

**D7 — "9 gates" vs the runtime middleware count.** VP-3 names Identity + 9 gates. Code adds two objects the design omits: `ControlPlaneRequiredMiddleware` (outermost, `policy_middleware.py:530`) and `OpenSearchIngestStatusAugmentMiddleware` (`:1344`); gate-1 `GatewayToolCatalogMiddleware` lives in `mcp_server.py:328`, not the `policy_middleware` list. Net runtime = 1 catalog mw + 9 policy-list mw (of which 2 are the code-only extras). Functionally consistent; the count differs. *(documentation.)*

**D8 — `case_summary`/`fix_host_mapping`/`inspect_container`/`ingest` are case-scoped with no `bound` index guard.** They rely on `safe_case_argument_names` injection (`case_dir`/`case_id`) + the backend `_resolve_index`/`_validate_index`. Correct for tools that take no `index`; the SEC-2 segment guard only covers the 6 `index`-taking query tools. *(informational.)*

**Security-model claims that DO match code (spot-checks @713b87d):** plane ⑤ "opensearch-mcp CORE" (✓ non-reference, `test_phase6.py:326`); VP-2 "Postgres authoritative / OpenSearch derived" (✓ manifest `data_plane.notes`, DB-authority readers §G); gate-7 EvidenceGate hard interlock (✓ `policy_middleware.py:580`); gate-9 dispatch returns `job_id` (✓ §D/F2); SEC-8 single hardened extraction chokepoint (✓ `containers.py:122`); SEC-7 active-case status binding (✓ `server.py:1533`); VP-5 run_command jail floor files exist (`sift-core/execute/{worker,dfir_exec_launcher,executor,config}.py`; Landlock/seccomp/AppArmor — opensearch-out-of-scope, not re-audited).

---

## Loadout / methodology report

- **Baseline:** `wt/main-cur @ 713b87d` (confirmed via `git rev-parse --short HEAD`). The earlier draft of this spec was produced against the shared checkout while it was parked on PR#28's branch (`0f26eca`), which predated batch-3 and lacked SEC-6/7/8 — that draft's "SEC-7 not landed" finding and stale line numbers were artifacts of the wrong baseline and are fully corrected here.
- **codebase-memory MCP:** `list_projects` shows the only indexed project is a now-deleted worktree (`wt/sec-auth-rm`); its line numbers are untrustworthy. I did **not** use the graph for cites — every `file:line` was re-verified with `Read`/`grep` against `wt/main-cur` at `713b87d`. *(Recommend re-indexing `wt/main-cur`.)*
- **codeguard-security:** not invoked — read-only research, no code modification (noted per contract).
- **Source read @713b87d:** `SIFT-GATEWAY-SECURITY-MODEL.md`; opensearch `sift-backend.json` + opencti manifest; gateway `policy_middleware.py` / `server.py` / `rest.py` / `mcp_server.py` / `mcp_backends_registry.py` / `supabase_auth.py`; opensearch `registry.py` / `server.py` / `gateway.py` / `wintools.py` / `threat_intel.py` / `parse_memory.py` / `ingest_cli.py` / `containers.py`; the worker systemd unit; `test_phase6.py`.
