# Add-on Ecosystem & Verification — Research + Design Brainstorm

> Covers: packages/sift-gateway/src/sift_gateway/backends/**, scripts/probe_backends.py, packages/sift-gateway/src/sift_gateway/sift-backend.schema.json
> Class: point-in-time
> Last validated: cb2993d (2026-06-18)

**Status:** architecture brainstorm / design input (not normative). Feeds the
Axis H work (Linear parent `XYE-45`: `XYE-25`, `XYE-56`–`XYE-59`).
**Grounded against:** working tree at `main` (commit `69a6b02`), 2026-06-18.
**Scope reality:** repo is PRIVATE, solo-used. No near-term third-party add-on
authors. Verification scope is deliberately *pragmatic*, designed to harden
later. Every code claim carries a `file:line` anchor; unverifiable claims are
marked **UNVERIFIED**.

---

## 0. TL;DR

The gateway is the only policy boundary and it already enforces a strong,
fail-closed runtime perimeter (auth scopes, add-on authority contract, DB
active-case injection, evidence gate, response guard). The residual gap is not
the perimeter — it is that the gateway **trusts the manifest's self-description
of tool behaviour** (read-only / non-authoritative / case-scoping / no secret
leak). The static probe (`scripts/probe_backends.py`) only checks what the
author *says*; nothing checks what the tool *does*.

Two facts shape the right answer. **First**, most DFIR capability is NOT a
backend — it enters via Path A (`run_command` allowlist/catalog or an OpenSearch
parser; super-timeline, memory, Sleuthkit, yara, tshark are already Path A), so
backends are rare, operator-installed, and mostly reference/query plane (live: 3
backends, OpenCTI is a feed not a backend). **Second**, the recurring real
failure is drift / stale-registration and declared-but-not-installed
capability, not malicious code. So the Axis H verifier should EXTEND the static
probe and weight toward (1) contract conformance + drift detection and (2) a
cheap authority-contradiction cross-check in a synthetic case context — emitting
a machine-readable report the portal consumes at register time, OFF the gateway
core. Broad adversarial fuzzing is low ROI (an MCP probe can't see host process
behaviour); the malicious-code tail belongs to RUN-3-style OS confinement of the
backend PROCESS, not the probe.

---

## 1. Add-on Integration Surface Map

### 1.0 Live deployment reality (verified)

Source: **live gateway `capability_guide`/`get_tool_help`, case-rocba-3,
2026-06-18.** The source tree carries 5 manifest packages, but the live VM has a
narrower, different reality — reconcile claims to this:

- **Live registered backends = 3 only:** `forensic-rag-mcp` (ns `kb`, provides
  reference), `opensearch-mcp` (ns `opensearch`, provides search/ingest/
  enrichment), `windows-triage-mcp` (ns `wintriage`, provides reference/baseline).
- **OpenCTI is NOT a standalone live backend.** The `opencti-mcp` package +
  manifest exist in source but are **not mounted live**. OpenCTI threat-intel is
  consumed as an **enrichment feed INTO opensearch** via the opensearch tool
  `opensearch_enrich_intel` ("Enrich indexed evidence with OpenCTI threat
  intel", opensearch sift-backend.json:448-498), NOT as `cti_*` query tools.
  In this surface map, treat OpenCTI as "enrichment feed into opensearch," not a
  query backend. (The `cti` manifest is still useful as the *reference contract*
  for a query-only TI backend and is cited as such below.)
- **`forensic-knowledge` is not a separate live backend** either — it is an
  in-process library (transport `library`, no MCP surface; forensic-knowledge
  sift-backend.json:6, 67); RAG/`kb` covers the reference plane live.

So the §4 candidate analysis and §5 probe target the **3-live-backend** reality;
a 4th routable backend (a query TI plane, or any Path-B service) is the
not-yet-present case the verifier must be ready for.

### 1.1 Manifest schema fields and their trust meaning

Schema: `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`
(JSON Schema draft-07, validated before registration; `additionalProperties:
false` at root and per-tool, so unknown keys are rejected — schema.json:181,
schema.json:157).

| Field | Schema anchor | Gateway USE | Trust meaning |
|---|---|---|---|
| `spec_version` `"1.x"` | schema.json:6-9 | rejected if not `1.*` (`backends/__init__.py` via probe; probe_backends.py:300-303) | structural |
| `name` | schema.json:10 | registry key in `app.mcp_backends` (mcp_backends_registry.py:462) | structural; uniqueness enforced |
| `tier` (`addon` only) | schema.json:12-15 | enum-gated | structural |
| `transport` (`stdio`/`http`) | schema.json:16-19 | selects spawn vs connect (`create_backend`, backends/__init__.py) | structural |
| `namespace` | schema.json:20 | tool-name prefix; ENFORCED static + runtime | **enforced** (see §1.3) |
| `default_case_scoped` | schema.json:21 | feeds `is_case_scoped_tool` fallback (server.py:827-829) | **trusted** (advisory unless schema/heuristic agrees) |
| `data_plane.writes` / `dependencies` / `notes` | schema.json:22-34 | surfaced in registry public dict (mcp_backends_registry.py:96); lint input (backends/__init__.py:210-211) | **trusted** declaration |
| `capabilities.provides/requires/enriches_responses` | schema.json:37-56 | `requires` gates mounting (spec.md §3); `provides:["reference"]` forces explicit `default_case_scoped` (backends/__init__.py:117-126) | `requires` **enforced**; rest **trusted** |
| per-tool `read_only`/`readOnlyHint` | schema.json:65-66 | must be equal; drives fail-closed audit on mutating (policy_middleware.py:1085-1086, 958-969) | **trusted** self-label (no behavioral check) |
| per-tool `evidence_class` (`read_only`/`analysis`/`mutating`) | schema.json:67-70 | consistency lint (backends/__init__.py:150-161); case-scope contradiction lint (backends/__init__.py:214-247) | **trusted** self-label |
| per-tool `category`/`recommended_phase` | schema.json:71-86 | case-scope heuristic fallback (server.py:827-829); UX | **trusted** |
| per-tool `case_scoped` | schema.json:89 | overrides default (server.py:817-819) | **trusted** |
| per-tool `hidden_from_agent` | schema.json:90 | filtered from agent `tools/list` (spec.md §6 step 1) | **trusted** (still callable — spec.md:130) |
| per-tool `required_scopes` | schema.json:111-114 | **ENFORCED** before dispatch (policy_middleware.py:397-414) | **enforced** |
| per-tool `safe_case_argument_names` (`case_id`/`case_key`/`case_dir`) | schema.json:116-124 | gateway injects DB case identity here (policy_middleware.py:840-863) | **enforced injection target**; absence ⇒ fail-closed deny (server.py:858-861, policy_middleware.py:830-836) |
| per-tool `prohibited_operations` | schema.json:133-138 | **ENFORCED** (policy_middleware.py:416-435) | **enforced** |
| per-tool `secret_leak_guarantee` | schema.json:139-142 | none (string assertion only) | **pure trust** — no enforcement |
| per-tool `enrichment_policy`/`receipt_policy`/`scope_enforcement` | schema.json:125-146 | metadata; `required_scopes` portion enforced | mostly **trusted** |
| `authority_contract.{non_authoritative,plane,query_only,prohibited_operations,authority_disclaimer}` | schema.json:163-178 | `prohibited_operations` + `non_authoritative` enforced via `AddonAuthorityMiddleware` (policy_middleware.py:388-435); `query_only` is **advisory** | **partially enforced** (see §1.4) |

### 1.1a Two admission models — capabilities don't all become backends

A new DFIR capability enters the platform through **one of two paths**, with
different trust models. Most tooling belongs to Path A, not Path B. (All
anchors verified in source.)

- **Path A — `run_command` tool catalog + allowlist** (a binary, not a backend).
  A forensic binary is admitted by adding it to the YAML tool catalog
  (`packages/sift-core/data/catalog/`) and the curated allowlist
  (`MVP_FORENSIC_ALLOWLIST`, `security_policy.py:136-247`). Trust = a permanent
  hardcoded `DENY_FLOOR` (`security_policy.py:14-40`: `mount`, `kill`, `nc`,
  `chattr`, `setcap`, …) + per-tool flag allow/block + the RUN-3 OS sandbox
  (Landlock + seccomp=kill + systemd-cgroup + AppArmor=enforce as
  `agent_runtime`). **Already allowed today** (verified, `security_policy.py:136-247`):
  Sleuth Kit (`fls`, `icat`, `mmls`, `tsk_recover`), Zimmerman EZ tools
  (`EvtxECmd`, …), `bulk_extractor`/`foremost`/`scalpel`/`binwalk`, `yara`,
  `sha256sum`, `exiftool`, EWF tools (`ewfexport`/`ewfinfo`/`ewfverify`),
  `vol`/`vol3`/`volatility3`, `tshark`/`tcpdump`, `curl`/`wget` (read-only fetch).
- **Path B — MCP backend** (manifest + register + proxy + probe). Trust =
  manifest contract + policy middleware + evidence gate + the probe of §5.

#### Path A has a 3-state availability gap (verified live)

"The platform supports tool X" is **not** one fact — it is three, and they can
disagree (live gateway, case-rocba-3, 2026-06-18: 70 cataloged / 62 available):

| State | Means | Authority |
|---|---|---|
| (a) **in policy allowlist** | the binary name is permitted to run | `MVP_FORENSIC_ALLOWLIST` (`security_policy.py:136-247`) |
| (b) **cataloged** | has a YAML catalog entry with flag policy + timeout | `packages/sift-core/data/catalog/` |
| (c) **installed** | the binary actually exists on the VM | the VM filesystem |

Live, `yara`, `tshark`, `binwalk`, `zeek`, `PECmd`, `RECmd`, `SQLECmd`,
`SrumECmd` are (a)+(b) but show under `core_tools.missing` — **not (c)**. This is
a real **operator-trust gap**: policy/catalog (and, by analogy, an add-on
manifest) can *claim* a capability the VM does not satisfy. It is the Path-A
mirror of manifest-vs-reality drift, and ties to the Axis F supply-chain
inventory work (`XYE-48`/`XYE-49`). **Implication for the verifier:** a
COMPATIBLE check should report the (c) gap (binary present? backend process
startable?), not just (a)/(b) declarations — a tool/backend that is declared but
not installed is the most common honest failure, far more than a malicious one.

**Already-DONE surface (do NOT propose as new backends).** `opensearch-mcp`
already ingests, via its parser set, the super-timeline and memory planes plus a
broad artifact set (verified):
- **Plaso / log2timeline super-timeline** —
  `packages/opensearch-mcp/src/opensearch_mcp/parse_plaso.py:31` runs
  `log2timeline.py` + `psort` to JSONL → OpenSearch.
- **Volatility 3 memory** — `…/parse_memory.py:3` runs vol3 plugins as
  subprocesses → structured index (`sift-vol3` template).
- Plus `parse_{evtx,srum,prefetch,tasks,wer,ssh,w3c,accesslog,csv,delimited,json,defender}.py`
  and Hayabusa (verified by `ls packages/opensearch-mcp/src/opensearch_mcp/parse_*.py`).

So timeline, memory, Windows-artifact, log, and ad-hoc-binary surfaces are
already covered by Path A + the OpenSearch parser plane. **A new backend (Path
B) is justified ONLY for a stateful external service** with its own
store/API/session that cannot be expressed as a one-shot binary (Path A) or an
OpenSearch parser.

#### Decision rule: Path A catalog entry vs Path B backend

| If the capability is… | Path | Why |
|---|---|---|
| a one-shot CLI binary that reads sealed evidence and prints/produces output | **A** (catalog + allowlist) | `run_command` + RUN-3 sandbox already bounds it; no session/state |
| a parser whose output should be searchable/timelined | **A→OpenSearch** (add a parser) | reuses the existing index plane; not a new tool surface |
| a one-shot enrichment over an online API expressible as a curl/HTTP fetch | **A** by default (curl catalog entry), **B only if** it needs an authenticated session, response shaping, pagination, or a typed multi-tool surface | a thin backend buys typed tools + scope gating; a curl entry is cheaper |
| a **stateful external service** with its own DB/API/graph/session (TI platform, link-analysis store, live-hunt server, detonation sandbox) | **B** (backend) | cannot be a one-shot binary or a parser; needs proxy + manifest + probe |

Examples that correctly land on **B**: `opencti-mcp` (external TI platform),
`windows-triage-mcp` (its own offline baseline DBs). Everything in the
already-DONE list above stays on **A**/parser.

### 1.2 Lifecycle: setup-addon → register → snapshot → mount → list → policy → gate

```
1. setup-addon.sh           Optional helper. Provisions prereqs, stages the extra
   (scripts/setup-addon.sh)  into the staged runtime venv, ECHOES every value, and
                             writes an operator-submittable register payload to
                             ~/.sift/addon-register/<name>.json. It REGISTERS NOTHING
                             and edits no gateway config (setup-addon.sh:28-41).
2. validate (read-only)      POST /api/v1/backends/validate -> load_and_validate_manifest:
                             load file/HTTP manifest -> spec_version 1.* -> JSON schema
                             -> validate_manifest_contract cross-field (spec.md §7.2).
3. register (operator-auth)  POST /api/v1/backends -> McpBackendRegistry.register:
                             normalize_connection_config rejects raw secrets
                             (mcp_backends_registry.py:271-325), upsert row into
                             app.mcp_backends with manifest_sha256 (mcp_backends_registry.py:
                             450, 462-505), audited mcp_backend.registered.
4. DB snapshot = AUTHORITY   The stored manifest JSON + manifest_sha256 in app.mcp_backends
                             IS the runtime authority, NOT the on-disk file
                             (mcp_backends_registry.py:430-525). Drift between the two is
                             only WARNED, never auto-applied (mcp_backends_registry.py:
                             206-227, 400-428) — B-MVP-032 (see §1.5).
5. proxy mount               At boot, create_backend_instances instantiates each enabled
                             row; resolve_runtime_config expands env_refs from gateway env
                             (mcp_backends_registry.py:384-398, 328-348). Hot reload:
                             _late_start_checker polls every 30s and mount_single_addon_proxy
                             mounts new rows live (spec.md §7.3).
6. tools/list aggregation    get_tools_list merges core in-process specs + proxied backend
                             tools; namespace + manifest-declared checks at _build_tool_map
                             (server.py:887+, spec.md §5).
7. policy middleware stack    Fixed order (policy_middleware.py:1247-1280):
                             ControlPlaneRequired -> ToolAuthorization -> AddonAuthority ->
                             CaseContext -> AuditEnvelope -> ProxyActiveCase -> EvidenceGate
                             -> ResponseGuard -> OpenSearchJobDispatch.
8. evidence gate             EvidenceGateMiddleware: if a case is bound, check_evidence_gate_db
                             reads app.evidence_gate_status; not-OK blocks ALL tools, fail-closed
                             (evidence_gate.py:62-133, policy_middleware.py:546-612).
```

### 1.3 ENFORCED at runtime vs TRUSTED from manifest (the attack/error surface)

| Concern | Gateway ENFORCES (with anchor) | Gateway merely TRUSTS (the gap) |
|---|---|---|
| Tool naming | every served tool name must start with `<namespace>_` and be declared, both static (backends/__init__.py:136-140) and runtime in `_build_tool_map` (spec.md §5); global uniqueness; no core collision | that the namespace describes a single coherent backend |
| Per-principal scopes | token `tool_scopes` checked on list AND call (policy_middleware.py:267-304) | — (genuinely enforced) |
| Add-on `required_scopes` | every declared scope must be satisfied pre-dispatch (policy_middleware.py:397-414) | that the declared scope set is *complete* for what the tool actually does |
| Add-on `prohibited_operations` | denied if tool name OR an `operation/action/op/command/mode` arg value matches the set (policy_middleware.py:438-449) | a tool that performs a prohibited op WITHOUT naming it in those arg keys or its name (e.g. a write hidden inside `cti_lookup_ioc`) is NOT caught |
| Active-case binding | DB case resolved per principal; case-scoped tool with no resolvable case is denied (policy_middleware.py:735-743) | which tools are case-scoped (heuristic + `default_case_scoped`/`case_scoped`) — server.py:811-829 |
| Case identity injection | DB `case_id`/`case_key`/`case_dir` injected only into declared `safe_case_argument_names`; client mismatch denied; unknown contract denied fail-closed (policy_middleware.py:822-863) | that the backend actually USES the injected case dir and does not resolve a different case from its own env/files |
| Evidence seal | DB-authority gate blocks all tools under an unsealed/violated chain (evidence_gate.py:128-133) | — (enforced); but a backend touching evidence OUT-OF-BAND of a gateway tool call is invisible to it |
| Secret/path leakage | `ResponseGuardMiddleware` redacts patterns + caps output on the response (policy_middleware.py:615-719); audit args redacted (policy_middleware.py:929) | `secret_leak_guarantee` itself is unchecked; redaction is pattern-based and best-effort, not a proof |
| `read_only`/`mutating` | drives fail-closed pre-dispatch audit for mutating tools (policy_middleware.py:958-969) | that a `read_only`-declared tool does not mutate (NO behavioral check) |
| Connection secrets | raw secret fields rejected at register; secrets only via `*_env`/`env_refs` (mcp_backends_registry.py:279-283, 21-34) | — (enforced) |
| HTTP egress | http backends must resolve to a public address; loopback/private/reserved rejected (spec.md §4.2) | what the backend then talks to outbound |
| Resource use | no per-tool CPU/mem/time budget on add-on calls **UNVERIFIED** (no timeout/quota seen in `AddonAuthorityMiddleware` or backend `call_tool`) | runaway/slow backend can degrade the shared MCP surface (cf. B-MVP-035 hang) |

**The gap in one sentence:** every *behavioral* property — "is it really
read-only", "does it really not touch evidence/paths", "does it really resolve
the injected case", "does it really leak no secrets", "does it terminate" — is
asserted by the manifest and **not verified** against the running backend.

### 1.4 `query_only` is advisory, `prohibited_operations` is enforced-but-shallow

`authority_contract.query_only` (schema.json:170) has **no enforcement codepath**
— `addon_authority_for_tool` extracts only `non_authoritative`,
`prohibited_operations`, and `required_scopes` (server.py:863-885). A backend
can declare `query_only:true` and still expose a `mutating` tool; only the
manifest-honesty lint (backends/__init__.py:214-247) pushes back, and only when
the *manifest itself* is internally contradictory. `prohibited_operations`
enforcement is real but **string-match shallow**: it matches tool name or a
fixed set of arg-key values (policy_middleware.py:445-448), so a prohibited
effect achieved through other argument names or internal logic slips through.

### 1.5 Authority is the DB snapshot, not the file (B-MVP-029/032/053 — verified)

- Runtime authority = the manifest JSON + `manifest_sha256` stored in
  `app.mcp_backends` (mcp_backends_registry.py:462-505). On-disk drift is only
  WARNED (`detect_manifest_drift`/`log_manifest_drift`,
  mcp_backends_registry.py:161-227) and never auto-applied — re-register to pick
  up changes. A stale snapshot silently disables manifest-declared features
  (e.g. a `case_dir` added to `safe_case_argument_names`). **Verified.**
- Reference-plane add-ons MUST declare a boolean `default_case_scoped`
  (backends/__init__.py:117-126); the heuristic in `is_case_scoped_tool` treats
  any non-"reference" category as case-scoped (server.py:827-829), so a
  reference/baseline/threat-intel tool that omits the flag would be classed
  case-scoped, expose no case arg, and be denied fail-closed by
  `ProxyActiveCaseMiddleware` (policy_middleware.py:830-836). This is exactly
  B-MVP-053. **Verified.** All four routable add-ons set
  `default_case_scoped:false` except `opensearch-mcp` which sets `true`
  (opensearch sift-backend.json:9; rag:8; wintriage:8; opencti:8).

---

## 2. Threat / Failure Model

For each scenario: what current controls catch, what slips through.

| # | Scenario | Caught by today | Slips through |
|---|---|---|---|
| **a** | **Honest-but-buggy backend** — crashes, returns malformed schema, hangs on a call | malformed `outputSchema` is repaired so it can't break aggregate `tools/list` (server.py:911-915, `_sanitize_output_schema`); a backend that fails to start is gated and absent (spec.md §8); trailing-space command FileNotFound mitigated (mcp_backends_registry.py:311-318) | a tool that *hangs mid-call* has **no per-call timeout/quota** at the add-on layer (**UNVERIFIED** — none found); a buggy tool returning wrong-but-valid data is undetected |
| **b** | **Lying manifest** — declares `read_only`/`query_only`/`non_authoritative` but the tool writes, touches case/evidence/paths, or resolves a different case | manifest-honesty lint catches *internally contradictory* manifests at load (backends/__init__.py:214-247); `prohibited_operations` catches name/arg-value matches; case injection is confined to declared args | a tool whose manifest is internally CONSISTENT but whose CODE lies (declares read-only, actually writes; declares non-case-scoped, actually opens an evidence path) — **the central XYE-25/57 gap.** Nothing executes the tool to check. |
| **c** | **Malicious backend the operator was tricked into installing** | register requires operator auth + audit (mcp_backends_registry.py:509-524); raw secrets rejected (mcp_backends_registry.py:279-283); env-refs resolved from gateway env only, never stored (mcp_backends_registry.py:328-348); http egress restricted to public addresses (spec.md §4.2); stdio gets a minimal env (spec.md §4.1) | a backend the operator approves runs as `sift-service` with whatever the gateway env exposes; it can exfil over its own outbound connections, read anything `sift-service` can read, and lie in every response. The gateway perimeter constrains the *tool-call data path* but not the *process*. Mitigation is admission-time scrutiny + operator informed consent, not runtime sandbox of the backend process (**UNVERIFIED** whether add-on subprocesses are seccomp/landlock-confined like `run_command`'s agent_runtime). |
| **d** | **Schema/behavior drift after a backend update** | runtime `_build_tool_map` rejects served tools not matching namespace/declared set (spec.md §5); on-disk vs registered SHA drift WARNED (mcp_backends_registry.py:206-227) | a backend binary updated in place (same registered manifest) that changes tool *behaviour* — drift detection is SHA-of-manifest only, blind to behaviour; the warn is log-only, not a gate |
| **e** | **Secret/PII leakage in tool output** | `ResponseGuardMiddleware` redacts known secret patterns + caps size, audits hits (policy_middleware.py:632-719) | redaction is pattern-based/best-effort; novel secret shapes, base64/obfuscated secrets, or PII not matching a pattern pass; `secret_leak_guarantee` is never tested |
| **f** | **Resource exhaustion** — huge response, tight loop, fork bomb, memory hog | per-principal MCP rate limit (policy_middleware.py:292-300); output cap on responses (policy_middleware.py:631-638); ingest/enrich offloaded to least-priv workers, non-blocking (policy_middleware.py:1123-1211) | no per-add-on CPU/mem/time cgroup or call timeout at the proxy layer found (**UNVERIFIED**); a stdio backend that spins or allocates can degrade the host/shared surface |

**Net:** controls (a),(e),(f) are partial-mitigation; (c) is admission +
informed-consent (no process sandbox guaranteed); (b),(d) are the genuinely
open behavioral gaps Axis H targets.

---

## 3. Existing Controls Inventory

### 3.1 What `scripts/probe_backends.py` (STATIC) already enforces

Read fully (probe_backends.py:1-449). It is an off-core conformance probe (run
manually / in CI), not wired into the gateway:

1. Manifest JSON parses; `spec_version` starts with `1.` (probe_backends.py:300-303).
2. **JSON Schema validation** against `sift-backend.schema.json`
   (probe_backends.py:306-311).
3. **Cross-field contract** (`validate_manifest_contract`, probe_backends.py:24-119):
   instructions XOR instructions_path + path containment (28-53); namespace
   prefix per tool (75-79); `read_only==readOnlyHint` (84-88); evidence_class
   valid + consistent (89-94); `recommended_phase` valid (95-99); exactly one
   health tool, named at top level (103-117).
4. **Live MCP handshake** (optional, `--skip-mcp` to disable): `initialize` +
   `tools/list` against `/mcp/<name>` (probe_backends.py:258-288, 322-330).
5. **Served-tools invariants:** every advertised tool is namespace-prefixed
   (339-341) and declared in the manifest (343-346); schema contains no
   forbidden identity/override args (`analyst_override`, `analyst_identity`,
   `override_examiner`) (349-354).
6. **Health readiness** via `/api/v1/services` (advisory warning only,
   probe_backends.py:359-374).

**Crucially, it never CALLS a tool.** It validates declarations and the
handshake surface only — it cannot detect behavioral lies (threat b/d).

### 3.2 What the gateway runtime enforces

The full middleware stack of §1.3 (anchors there). Summary: auth scopes, add-on
authority (scopes + prohibited-ops), DB active-case injection, evidence gate,
response redaction/cap, control-plane-required backstop. All fail-closed.

### 3.3 Residual gap a BEHAVIORAL probe (XYE-25 / Axis H) must close

- Prove `read_only`/`evidence_class` by observing actual effects of a call.
- Prove `default_case_scoped`/plane by observing whether the tool accepts/echoes
  path / evidence-ref / case-id arguments it shouldn't.
- Prove `secret_leak_guarantee` by scanning real responses for secret/PII.
- Catch behavioral drift across updates (re-run probe at re-register).
- Bound the tool (timeout / output size / error-shape) so a buggy or hostile
  tool can't hang or flood — closing the (a)/(f) per-call gap at admission time.

---

## 4. Candidate Ecosystem (research) — filtered through the two admission paths

Per §1.1a, most DFIR tooling is **Path A** (catalog/`run_command` or an
OpenSearch parser), not a backend. This section therefore answers, for each
candidate, the right question: **Path A or Path B, and why** — and reserves
"new backend" for genuine **stateful external services**. (Community MCP
existence/footprint from web research; licenses noted.)

### 4.1 Already covered — NOT candidates (verified)

| Capability | Where it already lives | Verdict |
|---|---|---|
| Plaso/log2timeline super-timeline | `opensearch-mcp/.../parse_plaso.py:31` | DONE (parser); not a backend |
| Volatility3 memory | `…/parse_memory.py:3`; `sift-vol3` template | DONE (parser); not a backend |
| evtx/srum/prefetch/tasks/wer/ssh/w3c/accesslog/csv/delimited/json/defender | `…/parse_*.py` | DONE (parsers) |
| Hayabusa Sigma scan | ingest pipeline | DONE |
| Sleuth Kit (`fls`/`icat`/`mmls`/`tsk_recover`), E01/EWF, `bulk_extractor`/`foremost`/`scalpel`/`binwalk`, `exiftool`, hashing | `MVP_FORENSIC_ALLOWLIST` (`security_policy.py:136-247`) | DONE (Path A) |
| `yara` static scan | allowlisted (`security_policy.py:136-247`) | **Path A** — catalog entry, NOT a YARA backend |
| `tshark`/`tcpdump` PCAP | allowlisted (`security_policy.py:136-247`) | **Path A** — network forensics is already a catalog binary, not a backend gap |
| capa, ALEAPP/iLEAPP, readpst/libpff, Sleuthkit interactive | not yet allowlisted, but one-shot CLIs | **Path A** — add catalog entry + allowlist; no backend needed |
| Timesketch, DFIR-IRIS, Autopsy | — | **neither** — overlap OpenSearch / our control plane / GUI; avoid |

So the earlier "candidate backends" PST, tshark, YARA, hashlookup-as-binary are
**reclassified to Path A** (catalog/curl), not Path B. The genuine Path-B gap is
small.

### 4.2 Genuine Path-B candidates (stateful external services)

| Candidate | What it is | Path A vs B — and why | Plane / case-scoped | Verification weight |
|---|---|---|---|---|
| **Velociraptor / GRR** (`socfortress/velociraptor-mcp-server`, AGPL) | live endpoint collection + VQL hunt server | **Path B (the one that justifies heavy verification)** — a stateful hunt server with sessions/clients; cannot be a one-shot binary. But it is **mutating + remote**: it touches live endpoints, violating "operator mounts + seals evidence". **Note (verified): the RAG corpus already grounds Velociraptor (+ KAPE, LOLBAS, GTFOBins, Sigma, MITRE ATT&CK, Atomic Red Team, Splunk) methodology** (live gateway, case-rocba-3, 2026-06-18), so the *knowledge* is already in-platform — only **live collection/acquisition** would be net-new, and acquisition is operator-side, outside the agent session. | mutating (remote); a NEW collection plane | **highest** — only case where adversarial behavioral probing + a separate re-auth-gated collection plane earn their cost |
| **CAPE / Cuckoo** detonation sandbox | live malware detonation w/ guest VMs | **Path B if at all** — stateful sandbox host+guests; not a one-shot binary. Very heavy; live detonation conflicts with the sealed-evidence model. | mutating (guest VMs) | high (but recommend OUT OF SCOPE) |
| **MISP** (`MISP/misp-mcp`, query-only) | TI sharing platform / feeds / galaxies | **Path B**, but **overlaps `opencti-mcp`** — run ONE TI plane. If a MISP already exists, the MCP is a thin API client; else heavy. | reference/threat-intel; `default_case_scoped:false` | low (mirror opencti contract) |
| **Graph / link-analysis store** (e.g. Maltego-class, a Neo4j-backed relationship store) | stateful relationship graph across cases/IOCs | **Path B** — a persistent graph store with its own query API; genuinely stateful, no Path-A equivalent. | analysis/reference | medium |
| **External enrichment APIs** — VirusTotal (`BurtTheCoder/mcp-virustotal`), Shodan (`BurtTheCoder/mcp-shodan`), GreyNoise, urlscan.io, abuse.ch (`lokallost/abusech-mcp`), CIRCL hashlookup/NSRL | online IOC/hash/host reputation | **Path A by default** (curl catalog entry over the public API), **Path B only if** you want an authenticated session, pagination/response shaping, scope-gated typed tools, and FK-style enrichment into OpenSearch. A thin `cti`-pattern backend mirrors `opencti-mcp` and is low-risk. | reference; `default_case_scoped:false`; query-only | **low** (contract-conformance + authority-contradiction is enough; no mutating risk) |

### 4.3 Recommendation (revised)

1. **External enrichment cluster — start Path A (curl catalog), graduate to a
   thin Path B `cti`-style backend only when session/typed-surface/FK-enrichment
   is wanted.** VT + abuse.ch + CIRCL hashlookup (NSRL known-good complements
   wintriage's known-bad) make OpenSearch hits actionable at near-zero infra and
   no mutating risk. This is the cleanest near-term win.
2. **One TI plane only — and it is already wired as an opensearch feed.** Live,
   OpenCTI is consumed via `opensearch_enrich_intel` (enrichment INTO opensearch),
   not a standalone `cti_*` query backend (live gateway, case-rocba-3,
   2026-06-18). A separate query-only TI backend (cti or MISP) is only worth
   adding if interactive TI *querying* (vs batch enrichment) is wanted; do NOT
   run two TI platforms.
3. **Velociraptor/GRR is the only candidate that justifies the full behavioral
   verifier** — and even then, narrowly: its *methodology* is already in the RAG
   corpus (verified), so the net-new value is **live collection only**, which is
   operator-side acquisition outside the agent session and conflicts with the
   sealed-evidence model. Worth it only behind a deliberate, separately
   re-auth-gated *collection* plane. Treat as a future design decision, not an
   MVP add-on.
4. **CAPE/Cuckoo, Timesketch, DFIR-IRIS, Autopsy: out of scope** (overlap or
   model conflict). YARA/tshark/PST/capa/ALEAPP: **Path A catalog entries**, not
   backends.

---

## 5. Verification Design (the core ask)

**Goal:** a STANDALONE verifier that keeps changes OFF the gateway core by
EXTENDING `scripts/probe_backends.py`. Run at `setup-addon`/register time
(and re-register), it emits one machine-readable report the portal consumes.
It decides three things.

### 5.1 The three decisions

**(1) COMPATIBLE** — structural/contract conformance + **drift/installed**
(the highest-value tier; the failures that actually recur). *Already mostly
built* in the static probe (§3.1): schema + cross-field contract + namespace
prefixing + declared-tool match + transport handshake (`initialize`) +
`tools/list` reachable + no forbidden identity args. **H2 (XYE-56)** hardens
this into a **live schema probe** and adds the two drift checks that map to the
real recurring pain:

- **Schema drift:** diff each served `inputSchema` against the manifest; flag
  missing/extra/changed tools and args before exposure.
- **Registered-SHA vs on-disk-SHA drift:** recompute `manifest_sha256`
  (mcp_backends_registry.py:134-136) and compare to the registered row — surface
  the B-MVP-029/032 stale-snapshot condition the gateway only WARNs about today
  (mcp_backends_registry.py:206-227).
- **(c)-installed reality:** confirm the backend process actually starts and the
  health probe responds (Path-B analogue of the §1.1a 3-state gap) — declared
  but not-installed is the most common honest failure.

**(2) SECURE** — behavioral. Spin the backend in an **isolated synthetic
case/evidence context**, dry-run/fuzz each tool with synthetic args, observe.
This is **H3 (XYE-57)**. Detect:

| Behavioral check | Method | Maps to threat |
|---|---|---|
| writes/mutations vs declared `read_only`/`query_only` | run tool in a synthetic case whose dir + a marker file are watched (mtime/inode/size); a `read_only`-declared tool that mutates the watched tree, or whose response reports a write, is flagged | (b),(d) |
| path / evidence-ref / case-id args vs `default_case_scoped`/plane | inject canary path + canary case-id; observe whether a tool declared non-case-scoped/reference ACCEPTS or ECHOES them, or whether a case-scoped tool ignores the injected `case_dir` and resolves a different case | (b) |
| secret/PII echo | seed the synthetic env with canary secrets/tokens and feed canary IOCs; scan every response for the canaries and for known secret/PII patterns (reuse response_guard patterns) — proves `secret_leak_guarantee` | (e) |
| timeout / resource limits | run each call under a hard wall-clock timeout + output-size cap + (where available) a cgroup/rlimit; a hang or flood is a finding, not a hang of the probe | (a),(f) |
| error-handling shape | call with malformed/empty/oversized args; require a structured MCP error, not a crash or stack-trace leak | (a) |

**(3) MANIFEST-APPROVED** — operator gate. The probe computes the
`manifest_sha256` (mcp_backends_registry.py:134-136) and the report binds to it.
Registration remains operator-authed + re-auth-gated (sensitive op).
Advisory-vs-blocking policy (see §6) decides whether SECURE findings block
register/start or only advise. **H4 (XYE-58)** surfaces the report in the portal
register/start flow; the approved SHA is what the gateway then serves (so any
later drift = re-probe + re-approve).

### 5.2 Report schema (proposed)

```json
{
  "probe_version": "1",
  "backend_name": "virustotal-mcp",
  "manifest_sha256": "<64-hex>",
  "probed_at": "2026-06-18T00:00:00Z",
  "transport": "stdio",
  "decisions": {
    "compatible": "pass",            // pass | fail
    "secure":     "warn",            // pass | warn | fail
    "manifest_approved": "pending"   // pending | approved (set by operator)
  },
  "overall": "advise",               // pass | advise | block
  "checks": [
    {
      "id": "schema.drift.tool_missing",
      "tier": "BLOCK",               // BLOCK | ADVISE | INFO
      "decision": "compatible",
      "status": "pass",
      "tool": "vt_lookup_ioc",
      "detail": "served tool matches manifest declaration",
      "reproducer": null             // minimal synthetic args only; never real data
    },
    {
      "id": "behavior.write_under_readonly",
      "tier": "BLOCK",
      "decision": "secure",
      "status": "fail",
      "tool": "cti_lookup_ioc",
      "detail": "tool declared read_only=true but synthetic case dir changed (1 file created)",
      "reproducer": {"args": {"ioc": "203.0.113.1"}}
    }
  ],
  "synthetic_context": {
    "case_id": "probe-synthetic-0001",
    "evidence": "synthetic fixtures only; no real case/evidence touched"
  }
}
```

### 5.3 Severity tiers — recommended BLOCK vs ADVISE

| Check | Tier | Rationale |
|---|---|---|
| schema/contract fail (existing static checks) | **BLOCK** | hard conformance; already fail-closed at register (spec.md §7.2) |
| registered-SHA ≠ on-disk-SHA (manifest drift) | **ADVISE** (BLOCK on re-register) | the recurring B-MVP-029/032 failure; warn at register, require re-register to clear |
| backend process won't start / health probe fails (not installed) | **BLOCK** (admission) | declared-but-not-installed (§1.1a state c); can't admit an unreachable backend |
| forbidden identity/override arg present | **BLOCK** | direct authority-bypass attempt (probe_backends.py:349-354) |
| served tool not declared / wrong namespace | **BLOCK** | runtime already raises (spec.md §5); fail early |
| `read_only` declared but write observed | **BLOCK** | hard authority contradiction (threat b) |
| `non_authoritative`/`query_only` but a prohibited-op effect observed | **BLOCK** | hard authority contradiction |
| canary secret/token echoed in response | **BLOCK** | `secret_leak_guarantee` falsified |
| tool hangs past timeout / exceeds output cap badly | **BLOCK** (admission) | a backend that can't be bounded shouldn't be admitted |
| case-scoped tool ignores injected `case_dir` (resolves other case) | **BLOCK** | breaks case isolation |
| non-case-scoped/reference tool ACCEPTS path/evidence/case-id args | **ADVISE** | suspicious but may be benign (generic schema); operator judges |
| canary PII (non-secret) echoed | **ADVISE** | soft signal; context-dependent |
| schema drift: extra optional arg / description change | **ADVISE** | informational drift |
| non-structured error shape on malformed input | **ADVISE** | robustness signal |
| health probe slow / degraded | **INFO** | already advisory (probe_backends.py:359-374) |

### 5.4 Isolation strategy (hard constraints)

- **Synthetic context only.** A throwaway case id + a tmpdir tree with marker
  files; **never a real case/evidence path** (XYE-57 hard constraint). The probe
  injects canary `case_id`/`case_dir`/secrets, not production identities.
- **No live external deps.** Do **not** spin live OpenCTI, do **not** pull the
  ~12 GB wintriage registry baseline (setup-addon.sh:503-510), do **not** hit
  real VT/abuse.ch endpoints with real keys — use a mocked/offline transport or a
  dedicated probe key with synthetic IOCs. Reference-plane online add-ons get a
  network-disabled or canary-only run.
- **Bounded & side-effect-safe.** Every tool call under a wall-clock timeout +
  output cap (+ cgroup/rlimit where available) — XYE-56/57 require timeout/
  resource bounds and no secret exposure. Run the backend the same way the
  gateway would (`resolve_runtime_config` shape) but in a probe sandbox, not the
  live gateway process.
- **Reproducers carry minimal synthetic args only** (XYE-57), never real bytes.

### 5.5 Mapping to Linear H-units (parent XYE-45)

| Unit | Title | This design delivers |
|---|---|---|
| **XYE-25 (H1)** | register-time behavioral scan/fuzz design | this whole §5 (the design + advisory-vs-blocking decision in §6); the "trust backend CODE not declarations" framing matches the issue |
| **XYE-56 (H2)** | tool surface + schema probe harness | §5.1(1) + §5.3 COMPATIBLE tier: live `tools/list`/`inputSchema` vs manifest, schema-drift detection, **registered-SHA-vs-on-disk drift (B-MVP-029/032) and (c)-installed/process-start checks** (the recurring real failures), side-effect-safe + timeout-bounded + no-secret-exposure (issue hard constraints) |
| **XYE-57 (H3)** | behavioral cross-check probe | §5.1(2) SECURE checks: writes-vs-readonly, path/evidence/case-id-vs-declaration, secret echo, error-shape — synthetic inputs only, never real case/evidence, minimal reproducers |
| **XYE-58 (H4)** | portal operator report + gating | §5.2 report schema consumed in portal register/start; §5.3 tiers drive pass/warn/fail; preserves re-auth/operator gate; defaults to advisory if blocking undecided (issue hard constraint) |
| **XYE-59 (H5)** | regression fixture backends | §5.3/§5.4 exercised by fixtures: honest reference, honest case-scoped, manifest/schema drift, contradictory-behavior backend; CI runs the matrix (issue acceptance) |

---

## 6. Recommendation + Scope Decision

### 6.1 What to adopt NOW (MVP) vs defer until public

**Probe weighting (explicit tradeoff).** Live reality (§1.0) is: backends are
**rare, operator-installed, and mostly reference/query plane** (3 live, all
read-only/derived except opensearch ingest). The recurring real-world pain is
NOT a malicious tool — it is **stale registration / drift** (B-MVP-029/032: the
DB snapshot SHA falls behind the on-disk manifest and silently disables features)
and **declared-but-not-installed** capability (§1.1a 3-state gap). So weight the
probe toward, in order:

1. **COMPATIBLE / contract conformance + drift** (highest value): schema +
   cross-field contract + namespace + served-tool-vs-manifest + the
   registered-SHA-vs-on-disk-SHA check + the (c)-installed check. This is cheap,
   already near-built (§3.1), and catches the failures that actually happen.
2. **Authority-contradiction cross-check** (cheap, high value): read-only-vs-
   write, query-only/non-authoritative-vs-prohibited-effect, case-isolation,
   secret-canary echo. A few synthetic calls catch a *lying manifest* — the main
   security win.
3. **Adversarial behavioral fuzzing** (LOWER priority): broad arg fuzzing /
   robustness probing buys little here and an MCP probe **cannot see host-level
   process behavior anyway** — a tool that lies through valid-looking responses
   or does damage out-of-band is invisible to a tool-call probe. Lean on the
   existing runtime enforcement (§1.3) plus **RUN-3-style OS confinement of the
   backend PROCESS** (Landlock/seccomp/cgroup/AppArmor, the way `run_command`'s
   `agent_runtime` is confined) for the malicious-code tail. That is the correct
   layer for "what the process does", not the MCP probe.

| Capability | Now (MVP) | Defer (until public / multi-author) |
|---|---|---|
| COMPATIBLE (schema/contract/handshake) | **Yes, FIRST** — wire the existing static probe (§3.1) into setup-addon/register and emit the §5.2 report | — |
| Registered-SHA-vs-on-disk drift + (c)-installed check (H2) | **Yes, FIRST** — this is the recurring real failure (B-MVP-029/032; §1.1a) | — |
| Live schema-drift probe (H2) | **Yes** — cheap, high value, already near-built | — |
| Authority-contradiction SECURE checks (H3) — read-only-vs-write + secret-canary + case-isolation | **Yes, lean** — highest security signal per effort; catches the lying manifest | — |
| Path/evidence/case-id cross-check (H3) | **Yes, ADVISE** — easy to observe, low effort | promote to BLOCK once fixture matrix tuned |
| Broad adversarial fuzzing / robustness corpus (H3) | **Defer / minimal** — low ROI; an MCP probe can't see process behavior; covered better by runtime enforcement + process sandbox | richer corpus once third-party authors exist |
| Portal report + gate (H4) | **Yes, advisory** — show pass/warn/fail at register; operator decides | hard-block enforcement policy |
| Fixture matrix (H5) | **Yes** — needed to keep H2/H3 honest in CI; emphasize drift + contradiction fixtures | expand to adversarial fixtures |
| Backend process sandbox (RUN-3-style seccomp/landlock/cgroup/AppArmor for add-on subprocesses) | **Yes for the malicious-code tail** — this is the RIGHT layer for "what the process does" (the probe can't be); confirm whether add-on subprocesses already inherit `agent_runtime`-style confinement (**UNVERIFIED**) and extend if not. Lower urgency under solo/private trust, but it — not the probe — is what bounds threat (c). | mandatory before any untrusted third-party author |
| Per-add-on runtime cgroup/quota at proxy | **Defer** — probe-time timeout covers admission; runtime quota is hardening | public hardening |

### 6.2 Advisory-vs-blocking — recommended default (confirming the working rec)

**Adopt: BLOCK on hard authority contradictions, ADVISE on soft signals,
operator override with re-auth + recorded rationale.** I confirm this — with the
mapping made concrete in §5.3:

- **BLOCK** = the manifest's authority self-description is *falsified* by
  behaviour: write under `read_only`, prohibited-op effect under
  `non_authoritative`/`query_only`, canary-secret echo, case-isolation break,
  forbidden identity arg, or a tool that can't be bounded. These are
  contradictions of the exact properties the gateway *trusts* (§1.3), so
  admitting them defeats the perimeter.
- **ADVISE** = soft signals (generic schema accepts a path it probably won't
  use, PII echo, optional-arg drift, non-structured error). Real-world add-ons
  (generic enrichment schemas) trip these benignly; blocking would make the
  ecosystem hostile for no security gain.
- **Override** = operator may admit a BLOCK finding via the existing re-auth
  gate (sensitive op) **with a recorded rationale** in the audit trail
  (mcp_backend.registered already audited, mcp_backends_registry.py:509-524 — add
  an override-rationale field). This preserves the solo-operator's autonomy while
  leaving a durable record — exactly the project's "move by evidence" posture.

This also matches the H4 issue's stated fallback ("if blocking policy is not
decided, default to advisory") — start advisory-everywhere, flip the hard-
contradiction set to BLOCK once the H5 fixture matrix proves low false-positive
rate.

### 6.3 Open questions for the operator

1. **Process sandbox:** are add-on stdio subprocesses currently confined the way
   `run_command`'s agent_runtime is (Landlock/seccomp/cgroup/AppArmor)? **I
   could not verify any add-on-process sandbox in source — UNVERIFIED.** If not,
   threat (c)/(f) rest entirely on admission + informed consent. Acceptable for
   solo/private? Required before public?
2. **Blocking flip date:** ship the behavioral probe ADVISE-only first, then flip
   the hard-contradiction set to BLOCK after the H5 matrix is green — agreed, or
   block from day one?
3. **Online reference add-ons in the SECURE probe:** mock the transport, or use a
   dedicated probe API key with synthetic IOCs and a network allowlist? (No real
   keys in the probe path.)
4. **Override granularity:** per-finding override, or whole-backend override?
   Per-finding is safer but more UI; whole-backend is simpler for solo use.
5. **Re-probe cadence:** probe only at register, or also on the 30s late-start
   reload (spec.md §7.3) and on detected manifest drift (mcp_backends_registry.py
   :400-428)? Re-probe-on-drift closes threat (d) but costs a probe run.
6. **First add-ons:** confirm the §4.3 revised stance — external-enrichment
   cluster as **Path A curl/catalog** first (VT/abuse.ch/hashlookup), graduating
   to a thin `cti`-style Path-B backend only if a typed/session surface is
   wanted; one TI plane only (OpenCTI is already an opensearch feed); explicitly
   reject the overlap set (Timesketch, MISP-alongside-OpenCTI, DFIR-IRIS,
   Volatility3/Plaso/Sleuthkit-as-backend) so we don't duplicate core.
7. **Resource budget shape:** what hard wall-clock timeout + output cap should a
   probe tool call get, and should the same bound apply at runtime to add-on
   calls (currently **UNVERIFIED** that any exists)?
8. **Drift policy:** should registered-SHA-vs-on-disk drift stay WARN-only
   (today) or become a gate at re-register? And should the probe re-run
   automatically on the 30s late-start reload / on detected drift, or only at
   explicit operator register (Q5 above)?
9. **3-state inventory (Axis F tie-in):** should the COMPATIBLE report include
   the Path-A (c)-installed gap for cataloged binaries too (XYE-48/49), so the
   operator sees one honest "declared vs actually-runnable" view across both
   admission paths?

---

## Appendix — Primary source anchors

- Manifest schema: `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`
- Static probe: `scripts/probe_backends.py`
- Cross-field contract + case-scope lints: `packages/sift-gateway/src/sift_gateway/backends/__init__.py:90-247`
- Middleware stack: `packages/sift-gateway/src/sift_gateway/policy_middleware.py:1247-1280` (and each class)
- Add-on authority enforcement: `policy_middleware.py:360-449`; profile build `server.py:863-885`
- Case-scope + injection logic: `server.py:811-861`; `policy_middleware.py:805-863`
- Evidence gate: `packages/sift-gateway/src/sift_gateway/evidence_gate.py`
- Registry / DB snapshot / drift: `packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py`
- Provisioning: `scripts/setup-addon.sh`
- Normative spec: `docs/drafts/add-ons/spec.md`; author guide `docs/drafts/add-ons/author-guide.md`
- Manifests: `packages/{opensearch-mcp,forensic-rag-mcp,forensic-knowledge,windows-triage-mcp,opencti-mcp}/sift-backend.json`
- Linear: parent `XYE-45`; units `XYE-25` (H1), `XYE-56` (H2), `XYE-57` (H3), `XYE-58` (H4), `XYE-59` (H5)
