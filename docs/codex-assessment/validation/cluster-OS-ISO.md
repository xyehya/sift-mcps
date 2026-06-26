# Validation — Cluster OS-ISO (OpenSearch cross-case isolation + scope)

> Validator agent: sec-osiso (Opus 4.8, xhigh). Read-only. Validates the restored
> Codex assessment against **current HEAD** `93f8999` (183 commits ahead of the
> stale scan base `b995491`). Codex line ranges were re-located on current source.
> No source code was modified — this file is the only output.
> Secure-coding lens: `codeguard-security:codeguard` skill run (Python / MCP-security
> + authorization-access-control rule sets). Verdict per candidate below.

## Summary table

| Candidate | Codex verdict | **Current status** | Current severity | Confidence | Already-fixed-by | Fix effort |
|---|---|---|---|---|---|---|
| DSS-CAN-010 | valid / high | **STILL-VALID** | **High** | high | — (partial mitigation: system-index block only) | M |
| DSS-CAN-011 | valid / med | **STILL-VALID** | **Medium** | high | — | M |
| DSS-CAN-012 | valid / med | **STILL-VALID (inert gate)** | **Low** | high | — (gateway middleware already protects the agent path) | S–M |

**Highest priority in cluster: DSS-CAN-010** — a single normal gateway-MCP call
(`opensearch_search(query="*", index="case-*")`) reads/exfiltrates **every case's**
indexed evidence. This is the only High and the one to fix first.

---

## DSS-CAN-010 — Explicit `index` parameter overrides active-case isolation

**Codex claim (verbatim intent):** Case-scoped OpenSearch query tools expose an explicit
`index` parameter. The Gateway injects/checks `case_id` and `case_dir` but not `index`,
and the backend resolver returns the caller-supplied `index` before active-case context →
cross-case reads (`index=case-*`, `case-other-*`, exact other-case index).

**Current code located at:**
- Typed surface (agent-settable field + only guard): `packages/opensearch-mcp/src/opensearch_mcp/registry.py:74-111` (`CaseScopedQueryBase.index` field 75-81; `_validate_case_index` validator 99-111). Codex cited `74-111` on `b995491` — same region, but the validator is **new since the scan**.
- Backend resolver: `packages/opensearch-mcp/src/opensearch_mcp/server.py:653-673` (`_resolve_index`).
- Backend guard: `packages/opensearch-mcp/src/opensearch_mcp/server.py:144-157` (`_validate_index`).
- Handler: `packages/opensearch-mcp/src/opensearch_mcp/server.py:847-906` (`opensearch_search`; resolve at 903, validate at 904). Same shape in `opensearch_count` (1035), `opensearch_aggregate` (1105), `opensearch_timeline` (1254), `opensearch_get_event` (1347).
- Gateway injection (what it does / does not touch): `packages/sift-gateway/src/sift_gateway/server.py:1112-1135`.

**Drift since scan:** `git log --oneline b995491..HEAD -- registry.py` shows 10 commits
(M-FIELDVALS, M-HOSTNAME, M-QUERYERR, F3-DIAG, etc.). The relevant change is that a
`_validate_case_index` field-validator (registry) and `_validate_index` (server) were
**added** — they enforce a `case-` prefix on every index segment. This is a *partial*
mitigation: it blocks system/`.`-indices, **not** cross-case reads. `_resolve_index`'s
caller-index short-circuit is unchanged.

**CURRENT STATUS:** STILL-VALID (partially mitigated — system-index access closed, cross-case isolation still open)

**Evidence (current source):**
```python
# server.py:653-673 — caller-supplied index returned VERBATIM, before any active-case resolution
def _resolve_index(index: str, case_id: str) -> str:
    if index:
        return index            # <-- short-circuit: active case never consulted
    cid = ""
    if case_id and not _UUID_RE.match(case_id.strip()):
        cid = case_id.strip()
    if not cid:
        cid = _get_active_case() or ""
    if cid:
        return build_index_pattern(cid)
    return "case-*"

# server.py:144-157 — the ONLY guard: case- prefix (system-index prevention), NOT case binding
def _validate_index(index: str) -> str | None:
    ...
        if not segment.startswith("case-"):
            return f"Index segment '{segment}' must start with 'case-' (security: blocks access to system indices)"
    return None

# server.py:903-904 — handler honors caller index, then runs the prefix-only guard
index = _resolve_index(index, case_id)
err = _validate_index(index)            # passes for case-* and any other case

# gateway server.py:1125-1135 — gateway injects/validates ONLY case_id/case_key/case_dir; `index` untouched
for key, expected in (("case_id", ...), ("case_key", ...), ("case_dir", ...)):
    if key not in safe_args: continue
    supplied = arguments.get(key)
    if supplied and str(supplied) != expected:
        raise RuntimeError(f"client-supplied {key} does not match DB active case")
    arguments[key] = expected
```
The intent is **confirmed by the project's own test suite**, `packages/opensearch-mcp/tests/test_security.py:221-224`:
```python
def test_case_wildcard_passes(self):
    assert _validate_index("case-*") is None   # case-* (ALL cases) is ALLOWED by design
```

**Reachability trace (gateway-MCP path — the dangerous one):**
1. Agent → gateway `/mcp` calls `opensearch_search(query="*", index="case-OTHERCASE-evtx-*")` (or `index="case-*"`).
2. `AddonAuthorityMiddleware`: opensearch_search has no `required_scopes`/prohibited ops → passes.
3. Case-scope injection (`server.py:1112-1135`): tool is case-scoped, `safe_args={case_id,case_dir}`. Gateway overwrites `case_id`/`case_dir` to the DB-active case and rejects a *mismatching* `case_id`/`case_dir` — **but never inspects `index`**.
4. Backend `run_opensearch_search` → `_impl_server().opensearch_search(**model_dump())` (`registry.py:930,942`). `SearchIn`/`CaseScopedQueryBase` validator passes (`case-` prefix present).
5. Impl: `_resolve_index("case-OTHERCASE-evtx-*", <injected active case_id>)` → returns the caller string verbatim (active case_id is ignored because `index` is truthy). `_validate_index` passes.
6. `client.search(index="case-OTHERCASE-evtx-*", body=...)` → returns the other case's documents. No per-hit case filter exists in `_strip_hits`/`_hoist_constant_fields`; `common_fields` will even surface the *other* case's `sift.case_id`.

This is reachable through the **normal gateway MCP surface** by any identity that can call
opensearch query tools — not a direct-backend bypass. The agent never needs DB creds.

**Exploit preconditions:** an active portal case + a token with the ordinary opensearch
query tool scope (the standard agent token). No operator/admin role, no re-auth, no
gateway bypass required. `index="case-*"` dumps **all** cases in one call.

**Blast radius:** full cross-case confidentiality breach — search/count/aggregate/timeline/
get_event across any or all other cases' indexed evidence (filenames, registry, event logs,
IOCs, host identities, `sift.*` provenance). Case isolation is a core security property of
this product; this defeats it at the agent surface.

**Project-invariant check:** Directly breaks **case isolation**. The fix interacts with the
**MCP surfacing layers** (the typed `*In` field + the gateway case-injection boundary) and
the **gateway-as-policy-boundary** invariant: case-scope enforcement must live at the
gateway/registry boundary, not only the impl. It must preserve **DB-authority** (the active
case identity comes from the gateway-injected `case_dir`/`case_id`; the backend has no DB
creds — `_get_active_case()` derives the key from the injected `case_dir` and is the
authority the backend legitimately holds).

**FIX APPROACH (secure-by-design, preserves invariants, NOT monkey-patching):**
- **Root cause:** `index` is a free-form, agent-settable parameter that *overrides* the
  active case; `_resolve_index` short-circuits on it; the only guard checks the `case-`
  prefix, not the active-case prefix; the gateway never constrains it.
- **Primary fix — bind the resolved index to the active case (backend, defense-in-depth that also covers the direct path):**
  Replace the `_validate_index` prefix-only check (and the `if index: return index`
  short-circuit) with active-case binding. Compute the authoritative prefix once via
  `build_index_pattern(_get_active_case(), tail="")` → `case-{normalize_case_key(key)}-`.
  When the caller supplies `index`, require **every** segment to start with that exact
  active-case prefix (or equal the active pattern); reject with a typed user-input error
  otherwise. When `index` is empty, resolve to the active pattern as today. This uses only
  the gateway-injected authority the backend already has and closes both the gateway and
  direct-CLI paths. The typed error already surfaces through the registry error envelope
  (`opensearch_search` returns `{"error": ...}` → `run_opensearch_search` wraps it) — so it
  satisfies the surfacing-layer rule, but a **surface test must assert it** (below).
- **Boundary fix — make the gateway constrain `index` too (the invariant's preferred home):**
  Because OpenSearch is first-party (the gateway *may* name it) and the gateway already
  knows `case_key`, extend `server.py:1112-1135` to validate a caller-supplied `index` on
  case-scoped opensearch tools against `case-{active_case_key}-`/the active pattern and
  reject a mismatch — exactly as it already rejects a mismatching `case_id`. Declare the
  index argument as case-bound in the manifest so the gateway knows to validate it. This
  puts case-isolation enforcement at the policy boundary, not only inside the add-on.
- **Why it preserves identity/invariants:** the active case remains DB-authoritative
  (gateway-injected); the agent keeps the ergonomic ability to narrow to an artifact family
  *within its own case*; system-index blocking is retained; no new DB creds in the backend.
- **Test strategy:** (1) unit on the new binding: active case = A → `index="case-B-*"`,
  `index="case-*"`, and an exact `case-B-...` name all rejected; `index=""` and
  `index="case-A-evtx-*"` allowed. (2) **fail-on-revert surface test** (sift_common
  surface harness) asserting the cross-case-denied error is visible in the registry
  `result_public` envelope for opensearch_search/count/aggregate/timeline/get_event — and
  add the denial key to `SURFACE_OPTIONAL_KEYS` if needed. Update
  `test_security.py:test_case_wildcard_passes` (currently asserts `case-*` passes — it must
  flip to assert denial under an active case). (3) **live deploy-and-prove:** two cases on
  the VM, activate case A, call `opensearch_search(index="case-B-*")` and `index="case-*"`
  → expect denial; diff before/after restart of gateway + opensearch workers.
- **Alternatives considered / rejected:** (a) *Remove `index` entirely* — loses legitimate
  intra-case artifact-family narrowing and is a larger agent-API break; rejected in favor
  of binding. A stronger long-term variant (replace raw `index` with an `artifact`/
  `index_suffix` selector the backend composes onto the authoritative prefix) is the most
  secure design and worth offering the operator, but is a bigger change. (b) *Post-query
  per-hit `sift.case_id` filtering* — wasteful, leaks via counts/aggregations, and fails for
  metadata; rejected.

**Cross-cluster dependency:** Tightly coupled to **DSS-CAN-011** — `opensearch_status`
hands the attacker the exact other-case index names that make 010 trivial to target. Fix
both; 010 is the read primitive, 011 is the recon. No shared code change, but validate them
together on the VM.

**Open question for operator:** Keep `index` (bound to active case) for ergonomics, or
replace it with a constrained `artifact`/suffix selector? Recommendation: bind now (fast,
closes the hole); consider the selector redesign as a follow-up.

---

## DSS-CAN-011 — `opensearch_status` enumerates all `case-*` indices without active-case binding

**Codex claim (verbatim intent):** `opensearch_status` and related resources enumerate every
`case-*` index name, doc count, size, and status without active-case filtering → cross-case
targeting recon. Separate cluster health from index catalog, filter to active case, or
require admin/operator scope for all-case metadata.

**Current code located at:**
- `packages/opensearch-mcp/src/opensearch_mcp/server.py:1457-1502` (`opensearch_status`; the all-case enumeration is 1469-1479). Codex cited `1359-1382` on `b995491` — relocated +~98 lines.
- Adjacent same-class leak: `packages/opensearch-mcp/src/opensearch_mcp/server.py:1505-1585` (`opensearch_shard_status`; `top_indices_by_shard_count` built unfiltered at 1549-1567).
- Manifest scoping: `packages/opensearch-mcp/sift-backend.json:267` (opensearch_status `safe_case_argument_names: []`) and `:290` (opensearch_shard_status `safe_case_argument_names: []`); global `default_case_scoped: true` at `:9`.

**Drift since scan:** `server.py` saw 8 commits (M-INGSTATUS, F3-DIAG, F7/F8, OOM preflight)
— none touched the status enumeration; logic is materially the same, only relocated.

**CURRENT STATUS:** STILL-VALID

**Evidence (current source):**
```python
# server.py:1469-1479 — every case-* index, all cases, no active-case filter
indices = _os_call(client.cat.indices, format="json")
case_indices = [
    {"index": idx["index"], "docs": int(idx.get("docs.count", 0)),
     "size": idx.get("store.size", "0"), "status": idx.get("status", "unknown")}
    for idx in indices
    if idx["index"].startswith("case-")     # ANY case, not the active one
]
```
`opensearch_status()` takes **no** `case_id`/`case_dir` args, and its manifest
`safe_case_argument_names` is `[]` — so it is treated as case-scoped-but-no-injection-arg
and the gateway lets it through unscoped (`server.py:1115` "empty set = pass through").

**Reachability trace:** Agent → gateway `/mcp` → `opensearch_status` (no required_scopes) →
AddonAuthorityMiddleware passes → case-scope injection sees empty `safe_args` → pass-through →
backend lists all `case-*` indices. Reachable on the normal gateway path by any opensearch-
capable identity, no special scope. Same for `opensearch_shard_status.top_indices_by_shard_count`.

**Exploit preconditions:** active case + ordinary opensearch tool scope. No admin.

**Blast radius:** Metadata/recon disclosure — index names embed case identifiers, hostnames,
and artifact families; plus per-index doc counts and sizes. Not document content, but it is
the targeting map that turns DSS-CAN-010 from "guess an index name" into "read this exact
other-case index." Medium.

**Project-invariant check:** Same **case-isolation** + **gateway-policy-boundary** invariants.
The fix needs the **surfacing layers**: to scope these tools the gateway must inject the
active case, which requires adding `case_id`/`case_dir` to the tool signature *and* to the
manifest `safe_case_argument_names` (today `[]`), then filtering in the impl.

**FIX APPROACH:**
- **Root cause:** status/shard-status are case-scoped tools with no case argument, so they
  cannot be bound to the active case and enumerate the whole cluster.
- **Proposed change (impl + manifest, surfacing-layer aware):** (1) Add `case_id: str=""`,
  `case_dir: str=""` to `opensearch_status`/`opensearch_shard_status` and add both to their
  manifest `safe_case_argument_names` so the gateway injects the DB-active case. (2) Filter
  `case_indices`/`top_indices` to `idx["index"].startswith(build_index_pattern(active_key, tail=""))`.
  (3) Keep cluster-level health (status, node count, headroom %) unscoped — it is not
  case-identifying. (4) For the legitimate all-case capacity view, gate the cross-case
  catalog behind an explicit operator scope via manifest `required_scopes` (e.g.
  `ops:cluster`) or a separate operator-only tool — do not expose all-case metadata to the
  agent identity.
- **Why it preserves invariants:** active case stays DB-authoritative/gateway-injected; the
  agent sees only its own case; operators retain full cluster visibility behind a scope.
- **Test strategy:** unit — active case A → `opensearch_status` returns only `case-A-*`;
  surface fail-on-revert test asserting the filtered `indices[]` in `result_public`; live
  deploy-and-prove with two cases (activate A, confirm B not listed).
- **Alternatives considered / rejected:** "redact names but keep counts" — counts + sizes
  still leak case existence/volume and are weak recon protection; rejected in favor of
  active-case filtering with an operator-scoped escape hatch.

**Cross-cluster dependency:** Feeds **DSS-CAN-010** (recon → read). Fix and prove together.

**Open question for operator:** Is an all-case capacity dashboard needed by the agent, or
only by operators? If operators only, the simplest correct answer is an operator-scoped tool
+ active-case-only agent tool.

---

## DSS-CAN-012 — Enrichment direct-MCP scope fallback fails open when `SIFT_ENRICHMENT_SCOPE` is unset

**Codex claim (verbatim intent):** Gateway MCP enforces `enrichment:intel`, but the backend
fallback denies only when `SIFT_ENRICHMENT_SCOPE` is nonempty and wrong. If unset,
`opensearch_enrich_intel(dry_run=false)` skips the deny block and starts enrichment on
direct-backend / gateway-bypass paths.

**Current code located at:**
- `packages/opensearch-mcp/src/opensearch_mcp/server.py:3348-3364` (deny block; the fail-open guard is 3349-3350). The manifest is a declaration only; enforcement is here. Codex cited `sift-backend.json:448-484` (the manifest entry, which is at `:464-499` now, with `required_scopes` at `:498-499`).
- Authoritative gateway gate: `packages/sift-gateway/src/sift_gateway/policy_middleware.py:398-415` (`AddonAuthorityMiddleware` enforces `required_scopes` unconditionally before dispatch).

**Drift since scan:** Manifest entry moved (M-HOSTNAME / status-enum commits); the
`required_scopes: ["enrichment:intel"]` declaration and the server.py env check are
materially unchanged.

**CURRENT STATUS:** STILL-VALID — but as an **inert/dead defense-in-depth gate**, not an
agent-reachable hole.

**Evidence (current source):**
```python
# server.py:3348-3350 — falsy guard: when SIFT_ENRICHMENT_SCOPE is unset, the deny is SKIPPED
if not dry_run:
    _scope_env = os.environ.get("SIFT_ENRICHMENT_SCOPE", "")
    if _scope_env and _scope_env != "*" and "enrichment:intel" not in _scope_env:
        return {"status": "scope_denied", ...}      # only reached when env is set-and-wrong
```
Repo-wide grep: `SIFT_ENRICHMENT_SCOPE` is **never set** anywhere — no systemd unit, no
install/harden script, no gateway backend-spawn env; it is only *read* here and *set in
tests* (`test_k4_host_identity_authority.py`). So in every real deployment `_scope_env` is
empty and this gate **always fails open** (it never denies).

**Reachability trace (why severity is Low, not Medium):**
- **Gateway-MCP path (the only agent-reachable path):** `opensearch_enrich_intel` carries
  manifest `required_scopes: ["enrichment:intel"]`. `AddonAuthorityMiddleware`
  (policy_middleware.py:398-415) denies (`addon_scope_missing`) before dispatch when the
  identity lacks the scope — **unconditional, independent of the env**. So the agent path is
  fully protected regardless of the env bug.
- **Direct-backend / gateway-bypass path:** the opensearch backend is a gateway-spawned
  stdio subprocess with no agent-facing listener. Reaching `opensearch_enrich_intel` while
  bypassing the gateway requires running the CLI as the operator on the VM or having already
  compromised a process — i.e. an actor outside the agent threat model the env gate is
  nominally for.

**Exploit preconditions:** local/CLI execution of the backend outside the gateway with the
env unset. Not reachable by a normal agent token through the gateway.

**Blast radius:** On the agent path: none (gateway-gated). On a direct-CLI path: an
unscoped invocation could start enrichment (a mutating, OpenCTI-contacting, async run). Low
in the deployed product because the env gate is inert *and* the agent path is independently
gated.

**Project-invariant check:** The authoritative gate correctly lives at the **gateway policy
boundary** (good). The backend env gate is a redundant direct-path gate that (a) fails open
and (b) is never armed. Important constraint for any fix: a *naive* fail-closed change
(dropping the `if _scope_env and`) would **break the legitimate gateway path** — the
gateway-spawned backend subprocess has the env unset and the gateway does not propagate
per-call scope into the subprocess, so the now-fail-closed impl gate would deny every
gateway-authorized enrich (and every pre-authorized worker job at `ingest_job.py:183`).

**FIX APPROACH:**
- **Root cause (two-part):** (i) the env condition fails open when unset; (ii) nothing ever
  sets the env, so the gate is inert — a false sense of protection, with the gateway
  middleware doing the real work.
- **Recommended (honest, invariant-aligned):** treat the gateway `AddonAuthorityMiddleware`
  as the sole authoritative gate (it already is) and **remove the inert in-process env gate**
  from `opensearch_enrich_intel` to eliminate the fail-open dead code and the false
  assurance. If a standalone-CLI defense-in-depth gate is genuinely wanted, **move it to the
  CLI entrypoint** (`ingest_cli.cmd_enrich_intel` / `sift_plugin`) where the operator
  identity/scope is actually available, and make *that* fail-closed — do **not** fail-close
  the in-process impl gate, which would break the gateway and worker paths.
- **Alternative (if the env gate is kept):** require the gateway to set
  `SIFT_ENRICHMENT_SCOPE` in the opensearch backend subprocess env at spawn (a "trust the
  gateway" signal), then make the impl gate fail-closed. This re-arms the gate without
  breaking legit calls, but couples backend trust to a static env and is more moving parts;
  rejected in favor of removing the redundant gate.
- **Why it preserves invariants:** keeps the single authoritative gate at the gateway
  boundary; removes dead fail-open code; no change to DB-authority.
- **Test strategy:** unit asserting `AddonAuthorityMiddleware` denies enrich without
  `enrichment:intel` (lock in the real gate); if a CLI gate is added, unit asserting it
  fails closed when no scope is presented. Behavioral live-proof is optional here since the
  agent path is already gated — a gateway-path deny test is the meaningful one. No surface
  test needed beyond the existing addon-authority deny path.

**Cross-cluster dependency:** None for the code change. Conceptually pairs with the
auth/scope cluster (DSS-CAN-014/015, `mcp:*` breadth) — least-privilege scopes there reduce
the chance any identity holds `enrichment:intel` unnecessarily, but no shared fix.

**Open question for operator:** Remove the inert env gate (recommended) or re-arm it by
having the gateway set the backend env? Either is fine; do **not** leave it fail-open. Note
the env gate provides **zero** protection today regardless.
