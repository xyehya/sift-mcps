# SIFT Sprint — Active Work & Open Decisions

_Last updated: 2026-06-10. Single source for everything requiring action or a decision._
_Companion to `docs/migration/task-batches.md` (batch definitions) and `docs/migration/Session-Notes.md` (change log)._

---

## Wave Execution Order

1. **Cleanup wave — run BEFORE fresh install** — NW1 ∥ NW2 ∥ NW3 ∥ NW4 in parallel worktrees off `main`
2. **Fresh VM install + end-to-end gate** — operator runs `./install.sh --no-windows-triage --no-opencti` on bare SIFT VM → satisfies PMI4 and OS6
3. **PTC enablement** — NW6 after install proves `opensearch_*` + `kb_*` tools are live
4. **FRZ1 close-out** — remaining demo-prep items after the full stack is proven on VM

---

## Open Batches

### BATCH-FRZ1 — Final freeze rehearsal, limitations, and demo runbook

**Status: IN_PROGRESS** — most of the work is done; specific items below remain open.

**Already proven live:**
- Services healthy (`sift-gateway` + `sift-job-worker` active), 13-tool catalog present
- `case_info` / `evidence_info` DB-backed aligned to `manifest_version=4`
- RAG corpus available (`app.rag_chunks=26586`)
- Bounded Volatility / E01 checks work via `run_command` with sealed `evidence_refs`
- Portal login, HMAC re-auth, fresh portal-issued agent TTL (172800 s / 48 h) live-proven
- Settings table UX: Supabase JWT token type, TTL remaining, revoke button — source-fixed and live-deployed
- `rag_search_case` replaced by `kb_*` tools; `tools/list` confirms 13 tools callable
- Installer hardening landed: `rg`, post-`uv sync` `pyewf` relink, worker unit install/restart, sudoers wiring

**Remaining open items (each requires implementation or an explicit defer decision):**

1. **Offline Volatility symbol packaging / pre-warm** — operator-requested next-session focus.
   Volatility downloads/generates ISF symbols live; a fresh VM has no cache, making `vol windows.info`
   slow or fail on first run. Options: pre-package symbols in the repo/installer, or document a
   pre-warm runbook step. Decision needed: implement or explicitly defer with caveat.

2. **Progress-stderr filtering** — `vol` and similar tools emit `\r`-separated progress spam into
   durable-job `result_public` stderr (capped at 4 KB but noisy). A filter in the worker would
   clean this for agent context. Small change; can be done before or after PMI4.

3. **Throwaway-VM destructive install idempotency proof** — `./install.sh` was not destructively
   replayed on a fresh throwaway VM (demo VM was preserved). A full destructive re-run proof is
   needed before the demo is called shipworthy. Done as part of PMI4 on the bare SIFT VM.

4. **Non-admin service-user cutover** — gateway/worker still runs as `sansforensics` (blanket
   `ALL=(ALL) NOPASSWD: ALL`). The narrow `sift-ingest-mount` sudoers rule is deployed but masked
   by the blanket grant. Actual enforcement requires a dedicated non-admin service user and removal
   of the blanket grant for that user. Explicit post-demo or demo-with-caveat decision needed.

5. **Re-acquisition click proof** — the portal Evidence-tab Re-seal/Retire actions are unit-proven
   and deployed but not click-proven live (operator password drifted from `~/.sift` during the
   relevant session). Requires a live portal walkthrough with the current operator password.

6. **Approval / report export live proof** — if the final demo script requires the full
   approval/report-export path live-proven (beyond what AUT2 already proved on 2026-06-09),
   needs a session with the current operator password.

**Scope:** `docs/product/demo-runbook.md`, `docs/product/known-limitations-and-improvements.md`,
`docs/product/README.md`, `docs/migration/task-batches.md`, `docs/migration/Session-Notes.md`

**Acceptance:** Demo runbook executable without hidden side-channel steps; known limitations
explicit and bounded; `python3 scripts/validate_docs.py` passes.

---

### BATCH-OS6 — Live VM OpenSearch proof

**Status: OPEN** — all code done (OS1–OS5 landed); this is the VM smoke gate only.
**Runs as part of PMI4 (the bare-SIFT install run).**

**What to do:**
- After install, confirm aggregate `/mcp tools/list` includes `opensearch_*` **without a restart**
  (OSX1 race fix: seed runs before gateway starts)
- Confirm `app.rag_chunks` == ~26,586 (full Chroma bundle; NOT the small seed)
- Confirm Hayabusa detections queryable
- Run one read-only OpenSearch path + one sealed-evidence ingest job on the Rocba case
- Record command-level proof in `Session-Notes.md`

**Acceptance:** Live aggregate MCP shows `opensearch_*` tools callable; search/ingest uses DB
active case and sealed evidence only; no path/DSN/credential leakage.

---

### BATCH-PMI4 — VM proof: bare-SIFT → live stack → Rocba case run

**Status: OPEN** — operator-run; the ONLY full end-to-end gate.
**Run after NW1/NW2/NW3/NW4 land so the clean install is tested.**

**Steps:**
1. Bare SIFT VM: `./install.sh --no-windows-triage --no-opencti`
2. Confirm `status:ok` (not degraded), job-worker not crash-looping
3. Confirm aggregate `/mcp` lists `opensearch_*` + `kb_*` tools after post-seed (no restart needed)
4. Confirm `app.rag_chunks` populated with full corpus (~26,586)
5. Confirm Hayabusa detections queryable
6. Portal: create case → issue agent token → register+seal Rocba disk+RAM evidence → agent end-to-end
7. Record command-level proof in `Session-Notes.md`

---

### BATCH-NW1 — compute_content_hash consolidation _(operator priority #1)_

**Status: OPEN**

**Problem:** `compute_content_hash` has TWO diverging implementations across 5 sites:
- **Authority** (`investigation_store.compute_content_hash`): 19-key wide set including
  `provenance_detail/chain/grade/gaps`; strips `_`-prefixed keys
- **Narrow copies** (`case_io.HASH_EXCLUDE_KEYS`, `reporting._HASH_EXCLUDE_KEYS`,
  `case-dashboard/routes._HASH_EXCLUDE_KEYS`): 15-key set, no `_`-strip →
  **produces a different content_hash for the same item**

**Scope:**
- `packages/sift-core/src/sift_core/{case_io.py,reporting.py,investigation_store.py,case_manager.py}`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- Their targeted tests

**Work:** Consolidate every site to import the `investigation_store` authority (do not re-declare
exclude-key sets). Add a test asserting all call sites hash an item identically.
**Note for existing deployments:** a re-hash migration pass would be needed — document it; do not
write the migration (fresh install has no pre-existing hashes).

**Tests:** sift-core + case-dashboard targeted hash tests only.

**Worktree:** `git worktree add ../sift-mcps-nw1 main`

**Paste-ready prompt:**
```text
Scope: packages/sift-core/src/sift_core/{case_io.py,reporting.py,investigation_store.py,case_manager.py},
packages/case-dashboard/src/case_dashboard/routes.py and their targeted tests. Problem:
compute_content_hash has TWO diverging shapes — authority = investigation_store.compute_content_hash
(19-key WIDE set incl provenance_detail/chain/grade/gaps AND strips k.startswith("_")); narrow copies
(case_io.HASH_EXCLUDE_KEYS, reporting._HASH_EXCLUDE_KEYS, case-dashboard/routes._HASH_EXCLUDE_KEYS,
15-key, no _-strip) produce a DIFFERENT content_hash for the same item. Do: consolidate every site to
a SINGLE shared implementation = the investigation_store authority (import it; do not re-declare
exclude-key sets). Add a test asserting all call sites hash an item identically. Behavior-touching:
a fresh DB has no pre-existing hashes, so no re-hash migration is needed for the fresh install —
but DOCUMENT that existing deployments would need a re-hash pass (note it; do not write that
migration). Tests: sift-core + case-dashboard targeted hash tests. Do not edit docs/migration.
End with a LANDING LOG: changed files, tests run, acceptance status.
```

---

### BATCH-NW2 — Remove windows-triage-mcp entirely + decouple opensearch enrich-triage

**Status: OPEN**

**Why:** `packages/windows-triage-mcp/` was never clean post-migration. Operator decision: remove
everything. Future need served by a fresh add-on via the Backend Contract (NW3 documents this).

**Coupling to sever:** `windows-triage-mcp` is coupled into `opensearch-mcp` via `triage_remote.py`
+ the `opensearch_enrich_triage` tool. Also referenced in `sift-common/instructions.py`, gateway
tests, root `pyproject.toml`, `install.sh`, `scripts/setup-addon.sh`.

**Scope:**
- Delete `packages/windows-triage-mcp/` (whole package)
- `pyproject.toml`: remove workspace member entry + `[core]`/optional list entries
- `install.sh`, `scripts/setup-addon.sh`: remove win-triage references
- `packages/sift-common/src/sift_common/instructions.py`: remove win-triage references
- `packages/sift-gateway/tests/test_windows_triage_backend.py`: delete
- `test_f1_opensearch_backend_registry.py`: remove win-triage rows
- `packages/opensearch-mcp/src/opensearch_mcp/triage_remote.py`: delete
- `opensearch_enrich_triage` tool: remove from `server.py`, `registry.py`, `sift-backend.json`
- `test_triage_remote.py`: delete
- Regenerate `tests/fixtures/mcp_surface_golden.json`
- Grep-prove each removal (no live importer remains)

**Tests:** opensearch-mcp surface (golden regen) + full gateway manifest/`test_phase6` + `bash -n install.sh setup-addon.sh`

**Worktree:** `git worktree add ../sift-mcps-nw2 main`

**Paste-ready prompt:**
```text
Scope: delete packages/windows-triage-mcp/ (whole package); remove its refs in root pyproject.toml
(workspace member + [core]/optional list), install.sh, scripts/setup-addon.sh,
packages/sift-common/src/sift_common/instructions.py, and the gateway tests
(test_windows_triage_backend.py + any win-triage rows in test_f1_opensearch_backend_registry.py);
keep a _RETIRED_CORE_BACKENDS-style guard if warranted. Decouple the opensearch coupling: remove
packages/opensearch-mcp/src/opensearch_mcp/triage_remote.py + the opensearch_enrich_triage tool
from server.py/registry.py/sift-backend.json + test_triage_remote.py, and regenerate
tests/fixtures/mcp_surface_golden.json (say so). Grep-PROVE each removal (no live importer remains).
Operator rationale: the package was never clean post-migration; a future need is served by a fresh
add-on via the Backend Contract (documented in NW3). Tests: opensearch-mcp surface (golden regen)
+ full gateway manifest/test_phase6 (backend-list change) + bash -n install.sh setup-addon.sh.
Do not edit docs/migration. End with a LANDING LOG.
```

---

### BATCH-NW3 — Add-on Backend Contract documentation _(docs-only; no code)_

**Status: OPEN**

**Why:** NW2 removes windows-triage-mcp with the rationale that future add-ons plug via the Backend
Contract. That contract must be documented now — it is the hackathon modularity story.

**Output:** One new reference doc — `docs/backend-contract.md` (NOT under `docs/migration/`).

**What to document:**
1. The `sift-backend.json` manifest schema from `sift-backend.schema.json`: `spec_version/name/
   version/tier/transport/namespace`, `capabilities.requires` (requirement gating), per-tool
   metadata including the OSX2 advanced-tool-use fields (`when_to_use/avoid_when/output_shape/
   response_shaping/usage_examples/defer_loading/recommended_phase/category`), and `authority_contract`
   (`non_authoritative/prohibited_operations`, tool `required_scopes/scope_enforcement`).
2. The lifecycle: `install.sh seed_addon_backends` + `scripts/setup-addon.sh` → DB row in
   `app.mcp_backends` (env refs only, no raw secrets) → Gateway mounts (`create_backend_instances`
   → `mount_single_addon_proxy`), requirement-gates it, enforces authority contract, and picks up
   late-seeded rows without restart (OSX1).
3. Worked example: adding a brand-new query-only add-on end to end (manifest → seed → mount →
   `tools/list`), citing `opensearch-mcp` and `forensic-rag-mcp` manifests as exemplars.

**Tests:** `python3 scripts/validate_docs.py` (still passes — `docs/migration/` untouched), `git diff --check`

**Worktree:** `git worktree add ../sift-mcps-nw3 main`

**Paste-ready prompt:**
```text
Scope: ONE new reference doc — docs/backend-contract.md (product/reference, NOT under
docs/migration/; do not trip the migration two-file validator). Document the CURRENT contract
(it changed with OSX2 — that batch added tool fields, schema updated in aaa244b):
(1) the sift-backend.json manifest schema from packages/sift-gateway/src/sift_gateway/sift-backend.schema.json
— spec_version/name/version/tier/transport/namespace, capabilities.requires (requirement gating),
per-tool metadata incl the advanced-tool-use fields (when_to_use/avoid_when/output_shape/
response_shaping/usage_examples/defer_loading/recommended_phase/category), and the authority_contract
(non_authoritative/prohibited_operations, tool required_scopes/scope_enforcement).
(2) The lifecycle: how install.sh seed_addon_backends + scripts/setup-addon.sh register a backend
row (env_refs only, no raw secrets) into app.mcp_backends, and how the Gateway mounts it
(create_backend_instances -> mount_single_addon_proxy), requirement-gates it, enforces the authority
contract, and picks up late-seeded rows without a restart (OSX1 fix).
(3) A WORKED EXAMPLE: adding a brand-new query-only add-on end to end (manifest -> seed -> mount ->
tools/list), citing the opensearch-mcp and forensic-rag-mcp manifests as exemplars.
Keep it concise and demo-ready. No code changes. Do not edit docs/migration. End with a LANDING LOG.
```

---

### BATCH-NW4 — RAG knowledge-only hardening _(drop per-case derived RAG)_

**Status: OPEN**

**Why:** Operator decision — B-MVP-RAG-DERIVED REJECTED (won't-do). No per-case RAG; case-sensitive
derived text must NEVER enter the vector store. Harden schema and code to enforce this.

**Scope:**
- NEW append-only `supabase/migrations/*.sql`: neutralize the `derived` branch of `app.rag_search`
  (knowledge-only; do NOT edit existing migrations); builds on `202606101100_rag_search_filters.sql`
- `packages/forensic-rag-mcp/src/rag_mcp/{pgvector_store.py,server.py}`: remove `include_derived`/
  case-scoped params from `search` + the kb tools; kb tools stay shared-knowledge only

**Tests:** forensic-rag-mcp targeted (knowledge-only search, no derived) + schema test for the new migration.

**Worktree:** `git worktree add ../sift-mcps-nw4 main`

**Paste-ready prompt:**
```text
Scope: a NEW append-only supabase/migrations/*.sql (neutralize the derived branch of app.rag_search
— knowledge-only; do NOT edit existing migrations; builds on 202606101100_rag_search_filters.sql),
packages/forensic-rag-mcp/src/rag_mcp/{pgvector_store.py,server.py} (remove the include_derived/
case-scoped params from search + the kb tool; the kb tools stay shared-knowledge only) + tests.
Operator decision (B-MVP-RAG-DERIVED REJECTED): no per-case RAG — case-sensitive derived text must
NEVER enter the vector store. Ensure no code path can insert/select kind='derived'; optionally keep
the columns but make the search path knowledge-only and assert it. Resolve the fork as won't-do in
Session-Notes. Tests: forensic-rag-mcp targeted (knowledge-only search; no derived) + a schema test
for the new migration. Coordinate: this builds on OSX-RAG's 202606101100_rag_search_filters.sql.
Do not edit docs/migration. End with a LANDING LOG.
```

---

### BATCH-NW6 — Programmatic Tool Calling: enable + native-harness validation

**Status: OPEN — runs AFTER PMI4/OS6 proves live `opensearch_*` + `kb_*` tools**

**Context:** PTC runs CLIENT-SIDE in the agent harness (not on the VM). The Messages-API
`code_execution` tool + `allowed_callers:["code_execution_20250825"]` on opt-in tools lets the
agent write code that calls OpenSearch tools and filters/transforms/pipes results locally so large
OS query results never flood context. Security posture already satisfied: Gateway sanitizes all
results (proven live — `case_dir: "[REDACTED:absolute_path]"`).

**OSX2's per-tool `defer_loading` / advanced metadata is the eligibility signal for PTC opt-in.**

**Target tools for PTC opt-in:** `opensearch_search`, `opensearch_aggregate`, `opensearch_timeline`,
`opensearch_count`, `opensearch_field_values`, `kb_*` (forensic-rag-mcp knowledge tools).

**Work:**
1. Decide how the SIFT agent-runtime (Messages-API/Agent-SDK harness) converts Gateway/MCP tool
   defs into Messages-API tool defs with the `code_execution` tool + `allowed_callers` on the
   heavy read-only tools
2. Confirm security: Gateway response-guard sanitizes every result (proven); client-side execution
   leaks nothing
3. VALIDATE live with native harness: write code calling two OpenSearch tools + filter/join locally,
   measure context savings vs naive tool calls
4. Deliver: enablement steps + live validation note

**Note:** On-VM Python sandbox (former OSX4) is a FALLBACK only if client-side PTC is rejected
for posture reasons.

**Worktree:** Run inline or `git worktree add ../sift-mcps-nw6 main` after install.

**Paste-ready prompt:**
```text
Goal: let the SIFT agent WRITE CODE that orchestrates OpenSearch tools and filters results
CLIENT-SIDE (in the agent harness's code sandbox), so a huge opensearch_search result never floods
context. Reference: anthropic.com/engineering/advanced-tool-use (PTC allowed_callers:
["code_execution_20250825"]) + code-execution-with-MCP. Do: (1) Decide how the SIFT agent-runtime
(the Messages-API/Agent-SDK harness) converts Gateway/MCP tool defs into Messages-API tool defs
with the code_execution tool + allowed_callers opt-in on the heavy read-only tools
(opensearch_search/aggregate/timeline/count/field_values, kb_*). Use OSX2's per-tool defer_loading/
advanced metadata as the eligibility signal. (2) Confirm the security posture is already satisfied:
Gateway response-guard sanitizes every result (proven live — [REDACTED:absolute_path]), so
client-side execution leaks nothing. (3) VALIDATE live with the native harness once the fresh
install exposes opensearch_*: write code that calls two OpenSearch tools and filters/joins locally,
measure context savings vs naive tool calls. Deliver: enablement steps + a live validation note
appended by the conductor. The on-VM Python sandbox (former OSX4) is a FALLBACK only if client-side
PTC is rejected for posture reasons. Do not edit docs/migration. End with a LANDING LOG.
```

---

## Backlog Items (require future decision or are deferred)

| ID | Item | Status | Notes |
|----|------|--------|-------|
| B-MVP-OS35-SEC | Post-MVP: evaluate enabling OpenSearch 3.5 security plugin (TLS + admin password + https client) | OPEN | MVP boundary is `DISABLE_SECURITY_PLUGIN=true` + loopback `:9200`; enabling security is post-demo |
| B-MVP-RAG-DERIVED | Per-case RAG ingest (case-derived text in vector store) | REJECTED | Operator won't-do; became NW4 (harden to knowledge-only) |
| OSX4 / on-VM Python sandbox | Dedicated `opensearch_query_code` tool with network-jailed interpreter on VM | DEFERRED | Only needed if NW6 client-side PTC is rejected for posture reasons |

---

## Resolved Decisions — Do Not Re-open

These were open forks or backlog items now settled. Listed here to prevent a fresh session
re-litigating them.

- **B-MVP-HASH-CONSOLIDATION → NW1** (now a batch; see above)
- **B-MVP-WINTRIAGE-SCRIPTS → NW2** (remove everything; see above)
- **F-MVP-OS-WIRING → RESOLVED** (OSX1: seed-before-start race fixed + double-spawn deduped; stdio add-on kept; P2/P3 not taken)
- **F-MVP-RAG-PORT → RESOLVED** (OSX-RAG: `kb_*` tools on pgvector at full parity; `rag_search_case` removed)
- **F-MVP-RAG-DERIVED → RESOLVED → REJECTED** (became NW4: knowledge-only hardening)
- **F-MVP-OS35-SEC → RESOLVED** (`DISABLE_SECURITY_PLUGIN=true` + loopback; security plugin evaluation = B-MVP-OS35-SEC backlog post-demo)
- **NW5 → RESOLVED** (opensearch-mcp has NO run_command/execute/shell tool; no duplicate to remove)
- **OSX3 → reframed as NW6** (PTC is client-side in agent harness, NOT on-VM; Gateway already sanitizes output — the "evidence leaves the VM" objection is moot)

---

## VM Quick Reference

- **VM:** `sansforensics@192.168.122.81` / password: `forensics`
- **Active service tree:** `/home/sansforensics/sift-mcps-test`
- **Operator portal:** `https://192.168.122.81:4508/portal/` — `examiner@operators.sift.local`
- **Host repo:** `/home/yk/AI/SIFTHACK/sift-mcps`
- **Sync:** `rsync -av --exclude='.git' --exclude='node_modules' --exclude='.venv' /home/yk/AI/SIFTHACK/sift-mcps/ sansforensics@192.168.122.81:/home/sansforensics/sift-mcps-test/`
- **Restart + health:** `systemctl --user restart sift-gateway.service sift-job-worker.service && curl -sk https://localhost:4443/health | python3 -m json.tool`
