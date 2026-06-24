# Audit-Provenance Hardening Wave — Requirements & Design Spec

**Status:** APPROVED — decisions LOCKED 2026-06-24 (W3 = cap-hint; L-1b = implement now; L-2a = defer). Implementation cleared (W1 → W2 → W3, gated loops).
**Branch:** `portal-v3/p0-foundation` · **HEAD at spec time:** `62cb650` (Unit 1 Gap A + Unit 2 Gap B complete + live-proven; NOT pushed; `main` clean at `b995491`).
**Authority basis:** `trackers/AUDIT_STATE_VERIFICATION.md` §9 (systemic contract), §10/§10b (Unit 1/2 status); `trackers/PORTAL_V3_EXTENSION_BACKLOG.md` B7 (UI render req); `security_report/sec_review_portal-v3-p0-foundation_2026-06-24_19-44-25.md` (open items I-2/L-1/L-2).
**Discovery basis:** 3 parallel read-only investigators (2026-06-24), findings folded in below with file:line anchors.

This wave hardens an **already-working, already-centralized** pipeline. It is assurance + render-completeness + a contract change for confidence — NOT a re-architecture.

---

## 0. Current state (discovery-verified, file:line)

The gateway is the single provenance authority and there is one resolver:

- **Mint authority:** `AuditEnvelopeMiddleware.on_call_tool` (`packages/sift-gateway/src/sift_gateway/policy_middleware.py:911`) mints `envelope_event_id` (uuid PK, `:927`) + `request_id` pre-dispatch for every call; canonical selection (§9.3) holds verbatim at `:1019-1024` (`is_core` → `native_ids[0] else envelope_event_id`; proxied → `envelope_event_id`).
- **Single resolver:** `InvestigationService.audit_events` (`packages/case-dashboard/src/case_dashboard/portal_services.py:1619`), 6 superset OR-clauses (`:1686-1691`), each ANDed with `case_id` (`:1685`).
- **Write-side classifier:** `record_finding` → `_classify_provenance` (`packages/sift-core/src/sift_core/case_manager.py:2175`), fail-closed DB verification `_db_audit_id_known` (`:901-924`) / `_db_audit_event_has_audit_id` (`:197-229`).

**Naming correction:** the core run_command scheme is minted as **`siftcore-*`** (`agent_tools.py:1308` `AuditWriter(mcp_name="sift-core")` → prefix transform in `sift-common/.../audit.py:176`), not `siftgateway-*`. The literal `siftgateway-*` survives only as the never-authoritative JSONL mirror (`sift-gateway/.../server.py:218`) and stale test/doc strings. Functionally identical scheme `{prefix}-{examiner}-{YYYYMMDD}-{NNN}`.

### Scheme → mint/record/resolve/render matrix (verified)

| Scheme | Minted | Recorded (event_type / id-bearing details key) | Resolved (predicate) | Rendered |
|---|---|---|---|---|
| core `siftcore-*` | `agent_tools.py:689,1308` | gateway envelope, `mcp.tool.result`, `backend_audit_id`+`audit_aliases`+`envelope_event_id` | `backend_audit_id` / `audit_aliases` / `envelope_event_id` (`portal_services.py:1686-1689`) | **RICH** |
| gateway uuid (`envelope_event_id`) | `policy_middleware.py:927` | PK of `mcp.tool.call` + `details.envelope_event_id` on result | `id::text` / `envelope_event_id` (`:1686,1689`) | **RICH** |
| opensearch native `opensearch-*` | add-on AuditWriter | alias only (proxied → canonical=envelope uuid; native kept in `audit_aliases`) | `audit_aliases ?\|` (`:1688`) | **RICH** |
| wintriage `windowstriage-*` | `windows_triage_mcp/server.py:203,248` | alias (recovered from `meta`, `audit_helpers.py:339-345`) | `audit_aliases ?\|` (`:1688`) | **RICH** |
| ingest `opensearchingest<PID>-sift-service-*` (B-D2) | `opensearch_mcp/ingest_cli.py:997` | own forward-write `_persist_ingest_audit_event` (`ingest.py:36-114`), `opensearch.ingest.artifact`, `backend_audit_id`, `case_id`=`SIFT_CASE_UUID` | `backend_audit_id` (`:1687`) | **BROKEN** (see W2 — 500s the panel) |
| shell `shell-<exam>-YYYYMMDD-NNN` (B-D3) | `case_manager.py:1137` | own forward-write `_persist_shell_audit_event` (`:94-146`), `finding.supporting_command`/`shell_self_report`, `backend_audit_id` | `backend_audit_id` (`:1687`) | **THIN/DEAD** (see W2) |
| durable lane `run_command_job` | `execute/run_command_job.py:41` | gateway envelope; §9.7 fix tags `sift-core` (`policy_middleware.py:1205-1220`) — "unknown" bucket closed | `backend_audit_id`/`audit_aliases`/`envelope_event_id` | **RICH** |
| forensic-rag `kb_*` | rag AuditWriter (varies) | envelope backstop → canonical=envelope uuid (test `test_audit_provenance_contract.py:398-414`) | `id::text`/`envelope_event_id`/`backend_audit_id` | **RICH** |

**Centralization verdict: CENTRALIZED.** No writer row is unmatched by a resolver predicate; canonical selection holds. Two minor non-blocking gaps (G1 = test coverage, the real W1 work; G2 = a dead-ish predicate). The render gaps (ingest/shell) are W2, not centralization defects.

---

## W1 — Centralization assurance + security follow-ups

### W1.1 Conformance test (the §9.9 "never breaks" guarantee) — the core W1 deliverable

**Gap (G1):** `TestConformancePerCategory::test_response_has_audit_id_and_row_has_backend_audit_id` (`packages/sift-gateway/tests/test_audit_provenance_contract.py:540-612`) exists but (a) parametrizes over a **hand-picked 5-tool sample** (`:545-578`), not every registered tool, and (b) **omits invariant (c)** — it never calls `InvestigationService.audit_events()`, so the resolver round-trip from the canonical id the envelope actually produced is untested in the same test. The docstring (`:11`) claims (c) but it lives separately + mocked (`test_k6_audit_events_reader.py:210-257`).

**Target behavior:** a parametrized conformance test that, for **every registered tool** (core plane via `agent_tools.core_tool_names()` at `agent_tools.py:386-387`; proxied plane via the gateway's registered add-on tool names / `tools/list` map), drives the tool through the envelope (fake backends OK, as the existing harness does) and asserts all three invariants:
1. response carries a top-level `audit_id`;
2. a `mcp.tool.result` row exists with non-empty `details.backend_audit_id`;
3. `InvestigationService.audit_events(case, [canonical] + aliases)` **returns that row** — closing (c), driven from the id the envelope produced (seed the resolver fake from the `_FakeDbAudit` recorder at `test_audit_provenance_contract.py:74-83`).

This test **fails the day a future backend breaks the invariant** — the systemic safety net §9.9 promised. Pair with the existing unified-extractor unit test across content/structured_content/meta shapes (already present — verify coverage).

**G2 (housekeeping, low):** `details->>'audit_id' = any(%s)` (`portal_services.py:1691`) has no producer in `app.audit_events` (every writer uses `backend_audit_id`/`envelope_event_id`/`audit_aliases`). **Decision: keep + add a one-line code comment marking it intentional defense-in-depth / `case_manager.py:97` parity** (do NOT drop — harmless, and removing it narrows a future-proofing seam). No functional change.

### W1.2 Security follow-ups

**Confirmed IN SCOPE to land (no decision needed — operator pre-scoped):**

- **I-2 — tighten sk/pk over-redaction.** `case_manager.py:57-60` bare-PAT rule includes short Stripe prefixes `sk`/`pk` with a `[-_]` separator + ≥10 chars, so a benign `sk-something-1234567890` over-redacts (reduces audit detail; never leaks). **Fix:** replace the `sk`/`pk` alternatives with the full Stripe forms `sk_live_` / `sk_test_` / `pk_live_` / `pk_test_` (and `rk_live_`/`rk_test_` if desired). Add a regression test asserting `sk-foo-1234567890` (benign) is **not** redacted while `sk_live_<24>` **is**. Cosmetic/availability only.
- **L-1a — document the DSN process-env footprint.** B-D1 injects `SIFT_CONTROL_PLANE_DSN` into the worker + ingest subprocess env (`policy_middleware.py:1305-1319`; `ingest_job.py:112-143`, save/finally-restore verified correct + symmetric). **Action:** add an "Audit-write DSN footprint" note to the worker/deploy runbook documenting the `/proc/<pid>/environ` footprint, the single-tenant-appliance trust model, and that `spec_internal` is excluded from the agent-facing job view (`jobs.py:_PUBLIC_STATUS_FIELDS`). Doc-only.

**OPEN — operator decisions (see §SEC-DEC):**

- **L-1b — least-privilege DB role for the forward-write path.** The injected DSN is the full control-plane DSN. A scoped role is *not* INSERT-only: `case_manager.py` runs **SELECTs** on `app.audit_events` for grounding (`:221`, `:226`, `:2078`, `:2086`) and the forward-writers INSERT (`case_manager.py:130-145`; `ingest.py:98-114`). So a least-privilege role needs **INSERT + SELECT on `app.audit_events`** (plus whatever the ingest/grounding reads touch). Larger blast radius (new role, migration, secret plumbing, deploy). **Decision: implement now / defer as tracked follow-up.**
- **L-2a — high-entropy redaction backstop.** `_redact_supporting_command` (`case_manager.py:74-91`) is a deny-known-shapes filter; a prefix-less, keyword-less, delimiter-less high-entropy secret could pass into `app.audit_events.details`. Compensating controls: defense-in-depth (the same string is already in local JSONL unredacted) + single-tenant examiner DB + agent-narrated source. **Decision: add an entropy backstop now / defer.**

### W1 acceptance criteria
- Conformance test enumerates **all** registered tools (core + add-on), asserts (a)+(b)+(c); **fails** if a tool is added without a resolvable canonical id (prove by a deliberate temporary break in a scratch run).
- I-2 regression test green; L-1a runbook note committed.
- (If approved) L-1b role live-proven: ingest + shell forward-writes succeed under the scoped role; grounding SELECTs succeed; the role **cannot** write outside `app.audit_events`.
- (If approved) L-2a backstop redacts a synthetic 40-char high-entropy positional token; existing forensic commands (`EvtxECmd … --csv`, `grep`, `fls`, `vol`) NOT over-redacted (regression test).
- **Live-prove:** run the conformance test on the VM venv; confirm a redaction probe via a recorded finding + read-only SQL.

---

## W2 — Every cited audit_id renders useful detail (backlog B7)

**Bar:** what a `gateway_mcp_envelope` `run_command` shows today (Tool / Params / Result · Exit — F-006). Zero "No tool-call provenance recorded for this audit id." for any id that resolves to a row.

### W2.1 Root cause (traced, with a bug discovery upgraded the severity)

`get_audit_for_finding` (`packages/case-dashboard/src/case_dashboard/routes.py:2537-2641`; DB path `:2552-2605`) applies ONE gateway-envelope-shaped projection to every row — it never keys off `event_type`/`source`:
- `details.tool → tool` (`:2580-2581`); `arguments → params` else `details.detail → params` (`:2588-2592`); `dict(details.result_summary or {}) → result` (`:2597`).
- It **never reads** `details.command`/`details.purpose` (shell tier) nor projects the ingest structured fields.

**Upgraded finding — this is a live bug, not just thinness:** for an `opensearch.ingest.artifact` row, `details.result_summary` is a **STRING** (`ingest.py:85,95`, `str(result_summary or "")`). `dict("<string>")` raises **`ValueError`** (verified), and the projection block has **no try/except**, so the exception propagates out of the whole route handler → the **entire `/audit` response 500s** for any finding citing an ingest row (e.g. F-009). The frontend `AuditTrailPanel.jsx:115` `.catch(()=>{})` swallows it → `data=[]` → **every** entry renders the dead-end. So F-009 doesn't render "thin" — it poisons the whole panel.

**Frontend (already capable, just not fed):** `AuditTrailPanel.jsx` (`packages/case-dashboard/frontend/src/components/findings/AuditTrailPanel.jsx`, 157 lines) groups by `e.audit_id` (`:126-127`), decides `isShell` from `_backend/mcp/source` containing `exec`/`shell` (`:47`) → renders a **Command** block from `entry.params?.command` (`:66-71`); else Tool+Params (`:72-84`); both render **Result** via `ResultSummary` which already handles string OR dict (`:17`). The dead-end string is gated by `hasProvenance = Boolean(params?.command || tool || params || result_summary)` (`:51,92`). For shell rows `isShell` is already true but `params.command` is undefined (backend never projects it) → `hasProvenance=false` → dead-end.

### W2.2 Systematic fix — one shaping layer keyed off `event_type`/`source` (backend-first, additive)

| event_type / source | id scheme | DB `details` available | Current render | Target shaping (routes.py) | Target render |
|---|---|---|---|---|---|
| `mcp.tool.result` / `gateway_mcp_envelope` | `siftcore-*`/uuid | tool, arguments(paired), result_summary(**dict**), detail | **RICH** | **unchanged** | RICH (no regression) |
| `finding.supporting_command` / `shell_self_report` | `shell-*` | command, purpose (redacted) | DEAD | `params = {command, purpose}` from `details.command/purpose` | Command + **Purpose** |
| `opensearch.ingest.artifact` / `opensearch-ingest` | `opensearchingest*` | tool, run_id, mcp_name, hostname, index_name, result_summary(**STRING**) | **500s panel** | (1) string-safe `result_summary` (`dict(...)` only when `isinstance(rs, dict)`, else pass string through); (2) project `run_id/hostname/index_name/mcp_name` into `params` | Tool + context + Result |

**Implementation shape:** inside the existing per-row loop, after `det = ev.get("details")`, branch on `event_type`/`source` to populate the entry fields the panel **already reads** (`tool`, `params`, `result_summary`). The two non-gateway branches set those fields; the gateway path is untouched and its `setdefault`-style guards (`ev.get(...) is None`) protect existing values. Fix the `result_summary` `dict()` call to be string-safe **first** (it is also the panel-poisoning bug fix).

**Frontend change (one small, optional-but-recommended):** add a **"Purpose"** line in the `isShell` branch (after `:70`) rendering `entry.params?.purpose` as an escaped text node with the existing `font-semibold text-muted-foreground` micro-label pattern. Justified because the shell tier carries an analyst-written `purpose` with no gateway equivalent that would otherwise be dropped. Governed by the frontend contract (note: it is `packages/case-dashboard/frontend/CLAUDE.md`, not `AGENTS.md`, in this worktree): no raw hex (use tokens), no template-literal Tailwind class names, 400-line cap (panel is 157), **no `dangerouslySetInnerHTML`** (Purpose must be an escaped text node), `mono` for ids/code. Everything else is backend-shaping-only.

### W2.3 Back-compat + acceptance
- **No regression to the gateway tier:** gateway rows have `source="gateway_mcp_envelope"` → skip the new branches; F-006/007/008 must still render Tool/Params/Result. Regression-test against those three.
- **Acceptance:** open F-006 (gateway), F-009 (ingest), F-010 (shell) → every cited id expands to non-empty useful detail; **zero** "No tool-call provenance recorded" for resolving ids; the `/audit` endpoint returns 200 (not 500) for F-009.
- **Test plan — RENDER-side mandatory** (the lesson from the last wave): unit-test the shaping for each event_type (assert projected fields); and a **live render check** — open the panel in Chrome and screenshot the expanded audit id for F-006/F-009/F-010 AND assert `GET /portal/api/audit/<finding>` returns 200 with the projected fields present (`params.command`/`purpose` for shell; `tool`+context+`result_summary` for ingest). "Resolves" ≠ "renders" — we assert rendered detail, not just a resolving row.

---

## W3 — Confidence auto-derived from cited audit ids (contract change)

**Today:** `confidence` is agent-SUPPLIED + REQUIRED (enum `HIGH/MEDIUM/LOW/SPECULATIVE`, validated `finding_validation.py:32,51-56`; enum from `confidence.yaml` + `agent_tools.py:235`). Stored in free-form JSONB `payload` (NO DB enum/CHECK — only `jsonb_typeof='object'`, `report_metadata.sql:28`). `grounding` (transient, post-stage, NOT persisted — `agent_tools.py:1229`) and `provenance_grade` (FULL/PARTIAL, rolled up `case_manager.py:1531-1538`) ARE backend-computed. **The exploit today:** an agent can self-assert `HIGH` while citing ids that classify `NONE` — the FK floor (`confidence.yaml` HIGH≥2 audit_ids) is only a *warning* (`finding_validation.py:76-82`), not enforced.

### W3.1 Signals already available at `record_finding` time (no new computation)
From `_classify_provenance` output (`case_manager.py:1623`) + per-artifact `provenance_grade` roll-up (`:1531-1538`) + counts:
- `provenance["summary"]` ∈ {NONE, MCP, HOOK, MIXED}; per-plane lists `mcp[]`, `hook[]`, `none[]`.
- `finding_prov_grade` ∈ {FULL, PARTIAL} (NONE is hard-rejected upstream `:1626-1637`).
- count of cited `audit_ids`; count of DB-resolved ids (fail-closed, case-scoped).
- `source_evidence` present (traced to registered evidence); `provenance_chain` depth; `validated_commands` count; auto-linked `timeline_event_id`.

**Would need NEW wiring (only if used):** `grounding` level (move/duplicate `_score_grounding` into `record_finding` before the record is built); a numeric `confidence_score` (does not exist anywhere — and P35-11 says don't fabricate one).

### W3.2 Proposed mapping (categorical, reuses FK thresholds, re-based on *resolved* ids)

| Derived ceiling | Condition (existing signals) |
|---|---|
| **HIGH** | `finding_prov_grade == FULL` AND `len(provenance["mcp"]) >= 2` AND `len(provenance["none"]) == 0` |
| **MEDIUM** | (`FULL` AND ≥1 resolved MCP id) OR (≥2 resolved MCP/HOOK ids AND `source_evidence`) |
| **LOW** | ≥1 resolved (MCP/HOOK/DB-verified) id but below MEDIUM; OR shell-only with `validated_commands` |
| **SPECULATIVE / floor** | only `none`/unverified ids; analytical-reasoning supporting_commands only |

This re-bases the FK's own HIGH≥2 / MEDIUM≥1 thresholds onto ids that actually **resolve** (pass the §2 plane gate + evidence trace), closing the self-asserted-HIGH-on-NONE gap.

### W3.3 The decision the operator must make (see §W3-DEC)
- **(A) Cap-hint [recommended]:** keep the agent's value but **clamp down** to the derived ceiling — `final = min(agent_confidence, derived_ceiling)` (rank order `ioc_helpers.py:19`). Agent may be *more* humble (LOW on strong evidence = allowed) but cannot *over-claim*. Preserves analytical caution; closes the exploit; aligns with P35-11. Store a `confidence_derivation` field + emit the downgrade reason via the existing warnings channel (`case_manager.py:1786-1787`).
- **(B) Full override:** ignore the agent's value entirely; confidence = derived ceiling. Cleanest "measured property" but discards genuine interpretive humility and risks **inflating** HIGH purely from resolved-id count even when alternative hypotheses are strong.
- **(C) Defer / keep as-is** (status quo: agent-asserted, floor stays a warning).

**Forensic tension (flagged):** confidence conventionally blends evidence strength (mechanizable) with interpretive ambiguity + alternative-hypothesis weight (NOT mechanizable from audit ids). A categorical **cap** can only *lower* confidence — defensible. A full **override** can manufacture certainty — the inverse error. The frontend already refuses numeric precision (P35-11). **Operator must approve the model before W3 is coded.**

### W3.4 Back-compat (hard constraint discovery caught)
- `confidence` is **inside the hashed payload** (NOT in `HASH_EXCLUDE_KEYS`, `investigation_store.py:161-184`). Re-deriving it for *existing* findings would mutate `content_hash` → break `content_hash_at_review` + the append-only approval ledger. **→ Auto-derivation applies to NEWLY recorded findings only.** No in-place backfill. No DB migration required (payload is free-form JSONB).
- **IOC propagation:** derived confidence flows into auto-extracted IOC confidence via `_process_iocs` / `_conf_rank` (`case_manager.py:2361,2408-2425`; `ioc_helpers.py:18-23`). Expected + acceptable; note in tests.
- **Human override:** `confidence` stays in `_DELTA_EDITABLE_FIELDS` (`routes.py:179`) so an examiner can still override at review (re-auth-ledger-linked). Decide whether the examiner edit re-clamps or is exempt (recommend: examiner edit is authoritative, exempt — a human reviewer outranks the formula).
- **SPECULATIVE tier:** the v3 UI already folds SPECULATIVE into Low display (`findings-utils.js:25-27`). Keep SPECULATIVE as the formula's floor value (display-safe) unless the operator wants it dropped.

### W3.5 Acceptance criteria
- New finding citing ≥2 resolved MCP ids + FULL grade → derived ceiling HIGH; agent HIGH passes; agent LOW stays LOW (cap-hint).
- New finding citing only `none` ids (that survive to confidence assignment) → floor LOW/SPECULATIVE; agent HIGH is **clamped** (cap-hint) — with a recorded `confidence_derivation` reason.
- Existing findings' `content_hash` unchanged (assert no re-hash on read).
- **Live-prove:** record a NEW test-probe finding citing a known set of audit ids; confirm the persisted confidence matches the approved formula; verify the row + `confidence_derivation` via read-only SQL; confirm the UI chip renders the derived value.

---

## Operator decisions — LOCKED 2026-06-24

- **§W3-DEC = (A) CAP-HINT.** `final = min(agent_confidence, derived_ceiling)` by `_conf_rank` ordering. Confidence may only be *lowered* by provenance, never inflated. Persist a `confidence_derivation` field (the reason + the derived ceiling) and emit any downgrade via the existing warnings channel. New-findings-only (hash constraint). Examiner edit at review stays authoritative (exempt from the clamp).
- **§SEC-DEC-1 = IMPLEMENT NOW (L-1b).** Create a least-privilege DB role granted **INSERT + SELECT on `app.audit_events`** (+ USAGE on schema `app`, + whatever the injected-DSN forward-write path actually touches — see implementation note). Inject **that role's DSN** through the B-D1 path instead of the full control-plane DSN. Live-prove forward-writes + grounding reads succeed under it and out-of-scope writes are denied.
  - **Implementation note (scope precisely):** the B-D1 DSN is injected into the **ingest subprocess** (`opensearch worker → ingest_cli`); the shell forward-write (B-D3) runs **in the gateway/core process** on its existing DSN. The W1 coder MUST first inventory the exact DB operations the *injected* DSN performs (ingest `app.audit_events` INSERT [B-D2]; the BATCH-F1 `opensearch_ingest_provenance`/`opensearch_indices` writers it un-broke; any reads) and grant the role exactly those — NOT a blanket INSERT+SELECT if narrower is correct. If the cleanest scoping diverges from "INSERT+SELECT on `app.audit_events`" (e.g. the ingest subprocess does not itself SELECT `app.audit_events` — the grounding SELECTs are in the gateway process on the full DSN), surface the divergence to the operator before finalizing grants. Keep fail-soft: a permissions error degrades to a skipped row, never wedges ingest.
- **§SEC-DEC-2 = DEFER (L-2a).** Do NOT add the entropy backstop this wave. Rationale: SHA-256/40-hex/64-hex hashes, hex blobs, and base64 artifacts are ubiquitous high-entropy ≥32-char strings in DFIR command lines — a naive backstop would over-redact legitimate evidence. Track as a follow-up requiring forensic-safe exemptions (canonical hash-length allowlist) + a regression corpus. The shape-based redaction + bound + JSONL-ledger compensating control stays.

(I-2 sk/pk tightening + L-1a DSN-footprint doc are confirmed in-scope, no decision needed. G2 = keep the `details->>'audit_id'` predicate + add an intentional-defense-in-depth comment.)

---

## Phasing & gates (per orchestrator brief)

Discovery (done) → **operator approves this spec** → W1 → W2 → W3 (W1 assurance+security first so the base is trusted; W2 render; W3 the contract change last). Each workstream runs the gated loop: coder (sole writer in worktree, codeguard-loaded, commit-in-worktree, NO push/deploy) → verifier-griller (read-only, reproduces tests with the PYTHONPATH gotcha, greps regressions, **verifies render/behavior** for W2/W3 not just resolution) → security-expert (one pass: PASS / PASS-WITH-FIXES / FAIL) → **orchestrator deploys + live-proves on the VM**. Agents deliver verdicts via `SendMessage(to:"main")`. Phase 4: consolidated security-review of the full unpushed delta + full-regression live test (F-006/007/008 still rich; F-009/010 now render detail; a NEW finding proves auto-confidence) → hand back for the push decision. **Do NOT push.**

### Lessons applied (from the last wave)
- **"Resolves" ≠ "renders":** W2/W3 live-prove MUST open the actual panel (Chrome screenshots) AND assert the `/portal/api/audit/<finding>` JSON carries the projected fields — not just that an id classifies MCP in the DB.
- **Don't break the rich tier:** every routes.py shaping change is additive + regression-tested against F-006/007/008.
- **rsync zsh exclude bug:** use INLINE quoted `--exclude=` args (zsh does not word-split an unquoted var → excludes silently collapse to one arg → would clobber the VM venv). Always `--dry-run` first; confirm 0 `.venv`/`node_modules` transfers + 0 deletions before the real run.
- **Worktree test PYTHONPATH:** root `.venv` editable-installs from the MAIN checkout. Run worktree tests with per-package PYTHONPATH prepended (sift-core: `packages/sift-core/src:packages/sift-common/src:packages/forensic-knowledge/src`; gateway: `packages/sift-gateway/src:packages/sift-core/src:packages/sift-common/src`; opensearch: add its `src`+`tests`). Prove worktree source via `inspect.getfile` before trusting green.
- **New id scheme ⇒ end-to-end acceptance test** (Unit 2 lesson): not just that the row is written, but that the scheme is accepted by `_AUDIT_ID_PATTERN`/`_classify_provenance` end-to-end.

---

## L-1a — Audit-write DSN process-env footprint

> Documented here (not in a worker/deploy runbook) because the SIFT portal-v3 deploy + opensearch-worker runbooks live in the **external ops hub** (`~/AI/SIFTHACK/sift-portal-ops/`), which is not part of this repo and cannot be committed on the `portal-v3/p0-foundation` branch. This is the repo-tracked home for the footprint note; mirror it into the ops-hub deploy runbook at deploy time.

**What is injected, and where.** To let the per-artifact ingest provenance forward-writes (Gap B / B-D1) reach `app.audit_events`, the gateway carries a Postgres write DSN into the opensearch-worker job and then into the ingest subprocess env:

- **Gateway → worker job:** `OpensearchJobDispatchMiddleware._enqueue` (`packages/sift-gateway/src/sift_gateway/policy_middleware.py:1305-1319`) reads the gateway's own `SIFT_CONTROL_PLANE_DSN` (or, with L-1b, `SIFT_AUDIT_WRITER_DSN` when set) and places it into the job's **`spec_internal`** (`spec_internal["control_plane_dsn"]`). It is injected **only when non-empty** and is **never logged**.
- **Worker job → ingest subprocess env:** `ingest_job` (`packages/opensearch-mcp/src/opensearch_mcp/ingest_job.py:112-143`) reads `spec_internal["control_plane_dsn"]` (anti-spoofed — sourced from `spec_internal` / `job.case_id`, never client-supplied) and binds it to `os.environ["SIFT_CONTROL_PLANE_DSN"]` for the duration of the launch, alongside `SIFT_CASE_DIR` / `SIFT_CASE_UUID`. The ingest forward-writers (`ingest.py:_persist_ingest_audit_event`, and the BATCH-F1 `register_opensearch_index` / `record_opensearch_ingest_provenance` writers) read the DSN from that env.

**Process-env exposure.** While a job runs, the DSN is present in the worker/ingest-subprocess environment and is therefore readable at **`/proc/<pid>/environ`** by the **same UID** (the process owner) and by **root**. It is **not** exposed to any other UID (Linux restricts `/proc/<pid>/environ` to the process owner + privileged readers) and is **not** written to the job record's agent-facing view.

**Trust model.** SIFT is a **single-tenant forensic appliance**: the gateway, the opensearch worker, and the ingest subprocesses all run under the **same trust domain** (the examiner appliance), and the gateway process **already holds** the control-plane DSN in its own environment. Injecting it into a same-domain child subprocess does not cross a trust boundary that wasn't already crossed by the gateway holding it. There is no multi-tenant separation to violate here. (L-1b narrows this further by injecting a **least-privilege** writer-role DSN instead of the full control-plane DSN, shrinking the blast radius of a `/proc` read to INSERT-on-`app.audit_events`-and-the-ingest-provenance-tables.)

**Agent-facing exclusion (verified).** `spec_internal` — and therefore the injected DSN — is **excluded from the agent-facing job view**. `jobs.py` returns only the agent-safe allow-list `_PUBLIC_STATUS_FIELDS` (`packages/sift-gateway/src/sift_gateway/jobs.py:53`), which **never** includes `spec_internal`, `worker_id`, or lease columns. An agent polling `running_commands_status(job_id)` cannot read the DSN.

**No long-lived persistence between jobs (verified).** `ingest_job` uses a **save / set / `finally`-restore** discipline for `SIFT_CONTROL_PLANE_DSN` (and `SIFT_CASE_UUID` / `SIFT_CASE_DIR`): it captures the previous value, sets the job's value, and in a `finally` block restores the previous value (popping it when there was none). The restore is **exception-safe** (it runs even if the launch raises), so the DSN does **not** linger in the long-lived worker process environment **between** jobs — it is present only for the window of a single ingest launch.
