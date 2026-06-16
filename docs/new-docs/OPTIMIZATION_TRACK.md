# Optimization Track — Plan Outlines (DRAFT)

**Status**: DRAFT plan outlines for Q&A expansion. Outlines + reference packs + proposed
approaches only — not yet scoped into executable build units.
**Basis**: validated findings in `CODEBASE_ASSESSMENT.md` (2026-06-16 pass) + the DFIR
data-plane authority map (grounded in `supabase/migrations/**`, see §B).
**Mode (locked by operator)**: each axis gets a plan outline carrying its own *reference
pack* ("boosters") so a coding session starts with the file:line anchors and migration
tables it needs and does NOT have to re-scan the whole codebase (which bloats context and
invites hallucination). Each axis also proposes a root-cause solution or at least a
candidate approach.

---

## 0. Decision summary (fill as we lock each axis)

| Field | Value |
|-------|-------|
| Chosen axis/axes | **B locked** (B-1…B-4 decided, below); A/C/D/F outlined; E deferred |
| Recommended sequence | A → B → C, D opportunistic, **F after a discovery pass**, E deferred |
| Out of scope | _TBD_ |
| Track definition of done | _TBD_ |

**Locked operator answers (2026-06-16):**
- **A1 (infra)**: Private GitHub repo, **no hosting** — only the SIFT VM on this host for
  live testing. ⇒ CI runs **lint + type + unit/integration** on GitHub Actions; **live-VM
  proof stays a separate manual gate** (Actions cannot reach the VM/Supabase).
- **B1 (north star)**: Move DFIR-process data off file authority. **DB-backed authority
  required** for active cases, keys, evidence hashes/ledgers, chain of custody, findings,
  reports. **File is acceptable only for low-risk data (logs) or where absolutely required
  with explicit mitigating controls.** Anything file-based or file-synced in the DFIR data
  plane is not accepted unless justified + mitigated.
- **Mode**: plan outlines with reference packs + proposed approaches (above).

**Axis-independent ground rules (proposed, confirm):**
- Grounded only in source/tests/configs/migrations/installer — not tracker notes.
- No silent behavioral change; security-touching diffs get `/security-review`.
- Each axis lands as its own unit with a scope fence; reference pack travels with the unit.

---

## Axis A — Process / safety-net hardening

**One-liner**: CI (lint+type+unit on GitHub Actions) + static typing to convert latent
runtime/security slips into PR-time failures. Live-VM proof stays a separate manual gate.

### Root cause
Nothing runs the 2,581 tests or the configured ruff on change (`.github/workflows` absent),
and there is no repo-wide type checker — so `gateway: Any` (×14 in `policy_middleware.py`)
on the policy layer means a wrong attribute is a *runtime*, often security-relevant,
discovery rather than a compile-time error.

### Proposed approach
1. **CI workflow** (`.github/workflows/ci.yml`): matrix on `requires-python >=3.10`;
   `uv sync` with the right extras; `ruff check`; `pytest`; coverage artifact. Because the
   repo has no hosting, CI is **unit/integration only** — no VM, no live Supabase; gate the
   psycopg/optional-dep tests with `importorskip` (already the pattern; confirm) so a lean
   runner passes.
2. **Coverage gate**: start with a **global `--cov-fail-under`** set just under current, then
   ratchet; or per-package floors so the bare add-ons (opencti 0.03, wintriage 0.05) don't
   drag a global number. (Open question A2.)
3. **Static typing**: add `pyright` (fast, no runtime import) in CI; introduce a
   `GatewayProtocol` (typed interface for the ~22 attributes `Gateway` exposes) and replace
   `gateway: Any` in `policy_middleware.py` with it — turning the service-locator into a
   checked contract. Roll out gateway-first, then widen.
4. **Test hygiene / anti-rot** (operator-raised 2026-06-16): the suite accretes tests and some
   now assert *retired* behavior. Grounded rot today: `ingest_job` ×3, `file.*HMAC` ×10,
   `reconcile_verification`/`_RETIRED` ×2, file `check_evidence_gate` branch ×11, `file_mode`
   ×2, CASE.yaml ×29, ticket-code-named tests ×6. **Discipline (not a blanket prune):**
   - **Classify, don't keyword-delete.** A test that *asserts a path is retired / DB is
     authority* is a **keeper**; only a test that *exercises a removed path as if live* is rot.
     Risk of over-pruning in a forensic product is real — coverage is a feature.
   - **Type 1 — orphaned tests** (import/exercise deleted code): CI surfaces these immediately
     as collection errors; delete with the code.
   - **Type 2 — deprecated-behavior tests** (pass against shim/compat code): remove **in the
     same commit that removes the behavior** — Axis B already does this for file-mode/CASE.yaml
     (BU1/BU3/BU5). Make "delete tests with the code path" a standing rule.
   - **Type 3 — redundant / ticket-code-named tests**: lower priority; rename/consolidate
     opportunistically (ties to Axis D's ticket-code cleanup).
   - **One-time audit** of already-retired subsystems (HMAC ledger, `ingest_job`,
     `_RETIRED_CORE_BACKENDS`, `deprecated_aliases`) to delete true orphans now.
5. **Docs-freshness mechanism** (operator-raised 2026-06-16) — keep `docs/new-docs/` live so
   nobody re-maps the codebase from scratch as it grows. Policy in `DOCS_MAINTENANCE.md`;
   summary: (a) classify each doc — *point-in-time* (assessment; frozen + dated addenda),
   *live-reference* (overview/data-flow/key-functions/etc.; must track code), *living-plan*
   (track/build plans); (b) each doc carries a `Covers:` + `Last validated:` header; (c) the
   **efficient cadence is per logical unit / change-group at the commit-PR gate** (not per
   keystroke): a unit updates the live-ref sections whose `Covers:` intersects its scope fence,
   in the same commit; (d) a **staleness checker** (`scripts/check_newdocs_refs.py`) in CI
   verifies cited `file:line`/symbol refs still resolve and warns when code under a doc's
   `Covers:` changed without the doc's `Last validated` advancing — so CI points you at the
   stale section instead of you re-reading everything.

### Reference pack (boosters)
- Ruff config + extras: `pyproject.toml` (`[tool.ruff]` line-length 88, `E501` ignored;
  `[project.optional-dependencies]` core/standard/full/opencti/windows-triage; `dev` extra
  has ruff>=0.15, pytest>=9).
- Only existing type config: `packages/opencti-mcp/pyproject.toml` (mentions mypy).
- `gateway: Any` sites: `packages/sift-gateway/src/sift_gateway/policy_middleware.py` (14×).
- Gateway surface to type: `Gateway.__init__` `server.py:162-196` (22 fields — config,
  backends, `_tool_map`/`_tool_cache`/`_tool_manifest_meta`, `_audit`, `active_case_service`,
  `control_plane_dsn`, `evidence_service`, `investigation_service`, `report_service`,
  `job_service`, `db_audit`, …).
- Optional-dep test gating precedent: search for `importorskip` in `packages/**/tests`.

### Acceptance (draft)
- CI green on push/PR: ruff clean, full pytest pass, coverage artifact uploaded.
- `pyright` clean on `sift-gateway` with `gateway: Any` eliminated from `policy_middleware.py`.
- Coverage gate active (value TBD).

> **Build plan:** `AXIS_A_BUILD_PLAN.md` — units AU1–AU5 (CI workflow + live-vm stub →
> typing/`GatewayProtocol` ∥ test-rot audit → coverage floors → docs-freshness checker).

### Remaining open questions (with proposed defaults — confirm/adjust)
- A2 (coverage gate). **Proposed: per-package floors**, strict for security-critical
  (`sift-gateway`/`sift-core`/`sift-common`), lenient for add-ons (`opencti`/`wintriage`),
  ratchet upward — so the strong core can't mask the bare add-ons and vice-versa. (Global
  `--cov-fail-under` rejected: one number distorts an uneven suite.)
- A3 (typing rollout). **Proposed: gateway-first** (`GatewayProtocol` + `policy_middleware`),
  then `sift-core`/`sift-common`, add-ons last.
- A4 (CI scope vs "no hosting"). **RESOLVED 2026-06-16 by code inspection**: DB-touching tests
  use **in-memory fakes** (`FakeConn`, `_install_fake_psycopg`, monkeypatched `_connect`, fake
  DSNs e.g. `postgresql://fake`) and Supabase auth is monkeypatched — **no real Postgres /
  Supabase / testcontainers**. ⇒ CI is **pure**: `uv sync --extra full --extra dev` → ruff →
  pyright → pytest, **no service container**. **Caveat (load-bearing):** DB tests validate
  SQL-calling control flow, not real schema/RPC behavior — the **live-VM gate is the only place
  real Postgres/Supabase is exercised** (reinforces Axis B BU5).
- A5 (live-vm stub). **Proposed: yes** — a dispatch-only `live-vm` workflow that documents the
  VM proof steps (Actions can't execute them, but it codifies the manual gate).
- A6 (test hygiene). One-time orphan-audit now, or fold entirely into Axis B's per-unit test
  deletions? **Proposed: do the one-time audit as part of Axis A, B handles file-mode/CASE.yaml.**

---

## Axis B — DFIR data plane: complete the move to DB authority *(operator priority)*

**One-liner**: The DFIR data plane is already DB-authoritative for 6 of 7 critical classes.
Close the residual file-authority/file-read seams so that, with a DSN, **no DFIR-process
truth is read from or synced to a tamperable file** — except where explicitly justified +
mitigated.

### Authority map (grounded; the booster for this whole axis)

| Data class | Authority today | DB ref | File ref | Residual concern |
|---|---|---|---|---|
| Evidence hashes / seal / custody ledger | **DB** | `app.evidence_custody_events`, `app.evidence_chain_heads`, RPC `app.evidence_gate_status()` — `202606081000_evidence_custody.sql` | `evidence_chain.py:137-163` load_manifest/load_ledger (legacy) | file manifest is **export-only**, but orientation read-path still reads it first (see B-2) |
| Agent/service keys | **DB** | `app.mcp_tokens` + `app.mcp_token_scopes` — `202606070101` | `token_gen.py:7-40` (in-memory gen; never persisted) | none — clean |
| Active case pointer | **DB** | `app.active_case_state` — `202606070101` | `~/.sift/active_case` (audit.py:142,256; `sift_common/__init__.py:22`) | legacy CLI fallback still readable (B-4) |
| Findings / timeline / todos | **DB** | `app.investigation_*` (+version, reauth) — `202606081500/202606081600` | `case_manager.py` JSON; `investigation_store.py:666` returns None→file | file fallback when `db_authority_active()` false (B-3) |
| Reports / verification | **DB** | `app.approval_commit_events` (+ heads) — `202606141200`; `app.report_metadata` — `202606081500` | `reporting.py:631,738-739` (HMAC ledger retired) | clean — legacy writer retired |
| Audit trail | **DB** | `app.audit_events` — `202606070101` | `audit.py` JSONL, labeled `legacy-file-mirror` (`audit_ops.py:115`) | mirror is low-risk by design (logs class) |
| **Case metadata** | **FILE** | `app.cases.legacy_case_yaml_path` = pointer only — `202606070101/202606070400` | `case_metadata.py:97-160` writes `CASE.yaml`; `case_io.py` reads | **the one real remaining file source-of-truth → B-1 decision** |

Authority decision logic: `active_case_context.py:96-111` (`db_authority_active()` — context
or `SIFT_DB_ACTIVE`); file-mode triggers when no control-plane DSN (`server.py:209/239`).

### Sub-tracks (root cause → proposed approach)

**B-1 — CASE.yaml → DB authority. *(DECIDED 2026-06-16: option (a) — DB-authoritative,
CASE.yaml becomes a DB→file export.)***
- Root cause: case identity/metadata (name, examiner, incident type, dates, tags, status) is
  still *read as authority* from `CASE.yaml`; the DB `app.cases` row is written in parallel
  but treated as secondary. This is the "DFIR-process source of truth on file" the migration
  set out to remove.
- Key finding — **the DB scaffolding already exists**; B-1 is *flip authority + retire the
  file write*, not greenfield:
  - DB columns present: `app.cases.metadata jsonb`, `title`, `description`, `status`,
    `legacy_case_yaml_path`, `compat_export_status ∈ {pending,exported,stale}`
    (`202606070101_identity_foundation.sql:17,35-43`).
  - DB write service present: `active_case.py` `create_case` (:236), `update_case_metadata`
    (:336), `get_case_metadata` (:166) — each writes `app.cases` + an `app.audit_events` row.
  - Portal already calls DB: `routes.py:4862` `create_case(...)` on case create; `routes.py:2683`
    `update_case_metadata(...)` on metadata edit — **but both still also write CASE.yaml**
    (`routes.py:2699-2701` `set_case_metadata`).
- Proposed approach (4 moves):
  1. **Portal writes DB-only.** Make case create + metadata-edit routes call the
     `active_case` DB service as the sole write; **add the re-auth ceremony** the other
     sensitive routes use (evidence seal / approval pattern: `_supabase_reverify` →
     `_record_reauth_event` → DB mutation) so metadata edits link a `reauth_audit_event_id`.
  2. **Flip readers to DB authority** when a DSN is present (the ~15 reader sites in the
     propagation map): `case_ops.case_status_data`/`build_case_brief`, `case_manager`
     `get_case_status`/`list_cases`/closed-case gate, `case_io` `get_examiner`/`_case_id_from_dir`,
     `reporting.generate_report`. File read stays only on the explicit no-DSN path (B-3).
  3. **CASE.yaml becomes a DB→file export** driven by `compat_export_status` (mirror the
     evidence-manifest export pattern), so on-disk YAML is a non-authoritative artifact for
     portability/offline, never read as truth in DB-mode.
  4. **Migrate file-coupled resolution off CASE.yaml**: worker/audit-dir `case_id`
     (`case_io:67-78`), examiner (`case_io:215-238`), and the closed-case gate
     (`case_manager:687-697`) resolve from DB/active-case context in DB-mode.
- Propagation / blast radius (assessed): **2 portal write routes**, **~15 reader sites**,
  file-coupled resolution (audit dir, examiner, closure gate), and **29 test files** that
  write/read CASE.yaml fixtures (will need DB-backed or dual-path fixtures). Ordering: write
  DB-only → flip readers → add export → migrate resolution → update tests.
- Reference pack: `case_metadata.py:97-169` (set/`_atomic_write`), `case_io.py:215-249`
  (`load_case_meta`/`get_examiner`), `case_ops.py:57-116` (brief/status readers),
  `case_manager.py:687-697,873-926` (closure gate, status/list), `active_case.py:166-407`
  (DB service), portal `routes.py:2656-2710` (edit) + `:4723-4885` (create),
  `app.cases` in `202606070101_identity_foundation.sql:17,35-43`. Re-auth precedent:
  evidence seal `routes.py:1070-1158`, approval `_apply_delta_db` `routes.py:1858-1910`.
  *(Line numbers from an exploration pass; confirm at build time.)*

**B-2 — Orientation read-path reads the file manifest, then overlays DB.
*(DECIDED 2026-06-16: B2-native — DB-native + fail-closed; delete the overlays.)***
- Root cause: `case_info`/`evidence_info` always read the **file** layer (CASE.yaml + file
  evidence manifest + file findings counters) to build the base object; the gateway then
  re-fetches DB truth and **overwrites** those fields via `_overlay_db_evidence_gate` /
  `_overlay_db_findings_counters` / `_overlay_db_evidence_listing`, stamping `authority:"db"`.
- **Security classification: integrity / tamper vector, not just maintainability.** The
  overlay is *best-effort*: on **any** DB exception it logs and KEEPS the file-derived values
  (`mcp_server.py:102-104,154-156,184-186`). So in a DB-active deployment, a transient DB
  error degrades orientation to **attacker-modifiable file values while still labeled
  `authority:"db"`** — case contamination via tampered local files. This breaks the
  DB-authority guarantee precisely under failure. (Distinct from the no-DSN fallbacks gated
  by B-3: this one fires *inside* DB-mode on a transient exception.)
- Proposed approach: make orientation **DB-native when a DSN is present** — read directly from
  `app.evidence_gate_status` / `app.investigation_findings` / evidence service, with **no file
  base layer** — and on DB failure **fail closed** (return blocked/error), never serve file
  values. Delete the three `_overlay_db_*` functions. The file read survives only on the
  explicit no-DSN/dev path (B-3); this is what makes B-3's "no file path reachable with a DSN"
  regression test honest.
- Reference pack: `mcp_server.py:76-219` (the three `_overlay_db_*` fns + call sites at
  :119-134), `policy_middleware.py:476-479` (file vs DB gate branch), `evidence_gate.py:16-21`
  ("legacy/bridge file flow" docstring) + `check_evidence_gate` / `check_evidence_gate_db`;
  core orientation builder `case_ops.py:108-116` (`case_status_data`).

**B-3 — Delete the implicit file-mode fallback entirely.
*(DECIDED 2026-06-16: no offline need — Postgres/Supabase run locally — so DELETE file-mode;
no DSN ⇒ refuse to serve DFIR tools. No `SIFT_FILE_MODE` flag.)***
- Root cause: "no DSN → file authority" (`server.py:209/239`) + `db_authority_active()` False
  (`active_case_context.py:96-111`) silently select file paths. Under the attacker model,
  anyone who can sever/break the DSN connection downgrades the **whole deployment** to
  tamperable file authority. With no legitimate offline use case, this is pure attack surface.
- Proposed approach: on startup, if no control-plane DSN ⇒ **refuse to serve DFIR tools**
  (hard fail, not core-only file mode). Remove the file-authority branches reachable in
  DB-deployments. Add a **regression test** asserting that with a DSN configured, **no**
  file-authority code path is reachable for any DFIR tool call (evidence gate, orientation,
  findings, active case, audit case_id).
- Reference pack: `server.py:209-243` (no-DSN branch), `active_case_context.py:96-111`,
  `case_ops.py:73-106` + `investigation_store.py:663-677` (None→file contract — collapse to
  DB-only). *(Keep only what a pure dev/unit-test harness needs; tests may stub the DSN.)*

**B-4 — Retire residual legacy file fallbacks once B-3 lands.
*(DECIDED 2026-06-16: retire — but VALIDATE first.)***
- Root cause: `~/.sift/active_case` legacy-CLI read and the file `resolve_evidence_ref`
  else-branch remain as silent fallbacks.
- **Pre-req validation (operator: ~90% nothing depends on `~/.sift/active_case`):** before
  removal, grep the repo for all readers of `~/.sift/active_case` and check the live VM for any
  operator/CLI/script/systemd unit that reads it. Only retire once confirmed unused.
- Proposed approach: after B-3, remove the `~/.sift/active_case` read in audit case_id
  resolution and the file `resolve_evidence_ref` else-branch in DB-mode (keep
  `_trusted_internal_evidence_refs`).
- Reference pack: `audit.py:142,256`, `sift_common/__init__.py:22`,
  `agent_tools.py:795-813` (DB-injected refs first; file resolve else-branch at :803).

### Acceptance (draft)
- B-1 decision recorded; CASE.yaml either DB-authoritative-with-export or documented
  mitigated exception.
- B-2: orientation tools DB-native with a DSN; `_overlay_db_*` deleted; behavior proven on VM.
- B-3: explicit file-mode flag; regression test green proving no file path with a DSN.
- B-4: legacy `~/.sift/active_case` + file `resolve_evidence_ref` removed from DB-mode.
- Live-VM proof recorded (separate manual gate per A1).

### Remaining open questions
- **B1-Q (headline)** — **RESOLVED 2026-06-16**: option (a). CASE.yaml → DB authority, file
  becomes a DB→file export; portal create/edit write DB-only with the re-auth ceremony.
- B2-Q — **RESOLVED 2026-06-16**: B2-native. The best-effort file fallback is a tamper
  vector (case contamination under DB failure); go DB-native + fail-closed, delete overlays.
- B3-Q — **RESOLVED 2026-06-16**: delete file-mode; no DSN ⇒ refuse to serve DFIR tools
  (Postgres/Supabase are local; no offline need).
- B4-Q — **RESOLVED 2026-06-16**: retire, but validate in code + on the live VM first (~90%
  nothing depends on `~/.sift/active_case`).

---

## Axis C — Custody-grade test backfill

**One-liner**: Adversarial tests for the audit linchpin + the two bare add-ons.

### Root cause
`sift-common`'s `AuditWriter` — the component underwriting court-defensibility — has **no
dedicated test** (the package's only test, `test_mcp_schema.py`, covers schema helpers).
`opencti-mcp` (0.03) and `windows-triage-mcp` (0.05) test:src are near-bare.

### Proposed approach
1. **Adversarial `AuditWriter` suite**: sequence resume across a simulated crash, corrupted
   sidecar `.seq`, fsync semantics, clock rollover, concurrent writers, and the DB-active vs
   `legacy-file-mirror` authority labeling.
2. **Add-on backfill**: cover the risk paths in `opencti`/`wintriage` (manifest contract,
   capability gating, tool error handling) rather than chasing a raw coverage number.

### Reference pack (boosters)
- `packages/sift-common/src/sift_common/audit.py:102-231` (`AuditWriter`, `_resume_sequence`
  sidecar `.seq` + JSONL fallback; specific exceptions OSError/JSONDecodeError; fsync at
  `_write_entry`).
- Authority labeling: `sift-core/.../audit_ops.py:115` (`legacy-file-mirror`).
- Add-on contracts: each `sift-backend.json` (`opencti-mcp` ns `cti`, `windows-triage-mcp` ns
  `wintriage`); capability gating `sift-gateway server.py:301-372` (`evaluate_requirement`).

### Acceptance (draft)
- `AuditWriter` adversarial suite present + green; ties into Axis A coverage gate.
- opencti/wintriage risk-path tests present.

### Remaining open questions
- C1. Scope to the `AuditWriter` suite only, or include add-on backfill?
- C2. Add-on tests mock the OpenCTI/Windows clients, or need live fixtures (no hosting ⇒ mock)?
- C3. Couple C's targets to Axis A's coverage gate value?

---

## Axis D — Maintainability / footprint

**One-liner**: Reduce god-file size, de-dup the security regex, sweep broad excepts, move
ticket codes to ADRs. Pure quality; no functional gain.

### Root cause
God files (`routes.py` 6,226; `opensearch/server.py` 4,503; `case_manager.py` 2,321;
`opencti/client.py` 3,188) resist review. `_EXAMINER_RE` slug pattern is duplicated across 6
files (a security validator that must never diverge). 442 broad `except Exception`. Ticket
codes (`B-MVP-017`×30, `BATCH-NW4`×26, `PR03A`×24, …) live in source + some runtime strings.

### Proposed approach
- **Pull the `_EXAMINER_RE` de-dup *out* of D and into A** (it's small, security-relevant,
  high-value): one `EXAMINER_RE` exported from `sift-common`, imported by the 6 sites, with an
  equivalence test.
- Split god files along clear seams **after** Axis B settles which orientation/authority files
  it will rewrite (avoid B↔D merge conflicts).
- Audit broad excepts for any that swallow without logging.
- Move ticket-code *rationale* to ADRs; codes stay in git history; strip from agent-facing
  runtime strings first.

### Reference pack (boosters)
- Regex sites (6): `sift-common/.../audit.py`, `sift-core/.../identity.py`, `case_manager.py`,
  `case_io.py`, `approval_auth.py`, `case-dashboard/.../routes.py` (pattern
  `^[a-z0-9][a-z0-9-]{0,19}$`).
- God files: see `CODEBASE_ASSESSMENT.md` §2.2.
- Atomic-swap smell: `sift-gateway server.py:569-596` (`_tool_map` swapped; `_tool_cache`/
  `_tool_manifest_meta` reassigned after — wrap in one snapshot object).

### Acceptance (draft)
- `EXAMINER_RE` single-sourced + equivalence test.
- Targeted god-file splits with tests passing.

### Remaining open questions
- D1. Promote the `EXAMINER_RE` de-dup into Axis A now? (recommended)
- D2. Which god file first, or hold all until B settles file ownership?
- D3. Appetite for an ADR doc type in this repo?

---

## Axis E — Runtime / performance (deferred unless measured)

**One-liner**: Only worth a track with a concrete latency/throughput target.

### Root cause / candidates
Not an assessment focus. Possible hotspots: the orientation file+DB double-read (addressed
*for free* by B-2) and the OpenSearch worker fan-out (`sift-opensearch-worker@` units).

### Proposed approach
Defer until a measured bottleneck or SLO exists; B-2 likely removes the overlay cost anyway.

### Remaining open questions
- E1. Is there an actual perf complaint/SLO, or speculative?
- E2. If real: ingest throughput, tool-call latency, or portal?

---

## Axis F — Supply-chain trust: fetched packages & data *(operator-raised 2026-06-16)*

**One-liner**: Make the artifacts the platform pulls from the internet — OS/Python packages
*and* forensic data packages (knowledge bases, rule sets, intel feeds) — verifiably
trustworthy (pinned + integrity-checked + provenance-recorded), not trust-on-first-use.

### Why (operator statement)
"We don't need offline — Postgres/Supabase are local — **but we need trustworthiness in the
packages and data packages we fetch from the internet.**" In a forensic product, a tampered
dependency or a poisoned rule/knowledge feed can silently corrupt analysis and the resulting
court-defensible findings. This is a distinct security axis from file-vs-DB authority.

### Status: needs a grounding/discovery pass before planning
Enumerate, with file:line, **everything fetched from the network and how it's verified today**:
- **OS/system packages + Python deps**: `install.sh` (the assessment notes SHA-256 download
  verification + `offline_die`); is there a `uv.lock` / pinned hashes / pip hash-checking?
- **Forensic data packages**: `forensic-knowledge` YAML KB; `forensic-rag-mcp` sources
  (`sources.py` 2,595 LOC — what does it fetch and from where?); any Sigma/Hayabusa rules,
  vol3 symbols, GeoIP/intel feeds pulled at install or runtime; `scripts/setup-addon.sh`.
- **Add-on integrations**: OpenCTI feeds (`opencti-mcp`), Windows-triage baselines.

### Candidate approaches (to refine after discovery)
- Pin + hash-verify every download (extend the existing `install.sh` SHA-256 pattern to all
  fetchers); fail-closed on mismatch.
- Lockfile + hash-checked installs for Python deps; SBOM in CI (ties to Axis A).
- Provenance record for data packages (source URL + hash + fetched_at) — candidate DB table,
  mirroring the evidence/provenance discipline already in the control plane.
- Pin to vetted versions/mirrors; signature verification where upstreams provide it.

### Open questions
- F1. Which fetches are install-time vs runtime, and which are operator-triggered vs automatic?
- F2. Do we want hard fail-closed on any integrity mismatch, or quarantine-and-warn?
- F3. Should data-package provenance live in the DB control plane (like evidence) or a signed
  manifest on disk?
- F4. In scope for this track now, or schedule the discovery pass first and plan F separately?

---

## Cross-axis dependencies & recommended sequence

- **A first** — CI/typing catches regressions from B/C/D; cheapest, no behavior change.
- **B second** (operator priority) — but B-2/B-4 rewrite orientation/authority files, so run
  before Axis D god-file splits touch the same files.
- **C** — most useful once A's coverage gate exists; the `AuditWriter` suite is high value
  regardless.
- **D** — opportunistic; pull `EXAMINER_RE` into A; hold god-file splits until B settles.
- **F** — supply-chain trust; security-relevant and operator-raised. Run a discovery pass
  (enumerate fetches + current verification) before planning; its SBOM/lockfile parts ride on
  Axis A's CI.
- **E** — deferred; partly subsumed by B-2.

**Recommended: A → B → C, D opportunistic, F after discovery, E deferred.**

### Axis B status (locked 2026-06-16)

> **Build plan:** `AXIS_B_BUILD_PLAN.md` — units BU0–BU5 (field-parity/backfill → DB-native
> readers+orientation → portal DB-only writes → delete file-mode → retire fallbacks → test
> sweep + live-VM proof).

- **B-1**: CASE.yaml → DB authority; file = DB→file export; portal writes DB-only + re-auth.
- **B-2**: DB-native orientation, fail-closed; delete the `_overlay_db_*` tamper-fallback.
- **B-3**: delete implicit file-mode; no DSN ⇒ refuse to serve DFIR tools.
- **B-4**: retire `~/.sift/active_case` + file `resolve_evidence_ref` else-branch, after a
  code + live-VM validation that nothing depends on them.
- Axis B carries `/security-review` (B-2/B-3 are integrity-critical) and a live-VM proof gate.
