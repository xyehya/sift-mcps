# Axis B — Build Plan: complete the DFIR data plane move to DB authority

**Status**: build-ready unit breakdown. Decisions locked in `OPTIMIZATION_TRACK.md` §B
(B-1…B-4, 2026-06-16). This doc turns them into coding-session briefs.
**Security**: integrity-critical. Every unit that touches authority/orientation gets
`/security-review`; the track ends on a **live-VM proof gate** (separate manual gate per A1 —
GitHub Actions cannot reach the VM/Supabase).
**Grounding caveat**: file:line refs come from exploration passes; **confirm at build time**
(the codebase drifts). Do not edit from these numbers blind.

## Operating constraints
- Units **share files** (`case_ops.py`, `case_manager.py`, `case_io.py`, `mcp_server.py`,
  `routes.py`) ⇒ they are a **sequential pipeline**, not parallel units. One worktree at a
  time, one commit per unit, off the current integration branch.
- **Never leave a window where neither file nor DB authority works.** Order guarantees DB is
  populated and readers are DB-native *before* the file write is dropped and file-mode deleted.
- Each unit updates its own tests; BU5 does the cross-cutting regression + live-VM proof.

## Authority/reference map (booster — same as OPTIMIZATION_TRACK §B)
- DB target: `app.cases` (`metadata jsonb`, `title`, `description`, `status`,
  `legacy_case_yaml_path`, `compat_export_status ∈ {pending,exported,stale}`) —
  `supabase/migrations/202606070101_identity_foundation.sql:17,35-43`.
- DB write service: `sift-gateway active_case.py` — `create_case` (:236),
  `update_case_metadata` (:336), `get_case_metadata` (:166); each writes `app.audit_events`.
- Authority predicate: `active_case_context.py:96-111` (`db_authority_active()`).
- Orientation overlay (to delete): `mcp_server.py:76-219` (`_overlay_db_evidence_gate`,
  `_overlay_db_findings_counters`, `_overlay_db_evidence_listing`); call sites `:119-134`.
- Core orientation builder: `case_ops.py:108-116` (`case_status_data`), `:57-70`
  (`build_case_brief`, `CASE_BRIEF_FIELDS`).
- Readers: `case_io.py:215-249` (`load_case_meta`/`get_examiner`), `:67-78` (`_case_id_from_dir`,
  audit-dir resolution); `case_manager.py:687-697` (closed-case gate), `:873-926`
  (`get_case_status`/`list_cases`); `reporting.py:421` (`load_case_meta`).
- Writers: `case_metadata.py:97-169` (`set_case_metadata`/`_atomic_write`); portal
  `routes.py:2656-2710` (edit), `:4723-4885` (create).
- Re-auth precedent: evidence seal `routes.py:1070-1158` (`_supabase_reverify` →
  `_record_reauth_event` → DB mutation); approval `_apply_delta_db` `routes.py:1858-1910`.
- File-mode branches (to delete in BU3): `server.py:209-243`, `case_ops.py:73-106`,
  `investigation_store.py:663-677`, `evidence_gate.py` file branch + `policy_middleware.py:476-479`.
- Residual fallbacks (BU4): `audit.py:142,256`, `sift_common/__init__.py:22`,
  `agent_tools.py:795-813` (file `resolve_evidence_ref` else-branch at :803).

---

## BU0 — Field-parity audit + backfill (prerequisite; no behavior change)

**Goal**: guarantee `app.cases` can hold and is populated with **every** case-metadata field
the readers consume, before any reader flips to DB. Prevents data loss for existing cases
(e.g. the live `case-rocba-round-2`) whose values live only in CASE.yaml today.

**Changes**
- Enumerate every field read from CASE.yaml: `CASE_BRIEF_FIELDS` (`case_ops.py:57-70` —
  description, incident_type, severity, tlp, client, poc, impact_summary, detected_at,
  occurred_at, reported_at, contained_at, eradicated_at, recovered_at, affected_systems,
  affected_accounts, tags, related_cases) + name/title, examiner, status, case_id, dates.
- Confirm `active_case.create_case`/`update_case_metadata` persist **all** of them (to
  `app.cases` columns or the `metadata` jsonb). Extend them where a field is dropped today.
  Prefer the existing `metadata jsonb` over new columns unless a field gates process logic.
- One-time **backfill**: script/migration that reads each existing case's CASE.yaml and
  upserts the values into `app.cases` (idempotent; only fills missing/empty DB fields; never
  overwrites a DB value that already differs — log divergences for operator review).

**Scope fence**: `active_case.py`, a new backfill script under `scripts/`, possibly a
`supabase/migrations/*` if columns are added. No reader/writer behavior change yet.

**Acceptance**: for every existing case, `app.cases` round-trips every CASE.yaml field a
reader uses; backfill is idempotent and logs divergences; existing tests green.

**Review**: standard. **Depends on**: nothing.

---

## BU1 — DB-native readers + fail-closed orientation (delete overlays) *(security-critical)*

**Goal**: when a DSN is present, all case-metadata + orientation reads come **directly from
DB**, with **no file base layer** and **fail-closed on DB error**. Implements B-2 fully and the
B-1 reader side. Portal still dual-writes file at this point, so the file stays a consistent
backup — no regression window.

**Changes**
- **Orientation (B-2)**: rewrite `case_info`/`evidence_info` so that with a DSN they build
  from DB (`app.evidence_gate_status`, `app.investigation_findings`, evidence service) — not
  from CASE.yaml/file manifest. On DB failure, **return blocked/error**, never file values.
  **Delete** `_overlay_db_evidence_gate`/`_overlay_db_findings_counters`/
  `_overlay_db_evidence_listing` (`mcp_server.py:76-219`) and their call sites; the
  best-effort `except … return text/keep file` fallbacks (`:102-104,154-156,184-186`) go away.
- **Metadata readers (B-1)**: `case_ops.case_status_data`/`build_case_brief`,
  `case_manager.get_case_status`/`list_cases`, `reporting.generate_report` read DB via
  `active_case.get_case_metadata` when `db_authority_active()`.
- **Resolution readers**: `case_io.get_examiner` and `_case_id_from_dir`/audit-dir resolution,
  and the `case_manager` closed-case gate (`:687-697`) resolve from DB/active-case context in
  DB-mode (no CASE.yaml read).

**Scope fence**: `mcp_server.py`, `case_ops.py`, `case_manager.py`, `case_io.py`,
`reporting.py`, `sift-gateway` orientation glue. (File *writes* untouched — that's BU2.)

**Acceptance**: with a DSN, orientation + metadata reads return DB values and **fail closed**
on a simulated DB outage (no file values served); overlay functions deleted; manual check that
tampering CASE.yaml/file-manifest does **not** change `case_info`/`evidence_info` output.

**Tests**: DB-outage → orientation blocked (not file fallback); tamper-CASE.yaml → no change in
DB-mode; reader unit tests point at DB.

**Review**: `/security-review` (this closes the tamper vector). **Depends on**: BU0.

---

## BU2 — Portal writes DB-only + re-auth + CASE.yaml export (B-1 writer side)

**Goal**: case create + metadata edit write **DB only**; CASE.yaml becomes a DB→file **export**;
metadata edits carry a re-auth proof.

**Changes**
- `routes.py` create (`:4723-4885`) and edit (`:2656-2710`): drop the `set_case_metadata`
  file write (`:2699-2701`); the `active_case` DB call becomes the sole write.
- Add the **re-auth ceremony** to metadata edit, mirroring evidence-seal/approval
  (`_supabase_reverify` → `_record_reauth_event` → DB mutation), linking a
  `reauth_audit_event_id` on `app.cases` updates. (Confirm whether the schema needs a column
  or it lands in `app.audit_events` + details.)
- **CASE.yaml export**: generate CASE.yaml from `app.cases` driven by `compat_export_status`
  (`pending`/`stale` → re-export, then `exported`), mirroring the evidence-manifest export
  pattern. Mark exported YAML clearly non-authoritative.
- Repurpose `set_case_metadata` (`case_metadata.py`) as the **export writer** (or retire it for
  portal use and keep only for the export path).

**Scope fence**: `routes.py` (case create/edit), `case_metadata.py` (export role),
new export helper. No reader changes (BU1 already DB-native).

**Acceptance**: portal create/edit mutate only DB + emit audit/re-auth; CASE.yaml regenerates
from DB on demand and matches DB; editing metadata with a stale/invalid re-auth is refused.

**Tests**: edit route writes DB + audit + reauth, no file write; export round-trips DB→YAML;
re-auth failure path blocks.

**Review**: `/security-review` (re-auth + write authority). **Depends on**: BU1.

---

## BU3 — Delete implicit file-mode; no DSN ⇒ refuse DFIR tools (B-3) *(security-critical)*

**Goal**: remove the silent "no DSN → file authority" downgrade entirely.

**Changes**
- `server.py:209-243`: no control-plane DSN ⇒ **refuse to serve DFIR tools** (hard fail at
  startup/serve), not core-only file mode.
- Collapse the file-fallback contracts: `case_ops.py:73-106` and
  `investigation_store.py:663-677` (None→file) become DB-only; remove the
  `evidence_gate` file branch + `policy_middleware.py:476-479` file gate path.
- **Cross-cutting regression test**: with a DSN configured, assert **no** file-authority code
  path is reachable for any DFIR tool call (evidence gate, orientation, findings, active case,
  audit case_id) — e.g. patch file readers to raise and prove tool calls still succeed via DB,
  and that no-DSN startup refuses.

**Scope fence**: `server.py`, `case_ops.py`, `investigation_store.py`, `evidence_gate.py`,
`policy_middleware.py`, the new regression test.

**Acceptance**: no-DSN deployment refuses DFIR tools; with a DSN, file readers are provably
unreachable; regression test green.

**Review**: `/security-review`. **Depends on**: BU1, BU2 (readers + writers must be DB-native
before file-mode is removed).

---

## BU4 — Retire residual legacy fallbacks (B-4) — after validation

**Goal**: remove the last silent file fallbacks once proven unused.

**Pre-req validation (gate)**: grep the repo for every reader of `~/.sift/active_case`; check
the **live VM** for any operator/CLI/script/systemd unit reading it. Proceed only if confirmed
unused (operator estimate: ~90% nothing depends on it).

**Changes**: remove `~/.sift/active_case` read in audit case_id resolution
(`audit.py:142,256`, `sift_common/__init__.py:22`); drop the file `resolve_evidence_ref`
else-branch in DB-mode (`agent_tools.py:803`), keep `_trusted_internal_evidence_refs`.

**Scope fence**: `audit.py`, `sift_common/__init__.py`, `agent_tools.py`.

**Acceptance**: fallbacks gone; audit case_id + evidence-ref resolution work DB-only; the
validation finding is recorded.

**Review**: standard (small). **Depends on**: BU3 + the validation gate.

---

## BU5 — Test sweep + live-VM end-to-end proof

**Goal**: migrate the **29 CASE.yaml test files** to DB-backed (or dual-path) fixtures, run the
full suite, and prove the whole change on the live VM.

**Changes**
- Update the 29 test files (`rg -l "CASE.yaml" packages/**/tests`) to set up case metadata via
  DB fixtures; keep file fixtures only where a unit explicitly exercises the export path.
- Full `pytest` green; `python3 scripts/validate_docs.py` if docs touched.
- **Live-VM proof** (manual gate): on `sansforensics@192.168.122.81` with local Supabase —
  create + edit a case from the portal (DB-only, re-auth), confirm CASE.yaml is a regenerated
  export, run `case_info`/`evidence_info` and confirm DB authority + that tampering local files
  does not change output, confirm no-DSN refuses DFIR tools, and verify the existing
  `case-rocba-round-2` case survived backfill. Record sanitized proof in the issue.

**Acceptance**: full suite green; live-VM proof recorded; `/health` + portal + MCP orientation
behave; tamper test negative.

**Depends on**: BU0–BU4.

---

## Definition of Done (Axis B)
- 6/7 DFIR classes were already DB-authoritative; after Axis B the **7th (case metadata) is
  DB-authoritative** and **no file-authority path is reachable with a DSN**.
- Overlays deleted; orientation fail-closed; implicit file-mode gone; residual fallbacks
  retired (post-validation).
- CASE.yaml is a regenerated, clearly non-authoritative export.
- Cross-cutting regression test + live-VM proof both green; security-reviews done on
  BU1/BU2/BU3.

## Suggested ordering
**BU0 → BU1 → BU2 → BU3 → BU4 → BU5.** BU0 is a safe prerequisite; BU1 is the security
linchpin (closes the tamper vector) and can land/ship value before the rest; BU3 must not
precede BU1+BU2.
