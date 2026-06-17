# Axis A — Build Plan: process / safety-net hardening

> Covers: .github/workflows/, pyproject.toml, packages/sift-gateway/src/sift_gateway/policy_middleware.py, packages/sift-gateway/src/sift_gateway/server.py, scripts/check_newdocs_refs.py, docs/new-docs/
> Class: living-plan
> Last validated: dd4c656 (2026-06-18)

**Status**: complete. This file is retained as the historical build plan for OT1
and should not keep absorbing new quality work. New assessment-compliance work
belongs in Axis C/D/F/G/H/I plans.
**Why it came first**: CI + typing caught regressions during the Axis B authority
rewrite. No runtime behavior change was intended in this axis.
**Completion map**: `XYE-13` AU1, `XYE-14` AU2, `XYE-15` AU3, `XYE-16` AU4,
`XYE-17` AU5.

## Completion addendum (2026-06-18)
- `.github/workflows/ci.yml` runs locked uv installs, ruff, pyright, docs
  freshness, pytest, and package coverage checks.
- `.github/workflows/live-vm.yml` exists as a manual proof gate.
- `pyrightconfig.json` and `GatewayProtocol` removed the original
  `gateway: Any` policy-layer gap.
- `scripts/check_newdocs_refs.py` is in CI.
- Further coverage and quality work is tracked under Axis C/D rather than
  reopening Axis A.

## Locked defaults (from the menu)
- **A2** per-package coverage floors (strict core, lenient add-ons, ratchet).
- **A3** typing gateway-first, then core/common, add-ons last.
- **A4** CI is pure — `uv sync --extra full --extra dev` → ruff → pyright → pytest, **no
  service container** (DB tests use in-memory fakes; Supabase auth monkeypatched). Live-VM is
  the only real-Postgres/Supabase gate.
- **A5** dispatch-only `live-vm` workflow stub documenting the manual proof gate.
- **A6** one-time test-rot orphan audit here; Axis B deletes file-mode/CASE.yaml tests inline.

---

## AU1 — CI workflow (foundational)
**Goal**: every push/PR runs lint + type + tests on GitHub Actions (private repo, no hosting).
**Changes**
- `.github/workflows/ci.yml`: checkout → install `uv` → `uv sync --extra full --extra dev` →
  `ruff check` → `pyright` (added in AU3; until then `pyright || true` or omit) → `pytest`.
  No `services:` block. Cache the uv environment.
- `.github/workflows/live-vm.yml` (A5): `workflow_dispatch` only; no runner steps execute the
  VM — it documents the manual proof checklist (health, portal create/edit, MCP orientation,
  tamper test, no-DSN refusal) so the gate is codified.
**Acceptance**: CI green on a no-op PR; ruff + pytest run; live-vm workflow visible as
dispatch-only. **Depends on**: none.

## AU2 — Coverage gate (per-package floors)
**Goal**: lock in current coverage so under-tested packages can't regress silently.
**Changes**
- Run `pytest --cov` once to get the **observed** per-package coverage (we have test:src LOC
  ratios, not coverage %, so floors are **measured, not guessed**).
- Set per-package `--cov-fail-under` style floors at *observed − small margin*: strict for
  `sift-gateway`/`sift-core`/`sift-common`; lenient for `opencti-mcp`/`windows-triage-mcp`
  (Axis C raises these later). Wire into the CI pytest step.
**Acceptance**: CI fails if any package drops below its floor; floors documented.
**Depends on**: AU1. *(Edits the CI workflow — sequence after AU1, before/after AU5 but not
concurrent with them on `ci.yml`.)*

## AU3 — Static typing: `GatewayProtocol` + pyright (security layer)
**Goal**: convert the untyped service-locator on the policy layer into a checked contract.
**Changes**
- Define `GatewayProtocol` (typed interface for the ~22 attributes `Gateway` exposes —
  `server.py:162-196`: config, backends, `_tool_map`/`_tool_cache`/`_tool_manifest_meta`,
  `_audit`, `active_case_service`, `control_plane_dsn`, `evidence_service`,
  `investigation_service`, `report_service`, `job_service`, `db_audit`, …).
- Replace the **14** `gateway: Any` annotations in `policy_middleware.py` with
  `GatewayProtocol`.
- Add `pyright` config scoped to `sift-gateway` first (strict there, basic elsewhere); add to
  CI (flip AU1's placeholder to a real gate).
**Acceptance**: `pyright` clean on `sift-gateway`; no `gateway: Any` left in
`policy_middleware.py`; CI enforces pyright. **Depends on**: AU1.

## AU4 — One-time test-rot orphan audit
**Goal**: delete tests that *exercise removed paths*, keep tests that *assert retirement*.
**Changes**
- Classify the grounded rot: `ingest_job` ×3, `file.*HMAC` ×10, `reconcile_verification`/
  `_RETIRED` ×2, file `check_evidence_gate` branch ×11, `file_mode` ×2, ticket-code-named ×6.
- **Keep** any test asserting "path retired / DB is authority"; **delete** any test exercising
  a deleted subsystem as if live (orphans should already error under AU1's CI — start there).
- Do **not** touch the CASE.yaml ×29 or the file-mode/`check_evidence_gate` tests that Axis B
  deletes inline (BU1/BU3/BU5) — avoid double-ownership; this unit handles only *already*-
  retired subsystems.
**Acceptance**: no orphaned tests collect-error; deletions justified per-file; suite green.
**Depends on**: AU1. Independent of AU3.

## AU5 — Docs-freshness mechanism
**Goal**: implement `DOCS_MAINTENANCE.md` so `docs/new-docs/` stays live.
**Changes**
- Add the `Covers:` / `Class:` / `Last validated:` header to each live-reference doc
  (`SYSTEM_OVERVIEW`, `DATA_FLOW`, `DATA_STRUCTURES`, `KEY_FUNCTIONS`, `ALGORITHM_FLOWS`,
  `KEY_QUESTIONS`, `DEVELOPER_ENTRYPOINT`) and the living-plan docs.
- Build `scripts/check_newdocs_refs.py`: (1) parse `file:line` + backticked path/symbol refs,
  hard-fail on dangling file, warn on missing symbol; (2) Covers-vs-diff drift warning. Scope
  to `docs/new-docs/` only; keep separate from `validate_docs.py`.
- Wire the checker into CI (warnings surface on PR; dangling-file = fail).
- One-time stamp pass over the 6 live-reference docs (skim for the drift classes already fixed
  in `CODEBASE_ASSESSMENT.md`).
**Acceptance**: headers present; checker runs in CI; a deliberately-broken ref fails the check.
**Depends on**: AU1. *(Edits `ci.yml` — sequence vs AU2 on that file.)*

---

## Definition of Done (Axis A)
- CI runs ruff + pyright + pytest on every PR (no services); per-package coverage floors active.
- `gateway: Any` eliminated from `policy_middleware.py` via `GatewayProtocol`; pyright clean on
  gateway.
- Already-retired-subsystem orphan tests removed; suite green.
- Docs-freshness headers + `check_newdocs_refs.py` live in CI; `DOCS_MAINTENANCE.md` adopted.

## Suggested ordering
**AU1 → (AU3 ∥ AU4) → AU2 → AU5.** AU1 is foundational; AU3 and AU4 are independent; AU2 and
AU5 both edit `ci.yml`, so land them one after another, not concurrently.
