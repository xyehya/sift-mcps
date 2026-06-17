# Optimization Track - Assessment Compliance Plan

> Covers: docs/new-docs/CODEBASE_ASSESSMENT.md, docs/new-docs/AXIS_*_BUILD_PLAN.md, .github/workflows/, pyproject.toml, install.sh, scripts/**, packages/**, supabase/migrations/**
> Class: living-plan
> Last validated: dd4c656 (2026-06-18)

**Status**: Wave 1 is complete. Axis A (process/safety net) and Axis B
(DB authority) are implemented and closed in Linear. This document now serves as
the assessment-compliance track: every actionable gap in
`CODEBASE_ASSESSMENT.md` is either closed, assigned to an existing Linear issue,
or mapped to a new build-plan unit.

**Operating model**: keep the successful Wave 1 pattern:

- One milestone for a coherent wave.
- One coordinator issue for the milestone.
- Small executable child issues with scope fences, hard constraints, acceptance,
  and validation commands.
- Reuse existing open issues rather than duplicating them.
- Keep old issue units; they remain useful troubleshooting breadcrumbs.

---

## 0. Wave Status

| Axis | Theme | Status | Linear mapping |
|---|---|---|---|
| A | CI, coverage, pyright, docs freshness | **Done** | `XYE-13`..`XYE-17` |
| B | DB authority / file-mode retirement | **Done** | `XYE-18`..`XYE-23` |
| B2 | Residual legacy authority exception audit | **Posted** | `XYE-60`..`XYE-62` |
| C | Custody-grade and add-on test backfill | **Posted** | `XYE-65`..`XYE-68` |
| D | Maintainability / reviewability | **Posted** | `XYE-69`..`XYE-79` |
| E | Runtime and DB hot-path performance | **Posted** | reuse `XYE-34` |
| F | Supply-chain and data-package trust | **Posted** | `XYE-48`..`XYE-51`; reuse `XYE-43` |
| G | OpenSearch data compatibility cleanup | **Posted** | `XYE-63`, `XYE-64`; reuse `XYE-10`, `XYE-40` |
| H | Add-on behavioral admission controls | **Posted** | `XYE-56`..`XYE-59`; reuse `XYE-25` |
| I | Installer verification / replacement path | **Posted** | `XYE-52`..`XYE-55` |
| J | RAG knowledge policy decision | **Decision gate** | reuse `XYE-6` |
| Ops | Repo rename / layout normalization | **Operator-gated** | reuse `XYE-7` |

Recommended next milestones:

- **OT2: Supply-Chain, Installer, And Add-On Trust** - `XYE-45`, Axis F/H/I.
- **OT3: Runtime, Authority Residuals, And OpenSearch Resilience** - `XYE-46`,
  Axis B2/E/G.
- **OT4: Custody Tests And Maintainability Closure** - `XYE-47`, Axis C/D.

### Linear issue map (created 2026-06-18)

| Wave | Issue IDs |
|---|---|
| OT2 coordinator | `XYE-45` |
| OT2 reused | `XYE-43` (F1), `XYE-25` (H1/root) |
| OT2 new | `XYE-48` F0, `XYE-49` F2, `XYE-50` F3, `XYE-51` F4, `XYE-52` I1, `XYE-53` I2, `XYE-54` I3, `XYE-55` I4, `XYE-56` H2, `XYE-57` H3, `XYE-58` H4, `XYE-59` H5 |
| OT3 coordinator | `XYE-46` |
| OT3 reused | `XYE-34` E1, `XYE-40` G1, `XYE-10` G2 |
| OT3 new | `XYE-60` B2-1, `XYE-61` B2-2, `XYE-62` B2-3, `XYE-63` G3, `XYE-64` G4 |
| OT4 coordinator | `XYE-47` |
| OT4 new | `XYE-65` C1, `XYE-66` C2, `XYE-67` C3, `XYE-68` C4, `XYE-69` D1, `XYE-70` D2, `XYE-71` D3, `XYE-72` D4, `XYE-73` D5, `XYE-74` D6, `XYE-75` D7, `XYE-76` D8, `XYE-77` D9, `XYE-78` D10, `XYE-79` D11 |

Recommended sequence:

1. OT2-F1 / `XYE-43` first: it can damage the runtime venv during add-on
   setup.
2. OT2-F0 discovery: network fetch and data-package trust inventory.
3. OT2-H/I units: add-on admission controls and installer proof.
4. OT3-B2: close residual legacy authority exceptions found after BU.
5. OT3-E1 / `XYE-34`: pool DB-authoritative case metadata reads after BU
   landed.
6. OT3-G units: OpenSearch re-ingest/index compatibility cleanup.
7. OT4-C units: deepen tests where the assessment still flags weak coverage.
8. OT4-D units: maintainability, DRY, and reviewability closure.
9. J / `XYE-6`: RAG shared-knowledge policy before portal RAG expansion.

---

## 1. Assessment Compliance Matrix

| Assessment item | Current state | Remaining action | Axis / issue |
|---|---|---|---|
| No CI enforcing tests + ruff | Closed by Wave 1; `.github/workflows/ci.yml` exists | Keep CI as the gate for new units | A / Done |
| No type checking + `gateway: Any` | Closed for gateway policy layer via `GatewayProtocol` and pyright | Widen typing opportunistically after hot-path units | A / Done, D follow-up only |
| Coverage gate absent | Closed by per-package coverage script in CI | Raise add-on coverage by risk-path tests | C |
| File/DB authority migration incomplete | Closed by BU0..BU5; current source has DB-only gate and no overlay functions | Update stale assessment checklist; keep regression tests | B / Done |
| Residual file-mode helpers/comments | Production gateway path closed, but legacy helpers/comments remain | Classify each as removed, dev/test-only, legacy CLI, export, or defect | B2-1 |
| Portal case-create compatibility artifact window | Needs focused failure-path proof | DB-first create or deterministic cleanup for orphan CASE.yaml exports | B2-2 |
| Legacy active-case pointer in core utilities | Gateway fallback retired; legacy CLI utilities may still touch pointer file | Retire or explicitly classify as non-authoritative compatibility | B2-3 |
| `AuditWriter` had no dedicated tests | Partly closed by `XYE-31`; basic `TestAuditWriter` exists | Add adversarial crash/corruption/concurrency/fsync suite | C1 |
| OpenCTI / Windows-triage under-tested | Still true as risk-path gap | Add mocked tool/error/manifest/config tests | C2, C3 |
| Duplicated examiner slug regex | Still duplicated across gateway, portal, core, and common packages | Single-source principal/examiner validation in `sift-common` | D1 |
| God files resist review | Still true; B churn has settled | Split only with scoped first extractions and characterization tests | D4..D6 |
| Broad `except Exception` volume | Partly improved by `XYE-32` | Recount and audit residual silent/swallowing paths | D2 |
| Ticket codes in source/runtime strings | Still present | Move rationale to ADR/prose; remove agent-facing code names first | D3 |
| Tool-map "atomic swap" not atomic | Still low-severity design smell | Wrap map/cache/meta in one immutable snapshot | D7 |
| 3.5K-line Bash installer untested | Still true despite recent fixes | Add installer static/unit/smoke harness, then decide wrapper/rewrite path | I |
| Supply-chain / fetched data trust | New operator-raised security axis | Inventory all network fetches; add hash/provenance/SBOM controls | F |
| Add-on manifest says little about behavior | Static lint exists (`XYE-24`) | Add synthetic behavioral probe before exposing backends | H / `XYE-25` |
| DB metadata reads on hot paths open new connections | Follow-up validated as `XYE-34` | Pool/cache connection provider with fail-closed semantics | E / `XYE-34` |
| OpenSearch `vhir` -> `sift` re-ingest duplication | Live follow-up `XYE-40` | Compatibility/idempotency repair | G1 |
| Doubled `case-case-` index prefix | Open polish `XYE-10` | Compatibility-aware naming/alias cleanup | G2 |
| Shared RAG knowledge policy | Open decision `XYE-6` | Operator decision before portal implementation | J / `XYE-6` |
| Repo rename/layout normalization | Open operator gate `XYE-7` | Impact map and cutover plan only when approved | Ops / `XYE-7` |

---

## 2. Axis A - Process / Safety-Net Hardening

**Status**: complete. See `AXIS_A_BUILD_PLAN.md`.

Completed units:

- `XYE-13` / AU1: GitHub Actions CI.
- `XYE-14` / AU2: per-package coverage floors.
- `XYE-15` / AU3: `GatewayProtocol` and pyright gate.
- `XYE-16` / AU4: retired-test audit.
- `XYE-17` / AU5: docs freshness checker.

Follow-up policy:

- Do not reopen Axis A for every quality task.
- New checks should be attached to the axis whose risk they guard.
- CI remains the acceptance gate for every implementation issue.

---

## 3. Axis B - DFIR Data Plane DB Authority

**Status**: complete. See `AXIS_B_BUILD_PLAN.md`.

Completed units:

- `XYE-18` / BU0: field parity and backfill.
- `XYE-19` / BU1: DB-native orientation and metadata readers.
- `XYE-20` / BU2: portal DB-only writes and CASE.yaml export.
- `XYE-21` / BU3: implicit file-mode removed; no DSN refuses service.
- `XYE-22` / BU4: residual active-case/evidence-ref fallbacks retired.
- `XYE-23` / BU5: test sweep and live-VM proof.

Source rebaseline notes:

- `_overlay_db_*` orientation functions are absent from
  `packages/sift-gateway/src/sift_gateway/mcp_server.py`.
- `EvidenceGateMiddleware.on_call_tool` calls `check_evidence_gate_db(...)`.
- `packages/sift-gateway/tests/test_bu3_no_file_mode.py` pins no-DSN refusal.
- `packages/sift-core/tests/test_bu3_file_readers_unreachable.py` pins DB-mode
  file-reader reachability constraints.

---

## 4. Axis B2 - DB Authority Residual Exception Audit

**Build plan**: `AXIS_B2_BUILD_PLAN.md`. Proposed milestone: OT3.

Goal: close or explicitly classify residual file-mode helpers, stale comments,
case-create compatibility artifact windows, and legacy active-case pointer
utilities without reopening the completed production DB-authority rewrite.

Units:

- B2-1: explicit legacy file-mode exception audit.
- B2-2: DB-first case create / orphan artifact cleanup.
- B2-3: legacy active-case pointer classification.

Acceptance:

- No reachable DB-active gateway/tool path can read file authority.
- Any retained file artifact is documented as export, dev/test, or legacy CLI
  compatibility.
- Stale comments contradicting BU3/BU4 behavior are corrected.

---

## 5. Axis C - Custody-Grade Test Backfill

**Build plan**: `AXIS_C_BUILD_PLAN.md`. Proposed milestone: OT4.

Goal: close the remaining test-distribution gaps from the assessment without
chasing raw coverage for its own sake.

Units:

- C1: adversarial `AuditWriter` suite.
- C2: OpenCTI MCP risk-path test backfill.
- C3: Windows-triage MCP risk-path and config/data-contract tests.
- C4: mixed package-root pytest import-layout follow-up, if still valuable after
  the CI path remains stable.

Acceptance:

- Custody/audit failure modes are directly tested.
- OpenCTI and Windows-triage tests pin manifest contracts, tool error handling,
  capability/config gates, and no-secret/no-case-authority behavior.
- Coverage floors can ratchet upward for the affected packages after tests land.

---

## 6. Axis D - Maintainability / Reviewability

**Build plan**: `AXIS_D_BUILD_PLAN.md`. Proposed milestone: OT4.

Goal: remove review and drift hazards that the assessment calls out, after the
authority rewrite has settled.

Units:

- D1: single-source examiner/principal slug validation.
- D2: residual broad-exception audit after `XYE-32`.
- D3: move ticket-code rationale to ADR/prose and remove agent-facing code-name
  strings.
- D4: portal `routes.py` first extraction with characterization tests.
- D5: OpenSearch server/registry first extraction with surface tests.
- D6: `case_manager.py` first extraction with DB-authority regressions.
- D7: atomic backend tool-map snapshot object.
- D8: lint-config cleanup (`E501`/line-length decision).
- D9: widen the type gate beyond the initial policy-layer pyright scope.
- D10: audit `opensearch-mcp` -> `sift-core` reach-ins and move legitimate
  shared utilities toward `sift-common`.
- D11: audit portal -> gateway internal imports and clarify supported boundary.

Acceptance:

- Security validators have one source of truth.
- Every broad exception either logs, fails closed, or is narrowed.
- Large-file work is incremental and test-backed; no broad rewrite.

---

## 7. Axis E - Runtime / DB Hot-Path Performance

**Build plan**: `AXIS_E_BUILD_PLAN.md`. Proposed milestone: OT3.

Goal: fix measured hot paths introduced or exposed by DB authority, not
speculative performance.

Primary issue:

- Reuse `XYE-34`: pool DB-authoritative case metadata reads.

Acceptance:

- Repeated `resolve_case_metadata()` calls do not open a fresh TCP connection
  per call.
- Missing DSN/context/row and DB errors still fail closed in DB-authority mode.
- BU1/BU3 tests still pass.

---

## 8. Axis F - Supply-Chain And Data-Package Trust

**Build plan**: `AXIS_F_BUILD_PLAN.md`. Proposed milestone: OT2.

Goal: every internet-fetched package or forensic data package is pinned,
integrity-checked, and provenance-recorded where it can affect findings.

Units:

- F0: discovery inventory of all network fetches and current verification.
- F1: reuse `XYE-43` to stop win-triage setup from clobbering the runtime venv.
- F2: installer/download integrity manifest and fail-closed verification.
- F3: forensic data-package provenance for RAG/Hayabusa/Sigma/wintriage feeds.
- F4: CI SBOM/dependency-audit artifact.

Acceptance:

- No unmanaged Python downloads on the VM.
- No trust-on-first-use data packages in default install paths.
- Operators can see source URL, version/ref, hash, fetched time, and verification
  status for forensic data packages.

---

## 9. Axis G - OpenSearch Data Compatibility

**Build plan**: `AXIS_G_BUILD_PLAN.md`. Proposed milestone: OT3.

Goal: make re-ingest and index naming stable across schema/name migrations.

Units:

- G1: reuse `XYE-40` for `vhir` -> `sift` CSV-family duplicate remediation.
- G2: reuse `XYE-10` for doubled `case-case-` index-prefix cleanup.
- G3: OpenSearch compatibility repair playbook and live mixed-case validation.

Acceptance:

- Force re-ingest across provenance-schema boundaries is idempotent or safely
  purges prior-schema duplicates per source.
- Existing indices remain queryable during naming cleanup.
- No blanket deletes that can drop unique pre-rename documents.

---

## 10. Axis H - Add-On Behavioral Admission Controls

**Build plan**: `AXIS_H_BUILD_PLAN.md`. Proposed milestone: OT2.

Goal: extend static manifest linting into deploy-time behavioral validation for
operator-registered backends.

Primary issue:

- Reuse `XYE-25`: register-time behavioral scan/fuzz of add-on MCP tool calls.

Units:

- H1: design the isolated synthetic probe protocol and operator decision
  semantics.
- H2: implement side-effect-safe tool-list/schema/call probes.
- H3: surface probe reports in the portal register/start flow.
- H4: add regression fixtures for honest, contradictory, and malicious-ish
  add-on behavior.

Acceptance:

- Probe never mutates real cases/evidence.
- Tool behavior is cross-checked against manifest case/evidence authority.
- Operator can choose advisory vs blocking policy with recorded rationale.

---

## 11. Axis I - Installer Verification / Replacement Path

**Build plan**: `AXIS_I_BUILD_PLAN.md`. Proposed milestone: OT2.

Goal: make the 3.5K-line installer reviewable and testable before considering a
larger replacement.

Units:

- I1: installer static and function-level test harness for risky shell helpers.
- I2: greenfield install/uninstall smoke harness on the SIFT VM.
- I3: staged Python/Ansible wrapper feasibility decision.
- I4: service/add-on lifecycle install regression suite.

Acceptance:

- Installer changes have automated proof beyond `bash -n`.
- Fresh install, add-on setup, service restart, and uninstall paths are covered
  by repeatable smoke steps.
- Any replacement path has an operator-approved migration plan.

---

## 12. Decision / Operator-Gated Work

These remain valid open issues and should not be duplicated:

- `XYE-6`: shared-RAG knowledge-document policy.
- `XYE-7`: repo rename to `ProtocolSiftGateway` and add-on layout
  normalization.

They should be linked to the OT2 coordinator but kept gated:

- `XYE-6` blocks any shared-RAG portal implementation.
- `XYE-7` blocks only rename/layout work; it should not block security,
  testing, or installer-trust hardening.

---

## 13. Track Definition Of Done

The assessment report is considered compliance-closed when:

- Every row in the compliance matrix is either Done or explicitly deferred by an
  operator decision issue.
- All implementation units have passing targeted tests and CI.
- Security-sensitive units have `gate:security-review` and recorded proof.
- Live-impacting installer, OpenSearch, gateway, or portal units have sanitized
  live-VM proof comments.
- `CODEBASE_ASSESSMENT.md` is updated with a completion addendum rather than
  silently rewriting the historical assessment.
