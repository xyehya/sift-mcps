# Axis D - Maintainability / Reviewability Closure

> Covers: packages/sift-common/src/sift_common/**, packages/sift-core/src/sift_core/**, packages/sift-gateway/src/sift_gateway/**, packages/case-dashboard/src/case_dashboard/routes.py, packages/opensearch-mcp/src/opensearch_mcp/**, docs/adr/**, docs/new-docs/CODEBASE_ASSESSMENT.md
> Class: living-plan
> Last validated: dd4c656 (2026-06-18)

**Status**: plan-ready for OT4.
**Source assessment gap**: the assessment called out duplicated security regexes,
god files, broad exceptions, ticket-code history in source/runtime strings, a
non-atomic backend tool-surface swap, cross-package reach-ins, and lint-config
drift.

## D1 - Single-Source Examiner / Principal Slug Validation

**Goal**: make the examiner/principal slug validator a single shared contract.

**Current state**: the pattern `^[a-z0-9][a-z0-9-]{0,19}$` still appears in
`sift-common`, `sift-core`, and `case-dashboard` validators.

**Scope fence**
- Add a shared validator/export in `sift-common`.
- Replace local regex copies in core and portal.
- Add an equivalence/regression test.

**Hard constraints**
- No accepted or rejected principal changes without explicit test proof.
- Preserve current error semantics where callers rely on them.

**Acceptance**
- One source of truth for the regex.
- All existing validator call sites import or delegate to the shared contract.
- Tests prove current valid/invalid examples keep the same result.

## D2 - Residual Broad-Exception Audit

**Goal**: finish the broad-exception cleanup after `XYE-32` by finding remaining
silent swallow or fail-open behavior.

**Scope fence**
- Recount `except Exception` sites.
- Classify each as fail-closed guard, diagnostic/logged boundary, or defect.
- Fix only silent/fail-open cases in this unit; defer large refactors.

**Hard constraints**
- Preserve deliberate fail-closed catches in policy/security boundaries.
- Do not add noisy logs that leak secrets, paths, DSNs, or JWT material.

**Acceptance**
- Audit table in the issue comment or doc.
- Every remaining broad catch has a reason or follow-up.
- Silent/fail-open cases are fixed or split into dedicated issues.

## D3 - Ticket-Code Cleanup And ADR/Prose Migration

**Goal**: keep useful design history while removing opaque ticket codes from
agent-facing runtime strings and high-traffic source comments.

**Scope fence**
- Inventory highest-volume code names (`B-MVP-*`, `BATCH-*`, `PR03A`, etc.).
- Move rationale that is still useful into ADR/prose docs.
- Remove or rewrite runtime strings that expose internal code names to agents or
  operators without context.

**Hard constraints**
- Do not erase historical traceability from git history.
- Do not churn comments that still contain useful live invariants.

**Acceptance**
- ADR/prose references exist for retained decisions.
- Agent/operator-facing strings are human-readable without project-code context.

## D4 - Portal `routes.py` First Extraction

**Goal**: reduce review risk in the largest portal file with one low-risk,
test-backed extraction.

**Scope fence**
- Choose one cohesive route/helper cluster only, preferably backends/add-ons or
  case metadata after Axis B stabilized.
- Keep public routes and templates compatible.
- Add characterization tests before moving code.

**Acceptance**
- `routes.py` shrinks by a meaningful, measured amount.
- Extracted module has focused tests.
- Portal tests pass.

## D5 - OpenSearch Server / Registry First Extraction

**Goal**: reduce single-file pressure in OpenSearch without changing the served
FastMCP 3 contract.

**Scope fence**
- Respect the current invariant: `registry.py` is the deployed typed FastMCP
  contract, `opensearch_mcp.server` is the implementation engine.
- Extract a cohesive helper area only.

**Acceptance**
- Surface snapshot/golden tests still pass.
- Worker-vs-direct dispatch invariant from `XYE-36` remains unchanged.

## D6 - `case_manager.py` First Extraction

**Goal**: reduce review risk in case management while preserving DB-authority
semantics from Axis B.

**Scope fence**
- One cohesive cluster only.
- Add DB-authority regression tests around any moved readers/gates.

**Acceptance**
- No CASE.yaml authority path is reintroduced.
- Existing BU1/BU3 tests pass.

## D7 - Atomic Gateway Tool-Surface Snapshot

**Goal**: replace the three separate `_tool_map`, `_tool_cache`, and
`_tool_manifest_meta` swaps with one immutable snapshot object.

**Acceptance**
- Concurrent readers cannot observe a new map with stale cache/meta.
- Existing backend reload tests pass.

## D8 - Lint Config Decision For Line Length

**Goal**: resolve the `line-length = 88` plus `E501` ignored drift.

**Acceptance**
- Either enable `E501` with targeted exceptions, or document why line length is
  advisory only.
- No mass formatting churn bundled with unrelated changes.

## D9 - Widen Type Gate Beyond The Policy Layer

**Goal**: extend the pyright/type-checking gain from AU3 beyond the initial
gateway policy layer.

**Scope fence**
- Start with `sift-gateway` modules that already have stable contracts.
- Do not attempt repo-wide strict mode in one issue.

**Acceptance**
- A new pyright include/scope is added with current errors resolved or
  intentionally excluded.
- CI enforces the widened scope.

## D10 - OpenSearch -> Core Dependency Audit

**Goal**: decide which `opensearch-mcp` imports from `sift-core` are legitimate
and which should move to `sift-common` or a local contract.

**Scope fence**
- Discovery first; implementation only for obvious shared utility moves.
- Do not weaken the deployed `registry.py` FastMCP contract.

**Acceptance**
- Import map and recommendation recorded.
- Follow-up issues created for any non-trivial extraction.

## D11 - Portal -> Gateway Boundary Audit

**Goal**: clarify which portal imports from gateway internals are supported
integration points and which are accidental coupling.

**Scope fence**
- Discovery first; no broad route rewrite.
- Keep the real v2 portal at `/portal` intact.

**Acceptance**
- Boundary map records supported imports, accidental reach-ins, and extraction
  candidates.
- Follow-up issues exist for any API/adapter work.
