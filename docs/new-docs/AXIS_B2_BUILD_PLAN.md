# Axis B2 - DB Authority Residual Exception Audit

> Covers: packages/sift-gateway/src/sift_gateway/server.py, packages/sift-gateway/src/sift_gateway/__main__.py, packages/sift-gateway/src/sift_gateway/policy_middleware.py, packages/sift-gateway/src/sift_gateway/evidence_gate.py, packages/case-dashboard/src/case_dashboard/routes.py, packages/sift-core/src/sift_core/case_ops.py, packages/sift-core/src/sift_core/case_manager.py, packages/sift-core/src/sift_core/case_metadata.py
> Class: living-plan
> Last validated: dd4c656 (2026-06-18)

**Status**: plan-ready for OT3.
**Purpose**: keep Axis B's production DB-authority completion intact while
tracking the residual legacy/compatibility exceptions found during the
assessment-compliance rebaseline.

## B2-1 - Explicit Legacy File-Mode Exception Audit

**Goal**: enumerate every remaining file-mode helper, comment, test, and CLI path
after BU3/BU4 and classify it as removed, dev/test-only, legacy CLI, or defect.

**Current state**
- Gateway serving path is DB-only/fail-closed.
- Some source comments and helper names still reference legacy/core-only file
  mode.
- Low-level file helpers may remain for tests, exports, or CLI compatibility.

**Scope fence**
- Audit only first; do not delete paths until their owner and compatibility role
  are clear.
- Include `evidence_gate.py`, `case_ops.py`, `case_manager.py`, gateway startup,
  and tests.

**Hard constraints**
- Do not reintroduce production file authority.
- Preserve explicit export/offline artifacts that are documented as
  non-authoritative.

**Acceptance**
- Classification table is posted to Linear and, if durable, added to docs.
- Any reachable DB-mode file authority path becomes a follow-up or is fixed in
  the same issue.
- Stale comments that contradict current behavior are corrected.

## B2-2 - DB-First Case Create / Orphan Artifact Cleanup

**Goal**: verify and, if needed, close the portal case-create window where a
compatibility `CASE.yaml` artifact can be written before DB create/export
authority is established.

**Scope fence**
- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/sift-core/src/sift_core/case_metadata.py`
- tests around portal case create/export failure paths.

**Hard constraints**
- DB remains the authority for case metadata.
- CASE.yaml is an export/compatibility artifact only.
- Failure cleanup must not delete operator evidence or unrelated case files.

**Acceptance**
- Case create is DB-first or has deterministic cleanup for any orphan
  compatibility artifact.
- Simulated DB-create/export failure cannot leave an authoritative-looking
  orphan CASE.yaml.
- Tests prove the failure path.

## B2-3 - Legacy Active-Case Pointer Classification

**Goal**: decide whether remaining `~/.sift/active_case` readers/writers in
core CLI/file-mode utilities should be retired or explicitly documented as
legacy non-gateway compatibility.

**Scope fence**
- `packages/sift-core/src/sift_core/case_ops.py`
- `packages/sift-core/src/sift_core/case_manager.py`
- docs that describe active-case authority.

**Hard constraints**
- Gateway and MCP tool execution must continue to use request-scoped DB
  authority, not the pointer file.
- If retained, the pointer file must be documented as non-authoritative outside
  legacy CLI/dev workflows.

**Acceptance**
- Remaining pointer-file uses are either removed or clearly classified.
- Tests prevent pointer tampering from affecting DB-active gateway behavior.
