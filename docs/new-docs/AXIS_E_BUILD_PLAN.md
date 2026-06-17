# Axis E - Runtime / DB Hot-Path Performance

> Covers: packages/sift-core/src/sift_core/investigation_store.py, packages/sift-core/src/sift_core/case_ops.py, packages/sift-core/src/sift_core/case_manager.py, packages/sift-core/src/sift_core/reporting.py, packages/sift-core/tests/**
> Class: living-plan
> Last validated: dd4c656 (2026-06-18)

**Status**: plan-ready for OT3.
**Source**: follow-up `XYE-34` after Axis B made case metadata
DB-authoritative on hot orientation/status/report paths.

## E1 - Pool DB-Authoritative Case Metadata Reads

**Goal**: avoid opening a fresh psycopg connection for every
`resolve_case_metadata()` call while preserving fail-closed DB authority.

**Existing Linear issue**: reuse `XYE-34`.

**Current state**
- `PostgresCaseStore._connect()` opens `psycopg.connect(self._dsn)`.
- `resolve_case_metadata()` constructs `PostgresCaseStore(dsn)` per call.
- Callers include `case_status_data`, `_refuse_closed_case_db`,
  `get_case_status`, `generate_report_data`, and `get_examiner`.

**Scope fence**
- `packages/sift-core/src/sift_core/investigation_store.py`
- Focused tests for connection reuse/provider pooling.
- No semantic change to metadata shape or DB-authority failure behavior.

**Hard constraints**
- Missing DSN, missing context, missing row, and DB errors still raise
  `InvestigationStoreError` in DB-authority mode.
- No long-lived unsafe global connection that crosses process/fork boundaries.

**Acceptance**
- Repeated metadata reads reuse a pool/provider instead of creating a TCP
  connection each time.
- Existing BU1/BU3 fail-closed tests still pass.
- A fake connection factory/pool test proves reuse.

**Validation**
- `uv run --extra dev --extra full pytest packages/sift-core/tests/test_bu1_db_case_metadata.py packages/sift-core/tests/test_bu3_file_readers_unreachable.py packages/sift-core/tests/test_case_ops.py`
