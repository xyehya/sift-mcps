# Axis C - Custody-Grade Test Backfill

> Covers: packages/sift-common/src/sift_common/audit.py, packages/sift-common/tests/, packages/opencti-mcp/**, packages/windows-triage-mcp/**, pyproject.toml, scripts/check_package_coverage.py
> Class: living-plan
> Last validated: dd4c656 (2026-06-18)

**Status**: plan-ready for OT4.
**Source assessment gap**: the 2026-06-15 assessment flagged uneven test
distribution: `sift-common` had no direct `AuditWriter` tests, while
`opencti-mcp` and `windows-triage-mcp` had very low test:src ratios. `XYE-31`
added baseline tests, so this axis now targets adversarial custody and risk-path
coverage rather than "first test exists".

## C1 - Adversarial `AuditWriter` Custody Tests

**Goal**: directly test the JSONL audit mirror's durability behavior under the
failure modes that matter for forensic defensibility.

**Current state**: `packages/sift-common/tests/test_audit.py::TestAuditWriter`
tests normal logging, explicit audit dir, sequence increment, filters, examiner
override, and DB-authority no-dir behavior. It does not cover corrupted `.seq`,
JSONL resume fallback, fsync/write failures, date rollover, or concurrent
writers.

**Scope fence**
- `packages/sift-common/tests/test_audit.py`
- Test-only helpers under `packages/sift-common/tests/`
- No production code unless a test exposes a real bug.

**Hard constraints**
- Keep the JSONL trail described as an audit mirror; Postgres remains authority.
- Do not weaken DB-authority behavior or change audit IDs for existing callers
  without an explicit migration note.

**Acceptance**
- Tests cover sidecar `.seq` corruption, missing sidecar with JSONL resume,
  malformed JSONL lines, fsync/write failure handling, day rollover, and
  concurrent logging.
- Any production fix needed by the tests is narrow and preserves current public
  audit entry shape.

**Validation**
- `uv run --extra dev --extra full pytest packages/sift-common/tests/test_audit.py`
- `uv run --extra dev --extra full python scripts/check_package_coverage.py`

## C2 - OpenCTI MCP Risk-Path Tests

**Goal**: cover OpenCTI add-on behavior that can affect operator trust without
requiring a live OpenCTI instance.

**Scope fence**
- `packages/opencti-mcp/tests/**`
- Mock external OpenCTI client/API calls.
- Production edits only for bugs exposed by tests.

**Hard constraints**
- No network dependency in CI.
- No raw secrets in fixtures, snapshots, or failure messages.
- Preserve add-on manifest and gateway contract compatibility.

**Acceptance**
- Tests cover manifest validation, namespace/tool surface consistency, client
  error translation, IOC validation edge cases, capability/config errors, and
  no-secret response behavior.
- Coverage floor can be ratcheted upward for `opencti-mcp` after the tests land.

**Validation**
- `uv run --extra dev --extra full --extra opencti pytest packages/opencti-mcp/tests`

## C3 - Windows-Triage MCP Risk-Path Tests

**Goal**: cover Windows-triage config, database availability, and tool error
behavior with bounded fixtures instead of the optional 12GB registry baseline.

**Scope fence**
- `packages/windows-triage-mcp/tests/**`
- Tiny synthetic databases/fixtures only.
- No live download in CI.

**Hard constraints**
- Preserve strict configuration error behavior for invalid integer env vars.
- Do not require the optional full registry baseline for tests.
- No managed-Python or network side effects.

**Acceptance**
- Tests cover missing/degraded baseline DBs, strict env parsing, tool error
  result shape, path bounds, and surface snapshot drift.
- Coverage floor can be ratcheted upward for `windows-triage-mcp`.

**Validation**
- `PYTHONPATH=packages/windows-triage-mcp/tests uv run --extra dev --extra full --extra windows-triage pytest packages/windows-triage-mcp/tests`

## C4 - Mixed Package-Root Test Invocation Hygiene

**Goal**: decide whether the known mixed-root pytest import-name collision should
be fixed or simply documented as an invocation caveat.

**Current state**: `XYE-31` recorded that package-root local pytest invocations
can collide while the repo CI path is stable.

**Acceptance**
- Either a focused fix lands, or `DEVELOPER_ENTRYPOINT.md` / AGENTS instructions
  explicitly preserve the supported invocation forms.
- No churn to package layouts unless it improves local validation materially.
