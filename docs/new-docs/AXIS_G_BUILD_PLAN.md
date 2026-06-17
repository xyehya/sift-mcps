# Axis G - OpenSearch Data Compatibility

> Covers: packages/opensearch-mcp/**, packages/sift-gateway/src/sift_gateway/policy_middleware.py, docs/new-docs/DEVELOPER_ENTRYPOINT.md, install.sh, scripts/**
> Class: living-plan
> Last validated: dd4c656 (2026-06-18)

**Status**: plan-ready for OT3.
**Source**: live re-ingest and polish follow-ups after `XYE-28` renamed `vhir.*`
fields to `sift.*`.

## G1 - Re-Ingest Across `vhir` -> `sift` Boundary

**Goal**: close `XYE-40` by making force re-ingest of pre-rename cases
idempotent or safely self-repairing.

**Existing Linear issue**: reuse `XYE-40`.

**Current state**
- CSV-family artifacts can duplicate because `_id` recipes changed across the
  provenance schema boundary.
- Record-id artifacts were idempotent.
- Blanket case-wide deletion is unsafe because some pre-rename artifact families
  may have only `vhir.*` copies.

**Hard constraints**
- No blanket delete of a case index.
- Repair must be scoped by artifact/source and prove that replacement documents
  exist before deleting prior-schema copies.

**Acceptance**
- Force re-ingest across the boundary is idempotent for CSV-family artifacts or
  purges stale prior-schema docs safely per source.
- Tests cover mixed `vhir`/`sift` source documents.
- Live mixed-case repair proof is recorded if touched on the VM.

## G2 - Normalize Doubled `case-case-` Index Prefix

**Goal**: close `XYE-10` without breaking existing indices or gateway case
segment guards.

**Existing Linear issue**: reuse `XYE-10`.

**Acceptance**
- Impact map identifies index naming, query routing, and guard assumptions.
- Existing doubled-prefix indices remain queryable.
- Migration/alias strategy is documented before any live rename.

## G3 - OpenSearch Compatibility Repair Playbook

**Goal**: document safe operator recovery for mixed provenance or index-name
states.

**Scope fence**
- Docs and scripts only unless G1/G2 identify a required helper.

**Acceptance**
- Playbook distinguishes greenfield-safe behavior from mixed-case repair.
- Commands are scoped, dry-run capable where possible, and avoid destructive
  blanket deletes.

## G4 - Force Re-Ingest Idempotency Regression Tests

**Goal**: pin the compatibility behavior so future schema renames do not
reintroduce duplicate documents.

**Acceptance**
- Tests cover fresh `sift.*` re-ingest, mixed `vhir`/`sift` re-ingest, and
  artifact families with source-derived IDs.
