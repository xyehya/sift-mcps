# JOB-0 Baseline Execution Checks

This note records the additive smoke checks for the first migration PR
candidate. They exercise current execution-critical behavior without live
OpenSearch, real forensic samples, schema migrations, workers, job APIs, or
runtime behavior changes.

## What These Tests Cover

- `packages/sift-core/tests/test_core_execution_baseline_smoke.py`
  - Evidence manifest sealing/status with a tiny temp case and temp evidence
    file.
  - Audit JSONL append shape using an explicit temp audit directory.
- `packages/opensearch-mcp/tests/test_opensearch_execution_baseline_smoke.py`
  - Current `case-{case}-{type}-{host}` OpenSearch index naming and JSON parser
    provenance/action shape with patched bulk writes.
  - Current file-backed ingest status JSON shape using a patched temp status
    directory.

The tests intentionally do not contact OpenSearch and do not read or mutate
real SIFT case, evidence, audit, active-case, or ingest-status paths.

## Targeted Commands

Run the baseline checks from the repository root with the repository virtual
environment:

```bash
PYTHONPATH=packages/sift-core/src:packages/sift-common/src \
  .venv/bin/python -m pytest packages/sift-core/tests/test_core_execution_baseline_smoke.py

PYTHONPATH=packages/opensearch-mcp/src:packages/opensearch-mcp/tests:packages/sift-core/src:packages/sift-common/src \
  .venv/bin/python -m pytest packages/opensearch-mcp/tests/test_opensearch_execution_baseline_smoke.py

PYTHONPATH=packages/opensearch-mcp/src:packages/opensearch-mcp/tests:packages/sift-core/src:packages/sift-common/src \
  .venv/bin/python -m pytest --import-mode=importlib packages/sift-core/tests/test_core_execution_baseline_smoke.py packages/opensearch-mcp/tests/test_opensearch_execution_baseline_smoke.py

git diff --check
```

The source-tree `PYTHONPATH` entries make the checks work without changing
package metadata. The OpenSearch tests still require the existing OpenSearch
MCP runtime/test dependencies to be available in `.venv`.

Practical touched-package suites:

```bash
PYTHONPATH=packages/sift-core/src:packages/sift-common/src \
  .venv/bin/python -m pytest packages/sift-core/tests

PYTHONPATH=packages/opensearch-mcp/src:packages/opensearch-mcp/tests:packages/sift-core/src:packages/sift-common/src \
  .venv/bin/python -m pytest packages/opensearch-mcp/tests
```

Some older tests in these packages may encode pre-migration assumptions. Treat
the JOB-0 smoke tests as the narrow baseline required before feature-bearing
migration work.
