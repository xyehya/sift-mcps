# Axis F - Supply-Chain And Data-Package Trust

> Covers: install.sh, scripts/setup-addon.sh, uv.lock, .github/workflows/ci.yml, packages/forensic-rag-mcp/**, packages/forensic-knowledge/**, packages/windows-triage-mcp/**, packages/opensearch-mcp/**, docs/drafts/operator/**
> Class: living-plan
> Last validated: dd4c656 (2026-06-18)

**Status**: plan-ready for OT2.
**Source assessment/operator gap**: a forensic platform must not treat packages,
rules, baselines, RAG indexes, or threat-intel/reference data fetched from the
internet as trust-on-first-use inputs.

## F0 - Network Fetch Inventory And Verification Map

**Goal**: enumerate every install-time, setup-time, and runtime network fetch and
document how it is verified today.

**Scope fence**
- `install.sh`
- `scripts/setup-addon.sh`
- `packages/forensic-rag-mcp/src/rag_mcp/**`
- Windows-triage database download scripts
- OpenSearch/Hayabusa/Sigma/rule/data setup paths

**Hard constraints**
- Discovery only; no behavior change.
- Classify fetches by install-time/runtime/operator-triggered/automatic.

**Acceptance**
- Inventory table includes source URL/API, trigger, destination, verification,
  offline behavior, provenance recording, and failure mode.
- Gaps become F2/F3/F4 implementation issues with source anchors.

## F1 - Fix Win-Triage Setup UV Discipline

**Goal**: close `XYE-43`: the win-triage downloader must not re-resolve the
runtime venv, download managed Python, downgrade Python, or drop `full` deps.

**Existing Linear issue**: reuse `XYE-43`.

**Current state**
- `stage_runtime_command()` is hardened with `UV_NO_MANAGED_PYTHON=1`,
  `UV_PYTHON_DOWNLOADS=never`, `--python "$PYTHON_BIN"`, and `--inexact`.
- `setup_wintriage()` still runs the downloader via
  `"$UV_BIN" run --project "$SIFT_MCPS_ROOT" --extra windows-triage python -m ...`
  without those safeguards.

**Acceptance**
- Downloader uses the existing runtime venv Python directly, or invokes uv with
  no-managed-Python, no-downloads, explicit `/usr/bin/python3.12`, `--extra full`,
  and `--extra windows-triage`.
- Other `setup-addon.sh` uv-run sites are audited.
- Live-VM recovery path is no longer needed after baseline download.

## F2 - Installer And Download Integrity Manifest

**Goal**: extend the existing `verify_sha256()` pattern into a maintained
manifest for every installer-managed downloaded artifact.

**Scope fence**
- `install.sh`
- installer docs
- no data-plane provenance DB work in this unit.

**Acceptance**
- Downloaded binaries/data archives have pinned URL/version/hash metadata.
- Integrity mismatches fail closed with actionable operator guidance.
- Offline-mode instructions name the exact staged file and expected hash.

## F3 - Forensic Data-Package Provenance

**Goal**: record provenance for data packages that can influence findings:
RAG indexes/sources, Hayabusa/Sigma rules, Windows-triage baselines, and similar
reference data.

**Scope fence**
- Pick DB table vs signed manifest after F0.
- Do not embed case evidence into shared RAG.

**Hard constraints**
- Case evidence remains isolated from shared pgvector unless `XYE-6` changes the
  policy.
- Data provenance must not include secrets or raw case paths.

**Acceptance**
- Operators can inspect source, version/ref, hash, fetched_at, verifier, and
  status for each forensic data package.
- Mismatch or missing provenance produces a clear degraded/blocked status.

## F4 - SBOM And Dependency Audit Artifact

**Goal**: add CI artifacting for dependency inventory and vulnerability review.

**Scope fence**
- CI only unless the chosen tool requires config.
- Use `uv.lock` as dependency source of truth.

**Acceptance**
- CI emits an SBOM or equivalent dependency inventory artifact.
- Vulnerability scanning policy is documented as warn-only or blocking.
