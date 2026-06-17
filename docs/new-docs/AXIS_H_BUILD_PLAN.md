# Axis H - Add-On Behavioral Admission Controls

> Covers: packages/sift-gateway/src/sift_gateway/backends/**, packages/sift-gateway/src/sift_gateway/rest.py, packages/sift-gateway/src/sift_gateway/server.py, packages/case-dashboard/**, scripts/probe_backends.py, packages/*/sift-backend.json
> Class: living-plan
> Last validated: dd4c656 (2026-06-18)

**Status**: plan-ready for OT2.
**Source**: `XYE-24` added static manifest contradiction lint. `XYE-25`
captures the durable control: verify what add-on tools do, not only what the
manifest says.

## H1 - Synthetic Probe Design For Add-On Admission

**Goal**: design a side-effect-safe probe protocol for registered backends before
their tools are exposed to agents.

**Existing Linear issue**: reuse `XYE-25` as the parent or first executable
issue.

**Hard constraints**
- Never execute probes against real cases/evidence.
- Do not require live OpenCTI or optional Windows-triage large baselines.
- Operator re-auth remains required for backend registration/start.

**Acceptance**
- Probe design specifies synthetic case/evidence context, allowed call shapes,
  timeout/resource limits, and report schema.
- Operator decision is recorded: advisory report vs blocking gate.

## H2 - Tool Surface And Schema Probe Harness

**Goal**: compare live `tools/list` / `inputSchema` with the manifest and catch
schema drift before exposure.

**Acceptance**
- Probe reports missing, extra, or schema-incompatible tools.
- Results are stored or surfaced without exposing secrets.

## H3 - Behavioral Cross-Check Probe

**Goal**: detect tools whose accepted arguments or returned output indicate
case/evidence/path behavior that contradicts non-case-scoped declarations.

**Acceptance**
- Probe covers path-like args, evidence refs, case IDs, mutating/write outputs,
  and declared `default_case_scoped` / authority metadata.
- Suspicious behavior is reported with a minimal reproducer.

## H4 - Portal Operator Report And Gating UX

**Goal**: surface probe results during backend register/start so operators can
make an informed decision.

**Acceptance**
- Portal shows pass/warn/fail state, details, and restart-to-apply implications.
- If blocking policy is chosen, failed probes prevent exposure to agents.

## H5 - Admission Regression Fixtures

**Goal**: keep the probe honest with fixture backends.

**Acceptance**
- Fixtures cover honest reference backend, honest case-scoped backend,
  manifest/schema drift, and contradictory behavior.
