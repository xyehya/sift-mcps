# Security Assessment Report

Status: template. Validation owner: BATCH-SEC1.
Last updated: 2026-06-09.

## Scope

Assess the post-MVP SIFT Gateway, Portal, MCP tools, Supabase/Postgres authority
plane, worker/job execution path, OpenSearch/RAG derived planes, evidence
custody flow, and report export path.

## Methodology

- Static review of security-critical code paths.
- Targeted tests for auth, authorization, evidence gate, response redaction,
  audit, custody, jobs, and report approval.
- Live VM smoke and negative testing where safe.
- Agent-eye MCP assessment from BATCH-AUT1.
- Secret/path leak scans on agent-visible and report-visible outputs.

## Finding Register

| ID | Severity | Status | Component | Finding | Evidence | Remediation |
| --- | --- | --- | --- | --- | --- | --- |
| SEC-TODO-1 | TODO | TODO | TODO | Populate during BATCH-SEC1. | TODO | TODO |

## Severity Rubric

| Severity | Meaning |
| --- | --- |
| Critical | Agent or remote user can bypass evidence/approval authority, access secrets, or tamper with custody/report truth. |
| High | Auth, authorization, path isolation, or report integrity failure with realistic exploit path. |
| Medium | Defense-in-depth gap, degraded auditability, or limited information leak. |
| Low | Hardening or clarity issue with low exploitability. |
| Informational | Documentation, test coverage, or operational improvement. |

## Required Outputs

BATCH-SEC1 should end with:

- completed finding register;
- list of tests run and live checks performed;
- accepted residual risks;
- blockers that must be fixed before demo freeze;
- links back to `Session-Notes.md` evidence.

