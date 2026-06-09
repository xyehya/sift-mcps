# Known Limitations and Areas of Improvement

Status: skeleton. Validation owner: BATCH-FRZ1.
Last updated: 2026-06-09.

## Current Known Limitations

| Area | Limitation | Demo impact | Improvement path |
| --- | --- | --- | --- |
| Re-auth | MVP uses a local HMAC/password bridge for some sensitive actions. | Acceptable if explained clearly. | Move to Supabase password re-auth/session verification. |
| OpenSearch | Single-node VM can report yellow cluster health. | Acceptable if indexing/search works. | Multi-node or replica-adjusted production profile. |
| Pre-context denials | Some pre-context denials remain Gateway local security telemetry, not `app.audit_events`. | Accepted MVP behavior. | Hardened DB projector for attributable denials. |
| RAG | Shared forensic knowledge is case-neutral (`case_id NULL`). | Correct for reference grounding; not case evidence. | Add case-derived chunks with provenance after ingest. |
| Product docs | This directory starts as a structured skeleton. | Must be filled before final presentation. | Run PDOC/AUT/SEC batches. |

## Improvement Backlog Template

| ID | Priority | Area | Improvement | Owner batch | Status |
| --- | --- | --- | --- | --- | --- |
| IMP-TODO-1 | TODO | TODO | Populate during post-MVP QA. | TODO | TODO |

## Demo Caveat Rules

- Caveats are acceptable only when they are explicit, bounded, and do not break
  the security thesis.
- Any caveat that weakens MCP-only autonomy, custody, report eligibility, or
  secret isolation must be fixed or called out as a blocker before freeze.

