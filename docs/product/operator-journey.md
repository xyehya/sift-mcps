# Operator Journey

Status: skeleton. Validation owner: BATCH-PDOC1 and BATCH-AUT2.
Last updated: 2026-06-09.

## Goal

The operator remains the authority for evidence handling, case activation,
credential issuance, review, approvals, and report export. The operator should
not need to touch code or side-channel APIs during the demo journey.

## Journey

1. Install or refresh the SIFT VM deployment.
2. Open the operator portal.
3. Sign in with the Supabase-backed operator account.
4. Complete forced reset if the account is in invited state.
5. Create a case.
6. Activate the case with re-auth.
7. Copy or mount evidence into the case evidence area.
8. Detect unregistered evidence from the portal.
9. Register evidence with names and descriptions.
10. Seal evidence with re-auth.
11. Issue a one-time AI agent credential.
12. Monitor agent jobs, proposed findings, timeline entries, TODOs, and status.
13. Approve, reject, or edit proposed findings and supporting data.
14. Generate and export an approved-only report with re-auth.
15. Export or review custody proof.

## Acceptance Signals

- The portal is sufficient for all operator-facing actions.
- No operator action requires raw database, local file, or curl access.
- Re-auth gates are visible and understandable.
- Evidence gate status is clear before and after sealing.
- Agent output appears as proposals until the operator approves it.
- Report eligibility clearly depends on approved data.

## Open Documentation Tasks

BATCH-PDOC1 should add screenshots or annotated flow diagrams after the portal
journey is re-tested. BATCH-AUT2 should add the exact demo-case operator script.

