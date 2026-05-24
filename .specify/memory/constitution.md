<!--
Sync Impact Report
Version change: template -> 1.0.0
Modified principles:
- PRINCIPLE_1_NAME -> I. Installer-First, Portal-First Runtime
- PRINCIPLE_2_NAME -> II. Gateway-Controlled Agent Boundary
- PRINCIPLE_3_NAME -> III. Chain of Custody and Human Approval
- PRINCIPLE_4_NAME -> IV. agentir-core as Source of Truth
- PRINCIPLE_5_NAME -> V. Verification Gates and Regression Discipline
Added sections:
- Security and Runtime Constraints
- Development Workflow
Removed sections:
- Template placeholder sections
Templates requiring updates:
- updated: .specify/templates/plan-template.md
- updated: .specify/templates/spec-template.md
- updated: .specify/templates/tasks-template.md
- not present: .specify/templates/commands/*.md
- reviewed: AGENTS.md
- reviewed: SIFT-MCPS-PLAN.md
- reviewed: TASKS.md
Follow-up TODOs: none
-->
# sift-mcps Constitution

## Core Principles

### I. Installer-First, Portal-First Runtime

sift-mcps MUST be designed around the final examiner workflow: one installer prepares the SIFT VM,
the examiner signs into `https://SIFT_VM:4508/portal/`, resets the default password if required,
creates or selects cases in the portal, and Hermes connects only after that through the gateway.
CLI operations are maintenance and emergency fallbacks, not the normal product interface. New
features MUST preserve portal-created case activation through `gateway.yaml` and
`AGENTIR_CASE_DIR`.

Rationale: the product exists to let an examiner operate a forensic runtime without granting the
remote AI agent shell or SSH access to the SIFT VM.

### II. Gateway-Controlled Agent Boundary

Hermes and all other agents MUST use only the aggregate HTTPS MCP endpoint `/mcp`. The gateway MUST
own bearer-token authentication, expiry checks, role enforcement, source attribution, audit
envelopes, backend routing, examiner identity injection, and response enrichment. Per-backend MCP
endpoints MAY exist only as local diagnostics and MUST NOT appear in installer output, Hermes
profiles, or supported workflow documentation.

Rationale: a single gateway boundary keeps security, audit, and enrichment behavior consistent
across all forensic tools.

### III. Chain of Custody and Human Approval

Every case write MUST preserve forensic custody: atomic file replacement, protected committed
artifacts, SHA-256 content hashes, append-only approvals, and HMAC verification ledger entries.
Hermes MAY propose findings and timeline events, but only an authenticated examiner MAY approve
them through the portal challenge-response flow. Final reports MUST include only approved,
verifiable findings and timeline entries.

Rationale: AI output is investigative assistance, not examiner approval. The report must be
auditable back to examiner action and immutable evidence records.

### IV. agentir-core as Source of Truth

Shared custody, identity, approval, verification, and case I/O behavior MUST live in
`agentir-core` and be imported by other packages. Duplicate implementations in portal, gateway,
or MCP packages MUST be removed when touched. `agentir-core` MUST remain a library: no
`sys.exit()`, no hardcoded non-overridable runtime paths, no `sudo` subprocess calls, and no new
gateway connectivity responsibilities.

Rationale: one tested library prevents divergent security behavior and keeps callers responsible
for UI, transport, and process-exit policy.

### V. Verification Gates and Regression Discipline

Structural, security, or workflow changes MUST be validated before handoff. At minimum, run
`uv run pytest packages/agentir-core/tests/ -v --tb=short` after structural changes and keep the
namespace gate
`grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."` at zero lines. Changes that
touch gateway, portal, auth, audit, installer, or MCP routing MUST include focused tests or smoke
checks that prove the relevant contract.

Rationale: this project is security-sensitive and workflow-sensitive; regressions are easy to hide
unless each phase keeps the gates current.

## Security and Runtime Constraints

- All remote MCP and portal access MUST be HTTPS when TLS is configured. Plain HTTP portal access
  MUST fail closed.
- Bearer tokens MUST use `agentir_gw_` or `agentir_svc_` prefixes with 192-bit entropy, timing-safe
  comparison, role metadata, and checked expiry. Raw tokens and HMAC responses MUST NOT be logged.
- `sift-mcp` MUST be the only command-execution gate. It MUST use `subprocess.run(shell=False)`,
  an allowed-binary catalog, sanitized arguments, validated paths, output limits, and audit logs.
- The namespace is `agentir`. New `vhir`, `VHIR`, `vhir_cli`, `~/.vhir`, or `/var/lib/vhir`
  references are prohibited in sift-mcps runtime code.
- `windows-triage-mcp` is permanently dropped and MUST NOT be restored, linked, or referenced as a
  supported component.
- The active case source of truth is `AGENTIR_CASE_DIR` as set by portal/gateway case activation.
  `~/.agentir/active_case` is not part of the runtime contract.

## Development Workflow

`SIFT-MCPS-PLAN.md` is the normative architecture and acceptance-criteria source. `TASKS.md` is the
execution checklist and session ledger. `AGENTS.md` is the coding-agent operating brief. Every
session MUST begin by reading `TASKS.md`; work that changes architecture, security behavior, or task
scope MUST also check `SIFT-MCPS-PLAN.md`. If the plan and task tracker contradict each other, stop
implementation and ask the user unless current code/tests clearly prove one side obsolete.

Task completion MUST be recorded in `TASKS.md` as each item is completed, and session notes MUST be
added before stopping. Edits SHOULD be targeted and preserve existing package boundaries. Reference
source repositories are read-only context; sift-mcps must stay decoupled, hardened, and portable.

## Governance

This constitution supersedes informal project habits and guides Spec Kit plans, specifications,
tasks, and reviews. Amendments require an explicit constitution update, a Sync Impact Report, and
review of dependent templates and runtime guidance docs. Any principle removal or redefinition is a
MAJOR version change. Adding or materially expanding principles or governance is a MINOR change.
Clarifications that do not change obligations are PATCH changes.

Compliance review is required for every feature plan and before handoff of implementation work.
Plans MUST document any constitution violations in Complexity Tracking and include a migration or
remediation path. Tasks MUST include the verification gates needed for the touched contracts.

**Version**: 1.0.0 | **Ratified**: 2026-05-24 | **Last Amended**: 2026-05-24
