# SIFT Conductor Handoff

Status: active conductor handoff.
Last updated: 2026-06-09 after BATCH-AUT1 integration.
Root repo: `/home/yk/AI/SIFTHACK/sift-mcps`
Primary branch: `revamp/spg-v1`

This file is the fast jump-in guide for conductor sessions. It does not replace
the source-of-truth docs. Start here to get oriented, then verify current state
from the referenced files before editing, merging, deploying, or testing.

## Mission

Complete the post-MVP QA and demo-freeze phase for SIFT MCP with the hackathon
theme centered on secure AI-agent autonomy for DFIR.

The product thesis to prove:

- the operator controls cases, evidence, credentials, approvals, report export,
  and custody through the portal;
- the AI agent investigates through Gateway MCP only;
- Gateway enforces auth, active case, scopes, evidence gate, response shaping,
  audit, rate limits, and job enqueue;
- Supabase/Postgres is authority for mutable DFIR state;
- OpenSearch, pgvector RAG, OpenCTI, Windows triage, and forensic knowledge are
  derived/reference planes only;
- agent-visible outputs must stay path-free, secret-free, scoped, concise, and
  provenance-linked.

## Required Reading Order

Every conductor session should read these first:

1. `AGENTS.md`
2. `docs/migration/Migration-Spec.md`
3. `docs/migration/task-batches.md`
4. `docs/migration/Session-Notes.md`
5. `docs/product/README.md`

Then read batch-owned product docs as needed:

- Architecture/journeys: `docs/product/architecture.md`,
  `docs/product/data-flows-and-lifecycles.md`,
  `docs/product/operator-journey.md`,
  `docs/product/ai-agent-journey.md`,
  `docs/product/interaction-model.md`,
  `docs/product/code-structure.md`
- Contracts/autonomy: `docs/product/api-contracts.md`,
  `docs/product/mcp-contracts.md`,
  `docs/product/agent-autonomy-assessment.md`
- Security/freeze: `docs/product/security-architecture.md`,
  `docs/product/security-assessment.md`,
  `docs/product/known-limitations-and-improvements.md`,
  `docs/product/demo-runbook.md`

## Current Repo State

Last verified root merge before the BATCH-AUT1 tracker/session-note commit:

- `11a95f8` - `Merge BATCH-AUT1 agent autonomy assessment`

Completed post-MVP batches:

- BATCH-PQA0 - Post-MVP QA/product documentation operating model
- BATCH-PDOC1 - Product architecture, journeys, lifecycles, and code map
- BATCH-PDOC2 - API, MCP, and interaction contract documentation
- BATCH-SEC1 - Security architecture and assessment baseline
- BATCH-AUT1 - AI agent autonomy and MCP tool-surface assessment

Open batches:

- BATCH-INST1 - Installer and component hardening QA
- BATCH-AUT2 - Demo-case autonomous investigation benchmark
- BATCH-FRZ1 - Final freeze rehearsal, limitations, and demo runbook

Important local note:

- Root `.mcp.json` may exist as local MCP configuration. Treat it as local/user
  state. Do not commit it without explicit review and secret scan.

## AUT1 Integrated State

AUT1 is integrated in root `revamp/spg-v1`.

- Worktree: `/home/yk/AI/SIFTHACK/sift-mcps-aut1`
- Branch: `revamp/postmvp-aut1`
- Worker commit: `3813033` -
  `BATCH-AUT1: live MCP autonomy assessment + job_status error-leak fix`
- Conductor branch commit: `0d27706` -
  `Close AUT1 low-friction tool guidance gaps`
- Root merge: `Merge BATCH-AUT1 agent autonomy assessment`

AUT1 landed changes:

- `docs/product/agent-autonomy-assessment.md`
- `docs/product/mcp-contracts.md`
- `docs/product/ai-agent-journey.md`
- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-core/src/sift_core/execute/security.py`
- `packages/sift-core/src/sift_core/execute/tools/discovery.py`
- `packages/sift-core/tests/test_execute_executor.py`
- `packages/sift-gateway/src/sift_gateway/job_tools.py`
- `packages/sift-gateway/tests/test_mvp_binding_job_tools.py`

AUT1 reported:

- 17 live MCP calls against `case-v1gate-06081857`
  (`57a06521-c9b8-4654-92ac-42b4f2bb0915`).
- Live-proven tools: `evidence_info`, `capability_guide`, `get_tool_help`,
  `list_existing_findings`, `manage_todo`, `job_status`, `run_command`,
  `run_command_job`.
- Surface scores: Discoverability 2, Sufficiency 2, Context 2,
  Composability 3, Error recovery 2, Provenance 3, Security 3,
  Autonomy friction 2.
- AUT1-B3 fixed in code: malformed `job_status` IDs now return typed
  `invalid_job_id`; durable-job tools return generic `internal_error` for
  unexpected exceptions while logging details server-side.
- AUT1-B4 fixed in the conductor pass: `run_command` and `run_command_job`
  descriptions now distinguish synchronous non-pollable `rc-*` receipts from
  durable pollable UUID jobs.
- AUT1-B5 fixed in the conductor pass: evidence-dir deletion denial now tells
  the agent to hand back to the operator/approved evidence workflow, not to
  leave the MCP harness.
- AUT1-B6 fixed in the conductor pass: `get_tool_help("run_command")` no longer
  contains a static absolute-path example that self-redacts.
- AUT1 validation: gateway job/tool tests, gateway D2/B1 suites, core executor
  tests, migration validators, `git diff --check`, and touched-file
  secret-shape scan passed before merge.

AUT1 open findings:

- AUT1-B1, HIGH, open: `case_info`/`evidence_info` orientation is file-backed
  and can contradict DB-authority evidence gate. Live AUT1 saw orientation say
  unsealed/ok=false while `run_command` executed because DB gate was OK. This is
  a stall trap for autonomous agents.
- AUT1-B2, MEDIUM, open: `rag_search_case` absent from live MCP catalog because
  `rag_query_service` was not wired in that deployment. Agent grounding through
  pgvector RAG was MCP-unreachable.
AUT1 readiness decision:

- AUT2 is conditionally unblocked only if the conductor ensures the demo Gateway
  has `rag_search_case` wired and scoped, and the demo case has file-manifest
  and DB evidence-gate state aligned or AUT1-B1 is fixed.
- AUT1-B3/B4/B5/B6 fixes are unit-proven only until the Gateway is redeployed
  and live re-verified.

## Immediate Conductor Steps

1. Finish this integration commit: root validators, `git diff --check`, secret
   scan, and clean status except local `.mcp.json` if present.
2. Run BATCH-INST1 or an equivalent conductor remediation pass before AUT2 to:
   - redeploy the AUT1-B3/B4/B5/B6 Gateway/core fixes;
   - verify `~/.sift/*.env` permissions;
   - verify per-case `agent_runtime` ACLs;
   - verify Gateway/worker restart and health;
   - verify OpenSearch setup;
   - wire and live-prove `rag_search_case`;
   - verify pgvector RAG corpus availability.
3. Resolve AUT1-B1 before AUT2 or prepare the demo case so DB gate and
   file-backed orientation agree. Prefer a real fix over case grooming if time
   allows.
4. Launch BATCH-AUT2 only when the agent can investigate the selected demo case
   through MCP alone, without hidden curl/shell/DB/OpenSearch side channels.

## Live VM References

Do not store raw secrets in this file.

- VM host/user: `192.168.122.81` / `sansforensics`
- Portal/Gateway: `https://192.168.122.81:4508/portal/`
- MCP endpoint: `https://192.168.122.81:4508/mcp`
- Deployed repo on VM: `~/sift-mcps-test`
- VM Python: `/usr/bin/python3.12`
- Required VM env discipline:
  - `UV_NO_MANAGED_PYTHON=1`
  - `UV_PYTHON_DOWNLOADS=never`
- User-level services:
  - `sift-gateway.service`
  - `sift-job-worker.service`

Use local environment variables for passwords/tokens when live testing. Do not
write them into repo files, docs, prompts, screenshots, or logs.

## MCP Autonomy Rules

When assessing AI-agent autonomy:

- Only calls made through configured Gateway MCP count as agent capability.
- Curl, SSH, shell, direct DB, direct OpenSearch, local filesystem, and source
  reads are diagnostics only and must be labeled as diagnostics.
- Diagnostics may explain a failure, but they do not prove agent autonomy.
- If the agent needs side-channel help to proceed, record that as an autonomy
  defect.
- Context bloat, vague errors, missing recovery hints, missing provenance, and
  contradictory tool state are product defects.
- Real evidence benchmark should be portal-prepared, sealed, and handed to the
  agent only through MCP credentials and a case brief.

## Batch Graph From Here

Recommended path:

1. Run BATCH-INST1 or conductor remediation for live deploy/readiness,
   especially AUT1-B2 and live re-verification of AUT1-B3/B4/B5/B6.
2. Fix or operationally neutralize AUT1-B1.
3. Run BATCH-AUT2 against the hackathon E01/raw-memory demo case through MCP
   only.
4. Run BATCH-FRZ1 final freeze, limitations, improvement backlog, and demo
   runbook.

Parallelism:

- AUT2 should be serial after BATCH-INST1/readiness and the B1/B2 gates are
  handled.
- FRZ1 is last.

## Validation Commands

Baseline validation for conductor docs/governance changes:

```bash
python3 scripts/validate_docs.py
python3 scripts/validate_migration_docs.py
git diff --check
```

Targeted AUT1 validation:

```bash
uv run pytest packages/sift-gateway/tests/test_mvp_binding_job_tools.py
uv run pytest packages/sift-gateway/tests/test_mvp_d2_jobs_and_authority.py packages/sift-gateway/tests/test_mvp_b1_policy_redaction.py
uv run pytest packages/sift-core/tests/test_execute_executor.py
```

Docs secret-shape scan pattern:

```bash
rg -n "postgres(ql)?://|service_role\s*[:=]|anon_key\s*[:=]|password\s*[:=]|BEGIN (RSA|OPENSSH|PRIVATE)|sk-[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{20,}" docs Conductor.md
```

## Standing Constraints

- Do not use stale K2-K5 or V1 worker directories as source of truth.
- Use clean worktrees from `revamp/spg-v1` for remaining batches.
- Parallel worker branches do not edit `docs/migration`; conductor updates
  tracker/session notes after integration.
- Keep implementation changes tightly scoped.
- Do not revert unrelated user or worker changes.
- Do not commit local MCP config or secrets.
- Product docs may be expanded under `docs/product/**`; migration state remains
  in the three-file `docs/migration` model only.
