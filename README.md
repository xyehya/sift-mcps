# Protocol SIFT Gateway

Protocol SIFT Gateway is an autonomous gateway to the SIFT workstation for
agentic DFIR operations. It lets AI coding and investigation agents work through
a governed MCP surface while human examiners keep authority over evidence,
case state, approvals, and report release.

The goal is not to replace the examiner. The goal is to give the examiner an
auditable, case-scoped operating layer where agents can search, triage, run
approved forensic commands, draft findings, and preserve chain-of-custody
discipline without bypassing human gates.

## What It Provides

- Case management with an active-case context for agent and portal operations.
- Evidence registration, sealing, unsealing, re-acquisition, custody events, and
  chain-status checks before agent analysis.
- A Gateway MCP boundary for agents, with policy middleware, active-case
  enforcement, tool gating, response redaction, and audit capture.
- A human operator portal for sensitive actions such as case activation,
  evidence seal/unseal, finding approval, report inclusion, export, and agent
  credential issuance.
- Hardened `run_command` execution for forensic tools, including allowlist
  policy, argument parsing, runtime environment scrubbing, sandbox layers,
  output labeling, and provenance.
- OpenSearch-backed indexing and search for case artifacts, timelines, parsed
  forensic events, memory analysis output, and other derived case data.
- A shared knowledge RAG plane backed by pgvector for reference material such as
  DFIR techniques, Sigma, ATT&CK-style context, and tool guidance. This plane is
  supporting context, not case evidence.
- Finding, timeline, and report workflows that keep approved findings and
  approved supporting data separate from drafts.
- Auditability through database-backed control-plane records, custody events,
  tool receipts, sanitized proof, and explicit operator re-auth for high-impact
  actions.
- Extensibility through add-on MCP backends, with manifests and contracts for
  integrations such as OpenCTI, Windows triage, and future forensic tools.

## Architecture

Protocol SIFT Gateway is organized around a few authority planes:

- `sift-gateway`: the policy boundary and MCP aggregation point for agents.
- `sift-core`: case-aware forensic tools, evidence-chain logic, command
  execution, findings, timeline, and reporting primitives.
- `case-dashboard`: the examiner portal for human review and approval.
- Supabase/Postgres: the authoritative control plane for cases, credentials,
  jobs, audit events, evidence custody, findings, and report state.
- OpenSearch: the rebuildable, case-scoped derived search plane.
- `forensic-rag-mcp` and `forensic-knowledge`: the shared reference knowledge
  plane backed by pgvector.
- Add-on MCP backends: optional integrations registered through the Gateway
  contract rather than hard-coded into the core install.

Agents enter through Gateway MCP. Human operators use the portal. Evidence bytes
are mounted or copied by the operator on the SIFT VM, then registered and sealed
before agent analysis.

## Core Invariants

- Gateway is the only policy boundary for portal and AI-agent operations.
- Supabase/Postgres is the authoritative control plane.
- Agents use MCP only. Portal REST is for human-operator workflows and tests.
- Evidence bytes are handled by the operator on the SIFT VM, not silently fetched
  or imported by agents.
- Evidence must be registered and sealed before analysis.
- Sensitive actions require re-auth: case activation, evidence seal/unseal,
  evidence ignore/retire, finding approval, report inclusion/export, and agent
  credential issuance.
- Reports include approved findings and approved supporting data only.
- Shared RAG is knowledge/reference only. Case evidence must not be silently
  embedded into shared pgvector.
- No raw JWTs, service-role keys, DSNs, passwords, private keys, or sensitive
  full evidence paths belong in commits, issue comments, or documentation.

## Operating Model

Active work is tracked in Linear under the `ProtocolSIFTGateway` project. Linear
issues are the unit of work; issue comments are the session notes and handoffs;
milestones group larger lanes; documents hold durable policies and decisions.

Repo documentation is intentionally narrower:

- This `README.md` is the stable product and architecture overview.
- `docs/migration/` is historical proof and migration context, not the active
  queue.
- Heavy temporary plans, research notes, and one-off specs should stay outside
  the default repo context unless a Linear issue links them for targeted use.

## Repository Layout

- `packages/sift-gateway/`: Gateway, MCP aggregation, policy middleware, portal
  routes, backend registry, jobs, and control-plane integration.
- `packages/sift-core/`: case tools, command execution, evidence chain,
  findings, timeline, and reporting.
- `packages/case-dashboard/`: examiner portal backend and frontend.
- `packages/opensearch-mcp/`: case-scoped OpenSearch ingest and search backend.
- `packages/forensic-rag-mcp/`: pgvector-backed knowledge retrieval backend.
- `packages/forensic-knowledge/`: curated reference knowledge data and helpers.
- `packages/opencti-mcp/`: optional OpenCTI threat-intelligence backend.
- `packages/windows-triage-mcp/`: optional Windows baseline and triage backend.
- `configs/`: AppArmor, audit, Supabase, and systemd configuration.
- `supabase/migrations/`: authoritative database schema and control-plane
  migrations.
- `scripts/`: installer and operational helper scripts.

## Install And Run

The normal SIFT VM install path is:

```bash
git clone <repo-url>
cd sift-mcps
./install.sh
```

The installer stages the runtime into `/opt/sift-mcps`, provisions services,
and wires the local control plane. Development and validation use the repo
`uv` workspace:

```bash
uv run --extra dev --extra full pytest <targeted test paths>
python3 scripts/validate_docs.py
git diff --check
```

Use targeted package tests for implementation work and record live VM proof only
when an issue requires it.
