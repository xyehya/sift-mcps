# Protocol SIFT Gateway System Overview

This overview is intentionally stable. It describes what the repository is and
how the major authority planes fit together. Active task state, forks, decisions
needed, and session handoffs live in Linear, not in this file.

For the public-facing product overview, start with [`README.md`](../../README.md).

## Purpose

Protocol SIFT Gateway turns a SIFT workstation into a governed agentic DFIR
platform. Agents can investigate through MCP tools, but the Gateway and portal
preserve examiner authority over evidence, case state, approvals, report
release, and credentials.

The system is built for repeatable case work:

- orient to the active case;
- register and seal evidence before analysis;
- run forensic tools through hardened `run_command` or durable jobs;
- index derived artifacts into OpenSearch;
- retrieve shared DFIR knowledge through pgvector RAG;
- draft findings and timeline events;
- approve supporting data and reports through the portal;
- retain audit and custody records for every sensitive step.

## Major Planes

### Gateway Policy Plane

`packages/sift-gateway/` is the agent entry point. It exposes MCP, mounts
registered backends, enforces active-case and evidence-gate policy, handles
agent credentials, redacts sensitive output, and writes audit/control-plane
records.

Agents should not bypass Gateway to call portal REST or backend services
directly.

### Core Forensic Plane

`packages/sift-core/` owns case-aware agent tools, command execution, evidence
chain checks, findings, timeline events, TODOs, and report primitives. Its
`run_command` path is designed for forensic command execution with policy,
sandboxing, provenance, and output labeling.

### Operator Portal Plane

`packages/case-dashboard/` is the human examiner surface at `/portal`. It owns
operator review and approval workflows such as case activation, evidence
seal/unseal, finding approval, report inclusion/export, agent credential
issuance, and health/status visibility.

### Control Plane

Supabase/Postgres is authoritative for cases, active-case state, evidence
objects, custody events, findings, reports, audit events, backend registry data,
and durable jobs. Filesystem and derived indexes are important, but they do not
replace control-plane authority.

### Evidence And Custody Plane

Evidence bytes are mounted or copied by the operator on the SIFT VM. The system
tracks evidence registration, seal state, immutable-file posture, unseal windows,
re-acquisition, custody events, and the case-level evidence gate. Agent analysis
is blocked when the evidence gate is not safe.

### Search And Derived Data Plane

`packages/opensearch-mcp/` provides case-scoped indexing and search for parsed
forensic data such as EVTX, timelines, memory-analysis output, and other
derived artifacts. OpenSearch is rebuildable derived data; the Gateway remains
the policy boundary.

### Reference Knowledge Plane

`packages/forensic-rag-mcp/` and `packages/forensic-knowledge/` provide shared
knowledge retrieval backed by pgvector. This plane is for reference material and
investigation guidance. It is not evidence, does not approve findings, and must
not silently absorb case evidence.

### Add-on Plane

Optional MCP backends such as OpenCTI and Windows triage integrate through
manifested add-on contracts. Add-ons can extend the tool surface without making
their internals part of the core install. Their manifests and Gateway registry
metadata define what is served and how the Gateway should treat it.

## Operating Model

Linear is the active operating pipeline for this project:

- Project: `ProtocolSIFTGateway`.
- Issues: unit of work for agents and humans.
- Comments: session notes, progress, blockers, handoffs, and validation proof.
- Milestones: larger work lanes or batches.
- Documents: durable policies, operating model, and decisions that should be
  visible outside a checkout.
- Relations and sub-issues: dependencies, forks, blockers, and parallel-agent
  coordination.

Repo docs should stay compact. Use this file and `README.md` for stable
overview and Linear for active work.

## Safety Invariants

- Gateway is the only policy boundary for AI-agent operations.
- Agents use MCP only.
- Portal REST is human-operator only unless an issue explicitly asks for route
  implementation or tests.
- Evidence is registered and sealed before analysis.
- Re-auth gates sensitive human actions.
- Reports contain approved findings and approved supporting data only.
- Shared RAG is reference knowledge only.
- No secrets or sensitive full evidence paths belong in commits, Linear comments,
  or documentation.
