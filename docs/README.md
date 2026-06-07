# AgentIR — Autonomous Incident Response on a SIFT Workstation

> **DevPost Hackathon Submission — Autonomous Agentic IR**

## What We Built

**AgentIR** is a production-grade runtime that lets an AI agent (Hermes) drive digital forensics investigations on a SIFT Workstation VM — with the cryptographic auditability, chain-of-custody controls, and human-in-the-loop oversight that real incident response requires.

The AI agent never gets a shell. The evidence never changes silently. Every action is signed.

---

## The Problem

Modern incident response is bottlenecked at the analysis layer. A skilled examiner can acquire disk images, memory dumps, and network captures, but correlating artifacts across hundreds of gigabytes of evidence — triage baseline lookups, IOC enrichment, timeline reconstruction — takes days of manual work.

AI agents can accelerate this. But deploying an AI agent in a forensics environment creates new risks that existing tooling ignores:

- **Chain-of-custody breaks.** An agent with file access can silently modify evidence.
- **No audit trail for AI actions.** If the agent queries the wrong tool or acts on tampered evidence, there is no record.
- **No human gate.** An autonomous agent can propose findings and generate reports without examiner review.
- **Secrets leak through tool output.** API keys, credentials, and PII surface in agent reasoning context.

AgentIR solves all four.

---

## What Makes This Different

### 1. Evidence integrity is cryptographically enforced at the gateway layer

Before any AI tool call executes, the gateway verifies the live `evidence/` tree against the latest sealed manifest. Any modification, deletion, or new unregistered file blocks the agent and surfaces a structured violation to the examiner.

The examiner sealed the evidence with HMAC-SHA256. The agent cannot unseal it.

### 2. Every evidence decision is ledger-recorded and Solana-anchored

Every evidence action — register, seal, ignore, retire — appends a signed event to `evidence-ledger.jsonl`. The ledger is a forward-linked HMAC chain: each entry commits to the previous one, making retroactive insertion detectable.

After sealing, the manifest hash is anchored to Solana via an SPL Memo transaction, creating a public timestamped record of the sealed state that is independent of the SIFT VM.

### 3. The agent is a tool-caller, not a sysadmin

- No shell access — only MCP tools with explicit allow-lists
- No direct file writes to evidence directories
- Every tool call is audited: examiner, role, token fingerprint, source IP, backend, elapsed time
- Sensitive data in tool output (API keys, credentials, PII) is automatically redacted before reaching the agent's context

### 4. Human-in-the-loop is a cryptographic requirement, not a UI suggestion

Findings and timeline events proposed by the agent go into a pending-review queue. They cannot be committed to the case record without examiner review and HMAC challenge-response confirmation — the same password confirmation used for evidence sealing. Approval is appended to an immutable `approvals.jsonl` log.

### 5. OS-level hardening makes tampering auditable

The `chattr +i` immutable flag is set on every sealed evidence file. The kernel audit daemon records every attribute-change — so deliberately clearing the flag before tampering creates a dated kernel audit event. AppArmor denies the gateway process write access to evidence files at the MAC layer. An inotify watcher detects any change and immediately invalidates the gate cache.

---

## Architecture at a Glance

```
Analyst Machine                      SIFT VM (sift-mcps installed)
────────────────         ─────────────────────────────────────────────────
                         sift-gateway :4508 (HTTPS/TLS, mTLS-optional)
                         │
Hermes Agent ──HTTPS──▶  ├── /mcp       ← aggregate MCP endpoint (agent entry)
                         │    ├── auth middleware (Bearer + expiry + role)
                         │    ├── rate limit (per-examiner/service-token)
                         │    ├── evidence gate (chain verify + 30s TTL cache)
                         │    ├── response guard (secret/PII redaction)
                         │    └── audit envelope (every call → sift-gateway.jsonl)
                         │         ↓
                         │    stdio backends (FastMCP)
                         │    ├── forensic-mcp    (enrichment lookups)
                         │    ├── case-mcp        (case ops, evidence status)
                         │    ├── sift-mcp        (sandboxed shell, shell=False)
                         │    ├── report-mcp      (signed report generation)
                         │    ├── opensearch-mcp  (indexed artifact search)
                         │    ├── forensic-rag-mcp (semantic DFIR context)
                         │    └── windows-triage-mcp (baseline validation)
                         │
Browser      ──HTTPS──▶  └── /portal/   ← Examiner Portal (case-dashboard)
                              ├── case creation + management
                              ├── evidence intake + sealing workflow
                              ├── HMAC-verified examiner commits
                              ├── findings/timeline review queue
                              └── audit / chain-of-custody views
```

---

## Security Controls At a Glance

| Layer | Control | Standard |
|-------|---------|----------|
| Transport | TLS 1.2+ with self-signed CA, per-installation keypair | RFC 8446 |
| Authentication | Bearer token + PBKDF2-HMAC-SHA256 challenge-response | NIST SP 800-132 |
| Authorization | RBAC: examiner / service-agent roles, must-reset guard | Least-privilege |
| Evidence integrity | HMAC-SHA256 forward-linked ledger, SHA-256 per file | NIST SP 800-86 |
| Evidence gate | Pre-tool-call chain verify, 30s TTL + inotify invalidation | Fail-closed |
| Immutability | `chattr +i` via CAP_LINUX_IMMUTABLE, AppArmor DENY write | Defense-in-depth |
| Audit | Kernel auditd (catches `chattr -i`), gateway JSONL envelope | CJIS 5.4 |
| Anchoring | Solana SPL Memo — public timestamped hash commitment | Blockchain timestamping |
| Secret redaction | 25-pattern scanner on all agent tool output | OpSec |
| Human gate | HMAC-confirmed approval before any finding is committed | Chain of custody |
| Report | Evidence chain state embedded; integrity warning on unsealed | SWGDE |

---

## Documentation Index

| Document | Contents |
|----------|----------|
| [Architecture](architecture.md) | Component breakdown, data flows, security boundaries |
| [Security Controls](security-controls.md) | Every control, its implementation, and the threat it addresses |
| [Evidence Chain of Custody](evidence-chain-of-custody.md) | Manifest, ledger, Solana anchoring, verification workflow |
| [OS Hardening Guide](dfir-hardening-guide.md) | chattr, auditd, AppArmor, inotify — honest threat model |

---

## Running It

```bash
# One-shot install on a SIFT Workstation VM
git clone <repo> sift-mcps
cd sift-mcps
./install.sh

# Lightweight install (no Docker/RAG/ML deps)
./install.sh --skip-rag --skip-db --skip-docker

# Portal
https://SIFT_VM:4508/portal/

# Agent MCP endpoint
https://SIFT_VM:4508/mcp
```

Hackathon snapshot metrics are historical. Use `docs/migration/MIGRATION_STATE.md`
and phase runbooks for current verification evidence.
