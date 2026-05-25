# Plan: sift-mcps — Portable MCP Runtime for Digital Forensics

## Tracking Contract

This file is the normative project spec: architecture, security requirements, behavioral contracts,
and phase acceptance criteria. It may describe completed work because completed behavior still needs
to remain testable.

`TASKS.md` is the execution tracker: checklists, implementation notes, current next step, and session
ledger. When a task is completed, update `TASKS.md`; update this file only when the spec itself
changes.

If this file and `TASKS.md` disagree:
1. Stop implementation work.
2. Identify the exact conflicting lines.
3. Ask the user which spec should win unless the code/tests already prove one side is obsolete.

## Purpose and End State

Extract and repackage forensic MCP server infrastructure into a single portable Python project
(`/sift-mcps`) installable on any SIFT Workstation VM via a one-shot `install.sh` script.
The original Valhuntir repo at `/home/yk/AI/SIFTHACK/Valhuntir` is a read-only reference for
workflow ideas and source functions. sift-mcps is not a straight replication: we cherry-pick,
improve, decouple, harden, and make the package portable/flexible.

**The operational picture:**
- The SIFT VM is prepared by one installer: packages, gateway, portal UI, OpenSearch Docker,
  enrichment/RAG assets, TLS, credentials, service token, and systemd service
- The human examiner/operator enters through the **Examiner Portal** and creates each new case there
- Portal case creation writes the selected case directory, canonical case files, and active gateway case config
- The AI agent (Hermes) runs on a **separate analyst machine** and connects over HTTPS to the aggregate gateway MCP endpoint
- The agent drives investigation through MCP tools; the examiner maintains control via case creation and human-in-the-loop approval
- The final deliverable is a cryptographically auditable case report

**What we are NOT doing:**
- Granting the agent direct shell access (sift-mcp is the sandboxed gate)
- Replacing the portal with CLI approval (portal is the primary interface)
- Requiring SSH or shell access for normal examiner case creation
- Building or controlling a Windows execution host. `wintools-mcp` remains out of scope.
- Copying the source repos as-is (we are refactoring, hardening, decoupling)

## Final Required Workflow

This workflow is the product contract. Implementation phases, tests, and docs must trace back to it.

1. **Install once on a SIFT VM**
   - Run `install.sh` from the repo root.
   - Installer validates OS/runtime prerequisites, syncs all packages, creates `/var/lib/agentir/`,
     deploys OpenSearch Docker, prepares enrichment/RAG assets, generates TLS material, writes
     `~/.agentir/gateway.yaml`, installs/enables `sift-gateway`, and verifies health.
   - For lightweight/offline validation, `install.sh --skip-rag --skip-db --skip-docker` installs
     the core gateway, portal, case, report, sift, forensic, OpenSearch client backend, TLS,
     credentials, and service token without downloading RAG ML dependencies, triage DBs, or
     starting OpenSearch Docker.
   - Installer creates a default examiner account and marks it `must_reset_password: true`.
   - Installer generates the first Hermes service token and prints/saves operator handoff material.

2. **Examiner signs in through the portal**
   - Browser goes to `https://SIFT_VM:4508/portal/`.
   - Default password must be reset on first login before case or token operations are allowed.
   - Portal sessions use secure cookies; commit actions still require HMAC password confirmation.

3. **Examiner creates a case from the portal**
   - Examiner submits case metadata and target directory.
   - Portal/gateway validates paths and `CASE.yaml` schema, creates the directory and all canonical files,
     writes protected files atomically, updates `gateway.yaml → case.dir`, sets `AGENTIR_CASE_DIR`,
     and restarts/reloads backends.
   - Manual `gateway.yaml` case edits are administrator fallback only.

4. **Examiner seals the evidence intake state**
   - Operator/examiner copies or read-only-mounts disk images, memory dumps, logs, pcaps, archives,
     and other acquired artifacts under the active case `evidence/` directory.
   - Portal detects any unregistered files under `evidence/` and shows a blocking warning before
     agent investigation proceeds.
   - Examiner runs the portal evidence security chain to register intended files, capture SHA-256,
     source notes, size, timestamps, and examiner identity, then appends a new evidence manifest
     version and evidence ledger event.
   - Later-discovered evidence is allowed through the same append-only workflow. Existing sealed
     evidence may not change silently; modified or missing evidence creates a chain-of-custody
     violation that blocks agent MCP operations until the examiner resolves it.

5. **Hermes connects to the gateway aggregate MCP endpoint**
   - Hermes uses `https://SIFT_VM:4508/mcp` with an `agentir_svc_*` token.
   - Per-backend URLs are not the supported agent workflow and must not be emitted by installer/templates.
   - Gateway performs auth, role enforcement, request audit, response enrichment, and identity injection.
   - Before routing each agent tool call, gateway verifies the active case evidence manifest and
     evidence ledger. If the live `evidence/` tree does not match the latest sealed state, the call
     is blocked and a structured warning is returned for human-in-the-loop action.

6. **Investigation and enrichment**
   - Gateway routes aggregate tool calls to stdio backends.
   - `sift-mcp` is the only command-execution gate and always uses `shell=False`.
   - OpenSearch indexing/search, forensic-rag semantic context, Windows baseline validation,
     OpenCTI enrichment, and forensic-knowledge guidance are exposed through gateway-mediated
     MCP tools and/or contextual MCP response enrichment.

7. **Review, approval, report**
   - Hermes can propose findings/timeline events but cannot approve them.
   - Examiner reviews in the portal, edits if needed, and commits via HMAC challenge-response.
   - Report generation includes only approved items and preserves hashes, approvals, verification ledger,
     evidence manifest/ledger state, and gateway/backend audit trail.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ SIFT VM                                                         │
│                                                                 │
│  sift-gateway (Starlette ASGI, :4508 HTTPS)                    │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────────────┐ │
│  │ auth    │  │ rate     │  │ MCP     │  │ Examiner Portal  │ │
│  │ Bearer  │  │ limit    │  │ proxy   │  │ /portal/         │ │
│  │ + expiry│  │ examiner │  │ /mcp    │  │ (case-dashboard) │ │
│  └─────────┘  └──────────┘  └────┬────┘  └──────────────────┘ │
│                                  │                             │
│           stdio subprocesses (FastMCP)                         │
│  ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌───────────────────┐  │
│  │forensic  │ │case-mcp │ │sift-mcp  │ │report-mcp         │  │
│  │-mcp      │ │         │ │shell=F   │ │                   │  │
│  └──────────┘ └─────────┘ └──────────┘ └───────────────────┘  │
│  ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌───────────────────┐  │
│  │opensearch│ │forensic │ │opencti   │ │windows-triage-mcp │  │
│  │-mcp      │ │-rag-mcp │ │-mcp      │ │baseline lookups   │  │
│  └──────────┘ └─────────┘ └──────────┘ └───────────────────┘  │
│                                                                 │
│  agentir-core library ──▶ /var/lib/agentir/                    │
│                           passwords/, verification/             │
│  Case directory: AGENTIR_CASE_DIR env var (portal-created)     │
└─────────────────────────────────────────────────────────────────┘
```

### What Is Sound — Do Not Change

| Component | Why It Stays |
|-----------|-------------|
| Streamable HTTP transport via `StreamableHTTPSessionManager` | Correct 2025-03-26 MCP spec |
| Gateway subprocess aggregation (Starlette + low-level MCP SDK) | Clean separation of concerns |
| FastMCP in all backends | Low boilerplate, type-safe tool registration |
| Challenge-response HMAC-SHA256 portal auth | Cryptographically sound; no plaintext password over wire |
| HMAC verification ledger at `/var/lib/agentir/verification/` | Non-forgeable integrity layer |
| Atomic writes + `chmod 444` on case files | Crash-safe, tamper-resistant |
| Per-backend audit JSONL | Evidence chain for every tool call |
| Gateway request audit with principal metadata | Separates examiner actions from Hermes/agent actions |
| Gateway aggregate `/mcp` as agent entry point | Single security, audit, enrichment, and routing boundary |
| `subprocess.run(shell=False)` in sift-mcp | Non-negotiable security boundary |
| Portal case creation | Normal examiner workflow; avoids shell/SSH dependency |
| Content hash + stale detection | Detects post-review tampering |
| Append-only `approvals.jsonl` | Immutable approval audit trail |
| Versioned evidence manifest + ledger | Allows legitimate evidence additions while detecting tampering |
| MCP evidence chain gate | Prevents the agent from running analysis on unsealed evidence or any tool on tampered evidence |
| `windows-triage-mcp` baseline validation | Deterministic local Windows known-good enrichment without Windows host execution |

---

## Case Directory Design (Settled)

The case directory is created and activated through the portal as the primary workflow.
There is no CLI activation command and no `active_case` file used in the gateway workflow.
Manual `gateway.yaml → case.dir` editing remains an administrator fallback for recovery.

### How it works

1. Installer writes an initial gateway config with no active case:
   ```yaml
   case:
     dir: ""   # no active case until the examiner creates one in the portal
   ```
2. Examiner signs into the portal and submits new case metadata + target directory.
3. Gateway REST validates the path, creates the directory, writes `CASE.yaml` and canonical files,
   and atomically updates `gateway.yaml → case.dir`.
4. Gateway sets `AGENTIR_CASE_DIR` in the current process and restarts/reloads stdio backends.
5. `stdio_backend.py` propagates `AGENTIR_*` env vars to all backend subprocesses.
6. `agentir_core.case_io.get_case_dir()` reads `AGENTIR_CASE_DIR` — all backends use this.
7. `case-dashboard/routes.py` reads `AGENTIR_CASE_DIR` — portal uses the same source.

### Case directory structure (created by portal/gateway)

```
/cases/{case-id}/
├── CASE.yaml           # Case metadata (case_id, title, examiner, created_at)
├── findings.json       # AI-proposed findings (DRAFT → APPROVED/REJECTED)
├── timeline.json       # Timeline events
├── evidence.json       # Evidence registry {files: [...]}
├── evidence-manifest.json # Latest sealed evidence manifest snapshot
├── evidence-ledger.jsonl # Append-only manifest/version chain-of-custody events
├── todos.json          # Investigation todos
├── iocs.json           # Indicators of Compromise
├── pending-reviews.json # Agent's proposed review batch (delta)
├── approvals.jsonl     # Append-only approval audit log
└── audit/              # Per-backend JSONL audit logs
    ├── forensic-mcp.jsonl
    ├── sift-mcp.jsonl
    └── ...
```

`CASE.yaml` minimal schema:
```yaml
case_id: case-2026-001
title: "Ransomware investigation — Contoso"
examiner: alice
created_at: "2026-05-23T10:00:00Z"
```

## Evidence Manifest and Chain-of-Custody Design (Upgrade)

This feature upgrades the existing evidence registry rather than inventing evidence tracking from
nothing. The original/current `case-mcp` contract already exposes `evidence_register`,
`evidence_list`, and `evidence_verify`, and `agentir_core.evidence_ops` already records SHA-256
hashes in `evidence.json` and can re-hash registered files on demand.

That legacy registry is still not enough for the portal-first runtime. It is a mutable point-in-time
registry, not a sealed chain of custody:
- It only knows files that were explicitly registered; it does not detect new files manually copied
  into `evidence/`.
- It verifies registered files only when a tool or portal route is explicitly called; it does not
  automatically warn the portal or block agent/backend analysis.
- Current same-path re-registration may update a changed hash, which is useful as a maintenance
  convenience but is not acceptable as an evidence-chain authority.
- It is not versioned, not hash-chained, and not HMAC-signed as an append-only evidence decision log.

Phase 16 therefore makes `evidence-manifest.json` plus `evidence-ledger.jsonl` the authority while
keeping `evidence.json` as a compatibility view for existing tools. The new design adds versioned
sealing, append-only evidence decisions, portal warnings, and a gateway evidence MCP gate.

### Evidence intake workflow

1. Case creation creates an empty `evidence/` directory, `evidence.json`,
   `evidence-manifest.json`, and `evidence-ledger.jsonl`.
2. The operator copies or read-only-mounts acquired evidence under `case/evidence/`.
3. The portal continuously compares the live `evidence/` tree to the latest sealed manifest:
   - New unregistered files: show "Unregistered evidence detected" warning.
   - Registered file missing: show "Registered evidence missing" violation.
   - Registered file hash mismatch: show "Evidence hash mismatch" violation.
   - Ledger/manifest hash-chain mismatch: show "Evidence ledger verification failed" violation.
4. Examiner opens the evidence intake panel and chooses one action per unregistered file:
   - Register and seal as new evidence.
   - Ignore/mark unintended with an audited reason.
   - Remove outside the app, then rescan.
5. Registering new evidence requires examiner session plus HMAC password confirmation, then appends
   a new manifest version. Existing manifest versions are never silently overwritten.
6. If later-discovered evidence is valid, the system creates manifest version `N+1` and a ledger
   event linking `previous_manifest_hash` to `new_manifest_hash`. This preserves the earlier chain
   while allowing the investigation scope to grow.

### Data files

`evidence-manifest.json` is the latest sealed state:
```json
{
  "version": 3,
  "case_id": "case-2026-001",
  "created_at": "2026-05-24T12:00:00Z",
  "created_by": "alice",
  "previous_manifest_hash": "sha256:...",
  "manifest_hash": "sha256:...",
  "files": [
    {
      "path": "evidence/host1/disk.E01",
      "sha256": "...",
      "bytes": 123456789,
      "mtime_ns": 1770000000000000000,
      "registered_at": "2026-05-24T12:00:00Z",
      "registered_by": "alice",
      "source": "USB evidence drive serial ABC123",
      "description": "Host1 acquired disk image",
      "status": "ACTIVE"
    }
  ]
}
```

**Note on `mtime_ns`:** This field is recorded for informational context only. It is trivially
spoofable (`touch -t`) and must never be used in any integrity assertion. The SHA-256 hash is the
only integrity anchor. Do not write validation logic that treats `mtime_ns` as tamper-evidence.

`evidence-ledger.jsonl` is append-only and records every evidence-chain event:
```json
{
  "event": "EVIDENCE_ADDED",
  "case_id": "case-2026-001",
  "version": 3,
  "path": "evidence/host2/memory.raw",
  "sha256": "...",
  "bytes": 34359738368,
  "previous_manifest_hash": "sha256:...",
  "new_manifest_hash": "sha256:...",
  "approved_by": "alice",
  "approved_at": "2026-05-24T12:00:00Z",
  "hmac_version": 2,
  "hmac": "..."
}
```

The manifest hash is computed from canonical JSON with `manifest_hash` excluded. Ledger events are
line-delimited JSON, fsynced after each append, and chmodded `0444` after writes where the filesystem
supports POSIX permissions. If the filesystem does not support permissions, the portal must show a
degraded-protection warning.

### Required controls

- `agentir-core` owns all evidence manifest, evidence ledger, scan, diff, append, and verify logic.
  Do not duplicate this logic in `case-dashboard`, `case-mcp`, `sift-gateway`, or `report-mcp`.
- Evidence paths are stored relative to `case_dir` and must resolve under `case_dir/evidence/` via
  `os.path.realpath`; symlink escapes are rejected.
- Directories are not registered as evidence. Register individual files, container archives, disk
  images, or memory images.
- Unknown files under `evidence/` do not automatically become trusted; they create a portal warning
  and an MCP block until examiner action.
- A modified or missing registered file is a chain-of-custody violation, not an automatic manifest
  update. The examiner must explicitly decide how to handle it.
- Legacy `evidence_register` must not silently bless a changed same-path file as the new authoritative
  chain state. Under Phase 16 it either delegates to the evidence-chain sealing workflow for an
  authenticated examiner or returns a portal-remediation response for agent/service-token callers.
- MCP agent tool calls are fail-closed on evidence-chain violations. The gateway returns a structured
  result with `blocked: true`, `reason: "evidence_chain_violation"`, issue counts, and portal
  remediation guidance; backend tools are not invoked.
- Examiner portal endpoints that mutate the evidence chain require session auth, role `examiner`,
  `must_reset_password == false`, and HMAC password confirmation.
- The evidence-chain gate is applied before aggregate `/mcp` `call_tool` routing. Read-only portal
  display endpoints may still show the violation so the examiner can remediate.
- Gateway audit logs include both successful evidence-chain checks and blocked tool-call checks,
  but never raw bearer tokens or HMAC responses.
- Report generation includes evidence manifest version/hash and refuses or prominently warns when
  evidence-chain verification fails.

### Gateway Evidence Gate Model (Performance-Critical)

The gateway does **NOT** rehash evidence files on every MCP tool call. Full rehashing of large
forensic artifacts (32 GB memory images, 500 GB disk images) would block every agent call for
seconds to minutes, making the system unusable.

The correct layered check model:

```
MCP Tool Call → Gateway
  1. Check in-memory cache: is evidence chain status valid? (0ms if cache fresh, 30s TTL)
  2. On cache miss: read manifest + ledger, verify HMAC + hash-chain (~5ms disk read)
  3. Stat-check: do registered files still exist with expected byte size? (~10ms for 20 files)
  4. If any stat changed: set chain_status = VIOLATION (do not rehash inline — defer to portal)
  5. If chain_status is UNSEALED: allow read-only tools with warning, block analysis/write tools
  6. If chain_status is a violation: return structured block response + write audit entry
  7. Else: route to backend, update cache
```

Full SHA-256 rehashing of evidence files is triggered **only** by:
- Portal "Verify Evidence Integrity" button (explicit examiner action)
- Pre-report generation check in `report-mcp`
- `case-mcp`'s `evidence_verify` MCP tool (agent-readable, examiner-triggered via portal)

The in-memory cache TTL is 30 seconds. On gateway restart, the first call after restart always
does a fresh stat-check (cache is cold). The cache must be invalidated immediately when the examiner
seals a new manifest version through the portal.

**Write-block detection:** The portal evidence intake panel must detect whether the `evidence/`
directory is mounted read-only (check `/proc/mounts` or `statvfs` flags on Linux) and display a
prominent warning when write protection is not present. The evidence chain provides detection and
policy enforcement but is not a substitute for OS-level write-blocking of acquired evidence.
Forensic best practice requires acquired evidence to be mounted read-only via hardware write-blocker
or `mount -o ro,noatime`. The system must make the status of this protection visible to the examiner.

### Affected modules

- `agentir-core`: new `evidence_chain.py` helpers for scanning, manifest canonicalization, ledger
  append, HMAC signing, hash-chain verification, and diff generation. Existing `evidence_ops.py`
  should delegate to this module or be migrated without changing public tool semantics abruptly.
- `case-dashboard`: add evidence intake/status panel, warning banner, rescan endpoint, register/seal
  endpoint, ignore unintended file endpoint, and violation display.
- `sift-gateway`: call the evidence gate before agent `/mcp` tool calls; emit structured block
  responses, read-only UNSEALED warnings, and audit entries.
- `case-mcp`: update `evidence_register`, `evidence_list`, and `evidence_verify` to use the evidence
  chain data model. Agent calls may read status and request remediation guidance, but only
  examiner-authorized portal actions may seal new evidence or resolve modified/missing evidence.
- `sift-mcp`, `opensearch-mcp`, `forensic-mcp`, `forensic-rag-mcp`, `opencti-mcp`: no direct evidence
  chain writes; they rely on gateway gating. Where they log input files, preserve `input_sha256s`.
- `report-mcp`: reconcile approved findings/timeline ledger plus evidence manifest/ledger state.
- Installer/config: case creation must create new evidence-chain files; no active case starts with a
  sealed manifest until the examiner runs initial evidence intake or explicitly seals an empty case.

### DFIR Hardening Requirements (Gaps Identified in Architecture Review)

The following gaps were identified against a real IR scenario where evidence is legitimately added,
replaced, or removed by the operator, and where Hermes must only operate on cryptographically
sealed evidence. These requirements extend the Phase 16 design.

#### Gap 1 — No `FILE_RETIRED` event (court-critical)

When a bad or corrupt artifact is deliberately removed by the examiner, the current design has no
operation for it. Evidence simply disappears between manifest versions with no documented reason,
which opposing counsel will exploit. Fix: add `retire_file(path, reason, examiner, derived_key)`
to `evidence_chain.py`. This writes a `FILE_RETIRED` ledger event (HMAC-signed) before the
manifest is re-sealed without the file, creating a documented chain: "file existed, examiner
removed it for stated reason, chain continues."

```python
# New ledger event
{"event": "FILE_RETIRED", "path": "evidence/bad-disk.E01", "reason": "corrupt acquisition",
 "retired_by": "alice", "retired_at": "...", "previous_manifest_hash": "sha256:...",
 "new_manifest_hash": "sha256:...", "hmac": "..."}
```

The portal must expose a "Retire evidence" action (HMAC-confirmed) distinct from "Ignore" (which
is for unregistered files) and "Remove outside app / rescan" (which is the ad-hoc workaround).

#### Gap 2 — Two registries diverge (`evidence.json` vs `evidence-manifest.json`)

`evidence_ops.py` / case-mcp's `evidence_register` still writes to the old `evidence.json` flat
file, which has no chain, no HMAC, no sealing. Until Phase 16c wires case-mcp to System B, an
agent can register evidence that bypasses the chain-of-custody entirely.

**Required 16c behavior:**
- `evidence_list` → reads `evidence-manifest.json` (authoritative); falls back to `evidence.json`
  for backward compat display only.
- `evidence_verify` → calls `chain_status()` (stat-check, no key needed); returns structured result.
- `evidence_register` called by agent → returns `{"blocked": true, "reason": "evidence_registration_requires_examiner", "remediation": "Use the Examiner Portal Evidence tab to register and seal new evidence."}`. Does NOT write to either registry. The agent can never self-register evidence.
- `evidence_register` called by examiner session (portal REST, not MCP tool) → unchanged existing
  behavior wired into seal_manifest flow.

#### Gap 3 — Two-tier evidence gate (usability vs. security tradeoff)

The gate started as fail-closed for ALL tool calls when the manifest was UNSEALED or violated.
That was safe but created unnecessary friction: at case start, the examiner could not even run
`list_findings` or `get_case_summary` until evidence was sealed. The implemented model is:

**Two-tier gate model:**
- Tier 1 (read-only): `UNSEALED` status allows read-only tools through with a warning annotation
  injected into the response (not a block). The set of read-only tools is defined by `annotations:
  {readOnlyHint: true}` on the FastMCP tool registration. The gateway checks this annotation.
- Tier 2 (analysis): `UNSEALED` or any violation BLOCKS analysis/write tools with the existing
  structured block response. A MODIFIED/MISSING/UNREGISTERED/LEDGER_ERROR status blocks everything.
- `UNSEALED` is not a violation — it means no evidence has been registered yet (valid at case start).
  Any of the other statuses IS a violation, even for read-only tools, because the chain is broken.

This model is implemented by consulting MCP tool annotations. Tests must keep covering read-only
UNSEALED pass-through, unsealed analysis blocks, and violation blocks for all tools.

#### Gap 4 — Stat-check window (same-size tampering)

The gateway stat-check only catches size changes. A sophisticated adversary who modifies a file
while preserving byte count fools the gate for up to 30s (TTL). This is a documented accepted
tradeoff — full rehash on every call is not feasible on 500 GB images. Mitigations:

1. `chattr +i` after sealing (Phase 17a) prevents the write from succeeding at all.
2. AppArmor profile (Phase 17c) prevents unauthorized processes from writing to evidence/.
3. auditd rules (Phase 17b) record any write attempt to the kernel audit log even if the write
   is permitted (to catch root-level tampering after-the-fact).
4. Procedural: examiner must run full HMAC verify (`verify_chain_hmac`) before submitting findings.

**Document requirement:** portal must show a "Full integrity verification recommended before
report submission" reminder whenever the last full-hash verify is older than 24h or has never
been run. Do not make it blocking — it is advisory.

#### Gap 5 — Ledger chmod is advisory on some filesystems

`chmod 444` is bypassed on NTFS/exFAT/FUSE mounts. Already documented in the compatibility
section. The OS-level hardening in Phase 17 (chattr, AppArmor) provides the real protection.
The portal write-block detection already covers this case with a warning.

### Compatibility and breakage risks

- Existing tests and tools assume `evidence.json` is the only evidence registry. Keep `evidence.json`
  as a compatibility view during migration, but make `evidence-manifest.json` the authority for
  integrity checks.
- Current `case-mcp` and `report-mcp` still consult `~/.agentir/active_case` in some paths. Phase 16
  must not deepen that dependency; use `AGENTIR_CASE_DIR`.
- Blocking every MCP call before any sealed manifest exists breaks first-run usability. Required
  behavior: case with no sealed manifest allows read-only tools with a warning annotation, blocks
  analysis/write tools with `evidence_chain_unsealed`, and prompts the examiner to seal an empty
  or populated evidence set in the portal.
- OpenSearch ingest currently writes ingest manifests under `audit/ingest-manifests/`. Do not move
  those into `evidence/`; they are processing provenance, not acquired evidence.
- Large evidence files can be expensive to hash. Hashing must stream in chunks and portal UI should
  support progress or asynchronous jobs before production use.
- Mounted evidence on NTFS/exFAT/FUSE may not honor `chmod`; detection must warn without pretending
  tamper-prevention is enforced.

### Removed Legacy Behavior

- `~/.agentir/active_case` file pointer — removed from `agentir_core.case_io.get_case_dir()` fallback chain (keep only `AGENTIR_CASE_DIR` env var)
- `_get_active_case()` in `sift-gateway/server.py` — delete it; gateway reads case dir from its own environment
- `agentir case activate` — not needed in agent workflow; examiner creates/activates cases in the portal

## Gateway MCP Boundary

Hermes and all other agents use only:

```text
https://SIFT_VM:4508/mcp
```

The gateway aggregates all enabled backend tools, handles name collision prefixing, and injects
principal/context metadata. Backend-specific URLs may exist for local diagnostics, but they are not
the supported agent contract and must not appear in Hermes profile templates.

For every MCP request the gateway must log at least:
- timestamp, request id, method/tool name, backend target, status, duration
- authenticated principal role (`agent`, `examiner`, `readonly`)
- token id or key fingerprint, agent id/examiner name, and source IP
- active case id/path when available

For MCP responses the gateway may add contextual enrichment from forensic-knowledge, forensic-rag,
OpenSearch, and OpenCTI. Enrichment must be auditable and must not mutate original backend output
without preserving the raw backend response in logs or structured response metadata.

---

## Liquefy Integration

Liquefy (`/home/yk/AI/SIFTHACK/liquefy/`) is an AI agent workspace archival and containment tool.
Full exploration of its codebase confirms: **its design center is the machine where agents run** —
the analyst machine with Hermes, not the SIFT VM. The integration decisions below are settled.

### What Liquefy is NOT for this project

- **Not a replacement for our evidence ledger.** Liquefy's audit chain uses SHA-256 hash-chaining
  without HMAC or signing — our Phase 16 ledger (HMAC-SHA256 + `derive_ledger_key()` + fsync) is
  stronger for DFIR chain-of-custody. Do not replace or supplement our ledger with Liquefy's.
- **Not for evidence file storage.** Liquefy's CAS shares blobs across runs by SHA-256, which would
  violate forensic case isolation. Do not vault evidence files with Liquefy.
- **Not a sandbox for Hermes on the SIFT VM.** Hermes never runs on the SIFT VM. The gateway is
  the isolation boundary.

### Approach A — Analyst Machine: Hermes Protection Layer (deployment docs only)

Liquefy is deployed on the analyst machine running Hermes. Zero code changes to sift-mcps.
Create `docs/analyst-machine-setup.md` documenting the full wrapper:

**Layer 1 — Pre-run blocking (State Guard strict mode):**
Declares SOUL.md, memory.md, auth-profiles.json as critical. Blocks Hermes from starting if any
declared file drifted from the last checkpoint since the previous session.
```bash
# One-time init
python liquefy/tools/liquefy_state_guard.py init ~/.hermes \
  --files "SOUL.md,memory.md,auth-profiles.json,hermes.config.yaml" --strict
# Every session start — BLOCKS if any file drifted
python liquefy/tools/liquefy_state_guard.py check ~/.hermes
# After successful run — saves new baseline
python liquefy/tools/liquefy_state_guard.py checkpoint ~/.hermes
```

**Layer 2 — Mid-run kill (Policy enforcer watch):**
Runs in background during Hermes execution. Sends HMAC-signed SIGTERM on critical violations
(secret leaks, forbidden executables) detected in Hermes workspace. Kill signal is nonce-protected
with a 5-minute TTL. For config-file-change-specific kill (SOUL.md hash drift), a ~20-line custom
poller uses the same halt signal mechanism.
```bash
python liquefy/tools/liquefy_policy_enforcer.py watch \
  --dir ~/.hermes --signal ~/.hermes/.liquefy-halt --pid $HERMES_PID --interval 5 &
```

**Layer 3 — Post-run rollback + forensic archive:**
```bash
# Runs Hermes; rolls back workspace if sentinels tampered or policy violated
python liquefy/tools/liquefy_safe_run.py \
  --workspace ~/.hermes --cmd "hermes run task.md" \
  --sentinels "SOUL.md,memory.md,auth-profiles.json" --heartbeat --json
# Archive session as AES-256-GCM encrypted, MRTV-verified, searchable vault (5-7x ratio)
python liquefy/tools/tracevault_pack.py ~/.hermes \
  --org "hermes-sessions" --out ./vault/$(date +%Y%m%d-%H%M%S) --json
# Token spend tracking
python liquefy/tools/liquefy_token_ledger.py scan --dir ~/.hermes
```

**What MRTV and LSEC v2 provide:** MRTV (Mandatory Round-Trip Verification) guarantees bit-perfect
vault restoration by immediately decompressing each compressed blob and verifying xxhash64 matches
the original — no silent data loss possible. LSEC v2 wraps compressed blobs in AES-256-GCM
encryption with PBKDF2 key derivation (300k iterations, per-tenant isolation). The vault is
searchable without full unpacking (streaming per-file decompress). This makes the vault a
compressed, encrypted, bit-perfect forensic archive of the Hermes session.

**What safe-run sentinels detect:** SOUL.md and memory.md are hashed pre-run; compared post-run.
If modified, full workspace rollback is triggered. Detection is post-run, not real-time — use
policy enforcer watch mode + custom poller for mid-run kill on config file changes.

### Approach B — SIFT VM: Solana Anchoring Pattern for Evidence Sealing (Phase 16 add-on)

Add an optional `anchor_manifest()` function to `agentir-core/evidence_chain.py`. When the examiner
seals a new manifest version, this function anchors the manifest hash on Solana via the SPL Memo
program, providing an immutable public timestamp proving the manifest existed at time T.

This closes the temporal-proof gap in our evidence chain: internal hash-chaining proves consistency
but not "existed at time T." Solana anchoring provides that external timestamp anchor.

**Do NOT import Liquefy as a Python dependency.** Implement the ~50-line SPL Memo pattern directly
in `evidence_chain.py` following the same approach as `liquefy/tools/liquefy_vault_anchor.py`.

```python
# agentir_core/evidence_chain.py — new optional function
def anchor_manifest(manifest_hash: str, ledger_tip_hash: str, keypair_path: str | None = None) -> dict:
    """Anchor manifest hash on Solana via SPL Memo. Degrades gracefully without solders."""
    payload = f"AGENTIR|{manifest_hash[:16]}|{ledger_tip_hash[:16]}"
    proof = {
        "schema": "agentir.evidence-anchor.v1",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "manifest_hash": manifest_hash,
        "ledger_tip_hash": ledger_tip_hash,
        "anchor_payload": payload,
        "solana_tx": None,
        "confirmed": False,
    }
    if keypair_path:
        try:
            from solders.keypair import Keypair  # optional dep
            # ~15 lines: build SPL Memo tx, send to Solana, record tx signature
            proof["solana_tx"] = tx_signature
            proof["confirmed"] = True
        except ImportError:
            pass  # graceful degradation — proof file still written without on-chain tx
    return proof
```

Proof written to `{case_dir}/evidence-anchor-v{N}.json`. Portal shows anchor status
(Unanchored / Anchored — Solana tx: …) in evidence intake panel.

**Examiner opt-in:** requires Solana keypair + ~0.000005 SOL per seal. Works perfectly without it;
anchoring is additive. For DFIR testimony: Solana anchoring proves "this hash was committed at T"
on a public blockchain. Supplement with RFC 3161 trusted timestamping for highest evidentiary value.

Files to modify: `packages/agentir-core/src/agentir_core/evidence_chain.py`,
`packages/case-dashboard/…/routes.py` (call after seal, show status),
`packages/agentir-core/pyproject.toml` (add `solders` as optional: `"agentir-core[solana]"`).

### Approach C — SIFT VM: Gateway Response Secret Redaction + Examiner Override

Before the gateway returns any MCP tool result to Hermes, scan the response payload for credential
patterns and redact matches inline. This prevents the gateway from forwarding secrets that may
appear in case file contents, process memory dumps, registry values, or network captures.

**Do NOT import Liquefy.** Port the ~15 regex patterns from
`liquefy/tools/liquefy_leakhunter.py` (`SECRET_PATTERNS` list) into a new module.

#### `packages/sift-gateway/src/sift_gateway/response_guard.py`

- `scan_tool_result(text: str) -> list[dict]` — returns `[{pattern_name, severity, char_offset}]`
- `redact_tool_result(text: str, override_active: bool) -> tuple[str, list[dict]]` — scans,
  redacts `critical`+`high` severity matches (unless override active) by replacing the exact
  matched span with `[REDACTED:{pattern_name}]`, returns `(redacted_text, findings)`. Medium/low
  matches are returned in `findings` for flagging but are never redacted.
- In-memory override state: `enable_override(case_dir_str, examiner, ttl=600)`,
  `is_override_active(case_dir_str) -> bool`, `cancel_override(case_dir_str)`,
  `get_override_status(case_dir_str) -> dict`
- Override is per-process, purely in-memory — a gateway restart resets it automatically.

#### Wiring in `sift_gateway/mcp_endpoint.py`

Called after `gateway.call_tool()` succeeds, before returning TextContent to Hermes:

```python
from sift_gateway.response_guard import redact_tool_result, is_override_active
case_dir_str = os.environ.get("AGENTIR_CASE_DIR", "")
override = is_override_active(case_dir_str)
redacted_text, findings = redact_tool_result(raw_text, override_active=override)
if findings:
    # log {pattern_name, char_offset, redact_override_active} — never matched value
    # add _agentir_context.secret_warning to returned TextContent
```

When override is active: text is NOT redacted but every call gets
`redact_override_active: true, override_by: examiner, override_expires_at: ...` in the audit log.

#### Portal endpoints in `case-dashboard/routes.py`

Three small endpoints added to `_dashboard_api_routes()`:

- `GET /api/response-guard/status` — session auth (examiner role). Returns `{active, expires_at,
  enabled_by, seconds_remaining}`. Read-only; no HMAC needed.
- `POST /api/response-guard/override` — **HMAC required** (same challenge-response pattern as
  evidence seal). Body: `{challenge_id, response, ttl_seconds?}`. Default TTL: 600s (10 min).
  Calls `response_guard.enable_override(case_dir_str, examiner, ttl)`. Logs override grant to
  gateway audit with examiner identity and expiry.
- `POST /api/response-guard/override/cancel` — session auth only. Calls
  `response_guard.cancel_override(case_dir_str)`. Logs cancellation.

The `on_chain_mutation`-style injection pattern used for `invalidate_evidence_cache` is NOT needed
here because `response_guard` state lives in `sift-gateway` — the portal endpoints import directly
from `sift_gateway.response_guard` at call time (same process, no circular dep).

#### Severity thresholds (settled)

- **Redact by default**: `critical` + `high` severity patterns only (AWS keys, GitHub tokens,
  private keys, OpenAI/Anthropic keys, Stripe, connection strings, bearer tokens, Discord tokens).
- **Flag-only (no redact)**: `medium` + `low` (env var assignments, JWT tokens, generic
  password= patterns, SkillsSnapshot dumps). These appear in audit as `secret_warning` metadata
  but the text is not altered. Forensic output is legitimately credential-dense at medium severity.
- **Override scope**: global — one HMAC confirm unlocks all patterns for all tools for 10 min.
  Examiner can cancel early from portal. Auto-expires; no persistent state.

#### If examiner cannot use the override

The `[REDACTED:{pattern_name}]` placeholder in the Hermes response tells the agent that content
exists but has been withheld. Hermes surfaces this to the examiner ("tool output contained
REDACTED:AWS Access Key — examiner action needed"). The examiner can then:
1. Enable the 10-minute override from the portal and re-run the same tool call via Hermes.
2. Inspect the tool output directly (SSH to SIFT VM, run sift-mcp tool manually, or use the
   portal's raw evidence viewer) and hand the finding to Hermes as a manual note.

#### Tests

- `scan_tool_result("AKIAIOSFODNN7EXAMPLE")` → 1 finding, severity `critical`
- `scan_tool_result("clean text")` → []
- `redact_tool_result("AKIAIOSFODNN7EXAMPLE", override_active=False)` → text contains `[REDACTED:AWS Access Key]`
- `redact_tool_result("AKIAIOSFODNN7EXAMPLE", override_active=True)` → text unchanged, 1 finding returned
- Medium severity (env var) → not redacted regardless of override
- `enable_override` / `is_override_active` / TTL expiry / `cancel_override` — unit tests
- Portal `GET /api/response-guard/status` → correct fields
- Portal `POST /api/response-guard/override` without HMAC → 400/401
- Portal `POST /api/response-guard/override/cancel` → 200 + override cleared

---

---

## OS-Level Evidence Hardening (Ubuntu 24.04 SIFT VM)

**Target:** Ubuntu 24.04 (Noble Numbat), kernel 6.8+. SIFT Workstation is based on Ubuntu.
Confirmed on SIFT test VM (192.168.122.81): kernel 6.17.0-29-generic, AppArmor active (77 enforce
profiles), ext4 root filesystem, `chattr +i` proven working, IMA compiled in (CONFIG_IMA=y,
CONFIG_IMA_APPRAISE=y), inotify_init1 functional, NOPASSWD sudo available.
Dev machine (Fedora 44) has no AppArmor — develop and test Phase 17c profile on Ubuntu only.
All other mechanisms work cross-platform.

**Delivery:** All Phase 17 steps are additions to `install.sh`. None require separate deployment
or out-of-band configuration. The install script already handles TLS, tokens, systemd, and
OpenSearch — OS hardening is an additional section at the end of the same script.

### Honest Threat Model — What This Layer Actually Covers

The OS hardening layer protects against **accidents and low-privilege tampering**. It does NOT
protect against a malicious examiner or system administrator with root access — they can disable
any of these controls with the same tools that set them. This is a documented and acceptable
constraint in DFIR: the examiner is a trusted principal.

What OS hardening actually does in the DFIR context:

1. **Accidents become impossible.** A wrong `rm`, errant `cp`, or misbehaving tool cannot silently
   overwrite or delete a sealed evidence file. EPERM fires before the damage happens.

2. **Intentional tampering becomes a deliberate, auditable act.** Without `chattr +i`, root can
   silently modify a file. With it, root must first run `chattr -i` — and if `auditd` is watching
   the directory, that `chattr -i` call is recorded in the kernel audit log with timestamp, UID,
   PID, and binary path. Combined with the SHA-256 mismatch in our ledger, you can show in court:
   "at 14:32 the immutable flag was cleared, at 14:33 the file was modified, at 14:34 the flag
   was restored — here is the kernel audit record of each step."

3. **The cryptographic ledger remains the actual chain-of-custody proof.** `chattr +i` is a
   practical barrier. The SHA-256 hash in `evidence-manifest.json`, the HMAC-signed ledger chain,
   and (optionally) the Solana timestamp anchor are what hold up in court when opposing counsel
   asks "was the file you analyzed the same as what was acquired?" The OS layer makes tampering
   require deliberate effort and leaves traces; the cryptographic layer makes tampering detectable
   and provable regardless.

**What cannot be protected at the software level:**
- A root user explicitly running `chattr -i` (leaves auditd trace but is still possible)
- Physical disk access — pull the drive, mount offline, modify, replace (out of scope)
- Kernel exploits that bypass the VFS layer (out of scope for this threat model)
- The examiner signing false findings — human integrity, not a software problem

Document these limitations in `docs/dfir-hardening-guide.md` so examiners understand the
system's guarantees and are not misled into thinking OS hardening replaces cryptographic proof.

### Phase 17a — `chattr +i` Immutable Flag After Sealing

**What it protects:** Accidents and low-privilege writes. Makes deliberate root-level tampering
require an explicit, auditable `chattr -i` step (see threat model above). Does NOT protect against
a malicious root user — that is the job of the cryptographic ledger + auditd.

After every successful `seal_manifest()` call, each registered evidence file is set immutable.
Any write, delete, truncate, rename, or `chmod` returns EPERM until explicitly cleared.
Clearing requires CAP_LINUX_IMMUTABLE — which on SIFT means a deliberate root action.

**Application code — `agentir_core/evidence_chain.py`:**

```python
import ctypes, fcntl
FS_IOC_SETFLAGS = 0x40086602
FS_IOC_GETFLAGS = 0x80086601
FS_IMMUTABLE_FL = 0x00000010

def _set_immutable(path: Path, immutable: bool) -> bool:
    """Accident guard: set or clear immutable flag. Graceful fallback if CAP_LINUX_IMMUTABLE absent."""
    try:
        with open(path, 'rb') as f:
            flags = ctypes.c_int(0)
            fcntl.ioctl(f.fileno(), FS_IOC_GETFLAGS, flags)
            if immutable:
                flags.value |= FS_IMMUTABLE_FL
            else:
                flags.value &= ~FS_IMMUTABLE_FL
            fcntl.ioctl(f.fileno(), FS_IOC_SETFLAGS, flags)
        return True
    except (OSError, PermissionError):
        return False  # logs WARNING; does not abort seal
```

- `seal_manifest()`: clear immutable on each path before re-hashing (in case re-sealing), set +i after.
- `retire_file()`: clear immutable before the external `rm`; does not set it back (file is being removed).
- Graceful degradation on NTFS/FUSE/NFS: logs `WARNING: immutable flag not supported on <path>`.
- Portal evidence status shows `immutable: true/false` per file.

**`install.sh` addition (Ubuntu-only block):**
```bash
# Grant CAP_LINUX_IMMUTABLE to the Python interpreter used by sift-gateway.
# This allows the gateway to set/clear the immutable flag without full root.
# Revoked if the interpreter is upgraded — installer must re-run on Python upgrade.
if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_linux_immutable+ep' "$(readlink -f "$(which python3)")"
    echo "[install] CAP_LINUX_IMMUTABLE granted to $(readlink -f $(which python3))"
else
    echo "[install] WARN: setcap not found — immutable flag protection not configured"
fi
```

**Filesystem compatibility:** ext4, XFS, btrfs — confirmed on SIFT VM (ext4 LVM, lsattr shows
`e` flag on evidence files, `i` flag absent until we set it). NTFS/FAT/NFS: graceful fallback.

### Phase 17b — auditd Rules for Evidence Directory

**What it provides:** A second, independent, kernel-level record of all writes and attribute
changes in the evidence directory. Critically: it records `chattr -i` calls (attribute changes,
`perm=a`), so if someone clears the immutable flag before tampering, auditd catches it even if our
application layer is bypassed. Clearing the auditd log itself requires `CAP_AUDIT_CONTROL` —
a separate deliberate root action that is itself auditable.

**Zero application code changes.** Entirely an `install.sh` and config file addition.
Rules template lives at `configs/audit/99-agentir-evidence.rules` in the repo.

**`install.sh` addition:**
```bash
# Install auditd (not present by default on SIFT — confirmed on test VM)
apt install -y auditd audispd-plugins

# Write evidence watch rules. AGENTIR_CASES_ROOT is substituted at install time
# from gateway.yaml template (default: /cases)
CASES_ROOT="${AGENTIR_CASES_ROOT:-/cases}"
cat > /etc/audit/rules.d/99-agentir-evidence.rules << EOF
# agentir — track all writes + attribute changes (incl. chattr -i) in case directories
# perm=w: file content writes; perm=a: attribute changes (chmod, chattr, xattr)
-a always,exit -F dir=${CASES_ROOT} -F perm=wa -F key=agentir_evidence_write
-a always,exit -F dir=/var/lib/agentir -F perm=wa -F key=agentir_core_write
EOF

augenrules --load
systemctl enable --now auditd
echo "[install] auditd configured — watching ${CASES_ROOT} for write/attribute changes"
```

**Forensic value in court:** Examiner can produce two independent records:
1. `evidence-ledger.jsonl` — application layer, HMAC-signed, cryptographically bound
2. `/var/log/audit/audit.log` — kernel layer, records every write + `chattr` call with UID/PID/timestamp

**Query to produce for discovery:** `ausearch -k agentir_evidence_write --format text`

### Phase 17c — AppArmor Profile for sift-gateway (Ubuntu 24.04 Only)

**What it protects:** Limits the blast radius if the gateway process is exploited. Even with a
vulnerability in application code, AppArmor prevents the process from writing to evidence files,
spawning arbitrary shells, or reaching the network beyond localhost. This is MAC enforcement at the
kernel level — it holds even if the application code is fully compromised.

**Delivery:** Profile file lives at `configs/apparmor/sift-gateway` in the repo. `install.sh`
copies it and loads it in enforce mode. Dev machine is Fedora 44 (SELinux, not AppArmor) —
develop and validate the profile on Ubuntu 24.04 using `aa-logprof` to catch legitimate denials
before flipping to enforce.

**Important:** Profile the sift-gateway entry point binary (the uv-installed script path), NOT
`/usr/bin/python3*` broadly — profiling all Python would catch unrelated processes. The installed
binary path will be something like `/usr/local/bin/sift-gateway` or `/home/sansforensics/.local/bin/sift-gateway`.
Confirm the exact path after `install.sh` runs and update `configs/apparmor/sift-gateway` accordingly.

**Profile goals:**
- Allow: read evidence files (for SHA-256 hashing during seal)
- **Deny: write to `evidence/**`** — gateway never needs to write evidence file content
- Allow: read/write manifest, ledger, audit/, approvals, findings, timeline
- Allow: read gateway.yaml and TLS certs
- Allow: TCP localhost only (OpenSearch :9200, stdio backend pipes)
- Deny: exec of arbitrary binaries beyond defined backend paths
- Deny: all network except localhost TCP

**Profile skeleton** (`configs/apparmor/sift-gateway`):
```
#include <tunables/global>

/usr/local/bin/sift-gateway {
  #include <abstractions/base>
  #include <abstractions/python>
  #include <abstractions/ssl_certs>
  #include <abstractions/nameservice>

  # Evidence: read for hashing; hard deny writes
  /cases/*/evidence/                 r,
  /cases/*/evidence/**               r,
  /cases/*/evidence/**               deny w,

  # Case metadata and outputs
  /cases/*/CASE.yaml                 r,
  /cases/*/evidence-manifest.json    rw,
  /cases/*/evidence-ledger.jsonl     rw,
  /cases/*/approvals.jsonl           rw,
  /cases/*/audit/                    rw,
  /cases/*/audit/**                  rw,
  /cases/*/**                        rw,

  # Config, TLS, runtime
  /home/*/.agentir/gateway.yaml      r,
  /var/lib/agentir/**                rw,
  /etc/ssl/                          r,
  /etc/ssl/**                        r,
  /tmp/agentir-*                     rw,

  # Network: localhost only
  network inet tcp,
  network inet6 tcp,
  deny network udp,
  deny network raw,

  # Backend subprocesses (uv-managed Python only)
  /usr/bin/python3*                  rix,
  /home/*/.local/bin/**              rix,
  /home/*/.venv/bin/**               rix,
  deny /bin/bash                     x,
  deny /bin/sh                       x,
  deny /usr/bin/bash                 x,
}
```

**`install.sh` addition:**
```bash
if command -v apparmor_parser >/dev/null 2>&1; then
    cp "${SIFT_MCPS_ROOT}/configs/apparmor/sift-gateway" /etc/apparmor.d/sift-gateway
    apparmor_parser -r /etc/apparmor.d/sift-gateway
    aa-enforce /etc/apparmor.d/sift-gateway
    echo "[install] AppArmor profile loaded in enforce mode"
else
    echo "[install] WARN: AppArmor not available — skipping profile (non-Ubuntu system?)"
fi
```

### Phase 17d — inotify Real-Time Gate Invalidation

The current gateway cache invalidation relies on two signals:
1. The portal calls `invalidate_evidence_cache()` after sealing (immediate)
2. Manifest mtime-change detection on the 30s TTL check path

Neither catches the case where someone modifies an evidence FILE directly without going through
the portal. The mtime check only watches the manifest file, not the evidence files themselves.

**inotify watcher:** A background asyncio task in sift-gateway watches `case_dir/evidence/` with
inotify. On `IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO`, it immediately
calls `invalidate_evidence_cache(case_dir_str)` and logs an audit entry.

**Implementation:** Pure stdlib via ctypes — no external dependencies. ~40 lines.

```python
# agentir_core/inotify_watch.py  (or sift_gateway/evidence_watcher.py)
import asyncio, ctypes, os, struct

IN_MODIFY    = 0x00000002
IN_CREATE    = 0x00000100
IN_DELETE    = 0x00000200
IN_MOVED     = 0x000000C0  # IN_MOVED_FROM | IN_MOVED_TO

_libc = ctypes.CDLL('libc.so.6', use_errno=True)

async def watch_evidence_dir(case_dir_str: str, on_change_fn) -> None:
    """Background task: invalidate gate cache on any evidence/ filesystem event."""
    fd = _libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    if fd < 0:
        logger.warning("inotify unavailable — falling back to TTL-only invalidation")
        return
    wd = _libc.inotify_add_watch(fd, os.fsencode(f"{case_dir_str}/evidence"),
                                  IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED)
    try:
        loop = asyncio.get_running_loop()
        while True:
            await asyncio.wait_for(
                loop.run_in_executor(None, lambda: os.read(fd, 4096)), timeout=60.0
            )
            await asyncio.to_thread(on_change_fn, case_dir_str)
    except asyncio.CancelledError:
        pass
    finally:
        _libc.inotify_rm_watch(fd, wd)
        os.close(fd)
```

The watcher is started by `server.py` when `AGENTIR_CASE_DIR` is set, cancelled on case switch.
Graceful fallback when inotify is unavailable (NTFS/NFS/FUSE), logs warning.

**Effect:** Tampering with an evidence file triggers a gate cache flush within milliseconds.
Combined with chattr +i (Phase 17a), the write is prevented entirely; without chattr, the gate
catches it before the next tool call.

### Phase 17e — IMA xattr File Hash Anchoring (Advanced, Optional)

Linux IMA (Integrity Measurement Architecture) can store cryptographic hashes of files in kernel-
managed extended attributes (`security.ima`). In appraise mode, the kernel refuses to open a file
whose content hash does not match the stored xattr. In measure mode, it records hashes to a TPM.

**What this adds over chattr:** chattr prevents writes. IMA-appraise additionally prevents READS
of a tampered file — the kernel itself denies access before any application code runs.

**Requirements:**
- Ubuntu 24.04 kernel 6.8: IMA is compiled in (confirmed via `/sys/kernel/security/ima`)
- Boot parameter: `ima_appraise=fix` initially (to write xattrs), then `ima_appraise=enforce`
- Package: `apt install ima-evm-utils` (provides `evmctl`)
- Policy in `/etc/ima/ima-policy`: restrict to evidence files

**After sealing in `evidence_chain.py`:**
```python
import subprocess
def _set_ima_hash(path: Path) -> bool:
    """Write SHA-256 into security.ima xattr for IMA appraisal. Optional."""
    try:
        subprocess.run(['evmctl', 'ima_hash', '--hash=sha256', str(path)],
                       check=True, capture_output=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False  # graceful degradation if ima-evm-utils not installed
```

**Verdict:** Valuable for the highest-assurance deployments but requires kernel boot parameter
changes (invasive for SIFT installers) and `ima-evm-utils` package. Implement as an opt-in
installer flag (`--enable-ima`) rather than default. Portal shows IMA status per file if enabled.

### OS Hardening — What Cannot Be Protected

Document these limitations explicitly in `docs/dfir-hardening-guide.md`:

- All mechanisms are bypassable by root (`chattr -i`, `aa-disable`, `auditctl -D`). The system
  assumes examiner/administrator integrity. The chain-of-custody provides the evidence trail if
  they do tamper.
- IMA appraise mode protects reads but not in-memory modifications after a file is opened.
- AppArmor profiles protect the gateway process but not other processes on the same host.
- auditd logs are not tamper-evident in the forensic sense — they require a separate log host or
  `audispd → remote logging` to be truly independent. For air-gapped deployments, the examiner
  should GPG-sign the audit log after each session.
- `chattr +i` does not work on NTFS, FAT, NFS, FUSE filesystems (degraded mode documented).

---

## Completed Phases

All phases 0–15 are complete. Implementation details live in git history. The table below records
what each phase achieved for regression context.

| Phase | Title | Key Outcome |
|-------|-------|-------------|
| 0 | Critical Bug Fixes | vhir→agentir sweep, active_case removed, TLS fixed, namespace gate passes |
| 1 | Workspace Scaffold | uv workspace, all packages extracted, agentir-core created |
| 2 / 2b | agentir-core Tests + Hardening | 139 tests; no sys.exit, env-overridable paths, no sudo |
| 3 | Portal Security Hardening | HTTPS guard, nonce IP-binding, CORS, error sanitization |
| 4a–4d | Gateway Improvements | Token expiry, rate limit, Origin validation, extractor dedup |
| 4e | MCP Notifications | DEFERRED — no session lifecycle hook in mcp==1.27.1 |
| 5 | forensic-rag FastMCP | Migrated from low-level Server to FastMCP |
| 6 | sift-mcp Sanitization | Null-byte reject, >4096-char reject, NFC normalize |
| 7 | Install Script | install.sh: TLS, token gen, systemd, default examiner, OpenSearch |
| 8 | Docker Compose | OpenSearch 2.18.0, localhost-only, agentir-opensearch container |
| 9 | Configs & Templates | gateway.yaml.template, hermes-forensics-profile.yaml, systemd service |
| 10 | Architecture Cleanup | DEFERRED — low-priority debt reduction |
| 11 | Windows Triage Backend | SQLite-backed, 13 tools, DB downloader, health/degraded mode; 8 tests |
| 12-pre | Security Prerequisites | derive_auth_key / derive_ledger_key (R8 domain separation) |
| 12a–12f | Portal Authentication | JWT sessions, middleware, 7 auth endpoints, R1–R9 guards; 36 tests |
| 13a–13f | Agent RBAC | generate_service_token, role enforcement, portal token lifecycle; 28 tests |
| 14a–14g | Dashboard Rewiring | Namespace sweep, auth flow, login screen, case init modal, token UI |
| 15a–15d | Session Security Hardening | JWT revocation, sliding refresh, login rate limit, secure headers; 271 total tests |

---

## Verification Checklist (End-to-End)

Run these after each phase to confirm nothing has regressed. The installer-first portal workflow
must have functional, resilience, and security tests; do not accept one-off manual success as proof.

```bash
# 1. All packages install cleanly
uv sync --all-packages

# 2. No vhir namespace leaks
grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "agentir_plugin"
# Expect: 0 lines

# 3. agentir-core tests pass
uv run pytest packages/agentir-core/tests/ -v --tb=short

# 4. Gateway starts before a case exists
uv run sift-gateway --config configs/gateway.yaml.template
# Expect: starts without error; case-dependent tools return clear "no active case" errors until portal case creation

# 5. Gateway health
curl -k https://127.0.0.1:4508/api/v1/health
# Expect: {"status": "ok"}

# 6. Portal HTTPS enforcement (when TLS configured)
curl http://127.0.0.1:4508/portal/
# Expect: 400 "Portal requires HTTPS"

# 7. Nonce consumed on use
# POST /portal/api/commit/challenge to get challenge_id
# POST /portal/api/commit with the challenge_id (valid password)
# POST /portal/api/commit AGAIN with same challenge_id
# Expect: 401 "Invalid or expired challenge"

# 8. Nonce IP binding
# Issue challenge from 127.0.0.1
# POST commit from different IP (if testable)
# Expect: 403 "Challenge IP mismatch"

# 9. Origin validation (CSRF test)
curl -X POST https://127.0.0.1:4508/mcp \
  -H "Origin: http://evil.example.com" \
  -H "Authorization: Bearer $AGENTIR_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# Expect: 403

# 10. Token expiry
# Set expires_at to a past ISO timestamp in gateway.yaml api_keys
# Restart gateway
# Make a tool call
# Expect: 401 or 403

# 11. Rate limit (per-examiner)
# Fire 121 requests in <60s as same examiner
# Expect: 429 after burst exhausted

# 12. opensearch TLS configurable
# Set verify_certs: false in gateway.yaml opensearch section
# Expect: connects without cert error; CERT_NONE only when explicitly configured

# 13. Import smoke tests
uv run python -c "from case_dashboard.routes import create_dashboard_v2_app; print('OK')"
uv run python -c "from sift_gateway.server import Gateway; print('OK')"
uv run python -c "from case_mcp.server import create_server; print('OK')"
uv run python -c "from agentir_core.case_io import get_case_dir; print('OK')"
```

### Workflow Acceptance Tests

Installer readiness:
- Run installer in a clean SIFT-like VM/container and verify it is idempotent.
- Verify generated TLS certs exist and gateway refuses plain HTTP portal access when TLS is configured.
- Verify OpenSearch container is running, healthy, bound only to `127.0.0.1:9200`, and templates are installed.
- Verify enrichment/RAG assets are present and searchable or report a clear degraded mode.
- Verify systemd user service survives restart and gateway health passes after reboot/session restart.

Portal authentication:
- Login with installer default examiner account requires password reset before any case/token operation.
- After reset, old temporary password fails and new password succeeds.
- Session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, path-limited, and expiry-checked.
- Commit still requires HMAC password confirmation even with a valid session.

Portal case creation:
- `POST /api/v1/case/create` creates the full canonical case tree from valid metadata.
- New case tree includes `evidence/`, `evidence-manifest.json`, and `evidence-ledger.jsonl`.
- Invalid case ids, path traversal, relative paths, existing non-empty directories, and unwritable roots are rejected.
- `gateway.yaml → case.dir` update is atomic; simulated failure cannot leave partial YAML.
- `AGENTIR_CASE_DIR` updates in process and reaches all restarted backends.
- Concurrent case-create requests serialize safely; one wins and the other returns a clear conflict.

Evidence manifest and chain-of-custody:
- New case with no sealed manifest shows portal warning and blocks agent MCP analysis tools.
- Manually copied file under `evidence/` appears as unregistered evidence in portal status.
- Examiner can seal an empty evidence state or register/seal intended files with HMAC confirmation.
- Later-discovered evidence can be appended as a new manifest version without invalidating older versions.
- Existing sealed evidence modification returns `modified` and blocks agent MCP tool routing.
- Existing sealed evidence deletion returns `missing` and blocks agent MCP tool routing.
- Unregistered files return `unregistered` and block agent MCP tool routing until examiner action.
- Manifest or ledger tampering returns a ledger/manifest error and blocks agent MCP tool routing.
- Gateway block response is structured for Hermes and includes human-remediation guidance, not a raw traceback.
- Gateway writes a `sift-gateway.jsonl` audit entry for every evidence-chain block.
- `report-mcp` includes evidence manifest version/hash and warns or refuses when evidence-chain status is not OK.
- OpenSearch ingest manifests remain under `audit/ingest-manifests/`; they are not treated as acquired evidence.
- Gateway evidence gate uses stat-check + 30s TTL cache; does NOT rehash files on every MCP call.
- Portal evidence intake panel shows write-block detection status (read-only mount warning if not protected).
- Portal shows an advisory full-HMAC-verify reminder when no full verification has been run or the
  last verification is 24 hours old or older.

Aggregate MCP gateway:
- Hermes config contains only `https://SIFT_VM:4508/mcp`.
- Service token can list/call allowed aggregate tools through `/mcp`.
- Service token is rejected from portal APIs.
- Per-backend MCP URLs are disabled in production config or require explicit diagnostic opt-in with the same auth/audit path.
- Gateway audit records include request id, principal role, token id, agent id/examiner, tool/backend, status, duration, and active case.
- Raw bearer tokens and HMAC responses never appear in logs.

Agent token lifecycle:
- Installer-generated service token works.
- Examiner can create an additional agent token from the portal; the raw token is shown once.
- Token metadata list never reveals raw token values.
- Revoked/rotated/expired tokens fail for MCP and record appropriate audit events.
- Two agents using different service tokens produce separable gateway logs.

Enrichment and response integrity:
- Gateway-enriched MCP responses keep raw backend output distinguishable from added context.
- Enrichment failures degrade gracefully and do not break the underlying tool response unless policy requires it.
- Enrichment additions are either logged or represented in structured response metadata.

Chain of custody:
- Findings/timeline writes remain atomic/protected.
- HMAC ledger entry is appended for approvals.
- Report generation excludes DRAFT/REJECTED items and includes only APPROVED items.
