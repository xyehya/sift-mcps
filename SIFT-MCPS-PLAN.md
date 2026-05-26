# SIFT-MCPS-PLAN.md — Architecture & Specification

## Tracking Contract

This file is the normative project spec: architecture, security, behavioral contracts,
and design decisions. Completed behavior stays documented because it remains testable.

**TASKS.md** is the execution tracker. **AGENTS.md** is the session entrypoint.

If this file and TASKS.md disagree: stop, identify the conflicting lines, ask the user.

---

## 1. Purpose and End State

A portable, secure MCP runtime installable on any SIFT Workstation VM via `install.sh`.
The AI agent (Hermes) drives forensic investigation through authenticated MCP tool calls.
The examiner maintains control through the portal. The deliverable is a cryptographically
auditable, HMAC-verified report with chain-of-custody preservation.

---

## 2. Authoritative Workflow

```
1. SIFT VM SETUP    install.sh → gateway → OpenSearch → portal at https://<VM>:4508/portal/
2. CASE INIT        Portal → New Case → casename slug + title → auto case_id with timestamp
3. EVIDENCE COPY    Examiner copies evidence to /cases/{case_id}/evidence/ (out-of-band)
4. SEAL             Portal → Evidence tab → Seal Manifest → SHA-256 → manifest + ledger
5. AGENT CONNECTS   Hermes connects with service token → MCP handshake → tool list
6. ORIENT           Agent calls case_status → gets paths, platform capabilities
7. SURVEY           Agent calls evidence_list → sees sealed + unregistered files
8. INGEST           Agent calls idx_ingest(path="evidence/file.e01", hostname="HOST") → OpenSearch populated
9. ANALYSIS         Agent uses idx_search, idx_aggregate, idx_case_summary, windows-triage, forensic-rag, opencti
10. FINDINGS        Agent calls record_finding (DRAFT) → Examiner reviews → APPROVED
11. REPORT          Agent calls generate_report → save_report → signed deliverable
```

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ SIFT VM                                                         │
│                                                                 │
│  sift-gateway (Starlette ASGI, :4508 HTTPS, localhost SAN)     │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────────────┐ │
│  │ auth    │  │ rate     │  │ MCP     │  │ Examiner Portal  │ │
│  │ Bearer  │  │ limit    │  │ proxy   │  │ /portal/         │ │
│  │ + expiry│  │          │  │ /mcp    │  │ (case-dashboard) │ │
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
│  Docker services: agentir-opensearch, agentir-opencti (+dep)   │
│  Host tools: xmount, ewfmount, ntfs-3g, AmcacheParser, etc.   │
└─────────────────────────────────────────────────────────────────┘
```

### Design Invariants (Do Not Change)

| Component | Why It Stays |
|-----------|-------------|
| Streamable HTTP via `StreamableHTTPSessionManager` | Correct MCP spec |
| Gateway subprocess aggregation | Clean separation of concerns |
| Challenge-response HMAC-SHA256 portal auth | No plaintext password over wire |
| HMAC verification ledger at `/var/lib/agentir/verification/` | Non-forgeable integrity |
| Atomic writes + `chmod 444` on case files | Crash-safe, tamper-resistant |
| Portal case creation | Normal examiner workflow |
| Append-only `approvals.jsonl` | Immutable approval audit trail |
| Versioned evidence manifest + ledger | Tamper-detection |
| Two-tier evidence gate | UNSEALED=read-only pass-through; VIOLATION=full block |
| sudo xmount + ntfs-3g for E01 mount | Works on SIFT xmount 0.7.6 |
| safe_rglob for NTFS filesystem traversal | Survives corrupted junctions |

---

## 4. Case Directory Design

### Case ID Format

`{casename}-{YYYYMMDD}-{HHMM}` — always includes time, no collision.
Casename slugified at portal: lowercase, `[a-z0-9-_]` only.

### Resolution Chain

1. `AGENTIR_CASE_DIR` env var (set by gateway, reaches all backends)
2. `AGENTIR_CASES_ROOT` env var = `Path(case_dir).parent`
3. `~/.agentir/active_case` — written on case switch for CLI compat only; never read as primary

---

## 5. Evidence Chain-of-Custody

Key points (full details unchanged from original Phase 16 spec):

- `evidence-manifest.json` is authoritative; `evidence.json` is compatibility view
- `evidence-ledger.jsonl` is append-only, fsynced, HMAC-signed per event
- Gateway evidence gate uses stat-check + 30s TTL cache; does NOT rehash on every call
- Two-tier gate: UNSEALED → read-only tools pass with warning; VIOLATION → all blocked
- Full SHA-256 rehash only on explicit "Verify Integrity" or pre-report check
- Solana anchoring available via `AGENTIR_SOLANA_KEYPAIR` (optional)

---

## 6. E01 Mount Architecture (Phase A-3)

Forensic images (.e01, .ex01) are mounted through a 4-strategy ladder:

```
Strategy 1: sudo xmount → ntfs-3g    (volume images — best success rate)
Strategy 2: sudo xmount → mount loop  (partitioned images via xmount)
Strategy 3: sudo ewfmount → mount loop (legacy, partitioned)
Strategy 4: sudo ewfmount → direct     (last resort, volume images)
```

All strategies use sudo so root can access FUSE files (xmount 0.7.6 lacks --allow-other).
`ntfs-3g` reads files directly without loop devices, avoiding the kernel's "Can't lookup
blockdev" error on FUSE-hosted files.

Corrupted NTFS paths (broken junctions, orphaned symlinks) are handled by `safe_rglob()`
in `discover.py` — catches OSError, logs warning, returns partial results. Applied across
all 7 files that traverse mounted NTFS volumes.

File hashing (`sha256_file` in `manifest.py`) is non-fatal — returns "" and logs warning
when FUSE read restrictions (EOVERFLOW on >2GB files) prevent hashing.

---

## 7. Installer Provisioning

The installer provisions these components in order:

```
check_os → check_python → install_uv → sync_workspace
  → install_state_dirs
  → configure_fuse (user_allow_other for forensic image mounting)
  → download_triage_databases (windows-triage SQLite DBs)
  → prepare_enrichment_assets
  → download_rag_index (22K-record ChromaDB from GitHub releases)
  → install_hayabusa (binary + 4,947 Sigma rules from GitHub)
  → generate_tls (CA + cert with localhost SAN)
  → write_default_examiner
  → write_gateway_config
  → start_opensearch + configure cluster/templates/GeoIP
  → install_opencti (opt-in, --enable-opencti)
  → install_opencti_feeds (opt-in, MITRE ATT&CK + CISA KEV)
  → install_systemd_service
  → configure_immutable_capability (Phase 17a)
  → configure_auditd (Phase 17b)
  → configure_apparmor (Phase 17c)
  → poll_gateway → write_handoff
```

Flags: `--skip-docker`, `--skip-db`, `--skip-rag`, `--skip-hayabusa`, `--enable-opencti`, `--enable-opencti-feeds`

---

## 8. Agent UX Optimization Plan

The Phase A audit revealed that the platform has a strong security foundation but lacks
agent-usable workflow structure. The optimization is structured in 5 phases.

### Phase A — Critical Unblockers ✅ COMPLETE

| Task | Status | Result |
|------|--------|--------|
| A-1: RAG index auto-build | ✅ | 22,268 records downloaded via `install.sh`; startup health check; fail-fast model loading |
| A-2: hayabusa + rules | ✅ | v3.9.0 + 4,947 YAML rules via `install.sh`; `_resolve_hayabusa_rules_dir` fixed |
| A-3: E01 ingest pipeline | ✅ | 5 bugs fixed; 38,805 docs indexed across 12 artifact types in 0.5 min |

### Phase B — Tool Surface Optimization 🟡 P1 ✅ COMPLETE (2026-05-25)

| Task | Description | Status |
|------|-------------|--------|
| B1 | Add `workflow_status` tool — single "what do I do now?" entry point | ✅ Deployed |
| B2 | Add `container_inspect` tool — inspect E01/disk images without mounting | ✅ Deployed |
| B3 | Add `environment_summary` tool — collapse 7+ discovery calls into 1 | ✅ Deployed |
| B4 | Prune deprecated tools from agent view (evidence_register, dead code) | ✅ Deployed |
| B5 | Add tool categories to aggregate listing (11 categories, 5 phase tags) | ✅ Deployed |

Deployment verified on SIFT VM: 79 tools, 56 readOnlyHint, 11 categories, 5 phase tags.
See TASKS.md Session 49 for full details. Group 3 (tool consolidation) designed, pending implementation.

### Phase C — Ingestion Resilience 🟡 P2

| Task | Description |
|------|-------------|
| C1 | E01 hostname auto-discovery from mounted SYSTEM registry hive |
| C2 | Lightweight ingest progress polling (`idx_ingest_progress`) |
| C3 | Ingest failure recovery / resume support |

### Phase D — Agent Workflow Engine 🟢 P3

| Task | Description |
|------|-------------|
| D1 | Investigation state machine (ORIENT→SURVEY→INGEST→TRIAGE→DEEP_DIVE→DETECTION→FINDINGS→REPORTING) |
| D2 | Phase-aware tool filtering in aggregate listing |
| D3 | Investigation playbook engine (ransomware, data_exfil, BEC, etc.) |

### Phase E — Production Hardening 🟢 P3

| Task | Description |
|------|-------------|
| E1 | RAG health check on startup (fail fast) |
| E2 | Gateway startup health check (all backends + services) |
| E3 | Agent session state export (resume across sessions) |

### Phase 17 — OS-Level Evidence Hardening

| Task | Description |
|------|-------------|
| 17a | chattr +i immutable flag after sealing |
| 17b | auditd rules for evidence directories |
| 17c | AppArmor profile for sift-gateway (complain→enforce after validation) |
| 17d | inotify evidence watcher for real-time gate cache invalidation |
| 17e | IMA xattr hash anchoring (optional, opt-in) |

---

## 9. Known Issues (Post Phase A)

These are documented issues discovered during live E01 ingest testing that
don't block the workflow but should be addressed:

1. **TLS enrichment calls**: Gateway-to-gateway HTTPS calls for triage/intel enrichment
   fail with SSL errors on some paths. Cert now includes `DNS:localhost`, needs
   verification across all enrichment paths.

2. **AppArmor profile**: Currently removed on SIFT VM (was blocking /tmp). Updated
   template is in `configs/apparmor/sift-gateway.template` but needs reloading and
   validation with `aa-logprof` before re-enabling.

3. **Plaso fallback tools**: `log2timeline.py` and `psort.py` not verified present
   on SIFT VM. If missing, prefetch and SRUM parsing fall back to wintools-mcp
   (which fails because no Windows host is configured).

4. **Amcache transaction logs**: After removing `--nl`, AmcacheParser uses LOG1/LOG2
   files. If those files are missing from a different evidence image, the parser
   may still fail — needs graceful error handling.

---

## 10. Security Model

### Auth Layers

1. **Bearer token** — timing-safe `hmac.compare_digest`, expiry-checked, two roles
2. **JWT session** — portal auth, HttpOnly/Secure/SameSite=Strict, sliding refresh
3. **HMAC challenge-response** — for state-mutating portal actions

### Defense in Depth

| Layer | Mechanism |
|-------|-----------|
| Transport | TLS with self-signed CA, SAN includes host IP + 127.0.0.1 + localhost |
| Auth | Bearer + expiry + timing-safe compare |
| Execution | shell=False, denylist, arg sanitization |
| Evidence | HMAC ledger + hash-chain manifest |
| Secrets | Response guard redaction (critical+high severity) |
| OS (Phase 17) | chattr +i, auditd, AppArmor, inotify |
| Blockchain | Solana SPL Memo anchoring (optional) |

---

## 11. Completed Phases

| Phase | Key Outcome |
|-------|-------------|
| 0-2 | vhir→agentir sweep, workspace scaffold, agentir-core hardened (225 tests) |
| 3-4 | Portal HTTPS, gateway auth/rate-limit |
| 5-6 | forensic-rag FastMCP migration, sift-mcp sanitization |
| 7-9 | install.sh, Docker Compose, configs/templates |
| 11 | Windows triage backend (SQLite, 13 tools) |
| 12-15 | Portal auth, agent RBAC, dashboard rewiring, session hardening |
| 16 | Evidence manifest + ledger + two-tier gate + Solana anchoring |
| R0-R4 | 93-tool audit, active case propagation, path resolution, portal-first language |
| A-1 | RAG index auto-build in install.sh (22,268 records, startup health check) |
| A-2 | hayabusa auto-install in install.sh (v3.9.0, 4,947 rules) |
| A-3 | E01 ingest pipeline fixed (5 bugs, 38,805 docs indexed, multi-strategy mount) |
